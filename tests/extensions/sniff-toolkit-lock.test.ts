import { afterEach, describe, expect, spyOn, test } from "bun:test";
import * as fs from "node:fs";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSniffInstall, type SniffInstallRuntime, TOOLKIT_LOCK_STALE_MS, withToolkitLock } from "../../src/core/install.ts";
import * as processControl from "../../src/core/process-control.ts";

const temporary: string[] = [];
afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

type LockOwner = { pid: number; token: string; startedAt: number };

function lockFixture(): { runtime: SniffInstallRuntime; directory: string; lockPath: string; ownerPath: string } {
  const cache = mkdtempSync(join(tmpdir(), "sniff-toolkit-lock-"));
  temporary.push(cache);
  const runtime: SniffInstallRuntime = {
    toolkitCacheRoot: cache,
    resolveCommand: () => null,
    readLauncher: () => "",
    resolveOpenGrep: () => null,
    provisionOpenGrep: async () => {
      throw new Error("unexpected OpenGrep provisioning");
    },
    run: async () => {
      throw new Error("unexpected command");
    },
    freshEnvironment: async (_cwd, env) => ({ env, source: "process" }),
  };
  const directory = join(cache, "core");
  const lockPath = join(directory, ".lock");
  return { runtime, directory, lockPath, ownerPath: join(lockPath, "owner.json") };
}

function holdLock(lockPath: string, owner: LockOwner): void {
  mkdirSync(lockPath, { recursive: true });
  writeFileSync(join(lockPath, "owner.json"), JSON.stringify(owner));
}

function readOwner(ownerPath: string): LockOwner {
  return JSON.parse(readFileSync(ownerPath, "utf8")) as LockOwner;
}

/** A PID with no live process behind it, found by probing downwards from the top of the PID space. */
function deadPid(): number {
  let pid = 4_194_303;
  while (pid > 1 && processControl.processAlive(pid)) pid -= 1;
  return pid;
}

/** A lock whose owner is long gone: older than the staleness bound and owned by a dead PID. */
function staleOwner(): LockOwner {
  return { pid: deadPid(), token: "stale-owner", startedAt: Date.now() - TOOLKIT_LOCK_STALE_MS * 2 };
}

describe("toolkit install lock", () => {
  test("an abort during the wait returns promptly with operation aborted and leaves no lock of its own", async () => {
    const { runtime, directory, lockPath, ownerPath } = lockFixture();
    const owner = { pid: process.pid, token: "live-owner", startedAt: Date.now() };
    holdLock(lockPath, owner);
    const controller = new AbortController();
    let entered = false;
    const startedAt = Date.now();
    const waiting = withToolkitLock("core", process.env, runtime, async () => {
      entered = true;
    }, { waitMs: 60_000, signal: controller.signal });
    setTimeout(() => controller.abort(), 20);
    await expect(waiting).rejects.toThrow("operation aborted");
    expect(Date.now() - startedAt).toBeLessThan(2_000);
    expect(entered).toBe(false);
    // The live owner's lock is untouched and the waiter left nothing beside it.
    expect(readOwner(ownerPath)).toEqual(owner);
    expect(readdirSync(directory)).toEqual([".lock"]);

    // An already aborted caller never takes a free lock either.
    rmSync(lockPath, { recursive: true, force: true });
    await expect(withToolkitLock("core", process.env, runtime, async () => {
      entered = true;
    }, { signal: AbortSignal.abort() })).rejects.toThrow("operation aborted");
    expect(entered).toBe(false);
    expect(readdirSync(directory)).toEqual([]);
  });

  test("two concurrent stale takeovers produce exactly one owner", async () => {
    const { runtime, lockPath } = lockFixture();
    const stale = staleOwner();
    holdLock(lockPath, stale);
    const inside = new Set<string>();
    let overlapped = false;
    const releaseFirst = Promise.withResolvers<void>();
    const critical = (name: string, hold: Promise<void>) => async () => {
      if (inside.size > 0) overlapped = true;
      inside.add(name);
      await hold;
      inside.delete(name);
    };
    let second: Promise<void> | undefined;
    let interleaved = false;
    // Waiter A reads the stale owner; before it acts, waiter B takes the lock over and acquires it.
    const realAlive = processControl.processAlive;
    const alive = spyOn(processControl, "processAlive").mockImplementation((pid: number) => {
      if (pid === stale.pid && !interleaved) {
        interleaved = true;
        second = withToolkitLock("core", process.env, runtime, critical("B", releaseFirst.promise), { waitMs: 30_000 });
      }
      return realAlive(pid);
    });
    try {
      const first = withToolkitLock("core", process.env, runtime, critical("A", Promise.resolve()), { waitMs: 30_000 });
      await Promise.resolve();
      expect(second).toBeDefined();
      expect([...inside]).toEqual(["B"]);
      expect(readOwner(join(lockPath, "owner.json")).pid).toBe(process.pid);
      releaseFirst.resolve();
      await Promise.all([first, second]);
      expect(overlapped).toBe(false);
      expect(existsSync(lockPath)).toBe(false);
    } finally {
      alive.mockRestore();
      releaseFirst.resolve();
    }
  });

  test("a takeover that races a fresh acquisition puts the live lock back", async () => {
    const { runtime, directory, lockPath, ownerPath } = lockFixture();
    holdLock(lockPath, staleOwner());
    const inside = new Set<string>();
    let overlapped = false;
    const releaseB = Promise.withResolvers<void>();
    const critical = (name: string, hold: Promise<void>) => async () => {
      if (inside.size > 0) overlapped = true;
      inside.add(name);
      await hold;
      inside.delete(name);
    };
    let second: Promise<void> | undefined;
    let interleaved = false;
    let liveToken: string | undefined;
    const realRename = fs.renameSync;
    // Waiter A has re-checked the stale owner; just before its rename, waiter B takes the lock over.
    const rename = spyOn(fs, "renameSync").mockImplementation((from: fs.PathLike, to: fs.PathLike) => {
      if (from === lockPath && !interleaved) {
        interleaved = true;
        second = withToolkitLock("core", process.env, runtime, critical("B", releaseB.promise), { waitMs: 30_000 });
        liveToken = readOwner(ownerPath).token;
      }
      return realRename(from, to);
    });
    try {
      const first = withToolkitLock("core", process.env, runtime, critical("A", Promise.resolve()), { waitMs: 30_000 });
      await Promise.resolve();
      expect([...inside]).toEqual(["B"]);
      // A moved B's live lock aside, saw it was not the stale one, and restored it.
      expect(readOwner(ownerPath).token).toBe(liveToken ?? "");
      expect(readdirSync(directory)).toEqual([".lock"]);
      releaseB.resolve();
      await Promise.all([first, second]);
      expect(overlapped).toBe(false);
      expect(readdirSync(directory)).toEqual([]);
    } finally {
      rename.mockRestore();
      releaseB.resolve();
    }
  });

  test("a cancelled install stops waiting for a toolkit lock held by another installer", async () => {
    const { runtime: base, lockPath, ownerPath } = lockFixture();
    const dupLock = join(lockPath, "..", "..", "dup", ".lock");
    const owner = { pid: process.pid, token: "live-installer", startedAt: Date.now() };
    holdLock(dupLock, owner);
    const commands: string[][] = [];
    const runtime: SniffInstallRuntime = {
      ...base,
      resolveCommand: (bin) => (bin === "mise" ? "/fake/bin/mise" : null),
      run: async (argv, _cwd, _env, timeoutMs) => {
        commands.push(argv);
        return { argv, exitCode: 0, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs };
      },
    };
    const controller = new AbortController();
    const startedAt = Date.now();
    const installing = runSniffInstall({ mode: "install", bundles: ["dup"], runtime, signal: controller.signal });
    setTimeout(() => controller.abort(), 20);
    await expect(installing).rejects.toThrow("operation aborted");
    expect(Date.now() - startedAt).toBeLessThan(2_000);
    expect(commands.filter((argv) => argv.includes("install"))).toEqual([]);
    expect(readOwner(join(dupLock, "owner.json"))).toEqual(owner);
    expect(existsSync(ownerPath)).toBe(false);
  });

  test("a live owner is never removed, however old its lock", async () => {
    const { runtime, directory, lockPath, ownerPath } = lockFixture();
    const owner = { pid: process.pid, token: "live-owner", startedAt: Date.now() - TOOLKIT_LOCK_STALE_MS * 4 };
    holdLock(lockPath, owner);
    let entered = false;
    const attempt = () => withToolkitLock("core", process.env, runtime, async () => {
      entered = true;
    }, { waitMs: 300 });
    await Promise.all([
      expect(attempt()).rejects.toThrow("Sniff toolkit bundle core is locked by another process"),
      expect(attempt()).rejects.toThrow("Sniff toolkit bundle core is locked by another process"),
    ]);
    expect(entered).toBe(false);
    expect(readOwner(ownerPath)).toEqual(owner);
    expect(readdirSync(directory)).toEqual([".lock"]);
  });
});
