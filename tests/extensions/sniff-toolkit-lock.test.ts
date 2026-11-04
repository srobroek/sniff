import { afterEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSniffInstall, type SniffInstallRuntime, withToolkitLock } from "../../src/core/install.ts";

// The multi-process tests wait on separate Bun processes; every wait is still bounded by a ready file.
setDefaultTimeout(30_000);

const temporary: string[] = [];
afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temporary.push(dir);
  return dir;
}

function lockRuntime(cache: string): SniffInstallRuntime {
  return {
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
}

async function until(condition: () => boolean, label: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await Bun.sleep(5);
  }
}

/**
 * A separate Bun process that takes the toolkit lock, proves it is alone inside by creating the
 * shared `inside` directory exclusively, reports `entered-<name>`, and leaves once `release-<name>`
 * appears. Every step is a ready file, so the test never sleeps for timing.
 */
const LOCK_HOLDER = `
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const [install, cache, sync, name] = process.argv.slice(2);
const { runCommand, withToolkitLock } = await import(install);
const mark = (file, text = "") => { writeFileSync(join(sync, file + ".tmp"), text); renameSync(join(sync, file + ".tmp"), join(sync, file)); };
const runtime = { toolkitCacheRoot: cache };
mark("waiting-" + name);
await withToolkitLock("core", process.env, runtime, async () => {
  let alone = true;
  try { mkdirSync(join(sync, "inside")); } catch { alone = false; mark("violation-" + name); }
  mark("entered-" + name);
  if (name === "spawner") {
    // An installer child that outlives this process must not keep the lock alive.
    const wait = 'while [ ! -e "$1" ]; do sleep 0.01; done';
    void runCommand(["sh", "-c", 'echo $$ > "$2.tmp" && mv "$2.tmp" "$2"; ' + wait, "sniff-test", join(sync, "release-child"), join(sync, "child")], sync, process.env, 60_000);
  }
  while (!existsSync(join(sync, "release-" + name))) await Bun.sleep(5);
  if (alone) rmSync(join(sync, "inside"), { recursive: true, force: true });
  mark("left-" + name);
}, { waitMs: 60_000 });
`;

describe("toolkit install lock", () => {
  test("an abort during the wait returns promptly with operation aborted and leaves no lock behind", async () => {
    const cache = tempDir("sniff-toolkit-lock-");
    const runtime = lockRuntime(cache);
    const held = Promise.withResolvers<void>();
    const holding = withToolkitLock("core", process.env, runtime, () => held.promise);
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
    held.resolve();
    await holding;

    // An already aborted caller never takes a free lock, and the aborted waiter left nothing held.
    await expect(withToolkitLock("core", process.env, runtime, async () => {
      entered = true;
    }, { signal: AbortSignal.abort() })).rejects.toThrow("operation aborted");
    expect(entered).toBe(false);
    await withToolkitLock("core", process.env, runtime, async () => {
      entered = true;
    }, { waitMs: 0 });
    expect(entered).toBe(true);
  });

  test("callers in one process never share the critical section", async () => {
    const runtime = lockRuntime(tempDir("sniff-toolkit-lock-"));
    let inside = 0;
    let most = 0;
    const order: number[] = [];
    await Promise.all([0, 1, 2, 3].map((index) => withToolkitLock("core", process.env, runtime, async () => {
      inside += 1;
      most = Math.max(most, inside);
      order.push(index);
      await Bun.sleep(1);
      inside -= 1;
    }, { waitMs: 30_000 })));
    expect(most).toBe(1);
    expect(order.toSorted()).toEqual([0, 1, 2, 3]);
  });

  test("a live owner in another process keeps its lock until it exits, and its death frees it", async () => {
    const cache = tempDir("sniff-toolkit-lock-");
    const sync = tempDir("sniff-toolkit-lock-sync-");
    const script = join(sync, "holder.ts");
    writeFileSync(script, LOCK_HOLDER);
    const install = join(import.meta.dir, "..", "..", "src", "core", "install.ts");
    const holder = Bun.spawn([process.execPath, script, install, cache, sync, "owner"], { stdout: "ignore", stderr: "inherit" });
    try {
      await until(() => existsSync(join(sync, "entered-owner")), "the owner to take the lock");
      const runtime = lockRuntime(cache);
      let entered = false;
      await expect(withToolkitLock("core", process.env, runtime, async () => {
        entered = true;
      }, { waitMs: 300 })).rejects.toThrow("Sniff toolkit bundle core is locked by another process");
      expect(entered).toBe(false);
      // The owner dies holding the lock; the kernel releases it, with no staleness heuristic.
      holder.kill("SIGKILL");
      await holder.exited;
      await withToolkitLock("core", process.env, runtime, async () => {
        entered = true;
      }, { waitMs: 5_000 });
      expect(entered).toBe(true);
    } finally {
      if (holder.exitCode === null && holder.signalCode === null) holder.kill("SIGKILL");
      await holder.exited;
    }
  });

  test("a holder that dies frees the lock even while its installer child keeps running", async () => {
    const cache = tempDir("sniff-toolkit-lock-");
    const sync = tempDir("sniff-toolkit-lock-sync-");
    const script = join(sync, "holder.ts");
    writeFileSync(script, LOCK_HOLDER);
    const install = join(import.meta.dir, "..", "..", "src", "core", "install.ts");
    const holder = Bun.spawn([process.execPath, script, install, cache, sync, "spawner"], { stdout: "ignore", stderr: "inherit" });
    try {
      await until(() => existsSync(join(sync, "entered-spawner")) && existsSync(join(sync, "child")), "the holder and its child to start");
      holder.kill("SIGKILL");
      await holder.exited;
      let entered = false;
      await withToolkitLock("core", process.env, lockRuntime(cache), async () => {
        entered = true;
      }, { waitMs: 5_000 });
      expect(entered).toBe(true);
    } finally {
      // The orphaned child exits on its own once released; no remembered PID is ever signalled.
      writeFileSync(join(sync, "release-child"), "");
      if (holder.exitCode === null && holder.signalCode === null) holder.kill("SIGKILL");
      await holder.exited;
    }
  });

  test("three installer processes never hold the lock together, even when the owner dies inside it", async () => {
    const cache = tempDir("sniff-toolkit-lock-");
    const sync = tempDir("sniff-toolkit-lock-sync-");
    const script = join(sync, "holder.ts");
    writeFileSync(script, LOCK_HOLDER);
    const install = join(import.meta.dir, "..", "..", "src", "core", "install.ts");
    const marker = (file: string) => existsSync(join(sync, file));
    const holders = new Map<string, ReturnType<typeof Bun.spawn>>();
    const start = (name: string) => holders.set(name, Bun.spawn([process.execPath, script, install, cache, sync, name], { stdout: "ignore", stderr: "inherit" }));
    try {
      start("A");
      await until(() => marker("entered-A"), "A to enter");
      start("B");
      start("C");
      await until(() => marker("waiting-B") && marker("waiting-C"), "B and C to wait");
      // A dies inside the critical section, the case a stale-lock takeover used to handle.
      holders.get("A")?.kill("SIGKILL");
      await holders.get("A")?.exited;
      rmSync(join(sync, "inside"), { recursive: true, force: true });
      await until(() => marker("entered-B") || marker("entered-C"), "B or C to enter");
      const [first, second] = marker("entered-B") ? ["B", "C"] : ["C", "B"];
      expect(marker(`entered-${second}`)).toBe(false);
      writeFileSync(join(sync, `release-${first}`), "");
      await until(() => marker(`left-${first}`), `${first} to leave`);
      await until(() => marker(`entered-${second}`), `${second} to enter`);
      writeFileSync(join(sync, `release-${second}`), "");
      expect(await holders.get(first)?.exited).toBe(0);
      expect(await holders.get(second)?.exited).toBe(0);
      expect(readdirSync(sync).filter((file) => file.startsWith("violation-"))).toEqual([]);
    } finally {
      for (const holder of holders.values()) {
        if (holder.exitCode === null && holder.signalCode === null) holder.kill("SIGKILL");
        await holder.exited;
      }
    }
  });

  test("a cancelled install stops waiting for a toolkit lock held by another installer", async () => {
    const cache = tempDir("sniff-toolkit-lock-");
    const base = lockRuntime(cache);
    const held = Promise.withResolvers<void>();
    const holding = withToolkitLock("dup", process.env, base, () => held.promise);
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
    try {
      await expect(installing).rejects.toThrow("operation aborted");
      expect(Date.now() - startedAt).toBeLessThan(2_000);
      expect(commands.filter((argv) => argv.includes("install"))).toEqual([]);
    } finally {
      held.resolve();
      await holding;
    }
  });

  test("never removes the lock file, so a waiter can never lock an unlinked inode", async () => {
    const cache = tempDir("sniff-toolkit-lock-");
    const runtime = lockRuntime(cache);
    await withToolkitLock("core", process.env, runtime, async () => undefined);
    const before = readdirSync(join(cache, "core"));
    await withToolkitLock("core", process.env, runtime, async () => undefined);
    expect(readdirSync(join(cache, "core"))).toEqual(before);
    expect(before.length).toBe(1);
  });
});
