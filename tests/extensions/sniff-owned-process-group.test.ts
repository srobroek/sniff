import { afterAll, describe, expect, spyOn, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCommand } from "../../src/core/install.ts";
import { processAlive, type SpawnedProcess, terminateAndAwait } from "../../src/core/process-control.ts";

const temps: string[] = [];
/** Foreign PIDs this file started; each was validated before it was registered. */
const strays = new Set<number>();
afterAll(() => {
  for (const pid of strays) {
    if (!processAlive(pid)) continue;
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  }
  for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "sniff-owned-group-"));
  temps.push(dir);
  return dir;
}

/** A PID safe to signal from a test: a positive integer that is neither init nor this runner. */
function foreignPid(text: string): number {
  const trimmed = text.trim();
  const pid = Number(trimmed);
  if (!/^[1-9]\d*$/.test(trimmed) || !Number.isSafeInteger(pid) || pid <= 1 || pid === process.pid) throw new Error(`invalid PID: ${JSON.stringify(text)}`);
  return pid;
}

async function until(condition: () => boolean, label: string, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await Bun.sleep(10);
  }
}

/** Waits for a ready file written atomically by a child and returns the PID it holds. */
async function readyPid(path: string): Promise<number> {
  await until(() => existsSync(path), `ready file ${path}`);
  const pid = foreignPid(readFileSync(path, "utf8"));
  strays.add(pid);
  return pid;
}

function processGroupOf(pid: number): number | null {
  const result = Bun.spawnSync(["ps", "-o", "pgid=", "-p", String(pid)], { stdout: "pipe", stderr: "ignore" });
  const text = result.stdout.toString().trim();
  return /^\d+$/.test(text) ? Number(text) : null;
}

/** The sentinel PID from the supervisor handshake; it is written before the command starts. */
function sentinelOf(spawned: SpawnedProcess | undefined): number {
  const pid = spawned?.group?.sentinelPid;
  if (pid === undefined) throw new Error("the spawned command has no owned process group");
  const sentinel = foreignPid(String(pid));
  strays.add(sentinel);
  return sentinel;
}

/** `sh` that writes its own PID to a ready file, then waits for a release file. */
function waitingCommand(dir: string): { argv: string[]; ready: string; release: string } {
  const ready = join(dir, "ready");
  const release = join(dir, "release");
  const script = 'echo $$ > "$1.tmp" && mv "$1.tmp" "$1"; while [ ! -e "$2" ]; do sleep 0.01; done';
  return { argv: ["sh", "-c", script, "sniff-test", ready, release], ready, release };
}

describe("owned process group", () => {
  test("keeps a sentinel in the command's group during a run and removes it afterwards", async () => {
    const { argv, ready, release } = waitingCommand(tempDir());
    let spawned: SpawnedProcess | undefined;
    const pending = runCommand(argv, tmpdir(), process.env, 20_000, undefined, undefined, (handle) => {
      spawned = handle;
    });
    const leader = await readyPid(ready);
    expect(leader).toBe(spawned?.pid ?? -1);
    const sentinel = sentinelOf(spawned);
    expect(sentinel).not.toBe(leader);
    expect(processAlive(sentinel)).toBe(true);
    // The command leads its own group and the sentinel is a member of it.
    expect(processGroupOf(leader)).toBe(leader);
    expect(processGroupOf(sentinel)).toBe(leader);
    writeFileSync(release, "");
    const result = await pending;
    expect(result.exitCode).toBe(0);
    await until(() => !processAlive(sentinel), "the sentinel to exit");
    expect(spawned?.group?.owned()).toBe(false);
  });

  test("signals the group only while the sentinel is alive and SIGKILLs a SIGTERM-ignoring member after the leader is reaped", async () => {
    const dir = tempDir();
    const ready = join(dir, "ready");
    // The leader dies on SIGTERM; its same-group child ignores SIGTERM and must still be SIGKILLed.
    const script = '(trap "" TERM; sh -c \'echo $PPID\' > "$1.tmp" && mv "$1.tmp" "$1"; while :; do sleep 1; done) </dev/null >/dev/null 2>&1 & wait';
    const controller = new AbortController();
    let spawned: SpawnedProcess | undefined;
    const realKill = process.kill.bind(process);
    const groupSignals: { pid: number; signal: string | number | undefined; sentinelAlive: boolean }[] = [];
    let sentinel = 0;
    const kill = spyOn(process, "kill").mockImplementation(((pid: number, signal?: NodeJS.Signals | number) => {
      if (pid <= 0) {
        let sentinelAlive = false;
        try {
          sentinelAlive = sentinel > 1 && realKill(sentinel, 0);
        } catch {
          sentinelAlive = false;
        }
        groupSignals.push({ pid, signal, sentinelAlive });
      }
      return realKill(pid, signal);
    }) as typeof process.kill);
    try {
      const pending = runCommand(["sh", "-c", script, "sniff-test", ready], tmpdir(), process.env, 20_000, controller.signal, undefined, (handle) => {
        spawned = handle;
      });
      const child = await readyPid(ready);
      sentinel = sentinelOf(spawned);
      expect(processGroupOf(child)).toBe(spawned?.pid ?? -1);
      controller.abort();
      const result = await pending;
      expect(result.error).toBe("operation aborted");
      await until(() => !processAlive(child), "the SIGTERM-ignoring child to be killed");
      expect(groupSignals.map((entry) => entry.signal)).toContain("SIGTERM");
      expect(groupSignals.map((entry) => entry.signal)).toContain("SIGKILL");
      for (const entry of groupSignals) {
        // Never PID 0, never this runner's group: only the spawned leader's group, while owned.
        expect(entry.pid).toBe(-(spawned?.pid ?? 0));
        expect(entry.sentinelAlive).toBe(true);
      }
    } finally {
      kill.mockRestore();
    }
  });

  test("a successful command leaves no same-group descendant behind", async () => {
    const result = await runCommand(["sh", "-c", "sleep 30 </dev/null >/dev/null 2>&1 & echo $!"], tmpdir(), process.env, 20_000);
    expect(result.exitCode).toBe(0);
    const descendant = foreignPid(result.stdout);
    strays.add(descendant);
    await until(() => !processAlive(descendant), "the background descendant to be killed");
  });

  test("reports the same exit codes and signals as a direct spawn", async () => {
    const commands = [["true"], ["false"], ["sh", "-c", "exit 3"], ["sh", "-c", "kill -TERM $$"], ["sh", "-c", "kill -KILL $$"], ["sh", "-c", "kill -INT $$"]];
    for (const argv of commands) {
      const direct = Bun.spawn(argv, { stdout: "ignore", stderr: "ignore" });
      const directCode = await direct.exited;
      const result = await runCommand(argv, tmpdir(), process.env, 20_000);
      expect({ argv, exitCode: result.exitCode, signalCode: result.signalCode }).toEqual({ argv, exitCode: directCode, signalCode: direct.signalCode ?? undefined });
    }
  });

  test("runs the command itself as the group leader with its argv passed through exactly", async () => {
    const script = 'printf "%s\\n" "$$" "$(ps -o pgid= -p $$ | tr -d " ")"; ps -ww -o args= -p $$; printf "<%s>" "$@"';
    const argv = ["sh", "-c", script, "sniff-test", "-leading", "with space", "quote'\"", "-", "--", "", "$HOME", "*", "back\\slash"];
    let spawned: SpawnedProcess | undefined;
    const result = await runCommand(argv, tmpdir(), process.env, 20_000, undefined, undefined, (handle) => {
      spawned = handle;
    });
    const direct = Bun.spawn(argv, { cwd: tmpdir(), stdout: "pipe", stderr: "pipe" });
    const directOut = await new Response(direct.stdout).text();
    await direct.exited;
    const [pid, pgid, args, passed] = result.stdout.split("\n");
    const [, , directArgs, directPassed] = directOut.split("\n");
    expect(pid).toBe(String(spawned?.pid));
    expect(pgid).toBe(pid);
    expect(args).toBe(directArgs);
    expect(passed).toBe(directPassed);
    expect(passed).toBe("<-leading><with space><quote'\"><-><--><><$HOME><*><back\\slash>");
  });

  test("runs a leading-dash executable name and rejects missing executables like a direct spawn", async () => {
    const bin = tempDir();
    const tool = join(bin, "-dash-tool");
    writeFileSync(tool, '#!/bin/sh\nprintf "%s|" "$@"\n', { mode: 0o755 });
    const env = { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` };
    const argv = ["-dash-tool", "-n", "a b"];
    const direct = Bun.spawn(argv, { env, stdout: "pipe" });
    const directOut = await new Response(direct.stdout).text();
    await direct.exited;
    const result = await runCommand(argv, tmpdir(), env, 5_000);
    expect(result).toMatchObject({ exitCode: 0, stdout: directOut });
    expect(directOut).toBe("-n|a b|");

    const missing = "sniff-definitely-missing-command";
    let directError: unknown;
    try {
      Bun.spawn([missing], { env: process.env });
    } catch (error) {
      directError = error;
    }
    expect(directError).toBeInstanceOf(Error);
    await expect(runCommand([missing], tmpdir(), process.env, 5_000)).rejects.toThrow((directError as Error).message);
    await expect(runCommand([join(tmpdir(), "sniff-missing", "-x")], tmpdir(), process.env, 5_000)).rejects.toThrow("ENOENT");
  });

  test("terminateAndAwait signals an owned group only while the sentinel is alive and never an unowned PID", async () => {
    const { argv, ready } = waitingCommand(tempDir());
    let spawned: SpawnedProcess | undefined;
    const pending = runCommand(argv, tmpdir(), process.env, 20_000, undefined, undefined, (handle) => {
      spawned = handle;
    });
    await readyPid(ready);
    const sentinel = sentinelOf(spawned);
    if (!spawned) throw new Error("no spawned handle");
    const realKill = process.kill.bind(process);
    const calls: { pid: number; sentinelAlive: boolean }[] = [];
    const kill = spyOn(process, "kill").mockImplementation(((pid: number, signal?: NodeJS.Signals | number) => {
      let sentinelAlive = false;
      try {
        sentinelAlive = realKill(sentinel, 0);
      } catch {
        sentinelAlive = false;
      }
      if (signal !== 0) calls.push({ pid, sentinelAlive });
      return realKill(pid, signal);
    }) as typeof process.kill);
    try {
      await terminateAndAwait(spawned);
      expect(calls.length).toBeGreaterThan(0);
      for (const call of calls) {
        expect(call.pid).toBe(-spawned.pid);
        expect(call.sentinelAlive).toBe(true);
      }
      const result = await pending;
      expect(result.signalCode).toBe("SIGTERM");
      calls.length = 0;
      // A handle with no owned group and no kill function is never signalled by its bare PID.
      await terminateAndAwait({ pid: spawned.pid, exited: Promise.resolve(0) });
      // The finished run released its group, so a late termination cannot reach a reused group ID.
      await terminateAndAwait(spawned);
      expect(calls.filter((call) => call.pid <= 0 || call.pid === spawned?.pid)).toEqual([]);
    } finally {
      kill.mockRestore();
    }
    await until(() => !processAlive(sentinel), "the sentinel to exit");
  });

  test("the sentinel exits when the Sniff process is killed", async () => {
    const dir = tempDir();
    const ready = join(dir, "ready");
    const leaderReady = join(dir, "leader");
    const script = join(dir, "host.ts");
    const install = join(import.meta.dir, "..", "..", "src", "core", "install.ts");
    writeFileSync(script, [
      "import { renameSync, writeFileSync } from \"node:fs\";",
      `import { runCommand } from ${JSON.stringify(install)};`,
      "const [ready, leaderReady] = process.argv.slice(2) as [string, string];",
      "await runCommand([\"sh\", \"-c\", 'echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; exec sleep 30', \"sniff-test\", leaderReady], process.cwd(), process.env, 60_000, undefined, undefined, (spawned) => {",
      "  const publish = () => {",
      "    const sentinel = spawned.group?.sentinelPid;",
      "    if (sentinel === undefined) return void setTimeout(publish, 5);",
      "    writeFileSync(ready + \".tmp\", String(sentinel));",
      "    renameSync(ready + \".tmp\", ready);",
      "  };",
      "  publish();",
      "});",
    ].join("\n"));
    const host = Bun.spawn([process.execPath, script, ready, leaderReady], { cwd: dir, stdout: "ignore", stderr: "inherit" });
    try {
      const sentinel = await readyPid(ready);
      const leader = await readyPid(leaderReady);
      expect(processAlive(sentinel)).toBe(true);
      host.kill("SIGKILL");
      await host.exited;
      await until(() => !processAlive(sentinel), "the orphaned sentinel to exit");
      // The orphaned command itself is outside this guarantee; end it so no process outlives the test.
      if (processAlive(leader)) process.kill(leader, "SIGKILL");
    } finally {
      if (host.exitCode === null && host.signalCode === null) host.kill("SIGKILL");
    }
  });
});
