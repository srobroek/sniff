import { afterAll, afterEach, beforeAll, describe, expect, spyOn, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCommand } from "../../src/core/install.ts";
import { createRunManifest } from "../../src/core/intake.ts";
import { processAlive, type SpawnedProcess, setSupervisorShellForTests, terminateAndAwait } from "../../src/core/process-control.ts";
import { createSniffRunOwner } from "../../src/core/run-owner.ts";
import { issueRunLease, registerActiveProcess, unregisterActiveProcess } from "../../src/core/run-registry.ts";
import { validateResolvedTarget } from "../../src/core/target.ts";

const temps: string[] = [];
/** Runs that may still be in flight; each is ended only through its own owned group. */
const active = new Set<SpawnedProcess>();
/**
 * Cleanup never signals a remembered PID: a run still in flight is ended through its owned group,
 * which signals only while its sentinel proves the group ID is still ours, and every helper process
 * waits on a hold file in its temp directory, so removing the directory lets it exit on its own.
 */
afterEach(() => {
  for (const spawned of active) spawned.group?.end();
  active.clear();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function track(onSpawn?: (spawned: SpawnedProcess) => void): (spawned: SpawnedProcess) => void {
  return (spawned) => {
    active.add(spawned);
    onSpawn?.(spawned);
  };
}

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "sniff-owned-group-"));
  temps.push(dir);
  return dir;
}

/** A PID reported by a child: a positive integer that is neither init nor this runner. */
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
  return foreignPid(readFileSync(path, "utf8"));
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
  return foreignPid(String(pid));
}

/** A hold file: helper processes run while it exists and exit on their own once it is removed. */
function holdFile(dir: string): string {
  const hold = join(dir, "hold");
  writeFileSync(hold, "");
  return hold;
}

/** `sh` that writes its own PID to a ready file, then runs until its hold file is removed. */
function waitingCommand(dir: string): { argv: string[]; ready: string; release: () => void } {
  const ready = join(dir, "ready");
  const hold = holdFile(dir);
  const script = 'echo $$ > "$1.tmp" && mv "$1.tmp" "$1"; while [ -e "$2" ]; do sleep 0.01; done';
  return { argv: ["sh", "-c", script, "sniff-test", ready, hold], ready, release: () => rmSync(hold, { force: true }) };
}

/** Every guarantee holds with dash, chosen automatically where present, and with the portable `/bin/sh` supervisor. */
for (const shell of ["auto", "portable"] as const) describe(`owned process group (${shell} supervisor shell)`, () => {
  beforeAll(() => setSupervisorShellForTests(shell === "portable" ? "portable" : undefined));
  afterAll(() => setSupervisorShellForTests());

  test("keeps a sentinel in the command's group during a run and removes it afterwards", async () => {
    const { argv, ready, release } = waitingCommand(tempDir());
    let spawned: SpawnedProcess | undefined;
    const pending = runCommand(argv, tmpdir(), process.env, 20_000, undefined, undefined, track((handle) => {
      spawned = handle;
    }));
    const leader = await readyPid(ready);
    expect(leader).toBe(spawned?.pid ?? -1);
    const sentinel = sentinelOf(spawned);
    expect(sentinel).not.toBe(leader);
    expect(processAlive(sentinel)).toBe(true);
    // The command leads its own group and the sentinel is a member of it.
    expect(processGroupOf(leader)).toBe(leader);
    expect(processGroupOf(sentinel)).toBe(leader);
    release();
    const result = await pending;
    expect(result.exitCode).toBe(0);
    await until(() => !processAlive(sentinel), "the sentinel to exit");
    expect(spawned?.group?.owned()).toBe(false);
  });

  test("signals the group only while the sentinel is alive and SIGKILLs a SIGTERM-ignoring member after the leader is reaped", async () => {
    const dir = tempDir();
    const ready = join(dir, "ready");
    const hold = holdFile(dir);
    // The leader dies on SIGTERM; its same-group child ignores SIGTERM and must still be SIGKILLed.
    const script = '(trap "" TERM; sh -c \'echo $PPID\' > "$1.tmp" && mv "$1.tmp" "$1"; while [ -e "$2" ]; do sleep 0.05; done) </dev/null >/dev/null 2>&1 & wait';
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
      const pending = runCommand(["sh", "-c", script, "sniff-test", ready, hold], tmpdir(), process.env, 20_000, controller.signal, undefined, track((handle) => {
        spawned = handle;
      }));
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
    const hold = holdFile(tempDir());
    const script = '(while [ -e "$1" ]; do sleep 0.05; done) </dev/null >/dev/null 2>&1 & echo $!';
    const result = await runCommand(["sh", "-c", script, "sniff-test", hold], tmpdir(), process.env, 20_000, undefined, undefined, track());
    expect(result.exitCode).toBe(0);
    const descendant = foreignPid(result.stdout);
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
    // env(1) would read such a name as an assignment, so it is refused instead of misread.
    await expect(runCommand(["NAME=value"], tmpdir(), process.env, 5_000)).rejects.toThrow('contains "="');
  });

  test("terminateAndAwait signals an owned group only while the sentinel is alive and never an unowned PID", async () => {
    const { argv, ready } = waitingCommand(tempDir());
    let spawned: SpawnedProcess | undefined;
    const pending = runCommand(argv, tmpdir(), process.env, 20_000, undefined, undefined, track((handle) => {
      spawned = handle;
    }));
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

  /** Runs a command under `extra` knobs and checks the supervisor ran and the command saw exactly the caller's environment. */
  async function expectIsolatedEnvironment(extra: (dir: string, printer: string) => Record<string, string>): Promise<void> {
    const dir = tempDir();
    const ready = join(dir, "ready");
    const hold = holdFile(dir);
    const printer = join(dir, "startup.sh");
    writeFileSync(printer, "echo STARTUP-FILE-RAN\necho STARTUP-FILE-RAN >&2\n");
    const env: Record<string, string> = {
      ...Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined)),
      ...extra(dir, printer),
    };
    // Perl reads no shell variable, so it reports the environment the command really received.
    const dump = 'open(my $fh, ">", "$ARGV[0].tmp") or die; print $fh $$; close($fh); rename("$ARGV[0].tmp", $ARGV[0]) or die; select(undef, undef, undef, 0.01) while -e $ARGV[1]; print map { "$_\\0$ENV{$_}\\0" } sort keys %ENV;';
    let spawned: SpawnedProcess | undefined;
    const pending = runCommand(["perl", "-e", dump, ready, hold], dir, env, 20_000, undefined, undefined, track((handle) => {
      spawned = handle;
    }));
    await until(() => existsSync(ready), "the command to start");
    // The supervisor ran: its sentinel is alive and owns the group.
    const sentinel = sentinelOf(spawned);
    expect(processAlive(sentinel)).toBe(true);
    expect(spawned?.group?.owned()).toBe(true);
    rmSync(hold);
    const result = await pending;
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).not.toContain("STARTUP-FILE-RAN");
    const fields = result.stdout.split("\0");
    const received: Record<string, string> = {};
    for (let index = 0; index + 1 < fields.length; index += 2) received[fields[index] ?? ""] = fields[index + 1] ?? "";
    expect(received).toEqual(env);
  }

  test("shell startup knobs in the caller's environment neither disable the supervisor nor reach it", async () => {
    await expectIsolatedEnvironment((dir, printer) => ({
      SHELLOPTS: "noexec:xtrace",
      BASHOPTS: "nullglob",
      BASH_ENV: printer,
      ENV: printer,
      IFS: "x",
      CDPATH: join(dir, "nowhere"),
      POSIXLY_CORRECT: "1",
      PS4: "TRACE ",
      TMOUT: "1",
      PWD: "/caller/pwd",
      OLDPWD: "/caller/oldpwd",
      SHLVL: "7",
      _: "/caller/underscore",
      LINENO: "not-a-line",
      PPID: "not-a-pid",
    }));
  });

  test("names dash cannot import or export still reach the command exactly", async () => {
    await expectIsolatedEnvironment((_dir, printer) => ({
      SHELLOPTS: "noexec",
      BASH_ENV: printer,
      OPTIND: "not-a-number",
      "BASH_FUNC_read%%": "() { return 0; }",
      "dash-name": "kept",
      PWD: "/caller/pwd",
    }));
  });

  test("the command receives exactly the caller's environment, not the supervisor shell's", async () => {
    const env = { PATH: process.env.PATH ?? "/usr/bin:/bin", ONLY: "this" };
    const result = await runCommand(["perl", "-e", 'print map { "$_\\0$ENV{$_}\\0" } sort keys %ENV;'], tmpdir(), env, 20_000);
    expect(result.exitCode).toBe(0);
    // No PWD, SHLVL or OLDPWD from the shell, which a direct spawn never adds either.
    expect(result.stdout).toBe(`ONLY\0this\0PATH\0${env.PATH}\0`);
  });

  test("disposing a run owner returns only after the analyzer's whole group, sentinel included, is SIGKILLed and gone", async () => {
    const dir = tempDir();
    const root = tempDir();
    writeFileSync(join(root, "a.ts"), "export const value = 1;\n");
    const owner = createSniffRunOwner({ label: "owned-group dispose test" });
    const manifest = createRunManifest({ target: validateResolvedTarget({ kind: "files", label: "a.ts", root, files: ["a.ts"], materialization: "in-place" }), intent: "audit", scopeMode: "full" });
    const order: string[] = [];
    const lease = issueRunLease(manifest, { target: manifest.resolvedTarget, release: () => order.push("release") }, { owner });
    const ready = join(dir, "ready");
    const hold = holdFile(dir);
    // The leader dies on SIGTERM; its same-group child ignores SIGTERM, so only a SIGKILL ends it.
    const script = '(trap "" TERM; sh -c \'echo $PPID\' > "$1.tmp" && mv "$1.tmp" "$1"; while [ -e "$2" ]; do sleep 0.05; done) </dev/null >/dev/null 2>&1 & wait';
    let spawned: SpawnedProcess | undefined;
    const pending = runCommand(["sh", "-c", script, "sniff-test", ready, hold], root, process.env, 20_000, undefined, undefined, track((handle) => {
      spawned = handle;
      registerActiveProcess(lease.capability, lease.manifestId, handle, owner);
    }));
    try {
      const child = await readyPid(ready);
      const sentinel = sentinelOf(spawned);
      await owner.dispose("test disposal");
      order.push("disposed");
      // No polling: once dispose settles, every member is already gone and the target released after.
      expect(processAlive(child)).toBe(false);
      expect(processAlive(sentinel)).toBe(false);
      expect(order).toEqual(["release", "disposed"]);
      expect((await pending).signalCode).toBe("SIGTERM");
    } finally {
      if (spawned) unregisterActiveProcess(lease.capability, lease.manifestId, spawned.pid, owner);
      await owner.dispose();
    }
  });

  test("the sentinel exits when the Sniff process is killed", async () => {
    const dir = tempDir();
    const ready = join(dir, "ready");
    const leaderReady = join(dir, "leader");
    const hold = holdFile(dir);
    const script = join(dir, "host.ts");
    const install = join(import.meta.dir, "..", "..", "src", "core", "install.ts");
    writeFileSync(script, [
      "import { renameSync, writeFileSync } from \"node:fs\";",
      `import { runCommand } from ${JSON.stringify(install)};`,
      "const [ready, leaderReady, hold] = process.argv.slice(2) as [string, string, string];",
      "await runCommand([\"sh\", \"-c\", 'echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; while [ -e \"$2\" ]; do sleep 0.01; done', \"sniff-test\", leaderReady, hold], process.cwd(), process.env, 60_000, undefined, undefined, (spawned) => {",
      "  const publish = () => {",
      "    const sentinel = spawned.group?.sentinelPid;",
      "    if (sentinel === undefined) return void setTimeout(publish, 5);",
      "    writeFileSync(ready + \".tmp\", String(sentinel));",
      "    renameSync(ready + \".tmp\", ready);",
      "  };",
      "  publish();",
      "});",
    ].join("\n"));
    const host = Bun.spawn([process.execPath, script, ready, leaderReady, hold], { cwd: dir, stdout: "ignore", stderr: "inherit" });
    try {
      const sentinel = await readyPid(ready);
      await readyPid(leaderReady);
      expect(processAlive(sentinel)).toBe(true);
      host.kill("SIGKILL");
      await host.exited;
      await until(() => !processAlive(sentinel), "the orphaned sentinel to exit");
    } finally {
      // The orphaned command is outside this guarantee; it exits on its own once its hold is gone.
      rmSync(hold, { force: true });
      if (host.exitCode === null && host.signalCode === null) host.kill("SIGKILL");
      await host.exited;
    }
  });
});

describe("supervisor shell selection", () => {
  afterEach(() => setSupervisorShellForTests());

  /** The shell and script the next command's supervisor was spawned with. */
  async function supervisorOf(env: Record<string, string | undefined>): Promise<{ shell: string; viaEnv: boolean }> {
    const spawn = spyOn(Bun, "spawn");
    try {
      const result = await runCommand(["true"], tmpdir(), env, 20_000, undefined, undefined, track());
      expect(result.exitCode).toBe(0);
      const argv = spawn.mock.calls[0]?.[0] as string[] | undefined;
      return { shell: argv?.[0] ?? "", viaEnv: (argv?.[2] ?? "").includes("/usr/bin/env") };
    } finally {
      spawn.mockRestore();
    }
  }

  test("prefers dash, which restores the environment itself, and falls back to /bin/sh with env", async () => {
    setSupervisorShellForTests();
    const dash = existsSync("/bin/dash");
    const automatic = await supervisorOf(process.env);
    if (dash) expect(automatic).toEqual({ shell: "/bin/dash", viaEnv: false });
    // OPTIND and names that are not identifiers are beyond dash's export, so they take the env route.
    expect((await supervisorOf({ ...process.env, OPTIND: "1" })).viaEnv).toBe(true);
    expect((await supervisorOf({ ...process.env, "dash-name": "kept" })).viaEnv).toBe(true);
    setSupervisorShellForTests("portable");
    expect(await supervisorOf(process.env)).toEqual({ shell: "/bin/sh", viaEnv: true });
  });
});
