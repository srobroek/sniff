/** Process-group ownership and termination shared by the install runtime and the run registry. */
import { accessSync, closeSync, constants, readSync, statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

export type SpawnedProcess = {
  readonly pid: number;
  /** Resolves once the child has exited; cleanup must never run before it settles. */
  readonly exited: Promise<unknown>;
  readonly kill?: (signal: "SIGTERM" | "SIGKILL") => void;
  /** The child's Sniff-owned process group; only it may signal the group ID. */
  readonly group?: OwnedProcessGroup;
};

/**
 * Why a captured output stream is incomplete without having overflowed its byte limit:
 * a descendant kept the pipe open after the child exited, so capture stopped before EOF.
 */
export type StreamIncompleteness = "descendant-held-pipe";

/** Grace period between SIGTERM and SIGKILL for an analyzer process group. */
export const TERMINATION_GRACE_MS = 100;

type GroupSignal = "SIGTERM" | "SIGKILL";

/**
 * Supervisor run as `/bin/sh -c SUPERVISOR sniff-supervisor <argv...>`. Before exec'ing the real
 * command it forks a sentinel into the same process group, through an intermediate subshell so
 * the command never inherits an unknown child. The sentinel ignores SIGTERM/SIGHUP/SIGINT, has
 * stdio on /dev/null so it never holds a capture pipe, and keeps only the control socket on fd 3:
 * it reports its PID there and blocks reading it, so it exits on its own once Sniff closes the
 * socket or dies. The command is exec'd with fd 3 closed, so it keeps the leader PID and its argv.
 */
const SUPERVISOR = "( { trap '' TERM HUP INT; read -r _ <&3; } </dev/null >/dev/null 2>&1 & echo \"$!\" >&3 ); exec \"$@\" 3>&-";
const SUPERVISOR_NAME = "sniff-supervisor";

/**
 * The process group of a spawned leader, pinned by a Sniff-owned sentinel member. The kernel never
 * hands out a group ID while any member, zombies included, still exists, so a signal sent while the
 * sentinel is proven alive reaches only this group.
 *
 * Liveness is read from the parent end of the control socket. Only group members ever hold its
 * child end: the supervisor shell, its intermediate subshell, and the sentinel. A non-blocking read
 * that would block therefore proves a member still exists; EOF proves every holder exited, after
 * which the group is never signalled again. The only residual window is the instant between that
 * probe and `kill`: the sentinel would have to be SIGKILLed by someone else, every other member gone
 * and reaped, and the PID space wrap to the same ID within it.
 */
export class OwnedProcessGroup {
  readonly #pgid: number;
  #control: number | undefined;
  #handshake = "";
  #sentinelPid: number | undefined;

  constructor(pgid: number, control: number) {
    this.#pgid = pgid;
    this.#control = control;
  }

  /** The sentinel's PID once the supervisor reported it; diagnostic only, never signalled. */
  get sentinelPid(): number | undefined {
    this.owned();
    return this.#sentinelPid;
  }

  /** Whether a group member is proven alive, so the group ID is still this group's. */
  owned(): boolean {
    const control = this.#control;
    if (control === undefined) return false;
    const buffer = Buffer.allocUnsafe(64);
    for (;;) {
      let length: number;
      try {
        length = readSync(control, buffer, 0, buffer.length, null);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "EAGAIN" || code === "EWOULDBLOCK") return true;
        if (code === "EINTR") continue;
        this.release();
        return false;
      }
      if (length === 0) {
        this.release();
        return false;
      }
      this.#recordHandshake(buffer.subarray(0, length).toString("latin1"));
    }
  }

  /**
   * Signals the whole group if, and only if, it is still owned. A delivered SIGKILL ends every
   * member, the sentinel included, so the group is released and never signalled again.
   */
  signal(signal: GroupSignal): boolean {
    // The group ID is the leader's PID: never 0, 1, or this process, so never Sniff's own group.
    if (!Number.isSafeInteger(this.#pgid) || this.#pgid <= 1 || this.#pgid === process.pid || !this.owned()) return false;
    try {
      process.kill(-this.#pgid, signal);
    } catch {
      return false;
    }
    if (signal === "SIGKILL") this.release();
    return true;
  }

  /** Ends every remaining member with SIGKILL while still owned, then releases the group for good. */
  end(): void {
    this.signal("SIGKILL");
    this.release();
  }

  /** Closes the control socket once; the sentinel then exits and the group is never signalled again. */
  release(): void {
    const control = this.#control;
    if (control === undefined) return;
    this.#control = undefined;
    try {
      closeSync(control);
    } catch {
      // Already closed.
    }
  }

  #recordHandshake(text: string): void {
    if (this.#sentinelPid !== undefined || this.#handshake.length > 32) return;
    this.#handshake += text;
    const line = this.#handshake.split("\n", 2);
    if (line.length < 2) return;
    const pid = Number(line[0]);
    if (/^[1-9]\d*$/.test(line[0] ?? "") && Number.isSafeInteger(pid) && pid > 1 && pid !== this.#pgid && pid !== process.pid) this.#sentinelPid = pid;
  }
}

type SpawnEnvironment = Record<string, string | undefined>;

function spawnError(code: "ENOENT" | "EACCES", message: string, path: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code, errno: code === "ENOENT" ? -2 : -13, path, syscall: "posix_spawn" });
}

/**
 * Resolves the word the supervisor shell exec's. An executable the shell could not exec is rejected
 * with the error a direct `Bun.spawn` throws, so a missing tool still fails to launch instead of
 * exiting 127. The shell's `exec` would parse a leading `-` as an option, so only such a name is
 * replaced by its resolved path; every other name reaches the command unchanged as its argv[0].
 */
function execTarget(executable: string | undefined, cwd: string, env: SpawnEnvironment): string {
  if (executable === undefined || executable.length === 0) throw new TypeError("cmd must not be empty");
  if (!executable.includes("/")) {
    const found = Bun.which(executable, { PATH: env.PATH ?? process.env.PATH ?? "", cwd });
    if (found === null) throw Object.assign(new Error(`Executable not found in $PATH: "${executable}"`), { code: "ENOENT", errno: -2, path: executable });
    return executable.startsWith("-") ? found : executable;
  }
  const path = isAbsolute(executable) ? executable : resolve(cwd, executable);
  let isFile: boolean;
  try {
    isFile = statSync(path).isFile();
  } catch {
    throw spawnError("ENOENT", `ENOENT: no such file or directory, posix_spawn '${executable}'`, executable);
  }
  let runnable = isFile;
  try {
    if (isFile) accessSync(path, constants.X_OK);
  } catch {
    runnable = false;
  }
  if (!runnable) throw spawnError("EACCES", `EACCES: permission denied, posix_spawn '${executable}'`, executable);
  return executable.startsWith("-") ? path : executable;
}

/**
 * Spawns `argv` as the leader of a new session and process group, with a sentinel that keeps the
 * group ID owned until `group.release()`. The leader is the command itself after the supervisor
 * shell exec's it, so its PID, argv, exit code and signal match a direct spawn.
 */
export function spawnInOwnedGroup(argv: readonly string[], options: { readonly cwd: string; readonly env: SpawnEnvironment }) {
  const proc = Bun.spawn(["/bin/sh", "-c", SUPERVISOR, SUPERVISOR_NAME, execTarget(argv[0], options.cwd, options.env), ...argv.slice(1)], {
    cwd: options.cwd,
    env: options.env,
    stdio: ["ignore", "pipe", "pipe", "socket-fd"],
    detached: true,
  });
  const control = proc.stdio[3];
  if (typeof control !== "number") {
    proc.kill("SIGKILL");
    throw new Error("the process supervisor has no control socket");
  }
  return { proc, group: new OwnedProcessGroup(proc.pid, control) };
}

/**
 * Signals a child's owned group, or only the child itself through its own handle once the group is
 * no longer owned. A bare PID is never signalled: without an owned group it may already be reused.
 */
export function terminateProcess(proc: Pick<SpawnedProcess, "kill" | "group">, signal: GroupSignal): void {
  if (proc.group?.signal(signal)) return;
  try {
    proc.kill?.(signal);
  } catch {
    // The child may have exited between termination and cleanup.
  }
}

/**
 * Terminates a child and waits for its exit, escalating to SIGKILL after the grace period. While
 * the child's group is still owned after the leader exits, the escalation still runs, so a
 * same-group member that ignores SIGTERM cannot outlive the termination.
 */
export async function terminateAndAwait(proc: SpawnedProcess, graceMs = TERMINATION_GRACE_MS): Promise<void> {
  terminateProcess(proc, "SIGTERM");
  let force: ReturnType<typeof setTimeout> | undefined;
  const escalated = new Promise<void>((resolve) => {
    force = setTimeout(() => {
      terminateProcess(proc, "SIGKILL");
      resolve();
    }, graceMs);
  });
  try {
    await proc.exited;
    if (proc.group?.owned()) await escalated;
  } catch {
    // An exit that rejects is still an exit; cleanup may proceed.
  } finally {
    clearTimeout(force);
  }
}

export function processAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}
