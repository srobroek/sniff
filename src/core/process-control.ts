/** Process-group ownership and termination shared by the install runtime and the run registry. */
import { accessSync, closeSync, constants, readSync, realpathSync, statSync } from "node:fs";
import { basename, isAbsolute, resolve } from "node:path";

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

/** Upper bound on waiting for a SIGKILLed group to be reaped; a member stuck in the kernel cannot hold cleanup forever. */
const GROUP_REAP_TIMEOUT_MS = 2_000;
const GROUP_REAP_POLL_MS = 5;

type GroupSignal = "SIGTERM" | "SIGKILL";

/**
 * Variables a POSIX shell reads at startup or maintains itself (bash, dash, ksh and ash), plus
 * bash's reserved `BASH*` family. Imported, they can change or stop the supervisor shell, for
 * example `SHELLOPTS=noexec` parses without executing and a non-numeric `OPTIND` aborts dash, and
 * the shell may rewrite them on export. They therefore never reach the shell's environment. A
 * shell outside this family with other special names could still rewrite those on export.
 */
const SHELL_VARIABLE = /^(?:BASH|BASH_.*|BASHOPTS|BASHPID|SHELLOPTS|POSIXLY_CORRECT|ENV|CDPATH|IFS|OPTIND|OPTARG|OPTERR|PS[1-4]|PPID|UID|EUID|GROUPS|LINENO|RANDOM|SRANDOM|SECONDS|HISTCMD|HIST[A-Z]*|PWD|OLDPWD|SHLVL|_|TMOUT|GLOBIGNORE|EXECIGNORE|FUNCNEST|FUNCNAME|DIRSTACK|PIPESTATUS|COMP_[A-Z]*|MAIL|MAILCHECK|MAILPATH|EPOCHSECONDS|EPOCHREALTIME|FCEDIT|FIGNORE|HOSTFILE|INPUTRC|TIMEFORMAT|PROMPT_COMMAND|IGNOREEOF|CHILD_MAX|FPATH|KSH_VERSION|ZDOTDIR)$/;
const SHELL_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
/** Variables a shell exports on its own even when it imported none of them. */
const SHELL_EXPORTED = ["PWD", "OLDPWD", "SHLVL", "_"];

/**
 * Forks the sentinel into the leader's process group, through an intermediate subshell so the
 * command never inherits an unknown child. The sentinel ignores SIGTERM/SIGHUP/SIGINT, has stdio on
 * /dev/null so it never holds a capture pipe, and keeps only the control socket on fd 3: it reports
 * its PID there and blocks reading it, so it exits on its own once Sniff closes the socket or dies.
 * The supervisors use no shell variable of their own, so they never clobber an exported one.
 */
const SENTINEL = `( { trap '' TERM HUP INT; read -r _ <&3; } </dev/null >/dev/null 2>&1 & echo "$!" >&3 )`;

/**
 * Supervisor for any POSIX sh, run as `sh -c VIA_ENV sniff-supervisor <NAME=value...> <argv...>`.
 * After the sentinel, the leader exec's `env` with fd 3 closed; `env` drops what the shell exported
 * on its own, restores the caller's shell variables and exec's the command.
 */
const VIA_ENV = `${SENTINEL}; exec /usr/bin/env ${SHELL_EXPORTED.map((name) => `-u ${name}`).join(" ")} -- "$@" 3>&-`;

/**
 * Supervisor for dash, which needs no `env` hop: of the variables it maintains, dash exports only
 * PWD on its own, which it may unset, and it exports any identifier verbatim except OPTIND, which it
 * validates as a number. The leader unsets PWD, exports each leading `NAME=value` operand and
 * exec's the rest with fd 3 closed. A command name never contains `=`, so the first operand without
 * one starts argv.
 */
const IN_DASH = `${SENTINEL}; unset PWD; while [ "$#" -gt 0 ]; do case $1 in *=*) export "$1"; shift ;; *) break ;; esac; done; exec "$@" 3>&-`;
const SUPERVISOR_NAME = "sniff-supervisor";

type SupervisorShell = { readonly path: string; readonly dash: boolean };

let supervisorShellChoice: SupervisorShell | undefined;

function isDash(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return basename(realpathSync(path)) === "dash";
  } catch {
    return false;
  }
}

/**
 * The shell that runs the supervisor, chosen once per process. dash is preferred: it starts much
 * faster than bash, which is `/bin/sh` on macOS and on some Linux distributions, and it restores the
 * caller's environment without an `env` exec. Without dash, `/bin/sh` runs the portable supervisor.
 */
function supervisorShell(): SupervisorShell {
  if (supervisorShellChoice) return supervisorShellChoice;
  const dash = ["/bin/dash", "/bin/sh"].find(isDash);
  supervisorShellChoice = dash ? { path: dash, dash: true } : { path: "/bin/sh", dash: false };
  return supervisorShellChoice;
}

/** Test seam: forces the portable `/bin/sh` supervisor, or restores automatic selection. */
export function setSupervisorShellForTests(choice?: "portable"): void {
  supervisorShellChoice = choice === "portable" ? { path: "/bin/sh", dash: false } : undefined;
}

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
  #killed = false;

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
    if (signal === "SIGKILL") {
      this.#killed = true;
      this.release();
    }
    return true;
  }

  /**
   * Resolves once a group this handle SIGKILLed has no member left, zombies included, so cleanup
   * that follows cannot race a dying member; immediately if it was never SIGKILLed through here.
   * Only the signal-0 existence probe touches the ID after release. Should the emptied ID be reused
   * meanwhile, the probe merely waits out the bound; it never delivers a signal.
   */
  async reaped(timeoutMs = GROUP_REAP_TIMEOUT_MS): Promise<void> {
    if (!this.#killed) return;
    const deadline = Date.now() + timeoutMs;
    while (groupExists(this.#pgid) && Date.now() < deadline) await Bun.sleep(GROUP_REAP_POLL_MS);
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

function groupExists(pgid: number): boolean {
  try {
    process.kill(-pgid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

type SpawnEnvironment = Record<string, string | undefined>;

function spawnError(code: "ENOENT" | "EACCES", message: string, path: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code, errno: code === "ENOENT" ? -2 : -13, path, syscall: "posix_spawn" });
}

/**
 * Rejects an executable `env` could not exec, with the error a direct `Bun.spawn` throws, so a
 * missing tool still fails to launch instead of exiting 127. `env` would read a name containing `=`
 * as one more assignment, so such a name is refused rather than misread.
 */
function assertSpawnable(executable: string | undefined, cwd: string, env: SpawnEnvironment): void {
  if (executable === undefined || executable.length === 0) throw new TypeError("cmd must not be empty");
  if (executable.includes("=")) throw new Error(`Sniff cannot launch an executable whose name contains "=": ${executable}`);
  if (!executable.includes("/")) {
    // `env` searches the caller's PATH, or the execvp default without one.
    if (Bun.which(executable, { PATH: env.PATH ?? "/usr/bin:/bin", cwd }) === null) {
      throw Object.assign(new Error(`Executable not found in $PATH: "${executable}"`), { code: "ENOENT", errno: -2, path: executable });
    }
    return;
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
}

/**
 * Splits the caller's environment into what the supervisor shell may import and the `NAME=value`
 * assignments restored before the command runs, by dash itself or by `env`: shell variables, and
 * names a shell might not pass through. Together they are exactly the caller's environment.
 *
 * Accepted exposure: the restored assignments travel as command-line arguments, first of the
 * supervisor shell and, on the `env` route, of `env`, until the final exec replaces them with the
 * command's own argv. While they do, any local user can read them with `ps`; measured, that lasts
 * under 1 ms on Linux and about 20 ms on macOS. It affects only the values of names matched by
 * `SHELL_VARIABLE` (such as PWD, OLDPWD, SHLVL, `_`, IFS, PS1-PS4, SHELLOPTS, BASH_ENV, ENV,
 * CDPATH, OPTIND, TMOUT and the BASH* family) and of names that are not shell identifiers (such as
 * exported bash functions, `BASH_FUNC_name%%`). Every other variable, which covers tokens and
 * credentials under ordinary names, reaches the command only through the process environment.
 * The trade is deliberate: importing those names would let the caller's environment control or
 * stop the supervisor shell, for example `SHELLOPTS=noexec`.
 */
function splitEnvironment(env: SpawnEnvironment): { readonly shell: Record<string, string>; readonly restored: string[]; readonly dashRestorable: boolean } {
  // Null-prototype: an own `__proto__` key is a valid variable and must be stored, not run a setter.
  const shell: Record<string, string> = Object.create(null);
  const restored: string[] = [];
  let dashRestorable = true;
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined || name.length === 0) continue;
    const identifier = SHELL_IDENTIFIER.test(name);
    if (identifier && !SHELL_VARIABLE.test(name)) {
      shell[name] = value;
      continue;
    }
    restored.push(`${name}=${value}`);
    // dash drops names that are not identifiers on import and cannot export them, and rejects a
    // non-numeric OPTIND; such an environment takes the `env` route.
    if (!identifier || name === "OPTIND") dashRestorable = false;
  }
  return { shell, restored, dashRestorable };
}

/**
 * Spawns `argv` as the leader of a new session and process group, with a sentinel that keeps the
 * group ID owned until `group.release()`. The leader is the command itself after the supervisor
 * shell (and, without dash, `env`) exec it, so its PID, argv, environment, exit code and signal
 * match a direct spawn.
 */
export function spawnInOwnedGroup(argv: readonly string[], options: { readonly cwd: string; readonly env: SpawnEnvironment }) {
  assertSpawnable(argv[0], options.cwd, options.env);
  const { shell, restored, dashRestorable } = splitEnvironment(options.env);
  const supervisor = supervisorShell();
  const script = supervisor.dash && dashRestorable ? IN_DASH : VIA_ENV;
  const proc = Bun.spawn([supervisor.path, "-c", script, SUPERVISOR_NAME, ...restored, ...argv], {
    cwd: options.cwd,
    env: shell,
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
 * same-group member that ignores SIGTERM cannot outlive the termination. Once the group was
 * SIGKILLed, by this escalation or by the run that owns it, the call returns only after every
 * member is reaped, so a release that awaits it never races a dying analyzer.
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
    await proc.group?.reaped();
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
