/** Process-group termination shared by the install runtime and the run registry. */

export type SpawnedProcess = {
  readonly pid: number;
  /** Resolves once the child has exited; cleanup must never run before it settles. */
  readonly exited: Promise<unknown>;
  readonly kill?: (signal: "SIGTERM" | "SIGKILL") => void;
};

/** Grace period between SIGTERM and SIGKILL for an analyzer process group. */
export const TERMINATION_GRACE_MS = 100;

export function terminateProcess(proc: { readonly pid: number; readonly kill?: (signal: "SIGTERM" | "SIGKILL") => void }, signal: "SIGTERM" | "SIGKILL"): void {
  try {
    process.kill(-proc.pid, signal);
    return;
  } catch {
    // The child may not lead a process group; fall back to the process itself.
  }
  try {
    if (proc.kill) proc.kill(signal);
    else process.kill(proc.pid, signal);
  } catch {
    // The child may have exited between termination and cleanup.
  }
}

/** Terminates a child and waits for its exit, escalating to SIGKILL after the grace period. */
export async function terminateAndAwait(proc: SpawnedProcess, graceMs = TERMINATION_GRACE_MS): Promise<void> {
  terminateProcess(proc, "SIGTERM");
  const force = setTimeout(() => terminateProcess(proc, "SIGKILL"), graceMs);
  try {
    await proc.exited;
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
