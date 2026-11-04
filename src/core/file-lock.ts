/** Exclusive OS advisory locks on lock files, held by an open descriptor and released by the kernel. */
import { dlopen, FFIType, read } from "bun:ffi";
import { closeSync, constants, openSync } from "node:fs";

const LOCK_EX = 2;
const LOCK_NB = 4;
const EINTR = 4;

type FlockSymbols = { readonly flock: (fd: number, operation: number) => number; readonly errno: () => number };

let symbols: FlockSymbols | undefined;

function flockSymbols(): FlockSymbols {
  if (symbols) return symbols;
  const darwin = process.platform === "darwin";
  if (!darwin && process.platform !== "linux") throw new Error(`Sniff toolkit locking does not support ${process.platform}`);
  const errnoName = darwin ? "__error" : "__errno_location";
  const loaded = dlopen(darwin ? "/usr/lib/libSystem.B.dylib" : "libc.so.6", {
    flock: { args: [FFIType.i32, FFIType.i32], returns: FFIType.i32 },
    [errnoName]: { args: [], returns: FFIType.ptr },
  });
  const native = loaded.symbols as unknown as Record<string, (...args: never[]) => unknown>;
  const errnoLocation = native[errnoName] as () => Parameters<typeof read.i32>[0];
  symbols = {
    flock: native.flock as unknown as FlockSymbols["flock"],
    errno: () => read.i32(errnoLocation()),
  };
  return symbols;
}

/** EWOULDBLOCK, which is EAGAIN on both supported platforms. */
function wouldBlock(code: number): boolean {
  return code === (process.platform === "darwin" ? 35 : 11);
}

/**
 * An exclusive `flock` on `path`, or null while another open description holds it. The lock
 * belongs to this descriptor alone: a second open of the same file in this process conflicts with
 * it too, and the kernel drops it when the descriptor closes or the process dies, so no lock is ever
 * stale. The file itself is never removed; unlinking a lock file lets a waiter lock an orphaned inode.
 */
export class ExclusiveFileLock {
  #fd: number | undefined;

  private constructor(fd: number) {
    this.#fd = fd;
  }

  static tryAcquire(path: string): ExclusiveFileLock | null {
    const native = flockSymbols();
    const fd = openSync(path, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
    for (;;) {
      if (native.flock(fd, LOCK_EX | LOCK_NB) === 0) return new ExclusiveFileLock(fd);
      const code = native.errno();
      if (code === EINTR) continue;
      closeSync(fd);
      if (wouldBlock(code)) return null;
      throw new Error(`Sniff could not lock ${path} (errno ${code})`);
    }
  }

  /** Releases the lock by closing its descriptor, exactly once. */
  release(): void {
    const fd = this.#fd;
    if (fd === undefined) return;
    this.#fd = undefined;
    closeSync(fd);
  }
}
