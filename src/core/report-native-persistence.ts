import { dlopen, FFIType, read } from "bun:ffi";
import { randomBytes } from "node:crypto";
import { closeSync, fchmodSync, readdirSync, rmSync, statSync, writeSync } from "node:fs";
import { parse, resolve, sep } from "node:path";

export type ReportSaveEntry = readonly [relativePath: string, content: string];

export interface OpenedReportDirectory {
  readonly path: string;
  readonly missingComponents: readonly string[];
  ensureDirectory(): void;
  close(): void;
  readonly directoryFd: number;
}

type NativeSymbols = {
  open: (path: string, flags: number, mode: number) => number;
  openat: (directoryFd: number, path: string, flags: number, mode: number) => number;
  mkdirat: (directoryFd: number, path: string, mode: number) => number;
  unlinkat: (directoryFd: number, path: string, flags: number) => number;
  publishNoReplace: (fromDirectoryFd: number, from: string, toDirectoryFd: number, to: string, flags: number) => number;
  errno: () => unknown;
};

type PlatformConstants = {
  readonly directoryFlags: number;
  readonly createExclusiveFlags: number;
  readonly removeDirectoryFlag: number;
  readonly publishNoReplaceFlag: number;
  readonly mode: number;
  readonly enoent: number;
  readonly eexist: number;
  readonly eloop: number;
  readonly enotdir: number;
};

const constantsByPlatform: Record<string, PlatformConstants> = {
  darwin: {
    directoryFlags: 0x0100_0000 | 0x0010_0000 | 0x0000_0100,
    createExclusiveFlags: 0x0000_0001 | 0x0000_0200 | 0x0000_0800 | 0x0100_0000 | 0x0000_0100,
    removeDirectoryFlag: 0x0000_0080,
    publishNoReplaceFlag: 0x0000_0004,
    mode: 0o700,
    enoent: 2,
    eexist: 17,
    eloop: 62,
    enotdir: 20,
  },
  linux: {
    directoryFlags: 0x0001_0000 | 0x0008_0000 | 0x0002_0000,
    createExclusiveFlags: 0x0000_0001 | 0x0000_0040 | 0x0000_0080 | 0x0008_0000 | 0x0002_0000,
    removeDirectoryFlag: 0x0000_0200,
    publishNoReplaceFlag: 0x0000_0001,
    mode: 0o700,
    enoent: 2,
    eexist: 17,
    eloop: 40,
    enotdir: 20,
  },
};

export function platformConstants(platformName: string = process.platform): PlatformConstants {
  const constants = constantsByPlatform[platformName];
  if (!constants) throw new Error("Sniff report persistence requires Darwin or Linux");
  return constants;
}

export function reportPersistenceSupported(platformName: string = process.platform): boolean {
  return constantsByPlatform[platformName] !== undefined;
}

let nativeSymbols: NativeSymbols | undefined;

function loadNativeSymbols(): NativeSymbols {
  if (nativeSymbols) return nativeSymbols;
  const constants = platformConstants();
  const errnoName = process.platform === "darwin" ? "__error" : "__errno_location";
  const libraryNames = process.platform === "darwin"
    ? ["/usr/lib/libSystem.B.dylib"]
    : [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/lib/arm-linux-gnueabihf/libc.so.6",
        "/lib/riscv64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/aarch64-linux-gnu/libc.so.6",
        "/usr/lib/arm-linux-gnueabihf/libc.so.6",
        "/usr/lib/riscv64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/lib/libc.so.6",
        "/usr/lib/libc.so.6",
      ];
  let lastError: unknown;
  for (const library of libraryNames) {
    try {
      const loaded = dlopen(library, {
        open: { args: [FFIType.cstring, FFIType.i32, FFIType.i32], returns: FFIType.i32 },
        openat: { args: [FFIType.i32, FFIType.cstring, FFIType.i32, FFIType.i32], returns: FFIType.i32 },
        mkdirat: { args: [FFIType.i32, FFIType.cstring, FFIType.i32], returns: FFIType.i32 },
        unlinkat: { args: [FFIType.i32, FFIType.cstring, FFIType.i32], returns: FFIType.i32 },
        [process.platform === "darwin" ? "renameatx_np" : "renameat2"]: {
          args: [FFIType.i32, FFIType.cstring, FFIType.i32, FFIType.cstring, FFIType.u32],
          returns: FFIType.i32,
        },
        [errnoName]: { args: [], returns: FFIType.ptr },
      });
      const symbols = loaded.symbols as unknown as Record<string, (...args: never[]) => unknown>;
      nativeSymbols = {
        open: symbols.open as NativeSymbols["open"],
        openat: symbols.openat as NativeSymbols["openat"],
        mkdirat: symbols.mkdirat as NativeSymbols["mkdirat"],
        unlinkat: symbols.unlinkat as NativeSymbols["unlinkat"],
        publishNoReplace: symbols[process.platform === "darwin" ? "renameatx_np" : "renameat2"] as NativeSymbols["publishNoReplace"],
        errno: symbols[errnoName] as NativeSymbols["errno"],
      };
      // Touch the constants before returning so unsupported platforms fail closed even
      // if a future loader adds another library candidate.
      void constants;
      return nativeSymbols;
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(`Sniff report persistence native API is unavailable: ${String(lastError)}`);
}

function errno(symbols: NativeSymbols): number {
  return read.i32(symbols.errno() as Parameters<typeof read.i32>[0]);
}

function closeFd(fd: number): void {
  try {
    closeSync(fd);
  } catch {
    // Preserve the operation's primary error; descriptors are best-effort cleanup.
  }
}

function operationError(operation: string, name: string, code: number, constants: PlatformConstants): Error {
  if (code === constants.eloop || code === constants.enotdir) return new Error(`Sniff report output directory cannot traverse a symlink: ${name}`);
  if (code === constants.eexist) return new Error(`Sniff report artifact already exists: ${name}`);
  return new Error(`Sniff report ${operation} failed for ${name} (errno ${code})`);
}

function openDirectoryAt(parentFd: number, name: string, symbols: NativeSymbols, constants: PlatformConstants): number {
  const fd = symbols.openat(parentFd, name, constants.directoryFlags, 0);
  if (fd >= 0) return fd;
  throw operationError("open", name, errno(symbols), constants);
}

function componentsFor(directory: string): { path: string; root: string; components: string[] } {
  const path = resolve(directory);
  const root = parse(path).root;
  const components = path.slice(root.length).split(sep).filter(Boolean);
  return { path, root, components };
}

export function openReportDirectory(directory: string): OpenedReportDirectory {
  const constants = platformConstants();
  const symbols = loadNativeSymbols();
  const { path, root, components } = componentsFor(directory);
  let currentFd = symbols.open(root, constants.directoryFlags, 0);
  if (currentFd < 0) throw operationError("open", root, errno(symbols), constants);
  let index = 0;
  try {
    for (; index < components.length; index += 1) {
      const name = components[index];
      if (!name) continue;
      const nextFd = symbols.openat(currentFd, name, constants.directoryFlags, 0);
      if (nextFd >= 0) {
        closeFd(currentFd);
        currentFd = nextFd;
        continue;
      }
      const code = errno(symbols);
      if (code === constants.enoent) break;
      throw operationError("open", name, code, constants);
    }
  } catch (error) {
    closeFd(currentFd);
    throw error;
  }
  const missingComponents = components.slice(index);
  let closed = false;
  return {
    path,
    missingComponents,
    get directoryFd() {
      if (closed) throw new Error("Sniff report output directory handle is closed");
      return currentFd;
    },
    ensureDirectory(): void {
      if (closed) throw new Error("Sniff report output directory handle is closed");
      for (const name of missingComponents.splice(0)) {
        const created = symbols.mkdirat(currentFd, name, constants.mode);
        if (created < 0) {
          const code = errno(symbols);
          if (code !== constants.eexist) throw operationError("create directory", name, code, constants);
        }
        const nextFd = openDirectoryAt(currentFd, name, symbols, constants);
        closeFd(currentFd);
        currentFd = nextFd;
      }
    },
    close(): void {
      if (closed) return;
      closed = true;
      closeFd(currentFd);
    },
  };
}

function validateEntries(entries: readonly ReportSaveEntry[]): void {
  const names = new Set<string>();
  for (const [relativePath] of entries) {
    if (relativePath.startsWith("/") || relativePath.split("/").some((part) => part === "" || part === "." || part === "..")) {
      throw new Error(`Invalid Sniff report artifact path: ${relativePath}`);
    }
    if (names.has(relativePath)) throw new Error(`Duplicate Sniff report artifact path: ${relativePath}`);
    names.add(relativePath);
  }
}

function writeEntry(directoryFd: number, relativePath: string, content: string, symbols: NativeSymbols, constants: PlatformConstants): void {
  const fd = symbols.openat(directoryFd, relativePath, constants.createExclusiveFlags, 0o600);
  if (fd < 0) throw operationError("write", relativePath, errno(symbols), constants);
  try {
    fchmodSync(fd, 0o600);
    const data = Buffer.from(content, "utf8");
    let offset = 0;
    while (offset < data.byteLength) {
      const written = writeSync(fd, data, offset, data.byteLength - offset, null);
      if (written <= 0) throw new Error(`Sniff report write failed for ${relativePath}`);
      offset += written;
    }
  } catch (error) {
    try {
      removeEntry(directoryFd, relativePath, symbols, constants);
    } catch {
      // Preserve the original write failure.
    }
    throw error;
  } finally {
    closeFd(fd);
  }
}

function removeEntry(directoryFd: number, relativePath: string, symbols: NativeSymbols, constants: PlatformConstants): void {
  if (symbols.unlinkat(directoryFd, relativePath, 0) < 0) {
    const code = errno(symbols);
    if (code !== constants.enoent) throw operationError("cleanup", relativePath, code, constants);
  }
}
function removeDirectory(directoryFd: number, name: string, symbols: NativeSymbols, constants: PlatformConstants): void {
  if (symbols.unlinkat(directoryFd, name, constants.removeDirectoryFlag) < 0) {
    const code = errno(symbols);
    if (code !== constants.enoent) throw operationError("cleanup directory", name, code, constants);
  }
}


export function saveReportEntriesAt(
  directory: OpenedReportDirectory,
  reportId: string,
  entries: readonly ReportSaveEntry[],
): string[] {
  validateEntries(entries);
  const constants = platformConstants();
  const symbols = loadNativeSymbols();
  directory.ensureDirectory();
  const parentFd = directory.directoryFd;
  const stagingPrefix = `.${reportId}.staging-`;
  // A pre-suffix build stranded `.<id>.staging`; recover those alongside this build's own strays.
  const legacyStagingName = `.${reportId}.staging`;
  const staleBefore = Date.now() - 60 * 60 * 1_000;
  let stagingEntries: string[] = [];
  try {
    stagingEntries = readdirSync(directory.path);
  } catch {
    // The approved parent may have been renamed; the open directory fd remains authoritative.
  }
  for (const name of stagingEntries) {
    if (!name.startsWith(stagingPrefix) && name !== legacyStagingName) continue;
    const candidate = resolve(directory.path, name);
    try {
      const stat = statSync(candidate);
      if (stat.isDirectory() && stat.mtimeMs < staleBefore) rmSync(candidate, { recursive: true, force: true });
    } catch {
      // Stale cleanup is best effort and must not hide the save operation.
    }
  }
  const stagingName = `${stagingPrefix}${randomBytes(12).toString("hex")}`;
  if (symbols.mkdirat(parentFd, stagingName, constants.mode) < 0) {
    throw operationError("create staging directory", stagingName, errno(symbols), constants);
  }
  let stagingFd: number | undefined;
  let filesFd: number | undefined;
  const written: string[] = [];
  let published = false;
  try {
    stagingFd = openDirectoryAt(parentFd, stagingName, symbols, constants);
    if (symbols.mkdirat(stagingFd, "files", constants.mode) < 0) {
      throw operationError("create files directory", "files", errno(symbols), constants);
    }
    filesFd = openDirectoryAt(stagingFd, "files", symbols, constants);
    for (const [relativePath, content] of entries) {
      const slash = relativePath.indexOf("/");
      const entryDirectoryFd = slash < 0 ? stagingFd : filesFd;
      if (entryDirectoryFd === undefined) throw new Error("Sniff report staging directory is closed");
      const name = slash < 0 ? relativePath : relativePath.slice(slash + 1);
      writeEntry(entryDirectoryFd, name, content, symbols, constants);
      written.push(relativePath);
    }
    const publishedResult = symbols.publishNoReplace(parentFd, stagingName, parentFd, reportId, constants.publishNoReplaceFlag);
    if (publishedResult < 0) throw operationError("publish", reportId, errno(symbols), constants);
    published = true;
    closeFd(filesFd);
    filesFd = undefined;
    closeFd(stagingFd);
    stagingFd = undefined;
    return entries.map(([relativePath]) => `${directory.path}/${reportId}/${relativePath}`);
  } catch (error) {
    if (!published) {
      if (filesFd !== undefined) {
        for (const relativePath of [...written].reverse()) {
          const slash = relativePath.indexOf("/");
          if (slash >= 0) {
            try {
              removeEntry(filesFd, relativePath.slice(slash + 1), symbols, constants);
            } catch {
              // Preserve the original failure while avoiding pathname-based cleanup.
            }
          }
        }
        if (stagingFd !== undefined) {
          try {
            removeDirectory(stagingFd, "files", symbols, constants);
          } catch {
            // Preserve the original failure.
          }
        }
        closeFd(filesFd);
        filesFd = undefined;
      }
      if (stagingFd !== undefined) {
        for (const relativePath of [...written].reverse()) {
          if (!relativePath.includes("/")) {
            try {
              removeEntry(stagingFd, relativePath, symbols, constants);
            } catch {
              // Preserve the original failure.
            }
          }
        }
        closeFd(stagingFd);
        stagingFd = undefined;
      }
      try {
        removeDirectory(parentFd, stagingName, symbols, constants);
      } catch {
        // Preserve the original failure; cleanup never follows a replacement.
      }
    }
    throw error;
  } finally {
    closeFd(filesFd ?? -1);
    closeFd(stagingFd ?? -1);
  }
}
