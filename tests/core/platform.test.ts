import { describe, expect, test } from "bun:test";
import { constants as fsConstants } from "node:fs";
import { OPENGREP_ASSETS, openGrepAsset } from "../../src/core/opengrep.ts";
import { platformConstants, reportPersistenceSupported } from "../../src/core/report-native-persistence.ts";

describe("OpenGrep platform assets", () => {
  test.each([
    ["darwin", "arm64", false, "darwin-arm64"],
    ["darwin", "x64", false, "darwin-x64"],
    ["linux", "arm64", false, "linux-arm64"],
    ["linux", "x64", false, "linux-x64"],
    ["linux", "arm64", true, "linux-musl-arm64"],
    ["linux", "x64", true, "linux-musl-x64"],
  ] as const)("selects %s/%s (musl=%s)", (os, cpu, musl, key) => {
    expect(openGrepAsset(os, cpu, musl)).toBe(OPENGREP_ASSETS[key]);
  });
  test.each([
    ["win32", "x64"],
    ["freebsd", "arm64"],
    ["linux", "ppc64le"],
  ] as const)("rejects unsupported %s/%s", (os, cpu) => {
    expect(openGrepAsset(os, cpu, false)).toBeNull();
  });
});

describe("report persistence platform constants", () => {
  const DARWIN_DIRECTORY = 0x0100_0000 | 0x0010_0000 | 0x0000_0100;
  // O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW per Linux architecture (asm-generic vs. Arm).
  const LINUX_GENERIC_DIRECTORY = 0x0001_0000 | 0x0008_0000 | 0x0002_0000;
  const LINUX_ARM_DIRECTORY = 0x4000 | 0x0008_0000 | 0x8000;
  test.each([
    ["darwin", "arm64", DARWIN_DIRECTORY, 0x0000_0001 | 0x0000_0200 | 0x0000_0800 | 0x0100_0000 | 0x0000_0100, 0x0000_0004],
    ["darwin", "x64", DARWIN_DIRECTORY, 0x0000_0001 | 0x0000_0200 | 0x0000_0800 | 0x0100_0000 | 0x0000_0100, 0x0000_0004],
    ["linux", "x64", LINUX_GENERIC_DIRECTORY, 0x1 | 0x40 | 0x80 | 0x0008_0000 | 0x0002_0000, 0x0000_0001],
    ["linux", "riscv64", LINUX_GENERIC_DIRECTORY, 0x1 | 0x40 | 0x80 | 0x0008_0000 | 0x0002_0000, 0x0000_0001],
    ["linux", "arm64", LINUX_ARM_DIRECTORY, 0x1 | 0x40 | 0x80 | 0x0008_0000 | 0x8000, 0x0000_0001],
    ["linux", "arm", LINUX_ARM_DIRECTORY, 0x1 | 0x40 | 0x80 | 0x0008_0000 | 0x8000, 0x0000_0001],
  ] as const)("provides constants for %s/%s", (platform, arch, directoryFlags, createExclusiveFlags, publishNoReplaceFlag) => {
    expect(platformConstants(platform, arch, {})).toMatchObject({ directoryFlags, createExclusiveFlags, publishNoReplaceFlag, mode: 0o700, enoent: 2, eexist: 17 });
  });

  test("never sets O_DIRECT on aarch64 in place of O_DIRECTORY or O_NOFOLLOW", () => {
    const O_DIRECT_AARCH64 = 0x1_0000;
    const { directoryFlags, createExclusiveFlags } = platformConstants("linux", "arm64", {});
    expect(directoryFlags & O_DIRECT_AARCH64).toBe(0);
    expect(createExclusiveFlags & O_DIRECT_AARCH64).toBe(0);
  });

  test("prefers flags the runtime exposes over the per-arch table", () => {
    const { directoryFlags } = platformConstants("linux", "arm64", { O_DIRECTORY: 0x4000, O_NOFOLLOW: 0x8000 });
    expect(directoryFlags).toBe(LINUX_ARM_DIRECTORY);
    expect(platformConstants("linux", "x64", { O_NOFOLLOW: 0x0400_0000 }).directoryFlags).toBe(0x0001_0000 | 0x0008_0000 | 0x0400_0000);
  });

  test("matches the host runtime's own fs.constants", () => {
    const host = platformConstants();
    const directory = (fsConstants.O_DIRECTORY ?? 0) | (fsConstants.O_NOFOLLOW ?? 0);
    expect(host.directoryFlags & directory).toBe(directory);
  });

  test("rejects unsupported platforms and architectures", () => {
    expect(() => platformConstants("windows")).toThrow("Sniff report persistence requires Darwin or Linux");
    expect(() => platformConstants("linux", "ppc64", {})).toThrow("does not support the linux/ppc64 architecture");
    expect(() => platformConstants("linux", "toString", {})).toThrow("does not support");
    expect(reportPersistenceSupported("linux", "mips")).toBe(false);
    expect(reportPersistenceSupported("linux", "arm64")).toBe(true);
  });
});
