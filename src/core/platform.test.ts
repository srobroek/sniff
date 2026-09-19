import { describe, expect, test } from "bun:test";
import { OPENGREP_ASSETS, openGrepAsset } from "./opengrep.ts";
import { platformConstants } from "./report-native-persistence.ts";

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
  test.each([
    ["darwin", 0x0100_0000 | 0x0010_0000 | 0x0000_0100, 0x0000_0004],
    ["linux", 0x0001_0000 | 0x0008_0000 | 0x0002_0000, 0x0000_0001],
  ] as const)("provides constants for %s", (platform, directoryFlags, publishNoReplaceFlag) => {
    expect(platformConstants(platform)).toMatchObject({ directoryFlags, publishNoReplaceFlag, mode: 0o700, enoent: 2, eexist: 17 });
  });

  test("rejects unsupported platforms", () => {
    expect(() => platformConstants("windows")).toThrow("Sniff report persistence requires Darwin or Linux");
  });
});
