import { describe, expect, test } from "bun:test";
import type { ArgvRunner } from "../../src/core/target.ts";
import { resolveProviderTarget } from "../../src/core/target-provider.ts";

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);
const ok = (stdout: string) => ({ code: 0, stdout, stderr: "" });

describe("GitHub PR files", () => {
  test("parse uppercase changeType and do not invent a base path for additions", async () => {
    const runner: ArgvRunner = (argv) => {
      if (argv[1] === "--version") return ok("x");
      const files = [
        { path: "add.ts", changeType: "ADDED" },
        { path: "mod.ts", changeType: "MODIFIED" },
        { path: "del.ts", changeType: "DELETED" },
        { path: "ren.ts", changeType: "RENAMED" },
        { path: "cp.ts", changeType: "COPIED" },
        { path: "chg.ts", changeType: "CHANGED" },
        { path: "legacy.ts", status: "removed" },
      ];
      return ok(JSON.stringify({ headRefOid: SHA_A, baseRefOid: SHA_B, files }));
    };
    const target = await resolveProviderTarget({ kind: "pr", repository: "https://github.com/o/r", number: 1 }, runner);
    const by = Object.fromEntries((target.changes ?? []).map((change) => [change.path, change]));
    expect(by["add.ts"]).toEqual({ path: "add.ts", status: "added", headPath: "add.ts" });
    expect(by["cp.ts"]?.status).toBe("added");
    expect(by["mod.ts"]?.status).toBe("modified");
    expect(by["chg.ts"]?.status).toBe("modified");
    expect(by["del.ts"]).toEqual({ path: "del.ts", status: "deleted", basePath: "del.ts" });
    expect(by["ren.ts"]?.status).toBe("renamed");
    expect(by["legacy.ts"]?.status).toBe("deleted");
    expect(target.files).not.toContain("del.ts");
  });
});

describe("repository ref resolution", () => {
  function lsRemoteRunner(rows: string[], calls: string[][]): ArgvRunner {
    return (argv) => {
      if (argv[1] === "--version") return ok("git");
      calls.push([...argv]);
      return ok(rows.join("\n"));
    };
  }

  test("matches only the exact branch, not a suffix match", async () => {
    const calls: string[][] = [];
    const runner = lsRemoteRunner([`${SHA_B}\trefs/heads/feature/main`, `${SHA_A}\trefs/heads/main`], calls);
    const target = await resolveProviderTarget({ kind: "repository", repository: "https://example.com/o/r", ref: "main" }, runner);
    expect(target.immutableRef).toBe(SHA_A);
    expect(calls[0]).toContain("refs/heads/main");
    expect(calls[0]).not.toContain("main");
  });

  test("peeled annotated tags resolve to the commit", async () => {
    const runner = lsRemoteRunner([`${SHA_B}\trefs/tags/v1`, `${SHA_A}\trefs/tags/v1^{}`], []);
    const target = await resolveProviderTarget({ kind: "repository", repository: "https://example.com/o/r", ref: "v1" }, runner);
    expect(target.immutableRef).toBe(SHA_A);
  });

  test("a full commit SHA is accepted without ls-remote", async () => {
    const calls: string[][] = [];
    const runner = lsRemoteRunner([], calls);
    const target = await resolveProviderTarget({ kind: "repository", repository: "https://example.com/o/r", ref: SHA_A.toUpperCase() }, runner);
    expect(target.immutableRef).toBe(SHA_A);
    expect(calls).toEqual([]);
  });
});
