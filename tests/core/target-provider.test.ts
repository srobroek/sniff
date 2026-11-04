import { describe, expect, test } from "bun:test";
import type { ArgvRunner } from "../../src/core/target.ts";
import { resolveProviderTarget } from "../../src/core/target-provider.ts";

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);
const ok = (stdout: string) => ({ code: 0, stdout, stderr: "" });

describe("PR and MR resolution", () => {
  test("GitHub PR keeps only immutable endpoints and metadata; it never trusts the capped file list", async () => {
    const calls: string[][] = [];
    const runner: ArgvRunner = (argv) => {
      calls.push([...argv]);
      if (argv[1] === "--version") return ok("x");
      return ok(JSON.stringify({ headRefOid: SHA_A, baseRefOid: SHA_B, changedFiles: 250, files: [{ path: "capped.ts", changeType: "ADDED" }] }));
    };
    const target = await resolveProviderTarget({ kind: "pr", repository: "https://github.com/o/r", number: 7 }, runner);
    expect(target).toMatchObject({ kind: "pr", headRef: SHA_A, baseRef: SHA_B, immutableRef: SHA_A, providerRefs: ["refs/pull/7/head"], providerChangedFiles: 250, files: [] });
    expect(target.changes).toBeUndefined();
    const view = calls.find((argv) => argv[0] === "gh" && argv[1] === "pr");
    expect(view?.[view.indexOf("--json") + 1]).not.toContain("files");
    expect(view?.[view.indexOf("--json") + 1]).toContain("changedFiles");
  });

  test("GitLab MR records its merge-request ref and a numeric change count only", async () => {
    const runner: ArgvRunner = (argv) => {
      if (argv[1] === "--version") return ok("x");
      return ok(JSON.stringify({ diff_refs: { head_sha: SHA_A, base_sha: SHA_B }, changes_count: "12" }));
    };
    const target = await resolveProviderTarget({ kind: "mr", repository: "https://gitlab.com/o/r", iid: 3 }, runner);
    expect(target).toMatchObject({ kind: "mr", providerRefs: ["refs/merge-requests/3/head"], providerChangedFiles: 12, files: [] });
    const overflow: ArgvRunner = (argv) => argv[1] === "--version" ? ok("x") : ok(JSON.stringify({ diff_refs: { head_sha: SHA_A, base_sha: SHA_B }, changes_count: "1000+" }));
    expect((await resolveProviderTarget({ kind: "mr", repository: "https://gitlab.com/o/r", iid: 3 }, overflow)).providerChangedFiles).toBeUndefined();
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
