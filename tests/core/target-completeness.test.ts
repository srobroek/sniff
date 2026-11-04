import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { intakeConfirmationText } from "../../src/core/confirmation-text.ts";
import { canonicalConfirmationRequest, createRunManifest } from "../../src/core/intake.ts";
import { runSniffIntakeTool } from "../../src/core/intake-use-case.ts";
import { cancelRunLease } from "../../src/core/run-registry.ts";
import {
  type ArgvResult,
  type ArgvRunner,
  createTemporaryCheckout,
  EMPTY_TREE,
  type ResolvedTarget,
  resolveTarget,
  runArgv,
} from "../../src/core/target.ts";
import { materializeProviderTarget, resolveHistoryAtRoot, resolveProviderTarget, resolveTargetLease, withResolvedTarget } from "../../src/core/target-provider.ts";

const temporary: string[] = [];
afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function scratch(prefix: string): string {
  const path = mkdtempSync(join(tmpdir(), prefix));
  temporary.push(path);
  return path;
}

function repo(init = true) {
  const root = scratch("sniff-complete-");
  let tick = 0;
  const git = (...args: string[]) => {
    const result = Bun.spawnSync(["git", ...args], { cwd: root, stdout: "pipe", stderr: "pipe", env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" } });
    if (result.exitCode !== 0) throw new Error(`git ${args.join(" ")}: ${result.stderr.toString()}`);
    return result.stdout.toString().trim();
  };
  if (init) {
    git("init", "-q", "-b", "main");
    git("config", "commit.gpgsign", "false");
  }
  const write = (files: Record<string, string>) => {
    for (const [name, body] of Object.entries(files)) {
      mkdirSync(dirname(join(root, name)), { recursive: true });
      writeFileSync(join(root, name), body);
    }
  };
  /** Commit with strictly increasing committer dates, one day apart from 2020-01-01. */
  const commit = (files: Record<string, string>, message = "c") => {
    write(files);
    git("add", "-A");
    tick += 1;
    const date = new Date(Date.UTC(2020, 0, tick, 12)).toISOString();
    const result = Bun.spawnSync(["git", "commit", "-q", "-m", message], { cwd: root, stdout: "pipe", stderr: "pipe", env: { ...process.env, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" } });
    if (result.exitCode !== 0) throw new Error(result.stderr.toString());
    return git("rev-parse", "HEAD");
  };
  return { root, git, write, commit };
}

const ok = (stdout: string): ArgvResult => ({ code: 0, stdout, stderr: "" });
const SHA_RE = /^[0-9a-f]{40}$/;

/** Maps fake remote URLs onto local repositories, mocks gh/glab, and can simulate servers refusing SHA fetches. */
function hostRunner(options: { remotes: Record<string, string>; gh?: (argv: readonly string[]) => ArgvResult; refuseShaFetch?: boolean; fail?: (argv: readonly string[]) => ArgvResult | undefined; calls?: string[][] }): ArgvRunner {
  return (argv, runOptions) => {
    const mapped = argv.map((part) => options.remotes[part] ?? part);
    options.calls?.push([...mapped]);
    if (argv[0] === "gh" || argv[0] === "glab") return argv[1] === "--version" ? ok("v") : (options.gh?.(argv) ?? { code: 1, stdout: "", stderr: "unexpected" });
    const failure = options.fail?.(mapped);
    if (failure) return failure;
    if (options.refuseShaFetch && mapped.includes("fetch")) {
      const sha = mapped.slice(mapped.indexOf("origin") + 1).find((part) => SHA_RE.test(part));
      if (sha) return { code: 128, stdout: "", stderr: `fatal: remote error: upload-pack: not our ref ${sha}` };
    }
    return runArgv(mapped, runOptions);
  };
}

const PR_URL = "https://github.com/o/r";
const GL_URL = "https://gitlab.com/o/r";

/** A server repository whose PR head lives only on refs/pull/1/head, with the base branch moved on since. */
function pullRequestServer() {
  const server = repo();
  server.commit({ "seed.ts": "seed\n", "gone.ts": "gone\n", "old.ts": "a rather long body so rename detection is stable\n".repeat(8) }, "base");
  const fork = server.commit({ "unrelated-start.ts": "x\n" }, "fork point");
  server.git("checkout", "-q", "-b", "pr");
  const prFiles: Record<string, string> = { "seed.ts": "edited\n" };
  for (let index = 0; index < 150; index += 1) prFiles[`pr/f${String(index).padStart(3, "0")}.ts`] = `${index}\n`;
  server.write(prFiles);
  server.git("rm", "-q", "gone.ts");
  server.git("mv", "old.ts", "renamed.ts");
  const head = server.commit(prFiles, "pr work");
  server.git("update-ref", "refs/pull/1/head", head);
  server.git("update-ref", "refs/merge-requests/3/head", head);
  server.git("checkout", "-q", "main");
  server.git("branch", "-q", "-D", "pr");
  const base = server.commit({ "main-only.ts": "moved on\n" }, "base moved on");
  return { server, head, base, fork };
}

const EXPECTED_PR_FILES = ["renamed.ts", "seed.ts", ...Array.from({ length: 150 }, (_, index) => `pr/f${String(index).padStart(3, "0")}.ts`)].sort();

function githubRunner(fixture: ReturnType<typeof pullRequestServer>, extra: { changedFiles?: number; base?: string; refuseShaFetch?: boolean; calls?: string[][] } = {}) {
  return hostRunner({
    remotes: { [PR_URL]: fixture.server.root },
    refuseShaFetch: extra.refuseShaFetch,
    calls: extra.calls,
    gh: () => ok(JSON.stringify({ headRefOid: fixture.head, baseRefOid: extra.base ?? fixture.base, changedFiles: extra.changedFiles ?? EXPECTED_PR_FILES.length + 1 })),
  });
}

describe("PR change sets come from git", () => {
  test("a 150+ file PR with a moved base resolves exactly, with no gap", async () => {
    const fixture = pullRequestServer();
    await withResolvedTarget({ kind: "pr", repository: PR_URL, number: 1 }, (target) => {
      expect([...target.files].sort()).toEqual(EXPECTED_PR_FILES);
      expect(target.files).not.toContain("main-only.ts");
      expect(target.changes).toContainEqual({ path: "gone.ts", status: "deleted", basePath: "gone.ts" });
      expect(target.changes).toContainEqual({ path: "renamed.ts", status: "renamed", basePath: "old.ts", headPath: "renamed.ts" });
      expect(target.gaps).toBeUndefined();
      expect(target.immutableRef).toBe(fixture.head);
    }, githubRunner(fixture));
  }, 30_000);

  test("a server that refuses SHA fetches is served through refs/pull/<n>/head, then a full fetch, and the result stays exact", async () => {
    const fixture = pullRequestServer();
    const calls: string[][] = [];
    await withResolvedTarget({ kind: "pr", repository: PR_URL, number: 1 }, (target) => {
      expect([...target.files].sort()).toEqual(EXPECTED_PR_FILES);
      expect(target.gaps).toBeUndefined();
    }, githubRunner(fixture, { refuseShaFetch: true, calls }));
    const fetches = calls.filter((argv) => argv.includes("fetch")).map((argv) => argv.join(" "));
    expect(fetches.some((command) => command.includes("+refs/pull/1/head:refs/sniff/0"))).toBe(true);
    expect(fetches.some((command) => command.includes("+refs/heads/*:refs/remotes/origin/*"))).toBe(true);
  }, 30_000);

  test("the head fetched through the PR ref alone is recorded as a ref fetch, not a full fallback", async () => {
    const fixture = pullRequestServer();
    const runner = hostRunner({ remotes: {}, refuseShaFetch: true });
    const lease = await createTemporaryCheckout(fixture.server.root, fixture.head, runner, { refspecs: ["refs/pull/1/head"] });
    try {
      expect(lease.fetch).toBe("refs");
      expect(lease.immutableRef).toBe(fixture.head);
    } finally {
      lease.release();
    }
  });

  test("a provider count that disagrees with git is recorded as a gap and surfaced in the manifest and approval text", async () => {
    const fixture = pullRequestServer();
    await withResolvedTarget({ kind: "pr", repository: PR_URL, number: 1 }, (target) => {
      expect([...target.files].sort()).toEqual(EXPECTED_PR_FILES);
      expect(target.gaps).toHaveLength(1);
      expect(target.gaps?.[0]).toMatchObject({ field: "target", impact: "high" });
      expect(target.gaps?.[0]?.reason).toContain("provider reports 100");
      const manifest = createRunManifest({ target, intent: "audit", scopeMode: "full", objectives: ["correctness-and-resilience"], budget: { maxMinutes: 5 } });
      expect(manifest.gaps).toContainEqual(target.gaps?.[0] ?? { field: "missing", reason: "", impact: "low" });
      const text = intakeConfirmationText(canonicalConfirmationRequest(manifest));
      expect(text).toContain("Target gaps (1):");
      expect(text).toContain("provider reports 100");
    }, githubRunner(fixture, { changedFiles: 100 }));
  }, 30_000);

  test("an unfetchable base records a gap instead of silently dropping files", async () => {
    const fixture = pullRequestServer();
    await withResolvedTarget({ kind: "pr", repository: PR_URL, number: 1 }, (target) => {
      expect(target.files).toEqual([]);
      expect(target.changes).toEqual([]);
      expect(target.gaps).toHaveLength(1);
      expect(target.gaps?.[0]?.reason).toContain(`Base commit ${"c".repeat(40)} could not be fetched`);
      expect(target.immutableRef).toBe(fixture.head);
    }, githubRunner(fixture, { base: "c".repeat(40) }));
  }, 30_000);

  test("GitLab MRs without a changes list resolve through refs/merge-requests/<iid>/head", async () => {
    const fixture = pullRequestServer();
    const calls: string[][] = [];
    const runner = hostRunner({
      remotes: { [GL_URL]: fixture.server.root },
      refuseShaFetch: true,
      calls,
      gh: () => ok(JSON.stringify({ diff_refs: { head_sha: fixture.head, base_sha: fixture.base }, changes_count: "1000+" })),
    });
    await withResolvedTarget({ kind: "mr", repository: GL_URL, iid: 3 }, (target) => {
      expect([...target.files].sort()).toEqual(EXPECTED_PR_FILES);
      expect(target.gaps).toBeUndefined();
    }, runner);
    expect(calls.some((argv) => argv.join(" ").includes("+refs/merge-requests/3/head:refs/sniff/0"))).toBe(true);
  }, 30_000);
});

describe("remote snapshots fetch only what they need", () => {
  test("a snapshot is a depth-1 fetch of the SHA into an empty repository, never a clone", async () => {
    const source = repo();
    for (let index = 0; index < 5; index += 1) source.commit({ [`f${index}.ts`]: `${index}\n` });
    const head = source.git("rev-parse", "HEAD");
    const seen: string[][] = [];
    const runner: ArgvRunner = (argv, options) => {
      seen.push([...argv]);
      return runArgv(argv, options);
    };
    const lease = await createTemporaryCheckout(source.root, head, runner);
    try {
      expect(seen.some((argv) => argv.includes("clone"))).toBe(false);
      const fetch = seen.find((argv) => argv.includes("fetch"));
      expect(fetch).toEqual(expect.arrayContaining(["--depth=1", "origin", head, "core.hooksPath=/dev/null"]));
      expect(lease.fetch).toBe("sha");
      const count = Bun.spawnSync(["git", "-C", lease.directory, "rev-list", "--count", "HEAD"]).stdout.toString().trim();
      expect(count).toBe("1");
    } finally {
      lease.release();
    }
  });

  test("a refused unadvertised SHA falls back to a full fetch and says so", async () => {
    const source = repo();
    for (let index = 0; index < 3; index += 1) source.commit({ [`f${index}.ts`]: `${index}\n` });
    const head = source.git("rev-parse", "HEAD");
    const lease = await createTemporaryCheckout(source.root, head, hostRunner({ remotes: {}, refuseShaFetch: true }));
    try {
      expect(lease.fetch).toBe("full-fallback");
      expect(lease.immutableRef).toBe(head);
    } finally {
      lease.release();
    }
  });

  test("other fetch failures are not mistaken for a refused SHA", async () => {
    const source = repo();
    source.commit({ "a.ts": "a\n" });
    const head = source.git("rev-parse", "HEAD");
    const calls: string[][] = [];
    const runner = hostRunner({ remotes: {}, calls, fail: (argv) => (argv.includes("fetch") ? { code: 128, stdout: "", stderr: "fatal: unable to access: Could not resolve host" } : undefined) });
    await expect(createTemporaryCheckout(source.root, head, runner)).rejects.toMatchObject({ code: "command-failure" });
    expect(calls.filter((argv) => argv.includes("fetch"))).toHaveLength(1);
  });

  test("remote last-commits and since-date windows fetch bounded history and compute exact files", async () => {
    const source = repo();
    for (let index = 1; index <= 8; index += 1) source.commit({ [`f${index}.ts`]: `${index}\n` });
    const remotes = { "https://example.com/o/r.git": source.root };
    const runner = hostRunner({ remotes });
    const requestFor = (window: { kind: "last-commits"; count: number } | { kind: "since-date"; date: string }) => ({ kind: "history", rootOrRepository: "https://example.com/o/r.git", window }) as const;
    await withResolvedTarget(requestFor({ kind: "last-commits", count: 2 }), (target) => {
      expect(target.history?.commits).toHaveLength(2);
      expect([...target.files].sort()).toEqual(["f7.ts", "f8.ts"]);
      const count = Bun.spawnSync(["git", "-C", target.root, "rev-list", "--count", "--all"]).stdout.toString().trim();
      expect(Number(count)).toBeLessThanOrEqual(3);
    }, runner);
    // Commits 6, 7 and 8 are dated on or after 2020-01-06.
    await withResolvedTarget(requestFor({ kind: "since-date", date: "2020-01-06" }), (target) => {
      expect(target.history?.commits).toHaveLength(3);
      expect([...target.files].sort()).toEqual(["f6.ts", "f7.ts", "f8.ts"]);
      const count = Bun.spawnSync(["git", "-C", target.root, "rev-list", "--count", "--all"]).stdout.toString().trim();
      expect(Number(count)).toBeLessThanOrEqual(5);
    }, runner);
    await withResolvedTarget(requestFor({ kind: "since-date", date: "2099-01-01" }), (target) => {
      expect(target.history?.commits).toEqual([]);
      expect(target.files).toEqual([]);
    }, runner);
  }, 30_000);
});

describe("history windows keep their confirmed selection through materialization", () => {
  function mergeRepo() {
    const r = repo();
    r.commit({ "base.ts": "base\n" }, "base");
    r.git("tag", "v1");
    r.git("checkout", "-q", "-b", "feature");
    r.commit({ "feature-a.ts": "a\n" }, "feature a");
    r.commit({ "feature-b.ts": "b\n" }, "feature b");
    r.git("checkout", "-q", "main");
    r.commit({ "main.ts": "m\n" }, "main work");
    const result = Bun.spawnSync(["git", "merge", "--no-ff", "-q", "-m", "merge", "feature"], { cwd: r.root, stdout: "pipe", stderr: "pipe", env: { ...process.env, GIT_COMMITTER_DATE: "2020-01-20T12:00:00Z", GIT_AUTHOR_DATE: "2020-01-20T12:00:00Z", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@e.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@e.invalid" } });
    if (result.exitCode !== 0) throw new Error(result.stderr.toString());
    return r;
  }

  const windows = [
    { kind: "last-commits", count: 1 },
    { kind: "since-date", date: "2020-01-15" },
    { kind: "context-aware-default" },
    { kind: "since-release", release: "v1" },
    { kind: "previous-release", release: "main" },
    { kind: "refs", base: "v1", head: "main" },
  ] as const;

  for (const window of windows) {
    test(`${window.kind}: commits and files after materialization match what was resolved`, async () => {
      const r = mergeRepo();
      if (window.kind === "previous-release") r.git("tag", "v2");
      const effective = window.kind === "previous-release" ? ({ kind: "previous-release", release: "v2" } as const) : window;
      const resolved = await resolveHistoryAtRoot(r.root, effective, runArgv);
      await withResolvedTarget({ kind: "history", rootOrRepository: r.root, window: effective }, (target) => {
        expect(target.history?.commits).toEqual(resolved.history?.commits ?? []);
        expect(target.files).toEqual(resolved.files);
        expect(target.changes).toEqual(resolved.changes);
        expect(target.history?.window).toEqual(effective);
      });
      if (window.kind === "last-commits" || window.kind === "context-aware-default" || window.kind === "since-date") {
        expect(resolved.history?.commits).toHaveLength(1);
        // The merge's first-parent diff: what the feature branch brought in.
        expect([...resolved.files].sort()).toEqual(["feature-a.ts", "feature-b.ts"]);
      }
    }, 30_000);
  }
});

describe("parentless targets", () => {
  test("a root commit target uses the empty tree as its base", async () => {
    const r = repo();
    const root = r.commit({ "a.ts": "a\n", "b.ts": "b\n" }, "root");
    const target = await resolveTarget({ kind: "commit", root: r.root, commit: root });
    expect(target.baseRef).toBe(EMPTY_TREE);
    expect(target.changes?.map((change) => [change.path, change.status])).toEqual([["a.ts", "added"], ["b.ts", "added"]]);
    expect([...target.files].sort()).toEqual(["a.ts", "b.ts"]);
  });

  test("history covering the initial commit includes the files the root commit added", async () => {
    const r = repo();
    r.commit({ "first.ts": "1\n" }, "root");
    r.commit({ "second.ts": "2\n" }, "second");
    const target = await resolveHistoryAtRoot(r.root, { kind: "last-commits", count: 10 }, runArgv);
    expect(target.baseRef).toBe(EMPTY_TREE);
    expect([...target.files].sort()).toEqual(["first.ts", "second.ts"]);
    await withResolvedTarget({ kind: "history", rootOrRepository: r.root, window: { kind: "last-commits", count: 10 } }, (materialized) => {
      expect([...materialized.files].sort()).toEqual(["first.ts", "second.ts"]);
      expect(materialized.history?.commits).toHaveLength(2);
    });
  });

  test("a repository with no commits resolves a working-tree scope over its untracked code", async () => {
    const r = repo();
    r.write({ "src/a.ts": "a\n", "b.ts": "b\n" });
    const target = await resolveTarget({ kind: "working-tree", root: r.root });
    expect([...target.files].sort()).toEqual(["b.ts", "src/a.ts"]);
    expect(target.unborn).toBe(true);
    expect(target.baseRef).toBe(EMPTY_TREE);
    expect(target.immutableRef).toBeUndefined();
  });

  test("a directory that is not a repository still fails instead of reading as unborn", async () => {
    const plain = scratch("sniff-plain-");
    writeFileSync(join(plain, "a.ts"), "a\n");
    await expect(resolveTarget({ kind: "working-tree", root: plain })).rejects.toMatchObject({ code: "command-failure" });
  });

  test("a shallow boundary commit is not mistaken for a root commit", async () => {
    const source = repo();
    source.commit({ "a.ts": "1\n" });
    source.commit({ "b.ts": "2\n" });
    const shallow = scratch("sniff-shallow-");
    const cloned = Bun.spawnSync(["git", "clone", "-q", "--depth=1", `file://${source.root}`, join(shallow, "c")]);
    expect(cloned.exitCode).toBe(0);
    await expect(resolveTarget({ kind: "commit", root: join(shallow, "c"), commit: "HEAD" })).rejects.toMatchObject({ code: "command-failure", details: expect.any(String) });
  });
});

const count = (dir: string, ...rest: string[]) => Number(Bun.spawnSync(["git", "-C", dir, "rev-list", "--count", ...rest]).stdout.toString().trim());

describe("history-walking analyzers see the ancestry they need", () => {
  function secretRepo() {
    const r = repo();
    r.commit({ "app.ts": "v1\n" }, "init");
    r.commit({ "app.ts": "v1\n", "secret.env": "TOKEN=sk_live_REMOVED_SECRET\n" }, "oops");
    r.git("rm", "-q", "secret.env");
    r.commit({ "app.ts": "v2\n" }, "remove the secret");
    return r;
  }
  const intake = (root: string, scopeMode: "full" | "quick") => runSniffIntakeTool({ input: { target: { kind: "whole-repo", root }, intent: "audit", scopeMode, objectives: ["correctness-and-resilience"], budget: { maxMinutes: 5 } } }, { confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test" }) });

  test("whole-repo with gitleaks selected keeps a secret removed before HEAD visible in the checkout", async () => {
    const r = secretRepo();
    const result = await intake(r.root, "full");
    try {
      expect(result.manifest?.analyzers.some((analyzer) => analyzer.name === "gitleaks:tracked-history" && analyzer.disposition === "selected")).toBe(true);
      const checkout = result.manifest?.resolvedTarget.root ?? "";
      expect(Bun.spawnSync(["git", "-C", checkout, "log", "--all", "--format=%H", "-S", "sk_live_REMOVED_SECRET"]).stdout.toString().trim()).not.toBe("");
      expect(count(checkout, "HEAD")).toBe(3);
    } finally {
      if (result.lease) cancelRunLease(result.lease.capability, result.lease.manifestId);
    }
  }, 30_000);

  test("without a history-walking recipe selected the checkout stays shallow", async () => {
    const r = secretRepo();
    const result = await intake(r.root, "quick");
    try {
      expect(result.manifest?.analyzers.some((analyzer) => analyzer.name === "gitleaks:tracked-history" && analyzer.disposition === "selected")).toBe(false);
      expect(count(result.manifest?.resolvedTarget.root ?? "", "HEAD")).toBe(1);
    } finally {
      if (result.lease) cancelRunLease(result.lease.capability, result.lease.manifestId);
    }
  }, 30_000);

  test("a confirmed local history window keeps every commit and its parents when history is walked", async () => {
    const r = secretRepo();
    const request = { kind: "history", rootOrRepository: r.root, window: { kind: "last-commits", count: 1 } } as const;
    const walked = await resolveTargetLease(request, runArgv, { walksHistory: true });
    const plain = await resolveTargetLease(request, runArgv);
    try {
      expect(count(walked.target.root, "HEAD")).toBe(3);
      expect(count(plain.target.root, "HEAD")).toBe(1);
      expect(walked.target.history?.commits).toEqual(plain.target.history?.commits ?? []);
    } finally {
      walked.release();
      plain.release();
    }
  }, 30_000);
});

describe("merge base proof in shallow history", () => {
  /** HEAD merges a short branch from old ancestor A, while its path to the newer common ancestor B is long. */
  function deepTopology() {
    const r = repo();
    const a = r.commit({ "a.ts": "a\n" }, "A");
    r.commit({ "m1.ts": "base work\n" }, "m1");
    const b = r.commit({ "b.ts": "b\n" }, "B");
    const base = r.commit({ "m2.ts": "more base work\n" }, "m2");
    r.git("checkout", "-q", "-b", "side", a);
    r.commit({ "p.ts": "p\n" }, "P");
    r.git("checkout", "-q", "-b", "pr", b);
    for (let index = 0; index < 60; index += 1) r.commit({ [`chain/c${index}.ts`]: `${index}\n` }, `c${index}`);
    const merge = Bun.spawnSync(["git", "merge", "--no-ff", "-q", "-m", "merge side", "side"], { cwd: r.root, stdout: "pipe", stderr: "pipe", env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@e.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@e.invalid" } });
    if (merge.exitCode !== 0) throw new Error(merge.stderr.toString());
    const head = r.git("rev-parse", "HEAD");
    r.git("update-ref", "refs/pull/1/head", head);
    r.git("checkout", "-q", "main");
    r.git("branch", "-q", "-D", "pr");
    return { server: r, head, base, b };
  }

  test("a merge base found in shallow history is not accepted until it is proven", async () => {
    const fixture = deepTopology();
    const runner = hostRunner({ remotes: { [PR_URL]: fixture.server.root }, gh: () => ok(JSON.stringify({ headRefOid: fixture.head, baseRefOid: fixture.base })) });
    await withResolvedTarget({ kind: "pr", repository: PR_URL, number: 1 }, (target) => {
      expect(target.gaps).toBeUndefined();
      // Relative to B the PR adds the chain and the side commit; m1/m2/b are base-side changes and must not appear.
      expect(target.files).toContain("p.ts");
      expect(target.files).toContain("chain/c0.ts");
      for (const unrelated of ["m1.ts", "m2.ts", "b.ts"]) expect(target.files).not.toContain(unrelated);
      expect(target.files).toHaveLength(61);
    }, runner);
  }, 60_000);

  test("history that stays shallow at the server is a gap, not a guessed diff", async () => {
    const fixture = deepTopology();
    const shallow = scratch("sniff-shallow-server-");
    const cloned = Bun.spawnSync(["git", "clone", "-q", "--depth=20", "--no-single-branch", `file://${fixture.server.root}`, join(shallow, "s")]);
    expect(cloned.exitCode).toBe(0);
    Bun.spawnSync(["git", "-C", join(shallow, "s"), "fetch", "-q", "--depth=20", "origin", "refs/pull/1/head:refs/pull/1/head"]);
    const runner = hostRunner({ remotes: { [PR_URL]: join(shallow, "s") }, gh: () => ok(JSON.stringify({ headRefOid: fixture.head, baseRefOid: fixture.base })) });
    await withResolvedTarget({ kind: "pr", repository: PR_URL, number: 1 }, (target) => {
      expect(target.files).toEqual([]);
      expect(target.gaps?.[0]).toMatchObject({ field: "target", impact: "high" });
      expect(target.gaps?.[0]?.reason).toContain("merge base");
    }, runner);
  }, 60_000);

  test("identical base and head is a connected, empty change set without a gap", async () => {
    const fixture = pullRequestServer();
    const runner = hostRunner({ remotes: { [GL_URL]: fixture.server.root }, gh: () => ok(JSON.stringify({ diff_refs: { head_sha: fixture.head, base_sha: fixture.head }, changes_count: "0" })) });
    await withResolvedTarget({ kind: "mr", repository: GL_URL, iid: 3 }, (target) => {
      expect(target.files).toEqual([]);
      expect(target.changes).toEqual([]);
      expect(target.gaps).toBeUndefined();
    }, runner);
  }, 30_000);
});

describe("captured selections are host-owned", () => {
  test("a request window carrying commits or diffBase is rejected, locally and for remotes", async () => {
    const r = repo();
    r.commit({ "a.ts": "a\n" });
    const head = r.commit({ "b.ts": "b\n" });
    const forged = { kind: "refs", base: "HEAD~1", head: "HEAD", commits: ["f".repeat(40)], diffBase: head } as never;
    const runner = hostRunner({ remotes: { "https://example.com/o/r.git": r.root } });
    await expect(resolveProviderTarget({ kind: "history", rootOrRepository: r.root, window: forged }, runner)).rejects.toMatchObject({ code: "invalid-target" });
    await expect(resolveProviderTarget({ kind: "history", rootOrRepository: "https://example.com/o/r.git", window: forged }, runner)).rejects.toMatchObject({ code: "invalid-target" });
    await expect(resolveHistoryAtRoot(r.root, forged, runner)).rejects.toMatchObject({ code: "invalid-target" });
    await expect(runSniffIntakeTool({ input: { target: { kind: "history", rootOrRepository: r.root, window: forged }, intent: "audit", scopeMode: "full", objectives: ["correctness-and-resilience"], budget: { maxMinutes: 5 } } }, { confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test" }) })).rejects.toMatchObject({ code: "invalid-target" });
  }, 30_000);

  test("a captured selection is validated against the repository at materialization", async () => {
    const r = repo();
    r.commit({ "a.ts": "a\n" });
    const head = r.commit({ "b.ts": "b\n" });
    const base = r.git("rev-parse", "HEAD~1");
    const resolved = await resolveHistoryAtRoot(r.root, { kind: "last-commits", count: 1 }, runArgv);
    const captured = resolved.history?.capturedWindow;
    if (!captured || !("diffBase" in captured)) throw new Error("expected a captured selection");
    const withCaptured = (window: unknown): ResolvedTarget => ({ ...resolved, history: { window: { kind: "last-commits", count: 1 }, capturedWindow: window as never, commits: [head] } });
    const keep = await materializeProviderTarget(withCaptured(captured), runArgv);
    expect(keep.files).toEqual(["b.ts"]);
    // Nonexistent commit as diff base, a selection that does not start at its head, and a repeated commit.
    await expect(materializeProviderTarget(withCaptured({ ...captured, diffBase: "e".repeat(40) }), runArgv)).rejects.toThrow();
    await expect(materializeProviderTarget(withCaptured({ ...captured, commits: [base] }), runArgv)).rejects.toMatchObject({ code: "invalid-target" });
    await expect(materializeProviderTarget(withCaptured({ ...captured, commits: [head, head] }), runArgv)).rejects.toMatchObject({ code: "invalid-target" });
  }, 30_000);
});
