import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import {
  buildNoninteractiveManifest,
  createRunManifest,
  decisionFrontier,
} from "./sniff-intake.ts";
import { SecurityScopeError, selectSecurityAnalyzers } from "./sniff-intake-security.ts";
import sniffIntakeExtension, { runSniffIntakeTool } from "./sniff-intake-tool.ts";
import {
  type ArgvResult,
  type ArgvRunner,
  redactTransportValues,
  resolveTarget,
  runArgv,
  TargetResolutionError,
  withResolvedTarget,
  withTemporaryCheckout,
} from "./sniff-target.ts";
import { resolveGitHubRelease, resolveGitLabRelease } from "./sniff-target-provider.ts";

const temporary: string[] = [];
const sha = (character: string) => character.repeat(40);

afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function target(root: string, remote = false) {
  return {
    kind: "files" as const,
    label: "src/a.ts",
    root,
    files: ["src/a.ts"],
    ...(remote ? { repository: "https://example.com/acme/repo.git" } : {}),
    materialization: "in-place" as const,
  };
}

function fakeRunner(responses: Record<string, ArgvResult>): ArgvRunner {
  return (argv) => responses[argv.join(" ")] ?? { code: 0, stdout: "", stderr: "" };
}

function initializeRepository(): { root: string; git: (...args: string[]) => string } {
  const root = mkdtempSync(join(tmpdir(), "sniff-repo-"));
  temporary.push(root);
  const git = (...args: string[]) => {
    const result = Bun.spawnSync(["git", ...args], { cwd: root, stdout: "pipe", stderr: "pipe" });
    if (result.exitCode !== 0) throw new Error(result.stderr.toString());
    return result.stdout.toString().trim();
  };
  git("init", "-q");
  git("config", "user.email", "sniff@example.invalid");
  git("config", "user.name", "Sniff Test");
  return { root, git };
}

function remoteCheckoutRunner(repository: string, head: string, base = sha("b")): { runner: ArgvRunner; calls: Array<{ argv: readonly string[]; cwd?: string }>; checkout: () => string } {
  const calls: Array<{ argv: readonly string[]; cwd?: string }> = [];
  let directory = "";
  const runner: ArgvRunner = (argv, options) => {
    calls.push({ argv: [...argv], cwd: options?.cwd });
    const command = argv.join(" ");
    if (command === "git --version") return { code: 0, stdout: "git version 2", stderr: "" };
    if (command === `git ls-remote -- ${repository} HEAD HEAD^{}`) return { code: 0, stdout: `${head}\tHEAD\n`, stderr: "" };
    if (argv[1] === "clone") directory = argv[5] ?? "";
    if (argv.includes("checkout") && directory) writeFileSync(join(directory, "a.ts"), "export {};\n");
    if (command.endsWith("rev-parse --verify HEAD^{commit}")) return { code: 0, stdout: `${head}\n`, stderr: "" };
    if (command === "git rev-parse --verify HEAD^{commit}") return { code: 0, stdout: `${head}\n`, stderr: "" };
    if (command.includes("rev-parse --verify") && command.includes("v1^{commit}")) return { code: 0, stdout: `${base}\n`, stderr: "" };
    if (command.includes("rev-parse --verify") && command.includes(`${head}^`)) return { code: 0, stdout: `${base}\n`, stderr: "" };
    if (command.includes("rev-parse --verify") && command.includes(`${base}^{commit}`)) return { code: 0, stdout: `${base}\n`, stderr: "" };
    if (command.startsWith("git log --format=%H")) return { code: 0, stdout: `${head}\n`, stderr: "" };
    if (command.startsWith("git diff --name-status")) return { code: 0, stdout: "M\0a.ts\0", stderr: "" };
    if (command.startsWith("git ls-tree")) return { code: 0, stdout: "a.ts\n", stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  return { runner, calls, checkout: () => directory };
}

describe("adaptive intake", () => {
  test("asks only the highest-impact unresolved question", () => {
    expect(decisionFrontier({}).questions.map(({ id }) => id)).toEqual(["target"]);
    expect(decisionFrontier({ target: { kind: "working-tree", root: "." } }).questions.map(({ id }) => id)).toEqual(["intent"]);
  });

  test("complete input is silent and produces one plan", () => {
    const interview = decisionFrontier({
      target: { kind: "working-tree", root: "." },
      intent: "audit",
      objectives: ["structure-and-maintainability"],
      budget: { maxMinutes: 5 },
    });
    expect(interview.questions).toEqual([]);
    expect(interview.plan?.objectives).toEqual(["structure-and-maintainability"]);
  });

  test("noninteractive manifests require a trusted authority boundary", async () => {
    const resolved = await buildNoninteractiveManifest(
      { target: target("/tmp"), intent: "audit" },
      { authorize: async () => ({ actor: "test-authority", reason: "fixture" }) },
    );
    expect(resolved.authorization).toMatchObject({ granted: true, actor: "test-authority" });
    expect(resolved.defaults.map(({ field }) => field).sort()).toEqual(["analyzers", "budget", "exclusions", "objectives"]);
    expect(resolved.gaps.map(({ field }) => field)).toEqual(["budget"]);
    await expect(buildNoninteractiveManifest({ target: target("/tmp"), intent: "audit", authorization: { granted: true, actor: "caller" } })).rejects.toThrow("trusted confirmation boundary");
  });

  test("remote defaults use only runnable config-free recipes", () => {
    const remote = selectSecurityAnalyzers({ deepStatic: true }, { trust: "untrusted-remote" });
    expect(remote.filter(({ disposition }) => disposition === "selected").map(({ name }) => name)).toEqual(["gitleaks:tracked-history", "lizard:complexity", "semgrep:hardcoded-values"]);
    expect(remote.every(({ name, recipe }) => name === recipe)).toBe(true);
    expect(remote.every(({ tier }) => tier === "lightweight-static")).toBe(true);
  });

  test("rejects malicious analyzer overrides and aliases", () => {
    expect(() => selectSecurityAnalyzers({ projectNative: ["DAST"] })).toThrow(SecurityScopeError);
    expect(() => selectSecurityAnalyzers({ lightweightStatic: ["dynamic-application-security-testing"] })).toThrow(SecurityScopeError);
    expect(() => selectSecurityAnalyzers({ deepStaticAnalyzers: ["unknown-analyzer"], deepStatic: true })).toThrow(SecurityScopeError);
  });

  test("canonicalizes set-like arrays and deeply freezes cloned values", () => {
    const defaults = [{ field: "z", value: { nested: true }, reason: "fixture" }];
    const left = createRunManifest({
      target: target("/tmp/a"),
      intent: "audit",
      objectives: ["correctness-and-resilience", "bounded-security-smells"],
      exclusions: ["beta", "alpha"],
      defaults,
    });
    const right = createRunManifest({
      target: target("/tmp/b"),
      intent: "audit",
      objectives: ["bounded-security-smells", "correctness-and-resilience"],
      exclusions: ["alpha", "beta"],
      defaults,
    });
    expect(left.manifestId).toBe(right.manifestId);
    expect(left.exclusions).toEqual([...left.exclusions].sort((a, b) => a.localeCompare(b)));
    expect(Object.isFrozen(left.defaults[0]?.value)).toBe(true);
    expect(Object.isFrozen(left.analyzers[0])).toBe(true);
    expect(Object.isFrozen(defaults[0]?.value)).toBe(false);
  });

});

describe("target containment and cleanup", () => {
  test("maps directories to explicit canonical file lists", async () => {
    const root = mkdtempSync(join(tmpdir(), "sniff-target-"));
    temporary.push(root);
    mkdirSync(join(root, "src"));
    writeFileSync(join(root, "src", "a.ts"), "export {};");
    writeFileSync(join(root, "src", "b.ts"), "export {};");
    await expect(resolveTarget({ kind: "directory", root, path: "src" })).resolves.toMatchObject({ files: ["src/a.ts", "src/b.ts"] });
  });

  test("rejects ancestor and final symlink escapes", async () => {
    const root = mkdtempSync(join(tmpdir(), "sniff-root-"));
    const outside = mkdtempSync(join(tmpdir(), "sniff-outside-"));
    temporary.push(root, outside);
    writeFileSync(join(outside, "secret.ts"), "secret");
    symlinkSync(outside, join(root, "ancestor"));
    symlinkSync(join(outside, "secret.ts"), join(root, "final.ts"));
    await expect(resolveTarget({ kind: "files", root, paths: ["ancestor/secret.ts"] })).rejects.toMatchObject({ code: "invalid-target" });
    await expect(resolveTarget({ kind: "files", root, paths: ["final.ts"] })).rejects.toMatchObject({ code: "invalid-target" });
  });

  test("cleans a temporary checkout after success and a thrown callback", async () => {
    const head = sha("a");
    let checkout = "";
    const runner: ArgvRunner = (argv) => {
      if (argv[1] === "clone") checkout = argv[5] ?? "";
      if (argv.includes("rev-parse")) return { code: 0, stdout: `${head}\n`, stderr: "" };
      return { code: 0, stdout: "", stderr: "" };
    };
    await withTemporaryCheckout("https://example.invalid/repo.git", head, ({ directory }) => {
      checkout = directory;
      expect(existsSync(directory)).toBe(true);
    }, runner);
    expect(existsSync(checkout)).toBe(false);
    let failedCheckout = "";
    await expect(withTemporaryCheckout("https://example.invalid/repo.git", head, ({ directory }) => {
      failedCheckout = directory;
      throw new Error("boom");
    }, runner)).rejects.toThrow("boom");
    expect(existsSync(failedCheckout)).toBe(false);
  });

  test("materializes local refs at the validated SHA", async () => {
    const { root, git } = initializeRepository();
    writeFileSync(join(root, "tracked.ts"), "committed\n");
    git("add", "tracked.ts");
    git("commit", "-qm", "fixture");
    const commit = git("rev-parse", "HEAD");
    writeFileSync(join(root, "tracked.ts"), "dirty\n");
    let checkout = "";
    await withResolvedTarget({ kind: "ref", root, ref: commit }, (resolved) => {
      checkout = resolved.root;
      expect(resolved.root).not.toBe(root);
      expect(resolved.immutableRef).toBe(commit);
      expect(readFileSync(join(resolved.root, "tracked.ts"), "utf8")).toBe("committed\n");
    });
    expect(existsSync(checkout)).toBe(false);
    expect(readFileSync(join(root, "tracked.ts"), "utf8")).toBe("dirty\n");
  }, 15_000);
});

describe("provider safety and releases", () => {
  test("rejects option-capable values, unsafe schemes, and URL credentials without disclosure", async () => {
    const runner = fakeRunner({});
    const requests = [
      { kind: "repository", repository: "--upload-pack=evil", ref: "HEAD" } as const,
      { kind: "repository", repository: "file:///tmp/repo", ref: "HEAD" } as const,
      { kind: "repository", repository: "https://example.com/repo.git", ref: "--help" } as const,
      { kind: "release", repository: "https://github.com/acme/repo", tag: "--upload-pack=evil" } as const,
      { kind: "pr", repository: "https://github.com/acme/repo", number: "--help" } as const,
    ];
    for (const request of requests) await expect(resolveTarget(request, runner)).rejects.toMatchObject({ code: "invalid-target" });
    const credentialUrl = "https://user:super-secret@example.com/repo.git";
    let caught: unknown;
    try {
      await resolveTarget({ kind: "repository", repository: credentialUrl }, runner);
    } catch (error) {
      caught = error;
    }
    expect(String(caught)).not.toContain("super-secret");
    expect(caught).toMatchObject({ code: "invalid-target" });
  });

  test("rejects query and fragment secrets before target or manifest persistence", async () => {
    const repositories = [
      "https://example.com/repo.git?token=query-super-secret",
      "https://example.com/repo.git#fragment-super-secret",
    ];
    for (const repository of repositories) {
      let resolutionError: unknown;
      try {
        await resolveTarget({ kind: "repository", repository }, fakeRunner({}));
      } catch (error) {
        resolutionError = error;
      }
      expect(resolutionError).toMatchObject({ code: "invalid-target" });
      expect(String(resolutionError)).not.toContain("super-secret");
      expect(() => createRunManifest({
        target: { ...target("/tmp", true), repository },
        intent: "audit",
      })).toThrow("must not contain query or fragment values");
    }
  });

  test("redacts transport query secrets from error messages and details", () => {
    const keys = ["token", "password", "passwd", "secret"];
    for (const key of keys) {
      const value = `${key}-super-secret`;
      const transport = `https://example.com/repo.git?${key}=${value}&ref=main`;
      const error = new TargetResolutionError("command-failure", `clone failed for ${transport}`, { details: transport });
      expect(error.message).toContain(`${key}=<redacted>`);
      expect(error.details).toContain(`${key}=<redacted>`);
      expect(error.message).not.toContain(value);
      expect(error.details).not.toContain(value);
      expect(redactTransportValues(transport)).not.toContain(value);
    }
  });

  test("maps missing generic Git and production spawn failures", async () => {
    const missing = fakeRunner({ "git --version": { code: 127, stdout: "", stderr: "git: command not found" } });
    await expect(resolveTarget({ kind: "repository", repository: "https://example.com/repo.git" }, missing)).rejects.toMatchObject({ code: "missing-cli" });
    await expect(runArgv(["sniff-definitely-missing-executable"])).resolves.toMatchObject({ code: 127 });
  });

  test("resolves typed GitHub and GitLab releases", async () => {
    const commit = sha("c");
    const github = fakeRunner({
      "gh --version": { code: 0, stdout: "gh version", stderr: "" },
      "gh release view v1 --repo acme/repo --json tagName,targetCommitish,url": { code: 0, stdout: JSON.stringify({ tagName: "v1" }), stderr: "" },
      "gh api repos/acme/repo/git/ref/tags/v1": { code: 0, stdout: JSON.stringify({ object: { sha: commit, type: "commit" } }), stderr: "" },
    });
    await expect(resolveGitHubRelease("https://github.com/acme/repo", "v1", github)).resolves.toMatchObject({ commit });
    const gitlab = fakeRunner({
      "glab --version": { code: 0, stdout: "glab version", stderr: "" },
      "glab release view v1 --repo acme/repo --output json": { code: 0, stdout: JSON.stringify({ tag_name: "v1", commit: { id: commit } }), stderr: "" },
    });
    await expect(resolveGitLabRelease("https://gitlab.com/acme/repo", "v1", gitlab)).resolves.toMatchObject({ commit });
    const absent = fakeRunner({
      "gh --version": { code: 0, stdout: "gh version", stderr: "" },
      "gh release view v1 --repo acme/repo --json tagName,targetCommitish,url": { code: 1, stdout: "", stderr: "release not found" },
    });
    await expect(resolveGitHubRelease("https://github.com/acme/repo", "v1", absent)).rejects.toMatchObject({ code: "absent-release" });
  });

  test("dereferences annotated GitHub tags", async () => {
    const tagObject = sha("d");
    const commit = sha("e");
    const runner = fakeRunner({
      "gh --version": { code: 0, stdout: "gh version", stderr: "" },
      "gh release view v2 --repo acme/repo --json tagName,targetCommitish,url": { code: 0, stdout: JSON.stringify({ tagName: "v2" }), stderr: "" },
      "gh api repos/acme/repo/git/ref/tags/v2": { code: 0, stdout: JSON.stringify({ object: { sha: tagObject, type: "tag" } }), stderr: "" },
      [`gh api repos/acme/repo/git/tags/${tagObject}`]: { code: 0, stdout: JSON.stringify({ object: { sha: commit, type: "commit" } }), stderr: "" },
    });
    await expect(resolveGitHubRelease("https://github.com/acme/repo", "v2", runner)).resolves.toMatchObject({ commit });
  });

  test("materializes repository snapshots and release deltas in the checkout", async () => {
    const repository = "https://github.com/acme/repo";
    const head = sha("f");
    const base = sha("b");
    const fixture = remoteCheckoutRunner(repository, head, base);
    const runner: ArgvRunner = (argv, options) => {
      const command = argv.join(" ");
      if (command === "gh --version") return { code: 0, stdout: "gh version", stderr: "" };
      if (command === "gh release view v2 --repo acme/repo --json tagName,targetCommitish,url") return { code: 0, stdout: JSON.stringify({ tagName: "v2" }), stderr: "" };
      if (command === "gh api repos/acme/repo/git/ref/tags/v2") return { code: 0, stdout: JSON.stringify({ object: { sha: head, type: "commit" } }), stderr: "" };
      if (command === `git ls-remote -- ${repository} v1 v1^{}`) return { code: 0, stdout: `${base}\trefs/tags/v1\n`, stderr: "" };
      return fixture.runner(argv, options);
    };
    let materializedRoot = "";
    await withResolvedTarget({ kind: "release", repository, tag: "v2", previousTag: "v1" }, (resolved) => {
      materializedRoot = resolved.root;
      expect(resolved.files).toEqual(["a.ts"]);
      expect(resolved.release).toMatchObject({ snapshotFiles: ["a.ts"], deltaFiles: ["a.ts"] });
      expect(resolved.baseRef).toBe(base);
    }, runner);
    expect(fixture.calls).toContainEqual({ argv: ["git", "ls-tree", "-r", "--name-only", head], cwd: materializedRoot });
    expect(fixture.calls).toContainEqual({ argv: ["git", "diff", "--name-status", "--find-renames", "-z", `${base}...${head}`], cwd: materializedRoot });
  });

  test("propagates release snapshot failures", async () => {
    const repository = "https://github.com/acme/repo";
    const head = sha("f");
    const fixture = remoteCheckoutRunner(repository, head);
    const runner: ArgvRunner = (argv, options) => {
      const command = argv.join(" ");
      if (command === "gh --version") return { code: 0, stdout: "gh version", stderr: "" };
      if (command === "gh release view v2 --repo acme/repo --json tagName,targetCommitish,url") return { code: 0, stdout: JSON.stringify({ tagName: "v2" }), stderr: "" };
      if (command === "gh api repos/acme/repo/git/ref/tags/v2") return { code: 0, stdout: JSON.stringify({ object: { sha: head, type: "commit" } }), stderr: "" };
      if (command.startsWith("git ls-tree")) return { code: 2, stdout: "", stderr: "archive unavailable" };
      return fixture.runner(argv, options);
    };
    await expect(withResolvedTarget({ kind: "release", repository, tag: "v2" }, () => undefined, runner)).rejects.toMatchObject({ code: "command-failure" });
  });
});

describe("history semantics", () => {
  test("uses exact refs, heads, dates, counts, releases, and context defaults in the repository cwd", async () => {
    const root = mkdtempSync(join(tmpdir(), "sniff-history-"));
    temporary.push(root);
    writeFileSync(join(root, "a.ts"), "export {};\n");
    const head = sha("a");
    const base = sha("b");
    const calls: Array<{ argv: readonly string[]; cwd?: string }> = [];
    const runner: ArgvRunner = (argv, options) => {
      calls.push({ argv: [...argv], cwd: options?.cwd });
      const command = argv.join(" ");
      if (command.includes("rev-parse") && (command.includes("base") || command.includes("v1") || command.includes(`${head}^`))) return { code: 0, stdout: `${base}\n`, stderr: "" };
      if (command.includes("rev-parse")) return { code: 0, stdout: `${head}\n`, stderr: "" };
      if (command.includes("describe") && command.includes("v2^")) return { code: 0, stdout: "v1\n", stderr: "" };
      if (command.includes("describe")) return { code: 0, stdout: "v2\n", stderr: "" };
      if (command.startsWith("git log")) return { code: 0, stdout: `${head}\n`, stderr: "" };
      if (command.startsWith("git diff")) return { code: 0, stdout: "a.ts\n", stderr: "" };
      return { code: 0, stdout: "", stderr: "" };
    };
    const windows = [
      { kind: "refs", base: "base", head: "feature" } as const,
      { kind: "since-date", date: "2026-01-02", head: "feature" } as const,
      { kind: "last-commits", count: 3, head: "feature" } as const,
      { kind: "since-release", release: "v1", head: "feature" } as const,
      { kind: "previous-release", head: "feature" } as const,
      { kind: "context-aware-default", head: "feature" } as const,
    ];
    for (const window of windows) await resolveTarget({ kind: "history", rootOrRepository: root, window }, runner);
    expect(calls).toContainEqual({ argv: ["git", "log", "--format=%H", `${base}..${head}`], cwd: root });
    expect(calls).toContainEqual({ argv: ["git", "log", "--format=%H", "--since=2026-01-02", head], cwd: root });
    expect(calls).toContainEqual({ argv: ["git", "log", "--format=%H", "-n", "3", head], cwd: root });
    expect(calls).toContainEqual({ argv: ["git", "log", "--format=%H", "-n", "1", head], cwd: root });
    expect(calls).toContainEqual({ argv: ["git", "describe", "--tags", "--abbrev=0", head], cwd: root });
    expect(calls).toContainEqual({ argv: ["git", "describe", "--tags", "--abbrev=0", "v2^"], cwd: root });
    expect(calls.filter(({ cwd }) => cwd !== root)).toEqual([]);
  });

  test("materializes remote history before computing commits and files", async () => {
    const repository = "https://example.com/acme/repo.git";
    const head = sha("a");
    const fixture = remoteCheckoutRunner(repository, head);
    let root = "";
    await withResolvedTarget({ kind: "history", rootOrRepository: repository, window: { kind: "last-commits", count: 1 } }, (resolved) => {
      root = resolved.root;
      expect(resolved.files).toEqual(["a.ts"]);
      expect(resolved.history?.commits).toEqual([head]);
    }, fixture.runner);
    expect(existsSync(root)).toBe(false);
    expect(fixture.calls.some(({ argv, cwd }) => argv.join(" ").startsWith("git log --format=%H") && cwd === root)).toBe(true);
  });
});

describe("extension reachability", () => {
  test("registers sniff_intake in the package and extension API", () => {
    const packageJson = JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8"));
    expect(packageJson.omp.extensions).toContain("./extensions/sniff-intake-tool.ts");
    let definition: { name?: string } | undefined;
    const schema = { describe() { return this; } };
    const api = {
      zod: { object: () => schema, unknown: () => schema, string: () => schema },
      registerTool: (tool: { name?: string }) => { if (tool.name === "sniff_intake") definition = tool; },
    };
    sniffIntakeExtension(api as unknown as ExtensionAPI);
    expect(definition?.name).toBe("sniff_intake");
  });

  test("drives the frontier, target resolution, and manifest creation", async () => {
    const root = mkdtempSync(join(tmpdir(), "sniff-entrypoint-"));
    temporary.push(root);
    mkdirSync(join(root, "src"));
    writeFileSync(join(root, "src", "a.ts"), "export {};\n");
    const incomplete = await runSniffIntakeTool({ input: {} });
    expect(incomplete.interview.questions.map(({ id }) => id)).toEqual(["target"]);
    const complete = await runSniffIntakeTool({
      input: {
        target: { kind: "files", root, paths: ["src/a.ts"] },
        intent: "audit",
        objectives: ["correctness-and-resilience"],
        budget: { maxMinutes: 5 },
      },
    }, { confirmInteractive: async () => true });
    expect(complete.manifest).toMatchObject({ resolvedTarget: { files: ["src/a.ts"] }, confirmation: { confirmed: true } });
  });
});

describe("complete target hardening matrix", () => {
  test("materializes commit, range, branch, ref, and local history targets", async () => {
    const root = mkdtempSync(join(tmpdir(), "sniff-local-matrix-"));
    temporary.push(root);
    writeFileSync(join(root, "a.ts"), "live\n");
    const head = sha("a");
    const base = sha("b");
    const checkouts: string[] = [];
    const runner: ArgvRunner = (argv) => {
      const command = argv.join(" ");
      if (argv[1] === "clone") checkouts.push(argv[5] ?? "");
      if (argv.includes("checkout")) writeFileSync(join(argv[2] ?? "", "a.ts"), "snapshot\n");
      if (command.includes("symbolic-ref")) return { code: 0, stdout: "main\n", stderr: "" };
      if (command.includes("rev-parse") && (command.includes("base") || command.includes("main") || command.includes(`${head}^^{commit}`))) return { code: 0, stdout: `${base}\n`, stderr: "" };
      if (command.includes("rev-parse")) return { code: 0, stdout: `${head}\n`, stderr: "" };
      if (command.startsWith("git log")) return { code: 0, stdout: `${head}\n`, stderr: "" };
      if (command.includes("diff") || command.includes("ls-tree")) return { code: 0, stdout: "a.ts\n", stderr: "" };
      return { code: 0, stdout: "", stderr: "" };
    };
    const requests = [
      { kind: "commit", root, commit: "feature" } as const,
      { kind: "range", root, base: "base", head: "feature" } as const,
      { kind: "branch", root, branch: "feature", base: "main" } as const,
      { kind: "ref", root, ref: "feature" } as const,
      { kind: "history", rootOrRepository: root, window: { kind: "last-commits", count: 1, head: "feature" } } as const,
    ];
    for (const request of requests) {
      await withResolvedTarget(request, (resolved) => {
        expect(resolved.root).not.toBe(root);
        expect(resolved.immutableRef).toBe(head);
        expect(resolved.files).toEqual(["a.ts"]);
      }, runner);
    }
    expect(checkouts).toHaveLength(requests.length);
    expect(checkouts.every((checkout) => !existsSync(checkout))).toBe(true);
  });

  test("preserves a range path that exists only at the requested head", async () => {
    const root = mkdtempSync(join(tmpdir(), "sniff-range-path-"));
    temporary.push(root);
    const head = sha("a");
    const base = sha("b");
    const runner: ArgvRunner = (argv) => {
      const command = argv.join(" ");
      if (command.includes("base^{commit}")) return { code: 0, stdout: `${base}\n`, stderr: "" };
      if (command.includes("rev-parse")) return { code: 0, stdout: `${head}\n`, stderr: "" };
      if (command.includes("diff")) return { code: 0, stdout: "added-only-at-head.ts\n", stderr: "" };
      return { code: 0, stdout: "", stderr: "" };
    };
    await expect(resolveTarget({ kind: "range", root, base: "base", head: "feature" }, runner)).resolves.toMatchObject({ files: ["added-only-at-head.ts"] });
  });

  test("revalidates canonical containment immediately before the callback", async () => {
    const repository = "https://example.com/acme/repo.git";
    const head = sha("a");
    const outside = mkdtempSync(join(tmpdir(), "sniff-precallback-outside-"));
    temporary.push(outside);
    writeFileSync(join(outside, "secret.ts"), "secret\n");
    const fixture = remoteCheckoutRunner(repository, head);
    let called = false;
    const runner: ArgvRunner = async (argv, options) => {
      const result = await fixture.runner(argv, options);
      if (argv.includes("checkout")) {
        const checkout = fixture.checkout();
        rmSync(join(checkout, "a.ts"), { force: true });
        symlinkSync(join(outside, "secret.ts"), join(checkout, "a.ts"));
      }
      return result;
    };
    await expect(withResolvedTarget({ kind: "repository", repository }, () => {
      called = true;
    }, runner)).rejects.toMatchObject({ code: "invalid-target" });
    expect(called).toBe(false);
  });

  test("rejects leading options across local refs, history fields, release tags, and request IDs", async () => {
    const root = mkdtempSync(join(tmpdir(), "sniff-options-"));
    temporary.push(root);
    const runner = fakeRunner({
      "gh --version": { code: 0, stdout: "gh", stderr: "" },
      "glab --version": { code: 0, stdout: "glab", stderr: "" },
    });
    const requests = [
      { kind: "commit", root, commit: "--help" } as const,
      { kind: "range", root, base: "--base", head: "HEAD" } as const,
      { kind: "branch", root, branch: "--branch" } as const,
      { kind: "ref", root, ref: "--ref" } as const,
      { kind: "history", rootOrRepository: root, window: { kind: "refs", base: "--base", head: "HEAD" } } as const,
      { kind: "history", rootOrRepository: root, window: { kind: "since-date", date: "--yesterday" } } as const,
      { kind: "history", rootOrRepository: root, window: { kind: "last-commits", count: 0 } } as const,
      { kind: "history", rootOrRepository: root, window: { kind: "since-release", release: "--tag" } } as const,
      { kind: "history", rootOrRepository: root, window: { kind: "previous-release", release: "--tag" } } as const,
      { kind: "release", repository: "https://github.com/acme/repo", tag: "v2", previousTag: "--tag" } as const,
      { kind: "pr", repository: "https://github.com/acme/repo", number: "--help" } as const,
      { kind: "mr", repository: "https://gitlab.com/acme/repo", iid: "--help" } as const,
    ];
    for (const request of requests) await expect(resolveTarget(request, runner)).rejects.toMatchObject({ code: "invalid-target" });
  });

  test("enumerates generic repository files after checkout", async () => {
    const repository = "https://example.com/acme/repo.git";
    const head = sha("a");
    const fixture = remoteCheckoutRunner(repository, head);
    await withResolvedTarget({ kind: "repository", repository }, (resolved) => {
      expect(resolved.files).toEqual(["a.ts"]);
      expect(resolved.immutableRef).toBe(head);
    }, fixture.runner);
  });
});
