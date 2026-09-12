import { afterEach, describe, expect, test, vi } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { runSniffAnalyzer, type SniffInstallRuntime } from "../src/core/install.ts";
import { createRunManifest, type RunManifest } from "../src/core/intake.ts";
import { canonicalReportTargetIdentity, runSniffIntakeTool, type SniffIntakePublicResult, type SniffIntakeToolResult } from "../src/core/intake-use-case.ts";
import type { ReportInput } from "../src/core/report.ts";
import { runSniffReportTool } from "../src/core/report-use-case.ts";
import { authorizeAnalyzerRun, cancelRunLease, issueRunLease, releaseAllRunLeases } from "../src/core/run-registry.ts";
import { type ArgvResult, type ArgvRunner, validateResolvedTarget } from "../src/core/target.ts";
import { detectProvider, withResolvedTarget } from "../src/core/target-provider.ts";
import sniffIntakeExtension from "./sniff-intake-tool.ts";

const temporary: string[] = [];
const sha = (value: string) => value.repeat(40);

afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function repository(): { root: string; git: (...args: string[]) => string } {
  const root = mkdtempSync(join(tmpdir(), "sniff-boundary-"));
  temporary.push(root);
  const git = (...args: string[]) => {
    const result = Bun.spawnSync(["git", ...args], { cwd: root, stdout: "pipe", stderr: "pipe" });
    if (result.exitCode !== 0) throw new Error(result.stderr.toString());
    return result.stdout.toString().trim();
  };
  git("init", "-q");
  git("config", "user.email", "sniff@example.invalid");
  git("config", "user.name", "Sniff Test");
  git("config", "commit.gpgsign", "false");
  git("config", "core.hooksPath", "/dev/null");
  return { root, git };
}


function reportInput(manifest: RunManifest): ReportInput {
  const reportTarget = canonicalReportTargetIdentity(manifest.resolvedTarget, manifest.scopeMode);
  return {
    generatedAt: "2026-09-11T00:00:00Z",
    target: { ...reportTarget, languages: ["TypeScript"] },
    headline: "No retained findings.",
    findings: [],
    coverage: [],
    suppressionCount: 0,
    systemicPatterns: [],
    extensions: { "example.dev": { preserved: true }, "sniff.intake": structuredClone(manifest) },
  };
}

function localLease(options: { remote?: boolean; ttlMs?: number; now?: () => number; files?: readonly string[]; kind?: RunManifest["resolvedTarget"]["kind"]; budget?: RunManifest["budget"]; removeRootOnRelease?: boolean } = {}) {
  const root = mkdtempSync(join(tmpdir(), "sniff-lease-target-"));
  temporary.push(root);
  const files = options.files ?? ["a.ts"];
  for (const file of files) writeFileSync(join(root, file), "export const value = 1;\n");
  const target = {
    kind: options.kind ?? "files",
    label: options.kind === "repository" ? "https://example.com/acme/repo.git" : files.join(", ") || "empty",
    root,
    files,
    ...(options.remote ? { repository: "https://example.com/acme/repo.git" } : {}),
    materialization: "in-place" as const,
  };
  const manifest = createRunManifest({ target: validateResolvedTarget(target), intent: "audit", scopeMode: "full", budget: options.budget });
  let releases = 0;
  const lease = issueRunLease(manifest, {
    target: manifest.resolvedTarget,
    release: () => {
      releases += 1;
      if (options.removeRootOnRelease) rmSync(root, { recursive: true, force: true });
    },
  }, { ttlMs: options.ttlMs, now: options.now });
  return { root, manifest, lease, releases: () => releases };
}

type AnalyzerCall = { argv: string[]; cwd: string; env: Record<string, string | undefined>; timeoutMs: number };

function analyzerRuntime(calls: AnalyzerCall[], overrides: Partial<SniffInstallRuntime> = {}): SniffInstallRuntime {
  const host = mkdtempSync(join(tmpdir(), "sniff-host-bin-"));
  temporary.push(host);
  const toolkitCacheRoot = mkdtempSync(join(tmpdir(), "sniff-toolkit-cache-"));
  temporary.push(toolkitCacheRoot);
  const resolveHostCommand = (bin: string): string => {
    const path = join(host, bin);
    if (!existsSync(path)) {
      writeFileSync(path, "#!/bin/sh\nexit 0\n");
      chmodSync(path, 0o755);
    }
    return path;
  };
  return {
    toolkitCacheRoot,
    resolveCommand: resolveHostCommand,
    resolveOpenGrep: () => resolveHostCommand("opengrep"),
    provisionOpenGrep: async () => { throw new Error("unexpected OpenGrep provisioning"); },
    readLauncher: () => "",
    run: async (argv, cwd, env, timeoutMs) => {
      calls.push({ argv, cwd, env: { ...env }, timeoutMs });
      const stdout = argv[0]?.endsWith("opengrep") && !argv.includes("--version")
        ? '{"results":[]}'
        : argv[0]?.endsWith("lizard") && !argv.includes("--version")
          ? "NLOC,CCN,token,PARAM,length,location,file,function,long_name\n1,1,1,0,1,1-1,a.ts,fixture,fixture\n"
          : argv[0]?.endsWith("gitleaks") && !argv.includes("--version") ? "[]" : "";
      return { argv, exitCode: 0, stdout, stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs };
    },
    freshEnvironment: async (_cwd, env) => ({ env, source: "process" }),
    ...overrides,
  };
}

function remoteRunner(repositoryUrl: string, providerKind: "git" | "github" | "gitlab" = "git") {
  const head = sha("a");
  const base = sha("b");
  const release = sha("c");
  const calls: Array<{ argv: readonly string[]; cwd?: string }> = [];
  let checkout = "";
  const runner: ArgvRunner = (argv, options): ArgvResult => {
    calls.push({ argv: [...argv], cwd: options?.cwd });
    const command = argv.join(" ");
    if (command === "git --version") return { code: 0, stdout: "git version 2", stderr: "" };
    if (command === "gh --version") return { code: 0, stdout: "gh version 2", stderr: "" };
    if (command === "glab --version") return { code: 0, stdout: "glab version 2", stderr: "" };
    if (providerKind === "github" && command.includes("gh release view")) return { code: 0, stdout: JSON.stringify({ tagName: "v2" }), stderr: "" };
    if (providerKind === "github" && command.includes("gh api repos/acme/repo/git/ref/tags/v2")) return { code: 0, stdout: JSON.stringify({ object: { sha: head, type: "commit" } }), stderr: "" };
    if (providerKind === "gitlab" && command.includes("glab mr view")) {
      return { code: 0, stdout: JSON.stringify({ diff_refs: { head_sha: head, base_sha: base }, changes: [{ old_path: "a.ts", new_path: "a.ts" }] }), stderr: "" };
    }
    if (command.startsWith(`git ls-remote -- ${repositoryUrl} `)) {
      const ref = argv.at(-2);
      const resolved = ref === "base" ? base : ref === "v1" ? release : head;
      return { code: 0, stdout: `${resolved}\t${ref}\n`, stderr: "" };
    }
    if (argv[1] === "clone") checkout = argv[5] ?? "";
    if (argv.includes("checkout") && checkout) writeFileSync(join(checkout, "a.ts"), "export const remote = true;\n");
    if (command.endsWith("rev-parse --verify HEAD^{commit}")) return { code: 0, stdout: `${head}\n`, stderr: "" };
    if (command.includes("rev-parse --verify")) {
      const operand = argv.at(-1) ?? "";
      if (operand.startsWith(head) || operand === "v2^{commit}") return { code: 0, stdout: `${head}\n`, stderr: "" };
      if (operand.startsWith(base) || operand === "v1^{commit}") return { code: 0, stdout: `${base}\n`, stderr: "" };
      if (operand.startsWith(release)) return { code: 0, stdout: `${release}\n`, stderr: "" };
      return { code: 2, stdout: "", stderr: "unknown symbolic ref" };
    }
    if (command.startsWith("git log --format=%H")) return { code: 0, stdout: `${head}\n${base}\n`, stderr: "" };
    if (command.includes("describe --tags --abbrev=0") && command.endsWith("^")) return { code: 0, stdout: "v1\n", stderr: "" };
    if (command.includes("describe --tags --abbrev=0")) return { code: 0, stdout: "v2\n", stderr: "" };
    if (command.startsWith("git diff --name-status")) return { code: 0, stdout: "M\0a.ts\0", stderr: "" };
    if (command.startsWith("git ls-tree")) return { code: 0, stdout: "a.ts\n", stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  return { runner, calls, checkout: () => checkout, head, base, release };
}

async function completeReport(result: SniffIntakeToolResult) {
  if (!result.manifest || !result.lease) throw new Error("Intake did not issue a leased manifest");
  return runSniffReportTool({
    capability: result.lease.capability,
    manifestId: result.lease.manifestId,
    report: reportInput(result.manifest),
  });
}

describe("adaptive runtime boundaries", () => {
  test("keeps immutable materialization alive until explicit cancellation", async () => {
    const { root, git } = repository();
    writeFileSync(join(root, "a.ts"), "export const a = 1;\n");
    git("add", "a.ts");
    git("commit", "-qm", "fixture");
    const commit = git("rev-parse", "HEAD");
    const result = await runSniffIntakeTool({ input: {
      target: { kind: "ref", root, ref: commit },
      intent: "audit",
      scopeMode: "full",
      objectives: ["correctness-and-resilience"],
      budget: { maxMinutes: 5 },
    } }, { confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test-user" }) });
    if (!result.manifest || !result.lease) throw new Error("Missing intake lease");
    const checkout = result.manifest.resolvedTarget.root;
    expect(existsSync(checkout)).toBe(true);
    cancelRunLease(result.lease.capability, result.lease.manifestId);
    expect(existsSync(checkout)).toBe(false);
    expect(() => cancelRunLease(result.lease?.capability ?? "", result.lease?.manifestId ?? "")).toThrow("already cancelled");
  }, 15_000);

  test("releases every active lease and preserves terminal replay evidence", () => {
    const first = localLease({ remote: true, removeRootOnRelease: true });
    const second = localLease({ remote: true, removeRootOnRelease: true });
    const firstHome = authorizeAnalyzerRun(first.lease.capability, first.lease.manifestId, "lizard:complexity").home;
    const secondHome = authorizeAnalyzerRun(second.lease.capability, second.lease.manifestId, "lizard:complexity").home;
    expect(existsSync(firstHome)).toBe(true);
    expect(existsSync(secondHome)).toBe(true);

    releaseAllRunLeases("SIGTERM: adapter shutdown");

    expect(existsSync(first.root)).toBe(false);
    expect(existsSync(second.root)).toBe(false);
    expect(existsSync(firstHome)).toBe(false);
    expect(existsSync(secondHome)).toBe(false);
    expect(() => cancelRunLease(first.lease.capability, first.lease.manifestId)).toThrow("already cancelled");
    expect(() => cancelRunLease(second.lease.capability, second.lease.manifestId)).toThrow("already cancelled");
    expect(() => releaseAllRunLeases("second shutdown")).not.toThrow();
  });

  test("registered headless intake applies host-authorized defaults and direct calls fail closed", async () => {
    const { root } = repository();
    type ToolOutput = { details: { ok: boolean; result?: SniffIntakePublicResult; error?: string } };
    type RegisteredTool = {
      name: string;
      execute: (id: string, params: { input: unknown }, signal: unknown, update: unknown, ctx: ExtensionContext) => Promise<ToolOutput>;
    };
    let definition: RegisteredTool | undefined;
    const schema = { describe() { return this; }, optional() { return this; } };
    const api = {
      zod: { object: () => schema, unknown: () => schema, string: () => schema },
      registerTool: (tool: RegisteredTool) => { if (tool.name === "sniff_intake") definition = tool; },
    };
    sniffIntakeExtension(api as unknown as ExtensionAPI);
    if (!definition) throw new Error("sniff_intake was not registered");
    const output = await definition.execute("id", { input: { target: { kind: "files", root, paths: [] }, intent: "audit", scopeMode: "full", interactive: false } }, undefined, undefined, {
      hasUI: false,
      mode: "rpc",
      cwd: root,
    } as unknown as ExtensionContext);
    expect(output.details.ok).toBe(true);
    expect(output.details.result).not.toHaveProperty("manifest");
    expect(output.details.result).not.toHaveProperty("files");
    expect(output.details.result?.reportTarget).toMatchObject({ kind: "files", scopeMode: "full" });
    expect(output.details.result?.reportTarget).not.toHaveProperty("baseRef");
    expect(output.details.result?.reportTarget?.filesAnalyzed).toBe(0);
    if (output.details.result?.lease) cancelRunLease(output.details.result.lease.capability, output.details.result.lease.manifestId);
    await expect(runSniffIntakeTool({ input: { target: { kind: "files", root, paths: [] }, intent: "audit", interactive: false } })).rejects.toThrow("trusted confirmation boundary");
  });

  test("distinguishes missing provider executables from launch failures", async () => {
    const denied = Object.assign(new Error("permission denied"), { code: "EACCES" });
    await expect(detectProvider("https://github.com/acme/repo", async () => { throw denied; })).rejects.toMatchObject({ code: "command-failure" });
    await expect(detectProvider("https://github.com/acme/repo", async () => ({ code: 126, stdout: "", stderr: "permission denied" }))).rejects.toMatchObject({ code: "command-failure" });
    await expect(detectProvider("https://github.com/acme/repo", async () => ({ code: 127, stdout: "", stderr: "command not found" }))).rejects.toMatchObject({ code: "missing-cli" });
  });

  test("retains deleted paths separately from analyzable head files", async () => {
    const { root, git } = repository();
    writeFileSync(join(root, "deleted.ts"), "export {};\n");
    git("add", "deleted.ts");
    git("commit", "-qm", "base");
    const base = git("rev-parse", "HEAD");
    rmSync(join(root, "deleted.ts"));
    git("add", "-u");
    git("commit", "-qm", "delete");
    const head = git("rev-parse", "HEAD");
    await withResolvedTarget({ kind: "range", root, base, head }, (target) => {
      expect(target.files).toEqual([]);
      expect(target.changes).toContainEqual({ path: "deleted.ts", status: "deleted", basePath: "deleted.ts" });
    });
  }, 15_000);

  test("captures every remote history window and fetches ancestry and tags", async () => {
    const repositoryUrl = "https://example.com/acme/repo.git";
    const windows = [
      { kind: "refs", base: "base", head: "feature" } as const,
      { kind: "since-date", date: "2026-01-01", head: "feature" } as const,
      { kind: "last-commits", count: 2, head: "feature" } as const,
      { kind: "since-release", release: "v1", head: "feature" } as const,
      { kind: "previous-release", head: "feature" } as const,
      { kind: "context-aware-default", head: "feature" } as const,
    ];
    for (const window of windows) {
      const fixture = remoteRunner(repositoryUrl);
      await withResolvedTarget({ kind: "history", rootOrRepository: repositoryUrl, window }, (target) => {
        expect(target.history?.window).toEqual(window);
        expect(target.headRef).toBe(fixture.head);
      }, fixture.runner);
      expect(fixture.calls.some(({ argv }) => argv.join(" ").includes("fetch --force --tags origin"))).toBe(true);
      expect(fixture.calls.some(({ argv }) => argv.join(" ").includes("rev-parse --verify feature"))).toBe(false);
    }
  });

  test("peels annotated tags for repository and every remote history reference", async () => {
    const repositoryUrl = "https://example.com/acme/annotated.git";
    const fixture = remoteRunner(repositoryUrl);
    const objects: Record<string, { tag: string; commit: string }> = {
      "v-head": { tag: sha("d"), commit: fixture.head },
      "v-base": { tag: sha("e"), commit: fixture.base },
      "v-release": { tag: sha("f"), commit: fixture.release },
    };
    const runner: ArgvRunner = (argv, options) => {
      if (argv[0] === "git" && argv[1] === "ls-remote") {
        const ref = argv.at(-2) ?? "";
        const object = objects[ref];
        if (object) return { code: 0, stdout: `${object.tag}\trefs/tags/${ref}\n${object.commit}\trefs/tags/${ref}^{}\n`, stderr: "" };
      }
      return fixture.runner(argv, options);
    };
    await withResolvedTarget({ kind: "repository", repository: repositoryUrl, ref: "v-head" }, (target) => {
      expect(target.immutableRef).toBe(fixture.head);
    }, runner);
    const windows = [
      { kind: "refs", base: "v-base", head: "v-head" } as const,
      { kind: "since-date", date: "2026-01-01", head: "v-head" } as const,
      { kind: "last-commits", count: 2, head: "v-head" } as const,
      { kind: "since-release", release: "v-release", head: "v-head" } as const,
      { kind: "previous-release", release: "v-release", head: "v-head" } as const,
      { kind: "context-aware-default", head: "v-head" } as const,
    ];
    for (const window of windows) {
      await withResolvedTarget({ kind: "history", rootOrRepository: repositoryUrl, window }, (target) => {
        expect(target.headRef).toBe(fixture.head);
        expect(JSON.stringify(target.history?.capturedWindow)).not.toContain("v-head");
      }, runner);
    }
  });

  test("runs every selectable disposition through fixed recipes with a scrubbed environment", async () => {
    process.env.SNIFF_TEST_SECRET = "must-not-leak";
    const miseData = mkdtempSync(join(tmpdir(), "sniff-mise-data-"));
    temporary.push(miseData);
    process.env.MISE_DATA_DIR = miseData;
    const { manifest, lease } = localLease({ remote: true });
    const calls: AnalyzerCall[] = [];
    const runtime = analyzerRuntime(calls);
    const coreToolkit = join(runtime.toolkitCacheRoot ?? "", "core");
    mkdirSync(coreToolkit, { recursive: true });
    writeFileSync(join(coreToolkit, "mise.toml"), '[tools]\n"pipx:lizard" = "latest"\n');
    const selected = manifest.analyzers.filter(({ disposition }) => disposition === "selected");
    expect(selected.map(({ name }) => name)).toEqual(["lizard:complexity", "opengrep:hardcoded-values"]);
    for (const analyzer of selected) {
      expect((await runSniffAnalyzer({ capability: lease.capability, manifestId: lease.manifestId, analyzer: analyzer.name, runtime })).ok).toBe(true);
    }
    const executions = calls.filter(({ argv }) => argv[0] !== "mise" && !argv.includes("--version"));
    expect(executions).toHaveLength(2);
    expect(executions.find(({ argv }) => argv[0]?.endsWith("opengrep"))?.argv).toContain("-f");
    expect(executions.find(({ argv }) => argv[0]?.endsWith("lizard"))?.argv.slice(1, 8)).toEqual(["--csv", "-C", "10", "-L", "50", "-a", "5"]);
    expect(executions.every(({ env }) => env.SNIFF_TEST_SECRET === undefined && env.HOME?.includes("sniff-run-home-"))).toBe(true);
    const miseWhich = calls.find(({ argv }) => argv.join(" ") === "mise which lizard");
    expect(miseWhich?.env).toMatchObject({ MISE_AUTO_INSTALL: "0", MISE_CEILING_PATHS: runtime.toolkitCacheRoot, MISE_DATA_DIR: miseData });
    expect(executions.find(({ argv }) => argv[0]?.endsWith("lizard"))?.env.MISE_DATA_DIR).toBe(miseData);
    cancelRunLease(lease.capability, lease.manifestId);

    delete process.env.SNIFF_TEST_SECRET;
    delete process.env.MISE_DATA_DIR;
  });
  test("accepts Lizard's warning exit and projects every configured threshold", async () => {
    const { lease, manifest } = localLease();
    const calls: AnalyzerCall[] = [];
    const runtime = analyzerRuntime(calls, {
      run: async (argv, cwd, env, timeoutMs) => {
        calls.push({ argv, cwd, env: { ...env }, timeoutMs });
        const scan = argv[0]?.endsWith("lizard") && !argv.includes("--version");
        return { argv, exitCode: scan ? 1 : 0, stdout: scan ? "NLOC,CCN,token,PARAM,length,location,file,function,long_name\n60,2,1,0,51,1-51,a.ts,long,long\n" : "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs };
      },
    });
    const result = await runSniffAnalyzer({ capability: lease.capability, manifestId: manifest.manifestId, analyzer: "lizard:complexity", runtime });
    expect(result).toMatchObject({
      ok: true,
      acceptedExitCodes: [0, 1],
      outcome: "completed-with-findings",
      report: expect.stringContaining("exit 1"),
      observations: [{ ruleId: "lizard:complexity", path: "a.ts", message: expect.stringContaining("51 lines") }],
    });
    expect(calls.find(({ argv }) => argv[0]?.endsWith("lizard") && !argv.includes("--version"))?.argv).toEqual(expect.arrayContaining(["-C", "10", "-L", "50", "-a", "5", "--csv"]));
    cancelRunLease(lease.capability, manifest.manifestId);
  });

  test("revalidates every canonical file immediately before analyzer execution", async () => {
    const { root, lease } = localLease({ remote: true });
    const outside = mkdtempSync(join(tmpdir(), "sniff-outside-"));
    temporary.push(outside);
    writeFileSync(join(outside, "secret.ts"), "secret\n");
    rmSync(join(root, "a.ts"));
    symlinkSync(join(outside, "secret.ts"), join(root, "a.ts"));
    const calls: AnalyzerCall[] = [];
    const result = await runSniffAnalyzer({ capability: lease.capability, manifestId: lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime(calls) });
    expect(result).toMatchObject({ ok: false, outcome: "not-run" });
    expect(calls).toEqual([]);
    cancelRunLease(lease.capability, lease.manifestId);
  });

  test("rejects a relative analyzer path that resolves to a remote lookalike", async () => {
    const { root, lease } = localLease({ remote: true });
    const lookalike = join(root, "tools", "opengrep");
    mkdirSync(join(root, "tools"));
    writeFileSync(lookalike, "#!/bin/sh\nexit 0\n", { flag: "w" });
    chmodSync(lookalike, 0o755);
    const calls: AnalyzerCall[] = [];
    const runtime = analyzerRuntime(calls, { resolveOpenGrep: () => "tools/opengrep" });
    const result = await runSniffAnalyzer({ capability: lease.capability, manifestId: lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime });
    expect(result.report).toContain("absolute host path");
    expect(calls).toHaveLength(0);
    cancelRunLease(lease.capability, lease.manifestId);
  });

  test("revalidates the target after preflight and before analyzer spawn", async () => {
    const { root, lease } = localLease({ remote: true });
    const outside = mkdtempSync(join(tmpdir(), "sniff-preflight-swap-"));
    temporary.push(outside);
    writeFileSync(join(outside, "secret.ts"), "secret\n");
    const calls: AnalyzerCall[] = [];
    const base = analyzerRuntime(calls);
    let swapped = false;
    const runtime = analyzerRuntime(calls, {
      resolveCommand: base.resolveCommand,
      run: async (argv, cwd, env, timeoutMs) => {
        calls.push({ argv, cwd, env: { ...env }, timeoutMs });
        if (!swapped) {
          swapped = true;
          rmSync(join(root, "a.ts"));
          symlinkSync(join(outside, "secret.ts"), join(root, "a.ts"));
        }
        return { argv, exitCode: 0, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs };
      },
    });
    const result = await runSniffAnalyzer({ capability: lease.capability, manifestId: lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime });
    expect(result).toMatchObject({ ok: false, outcome: "not-run" });
    expect(calls).toHaveLength(1);
    cancelRunLease(lease.capability, lease.manifestId);
  });

  test("preserves empty and narrow scopes without repository widening", async () => {
    const empty = localLease({ remote: true, files: [] });
    expect(empty.manifest.analyzers.every(({ disposition }) => disposition === "skipped")).toBe(true);
    expect((await runSniffAnalyzer({ capability: empty.lease.capability, manifestId: empty.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime([]) })).report).toContain("not selected");
    cancelRunLease(empty.lease.capability, empty.lease.manifestId);

    const narrow = localLease({ remote: true });
    const calls: AnalyzerCall[] = [];
    expect(narrow.manifest.analyzers.find(({ name }) => name === "gitleaks:tracked-history")?.disposition).toBe("skipped");
    expect((await runSniffAnalyzer({ capability: narrow.lease.capability, manifestId: narrow.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime(calls) })).ok).toBe(true);
    const execution = calls.at(-1)?.argv ?? [];
    expect(execution.at(-1)).toBe("a.ts");
    expect(execution).not.toContain(".");
    cancelRunLease(narrow.lease.capability, narrow.lease.manifestId);
  });
  test("terminates OpenGrep operands before dash-prefixed filenames", async () => {
    const scoped = localLease({ remote: true, files: ["--exclude=*.ts"] });
    const calls: AnalyzerCall[] = [];
    const result = await runSniffAnalyzer({ capability: scoped.lease.capability, manifestId: scoped.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime(calls) });
    expect(result.ok).toBe(true);
    const execution = calls.at(-1)?.argv ?? [];
    const separator = execution.indexOf("--");
    const operand = execution.indexOf("--exclude=*.ts");
    expect(separator).toBeGreaterThan(-1);
    expect(operand).toBeGreaterThan(separator);
    cancelRunLease(scoped.lease.capability, scoped.lease.manifestId);
  });
  test("authorizes gitleaks for local whole-repo targets only", async () => {
    const wholeRepo = localLease({ kind: "whole-repo" });
    expect(wholeRepo.manifest.analyzers.find(({ name }) => name === "gitleaks:tracked-history")?.disposition).toBe("selected");
    const wholeCalls: AnalyzerCall[] = [];
    const wholeResult = await runSniffAnalyzer({ capability: wholeRepo.lease.capability, manifestId: wholeRepo.lease.manifestId, analyzer: "gitleaks:tracked-history", runtime: analyzerRuntime(wholeCalls) });
    expect(wholeResult.ok).toBe(true);
    expect(wholeCalls.at(-1)?.argv).toContain(".");
    expect(wholeCalls.at(-1)?.argv).toContain("-");
    cancelRunLease(wholeRepo.lease.capability, wholeRepo.lease.manifestId);

    const remoteRepo = localLease({ remote: true, kind: "whole-repo" });
    expect(remoteRepo.manifest.analyzers.find(({ name }) => name === "gitleaks:tracked-history")?.disposition).toBe("skipped");
    cancelRunLease(remoteRepo.lease.capability, remoteRepo.lease.manifestId);

    for (const kind of ["files", "directory"] as const) {
      const scoped = localLease({ remote: true, kind });
      expect(scoped.manifest.analyzers.find(({ name }) => name === "gitleaks:tracked-history")?.disposition).toBe("skipped");
      const result = await runSniffAnalyzer({ capability: scoped.lease.capability, manifestId: scoped.lease.manifestId, analyzer: "gitleaks:tracked-history", runtime: analyzerRuntime([]) });
      expect(result.report).toContain("not selected");
      cancelRunLease(scoped.lease.capability, scoped.lease.manifestId);
    }
  });

  test("makes analyzer recipes one-shot under sequential and concurrent replay", async () => {
    const sequential = localLease({ budget: { maxAnalyzers: 2 } });
    expect((await runSniffAnalyzer({ capability: sequential.lease.capability, manifestId: sequential.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) })).ok).toBe(true);
    expect((await runSniffAnalyzer({ capability: sequential.lease.capability, manifestId: sequential.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) })).report).toContain("one-shot");
    cancelRunLease(sequential.lease.capability, sequential.lease.manifestId);

    const concurrent = localLease();
    const base = analyzerRuntime([]);
    let nestedReport = "";
    let nested = false;
    const runtime = analyzerRuntime([], {
      resolveCommand: base.resolveCommand,
      run: async (argv, _cwd, _env, timeoutMs) => {
        if (!nested) {
          nested = true;
          nestedReport = (await runSniffAnalyzer({ capability: concurrent.lease.capability, manifestId: concurrent.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: base })).report;
        }
        return { argv, exitCode: 0, stdout: '{"results":[]}', stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs };
      },
    });
    expect((await runSniffAnalyzer({ capability: concurrent.lease.capability, manifestId: concurrent.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime })).ok).toBe(true);
    expect(nestedReport).toContain("one-shot");
    cancelRunLease(concurrent.lease.capability, concurrent.lease.manifestId);
  });

  test("releases failed preflight reservations and enforces analyzer and file budgets", async () => {
    const retry = localLease();
    const unavailable = analyzerRuntime([], { resolveCommand: () => null });
    expect((await runSniffAnalyzer({ capability: retry.lease.capability, manifestId: retry.lease.manifestId, analyzer: "lizard:complexity", runtime: unavailable })).ok).toBe(false);
    expect((await runSniffAnalyzer({ capability: retry.lease.capability, manifestId: retry.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) })).ok).toBe(true);
    cancelRunLease(retry.lease.capability, retry.lease.manifestId);
    const analyzerBound = localLease({ budget: { maxAnalyzers: 1 } });

    expect((await runSniffAnalyzer({ capability: analyzerBound.lease.capability, manifestId: analyzerBound.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) })).ok).toBe(true);
    expect((await runSniffAnalyzer({ capability: analyzerBound.lease.capability, manifestId: analyzerBound.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime([]) })).report).toContain("maxAnalyzers");
    const fileBound = localLease({ files: ["a.ts", "b.ts"], budget: { maxFiles: 1 } });
    expect((await runSniffAnalyzer({ capability: fileBound.lease.capability, manifestId: fileBound.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime([]) })).report).toContain("maxFiles");
    cancelRunLease(fileBound.lease.capability, fileBound.lease.manifestId);
    expect(() => localLease({ budget: { maxAnalyzers: 0 } })).toThrow("positive finite integer");
  });
  test("enforces maxMinutes before, during, and after analyzer execution", async () => {
    const startedAt = Date.parse("2026-09-11T00:00:00Z");

    let now = startedAt;
    const expired = localLease({ budget: { maxMinutes: 1 }, now: () => now });
    now += 60_001;
    expect((await runSniffAnalyzer({ capability: expired.lease.capability, manifestId: expired.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) })).report).toContain("maxMinutes budget expired");
    cancelRunLease(expired.lease.capability, expired.lease.manifestId);

    now = startedAt;
    const clipped = localLease({ budget: { maxMinutes: 1 }, now: () => now });
    now += 59_000;
    const clippedCalls: AnalyzerCall[] = [];
    expect((await runSniffAnalyzer({ capability: clipped.lease.capability, manifestId: clipped.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime(clippedCalls) })).ok).toBe(true);
    expect(clippedCalls.at(-1)?.timeoutMs).toBe(1_000);
    cancelRunLease(clipped.lease.capability, clipped.lease.manifestId);

    now = startedAt;
    const overrun = localLease({ budget: { maxMinutes: 1 }, now: () => now });
    now += 59_000;
    const base = analyzerRuntime([]);
    const runtime = analyzerRuntime([], {
      resolveCommand: base.resolveCommand,
      run: async (argv, _cwd, _env, timeoutMs) => {
        if (argv.includes("--csv")) now = startedAt + 60_001;
        return { argv, exitCode: 0, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs };
      },
    });
    expect(await runSniffAnalyzer({ capability: overrun.lease.capability, manifestId: overrun.lease.manifestId, analyzer: "lizard:complexity", runtime })).toMatchObject({ ok: false, outcome: "not-run" });
    cancelRunLease(overrun.lease.capability, overrun.lease.manifestId);
  });

  test("passively expires an abandoned lease exactly once", () => {
    vi.useFakeTimers();
    try {
      const abandoned = localLease({ ttlMs: 20, removeRootOnRelease: true });
      vi.advanceTimersByTime(21);
      expect(abandoned.releases()).toBe(1);
      expect(existsSync(abandoned.root)).toBe(false);
      expect(() => cancelRunLease(abandoned.lease.capability, abandoned.lease.manifestId)).toThrow("already expired");
      expect(abandoned.releases()).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  test("rejects expired, forged, stale, and replayed capabilities while preserving extension namespaces", async () => {
    const expired = localLease({ ttlMs: 0 });
    expect((await runSniffAnalyzer({ capability: expired.lease.capability, manifestId: expired.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime([]) })).report).toContain("expired");

    const forged = localLease();
    const forgedInput = reportInput(forged.manifest);
    const forgedExtensions = forgedInput.extensions;
    if (!forgedExtensions) throw new Error("report fixture extensions are missing");
    forgedExtensions["sniff.intake"] = { ...structuredClone(forged.manifest), intent: "history" };
    await expect(runSniffReportTool({ capability: forged.lease.capability, manifestId: forged.lease.manifestId, report: forgedInput })).rejects.toThrow("differs");
    await expect(runSniffReportTool({ capability: forged.lease.capability, manifestId: forged.lease.manifestId, report: reportInput(forged.manifest) })).resolves.toBeDefined();
    await expect(runSniffReportTool({ capability: forged.lease.capability, manifestId: forged.lease.manifestId, report: reportInput(forged.manifest) })).rejects.toThrow("already released");

    const valid = localLease();
    const result = await runSniffReportTool({ capability: valid.lease.capability, manifestId: valid.lease.manifestId, report: reportInput(valid.manifest) });
    expect(result.artifacts.report.extensions["example.dev"]).toEqual({ preserved: true });
    await expect(runSniffReportTool({ capability: valid.lease.capability, manifestId: valid.lease.manifestId, report: reportInput(valid.manifest) })).rejects.toThrow("already released");
    expect((await runSniffAnalyzer({ capability: "unknown", manifestId: valid.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime([]) })).report).toContain("Unknown");
  });
  test("hydrates an omitted manifest extension into exact report artifacts", async () => {
    const root = mkdtempSync(join(tmpdir(), "sniff-large-report-"));
    temporary.push(root);
    writeFileSync(join(root, "seed.ts"), "export const value = 1;\n");
    const validated = validateResolvedTarget({ kind: "files", label: "seed.ts", root, files: ["seed.ts"], materialization: "in-place" });
    const manifest = createRunManifest({ target: { ...validated, label: "seed.ts, ".repeat(30_000) }, intent: "audit", scopeMode: "full" });
    const lease = issueRunLease(manifest, { target: manifest.resolvedTarget, release: () => {} });
    const input = reportInput(manifest);
    delete input.extensions?.["sniff.intake"];
    const result = await runSniffReportTool({ capability: lease.capability, manifestId: lease.manifestId, report: input });
    const canonical = JSON.parse(result.artifacts.json) as { extensions: { "sniff.intake": RunManifest } };
    expect(canonical.extensions["sniff.intake"]).toEqual(manifest);
    expect(result.artifacts.markdown).toContain(result.artifacts.report.reportId);
    expect(result.artifacts.markdown.length).toBeLessThan(200_000);
    expect(result.artifacts.markdown).not.toContain('"files"');
  });
  test("completes release, history, and MR intake-to-report lifecycles", async () => {
    const githubRepository = "https://github.com/acme/repo";
    const releaseFixture = remoteRunner(githubRepository, "github");
    const release = await runSniffIntakeTool({ input: {
      target: { kind: "release", repository: githubRepository, tag: "v2" },
      intent: "release-risk",
      scopeMode: "full",
      objectives: ["correctness-and-resilience"],
      budget: { maxMinutes: 5 },
    } }, { runner: releaseFixture.runner, confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test-user" }) });
    const releaseRoot = release.manifest?.resolvedTarget.root ?? "";
    expect((await completeReport(release)).artifacts.report.target.kind).toBe("release");
    expect(existsSync(releaseRoot)).toBe(false);

    const local = repository();
    writeFileSync(join(local.root, "a.ts"), "one\n");
    local.git("add", "a.ts");
    local.git("commit", "-qm", "one");
    writeFileSync(join(local.root, "a.ts"), "two\n");
    local.git("commit", "-qam", "two");
    const history = await runSniffIntakeTool({ input: {
      target: { kind: "history", rootOrRepository: local.root, window: { kind: "last-commits", count: 1 } },
      intent: "history",
      scopeMode: "full",
      objectives: ["correctness-and-resilience"],
      budget: { maxMinutes: 5 },
    } }, { confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test-user" }) });
    expect((await completeReport(history)).artifacts.report.target.kind).toBe("history");

    const gitlabRepository = "https://gitlab.com/acme/repo";
    const mrFixture = remoteRunner(gitlabRepository, "gitlab");
    const mr = await runSniffIntakeTool({ input: {
      target: { kind: "mr", repository: gitlabRepository, iid: 7 },
      intent: "review-change",
      scopeMode: "full",
      objectives: ["correctness-and-resilience"],
      budget: { maxMinutes: 5 },
    } }, { runner: mrFixture.runner, confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test-user" }) });
    expect((await completeReport(mr)).artifacts.report.target.kind).toBe("mr");
  }, 20_000);

  test("binds canonical reports to matching authenticated target identities", async () => {
    for (const kind of ["working-tree", "files", "directory", "module", "commit", "range", "branch", "ref", "repository", "pr", "mr", "release", "history"] as const) {
      const current = localLease({ kind, remote: kind === "repository" });
      const report = (await runSniffReportTool({ capability: current.lease.capability, manifestId: current.lease.manifestId, report: reportInput(current.manifest) })).artifacts.report;
      expect(report.target.kind).toBe(canonicalReportTargetIdentity(current.manifest.resolvedTarget, current.manifest.scopeMode).kind);
    }
    for (const field of ["kind", "label", "baseRef", "filesAnalyzed"] as const) {
      const current = localLease();
      const input = reportInput(current.manifest);
      if (field === "kind") input.target.kind = "release";
      if (field === "label") input.target.label = "forged";
      if (field === "baseRef") input.target.baseRef = sha("f");
      if (field === "filesAnalyzed") input.target.filesAnalyzed += 1;
      await expect(runSniffReportTool({ capability: current.lease.capability, manifestId: current.lease.manifestId, report: input })).rejects.toThrow("must match");
    }
  });
});
