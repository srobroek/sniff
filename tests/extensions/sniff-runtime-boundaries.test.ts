import { afterEach, beforeEach, describe, expect, test, vi } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import sniffIntakeExtension from "../../extensions/sniff-intake-tool.ts";
import { ANALYZER_TIMEOUT_MS, runSniffAnalyzer, runSniffInstall, type SniffInstallRuntime, withToolkitLock } from "../../src/core/install.ts";
import { createRunManifest, type RunManifest } from "../../src/core/intake.ts";
import { canonicalReportTargetIdentity, runSniffIntakeTool, type SniffIntakePublicResult, type SniffIntakeToolResult } from "../../src/core/intake-use-case.ts";
import type { ReportInput } from "../../src/core/report.ts";
import { runSniffReportTool } from "../../src/core/report-use-case.ts";
import { createSniffRunOwner, type SniffRunOwner } from "../../src/core/run-owner.ts";
import { authorizeAnalyzerRun, cancelRunLease, completeAnalyzerReservation, issueRunLease, prepareAnalyzerSpawn, readRunManifest, registerActiveProcess, releaseAllRunLeases, validateReportCoverage } from "../../src/core/run-registry.ts";
import { type ArgvResult, type ArgvRunner, validateResolvedTarget } from "../../src/core/target.ts";
import { detectProvider, withResolvedTarget } from "../../src/core/target-provider.ts";
import { unattendedIntakeAllowed } from "../../src/core/unattended.ts";

const temporary: string[] = [];
const sha = (value: string) => value.repeat(40);

// Every run a test starts belongs to that test's own owner, disposed after it, so no lease outlives
// its test and no test shares the process owner's lease cap. Only the shutdown tests use the
// process owner on purpose, and releaseAllRunLeases cleans up after them.
let runOwner: SniffRunOwner;
beforeEach(() => {
  runOwner = createSniffRunOwner({ label: "runtime-boundaries test" });
});

afterEach(async () => {
  await runOwner.dispose();
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

function localLease(options: { processOwner?: boolean; remote?: boolean; ttlMs?: number; now?: () => number; files?: readonly string[]; kind?: RunManifest["resolvedTarget"]["kind"]; history?: RunManifest["resolvedTarget"]["history"]; budget?: RunManifest["budget"]; removeRootOnRelease?: boolean; onRelease?: () => void } = {}) {
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
    ...(options.history ? { history: options.history } : {}),
    materialization: "in-place" as const,
  };
  const manifest = createRunManifest({ target: validateResolvedTarget(target), intent: "audit", scopeMode: "full", budget: options.budget });
  let releases = 0;
  const lease = issueRunLease(manifest, {
    target: manifest.resolvedTarget,
    release: () => {
      releases += 1;
      options.onRelease?.();
      if (options.removeRootOnRelease) rmSync(root, { recursive: true, force: true });
    },
  }, { ttlMs: options.ttlMs, now: options.now, owner: options.processOwner ? undefined : runOwner });
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
    run: async (argv, cwd, env, timeoutMs, _signal, _outputLimitBytes, onSpawn) => {
      onSpawn?.({ pid: 12345, exited: Promise.resolve(0) });
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
      const name = argv[4] ?? "";
      const ref = name.replace(/^refs\/(?:heads|tags)\//, "");
      const resolved = ref === "base" ? base : ref === "v1" ? release : head;
      return { code: 0, stdout: `${resolved}\t${name}\n`, stderr: "" };
    }
    if (argv.includes("init")) checkout = argv.at(-1) ?? "";
    if (argv.includes("checkout") && checkout) writeFileSync(join(checkout, "a.ts"), "export const remote = true;\n");
    if (command.startsWith("git rev-list --parents")) return { code: 0, stdout: `${argv.at(-1)} ${base}\n`, stderr: "" };
    if (command.startsWith("git merge-base")) return { code: 0, stdout: `${base}\n`, stderr: "" };
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
    if (command.startsWith("git ls-tree")) return { code: 0, stdout: "a.ts\0", stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  return { runner, calls, checkout: () => checkout, head, base, release };
}

async function completeReport(result: SniffIntakeToolResult) {
  if (!result.manifest || !result.lease) throw new Error("Intake did not issue a leased manifest");
  return runSniffReportTool({
    owner: runOwner,
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
    } }, { owner: runOwner, confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test-user" }) });
    if (!result.manifest || !result.lease) throw new Error("Missing intake lease");
    const checkout = result.manifest.resolvedTarget.root;
    expect(existsSync(checkout)).toBe(true);
    cancelRunLease(result.lease.capability, result.lease.manifestId, runOwner);
    expect(existsSync(checkout)).toBe(false);
    expect(() => cancelRunLease(result.lease?.capability ?? "", result.lease?.manifestId ?? "", runOwner)).toThrow("already cancelled");
  }, 15_000);

  test("releases every active lease and preserves terminal replay evidence", () => {
    const first = localLease({ processOwner: true, remote: true, removeRootOnRelease: true });
    const second = localLease({ processOwner: true, remote: true, removeRootOnRelease: true });
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

  test("releases the materialized target whenever lease issuance fails", () => {
    const root = mkdtempSync(join(tmpdir(), "sniff-issue-failure-"));
    temporary.push(root);
    writeFileSync(join(root, "a.ts"), "export {};\n");
    const manifest = createRunManifest({ target: validateResolvedTarget({ kind: "files", label: "a.ts", root, files: ["a.ts"], materialization: "in-place" }), intent: "audit", scopeMode: "full" });
    let releases = 0;
    const release = () => {
      releases += 1;
    };
    expect(() => issueRunLease(manifest, { target: { ...manifest.resolvedTarget, root: join(root, "missing") }, release }, { owner: runOwner })).toThrow();
    expect(releases).toBe(1);
    const previous = process.env.TMPDIR;
    process.env.TMPDIR = join(root, "no-such-tmpdir");
    try {
      expect(() => issueRunLease(manifest, { target: manifest.resolvedTarget, release }, { owner: runOwner })).toThrow();
    } finally {
      if (previous === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = previous;
    }
    expect(releases).toBe(2);
  });

  test("shutdown waits for every lease even when another lease's release fails", async () => {
    const failing = localLease({ processOwner: true, onRelease: () => { throw new Error("release exploded"); } });
    const busy = localLease({ processOwner: true });
    const exit = Promise.withResolvers<number>();
    const kill = vi.spyOn(process, "kill").mockImplementation((() => true) as typeof process.kill);
    try {
      registerActiveProcess(busy.lease.capability, busy.lease.manifestId, { pid: 98_765, exited: exit.promise });
      let settled = false;
      const shutdown = releaseAllRunLeases("SIGTERM: adapter shutdown").finally(() => {
        settled = true;
      });
      await Bun.sleep(20);
      expect(failing.releases()).toBe(1);
      expect(settled).toBe(false);
      expect(busy.releases()).toBe(0);
      exit.resolve(0);
      await expect(shutdown).resolves.toBeUndefined();
      expect(busy.releases()).toBe(1);
    } finally {
      kill.mockRestore();
      exit.resolve(0);
    }
  });

  type IntakeToolOutput = { details: { ok: boolean; result?: SniffIntakePublicResult; error?: string } };
  type IntakeTool = { name: string; execute: (id: string, params: { input: unknown }, signal: unknown, update: unknown, ctx: ExtensionContext) => Promise<IntakeToolOutput> };

  function registeredIntake(): IntakeTool {
    let definition: IntakeTool | undefined;
    const schema = { describe() { return this; }, optional() { return this; } };
    const api = {
      zod: { object: () => schema, unknown: () => schema, string: () => schema },
      registerTool: (tool: IntakeTool) => { if (tool.name === "sniff_intake") definition = tool; },
    };
    sniffIntakeExtension(api as unknown as ExtensionAPI, runOwner);
    if (!definition) throw new Error("sniff_intake was not registered");
    return definition;
  }

  async function withUnattendedEnv<T>(value: string | undefined, run: () => Promise<T>): Promise<T> {
    const previous = process.env.SNIFF_UNATTENDED_INTAKE;
    if (value === undefined) delete process.env.SNIFF_UNATTENDED_INTAKE;
    else process.env.SNIFF_UNATTENDED_INTAKE = value;
    try {
      return await run();
    } finally {
      if (previous === undefined) delete process.env.SNIFF_UNATTENDED_INTAKE;
      else process.env.SNIFF_UNATTENDED_INTAKE = previous;
    }
  }

  test("unattendedIntakeAllowed accepts only 1, true and yes", () => {
    for (const value of ["1", "true", "TRUE", "yes", " Yes "]) expect(unattendedIntakeAllowed({ SNIFF_UNATTENDED_INTAKE: value })).toBe(true);
    for (const value of [undefined, "", "0", "false", "no", "on", "2"]) expect(unattendedIntakeAllowed({ SNIFF_UNATTENDED_INTAKE: value })).toBe(false);
    expect(unattendedIntakeAllowed({})).toBe(false);
  });

  test("OMP headless intake with the operator opt-in records the opt-in as the host actor's reason", async () => {
    const { root } = repository();
    const definition = registeredIntake();
    const output = await withUnattendedEnv("1", () => definition.execute("id", { input: { target: { kind: "files", root, paths: [] }, intent: "audit", scopeMode: "full", interactive: false } }, undefined, undefined, {
      hasUI: false,
      mode: "rpc",
      cwd: root,
    } as unknown as ExtensionContext));
    expect(output.details.ok).toBe(true);
    expect(output.details.result).not.toHaveProperty("manifest");
    expect(output.details.result).not.toHaveProperty("files");
    expect(output.details.result?.reportTarget).toMatchObject({ kind: "files", scopeMode: "full" });
    expect(output.details.result?.reportTarget).not.toHaveProperty("baseRef");
    expect(output.details.result?.reportTarget?.filesAnalyzed).toBe(0);
    const lease = output.details.result?.lease;
    if (!lease) throw new Error("expected a lease");
    const manifest = readRunManifest(lease.capability, lease.manifestId, runOwner);
    expect(manifest.authorization.actor).toBe("extension-host");
    expect(manifest.authorization.reason).toContain("SNIFF_UNATTENDED_INTAKE");
    await cancelRunLease(lease.capability, lease.manifestId, runOwner);
    await expect(runSniffIntakeTool({ input: { target: { kind: "files", root, paths: [] }, intent: "audit", interactive: false } }, { owner: runOwner })).rejects.toThrow("trusted confirmation boundary");
  });

  test("OMP headless intake refuses by default and tool arguments cannot opt in", async () => {
    const { root } = repository();
    const definition = registeredIntake();
    const headless = { hasUI: false, mode: "rpc", cwd: root } as unknown as ExtensionContext;
    for (const extra of [{}, { unattended: true }, { env: { SNIFF_UNATTENDED_INTAKE: "1" } }, { SNIFF_UNATTENDED_INTAKE: "1" }]) {
      for (const env of [undefined, "0", "nope"]) {
        const output = await withUnattendedEnv(env, () => definition.execute("id", { input: { target: { kind: "files", root, paths: [] }, intent: "audit", scopeMode: "full", interactive: false, ...extra } }, undefined, undefined, headless));
        expect(output.details.ok).toBe(false);
        expect(output.details.result).toBeUndefined();
        expect(output.details.error).toContain("SNIFF_UNATTENDED_INTAKE=1");
      }
    }
  });

  test("OMP noninteractive intake with a UI asks ui.confirm and honours a refusal, regardless of the opt-in", async () => {
    const { root } = repository();
    const definition = registeredIntake();
    for (const env of [undefined, "1"]) {
      for (const approve of [true, false]) {
        const prompts: string[] = [];
        const ctx = { hasUI: true, mode: "tui", cwd: root, ui: { confirm: async (title: string) => { prompts.push(title); return approve; } } } as unknown as ExtensionContext;
        const output = await withUnattendedEnv(env, () => definition.execute("id", { input: { target: { kind: "files", root, paths: [] }, intent: "audit", scopeMode: "full", interactive: false } }, undefined, undefined, ctx));
        expect(prompts).toHaveLength(1);
        expect(output.details.ok).toBe(approve);
        if (approve) {
          const lease = output.details.result?.lease;
          if (!lease) throw new Error("expected a lease");
          expect(readRunManifest(lease.capability, lease.manifestId, runOwner).authorization.actor).toBe("interactive-user");
          await cancelRunLease(lease.capability, lease.manifestId, runOwner);
        } else expect(output.details.result).toBeUndefined();
      }
    }
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
      const fetches = fixture.calls.map(({ argv }) => argv.join(" ")).filter((command) => command.includes(" fetch "));
      // Only the previous-release window needs tags (git describe); no window clones the full history.
      expect(fetches.some((command) => command.includes("--tags"))).toBe(window.kind === "previous-release");
      expect(fetches.length).toBeGreaterThan(0);
      expect(fixture.calls.some(({ argv }) => argv.includes("clone"))).toBe(false);
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
        const ref = (argv[4] ?? "").replace(/^refs\/(?:heads|tags)\//, "");
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
    process.env.RUSTUP_HOME = "/host/rustup";
    process.env.RUSTUP_TOOLCHAIN = "host-toolchain";
    process.env.CARGO_HOME = "/host/cargo";
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
      expect((await runSniffAnalyzer({ owner: runOwner, capability: lease.capability, manifestId: lease.manifestId, analyzer: analyzer.name, runtime })).ok).toBe(true);
    }
    const executions = calls.filter(({ argv }) => argv[0] !== "mise" && !argv.includes("--version"));
    expect(executions).toHaveLength(2);
    expect(executions.find(({ argv }) => argv[0]?.endsWith("opengrep"))?.argv).toContain("-f");
    expect(executions.find(({ argv }) => argv[0]?.endsWith("lizard"))?.argv.slice(1, 8)).toEqual(["--csv", "-C", "10", "-L", "50", "-a", "5"]);
    expect(executions.every(({ env }) => env.SNIFF_TEST_SECRET === undefined && env.HOME?.includes("sniff-run-home-"))).toBe(true);
    const miseWhich = calls.find(({ argv }) => argv.join(" ") === "mise which lizard");
    expect(miseWhich?.env).toMatchObject({ CARGO_HOME: join(coreToolkit, ".cargo"), MISE_AUTO_INSTALL: "0", MISE_CEILING_PATHS: runtime.toolkitCacheRoot, MISE_DATA_DIR: miseData, RUSTUP_HOME: join(coreToolkit, ".rustup"), RUSTUP_TOOLCHAIN: "" });
    expect(executions.find(({ argv }) => argv[0]?.endsWith("lizard"))?.env).toMatchObject({ CARGO_HOME: join(coreToolkit, ".cargo"), MISE_DATA_DIR: miseData, RUSTUP_HOME: join(coreToolkit, ".rustup"), RUSTUP_TOOLCHAIN: "" });
    cancelRunLease(lease.capability, lease.manifestId, runOwner);

    delete process.env.SNIFF_TEST_SECRET;
    delete process.env.MISE_DATA_DIR;
    delete process.env.RUSTUP_HOME;
    delete process.env.RUSTUP_TOOLCHAIN;
    delete process.env.CARGO_HOME;
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
    const result = await runSniffAnalyzer({ owner: runOwner, capability: lease.capability, manifestId: manifest.manifestId, analyzer: "lizard:complexity", runtime });
    expect(result).toMatchObject({
      ok: true,
      acceptedExitCodes: [0, 1],
      outcome: "completed-with-findings",
      report: expect.stringContaining("exit 1"),
      observations: [{ ruleId: "lizard:complexity", path: "a.ts", message: expect.stringContaining("51 lines") }],
    });
    expect(calls.find(({ argv }) => argv[0]?.endsWith("lizard") && !argv.includes("--version"))?.argv).toEqual(expect.arrayContaining(["-C", "10", "-L", "50", "-a", "5", "--csv"]));
    cancelRunLease(lease.capability, manifest.manifestId, runOwner);
  });

  test("revalidates every canonical file immediately before analyzer execution", async () => {
    const { root, lease } = localLease({ remote: true });
    const outside = mkdtempSync(join(tmpdir(), "sniff-outside-"));
    temporary.push(outside);
    writeFileSync(join(outside, "secret.ts"), "secret\n");
    rmSync(join(root, "a.ts"));
    symlinkSync(join(outside, "secret.ts"), join(root, "a.ts"));
    const calls: AnalyzerCall[] = [];
    const result = await runSniffAnalyzer({ owner: runOwner, capability: lease.capability, manifestId: lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime(calls) });
    expect(result).toMatchObject({ ok: false, outcome: "not-run" });
    expect(calls).toEqual([]);
    cancelRunLease(lease.capability, lease.manifestId, runOwner);
  });

  test("rejects a relative analyzer path that resolves to a remote lookalike", async () => {
    const { root, lease } = localLease({ remote: true });
    const lookalike = join(root, "tools", "opengrep");
    mkdirSync(join(root, "tools"));
    writeFileSync(lookalike, "#!/bin/sh\nexit 0\n", { flag: "w" });
    chmodSync(lookalike, 0o755);
    const calls: AnalyzerCall[] = [];
    const runtime = analyzerRuntime(calls, { resolveOpenGrep: () => "tools/opengrep" });
    const result = await runSniffAnalyzer({ owner: runOwner, capability: lease.capability, manifestId: lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime });
    expect(result.report).toContain("absolute host path");
    expect(calls).toHaveLength(0);
    cancelRunLease(lease.capability, lease.manifestId, runOwner);
  });

	test("validates an analyzer symlink without changing its invocation path", async () => {
		const { lease } = localLease();
		const host = mkdtempSync(join(tmpdir(), "sniff-analyzer-proxy-"));
		temporary.push(host);
		const executable = join(host, "real-analyzer");
		writeFileSync(executable, "#!/bin/sh\nexit 0\n");
		chmodSync(executable, 0o755);
		const proxy = join(host, "lizard");
		symlinkSync(executable, proxy);
		const calls: AnalyzerCall[] = [];
		const runtime = analyzerRuntime(calls, { resolveCommand: (bin) => bin === "lizard" ? proxy : join(host, bin) });
		const result = await runSniffAnalyzer({ owner: runOwner, capability: lease.capability, manifestId: lease.manifestId, analyzer: "lizard:complexity", runtime });
		expect(result.ok).toBe(true);
		expect(calls.every(({ argv }) => argv[0] === proxy)).toBe(true);
		cancelRunLease(lease.capability, lease.manifestId, runOwner);
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
    const result = await runSniffAnalyzer({ owner: runOwner, capability: lease.capability, manifestId: lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime });
    expect(result).toMatchObject({ ok: false, outcome: "not-run" });
    expect(calls).toHaveLength(1);
    cancelRunLease(lease.capability, lease.manifestId, runOwner);
  });

  test("preserves empty and narrow scopes without repository widening", async () => {
    const empty = localLease({ remote: true, files: [] });
    expect(empty.manifest.analyzers.every(({ disposition }) => disposition === "skipped")).toBe(true);
    expect((await runSniffAnalyzer({ owner: runOwner, capability: empty.lease.capability, manifestId: empty.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime([]) })).report).toContain("not selected");
    cancelRunLease(empty.lease.capability, empty.lease.manifestId, runOwner);

    const narrow = localLease({ remote: true });
    const calls: AnalyzerCall[] = [];
    expect(narrow.manifest.analyzers.find(({ name }) => name === "gitleaks:tracked-history")?.disposition).toBe("skipped");
    expect((await runSniffAnalyzer({ owner: runOwner, capability: narrow.lease.capability, manifestId: narrow.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime(calls) })).ok).toBe(true);
    const execution = calls.at(-1)?.argv ?? [];
    expect(execution.at(-1)).toBe("a.ts");
    expect(execution).not.toContain(".");
    cancelRunLease(narrow.lease.capability, narrow.lease.manifestId, runOwner);
  });
  test("terminates OpenGrep operands before dash-prefixed filenames", async () => {
    const scoped = localLease({ remote: true, files: ["--exclude=*.ts"] });
    const calls: AnalyzerCall[] = [];
    const result = await runSniffAnalyzer({ owner: runOwner, capability: scoped.lease.capability, manifestId: scoped.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime(calls) });
    expect(result.ok).toBe(true);
    const execution = calls.at(-1)?.argv ?? [];
    const separator = execution.indexOf("--");
    const operand = execution.indexOf("--exclude=*.ts");
    expect(separator).toBeGreaterThan(-1);
    expect(operand).toBeGreaterThan(separator);
    cancelRunLease(scoped.lease.capability, scoped.lease.manifestId, runOwner);
  });
  test("keeps the operand separator in every shard of a sharded scoped-files run", async () => {
    const sharded = localLease({ files: ["-a.py", "b.py"], budget: { maxFiles: 1 } });
    const calls: AnalyzerCall[] = [];
    const result = await runSniffAnalyzer({ owner: runOwner, capability: sharded.lease.capability, manifestId: sharded.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime(calls) });
    expect(result.outcome).not.toBe("not-run");
    const shards = calls.filter((call) => call.argv.includes("--csv"));
    expect(shards.map((call) => call.argv.slice(-2))).toEqual([["--", "-a.py"], ["--", "b.py"]]);
    await cancelRunLease(sharded.lease.capability, sharded.lease.manifestId, runOwner);
  });
  test("authorizes gitleaks for local whole-repo targets only", async () => {
    const wholeRepo = localLease({ kind: "whole-repo" });
    expect(wholeRepo.manifest.analyzers.find(({ name }) => name === "gitleaks:tracked-history")?.disposition).toBe("selected");
    const wholeCalls: AnalyzerCall[] = [];
    const wholeResult = await runSniffAnalyzer({ owner: runOwner, capability: wholeRepo.lease.capability, manifestId: wholeRepo.lease.manifestId, analyzer: "gitleaks:tracked-history", runtime: analyzerRuntime(wholeCalls) });
    expect(wholeResult.ok).toBe(true);
    expect(wholeCalls.at(-1)?.argv).toContain(".");
    expect(wholeCalls.at(-1)?.argv).toContain("-");
    cancelRunLease(wholeRepo.lease.capability, wholeRepo.lease.manifestId, runOwner);

    const remoteRepo = localLease({ remote: true, kind: "whole-repo" });
    expect(remoteRepo.manifest.analyzers.find(({ name }) => name === "gitleaks:tracked-history")?.disposition).toBe("skipped");
    cancelRunLease(remoteRepo.lease.capability, remoteRepo.lease.manifestId, runOwner);

    for (const kind of ["files", "directory"] as const) {
      const scoped = localLease({ remote: true, kind });
      expect(scoped.manifest.analyzers.find(({ name }) => name === "gitleaks:tracked-history")?.disposition).toBe("skipped");
      const result = await runSniffAnalyzer({ owner: runOwner, capability: scoped.lease.capability, manifestId: scoped.lease.manifestId, analyzer: "gitleaks:tracked-history", runtime: analyzerRuntime([]) });
      expect(result.report).toContain("not selected");
      cancelRunLease(scoped.lease.capability, scoped.lease.manifestId, runOwner);
    }
  });

  test("makes analyzer recipes one-shot under sequential and concurrent replay", async () => {
    const sequential = localLease({ budget: { maxAnalyzers: 2 } });
    expect((await runSniffAnalyzer({ owner: runOwner, capability: sequential.lease.capability, manifestId: sequential.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) })).ok).toBe(true);
    expect((await runSniffAnalyzer({ owner: runOwner, capability: sequential.lease.capability, manifestId: sequential.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) })).report).toContain("one-shot");
    cancelRunLease(sequential.lease.capability, sequential.lease.manifestId, runOwner);

    const concurrent = localLease();
    const base = analyzerRuntime([]);
    let nestedReport = "";
    let nested = false;
    const runtime = analyzerRuntime([], {
      resolveCommand: base.resolveCommand,
      run: async (argv, _cwd, _env, timeoutMs) => {
        if (!nested) {
          nested = true;
          nestedReport = (await runSniffAnalyzer({ owner: runOwner, capability: concurrent.lease.capability, manifestId: concurrent.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: base })).report;
        }
        return { argv, exitCode: 0, stdout: '{"results":[]}', stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs };
      },
    });
    expect((await runSniffAnalyzer({ owner: runOwner, capability: concurrent.lease.capability, manifestId: concurrent.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime })).ok).toBe(true);
    expect(nestedReport).toContain("one-shot");
    cancelRunLease(concurrent.lease.capability, concurrent.lease.manifestId, runOwner);
  });

  test("releases failed preflight reservations and enforces analyzer and file budgets", async () => {
    const retry = localLease();
    const unavailable = analyzerRuntime([], { resolveCommand: () => null });
    expect((await runSniffAnalyzer({ owner: runOwner, capability: retry.lease.capability, manifestId: retry.lease.manifestId, analyzer: "lizard:complexity", runtime: unavailable })).ok).toBe(false);
    expect((await runSniffAnalyzer({ owner: runOwner, capability: retry.lease.capability, manifestId: retry.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) })).ok).toBe(true);
    cancelRunLease(retry.lease.capability, retry.lease.manifestId, runOwner);
    const analyzerBound = localLease({ budget: { maxAnalyzers: 1 } });

    expect((await runSniffAnalyzer({ owner: runOwner, capability: analyzerBound.lease.capability, manifestId: analyzerBound.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) })).ok).toBe(true);
    expect((await runSniffAnalyzer({ owner: runOwner, capability: analyzerBound.lease.capability, manifestId: analyzerBound.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime([]) })).report).toContain("maxAnalyzers");
    const fileBound = localLease({ files: ["a.ts", "b.ts"], budget: { maxFiles: 1 } });
    const shardedCalls: AnalyzerCall[] = [];
    const sharded = await runSniffAnalyzer({ owner: runOwner, capability: fileBound.lease.capability, manifestId: fileBound.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime(shardedCalls) });
    expect(sharded.outcome).toBe("completed");
    expect(shardedCalls.filter((call) => call.argv.includes("scan"))).toHaveLength(2);
    cancelRunLease(fileBound.lease.capability, fileBound.lease.manifestId, runOwner);
    expect(() => localLease({ budget: { maxAnalyzers: 0 } })).toThrow("positive finite integer");
  });
  test("enforces maxMinutes before, during, and after analyzer execution", async () => {
    const startedAt = Date.parse("2026-09-11T00:00:00Z");

    let now = startedAt;
    const expired = localLease({ budget: { maxMinutes: 1 }, now: () => now });
    now += 60_001;
    expect((await runSniffAnalyzer({ owner: runOwner, capability: expired.lease.capability, manifestId: expired.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) })).report).toContain("maxMinutes budget expired");
    cancelRunLease(expired.lease.capability, expired.lease.manifestId, runOwner);

    now = startedAt;
    const clipped = localLease({ budget: { maxMinutes: 1 }, now: () => now });
    now += 59_000;
    const clippedCalls: AnalyzerCall[] = [];
    expect((await runSniffAnalyzer({ owner: runOwner, capability: clipped.lease.capability, manifestId: clipped.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime(clippedCalls) })).ok).toBe(true);
    expect(clippedCalls.at(-1)?.timeoutMs).toBe(1_000);
    cancelRunLease(clipped.lease.capability, clipped.lease.manifestId, runOwner);

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
    expect(await runSniffAnalyzer({ owner: runOwner, capability: overrun.lease.capability, manifestId: overrun.lease.manifestId, analyzer: "lizard:complexity", runtime })).toMatchObject({ ok: false, outcome: "not-run" });
    cancelRunLease(overrun.lease.capability, overrun.lease.manifestId, runOwner);
  });
  test("waits for a terminated analyzer to exit before releasing its target and home", async () => {
    const order: string[] = [];
    const leaseFixture = localLease({ remote: true, removeRootOnRelease: true, onRelease: () => {
      order.push("releaseTarget");
      expect(existsSync(leaseFixture.root)).toBe(true);
    } });
    const calls: AnalyzerCall[] = [];
    const exit = Promise.withResolvers<number>();
    const spawned = Promise.withResolvers<void>();
    const base = analyzerRuntime(calls);
    const runtime = analyzerRuntime(calls, {
      resolveCommand: base.resolveCommand,
      run: async (argv, _cwd, _env, timeoutMs, _signal, outputLimitBytes, onSpawn) => {
        if (argv.includes("--csv")) {
          onSpawn?.({ pid: 54321, exited: exit.promise, kill: () => order.push("kill") });
          spawned.resolve();
          await exit.promise;
        }
        return { argv, exitCode: 0, stdout: "NLOC,CCN,token,PARAM,length,location,file,function,long_name\n", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: outputLimitBytes ?? 1_048_576, timedOut: false, timeoutMs };
      },
    });
    // The fake child has no owned process group, so it is ended only through its own handle.
    const kill = vi.spyOn(process, "kill").mockImplementation(((pid: number, _signal?: NodeJS.Signals | number) => {
      if (pid === -54321 || pid === 54321) order.push("unowned-pid-signal");
      return true;
    }) as typeof process.kill);
    try {
      const resultPromise = runSniffAnalyzer({ owner: runOwner, capability: leaseFixture.lease.capability, manifestId: leaseFixture.lease.manifestId, analyzer: "lizard:complexity", runtime });
      await spawned.promise;
      const released = cancelRunLease(leaseFixture.lease.capability, leaseFixture.lease.manifestId, runOwner);
      expect(order).toEqual(["kill"]);
      expect(existsSync(leaseFixture.root)).toBe(true);
      order.push("exit");
      exit.resolve(0);
      await released;
      expect(order).toEqual(["kill", "exit", "releaseTarget"]);
      expect(existsSync(leaseFixture.root)).toBe(false);
      await resultPromise;
    } finally {
      kill.mockRestore();
      exit.resolve(0);
    }
  });

  test("terminates a child whose lease expired between the spawn and its registration before releasing", async () => {
    const startedAt = Date.parse("2026-09-11T00:00:00Z");
    let now = startedAt;
    const order: string[] = [];
    const released = Promise.withResolvers<void>();
    const leaseFixture = localLease({ ttlMs: 50, now: () => now, removeRootOnRelease: true, onRelease: () => {
      order.push("releaseTarget");
      released.resolve();
    } });
    const calls: AnalyzerCall[] = [];
    const exit = Promise.withResolvers<number>();
    const base = analyzerRuntime(calls);
    const runtime = analyzerRuntime(calls, {
      resolveCommand: base.resolveCommand,
      run: async (argv, _cwd, _env, timeoutMs, _signal, outputLimitBytes, onSpawn) => {
        if (argv.includes("--csv")) {
          now = startedAt + 51;
          onSpawn?.({ pid: 4242, exited: exit.promise, kill: () => {
            order.push("kill");
            expect(existsSync(leaseFixture.root)).toBe(true);
          } });
        }
        return { argv, exitCode: 0, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: outputLimitBytes ?? 1_048_576, timedOut: false, timeoutMs };
      },
    });
    // The fake child has no owned process group, so it is ended only through its own handle.
    const kill = vi.spyOn(process, "kill").mockImplementation(((pid: number, _signal?: NodeJS.Signals | number) => {
      if (pid === -4242 || pid === 4242) order.push("unowned-pid-signal");
      return true;
    }) as typeof process.kill);
    try {
      const result = await runSniffAnalyzer({ owner: runOwner, capability: leaseFixture.lease.capability, manifestId: leaseFixture.lease.manifestId, analyzer: "lizard:complexity", runtime });
      expect(result).toMatchObject({ ok: false, outcome: "not-run" });
      expect(result.report).toContain("expired");
      expect(order).toEqual(["kill"]);
      expect(existsSync(leaseFixture.root)).toBe(true);
      exit.resolve(0);
      await released.promise;
      expect(order).toEqual(["kill", "releaseTarget"]);
      expect(existsSync(leaseFixture.root)).toBe(false);
    } finally {
      kill.mockRestore();
      exit.resolve(0);
    }
  });

  test("terminates a child registered against a foreign manifest and keeps the lease intact", async () => {
    const leaseFixture = localLease();
    const exited = Promise.withResolvers<number>();
    const killed: string[] = [];
    const pidSignals: number[] = [];
    const kill = vi.spyOn(process, "kill").mockImplementation(((pid: number) => {
      pidSignals.push(pid);
      return true;
    }) as typeof process.kill);
    try {
      const child = { pid: 777, exited: exited.promise, kill: (signal: "SIGTERM" | "SIGKILL") => {
        killed.push(signal);
        exited.resolve(0);
      } };
      expect(() => registerActiveProcess(leaseFixture.lease.capability, "other-manifest", child, runOwner)).toThrow("does not match the manifest ID");
      await exited.promise;
      expect(killed).toContain("SIGTERM");
      // Without an owned process group the bare PID is never signalled; it may already be reused.
      expect(pidSignals).toEqual([]);
      expect(existsSync(leaseFixture.root)).toBe(true);
      await cancelRunLease(leaseFixture.lease.capability, leaseFixture.lease.manifestId, runOwner);
    } finally {
      kill.mockRestore();
      exited.resolve(0);
    }
  });

  test("fails an over-budget reservation and rejects ran coverage", () => {
    const startedAt = Date.parse("2026-09-11T00:00:00Z");
    let now = startedAt;
    const leaseFixture = localLease({ budget: { maxMinutes: 1 }, now: () => now });
    const authorization = authorizeAnalyzerRun(leaseFixture.lease.capability, leaseFixture.lease.manifestId, "lizard:complexity", runOwner);
    prepareAnalyzerSpawn(leaseFixture.lease.capability, leaseFixture.lease.manifestId, "lizard:complexity", authorization.reservationId, runOwner);
    now += 60_001;
    expect(() => completeAnalyzerReservation(leaseFixture.lease.capability, leaseFixture.lease.manifestId, "lizard:complexity", authorization.reservationId, runOwner)).toThrow("Sniff analyzer exceeded the manifest maxMinutes budget");
    expect(() => validateReportCoverage(leaseFixture.lease.capability, leaseFixture.lease.manifestId, [{ tool: "lizard", status: "ran" }], runOwner)).toThrow("Report coverage claims analyzer lizard without a completed reservation");
    cancelRunLease(leaseFixture.lease.capability, leaseFixture.lease.manifestId, runOwner);
  });

  test("serializes concurrent toolkit installs and re-probes the loser", async () => {
    const cache = mkdtempSync(join(tmpdir(), "sniff-shared-toolkit-"));
    temporary.push(cache);
    const host = mkdtempSync(join(tmpdir(), "sniff-shared-host-"));
    temporary.push(host);
    let installed = false;
    const installCalls: string[][] = [];
    const makeRuntime = (): SniffInstallRuntime => ({
      toolkitCacheRoot: cache,
      resolveCommand: (bin) => bin === "mise" ? join(host, "mise") : installed ? join(host, bin) : null,
      readLauncher: () => "",
      resolveOpenGrep: () => installed ? join(host, "opengrep") : null,
      provisionOpenGrep: async () => { throw new Error("unexpected OpenGrep provisioning"); },
      run: async (argv, _cwd, _env, timeoutMs, _signal, outputLimitBytes) => {
        if (argv[0] === "mise" && argv.includes("install")) {
          installCalls.push(argv);
          installed = true;
        }
        const probing = argv.at(-1) === "--version";
        return { argv, exitCode: 0, stdout: probing ? "tool 1.2.3\\n" : "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: outputLimitBytes ?? 1_048_576, timedOut: false, timeoutMs };
      },
      freshEnvironment: async (_cwd, env) => ({ env, source: "mise" }),
    });
    const [first, second] = await Promise.all([
      runSniffInstall({ mode: "install", bundles: ["core"], cwd: host, runtime: makeRuntime() }),
      runSniffInstall({ mode: "install", bundles: ["core"], cwd: host, runtime: makeRuntime() }),
    ]);
    expect(installCalls).toHaveLength(1);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    const loser = first.tools.some((tool) => tool.install) ? second : first;
    expect(loser.tools.every((tool) => tool.status === "usable")).toBe(true);
  });


  test("merges sharded Lizard output and never masks an early rejected shard exit", async () => {
    const lizardCsv = (file: string, fn: string) => `NLOC,CCN,token,PARAM,length,location,file,function,long_name\n40,25,120,2,60,5-65,${file},${fn},${fn}()\n`;
    const shardRuntime = (calls: AnalyzerCall[], exitFor: (file: string) => number): SniffInstallRuntime => {
      const base = analyzerRuntime(calls);
      return analyzerRuntime(calls, {
        resolveCommand: base.resolveCommand,
        run: async (argv, cwd, env, timeoutMs, _signal, outputLimitBytes) => {
          if (!argv.includes("--csv")) return { argv, exitCode: 0, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: outputLimitBytes ?? 1_048_576, timedOut: false, timeoutMs };
          calls.push({ argv, cwd, env: { ...env }, timeoutMs });
          const operand = argv.at(-1) ?? "";
          return { argv, exitCode: exitFor(operand), stdout: lizardCsv(operand, `fn_${operand.replace(".ts", "")}`), stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: outputLimitBytes ?? 1_048_576, timedOut: false, timeoutMs };
        },
      });
    };
    const merged = localLease({ files: ["a.ts", "b.ts"], budget: { maxFiles: 1 } });
    const mergedCalls: AnalyzerCall[] = [];
    const mergedResult = await runSniffAnalyzer({ owner: runOwner, capability: merged.lease.capability, manifestId: merged.lease.manifestId, analyzer: "lizard:complexity", runtime: shardRuntime(mergedCalls, () => 0) });
    const shards = mergedCalls.filter((call) => call.argv.includes("--csv"));
    expect(shards).toHaveLength(2);
    expect(shards.map((call) => call.argv.at(-1))).toEqual(["a.ts", "b.ts"]);
    expect(mergedResult).toMatchObject({ ok: true, outcome: "completed-with-findings" });
    expect(mergedResult.capture?.incomplete).toBe(false);
    expect(mergedResult.observations?.map((observation) => observation.path).sort()).toEqual(["a.ts", "b.ts"]);
    await cancelRunLease(merged.lease.capability, merged.lease.manifestId, runOwner);

    const rejectedLease = localLease({ files: ["a.ts", "b.ts"], budget: { maxFiles: 1 } });
    const rejectedCalls: AnalyzerCall[] = [];
    const rejectedResult = await runSniffAnalyzer({ owner: runOwner, capability: rejectedLease.lease.capability, manifestId: rejectedLease.lease.manifestId, analyzer: "lizard:complexity", runtime: shardRuntime(rejectedCalls, (file) => file === "a.ts" ? 2 : 0) });
    expect(rejectedResult).toMatchObject({ ok: false, outcome: "rejected-exit" });
    expect(rejectedResult.report).toContain("exit 2");
    expect(rejectedCalls.filter((call) => call.argv.includes("--csv"))).toHaveLength(1);
    await cancelRunLease(rejectedLease.lease.capability, rejectedLease.lease.manifestId, runOwner);
  });

  test("classifies a crashed analyzer as a rejected exit and quotes a bounded stderr tail", async () => {
    const crashed = localLease();
    const base = analyzerRuntime([]);
    const noise = "x".repeat(10_000);
    const runtime = analyzerRuntime([], {
      resolveCommand: base.resolveCommand,
      run: async (argv, _cwd, _env, timeoutMs) => argv.includes("--csv")
        ? { argv, exitCode: 2, stdout: "", stderr: `${noise}\nTraceback: lizard crashed with boom\n`, stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs }
        : { argv, exitCode: 0, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs },
    });
    const result = await runSniffAnalyzer({ owner: runOwner, capability: crashed.lease.capability, manifestId: crashed.lease.manifestId, analyzer: "lizard:complexity", runtime });
    expect(result).toMatchObject({ ok: false, outcome: "rejected-exit" });
    expect(result.report).toContain("exit 2 is outside");
    expect(result.report).toContain("lizard crashed with boom");
    expect(Buffer.byteLength(result.report)).toBeLessThan(2_048 + 512);
    await cancelRunLease(crashed.lease.capability, crashed.lease.manifestId, runOwner);
  });

  test("reports a descendant-held output pipe as incomplete output with an accurate reason", async () => {
    const held = localLease();
    const base = analyzerRuntime([]);
    const runtime = analyzerRuntime([], {
      resolveCommand: base.resolveCommand,
      run: async (argv, _cwd, _env, timeoutMs) => argv.includes("--csv")
        ? { argv, exitCode: 0, stdout: "NLOC,CCN,token,PARAM,length,location,file,function,long_name\n", stderr: "", stdoutTruncated: false, stderrTruncated: false, stdoutIncomplete: "descendant-held-pipe", outputLimitBytes: 1_048_576, timedOut: false, timeoutMs }
        : { argv, exitCode: 0, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs },
    });
    const result = await runSniffAnalyzer({ owner: runOwner, capability: held.lease.capability, manifestId: held.lease.manifestId, analyzer: "lizard:complexity", runtime });
    expect(result).toMatchObject({ ok: false, outcome: "incomplete-output" });
    expect(result.capture).toMatchObject({ incomplete: true, truncated: false });
    expect(result.report).toContain("held open by a descendant process");
    expect(result.report).not.toContain("exceeded");
    await cancelRunLease(held.lease.capability, held.lease.manifestId, runOwner);
  });

  test("words a timeout from the effective deadline", async () => {
    const budgeted = localLease({ budget: { maxMinutes: 1 } });
    const base = analyzerRuntime([]);
    const runtime = analyzerRuntime([], {
      resolveCommand: base.resolveCommand,
      run: async (argv, _cwd, _env, timeoutMs) => ({ argv, exitCode: argv.includes("--csv") ? null : 0, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: argv.includes("--csv"), timeoutMs }),
    });
    const result = await runSniffAnalyzer({ owner: runOwner, capability: budgeted.lease.capability, manifestId: budgeted.lease.manifestId, analyzer: "lizard:complexity", runtime });
    expect(result).toMatchObject({ ok: false, outcome: "not-run" });
    expect(result.report).toContain("maxMinutes");
    expect(result.report).not.toContain("15 minute wall clock");
    await cancelRunLease(budgeted.lease.capability, budgeted.lease.manifestId, runOwner);
  });

  test("abandons the reservation when preflight throws so the analyzer can be retried", async () => {
    const retry = localLease();
    const throwing = analyzerRuntime([], { readLauncher: () => { throw new Error("launcher read exploded"); } });
    const failed = await runSniffAnalyzer({ owner: runOwner, capability: retry.lease.capability, manifestId: retry.lease.manifestId, analyzer: "lizard:complexity", runtime: throwing });
    expect(failed).toMatchObject({ ok: false, outcome: "not-run", preflight: null });
    expect(failed.report).toContain("launcher read exploded");
    const retried = await runSniffAnalyzer({ owner: runOwner, capability: retry.lease.capability, manifestId: retry.lease.manifestId, analyzer: "lizard:complexity", runtime: analyzerRuntime([]) });
    expect(retried.ok).toBe(true);
    await cancelRunLease(retry.lease.capability, retry.lease.manifestId, runOwner);
  });

  test("draws every shard from one analyzer wall clock", async () => {
    let now = Date.parse("2026-09-11T00:00:00Z");
    const lease = localLease({ files: ["a.ts", "b.ts", "c.ts"], budget: { maxFiles: 1 }, now: () => now });
    const calls: AnalyzerCall[] = [];
    const base = analyzerRuntime(calls);
    const runtime = analyzerRuntime(calls, {
      resolveCommand: base.resolveCommand,
      run: async (argv, cwd, env, timeoutMs, _signal, outputLimitBytes) => {
        if (argv.includes("--csv")) {
          calls.push({ argv, cwd, env: { ...env }, timeoutMs });
          now += 500_000;
        }
        return { argv, exitCode: 0, stdout: argv.includes("--csv") ? "NLOC,CCN,token,PARAM,length,location,file,function,long_name\n" : "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: outputLimitBytes ?? 1_048_576, timedOut: false, timeoutMs };
      },
    });
    const result = await runSniffAnalyzer({ owner: runOwner, capability: lease.lease.capability, manifestId: lease.lease.manifestId, analyzer: "lizard:complexity", runtime, now: () => now });
    const shards = calls.filter((call) => call.argv.includes("--csv"));
    expect(shards.map((call) => call.timeoutMs)).toEqual([ANALYZER_TIMEOUT_MS, ANALYZER_TIMEOUT_MS - 500_000]);
    expect(result).toMatchObject({ ok: false, outcome: "not-run" });
    expect(result.report).toContain("minute wall clock");
    await cancelRunLease(lease.lease.capability, lease.lease.manifestId, runOwner);
  });

  test("bounds a gitleaks history scan by its captured window and reports an unbounded scan honestly", async () => {
    const bounded = localLease({ kind: "history", history: { window: { kind: "since-release", release: "v1" }, capturedWindow: { kind: "refs", base: sha("b"), head: sha("a") }, commits: [sha("a")] } });
    const boundedCalls: AnalyzerCall[] = [];
    const boundedResult = await runSniffAnalyzer({ owner: runOwner, capability: bounded.lease.capability, manifestId: bounded.lease.manifestId, analyzer: "gitleaks:tracked-history", runtime: analyzerRuntime(boundedCalls) });
    const boundedArgv = boundedCalls.at(-1)?.argv ?? [];
    expect(boundedArgv[boundedArgv.indexOf("--log-opts") + 1]).toBe(`${sha("b")}..${sha("a")}`);
    expect(boundedResult.report).not.toContain("unbounded");
    await cancelRunLease(bounded.lease.capability, bounded.lease.manifestId, runOwner);

    const unbounded = localLease({ kind: "history", history: { window: { kind: "context-aware-default" }, commits: [sha("a")] } });
    const unboundedCalls: AnalyzerCall[] = [];
    const unboundedResult = await runSniffAnalyzer({ owner: runOwner, capability: unbounded.lease.capability, manifestId: unbounded.lease.manifestId, analyzer: "gitleaks:tracked-history", runtime: analyzerRuntime(unboundedCalls) });
    expect(unboundedCalls.at(-1)?.argv).not.toContain("--log-opts");
    expect(unboundedResult.report).toContain("unbounded history scan");
    await cancelRunLease(unbounded.lease.capability, unbounded.lease.manifestId, runOwner);
  });

  test("gitleaks scans exactly the confirmed commits of a history window, including a window that reaches the root commit", async () => {
    for (const [total, count, expected] of [[2, 10, 2], [3, 2, 2], [3, 1, 1]] as const) {
      const local = repository();
      for (let index = 0; index < total; index += 1) {
        writeFileSync(join(local.root, `f${index}.ts`), `${index}\n`);
        local.git("add", "-A");
        local.git("commit", "-qm", `c${index}`);
      }
      const result = await runSniffIntakeTool({ input: {
        target: { kind: "history", rootOrRepository: local.root, window: { kind: "last-commits", count } },
        intent: "history",
        scopeMode: "full",
        objectives: ["bounded-security-smells"],
        budget: { maxMinutes: 5 },
      } }, { owner: runOwner, confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test-user" }) });
      if (!result.manifest || !result.lease) throw new Error("history intake produced no lease");
      const calls: AnalyzerCall[] = [];
      const run = await runSniffAnalyzer({ owner: runOwner, capability: result.lease.capability, manifestId: result.lease.manifestId, analyzer: "gitleaks:tracked-history", runtime: analyzerRuntime(calls) });
      const argv = calls.at(-1)?.argv ?? [];
      const logOpts = argv[argv.indexOf("--log-opts") + 1] ?? "";
      expect(logOpts).not.toContain("4b825dc");
      expect(run.report).not.toContain("approximate");
      // The revisions gitleaks would walk, evaluated by git in the checkout the scan runs on.
      const walked = Bun.spawnSync(["git", "log", "--format=%H", ...logOpts.split(" ")], { cwd: calls.at(-1)?.cwd ?? result.manifest.resolvedTarget.root });
      expect(walked.exitCode).toBe(0);
      const scanned = walked.stdout.toString().split("\n").filter(Boolean);
      expect(scanned).toHaveLength(expected);
      expect(scanned.sort()).toEqual([...(result.manifest.resolvedTarget.history?.commits ?? [])].sort());
      await cancelRunLease(result.lease.capability, result.lease.manifestId, runOwner);
    }
  }, 60_000);

  test("a confirmed merge commit is scanned with its first-parent patch, so merged-in secrets are visible", async () => {
    const local = repository();
    writeFileSync(join(local.root, "base.ts"), "base\n");
    local.git("add", "-A");
    local.git("commit", "-qm", "base");
    local.git("checkout", "-qb", "feature");
    writeFileSync(join(local.root, "feature.env"), "API_KEY=sk_live_MERGED_IN_SECRET\n");
    local.git("add", "-A");
    local.git("commit", "-qm", "feature adds secret");
    local.git("checkout", "-q", "-");
    writeFileSync(join(local.root, "main.ts"), "main\n");
    local.git("add", "-A");
    local.git("commit", "-qm", "main work");
    local.git("merge", "--no-ff", "-qm", "merge feature", "feature");
    const result = await runSniffIntakeTool({ input: {
      target: { kind: "history", rootOrRepository: local.root, window: { kind: "last-commits", count: 1 } },
      intent: "history",
      scopeMode: "full",
      objectives: ["bounded-security-smells"],
      budget: { maxMinutes: 5 },
    } }, { owner: runOwner, confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test-user" }) });
    if (!result.manifest || !result.lease) throw new Error("history intake produced no lease");
    const calls: AnalyzerCall[] = [];
    await runSniffAnalyzer({ owner: runOwner, capability: result.lease.capability, manifestId: result.lease.manifestId, analyzer: "gitleaks:tracked-history", runtime: analyzerRuntime(calls) });
    const argv = calls.at(-1)?.argv ?? [];
    const logOpts = (argv[argv.indexOf("--log-opts") + 1] ?? "").split(" ");
    // gitleaks reads `git log -p -U0 <log-opts>`; the merge's patch must carry the merged-in secret.
    const patch = Bun.spawnSync(["git", "log", "-p", "-U0", ...logOpts], { cwd: calls.at(-1)?.cwd ?? result.manifest.resolvedTarget.root });
    expect(patch.exitCode).toBe(0);
    expect(patch.stdout.toString()).toContain("sk_live_MERGED_IN_SECRET");
    expect(result.manifest.resolvedTarget.history?.commits).toHaveLength(1);
    await cancelRunLease(result.lease.capability, result.lease.manifestId, runOwner);
  }, 30_000);

  test("refuses to take a toolkit lock while a live owner holds it", async () => {
    const cache = mkdtempSync(join(tmpdir(), "sniff-lock-cache-"));
    temporary.push(cache);
    const host = mkdtempSync(join(tmpdir(), "sniff-lock-host-"));
    temporary.push(host);
    const runtime: SniffInstallRuntime = {
      toolkitCacheRoot: cache,
      resolveCommand: (bin) => join(host, bin),
      readLauncher: () => "",
      resolveOpenGrep: () => join(host, "opengrep"),
      provisionOpenGrep: async () => { throw new Error("unexpected OpenGrep provisioning"); },
      run: async (argv, _cwd, _env, timeoutMs) => ({ argv, exitCode: 0, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: 1_048_576, timedOut: false, timeoutMs }),
      freshEnvironment: async (_cwd, env) => ({ env, source: "mise" }),
    };
    const owner = Promise.withResolvers<void>();
    const owning = withToolkitLock("core", process.env, runtime, () => owner.promise);
    let entered = false;
    await expect(withToolkitLock("core", process.env, runtime, async () => {
      entered = true;
    }, { waitMs: 300 })).rejects.toThrow("Sniff toolkit bundle core is locked by another process");
    expect(entered).toBe(false);

    // The same lock is free once its owner finished.
    owner.resolve();
    await owning;
    await withToolkitLock("core", process.env, runtime, async () => {
      entered = true;
    }, { waitMs: 300 });
    expect(entered).toBe(true);
  });

  test("passively expires an abandoned lease exactly once", () => {
    vi.useFakeTimers();
    try {
      const abandoned = localLease({ ttlMs: 20, removeRootOnRelease: true });
      vi.advanceTimersByTime(21);
      expect(abandoned.releases()).toBe(1);
      expect(existsSync(abandoned.root)).toBe(false);
      expect(() => cancelRunLease(abandoned.lease.capability, abandoned.lease.manifestId, runOwner)).toThrow("already expired");
      expect(abandoned.releases()).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  test("rejects expired, forged, stale, and replayed capabilities while preserving extension namespaces", async () => {
    const expired = localLease({ ttlMs: 0 });
    expect((await runSniffAnalyzer({ owner: runOwner, capability: expired.lease.capability, manifestId: expired.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime([]) })).report).toContain("expired");

    const forged = localLease();
    const forgedInput = reportInput(forged.manifest);
    const forgedExtensions = forgedInput.extensions;
    if (!forgedExtensions) throw new Error("report fixture extensions are missing");
    forgedExtensions["sniff.intake"] = { ...structuredClone(forged.manifest), intent: "history" };
    await expect(runSniffReportTool({ owner: runOwner, capability: forged.lease.capability, manifestId: forged.lease.manifestId, report: forgedInput })).rejects.toThrow("differs");
    await expect(runSniffReportTool({ owner: runOwner, capability: forged.lease.capability, manifestId: forged.lease.manifestId, report: reportInput(forged.manifest) })).resolves.toBeDefined();
    await expect(runSniffReportTool({ owner: runOwner, capability: forged.lease.capability, manifestId: forged.lease.manifestId, report: reportInput(forged.manifest) })).rejects.toThrow("already released");

    const valid = localLease();
    const result = await runSniffReportTool({ owner: runOwner, capability: valid.lease.capability, manifestId: valid.lease.manifestId, report: reportInput(valid.manifest) });
    expect(result.artifacts.report.extensions["example.dev"]).toEqual({ preserved: true });
    await expect(runSniffReportTool({ owner: runOwner, capability: valid.lease.capability, manifestId: valid.lease.manifestId, report: reportInput(valid.manifest) })).rejects.toThrow("already released");
    expect((await runSniffAnalyzer({ owner: runOwner, capability: "unknown", manifestId: valid.lease.manifestId, analyzer: "opengrep:hardcoded-values", runtime: analyzerRuntime([]) })).report).toContain("Unknown");
  });
  test("hydrates an omitted manifest extension into exact report artifacts", async () => {
    const root = mkdtempSync(join(tmpdir(), "sniff-large-report-"));
    temporary.push(root);
    writeFileSync(join(root, "seed.ts"), "export const value = 1;\n");
    const validated = validateResolvedTarget({ kind: "files", label: "seed.ts", root, files: ["seed.ts"], materialization: "in-place" });
    const manifest = createRunManifest({ target: { ...validated, label: "seed.ts, ".repeat(30_000) }, intent: "audit", scopeMode: "full" });
    const lease = issueRunLease(manifest, { target: manifest.resolvedTarget, release: () => {} }, { owner: runOwner });
    const input = reportInput(manifest);
    delete input.extensions?.["sniff.intake"];
    const result = await runSniffReportTool({ owner: runOwner, capability: lease.capability, manifestId: lease.manifestId, report: input });
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
    } }, { owner: runOwner, runner: releaseFixture.runner, confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test-user" }) });
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
      objectives: ["correctness-and-resilience", "bounded-security-smells"],
      budget: { maxMinutes: 5 },
    } }, { owner: runOwner, confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test-user" }) });
    const historyManifest = history.manifest;
    const historyLease = history.lease;
    if (!historyManifest || !historyLease) throw new Error("history intake produced no lease");
    expect(historyManifest.resolvedTarget.kind).toBe("history");
    expect(historyManifest.analyzers.find(({ name }) => name === "gitleaks:tracked-history")?.disposition).toBe("selected");
    const gitleaksCalls: AnalyzerCall[] = [];
    await runSniffAnalyzer({ owner: runOwner, capability: historyLease.capability, manifestId: historyLease.manifestId, analyzer: "gitleaks:tracked-history", runtime: analyzerRuntime(gitleaksCalls) });
    const gitleaksArgv = gitleaksCalls.at(-1)?.argv ?? [];
    const captured = historyManifest.resolvedTarget.history?.capturedWindow;
    if (captured?.kind !== "refs") throw new Error(`expected captured refs window, got ${JSON.stringify(captured)}`);
    expect(gitleaksArgv[gitleaksArgv.indexOf("--log-opts") + 1]).toBe(`--diff-merges=first-parent --no-walk=unsorted ${captured.head}`);
    expect((await completeReport(history)).artifacts.report.target.kind).toBe("history");

    const gitlabRepository = "https://gitlab.com/acme/repo";
    const mrFixture = remoteRunner(gitlabRepository, "gitlab");
    const mr = await runSniffIntakeTool({ input: {
      target: { kind: "mr", repository: gitlabRepository, iid: 7 },
      intent: "review-change",
      scopeMode: "full",
      objectives: ["correctness-and-resilience"],
      budget: { maxMinutes: 5 },
    } }, { owner: runOwner, runner: mrFixture.runner, confirmInteractive: async (request) => ({ acceptedDigest: request.digest, actor: "test-user" }) });
    expect((await completeReport(mr)).artifacts.report.target.kind).toBe("mr");
  }, 20_000);

  test("binds canonical reports to matching authenticated target identities", async () => {
    for (const kind of ["working-tree", "files", "directory", "module", "commit", "range", "branch", "ref", "repository", "pr", "mr", "release", "history"] as const) {
      const current = localLease({ kind, remote: kind === "repository" });
      const report = (await runSniffReportTool({ owner: runOwner, capability: current.lease.capability, manifestId: current.lease.manifestId, report: reportInput(current.manifest) })).artifacts.report;
      expect(report.target.kind).toBe(canonicalReportTargetIdentity(current.manifest.resolvedTarget, current.manifest.scopeMode).kind);
    }
    for (const field of ["kind", "label", "baseRef", "filesAnalyzed"] as const) {
      const current = localLease();
      const input = reportInput(current.manifest);
      if (field === "kind") input.target.kind = "release";
      if (field === "label") input.target.label = "forged";
      if (field === "baseRef") input.target.baseRef = sha("f");
      if (field === "filesAnalyzed") input.target.filesAnalyzed += 1;
      await expect(runSniffReportTool({ owner: runOwner, capability: current.lease.capability, manifestId: current.lease.manifestId, report: input })).rejects.toThrow("must match");
    }
  });
});
