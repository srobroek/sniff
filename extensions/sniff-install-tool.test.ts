import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
	readdirSync,
	readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { clearAnalyzerArtifactRegistryForTests, createAnalyzerArtifacts, registerAnalyzerArtifacts } from "../src/core/analyzer-artifact-registry.ts";
import { ANALYZER_MAX_OBSERVATIONS, parseGitleaksOutput, parseLizardOutput } from "../src/core/analyzer-output.ts";
import { OPENGREP_FILE_EXTENSIONS, SNIFF_ANALYZER_RECIPES, TOOLS } from "../src/core/catalog.ts";
import type { CommandResult, SniffInstallRuntime } from "../src/core/install.ts";
import { renderMiseToolkit, runSniffInstall } from "../src/core/install.ts";
import { OPENGREP_MAX_OUTPUT_BYTES, parseOpenGrepOutput } from "../src/core/opengrep.ts";
import sniffInstallTool from "./sniff-install-tool.ts";

const temps: string[] = [];
afterAll(() => {
	for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

function tempDir(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	temps.push(dir);
	return dir;
}

function executable(path: string, body: string): void {
	mkdirSync(join(path, ".."), { recursive: true });
	writeFileSync(path, `#!/bin/sh\n${body}\n`);
	chmodSync(path, 0o755);
}

function commandResult(argv: string[], timeoutMs: number, overrides: Partial<CommandResult> = {}): CommandResult {
	return {
		argv,
		exitCode: 0,
		stdout: "",
		stderr: "",
		stdoutTruncated: false,
		stderrTruncated: false,
		outputLimitBytes: 1_048_576,
		timedOut: false,
		timeoutMs,
		...overrides,
	};
}

function fakeRuntime(overrides: Partial<SniffInstallRuntime> = {}): SniffInstallRuntime {
	return {
		resolveCommand: (bin) => `/fake/bin/${bin}`,
		toolkitCacheRoot: tempDir("sniff-toolkit-"),
		readLauncher: () => "",
		run: async (argv, _cwd, _env, timeoutMs) => commandResult(argv, timeoutMs),
		freshEnvironment: async (_cwd, env, miseAware) => ({
			env: { ...env, FRESH: "1" },
			source: miseAware ? "mise" : "process",
		}),
		resolveOpenGrep: () => "/fake/bin/opengrep",
		provisionOpenGrep: async () => { throw new Error("unexpected OpenGrep provisioning"); },
		...overrides,
	};
}

function fakeZod(enumCalls: string[][]): { zod: unknown } {
	const chain: Record<string, unknown> = {};
	const self = () => chain;
	chain.string = self;
	chain.optional = self;
	chain.describe = self;
	chain.object = self;
	chain.array = self;
	chain.number = self;
	chain.int = self;
	chain.nonnegative = self;
	chain.boolean = self;
	chain.enum = (values: string[]) => {
		enumCalls.push(values);
		return chain;
	};
	return { zod: chain };
}

describe("sniff tool catalog", () => {
	test("runtime identities are unique and hosted plugins stay metadata", () => {
		const tools = Object.values(TOOLS).flat();
		const seen = new Set<string>();
		for (const tool of tools) {
			expect(seen.has(tool.name)).toBe(false);
			seen.add(tool.name);
		}
		const stylelint = tools.find((tool) => tool.name === "stylelint");
		if (!stylelint || !("hostPackages" in stylelint) || !("configFiles" in stylelint)) {
			throw new Error("stylelint catalog entry is missing host package metadata");
		}
		// Hosted plugins stay metadata on their host and never become runtime tools.
		// Asserted against the host list rather than by name: `tool.name` is a literal
		// union, so naming a non-tool directly is a comparison the compiler rejects.
		for (const hosted of stylelint.hostPackages) {
			expect(seen.has(hosted)).toBe(false);
		}
		expect(stylelint.hostPackages).toContain("stylelint-order");
		expect(stylelint.hostPackages).toContain(
			"stylelint-declaration-strict-value",
		);
		expect(stylelint.configFiles).toContain("stylelint.config.js");
		expect(tools.find((tool) => tool.name === "graphql-inspector")?.pkg).toBe(
			"@graphql-inspector/cli",
		);
		expect(tools.find((tool) => tool.name === "go-vet")?.key).toBe("manual");
	});
});

describe("OpenGrep parser contract", () => {
	test("uses OpenGrep's exact rule IDs, target-relative paths, and supported file extensions", () => {
		const root = tempDir("sniff-opengrep-target-");
		const parsed = parseOpenGrepOutput(JSON.stringify({ results: [
			{ check_id: "hardcoded-http-url", path: `${root}/src/main.go`, start: { line: 3, col: 5 }, extra: { message: "url", severity: "INFO" } },
			{ check_id: "outside", path: "../outside.ts", start: { line: 1, col: 1 }, extra: { message: "outside", severity: "INFO" } },
		] }), root);
		expect(parsed.observations).toEqual([
			{ ruleId: "hardcoded-http-url", path: "src/main.go", start: { line: 3, column: 5 }, message: "url", severity: "INFO" },
		]);
		expect(parsed.capture.incomplete).toBe(true);
		expect(parsed.capture.reason).toContain("escaped");
		expect(SNIFF_ANALYZER_RECIPES["opengrep:hardcoded-values"].args).toEqual(expect.arrayContaining(["--no-rewrite-rule-ids", "--disable-version-check"]));
		expect(SNIFF_ANALYZER_RECIPES["opengrep:hardcoded-values"].targetSeparator).toEqual(["--"]);
		expect(OPENGREP_FILE_EXTENSIONS).toEqual(expect.arrayContaining([".go", ".sh", ".bash", ".yaml", ".yml", ".json", ".toml", ".conf"]));
	});


	test("accepts more than 2,000 complete findings below the byte limit", () => {
		const root = tempDir("sniff-opengrep-large-");
		const results = Array.from({ length: 2_501 }, (_, index) => ({ check_id: "r", path: `src/${index}`, start: { line: 1, col: 1 }, extra: { message: "m", severity: "I" } }));
		const stdout = JSON.stringify({ results });
		expect(Buffer.byteLength(stdout)).toBeLessThan(OPENGREP_MAX_OUTPUT_BYTES);
		const parsed = parseOpenGrepOutput(stdout, root);
		expect(parsed.observations).toHaveLength(2_501);
		expect(parsed.capture.incomplete).toBe(false);
	});

	test("fails closed on malformed OpenGrep result entries", () => {
		const root = tempDir("sniff-opengrep-malformed-");
		const parsed = parseOpenGrepOutput(JSON.stringify({ results: [null, { check_id: "rule", path: "src/main.ts", start: { line: 1.5, col: 0 }, extra: { message: "finding", severity: "INFO" } }] }), root);
		expect(parsed.observations).toEqual([]);
		expect(parsed.capture.incomplete).toBe(true);
		expect(parsed.capture.reason).toContain("malformed");
	});
});
describe("bounded analyzer output projections", () => {
	test("normalizes Lizard CSV rows to target-relative complexity observations", () => {
		const root = tempDir("sniff-lizard-target-");
		mkdirSync(join(root, "src"), { recursive: true });
		writeFileSync(join(root, "src", "main.ts"), "function main() {}\n");
		const parsed = parseLizardOutput([
			"NLOC,CCN,token,PARAM,length,location,file,function,long_name",
			`14,12,50,2,20,4-23,${join(root, "src", "main.ts")},complex,complex`,
			`60,2,50,2,51,24-74,${join(root, "src", "main.ts")},long,long`,
			`10,2,50,6,10,75-84,${join(root, "src", "main.ts")},wide,wide`,
			`50,10,50,5,50,85-134,${join(root, "src", "main.ts")},boundary,boundary`,
		].join("\n"), root);
		expect(parsed.observations).toHaveLength(3);
		expect(parsed.observations.map(({ message }) => message)).toEqual([
			"complex: cyclomatic complexity 12 (NLOC 14, 2 parameters, 20 lines)",
			"long: cyclomatic complexity 2 (NLOC 60, 2 parameters, 51 lines)",
			"wide: cyclomatic complexity 2 (NLOC 10, 6 parameters, 10 lines)",
		]);
		expect(parsed.observations.map(({ severity }) => severity)).toEqual(["MEDIUM", "MEDIUM", "MEDIUM"]);
		expect(parsed.capture.incomplete).toBe(false);
		expect(parsed.capture.digest).toMatch(/^[a-f0-9]{64}$/);
	});

	test("accepts the headerless CSV emitted by Lizard 1.24", () => {
		const root = tempDir("sniff-lizard-headerless-");
		mkdirSync(join(root, "src"), { recursive: true });
		writeFileSync(join(root, "src", "main.ts"), "function complex() {}\n");
		const path = join(root, "src", "main.ts");
		const parsed = parseLizardOutput(`14,12,50,2,20,"complex@4-23@${path}",${path},complex,"complex ( value )",4,23`, root);
		expect(parsed.observations).toHaveLength(1);
		expect(parsed.observations[0]).toMatchObject({ path: "src/main.ts", start: { line: 4, column: 1 }, message: "complex: cyclomatic complexity 12 (NLOC 14, 2 parameters, 20 lines)" });
		expect(parsed.capture.incomplete).toBe(false);
	});

	test("projects Gitleaks JSON with exact rule IDs and rejects escaped paths", () => {
		const root = tempDir("sniff-gitleaks-target-");
		mkdirSync(join(root, "src"), { recursive: true });
		writeFileSync(join(root, "src", "secret.ts"), "const secret = true;\n");
		const parsed = parseGitleaksOutput(JSON.stringify([
			{ RuleID: "aws-access-key-id", Description: "AWS access key", File: "src/secret.ts", StartLine: 3, StartColumn: 5, Severity: "HIGH" },
			{ RuleID: "outside", Description: "must not escape", File: "../outside.ts", StartLine: 1, StartColumn: 1 },
		]), root);
		expect(parsed.observations).toEqual([{
			ruleId: "aws-access-key-id",
			path: "src/secret.ts",
			start: { line: 3, column: 5 },
			message: "AWS access key",
			severity: "HIGH",
		}]);
		expect(parsed.capture.incomplete).toBe(true);
		expect(parsed.capture.reason).toContain("escaped");
	});

	test("fails closed for malformed or truncated output and caps observations", () => {
		const root = tempDir("sniff-analyzer-bounds-");
		const malformed = parseGitleaksOutput("[{not-json", root);
		expect(malformed.observations).toEqual([]);
		expect(malformed.capture.incomplete).toBe(true);
		const truncated = parseLizardOutput("NLOC,CCN,token,PARAM,length,location,file,function,long_name", root, true);
		expect(truncated.observations).toEqual([]);
		expect(truncated.capture.truncated).toBe(true);
		expect(truncated.capture.incomplete).toBe(true);
		const rows = Array.from({ length: ANALYZER_MAX_OBSERVATIONS + 1 }, (_, index) => `1,11,1,0,1,${index + 1}-${index + 1},src/file-${index}.ts,fn${index},fn${index}`);
		const bounded = parseLizardOutput(["NLOC,CCN,token,PARAM,length,location,file,function,long_name", ...rows].join("\n"), root);
		expect(bounded.observations).toHaveLength(ANALYZER_MAX_OBSERVATIONS);
		expect(bounded.capture.incomplete).toBe(true);
		expect(bounded.capture.reason).toContain("2,000");
	});
});


describe("probe timeouts", () => {
	test("uses OpenGrep's extended bounded timeout without changing ordinary tools", async () => {
		const calls: Array<{ bin: string; timeoutMs: number }> = [];
		const result = await runSniffInstall({
			mode: "diagnose",
			bundles: ["core"],
			runtime: fakeRuntime({
				run: async (argv, _cwd, _env, timeoutMs) => {
					calls.push({ bin: (argv.at(0) ?? "").split("/").pop() ?? "", timeoutMs });
					return commandResult(argv, timeoutMs);
				},
			}),
		});
		expect(result.ok).toBe(true);
		expect(calls.find(({ bin }) => bin === "opengrep")?.timeoutMs).toBe(60_000);
		expect(calls.filter(({ bin }) => bin !== "opengrep").every(({ timeoutMs }) => timeoutMs === 1_500)).toBe(true);
	});

	test("runs Cargo version probes outside the target repository", async () => {
		const target = tempDir("sniff-untrusted-cargo-config-");
		const calls: Array<{ argv: string[]; cwd: string }> = [];
		const result = await runSniffInstall({
			mode: "diagnose",
			bundles: ["rust"],
			cwd: target,
			runtime: fakeRuntime({
				run: async (argv, cwd, _env, timeoutMs) => {
					calls.push({ argv, cwd });
					return commandResult(argv, timeoutMs);
				},
			}),
		});
		expect(result.ok).toBe(true);
		const cargoProbes = calls.filter(({ argv }) => argv[0] === "/fake/bin/cargo");
		expect(cargoProbes.length).toBeGreaterThan(0);
		expect(cargoProbes.every(({ cwd }) => cwd !== target)).toBe(true);
	});

	test("does not oscillate status at the old timeout boundary", async () => {
		const statuses: string[] = [];
		const runtime = fakeRuntime({
			run: async (argv, _cwd, _env, timeoutMs) =>
				commandResult(argv, timeoutMs, {
					exitCode: 1,
					stderr: timeoutMs === 1_500 ? "boundary crossed" : "",
				}),
		});
		for (const _ of [0, 1]) {
			const result = await runSniffInstall({ mode: "diagnose", bundles: ["core"], runtime });
			statuses.push(result.tools.find((tool) => tool.tool === "opengrep")?.status ?? "");
		}
		expect(statuses).toEqual(["unrunnable", "unrunnable"]);
	});
});

describe("runSniffInstall", () => {
	test("list mode preserves bundle inventory", async () => {
		const result = await runSniffInstall({ mode: "list" });
		expect(result.ok).toBe(true);
		for (const bundle of [
			"core",
			"dup",
			"security",
			"rust",
			"go",
			"python",
			"js-ts",
			"shell",
			"sql",
			"css",
			"data",
			"api",
			"infra",
			"docs",
		]) {
			expect(result.report).toContain(`[${bundle}]`);
		}
		expect(result.report).toContain("opengrep");
		expect(result.report).toContain("golangci-lint");
	});

	test("probe stays successful with missing tools and ignores unverified OpenGrep PATH shims", async () => {
		const dir = tempDir("sniff-probe-");
		const shimDir = join(dir, ".mise", "shims");
		executable(join(shimDir, "opengrep"), 'exec mise x -- opengrep "$@"');
		const result = await runSniffInstall({
			mode: "probe",
			cwd: dir,
			env: { PATH: shimDir, SNIFF_OPENGREP_CACHE_DIR: join(dir, "empty-opengrep-cache"), SNIFF_TOOLKIT_CACHE_DIR: tempDir("sniff-empty-toolkit-") },
		});
		expect(result.ok).toBe(true);
		expect(result.tools.find((tool) => tool.tool === "opengrep")?.status).toBe(
			"missing",
		);
		expect(result.tools.find((tool) => tool.tool === "scc")?.status).toBe(
			"missing",
		);
		expect(result.report).toContain("MISS opengrep");
		expect(result.report).toContain("MISS scc");
	});

	test("probe preserves SHIM text for a broken PATH executable", async () => {
		const dir = tempDir("sniff-probe-broken-");
		const binDir = join(dir, "bin");
		executable(join(binDir, "lizard"), "exit 19");
		const result = await runSniffInstall({
			mode: "probe",
			cwd: dir,
			env: { PATH: binDir, SNIFF_TOOLKIT_CACHE_DIR: tempDir("sniff-empty-toolkit-") },
		});
		expect(result.ok).toBe(true);
		expect(result.tools.find((tool) => tool.tool === "lizard")?.status).toBe(
			"unrunnable",
		);
		expect(result.report).toContain("SHIM lizard");
	});

	test("preflight succeeds when every selected required tool is usable", async () => {
		const result = await runSniffInstall({
			mode: "diagnose",
			bundles: ["core"],
			runtime: fakeRuntime(),
		});
		expect(result.ok).toBe(true);
		expect(result.tools.map((tool) => tool.tool)).toEqual([
			"opengrep",
			"lizard",
			"scc",
			"ast-grep",
			"tokei",
		]);
		expect(
			result.tools.every((tool) => tool.required && tool.status === "usable"),
		).toBe(true);
	});

	test("preflight fails for a missing required tool", async () => {
		const runtime = fakeRuntime({
			resolveOpenGrep: () => null,
		});
		const result = await runSniffInstall({
			mode: "diagnose",
			bundles: ["core"],
			runtime,
		});
		expect(result.ok).toBe(false);
		const missing = result.tools.find((tool) => tool.tool === "opengrep");
		expect(missing).toMatchObject({ status: "missing", resolvedPath: null });
		expect(missing?.remediation).toContain("sniff_install_tools mode=install bundles=[core]");
	});

	test("PATH launcher shim is classified as shimmed", async () => {
		const dir = tempDir("sniff-shim-");
		const shimDir = join(dir, ".mise", "shims");
		executable(join(shimDir, "jscpd"), 'exec mise x -- jscpd "$@"');
		const result = await runSniffInstall({
			mode: "diagnose",
			bundles: ["dup"],
			cwd: dir,
			env: { PATH: shimDir, SNIFF_TOOLKIT_CACHE_DIR: tempDir("sniff-empty-toolkit-") },
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]).toMatchObject({
			status: "shimmed",
			resolvedPath: realpathSync(join(shimDir, "jscpd")),
		});
	});

	test("runnable launcher shim is still classified as shimmed", async () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => `/fake/.mise/shims/${bin}`,
			readLauncher: () => '#!/bin/sh\nexec mise x -- "$0" "$@"',
			run: async (argv, _cwd, _env, timeoutMs) => commandResult(argv, timeoutMs),
		});
		const result = await runSniffInstall({
			mode: "diagnose",
			bundles: ["dup"],
			runtime,
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]).toMatchObject({ status: "shimmed", attempts: [] });
	});

	test("real executable failure is unrunnable rather than shimmed", async () => {
		const dir = tempDir("sniff-broken-");
		const binDir = join(dir, "bin");
		executable(join(binDir, "jscpd"), "exit 17");
		const result = await runSniffInstall({
			mode: "diagnose",
			bundles: ["dup"],
			cwd: dir,
			env: { PATH: binDir, SNIFF_TOOLKIT_CACHE_DIR: tempDir("sniff-empty-toolkit-") },
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]).toMatchObject({
			status: "unrunnable",
			resolvedPath: realpathSync(join(binDir, "jscpd")),
		});
	});

	test("real sleeping executable is classified as timed-out", async () => {
		const dir = tempDir("sniff-sleep-");
		const binDir = join(dir, "bin");
		executable(join(binDir, "jscpd"), "sleep 5");
		const result = await runSniffInstall({
			mode: "diagnose",
			bundles: ["dup"],
			cwd: dir,
			env: { PATH: `${binDir}${delimiter}/bin:/usr/bin`, SNIFF_TOOLKIT_CACHE_DIR: tempDir("sniff-empty-toolkit-") },
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]?.status).toBe("timed-out");
		expect(result.tools[0]?.attempts.every((attempt) => attempt.timedOut)).toBe(
			true,
		);
	});

	test("project-local-only tools require a project dependency", async () => {
		const dir = tempDir("sniff-local-");
		const result = await runSniffInstall({
			mode: "diagnose",
			bundles: ["js-ts"],
			cwd: dir,
			env: { PATH: "" },
		});
		expect(result.ok).toBe(false);
		expect(
			result.tools.every((tool) => tool.status === "project-local-required"),
		).toBe(true);
	});

	test("project-local tools never fall back to a global executable", async () => {
		const dir = tempDir("sniff-local-global-");
		const globalBin = join(dir, "global-bin");
		executable(join(globalBin, "eslint"), "exit 0");
		const result = await runSniffInstall({
			mode: "diagnose",
			bundles: ["js-ts"],
			cwd: dir,
			env: { PATH: globalBin },
		});
		expect(result.tools.find((tool) => tool.tool === "eslint")).toMatchObject({
			status: "project-local-required",
			resolvedPath: null,
		});
	});

	test("inventory reports project-local launchers without executing them", async () => {
		const dir = tempDir("sniff-local-inventory-");
		const marker = join(dir, "invoked");
		const launcher = join(dir, "node_modules", ".bin", "eslint");
		executable(launcher, `printf invoked > ${JSON.stringify(marker)}`);
		const expectedPath = realpathSync(launcher);

		for (const mode of ["probe", "diagnose", "install"] as const) {
			const result = await runSniffInstall({
				mode,
				...(mode === "diagnose" || mode === "install" ? { bundles: ["js-ts"] } : {}),
				...(mode === "install" ? { dryRun: true } : {}),
				cwd: dir,
				env: { PATH: "" },
			});
			const eslint = result.tools.find((tool) => tool.tool === "eslint");
			expect(eslint).toMatchObject({
				status: "policy-blocked",
				resolvedPath: expectedPath,
				attempts: [],
			});
			expect(eslint?.remediation).toContain("inventory does not execute project code");
		}
		expect(existsSync(marker)).toBe(false);
	});

	test("already-aborted install cancels before spawning a manager", async () => {
		const controller = new AbortController();
		controller.abort();
		let spawnCount = 0;
		const runtime = fakeRuntime({
			resolveCommand: (bin) => (bin === "jscpd" ? null : `/fake/bin/${bin}`),
			run: async (argv, _cwd, _env, timeoutMs) => {
				spawnCount += 1;
				return commandResult(argv, timeoutMs, {
					exitCode: null,
					error: "operation aborted",
				});
			},
		});
		const result = await runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			runtime,
			signal: controller.signal,
		});
		expect(result.ok).toBe(false);
		expect(result.report).toContain("operation aborted");
		expect(spawnCount).toBe(0);
	});
	test("installation timeout is structured as timed-out", async () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => (bin === "jscpd" ? null : `/fake/bin/${bin}`),
			run: async (argv, _cwd, _env, timeoutMs) =>
				commandResult(argv, timeoutMs, {
					exitCode: null,
					timedOut: true,
					error: "operation timed out",
				}),
		});
		const result = await runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			runtime,
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]?.status).toBe("timed-out");
		expect(result.tools[0]?.install?.timeoutMs).toBe(300_000);
	});

	test("supply-chain trust denial is policy-blocked", async () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => (bin === "jscpd" ? null : `/fake/bin/${bin}`),
			run: async (argv, _cwd, _env, timeoutMs) =>
				commandResult(argv, timeoutMs, {
					exitCode: 1,
					stderr: "package trust policy denied downgrade",
				}),
		});
		const result = await runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			runtime,
		});
		expect(result.tools[0]?.status).toBe("policy-blocked");
	});

	test("invalid manager registry route is unavailable-route", async () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => (bin === "jscpd" ? null : `/fake/bin/${bin}`),
			run: async (argv, _cwd, _env, timeoutMs) =>
				commandResult(argv, timeoutMs, {
					exitCode: 1,
					stderr: "unknown registry backend for package",
				}),
		});
		const result = await runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			runtime,
		});
		expect(result.tools[0]?.status).toBe("unavailable-route");
	});

	test("generic nonzero installation is installation-failed", async () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => (bin === "jscpd" ? null : `/fake/bin/${bin}`),
			run: async (argv, _cwd, _env, timeoutMs) =>
				commandResult(argv, timeoutMs, {
					exitCode: 73,
					stderr: "compiler exited unsuccessfully",
				}),
		});
		const result = await runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			runtime,
		});
		expect(result.tools[0]?.status).toBe("installation-failed");
	});

	test("installs one bundle toolkit and reuses it for later preflight", async () => {
		const target = tempDir("sniff-target-");
		writeFileSync(join(target, "marker"), "unchanged");
		const calls: Array<{ argv: string[]; cwd: string; env: Record<string, string | undefined> }> = [];
		const refreshes: Array<{ cwd: string; env: Record<string, string | undefined> }> = [];
		const runtime = fakeRuntime({
			resolveCommand: (bin, _cwd, env) => {
				if (bin === "jscpd") return env.FRESH === "1" ? "/fresh/bin/jscpd" : null;
				return `/fake/bin/${bin}`;
			},
			run: async (argv, cwd, env, timeoutMs) => {
				calls.push({ argv, cwd, env });
				return commandResult(argv, timeoutMs);
			},
			freshEnvironment: async (cwd, env) => {
				refreshes.push({ cwd, env });
				return { env: { ...env, FRESH: "1" }, source: "mise" };
			},
		});
		const toolkitDirectory = join(runtime.toolkitCacheRoot ?? "", "dup");
		const installed = await runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			cwd: target,
			runtime,
		});
		expect(installed.ok).toBe(true);
		expect(installed.tools[0]).toMatchObject({ status: "usable", resolvedPath: "/fresh/bin/jscpd" });
		const installCall = calls.find(({ argv }) => argv.join(" ") === "mise install");
		expect(installCall).toMatchObject({ argv: ["mise", "install"], cwd: toolkitDirectory, env: {
			MISE_CONFIG_DIR: join(toolkitDirectory, ".mise-config"),
			MISE_GLOBAL_CONFIG_FILE: join(toolkitDirectory, ".global-config-disabled.toml"),
			MISE_SYSTEM_CONFIG_FILE: join(toolkitDirectory, ".system-config-disabled.toml"),
		} });
		expect(readFileSync(join(toolkitDirectory, "mise.toml"), "utf8")).toBe(renderMiseToolkit("dup"));
		expect(readdirSync(target)).toEqual(["marker"]);

		const diagnosed = await runSniffInstall({ mode: "diagnose", bundles: ["dup"], cwd: target, runtime });
		expect(diagnosed.tools[0]).toMatchObject({ status: "usable", resolvedPath: "/fresh/bin/jscpd" });
		expect(refreshes).toHaveLength(2);
		for (const refresh of refreshes) {
			expect(refresh).toMatchObject({ cwd: toolkitDirectory, env: { MISE_CONFIG_DIR: join(toolkitDirectory, ".mise-config") } });
		}
	});

	test("managed installation requires mise without package-manager fallback", async () => {
		const calls: string[][] = [];
		const runtime = fakeRuntime({
			resolveCommand: (bin) => bin === "mise" || bin === "jscpd" ? null : `/fake/bin/${bin}`,
			run: async (argv, _cwd, _env, timeoutMs) => {
				calls.push(argv);
				return commandResult(argv, timeoutMs);
			},
		});
		const result = await runSniffInstall({ mode: "install", bundles: ["dup"], runtime });
		expect(result.ok).toBe(false);
		expect(result.tools[0]).toMatchObject({ status: "unavailable-route", remediation: "mise is required to install the Sniff-managed dup toolkit" });
		expect(calls).toEqual([]);
		expect(existsSync(join(runtime.toolkitCacheRoot ?? "", "dup", "mise.toml"))).toBe(false);
	});

	test("install fails when a successful manager command leaves a shim", async () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin, _cwd, env) => {
				if (bin === "jscpd")
					return env.FRESH === "1" ? "/fresh/.mise/shims/jscpd" : null;
				return `/fake/bin/${bin}`;
			},
			readLauncher: () => '#!/bin/sh\nexec mise x -- jscpd "$@"',
			run: async (argv, _cwd, env, timeoutMs) => {
				if (argv[0] === "/fresh/.mise/shims/jscpd" && env.FRESH === "1") {
					return commandResult(argv, timeoutMs, {
						exitCode: 1,
						stderr: "inactive shim",
					});
				}
				return commandResult(argv, timeoutMs);
			},
		});
		const result = await runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			runtime,
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]?.status).toBe("shimmed");
	});

	test("install without bundles and unknown bundles fail", async () => {
		const noBundle = await runSniffInstall({ mode: "install" });
		expect(noBundle.ok).toBe(false);
		const unknown = await runSniffInstall({ mode: "install", bundles: ["nope"] });
		expect(unknown.report).toContain('unknown bundle "nope"');
	});

	test("prototype names are not bundle names", async () => {
		for (const bundle of ["constructor", "toString", "__proto__"]) {
			expect((await runSniffInstall({ mode: "install", bundles: [bundle] })).ok).toBe(false);
		}
	});

	test("dry-run install prints commands without requiring success", async () => {
		const dir = tempDir("sniff-dry-");
		const result = await runSniffInstall({
			mode: "install",
			bundles: ["core"],
			dryRun: true,
			cwd: dir,
			runtime: fakeRuntime({
				resolveCommand: (bin) => (bin === "brew" ? "/fake/bin/brew" : null),
			}),
		});
		expect(result.ok).toBe(true);
		expect(result.report).toContain("(dry run — no changes will be made)");
		expect(result.report).toContain("[core]");
	});
	test("rejects empty PATH entries instead of resolving a host executable", async () => {
		const dir = tempDir("sniff-empty-path-");
		const binDir = join(dir, "bin");
		executable(join(binDir, "opengrep"), "exit 0");
		const result = await runSniffInstall({ mode: "probe", cwd: dir, env: { PATH: `${binDir}${delimiter}`, SNIFF_OPENGREP_CACHE_DIR: join(dir, "empty-opengrep-cache") } });
		expect(result.tools.find(({ tool }) => tool === "opengrep")?.status).toBe("missing");
	});
});


describe("sniff tools integration", () => {
	test("registration exposes catalog preflight and atomic analyzer runner", async () => {
		const enumCalls: string[][] = [];
		type RegisteredTool = {
			name: string;
			description: string;
			execute: (
				id: string,
				params: Record<string, unknown>,
				signal: unknown,
				onUpdate: unknown,
				context: { cwd: string },
			) => Promise<{
				content: Array<{ type: string; text: string }>;
				details: { ok: boolean; tools: Array<Record<string, unknown>>; [key: string]: unknown };
				isError?: boolean;
			}>;
		};
		const captured = new Map<string, RegisteredTool>();
		const fakePi = {
			...fakeZod(enumCalls),
			registerTool: (definition: RegisteredTool) => {
				captured.set(definition.name, definition);
			},
			on: () => {},
		};
		sniffInstallTool(fakePi as never);
		expect(captured.has("sniff_install_tools")).toBe(true);
		expect(captured.get("sniff_run_analyzer")?.description).toContain(
			"immediately before execution",
		);
		expect(enumCalls).toContainEqual(["probe", "diagnose", "list", "install"]);

		const dir = tempDir("sniff-int-");
		const registeredTool = captured.get("sniff_install_tools");
		if (!registeredTool)
			throw new Error("sniff_install_tools was not registered");
		const out = await registeredTool.execute(
			"id",
			{ mode: "diagnose", bundles: ["js-ts"], path: dir },
			undefined,
			undefined,
			{ cwd: dir },
		);
		expect(out.details.ok).toBe(false);
		expect(out.isError).toBe(true);
		expect(out.details.tools.length).toBeGreaterThan(0);
		expect(out.details.tools[0]).toHaveProperty("status");
	});
});


	test("analyzer reader content carries IDs and paging metadata within the model bound", async () => {
		type RegisteredTool = {
			name: string;
			description: string;
			execute: (
				id: string,
				params: Record<string, unknown>,
				signal: unknown,
				onUpdate: unknown,
				context: { cwd: string },
			) => Promise<{
				content: Array<{ type: string; text: string }>;
				details: { ok: boolean; tools: Array<Record<string, unknown>>; [key: string]: unknown };
				isError?: boolean;
			}>;
		};
		clearAnalyzerArtifactRegistryForTests();
		const artifacts = createAnalyzerArtifacts(
			"opengrep:test",
			Array.from({ length: 2_000 }, (_, index) => ({
				ruleId: "rule",
				path: "src/large.ts",
				start: { line: index + 1, column: 1 },
				message: `finding-${index}-${"x".repeat(96)}`,
				severity: "WARNING",
			})),
			"analyzer-result-test",
		);
		const capability = registerAnalyzerArtifacts(artifacts);
		const enumCalls: string[][] = [];
		const captured = new Map<string, RegisteredTool>();
		const fakePi = {
			...fakeZod(enumCalls),
			registerTool: (definition: RegisteredTool) => {
				captured.set(definition.name, definition);
			},
			on: () => {},
		};
		sniffInstallTool(fakePi as never);
		const reader = captured.get("sniff_read_analyzer_artifact");
		if (!reader) throw new Error("sniff_read_analyzer_artifact was not registered");
		const path = artifacts.descriptors.find((descriptor) => descriptor.kind === "source-file")?.relativePath;
		if (!path) throw new Error("source artifact was not registered");
    const first = await reader.execute("id", { readCapability: capability, analyzerResultId: artifacts.analyzerResultId, relativePath: path }, undefined, undefined, { cwd: process.cwd() });
		const firstText = first.content[0]?.text ?? "";
		const firstPage = JSON.parse(firstText) as { analyzerResultId: string; relativePath: string; offset: number; nextOffset: number; eof: boolean; bytes: number; content: string };
		expect(firstPage.analyzerResultId).toBe(artifacts.analyzerResultId);
		expect(firstPage.relativePath).toBe(path);
		expect(firstPage.offset).toBe(0);
		expect(firstPage.nextOffset).toBeGreaterThan(firstPage.offset);
		expect(firstPage.bytes).toBe(Buffer.byteLength(firstPage.content));
		expect(Buffer.byteLength(firstText)).toBeLessThan(64 * 1024);

    const second = await reader.execute("id", { readCapability: capability, analyzerResultId: firstPage.analyzerResultId, relativePath: firstPage.relativePath, offset: firstPage.nextOffset }, undefined, undefined, { cwd: process.cwd() });
		const secondPage = JSON.parse(second.content[0]?.text ?? "") as { analyzerResultId: string; offset: number; nextOffset: number; content: string };
		expect(secondPage.analyzerResultId).toBe(firstPage.analyzerResultId);
		expect(secondPage.offset).toBe(firstPage.nextOffset);
		expect(secondPage.nextOffset).toBeGreaterThan(secondPage.offset);
		clearAnalyzerArtifactRegistryForTests();

	});