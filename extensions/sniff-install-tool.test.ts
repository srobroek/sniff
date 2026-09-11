import { afterAll, describe, expect, test } from "bun:test";
import {
	chmodSync,
	mkdirSync,
	mkdtempSync,
	realpathSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { TOOLS } from "../src/core/catalog.ts";
import type { CommandResult, SniffInstallRuntime } from "../src/core/install.ts";
import { runSniffInstall } from "../src/core/install.ts";
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

function commandResult(
	argv: string[],
	timeoutMs: number,
	overrides: Partial<CommandResult> = {},
): CommandResult {
	return {
		argv,
		exitCode: 0,
		stdout: "",
		stderr: "",
		timedOut: false,
		timeoutMs,
		...overrides,
	};
}

function fakeRuntime(
	overrides: Partial<SniffInstallRuntime> = {},
): SniffInstallRuntime {
	return {
		resolveCommand: (bin) => `/fake/bin/${bin}`,
		readLauncher: () => "",
		run: (argv, _cwd, _env, timeoutMs) => commandResult(argv, timeoutMs),
		freshEnvironment: (_cwd, env, miseAware) => ({
			env: { ...env, FRESH: "1" },
			source: miseAware ? "mise" : "process",
		}),
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

describe("runSniffInstall", () => {
	test("list mode preserves bundle inventory", () => {
		const result = runSniffInstall({ mode: "list" });
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
		expect(result.report).toContain("semgrep");
		expect(result.report).toContain("golangci-lint");
	});

	test("probe stays successful with missing and shimmed tools", () => {
		const dir = tempDir("sniff-probe-");
		const shimDir = join(dir, ".mise", "shims");
		executable(join(shimDir, "semgrep"), 'exec mise x -- semgrep "$@"');
		const result = runSniffInstall({
			mode: "probe",
			cwd: dir,
			env: { PATH: shimDir },
		});
		expect(result.ok).toBe(true);
		expect(result.tools.find((tool) => tool.tool === "semgrep")?.status).toBe(
			"shimmed",
		);
		expect(result.tools.find((tool) => tool.tool === "scc")?.status).toBe(
			"missing",
		);
		expect(result.report).toContain("SHIM semgrep");
		expect(result.report).toContain("MISS scc");
	});

	test("probe preserves SHIM text for a broken PATH executable", () => {
		const dir = tempDir("sniff-probe-broken-");
		const binDir = join(dir, "bin");
		executable(join(binDir, "lizard"), "exit 19");
		const result = runSniffInstall({
			mode: "probe",
			cwd: dir,
			env: { PATH: binDir },
		});
		expect(result.ok).toBe(true);
		expect(result.tools.find((tool) => tool.tool === "lizard")?.status).toBe(
			"unrunnable",
		);
		expect(result.report).toContain("SHIM lizard");
	});

	test("preflight succeeds when every selected required tool is usable", () => {
		const result = runSniffInstall({
			mode: "diagnose",
			bundles: ["core"],
			runtime: fakeRuntime(),
		});
		expect(result.ok).toBe(true);
		expect(result.tools.map((tool) => tool.tool)).toEqual([
			"semgrep",
			"lizard",
			"scc",
			"ast-grep",
			"tokei",
		]);
		expect(
			result.tools.every((tool) => tool.required && tool.status === "usable"),
		).toBe(true);
	});

	test("preflight fails for a missing required tool", () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => (bin === "semgrep" ? null : `/fake/bin/${bin}`),
		});
		const result = runSniffInstall({
			mode: "diagnose",
			bundles: ["core"],
			runtime,
		});
		expect(result.ok).toBe(false);
		const missing = result.tools.find((tool) => tool.tool === "semgrep");
		expect(missing).toMatchObject({ status: "missing", resolvedPath: null });
		expect(missing?.remediation).toContain("pipx install semgrep");
	});

	test("PATH launcher shim is classified as shimmed", () => {
		const dir = tempDir("sniff-shim-");
		const shimDir = join(dir, ".mise", "shims");
		executable(join(shimDir, "jscpd"), 'exec mise x -- jscpd "$@"');
		const result = runSniffInstall({
			mode: "diagnose",
			bundles: ["dup"],
			cwd: dir,
			env: { PATH: shimDir },
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]).toMatchObject({
			status: "shimmed",
			resolvedPath: realpathSync(join(shimDir, "jscpd")),
		});
	});

	test("runnable launcher shim is still classified as shimmed", () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => `/fake/.mise/shims/${bin}`,
			readLauncher: () => '#!/bin/sh\nexec mise x -- "$0" "$@"',
			run: (argv, _cwd, _env, timeoutMs) => commandResult(argv, timeoutMs),
		});
		const result = runSniffInstall({
			mode: "diagnose",
			bundles: ["dup"],
			runtime,
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]).toMatchObject({ status: "shimmed", attempts: [] });
	});

	test("real executable failure is unrunnable rather than shimmed", () => {
		const dir = tempDir("sniff-broken-");
		const binDir = join(dir, "bin");
		executable(join(binDir, "jscpd"), "exit 17");
		const result = runSniffInstall({
			mode: "diagnose",
			bundles: ["dup"],
			cwd: dir,
			env: { PATH: binDir },
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]).toMatchObject({
			status: "unrunnable",
			resolvedPath: realpathSync(join(binDir, "jscpd")),
		});
	});

	test("real sleeping executable is classified as timed-out", () => {
		const dir = tempDir("sniff-sleep-");
		const binDir = join(dir, "bin");
		executable(join(binDir, "jscpd"), "sleep 5");
		const result = runSniffInstall({
			mode: "diagnose",
			bundles: ["dup"],
			cwd: dir,
			env: { PATH: `${binDir}${delimiter}/bin:/usr/bin` },
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]?.status).toBe("timed-out");
		expect(result.tools[0]?.attempts.every((attempt) => attempt.timedOut)).toBe(
			true,
		);
	});

	test("project-local-only tools require a project dependency", () => {
		const dir = tempDir("sniff-local-");
		const result = runSniffInstall({
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

	test("project-local tools never fall back to a global executable", () => {
		const dir = tempDir("sniff-local-global-");
		const globalBin = join(dir, "global-bin");
		executable(join(globalBin, "eslint"), "exit 0");
		const result = runSniffInstall({
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

	test("installation timeout is structured as timed-out", () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => (bin === "jscpd" ? null : `/fake/bin/${bin}`),
			run: (argv, _cwd, _env, timeoutMs) =>
				commandResult(argv, timeoutMs, {
					exitCode: null,
					timedOut: true,
					error: "operation timed out",
				}),
		});
		const result = runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			noMise: true,
			runtime,
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]?.status).toBe("timed-out");
		expect(result.tools[0]?.install?.timeoutMs).toBe(300_000);
	});

	test("supply-chain trust denial is policy-blocked", () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => (bin === "jscpd" ? null : `/fake/bin/${bin}`),
			run: (argv, _cwd, _env, timeoutMs) =>
				commandResult(argv, timeoutMs, {
					exitCode: 1,
					stderr: "package trust policy denied downgrade",
				}),
		});
		const result = runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			noMise: true,
			runtime,
		});
		expect(result.tools[0]?.status).toBe("policy-blocked");
	});

	test("invalid manager registry route is unavailable-route", () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => (bin === "jscpd" ? null : `/fake/bin/${bin}`),
			run: (argv, _cwd, _env, timeoutMs) =>
				commandResult(argv, timeoutMs, {
					exitCode: 1,
					stderr: "unknown registry backend for package",
				}),
		});
		const result = runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			runtime,
		});
		expect(result.tools[0]?.status).toBe("unavailable-route");
	});

	test("generic nonzero installation is installation-failed", () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin) => (bin === "jscpd" ? null : `/fake/bin/${bin}`),
			run: (argv, _cwd, _env, timeoutMs) =>
				commandResult(argv, timeoutMs, {
					exitCode: 73,
					stderr: "compiler exited unsuccessfully",
				}),
		});
		const result = runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			runtime,
		});
		expect(result.tools[0]?.status).toBe("installation-failed");
	});

	test("successful mise install is re-probed in a fresh environment", () => {
		const calls: string[][] = [];
		const refreshes: boolean[] = [];
		const runtime = fakeRuntime({
			resolveCommand: (bin, _cwd, env) => {
				if (bin === "jscpd")
					return env.FRESH === "1" ? "/fresh/bin/jscpd" : null;
				return `/fake/bin/${bin}`;
			},
			run: (argv, _cwd, _env, timeoutMs) => {
				calls.push(argv);
				return commandResult(argv, timeoutMs);
			},
			freshEnvironment: (_cwd, env, miseAware) => {
				refreshes.push(miseAware);
				return { env: { ...env, FRESH: "1" }, source: "mise" };
			},
		});
		const result = runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			runtime,
		});
		expect(result.ok).toBe(true);
		expect(result.tools[0]).toMatchObject({
			status: "usable",
			resolvedPath: "/fresh/bin/jscpd",
		});
		expect(calls.some((argv) => argv.join(" ") === "mise use npm:jscpd")).toBe(
			true,
		);
		expect(
			calls.some((argv) => argv.join(" ") === "/fresh/bin/jscpd --version"),
		).toBe(true);
		expect(refreshes).toEqual([true]);
	});

	test("install fails when a successful manager command leaves a shim", () => {
		const runtime = fakeRuntime({
			resolveCommand: (bin, _cwd, env) => {
				if (bin === "jscpd")
					return env.FRESH === "1" ? "/fresh/.mise/shims/jscpd" : null;
				return `/fake/bin/${bin}`;
			},
			readLauncher: () => '#!/bin/sh\nexec mise x -- jscpd "$@"',
			run: (argv, _cwd, env, timeoutMs) => {
				if (argv[0] === "/fresh/.mise/shims/jscpd" && env.FRESH === "1") {
					return commandResult(argv, timeoutMs, {
						exitCode: 1,
						stderr: "inactive shim",
					});
				}
				return commandResult(argv, timeoutMs);
			},
		});
		const result = runSniffInstall({
			mode: "install",
			bundles: ["dup"],
			runtime,
		});
		expect(result.ok).toBe(false);
		expect(result.tools[0]?.status).toBe("shimmed");
	});

	test("install without bundles and unknown bundles fail", () => {
		expect(runSniffInstall({ mode: "install" }).ok).toBe(false);
		expect(
			runSniffInstall({ mode: "install", bundles: ["nope"] }).report,
		).toContain('unknown bundle "nope"');
	});

	test("prototype names are not bundle names", () => {
		for (const bundle of ["constructor", "toString", "__proto__"]) {
			expect(runSniffInstall({ mode: "install", bundles: [bundle] }).ok).toBe(
				false,
			);
		}
	});

	test("dry-run install prints commands without requiring success", () => {
		const dir = tempDir("sniff-dry-");
		const result = runSniffInstall({
			mode: "install",
			bundles: ["core"],
			dryRun: true,
			noMise: true,
			cwd: dir,
			runtime: fakeRuntime({
				resolveCommand: (bin) => (bin === "brew" ? "/fake/bin/brew" : null),
			}),
		});
		expect(result.ok).toBe(true);
		expect(result.report).toContain("(dry run — no changes will be made)");
		expect(result.report).toContain("[core]");
	});
	test("rejects empty PATH entries instead of resolving a host executable", () => {
		const dir = tempDir("sniff-empty-path-");
		const binDir = join(dir, "bin");
		executable(join(binDir, "semgrep"), "exit 0");
		const result = runSniffInstall({ mode: "probe", cwd: dir, env: { PATH: `${binDir}${delimiter}` } });
		expect(result.tools.find(({ tool }) => tool === "semgrep")?.status).toBe("missing");
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
				details: { ok: boolean; tools: Array<Record<string, unknown>> };
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
