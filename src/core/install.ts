import {
	accessSync,
	closeSync,
	constants,
	openSync,
	readSync,
	realpathSync,
	statSync,
} from "node:fs";
import { delimiter, isAbsolute, join, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import {
	type AnalyzerRunAuthorization,
	abandonAnalyzerReservation,
	authorizeAnalyzerRun,
	completeAnalyzerReservation,
	prepareAnalyzerSpawn,
} from "./run-registry.ts";
import {
	BUNDLES,
	type BundleName,
	TOOLS,
	type ToolRec,
} from "./catalog.ts";
const PROBE_TIMEOUT_MS = 1_500;
const INSTALL_TIMEOUT_MS = 300_000;
const ENV_REFRESH_TIMEOUT_MS = 10_000;
/** Maximum bytes retained from each subprocess output stream. */
export const COMMAND_OUTPUT_LIMIT_BYTES = 1_048_576;

export type SniffToolStatus =
	| "usable"
	| "missing"
	| "shimmed"
	| "unrunnable"
	| "project-local-required"
	| "installation-failed"
	| "timed-out"
	| "policy-blocked"
	| "unavailable-route";

export type CommandResult = {
	argv: string[];
	exitCode: number | null;
	stdout: string;
	stderr: string;
	stdoutTruncated: boolean;
	stderrTruncated: boolean;
	outputLimitBytes: number;
	timedOut: boolean;
	signalCode?: string;
	error?: string;
	timeoutMs: number;
};

export type ProbeAttempt = Pick<CommandResult, "argv" | "exitCode" | "stderr" | "timedOut" | "error" | "timeoutMs">;

export type SniffToolResult = {
	bundle: BundleName;
	tool: string;
	bin: string;
	required: boolean;
	status: SniffToolStatus;
	resolvedPath: string | null;
	remediation: string;
	attempts: ProbeAttempt[];
	install?: CommandResult;
};

type ProcessEnvironment = Record<string, string | undefined>;
type FreshEnvironment = { env: ProcessEnvironment; source: "process" | "mise"; error?: string };

export type SniffInstallRuntime = {
	resolveCommand(bin: string, cwd: string, env: ProcessEnvironment): string | null;
	readLauncher(path: string): string;
	run(argv: string[], cwd: string, env: ProcessEnvironment, timeoutMs: number, signal?: AbortSignal): Promise<CommandResult>;
	freshEnvironment(cwd: string, env: ProcessEnvironment, miseAware: boolean, signal?: AbortSignal): Promise<FreshEnvironment>;
	/** Host-owned neutral cwd used for mutating installs, never the probe target. */
	readonly neutralCwd?: string;
};
export type SniffInstallResult = {
	ok: boolean;
	report: string;
	tools: SniffToolResult[];
};


function timeoutError(err: unknown): boolean {
	const candidate = err as { code?: string; name?: string; message?: string };
	return candidate?.code === "ETIMEDOUT" || candidate?.name === "TimeoutError" || /\b(?:timed?\s*out|timeout)\b/i.test(candidate?.message ?? "");
}

async function readBounded(stream: ReadableStream<Uint8Array> | null): Promise<{ text: string; truncated: boolean }> {
	if (!stream) return { text: "", truncated: false };
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let retained = 0;
	let truncated = false;
	try {
		for (;;) {
			const next = await reader.read();
			if (next.done) break;
			const chunk = next.value;
			if (retained < COMMAND_OUTPUT_LIMIT_BYTES) {
				const end = Math.min(chunk.byteLength, COMMAND_OUTPUT_LIMIT_BYTES - retained);
				if (end > 0) chunks.push(chunk.slice(0, end));
				retained += end;
			}
			if (retained >= COMMAND_OUTPUT_LIMIT_BYTES && chunk.byteLength > 0) truncated = true;
		}
	} finally {
		reader.releaseLock();
	}
	const output = new Uint8Array(retained);
	let offset = 0;
	for (const chunk of chunks) {
		output.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return { text: Buffer.from(output).toString("utf8"), truncated };
}

function terminateProcess(proc: { pid: number; kill(signal?: "SIGTERM" | "SIGKILL"): void }, signal: "SIGTERM" | "SIGKILL"): void {
	try {
		process.kill(-proc.pid, signal);
	} catch {
		try {
			proc.kill(signal);
		} catch {
			// The child may have exited between timeout/cancellation and cleanup.
		}
	}
}

async function runCommand(argv: string[], cwd: string, env: ProcessEnvironment, timeoutMs: number, signal?: AbortSignal): Promise<CommandResult> {
	if (signal?.aborted) {
		return { argv, exitCode: null, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: COMMAND_OUTPUT_LIMIT_BYTES, timedOut: false, error: "operation aborted", timeoutMs };
	}
	const proc = Bun.spawn(argv, { cwd, env, stdout: "pipe", stderr: "pipe", stdin: "ignore", detached: true });
	let timedOut = false;
	let aborted = false;
	let forceKill: ReturnType<typeof setTimeout> | undefined;
	const stop = (reason: "timeout" | "abort") => {
		if (reason === "timeout") timedOut = true;
		if (reason === "abort") aborted = true;
		terminateProcess(proc, "SIGTERM");
		forceKill = setTimeout(() => terminateProcess(proc, "SIGKILL"), 100);
	};
	const timeout = setTimeout(() => stop("timeout"), timeoutMs);
	const onAbort = () => stop("abort");
	signal?.addEventListener("abort", onAbort, { once: true });
	const [stdout, stderr, exitCode] = await Promise.all([
		readBounded(proc.stdout as ReadableStream<Uint8Array>),
		readBounded(proc.stderr as ReadableStream<Uint8Array>),
		proc.exited,
	]);
	clearTimeout(timeout);
	if (forceKill) clearTimeout(forceKill);
	signal?.removeEventListener("abort", onAbort);
	return {
		argv,
		exitCode,
		stdout: stdout.text,
		stderr: stderr.text,
		stdoutTruncated: stdout.truncated,
		stderrTruncated: stderr.truncated,
		outputLimitBytes: COMMAND_OUTPUT_LIMIT_BYTES,
		timedOut,
		error: aborted ? "operation aborted" : undefined,
		signalCode: proc.signalCode ?? undefined,
		timeoutMs,
	};
}
function resolveCommand(
	bin: string,
	cwd: string,
	env: ProcessEnvironment,
): string | null {
	const pathEntries = (env.PATH ?? "").split(delimiter);
	if (!bin.includes(sep) && pathEntries.some((entry) => entry.length === 0 || !isAbsolute(entry))) return null;
	const candidates = bin.includes(sep)
		? [isAbsolute(bin) ? bin : resolve(cwd, bin)]
		: pathEntries.map((dir) => join(dir, bin));
	for (const candidate of candidates) {
		try {
			if (!statSync(candidate).isFile()) continue;
			accessSync(candidate, constants.X_OK);
			return realpathSync(candidate);
		} catch {
			// Not an executable candidate.
		}
	}
	return null;
}

function readLauncher(path: string): string {
	let fd: number | undefined;
	try {
		fd = openSync(realpathSync(path), "r");
		const buffer = Buffer.allocUnsafe(8_192);
		const length = readSync(fd, buffer, 0, buffer.length, 0);
		return buffer.subarray(0, length).toString("utf8");
	} catch {
		return "";
	} finally {
		if (fd !== undefined) closeSync(fd);
	}
}

const DEFAULT_RUNTIME: SniffInstallRuntime = {
	resolveCommand,
	readLauncher,
	run: runCommand,
	neutralCwd: tmpdir(),
	async freshEnvironment(cwd, env, miseAware, signal) {
		if (!miseAware) return { env: { ...env }, source: "process" };
		const result = await runCommand(["mise", "env", "--json"], cwd, env, ENV_REFRESH_TIMEOUT_MS, signal);
		if (result.exitCode !== 0 || result.timedOut || result.error) {
			const reason = result.timedOut
				? `mise env timed out after ${ENV_REFRESH_TIMEOUT_MS}ms`
				: result.stderr.trim() || result.error || `mise env exited ${result.exitCode}`;
			return { env: { ...env }, source: "process", error: reason };
		}
		try {
			const miseEnv = JSON.parse(result.stdout) as Record<string, string>;
			return { env: { ...env, ...miseEnv }, source: "mise" };
		} catch (err) {
			return { env: { ...env }, source: "process", error: `mise env returned invalid JSON: ${err instanceof Error ? err.message : String(err)}` };
		}
	},
};

function projectEnvironment(
	rec: ToolRec,
	cwd: string,
	env: ProcessEnvironment,
): ProcessEnvironment {
	if (rec.key !== "npm-local") return env;
	const localBin = join(cwd, "node_modules", ".bin");
	return { ...env, PATH: `${localBin}${delimiter}${env.PATH ?? ""}` };
}

function resolutionEnvironment(
	rec: ToolRec,
	cwd: string,
	env: ProcessEnvironment,
): ProcessEnvironment {
	if (rec.key !== "npm-local") return env;
	return { ...env, PATH: join(cwd, "node_modules", ".bin") };
}

function isShimLauncher(path: string, launcher: string): boolean {
	const normalized = path.split(sep).join("/");
	if (
		/\/(?:\.mise|\.asdf|\.pyenv|\.rbenv|share\/mise)\/shims\//.test(normalized)
	)
		return true;
	return /\bexec\s+(?:[^\s]+\/)?(?:mise|asdf|pyenv|rbenv)\b/i.test(launcher);
}

async function inspectTool(
	bundle: BundleName,
	rec: ToolRec,
	required: boolean,
	cwd: string,
	env: ProcessEnvironment,
	runtime: SniffInstallRuntime,
  validateResolvedPath?: (path: string) => string,
  signal?: AbortSignal,
): Promise<SniffToolResult> {
	const effectiveEnv = projectEnvironment(rec, cwd, env);
	const foundPath = runtime.resolveCommand(rec.bin, cwd, resolutionEnvironment(rec, cwd, env));
	let resolvedPath = foundPath;
	if (!resolvedPath) {
		return { bundle, tool: rec.name, bin: rec.bin, required, status: rec.key === "npm-local" ? "project-local-required" : "missing", resolvedPath: null, remediation: rec.hint, attempts: [] };
	}
	if (validateResolvedPath) {
		try {
			resolvedPath = validateResolvedPath(resolvedPath);
		} catch (error) {
			return { bundle, tool: rec.name, bin: rec.bin, required, status: "policy-blocked", resolvedPath: null, remediation: error instanceof Error ? error.message : String(error), attempts: [] };
		}
	}
	const launcher = runtime.readLauncher(resolvedPath);
	if (isShimLauncher(resolvedPath, launcher)) {
		return { bundle, tool: rec.name, bin: rec.bin, required, status: "shimmed", resolvedPath, remediation: rec.hint, attempts: [] };
	}
	const attempts: ProbeAttempt[] = [];
	const probeArgs = rec.probeArgs ?? [["--version"], ["--help"]];
	const probeTimeoutMs = rec.probeTimeoutMs ?? PROBE_TIMEOUT_MS;
	for (const args of probeArgs) {
		const result = await runtime.run([resolvedPath, ...args], cwd, effectiveEnv, probeTimeoutMs, signal);
		attempts.push({ argv: result.argv, exitCode: result.exitCode, stderr: result.stderr, timedOut: result.timedOut, error: result.error, timeoutMs: result.timeoutMs });
		if (result.exitCode === 0 && !result.timedOut && !result.error) {
			return { bundle, tool: rec.name, bin: rec.bin, required, status: "usable", resolvedPath, remediation: "", attempts };
		}
	}
	const status: SniffToolStatus = attempts.some((attempt) => attempt.timedOut) ? "timed-out" : "unrunnable";
	return { bundle, tool: rec.name, bin: rec.bin, required, status, resolvedPath, remediation: rec.hint, attempts };
}

function managerRoute(
	rec: ToolRec,
	preferMise: boolean,
	cwd: string,
	env: ProcessEnvironment,
	runtime: SniffInstallRuntime,
): string {
	if (rec.key === "npm-local") return "npm-local";
	if (preferMise) {
		if (rec.key === "cargo") return "mise-cargo";
		if (rec.key === "npm") return "mise-npm";
		if (rec.key === "pipx") return "mise-pipx";
		if (rec.key === "go" || rec.key === "brew") return "mise-reg";
	}
	const available = (bin: string): boolean =>
		runtime.resolveCommand(bin, cwd, env) !== null;
	switch (rec.key) {
		case "brew":
			return available("brew") ? "brew" : "";
		case "pipx":
			if (available("pipx")) return "pipx";
			if (available("uv")) return "uv-tool";
			return "";
		case "npm":
			return available("npm") ? "npm" : "";
		case "cargo":
			return available("cargo") ? "cargo" : "";
		case "go":
			return available("go") ? "go" : "";
		case "rustup":
			return available("rustup") ? "rustup" : "";
		default:
			return "";
	}
}

function installArgv(rec: ToolRec, manager: string): string[] | null {
	const pkg = rec.pkg ?? rec.name;
	const miseSpec = rec.miseSpec ?? rec.bin;
	switch (manager) {
		case "brew":
			return ["brew", "install", pkg];
		case "pipx":
			return ["pipx", "install", pkg];
		case "uv-tool":
			return ["uv", "tool", "install", pkg];
		case "npm":
			return ["npm", "install", "-g", pkg];
		case "cargo":
			return ["cargo", "install", pkg];
		case "go": {
			let goPath = miseSpec.startsWith("go:") ? miseSpec.slice(3) : miseSpec;
			if (!goPath.includes("@")) goPath = `${goPath}@latest`;
			return ["go", "install", goPath];
		}
		case "rustup":
			return ["rustup", "component", "add", "clippy"];
		case "mise-cargo":
			return ["mise", "use", `cargo:${pkg}`];
		case "mise-npm":
			return ["mise", "use", `npm:${pkg}`];
		case "mise-pipx":
			return ["mise", "use", `pipx:${pkg}`];
		case "mise-reg":
			return ["mise", "use", miseSpec];
		default:
			return null;
	}
}

function classifyInstallFailure(result: CommandResult): SniffToolStatus {
	if (result.timedOut) return "timed-out";
	const evidence = `${result.stderr}\n${result.stdout}\n${result.error ?? ""}`;
	if (
		/(?:trust|trusted|policy|signature|provenance|integrity|checksum).*(?:block|den|refus|downgrad|reject|fail)|(?:block|den|refus|reject).*(?:trust|policy|signature|provenance|integrity)/i.test(
			evidence,
		)
	) {
		return "policy-blocked";
	}
	if (
		/(?:unknown|invalid|unsupported|unavailable).*(?:backend|registry|route|plugin)|(?:backend|registry|route).*(?:not found|unavailable)|no versions? found|not available for (?:this|your) platform/i.test(
			evidence,
		)
	) {
		return "unavailable-route";
	}
	return "installation-failed";
}

function failedInstallResult(
	initial: SniffToolResult,
	status: SniffToolStatus,
	install?: CommandResult,
	remediation = initial.remediation,
): SniffToolResult {
	return { ...initial, status, remediation, install };
}

async function installOne(
	bundle: BundleName,
	rec: ToolRec,
	probeCwd: string,
	installCwd: string,
	preferMise: boolean,
	dryRun: boolean,
	env: ProcessEnvironment,
	runtime: SniffInstallRuntime,
	lines: string[],
	signal?: AbortSignal,
): Promise<SniffToolResult> {
	const initial = await inspectTool(bundle, rec, true, probeCwd, env, runtime);
	if (initial.status === "usable") {
		lines.push(`  = ${rec.name} already installed (${initial.resolvedPath})`);
		return initial;
	}
	if (rec.key === "npm-local") {
		lines.push(`  ! ${rec.name} is project-local — install inside the repo, not globally:`);
		lines.push(`      ${rec.hint}`);
		return initial;
	}
	const manager = managerRoute(rec, preferMise, installCwd, env, runtime);
	const argv = installArgv(rec, manager);
	if (!manager || !argv) {
		lines.push(`  ! ${rec.name}: no supported installation route — ${rec.hint}`);
		return failedInstallResult(initial, "unavailable-route");
	}
	lines.push(`  + ${argv.join(" ")} (timeout ${INSTALL_TIMEOUT_MS}ms)`);
	if (dryRun) return initial;
	const install = await runtime.run(argv, installCwd, env, INSTALL_TIMEOUT_MS, signal);
	if (install.stdout.trim()) lines.push(install.stdout.trimEnd());
	if (install.stderr.trim()) lines.push(install.stderr.trimEnd());
	if (install.stdoutTruncated || install.stderrTruncated) lines.push(`      (output truncated at ${install.outputLimitBytes} bytes per stream)`);
	if (install.exitCode !== 0 || install.timedOut || install.error) {
		const status = classifyInstallFailure(install);
		lines.push(`      (${status}${install.exitCode === null ? "" : ` — exit ${install.exitCode}`})`);
		return failedInstallResult(initial, status, install);
	}
	const fresh = await runtime.freshEnvironment(installCwd, env, preferMise, signal);
	if (fresh.error) {
		lines.push(`      (unavailable-route — fresh environment failed: ${fresh.error})`);
		return failedInstallResult(initial, "unavailable-route", install, `${fresh.error}; ${rec.hint}`);
	}
	const verified = await inspectTool(bundle, rec, true, probeCwd, fresh.env, runtime);
	verified.install = install;
	if (verified.status === "usable") lines.push(`      verified usable in fresh ${fresh.source} environment (${verified.resolvedPath})`);
	else lines.push(`      (${verified.status} after successful install; resolved=${verified.resolvedPath ?? "<unresolved>"})`);
	return verified;
}

function probeLabel(result: SniffToolResult): string {
	switch (result.status) {
		case "usable":
			return `  ok   ${result.tool}`;
		case "missing":
		case "project-local-required":
			return `  MISS ${result.tool}   — ${result.remediation}`;
		default:
			return `  SHIM ${result.tool}   — on PATH but not runnable; install to activate: ${result.remediation}`;
	}
}

function selectedBundles(
	opts: SniffInstallOptions,
	mode: "diagnose" | "install",
): BundleName[] | string {
	const targets = opts.all ? [...BUNDLES] : (opts.bundles ?? []);
	if (targets.length === 0) {
		return `sniff_install_tools: ${mode} needs at least one bundle name or all=true (known: ${BUNDLES.join(" ")})`;
	}
	for (const target of targets) {
		if (!Object.hasOwn(TOOLS, target))
			return `sniff: unknown bundle "${target}" (known: ${BUNDLES.join(" ")})`;
	}
	return [...new Set(targets)] as BundleName[];
}

export type SniffInstallMode = "probe" | "diagnose" | "list" | "install";

export type SniffInstallOptions = {
	mode?: SniffInstallMode;
	bundles?: string[];
	all?: boolean;
	dryRun?: boolean;
	noMise?: boolean;
	cwd?: string;
	env?: ProcessEnvironment;
	runtime?: SniffInstallRuntime;
	signal?: AbortSignal;
};

export type SniffAnalyzerRunOptions = {
	capability: string;
	manifestId: string;
	analyzer: string;
	runtime?: SniffInstallRuntime;
	signal?: AbortSignal;
};

export type SniffAnalyzerOutcome =
	| "completed"
	| "completed-with-findings"
	| "rejected-exit"
	| "not-run";

export type SniffAnalyzerRunResult = {
	ok: boolean;
	report: string;
	preflight: SniffToolResult | null;
	acceptedExitCodes?: number[];
	outcome: SniffAnalyzerOutcome;
	execution?: CommandResult;
};

function findTool(tool: string): { bundle: BundleName; rec: ToolRec } | null {
	for (const bundle of BUNDLES) {
		const rec = TOOLS[bundle].find((candidate) => candidate.name === tool);
		if (rec) return { bundle, rec };
	}
	return null;
}


function analyzerEnvironment(home: string): ProcessEnvironment {
	const env: ProcessEnvironment = {
		HOME: home,
		TMPDIR: home,
		NO_COLOR: "1",
	};
	for (const name of ["PATH", "LANG", "LC_ALL", "TZ"] as const) {
		if (process.env[name] !== undefined) env[name] = process.env[name];
	}
	return env;
}

function hostAnalyzerExecutable(path: string, targetRoot: string): string {
	if (!isAbsolute(path)) throw new Error("Analyzer executable did not resolve to an absolute host path");
	const executable = realpathSync(path);
	const root = realpathSync(targetRoot);
	const relation = relative(root, executable);
	if (relation === "" || (relation !== ".." && !relation.startsWith(`..${sep}`) && !isAbsolute(relation))) {
		throw new Error("Analyzer executable resolves inside the target root");
	}
	if (!statSync(executable).isFile()) throw new Error("Analyzer executable is not a file");
	accessSync(executable, constants.X_OK);
	return executable;
}

function validExitContract(codes: readonly number[]): boolean {
	return codes.length > 0 && codes.includes(0) && new Set(codes).size === codes.length && codes.every((code) => Number.isInteger(code) && code >= 0 && code <= 255);
}

export async function runSniffAnalyzer(opts: SniffAnalyzerRunOptions): Promise<SniffAnalyzerRunResult> {
	let authorization: AnalyzerRunAuthorization;
	try {
		authorization = authorizeAnalyzerRun(opts.capability, opts.manifestId, opts.analyzer);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return { ok: false, report: `sniff analyzer authorization blocked: ${message}`, preflight: null, outcome: "not-run" };
	}
	const runtime = opts.runtime ?? DEFAULT_RUNTIME;
	const abandon = () => {
		try {
			abandonAnalyzerReservation(opts.capability, opts.manifestId, opts.analyzer, authorization.reservationId);
		} catch {
			// Expiry or cancellation already released the reservation and its resources.
		}
	};
	const catalog = findTool(authorization.recipe.tool);
	if (!catalog) {
		abandon();
		return { ok: false, report: `sniff analyzer policy references unknown tool "${authorization.recipe.tool}"`, preflight: null, outcome: "not-run" };
	}
	const acceptedExitCodes = [...authorization.acceptedExitCodes];
	if (!validExitContract(acceptedExitCodes)) {
		abandon();
		return { ok: false, report: "sniff analyzer policy contains an invalid exit contract", preflight: null, acceptedExitCodes, outcome: "not-run" };
  }
  const env = analyzerEnvironment(authorization.home);
  const preflight = await inspectTool(catalog.bundle, catalog.rec, true, authorization.target.root, env, runtime, (path) => hostAnalyzerExecutable(path, authorization.target.root), opts.signal);
	if (preflight.status !== "usable" || !preflight.resolvedPath) {
		abandon();
		return { ok: false, report: `sniff analyzer preflight blocked ${authorization.recipe.tool}: ${preflight.status}; ${preflight.remediation}`, preflight, acceptedExitCodes, outcome: "not-run" };
	}
	const executable = preflight.resolvedPath;
	try {
		authorization = prepareAnalyzerSpawn(opts.capability, opts.manifestId, opts.analyzer, authorization.reservationId);
	} catch (error) {
		abandon();
		const message = error instanceof Error ? error.message : String(error);
		return { ok: false, report: `sniff analyzer launch blocked: ${message}`, preflight, acceptedExitCodes, outcome: "not-run" };
	}
	const argv = [executable, ...(catalog.rec.runPrefix ?? []), ...authorization.argv];
	const timeoutMs = Math.min(INSTALL_TIMEOUT_MS, authorization.remainingBudgetMs);
	let execution: CommandResult;
	let completionError: string | undefined;
	try {
		execution = await runtime.run(argv, authorization.target.root, env, timeoutMs, opts.signal);
	} catch (error) {
		execution = { argv, exitCode: null, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes: COMMAND_OUTPUT_LIMIT_BYTES, timedOut: false, error: error instanceof Error ? error.message : String(error), timeoutMs };
	}
	try {
		completeAnalyzerReservation(opts.capability, opts.manifestId, opts.analyzer, authorization.reservationId);
	} catch (error) {
		completionError = error instanceof Error ? error.message : String(error);
	}
	const completed = !completionError && !execution.timedOut && !execution.error && execution.exitCode !== null;
	const accepted = completed && acceptedExitCodes.includes(execution.exitCode as number);
	const outcome: SniffAnalyzerOutcome = accepted ? execution.exitCode === 0 ? "completed" : "completed-with-findings" : completed ? "rejected-exit" : "not-run";
	return {
		ok: accepted,
		report: accepted
			? `sniff analyzer ran ${opts.analyzer} with its issued fixed recipe (exit ${execution.exitCode})`
			: completed
				? `sniff analyzer rejected ${opts.analyzer}: exit ${execution.exitCode} is outside [${acceptedExitCodes.join(", ")}]`
				: `sniff analyzer could not run ${opts.analyzer}: ${completionError ?? execution.error ?? (execution.timedOut ? "timed out" : "no exit status")}`,
		preflight,
		acceptedExitCodes,
		outcome,
		execution,
	};
}
export async function runSniffInstall(opts: SniffInstallOptions): Promise<SniffInstallResult> {
	if (opts.signal?.aborted) return { ok: false, report: "operation aborted", tools: [] };
	const mode: SniffInstallMode = opts.mode ?? "probe";
	const probeCwd = opts.cwd ?? process.cwd();
	const env = { ...process.env, ...opts.env };
	const runtime = opts.runtime ?? DEFAULT_RUNTIME;
	const installCwd = runtime.neutralCwd ?? tmpdir();
	const preferMise = !opts.noMise && runtime.resolveCommand("mise", installCwd, env) !== null;
	const lines: string[] = [];
	const tools: SniffToolResult[] = [];
	if (mode === "probe") {
		lines.push("sniff tool probe (all tools optional; missing ones are skipped, not fatal)");
		for (const bundle of BUNDLES) {
			lines.push("", `[${bundle}]`);
			const bundleResults: SniffToolResult[] = [];
			for (const rec of TOOLS[bundle]) bundleResults.push(await inspectTool(bundle, rec, false, probeCwd, env, runtime));
			tools.push(...bundleResults);
			for (const result of bundleResults) lines.push(probeLabel(result));
			const counts = new Map<SniffToolStatus, number>();
			for (const result of bundleResults) counts.set(result.status, (counts.get(result.status) ?? 0) + 1);
			lines.push(`  (${[...counts].map(([status, count]) => `${count} ${status}`).join(", ")})`);
		}
		lines.push("", "Install a bundle with: sniff_install_tools mode=install bundles=[<bundle>]");
		return { ok: true, report: lines.join("\n"), tools };
	}
	if (mode === "list") {
		for (const bundle of BUNDLES) {
			lines.push("", `[${bundle}]`);
			for (const rec of TOOLS[bundle]) {
				const hostPackages = "hostPackages" in rec ? rec.hostPackages : [];
				const hosted = hostPackages.length ? ` [host packages: ${hostPackages.join(", ")}]` : "";
				lines.push(`  ${rec.name.padEnd(18)} ${rec.hint}${hosted}`);
			}
		}
		return { ok: true, report: lines.join("\n"), tools };
	}
	const selected = selectedBundles(opts, mode);
	if (typeof selected === "string") return { ok: false, report: selected, tools };
	if (mode === "diagnose") {
		lines.push("sniff bundle diagnostics (inventory only; does not authorize analyzer execution)");
		for (const bundle of selected) {
			lines.push("", `[${bundle}]`);
			for (const rec of TOOLS[bundle]) {
				const result = await inspectTool(bundle, rec, true, probeCwd, env, runtime);
				tools.push(result);
				lines.push(`  ${result.status.padEnd(22)} ${result.tool} path=${result.resolvedPath ?? "<unresolved>"}${result.status === "usable" ? "" : ` — ${result.remediation}`}`);
			}
		}
		const failures = tools.filter((result) => result.status !== "usable");
		lines.push("", `diagnose: ${tools.length - failures.length} usable, ${failures.length} unavailable catalog entry/entries; use sniff_run_analyzer for authoritative per-run preflight`);
		return { ok: failures.length === 0, report: lines.join("\n"), tools };
	}
	if (opts.dryRun) lines.push("(dry run — no changes will be made)");
	for (const bundle of selected) {
		lines.push("", `[${bundle}]`);
		for (const rec of TOOLS[bundle]) tools.push(await installOne(bundle, rec, probeCwd, installCwd, preferMise, Boolean(opts.dryRun), env, runtime, lines, opts.signal));
	}
	const failures = tools.filter((result) => result.status !== "usable");
	if (opts.dryRun) {
		lines.push("", "Dry run complete; no tool state changed.");
		return { ok: true, report: lines.join("\n"), tools };
	}
	lines.push("", `install: ${tools.length - failures.length} usable, ${failures.length} failure(s) after verification`);
	return { ok: failures.length === 0, report: lines.join("\n"), tools };
}

