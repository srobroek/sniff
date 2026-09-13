import {
	accessSync,
	closeSync,
	constants,
	existsSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readSync,
	realpathSync,
	renameSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { type AnalyzerArtifactDescriptor, type AnalyzerObservationPreview, createAnalyzerArtifacts, projectAnalyzerObservations, publicAnalyzerDescriptors, registerAnalyzerArtifacts } from "./analyzer-artifact-registry.ts";
import { type AnalyzerCapture, type AnalyzerObservation, parseAnalyzerOutput } from "./analyzer-output.ts";
import {
	BUNDLES,
	type BundleName,
	TOOLS,
	type ToolRec,
} from "./catalog.ts";
import { OPENGREP_MAX_OUTPUT_BYTES, type OpenGrepProvisionResult, parseOpenGrepOutput, provisionOpenGrep, resolveOpenGrepExecutable } from "./opengrep.ts";
import {
	type AnalyzerRunAuthorization,
	abandonAnalyzerReservation,
	authorizeAnalyzerRun,
	completeAnalyzerReservation,
	prepareAnalyzerSpawn,
} from "./run-registry.ts";

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
	run(argv: string[], cwd: string, env: ProcessEnvironment, timeoutMs: number, signal?: AbortSignal, outputLimitBytes?: number): Promise<CommandResult>;
	freshEnvironment(cwd: string, env: ProcessEnvironment, miseAware: boolean, signal?: AbortSignal): Promise<FreshEnvironment>;
	resolveOpenGrep(cacheDir?: string): string | null;
	provisionOpenGrep(options: { cacheDir?: string; signal?: AbortSignal }): Promise<OpenGrepProvisionResult>;
	/** Host-owned neutral cwd used for mutating installs, never the probe target. */
	readonly neutralCwd?: string;
	/** Optional test seam for Sniff-owned toolkit storage. */
	readonly toolkitCacheRoot?: string;
};
export type SniffInstallResult = {
	ok: boolean;
	report: string;
	tools: SniffToolResult[];
};


async function readBounded(stream: ReadableStream<Uint8Array> | null, outputLimitBytes = COMMAND_OUTPUT_LIMIT_BYTES): Promise<{ text: string; truncated: boolean }> {
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
			if (retained < outputLimitBytes) {
				const end = Math.min(chunk.byteLength, outputLimitBytes - retained);
				if (end > 0) chunks.push(chunk.slice(0, end));
				retained += end;
			}
			if (retained >= outputLimitBytes && chunk.byteLength > 0) truncated = true;
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

async function runCommand(argv: string[], cwd: string, env: ProcessEnvironment, timeoutMs: number, signal?: AbortSignal, outputLimitBytes = COMMAND_OUTPUT_LIMIT_BYTES): Promise<CommandResult> {
	if (signal?.aborted) {
		return { argv, exitCode: null, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes, timedOut: false, error: "operation aborted", timeoutMs };
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
		readBounded(proc.stdout as ReadableStream<Uint8Array>, outputLimitBytes),
		readBounded(proc.stderr as ReadableStream<Uint8Array>, outputLimitBytes),
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
		outputLimitBytes,
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
			const resolved = realpathSync(candidate);
			return basename(resolved) === "rustup" && basename(candidate) !== "rustup" ? candidate : resolved;
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
	resolveOpenGrep: (cacheDir) => resolveOpenGrepExecutable({ cacheDir }),
	provisionOpenGrep,
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

type InspectToolAuthorization = (path: string) => string;

async function inspectTool(
	bundle: BundleName,
	rec: ToolRec,
	required: boolean,
	cwd: string,
	env: ProcessEnvironment,
	runtime: SniffInstallRuntime,
	validateResolvedPath?: InspectToolAuthorization,
	signal?: AbortSignal,
	allowAuthorizedProjectLocalProbe = false,
): Promise<SniffToolResult> {
	const effectiveEnv = projectEnvironment(rec, cwd, env);
	let foundPath: string | null;
	try {
		foundPath = rec.name === "opengrep"
			? runtime.resolveOpenGrep(env.SNIFF_OPENGREP_CACHE_DIR)
			: runtime.resolveCommand(rec.bin, cwd, resolutionEnvironment(rec, cwd, env));
	} catch (error) {
		return { bundle, tool: rec.name, bin: rec.bin, required, status: "policy-blocked", resolvedPath: null, remediation: error instanceof Error ? error.message : String(error), attempts: [] };
	}
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
  if (rec.key === "npm-local" && !allowAuthorizedProjectLocalProbe) {
    return {
      bundle,
      tool: rec.name,
      bin: rec.bin,
      required,
      status: "policy-blocked",
      resolvedPath,
      remediation: `project-local launcher found at ${resolvedPath}; inventory does not execute project code. Run sniff_run_analyzer after capability authorization, or ${rec.hint}`,
      attempts: [],
    };
  }
  const launcher = runtime.readLauncher(resolvedPath);
  if (isShimLauncher(resolvedPath, launcher)) {
    return { bundle, tool: rec.name, bin: rec.bin, required, status: "shimmed", resolvedPath, remediation: rec.hint, attempts: [] };
  }
  const attempts: ProbeAttempt[] = [];
  const probeArgs = rec.probeArgs ?? [["--version"], ["--help"]];
  const probeTimeoutMs = rec.probeTimeoutMs ?? PROBE_TIMEOUT_MS;
  const executionCwd = allowAuthorizedProjectLocalProbe && (rec.key === "npm-local" || rec.key === "rustup" || rec.key === "cargo") ? cwd : tmpdir();
  for (const args of probeArgs) {
    const result = await runtime.run([resolvedPath, ...args], executionCwd, effectiveEnv, probeTimeoutMs, signal);
    attempts.push({ argv: result.argv, exitCode: result.exitCode, stderr: result.stderr, timedOut: result.timedOut, error: result.error, timeoutMs: result.timeoutMs });
    if (result.exitCode === 0 && !result.timedOut && !result.error) {
      return { bundle, tool: rec.name, bin: rec.bin, required, status: "usable", resolvedPath, remediation: "", attempts };
    }
  }
  const status: SniffToolStatus = attempts.some((attempt) => attempt.timedOut) ? "timed-out" : "unrunnable";
  return { bundle, tool: rec.name, bin: rec.bin, required, status, resolvedPath, remediation: rec.hint, attempts };
}

function isMiseManaged(rec: ToolRec): boolean {
	return rec.key === "brew" || rec.key === "pipx" || rec.key === "npm" || rec.key === "cargo" || rec.key === "go";
}

function isolatedRustupEnvironment(directory: string, env: ProcessEnvironment): ProcessEnvironment {
	const cargoHome = join(directory, ".cargo");
	const cargoBin = join(cargoHome, "bin");
	const path = env.PATH ?? "";
	return {
		...env,
		CARGO_HOME: cargoHome,
		PATH: path.split(delimiter).includes(cargoBin) ? path : [cargoBin, path].filter(Boolean).join(delimiter),
		RUSTUP_HOME: join(directory, ".rustup"),
		RUSTUP_TOOLCHAIN: "",
	};
}
function usesToolkitEnvironment(rec: ToolRec): boolean {
	return isMiseManaged(rec) || rec.key === "rustup";
}

function environmentForTool(
	bundle: BundleName,
	rec: ToolRec,
	toolkit: FreshEnvironment,
	processEnvironment: ProcessEnvironment,
	runtime: SniffInstallRuntime,
): ProcessEnvironment {
	const directory = toolkitDirectory(bundle, processEnvironment, runtime);
	let environment = rec.key === "rustup"
		? isolatedRustupEnvironment(directory, toolkit.env)
		: isMiseManaged(rec) ? toolkit.env : processEnvironment;
	if (bundle !== "rust" || (rec.key !== "rustup" && rec.key !== "cargo")) return environment;
	environment = isolatedRustupEnvironment(directory, environment);
	delete environment.RUSTUP_TOOLCHAIN;
	return environment;
}

function miseToolSpec(rec: ToolRec): string | null {
	const pkg = rec.pkg ?? rec.name;
	switch (rec.key) {
		case "cargo":
			return `cargo:${pkg}`;
		case "npm":
			return `npm:${pkg}`;
		case "pipx":
			return `pipx:${pkg}`;
		case "go":
		case "brew":
			return rec.miseSpec ?? rec.bin;
		default:
			return null;
	}
}

export function resolveSniffToolkitCacheRoot(env: Record<string, string | undefined> = process.env, runtime?: SniffInstallRuntime): string {
	return runtime?.toolkitCacheRoot ?? env.SNIFF_TOOLKIT_CACHE_DIR ?? join(env.XDG_CACHE_HOME ?? join(env.HOME ?? homedir(), ".cache"), "sniff", "toolkits");
}

function toolkitDirectory(bundle: BundleName, env: ProcessEnvironment, runtime?: SniffInstallRuntime): string {
	return join(resolveSniffToolkitCacheRoot(env, runtime), bundle);
}

function toolkitConfigPath(bundle: BundleName, env: ProcessEnvironment, runtime?: SniffInstallRuntime): string {
	return join(toolkitDirectory(bundle, env, runtime), "mise.toml");
}

function isolatedMiseEnvironment(directory: string, env: ProcessEnvironment, miseHome?: string): ProcessEnvironment {
	return isolatedRustupEnvironment(directory, {
		...env,
		...(miseHome ? { HOME: miseHome } : {}),
		MISE_CONFIG_DIR: join(directory, ".mise-config"),
		MISE_GLOBAL_CONFIG_FILE: join(directory, ".global-config-disabled.toml"),
		MISE_SYSTEM_CONFIG_FILE: join(directory, ".system-config-disabled.toml"),
		MISE_AUTO_INSTALL: "0",
		MISE_CEILING_PATHS: dirname(directory),
		RUSTC_WRAPPER: "",
		RUSTC_WORKSPACE_WRAPPER: "",
		CARGO_BUILD_RUSTC_WRAPPER: "",
		CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER: "",
	});
}

export function renderMiseToolkit(bundle: BundleName): string {
	const records = TOOLS[bundle];
	const specs = records
		.map(miseToolSpec)
		.filter((spec): spec is string => spec !== null);
	const runtimeEntries = [
		...(records.some((rec) => rec.key === "npm") ? ['"node" = "lts"'] : []),
		...(specs.some((spec) => spec.startsWith("go:")) ? ['"go" = "latest"'] : []),
		...(records.some((rec) => rec.key === "cargo") ? ['"rust" = "stable"'] : []),
	];
	return ["# Generated by Sniff. Do not edit.", "[tools]", ...runtimeEntries, ...[...new Set(specs)].sort().map((spec) => `${JSON.stringify(spec)} = "latest"`), ""].join("\n");
}

function writeMiseToolkit(bundle: BundleName, env: ProcessEnvironment, runtime: SniffInstallRuntime): string {
	const directory = toolkitDirectory(bundle, env, runtime);
	mkdirSync(directory, { recursive: true });
	const temporaryDirectory = mkdtempSync(join(directory, ".write-"));
	const temporaryPath = join(temporaryDirectory, "mise.toml");
	const destination = toolkitConfigPath(bundle, env, runtime);
	try {
		writeFileSync(temporaryPath, renderMiseToolkit(bundle));
		renameSync(temporaryPath, destination);
	} finally {
		rmSync(temporaryDirectory, { recursive: true, force: true });
	}
	return directory;
}

async function toolkitEnvironment(
	bundle: BundleName,
	env: ProcessEnvironment,
	runtime: SniffInstallRuntime,
	signal?: AbortSignal,
	miseHome?: string,
): Promise<FreshEnvironment> {
	const directory = toolkitDirectory(bundle, env, runtime);
	if (!existsSync(toolkitConfigPath(bundle, env, runtime))) return { env: { ...env }, source: "process" };
	const miseEnvironment = isolatedMiseEnvironment(directory, env, miseHome);
	if (!runtime.resolveCommand("mise", directory, miseEnvironment)) {
		return { env: { ...env }, source: "process", error: `mise is required to load the Sniff toolkit at ${directory}` };
	}
	const fresh = await runtime.freshEnvironment(directory, miseEnvironment, true, signal);
	if (fresh.error) return fresh;
	const binDirectories = new Set<string>();
	for (const rec of TOOLS[bundle]) {
		if (!isMiseManaged(rec)) continue;
		const which = await runtime.run(["mise", "which", rec.bin], directory, miseEnvironment, ENV_REFRESH_TIMEOUT_MS, signal);
		const executable = which.stdout.trim();
		if (which.exitCode === 0 && !which.timedOut && !which.error && isAbsolute(executable)) binDirectories.add(dirname(executable));
	}
	const refreshedEnvironment: ProcessEnvironment = { ...fresh.env, HOME: env.HOME, TMPDIR: env.TMPDIR };
	return {
		...fresh,
		env: { ...refreshedEnvironment, PATH: [...binDirectories, refreshedEnvironment.PATH ?? ""].filter(Boolean).join(delimiter) },
	};
}

function toolkitUnavailableResult(bundle: BundleName, rec: ToolRec, required: boolean, remediation: string): SniffToolResult {
	return { bundle, tool: rec.name, bin: rec.bin, required, status: "unavailable-route", resolvedPath: null, remediation, attempts: [] };
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

async function ensureRustToolchain(
	rustupPath: string,
	channel: "stable" | "nightly",
	makeDefault: boolean,
	directory: string,
	env: ProcessEnvironment,
	runtime: SniffInstallRuntime,
	lines: string[],
	signal?: AbortSignal,
): Promise<CommandResult | null> {
	const bootstrapEnvironment = { ...env, RUSTUP_TOOLCHAIN: channel };
	const listed = await runtime.run([rustupPath, "toolchain", "list"], directory, bootstrapEnvironment, PROBE_TIMEOUT_MS, signal);
	const installedLine = listed.exitCode === 0 && !listed.timedOut && !listed.error
		? listed.stdout.split("\n").find((line) => line.trim() === channel || line.trim().startsWith(`${channel}-`) || line.trim().startsWith(`${channel} `))
		: undefined;
	const usable = installedLine
		? await runtime.run([rustupPath, "run", channel, "rustc", "--version"], directory, bootstrapEnvironment, PROBE_TIMEOUT_MS, signal)
		: undefined;
	if (!installedLine || !usable || usable.exitCode !== 0 || usable.timedOut || usable.error) {
		const argv = [rustupPath, "toolchain", "install", channel, "--profile", "minimal", "--no-self-update"];
		lines.push(`  + ${argv.join(" ")} (timeout ${INSTALL_TIMEOUT_MS}ms)`);
		const installed = await runtime.run(argv, directory, bootstrapEnvironment, INSTALL_TIMEOUT_MS, signal);
		if (installed.stdout.trim()) lines.push(installed.stdout.trimEnd());
		if (installed.stderr.trim()) lines.push(installed.stderr.trimEnd());
		if (installed.stdoutTruncated || installed.stderrTruncated) lines.push(`      (output truncated at ${installed.outputLimitBytes} bytes per stream)`);
		if (installed.exitCode !== 0 || installed.timedOut || installed.error) return installed;
	}
	if (!makeDefault || installedLine?.includes("default")) return null;
	const defaultArgv = [rustupPath, "default", channel];
	lines.push(`  + ${defaultArgv.join(" ")} (timeout ${INSTALL_TIMEOUT_MS}ms)`);
	const selected = await runtime.run(defaultArgv, directory, bootstrapEnvironment, INSTALL_TIMEOUT_MS, signal);
	if (selected.stdout.trim()) lines.push(selected.stdout.trimEnd());
	if (selected.stderr.trim()) lines.push(selected.stderr.trimEnd());
	if (selected.stdoutTruncated || selected.stderrTruncated) lines.push(`      (output truncated at ${selected.outputLimitBytes} bytes per stream)`);
	return selected.exitCode !== 0 || selected.timedOut || selected.error ? selected : null;
}

async function installUnmanagedTool(
	bundle: BundleName,
	rec: ToolRec,
	probeCwd: string,
	installCwd: string,
	dryRun: boolean,
	env: ProcessEnvironment,
	runtime: SniffInstallRuntime,
	lines: string[],
	signal?: AbortSignal,
	deferDryRunPlan = false,
): Promise<SniffToolResult> {
	const environment = rec.key === "rustup"
		? await toolkitEnvironment(bundle, env, runtime, signal)
		: { env, source: "process" as const };
	if (environment.error) {
		const result = toolkitUnavailableResult(bundle, rec, true, environment.error);
		lines.push(`  ! ${rec.name}: ${result.status} — ${result.remediation}`);
		return result;
	}
	const installEnvironment = environmentForTool(bundle, rec, environment, env, runtime);
	const initial = await inspectTool(bundle, rec, true, probeCwd, installEnvironment, runtime);
	if (initial.status === "usable") {
		lines.push(`  = ${rec.name} already installed (${initial.resolvedPath})`);
		return initial;
	}
	if (rec.key === "npm-local") {
		lines.push(`  ! ${rec.name} is project-local — install inside the repo, not globally:`);
		lines.push(`      ${rec.hint}`);
		return initial;
	}
	if (rec.name === "opengrep") {
		if (dryRun) {
			lines.push("  + download official OpenGrep v1.30.0 asset (timeout 120000ms)");
			return initial;
		}
		try {
			const provisioned = await runtime.provisionOpenGrep({ cacheDir: env.SNIFF_OPENGREP_CACHE_DIR, signal });
			lines.push(`  + OpenGrep ${provisioned.reused ? "reused verified cache" : "downloaded and cached"} (${provisioned.path})`);
			const verifiedResult = await inspectTool(bundle, rec, true, probeCwd, env, runtime);
			if (verifiedResult.status === "usable") return verifiedResult;
			return failedInstallResult(verifiedResult, "installation-failed", undefined, verifiedResult.remediation || "OpenGrep cache verification failed");
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			lines.push(`      (installation-failed — ${message})`);
			return failedInstallResult(initial, "installation-failed", undefined, message);
		}
	}
	const rustupPath = rec.key === "rustup" ? runtime.resolveCommand("rustup", probeCwd, installEnvironment) : null;
	if (!rustupPath) {
		if (dryRun && deferDryRunPlan) return initial;
		lines.push(`  ! ${rec.name}: no supported installation route — ${rec.hint}`);
		return failedInstallResult(initial, "unavailable-route");
	}
	const argv = [rustupPath, "component", "add", "clippy"];
	if (dryRun && deferDryRunPlan) return initial;
	if (dryRun) {
		lines.push(`  + ${rustupPath} toolchain install stable --profile minimal --no-self-update (if missing)`);
		lines.push(`  + ${rustupPath} default stable (if not default)`);
		lines.push(`  + ${argv.join(" ")} (timeout ${INSTALL_TIMEOUT_MS}ms)`);
		return initial;
	}
	const bootstrapFailure = await ensureRustToolchain(rustupPath, "stable", true, installCwd, installEnvironment, runtime, lines, signal);
	if (bootstrapFailure) {
		const status = classifyInstallFailure(bootstrapFailure);
		lines.push(`      (${status}${bootstrapFailure.exitCode === null ? "" : ` — exit ${bootstrapFailure.exitCode}`})`);
		return failedInstallResult(initial, status, bootstrapFailure, "isolated stable Rust toolchain bootstrap failed");
	}
	lines.push(`  + ${argv.join(" ")} (timeout ${INSTALL_TIMEOUT_MS}ms)`);
	const install = await runtime.run(argv, probeCwd, installEnvironment, INSTALL_TIMEOUT_MS, signal);
	if (install.stdout.trim()) lines.push(install.stdout.trimEnd());
	if (install.stderr.trim()) lines.push(install.stderr.trimEnd());
	if (install.stdoutTruncated || install.stderrTruncated) lines.push(`      (output truncated at ${install.outputLimitBytes} bytes per stream)`);
	if (install.exitCode !== 0 || install.timedOut || install.error) {
		const status = classifyInstallFailure(install);
		lines.push(`      (${status}${install.exitCode === null ? "" : ` — exit ${install.exitCode}`})`);
		return failedInstallResult(initial, status, install);
	}
	const verified = await inspectTool(bundle, rec, true, probeCwd, installEnvironment, runtime, undefined, signal, true);
	lines.push(verified.status === "usable"
		? `      verified ${rec.name} in target toolchain (${verified.resolvedPath})`
		: `      (${rec.name}: ${verified.status} after component install; resolved=${verified.resolvedPath ?? "<unresolved>"})`);
	verified.install = install;
	return verified;
}

function hasRustToolchainPin(target: string): boolean {
	let directory = resolve(target);
	for (;;) {
		if (existsSync(join(directory, "rust-toolchain.toml")) || existsSync(join(directory, "rust-toolchain"))) return true;
		const parent = dirname(directory);
		if (parent === directory) return false;
		directory = parent;
	}
}

type RustPreparationResult = {
	status: SniffToolStatus;
	remediation: string;
	install?: CommandResult;
};

async function prepareRustTargetToolchain(
	probeCwd: string,
	directory: string,
	env: ProcessEnvironment,
	runtime: SniffInstallRuntime,
	lines: string[],
	signal?: AbortSignal,
): Promise<RustPreparationResult | null> {
	const toolkit = await toolkitEnvironment("rust", env, runtime, signal);
	if (toolkit.error) {
		return {
			status: "unavailable-route",
			remediation: `managed Rust toolkit environment was unavailable: ${toolkit.error}`,
		};
	}
	const selectedCargo = await runtime.run(["mise", "which", "cargo"], directory, toolkit.env, ENV_REFRESH_TIMEOUT_MS, signal);
	const cargoPaths = selectedCargo.stdout.split(/\r?\n/).map((path) => path.trim()).filter(Boolean);
	const cargoPath = cargoPaths.length === 1 ? cargoPaths[0] : undefined;
	if (selectedCargo.exitCode !== 0 || selectedCargo.timedOut || selectedCargo.error || !cargoPath || !isAbsolute(cargoPath)) {
		const status = selectedCargo.exitCode !== 0 || selectedCargo.timedOut || selectedCargo.error
			? classifyInstallFailure(selectedCargo)
			: "unavailable-route";
		return {
			status,
			remediation: `managed Cargo was not uniquely resolved by the Rust toolkit at ${directory}`,
			install: selectedCargo,
		};
	}
	const cargoEnvironment = isolatedRustupEnvironment(directory, toolkit.env);
	delete cargoEnvironment.RUSTUP_TOOLCHAIN;
	const argv = [cargoPath, "--version"];
	lines.push(`  + ${argv.join(" ")} (timeout ${INSTALL_TIMEOUT_MS}ms)`);
	const prepared = await runtime.run(argv, probeCwd, cargoEnvironment, INSTALL_TIMEOUT_MS, signal);
	if (prepared.stdout.trim()) lines.push(prepared.stdout.trimEnd());
	if (prepared.stderr.trim()) lines.push(prepared.stderr.trimEnd());
	if (prepared.stdoutTruncated || prepared.stderrTruncated) lines.push(`      (output truncated at ${prepared.outputLimitBytes} bytes per stream)`);
	if (prepared.exitCode !== 0 || prepared.timedOut || prepared.error) {
		return {
			status: classifyInstallFailure(prepared),
			remediation: "target-selected Rust toolchain preparation failed",
			install: prepared,
		};
	}
	return null;
}

type MiseBundleInstallResult = {
	results: SniffToolResult[];
	preparationFailure?: RustPreparationResult;
};

async function installMiseBundle(
	bundle: BundleName,
	records: ToolRec[],
	probeCwd: string,
	dryRun: boolean,
	env: ProcessEnvironment,
	runtime: SniffInstallRuntime,
	lines: string[],
	signal?: AbortSignal,
	prepareVerification?: () => Promise<void>,
): Promise<MiseBundleInstallResult> {
	const initialEnvironment = await toolkitEnvironment(bundle, env, runtime, signal);
	const initial: SniffToolResult[] = [];
	for (const rec of records) {
		initial.push(await inspectTool(bundle, rec, true, probeCwd, environmentForTool(bundle, rec, initialEnvironment, env, runtime), runtime));
	}
	const directory = toolkitDirectory(bundle, env, runtime);
	lines.push(`  + Sniff mise toolkit ${directory}`);
	if (dryRun) {
		const rustupPath = runtime.resolveCommand("rustup", directory, isolatedMiseEnvironment(directory, env)) ?? "rustup";
		if (records.some((rec) => rec.key === "cargo")) {
			lines.push(`  + ${rustupPath} toolchain install stable --profile minimal --no-self-update (if missing)`);
			lines.push(`  + ${rustupPath} default stable (if not default)`);
		}
		if (records.some((rec) => rec.name === "cargo-udeps")) lines.push(`  + ${rustupPath} toolchain install nightly --profile minimal --no-self-update (if missing)`);
		lines.push(`  + mise install (timeout ${INSTALL_TIMEOUT_MS}ms)`);
		return { results: initial };
	}
	const miseEnvironment = isolatedMiseEnvironment(directory, env);
	if (!runtime.resolveCommand("mise", directory, miseEnvironment)) {
		const remediation = `mise is required to install the Sniff-managed ${bundle} toolkit`;
		lines.push(`      (unavailable-route — ${remediation})`);
		return { results: initial.map((result) => failedInstallResult(result, "unavailable-route", undefined, remediation)) };
	}
	writeMiseToolkit(bundle, env, runtime);
	if (records.some((rec) => rec.key === "cargo")) {
		const rustupPath = runtime.resolveCommand("rustup", directory, miseEnvironment);
		if (rustupPath) {
			const requiredToolchains: Array<{ channel: "stable" | "nightly"; makeDefault: boolean }> = [
				{ channel: "stable", makeDefault: true },
				...(records.some((rec) => rec.name === "cargo-udeps") ? [{ channel: "nightly" as const, makeDefault: false }] : []),
			];
			for (const { channel, makeDefault } of requiredToolchains) {
				const bootstrapFailure = await ensureRustToolchain(rustupPath, channel, makeDefault, directory, miseEnvironment, runtime, lines, signal);
				if (!bootstrapFailure) continue;
				const status = classifyInstallFailure(bootstrapFailure);
				lines.push(`      (${status}${bootstrapFailure.exitCode === null ? "" : ` — exit ${bootstrapFailure.exitCode}`})`);
				return { results: initial.map((result) => failedInstallResult(result, status, bootstrapFailure, `isolated ${channel} Rust toolchain bootstrap failed`)) };
			}
		}
	}
	lines.push(`  + mise install (timeout ${INSTALL_TIMEOUT_MS}ms)`);
	const install = await runtime.run(["mise", "install"], directory, miseEnvironment, INSTALL_TIMEOUT_MS, signal);
	if (install.stdout.trim()) lines.push(install.stdout.trimEnd());
	if (install.stderr.trim()) lines.push(install.stderr.trimEnd());
	if (install.stdoutTruncated || install.stderrTruncated) lines.push(`      (output truncated at ${install.outputLimitBytes} bytes per stream)`);
	const installStatus = install.exitCode !== 0 || install.timedOut || install.error
		? classifyInstallFailure(install)
		: undefined;
	if (!installStatus && bundle === "rust" && hasRustToolchainPin(probeCwd)) {
		const preparation = await prepareRustTargetToolchain(probeCwd, directory, env, runtime, lines, signal);
		if (preparation) {
			lines.push(`      (${preparation.status}${preparation.install?.exitCode === null || preparation.install === undefined ? "" : ` — exit ${preparation.install.exitCode}`})`);
			return {
				results: initial.map((result) => failedInstallResult(result, preparation.status, preparation.install, preparation.remediation)),
				preparationFailure: preparation,
			};
		}
	}
	if (!installStatus && records.some((rec) => rec.name === "cargo-udeps")) {
		const rustupPath = runtime.resolveCommand("rustup", directory, miseEnvironment);
		if (rustupPath) {
			const bootstrapFailure = await ensureRustToolchain(rustupPath, "nightly", false, directory, miseEnvironment, runtime, lines, signal);
			if (bootstrapFailure) {
				const status = classifyInstallFailure(bootstrapFailure);
				lines.push(`      (${status}${bootstrapFailure.exitCode === null ? "" : ` — exit ${bootstrapFailure.exitCode}`})`);
				return { results: initial.map((result) => failedInstallResult(result, status, bootstrapFailure, "isolated nightly Rust toolchain bootstrap failed")) };
			}
		}
	}
	if (installStatus) lines.push(`      (${installStatus}${install.exitCode === null ? "" : ` — exit ${install.exitCode}`})`);
	if (!installStatus) await prepareVerification?.();
	const fresh = await toolkitEnvironment(bundle, env, runtime, signal);
	if (fresh.error) {
		const status = installStatus ?? "unavailable-route";
		lines.push(`      (${status} — fresh mise environment failed: ${fresh.error})`);
		return { results: initial.map((result) => failedInstallResult(result, status, install, fresh.error)) };
	}
	const verified: SniffToolResult[] = [];
	for (const rec of records) {
		const inspected = await inspectTool(bundle, rec, true, probeCwd, environmentForTool(bundle, rec, fresh, env, runtime), runtime, undefined, signal, bundle === "rust" && rec.key === "cargo");
		const result = inspected.status !== "usable" && installStatus
			? failedInstallResult(inspected, installStatus, install)
			: { ...inspected, install };
		verified.push(result);
		lines.push(result.status === "usable"
			? `      verified ${rec.name} in fresh mise environment (${result.resolvedPath})`
			: `      (${rec.name}: ${result.status} after toolkit install; resolved=${result.resolvedPath ?? "<unresolved>"})`);
	}
	return { results: verified };
}


function probeLabel(result: SniffToolResult): string {
	switch (result.status) {
		case "usable":
			return `  ok   ${result.tool}`;
		case "missing":
		case "project-local-required":
			return `  MISS ${result.tool}   — ${result.remediation}`;
		case "policy-blocked":
			return `  BLOCK ${result.tool}   — ${result.remediation}`;
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
	| "incomplete-output"
	| "not-run";

export type SniffAnalyzerRunResult = {
	ok: boolean;
	report: string;
	preflight: SniffToolResult | null;
	acceptedExitCodes?: number[];
	outcome: SniffAnalyzerOutcome;
  /** Transport-bounded deterministic preview of complete observations. */
  observations?: readonly AnalyzerObservation[];
  observationPreview?: AnalyzerObservationPreview;
  analyzerResultId?: string;
  readCapability?: string;
  descriptors?: readonly AnalyzerArtifactDescriptor[];
  descriptorCount?: number;
  descriptorsTruncated?: boolean;
  capture?: AnalyzerCapture;
};

function findTool(tool: string): { bundle: BundleName; rec: ToolRec } | null {
	for (const bundle of BUNDLES) {
		const rec = TOOLS[bundle].find((candidate) => candidate.name === tool);
		if (rec) return { bundle, rec };
	}
	return null;
}


function analyzerEnvironment(home: string, runtime: SniffInstallRuntime): ProcessEnvironment {
	const env: ProcessEnvironment = {
		HOME: home,
		TMPDIR: home,
		NO_COLOR: "1",
		SNIFF_TOOLKIT_CACHE_DIR: resolveSniffToolkitCacheRoot(process.env, runtime),
	};
	for (const name of [
		"PATH",
		"LANG",
		"LC_ALL",
		"TZ",
		"SNIFF_OPENGREP_CACHE_DIR",
		"MISE_DATA_DIR",
		"MISE_INSTALLS_DIR",
		"MISE_STATE_DIR",
		"XDG_DATA_HOME",
		"XDG_STATE_HOME",
	] as const) {
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
	return path;
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
	const baseEnvironment = analyzerEnvironment(authorization.home, runtime);
	const toolkitScoped = usesToolkitEnvironment(catalog.rec);
	const toolkit = toolkitScoped
		? await toolkitEnvironment(catalog.bundle, baseEnvironment, runtime, opts.signal, process.env.HOME)
		: { env: baseEnvironment, source: "process" as const };
	if (toolkit.error) {
		abandon();
		const preflight = toolkitUnavailableResult(catalog.bundle, catalog.rec, true, toolkit.error);
		return { ok: false, report: `sniff analyzer preflight blocked ${authorization.recipe.tool}: ${preflight.status}; ${preflight.remediation}`, preflight, acceptedExitCodes, outcome: "not-run" };
	}
	const env = environmentForTool(catalog.bundle, catalog.rec, toolkit, baseEnvironment, runtime);
	const preflight = await inspectTool(catalog.bundle, catalog.rec, true, authorization.target.root, env, runtime, (path) => hostAnalyzerExecutable(path, authorization.target.root), opts.signal, true);
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
	const openGrep = authorization.recipe.tool === "opengrep";
	const outputLimitBytes = openGrep ? OPENGREP_MAX_OUTPUT_BYTES : COMMAND_OUTPUT_LIMIT_BYTES;
	let execution: CommandResult;
	let completionError: string | undefined;
	try {
		execution = await runtime.run(argv, authorization.target.root, env, timeoutMs, opts.signal, outputLimitBytes);
	} catch (error) {
		execution = { argv, exitCode: null, stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, outputLimitBytes, timedOut: false, error: error instanceof Error ? error.message : String(error), timeoutMs };
	}
	try {
		completeAnalyzerReservation(opts.capability, opts.manifestId, opts.analyzer, authorization.reservationId);
	} catch (error) {
		completionError = error instanceof Error ? error.message : String(error);
	}
	const parsed = openGrep
		? parseOpenGrepOutput(execution.stdout, authorization.target.root, execution.stdoutTruncated)
		: parseAnalyzerOutput(authorization.recipe.tool, authorization.recipe.id, execution.stdout, authorization.target.root, execution.stdoutTruncated);
	const completed = !completionError && !execution.timedOut && !execution.error && execution.exitCode !== null;
	const incomplete = parsed?.capture.incomplete ?? false;
	const accepted = completed && !incomplete && acceptedExitCodes.includes(execution.exitCode as number);
  const outcome: SniffAnalyzerOutcome = !completed
    ? "not-run"
    : incomplete
      ? "incomplete-output"
      : accepted
        ? execution.exitCode === 0 && (parsed?.observations.length ?? 0) === 0 ? "completed" : "completed-with-findings"
        : "rejected-exit";
  const artifacts = accepted && parsed ? createAnalyzerArtifacts(authorization.recipe.id, parsed.observations) : undefined;
  const readCapability = artifacts ? registerAnalyzerArtifacts(artifacts) : undefined;
    const descriptorProjection = artifacts ? publicAnalyzerDescriptors(artifacts) : undefined;
  const projection = artifacts ? projectAnalyzerObservations(artifacts.observations) : undefined;
  return {
    ok: accepted,
    report: !completed
      ? `sniff analyzer could not run ${opts.analyzer}: ${completionError ?? execution.error ?? (execution.timedOut ? "timed out" : "no exit status")}`
      : incomplete
        ? `sniff analyzer output was incomplete for ${opts.analyzer}: ${parsed?.capture.reason ?? "bounded capture exceeded"}`
        : accepted
          ? `sniff analyzer ran ${opts.analyzer} with its issued fixed recipe (exit ${execution.exitCode})`
          : `sniff analyzer rejected ${opts.analyzer}: exit ${execution.exitCode} is outside [${acceptedExitCodes.join(", ")}]`,
    preflight,
    acceptedExitCodes,
    outcome,
    ...(descriptorProjection ? { descriptors: descriptorProjection.descriptors, descriptorCount: descriptorProjection.descriptorCount, descriptorsTruncated: descriptorProjection.descriptorsTruncated } : {}),
    ...(projection ? { observations: projection.observations, observationPreview: projection.preview } : {}),
    ...(artifacts ? { analyzerResultId: artifacts.analyzerResultId } : {}),
    ...(readCapability ? { readCapability } : {}),
    ...(parsed ? { capture: parsed.capture } : {}),
  };
}
export async function runSniffInstall(opts: SniffInstallOptions): Promise<SniffInstallResult> {
	if (opts.signal?.aborted) return { ok: false, report: "operation aborted", tools: [] };
	const mode: SniffInstallMode = opts.mode ?? "probe";
	const probeCwd = opts.cwd ?? process.cwd();
	const env = { ...process.env, ...opts.env };
	const runtime = opts.runtime ?? DEFAULT_RUNTIME;
	const installCwd = runtime.neutralCwd ?? tmpdir();
	const lines: string[] = [];
	const tools: SniffToolResult[] = [];
	if (mode === "probe") {
		lines.push("sniff tool probe (all tools optional; missing ones are skipped, not fatal)");
		for (const bundle of BUNDLES) {
			lines.push("", `[${bundle}]`);
			const environment = await toolkitEnvironment(bundle, env, runtime, opts.signal);
			const bundleResults: SniffToolResult[] = [];
			for (const rec of TOOLS[bundle]) {
				const toolkitScoped = usesToolkitEnvironment(rec);
				bundleResults.push(environment.error && toolkitScoped
					? toolkitUnavailableResult(bundle, rec, false, environment.error)
					: await inspectTool(bundle, rec, false, probeCwd, environmentForTool(bundle, rec, environment, env, runtime), runtime));
			}
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
			const environment = await toolkitEnvironment(bundle, env, runtime, opts.signal);
			for (const rec of TOOLS[bundle]) {
				const toolkitScoped = usesToolkitEnvironment(rec);
				const result = environment.error && toolkitScoped
					? toolkitUnavailableResult(bundle, rec, true, environment.error)
					: await inspectTool(bundle, rec, true, probeCwd, environmentForTool(bundle, rec, environment, env, runtime), runtime);
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
		const records = TOOLS[bundle];
		const unmanagedByTool = new Map<string, SniffToolResult>();
		const unmanagedRecords = records.filter((rec) => !isMiseManaged(rec));
		if (bundle === "rust" && opts.dryRun) {
			for (const rec of unmanagedRecords) {
				unmanagedByTool.set(rec.name, await installUnmanagedTool(bundle, rec, probeCwd, installCwd, true, env, runtime, lines, opts.signal, true));
			}
		}
		const managedRecords = records.filter(isMiseManaged);
		const prepareVerification = bundle === "rust" && !opts.dryRun
			? async () => {
				for (const rec of unmanagedRecords) {
					unmanagedByTool.set(rec.name, await installUnmanagedTool(bundle, rec, probeCwd, installCwd, false, env, runtime, lines, opts.signal));
				}
			}
			: undefined;
		const managedBundle: MiseBundleInstallResult = managedRecords.length > 0
			? await installMiseBundle(bundle, managedRecords, probeCwd, Boolean(opts.dryRun), env, runtime, lines, opts.signal, prepareVerification)
			: { results: [] };
		const managedResults = managedBundle.results;
		const preparationFailure = managedBundle.preparationFailure;
		if (preparationFailure) {
			for (const rec of unmanagedRecords) {
				unmanagedByTool.set(rec.name, failedInstallResult({
					bundle,
					tool: rec.name,
					bin: rec.bin,
					required: true,
					status: "missing",
					resolvedPath: null,
					remediation: rec.hint,
					attempts: [],
				}, preparationFailure.status, preparationFailure.install, preparationFailure.remediation));
			}
		}
		if (bundle === "rust" && opts.dryRun) {
			for (const rec of unmanagedRecords) {
				if (unmanagedByTool.get(rec.name)?.status !== "usable") lines.push(`  + rustup component add clippy (timeout ${INSTALL_TIMEOUT_MS}ms)`);
			}
		}
		const managedByTool = new Map(managedResults.map((result) => [result.tool, result]));
		for (const rec of records) {
			tools.push(managedByTool.get(rec.name) ?? unmanagedByTool.get(rec.name) ?? await installUnmanagedTool(bundle, rec, probeCwd, installCwd, Boolean(opts.dryRun), env, runtime, lines, opts.signal));
		}
	}
	const failures = tools.filter((result) => result.status !== "usable");
	if (opts.dryRun) {
		lines.push("", "Dry run complete; no tool state changed.");
		return { ok: true, report: lines.join("\n"), tools };
	}
	lines.push("", `install: ${tools.length - failures.length} usable, ${failures.length} failure(s) after verification`);
	return { ok: failures.length === 0, report: lines.join("\n"), tools };
}

