import { createHash, randomBytes } from "node:crypto";
import { accessSync, chmodSync, constants, existsSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { arch, homedir, platform } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export const OPENGREP_VERSION = "v1.30.0";
export const OPENGREP_DOWNLOAD_TIMEOUT_MS = 120_000;
export const OPENGREP_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024;
export const OPENGREP_MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
export const OPENGREP_MAX_OBSERVATIONS = 2_000;
const OPENGREP_MAX_FIELD_BYTES = 8_192;

export type OpenGrepAsset = { readonly key: string; readonly name: string; readonly sha256: string };

export const OPENGREP_ASSETS = {
	"darwin-arm64": { key: "darwin-arm64", name: "opengrep_osx_arm64", sha256: "0f5bc3dec09d995c61331a4017b856ede508f90d95b018d95f1dc6166be89fdd" },
	"darwin-x64": { key: "darwin-x64", name: "opengrep_osx_x86", sha256: "650772a849a2986880982b7dea0371f96a75d354de95f94e8c1a2e6f8f6262d1" },
	"linux-arm64": { key: "linux-arm64", name: "opengrep_manylinux_aarch64", sha256: "a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae" },
	"linux-x64": { key: "linux-x64", name: "opengrep_manylinux_x86", sha256: "35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c" },
	"linux-musl-arm64": { key: "linux-musl-arm64", name: "opengrep_musllinux_aarch64", sha256: "937d0f35fc05af8877f5f34e04465f2466a8da3c33c2a0d510b8a896383354ef" },
	"linux-musl-x64": { key: "linux-musl-x64", name: "opengrep_musllinux_x86", sha256: "ee21fa70714531e1eccbcb50993a871e198fb0f4ade254ef7636c433304fe4bd" },
} as const satisfies Record<string, OpenGrepAsset>;

function linuxMusl(): boolean {
	try {
		const report = (process as typeof process & { report?: { getReport?: () => unknown } }).report;
		const value = report?.getReport?.() as { header?: { glibcVersionRuntime?: string } } | undefined;
		return !value?.header?.glibcVersionRuntime;
	} catch {
		return false;
	}
}

export function openGrepAsset(os = platform(), cpu = arch(), musl = linuxMusl()): OpenGrepAsset | null {
	if (os === "darwin" && cpu === "arm64") return OPENGREP_ASSETS["darwin-arm64"];
	if (os === "darwin" && cpu === "x64") return OPENGREP_ASSETS["darwin-x64"];
	if (os === "linux" && cpu === "arm64") return OPENGREP_ASSETS[musl ? "linux-musl-arm64" : "linux-arm64"];
	if (os === "linux" && cpu === "x64") return OPENGREP_ASSETS[musl ? "linux-musl-x64" : "linux-x64"];
	return null;
}

const cacheRoot = (override?: string): string => resolve(override ?? join(homedir(), ".cache", "sniff", "opengrep"));
const assetUrl = (asset: OpenGrepAsset): string => `https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${asset.name}`;
const cachePath = (asset: OpenGrepAsset, override?: string): string => join(cacheRoot(override), OPENGREP_VERSION, asset.key, "opengrep");

function digestFile(path: string): string {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function verified(path: string, asset: OpenGrepAsset): string | null {
	try {
		if (!statSync(path).isFile()) return null;
		accessSync(path, constants.X_OK);
		if (digestFile(path) !== asset.sha256) return null;
		return path;
	} catch {
		return null;
	}
}

export function resolveOpenGrepExecutable(options: { readonly cacheDir?: string; readonly os?: NodeJS.Platform; readonly cpu?: string; readonly musl?: boolean } = {}): string | null {
	const asset = openGrepAsset(options.os, options.cpu, options.musl);
	return asset ? verified(cachePath(asset, options.cacheDir), asset) : null;
}

export type OpenGrepProvisionOptions = {
	readonly cacheDir?: string;
	readonly os?: NodeJS.Platform;
	readonly cpu?: string;
	readonly musl?: boolean;
	readonly fetcher?: typeof fetch;
	readonly signal?: AbortSignal;
};


export type OpenGrepProvisionResult = { readonly path: string; readonly asset: OpenGrepAsset; readonly reused: boolean };

export async function provisionOpenGrep(options: OpenGrepProvisionOptions = {}): Promise<OpenGrepProvisionResult> {
	const asset = openGrepAsset(options.os, options.cpu, options.musl);
	if (!asset) throw new Error(`OpenGrep does not support ${options.os ?? platform()}/${options.cpu ?? arch()}`);
	const destination = cachePath(asset, options.cacheDir);
	const existing = verified(destination, asset);
	if (existing) return { path: existing, asset, reused: true };
	if (existsSync(destination)) rmSync(destination, { force: true });
	mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
	const temporary = `${destination}.download-${process.pid}-${randomBytes(8).toString("hex")}`;
	let timer: ReturnType<typeof setTimeout> | undefined;
	const controller = new AbortController();
	const abort = () => controller.abort(options.signal?.reason);
	if (options.signal?.aborted) abort();
	else options.signal?.addEventListener("abort", abort, { once: true });
	try {
		timer = setTimeout(() => controller.abort(new Error("OpenGrep download timed out")), OPENGREP_DOWNLOAD_TIMEOUT_MS);
		const response = await (options.fetcher ?? fetch)(assetUrl(asset), { signal: controller.signal });
		if (!response.ok) throw new Error(`OpenGrep download failed with HTTP ${response.status}`);
		const advertised = Number(response.headers.get("content-length") ?? "0");
		if (advertised > OPENGREP_MAX_DOWNLOAD_BYTES) throw new Error("OpenGrep download exceeds the maximum size");
		if (!response.body) throw new Error("OpenGrep download returned no body");
		const reader = response.body.getReader();
		const chunks: Uint8Array[] = [];
		let total = 0;
		for (;;) {
			const next = await reader.read();
			if (next.done) break;
			total += next.value.byteLength;
			if (total > OPENGREP_MAX_DOWNLOAD_BYTES) throw new Error("OpenGrep download exceeds the maximum size");
			chunks.push(next.value);
		}
		const bytes = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
		const digest = createHash("sha256").update(bytes).digest("hex");
		if (digest !== asset.sha256) throw new Error(`OpenGrep checksum mismatch: expected ${asset.sha256}, got ${digest}`);
		writeFileSync(temporary, bytes, { mode: 0o600, flag: "wx" });
		chmodSync(temporary, 0o755);
		renameSync(temporary, destination);
		return { path: destination, asset, reused: false };
	} finally {
		clearTimeout(timer);
		options.signal?.removeEventListener("abort", abort);
		if (existsSync(temporary)) rmSync(temporary, { force: true });
	}
}

export type OpenGrepObservation = { readonly ruleId: string; readonly path: string; readonly start: { readonly line: number; readonly column: number }; readonly message: string; readonly severity: string };
export type OpenGrepCapture = { readonly bytes: number; readonly truncated: boolean; readonly digest: string; readonly incomplete: boolean; readonly reason?: string };
export type OpenGrepParseResult = { readonly observations: readonly OpenGrepObservation[]; readonly capture: OpenGrepCapture };


function normalizeFindingPath(targetRoot: string, value: string): string | null {
	if (value.includes("\0")) return null;
	const root = resolve(targetRoot);
	const candidate = value.replaceAll("\\", "/");
	const absolute = isAbsolute(candidate) ? resolve(candidate) : resolve(root, candidate);
	const path = relative(root, absolute);
	if (!path || path === ".." || path.startsWith(`..${sep}`) || isAbsolute(path)) return null;
	try {
		if (existsSync(absolute)) {
			const canonical = realpathSync(absolute);
			const canonicalPath = relative(root, canonical);
			if (!canonicalPath || canonicalPath === ".." || canonicalPath.startsWith(`..${sep}`) || isAbsolute(canonicalPath)) return null;
		}
	} catch {
		return null;
	}
	return path.split(sep).join("/");
}

function addParseReason(reasons: string[], reason: string): void {
	if (!reasons.includes(reason)) reasons.push(reason);
}

function projectedString(value: unknown, label: string, reasons: string[]): string | null {
	if (typeof value !== "string" || value.includes("\0")) {
		addParseReason(reasons, `OpenGrep ${label} field was malformed`);
		return null;
	}
	const trimmed = value.trim();
	if (Buffer.byteLength(trimmed) > OPENGREP_MAX_FIELD_BYTES) {
		addParseReason(reasons, `OpenGrep ${label} field exceeded the bounded projection size`);
		return null;
	}
	return trimmed;
}

function positiveInteger(value: unknown, label: string, reasons: string[]): number | null {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
		addParseReason(reasons, `OpenGrep ${label} coordinate was malformed`);
		return null;
	}
	return value;
}

export function parseOpenGrepOutput(stdout: string, targetRoot: string, truncated = false): OpenGrepParseResult {
	const bytes = Buffer.byteLength(stdout);
	const digest = createHash("sha256").update(stdout).digest("hex");
	if (truncated) return { observations: [], capture: { bytes, truncated: true, digest, incomplete: true, reason: "OpenGrep JSON exceeded the bounded capture limit" } };
	try {
		const payload = JSON.parse(stdout) as { results?: unknown };
		if (!Array.isArray(payload.results)) throw new Error("OpenGrep JSON has no results array");
		const observations: OpenGrepObservation[] = [];
		const reasons: string[] = payload.results.length > OPENGREP_MAX_OBSERVATIONS ? [`OpenGrep observations exceeded the bounded limit of ${OPENGREP_MAX_OBSERVATIONS.toLocaleString("en-US")}`] : [];
		for (const candidate of payload.results) {
			if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
				addParseReason(reasons, "OpenGrep result entry was malformed");
				continue;
			}
			const result = candidate as { check_id?: unknown; path?: unknown; start?: { line?: unknown; col?: unknown }; extra?: { message?: unknown; severity?: unknown } };
			const ruleId = projectedString(result.check_id, "rule ID", reasons);
			const pathValue = projectedString(result.path, "path", reasons);
			const line = positiveInteger(result.start?.line, "line", reasons);
			const column = positiveInteger(result.start?.col, "column", reasons);
			const message = projectedString(result.extra?.message, "message", reasons);
			const severity = projectedString(result.extra?.severity, "severity", reasons);
			if (ruleId === null || pathValue === null || line === null || column === null || message === null || severity === null) continue;
			if (observations.length >= OPENGREP_MAX_OBSERVATIONS) break;
			const path = normalizeFindingPath(targetRoot, pathValue);
			if (!ruleId || !path) {
				addParseReason(reasons, !path ? "OpenGrep finding path escaped the authorized target root" : "OpenGrep finding had an empty rule ID");
				continue;
			}
			observations.push({ ruleId, path, start: { line, column }, message, severity });
		}
		const reason = reasons.length ? reasons.join("; ") : undefined;
		return { observations, capture: { bytes, truncated: false, digest, incomplete: Boolean(reason), ...(reason ? { reason } : {}) } };
	} catch (error) {
		return { observations: [], capture: { bytes, truncated: false, digest, incomplete: true, reason: error instanceof Error ? error.message : String(error) } };
	}
}
