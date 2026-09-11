import {
	existsSync,
	mkdirSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";

const ENTRYPOINT = join("adapters", "mcp", "server.ts");
const OUTPUTS = [
	join("dist", "claude", "server.js"),
	join("dist", "codex", "server.js"),
] as const;

const BUILTIN_MODULES: Record<string, true> = {
	assert: true,
	"assert/strict": true,
	async_hooks: true,
	buffer: true,
	child_process: true,
	cluster: true,
	console: true,
	constants: true,
	crypto: true,
	dgram: true,
	diagnostics_channel: true,
	dns: true,
	"dns/promises": true,
	domain: true,
	events: true,
	fs: true,
	"fs/promises": true,
	http: true,
	http2: true,
	https: true,
	module: true,
	net: true,
	os: true,
	path: true,
	"path/posix": true,
	"path/win32": true,
	perf_hooks: true,
	process: true,
	punycode: true,
	querystring: true,
	readline: true,
	"readline/promises": true,
	repl: true,
	stream: true,
	"stream/consumers": true,
	"stream/promises": true,
	"stream/web": true,
	string_decoder: true,
	sys: true,
	timers: true,
	"timers/promises": true,
	tls: true,
	trace_events: true,
	tty: true,
	url: true,
	util: true,
	"util/types": true,
	v8: true,
	vm: true,
	wasi: true,
	worker_threads: true,
	zlib: true,
};

type BuildOptions = {
	readonly check?: boolean;
	readonly repoRoot?: string;
};

type BuildResult = {
	readonly bytes: number;
	readonly changed: boolean;
};

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
	if (left.byteLength !== right.byteLength) return false;
	for (let index = 0; index < left.byteLength; index += 1) {
		if (left[index] !== right[index]) return false;
	}
	return true;
}

function assertPortableBundle(bundle: Uint8Array, repoRoot: string): void {
	const text = new TextDecoder().decode(bundle);
	if (text.includes("sourceMappingURL") || text.includes("sourcesContent")) {
		throw new Error("Harness bundle unexpectedly contains a source map");
	}
	for (const match of text.matchAll(/\bfrom\s*["']([^"']+)["']/g)) {
		const specifier = match[1];
		if (specifier && !specifier.startsWith("node:") && !BUILTIN_MODULES[specifier]) {
			throw new Error(`Harness bundle contains an external runtime import: ${specifier}`);
		}
	}
	if (text.includes(repoRoot)) {
		throw new Error("Harness bundle contains a checkout path");
	}
	if (/(?:from\s+|import\s*\()\s*["'](?:\/(?:Users|private|tmp)|[A-Za-z]:[\\/])/.test(text)) {
		throw new Error("Harness bundle contains an absolute runtime import");
	}
}

async function buildBundle(repoRoot: string): Promise<Uint8Array> {
	const result = await Bun.build({
		entrypoints: [join(repoRoot, ENTRYPOINT)],
		target: "bun",
		format: "esm",
		sourcemap: "none",
		splitting: false,
		minify: true,
		allowUnresolved: [],
		write: false,
	});
	if (!result.success) {
		const details = result.logs.map((log) => log.message).join("\n");
		throw new Error(`Unable to build harness bundle${details ? `:\n${details}` : ""}`);
	}
	if (result.outputs.length !== 1) {
		throw new Error(`Expected one harness bundle output, got ${result.outputs.length}`);
	}
	const output = result.outputs[0];
	if (output?.kind !== "entry-point") {
		throw new Error("Harness build did not produce an entry-point bundle");
	}
	const bundle = new Uint8Array(await output.arrayBuffer());
	assertPortableBundle(bundle, repoRoot);
	return bundle;
}

export async function buildHarnessBundles(
	options: BuildOptions = {},
): Promise<BuildResult> {
	const repoRoot = resolve(options.repoRoot ?? join(import.meta.dir, ".."));
	const bundle = await buildBundle(repoRoot);
	const outputPaths = OUTPUTS.map((path) => join(repoRoot, path));
	const current = outputPaths.every(
		(path) => existsSync(path) && bytesEqual(new Uint8Array(readFileSync(path)), bundle),
	);
	if (options.check) {
		if (!current) {
			throw new Error(
				"Harness bundles are stale or missing; run the bundle builder without --check.",
			);
		}
		return { bytes: bundle.byteLength, changed: false };
	}
	for (const path of outputPaths) {
		mkdirSync(resolve(path, ".."), { recursive: true });
		writeFileSync(path, bundle);
	}
	return { bytes: bundle.byteLength, changed: !current };
}

async function runFromCli(): Promise<void> {
	const args = process.argv.slice(2);
	if (args.some((argument) => argument !== "--check")) {
		throw new Error("Usage: bun scripts/build-harness-bundles.ts [--check]");
	}
	const check = args.includes("--check");
	const result = await buildHarnessBundles({ check });
	const action = check ? "current" : result.changed ? "built" : "unchanged";
	console.log(`${action} ${result.bytes} harness bundle bytes`);
}

if (import.meta.main) {
	try {
		await runFromCli();
	} catch (error) {
		console.error(error instanceof Error ? error.message : error);
		process.exitCode = 1;
	}
}
