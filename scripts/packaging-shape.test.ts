import { expect, setDefaultTimeout, test } from "bun:test";
import {
	cpSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { builtinModules } from "node:module";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

type JsonObject = Record<string, unknown>;

setDefaultTimeout(30_000);

const repoRoot = resolve(import.meta.dir, "..");
const codexRoot = join(repoRoot, "dist", "codex");
const claudeServerPath = join(repoRoot, "dist", "claude", "server.js");
const codexServerPath = join(codexRoot, "server.js");
const OPENGREP_RULE_NAME = "sniff-opengrep-hardcoded-values.yml";
const opengrepRuleSourcePath = join(
	repoRoot,
	".skill-source",
	"sniff",
	"references",
	"opengrep-rules",
	"hardcoded-values.yml",
);
const opengrepRuleOutputPaths = [
	join(repoRoot, "dist", "omp", OPENGREP_RULE_NAME),
	join(repoRoot, "dist", "claude", OPENGREP_RULE_NAME),
	join(repoRoot, "dist", "codex", OPENGREP_RULE_NAME),
] as const;
const packageJson = JSON.parse(
	readFileSync(join(repoRoot, "package.json"), "utf8"),
) as JsonObject;
const ompManifest = JSON.parse(
	readFileSync(join(repoRoot, ".omp-plugin", "plugin.json"), "utf8"),
) as JsonObject;
const claudeManifest = JSON.parse(
	readFileSync(join(repoRoot, ".claude-plugin", "plugin.json"), "utf8"),
) as JsonObject;
const codexManifest = JSON.parse(
	readFileSync(join(codexRoot, "plugin.json"), "utf8"),
) as JsonObject;
const claudeMcp = JSON.parse(
	readFileSync(join(repoRoot, "claude-mcp.json"), "utf8"),
) as JsonObject;
const codexMcp = JSON.parse(
	readFileSync(join(codexRoot, "mcp.json"), "utf8"),
) as JsonObject;
const claudeCatalog = JSON.parse(
	readFileSync(join(repoRoot, ".claude-plugin", "marketplace.json"), "utf8"),
) as JsonObject;
const codexCatalog = JSON.parse(
	readFileSync(
		join(repoRoot, ".agents", "plugins", "marketplace.json"),
		"utf8",
	),
) as JsonObject;

const PORTABLE_PLUGIN_SCHEMA =
	"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
const PORTABLE_MCP_SCHEMA =
	"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";
const CLAUDE_PLUGIN_ROOT = "${" + "CLAUDE_PLUGIN_ROOT}";
const PLUGIN_ROOT = "${" + "PLUGIN_ROOT}";
const EXPECTED_TOOLS = [
	"sniff_intake",
	"sniff_cancel",
	"sniff_install_tools",
	"sniff_run_analyzer",
	"sniff_report",
	"sniff_read_report_artifact",
	"sniff_read_analyzer_artifact",
] as const;

function pluginEntry(catalog: JsonObject): JsonObject {
	const plugins = catalog.plugins;
	expect(Array.isArray(plugins)).toBe(true);
	if (
		!Array.isArray(plugins) ||
		plugins.length !== 1 ||
		typeof plugins[0] !== "object" ||
		plugins[0] === null
	) {
		throw new Error("Marketplace catalog must contain exactly one plugin entry");
	}
	return plugins[0] as JsonObject;
}

function object(value: unknown, description: string): JsonObject {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new Error(`${description} must be an object`);
	}
	return value as JsonObject;
}

function serverArgs(config: JsonObject, variable: string, pluginRoot: string): string[] {
	const args = config.args;
	if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) {
		throw new Error("MCP server args must be an array of strings");
	}
	const expanded = args.map((arg) => arg.replaceAll(variable, pluginRoot));
	expect(expanded.some((arg) => arg.includes("${"))).toBe(false);
	return expanded;
}
function assertContained(root: string, candidate: string): void {
	const fromRoot = relative(resolve(root), resolve(candidate));
	expect(
		fromRoot === "" || (!fromRoot.startsWith("..") && !isAbsolute(fromRoot)),
	).toBe(true);
}

async function listTools(
	command: string,
	args: string[],
	cwd: string,
): Promise<JsonObject[]> {
	const child = Bun.spawn([command, ...args], {
		cwd,
		stdin: "pipe",
		stdout: "pipe",
		stderr: "pipe",
	});
	const input = child.stdin;
	if (!input) throw new Error("MCP smoke process stdin was not piped");
	const reader = child.stdout.getReader();
	const decoder = new TextDecoder();
	let buffer = "";

	const nextMessage = async (): Promise<JsonObject> => {
		const deadline = Date.now() + 10_000;
		for (;;) {
			const newline = buffer.indexOf("\n");
			if (newline >= 0) {
				const line = buffer.slice(0, newline);
				buffer = buffer.slice(newline + 1);
				if (line.trim().length > 0) return object(JSON.parse(line), "MCP response");
				continue;
			}
			const remaining = deadline - Date.now();
			if (remaining <= 0) throw new Error("Timed out waiting for MCP response");
			const chunk = await Promise.race([
				reader.read(),
				Bun.sleep(remaining).then(() => undefined),
			]);
			if (!chunk) throw new Error("Timed out waiting for MCP response");
			if (chunk.done) throw new Error("MCP server closed stdout before responding");
			buffer += decoder.decode(chunk.value, { stream: true });
		}
	};

	const request = async (
		id: number,
		method: string,
		params: JsonObject,
	): Promise<JsonObject> => {
		input.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
		input.flush();
		for (;;) {
			const response = await nextMessage();
			if (response.id === id) return response;
		}
	};

	try {
		const initialize = await request(1, "initialize", {
			protocolVersion: "2025-06-18",
			capabilities: {},
			clientInfo: { name: "packaging-shape", version: "1" },
		});
		expect(initialize.error).toBeUndefined();
		input.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
		input.flush();
		const listed = await request(2, "tools/list", {});
		expect(listed.error).toBeUndefined();
		const result = object(listed.result, "tools/list result");
		const tools = result.tools;
		expect(Array.isArray(tools)).toBe(true);
		if (!Array.isArray(tools)) throw new Error("tools/list result did not contain tools");
		return tools.map((tool) => object(tool, "advertised tool"));
	} finally {
		input.end();
		child.kill();
		await Promise.race([child.exited, Bun.sleep(2_000)]);
	}
}
function copyClaudePackage(destination: string): void {
	mkdirSync(join(destination, ".claude-plugin"), { recursive: true });
	mkdirSync(join(destination, ".claude", "skills"), { recursive: true });
	mkdirSync(join(destination, "dist", "claude"), { recursive: true });
	cpSync(
		join(repoRoot, ".claude-plugin", "plugin.json"),
		join(destination, ".claude-plugin", "plugin.json"),
	);
	cpSync(join(repoRoot, ".claude", "skills"), join(destination, ".claude", "skills"), {
		recursive: true,
	});
	cpSync(join(repoRoot, "claude-mcp.json"), join(destination, "claude-mcp.json"));
	cpSync(claudeServerPath, join(destination, "dist", "claude", "server.js"));
	cpSync(
		join(repoRoot, "dist", "claude", OPENGREP_RULE_NAME),
		join(destination, "dist", "claude", OPENGREP_RULE_NAME),
	);
}

function copyCodexPackage(destination: string): void {
	mkdirSync(destination, { recursive: true });
	for (const file of ["plugin.json", "mcp.json", "server.js", OPENGREP_RULE_NAME] as const) {
		cpSync(join(codexRoot, file), join(destination, file));
	}
}
const OMP_EXTENSION = "sniff-plugin.js" as const;

type RegisteredTool = {
	readonly name: string;
	readonly parameters?: JsonObject;
	readonly execute: (
		id: string,
		params: JsonObject,
		signal: unknown,
		onUpdate: unknown,
		context: JsonObject,
	) => Promise<JsonObject>;
};

function fakeOmpApi(tools: Map<string, RegisteredTool>): JsonObject {
	const schema: Record<string, unknown> = {};
	const chain = () => schema;
	for (const method of ["array", "boolean", "describe", "int", "nonnegative", "number", "object", "optional", "string", "unknown"]) {
		schema[method] = chain;
	}
	schema.enum = chain;
	return {
		zod: schema,
		registerTool: (tool: RegisteredTool) => tools.set(tool.name, tool),
	};
}

function assertPortableExtensionImports(path: string): void {
	const source = readFileSync(path, "utf8");
	for (const match of source.matchAll(/\bfrom\s*["']([^"']+)["']/g)) {
		const specifier = match[1];
		if (!specifier) continue;
		const builtin = specifier.startsWith("node:") ? specifier.slice(5) : specifier;
		expect(builtinModules).toContain(builtin);
	}
}

function stringValue(value: unknown, description: string): string {
	if (typeof value !== "string") throw new Error(`${description} must be a string`);
	return value;
}
function assertOpenGrepResource(root: string, relativePath: string): void {
	const outputPath = join(root, relativePath);
	expect(existsSync(outputPath)).toBe(true);
	expect(readFileSync(outputPath).equals(readFileSync(opengrepRuleSourcePath))).toBe(true);
	expect(existsSync(join(root, ".skill-source"))).toBe(false);
}

test("Copied OMP package imports one bundled extension and completes a leased lifecycle", async () => {
	const cache = mkdtempSync(join(tmpdir(), "sniff-omp-cache-"));
	const targetRoot = mkdtempSync(join(tmpdir(), "sniff-omp-target-"));
	const analyzerBin = mkdtempSync(join(tmpdir(), "sniff-omp-analyzer-"));
	const originalPath = process.env.PATH;
	const originalToolkitCache = process.env.SNIFF_TOOLKIT_CACHE_DIR;
	process.env.PATH = `${analyzerBin}${delimiter}${originalPath ?? ""}`;
	process.env.SNIFF_TOOLKIT_CACHE_DIR = join(cache, "toolkits");
	try {
		writeFileSync(join(analyzerBin, "lizard"), "#!/bin/sh\nfor arg do last=$arg; done\nprintf 'NLOC,CCN,token,PARAM,length,location,file,function,long_name\\n1,1,1,0,1,1-1,%s,module,module\\n' \"$last\"\n", { mode: 0o755 });
		writeFileSync(join(targetRoot, "source.ts"), "export const source = true;\n");

		const rootOmp = object(packageJson.omp, "package omp metadata");
		const rootExtensions = rootOmp.extensions;
		if (!Array.isArray(rootExtensions)) throw new Error("package omp extensions must be an array");
		const declaredExtensions = rootExtensions.map((entry) => stringValue(entry, "package omp extension"));
		expect(declaredExtensions).toEqual([`./dist/omp/${OMP_EXTENSION}`]);
		const pluginRoot = join(cache, "sniff");
		mkdirSync(join(pluginRoot, ".omp-plugin"), { recursive: true });
		mkdirSync(join(pluginRoot, "dist", "omp"), { recursive: true });
		writeFileSync(
			join(pluginRoot, "package.json"),
			JSON.stringify({
				name: packageJson.name,
				version: packageJson.version,
				private: true,
				omp: { extensions: declaredExtensions },
			}),
		);
		cpSync(join(repoRoot, ".omp-plugin", "plugin.json"), join(pluginRoot, ".omp-plugin", "plugin.json"));
		cpSync(join(repoRoot, "dist", "omp"), join(pluginRoot, "dist", "omp"), { recursive: true });

		expect(readdirSync(pluginRoot).sort()).toEqual([".omp-plugin", "dist", "package.json"]);
		expect(readdirSync(join(pluginRoot, ".omp-plugin")).sort()).toEqual(["plugin.json"]);
		expect(readdirSync(join(pluginRoot, "dist")).sort()).toEqual(["omp"]);
		expect(readdirSync(join(pluginRoot, "dist", "omp")).sort()).toEqual([
			OMP_EXTENSION,
			OPENGREP_RULE_NAME,
		].sort());
		expect(existsSync(join(pluginRoot, "node_modules"))).toBe(false);
		expect(existsSync(join(pluginRoot, "src"))).toBe(false);
		expect(existsSync(join(pluginRoot, "extensions"))).toBe(false);
		expect(existsSync(join(pluginRoot, "adapters"))).toBe(false);
		assertOpenGrepResource(pluginRoot, join("dist", "omp", OPENGREP_RULE_NAME));

		const tools = new Map<string, RegisteredTool>();
		const bundlePath = join(pluginRoot, "dist", "omp", OMP_EXTENSION);
		assertContained(cache, bundlePath);
		assertPortableExtensionImports(bundlePath);
		const extension = await import(pathToFileURL(bundlePath).href);
		expect(typeof extension.default).toBe("function");
		extension.default(fakeOmpApi(tools));
		expect([...tools.keys()].sort()).toEqual([...EXPECTED_TOOLS].sort());

		const context = { cwd: targetRoot, hasUI: false, mode: "rpc" };
		const install = tools.get("sniff_install_tools");
		if (!install) throw new Error("sniff_install_tools was not registered");
		const listed = await install.execute("list", { mode: "list" }, undefined, undefined, context);
		const listedDetails = object(listed.details, "sniff_install_tools details");
		expect(listedDetails.ok).toBe(true);

		const intake = tools.get("sniff_intake");
		if (!intake) throw new Error("sniff_intake was not registered");
		const intakeOutput = await intake.execute(
			"intake",
			{
				input: {
					target: { kind: "files", root: targetRoot, paths: ["source.ts"] },
					intent: "audit",
					scopeMode: "quick",
					interactive: false,
				},
			},
			undefined,
			undefined,
			context,
		);
		const intakeDetails = object(intakeOutput.details, "sniff_intake details");
		expect(intakeDetails.ok).toBe(true);
		const intakeResult = object(intakeDetails.result, "sniff_intake result");
		expect(intakeResult).not.toHaveProperty("manifest");
		expect(intakeResult).not.toHaveProperty("files");
		const confirmation = object(intakeResult.confirmation, "sniff_intake confirmation");
		const confirmedTarget = object(confirmation.target, "confirmed target");
		expect(confirmedTarget).not.toHaveProperty("root");
		const reportTarget = object(intakeResult.reportTarget, "sniff_intake reportTarget");
		expect(reportTarget).toEqual({ kind: "files", label: "selected files", scopeMode: "quick", filesAnalyzed: 1 });

		const lease = object(intakeResult.lease, "sniff_intake lease");
		const capability = stringValue(lease.capability, "lease capability");
		const manifestId = stringValue(lease.manifestId, "lease manifest ID");
		const analyzer = tools.get("sniff_run_analyzer");
		if (!analyzer) throw new Error("sniff_run_analyzer was not registered");
		const analyzerOutput = await analyzer.execute(
			"analyzer",
			{ capability, manifestId, analyzer: "lizard:complexity" },
			undefined,
			undefined,
			context,
		);
		const analyzerDetails = object(analyzerOutput.details, "sniff_run_analyzer details");
		expect(analyzerDetails.ok).toBe(true);
		expect(analyzerDetails.outcome).toBe("completed");

		const reportTool = tools.get("sniff_report");
		if (!reportTool) throw new Error("sniff_report was not registered");
		const reportParameters = object(reportTool.parameters, "sniff_report parameters");
		const reportProperties = object(reportParameters.properties, "sniff_report properties");
		const { description: _description, ...actualReportSchema } = object(reportProperties.report, "sniff_report report schema");
		const canonicalReportSchema = JSON.parse(readFileSync(join(repoRoot, ".skill-source", "sniff", "references", "report-input.schema.json"), "utf8")) as JsonObject;
		const { $schema: _schema, $id: _id, title: _title, $defs: canonicalDefinitions, ...canonicalReportBody } = canonicalReportSchema;
		expect(reportParameters.$defs).toEqual(canonicalDefinitions);
		expect(actualReportSchema).toEqual(canonicalReportBody);
		const reportOutput = await reportTool.execute(
			"report",
			{
				capability,
				manifestId,
				mode: "render",
				report: {
					generatedAt: "2026-09-11T00:00:00.000Z",
					target: { ...reportTarget, languages: ["TypeScript"] },
					headline: "Deterministic lifecycle fixture completed.",
					findings: [],
					coverage: [{ dimension: "complexity", tool: "lizard", analysisClass: "local", status: "ran", notes: "The fixed fixture analyzer completed." }],
					suppressionCount: 0,
					systemicPatterns: [],
				},
			},
			undefined,
			undefined,
			context,
		);
		const reportDetails = object(reportOutput.details, "sniff_report details");
		expect(reportDetails.ok).toBe(true);
		const reportDescriptors = reportDetails.descriptors;
		expect(Array.isArray(reportDescriptors)).toBe(true);
		expect((reportDescriptors as unknown[]).length).toBeGreaterThan(0);

		const cancel = tools.get("sniff_cancel");
		if (!cancel) throw new Error("sniff_cancel was not registered");
		const replay = await cancel.execute("replay", { capability, manifestId }, undefined, undefined, context);
		const replayDetails = object(replay.details, "sniff_cancel replay details");
		expect(replayDetails.ok).toBe(false);
		expect(replay.isError).toBe(true);
		expect(stringValue(replayDetails.error, "sniff_cancel replay error")).toContain("already released");
	} finally {
		process.env.PATH = originalPath;
		if (originalToolkitCache === undefined) delete process.env.SNIFF_TOOLKIT_CACHE_DIR;
		else process.env.SNIFF_TOOLKIT_CACHE_DIR = originalToolkitCache;
		rmSync(cache, { recursive: true, force: true });
		rmSync(targetRoot, { recursive: true, force: true });
		rmSync(analyzerBin, { recursive: true, force: true });
	}
});

test("Claude metadata discovers its generated skill and shared MCP config", () => {
	expect(claudeManifest.name).toBe("sniff");
	expect(claudeManifest.version).toBe(packageJson.version);
	expect(ompManifest.version).toBe(packageJson.version);
	expect(claudeManifest.skills).toBe("./.claude/skills/");
	expect(claudeManifest.mcpServers).toBe("./claude-mcp.json");
	expect(existsSync(join(repoRoot, ".mcp.json"))).toBe(false);
	expect(claudeManifest).not.toHaveProperty("agents");
	expect(claudeManifest).not.toHaveProperty("rules");
});

test("Codex package uses the Agent Plugins 1.0 manifest and fixed paths", () => {
	expect(codexManifest.$schema).toBe(PORTABLE_PLUGIN_SCHEMA);
	expect(codexManifest.name).toBe("sniff");
	expect(codexManifest.version).toBe(packageJson.version);
	expect(codexManifest).not.toHaveProperty("skills");
	expect(codexManifest).not.toHaveProperty("mcpServers");
	expect(codexManifest).not.toHaveProperty("interface");
	expect(codexManifest).not.toHaveProperty("agents");
	expect(codexManifest).not.toHaveProperty("rules");

	const extensions = object(codexManifest.extensions, "extensions");
	expect(Object.keys(extensions)).toEqual(["com.openai"]);
	const openai = object(extensions["com.openai"], "extensions.com.openai");
	expect(Object.keys(openai)).toEqual(["interface"]);
	expect(openai.interface).toEqual({
		displayName: "Sniff",
		shortDescription: "Audits code smells and produces reviewed plans.",
		longDescription:
			"A read-only-first code-smell audit workflow with adaptive intake, analyzer preflight, challenge review, and validated reports.",
		developerName: "srobroek",
		category: "Productivity",
		capabilities: ["Interactive"],
		defaultPrompt: [
			"Audit this repository for code smells and produce a reviewed plan.",
		],
	});

	expect(existsSync(join(codexRoot, "skills", "sniff", "SKILL.md"))).toBe(true);
	expect(existsSync(join(repoRoot, "plugin.json"))).toBe(false);
	expect(existsSync(join(repoRoot, "mcp.json"))).toBe(false);
});

test("MCP configs launch the cache-local bundled servers", () => {
	const claudeServers = object(claudeMcp.mcpServers, "mcpServers");
	const claude = object(claudeServers.sniff, "mcpServers.sniff");
	expect(claude.command).toBe("bun");
	expect(serverArgs(claude, CLAUDE_PLUGIN_ROOT, "/cache/claude")).toEqual([
		"run",
		"/cache/claude/dist/claude/server.js",
	]);

	expect(codexMcp.$schema).toBe(PORTABLE_MCP_SCHEMA);
	const codexServers = object(codexMcp.mcpServers, "mcpServers");
	const codex = object(codexServers.sniff, "mcpServers.sniff");
	expect(codex.type).toBe("stdio");
	expect(codex.command).toBe("bun");
	expect(serverArgs(codex, PLUGIN_ROOT, "/cache/codex")).toEqual([
		"run",
		"/cache/codex/server.js",
	]);
	expect(codex).not.toHaveProperty("url");
});

test("All published version declarations match package.json", () => {
	const claudeEntry = pluginEntry(claudeCatalog);
	const codexEntry = pluginEntry(codexCatalog);
	expect(ompManifest.version).toBe(packageJson.version);
	expect(claudeManifest.version).toBe(packageJson.version);
	expect(claudeCatalog.version).toBe(packageJson.version);
	expect(claudeEntry.version).toBe(packageJson.version);
	expect(codexEntry.version).toBe(packageJson.version);
	expect(codexManifest.version).toBe(packageJson.version);
});

test("Codex marketplace entries use the current local source policy", () => {
	const claudeEntry = pluginEntry(claudeCatalog);
	const codexEntry = pluginEntry(codexCatalog);
	expect(codexCatalog.name).toBe("sniff");
	expect(codexCatalog.interface).toEqual({ displayName: "Sniff" });
	expect(claudeEntry.name).toBe(codexEntry.name);
	expect(claudeEntry.version).toBe(packageJson.version);
	expect(codexEntry.version).toBe(packageJson.version);
	expect(claudeEntry.description).toBe(codexEntry.description);
	expect(claudeEntry.source).toBe("./");
	expect(codexEntry.source).toEqual({
		source: "local",
		path: "./dist/codex",
	});
	expect(codexEntry.policy).toEqual({
		installation: "AVAILABLE",
		authentication: "ON_INSTALL",
	});
	expect(codexEntry.category).toBe("Productivity");
});

test("All harnesses ship the authoritative OpenGrep ruleset without source fallback", () => {
	const source = readFileSync(opengrepRuleSourcePath);
	for (const outputPath of opengrepRuleOutputPaths) {
		expect(existsSync(outputPath)).toBe(true);
		expect(readFileSync(outputPath).equals(source)).toBe(true);
	}
});

test("Harness bundles are one byte-identical portable payload", () => {
	expect(existsSync(claudeServerPath)).toBe(true);
	expect(existsSync(codexServerPath)).toBe(true);
	const claudeBundle = readFileSync(claudeServerPath);
	const codexBundle = readFileSync(codexServerPath);
	expect(claudeBundle.equals(codexBundle)).toBe(true);
	const text = claudeBundle.toString("utf8");
	expect(text).not.toContain("sourceMappingURL");
	expect(text).not.toContain(repoRoot);
});

test("Copied Claude and nested Codex caches serve exactly seven MCP tools", async () => {
	const cache = mkdtempSync(join(tmpdir(), "sniff-packaging-cache-"));
	try {
		const claudeRoot = join(cache, "claude");
		copyClaudePackage(claudeRoot);
		const claudeServers = object(claudeMcp.mcpServers, "mcpServers");
		const claude = object(claudeServers.sniff, "mcpServers.sniff");
		const claudeArgs = serverArgs(claude, CLAUDE_PLUGIN_ROOT, claudeRoot);
		expect(claudeArgs[1]).toBe(join(claudeRoot, "dist", "claude", "server.js"));
		if (typeof claudeArgs[1] !== "string") throw new Error("Claude server path is missing");
		assertContained(claudeRoot, claudeArgs[1]);
		expect(existsSync(join(claudeRoot, "node_modules"))).toBe(false);
		expect(existsSync(join(claudeRoot, "adapters"))).toBe(false);
		assertOpenGrepResource(claudeRoot, join("dist", "claude", OPENGREP_RULE_NAME));
		const claudeTools = await listTools(String(claude.command), claudeArgs, claudeRoot);
		expect(claudeTools).toHaveLength(EXPECTED_TOOLS.length);
		expect(claudeTools.map((tool) => tool.name)).toEqual([...EXPECTED_TOOLS]);

		const codexRoot = join(cache, "codex");
		copyCodexPackage(codexRoot);
		const codexServers = object(codexMcp.mcpServers, "mcpServers");
		const codex = object(codexServers.sniff, "mcpServers.sniff");
		const codexArgs = serverArgs(codex, PLUGIN_ROOT, codexRoot);
		expect(codexArgs[1]).toBe(join(codexRoot, "server.js"));
		if (typeof codexArgs[1] !== "string") throw new Error("Codex server path is missing");
		assertContained(codexRoot, codexArgs[1]);
		expect(existsSync(join(codexRoot, "node_modules"))).toBe(false);
		expect(existsSync(join(codexRoot, "adapters"))).toBe(false);
		assertOpenGrepResource(codexRoot, OPENGREP_RULE_NAME);
		const codexTools = await listTools(String(codex.command), codexArgs, codexRoot);
		expect(codexTools).toHaveLength(EXPECTED_TOOLS.length);
		expect(codexTools.map((tool) => tool.name)).toEqual([...EXPECTED_TOOLS]);
	} finally {
		rmSync(cache, { recursive: true, force: true });
	}
});
