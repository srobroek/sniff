import { expect, setDefaultTimeout, test } from "bun:test";
import {
	cpSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";

type JsonObject = Record<string, unknown>;

setDefaultTimeout(30_000);

const repoRoot = resolve(import.meta.dir, "..");
const codexRoot = join(repoRoot, "dist", "codex");
const claudeServerPath = join(repoRoot, "dist", "claude", "server.js");
const codexServerPath = join(codexRoot, "server.js");
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
	readFileSync(join(repoRoot, ".mcp.json"), "utf8"),
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
	cpSync(join(repoRoot, ".mcp.json"), join(destination, ".mcp.json"));
	cpSync(claudeServerPath, join(destination, "dist", "claude", "server.js"));
}

function copyCodexPackage(destination: string): void {
	mkdirSync(destination, { recursive: true });
	for (const file of ["plugin.json", "mcp.json", "server.js"] as const) {
		cpSync(join(codexRoot, file), join(destination, file));
	}
}

test("Claude metadata discovers its generated skill and shared MCP config", () => {
	expect(claudeManifest.name).toBe("sniff");
	expect(claudeManifest.version).toBe(packageJson.version);
	expect(ompManifest.version).toBe(packageJson.version);
	expect(claudeManifest.skills).toBe("./.claude/skills/");
	expect(claudeManifest.mcpServers).toBe("./.mcp.json");
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

test("Copied Claude and nested Codex caches serve exactly five MCP tools", async () => {
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
		const claudeTools = await listTools(String(claude.command), claudeArgs, claudeRoot);
		expect(claudeTools).toHaveLength(5);
		expect(claudeTools.map((tool) => tool.name)).toEqual(EXPECTED_TOOLS);

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
		const codexTools = await listTools(String(codex.command), codexArgs, codexRoot);
		expect(codexTools).toHaveLength(5);
		expect(codexTools.map((tool) => tool.name)).toEqual(EXPECTED_TOOLS);
	} finally {
		rmSync(cache, { recursive: true, force: true });
	}
});
