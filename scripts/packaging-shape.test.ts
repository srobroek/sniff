import { expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

type JsonObject = Record<string, unknown>;

const repoRoot = resolve(import.meta.dir, "..");
const codexRoot = join(repoRoot, "dist", "codex");
const packageJson = JSON.parse(
	readFileSync(join(repoRoot, "package.json"), "utf8"),
) as JsonObject;
const claudeManifest = JSON.parse(
	readFileSync(join(repoRoot, ".claude-plugin", "plugin.json"), "utf8"),
) as JsonObject;
const codexManifest = JSON.parse(
	readFileSync(join(codexRoot, "plugin.json"), "utf8"),
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

test("Claude metadata discovers its generated skill and shared MCP config", () => {
	expect(claudeManifest.name).toBe("sniff");
	expect(claudeManifest.version).toBe(packageJson.version);
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

test("Codex MCP package uses the portable stdio schema and plugin root", () => {
	expect(codexMcp.$schema).toBe(PORTABLE_MCP_SCHEMA);
	const servers = object(codexMcp.mcpServers, "mcpServers");
	const sniff = object(servers.sniff, "mcpServers.sniff");
	expect(sniff.type).toBe("stdio");
	expect(sniff.command).toBe("bun");
	expect(sniff.args).toEqual(["run", `\${PLUGIN_ROOT}/server.js`]);
	expect(sniff).not.toHaveProperty("url");
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
