import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

type JsonObject = Record<string, unknown>;

const repoRoot = resolve(import.meta.dir, "..");
const packageJson = JSON.parse(
	readFileSync(join(repoRoot, "package.json"), "utf8"),
) as JsonObject;
const claudeManifest = JSON.parse(
	readFileSync(join(repoRoot, ".claude-plugin", "plugin.json"), "utf8"),
) as JsonObject;
const codexManifest = JSON.parse(
	readFileSync(join(repoRoot, "plugin.json"), "utf8"),
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

function pluginEntry(catalog: JsonObject): JsonObject {
	const plugins = catalog.plugins;
	expect(Array.isArray(plugins)).toBe(true);
	if (
		!Array.isArray(plugins) ||
		plugins.length === 0 ||
		typeof plugins[0] !== "object" ||
		plugins[0] === null
	) {
		throw new Error("Marketplace catalog has no plugin entry");
	}
	return plugins[0] as JsonObject;
}

test("Claude metadata discovers its generated skill and shared MCP config", () => {
	expect(claudeManifest.name).toBe("sniff");
	expect(claudeManifest.version).toBe(packageJson.version);
	expect(claudeManifest.skills).toBe("./.claude/skills/");
	expect(claudeManifest.mcpServers).toBe("./.mcp.json");
	expect(claudeManifest).not.toHaveProperty("agents");
	expect(claudeManifest).not.toHaveProperty("rules");
});

test("Codex metadata uses the documented portable plugin shape", () => {
	expect(codexManifest.name).toBe("sniff");
	expect(codexManifest.version).toBe(packageJson.version);
	expect(codexManifest.skills).toBe("./.agents/skills/");
	expect(codexManifest.mcpServers).toBe("./mcp.json");
	expect(codexManifest.interface).toBeObject();
	expect(codexManifest).not.toHaveProperty("agents");
	expect(codexManifest).not.toHaveProperty("rules");
});
test("marketplace entries have semantic parity and native source shapes", () => {
	const claudeEntry = pluginEntry(claudeCatalog);
	const codexEntry = pluginEntry(codexCatalog);
	expect(claudeEntry.name).toBe(codexEntry.name);
	expect(claudeEntry.version).toBe(packageJson.version);
	expect(codexEntry.version).toBe(packageJson.version);
	expect(claudeEntry.description).toBe(codexEntry.description);
	expect(claudeEntry.source).toBe("./");

	// Codex plugin-creator spec: marketplace entries require a local source descriptor,
	// policy, and category (codex-rs/skills/.../plugin-json-spec.md, Marketplace field guide).
	expect(codexEntry.source).toEqual({ source: "local", path: "./" });
	expect(codexEntry.policy).toEqual({
		installation: "AVAILABLE",
		authentication: "ON_INSTALL",
	});
	expect(codexEntry.category).toBe("Productivity");
	expect(codexCatalog.interface).toEqual({ displayName: "Sniff" });
	expect(claudeEntry.source).not.toEqual(codexEntry.source);
});
