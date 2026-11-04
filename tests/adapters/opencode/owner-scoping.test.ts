import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { sniffOpenCodePlugin } from "../../../adapters/opencode/plugin.ts";
import { readRunManifest, runLeaseStateForTests } from "../../../src/core/run-registry.ts";
import { type FakeHost, fakeHost, toolContext } from "./fake-host.ts";

setDefaultTimeout(30_000);

const skillPath = join(resolve(import.meta.dir, "..", "..", ".."), "dist", "opencode", "skills", "sniff", "SKILL.md");
let scratch = "";

beforeAll(() => {
  scratch = realpathSync(mkdtempSync(join(tmpdir(), "sniff-opencode-owner-")));
});

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

function project(): string {
  const root = mkdtempSync(join(scratch, "project-"));
  writeFileSync(join(root, "source.ts"), "export const source = true;\n");
  return root;
}

async function load(directory: string): Promise<{ host: FakeHost; cleanup: () => Promise<void> }> {
  const host = fakeHost(directory);
  const cleanup = await sniffOpenCodePlugin({ skillPath }).setup(host.ctx);
  if (typeof cleanup !== "function") throw new Error("setup returned no cleanup");
  return { host, cleanup: async () => cleanup() };
}

function tool(host: FakeHost, name: string) {
  const found = host.tools.get(name);
  if (!found) throw new Error(`${name} was not registered`);
  return found;
}

function json(result: { readonly content?: unknown }): Record<string, unknown> {
  if (typeof result.content !== "string") throw new Error("tool content is not text");
  return JSON.parse(result.content) as Record<string, unknown>;
}

const plannedFiles = (root: string) => ({
  input: { target: { kind: "files", root, paths: ["source.ts"] }, intent: "audit", scopeMode: "quick", objectives: ["structure-and-maintainability"], budget: { maxMinutes: 5 } },
});

describe("OpenCode instances are separate run owners", () => {
  test("one location's capabilities and artifacts are unknown to another location's tools", async () => {
    const first = await load(project());
    const second = await load(project());
    try {
      const intake = json(await tool(first.host, "sniff_intake").execute(plannedFiles(project()), toolContext()));
      const lease = intake.lease as { capability: string; manifestId: string };
      const reportTarget = intake.reportTarget as Record<string, unknown>;
      const run = { capability: lease.capability, manifestId: lease.manifestId };

      await expect(tool(second.host, "sniff_run_analyzer").execute({ ...run, analyzer: "lizard:complexity" }, toolContext())).rejects.toThrow("Unknown Sniff run capability");
      await expect(tool(second.host, "sniff_cancel").execute(run, toolContext())).rejects.toThrow("Unknown Sniff run capability");
      const report = { generatedAt: "2026-09-11T00:00:00.000Z", target: { ...reportTarget, languages: ["TypeScript"] }, headline: "Owner fixture.", findings: [], coverage: [], suppressionCount: 0, systemicPatterns: [] };
      await expect(tool(second.host, "sniff_report").execute({ ...run, report }, toolContext())).rejects.toThrow("Unknown Sniff run capability");
      // The rejected calls left the issuing instance's lease live, and an ownerless lookup cannot see it.
      expect(runLeaseStateForTests(run.capability)?.state).toBe("live");
      expect(() => readRunManifest(run.capability, run.manifestId)).toThrow("Unknown Sniff run capability");

      const rendered = await tool(first.host, "sniff_report").execute({ ...run, report }, toolContext());
      const metadata = JSON.parse(String(rendered.content).split("\n")[0] ?? "{}") as { reportId: string; readCapability: string };
      const page = { readCapability: metadata.readCapability, reportId: metadata.reportId, relativePath: "index.json" };
      await expect(tool(second.host, "sniff_read_report_artifact").execute(page, toolContext())).rejects.toThrow("Unknown Sniff report artifact capability");
      expect(json(await tool(first.host, "sniff_read_report_artifact").execute(page, toolContext()))).toMatchObject({ offset: 0 });

      // Unloading the issuing instance drops its artifacts as well as its runs.
      await first.cleanup();
      await expect(tool(second.host, "sniff_read_report_artifact").execute(page, toolContext())).rejects.toThrow("Unknown Sniff report artifact capability");
    } finally {
      await first.cleanup();
      await second.cleanup();
    }
  });
});
