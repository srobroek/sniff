import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import sniffPlugin from "../../extensions/sniff-plugin.ts";
import { readRunManifest, runLeaseStateForTests } from "../../src/core/run-registry.ts";

type ToolOutput = { readonly details: { readonly ok: boolean; readonly error?: string; readonly result?: { readonly lease?: { capability: string; manifestId: string } } } };
type RegisteredTool = { readonly name: string; readonly execute: (id: string, params: unknown, signal: unknown, update: unknown, ctx: ExtensionContext) => Promise<ToolOutput> };

const temporary: string[] = [];
afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function loadExtension() {
  const tools = new Map<string, RegisteredTool>();
  const handlers = new Map<string, () => unknown>();
  const schema = { describe() { return this; }, optional() { return this; } };
  const api = {
    zod: { object: () => schema, unknown: () => schema, string: () => schema },
    registerTool: (tool: RegisteredTool) => tools.set(tool.name, tool),
    on: (event: string, handler: () => unknown) => handlers.set(event, handler),
  };
  sniffPlugin(api as unknown as ExtensionAPI);
  const run = (name: string, params: unknown, ctx: ExtensionContext) => {
    const found = tools.get(name);
    if (!found) throw new Error(`${name} was not registered`);
    return found.execute("id", params, undefined, undefined, ctx);
  };
  return { run, shutdown: async () => handlers.get("session_shutdown")?.() };
}

describe("OMP extension loads are separate run owners", () => {
  test("a load rejects another load's capability and releases its own runs at session shutdown", async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "sniff-omp-owner-")));
    temporary.push(root);
    writeFileSync(join(root, "a.ts"), "export const value = 1;\n");
    const ctx = { hasUI: false, mode: "rpc", cwd: root } as unknown as ExtensionContext;
    const first = loadExtension();
    const second = loadExtension();
    const previous = process.env.SNIFF_UNATTENDED_INTAKE;
    process.env.SNIFF_UNATTENDED_INTAKE = "1";
    let intake: ToolOutput;
    try {
      intake = await first.run("sniff_intake", { input: { target: { kind: "files", root, paths: ["a.ts"] }, intent: "audit", scopeMode: "full", interactive: false } }, ctx);
    } finally {
      if (previous === undefined) delete process.env.SNIFF_UNATTENDED_INTAKE;
      else process.env.SNIFF_UNATTENDED_INTAKE = previous;
    }
    const lease = intake.details.result?.lease;
    if (!lease) throw new Error(`intake issued no lease: ${intake.details.error}`);

    const crossLoad = await second.run("sniff_cancel", lease, ctx);
    expect(crossLoad.details).toEqual({ ok: false, error: "Unknown Sniff run capability" });
    expect(runLeaseStateForTests(lease.capability)?.state).toBe("live");
    expect(() => readRunManifest(lease.capability, lease.manifestId)).toThrow("Unknown Sniff run capability");

    await first.shutdown();
    expect(runLeaseStateForTests(lease.capability)).toMatchObject({ state: "cancelled", reason: "session shutdown" });
    await second.shutdown();
  });
});
