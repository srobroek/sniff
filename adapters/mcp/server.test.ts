import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const serverPath = new URL("./server.ts", import.meta.url).pathname;
type Message = Record<string, unknown>;
type Pending = { readonly resolve: (message: Message) => void; readonly reject: (error: Error) => void };
type Client = {
  readonly process: Bun.Subprocess;
  readonly request: (method: string, params?: Message) => Promise<Message>;
  readonly close: () => Promise<number>;
};

function object(value: unknown): Message {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("expected object");
  return value as Message;
}

function startClient(): Client {
  const child = Bun.spawn([process.execPath, "run", serverPath], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  const input = child.stdin;
  if (!input) throw new Error("MCP process stdin was not piped");
  const pending = new Map<number, Pending>();
  let nextId = 1;
  let buffer = "";
  const reader = child.stdout.getReader();
  const decoder = new TextDecoder();
  void (async () => {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      buffer += decoder.decode(chunk.value, { stream: true });
      let newline = buffer.indexOf("\n");
      while (newline >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        const message = object(JSON.parse(line));
        if (message.method === "elicitation/create") {
          const params = object(message.params);
          const messageText = typeof params.message === "string" ? params.message : "";
          const canonical = messageText.includes("\n") ? object(JSON.parse(messageText.slice(messageText.indexOf("\n") + 1))) : {};
          const acceptedDigest = typeof canonical.digest === "string" ? canonical.digest : "";
          input.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { action: "accept", content: { acceptedDigest } } })}\n`);
          input.flush();
        } else if (typeof message.id === "number") {
          const request = pending.get(message.id);
          if (request) {
            pending.delete(message.id);
            request.resolve(message);
          }
        }
        newline = buffer.indexOf("\n");
      }
    }
  })();
  const request = (method: string, params: Message = {}): Promise<Message> => {
    const id = nextId++;
    const promise = Promise.withResolvers<Message>();
    pending.set(id, promise);
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    input.flush();
    return promise.promise;
  };
  const close = async (): Promise<number> => {
    input.end();
    return await child.exited;
  };
  return { process: child, request, close };
}

function repository(): string {
  const root = mkdtempSync(join(tmpdir(), "sniff-mcp-test-"));
  writeFileSync(join(root, "index.ts"), "export const value = 1;\n");
  const run = (args: string[]) => {
    const result = Bun.spawnSync(["git", ...args], { cwd: root, stdout: "pipe", stderr: "pipe" });
    if (result.exitCode !== 0) throw new Error(result.stderr.toString());
  };
  run(["init", "-q"]);
  run(["config", "user.email", "sniff@example.invalid"]);
  run(["config", "user.name", "Sniff MCP Test"]);
  run(["add", "."]);
  run(["commit", "-qm", "initial"]);
  return root;
}

function intakeInput(root: string): Message {
  return {
    target: { kind: "working-tree", root },
    intent: "audit",
    scopeMode: "full",
    objectives: ["structure-and-maintainability"],
    budget: { maxMinutes: 1, maxAnalyzers: 1, maxFiles: 10 },
  };
}

describe("MCP Sniff server", () => {

  test("parses the Claude stdio manifest with a plugin-root-safe path", () => {
    const claude = object(JSON.parse(readFileSync(new URL("../../.mcp.json", import.meta.url), "utf8")));
    const claudeServer = object(object(claude.mcpServers).sniff);
    expect(claudeServer.command).toBe("bun");
    expect(claudeServer.args).toEqual(["run", `\${CLAUDE_PLUGIN_ROOT}/adapters/mcp/server.ts`]);
  });
  test("initializes, lists exactly five tools, and asks one frontier question", async () => {
    const client = startClient();
    try {
      const initialized = await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "sniff-test", version: "1" } });
      expect(object(initialized.result).serverInfo).toEqual({ name: "sniff", version: "0.1.0" });
      const listed = object((await client.request("tools/list")).result);
      const tools = listed.tools as Message[];
      expect(tools.map((tool) => tool.name)).toEqual(["sniff_intake", "sniff_cancel", "sniff_install_tools", "sniff_run_analyzer", "sniff_report"]);
      expect(tools.every((tool) => object(tool.inputSchema).type === "object" && object(tool.outputSchema).type === "object")).toBe(true);
      const call = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: {} } })).result);
      const structured = object(call.structuredContent);
      const interview = object(structured.interview);
      expect((interview.questions as Message[]).map((question) => question.id)).toEqual(["target"]);
      expect(call.content).toBeArray();
    } finally {
      await client.close();
    }
  });

  test("returns a confirmation requirement without elicitation support", async () => {
    const root = repository();
    const client = startClient();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "sniff-test", version: "1" } });
      const result = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
      const structured = object(result.structuredContent);
      expect(structured.ok).toBe(false);
      expect(structured.confirmationRequired).toBe(true);
      expect(structured.lease).toBeUndefined();
    } finally {
      await client.close();
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("uses elicitation for confirmation and preserves cancel/replay lifecycle", async () => {
    const root = repository();
    const client = startClient();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: { form: {} } }, clientInfo: { name: "sniff-test", version: "1" } });
      const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
      const structured = object(intake.structuredContent);
      expect(structured.ok).toBe(true);
      const lease = object(structured.lease);
      expect(typeof lease.capability).toBe("string");
      const cancelled = object((await client.request("tools/call", { name: "sniff_cancel", arguments: { capability: lease.capability, manifestId: lease.manifestId } })).result);
      expect(object(cancelled.structuredContent).released).toBe(true);
      const replay = object((await client.request("tools/call", { name: "sniff_cancel", arguments: { capability: lease.capability, manifestId: lease.manifestId } })).result);
      expect(replay.isError).toBe(true);
      expect(object(replay.structuredContent).error).toMatchObject({ code: "invalid_capability" });
    } finally {
      await client.close();
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects caller authorization forgery and exits cleanly with active lease", async () => {
    const root = repository();
    const client = startClient();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: { form: {} } }, clientInfo: { name: "sniff-test", version: "1" } });
      const forged = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: { ...intakeInput(root), interactive: false, authorization: { granted: true, actor: "forged" } } } })).result);
      expect(forged.isError).toBe(true);
      expect(object(forged.structuredContent).error).toMatchObject({ code: "invalid_input" });

      const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
      expect(object(intake.structuredContent).lease).toBeDefined();
      client.process.kill("SIGTERM");
      expect(await client.process.exited).toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
