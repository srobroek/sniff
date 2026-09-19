import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import Ajv2020 from "ajv/dist/2020.js";
import { BoundedStdioTransport, Semaphore } from "./server.ts";

const serverPath = new URL("./server.ts", import.meta.url).pathname;
setDefaultTimeout(30_000);

type Message = Record<string, unknown>;
type Pending = { readonly resolve: (message: Message) => void; readonly reject: (error: Error) => void };
type Client = {
  readonly process: Bun.Subprocess;
  readonly request: (method: string, params?: Message) => Promise<Message>;
  readonly rawRequest: (id: number, message: Message) => Promise<Message>;
  readonly rawLine: (line: string) => void;
  readonly close: () => Promise<number>;
  readonly stderr: () => Promise<string>;
  readonly elicitationParams: Message[];
};

function object(value: unknown): Message {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("expected object");
  return value as Message;
}

type ElicitationAction = "accept" | "decline" | "method-not-found" | "error";

function startClient(action: ElicitationAction = "accept", env: Record<string, string> = {}, sequence: readonly ElicitationAction[] = []): Client {
  const child = Bun.spawn([process.execPath, "run", serverPath], { stdin: "pipe", stdout: "pipe", stderr: "pipe", env: { ...process.env, ...env } });
  const input = child.stdin;
  if (!input) throw new Error("MCP process stdin was not piped");
  const pending = new Map<number, Pending>();
  const elicitationParams: Message[] = [];
  const stderrPromise = child.stderr ? new Response(child.stderr).text() : Promise.resolve("");
  let nextId = 1;
  let buffer = "";
  const reader = child.stdout.getReader();
  const decoder = new TextDecoder();
  void (async () => {
    try {
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
            elicitationParams.push(params);
            const messageText = typeof params.message === "string" ? params.message : "";
            const canonical = messageText.includes("\n") ? object(JSON.parse(messageText.slice(messageText.indexOf("\n") + 1))) : {};
            const acceptedDigest = typeof canonical.digest === "string" ? canonical.digest : "";
            const responseAction = sequence[elicitationParams.length - 1] ?? action;
            if (responseAction === "method-not-found") {
              input.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } })}\n`);
            } else if (responseAction === "error") {
              input.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: 42, message: "Codex elicitation failed" } })}\n`);
            } else {
              const result = responseAction === "accept" ? { action: "accept", content: { acceptedDigest } } : { action: "decline" };
              input.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, result })}\n`);
            }
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
    } catch {
      // The process may close while the reader is awaiting its final chunk.
    }
  })();
  const rawLine = (line: string): void => {
    input.write(`${line}\n`);
    input.flush();
  };
  const rawRequest = (id: number, message: Message): Promise<Message> => {
    const promise = Promise.withResolvers<Message>();
    pending.set(id, promise);
    rawLine(JSON.stringify({ ...message, id }));
    return promise.promise;
  };
  const request = (method: string, params: Message = {}): Promise<Message> => rawRequest(nextId++, { jsonrpc: "2.0", method, params });
  const close = async (): Promise<number> => {
    input.end();
    return await child.exited;
  };
  return { process: child, request, rawRequest, rawLine, close, stderr: () => stderrPromise, elicitationParams };
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
  writeFileSync(join(root, "index.ts"), "export const value = 2;\n");
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
function executable(path: string, body: string): void {
  writeFileSync(path, body, { mode: 0o755 });
}

function fakeToolchain(): { readonly root: string; readonly bin: string; readonly env: Record<string, string> } {
  const root = mkdtempSync(join(tmpdir(), "sniff-mcp-tools-"));
  const bin = join(root, "bin");
  mkdirSync(bin);
  return { root, bin, env: { HOME: root, SNIFF_TOOLKIT_CACHE_DIR: join(root, "toolkits"), PATH: `${bin}:${process.env.PATH ?? ""}` } };
}

async function waitForFile(path: string, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(path) && Date.now() < deadline) await Bun.sleep(10);
  if (!existsSync(path)) throw new Error(`Timed out waiting for ${path}`);
}

function reportInputForConfirmation(summary: Message): Message {
  const target = object(summary.target);
  const reportTarget: Message = {
    kind: target.kind === "working-tree" ? "uncommitted" : target.kind,
    label: typeof target.label === "string" ? target.label : "working tree",
    scopeMode: typeof summary.scopeMode === "string" ? summary.scopeMode : "full",
    languages: ["TypeScript"],
    filesAnalyzed: typeof target.filesAnalyzed === "number" ? target.filesAnalyzed : 1,
  };
  if (typeof target.baseRef === "string") reportTarget.baseRef = target.baseRef;
  return {
    generatedAt: "2026-09-11T08:00:00.000Z",
    target: reportTarget,
    headline: "Deterministic MCP report fixture.",
    findings: [],
    coverage: [{ dimension: "complexity", tool: "lizard", analysisClass: "local", status: "skipped", notes: "The protocol fixture does not run analyzers." }],
    suppressionCount: 0,
    systemicPatterns: ["The fixture intentionally contains no findings."],
  };
}

function outputSchemaValidator(tools: Message[], name: string): (value: unknown) => boolean {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`Missing advertised tool ${name}`);
  const validate = new Ajv2020({ strict: false }).compile(tool.outputSchema as Record<string, unknown>);
  return (value: unknown): boolean => {
    const valid = validate(value) as boolean;
    return valid;
  };
}

describe("MCP transport and concurrency units", () => {
  test("returns recoverable invalid-request and invalid-params errors without dispatching malformed notifications", async () => {
    const input = new PassThrough();
    const outputLines: Message[] = [];
    const output = new Writable({ write(chunk, _encoding, callback) { outputLines.push(object(JSON.parse(chunk.toString()))); callback(); } });
    const dispatched: Message[] = [];
    const transport = new BoundedStdioTransport(input, output, 512);
    transport.onmessage = (message) => dispatched.push(object(message));
    await transport.start();
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: 42 } })}\n`);
    input.write(`${JSON.stringify({ jsonrpc: "2.0", method: "tools/call", params: { name: 42 } })}\n`);
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 8, method: "ping" })}\n`);
    await Promise.resolve();
    await Promise.resolve();
    expect(outputLines[0]).toMatchObject({ jsonrpc: "2.0", id: 7, error: { code: -32602 } });
    expect(dispatched).toHaveLength(1);
    expect(dispatched[0]).toMatchObject({ id: 8, method: "ping" });
    await transport.close();
  });

  test("emits a bounded-frame error and continues with the next request", async () => {
    const input = new PassThrough();
    const outputLines: Message[] = [];
    const output = new Writable({ write(chunk, _encoding, callback) { outputLines.push(object(JSON.parse(chunk.toString()))); callback(); } });
    const dispatched: Message[] = [];
    const transport = new BoundedStdioTransport(input, output, 64);
    transport.onmessage = (message) => dispatched.push(object(message));
    await transport.start();
    input.write(`${"x".repeat(80)}\n`);
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 9, method: "ping" })}\n`);
    await Promise.resolve();
    await Promise.resolve();
    expect(outputLines[0]).toMatchObject({ id: null, error: { code: -32600 } });
    expect(dispatched).toHaveLength(1);
    expect(dispatched[0]).toMatchObject({ id: 9, method: "ping" });
    await transport.close();
  });

  test("bounds queued requests and removes aborted waiters immediately", async () => {
    const semaphore = new Semaphore();
    const active = await Promise.all(Array.from({ length: 8 }, () => semaphore.acquire(new AbortController().signal)));
    expect(semaphore.activeCount).toBe(8);
    const abortedController = new AbortController();
    const queued = Array.from({ length: 31 }, () => semaphore.acquire(new AbortController().signal));
    const aborted = semaphore.acquire(abortedController.signal);
    expect(semaphore.queuedCount).toBe(32);
    await expect(semaphore.acquire(new AbortController().signal)).rejects.toMatchObject({ code: "server_busy" });
    abortedController.abort();
    await expect(aborted).rejects.toMatchObject({ name: "AbortError" });
    expect(semaphore.queuedCount).toBe(31);
    for (const release of active) release();
    for (let offset = 0; offset < queued.length; offset += 8) {
      const batch = await Promise.all(queued.slice(offset, offset + 8));
      for (const release of batch) release();
    }
    expect(semaphore.activeCount).toBe(0);
    expect(semaphore.queuedCount).toBe(0);
  });
});

describe("MCP Sniff server", () => {

  test("parses the Claude stdio manifest with a plugin-root-safe path", () => {
    const claude = object(JSON.parse(readFileSync(new URL("../../claude-mcp.json", import.meta.url), "utf8")));
    const claudeServer = object(object(claude.mcpServers).sniff);
    expect(claudeServer.command).toBe("bun");
    expect(claudeServer.args).toEqual(["run", `\${CLAUDE_PLUGIN_ROOT}/dist/claude/server.js`]);
  });
  test("initializes, lists exactly seven tools, and asks one frontier question", async () => {
    const client = startClient();
    try {
      const initialized = await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "sniff-test", version: "1" } });
      expect(object(initialized.result).serverInfo).toEqual({ name: "sniff", version: "0.1.0" });
      const listed = object((await client.request("tools/list")).result);
      const tools = listed.tools as Message[];
      const analyzerReader = tools.find((tool) => tool.name === "sniff_read_analyzer_artifact");
      if (!analyzerReader) throw new Error("Missing sniff_read_analyzer_artifact tool");
      const analyzerReaderSchema = object(analyzerReader.inputSchema);
      expect(analyzerReaderSchema.oneOf).toBeUndefined();
      expect(analyzerReaderSchema.required).toEqual(["analyzerResultId", "readCapability"]);
      expect(Object.keys(object(analyzerReaderSchema.properties)).sort()).toEqual(["analyzerResultId", "maxBytes", "offset", "readCapability", "relativePath", "sourcePath"]);
      const reportReader = tools.find((tool) => tool.name === "sniff_read_report_artifact");
      if (!reportReader) throw new Error("Missing sniff_read_report_artifact tool");
      const reportReaderSchema = object(reportReader.inputSchema);
      expect(reportReaderSchema.required).toEqual(["readCapability", "reportId", "relativePath"]);
      expect(Object.keys(object(reportReaderSchema.properties)).sort()).toEqual(["offset", "readCapability", "relativePath", "reportId"]);
      expect(tools.map((tool) => tool.name)).toEqual(["sniff_intake", "sniff_cancel", "sniff_install_tools", "sniff_run_analyzer", "sniff_report", "sniff_read_report_artifact", "sniff_read_analyzer_artifact"]);
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
  test("advertises a compilable report schema with optional host-hydrated extension", async () => {
    const client = startClient();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "report-schema-test", version: "1" } });
      const tools = object((await client.request("tools/list")).result).tools as Message[];
      const reportTool = tools.find((tool) => tool.name === "sniff_report");
      if (!reportTool) throw new Error("Missing sniff_report tool");
      const schema = object(reportTool.inputSchema);
      const validate = new Ajv2020({ strict: false }).compile(schema as Record<string, unknown>);
      const report = {
        generatedAt: "2026-09-11T08:00:00Z",
        target: { kind: "files", label: "a.ts", scopeMode: "full", languages: ["TypeScript"], filesAnalyzed: 1 },
        headline: "Schema fixture",
        findings: [],
        coverage: [],
        suppressionCount: 0,
        systemicPatterns: [],
      };
      expect(validate({ capability: "capability", manifestId: "manifest-id", report })).toBe(true);
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
  test("rejects analyzer artifact reads with zero or multiple selectors", async () => {
    const client = startClient();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "analyzer-selector-test", version: "1" } });
      const base = { analyzerResultId: "analyzer-result", readCapability: "read-capability" };
      for (const selectors of [{}, { relativePath: "index.json", sourcePath: "src/index.ts" }]) {
        const result = object((await client.request("tools/call", { name: "sniff_read_analyzer_artifact", arguments: { ...base, ...selectors } })).result);
        expect(result.isError).toBe(true);
        expect(object(result.structuredContent).error).toEqual({ code: "invalid_input", message: "Provide exactly one analyzer artifact relativePath or sourcePath" });
      }
    } finally {
      await client.close();
    }
  });
  // @ts-expect-error Bun runtime supports timeout options despite installed test typings.
  test("reads analyzer artifacts by relativePath and sourcePath", { timeout: 30_000 }, async () => {
    const toolsFixture = fakeToolchain();
    executable(join(toolsFixture.bin, "lizard"), `#!/bin/sh
if [ "$1" = "--version" ] || [ "$1" = "--help" ]; then exit 0; fi
printf 'nloc,ccn,param,length,location,file,function\\n60,11,1,55,1-55,é.ts,main\\n'
`);
    const root = repository();
    const client = startClient("accept", toolsFixture.env);
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "analyzer-reader-test", version: "1" } });
      const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
      const lease = object(object(intake.structuredContent).lease);
      const analyzer = object((await client.request("tools/call", { name: "sniff_run_analyzer", arguments: { capability: lease.capability, manifestId: lease.manifestId, analyzer: "lizard:complexity" } })).result);
      const analyzerStructured = object(analyzer.structuredContent);
      expect(analyzerStructured.ok).toBe(true);
      const analyzerResultId = analyzerStructured.analyzerResultId;
      const readCapability = analyzerStructured.readCapability;
      expect(typeof analyzerResultId).toBe("string");
      expect(typeof readCapability).toBe("string");
      const index = object((await client.request("tools/call", { name: "sniff_read_analyzer_artifact", arguments: { analyzerResultId, readCapability, relativePath: "index.json", maxBytes: 8 } })).result);
      const indexStructured = object(index.structuredContent);
      expect(indexStructured.ok).toBe(true);
      expect(indexStructured.bytes).toBeLessThanOrEqual(8);
      expect(indexStructured.relativePath).toBe("index.json");
      const descriptors = analyzerStructured.descriptors as Message[];
      const source = descriptors.find((descriptor) => typeof descriptor.sourcePath === "string");
      if (!source) throw new Error("Analyzer fixture did not produce a source descriptor");
      const sourceRead = object((await client.request("tools/call", { name: "sniff_read_analyzer_artifact", arguments: { analyzerResultId, readCapability, sourcePath: source.sourcePath } })).result);
      const sourceStructured = object(sourceRead.structuredContent);
      expect(sourceStructured.ok).toBe(true);
      expect(sourceStructured.sourcePath).toBe(source.sourcePath);
      const sourceContent = String(sourceStructured.content);
      const multibyteOffset = Buffer.from(sourceContent.slice(0, sourceContent.indexOf("é")), "utf8").byteLength;
      const tooSmall = object((await client.request("tools/call", { name: "sniff_read_analyzer_artifact", arguments: { analyzerResultId, readCapability, relativePath: source.relativePath, offset: multibyteOffset, maxBytes: 1 } })).result);
      expect(tooSmall.isError).toBe(true);
      expect(object(tooSmall.structuredContent).error).toEqual({ code: "invalid_input", message: "Analyzer artifact maxBytes must be an integer from 4 through 65536" });
      const bounded = object((await client.request("tools/call", { name: "sniff_read_analyzer_artifact", arguments: { analyzerResultId, readCapability, relativePath: source.relativePath, offset: multibyteOffset, maxBytes: 4 } })).result);
      const boundedStructured = object(bounded.structuredContent);
      expect(Number(boundedStructured.bytes)).toBeGreaterThan(0);
      expect(Number(boundedStructured.bytes)).toBeLessThanOrEqual(4);
      expect(Number(boundedStructured.nextOffset)).toBeGreaterThan(multibyteOffset);
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(root, { recursive: true, force: true });
      rmSync(toolsFixture.root, { recursive: true, force: true });
    }
  });

  test("issues a lifecycle lease for explicit noninteractive intake without elicitation", async () => {
    const root = repository();
    const client = startClient();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "headless-test", version: "1" } });
      const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: { ...intakeInput(root), interactive: false } } })).result);
      const structured = object(intake.structuredContent);
      expect(structured.ok).toBe(true);
      expect(client.elicitationParams).toHaveLength(0);
      const confirmation = object(structured.confirmation);
      expect(confirmation.scopeMode).toBe("full");
      expect(confirmation).not.toHaveProperty("files");
      const lease = object(structured.lease);
      expect(typeof lease.capability).toBe("string");
      expect(typeof lease.manifestId).toBe("string");
      const cancelled = object((await client.request("tools/call", { name: "sniff_cancel", arguments: { capability: lease.capability, manifestId: lease.manifestId } })).result);
      expect(object(cancelled.structuredContent).released).toBe(true);
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("issues a minimal noninteractive lease with recorded defaults and gaps", async () => {
    const root = repository();
    const client = startClient();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "minimal-headless-test", version: "1" } });
      const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: { target: { kind: "working-tree", root }, intent: "audit", interactive: false } } })).result);
      const structured = object(intake.structuredContent);
      expect(structured.ok).toBe(true);
      expect(client.elicitationParams).toHaveLength(0);
      const confirmation = object(structured.confirmation);
      expect(confirmation.scopeMode).toBe("full");
      expect(confirmation).not.toHaveProperty("files");
      expect(structured).not.toHaveProperty("manifest");
      expect(structured).not.toHaveProperty("files");
      const lease = object(structured.lease);
      expect(typeof lease.capability).toBe("string");
      expect(typeof lease.manifestId).toBe("string");
      const cancelled = object((await client.request("tools/call", { name: "sniff_cancel", arguments: { capability: lease.capability, manifestId: lease.manifestId } })).result);
      expect(object(cancelled.structuredContent).released).toBe(true);
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("keeps incomplete interactive intake at the ordered frontier", async () => {
    const root = repository();
    const client = startClient();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "interactive-frontier-test", version: "1" } });
      const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: { target: { kind: "working-tree", root }, intent: "audit", interactive: true } } })).result);
      const structured = object(intake.structuredContent);
      expect(structured.ok).toBe(true);
      expect(object(structured.interview).questions).toEqual([
        expect.objectContaining({ id: "scopeMode" }),
      ]);
      expect(structured.lease).toBeUndefined();
      expect(client.elicitationParams).toHaveLength(0);
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("advertises exact discriminated intake target variants", async () => {
    const client = startClient();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "schema-test", version: "1" } });
      const tools = object((await client.request("tools/list")).result).tools as Message[];
      const intakeTool = tools.find((tool) => tool.name === "sniff_intake");
      if (!intakeTool) throw new Error("Missing sniff_intake tool");
      const inputSchema = object(intakeTool.inputSchema);
      const inputProperties = object(inputSchema.properties);
      const intakeInput = object(inputProperties.input);
      const targetSchema = object(object(intakeInput.properties).target);
      const variants = targetSchema.oneOf as Message[];
      expect(variants).toHaveLength(14);
      const wholeRepo = variants.find((variant) => object(object(variant).properties).kind && object(object(object(variant).properties).kind).const === "whole-repo");
      expect(wholeRepo).toBeDefined();
      const validate = new Ajv2020({ strict: false }).compile(targetSchema as Record<string, unknown>);
      expect(validate({ kind: "whole-repo", root: "/tmp/repo" })).toBe(true);
      expect(validate({ kind: "working-tree", root: "/tmp/repo", path: "src" })).toBe(false);
      expect(validate({ kind: "whole-repo", root: "/tmp/repo", extra: true })).toBe(false);
      expect(validate({ kind: "unknown", root: "/tmp/repo" })).toBe(false);
    } finally {
      await client.close();
    }
  });

  test("accepts minimal optional target and history window variants while rejecting extras", async () => {
    const client = startClient();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "optional-schema-test", version: "1" } });
      const tools = object((await client.request("tools/list")).result).tools as Message[];
      const intakeTool = tools.find((tool) => tool.name === "sniff_intake");
      if (!intakeTool) throw new Error("Missing sniff_intake tool");
      const intakeInput = object(object(intakeTool.inputSchema).properties).input;
      const targetSchema = object(object(intakeInput).properties).target;
      const variants = object(targetSchema).oneOf as Message[];
      const variant = (kind: string): Message => {
        const found = variants.find((candidate) => object(object(candidate).properties).kind && object(object(object(candidate).properties).kind).const === kind);
        if (!found) throw new Error(`Missing ${kind} target variant`);
        return found;
      };
      const validateTarget = new Ajv2020({ strict: false }).compile(targetSchema as Record<string, unknown>);
      expect(validateTarget({ kind: "branch", root: "/tmp/repo", branch: "main" })).toBe(true);
      expect(validateTarget({ kind: "branch", root: "/tmp/repo", branch: "main", base: "origin/main" })).toBe(true);
      expect(validateTarget({ kind: "repository", repository: "owner/repo" })).toBe(true);
      expect(validateTarget({ kind: "repository", repository: "owner/repo", ref: "main" })).toBe(true);
      expect(validateTarget({ kind: "release", repository: "owner/repo", tag: "v1.0.0" })).toBe(true);
      expect(validateTarget({ kind: "release", repository: "owner/repo", tag: "v1.0.0", previousTag: "v0.9.0" })).toBe(true);
      expect(validateTarget({ kind: "branch", root: "/tmp/repo", branch: "main", extra: true })).toBe(false);

      const historyWindow = object(object(variant("history")).properties).window;
      const validateWindow = new Ajv2020({ strict: false }).compile(historyWindow as Record<string, unknown>);
      const history = (window: Message): Message => ({ kind: "history", rootOrRepository: "/tmp/repo", window });
      expect(validateWindow({ kind: "refs", base: "main", head: "HEAD" })).toBe(true);
      expect(validateWindow({ kind: "since-date", date: "2026-01-01" })).toBe(true);
      expect(validateWindow({ kind: "last-commits", count: 1 })).toBe(true);
      expect(validateWindow({ kind: "since-release", release: "v1.0.0" })).toBe(true);
      expect(validateWindow({ kind: "previous-release" })).toBe(true);
      expect(validateWindow({ kind: "context-aware-default" })).toBe(true);
      expect(validateTarget(history({ kind: "context-aware-default" }))).toBe(true);
      expect(validateWindow({ kind: "since-date", date: "2026-01-01", extra: true })).toBe(false);
    } finally {
      await client.close();
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
  test("uses strict and modern elicitation capability shapes", async () => {
    const root = repository();
    for (const [protocolVersion, capabilities, expectedMode] of [
      ["2025-06-18", { elicitation: {} }, undefined],
      ["2025-11-25", { elicitation: { form: {} } }, "form"],
    ] as const) {
      const client = startClient();
      try {
        await client.request("initialize", { protocolVersion, capabilities, clientInfo: { name: "shape-test", version: "1" } });
        const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
        const structured = object(intake.structuredContent);
        expect(structured.ok).toBe(true);
        const elicitation = client.elicitationParams[0];
        expect(elicitation).toBeDefined();
        expect(elicitation?.mode).toBe(expectedMode);
        const lease = object(structured.lease);
        await client.request("tools/call", { name: "sniff_cancel", arguments: { capability: lease.capability, manifestId: lease.manifestId } });
      } finally {
        await client.close();
      }
    }
    rmSync(root, { recursive: true, force: true });
  });

  test("returns recoverable errors for malformed initialize and tool requests while malformed notifications stay harmless", async () => {
    const client = startClient();
    try {
      const malformedInitialize = await client.rawRequest(90, { jsonrpc: "2.0", method: "initialize", params: { protocolVersion: 42 } });
      expect(malformedInitialize).toMatchObject({ id: 90, error: { code: -32602 } });
      const malformedEnvelope = await client.rawRequest(91, { jsonrpc: "1.0", method: "ping" });
      expect(malformedEnvelope).toMatchObject({ id: 91, error: { code: -32600 } });
      client.rawLine(JSON.stringify({ jsonrpc: "2.0", method: "tools/call", params: { name: 42 } }));
      const unsupported = await client.request("initialize", { protocolVersion: "2099-01-01", capabilities: {}, clientInfo: { name: "invalid-test", version: "1" } });
      expect(unsupported).toMatchObject({ error: { code: -32600 } });
      const listed = await client.request("tools/list");
      expect(object(listed.result).tools).toBeArray();
    } finally {
      const code = await client.close();
      expect(code).toBe(0);
      expect(await client.stderr()).toBe("");
    }
  });
  test("denies elicited intake without issuing a lease", async () => {
    const root = repository();
    const client = startClient("decline");
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "denial-test", version: "1" } });
      const result = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
      const structured = object(result.structuredContent);
      expect(result.isError).toBe(true);
      expect(structured).toMatchObject({ ok: false, error: { code: "confirmation_required" } });
      expect(structured.lease).toBeUndefined();
      expect(client.elicitationParams).toHaveLength(1);
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(root, { recursive: true, force: true });
    }
  });
  test("authorizes install plans and rejects denial or caller-selected mutation paths", async () => {
    const approvedTools = fakeToolchain();
    const approvedMarker = join(approvedTools.root, "install-called");
    executable(join(approvedTools.bin, "jscpd"), "#!/bin/sh\nexit 17\n");
    executable(join(approvedTools.bin, "mise"), `#!/bin/sh
case "$1" in
  install)
    printf called > ${approvedMarker}
    cat > ${join(approvedTools.bin, "jscpd")} <<'SCRIPT'
#!/bin/sh
exit 0
SCRIPT
    chmod +x ${join(approvedTools.bin, "jscpd")}
    ;;
  env)
    printf '%s\\n' '{"PATH":"${approvedTools.bin}"}'
    ;;
esac
exit 0
`);
    const approved = startClient("accept", approvedTools.env);
    try {
      await approved.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "install-approval-test", version: "1" } });
      const result = object((await approved.request("tools/call", { name: "sniff_install_tools", arguments: { mode: "install", bundles: ["dup"] } })).result);
      const structured = object(result.structuredContent);
      expect(structured.ok).toBe(true);
      expect(object((await approved.request("tools/call", { name: "sniff_install_tools", arguments: { mode: "diagnose", bundles: ["dup"] } })).result).structuredContent).toBeDefined();
      expect(existsSync(approvedMarker)).toBe(true);
      expect(approved.elicitationParams).toHaveLength(1);
    } finally {
      await approved.close();
      expect(await approved.stderr()).toBe("");
      rmSync(approvedTools.root, { recursive: true, force: true });
    }

    const deniedTools = fakeToolchain();
    const deniedMarker = join(deniedTools.root, "install-called");
    executable(join(deniedTools.bin, "mise"), `#!/bin/sh
printf called > ${deniedMarker}
exit 0
`);
    const denied = startClient("decline", deniedTools.env);
    try {
      await denied.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "install-denial-test", version: "1" } });
      const result = object((await denied.request("tools/call", { name: "sniff_install_tools", arguments: { mode: "install", bundles: ["dup"] } })).result);
      expect(result.isError).toBe(true);
      expect(object(result.structuredContent).error).toMatchObject({ code: "confirmation_required" });
      expect(existsSync(deniedMarker)).toBe(false);
      const forgedPath = object((await denied.request("tools/call", { name: "sniff_install_tools", arguments: { mode: "install", bundles: ["dup"], path: deniedTools.root } })).result);
      expect(forgedPath.isError).toBe(true);
      expect(object(forgedPath.structuredContent).error).toMatchObject({ code: "invalid_input" });
      expect(existsSync(deniedMarker)).toBe(false);
    } finally {
      await denied.close();
      expect(await denied.stderr()).toBe("");
      rmSync(deniedTools.root, { recursive: true, force: true });
    }
  });
  test("classifies a Codex method-not-found elicitation failure without installing", async () => {
    const toolsFixture = fakeToolchain();
    const mutationMarker = join(toolsFixture.root, "install-called");
    const usableTool = "#!/bin/sh\nexit 0\n";
    for (const bin of ["opengrep", "lizard", "scc", "sg", "tokei"]) executable(join(toolsFixture.bin, bin), usableTool);
    for (const bin of ["pipx", "brew", "cargo"]) {
      executable(join(toolsFixture.bin, bin), `#!/bin/sh\nprintf called > ${mutationMarker}\nexit 0\n`);
    }
    const client = startClient("method-not-found", toolsFixture.env);
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "codex-headless-install-test", version: "1" } });
      const result = object((await client.request("tools/call", { name: "sniff_install_tools", arguments: { mode: "install", bundles: ["core"], dryRun: true } })).result);
      expect(result.isError).toBe(true);
      expect(object(result.structuredContent).error).toMatchObject({ code: "confirmation_required" });
      expect(existsSync(mutationMarker)).toBe(false);
      expect(client.elicitationParams).toHaveLength(1);
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(toolsFixture.root, { recursive: true, force: true });
    }
  });
  test("maps arbitrary Codex elicitation errors to confirmation_required without installing", async () => {
    const toolsFixture = fakeToolchain();
    const mutationMarker = join(toolsFixture.root, "install-called");
    const usableTool = "#!/bin/sh\nexit 0\n";
    for (const bin of ["opengrep", "lizard", "scc", "sg", "tokei"]) executable(join(toolsFixture.bin, bin), usableTool);
    for (const bin of ["pipx", "brew", "cargo"]) {
      executable(join(toolsFixture.bin, bin), `#!/bin/sh\nprintf called > ${mutationMarker}\nexit 0\n`);
    }
    const client = startClient("error", toolsFixture.env);
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "codex-arbitrary-error-test", version: "1" } });
      const result = object((await client.request("tools/call", { name: "sniff_install_tools", arguments: { mode: "install", bundles: ["core"], dryRun: true } })).result);
      expect(result.isError).toBe(true);
      expect(object(result.structuredContent).error).toMatchObject({ code: "confirmation_required" });
      expect(existsSync(mutationMarker)).toBe(false);
      expect(client.elicitationParams).toHaveLength(1);
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(toolsFixture.root, { recursive: true, force: true });
    }
  });
  // @ts-expect-error Bun runtime supports timeout options despite installed test typings.
  test("renders reports and saves only after approval", { timeout: 30_000 }, async () => {
    const root = repository();
    const client = startClient("accept");
    const outputRoot = mkdtempSync(join(import.meta.dir, ".sniff-mcp-report-output-"));
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "report-test", version: "1" } });
      const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
      const intakeStructured = object(intake.structuredContent);
      const lease = object(intakeStructured.lease);
      const rendered = object((await client.request("tools/call", { name: "sniff_report", arguments: { capability: lease.capability, manifestId: lease.manifestId, mode: "render", report: reportInputForConfirmation(object(intakeStructured.confirmation)) } })).result);
      expect(rendered.isError).not.toBe(true);
      expect(object(rendered.structuredContent).savedPaths).toEqual([]);
      expect(object(rendered.structuredContent).summary).toContain("Deterministic MCP report fixture.");
      const renderedStructured = object(rendered.structuredContent);
      const listedTools = object((await client.request("tools/list")).result).tools as Message[];
      const readValid = outputSchemaValidator(listedTools, "sniff_read_report_artifact");
      const read = object((await client.request("tools/call", { name: "sniff_read_report_artifact", arguments: { readCapability: renderedStructured.readCapability, reportId: renderedStructured.reportId, relativePath: "summary.md" } })).result);
      const readStructured = object(read.structuredContent);
      expect(readStructured.content).toContain("Deterministic MCP report fixture.");
      expect(readStructured.eof).toBe(true);
      expect(readValid(readStructured)).toBe(true);
      const rejectedRead = object((await client.request("tools/call", { name: "sniff_read_report_artifact", arguments: { readCapability: "wrong-capability", reportId: renderedStructured.reportId, relativePath: "summary.md" } })).result);
      expect(rejectedRead.isError).toBe(true);

      const secondIntake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
      const secondStructured = object(secondIntake.structuredContent);
      const secondLease = object(secondStructured.lease);
      const output = outputRoot;
      const saved = object((await client.request("tools/call", { name: "sniff_report", arguments: { capability: secondLease.capability, manifestId: secondLease.manifestId, mode: "save", path: output, report: reportInputForConfirmation(object(secondStructured.confirmation)) } })).result);
      expect(object(saved.structuredContent).ok).toBe(true);
      const savedPaths = object(saved.structuredContent).savedPaths as string[];
      expect(savedPaths.every((path) => existsSync(path))).toBe(true);
      expect(client.elicitationParams).toHaveLength(3);
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(root, { recursive: true, force: true });
      rmSync(outputRoot, { recursive: true, force: true });
    }

    const deniedRoot = repository();
    const deniedOutputRoot = mkdtempSync(join(import.meta.dir, ".sniff-mcp-report-denied-"));
    const denied = startClient("accept", {}, ["accept", "decline"]);
    const deniedOutput = join(deniedOutputRoot, "denied");
    try {
      await denied.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "report-denial-test", version: "1" } });
      const intake = object((await denied.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(deniedRoot) } })).result);
      const structured = object(intake.structuredContent);
      const lease = object(structured.lease);
      const result = object((await denied.request("tools/call", { name: "sniff_report", arguments: { capability: lease.capability, manifestId: lease.manifestId, mode: "save", path: deniedOutput, report: reportInputForConfirmation(object(structured.confirmation)) } })).result);
      expect(result.isError).toBe(true);
      expect(object(result.structuredContent).error).toMatchObject({ code: "confirmation_required" });
      expect(existsSync(deniedOutput)).toBe(false);
    } finally {
      await denied.close();
      expect(await denied.stderr()).toBe("");
      rmSync(deniedRoot, { recursive: true, force: true });
      rmSync(deniedOutputRoot, { recursive: true, force: true });
    }
  });
  // @ts-expect-error Bun runtime supports timeout options despite installed test typings.
  test("ignores unverified OpenGrep executables on PATH", { timeout: 30_000 }, async () => {
    const toolsFixture = fakeToolchain();
    executable(join(toolsFixture.bin, "opengrep"), `#!/bin/sh
if [ "$1" = "--version" ]; then printf 'OpenGrep fixture\\n'; exit 0; fi
printf '%s' '{"results":[{"check_id":"hardcoded-http-url","path":"index.ts","start":{"line":1,"col":2},"extra":{"message":"bounded observation","severity":"INFO","metavars":{"raw":"raw-secret"}},"raw":"raw-secret"}]}'
printf 'raw-stderr-secret' >&2
`);
    const root = repository();
    const client = startClient("accept", { ...toolsFixture.env, SNIFF_OPENGREP_CACHE_DIR: join(toolsFixture.root, "empty-opengrep-cache") });
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "projection-test", version: "1" } });
      const tools = object((await client.request("tools/list")).result).tools as Message[];
      const analyzerValid = outputSchemaValidator(tools, "sniff_run_analyzer");
      const input = intakeInput(root);
      input.budget = { maxMinutes: 1, maxAnalyzers: 2, maxFiles: 10 };
      input.security = { lightweightStatic: ["opengrep:hardcoded-values"] };
      const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input } })).result);
      const structured = object(intake.structuredContent);
      const lease = object(structured.lease);
      const analyzer = object((await client.request("tools/call", { name: "sniff_run_analyzer", arguments: { capability: lease.capability, manifestId: lease.manifestId, analyzer: "opengrep:hardcoded-values" } })).result);
      const analyzerStructured = object(analyzer.structuredContent);
      expect(analyzerStructured.ok).toBe(false);
      expect(analyzerStructured.outcome).toBe("not-run");
      expect(object(analyzerStructured.error)).toMatchObject({ code: "analyzer_failed" });
      expect(object(analyzerStructured.preflight)).toMatchObject({ tool: "opengrep", status: "missing", resolvedPath: null });
      expect(analyzerStructured.observations).toBeUndefined();
      expect(analyzerStructured.capture).toBeUndefined();
      expect(analyzerStructured.execution).toBeUndefined();
      expect(analyzerValid(analyzerStructured)).toBe(true);
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(root, { recursive: true, force: true });
      rmSync(toolsFixture.root, { recursive: true, force: true });
    }
  });

  // @ts-expect-error Bun runtime supports timeout options despite installed test typings.
  test("cancels a sleeping analyzer without exiting the server", { timeout: 30_000 }, async () => {
    const toolsFixture = fakeToolchain();
    const started = join(toolsFixture.root, "analyzer-started");
    const sleepingAnalyzer = `#!/bin/sh
if [ "$1" = "--version" ] || [ "$1" = "--help" ]; then exit 0; fi
printf started > ${started}
trap 'exit 143' TERM
sleep 1; exit 0
`;
    executable(join(toolsFixture.bin, "opengrep"), sleepingAnalyzer);
    executable(join(toolsFixture.bin, "lizard"), sleepingAnalyzer);
    const root = repository();
    const client = startClient("accept", toolsFixture.env);
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "cancel-test", version: "1" } });
      const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
      const intakeStructured = object(intake.structuredContent);
      const analyzerName = "lizard:complexity";
      const lease = object(intakeStructured.lease);
      const pending = client.rawRequest(700, { jsonrpc: "2.0", method: "tools/call", params: { name: "sniff_run_analyzer", arguments: { capability: lease.capability, manifestId: lease.manifestId, analyzer: analyzerName } } });
      await waitForFile(started);
      const released = object((await client.request("tools/call", { name: "sniff_cancel", arguments: { capability: lease.capability, manifestId: lease.manifestId } })).result);
      expect(object(released.structuredContent).released).toBe(true);
      const analyzerResult = object((await pending).result);
      expect(analyzerResult.isError).toBe(true);
      expect(object(analyzerResult.structuredContent).error).toMatchObject({ code: "analyzer_failed" });
      expect(object((await client.request("tools/list")).result).tools).toBeArray();
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(root, { recursive: true, force: true });
      rmSync(toolsFixture.root, { recursive: true, force: true });
    }
  });

  // @ts-expect-error Bun runtime supports timeout options despite installed test typings.
  test("allows one corrected report after malformed input and rejects replay", { timeout: 30_000 }, async () => {
    const root = repository();
    const client = startClient("accept");
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "report-finalize-test", version: "1" } });
      const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
      const structured = object(intake.structuredContent);
      const lease = object(structured.lease);
      const malformed = reportInputForConfirmation(object(structured.confirmation));
      malformed.headline = "";
      const terminal = object((await client.request("tools/call", { name: "sniff_report", arguments: { capability: lease.capability, manifestId: lease.manifestId, report: malformed } })).result);
      expect(terminal.isError).toBe(true);
      expect(object(terminal.structuredContent).error).toMatchObject({ code: "invalid_input" });
      const corrected = object((await client.request("tools/call", { name: "sniff_report", arguments: { capability: lease.capability, manifestId: lease.manifestId, report: reportInputForConfirmation(object(structured.confirmation)) } })).result);
      expect(corrected.isError).toBeUndefined();
      expect(object(corrected.structuredContent).ok).toBe(true);
      const replay = object((await client.request("tools/call", { name: "sniff_report", arguments: { capability: lease.capability, manifestId: lease.manifestId, report: reportInputForConfirmation(object(structured.confirmation)) } })).result);
      expect(replay.isError).toBe(true);
      expect(object(replay.structuredContent).error).toMatchObject({ code: "invalid_capability" });
    } finally {
      await client.close();
      expect(await client.stderr()).toBe("");
      rmSync(root, { recursive: true, force: true });
    }
  });

  // @ts-expect-error Bun runtime supports timeout options despite installed test typings.
  test("EOF releases an active lease and exits cleanly", { timeout: 30_000 }, async () => {
    const root = repository();
    const client = startClient("accept");
    await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: { elicitation: {} }, clientInfo: { name: "eof-test", version: "1" } });
    const intake = object((await client.request("tools/call", { name: "sniff_intake", arguments: { input: intakeInput(root) } })).result);
    expect(object(intake.structuredContent).lease).toBeDefined();
    expect(await client.close()).toBe(0);
    expect(await client.stderr()).toBe("");
    rmSync(root, { recursive: true, force: true });
  });
});

describe("shared tool contracts", () => {
  test("advertised MCP input schemas are field-for-field shared with extension schemas", async () => {
    const { tools } = await import("./server.ts");
    const { sniffToolInputSchemas } = await import("../../src/core/tool-schemas.ts");
    const expectedProperties: Record<string, string[]> = {
      sniff_intake: ["input"], sniff_cancel: ["capability", "manifestId"], sniff_install_tools: ["all", "bundles", "dryRun", "mode", "path"],
      sniff_run_analyzer: ["analyzer", "capability", "manifestId"], sniff_report: ["capability", "manifestId", "mode", "path", "report"],
      sniff_read_report_artifact: ["offset", "readCapability", "relativePath", "reportId"], sniff_read_analyzer_artifact: ["analyzerResultId", "maxBytes", "offset", "readCapability", "relativePath", "sourcePath"],
    };
    for (const tool of tools) {
      const schema = sniffToolInputSchemas[tool.name as keyof typeof sniffToolInputSchemas];
      expect(tool.inputSchema).toEqual(schema);
      expect(Object.keys(object(schema.properties)).sort()).toEqual(expectedProperties[tool.name]?.sort() ?? []);
    }
  });

  test("approval policies select the least-privileged tier for representative arguments", async () => {
    const { sniffInstallApproval, sniffIntakeApproval, sniffReportApproval } = await import("../../src/core/tool-schemas.ts");
    expect(sniffInstallApproval({ mode: "probe" })).toBe("read");
    expect(sniffInstallApproval({ mode: "diagnose" })).toBe("read");
    expect(sniffInstallApproval({ mode: "list" })).toBe("read");
    expect(sniffInstallApproval({ mode: "install" })).toBe("exec");
    expect(sniffReportApproval({ mode: "render" })).toBe("read");
    expect(sniffReportApproval({ mode: "save" })).toBe("write");
    expect(sniffIntakeApproval({ input: { target: { kind: "files" } } })).toBe("read");
    expect(sniffIntakeApproval({ input: { target: { kind: "repository" } } })).toBe("exec");
    expect(sniffIntakeApproval({ input: {} })).toBe("exec");
  });
});
