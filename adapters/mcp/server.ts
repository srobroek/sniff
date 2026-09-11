import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import type { Readable, Writable } from "node:stream";
import { Server } from "@modelcontextprotocol/sdk/server";
import type { Transport, TransportSendOptions } from "@modelcontextprotocol/sdk/shared/transport";
import {
  CallToolRequestSchema,
  type CallToolResult,
  type ElicitRequestFormParams,
  ErrorCode,
  InitializeRequestSchema,
  type JSONRPCMessage, ListToolsRequestSchema,
  McpError,
  SUPPORTED_PROTOCOL_VERSIONS
} from "@modelcontextprotocol/sdk/types";
import reportInputSchema from "../../skills/sniff/references/report-input.schema.json" with { type: "json" };
import {
  cancelRunLease,
  decisionFrontier,
  finalizeRunLease,
  intakeInput,
  type ReportInput,
  releaseAllRunLeases,
  runSniffAnalyzer,
  runSniffInstall,
  runSniffIntakeTool,
  runSniffReportTool,
  type SaveAuthorizationRequest,
  type SniffInstallMode,
  type SniffReportMode,
} from "../../src/core/index.ts";

const SERVER_VERSION = "0.1.0";
const MAX_FRAME_BYTES = 1_048_576;
const MAX_INPUT_STRING_BYTES = 131_072;
const MAX_INPUT_ARRAY_LENGTH = 2_000;
const MAX_INPUT_OBJECT_KEYS = 2_000;
const MAX_OUTPUT_TEXT_BYTES = 65_536;
const MAX_OUTPUT_STRUCTURED_BYTES = 524_288;
const MAX_CONCURRENT_REQUESTS = 8;
const ELICITATION_TIMEOUT_MS = 120_000;

// MCP stdio is newline-delimited JSON. The SDK's transport already provides
// ordered, backpressured writes; this small transport adds an input frame cap
// and emits protocol errors for malformed/oversized frames.
class BoundedStdioTransport implements Transport {
  private buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0) as Buffer<ArrayBufferLike>;
  private started = false;
  private closed = false;
  private writeQueue = Promise.resolve();
  private readonly onData = (chunk: Buffer | string) => this.consume(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  private readonly onEnd = () => void this.close();
  private readonly onError = (error: Error) => this.onerror?.(error);

  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T) => void;

  constructor(
    private readonly input: Readable = process.stdin,
    private readonly output: Writable = process.stdout,
    private readonly maxFrameBytes = MAX_FRAME_BYTES,
  ) {}

  async start(): Promise<void> {
    if (this.started) throw new Error("MCP stdio transport already started");
    this.started = true;
    this.input.on("data", this.onData);
    this.input.once("end", this.onEnd);
    this.input.once("error", this.onError);
  }

  private consume(chunk: Buffer): void {
    if (this.closed) return;
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    for (;;) {
      const newline = this.buffer.indexOf(10);
      if (newline < 0) {
        if (this.buffer.length > this.maxFrameBytes) {
          this.buffer = Buffer.alloc(0) as Buffer<ArrayBufferLike>;
          void this.sendProtocolError("Frame exceeds the maximum MCP input size");
        }
        return;
      }
      const line = this.buffer.subarray(0, newline);
      this.buffer = this.buffer.subarray(newline + 1) as Buffer<ArrayBufferLike>;
      const text = line[line.length - 1] === 13 ? line.subarray(0, line.length - 1).toString("utf8") : line.toString("utf8");
      if (line.length > this.maxFrameBytes) {
        void this.sendProtocolError("Frame exceeds the maximum MCP input size");
        continue;
      }
      if (text.length === 0) continue;
      try {
        const message = JSON.parse(text) as JSONRPCMessage;
        this.onmessage?.(message);
      } catch {
        void this.sendProtocolError("Parse error", ErrorCode.ParseError);
      }
    }
  }

  private sendProtocolError(message: string, code = ErrorCode.InvalidRequest): Promise<void> {
    return this.send({ jsonrpc: "2.0", id: null, error: { code, message } } as unknown as JSONRPCMessage);
  }

  send(message: JSONRPCMessage, _options?: TransportSendOptions): Promise<void> {
    if (this.closed) return Promise.resolve();
    const encoded = `${JSON.stringify(message)}\n`;
    this.writeQueue = this.writeQueue.then(
      () =>
        new Promise<void>((resolve, reject) => {
          const done = (error?: Error | null) => (error ? reject(error) : resolve());
          try {
            if (this.output.write(encoded, done)) resolve();
          } catch (error) {
            reject(error);
          }
        }),
    );
    return this.writeQueue;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.input.off("data", this.onData);
    this.input.off("end", this.onEnd);
    this.input.off("error", this.onError);
    this.input.pause();
    this.onclose?.();
  }
}

type JsonObject = Record<string, unknown>;
type ToolResponse = CallToolResult & { readonly structuredContent: JsonObject };
type DigestRequest = {
  readonly digest: string;
  readonly [key: string]: unknown;
};


class SniffMcpError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "SniffMcpError";
  }
}

const stringSchema = { type: "string" } as const;
const positiveIntegerSchema = { type: "integer", minimum: 1 } as const;
const errorSchema = {
  type: "object",
  required: ["ok", "error"],
  properties: {
    ok: { const: false },
    error: {
      type: "object",
      required: ["code", "message"],
      properties: { code: stringSchema, message: stringSchema },
      additionalProperties: false,
    },
  },
  additionalProperties: true,
} as const;

const targetSchema = {
  type: "object",
  additionalProperties: true,
  required: ["kind"],
  properties: {
    kind: stringSchema,
    root: stringSchema,
    path: stringSchema,
    paths: { type: "array", items: stringSchema, maxItems: MAX_INPUT_ARRAY_LENGTH },
    commit: stringSchema,
    base: stringSchema,
    head: stringSchema,
    branch: stringSchema,
    ref: stringSchema,
    repository: stringSchema,
    tag: stringSchema,
    previousTag: stringSchema,
    iid: { oneOf: [stringSchema, { type: "integer" }] },
    number: { oneOf: [stringSchema, { type: "integer" }] },
    rootOrRepository: stringSchema,
    window: { type: "object" },
  },
} as const;

const intakeInputSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    target: targetSchema,
    intent: { enum: ["audit", "review-change", "release-risk", "history", "plan-only"] },
    scopeMode: { enum: ["quick", "full", "plan-only"] },
    objectives: { type: "array", items: stringSchema, uniqueItems: true, maxItems: MAX_INPUT_ARRAY_LENGTH },
    exclusions: { type: "array", items: stringSchema, uniqueItems: true, maxItems: MAX_INPUT_ARRAY_LENGTH },
    budget: {
      type: "object",
      additionalProperties: false,
      properties: { maxMinutes: positiveIntegerSchema, maxAnalyzers: positiveIntegerSchema, maxFiles: positiveIntegerSchema },
    },
    security: { type: "object" },
    interactive: { type: "boolean" },
    // Deliberately not accepted as authority by the core boundary.
    authorization: { type: "object" },
  },
} as const;

const resultSchema = (successProperties: JsonObject) => ({
  type: "object" as const,
  oneOf: [
    { required: ["ok"], properties: { ok: { const: true }, ...successProperties }, additionalProperties: true },
    errorSchema,
  ],
});

const outputSchemas = {
  intake: resultSchema({ interview: { type: "object" }, confirmation: { type: "object" }, confirmationRequired: { type: "boolean" }, manifest: { type: "object" }, lease: { type: "object" } }),
  cancel: resultSchema({ capability: stringSchema, manifestId: stringSchema, released: { type: "boolean" } }),
  install: resultSchema({ report: stringSchema, tools: { type: "array", items: { type: "object" } } }),
  analyzer: resultSchema({ report: stringSchema, outcome: stringSchema, preflight: { type: ["object", "null"] }, execution: { type: "object" }, acceptedExitCodes: { type: "array", items: { type: "integer" } } }),
  report: resultSchema({ artifacts: { type: "object" }, savedPaths: { type: "array", items: stringSchema } }),
} as const;

const tools = [
  {
    name: "sniff_intake",
    title: "Sniff adaptive intake",
    description: "Resolve the Sniff intake plan and obtain a trusted MCP elicitation before issuing a run lease.",
    inputSchema: { type: "object", properties: { input: intakeInputSchema }, required: ["input"], additionalProperties: false },
    outputSchema: outputSchemas.intake,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "sniff_cancel",
    title: "Cancel Sniff run",
    description: "Cancel an issued Sniff run and release its host-owned materialization.",
    inputSchema: { type: "object", properties: { capability: stringSchema, manifestId: stringSchema }, required: ["capability", "manifestId"], additionalProperties: false },
    outputSchema: outputSchemas.cancel,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "sniff_install_tools",
    title: "Sniff install tools",
    description: "Probe, diagnose, list, or explicitly authorize installation of Sniff analyzer catalog entries.",
    inputSchema: {
      type: "object",
      properties: {
        mode: { enum: ["probe", "diagnose", "list", "install"] },
        bundles: { type: "array", items: stringSchema, uniqueItems: true, maxItems: MAX_INPUT_ARRAY_LENGTH },
        all: { type: "boolean" },
        dryRun: { type: "boolean" },
        noMise: { type: "boolean" },
        path: stringSchema,
      },
      additionalProperties: false,
    },
    outputSchema: outputSchemas.install,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "sniff_run_analyzer",
    title: "Sniff run analyzer",
    description: "Run one analyzer selected by a live Sniff intake capability and its fixed catalogued recipe.",
    inputSchema: { type: "object", properties: { capability: stringSchema, manifestId: stringSchema, analyzer: stringSchema }, required: ["capability", "manifestId", "analyzer"], additionalProperties: false },
    outputSchema: outputSchemas.analyzer,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "sniff_report",
    title: "Sniff structured report",
    description: "Validate and render or explicitly authorize saving a Sniff report bound to the issued intake manifest.",
    inputSchema: {
      type: "object",
      properties: {
        capability: stringSchema,
        manifestId: stringSchema,
        mode: { enum: ["render", "save"] },
        report: reportInputSchema,
        path: stringSchema,
      },
      required: ["capability", "manifestId", "report"],
      additionalProperties: false,
    },
    outputSchema: outputSchemas.report,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
] as const;

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > MAX_INPUT_STRING_BYTES) throw new SniffMcpError("invalid_input", `${field} is invalid`);
  return value;
}

function inspectInput(value: unknown, depth = 0): void {
  if (depth > 32) throw new SniffMcpError("invalid_input", "Input nesting is too deep");
  if (typeof value === "string") {
    if (Buffer.byteLength(value) > MAX_INPUT_STRING_BYTES) throw new SniffMcpError("input_too_large", "Input string is too large");
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_INPUT_ARRAY_LENGTH) throw new SniffMcpError("input_too_large", "Input array is too large");
    for (const item of value) inspectInput(item, depth + 1);
    return;
  }
  if (isObject(value)) {
    const keys = Object.keys(value);
    if (keys.length > MAX_INPUT_OBJECT_KEYS) throw new SniffMcpError("input_too_large", "Input object is too large");
    for (const [key, item] of Object.entries(value)) {
      if (Buffer.byteLength(key) > MAX_INPUT_STRING_BYTES) throw new SniffMcpError("input_too_large", "Input key is too large");
      inspectInput(item, depth + 1);
    }
  }
}

function errorDetails(error: unknown): { code: string; message: string } {
  if (error instanceof SniffMcpError) return { code: error.code, message: error.message };
  if (error instanceof Error && error.name === "AbortError") return { code: "cancelled", message: "The MCP request was cancelled." };
  const message = error instanceof Error ? error.message : "Sniff operation failed";
  if (/capability|manifest|lease|reservation|authorization|authorized/i.test(message)) return { code: "invalid_capability", message: "The capability or manifest is invalid, expired, or already finalized." };
  if (/confirm|elicitation|denied/i.test(message)) return { code: "confirmation_required", message: "Trusted MCP confirmation was not accepted." };
  if (/input|target|budget|security|mode|bundles|report|path|schema/i.test(message)) return { code: "invalid_input", message: "The request does not satisfy the Sniff input contract." };
  return { code: "sniff_operation_failed", message: "Sniff could not complete the requested operation." };
}

function boundedString(value: string, max = MAX_OUTPUT_TEXT_BYTES): string {
  if (Buffer.byteLength(value) <= max) return value;
  const bytes = Buffer.from(value);
  return `${bytes.subarray(0, max).toString("utf8")}\n[truncated]`;
}

function boundedValue(value: unknown, depth = 0): unknown {
  if (typeof value === "string") return boundedString(value);
  if (depth > 12) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, MAX_INPUT_ARRAY_LENGTH).map((item) => boundedValue(item, depth + 1));
  if (isObject(value)) return Object.fromEntries(Object.entries(value).slice(0, MAX_INPUT_OBJECT_KEYS).map(([key, item]) => [key, boundedValue(item, depth + 1)]));
  return value;
}

function toolError(name: string, error: unknown): ToolResponse {
  const details = errorDetails(error);
  const value = { ok: false, error: details };
  return {
    content: [{ type: "text", text: `${name} failed [${details.code}]` }],
    structuredContent: value,
    isError: true,
  };
}

function toolSuccess(value: JsonObject, text: string): ToolResponse {
  const bounded = boundedValue(value) as JsonObject;
  let structured = bounded;
  try {
    if (Buffer.byteLength(JSON.stringify(structured)) > MAX_OUTPUT_STRUCTURED_BYTES) structured = { ok: false, error: { code: "output_too_large", message: "Sniff output exceeded the MCP size limit." } };
  } catch {
    structured = { ok: false, error: { code: "output_too_large", message: "Sniff output could not be serialized within the MCP size limit." } };
  }
  const isError = structured.ok === false;
  return { content: [{ type: "text", text: boundedString(text) }], structuredContent: structured, ...(isError ? { isError: true } : {}) };
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function digest(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function abortError(): Error {
  return new DOMException("The MCP request was cancelled.", "AbortError");
}

function assertNotAborted(signal: AbortSignal): void {
  if (signal.aborted) throw abortError();
}

async function raceWithAbort<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  assertNotAborted(signal);
  const { promise: aborted, reject } = Promise.withResolvers<never>();
  const onAbort = () => reject(abortError());
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    return await Promise.race([operation, aborted]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

class Semaphore {
  private permits = MAX_CONCURRENT_REQUESTS;
  private readonly waiters: Array<{ readonly signal: AbortSignal; readonly resolve: (release: () => void) => void; readonly reject: (error: Error) => void; readonly onAbort: () => void }> = [];

  async acquire(signal: AbortSignal): Promise<() => void> {
    assertNotAborted(signal);
    if (this.permits > 0) {
      this.permits -= 1;
      return this.release;
    }
    return new Promise((resolve, reject) => {
      const waiter = { signal, resolve, reject, onAbort: () => reject(abortError()) };
      signal.addEventListener("abort", waiter.onAbort, { once: true });
      this.waiters.push(waiter);
    });
  }

  private readonly release = (): void => {
    const waiter = this.waiters.shift();
    if (!waiter) {
      this.permits += 1;
      return;
    }
    waiter.signal.removeEventListener("abort", waiter.onAbort);
    if (waiter.signal.aborted) {
      waiter.reject(abortError());
      this.release();
      return;
    }
    waiter.resolve(this.release);
  };
}

const semaphore = new Semaphore();
const server = new Server({ name: "sniff", version: SERVER_VERSION }, { capabilities: { tools: { listChanged: false } }, enforceStrictCapabilities: true });
let negotiatedVersion: string | undefined;
let shuttingDown = false;
const activeLeases = new Set<string>();

function supportsFormElicitation(): boolean {
  if (!negotiatedVersion || negotiatedVersion < "2025-06-18") return false;
  const capabilities = server.getClientCapabilities();
  return isObject(capabilities?.elicitation) && isObject(capabilities.elicitation.form);
}

function leaseKey(capability: string, manifestId: string): string {
  return `${capability}\0${manifestId}`;
}

function setClientHandshake(request: { params: { protocolVersion: string; capabilities?: unknown; clientInfo?: unknown } }, version: string): void {
  const mutable = server as unknown as { _clientCapabilities?: unknown; _clientVersion?: unknown; _protocolVersion?: string };
  mutable._clientCapabilities = request.params.capabilities ?? {};
  mutable._clientVersion = request.params.clientInfo;
  mutable._protocolVersion = version;
}

server.setRequestHandler(InitializeRequestSchema, (request) => {
  const requested = request.params.protocolVersion;
  if (!SUPPORTED_PROTOCOL_VERSIONS.includes(requested)) throw new McpError(ErrorCode.InvalidRequest, "Unsupported MCP protocol version");
  negotiatedVersion = requested;
  setClientHandshake(request, requested);
  return {
    protocolVersion: requested,
    capabilities: { tools: { listChanged: false } },
    serverInfo: { name: "sniff", version: SERVER_VERSION },
  };
});

server.setRequestHandler(ListToolsRequestSchema, () => ({ tools }));

async function elicitDigest(request: DigestRequest, signal: AbortSignal, label: string): Promise<false | { acceptedDigest: string; actor?: string; reason?: string }> {
  assertNotAborted(signal);
  if (!supportsFormElicitation()) return false;
  const fields = Object.fromEntries(Object.entries(request).filter(([key]) => key !== "digest").map(([key, value]) => [key, { const: value }]));
  const requestedSchema = {
    type: "object" as const,
    properties: {
      ...fields,
      acceptedDigest: { type: "string" as const, const: request.digest },
      actor: stringSchema,
      reason: stringSchema,
    },
    required: ["acceptedDigest"],
    additionalProperties: false,
  } as ElicitRequestFormParams["requestedSchema"];
  const response = await server.elicitInput(
    { mode: "form", message: `${label}\n${boundedString(JSON.stringify(request), MAX_OUTPUT_TEXT_BYTES)}`, requestedSchema },
    { signal, timeout: ELICITATION_TIMEOUT_MS, maxTotalTimeout: ELICITATION_TIMEOUT_MS },
  );
  assertNotAborted(signal);
  if (response.action !== "accept" || !isObject(response.content) || response.content.acceptedDigest !== request.digest) return false;
  return {
    acceptedDigest: request.digest,
    ...(typeof response.content.actor === "string" ? { actor: boundedString(response.content.actor, 1_024) } : {}),
    ...(typeof response.content.reason === "string" ? { reason: boundedString(response.content.reason, 1_024) } : {}),
  };
}

async function intake(args: JsonObject, signal: AbortSignal): Promise<ToolResponse> {
  const input = intakeInput(args.input);
  if (input.authorization) throw new SniffMcpError("invalid_input", "Caller-provided authorization is not accepted");
  const frontier = decisionFrontier(input);
  if (!frontier.plan) return toolSuccess({ ok: true, interview: frontier }, JSON.stringify(frontier));
  if (!supportsFormElicitation()) {
    return toolSuccess(
      { ok: false, interview: frontier, confirmationRequired: true, error: { code: "confirmation_required", message: "MCP form elicitation is required before issuing a lease" } },
      "Sniff intake requires MCP form elicitation; no lease was issued.",
    );
  }
  const resultPromise = runSniffIntakeTool(
    { input: { ...input, interactive: true } },
    { confirmInteractive: (request) => elicitDigest(request, signal, "Confirm the complete canonical Sniff intake request."), },
  );
  const result = await raceWithAbort(resultPromise, signal).catch((error) => {
    void resultPromise.then((late) => {
      if (late.lease) {
        try {
          cancelRunLease(late.lease.capability, late.lease.manifestId);
        } catch {
          // The request was already cancelled or expired.
        }
      }
    });
    throw error;
  });
  assertNotAborted(signal);
  if (result.lease) activeLeases.add(leaseKey(result.lease.capability, result.lease.manifestId));
  return toolSuccess({ ok: true, ...result }, JSON.stringify(result));
}

async function install(args: JsonObject, signal: AbortSignal): Promise<ToolResponse> {
  const mode = args.mode as SniffInstallMode | undefined;
  if (mode !== undefined && !["probe", "diagnose", "list", "install"].includes(mode)) throw new SniffMcpError("invalid_input", "Install mode is invalid");
  const bundles = args.bundles;
  if (bundles !== undefined && (!Array.isArray(bundles) || bundles.some((bundle) => typeof bundle !== "string"))) throw new SniffMcpError("invalid_input", "Install bundles are invalid");
  inspectInput(args);
  const selectedMode = mode ?? "probe";
  if (selectedMode === "install" && args.path !== undefined) throw new SniffMcpError("invalid_input", "Install mode does not accept a caller-controlled cwd");
  const options = {
    ...(mode ? { mode } : {}),
    ...(bundles ? { bundles: bundles as string[] } : {}),
    ...(typeof args.all === "boolean" ? { all: args.all } : {}),
    ...(typeof args.dryRun === "boolean" ? { dryRun: args.dryRun } : {}),
    ...(typeof args.noMise === "boolean" ? { noMise: args.noMise } : {}),
    cwd: selectedMode === "install" ? process.cwd() : typeof args.path === "string" ? args.path : process.cwd(),
    signal,
  };
  if (selectedMode === "install") {
    if (!supportsFormElicitation()) return toolError("sniff_install_tools", new SniffMcpError("confirmation_required", "MCP form elicitation is required before installation"));
    const plan = await runSniffInstall({ ...options, mode: "diagnose", signal });
    assertNotAborted(signal);
    if (plan.tools.length === 0) {
      return toolSuccess(
        { ok: false, report: plan.report, tools: plan.tools, error: { code: "invalid_input", message: "No tools matched the requested install bundles" } },
        plan.report,
      );
    }
    const planTools = plan.tools.map((tool) => ({ bundle: tool.bundle, tool: tool.tool, bin: tool.bin, status: tool.status, resolvedPath: tool.resolvedPath, routes: tool.attempts.map((attempt) => ({ argv: attempt.argv, exitCode: attempt.exitCode, timeoutMs: attempt.timeoutMs })) }));
    const plannedBundles = [...new Set(plan.tools.map((tool) => tool.bundle))];
    const authorization = { mode: "install", bundles: plannedBundles, all: options.all ?? false, dryRun: options.dryRun ?? false, noMise: options.noMise ?? false, cwd: tmpdir(), tools: planTools };
    const request = { ...authorization, digest: digest(authorization) };
    const accepted = await elicitDigest(request, signal, "Authorize this exact Sniff installation plan (host-owned neutral cwd). ");
    if (!accepted) throw new SniffMcpError("confirmation_required", "Sniff installation authorization was denied");
    assertNotAborted(signal);
    const installed = await runSniffInstall({ ...options, mode: "install", signal });
    return toolSuccess({ ok: installed.ok, report: installed.report, tools: installed.tools }, installed.report);
  }
  const result = await runSniffInstall(options);
  return toolSuccess({ ok: result.ok, report: result.report, tools: result.tools }, result.report);
}

async function analyzer(args: JsonObject, signal: AbortSignal): Promise<ToolResponse> {
  const capability = requiredString(args.capability, "capability");
  const manifestId = requiredString(args.manifestId, "manifestId");
  const analyzerName = requiredString(args.analyzer, "analyzer");
  const result = await runSniffAnalyzer({ capability, manifestId, analyzer: analyzerName, signal });
  const text = result.execution ? `${result.report}\n\nstdout:\n${result.execution.stdout}\n\nstderr:\n${result.execution.stderr}` : result.report;
  return toolSuccess({ ok: result.ok, report: result.report, preflight: result.preflight, ...(result.acceptedExitCodes ? { acceptedExitCodes: result.acceptedExitCodes } : {}), outcome: result.outcome, ...(result.execution ? { execution: result.execution } : {}) }, text);
}

async function report(args: JsonObject, signal: AbortSignal): Promise<ToolResponse> {
  const capability = requiredString(args.capability, "capability");
  const manifestId = requiredString(args.manifestId, "manifestId");
  let delegatedToCore = false;
  try {
    if (args.mode !== undefined && args.mode !== "render" && args.mode !== "save") throw new SniffMcpError("invalid_input", "Report mode is invalid");
    if (!isObject(args.report)) throw new SniffMcpError("invalid_input", "Report must be an object");
    inspectInput(args.report);
    const mode = args.mode as SniffReportMode | undefined;
    const runtime = mode === "save" ? { authorizeSave: async (request: SaveAuthorizationRequest) => elicitDigest(request, signal, "Authorize saving this exact canonical Sniff report (directory, manifest, artifacts, and digest).") } : undefined;
    delegatedToCore = true;
    const result = await runSniffReportTool({ capability, manifestId, mode, report: args.report as unknown as ReportInput, ...(typeof args.path === "string" ? { path: args.path } : {}), ...(runtime ? { runtime } : {}) });
    assertNotAborted(signal);
    return toolSuccess({ ok: true, artifacts: result.artifacts, savedPaths: result.savedPaths }, result.artifacts.markdown);
  } finally {
    // Core finalizes after every delegated report attempt. This fallback is
    // only for validation failures before entering the core use case.
    if (!delegatedToCore) {
      try {
        finalizeRunLease(capability, manifestId);
      } catch {
        // Expiry, cancellation, or an already-finalized lease is terminal.
      }
    }
    activeLeases.delete(leaseKey(capability, manifestId));
  }
}

async function callTool(name: string, args: JsonObject, signal: AbortSignal): Promise<ToolResponse> {
  inspectInput(args);
  switch (name) {
    case "sniff_intake": return intake(args, signal);
    case "sniff_cancel": {
      const capability = requiredString(args.capability, "capability");
      const manifestId = requiredString(args.manifestId, "manifestId");
      cancelRunLease(capability, manifestId);
      activeLeases.delete(leaseKey(capability, manifestId));
      return toolSuccess({ ok: true, capability, manifestId, released: true }, "Sniff run cancelled and materialization released.");
    }
    case "sniff_install_tools": return install(args, signal);
    case "sniff_run_analyzer": return analyzer(args, signal);
    case "sniff_report": return report(args, signal);
    default: throw new SniffMcpError("unknown_tool", "Unknown Sniff tool");
  }
}

server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
  const release = await semaphore.acquire(extra.signal);
  try {
    const args = isObject(request.params.arguments) ? request.params.arguments : {};
    try {
      return await callTool(request.params.name, args, extra.signal);
    } catch (error) {
      return toolError(request.params.name, error);
    }
  } finally {
    release();
  }
});

function cleanup(reason: string): void {
  if (shuttingDown) return;
  shuttingDown = true;
  try {
    releaseAllRunLeases(reason);
  } finally {
    activeLeases.clear();
  }
}

export async function serve(): Promise<void> {
  const transport = new BoundedStdioTransport();
  let closedResolve: (() => void) | undefined;
  const closed = new Promise<void>((resolve) => { closedResolve = resolve; });
  transport.onclose = () => {
    cleanup("stdin-closed");
    closedResolve?.();
  };
  transport.onerror = () => {
    cleanup("stdio-error");
  };
  server.onclose = () => {
    cleanup("server-closed");
  };
  process.once("SIGINT", () => {
    cleanup("SIGINT");
    void transport.close();
  });
  process.once("SIGTERM", () => {
    cleanup("SIGTERM");
    void transport.close();
  });
  process.once("exit", () => cleanup("process-exit"));
  await server.connect(transport);
  await closed;
}

if (import.meta.main) {
  void serve().catch((error: unknown) => {
    cleanup("serve-error");
    console.error(error instanceof Error ? error.message : "MCP server failed");
    process.exitCode = 1;
  });
}
