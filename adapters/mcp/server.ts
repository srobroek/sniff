import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import type { Readable, Writable } from "node:stream";
import { Server } from "@modelcontextprotocol/sdk/server";
import type { Transport, TransportSendOptions } from "@modelcontextprotocol/sdk/shared/transport";
import {
  CallToolRequestSchema,
  type CallToolResult,
  type ElicitRequestFormParams,
  ElicitResultSchema,
  ErrorCode,
  InitializeRequestSchema,
  type JSONRPCMessage, ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types";
import reportInputSchema from "../../skills/sniff/references/report-input.schema.json" with { type: "json" };
import { readAnalyzerArtifact } from "../../src/core/analyzer-artifact-registry.ts";
import {
  cancelRunLease,
  decisionFrontier,
  finalizeRunLease,
  type IntakeInput,
  intakeInput,
  publicSniffIntakeResult,
  releaseAllRunLeases,
  runSniffAnalyzer,
  runSniffInstall,
  runSniffIntakeTool,
  runSniffReportTool,
  type SaveAuthorizationRequest,
  type SniffInstallMode,
  type SniffIntakePublicResult,
  type SniffReportMode,
  type SniffToolResult,
} from "../../src/core/index.ts";
import type { ReportInput } from "../../src/core/report.ts";
import { readReportArtifact } from "../../src/core/report-artifact-registry.ts";

const SERVER_VERSION = "0.1.0";
const MAX_FRAME_BYTES = 1_048_576;
const MAX_INPUT_STRING_BYTES = 131_072;
const MAX_INPUT_ARRAY_LENGTH = 2_000;
const MAX_INPUT_OBJECT_KEYS = 2_000;
const MAX_OUTPUT_TEXT_BYTES = 65_536;
const MAX_OUTPUT_STRUCTURED_BYTES = 524_288;
const MAX_CONCURRENT_REQUESTS = 8;
const MAX_QUEUED_REQUESTS = 32;
const ELICITATION_TIMEOUT_MS = 120_000;

// MCP stdio is newline-delimited JSON. The SDK's transport already provides
// ordered, backpressured writes; this small transport adds an input frame cap,
// JSON-RPC envelope validation, and protocol errors for malformed frames.
type RpcId = string | number;
type RpcRecord = Record<string, unknown>;

function rpcRecord(value: unknown): value is RpcRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validRequestId(value: unknown): value is RpcId {
  return typeof value === "string" || (typeof value === "number" && Number.isFinite(value));
}

function recoverableId(value: RpcRecord): RpcId | null {
  return validRequestId(value.id) ? value.id : null;
}

function validParams(method: string, params: unknown): boolean {
  if (params === undefined) return method !== "initialize" && method !== "tools/call";
  if (!rpcRecord(params)) return false;
  if (method === "initialize") {
    return typeof params.protocolVersion === "string" && (params.capabilities === undefined || rpcRecord(params.capabilities)) && (params.clientInfo === undefined || rpcRecord(params.clientInfo));
  }
  if (method === "tools/call") {
    return typeof params.name === "string" && params.name.length > 0 && (params.arguments === undefined || rpcRecord(params.arguments));
  }
  return true;
}

function validateRpcMessage(value: unknown): { readonly message?: JSONRPCMessage; readonly code?: ErrorCode; readonly id: RpcId | null } {
  if (!rpcRecord(value) || value.jsonrpc !== "2.0") return { code: ErrorCode.InvalidRequest, id: rpcRecord(value) ? recoverableId(value) : null };
  const hasMethod = Object.hasOwn(value, "method");
  const hasResult = Object.hasOwn(value, "result");
  const hasError = Object.hasOwn(value, "error");
  if (hasMethod) {
    if (typeof value.method !== "string" || value.method.length === 0 || (Object.hasOwn(value, "id") && !validRequestId(value.id))) {
      return { code: ErrorCode.InvalidRequest, id: recoverableId(value) };
    }
    if (!validParams(value.method, value.params)) return { code: ErrorCode.InvalidParams, id: recoverableId(value) };
    return { message: value as unknown as JSONRPCMessage, id: recoverableId(value) };
  }
  if (hasResult || hasError) {
    if (!Object.hasOwn(value, "id") || (value.id !== null && !validRequestId(value.id))) return { code: ErrorCode.InvalidRequest, id: recoverableId(value) };
    return { message: value as unknown as JSONRPCMessage, id: recoverableId(value) };
  }
  return { code: ErrorCode.InvalidRequest, id: recoverableId(value) };
}

export class BoundedStdioTransport implements Transport {
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
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        void this.sendProtocolError("Parse error", ErrorCode.ParseError);
        continue;
      }
      const validation = validateRpcMessage(parsed);
      if (!validation.message) {
        // Notifications have no response by definition; malformed ones are
        // ignored after validation so they cannot terminate the server.
        if (rpcRecord(parsed) && Object.hasOwn(parsed, "id")) void this.sendProtocolError(validation.code === ErrorCode.InvalidParams ? "Invalid request parameters" : "Invalid Request", validation.code, validation.id);
        continue;
      }
      try {
        this.onmessage?.(validation.message);
      } catch {
        if (validation.id !== null) void this.sendProtocolError("Invalid Request", ErrorCode.InvalidRequest, validation.id);
      }
    }
  }

  private sendProtocolError(message: string, code = ErrorCode.InvalidRequest, id: RpcId | null = null): Promise<void> {
    return this.send({ jsonrpc: "2.0", id, error: { code, message } } as unknown as JSONRPCMessage);
  }

  send(message: JSONRPCMessage, _options?: TransportSendOptions): Promise<void> {
    if (this.closed) return Promise.resolve();
    const encoded = `${JSON.stringify(message)}\n`;
    this.writeQueue = this.writeQueue.catch(() => undefined).then(
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
const reportInputSchemaForTool = (() => {
  const schema = structuredClone(reportInputSchema) as JsonObject;
  delete schema.$schema;
  delete schema.$id;
  const definitions = schema.$defs !== null && typeof schema.$defs === "object" && !Array.isArray(schema.$defs) ? schema.$defs as JsonObject : {};
  delete schema.$defs;
  if (Array.isArray(schema.required)) schema.required = schema.required.filter((field) => field !== "extensions");
  return {
    report: { $ref: "#/$defs/reportInput" },
    $defs: { ...definitions, reportInput: schema },
  } as const;
})();

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

const historyWindowSchema = {
  type: "object",
  oneOf: [
    {
      type: "object",
      additionalProperties: false,
      required: ["kind", "base", "head"],
      properties: { kind: { const: "refs" }, base: stringSchema, head: stringSchema },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["kind", "date"],
      properties: { kind: { const: "since-date" }, date: stringSchema, head: stringSchema },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["kind", "count"],
      properties: { kind: { const: "last-commits" }, count: { type: "integer", minimum: 1 }, head: stringSchema },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["kind", "release"],
      properties: { kind: { const: "since-release" }, release: stringSchema, head: stringSchema },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["kind"],
      properties: { kind: { const: "previous-release" }, release: stringSchema, head: stringSchema },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["kind"],
      properties: { kind: { const: "context-aware-default" }, head: stringSchema },
    },
  ],
} as const;

const targetSchema = {
  type: "object",
  oneOf: [
    { type: "object", additionalProperties: false, required: ["kind", "root"], properties: { kind: { const: "whole-repo" }, root: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "root"], properties: { kind: { const: "working-tree" }, root: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "root", "paths"], properties: { kind: { const: "files" }, root: stringSchema, paths: { type: "array", items: stringSchema, maxItems: MAX_INPUT_ARRAY_LENGTH } } },
    { type: "object", additionalProperties: false, required: ["kind", "root", "path"], properties: { kind: { const: "directory" }, root: stringSchema, path: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "root", "path"], properties: { kind: { const: "module" }, root: stringSchema, path: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "root", "commit"], properties: { kind: { const: "commit" }, root: stringSchema, commit: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "root", "base", "head"], properties: { kind: { const: "range" }, root: stringSchema, base: stringSchema, head: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "root", "branch"], properties: { kind: { const: "branch" }, root: stringSchema, branch: stringSchema, base: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "root", "ref"], properties: { kind: { const: "ref" }, root: stringSchema, ref: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "repository"], properties: { kind: { const: "repository" }, repository: stringSchema, ref: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "repository", "tag"], properties: { kind: { const: "release" }, repository: stringSchema, tag: stringSchema, previousTag: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "rootOrRepository", "window"], properties: { kind: { const: "history" }, rootOrRepository: stringSchema, window: historyWindowSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "repository", "number"], properties: { kind: { const: "pr" }, repository: stringSchema, number: { oneOf: [stringSchema, { type: "integer" }] } } },
    { type: "object", additionalProperties: false, required: ["kind", "repository", "iid"], properties: { kind: { const: "mr" }, repository: stringSchema, iid: { oneOf: [stringSchema, { type: "integer" }] } } },
  ],
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

const analyzerObservationSchema = {
  type: "array",
  items: {
    type: "object",
    required: ["ruleId", "path", "start", "message", "severity"],
    properties: {
      ruleId: stringSchema,
      path: stringSchema,
      start: { type: "object", required: ["line", "column"], properties: { line: { type: "integer" }, column: { type: "integer" } }, additionalProperties: false },
      message: stringSchema,
      severity: stringSchema,
    },
    additionalProperties: false,
  },
} as const;

const analyzerCaptureSchema = {
  type: "object",
  required: ["bytes", "truncated", "digest", "incomplete"],
  properties: { bytes: { type: "number", minimum: 0 }, truncated: { type: "boolean" }, digest: stringSchema, incomplete: { type: "boolean" }, reason: stringSchema },
  additionalProperties: false,
} as const;

const outputSchemas = {
  intake: resultSchema({ interview: { type: "object" }, confirmation: { type: "object" }, confirmationRequired: { type: "boolean" }, lease: { type: "object" }, reportTarget: { type: "object" } }),
  cancel: resultSchema({ capability: stringSchema, manifestId: stringSchema, released: { type: "boolean" } }),
  install: resultSchema({ report: stringSchema, tools: { type: "array", items: { type: "object" } } }),
  analyzer: resultSchema({ report: stringSchema, outcome: stringSchema, preflight: { type: ["object", "null"] }, acceptedExitCodes: { type: "array", items: { type: "integer" } }, analyzerResultId: stringSchema, readCapability: stringSchema, descriptors: { type: "array", items: { type: "object" } }, descriptorCount: { type: "integer", minimum: 0 }, descriptorsTruncated: { type: "boolean" }, observations: analyzerObservationSchema, observationPreview: { type: "object", required: ["total", "returned", "truncated"], properties: { total: { type: "integer", minimum: 0 }, returned: { type: "integer", minimum: 0 }, truncated: { type: "boolean" } }, additionalProperties: false }, capture: analyzerCaptureSchema }),
  report: resultSchema({ reportId: stringSchema, readCapability: stringSchema, summary: stringSchema, artifacts: { type: "array", items: { type: "object" } }, descriptorCount: { type: "integer" }, descriptorsTruncated: { type: "boolean" }, receipt: { type: "object" }, savedPaths: { type: "array", items: stringSchema } }),
  reportArtifact: resultSchema({ reportId: stringSchema, relativePath: stringSchema, content: stringSchema, offset: { type: "integer", minimum: 0 }, nextOffset: { type: "integer", minimum: 0 }, eof: { type: "boolean" }, bytes: { type: "integer", minimum: 0 }, totalBytes: { type: "integer", minimum: 0 }, sha256: stringSchema }),
  analyzerArtifact: resultSchema({ analyzerResultId: stringSchema, relativePath: stringSchema, sourcePath: stringSchema, content: stringSchema, offset: { type: "integer", minimum: 0 }, nextOffset: { type: "integer", minimum: 0 }, eof: { type: "boolean" }, bytes: { type: "integer", minimum: 0 }, totalBytes: { type: "integer", minimum: 0 }, sha256: stringSchema }),
} as const;

const tools = [
  {
    name: "sniff_intake",
    title: "Sniff adaptive intake",
    description: "Resolve the Sniff intake plan, issue a run lease, and return reportTarget for the matching sniff_report payload.",
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
    description: "Validate and render or save a report. Copy reportTarget from sniff_intake into report.target, then add languages.",
    inputSchema: {
      type: "object",
      $defs: reportInputSchemaForTool.$defs,
      properties: {
        capability: stringSchema,
        manifestId: stringSchema,
        mode: { enum: ["render", "save"] },
        report: reportInputSchemaForTool.report,
        path: stringSchema,
      },
      required: ["capability", "manifestId", "report"],
      additionalProperties: false,
    },
    outputSchema: outputSchemas.report,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "sniff_read_report_artifact",
    title: "Read Sniff report artifact",
    description: "Read one bounded UTF-8 page from a complete in-process Sniff report artifact using its opaque read capability.",
    inputSchema: {
      type: "object",
      properties: { capability: stringSchema, reportId: stringSchema, relativePath: stringSchema, offset: { type: "integer", minimum: 0 } },
      required: ["capability", "reportId", "relativePath"],
      additionalProperties: false,
    },
    outputSchema: outputSchemas.reportArtifact,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "sniff_read_analyzer_artifact",
    title: "Read Sniff analyzer artifact",
    description: "Read one bounded UTF-8 page from complete analyzer observations using an opaque capability; provide relativePath or sourcePath.",
    inputSchema: {
      type: "object",
      properties: {
        analyzerResultId: stringSchema,
        readCapability: stringSchema,
        relativePath: stringSchema,
        sourcePath: stringSchema,
        offset: { type: "integer", minimum: 0 },
        maxBytes: { type: "integer", minimum: 4, maximum: MAX_OUTPUT_TEXT_BYTES },
      },
      required: ["analyzerResultId", "readCapability"],
      additionalProperties: false,
    },
    outputSchema: outputSchemas.analyzerArtifact,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
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
  if (/confirm|elicitation|denied|authorization/i.test(message)) return { code: "confirmation_required", message: "Trusted MCP confirmation was not accepted." };
  if (/capability|manifest|lease|reservation/i.test(message)) return { code: "invalid_capability", message: "The capability or manifest is invalid, expired, or already finalized." };
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

function publicAnalyzerPreflight(value: SniffToolResult | null): SniffToolResult | null {
  if (!value) return null;
  return {
    ...value,
    attempts: value.attempts.map(({ argv, exitCode, timedOut, error, timeoutMs }) => ({ argv, exitCode, stderr: "", timedOut, ...(error ? { error } : {}), timeoutMs })),
  };
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

export class Semaphore {
  private permits = MAX_CONCURRENT_REQUESTS;
  private readonly waiters: Array<{ readonly signal: AbortSignal; readonly resolve: (release: () => void) => void; readonly reject: (error: Error) => void; readonly onAbort: () => void }> = [];

  get activeCount(): number {
    return MAX_CONCURRENT_REQUESTS - this.permits;
  }

  get queuedCount(): number {
    return this.waiters.length;
  }

  async acquire(signal: AbortSignal): Promise<() => void> {
    assertNotAborted(signal);
    if (this.permits > 0) {
      this.permits -= 1;
      return this.release;
    }
    if (this.waiters.length >= MAX_QUEUED_REQUESTS) throw new SniffMcpError("server_busy", "MCP server concurrency queue is full");
    return new Promise((resolve, reject) => {
      let settled = false;
      const waiter = {
        signal,
        resolve: (release: () => void) => {
          if (settled) return;
          settled = true;
          signal.removeEventListener("abort", onAbort);
          resolve(release);
        },
        reject: (error: Error) => {
          if (settled) return;
          settled = true;
          signal.removeEventListener("abort", onAbort);
          reject(error);
        },
        onAbort: () => {
          const index = this.waiters.indexOf(waiter);
          if (index >= 0) this.waiters.splice(index, 1);
          waiter.reject(abortError());
        },
      };
      const onAbort = waiter.onAbort;
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) {
        waiter.onAbort();
        return;
      }
      this.waiters.push(waiter);
    });
  }

  close(reason = "MCP server is shutting down"): void {
    const error = new SniffMcpError("server_closed", reason);
    for (const waiter of this.waiters.splice(0)) waiter.reject(error);
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
const SUPPORTED_SERVER_PROTOCOL_VERSIONS = ["2025-06-18", "2025-11-25"] as const;
let negotiatedVersion: string | undefined;
let shuttingDown = false;
const activeLeases = new Set<string>();

function supportsFormElicitation(): boolean {
  if (!negotiatedVersion) return false;
  const capabilities = server.getClientCapabilities();
  if (!isObject(capabilities?.elicitation)) return false;
  if (negotiatedVersion === "2025-06-18") return true;
  return isObject(capabilities.elicitation.form);
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
  if (!SUPPORTED_SERVER_PROTOCOL_VERSIONS.includes(requested as (typeof SUPPORTED_SERVER_PROTOCOL_VERSIONS)[number])) throw new McpError(ErrorCode.InvalidRequest, "Unsupported MCP protocol version");
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
  const message = `${label}\n${boundedString(JSON.stringify(request), MAX_OUTPUT_TEXT_BYTES)}`;
  const elicitationParams = negotiatedVersion === "2025-06-18" ? { message, requestedSchema } : { mode: "form" as const, message, requestedSchema };
  const requestOptions = { signal, timeout: ELICITATION_TIMEOUT_MS, maxTotalTimeout: ELICITATION_TIMEOUT_MS };
  const response = negotiatedVersion === "2025-06-18"
    ? await (server as unknown as { request: (request: unknown, schema: unknown, options: unknown) => Promise<{ readonly action: string; readonly content?: unknown }> }).request({ method: "elicitation/create", params: elicitationParams }, ElicitResultSchema, requestOptions)
    : await server.elicitInput(elicitationParams, requestOptions);
  assertNotAborted(signal);
  if (response.action !== "accept" || !isObject(response.content) || response.content.acceptedDigest !== request.digest) return false;
  return {
    acceptedDigest: request.digest,
    ...(typeof response.content.actor === "string" ? { actor: boundedString(response.content.actor, 1_024) } : {}),
    ...(typeof response.content.reason === "string" ? { reason: boundedString(response.content.reason, 1_024) } : {}),
  };
}

function isElicitationFailure(error: unknown): boolean {
  const candidate = error as { readonly code?: unknown; readonly name?: unknown; readonly message?: unknown };
  const code = String(candidate?.code ?? "").toLowerCase();
  const name = String(candidate?.name ?? "").toLowerCase();
  const message = String(candidate?.message ?? error ?? "").toLowerCase();
  return code === "-32601" || code.includes("method_not_found") || code.includes("timeout") || code.includes("elicitation") || name.includes("timeout") || /elicitation|confirmation|method\s*not\s*found|timed?\s*out|timeout/i.test(message);
}

function confirmationRequiredError(): SniffMcpError {
  return new SniffMcpError("confirmation_required", "MCP form elicitation did not produce trusted confirmation; retry with an interactive MCP client.");
}
function publicIntakeInterview(input: IntakeInput): SniffIntakePublicResult["interview"] {
  return publicSniffIntakeResult({ interview: decisionFrontier(input) }).interview;
}

async function intake(args: JsonObject, signal: AbortSignal): Promise<ToolResponse> {
  const input = intakeInput(args.input);
  if (input.authorization) throw new SniffMcpError("invalid_input", "Caller-provided authorization is not accepted");
  const noninteractive = input.interactive === false;
  if (noninteractive) {
    if (!input.target || !input.intent) {
      const interview = publicIntakeInterview(input);
      return toolSuccess({ ok: true, interview }, JSON.stringify(interview));
    }
  } else {
    const interview = publicIntakeInterview(input);
    if (!interview.planSummary) return toolSuccess({ ok: true, interview }, JSON.stringify(interview));
  }
  if (!noninteractive && !supportsFormElicitation()) {
    const interview = publicIntakeInterview(input);
    return toolSuccess(
      { ok: false, interview, confirmationRequired: true, error: { code: "confirmation_required", message: "MCP form elicitation is required before issuing a lease" } },
      "Sniff intake requires MCP form elicitation; no lease was issued.",
    );
  }
  const resultPromise = runSniffIntakeTool(
    { input: noninteractive ? input : { ...input, interactive: true } },
    noninteractive
      ? {
          authority: {
            authorize: async (request) => ({
              acceptedDigest: request.digest,
              actor: "mcp-headless-read-authority",
              reason: "Explicit interactive:false requests a server-owned noninteractive read authorization for this exact intake digest.",
            }),
          },
        }
      : { confirmInteractive: (request) => elicitDigest(request, signal, "Confirm the complete canonical Sniff intake request.") },
  );
  const result = await raceWithAbort(resultPromise, signal).catch((error) => {
    void resultPromise.then(
      (late) => {
        if (!late.lease) return;
        try {
          cancelRunLease(late.lease.capability, late.lease.manifestId);
        } catch {
          // The request was already cancelled or expired.
        }
      },
      () => {
        // The core rejection was observed; never leave a late promise unhandled.
      },
    );
    if (!noninteractive && isElicitationFailure(error)) throw confirmationRequiredError();
    throw error;
  });
  if (signal.aborted) {
    if (result.lease) {
      try {
        cancelRunLease(result.lease.capability, result.lease.manifestId);
      } catch {
        // The lease was already finalized or expired.
      }
    }
    throw abortError();
  }
  const publicResult = publicSniffIntakeResult(result);
  if (publicResult.lease) activeLeases.add(leaseKey(publicResult.lease.capability, publicResult.lease.manifestId));
  return toolSuccess({ ok: true, ...publicResult }, JSON.stringify(publicResult));
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
    const planTools = plan.tools.map((tool) => ({ bundle: tool.bundle, tool: tool.tool, bin: tool.bin, status: tool.status, resolvedPath: tool.resolvedPath, routes: tool.attempts.map((attempt) => ({ argv: attempt.argv, exitCode: attempt.exitCode, timeoutMs: attempt.timeoutMs })) }));
    const plannedBundles = [...new Set(plan.tools.map((tool) => tool.bundle))];
    const authorization = { mode: "install", bundles: plannedBundles, all: options.all ?? false, dryRun: options.dryRun ?? false, noMise: options.noMise ?? false, cwd: tmpdir(), tools: planTools };
    const request = { ...authorization, digest: digest(authorization) };
    let accepted: false | { acceptedDigest: string; actor?: string; reason?: string };
    try {
      accepted = await elicitDigest(request, signal, "Authorize this exact Sniff installation plan (host-owned neutral cwd). ");
    } catch {
      throw confirmationRequiredError();
    }
    if (!accepted) throw new SniffMcpError("confirmation_required", "Sniff installation authorization was denied");
    assertNotAborted(signal);
    const installed = await runSniffInstall({ ...options, mode: "install", signal });
    const error = installed.ok ? undefined : { code: "install_failed", message: boundedString(installed.report, 1_024) };
    return toolSuccess({ ok: installed.ok, report: installed.report, tools: installed.tools, ...(error ? { error } : {}) }, installed.report);
  }
  const result = await runSniffInstall(options);
  const error = result.ok ? undefined : { code: "install_failed", message: boundedString(result.report, 1_024) };
  return toolSuccess({ ok: result.ok, report: result.report, tools: result.tools, ...(error ? { error } : {}) }, result.report);
}

async function analyzer(args: JsonObject, signal: AbortSignal): Promise<ToolResponse> {
  const capability = requiredString(args.capability, "capability");
  const manifestId = requiredString(args.manifestId, "manifestId");
  const analyzerName = requiredString(args.analyzer, "analyzer");
  const result = await runSniffAnalyzer({ capability, manifestId, analyzer: analyzerName, signal });
  const capture = result.capture ? { bytes: Number(result.capture.bytes), truncated: Boolean(result.capture.truncated), digest: String(result.capture.digest), incomplete: Boolean(result.capture.incomplete), ...(result.capture.reason ? { reason: String(result.capture.reason) } : {}) } : undefined;
  const error = result.ok ? undefined : { code: "analyzer_failed", message: boundedString(result.report, 1_024) };
  const value = {
    ok: result.ok,
    report: result.report,
    preflight: publicAnalyzerPreflight(result.preflight),
    ...(result.acceptedExitCodes ? { acceptedExitCodes: result.acceptedExitCodes } : {}),
    outcome: result.outcome,
    ...(result.analyzerResultId ? { analyzerResultId: result.analyzerResultId } : {}),
    ...(result.readCapability ? { readCapability: result.readCapability } : {}),
    ...(result.descriptors ? { descriptors: result.descriptors } : {}),
    ...(result.descriptorCount !== undefined ? { descriptorCount: result.descriptorCount } : {}),
    ...(result.descriptorsTruncated !== undefined ? { descriptorsTruncated: result.descriptorsTruncated } : {}),
    ...(result.observations ? { observations: result.observations } : {}),
    ...(result.observationPreview ? { observationPreview: result.observationPreview } : {}),
    ...(capture ? { capture } : {}),
    ...(error ? { error } : {}),
  };
  return toolSuccess(value, result.report);
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
    return toolSuccess({ ok: true, reportId: result.publicArtifacts.reportId, readCapability: result.publicArtifacts.readCapability, summary: result.publicArtifacts.summary, artifacts: result.publicArtifacts.descriptors, descriptorCount: result.publicArtifacts.descriptorCount, descriptorsTruncated: result.publicArtifacts.descriptorsTruncated, receipt: result.publicArtifacts.receipt, savedPaths: result.publicArtifacts.descriptors.flatMap((descriptor) => descriptor.savedPath ? [descriptor.savedPath] : []) }, result.publicArtifacts.summary);
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
function reportArtifact(args: JsonObject): ToolResponse {
  const capability = requiredString(args.capability, "capability");
  const reportId = requiredString(args.reportId, "reportId");
  const relativePath = requiredString(args.relativePath, "relativePath");
  const offset = args.offset;
  const result = readReportArtifact({ capability, reportId, relativePath, ...(offset === undefined ? {} : { offset: Number(offset) }) });
  return toolSuccess({ ok: true, ...result }, `Read ${result.bytes} bytes from ${result.relativePath} at offset ${result.offset}.`);
}
function analyzerArtifact(args: JsonObject): ToolResponse {
  const readCapability = requiredString(args.readCapability, "readCapability");
  const analyzerResultId = requiredString(args.analyzerResultId, "analyzerResultId");
  const relativePath = args.relativePath === undefined ? undefined : requiredString(args.relativePath, "relativePath");
  const sourcePath = args.sourcePath === undefined ? undefined : requiredString(args.sourcePath, "sourcePath");
  if ((relativePath === undefined) === (sourcePath === undefined)) throw new SniffMcpError("invalid_input", "Provide exactly one analyzer artifact relativePath or sourcePath");
  const offset = args.offset;
  if (offset !== undefined && (!Number.isSafeInteger(offset) || Number(offset) < 0)) throw new SniffMcpError("invalid_input", "Analyzer artifact offset must be a non-negative integer");
  const maxBytes = args.maxBytes;
  if (maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || Number(maxBytes) < 4 || Number(maxBytes) > MAX_OUTPUT_TEXT_BYTES)) throw new SniffMcpError("invalid_input", "Analyzer artifact maxBytes must be an integer from 4 through 65536");
  const result = readAnalyzerArtifact({ capability: readCapability, analyzerResultId, ...(relativePath === undefined ? { sourcePath } : { relativePath }), ...(offset === undefined ? {} : { offset: Number(offset) }) });
  if (maxBytes === undefined || result.bytes <= Number(maxBytes)) return toolSuccess({ ok: true, ...result }, `Read ${result.bytes} bytes from ${result.relativePath} at offset ${result.offset}.`);
  const bytes = Buffer.from(result.content, "utf8");
  let end = Math.min(Number(maxBytes), bytes.byteLength);
  while (end > 0 && end < bytes.byteLength && ((bytes[end] ?? 0) & 0xc0) === 0x80) end -= 1;
  const page = bytes.subarray(0, end).toString("utf8");
  const nextOffset = result.offset + end;
  const bounded = { ...result, content: page, bytes: end, nextOffset, eof: nextOffset === result.totalBytes };
  return toolSuccess({ ok: true, ...bounded }, `Read ${bounded.bytes} bytes from ${bounded.relativePath} at offset ${bounded.offset}.`);
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
    case "sniff_read_analyzer_artifact": return analyzerArtifact(args);
    case "sniff_report": return report(args, signal);
    case "sniff_read_report_artifact": return reportArtifact(args);
    default: throw new SniffMcpError("unknown_tool", "Unknown Sniff tool");
  }
}
server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
  let release: (() => void) | undefined;
  try {
    release = await semaphore.acquire(extra.signal);
    const args = isObject(request.params.arguments) ? request.params.arguments : {};
    const response = await callTool(request.params.name, args, extra.signal);
    return response;
  } catch (error) {
    return toolError(request.params.name, error);
  } finally {
    release?.();
  }
});

function cleanup(reason: string): void {
  if (shuttingDown) return;
  shuttingDown = true;
  semaphore.close(reason);
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
