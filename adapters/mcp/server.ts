import { createInterface } from "node:readline";
import {
  cancelRunLease,
  decisionFrontier,
  intakeInput,
  type ReportInput,
  releaseAllRunLeases,
  runSniffAnalyzer,
  runSniffInstall,
  runSniffIntakeTool,
  runSniffReportTool,
  type SniffInstallMode,
  type SniffReportMode,
} from "../../src/core/index.ts";

type JsonRpcId = string | number;
type JsonObject = Record<string, unknown>;
type JsonRpcMessage = JsonObject & { jsonrpc: "2.0" };
type ToolResult = {
  readonly content: readonly [{ readonly type: "text"; readonly text: string }];
  readonly structuredContent: JsonObject;
  readonly isError?: boolean;
};
type PendingClientRequest = {
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: Error) => void;
  readonly timer: ReturnType<typeof setTimeout>;
};

const SERVER_VERSION = "0.1.0";
const ELICITATION_TIMEOUT_MS = 120_000;
let nextClientRequestId = 1;
let clientCapabilities: JsonObject = {};
let shuttingDown = false;
const pendingClientRequests = new Map<JsonRpcId, PendingClientRequest>();
const activeLeases = new Map<string, { readonly capability: string; readonly manifestId: string }>();

class SniffMcpError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly data: JsonObject = {},
  ) {
    super(message);
    this.name = "SniffMcpError";
  }
}

const stringSchema = { type: "string" } as const;
const positiveIntegerSchema = { type: "integer", minimum: 1 } as const;
const targetSchema = {
  oneOf: [
    { type: "object", properties: { kind: { const: "working-tree" }, root: stringSchema }, required: ["kind", "root"], additionalProperties: false },
    { type: "object", properties: { kind: { const: "files" }, root: stringSchema, paths: { type: "array", items: stringSchema } }, required: ["kind", "root", "paths"], additionalProperties: false },
    { type: "object", properties: { kind: { enum: ["directory", "module"] }, root: stringSchema, path: stringSchema }, required: ["kind", "root", "path"], additionalProperties: false },
    { type: "object", properties: { kind: { const: "commit" }, root: stringSchema, commit: stringSchema }, required: ["kind", "root", "commit"], additionalProperties: false },
    { type: "object", properties: { kind: { const: "range" }, root: stringSchema, base: stringSchema, head: stringSchema }, required: ["kind", "root", "base", "head"], additionalProperties: false },
    { type: "object", properties: { kind: { const: "branch" }, root: stringSchema, branch: stringSchema, base: stringSchema }, required: ["kind", "root", "branch"], additionalProperties: false },
    { type: "object", properties: { kind: { const: "ref" }, root: stringSchema, ref: stringSchema }, required: ["kind", "root", "ref"], additionalProperties: false },
    { type: "object", properties: { kind: { const: "repository" }, repository: stringSchema, ref: stringSchema }, required: ["kind", "repository"], additionalProperties: false },
    { type: "object", properties: { kind: { const: "release" }, repository: stringSchema, tag: stringSchema, previousTag: stringSchema }, required: ["kind", "repository", "tag"], additionalProperties: false },
    {
      type: "object",
      properties: {
        kind: { const: "history" },
        rootOrRepository: stringSchema,
        window: {
          oneOf: [
            { type: "object", properties: { kind: { const: "refs" }, base: stringSchema, head: stringSchema }, required: ["kind", "base", "head"], additionalProperties: false },
            { type: "object", properties: { kind: { const: "since-date" }, date: stringSchema, head: stringSchema }, required: ["kind", "date"], additionalProperties: false },
            { type: "object", properties: { kind: { const: "last-commits" }, count: positiveIntegerSchema, head: stringSchema }, required: ["kind", "count"], additionalProperties: false },
            { type: "object", properties: { kind: { const: "since-release" }, release: stringSchema, head: stringSchema }, required: ["kind", "release"], additionalProperties: false },
            { type: "object", properties: { kind: { const: "previous-release" }, release: stringSchema, head: stringSchema }, required: ["kind"], additionalProperties: false },
            { type: "object", properties: { kind: { const: "context-aware-default" }, head: stringSchema }, required: ["kind"], additionalProperties: false },
          ],
        },
      },
      required: ["kind", "rootOrRepository", "window"],
      additionalProperties: false,
    },
    { type: "object", properties: { kind: { const: "pr" }, repository: stringSchema, number: { oneOf: [stringSchema, { type: "integer" }] } }, required: ["kind", "repository", "number"], additionalProperties: false },
    { type: "object", properties: { kind: { const: "mr" }, repository: stringSchema, iid: { oneOf: [stringSchema, { type: "integer" }] } }, required: ["kind", "repository", "iid"], additionalProperties: false },
  ],
} as const;
const intakeInputSchema = {
  type: "object",
  properties: {
    target: targetSchema,
    intent: { enum: ["audit", "review-change", "release-risk", "history", "plan-only"] },
    objectives: { type: "array", items: stringSchema, uniqueItems: true },
    exclusions: { type: "array", items: stringSchema, uniqueItems: true },
    budget: {
      type: "object",
      properties: { maxMinutes: positiveIntegerSchema, maxAnalyzers: positiveIntegerSchema, maxFiles: positiveIntegerSchema },
      additionalProperties: false,
    },
    security: {
      type: "object",
      properties: {
        deepStatic: { type: "boolean" },
        unavailable: { type: "array", items: stringSchema, uniqueItems: true },
        projectNative: { type: "array", items: stringSchema, uniqueItems: true },
        lightweightStatic: { type: "array", items: stringSchema, uniqueItems: true },
        deepStaticAnalyzers: { type: "array", items: stringSchema, uniqueItems: true },
        requestedActions: { type: "array", items: stringSchema, uniqueItems: true },
      },
      additionalProperties: false,
    },
    interactive: { type: "boolean" },
    authorization: {
      type: "object",
      properties: { granted: { const: true }, actor: stringSchema, reason: stringSchema },
      required: ["granted"],
      additionalProperties: false,
    },
    confirmation: {
      type: "object",
      properties: { confirmed: { type: "boolean" }, actor: stringSchema },
      required: ["confirmed"],
      additionalProperties: false,
    },
  },
  additionalProperties: false,
} as const;

const interviewSchema = {
  type: "object",
  properties: {
    questions: {
      type: "array",
      items: {
        type: "object",
        properties: { id: { enum: ["target", "intent", "objectives", "budget"] }, impact: { type: "number" }, prompt: stringSchema, reason: stringSchema },
        required: ["id", "impact", "prompt", "reason"],
        additionalProperties: false,
      },
    },
    plan: { type: "object" },
    confirmationRequired: { type: "boolean" },
  },
  required: ["questions", "confirmationRequired"],
  additionalProperties: true,
} as const;
const reportLinkSchema = {
  type: "object",
  properties: { name: stringSchema, url: { type: "string", pattern: "^https://refactoring\\.guru/[A-Za-z0-9/_-]+$" } },
  required: ["name", "url"],
  additionalProperties: false,
} as const;
const reportFindingSchema = {
  type: "object",
  properties: {
    stableKey: stringSchema,
    title: stringSchema,
    location: { type: "object", properties: { path: stringSchema, line: positiveIntegerSchema, column: positiveIntegerSchema, anchor: stringSchema }, required: ["path", "line", "anchor"], additionalProperties: false },
    evidence: { type: "object", properties: { tier: { enum: ["observed", "reproduced", "corroborated", "hypothesis"] }, source: stringSchema, detail: stringSchema }, required: ["tier", "source", "detail"], additionalProperties: false },
    impact: { enum: ["critical", "high", "medium", "low"] },
    value: { enum: ["high", "medium", "low"] },
    cost: { enum: ["S", "M", "L"] },
    compatibility: { type: "object", properties: { kind: { enum: ["safe", "breaking"] }, surface: stringSchema }, required: ["kind"], additionalProperties: false },
    applyTier: { enum: ["mechanical", "assisted", "manual"] },
    smell: reportLinkSchema,
    refactoring: reportLinkSchema,
    adversarial: { type: "object", properties: { verdict: { enum: ["keep", "downgrade", "drop"] }, reason: stringSchema }, required: ["verdict", "reason"], additionalProperties: false },
  },
  required: ["stableKey", "title", "location", "evidence", "impact", "value", "cost", "compatibility", "applyTier", "adversarial"],
  additionalProperties: false,
} as const;
const reportCoverageSchema = {
  type: "object",
  properties: { dimension: stringSchema, tool: stringSchema, analysisClass: { enum: ["local", "relational", "global", "baseline"] }, status: { enum: ["ran", "skipped", "gap", "not-applicable"] }, notes: stringSchema, config: stringSchema },
  required: ["dimension", "tool", "analysisClass", "status", "notes"],
  additionalProperties: false,
} as const;
const reportInputSchema = {
  type: "object",
  required: ["generatedAt", "target", "headline", "findings", "coverage", "suppressionCount", "systemicPatterns", "extensions"],
  properties: {
    generatedAt: stringSchema,
    target: {
      type: "object",
      required: ["kind", "label", "scopeMode", "languages", "filesAnalyzed"],
      properties: { kind: stringSchema, label: stringSchema, scopeMode: { enum: ["quick", "full", "plan-only"] }, baseRef: stringSchema, languages: { type: "array", items: stringSchema }, filesAnalyzed: { type: "integer", minimum: 0 } },
      additionalProperties: false,
    },
    headline: stringSchema,
    findings: { type: "array", items: reportFindingSchema },
    coverage: { type: "array", items: reportCoverageSchema },
    suppressionCount: { type: "integer", minimum: 0 },
    systemicPatterns: { type: "array", items: stringSchema },
    extensions: { type: "object", additionalProperties: true },
  },
  additionalProperties: false,
} as const;

const outputSchemas = {
  intake: {
    type: "object",
    required: ["ok", "interview"],
    properties: {
      ok: { type: "boolean" },
      interview: interviewSchema,
      manifest: { type: "object" },
      lease: { type: "object", properties: { capability: stringSchema, manifestId: stringSchema, expiresAt: stringSchema }, required: ["capability", "manifestId", "expiresAt"], additionalProperties: false },
      confirmation: { type: "object", additionalProperties: true },
      error: { type: "object", additionalProperties: true },
    },
    additionalProperties: true,
  },
  cancel: { type: "object", required: ["ok"], properties: { ok: { type: "boolean" }, capability: stringSchema, manifestId: stringSchema, released: { type: "boolean" }, error: { type: "object", additionalProperties: true } }, additionalProperties: true },
  install: { type: "object", required: ["ok", "report", "tools"], properties: { ok: { type: "boolean" }, report: stringSchema, tools: { type: "array", items: { type: "object" } }, error: { type: "object", additionalProperties: true } }, additionalProperties: true },
  analyzer: { type: "object", required: ["ok", "report", "outcome"], properties: { ok: { type: "boolean" }, report: stringSchema, outcome: stringSchema, preflight: { type: ["object", "null"] }, execution: { type: "object" }, acceptedExitCodes: { type: "array", items: { type: "integer" } }, error: { type: "object", additionalProperties: true } }, additionalProperties: true },
  report: { type: "object", required: ["ok", "artifacts", "savedPaths"], properties: { ok: { type: "boolean" }, artifacts: { type: "object" }, savedPaths: { type: "array", items: stringSchema }, error: { type: "object", additionalProperties: true } }, additionalProperties: true },
} as const;

const tools = [
  {
    name: "sniff_intake",
    title: "Sniff adaptive intake",
    description: "Resolve one highest-impact Sniff intake question, then obtain a trusted MCP confirmation before issuing a run lease.",
    inputSchema: { type: "object", properties: { input: intakeInputSchema }, required: ["input"], additionalProperties: false },
    outputSchema: outputSchemas.intake,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "sniff_cancel",
    title: "Cancel Sniff run",
    description: "Cancel an issued Sniff run and release its host-owned temporary materialization.",
    inputSchema: { type: "object", properties: { capability: stringSchema, manifestId: stringSchema }, required: ["capability", "manifestId"], additionalProperties: false },
    outputSchema: outputSchemas.cancel,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "sniff_install_tools",
    title: "Sniff install tools",
    description: "Probe, diagnose, list, or install Sniff analyzer catalog entries. Installation is explicit and never uses sudo.",
    inputSchema: {
      type: "object",
      properties: {
        mode: { enum: ["probe", "diagnose", "list", "install"] },
        bundles: { type: "array", items: stringSchema, uniqueItems: true },
        all: { type: "boolean" },
        dryRun: { type: "boolean" },
        noMise: { type: "boolean" },
        path: stringSchema,
      },
      additionalProperties: false,
    },
    outputSchema: outputSchemas.install,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "sniff_run_analyzer",
    title: "Sniff run analyzer",
    description: "Run one analyzer selected by a live sniff_intake capability with its fixed catalogued recipe and one-shot budget reservation.",
    inputSchema: { type: "object", properties: { capability: stringSchema, manifestId: stringSchema, analyzer: stringSchema }, required: ["capability", "manifestId", "analyzer"], additionalProperties: false },
    outputSchema: outputSchemas.analyzer,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "sniff_report",
    title: "Sniff structured report",
    description: "Validate and render or save a Sniff report bound to the exact issued intake manifest, then finalize its lease.",
    inputSchema: {
      type: "object",
      properties: { capability: stringSchema, manifestId: stringSchema, mode: { enum: ["render", "save"] }, report: reportInputSchema, path: stringSchema },
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

function asObject(value: unknown, message: string): JsonObject {
  if (!isObject(value)) throw new SniffMcpError("invalid_input", message);
  return value;
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new SniffMcpError("invalid_input", `${field} must be a non-empty string`);
  return value;
}

function errorDetails(error: unknown): { code: string; message: string } {
  const message = error instanceof Error ? error.message : String(error);
  if (error instanceof SniffMcpError) return { code: error.code, message };
  if (/input|target|budget|security|mode|bundles|report/i.test(message)) return { code: "invalid_input", message };
  if (/capability|manifest|reservation|lease|selected|recipe|authorized/i.test(message)) return { code: "invalid_capability", message };
  if (/confirm|authoriz/i.test(message)) return { code: "confirmation_required", message };
  return { code: "sniff_operation_failed", message };
}

function toolError(name: string, error: unknown): ToolResult {
  const details = errorDetails(error);
  const value = { ok: false, error: { code: details.code, message: details.message } };
  return {
    content: [{ type: "text", text: `${name} failed [${details.code}]: ${details.message}` }],
    structuredContent: value,
    isError: true,
  };
}

function toolSuccess(value: JsonObject, text: string): ToolResult {
  return { content: [{ type: "text", text }], structuredContent: value };
}

function activeLeaseKey(capability: string, manifestId: string): string {
  return `${capability}\0${manifestId}`;
}

function supportsElicitation(): boolean {
  const elicitation = clientCapabilities.elicitation;
  return isObject(elicitation) && isObject(elicitation.form);
}

function send(message: JsonRpcMessage): void {
  if (!process.stdout.writable || shuttingDown) return;
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function requestClient(method: string, params: JsonObject): Promise<unknown> {
  if (shuttingDown) return Promise.reject(new SniffMcpError("server_shutting_down", "MCP server is shutting down"));
  const id = nextClientRequestId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingClientRequests.delete(id);
      reject(new SniffMcpError("elicitation_timeout", "MCP elicitation timed out"));
    }, ELICITATION_TIMEOUT_MS);
    pendingClientRequests.set(id, { resolve, reject, timer });
    send({ jsonrpc: "2.0", id, method, params });
  });
}

async function confirmThroughElicitation(summary: Readonly<{ target: string; files: number }>): Promise<boolean> {
  const response = await requestClient("elicitation/create", {
    mode: "form",
    message: `Confirm Sniff intake for ${summary.target} (${summary.files} files)? This authorizes read-only analysis and temporary materialization only.`,
    requestedSchema: {
      type: "object",
      properties: { confirmed: { type: "boolean", title: "Confirm Sniff intake" } },
      required: ["confirmed"],
      additionalProperties: false,
    },
  });
  if (!isObject(response) || response.action !== "accept") return false;
  const content = response.content;
  return isObject(content) && content.confirmed === true;
}

async function handleIntake(args: JsonObject): Promise<ToolResult> {
  const input = intakeInput(args.input);
  if (input.authorization) throw new SniffMcpError("invalid_input", "Caller-provided authorization is not a trusted MCP confirmation receipt");
  const frontier = decisionFrontier(input);
  if (!frontier.plan) return toolSuccess({ ok: true, interview: frontier }, JSON.stringify(frontier));
  if (input.interactive === false) {
    return toolSuccess(
      { ok: false, interview: frontier, confirmationRequired: true, confirmation: { required: true, reason: "MCP callers cannot authorize intake with interactive=false; use MCP elicitation." } },
      "Sniff intake requires MCP elicitation confirmation before issuing a lease.",
    );
  }
  if (!supportsElicitation()) {
    return toolSuccess(
      { ok: false, interview: frontier, confirmationRequired: true, confirmation: { required: true, mechanism: "elicitation", reason: "The MCP client did not advertise elicitation support." } },
      "Sniff intake is complete but requires a client that supports MCP elicitation; no lease was issued.",
    );
  }
  const result = await runSniffIntakeTool(
    { input: { ...input, interactive: true } },
    { confirmInteractive: confirmThroughElicitation },
  );
  if (result.lease) activeLeases.set(activeLeaseKey(result.lease.capability, result.lease.manifestId), result.lease);
  return toolSuccess({ ok: true, ...result }, JSON.stringify(result));
}

function handleCancel(args: JsonObject): ToolResult {
  const capability = requiredString(args.capability, "capability");
  const manifestId = requiredString(args.manifestId, "manifestId");
  cancelRunLease(capability, manifestId);
  activeLeases.delete(activeLeaseKey(capability, manifestId));
  return toolSuccess({ ok: true, capability, manifestId, released: true }, "Sniff run cancelled and materialization released.");
}

function handleInstall(args: JsonObject): ToolResult {
  const mode = args.mode as SniffInstallMode | undefined;
  if (mode !== undefined && !["probe", "diagnose", "list", "install"].includes(mode)) throw new SniffMcpError("invalid_input", "mode is invalid");
  const bundles = args.bundles;
  if (bundles !== undefined && (!Array.isArray(bundles) || bundles.some((bundle) => typeof bundle !== "string"))) throw new SniffMcpError("invalid_input", "bundles must be an array of strings");
  const result = runSniffInstall({
    ...(mode ? { mode } : {}),
    ...(bundles ? { bundles } : {}),
    ...(typeof args.all === "boolean" ? { all: args.all } : {}),
    ...(typeof args.dryRun === "boolean" ? { dryRun: args.dryRun } : {}),
    ...(typeof args.noMise === "boolean" ? { noMise: args.noMise } : {}),
    cwd: typeof args.path === "string" ? args.path : process.cwd(),
  });
  return { ...toolSuccess({ ok: result.ok, report: result.report, tools: result.tools }, result.report), ...(result.ok ? {} : { isError: true }) };
}

function handleAnalyzer(args: JsonObject): ToolResult {
  const capability = requiredString(args.capability, "capability");
  const manifestId = requiredString(args.manifestId, "manifestId");
  const analyzer = requiredString(args.analyzer, "analyzer");
  const result = runSniffAnalyzer({ capability, manifestId, analyzer });
  const text = result.execution ? `${result.report}\n\nstdout:\n${result.execution.stdout}\n\nstderr:\n${result.execution.stderr}` : result.report;
  return {
    ...toolSuccess(
      { ok: result.ok, report: result.report, preflight: result.preflight, ...(result.acceptedExitCodes ? { acceptedExitCodes: result.acceptedExitCodes } : {}), outcome: result.outcome, ...(result.execution ? { execution: result.execution } : {}) },
      text,
    ),
    ...(result.ok ? {} : { isError: true }),
  };
}

function handleReport(args: JsonObject): ToolResult {
  const capability = requiredString(args.capability, "capability");
  const manifestId = requiredString(args.manifestId, "manifestId");
  if (args.mode !== undefined && args.mode !== "render" && args.mode !== "save") throw new SniffMcpError("invalid_input", "mode is invalid");
  const mode = args.mode as SniffReportMode | undefined;
  try {
    if (!isObject(args.report)) throw new SniffMcpError("invalid_input", "report must be an object");
    const result = runSniffReportTool({ capability, manifestId, mode, report: args.report as unknown as ReportInput, ...(typeof args.path === "string" ? { path: args.path } : {}) });
    return toolSuccess({ ok: true, artifacts: result.artifacts, savedPaths: result.savedPaths }, result.artifacts.markdown);
  } finally {
    activeLeases.delete(activeLeaseKey(capability, manifestId));
  }
}

async function callTool(name: string, args: JsonObject): Promise<ToolResult> {
  try {
    switch (name) {
      case "sniff_intake":
        return await handleIntake(args);
      case "sniff_cancel":
        return handleCancel(args);
      case "sniff_install_tools":
        return handleInstall(args);
      case "sniff_run_analyzer":
        return handleAnalyzer(args);
      case "sniff_report":
        return handleReport(args);
      default:
        throw new SniffMcpError("unknown_tool", `Unknown tool ${name}`);
    }
  } catch (error) {
    return toolError(name, error);
  }
}

function rpcError(id: JsonRpcId | null, code: number, message: string, data?: JsonObject): void {
  send({ jsonrpc: "2.0", id, error: { code, message, ...(data ? { data } : {}) } });
}

function responseId(value: unknown): JsonRpcId | null {
  return typeof value === "string" || (typeof value === "number" && Number.isFinite(value)) ? value : null;
}

async function handleMessage(value: unknown): Promise<void> {
  if (!isObject(value) || value.jsonrpc !== "2.0") {
    rpcError(null, -32600, "Invalid JSON-RPC request");
    return;
  }
  const id = responseId(value.id);
  if (typeof value.method !== "string") {
    if (id !== null) {
      const pending = pendingClientRequests.get(id);
      if (pending) {
        pendingClientRequests.delete(id);
        clearTimeout(pending.timer);
        if (isObject(value.error)) pending.reject(new SniffMcpError("elicitation_rejected", typeof value.error.message === "string" ? value.error.message : "MCP client rejected request"));
        else pending.resolve(value.result);
      }
    }
    return;
  }
  const method = value.method;
  if (method === "notifications/initialized" || method === "notifications/cancelled") return;
  if (method === "initialize") {
    const params = asObject(value.params ?? {}, "initialize params must be an object");
    clientCapabilities = isObject(params.capabilities) ? params.capabilities : {};
    if (id === null) return;
    send({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: typeof params.protocolVersion === "string" ? params.protocolVersion : "2025-06-18",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "sniff", version: SERVER_VERSION },
      },
    });
    return;
  }
  if (method === "ping") {
    if (id !== null) send({ jsonrpc: "2.0", id, result: {} });
    return;
  }
  if (method === "tools/list") {
    if (id !== null) send({ jsonrpc: "2.0", id, result: { tools } });
    return;
  }
  if (method === "tools/call") {
    if (id === null) return;
    try {
      const params = asObject(value.params ?? {}, "tools/call params must be an object");
      const name = requiredString(params.name, "name");
      const args = asObject(params.arguments ?? {}, "tools/call arguments must be an object");
      send({ jsonrpc: "2.0", id, result: await callTool(name, args) });
    } catch (error) {
      const details = errorDetails(error);
      rpcError(id, -32602, details.message, { code: details.code });
    }
    return;
  }
  if (method === "shutdown") {
    if (id !== null) send({ jsonrpc: "2.0", id, result: null });
    return;
  }
  if (id !== null) rpcError(id, -32601, `Method not found: ${method}`);
}

function releaseLeases(reason: string): void {
  try {
    releaseAllRunLeases(reason);
  } finally {
    activeLeases.clear();
  }
}

function terminate(reason: string): void {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const pending of pendingClientRequests.values()) {
    clearTimeout(pending.timer);
    pending.reject(new SniffMcpError("server_shutting_down", "MCP server is shutting down"));
  }
  pendingClientRequests.clear();
  releaseLeases(reason);
  process.stdin.pause();
  process.exit(0);
}

process.once("SIGINT", () => terminate("SIGINT"));
process.once("SIGTERM", () => terminate("SIGTERM"));
process.once("exit", () => releaseLeases("process-exit"));

export async function serve(): Promise<void> {
  const readline = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let resolveClosed: (() => void) | undefined;
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });
  readline.on("line", (line) => {
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      rpcError(null, -32700, "Parse error");
      return;
    }
    void handleMessage(value);
  });
  readline.on("close", () => {
    if (!shuttingDown) {
      shuttingDown = true;
      for (const pending of pendingClientRequests.values()) {
        clearTimeout(pending.timer);
        pending.reject(new SniffMcpError("stdin_closed", "MCP client closed stdin"));
      }
      pendingClientRequests.clear();
      releaseLeases("stdin-closed");
    }
    resolveClosed?.();
  });
  await closed;
}

if (import.meta.main) void serve();
