import reportInputSchemaDocument from "../../skills/sniff/references/report-input.schema.json";

const MAX_INPUT_ARRAY_LENGTH = 2_000;
const MAX_OUTPUT_TEXT_BYTES = 65_536;
const stringSchema = { type: "string" } as const;
const positiveIntegerSchema = { type: "integer", minimum: 1 } as const;

const historyWindowSchema = {
  type: "object",
  oneOf: [
    { type: "object", additionalProperties: false, required: ["kind", "base", "head"], properties: { kind: { const: "refs" }, base: stringSchema, head: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "date"], properties: { kind: { const: "since-date" }, date: stringSchema, head: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "count"], properties: { kind: { const: "last-commits" }, count: { type: "integer", minimum: 1 }, head: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "release"], properties: { kind: { const: "since-release" }, release: stringSchema, head: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind"], properties: { kind: { const: "previous-release" }, release: stringSchema, head: stringSchema } },
    { type: "object", additionalProperties: false, required: ["kind"], properties: { kind: { const: "context-aware-default" }, head: stringSchema } },
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
    { type: "object", additionalProperties: false, required: ["kind", "repository", "iid"], properties: { kind: { const: "mr" }, repository: stringSchema, iid: { oneOf: [stringSchema, { type: "integer" }] } }, },
  ],
} as const;

const intakeInput = {
  type: "object",
  additionalProperties: false,
  properties: {
    target: targetSchema,
    intent: { enum: ["audit", "review-change", "release-risk", "history", "plan-only"] },
    scopeMode: { enum: ["quick", "full", "plan-only"] },
    objectives: { type: "array", items: stringSchema, uniqueItems: true, maxItems: MAX_INPUT_ARRAY_LENGTH },
    exclusions: { type: "array", items: stringSchema, uniqueItems: true, maxItems: MAX_INPUT_ARRAY_LENGTH },
    budget: { type: "object", additionalProperties: false, properties: { maxMinutes: positiveIntegerSchema, maxAnalyzers: positiveIntegerSchema, maxFiles: positiveIntegerSchema } },
    security: { type: "object" },
    interactive: { type: "boolean" },
  },
} as const;

const reportSchema = reportInputSchemaDocument as Record<string, unknown> & { readonly $defs?: Record<string, unknown> };
const { $schema: _schema, $id: _id, title: _title, $defs: reportDefinitions, ...reportBody } = reportSchema;
const reportInput = {
  type: "object",
  properties: {
    capability: { type: "string", minLength: 1 },
    manifestId: { type: "string", minLength: 1 },
    mode: { enum: ["render", "save"] },
    report: reportBody,
    path: { type: "string", minLength: 1 },
  },
  $defs: reportDefinitions,
  required: ["capability", "manifestId", "report"],
  additionalProperties: false,
} as const;

export const sniffToolInputSchemas = {
  sniff_intake: { type: "object", properties: { input: intakeInput }, required: ["input"], additionalProperties: false },
  sniff_cancel: { type: "object", properties: { capability: stringSchema, manifestId: stringSchema }, required: ["capability", "manifestId"], additionalProperties: false },
  sniff_install_tools: { type: "object", properties: { mode: { enum: ["probe", "diagnose", "list", "install"] }, bundles: { type: "array", items: stringSchema, uniqueItems: true, maxItems: MAX_INPUT_ARRAY_LENGTH }, all: { type: "boolean" }, dryRun: { type: "boolean" }, path: stringSchema }, additionalProperties: false },
  sniff_run_analyzer: { type: "object", properties: { capability: stringSchema, manifestId: stringSchema, analyzer: stringSchema }, required: ["capability", "manifestId", "analyzer"], additionalProperties: false },
  sniff_report: reportInput,
  sniff_read_report_artifact: { type: "object", properties: { readCapability: stringSchema, reportId: stringSchema, relativePath: stringSchema, offset: { type: "integer", minimum: 0 } }, required: ["readCapability", "reportId", "relativePath"], additionalProperties: false },
  sniff_read_analyzer_artifact: { type: "object", properties: { analyzerResultId: stringSchema, readCapability: stringSchema, relativePath: stringSchema, sourcePath: stringSchema, offset: { type: "integer", minimum: 0 }, maxBytes: { type: "integer", minimum: 4, maximum: MAX_OUTPUT_TEXT_BYTES } }, required: ["analyzerResultId", "readCapability"], additionalProperties: false },
} as const;

export type SniffToolName = keyof typeof sniffToolInputSchemas;

export function sniffInstallApproval(args: unknown): "read" | "exec" {
  return args && typeof args === "object" && "mode" in args && args.mode === "install" ? "exec" : "read";
}

export function sniffReportApproval(args: unknown): "read" | "write" {
  return args && typeof args === "object" && "mode" in args && args.mode === "save" ? "write" : "read";
}

export function sniffIntakeApproval(args: unknown): "read" | "exec" {
  if (!args || typeof args !== "object" || !("input" in args) || !args.input || typeof args.input !== "object" || !("target" in args.input) || !args.input.target || typeof args.input.target !== "object" || !("kind" in args.input.target)) return "exec";
  const kind = args.input.target.kind;
  return ["whole-repo", "working-tree", "files", "directory", "module"].includes(typeof kind === "string" ? kind : "") ? "read" : "exec";
}
