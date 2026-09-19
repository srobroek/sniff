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
    { type: "object", additionalProperties: false, required: ["kind", "root"], properties: { kind: { const: "whole-repo", description: "Whole repository snapshot" }, root: { ...stringSchema, description: "Repository root" } } },
    { type: "object", additionalProperties: false, required: ["kind", "root"], properties: { kind: { const: "working-tree", description: "Uncommitted working tree" }, root: { ...stringSchema, description: "Repository root" } } },
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
    capability: { type: "string", minLength: 1, description: "Opaque capability returned by sniff_intake" },
    manifestId: { type: "string", minLength: 1, description: "Opaque manifest ID returned by sniff_intake" },
    mode: { enum: ["render", "save"], description: "render (default) or explicit save" },
    report: { ...reportBody, description: "Copy reportTarget from sniff_intake into target, add languages, and omit extensions[sniff.intake] so the host injects it" },
    path: { type: "string", minLength: 1, description: "Output parent directory required only for save mode" },
  },
  $defs: reportDefinitions,
  required: ["capability", "manifestId", "report"],
  additionalProperties: false,
} as const;

export const sniffToolInputSchemas = {
  sniff_intake: { type: "object", properties: { input: { ...intakeInput, description: "Adaptive intake request" } }, required: ["input"], additionalProperties: false },
  sniff_cancel: { type: "object", properties: { capability: { ...stringSchema, description: "Opaque capability returned by sniff_intake" }, manifestId: { ...stringSchema, description: "Manifest ID returned by sniff_intake" } }, required: ["capability", "manifestId"], additionalProperties: false },
  sniff_install_tools: { type: "object", properties: { mode: { enum: ["probe", "diagnose", "list", "install"], description: "probe (default), inventory-only diagnose, list, or install" }, bundles: { type: "array", items: stringSchema, uniqueItems: true, maxItems: MAX_INPUT_ARRAY_LENGTH, description: "Required/install bundle names" }, all: { type: "boolean", description: "Select every bundle" }, dryRun: { type: "boolean", description: "Print install commands without running them" }, path: { ...stringSchema, description: "Repo cwd for project-local tools" } }, additionalProperties: false },
  sniff_run_analyzer: { type: "object", properties: { capability: { ...stringSchema, description: "Opaque capability returned by sniff_intake" }, manifestId: { ...stringSchema, description: "Manifest ID returned by sniff_intake" }, analyzer: { ...stringSchema, description: "Selected analyzer recipe ID from the issued manifest" } }, required: ["capability", "manifestId", "analyzer"], additionalProperties: false },
  sniff_report: reportInput,
  sniff_read_report_artifact: { type: "object", properties: { readCapability: { ...stringSchema, description: "Opaque report artifact read capability" }, reportId: { ...stringSchema, description: "Report ID returned by sniff_report" }, relativePath: { ...stringSchema, description: "Artifact relative path" }, offset: { type: "integer", minimum: 0 } }, required: ["readCapability", "reportId", "relativePath"], additionalProperties: false },
  sniff_read_analyzer_artifact: { type: "object", properties: { analyzerResultId: { ...stringSchema, description: "Analyzer result ID returned by sniff_run_analyzer" }, readCapability: { ...stringSchema, description: "Opaque analyzer artifact read capability" }, relativePath: { ...stringSchema, description: "Artifact relative path" }, sourcePath: { ...stringSchema, description: "Normalized source path for direct lookup" }, offset: { type: "integer", minimum: 0 }, maxBytes: { type: "integer", minimum: 4, maximum: MAX_OUTPUT_TEXT_BYTES, description: "Maximum UTF-8 bytes to return" } }, required: ["analyzerResultId", "readCapability"], additionalProperties: false },
} as const;

export type SniffToolName = keyof typeof sniffToolInputSchemas;

export function sniffInstallApproval(args: unknown): "read" | "exec" {
  if (!args || typeof args !== "object" || !("mode" in args) || args.mode === undefined) return "read";
  return args.mode === "probe" || args.mode === "diagnose" || args.mode === "list" ? "read" : "exec";
}

export function sniffReportApproval(args: unknown): "read" | "write" {
  if (!args || typeof args !== "object" || !("mode" in args) || args.mode === undefined) return "read";
  return args.mode === "render" ? "read" : "write";
}

export function sniffIntakeApproval(args: unknown): "read" | "exec" {
  if (!args || typeof args !== "object" || !("input" in args) || !args.input || typeof args.input !== "object" || !("target" in args.input) || !args.input.target || typeof args.input.target !== "object" || !("kind" in args.input.target)) return "exec";
  const kind = args.input.target.kind;
  return ["working-tree", "files", "directory", "module"].includes(typeof kind === "string" ? kind : "") ? "read" : "exec";
}
