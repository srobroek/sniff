import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import reportInputSchemaDocument from "../skills/sniff/references/report-input.schema.json";
import { type ReportArtifactReadOptions, readReportArtifact } from "../src/core/report-artifact-registry.ts";
import {
  runSniffReportTool,
  type SaveAuthorizationRequest,
  type SniffReportRuntime,
  type SniffReportToolOptions,
} from "../src/core/report-use-case.ts";

type SniffReadReportArtifactParams = ReportArtifactReadOptions;

function registerReportArtifactReader(pi: ExtensionAPI): void {
  const z = pi.zod;
  pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string }>({
    name: "sniff_read_report_artifact",
    label: "Read Sniff report artifact",
    description: "Read one UTF-8-safe page from a complete in-process Sniff report artifact using its opaque capability.",
    parameters: z.object({
      capability: z.string().describe("Opaque report artifact read capability returned by sniff_report"),
      reportId: z.string().describe("Report ID returned by sniff_report"),
      relativePath: z.string().describe("Artifact relative path from a sniff_report descriptor"),
      offset: z.number().int().nonnegative().optional().describe("UTF-8 byte offset returned as nextOffset; defaults to zero"),
    }) as unknown as TSchema,
    execute: async (_id, params: SniffReadReportArtifactParams) => {
      try {
        const result = readReportArtifact(params);
        return {
          content: [{ type: "text", text: result.content }],
          details: {
            ok: true,
            reportId: result.reportId,
            relativePath: result.relativePath,
            offset: result.offset,
            nextOffset: result.nextOffset,
            eof: result.eof,
            bytes: result.bytes,
            totalBytes: result.totalBytes,
            sha256: result.sha256,
          },
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: "text", text: `sniff_read_report_artifact failed: ${message}` }], details: { ok: false, error: message }, isError: true };
      }
    },
  });
}

function saveConfirmationMessage(request: SaveAuthorizationRequest): string {
  return [
    `Canonical report directory: ${request.directory}`,
    `Manifest ID: ${request.manifestId}`,
    `Report ID: ${request.reportId}`,
    `Artifacts: ${request.files.length} files with SHA-256 digests`,
    `Save digest: ${request.digest}`,
  ].join("\n");
}

function runtimeForContext(ctx: ExtensionContext): SniffReportRuntime {
  return {
    authorizeSave: async (request) => {
      if (!ctx.hasUI) return false;
      const approved = await ctx.ui.confirm("Confirm Sniff report save", saveConfirmationMessage(request));
      return approved ? { acceptedDigest: request.digest, actor: "interactive-user", reason: "Confirmed through the OMP UI boundary." } : false;
    },
  };
}
type JsonSchema = Record<string, unknown> & { readonly $defs?: Record<string, unknown> };

const canonicalReportSchema = reportInputSchemaDocument as JsonSchema;
const { $schema: _schema, $id: _id, title: _title, $defs: reportDefinitions, ...reportSchema } = canonicalReportSchema;
const reportToolParameters = {
  type: "object",
  $defs: reportDefinitions,
  properties: {
    capability: { type: "string", minLength: 1, description: "Opaque capability returned by sniff_intake" },
    manifestId: { type: "string", minLength: 1, description: "Opaque manifest ID returned by sniff_intake" },
    mode: { enum: ["render", "save"], description: "render (default) or explicit save" },
    report: { ...reportSchema, description: "Copy reportTarget from sniff_intake into target, add languages, and omit extensions[sniff.intake] so the host injects it" },
    path: { type: "string", minLength: 1, description: "Output parent directory required only for save mode" },
  },
  required: ["capability", "manifestId", "report"],
  additionalProperties: false,
} as unknown as TSchema;

export default function sniffReportTool(pi: ExtensionAPI): void {
  pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string }>({
    name: "sniff_report",
    label: "Sniff structured report",
    description: "Build a canonical Sniff report for a live sniff_intake capability; the host injects the authenticated manifest when the report extension is omitted and rejects mismatches.",
    parameters: reportToolParameters,
    execute: async (_id, params: SniffReportToolOptions, _signal, _onUpdate, ctx) => {
      try {
        const result = await runSniffReportTool({ ...params, runtime: runtimeForContext(ctx) });
        return {
          content: [{ type: "text", text: result.publicArtifacts.summary }],
          details: {
            ok: true,
            reportId: result.publicArtifacts.reportId,
            readCapability: result.publicArtifacts.readCapability,
            summary: result.publicArtifacts.summary,
            descriptors: result.publicArtifacts.descriptors,
            savedPaths: result.publicArtifacts.descriptors.flatMap((descriptor) => descriptor.savedPath ? [descriptor.savedPath] : []),
            descriptorCount: result.publicArtifacts.descriptorCount,
            descriptorsTruncated: result.publicArtifacts.descriptorsTruncated,
            receipt: result.publicArtifacts.receipt,
          },
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: "text", text: `sniff_report failed: ${message}` }], details: { ok: false, error: message, savedPaths: [] }, isError: true };
      }
    },
  });
  registerReportArtifactReader(pi);
}
