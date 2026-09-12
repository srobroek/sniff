import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import reportInputSchemaDocument from "../skills/sniff/references/report-input.schema.json";
import type { PublicReportArtifacts } from "../src/core/report.ts";
import { type ReportArtifactReadOptions, type ReportArtifactReadResult, readReportArtifact } from "../src/core/report-artifact-registry.ts";
import {
  runSniffReportTool,
  type SaveAuthorizationRequest,
  type SniffReportRuntime,
  type SniffReportToolOptions,
} from "../src/core/report-use-case.ts";

const MAX_MODEL_CONTENT_BYTES = 64 * 1024 - 1;

function utf8Prefix(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value, "utf8");
  let end = Math.min(bytes.length, Math.max(0, maxBytes));
  while (end > 0 && (bytes[end] ?? 0) >= 0x80 && (bytes[end] ?? 0) < 0xc0) end -= 1;
  return bytes.subarray(0, end).toString("utf8");
}

function reportMetadata(publicArtifacts: PublicReportArtifacts, descriptors: PublicReportArtifacts["descriptors"]): string {
  return JSON.stringify({ reportId: publicArtifacts.reportId, readCapability: publicArtifacts.readCapability, descriptors });
}

function reportRenderContent(publicArtifacts: PublicReportArtifacts): string {
  const allDescriptors = [...publicArtifacts.descriptors];
  const encode = (descriptors: PublicReportArtifacts["descriptors"], summary: string): string => `${reportMetadata(publicArtifacts, descriptors)}\n${summary}`;
  const fits = (descriptors: PublicReportArtifacts["descriptors"], summary: string): boolean => Buffer.byteLength(encode(descriptors, summary), "utf8") <= MAX_MODEL_CONTENT_BYTES;

  let low = 0;
  let high = allDescriptors.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (fits(allDescriptors.slice(0, middle), publicArtifacts.summary)) low = middle;
    else high = middle - 1;
  }
  const selectedDescriptors = allDescriptors.slice(0, low);
  if (fits(selectedDescriptors, publicArtifacts.summary)) return encode(selectedDescriptors, publicArtifacts.summary);

  let descriptorLow = 0;
  let descriptorHigh = allDescriptors.length;
  while (descriptorLow < descriptorHigh) {
    const middle = Math.ceil((descriptorLow + descriptorHigh) / 2);
    if (fits(allDescriptors.slice(0, middle), "")) descriptorLow = middle;
    else descriptorHigh = middle - 1;
  }
  const boundedDescriptors = allDescriptors.slice(0, descriptorLow);
  const summaryBudget = MAX_MODEL_CONTENT_BYTES - Buffer.byteLength(reportMetadata(publicArtifacts, boundedDescriptors), "utf8") - 1;
  return encode(boundedDescriptors, utf8Prefix(publicArtifacts.summary, summaryBudget));
}

function reportArtifactEnvelope(result: ReportArtifactReadResult): string {
  const metadata = { relativePath: result.relativePath, offset: result.offset };
  const encode = (content: string, consumed: number): string => JSON.stringify({
    ...metadata,
    nextOffset: result.offset + consumed,
    eof: result.eof && consumed === result.bytes,
    bytes: consumed,
    content,
  });
  const originalBytes = Buffer.byteLength(result.content, "utf8");
  const original = encode(result.content, originalBytes);
  if (Buffer.byteLength(original, "utf8") <= MAX_MODEL_CONTENT_BYTES) return original;

  let low = 0;
  let high = originalBytes;
  let best = encode("", 0);
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const content = utf8Prefix(result.content, middle);
    const candidate = encode(content, Buffer.byteLength(content, "utf8"));
    if (Buffer.byteLength(candidate, "utf8") <= MAX_MODEL_CONTENT_BYTES) {
      best = candidate;
      low = middle + 1;
    } else high = middle - 1;
  }
  return best;
}

type SniffReadReportArtifactParams = Omit<ReportArtifactReadOptions, "capability"> & {
  readonly readCapability: string;
};

function registerReportArtifactReader(pi: ExtensionAPI): void {
  const z = pi.zod;
  pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string }>({
    name: "sniff_read_report_artifact",
    label: "Read Sniff report artifact",
    description: "Read one UTF-8-safe page from a complete in-process Sniff report artifact using the readCapability returned by sniff_report.",
    parameters: z.object({
      readCapability: z.string().describe("Opaque report artifact read capability returned by sniff_report"),
      reportId: z.string().describe("Report ID returned by sniff_report"),
      relativePath: z.string().describe("Artifact relative path from a sniff_report descriptor"),
      offset: z.number().int().nonnegative().optional().describe("UTF-8 byte offset returned as nextOffset; defaults to zero"),
    }) as unknown as TSchema,
    execute: async (_id, params: SniffReadReportArtifactParams) => {
      try {
        const { readCapability, ...options } = params;
        const result = readReportArtifact({ ...options, capability: readCapability });
        return {
          content: [{ type: "text", text: reportArtifactEnvelope(result) }],
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
          content: [{ type: "text", text: reportRenderContent(result.publicArtifacts) }],
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
