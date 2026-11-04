import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { saveConfirmationText as saveConfirmationMessage } from "../src/core/confirmation-text.ts";
import { reportArtifactPage, reportRenderContent } from "../src/core/model-content.ts";
import { type ReportArtifactReadOptions, readReportArtifact } from "../src/core/report-artifact-registry.ts";
import {
  runSniffReportTool,
  type SniffReportRuntime,
  type SniffReportToolOptions,
} from "../src/core/report-use-case.ts";
import type { SniffRunOwner } from "../src/core/run-owner.ts";
import { sniffReportApproval, sniffToolInputSchemas } from "../src/core/tool-schemas.ts";

type SniffReadReportArtifactParams = Omit<ReportArtifactReadOptions, "capability"> & {
  readonly readCapability: string;
};

function registerReportArtifactReader(pi: ExtensionAPI, owner: SniffRunOwner | undefined): void {
  pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string }>({
    name: "sniff_read_report_artifact",
    label: "Read Sniff report artifact",
    description: "Read one UTF-8-safe page from a complete in-process Sniff report artifact using the readCapability returned by sniff_report.",
    approval: "read",
    parameters: sniffToolInputSchemas.sniff_read_report_artifact as unknown as TSchema,
    execute: async (_id, params: SniffReadReportArtifactParams) => {
      try {
        const { readCapability, ...options } = params;
        const result = readReportArtifact({ ...options, capability: readCapability }, undefined, owner);
        const { text, page: delivered } = reportArtifactPage(result);
        const page = { nextOffset: delivered.nextOffset, eof: delivered.eof, bytes: delivered.bytes };
        return {
          content: [{ type: "text", text }],
          details: {
            ok: true,
            reportId: result.reportId,
            relativePath: result.relativePath,
            offset: result.offset,
            ...page,
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

function runtimeForContext(ctx: ExtensionContext): SniffReportRuntime {
  return {
    authorizeSave: async (request) => {
      if (!ctx.hasUI) return false;
      const approved = await ctx.ui.confirm("Confirm Sniff report save", saveConfirmationMessage(request));
      return approved ? { acceptedDigest: request.digest, actor: "interactive-user", reason: "Confirmed through the OMP UI boundary." } : false;
    },
  };
}
/** Registers report and artifact reading; `owner` scopes the runs, and omitted they use the unscoped view. */
export default function sniffReportTool(pi: ExtensionAPI, owner?: SniffRunOwner): void {
  pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string }>({
    name: "sniff_report",
    label: "Sniff structured report",
    description: "Build a canonical Sniff report for a live sniff_intake capability; the host injects the authenticated manifest when the report extension is omitted and rejects mismatches.",
    approval: sniffReportApproval,
    parameters: sniffToolInputSchemas.sniff_report as unknown as TSchema,
    execute: async (_id, params: SniffReportToolOptions, _signal, _onUpdate, ctx) => {
      try {
        const result = await runSniffReportTool({ ...params, runtime: runtimeForContext(ctx), owner });
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
  registerReportArtifactReader(pi, owner);
}
