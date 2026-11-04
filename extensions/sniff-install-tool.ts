import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { type AnalyzerArtifactDescriptor, type AnalyzerArtifactReadOptions, type AnalyzerObservationPreview, readAnalyzerArtifact } from "../src/core/analyzer-artifact-registry.ts";
import type { AnalyzerCapture, AnalyzerObservation } from "../src/core/analyzer-output.ts";
import { installConfirmationText as installConfirmationMessage } from "../src/core/confirmation-text.ts";
import {
  runSniffAnalyzer,
  runSniffInstall,
  type SniffAnalyzerOutcome,
  type SniffInstallMode,
  type SniffToolResult,
  sniffInstallAuthorizationRequest,
} from "../src/core/install.ts";
import { analyzerArtifactPage, analyzerPageLimit, analyzerProjection, publicPreflight } from "../src/core/model-content.ts";
import type { SniffRunOwner } from "../src/core/run-owner.ts";
import { sniffInstallApproval, sniffToolInputSchemas } from "../src/core/tool-schemas.ts";

type SniffReadAnalyzerArtifactParams = Omit<AnalyzerArtifactReadOptions, "capability"> & {
  readonly readCapability: string;
  readonly maxBytes?: number;
};

function registerAnalyzerArtifactReader(pi: ExtensionAPI, owner: SniffRunOwner | undefined): void {
  pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string }>({
    name: "sniff_read_analyzer_artifact",
    label: "Read Sniff analyzer artifact",
    description: "Read one UTF-8-safe page from complete analyzer observations using the readCapability returned by sniff_run_analyzer. Provide relativePath or sourcePath.",
    approval: "read",
    parameters: sniffToolInputSchemas.sniff_read_analyzer_artifact as unknown as TSchema,
    execute: async (_id, params: SniffReadAnalyzerArtifactParams) => {
      try {
        const { readCapability, maxBytes, ...options } = params;
        const limit = analyzerPageLimit(maxBytes);
        const { text, page } = analyzerArtifactPage(readAnalyzerArtifact({ ...options, capability: readCapability }, undefined, owner), limit);
        return { content: [{ type: "text", text }], details: { ok: true, analyzerResultId: page.analyzerResultId, relativePath: page.relativePath, sourcePath: page.sourcePath, offset: page.offset, nextOffset: page.nextOffset, eof: page.eof, bytes: page.bytes, totalBytes: page.totalBytes, sha256: page.sha256 } };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: "text", text: `sniff_read_analyzer_artifact failed: ${message}` }], details: { ok: false, error: message }, isError: true };
      }
    },
  });
}

type SniffInstallParams = { mode?: SniffInstallMode; bundles?: string[]; all?: boolean; dryRun?: boolean; path?: string };

/**
 * Installation mirrors the MCP adapter: the host owns the cwd, the exact
 * diagnosed plan is shown with its digest, and only an interactive user can
 * approve it. Headless sessions (including subagents under yolo) are refused.
 */
async function confirmedInstall(params: SniffInstallParams, signal: AbortSignal | undefined, ctx: ExtensionContext | undefined) {
  if (params.path !== undefined) throw new Error("Install mode does not accept a caller-controlled cwd");
  if (!ctx?.hasUI) throw new Error("Installation requires interactive confirmation of the exact plan; headless sessions cannot install");
  const options = { bundles: params.bundles, all: params.all, dryRun: params.dryRun, cwd: ctx.cwd ?? process.cwd(), signal };
  const request = await sniffInstallAuthorizationRequest(options);
  const approved = await ctx.ui.confirm("Authorize this exact Sniff installation plan", installConfirmationMessage(request));
  if (!approved) throw new Error("Sniff installation authorization was denied");
  if (signal?.aborted) throw new Error("operation aborted");
  return runSniffInstall({ ...options, mode: "install" });
}

/** Registers install, analyzer, and artifact reading; `owner` scopes the runs, and omitted they use the process owner. */
export default function sniffInstallTool(pi: ExtensionAPI, owner?: SniffRunOwner): void {
  pi.registerTool({
    name: "sniff_install_tools",
    label: "Sniff install tools",
    description: "Probe, diagnose, list, or install sniff analyzer catalog entries. Diagnose is inventory-only and never authorizes execution. Managed installs require mise and are re-probed from a Sniff-owned toolkit. Never sudo or bypass trust policy. Default mode is probe.",
    approval: sniffInstallApproval,
    parameters: sniffToolInputSchemas.sniff_install_tools as unknown as TSchema,
    execute: async (_id, params: SniffInstallParams, signal, _onUpdate, ctx) => {
      try {
        const result = params.mode === "install"
          ? await confirmedInstall(params, signal, ctx)
          : await runSniffInstall({ ...params, cwd: params.path ?? ctx?.cwd ?? process.cwd(), signal });
        return { content: [{ type: "text", text: result.report }], details: { ok: result.ok, tools: result.tools }, isError: !result.ok };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: "text", text: `sniff_install_tools failed: ${message}` }], details: { ok: false, error: message, tools: [] }, isError: true };
      }
    },
  });

  pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string; readonly preflight: SniffToolResult | null; readonly acceptedExitCodes?: number[]; readonly outcome?: SniffAnalyzerOutcome; readonly analyzerResultId?: string; readonly readCapability?: string; readonly descriptors?: readonly AnalyzerArtifactDescriptor[]; readonly descriptorCount?: number; readonly descriptorsTruncated?: boolean; readonly observationPreview?: AnalyzerObservationPreview; readonly observations?: readonly AnalyzerObservation[]; readonly capture?: AnalyzerCapture }>({
    name: "sniff_run_analyzer",
    label: "Sniff run analyzer",
    description: "Run one analyzer selected by a live sniff_intake capability. The host revalidates the materialized target and enforces the catalogued fixed recipe immediately before execution.",
    approval: "exec",
    parameters: sniffToolInputSchemas.sniff_run_analyzer as unknown as TSchema,
    execute: async (_id, params: { capability: string; manifestId: string; analyzer: string }, signal) => {
      try {
        const result = await runSniffAnalyzer({ ...params, signal, owner });
        const text = result.ok
          ? JSON.stringify(analyzerProjection(params.analyzer, result))
          : result.report;
        return { content: [{ type: "text", text }], details: { ok: result.ok, preflight: publicPreflight(result.preflight), acceptedExitCodes: result.acceptedExitCodes, outcome: result.outcome, analyzerResultId: result.analyzerResultId, readCapability: result.readCapability, descriptors: result.descriptors, descriptorCount: result.descriptorCount, descriptorsTruncated: result.descriptorsTruncated, observationPreview: result.observationPreview, observations: result.observations, capture: result.capture }, isError: !result.ok };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: "text", text: `sniff_run_analyzer failed: ${message}` }], details: { ok: false, error: message, preflight: null }, isError: true };
      }
    },
  });
  registerAnalyzerArtifactReader(pi, owner);
}
