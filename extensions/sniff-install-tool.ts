import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import {
  runSniffAnalyzer,
  runSniffInstall,
  type SniffAnalyzerOutcome,
  type SniffInstallMode,
  type SniffToolResult,
} from "../src/core/install.ts";

export default function sniffInstallTool(pi: ExtensionAPI): void {
  const z = pi.zod;
  pi.registerTool({
    name: "sniff_install_tools",
    label: "Sniff install tools",
    description: "Probe, diagnose, list, or install sniff analyzer catalog entries. Diagnose is inventory-only and never authorizes execution. Install re-probes in a fresh mise-aware environment. Never sudo or bypass trust policy. Default mode is probe.",
    parameters: z.object({
      mode: z.enum(["probe", "diagnose", "list", "install"]).optional().describe("probe (default), inventory-only diagnose, list, or install"),
      bundles: z.array(z.string()).optional().describe("Required/install bundle names: core dup security rust go python js-ts shell sql css data api infra docs"),
      all: z.boolean().optional().describe("Select every bundle"),
      dryRun: z.boolean().optional().describe("Print install commands without running them"),
      noMise: z.boolean().optional().describe("Ignore mise even if present"),
      path: z.string().optional().describe("Repo cwd for project-local tools and mise-local pins"),
    }) as unknown as TSchema,
    execute: async (_id, params: { mode?: SniffInstallMode; bundles?: string[]; all?: boolean; dryRun?: boolean; noMise?: boolean; path?: string }, signal, _onUpdate, ctx) => {
      try {
        const result = await runSniffInstall({ ...params, cwd: params.path ?? ctx?.cwd ?? process.cwd(), signal });
        return { content: [{ type: "text", text: result.report }], details: { ok: result.ok, tools: result.tools }, isError: !result.ok };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: "text", text: `sniff_install_tools failed: ${message}` }], details: { ok: false, error: message, tools: [] }, isError: true };
      }
    },
  });

  pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string; readonly preflight: SniffToolResult | null; readonly acceptedExitCodes?: number[]; readonly outcome?: SniffAnalyzerOutcome }>({
    name: "sniff_run_analyzer",
    label: "Sniff run analyzer",
    description: "Run one analyzer selected by a live sniff_intake capability. The host revalidates the materialized target and enforces the catalogued fixed recipe immediately before execution.",
    parameters: z.object({
      capability: z.string().describe("Opaque capability returned by sniff_intake"),
      manifestId: z.string().describe("Manifest ID returned by sniff_intake"),
      analyzer: z.string().describe("Selected analyzer recipe ID from the issued manifest"),
    }) as unknown as TSchema,
    execute: async (_id, params: { capability: string; manifestId: string; analyzer: string }, signal) => {
      try {
        const result = await runSniffAnalyzer({ ...params, signal });
        const text = result.execution ? `${result.report}\n\nstdout:\n${result.execution.stdout}${result.execution.stdoutTruncated ? "\n[stdout truncated]" : ""}\n\nstderr:\n${result.execution.stderr}${result.execution.stderrTruncated ? "\n[stderr truncated]" : ""}` : result.report;
        return { content: [{ type: "text", text }], details: { ok: result.ok, preflight: result.preflight, acceptedExitCodes: result.acceptedExitCodes, outcome: result.outcome }, isError: !result.ok };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: "text", text: `sniff_run_analyzer failed: ${message}` }], details: { ok: false, error: message, preflight: null }, isError: true };
      }
    },
  });
}
