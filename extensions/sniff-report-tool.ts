import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import {
  buildSniffReport,
  createReportArtifacts,
  type ReportArtifacts,
  type ReportInput,
  saveReportArtifacts,
} from "./sniff-report.ts";

export type SniffReportMode = "render" | "save";

export interface SniffReportToolOptions {
  mode?: SniffReportMode;
  report: ReportInput;
  path?: string;
}

export interface SniffReportToolResult {
  artifacts: ReportArtifacts;
  savedPaths: string[];
}
interface SniffReportToolDetails {
  ok: boolean;
  report?: ReportArtifacts["report"];
  receipt?: ReportArtifacts["receipt"];
  savedPaths: string[];
  error?: string;
}


export function runSniffReportTool(options: SniffReportToolOptions): SniffReportToolResult {
  const report = buildSniffReport(options.report);
  const artifacts = createReportArtifacts(report);
  if (options.mode === "save" && !options.path?.trim()) {
    throw new Error("sniff_report mode=save requires path");
  }
  return {
    artifacts,
    savedPaths: options.mode === "save" ? saveReportArtifacts(artifacts, options.path ?? "") : [],
  };
}

export default function sniffReportTool(pi: ExtensionAPI): void {
  const z = pi.zod;
  pi.registerTool<TSchema, SniffReportToolDetails>({
    name: "sniff_report",
    label: "Sniff structured report",
    description:
      "Build a validated canonical Sniff JSON report and deterministic Markdown. Default render mode is ephemeral. Save mode requires an explicit output path and writes JSON, Markdown, and a validation receipt.",
    parameters: z.object({
      mode: z.enum(["render", "save"]).optional().describe("render (default) or explicit save"),
      report: z.unknown().describe("Report input conforming to skills/sniff/references/report.schema.json, without generated ids or census"),
      path: z.string().optional().describe("Output directory required only for save mode"),
    }) as unknown as TSchema,
    execute: async (_id, params: SniffReportToolOptions) => {
      try {
        const result = runSniffReportTool(params);
        return {
          content: [{ type: "text", text: result.artifacts.markdown }],
          details: {
            ok: true,
            report: result.artifacts.report,
            receipt: result.artifacts.receipt,
            savedPaths: result.savedPaths,
          },
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: "text", text: `sniff_report failed: ${message}` }],
          details: { ok: false, error: message, savedPaths: [] },
          isError: true,
        };
      }
    },
  });
}
