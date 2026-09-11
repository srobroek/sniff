import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import type { RunManifest } from "./sniff-intake.ts";
import {
  buildSniffReport,
  createReportArtifacts,
  type ReportArtifacts,
  type ReportInput,
  type ReportTarget,
  saveReportArtifacts,
} from "./sniff-report.ts";
import { finalizeRunLease, validateReportManifest } from "./sniff-run-registry.ts";

export type SniffReportMode = "render" | "save";

export interface SniffReportToolOptions {
  capability: string;
  manifestId: string;
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


const REPORT_KIND_BY_TARGET: Record<RunManifest["resolvedTarget"]["kind"], ReportTarget["kind"]> = {
  "working-tree": "uncommitted",
  files: "files",
  directory: "directory",
  module: "area",
  commit: "commit",
  range: "range",
  branch: "branch",
  ref: "ref",
  repository: "repository",
  release: "release",
  history: "history",
  pr: "pr",
  mr: "mr",
};

function authenticatedTarget(manifest: RunManifest, supplied: ReportTarget): ReportTarget {
  const resolved = manifest.resolvedTarget;
  const identity = {
    kind: REPORT_KIND_BY_TARGET[resolved.kind],
    label: resolved.label,
    baseRef: resolved.baseRef,
    filesAnalyzed: resolved.files.length,
  };
  if (supplied.kind !== identity.kind || supplied.label !== identity.label || supplied.baseRef !== identity.baseRef || supplied.filesAnalyzed !== identity.filesAnalyzed) {
    throw new Error("sniff_report target kind, label, baseRef, and filesAnalyzed must match the authenticated manifest target");
  }
  return { ...supplied, ...identity };
}

export function runSniffReportTool(options: SniffReportToolOptions): SniffReportToolResult {
  try {
    const suppliedManifest = options.report.extensions["sniff.intake"];
    if (suppliedManifest === undefined) throw new Error("sniff_report requires the issued sniff.intake manifest extension");
    const manifest = validateReportManifest(options.capability, options.manifestId, suppliedManifest);
    if (options.mode === "save" && !options.path?.trim()) throw new Error("sniff_report mode=save requires path");
    const report = buildSniffReport({
      ...options.report,
      target: authenticatedTarget(manifest, options.report.target),
      extensions: { ...options.report.extensions, "sniff.intake": manifest },
    });
    const artifacts = createReportArtifacts(report);
    return {
      artifacts,
      savedPaths: options.mode === "save" ? saveReportArtifacts(artifacts, options.path ?? "") : [],
    };
  } finally {
    finalizeRunLease(options.capability, options.manifestId);
  }
}

export default function sniffReportTool(pi: ExtensionAPI): void {
  const z = pi.zod;
  pi.registerTool<TSchema, SniffReportToolDetails>({
    name: "sniff_report",
    label: "Sniff structured report",
    description:
      "Build a canonical Sniff report only for a live sniff_intake capability, validate the serialized issued manifest, and release its materialization after terminal success or failure.",
    parameters: z.object({
      capability: z.string().describe("Opaque capability returned by sniff_intake"),
      manifestId: z.string().describe("Manifest ID returned by sniff_intake"),
      mode: z.enum(["render", "save"]).optional().describe("render (default) or explicit save"),
      report: z.unknown().describe("Report input including the exact issued sniff.intake manifest extension"),
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
