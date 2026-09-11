import type { RunManifest } from "./intake.ts";
import {
  buildSniffReport,
  createReportArtifacts,
  type ReportArtifacts,
  type ReportInput,
  type ReportTarget,
  saveReportArtifacts,
} from "./report.ts";
import { finalizeRunLease, validateReportManifest } from "./run-registry.ts";

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

