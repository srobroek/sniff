import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, parse, resolve, sep } from "node:path";
import type { RunManifest } from "./intake.ts";
import { buildSniffReport, createReportArtifacts, type ReportArtifacts, type ReportInput, type ReportTarget, saveReportArtifacts } from "./report.ts";
import { finalizeRunLease, validateReportCoverage, validateReportManifest } from "./run-registry.ts";

export type SniffReportMode = "render" | "save";
export type SaveAuthorizationRequest = { readonly directory: string; readonly manifestId: string; readonly reportId: string; readonly files: readonly string[]; readonly digest: string; readonly manifest: RunManifest };
export type SniffReportRuntime = { readonly authorizeSave: (request: SaveAuthorizationRequest) => boolean | Promise<boolean | { readonly approved: boolean; readonly acceptedDigest?: string }> };
export interface SniffReportToolOptions { capability: string; manifestId: string; mode?: SniffReportMode; report: ReportInput; path?: string; runtime?: SniffReportRuntime; }
export interface SniffReportToolResult { artifacts: ReportArtifacts; savedPaths: string[]; }
const REPORT_KIND_BY_TARGET: Record<RunManifest["resolvedTarget"]["kind"], ReportTarget["kind"]> = { "working-tree": "uncommitted", files: "files", directory: "directory", module: "area", commit: "commit", range: "range", branch: "branch", ref: "ref", repository: "repository", release: "release", history: "history", pr: "pr", mr: "mr" };
function authenticatedTarget(manifest: RunManifest, supplied: ReportTarget): ReportTarget {
  const resolved = manifest.resolvedTarget; const identity = { kind: REPORT_KIND_BY_TARGET[resolved.kind], label: resolved.label, baseRef: resolved.baseRef, filesAnalyzed: resolved.files.length, scopeMode: manifest.scopeMode };
  if (supplied.kind !== identity.kind || supplied.label !== identity.label || supplied.baseRef !== identity.baseRef || supplied.filesAnalyzed !== identity.filesAnalyzed || supplied.scopeMode !== identity.scopeMode) throw new Error("sniff_report target kind, label, baseRef, filesAnalyzed, and scopeMode must match the authenticated manifest target");
  return { ...supplied, ...identity };
}
function normalizedFindingPath(value: string): string {
  if (isAbsolute(value) || value.includes("\\") || value.split("/").some((part) => part === "..")) throw new Error("sniff report finding path must be a normalized relative path");
  const normalized = value.replace(/^\.\//, ""); if (!normalized || normalized === "." || normalized.split("/").some((part) => part === "" || part === ".")) throw new Error("sniff report finding path must be a normalized relative path"); return normalized;
}
function validateFindingPaths(manifest: RunManifest, report: ReportInput): void { const allowed = new Set(manifest.resolvedTarget.files); for (const finding of report.findings) { const path = normalizedFindingPath(finding.location.path); if (!allowed.has(path)) throw new Error(`sniff report finding path is outside the authenticated target: ${path}`); } }
function safeDirectory(directory: string): string { const requested = resolve(directory); const root = parse(requested).root; let current = root; for (const component of requested.slice(root.length).split(sep).filter(Boolean)) { current = join(current, component); if (existsSync(current) && lstatSync(current).isSymbolicLink()) throw new Error("sniff report output directory cannot traverse a symlink"); if (!existsSync(current)) mkdirSync(current); } return realpathSync(requested); }
function saveDigest(request: Omit<SaveAuthorizationRequest, "digest">): string { return createHash("sha256").update(JSON.stringify(request, (_, value) => value && typeof value === "object" && !Array.isArray(value) ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))) : value)).digest("hex"); }
export function runSniffReportTool(options: SniffReportToolOptions): SniffReportToolResult {
  try {
    const suppliedManifest = options.report.extensions["sniff.intake"]; if (suppliedManifest === undefined) throw new Error("sniff_report requires the issued sniff.intake manifest extension");
    const manifest = validateReportManifest(options.capability, options.manifestId, suppliedManifest); validateFindingPaths(manifest, options.report); validateReportCoverage(options.capability, options.manifestId, options.report.coverage);
    if (options.mode === "save" && !options.path?.trim()) throw new Error("sniff_report mode=save requires path");
    const report = buildSniffReport({ ...options.report, target: authenticatedTarget(manifest, options.report.target), extensions: { ...options.report.extensions, "sniff.intake": manifest } }); const artifacts = createReportArtifacts(report);
    if (options.mode !== "save") return { artifacts, savedPaths: [] };
    const directory = safeDirectory(options.path ?? ""); const files = [`${report.reportId}.json`, `${report.reportId}.md`, `${report.reportId}.receipt.json`]; const unsigned = { directory, manifestId: manifest.manifestId, reportId: report.reportId, files, manifest }; const request = { ...unsigned, digest: saveDigest(unsigned) };
    const approved = options.runtime ? options.runtime.authorizeSave(request) : true;
    if (approved && typeof (approved as Promise<unknown>).then === "function") return (approved as Promise<boolean | { approved: boolean; acceptedDigest?: string }>).then((result) => { const denied = result === false || (typeof result === "object" && (!result.approved || (result.acceptedDigest !== undefined && result.acceptedDigest !== request.digest))); if (denied) throw new Error("Sniff report save authorization was denied or mismatched"); return { artifacts, savedPaths: saveReportArtifacts(artifacts, directory) }; }) as unknown as SniffReportToolResult;
    return { artifacts, savedPaths: saveReportArtifacts(artifacts, directory) };
  } finally { finalizeRunLease(options.capability, options.manifestId); }
}
