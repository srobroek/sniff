import { createHash } from "node:crypto";
import { isAbsolute, join } from "node:path";
import { stableJson } from "./canonical-json.ts";
import type { RunManifest } from "./intake.ts";
import { canonicalReportTargetIdentity } from "./intake-use-case.ts";
import {
  buildSniffReport,
  canonicalizeTrustedTemporaryPrefix,
  createReportArtifacts,
  type PublicReportArtifacts,
  projectReportArtifacts,
  type ReportArtifacts,
  type ReportInput,
  type ReportTarget,
  saveReportArtifactsAt,
} from "./report.ts";
import { registerReportArtifacts } from "./report-artifact-registry.ts";
import { type OpenedReportDirectory, openReportDirectory } from "./report-native-persistence.ts";
import type { SniffRunOwner } from "./run-owner.ts";
import { assertRunReport, beginRunReport, endRunReport, finalizeRunLease, readRunManifest, validateReportCoverage, validateReportManifest } from "./run-registry.ts";

export type SniffReportMode = "render" | "save";
export type SaveAuthorizationRequest = {
  readonly directory: string;
  readonly parentDirectory: string;
  readonly manifestId: string;
  readonly reportId: string;
  readonly files: readonly string[];
  readonly artifactDigests: Readonly<Record<string, string>>;
  readonly manifest: RunManifest;
  readonly digest: string;
};
export type SaveAuthorizationResponse = {
  readonly acceptedDigest: string;
  readonly actor?: string;
  readonly reason?: string;
};
export type SniffReportRuntime = {
  readonly authorizeSave: (request: SaveAuthorizationRequest) => Promise<false | SaveAuthorizationResponse>;
};
export interface SniffReportToolOptions {
  capability: string;
  /** The owner that issued the capability; omitted, the process owner. */
  owner?: SniffRunOwner;
  manifestId: string;
  mode?: SniffReportMode;
  report: ReportInput;
  path?: string;
  runtime?: SniffReportRuntime;
}
export interface SniffReportToolResult {
  artifacts: ReportArtifacts;
  publicArtifacts: PublicReportArtifacts;
  savedPaths: string[];
  /** Set only when the report was saved but its parent directory could not be synced. */
  durabilityWarning?: string;
}


function authenticatedTarget(manifest: RunManifest, supplied: ReportTarget): ReportTarget {
  const identity = canonicalReportTargetIdentity(manifest.resolvedTarget, manifest.scopeMode);
  if (
    supplied.kind !== identity.kind ||
    supplied.label !== identity.label ||
    supplied.baseRef !== identity.baseRef ||
    supplied.filesAnalyzed !== identity.filesAnalyzed ||
    supplied.scopeMode !== identity.scopeMode
  ) {
    throw new Error("sniff report target kind, label, baseRef, filesAnalyzed, and scopeMode must match the authenticated manifest target");
  }
  return { ...supplied, ...identity };
}

function normalizedFindingPath(value: string): string {
  if (isAbsolute(value) || value.includes("\\") || value.split("/").some((part) => part === "..")) {
    throw new Error("sniff report finding path must be a normalized relative path");
  }
  const normalized = value.replace(/^\.\//, "");
  if (!normalized || normalized === "." || normalized.split("/").some((part) => part === "" || part === ".")) {
    throw new Error("sniff report finding path must be a normalized relative path");
  }
  return normalized;
}

function validateFindingPaths(manifest: RunManifest, report: ReportInput): void {
  const allowed = new Set(manifest.resolvedTarget.files);
  for (const finding of report.findings) {
    const path = normalizedFindingPath(finding.location.path);
    if (!allowed.has(path)) throw new Error(`sniff report finding path is outside the authenticated target: ${path}`);
  }
}

type PlannedDirectory = { readonly lexical: string; readonly canonical: string; readonly opened: OpenedReportDirectory };

function plannedDirectory(directory: string): PlannedDirectory {
  const lexical = canonicalizeTrustedTemporaryPrefix(directory);
  const opened = openReportDirectory(lexical);
  return { lexical, canonical: opened.path, opened };
}

function saveDigest(request: Omit<SaveAuthorizationRequest, "digest">): string {
  return createHash("sha256").update(stableJson(request)).digest("hex");
}

/**
 * Builds, and in save mode persists, one report for a lease. The lease ends only once artifacts
 * exist: render registered them or save wrote them. Any earlier failure (validation, output
 * directory, denied approval, failed write) keeps the lease for a corrected retry.
 */
export async function runSniffReportTool(options: SniffReportToolOptions): Promise<SniffReportToolResult> {
  const { owner } = options;
  const claim = beginRunReport(options.capability, options.manifestId, owner);
  let finalizeLease = false;
  try {
    const manifest = readRunManifest(options.capability, options.manifestId, owner);
    const suppliedExtensions = options.report.extensions;
    if (suppliedExtensions !== undefined && (suppliedExtensions === null || typeof suppliedExtensions !== "object" || Array.isArray(suppliedExtensions))) {
      throw new Error("sniff report extensions must be an object");
    }
    const suppliedManifest = suppliedExtensions?.["sniff.intake"];
    if (suppliedManifest !== undefined) validateReportManifest(options.capability, options.manifestId, suppliedManifest, owner);
    validateFindingPaths(manifest, options.report);
    validateReportCoverage(options.capability, options.manifestId, options.report.coverage, owner);
    if (options.mode === "save" && !options.path?.trim()) throw new Error("sniff_report mode=save requires path");
    const report = buildSniffReport({
      ...options.report,
      target: authenticatedTarget(manifest, options.report.target),
      extensions: { ...(suppliedExtensions ?? {}), "sniff.intake": manifest },
    });
    const artifacts = createReportArtifacts(report);
    if (options.mode !== "save") {
      const readCapability = registerReportArtifacts(artifacts, undefined, owner);
      finalizeLease = true;
      return { artifacts, publicArtifacts: projectReportArtifacts(artifacts, [], readCapability), savedPaths: [] };
    }
    if (options.runtime === undefined) throw new Error("sniff_report mode=save requires a trusted save authorization boundary");
    const planned = plannedDirectory(options.path ?? "");
    try {
      const reportDirectory = join(planned.canonical, report.reportId);
      const files = artifacts.descriptors.map((descriptor) => descriptor.relativePath);
      const artifactDigests = Object.fromEntries(artifacts.descriptors.map((descriptor) => [descriptor.relativePath, descriptor.sha256]));
      const unsigned = {
        directory: reportDirectory,
        parentDirectory: planned.canonical,
        manifestId: manifest.manifestId,
        reportId: report.reportId,
        files,
        artifactDigests,
        manifest,
      };
      const request = { ...unsigned, digest: saveDigest(unsigned) };
      const approval = await options.runtime.authorizeSave(request);
      // A cancel or expiry while approval was pending ended the run; nothing may be written for it.
      assertRunReport(options.capability, options.manifestId, claim, owner);
      if (!approval || approval.acceptedDigest !== request.digest) throw new Error("Sniff report save authorization was denied or mismatched");
      // Once published the report exists, even when it is not yet durable: the run ends and the
      // saved location is returned with the warning, since a retry would only collide with it.
      const { savedPaths, durabilityWarning } = saveReportArtifactsAt(artifacts, planned.opened);
      finalizeLease = true;
      const readCapability = registerReportArtifacts(artifacts, undefined, owner);
      const publicArtifacts = projectReportArtifacts(artifacts, savedPaths, readCapability);
      if (durabilityWarning === undefined) return { artifacts, publicArtifacts, savedPaths };
      return { artifacts, publicArtifacts: { ...publicArtifacts, durabilityWarning }, savedPaths, durabilityWarning };
    } finally {
      planned.opened.close();
    }
  } finally {
    if (finalizeLease) await finalizeRunLease(options.capability, options.manifestId, owner);
    else endRunReport(options.capability, options.manifestId, claim, owner);
  }
}
