import type { SniffInstallAuthorizationRequest } from "./install.ts";
import type { CanonicalConfirmationRequest } from "./intake.ts";
import type { SaveAuthorizationRequest } from "./report-use-case.ts";

// Approval text renders model- and provider-controlled strings (paths, labels, refs), so every
// value is escaped to one visible line: a newline or ANSI escape cannot fake or hide plan lines.
function visible(value: string): string {
  let escaped = "";
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    const control = code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029;
    escaped += !control ? character : character === "\n" ? "\\n" : character === "\t" ? "\\t" : `\\u${code.toString(16).padStart(4, "0")}`;
  }
  return escaped;
}

export type IntakeConfirmationTextOptions = {
  /** Files listed before the remainder is summarized as a count; every file is listed by default. */
  readonly maxFiles?: number;
};

/** The complete canonical intake plan a trusted host shows before it accepts the plan digest. */
export function intakeConfirmationText(request: CanonicalConfirmationRequest, options: IntakeConfirmationTextOptions = {}): string {
  const target = request.target;
  const immutableTarget = [
    `root=${target.root}`,
    `kind=${target.kind}`,
    `label=${target.label}`,
    ...(target.repository ? [`repository=${target.repository}`] : []),
    ...(target.immutableRef ? [`immutableRef=${target.immutableRef}`] : []),
    ...(target.baseRef ? [`baseRef=${target.baseRef}`] : []),
    ...(target.headRef ? [`headRef=${target.headRef}`] : []),
  ].map(visible).join(", ");
  const shown = options.maxFiles === undefined ? request.files : request.files.slice(0, options.maxFiles);
  const files = [
    ...shown.map((file) => `  - ${visible(file)}`),
    ...(shown.length < request.files.length ? [`  - … and ${request.files.length - shown.length} more`] : []),
  ].join("\n");
  const analyzers = request.analyzers.map((analyzer) => JSON.stringify(analyzer)).join("; ");
  return [
    `Trust: ${request.trust}`,
    `Immutable target/ref: ${immutableTarget}`,
    `Files (${request.files.length}):`,
    files || "  - <none>",
    `Intent: ${request.intent}`,
    `Scope mode: ${request.scopeMode}`,
    `Objectives: ${JSON.stringify(request.objectives)}`,
    `Exclusions: ${JSON.stringify(request.exclusions)}`,
    `Analyzers/dispositions: ${analyzers || "<none>"}`,
    `Coverage gaps: ${request.coverageGaps.length === 0 ? "<none>" : request.coverageGaps.map((gap) => visible(gap.reason)).join("; ")}`,
    `Budgets: ${JSON.stringify(request.budget)}`,
    `Materialization: ${request.materialization}`,
    `Plan digest: ${request.digest}`,
  ].join("\n");
}

/** The exact installation plan a trusted host shows before it runs `runSniffInstall` in install mode. */
export function installConfirmationText(request: SniffInstallAuthorizationRequest): string {
  const tools = request.tools.map((tool) => `  - ${tool.bundle}/${tool.tool}: ${tool.status}${tool.resolvedPath ? ` (${visible(tool.resolvedPath)})` : ""}`).join("\n");
  return [
    `Bundles: ${request.bundles.join(", ") || "<none>"}`,
    `All bundles: ${request.all}`,
    `Dry run: ${request.dryRun}`,
    `Sniff-owned toolkit cache: ${visible(request.toolkitCacheRoot)}`,
    `Tools (${request.tools.length}):`,
    tools || "  - <none>",
    `Install digest: ${request.digest}`,
  ].join("\n");
}

/** The exact report save a trusted host shows before it accepts the save digest. */
export function saveConfirmationText(request: SaveAuthorizationRequest): string {
  return [
    `Canonical report directory: ${visible(request.directory)}`,
    `Manifest ID: ${request.manifestId}`,
    `Report ID: ${request.reportId}`,
    `Artifacts: ${request.files.length} files with SHA-256 digests`,
    `Save digest: ${request.digest}`,
  ].join("\n");
}
