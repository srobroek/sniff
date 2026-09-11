import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, resolve, sep } from "node:path";
import { assertReportInput, assertSniffReportSchema } from "./report-schema.ts";
import { openReportDirectory, saveReportEntriesAt, type OpenedReportDirectory } from "./report-native-persistence.ts";

export const SNIFF_REPORT_SCHEMA_VERSION = "1.0.0" as const;
export const MAX_REPORT_SUMMARY_BYTES = 60_000;
export const MAX_REPORT_SUMMARY_FINDINGS = 64;
export const MAX_PUBLIC_REPORT_DESCRIPTORS = 128;
export const MAX_PUBLIC_REPORT_DESCRIPTOR_BYTES = 256 * 1024;

export type EvidenceTier = "observed" | "reproduced" | "corroborated" | "hypothesis";
export type Impact = "critical" | "high" | "medium" | "low";
export type Value = "high" | "medium" | "low";
export type Cost = "S" | "M" | "L";
export type AdversarialVerdict = "keep" | "downgrade" | "drop";
export type CoverageStatus = "ran" | "skipped" | "gap" | "not-applicable";

export interface ReportTarget {
  kind: "whole-repo" | "area" | "directory" | "files" | "uncommitted" | "commit" | "range" | "branch" | "ref" | "repository" | "pr" | "mr" | "release" | "history";
  label: string;
  scopeMode: "quick" | "full" | "plan-only";
  baseRef?: string;
  languages: string[];
  filesAnalyzed: number;
}

export interface ToolCoverage {
  dimension: string;
  tool: string;
  analysisClass: "local" | "relational" | "global" | "baseline";
  status: CoverageStatus;
  notes: string;
  config?: string;
}

export interface SniffFinding {
  id: string;
  stableKey: string;
  title: string;
  location: { path: string; line: number; column?: number; anchor: string };
  evidence: { tier: EvidenceTier; source: string; detail: string };
  impact: Impact;
  value: Value;
  cost: Cost;
  compatibility: { kind: "safe" | "breaking"; surface?: string };
  applyTier: "mechanical" | "assisted" | "manual";
  smell?: { name: string; url: string };
  refactoring?: { name: string; url: string };
  adversarial: { verdict: AdversarialVerdict; reason: string };
}

export interface SniffReport {
  schemaVersion: typeof SNIFF_REPORT_SCHEMA_VERSION;
  reportId: string;
  generatedAt: string;
  target: ReportTarget;
  headline: string;
  findings: SniffFinding[];
  coverage: ToolCoverage[];
  suppressionCount: number;
  systemicPatterns: string[];
  extensions: Record<string, unknown>;
  census: {
    considered: number;
    retained: number;
    dropped: number;
    downgraded: number;
    byImpact: Record<Impact, number>;
  };
}

export type FindingInput = Omit<SniffFinding, "id">;

export interface ReportInput extends Omit<SniffReport, "schemaVersion" | "reportId" | "findings" | "census" | "extensions"> {
  findings: FindingInput[];
  extensions?: SniffReport["extensions"];
}

export interface ValidationReceipt {
  schemaVersion: typeof SNIFF_REPORT_SCHEMA_VERSION;
  reportId: string;
  reportSha256: string;
  markdownSha256: string;
  findingCount: number;
  artifactCount: number;
}

export type ReportArtifactKind = "index" | "summary" | "manifest" | "coverage" | "receipt" | "file";

export interface ReportArtifactDescriptor {
  kind: ReportArtifactKind;
  relativePath: string;
  sha256: string;
  bytes: number;
  sourcePath?: string;
  findingCount?: number;
  savedPath?: string;
}

export interface ReportFileArtifact {
  relativePath: string;
  sourcePath: string;
  findings: SniffFinding[];
  json: string;
  sha256: string;
  bytes: number;
}

export interface ReportArtifactIndex {
  schemaVersion: typeof SNIFF_REPORT_SCHEMA_VERSION;
  reportId: string;
  generatedAt: string;
  target: Pick<ReportTarget, "kind" | "label" | "scopeMode" | "filesAnalyzed">;
  headline: string;
  census: SniffReport["census"];
  references: {
    summary: string;
    manifest: string;
    coverage: string;
    receipt: string;
  };
  files: readonly Pick<ReportArtifactDescriptor, "sourcePath" | "relativePath" | "sha256" | "bytes" | "findingCount">[];
  artifacts: readonly Pick<ReportArtifactDescriptor, "kind" | "relativePath" | "sha256" | "bytes">[];
}

/** Internal, complete artifacts. Adapters must use projectReportArtifacts before returning a result. */
export interface ReportArtifacts {
  report: SniffReport;
  json: string;
  /** Bounded Markdown summary returned directly to callers. */
  markdown: string;
  /** Complete Markdown artifact retained for paged reads and explicit saves. */
  fullMarkdown: string;
  receipt: ValidationReceipt;
  index: ReportArtifactIndex;
  indexJson: string;
  manifestJson: string;
  coverageJson: string;
  fileArtifacts: readonly ReportFileArtifact[];
  descriptors: readonly ReportArtifactDescriptor[];
}

export interface PublicReportArtifacts {
  reportId: string;
  /** Opaque capability for reading complete artifacts in bounded pages. */
  readCapability: string;
  summary: string;
  descriptors: readonly ReportArtifactDescriptor[];
  descriptorCount: number;
  descriptorsTruncated: boolean;
  receipt: Pick<ValidationReceipt, "schemaVersion" | "reportId" | "findingCount" | "artifactCount">;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, entry]) => entry !== undefined)
        .sort(([left], [right]) => compareText(left, right))
        .map(([key, entry]) => [key, canonicalValue(entry)]),
    );
  }
  return value;
}

function stableJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

function canonicalJson(value: unknown): string {
  return `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function requireCondition(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(`Invalid Sniff report: ${message}`);
}

function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

function findingIdentity(finding: FindingInput): string {
  return stableJson({
    stableKey: finding.stableKey,
    path: normalizePath(finding.location.path),
    anchor: finding.location.anchor,
  });
}

export function deterministicFindingId(finding: FindingInput): string {
  return `sniff-${sha256(findingIdentity(finding)).slice(0, 16)}`;
}

function calculateCensus(findings: readonly SniffFinding[]): SniffReport["census"] {
  const retained = findings.filter((finding) => finding.adversarial.verdict !== "drop");
  return {
    considered: findings.length,
    retained: retained.length,
    dropped: findings.length - retained.length,
    downgraded: findings.filter((finding) => finding.adversarial.verdict === "downgrade").length,
    byImpact: {
      critical: retained.filter((finding) => finding.impact === "critical").length,
      high: retained.filter((finding) => finding.impact === "high").length,
      medium: retained.filter((finding) => finding.impact === "medium").length,
      low: retained.filter((finding) => finding.impact === "low").length,
    },
  };
}

function reportIdentity(report: Omit<SniffReport, "reportId">): string {
  return stableJson({
    schemaVersion: report.schemaVersion,
    target: report.target,
    headline: report.headline,
    findings: report.findings,
    coverage: report.coverage,
    suppressionCount: report.suppressionCount,
    systemicPatterns: report.systemicPatterns,
    extensions: report.extensions,
  });
}

export function buildSniffReport(value: unknown): SniffReport {
  assertReportInput(value);
  const input = value;
  const findings = input.findings
    .map((finding) => ({ ...finding, location: { ...finding.location, path: normalizePath(finding.location.path) }, id: deterministicFindingId(finding) }))
    .sort((left, right) => compareText(left.id, right.id));
  const coverage = [...input.coverage].sort((left, right) => {
    const keyOrder = compareText(`${left.dimension}\0${left.tool}\0${left.analysisClass}`, `${right.dimension}\0${right.tool}\0${right.analysisClass}`);
    return keyOrder === 0 ? compareText(stableJson(left), stableJson(right)) : keyOrder;
  });
  const withoutId: Omit<SniffReport, "reportId"> = {
    schemaVersion: SNIFF_REPORT_SCHEMA_VERSION,
    generatedAt: input.generatedAt,
    target: { ...input.target, languages: [...input.target.languages].sort(compareText) },
    headline: input.headline,
    findings,
    coverage,
    suppressionCount: input.suppressionCount,
    systemicPatterns: [...input.systemicPatterns].sort(compareText),
    extensions: input.extensions ?? {},
    census: calculateCensus(findings),
  };
  const report: SniffReport = { ...withoutId, reportId: `report-${sha256(reportIdentity(withoutId)).slice(0, 16)}` };
  validateSniffReport(report);
  return report;
}

export function validateSniffReport(value: unknown): asserts value is SniffReport {
  assertSniffReportSchema(value);
  const report = value;
  requireCondition(!Number.isNaN(Date.parse(report.generatedAt)), "generatedAt must be a real date-time");
  const ids = new Set<string>();
  for (const [index, finding] of report.findings.entries()) {
    requireCondition(finding.id === deterministicFindingId(finding), `findings[${index}].id does not match its structural identity`);
    requireCondition(!ids.has(finding.id), `findings[${index}].id duplicates ${finding.id}`);
    ids.add(finding.id);
  }
  const expectedCensus = calculateCensus(report.findings);
  requireCondition(stableJson(report.census) === stableJson(expectedCensus), "census does not match findings");
  const expectedReportId = `report-${sha256(reportIdentity(report)).slice(0, 16)}`;
  requireCondition(report.reportId === expectedReportId, "reportId does not match report contents");
}

const VALUE_RANK: Record<Value, number> = { high: 3, medium: 2, low: 1 };
const COST_WEIGHT: Record<Cost, number> = { S: 1, M: 2, L: 3 };

function escapeMarkdown(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replace(/\r\n?|[\n\u2028\u2029]/g, " ")
    .replace(/[<>`*_\[\]#]/g, "\\$&")
    .replaceAll("|", "\\|");
}

function comparePriority(left: SniffFinding, right: SniffFinding): number {
  const leftRatio = VALUE_RANK[left.value] * COST_WEIGHT[right.cost];
  const rightRatio = VALUE_RANK[right.value] * COST_WEIGHT[left.cost];
  return leftRatio === rightRatio ? compareText(left.id, right.id) : rightRatio - leftRatio;
}

function boundedUtf8(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value);
  if (bytes.byteLength <= maxBytes) return value;
  const suffix = Buffer.from("\n[truncated]");
  if (maxBytes <= suffix.byteLength) return suffix.subarray(0, Math.max(0, maxBytes)).toString("utf8");
  let prefixEnd = maxBytes - suffix.byteLength;
  while (prefixEnd > 0 && isContinuationByte(bytes[prefixEnd] ?? 0)) prefixEnd -= 1;
  return `${bytes.subarray(0, prefixEnd).toString("utf8")}${suffix.toString("utf8")}`;
}

function isContinuationByte(value: number): boolean {
  return (value & 0xc0) === 0x80;
}
function boundedInline(value: string, maxCharacters = 160): string {
  return value.length <= maxCharacters ? value : `${value.slice(0, maxCharacters - 3)}...`;
}


function safeBasename(sourcePath: string): string {
  const candidate = basename(sourcePath).replace(/[^A-Za-z0-9._-]/g, "-").replace(/^\.+/, "").slice(0, 96);
  return candidate || "source";
}

export function reportFileRelativePath(sourcePath: string): string {
  const normalized = normalizePath(sourcePath);
  return `files/${sha256(normalized).slice(0, 12)}-${safeBasename(normalized)}.json`;
}

function fileArtifactNameMap(report: SniffReport): Map<string, string> {
  const paths = [...new Set(report.findings.map((finding) => normalizePath(finding.location.path)))].sort(compareText);
  const map = new Map<string, string>();
  const names = new Set<string>();
  for (const path of paths) {
    const relativePath = reportFileRelativePath(path);
    requireCondition(!names.has(relativePath), `file artifact name collides for ${path}`);
    names.add(relativePath);
    map.set(path, relativePath);
  }
  return map;
}

function renderMarkdown(report: SniffReport, bounded: boolean): string {
  validateSniffReport(report);
  const files = fileArtifactNameMap(report);
  const allRetained = report.findings.filter((finding) => finding.adversarial.verdict !== "drop").sort(comparePriority);
  const retained = bounded ? allRetained.slice(0, MAX_REPORT_SUMMARY_FINDINGS) : allRetained;
  const allChallenged = report.findings.filter((finding) => finding.adversarial.verdict !== "keep").sort(comparePriority);
  const challenged = bounded ? allChallenged.slice(0, MAX_REPORT_SUMMARY_FINDINGS) : allChallenged;
  const coverageRows = report.coverage.map(
    (entry) => `| ${escapeMarkdown(entry.dimension)} | ${escapeMarkdown(entry.tool)} | ${entry.analysisClass} | ${entry.status} | ${escapeMarkdown(entry.notes)} |`,
  );
  const findingRows = retained.map((finding, index) => {
    const mapping = finding.smell && finding.refactoring
      ? `[${escapeMarkdown(finding.smell.name)}](${finding.smell.url}) → [${escapeMarkdown(finding.refactoring.name)}](${finding.refactoring.url})`
      : "—";
    const compatibility = finding.compatibility.kind === "safe" ? "safe" : `breaking: ${escapeMarkdown(finding.compatibility.surface ?? "")}`;
    const file = files.get(finding.location.path) ?? reportFileRelativePath(finding.location.path);
    const findingLabel = `[${escapeMarkdown(finding.title)}](${file})`;
    return `| ${index + 1} | ${findingLabel} (${escapeMarkdown(finding.location.path)}:${finding.location.line}) | ${mapping} | ${finding.impact} | ${finding.evidence.tier} | ${finding.value} | ${finding.cost} | ${compatibility} | ${finding.applyTier} |`;
  });
  const challengedRows = challenged.map(
    (finding) => `| ${escapeMarkdown(finding.title)} (${escapeMarkdown(finding.location.path)}:${finding.location.line}) | ${finding.adversarial.verdict.toUpperCase()} | ${escapeMarkdown(finding.adversarial.reason)} |`,
  );
  const lines = [
    `# Sniff Refactoring Plan — ${bounded ? escapeMarkdown(boundedInline(report.target.label)) : escapeMarkdown(report.target.label)}`,
    "",
    `**Report:** \`${report.reportId}\`  ·  **Target:** ${report.target.kind}  ·  **Scope mode:** ${report.target.scopeMode}  ·  **Base ref:** ${report.target.baseRef ? escapeMarkdown(report.target.baseRef) : "none"}`,
    `**Languages:** ${report.target.languages.map(escapeMarkdown).join(", ") || "none"}  ·  **Date:** ${report.generatedAt.slice(0, 10)}`,
    "",
    "## Summary",
    "",
    `- Findings retained: ${report.census.retained} of ${report.census.considered} (${report.census.dropped} dropped, ${report.census.downgraded} downgraded)`,
    `- By impact: critical ${report.census.byImpact.critical} · high ${report.census.byImpact.high} · medium ${report.census.byImpact.medium} · low ${report.census.byImpact.low}`,
    `- Suppressions observed: ${report.suppressionCount}`,
    `- Headline: ${escapeMarkdown(report.headline)}`,
    ...(bounded && allRetained.length > retained.length ? [`- Showing ${retained.length} highest-priority findings; ${allRetained.length - retained.length} more findings are available in the per-file artifacts.`] : []),
    "",
    "## Tool coverage",
    "",
    "| Dimension | Tool | Class | Status | Notes |",
    "|---|---|---|---|---|",
    ...(coverageRows.length > 0 ? coverageRows : ["| — | — | — | not-applicable | No analyzer coverage was planned. |"]),
    "",
    "## Prioritized refactoring plan",
    "",
    "| # | Finding | Smell → refactoring | Impact | Evidence | Value | Cost | Back-compat | Apply tier |",
    "|---|---|---|---|---|---|---|---|---|",
    ...(findingRows.length > 0 ? findingRows : ["| — | No findings survived adversarial review. | — | — | — | — | — | — | — |"]),
  ];
  if (report.systemicPatterns.length > 0) {
    const patterns = bounded ? report.systemicPatterns.slice(0, 32) : report.systemicPatterns;
    lines.push("", "## Systemic patterns", "", ...patterns.map((pattern) => `- ${escapeMarkdown(pattern)}`));
  }
  lines.push(
    "",
    "## Dropped & downgraded",
    "",
    "| Finding | Verdict | Reason |",
    "|---|---|---|",
    ...(challengedRows.length > 0 ? challengedRows : ["| — | — | No findings were dropped or downgraded. |"]),
    "",
  );
  if (files.size > 0) {
    const listedFiles = bounded ? [...files.entries()].slice(0, MAX_REPORT_SUMMARY_FINDINGS) : [...files.entries()];
    lines.push("## Source files", "", ...listedFiles.map(([path, relativePath]) => `- [${escapeMarkdown(path)}](${relativePath})`));
    if (bounded && files.size > MAX_REPORT_SUMMARY_FINDINGS) lines.push(`- ${files.size - MAX_REPORT_SUMMARY_FINDINGS} additional source files are listed in index.json.`);
    lines.push("");
  }
  const markdown = lines.join("\n");
  return bounded ? boundedUtf8(markdown, MAX_REPORT_SUMMARY_BYTES) : `${markdown}\n`;
}

export function renderSniffMarkdown(report: SniffReport): string {
  return renderMarkdown(report, true);
}

export function renderCompleteSniffMarkdown(report: SniffReport): string {
  return renderMarkdown(report, false);
}

function manifestFromReport(report: SniffReport): unknown {
  const manifest = report.extensions["sniff.intake"];
  return manifest === undefined ? {} : manifest;
}

function createFileArtifacts(report: SniffReport): ReportFileArtifact[] {
  const grouped = new Map<string, SniffFinding[]>();
  for (const finding of report.findings) {
    const path = normalizePath(finding.location.path);
    const group = grouped.get(path);
    if (group) group.push(finding);
    else grouped.set(path, [finding]);
  }
  const names = new Set<string>();
  return [...grouped.entries()].sort(([left], [right]) => compareText(left, right)).map(([sourcePath, findings]) => {
    const relativePath = reportFileRelativePath(sourcePath);
    requireCondition(!names.has(relativePath), `file artifact name collides for ${sourcePath}`);
    names.add(relativePath);
    const ordered = [...findings].sort((left, right) => compareText(left.id, right.id));
    const json = canonicalJson({ path: sourcePath, findings: ordered });
    return { relativePath, sourcePath, findings: ordered, json, sha256: sha256(json), bytes: Buffer.byteLength(json) };
  });
}

export function createReportArtifacts(report: SniffReport): ReportArtifacts {
  validateSniffReport(report);
  const json = canonicalJson(report);
  const markdown = renderSniffMarkdown(report);
  const fullMarkdown = renderCompleteSniffMarkdown(report);
  const manifestJson = canonicalJson(manifestFromReport(report));
  const coverageJson = canonicalJson(report.coverage);
  const fileArtifacts = createFileArtifacts(report);
  const nonIndex: ReportArtifactDescriptor[] = [
    { kind: "summary", relativePath: "summary.md", sha256: sha256(fullMarkdown), bytes: Buffer.byteLength(fullMarkdown) },
    { kind: "manifest", relativePath: "manifest.json", sha256: sha256(manifestJson), bytes: Buffer.byteLength(manifestJson) },
    { kind: "coverage", relativePath: "coverage.json", sha256: sha256(coverageJson), bytes: Buffer.byteLength(coverageJson) },
    ...fileArtifacts.map((file) => ({ kind: "file" as const, relativePath: file.relativePath, sourcePath: file.sourcePath, findingCount: file.findings.length, sha256: file.sha256, bytes: file.bytes })),
  ];
  const artifactCount = nonIndex.length + 2;
  const receipt: ValidationReceipt = {
    schemaVersion: SNIFF_REPORT_SCHEMA_VERSION,
    reportId: report.reportId,
    reportSha256: sha256(json),
    markdownSha256: sha256(fullMarkdown),
    findingCount: report.findings.length,
    artifactCount,
  };
  const receiptJson = canonicalJson(receipt);
  const receiptDescriptor: ReportArtifactDescriptor = { kind: "receipt", relativePath: "receipt.json", sha256: sha256(receiptJson), bytes: Buffer.byteLength(receiptJson) };
  const descriptorsWithoutIndex = [...nonIndex, receiptDescriptor].sort((left, right) => compareText(left.relativePath, right.relativePath));
  const index: ReportArtifactIndex = {
    schemaVersion: SNIFF_REPORT_SCHEMA_VERSION,
    reportId: report.reportId,
    generatedAt: report.generatedAt,
    target: { kind: report.target.kind, label: report.target.label, scopeMode: report.target.scopeMode, filesAnalyzed: report.target.filesAnalyzed },
    headline: report.headline,
    census: report.census,
    references: { summary: "summary.md", manifest: "manifest.json", coverage: "coverage.json", receipt: "receipt.json" },
    files: fileArtifacts.map(({ sourcePath, relativePath, sha256: fileSha256, bytes, findings }) => ({ sourcePath, relativePath, sha256: fileSha256, bytes, findingCount: findings.length })),
    artifacts: descriptorsWithoutIndex.map(({ kind, relativePath, sha256: artifactSha256, bytes }) => ({ kind, relativePath, sha256: artifactSha256, bytes })),
  };
  const indexJson = canonicalJson(index);
  const indexDescriptor: ReportArtifactDescriptor = { kind: "index", relativePath: "index.json", sha256: sha256(indexJson), bytes: Buffer.byteLength(indexJson) };
  return { report, json, markdown, fullMarkdown, receipt, index, indexJson, manifestJson, coverageJson, fileArtifacts, descriptors: [indexDescriptor, ...descriptorsWithoutIndex] };
}

export function projectReportArtifacts(artifacts: ReportArtifacts, savedPaths: readonly string[] = [], readCapability = ""): PublicReportArtifacts {
  const savedByRelativePath = new Map<string, string>();
  const normalizedSavedPaths = savedPaths.map((path) => ({ path, normalized: path.replaceAll("\\", "/") }));
  const indexSuffix = `/${artifacts.report.reportId}/index.json`;
  const indexPath = normalizedSavedPaths.find(({ normalized }) => normalized.endsWith(indexSuffix));
  const reportRoot = indexPath?.normalized.slice(0, -"/index.json".length);
  if (reportRoot) {
    for (const { path, normalized } of normalizedSavedPaths) {
      const prefix = `${reportRoot}/`;
      if (normalized.startsWith(prefix)) savedByRelativePath.set(normalized.slice(prefix.length), path);
    }
  }
  const descriptors: ReportArtifactDescriptor[] = [];
  for (const descriptor of artifacts.descriptors.slice(0, MAX_PUBLIC_REPORT_DESCRIPTORS)) {
    const { sourcePath: _sourcePath, ...withoutSourcePath } = descriptor;
    const savedPath = savedByRelativePath.get(descriptor.relativePath);
    const withSavedPath = savedPath === undefined ? withoutSourcePath : { ...withoutSourcePath, savedPath };
    const candidate = Buffer.byteLength(JSON.stringify([...descriptors, withSavedPath])) <= MAX_PUBLIC_REPORT_DESCRIPTOR_BYTES
      ? withSavedPath
      : withoutSourcePath;
    if (Buffer.byteLength(JSON.stringify([...descriptors, candidate])) > MAX_PUBLIC_REPORT_DESCRIPTOR_BYTES) break;
    descriptors.push(candidate);
  }
  return {
    reportId: artifacts.report.reportId,
    readCapability,
    summary: artifacts.markdown,
    descriptors,
    descriptorCount: artifacts.descriptors.length,
    descriptorsTruncated: artifacts.descriptors.length > descriptors.length,
    receipt: { schemaVersion: artifacts.receipt.schemaVersion, reportId: artifacts.receipt.reportId, findingCount: artifacts.receipt.findingCount, artifactCount: artifacts.receipt.artifactCount },
  };
}



export function canonicalizeTrustedTemporaryPrefix(directory: string): string {
  const lexical = resolve(directory);
  const temporary = resolve(tmpdir());
  if (lexical !== temporary && !lexical.startsWith(`${temporary}${sep}`)) return lexical;
  return resolve(realpathSync(temporary), lexical.slice(temporary.length + (lexical === temporary ? 0 : 1)));
}


function saveEntries(artifacts: ReportArtifacts): readonly (readonly [string, string])[] {
  return [
    ["index.json", artifacts.indexJson],
    ["summary.md", artifacts.fullMarkdown],
    ["manifest.json", artifacts.manifestJson],
    ["coverage.json", artifacts.coverageJson],
    ["receipt.json", canonicalJson(artifacts.receipt)],
    ...artifacts.fileArtifacts.map((file) => [file.relativePath, file.json] as const),
  ];
}

function assertArtifactIntegrity(artifacts: ReportArtifacts): ReportArtifacts {
  const canonical = createReportArtifacts(artifacts.report);
  requireCondition(artifacts.json === canonical.json, "JSON artifact does not match report");
  requireCondition(artifacts.markdown === canonical.markdown, "Markdown summary does not match report");
  requireCondition(artifacts.fullMarkdown === canonical.fullMarkdown, "Markdown artifact does not match report");
  requireCondition(stableJson(artifacts.receipt) === stableJson(canonical.receipt), "receipt does not match report artifacts");
  requireCondition(artifacts.indexJson === canonical.indexJson, "index artifact does not match report");
  requireCondition(artifacts.manifestJson === canonical.manifestJson, "manifest artifact does not match report");
  requireCondition(artifacts.coverageJson === canonical.coverageJson, "coverage artifact does not match report");
  requireCondition(stableJson(artifacts.fileArtifacts) === stableJson(canonical.fileArtifacts), "file artifacts do not match report");
  return canonical;
}

export function saveReportArtifactsAt(artifacts: ReportArtifacts, directory: OpenedReportDirectory): string[] {
  const canonical = assertArtifactIntegrity(artifacts);
  const entries = saveEntries(canonical);
  return saveReportEntriesAt(directory, canonical.report.reportId, entries);
}

export function saveReportArtifacts(artifacts: ReportArtifacts, directory: string): string[] {
  const opened = openReportDirectory(canonicalizeTrustedTemporaryPrefix(directory));
  try {
    return saveReportArtifactsAt(artifacts, opened);
  } finally {
    opened.close();
  }
}
