import { createHash } from "node:crypto";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { assertReportInput, assertSniffReportSchema } from "./sniff-report-schema.ts";

export const SNIFF_REPORT_SCHEMA_VERSION = "1.0.0" as const;

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

export interface ReportInput extends Omit<SniffReport, "schemaVersion" | "reportId" | "findings" | "census"> {
  findings: FindingInput[];
}

export interface ValidationReceipt {
  schemaVersion: typeof SNIFF_REPORT_SCHEMA_VERSION;
  reportId: string;
  reportSha256: string;
  markdownSha256: string;
  findingCount: number;
}

export interface ReportArtifacts {
  report: SniffReport;
  json: string;
  markdown: string;
  receipt: ValidationReceipt;
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
    extensions: input.extensions,
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
    .replace(/[<>`*_[\]#]/g, "\\$&")
    .replaceAll("|", "\\|");
}

function comparePriority(left: SniffFinding, right: SniffFinding): number {
  const leftRatio = VALUE_RANK[left.value] * COST_WEIGHT[right.cost];
  const rightRatio = VALUE_RANK[right.value] * COST_WEIGHT[left.cost];
  return leftRatio === rightRatio ? compareText(left.id, right.id) : rightRatio - leftRatio;
}

export function renderSniffMarkdown(report: SniffReport): string {
  validateSniffReport(report);
  const retained = report.findings
    .filter((finding) => finding.adversarial.verdict !== "drop")
    .sort(comparePriority);
  const challenged = report.findings.filter((finding) => finding.adversarial.verdict !== "keep");
  const coverageRows = report.coverage.map(
    (entry) => `| ${escapeMarkdown(entry.dimension)} | ${escapeMarkdown(entry.tool)} | ${entry.analysisClass} | ${entry.status} | ${escapeMarkdown(entry.notes)} |`,
  );
  const findingRows = retained.map((finding, index) => {
    const mapping = finding.smell && finding.refactoring
      ? `[${escapeMarkdown(finding.smell.name)}](${finding.smell.url}) → [${escapeMarkdown(finding.refactoring.name)}](${finding.refactoring.url})`
      : "—";
    const compatibility = finding.compatibility.kind === "safe" ? "safe" : `breaking: ${escapeMarkdown(finding.compatibility.surface ?? "")}`;
    return `| ${index + 1} | ${escapeMarkdown(finding.title)} (${escapeMarkdown(finding.location.path)}:${finding.location.line}) | ${mapping} | ${finding.impact} | ${finding.evidence.tier} | ${finding.value} | ${finding.cost} | ${compatibility} | ${finding.applyTier} |`;
  });
  const challengedRows = challenged.map(
    (finding) => `| ${escapeMarkdown(finding.title)} (${escapeMarkdown(finding.location.path)}:${finding.location.line}) | ${finding.adversarial.verdict.toUpperCase()} | ${escapeMarkdown(finding.adversarial.reason)} |`,
  );
  const lines = [
    `# Sniff Refactoring Plan — ${escapeMarkdown(report.target.label)}`,
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
    lines.push("", "## Systemic patterns", "", ...report.systemicPatterns.map((pattern) => `- ${escapeMarkdown(pattern)}`));
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
  return lines.join("\n");
}

export function createReportArtifacts(report: SniffReport): ReportArtifacts {
  validateSniffReport(report);
  const json = canonicalJson(report);
  const markdown = renderSniffMarkdown(report);
  return {
    report,
    json,
    markdown,
    receipt: {
      schemaVersion: SNIFF_REPORT_SCHEMA_VERSION,
      reportId: report.reportId,
      reportSha256: sha256(json),
      markdownSha256: sha256(markdown),
      findingCount: report.findings.length,
    },
  };
}

export function saveReportArtifacts(artifacts: ReportArtifacts, directory: string): string[] {
  const canonical = createReportArtifacts(artifacts.report);
  requireCondition(artifacts.json === canonical.json, "JSON artifact does not match report");
  requireCondition(artifacts.markdown === canonical.markdown, "Markdown artifact does not match report");
  requireCondition(stableJson(artifacts.receipt) === stableJson(canonical.receipt), "receipt does not match report artifacts");
  mkdirSync(directory, { recursive: true });
  const base = canonical.report.reportId;
  const files = [
    [join(directory, `${base}.json`), canonical.json],
    [join(directory, `${base}.md`), canonical.markdown],
    [join(directory, `${base}.receipt.json`), canonicalJson(canonical.receipt)],
  ] as const;
  const collision = files.find(([path]) => existsSync(path));
  if (collision) throw new Error(`Sniff report artifact already exists: ${collision[0]}`);

  const written: string[] = [];
  try {
    for (const [path, content] of files) {
      writeFileSync(path, content, { encoding: "utf8", flag: "wx" });
      written.push(path);
    }
    return written;
  } catch (error) {
    for (const path of written) rmSync(path, { force: true });
    throw error;
  }
}
