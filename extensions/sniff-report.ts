import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const SNIFF_REPORT_SCHEMA_VERSION = "1.0.0" as const;

export type EvidenceTier = "observed" | "reproduced" | "corroborated" | "hypothesis";
export type Impact = "critical" | "high" | "medium" | "low";
export type Value = "high" | "medium" | "low";
export type Cost = "S" | "M" | "L";
export type AdversarialVerdict = "keep" | "downgrade" | "drop";
export type CoverageStatus = "ran" | "skipped" | "gap" | "not-applicable";

export interface ReportTarget {
  kind: "whole-repo" | "area" | "directory" | "files" | "uncommitted" | "commit" | "range" | "pr";
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
  title: string;
  location: { path: string; line: number; column?: number };
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

export interface FindingInput extends Omit<SniffFinding, "id"> {
  id?: string;
}

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

const IMPACTS: readonly Impact[] = ["critical", "high", "medium", "low"];
const EVIDENCE_TIERS: readonly EvidenceTier[] = ["observed", "reproduced", "corroborated", "hypothesis"];
const VERDICTS: readonly AdversarialVerdict[] = ["keep", "downgrade", "drop"];
const COVERAGE_STATUSES: readonly CoverageStatus[] = ["ran", "skipped", "gap", "not-applicable"];

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function requireCondition(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(`Invalid Sniff report: ${message}`);
}

function requireNonEmpty(value: string, path: string): void {
  requireCondition(typeof value === "string" && value.trim().length > 0, `${path} must be a non-empty string`);
}

function findingIdentity(finding: FindingInput): string {
  return stableJson({
    path: finding.location.path,
    line: finding.location.line,
    column: finding.location.column,
    source: finding.evidence.source,
    title: finding.title,
    smell: finding.smell?.name,
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

export function buildSniffReport(input: ReportInput): SniffReport {
  const findings = input.findings.map((finding) => ({ ...finding, id: finding.id ?? deterministicFindingId(finding) }));
  const withoutId: Omit<SniffReport, "reportId"> = {
    schemaVersion: SNIFF_REPORT_SCHEMA_VERSION,
    generatedAt: input.generatedAt,
    target: input.target,
    headline: input.headline,
    findings,
    coverage: input.coverage,
    suppressionCount: input.suppressionCount,
    systemicPatterns: input.systemicPatterns,
    extensions: input.extensions,
    census: calculateCensus(findings),
  };
  const report: SniffReport = { ...withoutId, reportId: `report-${sha256(reportIdentity(withoutId)).slice(0, 16)}` };
  validateSniffReport(report);
  return report;
}

export function validateSniffReport(report: SniffReport): void {
  requireCondition(report.schemaVersion === SNIFF_REPORT_SCHEMA_VERSION, `schemaVersion must be ${SNIFF_REPORT_SCHEMA_VERSION}`);
  requireCondition(/^report-[0-9a-f]{16}$/.test(report.reportId), "reportId must be a deterministic report id");
  requireCondition(!Number.isNaN(Date.parse(report.generatedAt)), "generatedAt must be an ISO date-time");
  requireNonEmpty(report.target.label, "target.label");
  requireCondition(Number.isInteger(report.target.filesAnalyzed) && report.target.filesAnalyzed >= 0, "target.filesAnalyzed must be a non-negative integer");
  requireNonEmpty(report.headline, "headline");
  requireCondition(Number.isInteger(report.suppressionCount) && report.suppressionCount >= 0, "suppressionCount must be a non-negative integer");

  const ids = new Set<string>();
  for (const [index, finding] of report.findings.entries()) {
    requireCondition(finding.id === deterministicFindingId(finding), `findings[${index}].id does not match its structural identity`);
    requireCondition(!ids.has(finding.id), `findings[${index}].id duplicates ${finding.id}`);
    ids.add(finding.id);
    requireNonEmpty(finding.title, `findings[${index}].title`);
    requireNonEmpty(finding.location.path, `findings[${index}].location.path`);
    requireCondition(Number.isInteger(finding.location.line) && finding.location.line > 0, `findings[${index}].location.line must be positive`);
    requireCondition(EVIDENCE_TIERS.includes(finding.evidence.tier), `findings[${index}].evidence.tier is unknown`);
    requireCondition(IMPACTS.includes(finding.impact), `findings[${index}].impact is unknown`);
    requireCondition(VERDICTS.includes(finding.adversarial.verdict), `findings[${index}].adversarial.verdict is unknown`);
    requireNonEmpty(finding.evidence.source, `findings[${index}].evidence.source`);
    requireNonEmpty(finding.evidence.detail, `findings[${index}].evidence.detail`);
    requireNonEmpty(finding.adversarial.reason, `findings[${index}].adversarial.reason`);
    requireCondition(finding.compatibility.kind === "safe" || Boolean(finding.compatibility.surface?.trim()), `findings[${index}].compatibility.surface is required for breaking changes`);
    requireCondition(Boolean(finding.smell) === Boolean(finding.refactoring), `findings[${index}] must provide both smell and refactoring mappings or neither`);
  }

  for (const [index, coverage] of report.coverage.entries()) {
    requireNonEmpty(coverage.dimension, `coverage[${index}].dimension`);
    requireNonEmpty(coverage.tool, `coverage[${index}].tool`);
    requireCondition(COVERAGE_STATUSES.includes(coverage.status), `coverage[${index}].status is unknown`);
    requireNonEmpty(coverage.notes, `coverage[${index}].notes`);
  }

  const expectedCensus = calculateCensus(report.findings);
  requireCondition(stableJson(report.census) === stableJson(expectedCensus), "census does not match findings");
  const expectedReportId = `report-${sha256(reportIdentity(report)).slice(0, 16)}`;
  requireCondition(report.reportId === expectedReportId, "reportId does not match report contents");
}

function escapeCell(value: string): string {
  return value.replaceAll("|", "\\|").replaceAll("\n", " ");
}

function impactLabel(impact: Impact): string {
  return impact === "critical" ? "critical" : impact;
}

export function renderSniffMarkdown(report: SniffReport): string {
  validateSniffReport(report);
  const retained = report.findings.filter((finding) => finding.adversarial.verdict !== "drop");
  const dropped = report.findings.filter((finding) => finding.adversarial.verdict === "drop");
  const coverageRows = report.coverage.map(
    (entry) => `| ${escapeCell(entry.dimension)} | ${escapeCell(entry.tool)} | ${entry.analysisClass} | ${entry.status} | ${escapeCell(entry.notes)} |`,
  );
  const findingRows = retained.map((finding, index) => {
    const mapping = finding.smell && finding.refactoring
      ? `[${escapeCell(finding.smell.name)}](${finding.smell.url}) → [${escapeCell(finding.refactoring.name)}](${finding.refactoring.url})`
      : "—";
    const compatibility = finding.compatibility.kind === "safe" ? "safe" : `breaking: ${escapeCell(finding.compatibility.surface ?? "")}`;
    return `| ${index + 1} | ${escapeCell(finding.title)} (${escapeCell(finding.location.path)}:${finding.location.line}) | ${mapping} | ${impactLabel(finding.impact)} | ${finding.evidence.tier} | ${finding.value} | ${finding.cost} | ${compatibility} | ${finding.applyTier} |`;
  });
  const droppedRows = dropped.map(
    (finding) => `| ${escapeCell(finding.title)} (${escapeCell(finding.location.path)}:${finding.location.line}) | DROP | ${escapeCell(finding.adversarial.reason)} |`,
  );
  const lines = [
    `# Sniff Refactoring Plan — ${report.target.label}`,
    "",
    `**Report:** \`${report.reportId}\`  ·  **Target:** ${report.target.kind}  ·  **Scope mode:** ${report.target.scopeMode}  ·  **Base ref:** ${report.target.baseRef ? `\`${report.target.baseRef}\`` : "none"}`,
    `**Languages:** ${report.target.languages.join(", ") || "none"}  ·  **Date:** ${report.generatedAt.slice(0, 10)}`,
    "",
    "## Summary",
    "",
    `- Findings retained: ${report.census.retained} of ${report.census.considered} (${report.census.dropped} dropped, ${report.census.downgraded} downgraded)` ,
    `- By impact: critical ${report.census.byImpact.critical} · high ${report.census.byImpact.high} · medium ${report.census.byImpact.medium} · low ${report.census.byImpact.low}`,
    `- Suppressions observed: ${report.suppressionCount}`,
    `- Headline: ${report.headline}`,
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
    lines.push("", "## Systemic patterns", "", ...report.systemicPatterns.map((pattern) => `- ${pattern}`));
  }
  lines.push(
    "",
    "## Dropped & downgraded",
    "",
    "| Finding | Verdict | Reason |",
    "|---|---|---|",
    ...(droppedRows.length > 0 ? droppedRows : ["| — | — | No findings were dropped. |"]),
    "",
  );
  return lines.join("\n");
}

export function createReportArtifacts(report: SniffReport): ReportArtifacts {
  validateSniffReport(report);
  const json = `${JSON.stringify(report, null, 2)}\n`;
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
  validateSniffReport(artifacts.report);
  mkdirSync(directory, { recursive: true });
  const base = artifacts.report.reportId;
  const files = [
    [join(directory, `${base}.json`), artifacts.json],
    [join(directory, `${base}.md`), artifacts.markdown],
    [join(directory, `${base}.receipt.json`), `${JSON.stringify(artifacts.receipt, null, 2)}\n`],
  ] as const;
  for (const [path, content] of files) writeFileSync(path, content, { encoding: "utf8", flag: "wx" });
  return files.map(([path]) => path);
}
