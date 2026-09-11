import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildSniffReport,
  createReportArtifacts,
  deterministicFindingId,
  type FindingInput,
  type ReportInput,
  renderSniffMarkdown,
  saveReportArtifacts,
  validateSniffReport,
} from "./sniff-report.ts";
import { runSniffReportTool } from "./sniff-report-tool.ts";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function finding(overrides: Partial<FindingInput> = {}): FindingInput {
  return {
    title: "Parser mixes transport and validation",
    location: { path: "src/parser.ts", line: 42 },
    evidence: { tier: "observed", source: "bloodhound", detail: "The function has 87 lines and three responsibilities." },
    impact: "medium",
    value: "high",
    cost: "M",
    compatibility: { kind: "safe" },
    applyTier: "assisted",
    smell: { name: "Long Method", url: "https://refactoring.guru/smells/long-method" },
    refactoring: { name: "Extract Method", url: "https://refactoring.guru/extract-method" },
    adversarial: { verdict: "keep", reason: "The split follows existing module boundaries." },
    ...overrides,
  };
}

function reportInput(findings: FindingInput[] = [finding()]): ReportInput {
  return {
    generatedAt: "2026-09-11T08:00:00.000Z",
    target: {
      kind: "pr",
      label: "PR #42",
      scopeMode: "full",
      baseRef: "main",
      languages: ["TypeScript"],
      filesAnalyzed: 12,
    },
    headline: "Separate parsing from transport before extending the protocol.",
    findings,
    coverage: [
      {
        dimension: "complexity",
        tool: "biome",
        analysisClass: "local",
        status: "ran",
        notes: "Used biome.json from the target repository.",
        config: "biome.json",
      },
      {
        dimension: "dead-code",
        tool: "knip",
        analysisClass: "global",
        status: "skipped",
        notes: "Scoped PR target cannot support global dead-code analysis.",
      },
    ],
    suppressionCount: 2,
    systemicPatterns: ["Validation and transport concerns repeat across three parser entry points."],
    extensions: { "example.dev/team": { owner: "platform" } },
  };
}

describe("structured Sniff reports", () => {
  test("assigns stable structural finding and report IDs", () => {
    const input = finding();
    const first = buildSniffReport(reportInput([input]));
    const second = buildSniffReport({ ...reportInput([{ ...input }]), generatedAt: "2027-01-01T00:00:00.000Z" });

    expect(first.findings[0]?.id).toBe(deterministicFindingId(input));
    expect(first.findings[0]?.id).toBe(second.findings[0]?.id);
    expect(first.reportId).toBe(second.reportId);
  });

  test("keeps evidence confidence independent from impact", () => {
    const report = buildSniffReport(
      reportInput([
        finding({ title: "Proven typo", evidence: { tier: "reproduced", source: "test", detail: "Fixture reproduces it." }, impact: "low" }),
        finding({ title: "Unverified data loss", location: { path: "src/store.ts", line: 9 }, evidence: { tier: "hypothesis", source: "review", detail: "Reachable path needs reproduction." }, impact: "critical" }),
      ]),
    );

    expect(report.findings.map(({ evidence, impact }) => [evidence.tier, impact])).toEqual([
      ["reproduced", "low"],
      ["hypothesis", "critical"],
    ]);
  });

  test("retains dropped findings while census excludes them from impact totals", () => {
    const dropped = finding({
      title: "Suggested wrapper adds no policy",
      location: { path: "src/value.ts", line: 7 },
      adversarial: { verdict: "drop", reason: "The wrapper would only rename one expression." },
      impact: "high",
    });
    const report = buildSniffReport(reportInput([finding(), dropped]));

    expect(report.census).toEqual({
      considered: 2,
      retained: 1,
      dropped: 1,
      downgraded: 0,
      byImpact: { critical: 0, high: 0, medium: 1, low: 0 },
    });
    expect(report.findings).toHaveLength(2);
    expect(renderSniffMarkdown(report)).toContain("The wrapper would only rename one expression.");
  });

  test("rejects identities and summaries that drift from canonical content", () => {
    const report = buildSniffReport(reportInput());
    const badFinding = structuredClone(report);
    const [firstFinding] = badFinding.findings;
    if (!firstFinding) throw new Error("report fixture has no finding");
    firstFinding.id = "sniff-0000000000000000";
    expect(() => validateSniffReport(badFinding)).toThrow("structural identity");

    const badCensus = structuredClone(report);
    badCensus.census.retained = 0;
    expect(() => validateSniffReport(badCensus)).toThrow("census does not match findings");
  });

  test("requires a surface for breaking compatibility", () => {
    expect(() => buildSniffReport(reportInput([finding({ compatibility: { kind: "breaking" } })]))).toThrow(
      "compatibility.surface is required",
    );
  });

  test("renders Markdown and receipts deterministically without writing", () => {
    const report = buildSniffReport(reportInput());
    const first = createReportArtifacts(report);
    const second = createReportArtifacts(report);

    expect(first).toEqual(second);
    expect(first.markdown).toContain("| Impact | Evidence | Value | Cost |");
    expect(first.json).toContain(`"reportId": "${report.reportId}"`);
    expect(first.receipt.reportSha256).toHaveLength(64);
  });

  test("persists only through the explicit save operation and refuses overwrite", () => {
    const directory = mkdtempSync(join(tmpdir(), "sniff-report-"));
    temporaryDirectories.push(directory);
    const artifacts = createReportArtifacts(buildSniffReport(reportInput()));
    const expectedJson = join(directory, `${artifacts.report.reportId}.json`);

    expect(existsSync(expectedJson)).toBe(false);
    const paths = saveReportArtifacts(artifacts, directory);
    expect(paths).toHaveLength(3);
    expect(readFileSync(expectedJson, "utf8")).toBe(artifacts.json);
    expect(() => saveReportArtifacts(artifacts, directory)).toThrow();
  });

  test("tool rendering remains ephemeral unless save is explicit", () => {
    const rendered = runSniffReportTool({ report: reportInput() });
    expect(rendered.savedPaths).toEqual([]);

    const directory = mkdtempSync(join(tmpdir(), "sniff-report-tool-"));
    temporaryDirectories.push(directory);
    const saved = runSniffReportTool({ mode: "save", report: reportInput(), path: directory });
    expect(saved.savedPaths).toHaveLength(3);
  });

  test("tool save mode rejects an absent output path", () => {
    expect(() => runSniffReportTool({ mode: "save", report: reportInput() })).toThrow(
      "mode=save requires path",
    );
  });
});
