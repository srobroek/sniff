import { describe, expect, test } from "bun:test";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildSniffReport, createReportArtifacts, type FindingInput, type ReportInput, renderSniffMarkdown, type SniffReport, saveReportArtifacts } from "../../src/core/report.ts";

function finding(): FindingInput {
  return {
    title: "Original title",
    stableKey: "test:frozen",
    location: { path: "src/a.ts", line: 1, anchor: "a" },
    evidence: { tier: "observed", source: "bloodhound", detail: "original detail" },
    impact: "high",
    value: "high",
    cost: "S",
    compatibility: { kind: "safe" },
    applyTier: "assisted",
    adversarial: { verdict: "keep", reason: "reason" },
  };
}

function input(): ReportInput {
  return {
    generatedAt: "2026-09-11T08:00:00.000Z",
    target: { kind: "files", label: "selected files", scopeMode: "full", languages: ["TypeScript"], filesAnalyzed: 1 },
    headline: "Original headline",
    findings: [finding()],
    coverage: [{ dimension: "complexity", tool: "lizard", analysisClass: "local", status: "ran", notes: "original notes" }],
    suppressionCount: 0,
    systemicPatterns: [],
    extensions: { "example.dev": { nested: { value: "original" } } },
  };
}

describe("built reports and artifacts cannot change after validation", () => {
  test("a built report is deeply frozen, so it cannot drift from its validated identity", () => {
    const report = buildSniffReport(input());
    const writable = report as { -readonly [K in keyof SniffReport]: SniffReport[K] };
    expect(() => {
      writable.headline = "changed";
    }).toThrow(TypeError);
    expect(() => report.coverage.push({ ...report.coverage[0], tool: "forged" } as SniffReport["coverage"][number])).toThrow(TypeError);
    expect(() => {
      (report.coverage[0] as { notes: string }).notes = "changed";
    }).toThrow(TypeError);
    expect(() => {
      (report.findings[0]?.evidence as { detail: string }).detail = "changed";
    }).toThrow(TypeError);
    expect(() => {
      report.census.retained = 0;
    }).toThrow(TypeError);
    expect(() => {
      ((report.extensions["example.dev"] as { nested: { value: string } }).nested).value = "changed";
    }).toThrow(TypeError);
    expect(report.headline).toBe("Original headline");
  });

  test("mutating the builder's input afterwards never reaches the built report", () => {
    const source = input();
    const report = buildSniffReport(source);
    const before = createReportArtifacts(report).json;
    (source.findings[0] as FindingInput).evidence.detail = "changed through an alias";
    (source.coverage[0] as { notes: string }).notes = "changed through an alias";
    const extension = source.extensions?.["example.dev"] as { nested: { value: string } } | undefined;
    if (!extension) throw new Error("fixture has no extension");
    extension.nested.value = "changed through an alias";
    expect(createReportArtifacts(report).json).toBe(before);
    expect(renderSniffMarkdown(report)).not.toContain("changed through an alias");
  });

  test("built artifacts are deeply frozen, so a save cannot write bytes that disagree with the receipt", () => {
    const artifacts = createReportArtifacts(buildSniffReport(input()));
    const writable = artifacts as { fullMarkdown: string; json: string };
    expect(() => {
      writable.fullMarkdown = "# forged\n";
    }).toThrow(TypeError);
    expect(() => {
      writable.json = "{}\n";
    }).toThrow(TypeError);
    expect(() => {
      (artifacts.fileArtifacts[0] as { json: string }).json = "{}\n";
    }).toThrow(TypeError);
    expect(() => {
      (artifacts.receipt as { findingCount: number }).findingCount = 99;
    }).toThrow(TypeError);
    expect(() => (artifacts.descriptors as unknown[]).push({})).toThrow(TypeError);
    const directory = mkdtempSync(join(tmpdir(), "sniff-frozen-save-"));
    try {
      saveReportArtifacts(artifacts, directory);
      expect(readdirSync(join(directory, artifacts.report.reportId)).sort()).toContain("summary.md");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("artifacts built from a foreign report freeze their own validated copy", () => {
    const foreign = structuredClone(buildSniffReport(input()));
    const artifacts = createReportArtifacts(foreign);
    foreign.headline = "changed after artifacts were built";
    expect(artifacts.report.headline).toBe("Original headline");
    expect(Object.isFrozen(artifacts.report)).toBe(true);
    expect(() => createReportArtifacts(foreign)).toThrow("reportId does not match");
  });
});
