import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildSniffReport,
  createReportArtifacts,
  type FindingInput,
  MAX_PUBLIC_REPORT_DESCRIPTOR_BYTES,
  MAX_PUBLIC_REPORT_DESCRIPTORS,
  type PublicReportArtifacts,
  projectReportArtifacts,
  type ReportArtifactDescriptor,
  type ReportArtifacts,
  type ReportInput,
  renderCompleteSniffMarkdown,
  renderSniffMarkdown,
  saveReportArtifacts,
} from "../../src/core/report.ts";
import * as schema from "../../src/core/report-schema.ts";

const temporary: string[] = [];
afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function finding(index: number): FindingInput {
  return {
    title: `Finding ${index}`,
    stableKey: `test:validate-once-${index}`,
    location: { path: `src/file-${index % 7}.ts`, line: index + 1, anchor: `anchor${index}` },
    evidence: { tier: "observed", source: "bloodhound", detail: "detail" },
    impact: index % 2 === 0 ? "high" : "low",
    value: "medium",
    cost: "S",
    compatibility: { kind: "safe" },
    applyTier: "assisted",
    adversarial: { verdict: index % 5 === 0 ? "downgrade" : "keep", reason: "reason" },
  };
}

function reportInput(count = 12): ReportInput {
  return {
    generatedAt: "2026-09-11T08:00:00.000Z",
    target: { kind: "files", label: "selected files", scopeMode: "full", languages: ["TypeScript"], filesAnalyzed: 7 },
    headline: "Validate each report once.",
    findings: Array.from({ length: count }, (_, index) => finding(index)),
    coverage: [{ dimension: "complexity", tool: "lizard", analysisClass: "local", status: "ran", notes: "ok" }],
    suppressionCount: 0,
    systemicPatterns: ["pattern"],
    extensions: { "example.dev": { kept: true } },
  };
}

/** The pre-change projection, kept here as the byte-for-byte reference for the linear one. */
function referenceProjection(artifacts: ReportArtifacts, savedPaths: readonly string[], readCapability: string): PublicReportArtifacts {
  const savedByRelativePath = new Map<string, string>();
  const indexSuffix = `/${artifacts.report.reportId}/index.json`;
  const indexPath = savedPaths.find((path) => path.endsWith(indexSuffix));
  const reportRoot = indexPath?.slice(0, -"/index.json".length);
  if (reportRoot) for (const path of savedPaths) if (path.startsWith(`${reportRoot}/`)) savedByRelativePath.set(path.slice(reportRoot.length + 1), path);
  const descriptors: ReportArtifactDescriptor[] = [];
  for (const descriptor of artifacts.descriptors.slice(0, MAX_PUBLIC_REPORT_DESCRIPTORS)) {
    const { sourcePath: _sourcePath, ...withoutSourcePath } = descriptor;
    const savedPath = savedByRelativePath.get(descriptor.relativePath);
    const withSavedPath = savedPath === undefined ? withoutSourcePath : { ...withoutSourcePath, savedPath };
    const candidate = Buffer.byteLength(JSON.stringify([...descriptors, withSavedPath])) <= MAX_PUBLIC_REPORT_DESCRIPTOR_BYTES ? withSavedPath : withoutSourcePath;
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

describe("report validation runs once per built report", () => {
  test("render validates the built report exactly once", () => {
    const spy = spyOn(schema, "assertSniffReportSchema");
    try {
      const artifacts = createReportArtifacts(buildSniffReport(reportInput()));
      renderSniffMarkdown(artifacts.report);
      renderCompleteSniffMarkdown(artifacts.report);
      expect(spy).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  test("save validates once and writes the artifacts it was given without rebuilding them", () => {
    const directory = mkdtempSync(join(tmpdir(), "sniff-validate-once-"));
    temporary.push(directory);
    const spy = spyOn(schema, "assertSniffReportSchema");
    try {
      const artifacts = createReportArtifacts(buildSniffReport(reportInput()));
      const saved = saveReportArtifacts(artifacts, directory);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(readdirSync(join(directory, artifacts.report.reportId)).sort()).toEqual(["coverage.json", "files", "index.json", "manifest.json", "receipt.json", "report.json", "summary.md"]);
      expect(readFileSync(saved[0] ?? "", "utf8")).toBe(artifacts.indexJson);
    } finally {
      spy.mockRestore();
    }
  });

  test("a report or artifact set not built in-process is still fully validated and gives identical bytes", () => {
    const built = createReportArtifacts(buildSniffReport(reportInput()));
    const foreignReport = structuredClone(built.report);
    const spy = spyOn(schema, "assertSniffReportSchema");
    try {
      const foreign = createReportArtifacts(foreignReport);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(foreign.indexJson).toBe(built.indexJson);
      expect(foreign.json).toBe(built.json);
      expect(foreign.fullMarkdown).toBe(built.fullMarkdown);
      expect(foreign.descriptors).toEqual(built.descriptors);
      expect(renderSniffMarkdown(foreignReport)).toBe(built.markdown);
      expect(spy).toHaveBeenCalledTimes(2);
    } finally {
      spy.mockRestore();
    }
    const tampered = { ...built.report, headline: "changed" };
    expect(() => createReportArtifacts(tampered)).toThrow("reportId does not match");
  });

  test("a copied artifact set is integrity-checked before it is saved", () => {
    const directory = mkdtempSync(join(tmpdir(), "sniff-validate-copy-"));
    temporary.push(directory);
    const artifacts = createReportArtifacts(buildSniffReport(reportInput()));
    expect(() => saveReportArtifacts({ ...artifacts, fullMarkdown: "# drift\n" }, directory)).toThrow("Markdown artifact does not match");
    expect(readdirSync(directory)).toEqual([]);
  });

  test("the linear descriptor projection matches the quadratic reference byte for byte", () => {
    const artifacts = createReportArtifacts(buildSniffReport(reportInput(400)));
    const root = `/tmp/${"deep/".repeat(200)}${artifacts.report.reportId}`;
    const savedPaths = artifacts.descriptors.map((descriptor) => `${root}/${descriptor.relativePath}`);
    for (const paths of [[], savedPaths]) {
      const projected = projectReportArtifacts(artifacts, paths, "cap");
      expect(JSON.stringify(projected)).toBe(JSON.stringify(referenceProjection(artifacts, paths, "cap")));
    }
    const large = createReportArtifacts(buildSniffReport({ ...reportInput(1), findings: Array.from({ length: 300 }, (_, index) => ({ ...finding(index), location: { path: `src/${"x".repeat(80)}-${index}.ts`, line: 1, anchor: "a" } })) }));
    const largeRoot = `/tmp/${"y".repeat(2_000)}/${large.report.reportId}`;
    const largePaths = large.descriptors.map((descriptor) => `${largeRoot}/${descriptor.relativePath}`);
    const projected = projectReportArtifacts(large, largePaths, "cap");
    expect(JSON.stringify(projected)).toBe(JSON.stringify(referenceProjection(large, largePaths, "cap")));
    expect(projected.descriptors.some((descriptor) => descriptor.savedPath === undefined)).toBe(true);
  });
});
