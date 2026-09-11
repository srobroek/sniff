import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createRunManifest } from "../src/core/intake.ts";
import {
  buildSniffReport,
  createReportArtifacts,
  deterministicFindingId,
  type FindingInput,
  type ReportInput,
  renderSniffMarkdown,
  saveReportArtifacts,
  validateSniffReport,
} from "../src/core/report.ts";
import { runSniffReportTool } from "../src/core/report-use-case.ts";
import { issueRunLease } from "../src/core/run-registry.ts";
import { validateResolvedTarget } from "../src/core/target.ts";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function finding(overrides: Partial<FindingInput> = {}): FindingInput {
  return {
    title: "Parser mixes transport and validation",
    stableKey: "bloodhound:long-method",
    location: { path: "src/parser.ts", line: 42, anchor: "parseRequest" },
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
        status: "skipped",
        notes: "Used biome.json from the target repository; execution was not requested.",
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

function authorizedReport(input: ReportInput = reportInput()): Parameters<typeof runSniffReportTool>[0] {
  const root = mkdtempSync(join(tmpdir(), "sniff-report-lease-"));
  temporaryDirectories.push(root);
  const files = Array.from({ length: input.target.filesAnalyzed }, (_, index) => `fixture-${index}.ts`);
  for (const file of files) writeFileSync(join(root, file), "export {};\n");
  const findings = input.findings.map((item, index) => ({ ...item, location: { ...item.location, path: files[index % files.length] ?? "fixture-0.ts" } }));
  const manifest = createRunManifest({
    target: validateResolvedTarget({ kind: "pr", label: input.target.label, root, files, baseRef: input.target.baseRef, materialization: "in-place" }),
    intent: "audit",
    scopeMode: input.target.scopeMode,
  });
  const lease = issueRunLease(manifest, { target: manifest.resolvedTarget, release: () => undefined });
  return {
    capability: lease.capability,
    manifestId: lease.manifestId,
    report: { ...input, findings, extensions: { ...input.extensions, "sniff.intake": structuredClone(manifest) } },
  };
}

describe("structured Sniff reports", () => {
  test("keeps finding IDs stable across presentation and evidence changes", () => {
    const input = finding();
    const first = buildSniffReport(reportInput([input]));
    const revised = finding({
      title: "Parser combines validation with transport",
      location: { ...input.location, line: 57 },
      evidence: { tier: "reproduced", source: "integration-test", detail: "A fixture now reproduces both branches." },
    });
    const second = buildSniffReport(reportInput([revised]));
    const later = buildSniffReport({ ...reportInput([input]), generatedAt: "2027-01-01T00:00:00.000Z" });

    expect(first.findings[0]?.id).toBe(deterministicFindingId(input));
    expect(first.findings[0]?.id).toBe(second.findings[0]?.id);
    expect(first.reportId).not.toBe(second.reportId);
    expect(first.reportId).toBe(later.reportId);
  });

  test("keeps evidence confidence independent from impact", () => {
    const report = buildSniffReport(
      reportInput([
        finding({ title: "Proven typo", evidence: { tier: "reproduced", source: "test", detail: "Fixture reproduces it." }, impact: "low" }),
        finding({ stableKey: "review:data-loss", title: "Unverified data loss", location: { path: "src/store.ts", line: 9, anchor: "Store.write" }, evidence: { tier: "hypothesis", source: "review", detail: "Reachable path needs reproduction." }, impact: "critical" }),
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
      stableKey: "review:weightless-wrapper",
      location: { path: "src/value.ts", line: 7, anchor: "normalizeValue" },
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
      "required property 'surface'",
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

  test("validates the complete input and output schemas", () => {
    const extraField = { ...reportInput(), unexpected: true };
    expect(() => buildSniffReport(extraField)).toThrow("additional properties");
    const duplicateLanguages = reportInput();
    duplicateLanguages.target.languages = ["TypeScript", "TypeScript"];
    expect(() => buildSniffReport(duplicateLanguages)).toThrow("duplicate items");
    expect(() => buildSniffReport(reportInput([finding({ value: "urgent" as never })]))).toThrow("allowed values");
    expect(() => buildSniffReport(reportInput([finding({ smell: { name: "Long Method", url: "javascript:alert(1)" } })]))).toThrow(
      "pattern",
    );
    const impossibleDate = reportInput();
    impossibleDate.generatedAt = "2026-02-31T10:00:00Z";
    expect(() => buildSniffReport(impossibleDate)).toThrow("format");
    expect(() => buildSniffReport(reportInput([finding({ smell: { name: "Long Method", url: "https://refactoring.guru/foo)<script>" } })]))).toThrow(
      "pattern",
    );
  });

  test("canonicalizes equivalent object and collection order", () => {
    const firstInput = reportInput([finding(), finding({ stableKey: "review:second", location: { path: "src/second.ts", line: 3, anchor: "second" } })]);
    firstInput.extensions = { zeta: { second: 2, first: 1 }, alpha: true };
    firstInput.target.languages = ["TypeScript", "JavaScript"];
    firstInput.coverage = [
      { dimension: "complexity", tool: "biome", analysisClass: "local", status: "skipped", notes: "Unavailable." },
      { dimension: "complexity", tool: "biome", analysisClass: "local", status: "ran", notes: "Completed." },
    ];
    const secondInput = reportInput([...firstInput.findings].reverse());
    secondInput.extensions = { alpha: true, zeta: { first: 1, second: 2 } };
    secondInput.target.languages = ["JavaScript", "TypeScript"];
    secondInput.coverage = [...firstInput.coverage].reverse();

    const first = createReportArtifacts(buildSniffReport(firstInput));
    const second = createReportArtifacts(buildSniffReport(secondInput));
    expect(first.report.reportId).toBe(second.report.reportId);
    expect(first.json).toBe(second.json);
    expect(first.receipt).toEqual(second.receipt);
  });

  test("sorts retained findings by value per cost and discloses downgrades", () => {
    const report = buildSniffReport(
      reportInput([
        finding({ stableKey: "review:large", title: "Large low value", location: { path: "src/large.ts", line: 1, anchor: "large" }, value: "low", cost: "L" }),
        finding({ stableKey: "review:small", title: "Small high value", location: { path: "src/small.ts", line: 1, anchor: "small" }, value: "high", cost: "S", adversarial: { verdict: "downgrade", reason: "Impact lowered after call-site census." } }),
      ]),
    );
    const markdown = renderSniffMarkdown(report);
    expect(markdown.indexOf("Small high value")).toBeLessThan(markdown.indexOf("Large low value"));
    expect(markdown).toContain("| DOWNGRADE | Impact lowered after call-site census. |");
  });

  test("escapes analyzer-controlled Markdown contexts and line endings", () => {
    const input = reportInput([finding({ title: "# Inject <script> | value" })]);
    input.target.label = "# target <unsafe>\r---\u2028next";
    const markdown = renderSniffMarkdown(buildSniffReport(input));
    expect(markdown).toContain("\\# target \\<unsafe\\> --- next");
    expect(markdown).not.toMatch(/[\r\u2028\u2029]/);
    expect(markdown).toContain("\\# Inject \\<script\\> \\| value");
  });

  test("preflights every artifact collision without partial writes", () => {
    const artifacts = createReportArtifacts(buildSniffReport(reportInput()));
    for (const suffix of [".json", ".md", ".receipt.json"]) {
      const directory = mkdtempSync(join(tmpdir(), "sniff-report-collision-"));
      temporaryDirectories.push(directory);
      const collision = join(directory, `${artifacts.report.reportId}${suffix}`);
      writeFileSync(collision, "existing", "utf8");

      expect(() => saveReportArtifacts(artifacts, directory)).toThrow("already exists");
      expect(readdirSync(directory)).toEqual([`${artifacts.report.reportId}${suffix}`]);
      expect(readFileSync(collision, "utf8")).toBe("existing");
    }
  });


  test("refuses artifacts whose bytes or receipt drift from the report", () => {
    const directory = mkdtempSync(join(tmpdir(), "sniff-report-mismatch-"));
    temporaryDirectories.push(directory);
    const artifacts = createReportArtifacts(buildSniffReport(reportInput()));
    expect(() => saveReportArtifacts({ ...artifacts, json: "{}\n" }, directory)).toThrow("JSON artifact does not match");
    expect(() => saveReportArtifacts({ ...artifacts, receipt: { ...artifacts.receipt, findingCount: 99 } }, directory)).toThrow(
      "receipt does not match",
    );
    expect(readdirSync(directory)).toEqual([]);
  });
  test("tool rendering remains ephemeral unless save is explicit", async () => {
    const rendered = await runSniffReportTool(authorizedReport());
    expect(rendered.savedPaths).toEqual([]);

    const directory = mkdtempSync(join(import.meta.dir, ".sniff-report-tool-"));
    temporaryDirectories.push(directory);
    const saved = await runSniffReportTool({ ...authorizedReport(), mode: "save", path: directory, runtime: { authorizeSave: async (request) => ({ acceptedDigest: request.digest, actor: "test-authority" }) } });
    expect(saved.savedPaths).toHaveLength(3);
  });

  test("tool save mode rejects an absent output path", async () => {
    await expect(runSniffReportTool({ ...authorizedReport(), mode: "save" })).rejects.toThrow("mode=save requires path");
  });

	test("does not create a requested destination before save approval", async () => {
		const parent = mkdtempSync(join(import.meta.dir, ".sniff-report-save-parent-"));
		temporaryDirectories.push(parent);
		const directory = join(parent, "denied");
		let requested = false;
		await expect(
			runSniffReportTool({
				...authorizedReport(),
				mode: "save",
				path: directory,
				runtime: {
					authorizeSave: async (request) => {
						requested = true;
						expect(request.directory).toBe(resolve(directory));
						expect(existsSync(directory)).toBe(false);
						return false;
					},
				},
			}),
		).rejects.toThrow("denied or mismatched");
		expect(requested).toBe(true);
		expect(existsSync(directory)).toBe(false);
	});

	test("does not create a requested destination when the save digest mismatches", async () => {
		const parent = mkdtempSync(join(import.meta.dir, ".sniff-report-save-parent-"));
		temporaryDirectories.push(parent);
		const directory = join(parent, "mismatched");
		await expect(
			runSniffReportTool({
				...authorizedReport(),
				mode: "save",
				path: directory,
				runtime: { authorizeSave: async () => ({ acceptedDigest: "not-the-request-digest" }) },
			}),
		).rejects.toThrow("denied or mismatched");
		expect(existsSync(directory)).toBe(false);
	});
});
