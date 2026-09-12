import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createRunManifest } from "../src/core/intake.ts";
import { canonicalReportTargetIdentity, publicSniffIntakeResult } from "../src/core/intake-use-case.ts";
import {
  buildSniffReport,
  createReportArtifacts,
  deterministicFindingId,
  type FindingInput,
  MAX_PUBLIC_REPORT_DESCRIPTOR_BYTES,
  projectReportArtifacts,
  type ReportInput,
  renderSniffMarkdown,
  saveReportArtifacts,
  validateSniffReport,
} from "../src/core/report.ts";
import { readReportArtifact, registerReportArtifacts } from "../src/core/report-artifact-registry.ts";
import { runSniffReportTool } from "../src/core/report-use-case.ts";
import { issueRunLease } from "../src/core/run-registry.ts";
import { validateResolvedTarget } from "../src/core/target.ts";
import sniffReportTool from "./sniff-report-tool.ts";

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
    report: { ...input, target: { ...canonicalReportTargetIdentity(manifest.resolvedTarget, manifest.scopeMode), languages: input.target.languages }, findings, extensions: { ...input.extensions, "sniff.intake": structuredClone(manifest) } },
  };
}
type RegisteredReportOutput = {
  readonly content: readonly { readonly type: string; readonly text: string }[];
  readonly details: Record<string, unknown>;
  readonly isError?: boolean;
};

type RegisteredReportTool = {
  readonly name: string;
  readonly execute: (id: string, params: unknown, signal: unknown, onUpdate: unknown, context: unknown) => Promise<RegisteredReportOutput>;
};

function registeredReportTools(): Map<string, RegisteredReportTool> {
  const schema = {
    describe() { return this; },
    optional() { return this; },
    int() { return this; },
    nonnegative() { return this; },
  };
  const captured = new Map<string, RegisteredReportTool>();
  const pi = {
    zod: { object: () => schema, string: () => schema, number: () => schema },
    registerTool: (definition: RegisteredReportTool) => { captured.set(definition.name, definition); },
  };
  sniffReportTool(pi as never);
  return captured;
}

function outputText(output: RegisteredReportOutput): string {
  const [first] = output.content;
  if (!first) throw new Error("report tool returned no text content");
  return first.text;
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

  test("preflights report-directory collisions without partial writes", () => {
    const artifacts = createReportArtifacts(buildSniffReport(reportInput()));
    const directory = mkdtempSync(join(tmpdir(), "sniff-report-collision-"));
    temporaryDirectories.push(directory);
    const destination = join(directory, artifacts.report.reportId);
    mkdirSync(destination);
    const collision = join(destination, "index.json");
    writeFileSync(collision, "existing", "utf8");

    expect(() => saveReportArtifacts(artifacts, directory)).toThrow("already exists");
    expect(readdirSync(directory)).toEqual([artifacts.report.reportId]);
    expect(readFileSync(collision, "utf8")).toBe("existing");
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
  test("chains model-visible report metadata into bounded artifact paging", async () => {
    const findings = Array.from({ length: 2_000 }, (_, index) => finding({
      stableKey: `test:model-visible-${index}`,
      title: `Model-visible finding ${index}`,
      location: { path: `src/model-visible-${index}.ts`, line: index + 1, anchor: `modelVisible${index}` },
    }));
    const tools = registeredReportTools();
    const reportTool = tools.get("sniff_report");
    const readerTool = tools.get("sniff_read_report_artifact");
    if (!reportTool || !readerTool) throw new Error("report tools were not registered");

    const rendered = await reportTool.execute("render", authorizedReport(reportInput(findings)), undefined, undefined, { hasUI: false });
    expect(rendered.isError).toBeUndefined();
    expect(Object.keys(rendered.details).sort()).toEqual([
      "descriptorCount",
      "descriptors",
      "descriptorsTruncated",
      "ok",
      "readCapability",
      "receipt",
      "reportId",
      "savedPaths",
      "summary",
    ]);
    const renderedText = outputText(rendered);
    expect(Buffer.byteLength(renderedText, "utf8")).toBeLessThanOrEqual(64 * 1024 - 1);
    const separator = renderedText.indexOf("\n");
    expect(separator).toBeGreaterThan(0);
    const metadata = JSON.parse(renderedText.slice(0, separator)) as {
      reportId: string;
      readCapability: string;
      descriptors: readonly { relativePath: string; bytes: number; sha256: string }[];
    };
    const markdown = renderedText.slice(separator + 1);
    expect(markdown).toBe(rendered.details.summary as string);
    expect(metadata.reportId).toBe(rendered.details.reportId as string);
    expect(metadata.readCapability).toBe(rendered.details.readCapability as string);
    expect(markdown).toContain("Model-visible finding");
    expect(markdown).toContain("# Sniff Refactoring Plan");
    expect(metadata.descriptors.length).toBeLessThanOrEqual(rendered.details.descriptorCount as number);

    const descriptor = metadata.descriptors.find((item) => item.relativePath === "summary.md");
    if (!descriptor) throw new Error("bounded report metadata omitted summary.md");
    const rejected = await readerTool.execute("read", { capability: "wrong-capability", reportId: metadata.reportId, relativePath: descriptor.relativePath }, undefined, undefined, { hasUI: false });
    expect(rejected.isError).toBe(true);
    expect(outputText(rejected)).toBe("sniff_read_report_artifact failed: Unknown Sniff report artifact capability");
    expect(rejected.details).toEqual({ ok: false, error: "Unknown Sniff report artifact capability" });

    let offset = 0;
    let assembled = "";
    let eof = false;
    for (let pageCount = 0; pageCount < 128; pageCount += 1) {
      const pageOutput = await readerTool.execute("read", {
        capability: metadata.readCapability,
        reportId: metadata.reportId,
        relativePath: descriptor.relativePath,
        offset,
      }, undefined, undefined, { hasUI: false });
      expect(pageOutput.isError).toBeUndefined();
      expect(Object.keys(pageOutput.details).sort()).toEqual(["bytes", "eof", "nextOffset", "offset", "ok", "relativePath", "reportId", "sha256", "totalBytes"]);
      const pageText = outputText(pageOutput);
      expect(Buffer.byteLength(pageText, "utf8")).toBeLessThanOrEqual(64 * 1024 - 1);
      const page = JSON.parse(pageText) as {
        relativePath: string;
        offset: number;
        nextOffset: number;
        eof: boolean;
        bytes: number;
        content: string;
      };
      expect(Object.keys(page).sort()).toEqual(["bytes", "content", "eof", "nextOffset", "offset", "relativePath"]);
      expect(page.relativePath).toBe(descriptor.relativePath);
      expect(page.offset).toBe(offset);
      expect(Buffer.byteLength(page.content, "utf8")).toBe(page.bytes);
      expect(Buffer.from(page.content, "utf8").toString("utf8")).toBe(page.content);
      assembled += page.content;
      if (page.eof) {
        eof = true;
        expect(page.nextOffset).toBe(descriptor.bytes);
        break;
      }
      expect(page.nextOffset).toBeGreaterThan(offset);
      offset = page.nextOffset;
    }
    expect(eof).toBe(true);
    expect(assembled).toContain("# Sniff Refactoring Plan");
    expect(createHash("sha256").update(assembled).digest("hex")).toBe(descriptor.sha256);
  });

  test("tool rendering remains ephemeral unless save is explicit", async () => {
    const rendered = await runSniffReportTool(authorizedReport());
    expect(rendered.savedPaths).toEqual([]);
    expect(rendered.publicArtifacts.descriptors.every((descriptor) => descriptor.savedPath === undefined)).toBe(true);

    const directory = mkdtempSync(join(import.meta.dir, ".sniff-report-tool-"));
    temporaryDirectories.push(directory);
    const saved = await runSniffReportTool({ ...authorizedReport(), mode: "save", path: directory, runtime: { authorizeSave: async (request) => ({ acceptedDigest: request.digest, actor: "test-authority" }) } });
    expect(saved.savedPaths).toHaveLength(7);
    expect(saved.savedPaths.every((path) => path.startsWith(join(directory, saved.artifacts.report.reportId)))).toBe(true);
    expect(saved.publicArtifacts.descriptors.some((descriptor) => descriptor.savedPath !== undefined)).toBe(true);
    expect(readFileSync(join(directory, saved.artifacts.report.reportId, "report.json"), "utf8")).toBe(saved.artifacts.json);

    const nestedParentRoot = mkdtempSync(join(tmpdir(), "sniff-report-parent-"));
    temporaryDirectories.push(nestedParentRoot);
    const nestedParent = join(nestedParentRoot, "files", "output");
    const nested = await runSniffReportTool({ ...authorizedReport(), mode: "save", path: nestedParent, runtime: { authorizeSave: async (request) => ({ acceptedDigest: request.digest, actor: "test-authority" }) } });
    expect(nested.publicArtifacts.descriptors.every((descriptor) => descriptor.savedPath !== undefined)).toBe(true);
  });
  test("keeps the run lease for a corrected retry after malformed report input", async () => {
    const request = authorizedReport();
    const { headline: _headline, ...withoutHeadline } = request.report;
    const malformed = { ...request, report: { ...withoutHeadline, target: { ...request.report.target, unexpected: true } } } as never;
    await expect(runSniffReportTool(malformed)).rejects.toThrow("required property 'headline'");
    const corrected = await runSniffReportTool(request);
    expect(corrected.artifacts.report.reportId).toMatch(/^report-/);
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
						expect(request.directory).toBe(join(resolve(directory), request.reportId));
						expect(request.parentDirectory).toBe(resolve(directory));
						expect(request.files).toContain("index.json");
						expect(Object.keys(request.artifactDigests)).toEqual([...request.files]);
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
  test("tool save mode rejects an absent output path", async () => {
    await expect(runSniffReportTool({ ...authorizedReport(), mode: "save" })).rejects.toThrow("mode=save requires path");
  });
  test("groups findings into deterministic per-file artifacts and verifies index digests", () => {
    const report = buildSniffReport(reportInput([
      finding({ stableKey: "test:second", location: { path: "src/z.ts", line: 4, anchor: "z" } }),
      finding({ stableKey: "test:first", location: { path: "src/a.ts", line: 2, anchor: "a" } }),
      finding({ stableKey: "test:third", location: { path: "src/a.ts", line: 1, anchor: "a2" } }),
    ]));
    const artifacts = createReportArtifacts(report);
    expect(artifacts.fileArtifacts.map((file) => file.sourcePath)).toEqual(["src/a.ts", "src/z.ts"]);
    expect(artifacts.fileArtifacts.flatMap((file) => file.findings.map((item) => item.id)).sort()).toEqual(report.findings.map((item) => item.id).sort());

    const directory = mkdtempSync(join(tmpdir(), "sniff-report-digest-"));
    temporaryDirectories.push(directory);
    saveReportArtifacts(artifacts, directory);
    const destination = join(directory, report.reportId);
    const index = JSON.parse(readFileSync(join(destination, "index.json"), "utf8")) as { files: Array<{ relativePath: string; sha256: string }> };
    for (const file of index.files) {
      const bytes = readFileSync(join(destination, file.relativePath));
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(file.sha256);
    }
  });

  test("bounds large summaries and public descriptors without losing saved artifacts", () => {
    const findings = Array.from({ length: 10_000 }, (_, index) => finding({
      stableKey: `test:large-${index}`,
      title: `Finding ${index}`,
      location: { path: `src/file-${index}.ts`, line: index + 1, anchor: `anchor-${index}` },
    }));
    const artifacts = createReportArtifacts(buildSniffReport(reportInput(findings)));
    const projection = projectReportArtifacts(artifacts);
    expect(Buffer.byteLength(artifacts.markdown)).toBeLessThanOrEqual(60_000);
    expect(Buffer.byteLength(JSON.stringify(projection.descriptors))).toBeLessThanOrEqual(MAX_PUBLIC_REPORT_DESCRIPTOR_BYTES);
    expect(projection.descriptors.every((descriptor) => !Object.hasOwn(descriptor, "sourcePath"))).toBe(true);
    expect(projection.descriptors).toHaveLength(128);
    expect(projection.descriptorCount).toBe(10_006);
    expect(projection.descriptorsTruncated).toBe(true);
    expect(artifacts.fileArtifacts).toHaveLength(10_000);
    expect(artifacts.fileArtifacts.reduce((total, file) => total + file.findings.length, 0)).toBe(10_000);
  });
  test("truncates public Markdown without splitting UTF-8 code points", () => {
    const findings = Array.from({ length: 64 }, (_, index) => finding({
      stableKey: `test:utf8-${index}`,
      title: `界${"界".repeat(2_000)}-${index}`,
      location: { path: `src/utf8-${index}.ts`, line: index + 1, anchor: `anchor-${index}` },
    }));
    const markdown = renderSniffMarkdown(buildSniffReport(reportInput(findings)));
    expect(Buffer.byteLength(markdown)).toBeLessThanOrEqual(60_000);
    expect(Buffer.from(markdown, "utf8").toString("utf8")).toBe(markdown);
    expect(markdown).not.toContain("\uFFFD");
  });

  test("pages complete artifacts beyond bounded summaries and preserves UTF-8 boundaries", () => {
    const findings = Array.from({ length: 10_000 }, (_, index) => finding({
      stableKey: `test:paged-${index}`,
      title: `Finding ${index}`,
      location: { path: `src/file-${index}.ts`, line: index + 1, anchor: `anchor-${index}` },
    }));
    const artifacts = createReportArtifacts(buildSniffReport(reportInput(findings)));
    const capability = registerReportArtifacts(artifacts);
    const descriptor = artifacts.descriptors.slice(128).find((item) => item.kind === "file");
    if (!descriptor) throw new Error("expected an artifact beyond the public descriptor bound");
    let offset = 0;
    let content = "";
    let pages = 0;
    for (;;) {
      const page = readReportArtifact({ capability, reportId: artifacts.report.reportId, relativePath: descriptor.relativePath, offset });
      expect(page.offset).toBe(offset);
      expect(page.bytes).toBeLessThanOrEqual(64 * 1024);
      expect(Buffer.byteLength(page.content)).toBe(page.bytes);
      expect(Buffer.from(page.content, "utf8").toString("utf8")).toBe(page.content);
      content += page.content;
      pages += 1;
      if (page.eof) {
        expect(page.nextOffset).toBe(descriptor.bytes);
        break;
      }
      offset = page.nextOffset;
    }
    expect(pages).toBeGreaterThan(0);
    expect(content).toContain('"findings"');
    expect(createHash("sha256").update(content).digest("hex")).toBe(descriptor.sha256);
  });

  test("rejects a symlink ancestor before save authorization", async () => {
    const target = mkdtempSync(join(tmpdir(), "sniff-report-symlink-target-"));
    const parent = mkdtempSync(join(tmpdir(), "sniff-report-symlink-parent-"));
    temporaryDirectories.push(target, parent);
    const link = join(parent, "linked");
    symlinkSync(target, link);
    let authorized = false;
    await expect(runSniffReportTool({
      ...authorizedReport(),
      mode: "save",
      path: join(link, "reports"),
      runtime: { authorizeSave: async () => { authorized = true; return false; } },
    })).rejects.toThrow("cannot traverse a symlink");
    expect(authorized).toBe(false);
  });

  test("rejects a canonical destination replaced after approval without residue", async () => {
    const parent = mkdtempSync(join(tmpdir(), "sniff-report-replacement-parent-"));
    const outside = mkdtempSync(join(tmpdir(), "sniff-report-replacement-outside-"));
    temporaryDirectories.push(parent, outside);
    const destination = join(parent, "reports");
    await expect(runSniffReportTool({
      ...authorizedReport(),
      mode: "save",
      path: destination,
      runtime: {
        authorizeSave: async (request) => {
          symlinkSync(outside, destination);
          return { acceptedDigest: request.digest, actor: "test-authority" };
        },
      },
    })).rejects.toThrow("cannot traverse a symlink");
    expect(existsSync(join(outside, "index.json"))).toBe(false);
  });
  test("pins the approved parent across rename and symlink replacement", async () => {
    const parent = mkdtempSync(join(tmpdir(), "sniff-report-pinned-parent-"));
    const moved = `${parent}-moved`;
    const outside = mkdtempSync(join(tmpdir(), "sniff-report-pinned-outside-"));
    temporaryDirectories.push(parent, moved, outside);
    const destination = join(parent, "reports");
    const saved = await runSniffReportTool({
      ...authorizedReport(),
      mode: "save",
      path: destination,
      runtime: {
        authorizeSave: async (request) => {
          renameSync(parent, moved);
          symlinkSync(outside, parent);
          return { acceptedDigest: request.digest, actor: "test-authority" };
        },
      },
    });
    expect(existsSync(join(moved, "reports", saved.artifacts.report.reportId, "index.json"))).toBe(true);
    expect(existsSync(join(outside, "index.json"))).toBe(false);
    expect(existsSync(join(outside, "reports"))).toBe(false);
  });

  test("does not overwrite a destination created after approval", async () => {
    const parent = mkdtempSync(join(tmpdir(), "sniff-report-destination-race-"));
    temporaryDirectories.push(parent);
    const destination = join(parent, "reports");
    const sentinel = "created-after-approval";
    let reportDirectory = "";
    await expect(runSniffReportTool({
      ...authorizedReport(),
      mode: "save",
      path: destination,
      runtime: {
        authorizeSave: async (request) => {
          reportDirectory = join(destination, request.reportId);
          mkdirSync(reportDirectory, { recursive: true });
          writeFileSync(join(reportDirectory, "index.json"), sentinel, "utf8");
          return { acceptedDigest: request.digest, actor: "test-authority" };
        },
      },
    })).rejects.toThrow("already exists");
    expect(readFileSync(join(reportDirectory, "index.json"), "utf8")).toBe(sentinel);
  });
  test("replaces complete intake plans with a bounded summary", () => {
    const result = publicSniffIntakeResult({
      interview: {
        questions: [],
        confirmationRequired: true,
        plan: {
          target: { kind: "files", root: "/private/secret/repository", paths: Array.from({ length: 10_000 }, (_, index) => `src/file-${index}.ts`) },
          intent: "audit",
          scopeMode: "full",
          objectives: ["structure-and-maintainability"],
          exclusions: [],
          budget: { maxMinutes: 1, maxAnalyzers: 2, maxFiles: 10_000 },
          security: {},
        },
      },
    });
    expect(result.interview).not.toHaveProperty("plan");
    expect(result.interview.planSummary).toEqual({ target: { kind: "files", rootBasename: "repository" }, intent: "audit", scopeMode: "full", objectiveCount: 1, exclusionCount: 0, budget: { maxMinutes: 1, maxAnalyzers: 2, maxFiles: 10_000 } });
    expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThan(2_000);
  });
});