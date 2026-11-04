import { describe, expect, test } from "bun:test";
import { createRunManifest } from "../../src/core/intake.ts";
import { buildSniffReport, renderCompleteSniffMarkdown, renderSniffMarkdown } from "../../src/core/report.ts";
import type { ResolvedTarget } from "../../src/core/target.ts";

const wholeRepo: ResolvedTarget = { kind: "whole-repo", label: "repo", root: "/tmp/r", files: ["src/a.ts"], materialization: "temporary-checkout" };

describe("report objective coverage", () => {
test("the report shows an objective gap as a gap row, not not-applicable", () => {
    const manifest = createRunManifest({ target: wholeRepo, intent: "audit", scopeMode: "full", objectives: ["performance-and-efficiency"] });
    const report = buildSniffReport({
      generatedAt: "2026-09-11T00:00:00.000Z",
      target: { kind: "whole-repo", label: "repo", scopeMode: "full", languages: ["TypeScript"], filesAnalyzed: 1 },
      headline: "No analyzers ran.",
      findings: [],
      coverage: [],
      suppressionCount: 0,
      systemicPatterns: [],
      extensions: { "sniff.intake": manifest },
    });
    for (const markdown of [renderSniffMarkdown(report), renderCompleteSniffMarkdown(report)]) {
      expect(markdown).not.toContain("not-applicable");
      expect(markdown).toContain("| gap |");
      expect(markdown).toContain("performance-and-efficiency");
    }
  });

  test("every manifest gap becomes an unmet coverage row, whatever its field", () => {
    const manifest = createRunManifest({
      target: wholeRepo,
      intent: "audit",
      scopeMode: "full",
      objectives: ["structure-and-maintainability"],
      gaps: [{ field: "target", reason: "The target listing was truncated at 5000 files.", impact: "high" }],
    });
    const report = buildSniffReport({
      generatedAt: "2026-09-11T00:00:00.000Z",
      target: { kind: "whole-repo", label: "repo", scopeMode: "full", languages: ["TypeScript"], filesAnalyzed: 1 },
      headline: "Gaps recorded.",
      findings: [],
      coverage: [],
      suppressionCount: 0,
      systemicPatterns: [],
      extensions: { "sniff.intake": manifest },
    });
    for (const markdown of [renderSniffMarkdown(report), renderCompleteSniffMarkdown(report)]) {
      expect(markdown).not.toContain("not-applicable");
      expect(markdown).toContain("| target | — | — | gap | The target listing was truncated at 5000 files. |");
    }
  });
});
