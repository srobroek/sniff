import { describe, expect, test } from "bun:test";
import { SNIFF_ANALYZER_RECIPES } from "../../src/core/analyzer-recipes.ts";
import { intakeConfirmationText } from "../../src/core/confirmation-text.ts";
import { canonicalConfirmationRequest, createRunManifest, validateRunManifest } from "../../src/core/intake.ts";
import { publicConfirmationSummary } from "../../src/core/intake-use-case.ts";
import { OBJECTIVE_GROUPS, type ObjectiveGroup } from "../../src/core/objectives.ts";
import { SECURITY_ANALYZER_CATALOG, selectSecurityAnalyzers } from "../../src/core/security.ts";
import type { ResolvedTarget } from "../../src/core/target.ts";

const files: ResolvedTarget = { kind: "files", label: "src/a.ts", root: "/tmp/r", files: ["src/a.ts"], materialization: "in-place" };
const wholeRepo: ResolvedTarget = { ...files, kind: "whole-repo", label: "repo", materialization: "temporary-checkout" };
const remote: ResolvedTarget = { ...wholeRepo, kind: "repository", repository: "https://example.com/acme/repo.git" };

const selected = (objectives: readonly ObjectiveGroup[] | undefined, target: ResolvedTarget, trust: "trusted-local" | "untrusted-remote" = "trusted-local") =>
  selectSecurityAnalyzers({}, { target, trust, scopeMode: "full", ...(objectives ? { objectives } : {}) })
    .filter(({ disposition }) => disposition === "selected")
    .map(({ name }) => name);

describe("objectives drive analyzer selection", () => {
  test("the default (all objectives) selects what was selected before objectives existed", () => {
    for (const [target, trust, expected] of [
      [files, "trusted-local", ["lizard:complexity", "opengrep:hardcoded-values"]],
      [wholeRepo, "trusted-local", ["gitleaks:tracked-history", "lizard:complexity", "opengrep:hardcoded-values"]],
      [remote, "untrusted-remote", ["lizard:complexity", "opengrep:hardcoded-values"]],
    ] as const) {
      expect(selected(undefined, target, trust)).toEqual([...expected]);
      expect(selected(OBJECTIVE_GROUPS, target, trust)).toEqual([...expected]);
    }
  });

  test("structure-only and security-only objectives select different recipes", () => {
    expect(selected(["structure-and-maintainability"], wholeRepo)).toEqual(["lizard:complexity", "opengrep:hardcoded-values"]);
    expect(selected(["bounded-security-smells"], wholeRepo)).toEqual(["gitleaks:tracked-history", "opengrep:hardcoded-values"]);
    expect(selected(["bounded-security-smells"], files)).toEqual(["opengrep:hardcoded-values"]);
    expect(selected(["performance-and-efficiency"], wholeRepo)).toEqual([]);
  });

  test("recipes excluded by objectives are recorded as skipped with a reason", () => {
    const dispositions = selectSecurityAnalyzers({}, { target: wholeRepo, scopeMode: "full", objectives: ["structure-and-maintainability"] });
    const gitleaks = dispositions.find(({ name }) => name === "gitleaks:tracked-history");
    expect(gitleaks).toMatchObject({ disposition: "skipped" });
    expect(gitleaks?.reason).toContain("objective");
    expect(gitleaks?.reason).toContain("bounded-security-smells");
    expect(dispositions).toHaveLength(Object.keys(SNIFF_ANALYZER_RECIPES).length);
  });

  test("objective exclusion is reported before availability and scope gating", () => {
    const [disposition] = selectSecurityAnalyzers({ unavailable: ["lizard:complexity"], lightweightStatic: ["lizard:complexity"] }, { target: files, scopeMode: "plan-only", objectives: ["bounded-security-smells"] });
    expect(disposition?.disposition).toBe("skipped");
    expect(disposition?.reason).toContain("objective");
  });

  test("the manifest and its confirmation reflect the selected objectives", () => {
    const manifest = createRunManifest({ target: wholeRepo, intent: "audit", scopeMode: "full", objectives: ["bounded-security-smells"] });
    const request = canonicalConfirmationRequest(manifest);
    expect(request.analyzers.filter(({ disposition }) => disposition === "selected").map(({ name }) => name)).toEqual(["gitleaks:tracked-history", "opengrep:hardcoded-values"]);
    expect(request.analyzers.find(({ name }) => name === "lizard:complexity")).toMatchObject({ disposition: "skipped" });
    const all = canonicalConfirmationRequest(createRunManifest({ target: wholeRepo, intent: "audit", scopeMode: "full" }));
    expect(all.digest).not.toBe(request.digest);
  });

  test("recipes declare their objective groups and the catalog derives from them", () => {
    for (const [id, recipe] of Object.entries(SNIFF_ANALYZER_RECIPES)) {
      expect(recipe.objectives.length).toBeGreaterThan(0);
      for (const group of recipe.objectives) expect(OBJECTIVE_GROUPS).toContain(group);
      const entry = SECURITY_ANALYZER_CATALOG[id as keyof typeof SECURITY_ANALYZER_CATALOG];
      expect(entry as unknown).toEqual({ tool: recipe.tool, recipe: recipe.id, tier: recipe.tier, remoteSafe: recipe.remoteSafe });
    }
  });

  describe("unmet objectives are surfaced", () => {
    const gapObjectives = (manifest: ReturnType<typeof createRunManifest>) => manifest.gaps.filter(({ field }) => field === "objectives");

    test("an objective no recipe serves becomes a manifest gap that names it", () => {
      const manifest = createRunManifest({ target: wholeRepo, intent: "audit", scopeMode: "full", objectives: ["performance-and-efficiency"] });
      expect(manifest.analyzers.some(({ disposition }) => disposition === "selected")).toBe(false);
      const gaps = gapObjectives(manifest);
      expect(gaps).toHaveLength(1);
      expect(gaps[0]?.reason).toContain("performance-and-efficiency");
      expect(gaps[0]?.impact).toBe("medium");
    });

    test("served objectives have no gap, and all-but-served objectives each get one", () => {
      const served = createRunManifest({ target: wholeRepo, intent: "audit", scopeMode: "full", objectives: ["structure-and-maintainability", "bounded-security-smells"] });
      expect(gapObjectives(served)).toEqual([]);
      const all = createRunManifest({ target: wholeRepo, intent: "audit", scopeMode: "full" });
      const named = gapObjectives(all).map(({ reason }) => OBJECTIVE_GROUPS.filter((group) => reason.includes(group)));
      expect(named.flat().sort()).toEqual(["change-and-release-risk", "performance-and-efficiency", "tests-delivery-and-tooling"]);
    });

    test("an objective whose recipes are all skipped by scope or trust gets a gap with the reasons", () => {
      const quick = createRunManifest({ target: wholeRepo, intent: "audit", scopeMode: "quick", objectives: ["bounded-security-smells"] });
      expect(quick.analyzers.find(({ name }) => name === "opengrep:hardcoded-values")?.disposition).toBe("selected");
      expect(gapObjectives(quick)).toEqual([]);
      const planOnly = createRunManifest({ target: wholeRepo, intent: "plan-only", scopeMode: "plan-only", objectives: ["bounded-security-smells"] });
      const [gap] = gapObjectives(planOnly);
      expect(gap?.reason).toContain("bounded-security-smells");
      expect(gap?.reason).toContain("Plan-only");
    });

    test("the confirmation request, public summary and approval text show gaps and skipped reasons", () => {
      const manifest = createRunManifest({ target: wholeRepo, intent: "audit", scopeMode: "full", objectives: ["structure-and-maintainability", "performance-and-efficiency"] });
      const request = canonicalConfirmationRequest(manifest);
      const summary = publicConfirmationSummary(request);
      expect(summary.coverageGaps.map(({ field }) => field)).toEqual(["objectives"]);
      expect(summary.coverageGaps[0]?.reason).toContain("performance-and-efficiency");
      const skipped = summary.skippedAnalyzers.find(({ name }) => name === "gitleaks:tracked-history");
      expect(skipped?.reason).toContain("selected objectives");
      expect(summary.skippedAnalyzers.map(({ name }) => name)).not.toContain("lizard:complexity");
      expect(summary.skippedAnalyzers.map(({ name }) => name)).toContain("gitleaks:tracked-history");
      const text = intakeConfirmationText(request);
      expect(text).toContain("Coverage gaps:");
      expect(text).toContain("performance-and-efficiency");
    });

    test("validateRunManifest rejects a manifest that drops a derived objective gap", () => {
      const manifest = createRunManifest({ target: wholeRepo, intent: "audit", scopeMode: "full", objectives: ["performance-and-efficiency"] });
      expect(() => validateRunManifest(manifest)).not.toThrow();
      expect(() => validateRunManifest({ ...manifest, gaps: [] })).toThrow();
    });
  });
});
