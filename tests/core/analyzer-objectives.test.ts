import { describe, expect, test } from "bun:test";
import { SNIFF_ANALYZER_RECIPES } from "../../src/core/analyzer-recipes.ts";
import { canonicalConfirmationRequest, createRunManifest } from "../../src/core/intake.ts";
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
});
