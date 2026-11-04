import { extname } from "node:path";
import { SNIFF_ANALYZER_RECIPES, type SniffAnalyzerRecipe, type SniffAnalyzerRecipeId, type SniffAnalyzerTier } from "./analyzer-recipes.ts";
import type { ObjectiveGroup } from "./objectives.ts";
import type { ResolvedTarget } from "./target.ts";

export type SecurityAnalyzerTier = SniffAnalyzerTier;
export type TargetTrust = "trusted-local" | "untrusted-remote";

export type SecurityAnalyzerDisposition = {
  readonly name: SniffAnalyzerRecipeId;
  readonly tool: string;
  readonly recipe: SniffAnalyzerRecipeId;
  readonly tier: SecurityAnalyzerTier;
  readonly disposition: "selected" | "skipped" | "unavailable";
  readonly reason: string;
  readonly version?: string;
};

export type SecurityRequest = {
  readonly deepStatic?: boolean;
  readonly unavailable?: readonly string[];
  readonly projectNative?: readonly string[];
  readonly lightweightStatic?: readonly string[];
  readonly deepStaticAnalyzers?: readonly string[];
  readonly requestedActions?: readonly string[];
};

export type AnalyzerSelectionContext = {
  readonly trust?: TargetTrust;
  readonly target?: ResolvedTarget;
  readonly scopeMode?: "quick" | "full" | "plan-only";
  /** The selected objective groups; a recipe that serves none of them is skipped. Omitted means every group. */
  readonly objectives?: readonly ObjectiveGroup[];
};

export class SecurityScopeError extends Error {
  readonly action: string;

  constructor(action: string) {
    super(`Security scope rejects ${action}; Sniff permits allowlisted static checks only.`);
    this.name = "SecurityScopeError";
    this.action = action;
  }
}

type AnalyzerCatalogEntry = {
  readonly tool: string;
  readonly recipe: SniffAnalyzerRecipeId;
  readonly tier: SecurityAnalyzerTier;
  readonly remoteSafe: boolean;
};

function recipeFor(name: SniffAnalyzerRecipeId): SniffAnalyzerRecipe {
  const recipe = SNIFF_ANALYZER_RECIPES[name];
  if (!recipe) throw new Error(`Unknown analyzer recipe ${name}`);
  return recipe;
}

// Tool, tier, and remote safety live in the recipe data only; this view just indexes them.
export const SECURITY_ANALYZER_CATALOG = Object.fromEntries(
  Object.values(SNIFF_ANALYZER_RECIPES).map((recipe) => [recipe.id, { tool: recipe.tool, recipe: recipe.id, tier: recipe.tier, remoteSafe: recipe.remoteSafe }]),
) as { readonly [K in SniffAnalyzerRecipeId]: AnalyzerCatalogEntry };

const FORBIDDEN_ALIAS: Record<string, string> = {
  dast: "DAST",
  dynamicapplicationsecuritytest: "DAST",
  dynamicapplicationsecuritytesting: "DAST",
  exploit: "exploitation",
  exploitation: "exploitation",
  fuzz: "fuzzing",
  fuzzer: "fuzzing",
  fuzzing: "fuzzing",
  livesecretvalidation: "live-secret validation",
  threatcampaign: "threat campaigns",
  threatcampaigns: "threat campaigns",
};

function defaultRecipes(tier: SecurityAnalyzerTier): SniffAnalyzerRecipeId[] {
  return Object.values(SNIFF_ANALYZER_RECIPES)
    .filter((recipe) => recipe.tier === tier && recipe.defaultEnabled)
    .map((recipe) => recipe.id as SniffAnalyzerRecipeId);
}

/** Why the selected objectives leave this recipe out, or undefined when it serves one of them. */
function objectiveExclusion(name: SniffAnalyzerRecipeId, objectives: readonly ObjectiveGroup[] | undefined): string | undefined {
  if (!objectives) return undefined;
  const serves = recipeFor(name).objectives;
  if (serves.some((group) => objectives.includes(group))) return undefined;
  return `Not needed by the selected objectives; this recipe serves ${serves.join(", ")}.`;
}

function normalizedAlias(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9]/g, "");
}

function validateAnalyzerName(name: string, tier?: SecurityAnalyzerTier): keyof typeof SECURITY_ANALYZER_CATALOG {
  const forbidden = FORBIDDEN_ALIAS[normalizedAlias(name)];
  if (forbidden) throw new SecurityScopeError(forbidden);
  if (!(name in SECURITY_ANALYZER_CATALOG)) throw new SecurityScopeError(`unknown analyzer ${name}`);
  const catalogName = name as keyof typeof SECURITY_ANALYZER_CATALOG;
  if (tier && SECURITY_ANALYZER_CATALOG[catalogName].tier !== tier) throw new SecurityScopeError(`analyzer ${name} in the wrong tier`);
  return catalogName;
}

function checkedNames(names: readonly string[], tier: SecurityAnalyzerTier): Array<keyof typeof SECURITY_ANALYZER_CATALOG> {
  return [...new Set(names.map((name) => validateAnalyzerName(name, tier)))].sort();
}

function scopeCompatibility(name: SniffAnalyzerRecipeId, target: ResolvedTarget | undefined): string | undefined {
  if (!target) return undefined;
  const recipe = recipeFor(name);
  if (recipe.scope === "repository-wide") {
    // A history target is a repository-wide walk bounded by its window; trust gating happens at authorization.
    return target.kind === "repository" || target.kind === "whole-repo" || target.kind === "history" ? undefined : "Analyzer requires an explicitly repository-wide target.";
  }
  if (target.files.length === 0) return "Exact target contains no analyzable files; scope was not widened.";
  if (recipe.fileExtensions && !target.files.some((file) => recipe.fileExtensions?.includes(extname(file).toLowerCase()))) {
    return "Analyzer does not support the target's detected file types.";
  }
  return undefined;
}

export function selectSecurityAnalyzers(request: SecurityRequest = {}, context: AnalyzerSelectionContext = {}): SecurityAnalyzerDisposition[] {
  for (const action of request.requestedActions ?? []) {
    const forbidden = FORBIDDEN_ALIAS[normalizedAlias(action)];
    if (forbidden) throw new SecurityScopeError(forbidden);
  }
  const unavailableNames = (request.unavailable ?? []).map((name) => validateAnalyzerName(name));
  const unavailable = new Set(unavailableNames);
  const projectNative = checkedNames(request.projectNative ?? defaultRecipes("project-native"), "project-native");
  const lightweight = checkedNames(request.lightweightStatic ?? defaultRecipes("lightweight-static"), "lightweight-static");
  const deep = checkedNames(request.deepStaticAnalyzers ?? defaultRecipes("deep-static"), "deep-static");
  const trust = context.trust ?? "trusted-local";
  const dispositions: SecurityAnalyzerDisposition[] = [];

  for (const name of projectNative) {
    const absent = unavailable.has(name);
    const unserved = objectiveExclusion(name, context.objectives);
    const selected = !unserved && trust === "trusted-local" && !absent;
    dispositions.push({
      name,
      tool: SECURITY_ANALYZER_CATALOG[name].tool,
      recipe: SECURITY_ANALYZER_CATALOG[name].recipe,
      tier: "project-native",
      disposition: unserved ? "skipped" : absent ? "unavailable" : selected ? "selected" : "skipped",
      reason: unserved
        ? unserved
        : absent
        ? "Analyzer is unavailable in the target environment."
        : selected
          ? "Trusted local targets may use repository configuration."
          : "Untrusted remote targets cannot execute repository configuration.",
    });
  }
  for (const name of lightweight) {
    const absent = unavailable.has(name);
    const unserved = objectiveExclusion(name, context.objectives);
    const incompatible = scopeCompatibility(name, context.target);
    const remoteBlocked = trust === "untrusted-remote" && !SECURITY_ANALYZER_CATALOG[name].remoteSafe;
    const scopeBlocked = context.scopeMode === "plan-only" ? "Plan-only mode does not execute analyzers." : context.scopeMode === "quick" && name === "gitleaks:tracked-history" ? "Quick mode omits bounded-history coverage." : undefined;
    dispositions.push({
      name,
      tool: SECURITY_ANALYZER_CATALOG[name].tool,
      recipe: SECURITY_ANALYZER_CATALOG[name].recipe,
      tier: "lightweight-static",
      disposition: unserved ? "skipped" : absent ? "unavailable" : scopeBlocked || incompatible || remoteBlocked ? "skipped" : "selected",
      reason: unserved ?? (absent ? "Analyzer is unavailable in the target environment." : scopeBlocked ?? incompatible ?? (remoteBlocked ? "Untrusted remote targets cannot use target-controlled analyzer configuration." : "Config-free offline static coverage is enabled.")),
    });
  }
  for (const name of deep) {
    const absent = unavailable.has(name);
    const unserved = objectiveExclusion(name, context.objectives);
    const remoteBlocked = trust === "untrusted-remote" && !SECURITY_ANALYZER_CATALOG[name].remoteSafe;
    const scopeBlocked = context.scopeMode === "plan-only" ? "Plan-only mode does not execute analyzers." : undefined;
    const selected = !unserved && request.deepStatic === true && !absent && !remoteBlocked && !scopeBlocked;
    dispositions.push({
      name,
      tool: SECURITY_ANALYZER_CATALOG[name].tool,
      recipe: SECURITY_ANALYZER_CATALOG[name].recipe,
      tier: "deep-static",
      disposition: unserved ? "skipped" : absent ? "unavailable" : selected ? "selected" : "skipped",
      reason: unserved ?? (absent ? "Analyzer is unavailable in the target environment." : scopeBlocked ? scopeBlocked : remoteBlocked ? "Untrusted remote targets require a separate sandboxed code-execution grant." : selected ? "Explicit deep-static opt-in was recorded for a trusted target." : "Deep static analysis requires explicit opt-in."),
    });
  }
  return dispositions.sort((left, right) => left.tier.localeCompare(right.tier) || left.name.localeCompare(right.name));
}

export function validateAnalyzerDispositions(dispositions: readonly SecurityAnalyzerDisposition[], trust: TargetTrust): void {
  const seen = new Set<string>();
  for (const analyzer of dispositions) {
    const name = validateAnalyzerName(analyzer.name, analyzer.tier);
    if (seen.has(name)) throw new SecurityScopeError(`duplicate analyzer ${name}`);
    seen.add(name);
    const catalog = SECURITY_ANALYZER_CATALOG[name];
    if (analyzer.tool !== catalog.tool || analyzer.recipe !== catalog.recipe) throw new SecurityScopeError(`forged analyzer mapping ${name}`);
    if (trust === "untrusted-remote" && analyzer.disposition === "selected" && !SECURITY_ANALYZER_CATALOG[name].remoteSafe) {
      throw new SecurityScopeError(`remote analyzer ${name}`);
    }
  }
}

export function securityExclusions(): readonly string[] {
  return ["DAST", "exploitation", "fuzzing", "live-secret validation", "threat campaigns"];
}
