import { SNIFF_ANALYZER_RECIPES } from "./analyzer-recipes.ts";
import type { ObjectiveGroup } from "./objectives.ts";
import type { SecurityAnalyzerDisposition } from "./security.ts";

export type ObjectiveCoverageGap = {
	readonly field: "objectives";
	readonly reason: string;
	readonly impact: "medium";
};

/**
 * One gap per selected objective that no selected analyzer serves: either the catalog has no recipe
 * for it, or every recipe that serves it was skipped or unavailable. Pure and derived from the
 * plan, so a validator can recompute it.
 */
export function objectiveCoverageGaps(objectives: readonly ObjectiveGroup[], analyzers: readonly Pick<SecurityAnalyzerDisposition, "name" | "disposition" | "reason">[]): ObjectiveCoverageGap[] {
	const recipes = Object.values(SNIFF_ANALYZER_RECIPES);
	const gaps: ObjectiveCoverageGap[] = [];
	for (const group of objectives) {
		const serving = recipes.filter((recipe) => recipe.objectives.includes(group));
		const dispositions = analyzers.filter((analyzer) => serving.some((recipe) => recipe.id === analyzer.name));
		if (dispositions.some(({ disposition }) => disposition === "selected")) continue;
		const reason = serving.length === 0
			? `Objective ${group} is requested but no Sniff analyzer recipe serves it, so no automated analysis covers it.`
			: `Objective ${group} is requested but no runnable analyzer serves it: ${dispositions.map(({ name, disposition, reason: why }) => `${name} ${disposition} (${why})`).join("; ")}`;
		gaps.push({ field: "objectives", reason, impact: "medium" });
	}
	return gaps;
}
