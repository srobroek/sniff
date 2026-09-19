import rawRecipes from "./analyzer-recipes.json";
import { OPENGREP_FILE_EXTENSIONS, TOOLS, type ToolRec } from "./catalog.ts";

export type AnalyzerOutput = "sarif" | "lizard-csv" | "gitleaks-json" | "opengrep-json";

export type SniffAnalyzerRecipe = {
	readonly id: string;
	readonly tool: string;
	readonly tier: "project-native" | "lightweight-static" | "deep-static";
	readonly args: readonly string[];
	readonly scope: "scoped-files" | "bounded-history" | "repository-wide";
	readonly fileExtensions?: readonly string[];
	readonly targetSeparator?: readonly string[];
	readonly acceptedExitCodes: readonly number[];
	readonly remoteSafe: boolean;
	readonly configFree: boolean;
	readonly projectControlled: boolean;
	readonly output: AnalyzerOutput;
};

const toolRecords = new Map<string, ToolRec>();
for (const bundle of Object.values(TOOLS)) {
	for (const tool of bundle) toolRecords.set(tool.name, tool);
}

const recipes: Record<string, unknown> = rawRecipes;
const seenIds = new Set<string>();
const outputs = new Set<AnalyzerOutput>(["sarif", "lizard-csv", "gitleaks-json", "opengrep-json"]);

function loadRecipe(key: string, value: unknown): SniffAnalyzerRecipe {
	if (!value || typeof value !== "object") throw new Error(`Analyzer recipe ${key} must be an object`);
	const recipe = value as Record<string, unknown>;
	const id = recipe.id;
	if (typeof id !== "string" || !id) throw new Error(`Analyzer recipe ${key} is missing id`);
	if (seenIds.has(id)) throw new Error(`Duplicate analyzer recipe id ${id}`);
	seenIds.add(id);
	if (typeof recipe.tool !== "string" || !toolRecords.has(recipe.tool)) throw new Error(`Analyzer recipe ${id} references unknown tool ${String(recipe.tool)}`);
	const tool = toolRecords.get(recipe.tool);
	if (tool?.key === "npm-local") throw new Error(`Analyzer recipe ${id} cannot use project-local tool ${recipe.tool}`);
	if (!Array.isArray(recipe.acceptedExitCodes)) throw new Error(`Analyzer recipe ${id} is missing acceptedExitCodes`);
	if (typeof recipe.output !== "string" || !outputs.has(recipe.output as AnalyzerOutput)) throw new Error(`Analyzer recipe ${id} has unknown output ${String(recipe.output)}`);
	if (!Array.isArray(recipe.args) || typeof recipe.tier !== "string" || typeof recipe.scope !== "string") throw new Error(`Analyzer recipe ${id} is malformed`);
	const args = recipe.args.map((arg) => {
		if (typeof arg !== "string") throw new Error(`Analyzer recipe ${id} has a non-string argument`);
		return arg === "@opengrep-rule-file" ? `${import.meta.dir}/sniff-opengrep-hardcoded-values.yml` : arg;
	});
	const fileExtensions = recipe.fileExtensions === "@opengrep-extensions" ? OPENGREP_FILE_EXTENSIONS : recipe.fileExtensions;
	return {
		...recipe,
		id,
		tool: recipe.tool,
		tier: recipe.tier as SniffAnalyzerRecipe["tier"],
		args,
		scope: recipe.scope as SniffAnalyzerRecipe["scope"],
		fileExtensions: Array.isArray(fileExtensions) ? fileExtensions.filter((item): item is string => typeof item === "string") : undefined,
		targetSeparator: Array.isArray(recipe.targetSeparator) ? recipe.targetSeparator.filter((item): item is string => typeof item === "string") : undefined,
		acceptedExitCodes: recipe.acceptedExitCodes.filter((item): item is number => typeof item === "number"),
		remoteSafe: recipe.remoteSafe === true,
		configFree: recipe.configFree === true,
		projectControlled: recipe.projectControlled === true,
		output: recipe.output as AnalyzerOutput,
	};
}

export const SNIFF_ANALYZER_RECIPES = Object.fromEntries(Object.entries(recipes).map(([key, value]) => [key, loadRecipe(key, value)])) as Record<string, SniffAnalyzerRecipe>;
export type SniffAnalyzerRecipeId = keyof typeof SNIFF_ANALYZER_RECIPES;
