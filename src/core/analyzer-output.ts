import { createHash } from "node:crypto";
import { existsSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

/** Maximum number of normalized observations retained from one analyzer run. */
export const ANALYZER_MAX_OBSERVATIONS = 2_000;
/** Maximum UTF-8 bytes retained for one projected observation field. */
const MAX_OBSERVATION_FIELD_BYTES = 8_192;

export type AnalyzerObservation = {
	readonly ruleId: string;
	readonly path: string;
	readonly start: { readonly line: number; readonly column: number };
	readonly message: string;
	readonly severity: string;
};

export type AnalyzerCapture = {
	readonly bytes: number;
	readonly truncated: boolean;
	readonly digest: string;
	readonly incomplete: boolean;
	readonly reason?: string;
};

export type AnalyzerParseResult = {
	readonly observations: readonly AnalyzerObservation[];
	readonly capture: AnalyzerCapture;
};

type ParseState = {
	readonly reasons: string[];
};

function capture(stdout: string, truncated: boolean, incomplete: boolean, reason?: string): AnalyzerCapture {
	const boundedReason = reason?.trim().slice(0, 512);
	return {
		bytes: Buffer.byteLength(stdout),
		truncated,
		digest: createHash("sha256").update(stdout).digest("hex"),
		incomplete,
		...(boundedReason ? { reason: boundedReason } : {}),
	};
}

function incompleteResult(stdout: string, truncated: boolean, reason: string): AnalyzerParseResult {
	return { observations: [], capture: capture(stdout, truncated, true, reason) };
}

/**
 * Merges the parse results of one sharded analyzer run. Each shard is parsed on its own, so a
 * shard-local header or malformed row can never corrupt a sibling shard. The merged digest chains
 * the shard digests, because no single stdout exists for a sharded run.
 */
export function mergeAnalyzerResults(results: readonly AnalyzerParseResult[]): AnalyzerParseResult {
	if (results.length === 1) return results[0] as AnalyzerParseResult;
	const observations: AnalyzerObservation[] = [];
	const state: ParseState = { reasons: [] };
	let capped = false;
	for (const result of results) {
		for (const observation of result.observations) {
			if (observations.length >= ANALYZER_MAX_OBSERVATIONS) {
				capped = true;
				break;
			}
			observations.push(observation);
		}
		if (result.capture.reason) addReason(state, result.capture.reason);
	}
	if (capped) addReason(state, `Analyzer observations exceeded the bounded limit of ${ANALYZER_MAX_OBSERVATIONS.toLocaleString("en-US")}`);
	const reason = state.reasons.join("; ");
	const digest = createHash("sha256");
	for (const result of results) digest.update(result.capture.digest);
	return {
		observations,
		capture: {
			bytes: results.reduce((total, result) => total + result.capture.bytes, 0),
			truncated: results.some((result) => result.capture.truncated),
			digest: digest.digest("hex"),
			incomplete: capped || results.some((result) => result.capture.incomplete),
			...(reason ? { reason: reason.slice(0, 512) } : {}),
		},
	};
}

function addReason(state: ParseState, reason: string): void {
	if (!state.reasons.includes(reason)) state.reasons.push(reason);
}

function field(value: unknown, state: ParseState, label: string): string | null {
	if (typeof value !== "string") {
		addReason(state, `Analyzer ${label} field was not a string`);
		return null;
	}
	if (value.includes("\0")) {
		addReason(state, `Analyzer ${label} field contained a NUL byte`);
		return null;
	}
	const trimmed = value.trim();
	if (Buffer.byteLength(trimmed) > MAX_OBSERVATION_FIELD_BYTES) {
		addReason(state, `Analyzer ${label} field exceeded the bounded projection size`);
		return null;
	}
	return trimmed;
}

function normalizePath(targetRoot: string, value: string): string | null {
	if (!value || value.includes("\0")) return null;
	const candidate = value.replaceAll("\\", "/");
	// Windows drive and UNC paths are not native paths on the supported hosts.
	// Treating one as a relative path would weaken the containment check.
	if (/^[A-Za-z]:\//.test(candidate) || candidate.startsWith("//")) return null;
	let root: string;
	try {
		root = realpathSync(resolve(targetRoot));
	} catch {
		return null;
	}
	const unresolved = isAbsolute(candidate) ? resolve(candidate) : resolve(root, candidate);
	let absolute = unresolved;
	try {
		if (existsSync(unresolved)) absolute = realpathSync(unresolved);
	} catch {
		return null;
	}
	const relativePath = relative(root, absolute);
	if (!relativePath || relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) return null;
	return relativePath.split(sep).join("/");
}

function integer(value: unknown, label: string, state: ParseState, minimum = 0): number | null {
	const number = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN;
	if (!Number.isSafeInteger(number) || number < minimum) {
		addReason(state, `Analyzer ${label} was not a valid integer`);
		return null;
	}
	return number;
}

function lizardSeverity(ccn: number, length: number, params: number): string {
	if (ccn > 20 || length > 100 || params > 10) return "HIGH";
	return "MEDIUM";
}

function parseCsv(stdout: string): { rows: string[][]; malformed: boolean } {
	const rows: string[][] = [];
	let row: string[] = [];
	let value = "";
	let quoted = false;
	let afterQuote = false;
	for (let index = 0; index < stdout.length; index += 1) {
		const character = stdout[index] ?? "";
		if (quoted) {
			if (character === '"') {
				if (stdout[index + 1] === '"') {
					value += '"';
					index += 1;
				} else {
					quoted = false;
					afterQuote = true;
				}
			} else {
				value += character;
			}
			continue;
		}
		if (afterQuote) {
			if (character === ",") {
				row.push(value);
				value = "";
				afterQuote = false;
				continue;
			}
			if (character === "\r" || character === "\n") {
				row.push(value);
				rows.push(row);
				row = [];
				value = "";
				afterQuote = false;
				if (character === "\r" && stdout[index + 1] === "\n") index += 1;
				continue;
			}
			return { rows: [], malformed: true };
		}
		if (character === '"' && value.length === 0) {
			quoted = true;
			continue;
		}
		if (character === ",") {
			row.push(value);
			value = "";
			continue;
		}
		if (character === "\r" || character === "\n") {
			row.push(value);
			rows.push(row);
			row = [];
			value = "";
			if (character === "\r" && stdout[index + 1] === "\n") index += 1;
			continue;
		}
		value += character;
	}
	if (quoted) return { rows: [], malformed: true };
	if (afterQuote || row.length > 0 || value.length > 0) {
		row.push(value);
		rows.push(row);
	}
	return { rows, malformed: false };
}

function nonBlankRows(rows: readonly string[][]): string[][] {
	return rows.filter((row) => row.some((value) => value.trim().length > 0));
}

export function parseLizardOutput(stdout: string, targetRoot: string, truncated = false, recipeId = "lizard:complexity"): AnalyzerParseResult {
	if (recipeId !== "lizard:complexity") return incompleteResult(stdout, truncated, `Unexpected Lizard recipe identity ${recipeId}`);
	if (truncated) return incompleteResult(stdout, true, "Lizard CSV exceeded the bounded capture limit");
	const parsed = parseCsv(stdout.replace(/^\uFEFF/, ""));
	if (parsed.malformed) return incompleteResult(stdout, false, "Lizard CSV was malformed or unterminated");
	const rows = nonBlankRows(parsed.rows);
	if (rows.length === 0) return incompleteResult(stdout, false, "Lizard CSV did not contain its header row");
	const firstRow = rows[0]?.map((value) => value.trim()) ?? [];
	const header = firstRow.map((value) => value.toLowerCase());
	const headerIndexes = {
		nloc: header.indexOf("nloc"),
		ccn: header.indexOf("ccn"),
		param: header.indexOf("param"),
		length: header.indexOf("length"),
		location: header.indexOf("location"),
		file: header.indexOf("file"),
		function: header.indexOf("function"),
	};
	const hasHeader = Object.values(headerIndexes).every((index) => index >= 0);
	const headerless = !hasHeader && firstRow.length === 11 && [0, 1, 3, 4, 9, 10].every((index) => /^\d+$/.test(firstRow[index] ?? ""));
	if (!hasHeader && !headerless) return incompleteResult(stdout, false, "Lizard CSV was missing one or more required columns");
	const indexes = hasHeader ? headerIndexes : { nloc: 0, ccn: 1, param: 3, length: 4, location: 9, file: 6, function: 7 };
	const dataRows = hasHeader ? rows.slice(1) : rows;
	const expectedColumns = hasHeader ? header.length : 11;
	const state: ParseState = { reasons: [] };
	const observations: AnalyzerObservation[] = [];
	for (const row of dataRows) {
		if (row.length !== expectedColumns) {
			addReason(state, "Lizard CSV contained a row with the wrong number of columns");
			continue;
		}
		const ccn = integer(row[indexes.ccn], "CCN", state);
		const nloc = integer(row[indexes.nloc], "NLOC", state);
		const params = integer(row[indexes.param], "parameter count", state);
		const length = integer(row[indexes.length], "length", state);
		const location = row[indexes.location]?.trim() ?? "";
		const locationMatch = /^(\d+)(?:-(\d+))?$/.exec(location);
		if (!locationMatch) addReason(state, "Lizard CSV contained an invalid function location");
		const line = locationMatch ? integer(locationMatch[1], "location", state, 1) : null;
		const pathValue = field(row[indexes.file], state, "file");
		const functionName = field(row[indexes.function], state, "function");
		if (ccn === null || nloc === null || params === null || length === null || line === null || !pathValue || functionName === null) continue;
		const path = normalizePath(targetRoot, pathValue);
		if (!path) {
			addReason(state, "Lizard finding path escaped the authorized target root");
			continue;
		}
		if (ccn <= 10 && length <= 50 && params <= 5) continue;
		if (observations.length >= ANALYZER_MAX_OBSERVATIONS) {
			addReason(state, `Lizard observations exceeded the bounded limit of ${ANALYZER_MAX_OBSERVATIONS.toLocaleString("en-US")}`);
			break;
		}
		const message = `${functionName || "<anonymous>"}: cyclomatic complexity ${ccn} (NLOC ${nloc}, ${params} parameters, ${length} lines)`;
		observations.push({ ruleId: recipeId, path, start: { line, column: 1 }, message, severity: lizardSeverity(ccn, length, params) });
	}
	const reason = state.reasons.length ? state.reasons.join("; ") : undefined;
	return { observations, capture: capture(stdout, false, Boolean(reason), reason) };
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function findingArray(payload: unknown): unknown[] | null {
	if (Array.isArray(payload)) return payload;
	if (!isRecord(payload) || !Array.isArray(payload.findings)) return null;
	return payload.findings;
}
export function parseGitleaksOutput(stdout: string, targetRoot: string, truncated = false, recipeId = "gitleaks:tracked-history"): AnalyzerParseResult {
	if (recipeId !== "gitleaks:tracked-history") return incompleteResult(stdout, truncated, `Unexpected Gitleaks recipe identity ${recipeId}`);
	if (truncated) return incompleteResult(stdout, true, "Gitleaks JSON exceeded the bounded capture limit");
	let payload: unknown;
	try {
		payload = JSON.parse(stdout.replace(/^\uFEFF/, ""));
	} catch {
		return incompleteResult(stdout, false, "Gitleaks JSON was malformed");
	}
	const findings = findingArray(payload);
	if (!findings) return incompleteResult(stdout, false, "Gitleaks JSON did not contain a findings array");
	const state: ParseState = { reasons: findings.length > ANALYZER_MAX_OBSERVATIONS ? [`Gitleaks observations exceeded the bounded limit of ${ANALYZER_MAX_OBSERVATIONS.toLocaleString("en-US")}`] : [] };
	const observations: AnalyzerObservation[] = [];
	for (const candidate of findings) {
		if (observations.length >= ANALYZER_MAX_OBSERVATIONS) break;
		if (!isRecord(candidate)) {
			addReason(state, "Gitleaks findings contained a non-object entry");
			continue;
		}
		const finding = candidate;
		const ruleId = field(finding.RuleID ?? finding.ruleId, state, "RuleID");
		const pathValue = field(finding.File ?? finding.file, state, "file");
		const line = integer(finding.StartLine ?? finding.startLine, "start line", state, 1);
		const column = integer(finding.StartColumn ?? finding.startColumn ?? 1, "start column", state, 1);
		const description = typeof finding.Description === "string" ? finding.Description : typeof finding.description === "string" ? finding.description : "";
		const sourceMessage = typeof finding.Message === "string" ? finding.Message : typeof finding.message === "string" ? finding.message : "";
		const message = field(description || sourceMessage || ruleId || "Gitleaks finding", state, "message");
		const severity = field(finding.Severity ?? finding.severity ?? "HIGH", state, "severity");
		if (!ruleId || !pathValue || line === null || column === null || !message || !severity) continue;
		const path = normalizePath(targetRoot, pathValue);
		if (!path) {
			addReason(state, "Gitleaks finding path escaped the authorized target root");
			continue;
		}
		observations.push({ ruleId, path, start: { line, column }, message, severity });
	}
	const reason = state.reasons.length ? state.reasons.join("; ") : undefined;
	return { observations, capture: capture(stdout, false, Boolean(reason), reason) };
}

export function parseAnalyzerOutput(tool: string, recipeId: string, stdout: string, targetRoot: string, truncated = false): AnalyzerParseResult {
	if (tool === "lizard" && recipeId === "lizard:complexity") return parseLizardOutput(stdout, targetRoot, truncated, recipeId);
	if (tool === "gitleaks" && recipeId === "gitleaks:tracked-history") return parseGitleaksOutput(stdout, targetRoot, truncated, recipeId);
	return incompleteResult(stdout, truncated, `No bounded parser is registered for analyzer recipe ${recipeId}`);
}
