import { basename } from "node:path";
import {
	buildNoninteractiveManifest,
	canonicalConfirmationRequest,
	createRunManifest,
	decisionFrontier,
	type CanonicalConfirmationRequest,
	type IntakeAuthority,
	type IntakeInput,
	type IntakeInterview,
	type RunManifest,
	type ScopeMode,
} from "./intake.ts";
import { issueRunLease, type RunLeaseReceipt } from "./run-registry.ts";
import { resolveTargetLease } from "./target-provider.ts";
import { type ArgvRunner, runArgv } from "./target.ts";

export type SniffIntakeToolOptions = { readonly input: IntakeInput };
const REPORT_KIND_BY_TARGET = {
	"whole-repo": "whole-repo", "working-tree": "uncommitted", files: "files", directory: "directory", module: "area", commit: "commit", range: "range", branch: "branch", ref: "ref", repository: "repository", release: "release", history: "history", pr: "pr", mr: "mr",
} as const satisfies Record<RunManifest["resolvedTarget"]["kind"], string>;

const REPORT_LABEL_BY_TARGET: Record<RunManifest["resolvedTarget"]["kind"], string> = {
	"whole-repo": "whole repository", "working-tree": "uncommitted changes", files: "selected files", directory: "selected directory", module: "selected area", commit: "selected commit", range: "selected range", branch: "selected branch", ref: "selected ref", repository: "selected repository", release: "selected release", history: "repository history", pr: "selected pull request", mr: "selected merge request",
};

export type SniffReportTargetIdentity = {
	readonly kind: (typeof REPORT_KIND_BY_TARGET)[RunManifest["resolvedTarget"]["kind"]];
	readonly label: string;
	readonly scopeMode: ScopeMode;
	readonly baseRef?: string;
	readonly filesAnalyzed: number;
};

export function canonicalReportTargetIdentity(target: RunManifest["resolvedTarget"], scopeMode: ScopeMode): SniffReportTargetIdentity {
	return {
		kind: REPORT_KIND_BY_TARGET[target.kind],
		label: REPORT_LABEL_BY_TARGET[target.kind],
		scopeMode,
		...(target.baseRef ? { baseRef: target.baseRef } : {}),
		filesAnalyzed: target.files.length,
	};
}

export type SniffIntakeConfirmationSummary = {
	readonly digest: string;
	readonly target: SniffReportTargetIdentity;
	readonly intent: CanonicalConfirmationRequest["intent"];
	readonly scopeMode: CanonicalConfirmationRequest["scopeMode"];
	readonly trust: CanonicalConfirmationRequest["trust"];
	readonly materialization: CanonicalConfirmationRequest["materialization"];
	readonly objectiveCount: number;
	readonly exclusionCount: number;
	readonly analyzerCount: number;
	readonly selectedAnalyzers: readonly {
		readonly name: string;
		readonly tool: string;
		readonly recipe: string;
		readonly disposition: "selected";
	}[];
};
export type SniffIntakeToolResult = {
	readonly interview: IntakeInterview;
	readonly confirmation?: SniffIntakeConfirmationSummary;
	readonly manifest?: RunManifest;
	readonly lease?: RunLeaseReceipt;
};
export type SniffIntakePlanSummary = {
	readonly target: { readonly kind: string; readonly rootBasename?: string };
	readonly intent: NonNullable<IntakeInterview["plan"]>["intent"];
	readonly scopeMode: ScopeMode;
	readonly objectiveCount: number;
	readonly exclusionCount: number;
	readonly budget: { readonly maxMinutes?: number; readonly maxAnalyzers?: number; readonly maxFiles?: number };
};
export type SniffIntakePublicInterview = Omit<IntakeInterview, "plan"> & { readonly planSummary?: SniffIntakePlanSummary };
export type SniffIntakePublicResult = Omit<SniffIntakeToolResult, "manifest" | "interview"> & { readonly interview: SniffIntakePublicInterview; readonly reportTarget?: SniffReportTargetIdentity };

function publicPlanSummary(plan: NonNullable<IntakeInterview["plan"]>): SniffIntakePlanSummary {
	const target = plan.target;
	const root = "root" in target ? target.root : "rootOrRepository" in target ? target.rootOrRepository : undefined;
	return {
		target: { kind: target.kind, ...(root ? { rootBasename: basename(root).slice(0, 256) } : {}) },
		intent: plan.intent,
		scopeMode: plan.scopeMode,
		objectiveCount: plan.objectives.length,
		exclusionCount: plan.exclusions.length,
		budget: { ...plan.budget },
	};
}

export function publicSniffIntakeResult(result: SniffIntakeToolResult): SniffIntakePublicResult {
	const { manifest, interview, ...publicResult } = result;
	const { plan, ...boundedInterview } = interview;
	const reportTarget = manifest ? canonicalReportTargetIdentity(manifest.resolvedTarget, manifest.scopeMode) : undefined;
	return { ...publicResult, interview: { ...boundedInterview, ...(plan ? { planSummary: publicPlanSummary(plan) } : {}) }, ...(reportTarget ? { reportTarget } : {}) };
}
export function publicConfirmationSummary(request: CanonicalConfirmationRequest): SniffIntakeConfirmationSummary {
	return {
		digest: request.digest,
		target: canonicalReportTargetIdentity(request.target, request.scopeMode),
		intent: request.intent,
		scopeMode: request.scopeMode,
		trust: request.trust,
		materialization: request.materialization,
		objectiveCount: request.objectives.length,
		exclusionCount: request.exclusions.length,
		analyzerCount: request.analyzers.length,
		selectedAnalyzers: request.analyzers.flatMap((analyzer) =>
			analyzer.disposition === "selected"
				? [{ name: analyzer.name, tool: analyzer.tool, recipe: analyzer.recipe, disposition: "selected" as const }]
				: [],
		),
	};
}
export type ConfirmationResponse = false | {
	readonly acceptedDigest: string;
	readonly actor?: string;
	readonly reason?: string;
};
export type SniffIntakeRuntime = {
	readonly runner?: ArgvRunner;
	readonly confirmInteractive?: (request: CanonicalConfirmationRequest) => Promise<ConfirmationResponse>;
	readonly authority?: IntakeAuthority;
	readonly leaseTtlMs?: number;
	readonly sandboxGrant?: string;
};
const INTAKE_INTENTS: Record<string, true> = {
	audit: true,
	"review-change": true,
	"release-risk": true,
	history: true,
	"plan-only": true,
};
const SCOPE_MODES: Record<string, true> = { quick: true, full: true, "plan-only": true };

function stringArray(value: unknown, field: string): readonly string[] | undefined {
	if (value === undefined) return undefined;
	if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
		throw new Error(`${field} must be an array of strings`);
	}
	return value;
}

export function intakeInput(value: unknown): IntakeInput {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("sniff_intake input must be an object");
	}
	const record = value as Record<string, unknown>;
	if (record.intent !== undefined && (typeof record.intent !== "string" || !INTAKE_INTENTS[record.intent])) {
		throw new Error("sniff_intake intent is invalid");
	}
	if (record.scopeMode !== undefined && (typeof record.scopeMode !== "string" || !SCOPE_MODES[record.scopeMode])) {
		throw new Error("sniff_intake scopeMode is invalid");
	}
	if (record.target !== undefined && (!record.target || typeof record.target !== "object" || Array.isArray(record.target))) {
		throw new Error("sniff_intake target must be an object");
	}
	if (record.budget !== undefined && (!record.budget || typeof record.budget !== "object" || Array.isArray(record.budget))) {
		throw new Error("sniff_intake budget must be an object");
	}
	stringArray(record.objectives, "objectives");
	stringArray(record.exclusions, "exclusions");
	return structuredClone(record) as IntakeInput;
}

export async function runSniffIntakeTool(
	options: SniffIntakeToolOptions,
	runtime: SniffIntakeRuntime = {},
): Promise<SniffIntakeToolResult> {
	if (options.input.authorization) throw new Error("Caller-provided authorization is not a trusted confirmation receipt");
	const noninteractive = options.input.interactive === false;
	const input = options.input;
	let interview: IntakeInterview;
	let targetRequest: NonNullable<IntakeInput["target"]>;
	let intent: NonNullable<IntakeInput["intent"]>;
	let scopeMode: ScopeMode;
	let objectives: IntakeInput["objectives"];
	let exclusions: IntakeInput["exclusions"];
	let security: IntakeInput["security"];
	let budget: IntakeInput["budget"];

	if (noninteractive) {
		if (!input.target || !input.intent) return { interview: decisionFrontier(input) };
		interview = { questions: [], confirmationRequired: false };
		targetRequest = input.target;
		intent = input.intent;
		scopeMode = input.scopeMode ?? "full";
		objectives = input.objectives;
		exclusions = input.exclusions;
		security = input.security;
		budget = input.budget;
	} else {
		interview = decisionFrontier(input);
		if (!interview.plan) return { interview };
		targetRequest = interview.plan.target;
		intent = interview.plan.intent;
		scopeMode = interview.plan.scopeMode;
		objectives = interview.plan.objectives;
		exclusions = interview.plan.exclusions;
		security = interview.plan.security;
		budget = interview.plan.budget;
	}

	const targetLease = await resolveTargetLease(targetRequest, runtime.runner ?? runArgv);
	try {
		const target = targetLease.target;
		const common = {
			target,
			intent,
			scopeMode,
			objectives,
			exclusions,
			security,
			budget,
			route: { provider: target.repository },
		};
		if (noninteractive) {
			if (!runtime.authority) throw new Error("Noninteractive intake requires the trusted confirmation boundary");
			const manifest = await buildNoninteractiveManifest(common, runtime.authority);
			const lease = issueRunLease(manifest, targetLease, {
				ttlMs: runtime.leaseTtlMs,
				sandboxGrant: runtime.sandboxGrant,
			});
			return { interview, confirmation: publicConfirmationSummary(canonicalConfirmationRequest(manifest)), manifest, lease };
		}
		if (!runtime.confirmInteractive) throw new Error("Interactive intake requires the trusted UI confirmation boundary");
		const provisional = createRunManifest({ ...common, confirmation: undefined });
		const request = canonicalConfirmationRequest(provisional);
		const accepted = await runtime.confirmInteractive(request);
		if (!accepted || accepted.acceptedDigest !== request.digest) {
			throw new Error(accepted ? "Trusted confirmation digest does not match the resolved intake plan" : "Interactive intake confirmation was denied");
		}
		const manifest = createRunManifest({ ...common, confirmation: accepted });
		const lease = issueRunLease(manifest, targetLease, {
			ttlMs: runtime.leaseTtlMs,
			sandboxGrant: runtime.sandboxGrant,
		});
		return { interview, confirmation: publicConfirmationSummary(canonicalConfirmationRequest(manifest)), manifest, lease };
	} catch (error) {
		targetLease.release();
		throw error;
	}
}
