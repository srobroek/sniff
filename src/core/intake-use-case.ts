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
export type SniffIntakeToolResult = {
	readonly interview: IntakeInterview;
	readonly confirmation?: CanonicalConfirmationRequest;
	readonly manifest?: RunManifest;
	readonly lease?: RunLeaseReceipt;
};
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
			return { interview, confirmation: canonicalConfirmationRequest(manifest), manifest, lease };
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
		return { interview, confirmation: canonicalConfirmationRequest(manifest), manifest, lease };
	} catch (error) {
		targetLease.release();
		throw error;
	}
}
