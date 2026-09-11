import {
  buildNoninteractiveManifest,
  createRunManifest,
  decisionFrontier,
  type IntakeAuthority,
  type IntakeInput,
  type IntakeInterview,
  type RunManifest,
} from "./intake.ts";
import { cancelRunLease, issueRunLease, type RunLeaseReceipt } from "./run-registry.ts";
import { resolveTargetLease } from "./target-provider.ts";
import { type ArgvRunner, runArgv } from "./target.ts";

export type SniffIntakeToolOptions = {
  readonly input: IntakeInput;
};

export type SniffIntakeToolResult = {
  readonly interview: IntakeInterview;
  readonly manifest?: RunManifest;
  readonly lease?: RunLeaseReceipt;
};

export type SniffIntakeRuntime = {
  readonly runner?: ArgvRunner;
  readonly confirmInteractive?: (summary: Readonly<{ target: string; files: number }>) => Promise<boolean>;
  readonly authority?: IntakeAuthority;
  readonly leaseTtlMs?: number;
  readonly sandboxGrant?: string;
};

type SniffIntakeToolDetails = {
  readonly ok: boolean;
  readonly result?: SniffIntakeToolResult;
  readonly error?: string;
};

const INTAKE_INTENTS: Record<string, true> = {
  audit: true,
  "review-change": true,
  "release-risk": true,
  history: true,
  "plan-only": true,
};

function stringArray(value: unknown, field: string): readonly string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) throw new Error(`${field} must be an array of strings`);
  return value;
}

export function intakeInput(value: unknown): IntakeInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("sniff_intake input must be an object");
  const record = value as Record<string, unknown>;
  if (record.intent !== undefined && (typeof record.intent !== "string" || !INTAKE_INTENTS[record.intent])) throw new Error("sniff_intake intent is invalid");
  if (record.target !== undefined && (!record.target || typeof record.target !== "object" || Array.isArray(record.target))) throw new Error("sniff_intake target must be an object");
  if (record.budget !== undefined && (!record.budget || typeof record.budget !== "object" || Array.isArray(record.budget))) throw new Error("sniff_intake budget must be an object");
  if (record.security !== undefined && (!record.security || typeof record.security !== "object" || Array.isArray(record.security))) throw new Error("sniff_intake security must be an object");
  stringArray(record.objectives, "objectives");
  stringArray(record.exclusions, "exclusions");
  return structuredClone(record) as IntakeInput;
}
export async function runSniffIntakeTool(options: SniffIntakeToolOptions, runtime: SniffIntakeRuntime = {}): Promise<SniffIntakeToolResult> {
  if (options.input.authorization) throw new Error("Caller-provided authorization is not a trusted confirmation receipt");
  const noninteractive = options.input.interactive === false;
  let interview: IntakeInterview;
  let targetRequest: NonNullable<IntakeInput["target"]>;
  let intent: NonNullable<IntakeInput["intent"]>;
  let objectives: IntakeInput["objectives"];
  let exclusions: IntakeInput["exclusions"];
  let security: IntakeInput["security"];
  let budget: IntakeInput["budget"];
  if (noninteractive) {
    if (!options.input.target || !options.input.intent) return { interview: decisionFrontier(options.input) };
    interview = { questions: [], confirmationRequired: false };
    targetRequest = options.input.target;
    intent = options.input.intent;
    objectives = options.input.objectives;
    exclusions = options.input.exclusions;
    security = options.input.security;
    budget = options.input.budget;
  } else {
    interview = decisionFrontier(options.input);
    if (!interview.plan) return { interview };
    targetRequest = interview.plan.target;
    intent = interview.plan.intent;
    objectives = interview.plan.objectives;
    exclusions = interview.plan.exclusions;
    security = interview.plan.security;
    budget = interview.plan.budget;
  }
  const targetLease = await resolveTargetLease(targetRequest, runtime.runner ?? runArgv);
  try {
    const target = targetLease.target;
    const manifest = noninteractive
      ? await buildNoninteractiveManifest({ target, intent, objectives, exclusions, security, budget, route: { provider: target.repository } }, runtime.authority)
      : await (async () => {
          if (!runtime.confirmInteractive) throw new Error("Interactive intake requires the trusted UI confirmation boundary");
          const confirmed = await runtime.confirmInteractive({ target: target.label, files: target.files.length });
          if (!confirmed) throw new Error("Interactive intake confirmation was denied");
          return createRunManifest({ target, intent, objectives, exclusions, security, budget, confirmation: { confirmed: true }, route: { provider: target.repository } });
        })();
    const lease = issueRunLease(manifest, targetLease, { ttlMs: runtime.leaseTtlMs, sandboxGrant: runtime.sandboxGrant });
    return { interview, manifest, lease };
  } catch (error) {
    targetLease.release();
    throw error;
  }
}

