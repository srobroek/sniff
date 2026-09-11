import { createHash } from "node:crypto";
import { OBJECTIVE_GROUPS, type ObjectiveGroup, selectObjectiveGroups } from "./sniff-intake-objectives.ts";
import {
  type SecurityAnalyzerDisposition,
  type SecurityRequest,
  securityExclusions,
  selectSecurityAnalyzers,
  type TargetTrust,
  validateAnalyzerDispositions,
} from "./sniff-intake-security.ts";
import { type ResolvedTarget, type TargetRequest, validateRepository } from "./sniff-target.ts";

export type IntakeIntent = "audit" | "review-change" | "release-risk" | "history" | "plan-only";

export type IntakeBudget = {
  readonly maxMinutes?: number;
  readonly maxAnalyzers?: number;
  readonly maxFiles?: number;
};

export type IntakeAuthorization = {
  readonly granted: true;
  readonly actor?: string;
  readonly reason?: string;
};

export type IntakeInput = {
  readonly target?: TargetRequest;
  readonly intent?: IntakeIntent;
  readonly objectives?: readonly string[];
  readonly exclusions?: readonly string[];
  readonly budget?: IntakeBudget;
  readonly security?: SecurityRequest;
  readonly interactive?: boolean;
  readonly authorization?: IntakeAuthorization;
  readonly confirmation?: { readonly confirmed: boolean; readonly actor?: string };
};

export type IntakeQuestionId = "target" | "intent" | "objectives" | "budget";

export type IntakeQuestion = {
  readonly id: IntakeQuestionId;
  readonly impact: number;
  readonly prompt: string;
  readonly reason: string;
};

export type IntakePlan = {
  readonly target: TargetRequest;
  readonly intent: IntakeIntent;
  readonly objectives: readonly ObjectiveGroup[];
  readonly exclusions: readonly string[];
  readonly budget: IntakeBudget;
  readonly security: SecurityRequest;
};

export type IntakeInterview = {
  readonly questions: readonly IntakeQuestion[];
  readonly plan?: IntakePlan;
  readonly confirmationRequired: boolean;
};

export type AppliedDefault = {
  readonly field: string;
  readonly value: unknown;
  readonly reason: string;
};

export type IntakeGap = {
  readonly field: string;
  readonly reason: string;
  readonly impact: "low" | "medium" | "high";
};

export type AnalyzerDisposition = SecurityAnalyzerDisposition & { readonly version?: string };

export type RunManifest = {
  readonly schemaVersion: "1.0.0";
  readonly manifestId: string;
  readonly resolvedTarget: ResolvedTarget;
  readonly intent: IntakeIntent;
  readonly objectives: readonly ObjectiveGroup[];
  readonly exclusions: readonly string[];
  readonly analyzers: readonly AnalyzerDisposition[];
  readonly budget: IntakeBudget;
  readonly defaults: readonly AppliedDefault[];
  readonly gaps: readonly IntakeGap[];
  readonly authorization: { readonly required: boolean; readonly granted: boolean; readonly actor?: string; readonly reason?: string };
  readonly confirmation: { readonly required: boolean; readonly confirmed: boolean; readonly actor?: string };
  readonly route: { readonly mode: "interactive" | "noninteractive"; readonly materialization: ResolvedTarget["materialization"]; readonly trust: TargetTrust; readonly provider?: string };
};

const QUESTION_ORDER: readonly IntakeQuestion[] = [
  { id: "target", impact: 100, prompt: "What should Sniff inspect?", reason: "A target is required before any other decision is meaningful." },
  { id: "intent", impact: 90, prompt: "What outcome should this Sniff run optimize for?", reason: "Intent changes the route, budget, and analyzer set." },
  { id: "objectives", impact: 80, prompt: "Which objective groups should be included?", reason: "Objective selection determines which analyzers are relevant." },
  { id: "budget", impact: 60, prompt: "What time or analyzer budget should Sniff use?", reason: "A budget bounds an otherwise open-ended audit." },
];


function isCompleteInput(input: IntakeInput): boolean {
  return input.target !== undefined && input.intent !== undefined && (input.objectives?.length ?? 0) > 0 && input.budget !== undefined;
}

export function decisionFrontier(input: IntakeInput): IntakeInterview {
  if (isCompleteInput(input)) {
    const objectives = selectObjectiveGroups(input.objectives).selected;
    return { questions: [], plan: buildPlan(input, objectives), confirmationRequired: true };
  }
  const question = QUESTION_ORDER.find((candidate) => {
    if (candidate.id === "target") return input.target === undefined;
    if (candidate.id === "intent") return input.intent === undefined;
    if (candidate.id === "objectives") return (input.objectives?.length ?? 0) === 0;
    return input.budget === undefined;
  });
  return { questions: question ? [question] : [], confirmationRequired: false };
}

export const getDecisionFrontier = decisionFrontier;

function buildPlan(input: IntakeInput, objectives: readonly ObjectiveGroup[]): IntakePlan {
  if (!input.target || !input.intent || !input.budget) throw new Error("Cannot build an intake plan from incomplete input");
  return {
    target: structuredClone(input.target),
    intent: input.intent,
    objectives: [...objectives],
    exclusions: canonicalStrings(input.exclusions ?? []),
    budget: { ...input.budget },
    security: structuredClone(input.security ?? {}),
  };
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.entries(record).sort(([left], [right]) => left.localeCompare(right)).map(([key, entry]) => [key, stableValue(entry)]));
  }
  return value;
}

function stableJson(value: unknown): string {
  return JSON.stringify(stableValue(value));
}

function freezeDeep<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    const record = value as Record<string, unknown>;
    for (const child of Object.values(record)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function canonicalStrings(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function canonicalTarget(target: ResolvedTarget): ResolvedTarget {
  const cloned = structuredClone(target);
  if (cloned.repository) validateRepository(cloned.repository);
  return {
    ...cloned,
    files: canonicalStrings(cloned.files),
    ...(cloned.changes ? { changes: [...cloned.changes].sort((left, right) => left.path.localeCompare(right.path)) } : {}),
    ...(cloned.release
      ? { release: { ...cloned.release, deltaFiles: canonicalStrings(cloned.release.deltaFiles), snapshotFiles: canonicalStrings(cloned.release.snapshotFiles) } }
      : {}),
  };
}

function targetTrust(target: ResolvedTarget): TargetTrust {
  return target.repository ? "untrusted-remote" : "trusted-local";
}

function semanticContent(content: Omit<RunManifest, "manifestId">): unknown {
  const { root: _ephemeralRoot, ...semanticTarget } = content.resolvedTarget;
  return { ...content, resolvedTarget: semanticTarget };
}

function manifestId(content: Omit<RunManifest, "manifestId">): string {
  return `manifest-${createHash("sha256").update(stableJson(semanticContent(content))).digest("hex").slice(0, 16)}`;
}

export type ManifestInput = {
  readonly target: ResolvedTarget;
  readonly intent: IntakeIntent;
  readonly objectives?: readonly string[];
  readonly exclusions?: readonly string[];
  readonly security?: SecurityRequest;
  readonly analyzers?: readonly AnalyzerDisposition[];
  readonly budget?: IntakeBudget;
  readonly defaults?: readonly AppliedDefault[];
  readonly gaps?: readonly IntakeGap[];
  readonly authorization?: IntakeAuthorization;
  readonly confirmation?: { readonly confirmed: boolean; readonly actor?: string };
  readonly route?: { readonly mode?: "interactive" | "noninteractive"; readonly provider?: string };
};

function cloneSorted<T>(values: readonly T[]): T[] {
  const sorted = [...structuredClone(values)].sort((left, right) => stableJson(left).localeCompare(stableJson(right)));
  return sorted.filter((value, index) => index === 0 || stableJson(value) !== stableJson(sorted[index - 1]));
}

function validateBudget(budget: IntakeBudget): void {
  for (const [field, value] of Object.entries(budget)) {
    if (!Number.isFinite(value) || !Number.isInteger(value) || value <= 0) {
      throw new Error(`Intake budget ${field} must be a positive finite integer`);
    }
  }
}

function buildManifest(input: ManifestInput, authorization?: { readonly actor?: string; readonly reason?: string }): RunManifest {
  if (input.analyzers) throw new Error("Analyzer dispositions are derived from the trusted catalog and cannot be supplied by callers");
  if (input.authorization) throw new Error("Authorization requires a trusted confirmation boundary");
  validateBudget(input.budget ?? {});
  const mode = input.route?.mode ?? "interactive";
  const trust = targetTrust(input.target);
  const route = {
    mode,
    materialization: input.target.materialization,
    trust,
    ...(input.route?.provider ? { provider: input.route.provider } : {}),
  } as RunManifest["route"];
  const analyzers = selectSecurityAnalyzers(input.security, { trust, target: input.target });
  const content: Omit<RunManifest, "manifestId"> = {
    schemaVersion: "1.0.0",
    resolvedTarget: canonicalTarget(input.target),
    intent: input.intent,
    objectives: [...selectObjectiveGroups(input.objectives).selected],
    exclusions: canonicalStrings([...(input.exclusions ?? []), ...securityExclusions()]),
    analyzers: cloneSorted(analyzers),
    budget: structuredClone(input.budget ?? {}),
    defaults: cloneSorted(input.defaults ?? []),
    gaps: cloneSorted(input.gaps ?? []),
    authorization: { required: mode === "noninteractive", granted: mode === "noninteractive" && authorization !== undefined, actor: authorization?.actor, reason: authorization?.reason },
    confirmation: { required: mode === "interactive", confirmed: input.confirmation?.confirmed === true, actor: input.confirmation?.actor },
    route,
  };
  if (mode === "noninteractive" && !authorization) throw new Error("Noninteractive intake requires a trusted confirmation receipt");
  validateAnalyzerDispositions(content.analyzers, trust);
  const manifest = freezeDeep({ ...content, manifestId: manifestId(content) });
  return manifest;
}

export function createRunManifest(input: ManifestInput): RunManifest {
  if (input.route?.mode === "noninteractive") throw new Error("Noninteractive intake requires a trusted confirmation boundary");
  return buildManifest({ ...input, route: { ...input.route, mode: "interactive" } });
}

export type IntakeAuthority = {
  authorize(plan: Readonly<{ target: ResolvedTarget; intent: IntakeIntent }>): Promise<false | { readonly actor?: string; readonly reason?: string }>;
};

export async function buildNoninteractiveManifest(input: ManifestInput, authority?: IntakeAuthority): Promise<RunManifest> {
  if (input.authorization) throw new Error("Authorization requires a trusted confirmation boundary");
  if (!authority) throw new Error("Noninteractive intake requires a trusted confirmation boundary");
  const authorization = await authority.authorize({ target: input.target, intent: input.intent });
  if (!authorization) throw new Error("Noninteractive intake authorization was denied");
  const defaults: AppliedDefault[] = structuredClone([...(input.defaults ?? [])]);
  if (!input.objectives || input.objectives.length === 0) defaults.push({ field: "objectives", value: [...OBJECTIVE_GROUPS], reason: "All objective groups are selected when no interactive narrowing was supplied." });
  if (!input.exclusions) defaults.push({ field: "exclusions", value: [], reason: "No user exclusions were supplied; bounded security exclusions still apply." });
  if (!input.security) defaults.push({ field: "analyzers", value: "catalog defaults", reason: "The target trust tier selects the analyzer defaults." });
  if (!input.budget) defaults.push({ field: "budget", value: {}, reason: "No budget was supplied; analyzer availability remains the limiting bound." });
  const gaps: IntakeGap[] = structuredClone([...(input.gaps ?? [])]);
  if (!input.budget) gaps.push({ field: "budget", reason: "No explicit budget was provided in noninteractive mode.", impact: "medium" });
  return buildManifest({ ...input, defaults, gaps, route: { ...input.route, mode: "noninteractive" } }, authorization);
}

export function validateRunManifest(manifest: RunManifest): void {
  const { manifestId: suppliedId, ...content } = manifest;
  if (manifestId(content) !== suppliedId) throw new Error("Run manifest identity does not match its content");
  const requiredExclusions = securityExclusions();
  if (requiredExclusions.some((value) => !manifest.exclusions.includes(value))) throw new Error("Run manifest omits a mandatory security exclusion");
  if (manifest.authorization.required !== (manifest.route.mode === "noninteractive") || (manifest.authorization.required && !manifest.authorization.granted)) {
    throw new Error("Run manifest authorization is inconsistent with its route");
  }
  if (manifest.confirmation.required !== (manifest.route.mode === "interactive") || (manifest.confirmation.required && !manifest.confirmation.confirmed)) {
    throw new Error("Run manifest confirmation is inconsistent with its route");
  }
  validateBudget(manifest.budget);
  validateAnalyzerDispositions(manifest.analyzers, manifest.route.trust);
}

export function canonicalManifestJson(manifest: RunManifest): string {
  validateRunManifest(manifest);
  return stableJson(manifest);
}
