export const OBJECTIVE_GROUPS = [
  "structure-and-maintainability",
  "correctness-and-resilience",
  "performance-and-efficiency",
  "change-and-release-risk",
  "tests-delivery-and-tooling",
  "bounded-security-smells",
] as const;

export type ObjectiveGroup = (typeof OBJECTIVE_GROUPS)[number];

export type ObjectiveSelection = {
  readonly selected: readonly ObjectiveGroup[];
  readonly skipped: readonly { readonly group: ObjectiveGroup; readonly reason: string }[];
};

const GROUP_LABELS: Record<ObjectiveGroup, string> = {
  "structure-and-maintainability": "Structure and maintainability",
  "correctness-and-resilience": "Correctness and resilience",
  "performance-and-efficiency": "Performance and efficiency",
  "change-and-release-risk": "Change and release risk",
  "tests-delivery-and-tooling": "Tests, delivery, and tooling",
  "bounded-security-smells": "Bounded security smells",
};

export function objectiveGroupLabel(group: ObjectiveGroup): string {
  return GROUP_LABELS[group];
}

export function selectObjectiveGroups(requested?: readonly string[]): ObjectiveSelection {
  if (!requested || requested.length === 0) return { selected: [...OBJECTIVE_GROUPS], skipped: [] };
  const selected: ObjectiveGroup[] = [];
  const skipped: Array<{ readonly group: ObjectiveGroup; readonly reason: string }> = [];
  const requestedSet = new Set(requested);
  for (const group of OBJECTIVE_GROUPS) {
    if (requestedSet.has(group)) selected.push(group);
    else skipped.push({ group, reason: "Not selected by the intake intent." });
  }
  const unknown = requested.filter((value) => !OBJECTIVE_GROUPS.includes(value as ObjectiveGroup));
  if (unknown.length > 0) throw new Error(`Unknown objective group(s): ${unknown.join(", ")}`);
  return { selected, skipped };
}
