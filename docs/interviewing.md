# Interviewing

Sniff uses one harness-neutral interview contract. Each adapter presents the same decisions through its host interface.

The host confirms the plan. Sniff issues a run capability.

Natural-language requests describe a conversation. They are not shell commands.

## Decision frontier

The core models five frontier axes:

- `target` identifies the repository or file set.
- `intent` identifies the desired outcome.
- `scopeMode` selects run behavior.
- `objectives` identifies the objective groups.
- `budget` sets time, analyzer, and file limits.

Analyzer family and tier follow from the confirmed target, objectives, trust route, and availability.

The five choices form the adaptive frontier. Sniff asks the highest-impact unresolved question. It waits for the answer. Sniff asks the next question. Analyzer selection follows the confirmed choices.

## Request patterns

These examples show the next decision:

- `Inspect this repository.` names `target`. Sniff asks for `intent`.
- `Audit the uncommitted changes.` names `target` and `intent: audit`. Sniff asks for `scopeMode`.
- `Audit the uncommitted changes for structure and maintainability.` names an objective group. Sniff asks for `scopeMode`.
- `Audit the uncommitted changes for structure and maintainability in plan-only mode with a five-minute budget.` names the frontier choices. Sniff asks for final plan confirmation.

A complete request does not grant approval. Confirmation remains separate. Installation remains separate. Report saving remains separate. Refactoring remains separate.

## Confirm the plan

Before confirmation, review these values:

- resolved target label
- immutable commit or working-tree state
- exact file set and file count
- intent and objective groups
- scope mode and exclusions
- analyzer selections and skipped analyzers
- time, analyzer, and file limits
- defaults and coverage gaps
- trust route and materialization mode

The interactive host asks questions.

## Interactive and noninteractive intake

Adapters with elicitation support use it for confirmation.

Authorized noninteractive intake supplies `target` and `intent` through host authorization. The trusted host records the authorization receipt. The caller cannot supply authorization fields. Sniff records defaults and gaps instead of asking frontier questions.

Without an objective choice, noninteractive intake selects all six groups.

Without exclusions, it records an empty list.

Security rules stay active.

Without a budget, it records an empty budget object.

Sniff records a medium-impact gap.

Each budget value must be a positive finite integer.

Supported fields are `maxMinutes`, `maxAnalyzers`, and `maxFiles`.

## Approval boundaries

The canonical lifecycle and approval contract lives in the [Sniff skill](../.skill-source/sniff/SKILL.md). Installation, analyzer execution, report saving, and refactoring require separate approval; probe, diagnose, and list remain read-only.


## Related guides

- [Getting started](getting-started.md)
- [Capabilities and clean-room evidence](capabilities.md)
- [Sniff types](sniff-types.md)
- [Workflow](workflow.md)
- [Targets and providers](targets-and-providers.md)
- [Security and trust](security-and-trust.md)
- [Reports](reports.md)
