# Adaptive interviewing

Sniff runs adaptive intake. Analyzer execution follows. The current verified adapter is OMP. Claude Code and Codex adapters are not documented as supported adapters.

Requests describe a conversation. Natural-language text is not a deterministic shell command.

## Decision frontier

Interactive intake checks four decisions:

- `target` has impact 100. Sniff needs a target before later choices.
- `intent` has impact 90. Intent changes the route. It changes the budget and analyzer selection.
- `objectives` has impact 80. Objective choice selects analyzers.
- `budget` has impact 60. A budget bounds an otherwise open-ended audit.

Sniff asks the first unresolved question. It waits. Then it asks another question.

Exclusions shape the plan. Security preferences shape the plan. After intake, Sniff applies both. See [Sniff types](sniff-types.md) for accepted values.

## Request patterns

These patterns identify explicit choices and the next question. They describe interaction rather than natural-language parsing.

- `Inspect this repository.` Explicit choice: `target`. Next question: `intent`.
- `Audit the uncommitted changes.` Explicit choices: `target` and `intent: audit`. Next question: `objectives`.
- `Audit the uncommitted changes for structure and maintainability.` Explicit choices include `structure-and-maintainability`. Next question: `budget`.
- `Audit the uncommitted changes for structure and maintainability with a five-minute budget.` The request names all four frontier decisions. Sniff asks no frontier question. It asks for final plan confirmation.
- `Review the pull request for release risk with an analyzer limit of three.` The request names `intent: review-change`, `objectives: [change-and-release-risk]`, and `maxAnalyzers: 3`. Sniff asks no frontier question. It asks for final plan confirmation.

When a request names a target but no intent, Sniff asks about the desired outcome.

When a request names an intent but no objective group, Sniff asks which groups to include.

When a request names objective groups but no budget, Sniff asks for a budget bound.

A complete prompt produces no frontier question. It does not grant approval. Each later action needs separate approval.

## Final plan confirmation

After the frontier is complete, Sniff resolves the target and prepares one plan. Before confirmation, review these values:

- resolved target label
- immutable commit or mutable working-tree state
- exact file set and file count
- intent and objective groups
- exclusions
- analyzer selections and skipped analyzers
- time, analyzer, and file limits
- defaults and coverage gaps
- trust route and materialization mode

Interactive intake needs confirmation through OMP. Sniff records the confirmation in the run manifest. It issues a capability for that manifest.

Installation needs separate approval. Report saving needs separate approval. Refactoring needs separate approval.

## Interactive and noninteractive intake

Interactive intake needs these values:

- `target`
- `intent`
- one objective group
- `budget`

The OMP UI confirms the resolved plan. The interview exposes unresolved decisions.

Authorized noninteractive intake needs `target` and `intent`. The trusted host records an authorization receipt. The caller cannot supply authorization fields. Sniff records defaults and gaps instead of asking conversational questions.

The boundary rejects input. Sniff derives choices from trust data. Missing authorization blocks the run.

## Noninteractive defaults and gaps

Sniff records entries for fields omitted by an authorized noninteractive request:

- `objectives`: all six groups. No gap applies.
- `exclusions`: empty list. Security exclusions still apply. No gap applies.
- `security`: analyzer defaults from the target trust tier. No gap applies.
- `budget`: an empty budget object. Sniff records a medium-impact gap because no explicit budget was supplied.

Every supplied budget value must be a positive finite integer. Supported fields are `maxMinutes`, `maxAnalyzers`, and `maxFiles`.

## Cancellation

A stopped run needs `sniff_cancel` before reporting.

Cancellation closes the capability. It releases reservations. It removes the temporary checkout. It removes the analyzer home.

A terminal report attempt closes the lease even when validation fails. An expiry timer cleans up an abandoned lease. The lease registry is single-process state.

## Related guides

- [Getting started](getting-started.md)
- [Workflow](workflow.md)
- [Sniff types](sniff-types.md)
- [Security and trust](security-and-trust.md)
- [Reports](reports.md)
