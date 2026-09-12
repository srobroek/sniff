# Interviewing

Sniff uses one harness-neutral interview contract. OMP presents the contract through its native extension UI. Claude Code and Codex present it through MCP elicitation.

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

OMP uses its native confirmation UI.

## Interactive and noninteractive intake

The host can expose elicitation. Both adapters use it.

Authorized noninteractive intake supplies `target` and `intent` through host authorization. The trusted host records the authorization receipt. The caller cannot supply authorization fields. Sniff records defaults and gaps instead of asking frontier questions.

Without an objective choice, noninteractive intake selects all six groups.

Without exclusions, it records an empty list.

Security rules stay active.

Without a budget, it records an empty budget object.

Sniff records a medium-impact gap.

Each budget value must be a positive finite integer.

Supported fields are `maxMinutes`, `maxAnalyzers`, and `maxFiles`.

## Approval boundaries

The seven tools keep approvals separate:

1. `sniff_intake` needs plan confirmation before it issues a capability.
2. `sniff_install_tools` needs installation approval before it installs bundles. Probe, diagnose, and list stay read-only.
3. `sniff_run_analyzer` accepts only the issued capability and selected recipe. Before execution, the host revalidates the target.
4. `sniff_read_analyzer_artifact` reads complete analyzer observations with the opaque capability returned by `sniff_run_analyzer`. It does not grant repository write access. Continue with `nextOffset` until `eof`.
5. `sniff_report` renders a validated report or needs save approval before it writes artifacts.
6. `sniff_read_report_artifact` reads a descriptor artifact with the opaque read capability returned by `sniff_report`. Continue with `nextOffset` until `eof`. It does not grant repository write access.
7. `sniff_cancel` closes an unfinished run and releases its materialization.


## Related guides

- [Getting started](getting-started.md)
- [Capabilities and clean-room evidence](capabilities.md)
- [Sniff types](sniff-types.md)
- [Workflow](workflow.md)
- [Targets and providers](targets-and-providers.md)
- [Security and trust](security-and-trust.md)
- [Reports](reports.md)
