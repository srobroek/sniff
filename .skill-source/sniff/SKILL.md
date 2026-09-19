---
name: sniff
description: Audit code smells and produce reviewed refactoring plans. Use when asked to sniff, audit quality, or plan a refactor.
---

# Sniff

Until step 7 grants approval, do not edit code. Audit smells and produce a reviewed plan. Before reading code, read `skill://sniff/references/approval-gates.md`. Use direct evidence to identify structural risk. Preserve disputed findings for the challenge pass. Report only findings that survive that pass.

## Workflow

Read `skill://sniff/references/workflow.md` first. Follow these steps in order:

1. Adaptive intake.
   - Read `skill://sniff/references/intake.md` and `skill://sniff/references/targeting.md`.
   - Resolve the decision frontier in this order: `target`, `intent`, `scopeMode`, `objectives`, `budget`.
   - Call `sniff_intake`.
   - Ask only the highest-impact unresolved question.
   - Confirm one resolved plan.
   - Keep the issued capability and manifest ID.
   - Treat remote targets as untrusted.

The intake response issues a capability and manifest ID for one lease-backed materialization. The lease owns the materialization until reporting or cancellation releases it. The report target identifies the persisted report artifact route. Expired or replayed recipes require a new intake and must never be replayed.
2. Detect the stack.
   - Detect every language and format in the resolved target.
   - Map each one through `skill://sniff/references/languages/index.md`.
3. Probe tools.
   - Run `sniff_install_tools` in `probe` mode.
   - Show viable tools by language and tier.
   - Probing is safe. Installing needs host confirmation. Without authorization, report the plan and stop.
   - Read `skill://sniff/references/tooling.md` and `skill://sniff/references/installer.md`.
   - For trusted local work, read each governing configuration file.
   - For remote work, do not load executable configuration or install dependencies.
4. Run detection.
   - Pass the capability, manifest ID, and selected recipe ID to `sniff_run_analyzer`. If its preview is truncated or complete observations are needed, page `sniff_read_analyzer_artifact` with its `readCapability`, `analyzerResultId`, and either `relativePath` or `sourcePath`; continue with `nextOffset` until `eof`.
   - Record unavailable analyzers as coverage gaps.
   - For large targets, propose a `bloodhound` plan by language and subtree. Build each brief from `skill://sniff/references/scout-brief.md` and include the matching `skill://sniff/references/languages/<lang>.md` path.
5. Map findings.
   - Use `skill://sniff/references/refactoring-catalog.md` and attach the complete catalog entry.
6. Challenge findings.
   - Build the `refactor-challenger` brief from `skill://sniff/references/adversarial-brief.md` and drop or downgrade refuted findings.
7. Report or apply.
   - Copy `reportTarget` from `sniff_intake` into `report.target`, then add `languages`.
   - Pass the capability and manifest ID to `sniff_report`; omit `extensions["sniff.intake"]` so the host injects the authenticated manifest.
   - Pass the returned `readCapability`, report ID, and descriptor relative path to `sniff_read_report_artifact`; follow UTF-8-safe pages through `nextOffset` until `eof`.
   - Call `sniff_cancel` when a run stops before reporting.
   - Save or apply only with explicit approval.

## Rules

- MUST use real analyzers. Do not use low-precision grep for smell detection.
- MUST use exact-file checksums only as the duplication floor.
- MUST keep steps 1 through 6 read-only.
- MUST classify each analyzer by scope class.
- MUST headline base-ref breaks. Skip invalid scoped global runs and record them.
- MUST resolve shipped assets through `skill://sniff/`.
- MUST run each selected analyzer only through `sniff_run_analyzer`.
- MUST pass only the issued capability, manifest ID, and recipe ID.
- MUST keep evidence tier separate from impact.
- MUST preserve challenged findings and coverage data.
- MUST save only with explicit intent and a path.
- MUST use `files` or `directory` scope when a non-Git tree cannot support `whole-repo` or `working-tree`; never fall back silently.
- Artifact pages are UTF-8 safe and at most 64 KiB; continue with `nextOffset` until `eof`.
- DEFAULT load only references needed by the detected stack.

Modes:

- `quick` skips the full sweep and challenge.
- `full` runs all steps.
- `plan-only` never applies changes.
- Keep debug annotations off by default.

## References

| File | Load when |
|------|-----------|
| `references/workflow.md` | Always, before step 1 |
| `references/targeting.md` | Target resolution/reduction |
| `references/intake.md` | Intake decisions |
| `references/providers.md` | Provider decisions |
| `references/objectives.md` | Objective decisions |
| `references/security-scope.md` | Security decisions |
| `references/report-template.md` | Report |
| `references/report-input.schema.json` | Strict input contract |
| `references/report.schema.json` | Strict output contract |
