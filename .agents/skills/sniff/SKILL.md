---
name: sniff
description: Audit code smells and produce reviewed refactoring plans. Use when asked to sniff, audit quality, or plan a refactor.
---

# Sniff

Until step 7 grants approval, do not edit code. Audit smells and produce a reviewed plan. Before reading code, read `./references/approval-gates.md`. Use direct evidence to identify structural risk. Preserve disputed findings for the challenge pass. Report only findings that survive that pass.

## Workflow

Read `./references/workflow.md` first. Follow these steps in order:

1. Adaptive intake.
   - Read `./references/intake.md` and `./references/targeting.md`.
   - Resolve the decision frontier in this order: `target`, `intent`, `scopeMode`, `objectives`, `budget`.
   - Call `sniff_intake`.
   - Ask only the highest-impact unresolved question.
   - Confirm one resolved plan.
   - Keep the issued capability and manifest ID.
   - Treat remote targets as untrusted.
2. Detect the stack.
   - Detect every language and format in the resolved target.
   - Map each one through `./references/languages/index.md`.
3. Probe tools.
   - Run `sniff_install_tools` in `probe` mode.
   - Show viable tools by language and tier.
   - Stop unless the brief already authorizes that set.
   - Read `./references/tooling.md` and `./references/installer.md`.
   - For trusted local work, read each governing configuration file.
   - For remote work, do not load executable configuration or install dependencies.
4. Run detection.
   - Pass the capability, manifest ID, and selected recipe ID to `sniff_run_analyzer`. If its preview is truncated or complete observations are needed, page `sniff_read_analyzer_artifact` with `analyzerResultId` and either `relativePath` or `sourcePath`; continue with `nextOffset` until `eof`.
   - Record unavailable analyzers as coverage gaps.
   - For large targets, propose an independent read-only scout plan by language and subtree. Build each brief from `./references/scout-brief.md` and include the matching `./references/languages/<lang>.md` path.
5. Map findings.
   - Use `./references/refactoring-catalog.md` and attach the complete catalog entry.
6. Challenge findings.
   - Build the `independent challenge reviewer` brief from `./references/adversarial-brief.md` and drop or downgrade refuted findings.
7. Report or apply.
   - Copy `reportTarget` from `sniff_intake` into `report.target`, then add `languages`.
   - Pass the capability and manifest ID to `sniff_report`; omit `extensions["sniff.intake"]` so the host injects the authenticated manifest.
   - Use the returned read capability, report ID, and descriptor relative path with `sniff_read_report_artifact`; follow UTF-8-safe pages through `nextOffset` until `eof`.
   - Call `sniff_cancel` when a run stops before reporting.
   - Save or apply only with explicit approval.

## Rules

- MUST use real analyzers. Do not use low-precision grep for smell detection.
- MUST use exact-file checksums only as the duplication floor.
- MUST keep steps 1 through 6 read-only.
- MUST classify each analyzer by scope class.
- MUST headline base-ref breaks. Skip invalid scoped global runs and record them.
- MUST resolve shipped assets through this skill's `references/` directory.
- MUST run each selected analyzer only through `sniff_run_analyzer`.
- MUST pass only the issued capability, manifest ID, and recipe ID.
- MUST run Sniff Bash commands only after the issued capability and one-shot recipe authorization are verified.
- MUST keep evidence tier separate from impact.
- MUST preserve challenged findings and coverage data.
- MUST save only with explicit intent and a path.
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
