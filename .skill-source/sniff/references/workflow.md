# Workflow

The operational sequence lives in `../SKILL.md`. Read that skill before every run.

## Concepts

- Intake resolves `target`, `intent`, `scopeMode`, `objectives`, and `budget`, then gets confirmation and an authenticated lease.
- Target resolution produces an exact file set, immutable refs where applicable, and a trust route. Non-Git trees use `files` or `directory`, not `whole-repo` or `working-tree`.
- Detection maps the resolved files to language references. Tool probing reports availability and versions; installation and analysis require their own approvals.
- Each analyzer runs once through its issued capability and fixed recipe. The host revalidates the lease root, files, executable, scope, budget, and recipe before spawning.
- Analyzer previews and report artifacts are paged with `nextOffset` until `eof`; each UTF-8-safe page is at most 64 KiB.
- Full mode includes a separate challenge pass. Quick mode skips the full sweep and challenge. Plan-only mode never applies changes.
- Reporting validates the authenticated manifest, renders or saves artifacts, and releases the lease. Cancellation releases unfinished runs.

## Safety boundaries

- Remote targets use host-owned, config-free recipes and never load target executable configuration or dependencies.
- Credentials, caller-controlled analyzer execution, out-of-root files, and replayed capabilities are rejected.
- Save, install, analysis, and refactor actions retain separate approval boundaries.

See `intake.md`, `targeting.md`, `security-scope.md`, `report-template.md`, and `report-input.schema.json` for exact contracts.
