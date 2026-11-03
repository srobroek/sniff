# Workflow concepts

`SKILL.md` owns the step sequence. This file defines the terms it relies on.

- **Lease.** `sniff_intake` binds one capability and manifest ID to an exact file set, immutable refs, and a trust route. `sniff_report` or `sniff_cancel` releases it; an abandoned lease expires on its own.
- **Recipe.** Sniff coverage comes only from the fixed host recipes `lizard:complexity`, `opengrep:hardcoded-values`, and `gitleaks:tracked-history`. Each runs at most once per lease, after the host revalidates root, files, executable, scope, and budget.
- **Modes.** `full` runs every selected recipe and the challenge pass. `quick` also omits `gitleaks:tracked-history`. `plan-only` executes no analyzer: every recipe is skipped, so the report rests on reading alone. Say so before the user picks it.
- **Approvals.** Intake confirmation authorizes analysis of the confirmed plan only. Installing tools and saving a report each need the host's own confirmation of the exact plan, which a headless session cannot give. Applying changes needs explicit user approval at step 7.
- **Remote targets** run only config-free, remote-safe recipes. Never load their executable configuration or dependencies.

Exact contracts: `intake.md`, `targeting.md`, `security-scope.md`, `report-template.md`, and `report-input.schema.json`.
