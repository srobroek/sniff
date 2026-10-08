# Report Template

`sniff_report` builds the report. It validates agent input against
`report-input.schema.json` and canonical output against `report.schema.json`,
then renders the Markdown and per-file artifacts itself. Never compose the
report independently, because hand-written prose drifts from the
machine-readable findings. This file explains how to fill the input and what
the renderer emits.

The caller supplies the capability and manifest ID; the host authenticates that pair and injects
the exact issued `sniff.intake` manifest when the report extension is omitted. If the extension is
present, it must match the issued manifest exactly.

## What `sniff_report` renders

`summary.md` contains these sections, in order:

1. **Header**: report ID, target kind, scope mode, base ref, languages, and date.
2. **Summary**: retained, dropped, and downgraded counts; counts by impact;
   suppressions observed; and the `headline`.
3. **Tool coverage**: one row per `coverage` entry (dimension, tool, analysis
   class, status, notes with any probed version).
4. **Prioritized refactoring plan**: KEEP and DOWNGRADE findings ordered by
   value per cost, with columns for finding, smell → refactoring, impact,
   evidence tier, value, cost, back-compat, and apply tier.
5. **Systemic patterns**, when `systemicPatterns` is non-empty.
6. **Dropped & downgraded**: every challenged finding with its verdict and
   reason.
7. **Source files**: links to the per-file JSON artifacts.

`report.json`, `coverage.json`, `manifest.json`, `receipt.json`, and
`index.json` carry the same data in machine-readable form. Every challenged
finding, including drops, stays in JSON.

## Filling the input

- **`headline`**: one sentence naming the single most valuable action. When a
  ref target breaks a public contract against its base, headline that break.
- **Framing**: a diff, PR, or range report is a regression review; a module
  report is a mini-audit; a file report is a focused read. Write `headline` and
  finding titles accordingly.
- **`impact`**: severity of the current smell (`critical`, `high`, `medium`,
  `low`), not of the fix. Keep it independent of `evidence.tier`.
- **`value`** and **`cost`**: benefit if fixed (`high`, `medium`, `low`) and
  effort or blast radius (`S` one mechanical site, `M` a few files, `L`
  cross-cutting design).
- **`compatibility`**: `safe`, or `breaking` with the exact `surface` (public
  signature, wire or serialized format, config key, documented behavior).
- **`applyTier`**: `mechanical` (Sniff may apply it on approval: rename,
  extract, inline, guard clause, dead-code removal), `assisted` (needs review),
  or `manual` (design change; advisory only). The schema rejects `mechanical`
  for a `breaking` change.
- **`smell`** and **`refactoring`**: refactoring.guru links from
  `refactoring-catalog.md`; supply both or neither.
- **`adversarial`**: the challenger's verdict and rationale for every finding.

## Coverage honesty

- `ran`: a Sniff recipe executed for this dimension.
- `skipped`: a recipe was ruled out by scope, mode, or trust. State the reason
  precisely, for example `scoped: global class` or `plan-only: no analyzers run`.
  When a global-class dimension is both out of scope and unavailable, report it
  once as skipped for scope.
- `gap`: no Sniff recipe checked this dimension, or its tool was unavailable.
  Put the operator follow-up command in `notes`. A recipe covers only its own
  dimensions: `lizard:complexity` covers complexity, length, and parameter
  count, and a language linter the operator may run does not stand in for it.
- `not-applicable`: the detected stack has nothing for this dimension, such as
  global analyses on a docs-only target.

## Rules

- In full mode, every challenged finding keeps its verdict so the Dropped &
  downgraded section shows what the pragmatism filter removed.
- If nothing survives the challenge, say the codebase is clean on the
  dimensions checked and keep every gap; do not invent findings.
- Lint-rule or config recommendations that would prevent a confirmed smell
  from recurring go in `systemicPatterns` as advice. Never apply them during
  reporting.
- Applying changes is a separate step-7 action that needs explicit approval and
  never happens in plan-only mode.
