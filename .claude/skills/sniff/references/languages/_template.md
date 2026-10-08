# <Language / Format> -- Sniff Reference

> Authoring template for a sniff language doc. Copy this, fill every section,
> keep it self-contained (an independent scout agent reads ONLY this doc for the
> language). Aim for tight, concrete content -- checklists over prose. Delete
> this blockquote in real docs.

One-line scope: what this doc covers (e.g. "Go source: `.go` files, `go.mod`").

## Detect

How sniff knows this language/format is present: key files, extensions, config.
- Files/extensions: `...`
- Config that governs it: `...`

## Tools

Operator follow-up tools, primary first. Sniff never runs these during a run:
its only coverage is the fixed `sniff_run_analyzer` recipes (see
`../tooling.md`). Name any recipe that covers this target in the Notes, and
keep each row runnable by an operator. Each row needs all five columns; the universal run-rules
(cwd=repo root, project-config-wins, exit-codes, absolutize shipped assets) live
in `../tooling.md` -- don't restate them, add only tool-specific detail.

| Tool | Run recipe | Covers | Tier | Installed via |
|------|-----------|--------|------|---------------|
| <primary> | **exact command** + machine-readable flag + how the file set is passed; **config:** auto-uses project config / needs `--config` / no-config fallback; **exit:** 0 clean · N findings (parse) · usage/crash = INVALID (fix+re-run, never "clean"); any gotcha | <dimensions> | default-on | <install route> |
| <secondary> | … | <dimensions> | opt-in (reason) | … |

- **Tier** is `default-on` (a standard follow-up recommendation in the step 3 plan) or `opt-in`
  (shown off, with the reason: nightly / redundant-with-X / heavy / security-only
  / needs-baseline). Default-on = recommend it as a follow-up unless redundant.
- **Run recipe** must be complete enough to run without guessing -- a terse
  invocation is what causes bad-flag / wrong-cwd / unhandled-crash bugs.

Notes: which tool is the meta-linter, what overlaps, what to skip if another is
present. Note when the standard toolchain already covers a dimension.

## Smell checklist

The smells to look for, beyond what tools flag. Each: what it looks like + the
idiomatic alternative. Group by category. Be language-specific -- not generic OO.

| Smell | What it looks like (this language) | Idiomatic alternative |
|-------|-----------------------------------|-----------------------|
| ... | ... | ... |

## Idioms & style authorities

The leading style guide(s)/handbook(s) for this language, with URLs. State the
few conventions most worth enforcing.

- <Guide name> -- <URL>
- Key conventions: ...

## refactoring.guru mappings

The smells common in this language → the catalog entry to cite (see
`../refactoring-catalog.md`). Note where the language-idiomatic fix differs from
the generic catalog.

| This-language smell | refactoring.guru smell | Idiomatic refactoring |
|---------------------|------------------------|-----------------------|
| ... | ... | ... |

## Pragmatism notes (for the adversarial pass)

Where "fixes" commonly over-reach in this language -- the false positives and
non-idiomatic-but-fine patterns the `independent challenge reviewer` should protect.

- ...

**Execution routing:** Sniff coverage comes only from fixed recipes run through `sniff_run_analyzer` (`lizard:complexity`, `opengrep:hardcoded-values`, `gitleaks:tracked-history`). Every tool in this table is an operator follow-up: never run it during a Sniff run. Record each dimension it would cover as a `gap` coverage entry naming the tool, and list its command as a follow-up the user may run outside Sniff.
