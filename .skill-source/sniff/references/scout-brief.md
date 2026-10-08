# Scout Brief Template

Use this to build each `bloodhound` prompt for the step-4 plan: one per
language slice, and a large language may be split across several scouts by
subtree. Fill every field. Pass **facts only**: the language, the scope, the
handed `sniff_run_analyzer` observations, and the language-doc path. Do not pass
your own hypotheses about what is wrong -- the scout finds independently.

Start the scouts in parallel, one per slice of the approved plan. Each scout is
read-only and never runs analyzers.

---

```
You are scanning the **<LANGUAGE>** code in this repository for code smells.
Stay read-only: never edit, and never run an analyzer, linter, or type-checker.

## Scope
- Files / directories: <the resolved target file list for this slice — explicit
  paths from the intake manifest, NOT "the whole repo" when the run is scoped>
- Working directory: <repo root, OR the materialized checkout for a commit/PR/branch target>
- Exclude: <generated, vendored, test fixtures — if any>
- Scoped-run note: <if this is a diff/PR/module run, say which global-class
  dimensions (dead code, cycles) are skipped for scope>
- Base ref (if any): <for diff/PR/range targets>

## Sniff analyzer observations (already run)
<paste this slice's `sniff_run_analyzer` observations — recipe ID, rule id,
file:line, message. Verify and contextualize them, drop false positives, and add
the reading-layer smells tools cannot see.>
Any dimension these observations do not cover is a coverage gap. Record it; do
not try to fill it by running a tool.

## Your reference
Read the **absolute path** to `references/languages/<LANGUAGE>.md` supplied in
this Brief, under the installed sniff skill directory, FIRST. It is your smell
checklist and idiom guide; its tool commands are operator follow-ups, not
commands for you. Do not resolve that path from the target repository's working
directory or improvise the catalog.

## Project conventions
- Config files governing this language: <e.g. .golangci.yml, pyproject.toml>
- Respect them; do not override project config.

## Return
1. One line: `STATUS: FINDINGS|CLEAN` with the language and scope.
2. Coverage: observations used, dimensions left as gaps, and the scanned scope.
3. Findings, one line each: `file:line`, smell, source (observation or
   reading), evidence, idiomatic alternative, and the refactoring.guru smell
   name when one applies.
Do not prioritize or fix; return raw findings. Never reprint code or file contents.
```

---

## Filling guidance

- **One language per scout is the floor, not the cap.** Go + TS + Dockerfile is
  three scouts; a large single language (29k-LOC Rust) is several scouts split by
  subtree/crate, each with its own narrowed Scope.
- **Hand observations, don't re-run.** Each Brief carries that slice's
  `sniff_run_analyzer` observations; the scout verifies them and adds the
  reading layer. A dimension no recipe covered stays a gap in the report.
- **Scope tightly.** Pass real paths, not "the whole repo" -- for a split language,
  the specific subtree this scout owns. Keeps the scan focused and findings
  locatable, and stops two scouts covering the same files.
