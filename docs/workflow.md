# Workflow

The operational sequence lives in the authored [Sniff skill](../.skill-source/sniff/SKILL.md). Read it before each run.

Sniff resolves the decision frontier (`target`, `intent`, `scopeMode`, `objectives`, `budget`), confirms one plan, and issues a capability and manifest ID for a lease-backed materialization. It detects languages, probes tools, runs each selected fixed recipe once, challenges findings in full mode, and renders or saves a validated report.

Noninteractive runs require host authorization. Installation, analysis, report saving, and refactoring retain separate approval boundaries. A non-Git tree uses `files` or `directory` scope instead of Git-only `whole-repo` or `working-tree` scope.

Page incomplete analyzer and report artifacts with their read capability, passing `nextOffset` until `eof`. Each UTF-8-safe page is at most 64 KiB. Reporting or cancellation releases the lease and materialization.

See [Interviewing](interviewing.md), [Sniff types](sniff-types.md), and the skill references for exact values and contracts.
