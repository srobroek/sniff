# Adaptive intake

`sniff_intake` resolves a decision frontier. A complete request yields no question. An incomplete request yields one question: the first unresolved choice in the frontier order, because it has the greatest effect on the plan. The plan covers these fields:

- target
- intent
- scopeMode
- objectives
- exclusions
- analyzers
- budget
- route
- confirmation before analysis

## Frontier order

1. target
2. intent
3. scopeMode
4. objectives
5. budget

## Interactive runs

- Keep resolved commit IDs fixed.
- Show the file set and checkout mode, then ask for confirmation before analysis.
- Keep installation and report saving as separate approvals.

## Noninteractive runs

- Authorization comes only from the host confirmation boundary. In a headless OMP session, the extension host authorizes the `sniff_intake` call it executes. A delegated brief can name the target and objectives, but it cannot authorize; never send authorization fields or analyzer dispositions, because intake rejects them.
- Intake applies documented defaults before treating the frontier as incomplete, and records defaults, gaps, the route, and the authorization receipt in the manifest.

## Budget and cancellation

- The host enforces `maxAnalyzers`, `maxMinutes`, and `maxFiles` before each launch and after completion. A launched recipe never runs again; a further run needs a new intake.
- Call `sniff_cancel` if the run ends without a report.
