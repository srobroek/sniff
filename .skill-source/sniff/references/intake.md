# Adaptive intake

Sniff uses a decision frontier. A complete request yields no question. An incomplete request yields one question. The runtime selects the first unresolved choice from the order below. That choice has the greatest effect on the plan. The plan covers these fields:

- target
- intent
- objectives
- exclusions
- analyzers
- budget
- route
- confirmation before analysis

## Frontier order

1. target
2. intent
3. objective groups
4. budget

## Interactive runs

- Use `references/targeting.md` to resolve the target.
- Keep its commit IDs fixed.
- Display the file set and checkout mode.
- Ask for confirmation before analysis.
- Keep installation and report saving as separate approvals.
- Keep the issued lease active until terminal report completion or explicit cancellation.

## Noninteractive runs

- Need authorization from the runtime confirmation boundary.
- Reject caller-provided authorization fields.
- Reject caller-provided analyzer dispositions.
- Apply documented defaults before deciding that the frontier is incomplete.
- Accept headless authorization only from the registered extension-host boundary.
- Record defaults and gaps in the manifest.
- Record the route and authorization receipt.
- Bind the capability to the manifest ID and trust tier.
- Bind it to the canonical target and selected recipes.
- Bind it to the confirmation receipt.
- Keep installation and sandbox grants in separate trusted host boundaries.
- Pass the exact serialized manifest to `sniff_report` under `sniff.intake` with the capability and manifest ID.
- Treat each selected analyzer recipe as a one-shot authorization.
- Enforce `maxAnalyzers`, `maxMinutes`, and `maxFiles` before launch and after completion.
- Release a reservation when preflight fails before launch. Never replay a launched recipe.
- Let the unref'd lease timer remove abandoned checkouts and isolated analyzer homes at expiry.
- Match the report kind and label to the authenticated `resolvedTarget`.
- Match the report base ref and file count to the authenticated `resolvedTarget`.
- Call `sniff_cancel` if the run ends without a report.
