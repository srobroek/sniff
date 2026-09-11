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
- Copy the returned `reportTarget` into `report.target`, then add `languages`. Pass capability and manifest ID to `sniff_report`. The host authenticates that pair and injects the exact stored manifest when `extensions["sniff.intake"]` is omitted; if supplied, the extension must be byte-for-byte equivalent to the issued manifest.
- Use the opaque read capability returned by `sniff_report` with `reportId` and a descriptor `relativePath` when reading complete report artifacts. Pass `nextOffset` to continue paging; each page is UTF-8-safe and at most 64 KiB.
- Enforce `maxAnalyzers`, `maxMinutes`, and `maxFiles` before launch and after completion.
- Release a reservation when preflight fails before launch. Never replay a launched recipe.
- Let the unref'd lease timer remove abandoned checkouts and isolated analyzer homes at expiry.
- Match the report kind and label to the authenticated `resolvedTarget`.
- Match the report base ref and file count to the authenticated `resolvedTarget`.
- Call `sniff_cancel` if the run ends without a report.
