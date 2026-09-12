# Workflow

Sniff binds one run from intake through reporting. A capability and manifest ID authorize later tool calls. Every adapter follows this workflow.

## 1. Interview the request

Interactive intake checks the decision frontier in this order:

1. `target`
2. `intent`
3. `scopeMode`
4. `objectives`
5. `budget`

Sniff asks the next unresolved question. A complete prompt is silent at the frontier. Silence does not replace confirmation.

The plan keeps these axes separate:

- target identity
- exact file set
- intake intent
- objective groups
- exclusions
- analyzer dispositions
- budgets
- defaults and gaps
- trust route

See [Interviewing](interviewing.md) for request patterns. See [Sniff types](sniff-types.md) for exact values.

## 2. Confirm the resolved plan

Sniff resolves Git refs to immutable commits. Mutable local targets remain in place.

Sniff displays the target label and file count. It displays checkout mode. It displays analyzer choices and skipped analyzers. It displays the budget. It displays defaults and gaps. It displays the trust route.

Interactive runs need confirmation through the host interface. Sniff issues a capability only for the confirmed manifest. It rejects changed manifests and replayed capabilities.

Noninteractive runs need host authorization. They skip frontier questions.

Sniff applies these rules:

- Reject caller authorization.
- Reject caller choices.
- Record the receipt.
- Record defaults.
- Record gaps.

## 3. Detect the stack

Sniff detects languages from resolved files. It loads the matching language references.

Generated files and vendor files do not determine the stack. Before detection, Sniff removes them from the stack sample.

## 4. Probe analyzers

Sniff probes analyzers. A probe checks availability and version. A probe does not authorize a scan.

Before an interactive run, Sniff shows available tools by bundle. Installation needs separate approval. Bundles group catalog entries. Bundles do not authorize execution.

## 5. Run fixed recipes

Each selected analyzer has a fixed recipe. The capability limits the recipe to the target.

Sniff enforces these limits:

- exact file scope
- analyzer count
- file count
- elapsed minutes
- one run for each selected recipe

After preflight, Sniff checks the target again. Sniff blocks a file outside the root.

If observations are absent from the preview or the run needs full artifacts, use `sniff_read_analyzer_artifact`. Pass `nextOffset` until `eof`.

## 6. Read and challenge findings

Static tools do not cover every structural smell. Sniff reads the remaining target. It may divide large targets by language.

In `full` mode, a separate challenge pass tests each finding. The pass checks evidence and refactoring value. It can keep, downgrade, or drop a finding. `quick` mode skips the full sweep and challenge pass.

## 7. Report or apply

Match the target kind. Match the target label. Match the base ref and file count.

`render` mode returns validated report content without writing files. `save` mode needs an explicit output directory. It writes these files under a report directory:

- `index.json`
- `report.json`
- `summary.md`
- `manifest.json`
- `coverage.json`
- `receipt.json`
- per-file artifacts under `files/`

Applying a refactor needs separate approval. `plan-only` mode never applies changes.

## 8. Cancel and clean up

A run that stops before reporting needs `sniff_cancel`.

Cancellation closes the capability. It releases analyzer reservations. It removes the temporary checkout. It removes the analyzer home.

A successful report closes the lease. A failed report keeps the lease active for another attempt. Cancellation performs the same cleanup as successful reporting. An expiry timer cleans abandoned runs. The lease registry is single-process state.
