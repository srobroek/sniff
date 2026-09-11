# Reports

After analysis, Sniff creates one canonical report.

## Report contents

The Markdown report contains these sections:

- summary
- tool coverage
- prioritized refactoring plan
- systemic patterns when present
- dropped and downgraded findings

Coverage rows use these states:

- `ran`: the analyzer completed
- `skipped`: policy or scope excluded the analyzer
- `gap`: a required analyzer was unavailable
- `not-applicable`: the analyzer did not match the target

Read the Notes column for details about any state other than `ran`.

The prioritized plan includes `keep` and `downgrade` findings. The disposition table lists only `downgrade` and `drop` results. Quick mode skips the challenge pass.

Each finding has a deterministic ID. If the analyzer key and structural location stay unchanged, presentation changes do not change the ID.

## Render mode

Render mode returns Markdown to the OMP session. Tool details expose the validated report and receipt. It does not write files.

While you review findings or change the plan, use render mode.

## Save mode

Save mode needs an explicit output directory. Sniff writes these files:

```text
<report-id>.json
<report-id>.md
<report-id>.receipt.json
```

If the directory does not exist, Sniff creates it. If any destination exists, Sniff refuses the complete save.

## Validation receipt

The receipt records:

- schema version
- report ID
- SHA-256 hash of canonical JSON
- SHA-256 hash of Markdown
- finding count

Before saving, Sniff regenerates each artifact and verifies its canonical hash.

## Manifest authentication

The report carries the exact intake manifest under the `sniff.intake` extension key. The report tool also receives the capability and manifest ID.

Sniff rejects these states:

- changed manifest content
- unknown capability
- expired capability
- replayed capability
- target metadata that differs from intake

A terminal report attempt releases the capability even when validation fails.

## Apply tiers

Each retained finding has an apply tier. The tier tells the host or agent whether the proposed refactor needs another approval. The report tool does not edit code.

Plan-only mode keeps every proposal read-only.
