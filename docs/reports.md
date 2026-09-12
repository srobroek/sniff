# Reports

Sniff creates one canonical report from an authenticated intake lease.

Build the report input from `reportTarget` returned by `sniff_intake`. Copy it into `report.target`. Add `languages`. Omit these fields:

- `root`
- `paths`
- `materialization`
- `immutableRef`
- `headRef`

## Render mode

Render mode returns a bounded Markdown summary and virtual artifact descriptors. It does not write files. The summary shows the highest-priority findings and links each shown source file to its per-file artifact. The complete findings remain available through the virtual descriptors.

Every adapter returns bounded metadata instead of the canonical report JSON or authenticated manifest. The response contains:

- the summary
- artifact descriptors
- the census receipt
- saved-path metadata

After rendering, call `sniff_read_report_artifact`. Pass the returned `readCapability` and `reportId`. Pass the descriptor `relativePath`. Continue with `nextOffset` until `eof`.

Each UTF-8-safe page is at most 64 KiB. The response includes `totalBytes` and a SHA-256 digest. The capability remains usable in-process until registry eviction. Repository saves need separate approval.

## Save mode

Before Sniff creates a destination directory, save mode needs trusted confirmation for:

- the exact report directory
- every relative artifact path and SHA-256 digest
- the manifest identity

A successful save atomically installs this layout under the authorized parent:

```text
<report-id>/
├── index.json
├── report.json
├── summary.md
├── manifest.json
├── coverage.json
├── receipt.json
└── files/
    └── <12-hex>-<safe-basename>.json
```

The files contain:

- `index.json`: report metadata and census values, with each artifact's reference, byte count, and SHA-256 digest
- `report.json`: the canonical report JSON
- `summary.md`: the complete Markdown report
- `manifest.json`: the authenticated intake manifest
- `coverage.json`: canonical analyzer coverage
- each file record: one normalized source path and its sorted findings
- `receipt.json`: report identity and digests, with finding and artifact counts

Sniff groups findings by normalized source path. It writes files and findings in sorted order. The report ID derives from the complete semantic report, so splitting artifacts does not change its identity.

Sniff rejects:

- output traversal or symlink components
- existing report destinations or staging collisions
- duplicate artifact names
- partial writes

It uses a sibling staging directory. If a write or rename fails, Sniff removes that directory.

## Summary and coverage

The Markdown summary contains these sections:

- summary
- tool coverage
- prioritized refactoring plan
- systemic patterns when present
- dropped and downgraded findings
- source-file links when findings exist

Coverage rows use these states:

- `ran`: the analyzer completed
- `skipped`: policy or scope excluded the analyzer
- `gap`: a required analyzer was unavailable
- `not-applicable`: the analyzer did not match the target

Read the Notes column for details about any state other than `ran`.

Each finding has a deterministic ID. If the analyzer key and structural location stay unchanged, presentation changes do not change the ID.

## Manifest authentication

The report carries the exact intake manifest under the internal `sniff.intake` extension key. Before calculating report identity, the report tool authenticates the lease. The hydrated manifest determines report identity.

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
