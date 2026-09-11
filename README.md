# Sniff

Sniff audits code smells and produces a reviewed plan. It asks for unresolved intake decisions. It runs approved analyzers. It challenges findings in `full` mode. It renders or saves a report.

## Portable core and adapters

Sniff uses a portable core. The core handles these concerns:

- intake and target resolution
- analyzer catalogs
- run leases and approvals
- report validation
- cancellation, expiry, and replay protection

The source skill generates native skill trees. It lives in `.skill-source/sniff/`.

Claude Code and Codex load the bundled MCP server through plugin manifests.

All adapters expose six tools:

- `sniff_intake`
- `sniff_install_tools`
- `sniff_run_analyzer`
- `sniff_report`
- `sniff_read_report_artifact`
- `sniff_cancel`

The authored skill in `.skill-source/sniff/` generates native skill trees for OMP, Claude Code, and Codex.

The interview models five axes:

- `target`
- `intent`
- `objectives`
- `scopeMode`
- analyzer family and tier

The first four axes form the adaptive frontier. Analyzer selection uses the confirmed target and objectives.

## Install

Install Git.

Install Bun for the bundled Claude Code and Codex MCP server. The clean-room probe used Bun `1.4.2`.

After the cross-harness branch or release reaches public main or a public release, run the GitHub marketplace commands for your harness.

### OMP

```sh
omp plugin marketplace add https://github.com/srobroek/sniff.git
omp plugin install sniff@srobroek/sniff --scope=user
```

### Claude Code

```sh
claude plugin marketplace add https://github.com/srobroek/sniff.git
claude plugin install sniff@srobroek/sniff --scope user --yes
```

### Codex

```sh
codex plugin marketplace add https://github.com/srobroek/sniff.git
codex plugin add sniff@srobroek/sniff
```

After the cross-harness branch or release reaches public main or a public release, run these commands.

Validation on 2026-09-11 used copied local marketplace sources. The remaining delivery gate is publication to public main or a public release. Remote publication was not tested.

## Use Sniff

Describe the target and desired outcome in the host conversation. Sniff asks for the highest-impact unresolved choice. Sniff asks for the next choice. A complete request still needs plan confirmation.

A confirmed run follows this flow:

1. Resolve the target and file set.
2. Detect languages.
3. Select analyzer recipes.
4. Probe analyzer availability.
5. Ask before installing a missing bundle.
6. Run approved analyzers.
7. Challenge findings in `full` mode.
8. Render a validated report.
9. Page complete report artifacts with `sniff_read_report_artifact` when needed.
10. Ask before saving report files.

Each approval has a separate boundary. A denied intake issues no lease. Installation approval does not authorize analysis. Save approval does not authorize a refactor. Use `sniff_cancel` to stop an unfinished run. Expiry and terminal report events also release the host-owned materialization.

After `sniff_report`, call `sniff_read_report_artifact`. Pass its read capability and report ID. Pass the descriptor path. Continue with `nextOffset` until `eof`.

Each UTF-8-safe page is at most 64 KiB. The response includes `totalBytes` and a SHA-256 digest. The read capability remains usable in-process until bounded registry eviction. Saving to a repository still needs separate approval.

`quick` skips the full sweep and challenge pass. `full` runs every skill step. `plan-only` keeps proposals read-only.

Read [Getting started](docs/getting-started.md) for installation and the first run. Read [Interviewing](docs/interviewing.md) for adaptive intake and approvals. Read [Sniff types](docs/sniff-types.md) for the structured contract. Read [Capabilities](docs/capabilities.md) for implementation and clean-room evidence.

## Targets and trust

Sniff accepts these target kinds:

- local paths
- commits and ranges
- branches and refs
- repositories and releases
- history windows
- pull requests and merge requests

Remote targets use an isolated checkout. They use bundled rules. They use an analyzer home.
The analyzer home does not load project executable configuration. It does not install target dependencies.

See [Targets and providers](docs/targets-and-providers.md) for provider behavior. See [Security and trust](docs/security-and-trust.md) for trust boundaries.

## Development

```sh
bun install
bun run check
```

The check validates generated harness skills. It validates MCP bundles. It runs TypeScript, Biome, and Bun tests.

## License

Apache-2.0.
