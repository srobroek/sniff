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

All adapters expose exactly seven tools:

- `sniff_intake`
- `sniff_install_tools`
- `sniff_run_analyzer`
- `sniff_report`
- `sniff_read_report_artifact`
- `sniff_read_analyzer_artifact`
- `sniff_cancel`

The authored skill generates native skill trees for every supported adapter.

The interview uses five frontier axes:

- `target`
- `intent`
- `scopeMode`
- `objectives`
- `budget`

Analyzer family and tier follow from the confirmed target, objectives, trust route, and availability.

## Install

Install Git.

Install Bun for the bundled Claude Code and Codex MCP server. The clean-room probe used Bun `1.4.2`.

Use the marketplace commands for your harness.

### OMP

```sh
omp plugin marketplace add https://github.com/srobroek/sniff.git
omp plugin install sniff@sniff --scope=user
```

### Claude Code

```sh
claude plugin marketplace add https://github.com/srobroek/sniff.git
claude plugin install sniff@sniff --scope user --yes
```

### Codex

```sh
codex plugin marketplace add https://github.com/srobroek/sniff.git
codex plugin add sniff@sniff
```


## Use Sniff

Describe the target and desired outcome in the host conversation. Sniff asks for the highest-impact unresolved choice. Sniff asks for the next choice. A complete request still needs plan confirmation.

Example requests:

- `Find code smells in src/auth and explain which ones are worth fixing.`
- `Audit this branch for maintainability risks without changing code.`
- `Review PR 42 for structural problems and risky refactoring opportunities.`
- `Plan a refactor of the payment module, but do not apply it.`
- `Check these files for hardcoded credentials and configuration values.`

A confirmed run follows this flow:

1. Resolve the target and file set.
2. Detect languages.
3. Select analyzer recipes.
4. Probe analyzer availability.
5. Approve installation.
6. Run approved analyzers.
7. If the preview omits observations, page them with `sniff_read_analyzer_artifact`.
8. Challenge findings in `full` mode.
9. Render a validated report.
10. Use `sniff_read_report_artifact` to page complete findings.
11. Before saving report files, get approval.

Each approval has a separate boundary. A denied intake issues no lease. Installation approval does not authorize analysis. Save approval does not authorize a refactor. Use `sniff_cancel` to stop an unfinished run. Expiry and terminal report events also release the host-owned materialization.

If observations are absent from the preview, call `sniff_read_analyzer_artifact`. Pass `readCapability`, `analyzerResultId`, and one `relativePath` or `sourcePath`. Continue from `nextOffset` until `eof`.

After `sniff_report`, call `sniff_read_report_artifact`. Pass its `readCapability`, `reportId`, and descriptor `relativePath`. Continue with the returned `nextOffset` until `eof`.

Registry expiry or eviction ends a read capability. Each page is UTF-8 safe and at most 64 KiB. Responses include `totalBytes` and a SHA-256 digest. Saving to a repository still needs separate approval.

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
