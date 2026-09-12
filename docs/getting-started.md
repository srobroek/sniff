# Getting started

Sniff exposes one portable workflow through native and MCP adapters. Every adapter provides the same seven tools.

## Requirements

Install Git.

Install Bun for the bundled MCP server. Claude Code and Codex use Bun to run that server. The 2026-09-11 clean-room probes used Bun `1.4.2`.

## Install an adapter

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

After installation, start a new session in the repository that you want to inspect.

## Describe the intake

Sniff adapts its interview across five frontier axes:

- `target` identifies the repository or file set.
- `intent` identifies the desired outcome.
- `scopeMode` selects `quick`, `full`, or `plan-only` behavior.
- `objectives` identifies the objective groups.
- `budget` sets time, analyzer, and file limits.

Analyzer family and tier follow from the target, objectives, trust route, and availability.

The five frontier axes form the decision frontier. Sniff asks the highest-impact unresolved question. It waits for the answer. Sniff asks the next unresolved question.

Example requests:

- `Find code smells in the authentication package.`
- `Audit my uncommitted changes for correctness and maintainability.`
- `Review this pull request for structural risks.`
- `Plan a safe refactor of the cache layer without applying changes.`

Requests can specify any frontier axis. Sniff resolves missing choices and shows the plan that needs confirmation.

Read [Interviewing](interviewing.md) for request patterns and noninteractive defaults. Read [Sniff types](sniff-types.md) for exact values.

## Approve, analyze, and report

Plan confirmation issues a capability bound to the manifest. Installation needs separate approval. Analyzer execution uses the live capability. Report saving needs separate approval. Refactoring needs separate approval.

The seven tools follow this sequence:

1. `sniff_intake` resolves the frontier and obtains host approval or denial.
2. `sniff_install_tools` checks analyzer bundles and installs approved bundles.
3. `sniff_run_analyzer` revalidates the target and runs one selected recipe.
4. Use `sniff_read_analyzer_artifact` to page analyzer observations with the capability from `sniff_run_analyzer`.
5. `sniff_report` validates and renders a report or saves its artifact set.
6. `sniff_read_report_artifact` pages a complete report artifact with the opaque read capability returned by `sniff_report`.
7. `sniff_cancel` closes an unfinished run and removes temporary materialization.

Pass each reader's `nextOffset` as the next `offset` until `eof`. Each page is UTF-8 safe and at most 64 KiB. Responses include `totalBytes` and a SHA-256 digest. Registry expiry or eviction ends a read capability. Saving to a repository still needs separate approval.

Before installation, Sniff needs explicit approval. Remote targets use config-free, remote-safe recipes. Remote targets do not load project executable configuration.

After explicit approval, `sniff_install_tools` provisions pinned OpenGrep v1.30.0 for the selected `core` bundle. Before caching the asset, Sniff verifies its SHA-256 digest. Provisioning and version probing use a host-owned neutral directory. They do not execute target code. A later `sniff_run_analyzer` call runs the fixed, config-free recipe against authorized files.

`quick` skips the full sweep and challenge pass. `full` runs every skill step. `plan-only` keeps proposals read-only.

## Continue with the guides

- [Interviewing](interviewing.md)
- [Sniff types](sniff-types.md)
- [Workflow](workflow.md)
- [Targets and providers](targets-and-providers.md)
- [Capabilities and evidence](capabilities.md)
- [Security and trust](security-and-trust.md)
- [Reports](reports.md)
