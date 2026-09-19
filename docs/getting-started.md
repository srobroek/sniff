# Getting started

The canonical seven-tool contract is defined in [Capabilities](capabilities.md).

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

Read [Workflow](workflow.md) for the operational lifecycle and approval boundaries. The lifecycle pages analyzer and report artifacts with UTF-8-safe pages of at most 64 KiB, and each reader continues with `nextOffset` until `eof`.

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
