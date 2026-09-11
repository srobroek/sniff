# Getting started

Sniff uses one portable core. OMP loads a native extension. Claude Code and Codex load MCP adapters. Every adapter exposes the same five tools.

## Requirements

Install Git.

Install Bun for the bundled MCP server. Claude Code and Codex use Bun to run that server. The 2026-09-11 clean-room probes used Bun `1.4.2`.

## Install an adapter

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

After the cross-harness branch or release reaches public main or a public release, run these commands. Validation on 2026-09-11 used copied local marketplace sources. The remaining delivery gate is publication to public main or a public release. Remote publication was not tested.

After installation, start a new session. Run it from the repository that you want to inspect.

## Describe the intake

Sniff adapts its interview across five axes:

- `target` identifies the repository or file set.
- `intent` identifies the desired outcome.
- `objectives` identifies the objective groups.
- `scopeMode` selects `quick`, `full`, or `plan-only` behavior.
- analyzer family and tier follow from the target, objectives, trust route, and availability.

The first four axes form the decision frontier. Sniff asks the highest-impact unresolved question. It waits for the answer. Sniff asks the next unresolved question.

For example:

> Inspect the uncommitted changes for structure and correctness in plan-only mode with a five-minute budget.

Sniff resolves the target. Sniff resolves the intent. Sniff resolves objective groups. Sniff resolves scope mode. Sniff records the budget. Sniff shows the plan for confirmation.

Read [Interviewing](interviewing.md) for request patterns and noninteractive defaults. Read [Sniff types](sniff-types.md) for exact values.

## Approve, analyze, and report

Plan confirmation issues a capability bound to the manifest. Installation needs separate approval. Analyzer execution uses the live capability. Report saving needs separate approval. Refactoring needs separate approval.

The five tools follow this sequence:

1. `sniff_intake` resolves the frontier and obtains host approval or denial.
2. `sniff_install_tools` checks analyzer bundles and installs approved bundles.
3. `sniff_run_analyzer` revalidates the target and runs one selected recipe.
4. `sniff_report` validates and renders a report or saves its artifact set.
5. `sniff_cancel` closes the capability and removes temporary materialization.

Before installation, Sniff needs explicit approval. Remote targets use config-free, remote-safe recipes. Remote targets do not load project executable configuration.

`quick` skips the full sweep and challenge pass. `full` runs every skill step. `plan-only` keeps proposals read-only.

## Continue with the guides

- [Interviewing](interviewing.md)
- [Sniff types](sniff-types.md)
- [Workflow](workflow.md)
- [Targets and providers](targets-and-providers.md)
- [Capabilities and evidence](capabilities.md)
- [Security and trust](security-and-trust.md)
- [Reports](reports.md)
