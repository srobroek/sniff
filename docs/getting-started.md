# Getting started

Sniff runs as an OMP extension. The current verified adapter is OMP. Claude Code and Codex adapters are not documented as supported adapters.

## Requirements

Before you begin, install these commands:

- `git`
- `omp`

Analyzer availability depends on the languages in the selected target. Sniff never installs an analyzer without a separate approval.

## Link the plugin

Clone the repository and link its root directory:

```sh
git clone https://github.com/srobroek/sniff.git
omp plugin link "$(pwd)/sniff"
omp plugin doctor
```

After linking, start a new OMP session. Run the session from the repository that you want to inspect.

## Describe the intake

Interactive intake has four frontier decisions:

1. `target`
2. `intent`
3. `objectives`
4. `budget`

Sniff orders questions by plan impact. Natural-language text does not follow a fixed script.

When you know all four decisions, use a request that names them:

> Inspect the uncommitted changes for structure and correctness in plan-only mode with a five-minute budget.

The request sets `target`.

It sets `intent: audit`.

It sets two objective groups.

It sets `plan-only` scope mode.

It sets `maxMinutes: 5`.

Sniff asks no frontier question. Before analysis, Sniff asks you to confirm the resolved plan.

Read [Interviewing](interviewing.md) for request patterns. Read it for defaults, gaps, and cancellation. Read [Sniff types](sniff-types.md) for the exact enums.

## Confirm the plan

Before analysis, inspect these resolved values:

- target label
- immutable commit or working-tree state
- exact file count
- selected objective groups
- selected analyzers
- skipped analyzers and reasons
- time, analyzer, and file budgets
- defaults, coverage gaps, and trust route

Check that the target matches your request. Then confirm the plan. Confirmation is separate from analyzer installation, report saving, and applying a refactor.

## Handle analyzer availability

Before installation, ask Sniff to probe the catalog. The agent calls `sniff_install_tools` with `mode: "probe"` and shows each selected bundle status.

Choose only the bundles that the target needs. After you approve installation, the agent can call `sniff_install_tools` with `mode: "install"` and the bundle names returned by the probe.

Bundles group catalog entries for installation. They do not authorize a scan. Installation also does not authorize a later analyzer run.

An unavailable analyzer becomes a coverage gap. Remote targets use config-free recipes. Sniff does not install target dependencies or run executable project configuration for a remote target.

## Finish the run

Before report rendering, `full` mode challenges the initial findings. `quick` mode skips the full sweep and challenge pass. `plan-only` mode keeps every proposal read-only.

Render mode keeps the validated report in the OMP session. Save mode needs an explicit output directory and writes JSON, Markdown, and receipt artifacts.

A cancellation before reporting stops the run. `sniff_cancel` releases the single-process lease and removes temporary checkout and analyzer-home materialization.

## Next guides

- [Interviewing](interviewing.md)
- [Sniff types](sniff-types.md)
- [Workflow](workflow.md)
- [Targets and providers](targets-and-providers.md)
- [Security and trust](security-and-trust.md)
- [Reports](reports.md)
