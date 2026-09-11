# Getting started

## Requirements

Before you begin, install these commands:

- `git`
- `omp`

Sniff runs inside OMP. Analyzer availability depends on the languages in your selected target.

## Link the plugin

Clone the repository and link its root directory:

```sh
git clone https://github.com/srobroek/sniff.git
omp plugin link "$(pwd)/sniff"
omp plugin doctor
```

After linking, start a new OMP session. Run the session from the repository that you want to inspect.

## Make a complete request

A complete request names these decisions:

- target
- intent
- objective group
- budget choice

Interactive intake requires the budget choice. The time, file, and analyzer limits are optional. Every supplied limit must be a positive integer.

Noninteractive intake can omit the budget. Its manifest records an empty default and a budget gap.

Use this request for a first run:

> Sniff the uncommitted changes in this repository. Audit structure and correctness in plan-only mode with a five-minute budget.

A required decision triggers one question. Sniff chooses the question that changes the plan most.

## Confirm the plan

Before analysis, check these values:

- target label
- immutable commit or working-tree state
- exact file count
- selected analyzers
- skipped analyzers and reasons
- time and file budgets

Check that the target matches your request. Then confirm the plan.

## Handle analyzer availability

Before installation, ask Sniff to probe the catalog. The agent calls `sniff_install_tools mode=probe` and shows each bundle status.

Choose only the bundles that the target needs. After you approve installation, the agent can call `sniff_install_tools mode=install bundles=["core","js-ts"]`. Replace those names with the bundles from the probe.

An unavailable analyzer becomes a coverage gap. Remote targets use config-free recipes. Sniff does not install their dependencies or run their executable configuration.

## Finish the run

Before report rendering, full mode challenges the initial findings. Quick mode skips that pass. Refuted full-mode findings remain visible as dropped or downgraded entries.

The rendered report stays in the session. When you need files, ask Sniff to save the report. Give an explicit output directory with that request.

A cancellation before reporting stops the run. It removes any temporary checkout and the isolated analyzer home.

## Next guides

- [Workflow](workflow.md)
- [Targets and providers](targets-and-providers.md)
- [Security and trust](security-and-trust.md)
- [Reports](reports.md)
