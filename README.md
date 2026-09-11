# Sniff

Sniff finds code smells in OMP and produces reviewed plans for refactoring. Analysis stays read-only until you approve a change.

| Field | Value |
| --- | --- |
| Status | Pre-release |
| Version | `0.1.0` |
| Runtime | Oh My Pi |

## Install from source

You need Git and an installed `omp` command.

```sh
git clone https://github.com/srobroek/sniff.git
omp plugin link "$(pwd)/sniff"
omp plugin doctor
```

After linking the plugin, start a new OMP session. Run `omp plugin doctor` and confirm that it identifies Sniff as a plugin.

## Run your first audit

Open OMP in the repository that you want to inspect. Ask:

> Sniff the uncommitted changes in this repository.

A normal run follows this sequence:

1. Resolve the target and its exact file set.
2. Ask for the highest-impact missing decision.
3. Detect the languages in scope.
4. Probe suitable analyzers.
5. Run approved analyzers with fixed recipes.
6. Challenge each finding.
7. Render a validated report.

Remote repositories use an isolated checkout. Sniff treats every remote target as untrusted. It does not load project executable configuration or install project dependencies for that target.

## Choose a skill mode

| Mode | Behavior |
| --- | --- |
| `quick` | Checks common errors and local smells. It skips the full sweep and challenge. |
| `full` | Runs every skill step. |
| `plan-only` | Runs planning and inspection but never changes code. |

A missing mode triggers a question only if the choice changes the plan.

## Select a target

Sniff accepts local and hosted Git targets. It also accepts releases and history windows.

Example requests:

- `Sniff src/parser in full mode.`
- `Sniff the range main...HEAD for correctness and maintainability.`
- `Sniff PR 42 from https://github.com/srobroek/sniff in plan-only mode.`
- `Sniff changes since release v2.4.0.`

See [Targets and providers](docs/targets-and-providers.md) for the full target table.

## Understand approvals

Sniff separates these decisions:

- confirm the resolved analysis plan
- install a missing analyzer
- save report artifacts
- apply an approved refactor

Analysis does not grant permission for installation, saving, or editing. To stop a run, ask Sniff to cancel it. Otherwise, lease expiry removes temporary files.

## Read the output

The default report stays in the session. An explicit save request writes three files:

- `<report-id>.json`
- `<report-id>.md`
- `<report-id>.receipt.json`

The receipt binds the report ID to the canonical JSON hash. Sniff refuses to overwrite an existing artifact set.

## Guides

- [Getting started](docs/getting-started.md)
- [Workflow](docs/workflow.md)
- [Targets and providers](docs/targets-and-providers.md)
- [Security and trust](docs/security-and-trust.md)
- [Reports](docs/reports.md)

## Develop Sniff

```sh
bun install
bun run check
```

The check runs TypeScript and Biome. It also runs the Bun test suite.
