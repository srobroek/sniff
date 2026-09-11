# Sniff

Sniff audits code smells and produces reviewed plans. Analysis stays read-only until you approve a change.

| Field | Value |
| --- | --- |
| Status | Pre-release |
| Version | `0.1.0` |
| Current verified adapter | Oh My Pi (OMP) |

Sniff runs through its OMP extension entrypoints. Claude Code and Codex adapters are not documented as supported adapters.

## Install from source

You need Git and an installed `omp` command.

```sh
git clone https://github.com/srobroek/sniff.git
omp plugin link "$(pwd)/sniff"
omp plugin doctor
```

After linking the plugin, start a new OMP session. Run `omp plugin doctor` and confirm that it identifies Sniff as a plugin.

## Run your first audit

Open OMP in the repository that you want to inspect.

When you know all decisions, describe them in one request.

> Inspect the uncommitted changes for structure and correctness in plan-only mode with a five-minute budget.

The request is an interaction description, not a deterministic shell command. When a decision remains unresolved, Sniff asks the highest-impact choice. A complete request produces no intake question. Sniff still asks you to confirm the resolved plan.

A confirmed run follows this sequence:

1. Resolve the target and its exact file set.
2. Detect the languages in scope.
3. Probe suitable analyzers.
4. Run approved analyzers with fixed recipes.
5. Challenge each finding in `full` mode.
6. Render a validated report.

Remote repositories use an isolated checkout. Sniff treats every remote target as untrusted. It does not load project executable configuration or install project dependencies for that target.

Read [Interviewing](docs/interviewing.md) for the adaptive questions and [Sniff types](docs/sniff-types.md) for every supported axis.

## Choose a skill mode

| Mode | Behavior |
| --- | --- |
| `quick` | Runs common checks and local smell detection. It skips the full sweep and challenge pass. |
| `full` | Runs every skill step, including the challenge pass. |
| `plan-only` | Produces a read-only plan and never applies changes. |

## Select a target

Sniff accepts local and hosted Git targets. It also accepts releases and history windows. See [Targets and providers](docs/targets-and-providers.md) for request examples and provider behavior.

Examples of interaction descriptions:

- `Sniff src/parser in full mode.`
- `Sniff the range main...HEAD for correctness and maintainability.`
- `Sniff pull request 42 from the Sniff repository in plan-only mode.`
- `Sniff changes since release v2.4.0.`

When you provide structured intake data, use the exact target kind. See [Sniff types](docs/sniff-types.md) for the complete target and history enums.

## Understand approvals

Sniff separates these decisions:

- confirm the resolved analysis plan
- install a missing analyzer
- save report artifacts
- apply an approved refactor

Analysis does not grant permission for installation, saving, or editing. To stop a run, ask Sniff to cancel it. Otherwise, lease expiry removes temporary files.

## Read the output

Render mode returns the report in the OMP session. An explicit save request writes three files:

- `<report-id>.json`
- `<report-id>.md`
- `<report-id>.receipt.json`

The receipt binds the report ID to the canonical JSON hash. Sniff refuses to overwrite an existing artifact set.

## Guides

- [Getting started](docs/getting-started.md)
- [Interviewing](docs/interviewing.md)
- [Workflow](docs/workflow.md)
- [Sniff types](docs/sniff-types.md)
- [Targets and providers](docs/targets-and-providers.md)
- [Security and trust](docs/security-and-trust.md)
- [Reports](docs/reports.md)

## Develop Sniff

```sh
bun install
bun run check
```

The check runs TypeScript and Biome. It also runs the Bun test suite.
