# Sniff types

Sniff keeps intake and report axes separate in one portable core. Native and MCP adapters expose the same seven tools:

- `sniff_intake`
- `sniff_install_tools`
- `sniff_run_analyzer`
- `sniff_report`
- `sniff_read_analyzer_artifact`
- `sniff_read_report_artifact`
- `sniff_cancel`

Use these values in structured intake. Natural-language requests describe interaction. They are not shell commands.

## Intake intents

`IntakeIntent` accepts five values:

- `audit`: general code-smell audit.
- `review-change`: review a change target.
- `release-risk`: focus on release risk.
- `history`: analyze a history target or window.
- `plan-only`: request a planning outcome without applying a refactor.

Intent chooses the intake outcome. It does not choose the target. It does not choose the objective group. It does not choose scope mode. It does not choose analyzer tier.

## Objective groups

`OBJECTIVE_GROUPS` contains six values:

- `structure-and-maintainability`: cohesion and complexity checks.
- `correctness-and-resilience`: bugs and failure-path checks.
- `performance-and-efficiency`: avoidable-work and hotspot checks.
- `change-and-release-risk`: compatibility and release-delta checks.
- `tests-delivery-and-tooling`: test-gap and CI checks.
- `bounded-security-smells`: bounded security checks.

Without an objective choice, authorized noninteractive intake selects all six groups. Sniff records unselected groups as skipped.

## Target kinds

`TargetKind` contains fourteen intake target values. Each target resolves to an exact file set. Immutable Git targets also receive an immutable commit identity.

- `working-tree`: tracked and untracked changes in a local root.
- `files`: named files inside a local root.
- `directory`: files below a local directory.
- `module`: files below a resolved module path.
- `commit`: a commit snapshot in an isolated checkout.
- `range`: captured base and head commits with their change set.
- `branch`: captured branch and optional base commits.
- `ref`: a peeled commit snapshot.
- `repository`: a repository URL with an optional ref.
- `release`: a repository URL with a release tag and optional preceding tag.
- `history`: a local root or repository with one `HistoryWindow`.
- `pr`: a GitHub pull request target.
- `mr`: a GitLab merge request IID with provider metadata.

Local paths stay inside the selected root. Remote targets use a temporary checkout and the `untrusted-remote` route.

### Providers

`ProviderName` contains three values:

- `github`: uses `gh` for GitHub requests.
- `gitlab`: uses `glab` for GitLab requests.
- `generic-git`: uses `git` for generic repository operations.

Sniff uses provider credential stores. Repository URLs must not contain user information, query values, or fragments.

## History windows

`HistoryWindow` contains six values:

- `refs`: compare `base` with `head`.
- `since-date`: select history after `date`. An optional `head` ends the window.
- `last-commits`: select a positive `count`. An optional `head` ends the window.
- `since-release`: select changes after `release`. An optional `head` ends the window.
- `previous-release`: compare a release with its predecessor. `release` and `head` are optional.
- `context-aware-default`: choose the window from repository context. `head` is optional.

Before checkout, remote history resolves refs. History semantics stay separate from target kind and intake intent.

## Skill scope modes

The report target contract calls this axis `scopeMode`. It accepts three values:

- `quick`: run common checks and local smell detection. Skip the full sweep and challenge pass.
- `full`: run every skill step. Include the challenge pass.
- `plan-only`: keep the proposed plan read-only. Never apply changes.

`plan-only` appears in both `IntakeIntent` and `scopeMode`. Intent describes the requested outcome. Scope mode describes run behavior.

## Security tiers and trust

`SecurityAnalyzerTier` contains three values:

- `project-native`: project-controlled analyzer execution.
- `lightweight-static`: bounded static checks with a remote-safe, config-free recipe.
- `deep-static`: deeper static analysis with explicit opt-in on a trusted local target.

`TargetTrust` contains two values:

- `trusted-local`: local targets can use host-owned recipes. Project-controlled execution still needs a sandbox grant without credentials or network access.
- `untrusted-remote`: remote targets use config-free offline recipes, bundled rules, and an isolated analyzer home. Sniff does not install target dependencies.

Remote targets select only recipes marked `remoteSafe` and `configFree`.

Sniff records each analyzer as selected, skipped, or unavailable. It rejects fuzzing and exploitation. It rejects DAST. It rejects live-secret validation. It rejects threat campaigns.

## Analyzer recipes

`SNIFF_ANALYZER_RECIPES` is the execution catalog. Recipe IDs differ from installer bundle names.

- `lizard:complexity`: tool `lizard`; tier `lightweight-static`; scope `scoped-files`; remote-safe and config-free.
- `opengrep:hardcoded-values`: tool `opengrep`; tier `lightweight-static`; scope `scoped-files`; remote-safe and config-free.
- `gitleaks:tracked-history`: tool `gitleaks`; tier `lightweight-static`; scope `repository-wide`; the recipe runs locally and reads target configuration.

When cyclomatic complexity exceeds 10, function length exceeds 50, or parameter count exceeds 5, Lizard emits an observation.

The `opengrep` recipe uses pinned OpenGrep v1.30.0. With explicit `sniff_install_tools` approval, Sniff downloads the platform asset and verifies its SHA-256 digest before caching it. Provisioning and probing use a host-owned neutral directory. They do not execute target code. A later analyzer run uses the fixed, config-free recipe against authorized files.

The security catalog uses these three recipe IDs. Each recipe is default-enabled. A capability authorizes a selected recipe once for the confirmed target.

## Installer bundles

`BUNDLES` contains fourteen values. `TOOLS` defines membership. Bundles group catalog entries by target family. Bundles do not authorize execution.

- `core`: `opengrep` `lizard` `scc` `ast-grep` `tokei`
- `dup`: `jscpd`
- `security`: `trivy` `checkov` `gitleaks`
- `rust`: `cargo-clippy` `cargo-machete` `cargo-udeps` `cargo-geiger`
- `go`: `golangci-lint` `deadcode` `go-vet` `staticcheck` `gocyclo` `gocognit` `gosec`
- `python`: `ruff` `vulture` `pylint` `mypy` `pyright` `radon` `xenon` `deptry` `bandit`
- `js-ts`: `eslint` `tsc` `knip` `dependency-cruiser` `type-coverage` `madge` `biome` `svelte-check` `vue-tsc`
- `shell`: `shellcheck` `shfmt`
- `sql`: `sqlfluff` `squawk`
- `css`: `stylelint` `css-analyzer`
- `data`: `yamllint` `taplo` `check-jsonschema`
- `api`: `vacuum` `spectral` `openapi-spec-validator` `oasdiff` `graphql-inspector` `buf` `protolint`
- `infra`: `hadolint` `tflint` `terraform` `actionlint` `zizmor` `pinact` `glab-ci-lint` `kube-linter` `kubeconform`
- `docs`: `markdownlint-cli2` `lychee` `cspell`

`SniffInstallMode` accepts four values:

- `probe`: check tool availability and version behavior.
- `diagnose`: inspect selected bundles and report routes or failures.
- `list`: list the canonical bundle inventory.
- `install`: install selected bundles and re-probe a fresh environment.

Installation approval stays separate from intake confirmation and analyzer execution approval.

## Report modes and outcomes

`SniffReportMode` accepts two values:

- `render`: return validated report content to the host session. Do not write files.
- `save`: need an explicit output directory. Write the report artifact set.

Save mode writes one report directory:

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

If a destination exists, Sniff refuses the complete save. The receipt records the report ID. It records the schema version. It records the canonical JSON SHA-256. It records the Markdown SHA-256. It records the finding count.

After `sniff_run_analyzer` returns a truncated preview or complete observations are required, call `sniff_read_analyzer_artifact` with its `readCapability`, `analyzerResultId`, and either a descriptor `relativePath` or `sourcePath`. Continue with `nextOffset` until `eof`.

After `sniff_report` returns render descriptors, call `sniff_read_report_artifact`. Pass its `readCapability`, `reportId`, and a descriptor `relativePath`. Continue with `nextOffset` until `eof`.

Registry expiry or eviction ends a read capability. Each page is UTF-8 safe and at most 64 KiB. Responses include `totalBytes` and a SHA-256 digest. Repository saves still need separate approval.

`CoverageStatus` contains four values:

- `ran`: the analyzer completed.
- `skipped`: policy or scope excluded the analyzer.
- `gap`: a required analyzer was unavailable.
- `not-applicable`: the analyzer did not match the target.

A stopped run needs `sniff_cancel` before reporting. The lease registry is single-process state. See [Getting started](getting-started.md) for adapter installation and [Capabilities](capabilities.md) for verified behavior and clean-room limits.

## Related guides

- [Getting started](getting-started.md)
- [Interviewing](interviewing.md)
- [Capabilities and evidence](capabilities.md)
- [Workflow](workflow.md)
- [Targets and providers](targets-and-providers.md)
- [Security and trust](security-and-trust.md)
- [Reports](reports.md)
