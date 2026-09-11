# Workflow

- Intake runs first.
- Before analysis, scope and plan confirmation must exist.

## Step 0: intake

- Load `references/intake.md`.
- Use the decision frontier.
- Ask no question for a complete request.
- Ask one question for an incomplete request.
- Ask the highest-impact unresolved question.
- Present one plan after the answer.
- Need explicit authorization for noninteractive runs.
- Record defaults and gaps in the run manifest.
- Pass the manifest to reports through the `sniff.intake` extensions namespace.

## Step 0.5: target

- Offer the full target taxonomy:

- whole repo
- language or area filter
- directory or module
- file or files
- working tree
- commit
- range
- branch comparison
- exact ref
- repository
- PR or MR
- release or tag
- change history

- Do not infer whole-repository scope from a bare request.
- Resolve the target to an explicit file list.
- Before analysis, resolve a branch name to a full commit ID.
- Before analysis, resolve a tag name to a full commit ID.
- Before analysis, resolve a symbolic ref to a full commit ID.
- Record the base ID.
- Record the head ID.
- Choose in-place work for mutable local files and working-tree changes.
- Choose a host-owned lease for every immutable local or remote target.
- Keep it alive until reporting ends.
- Release it exactly once after terminal report success or failure, or through `sniff_cancel`.

## Step 1: reduce scope

- Drop vendor directories.
- Drop build directories.
- Drop tool directories.
- Drop scaffolding directories.
- Drop lockfiles.
- Drop generated files by header marker.
- Drop generated files by lockfile name.
- Drop paths marked `linguist-generated`.
- Drop binaries.
- Drop data blobs.
- Drop images.
- Drop `.onnx` files.
- Drop archives.
- Echo first-party counts.

- Apply reduction on every path.
- `.gitignore` does not cover committed vendor or generated trees.
- A language filter can span directories and crates.
- Detect languages from the reduced file set.


## Step 2: detect stack

- Load `references/languages/index.md` for each language and format in the reduced set.
- Treat configuration and data as targets.
- Treat contracts and infrastructure as targets.
- Treat Markdown as a target.
- For a trusted local target, inventory project config that can execute code.
- Do not execute or import repository-controlled configuration from an untrusted remote target.

- When these files are present, check them:

- `Cargo.toml`
- `go.mod`
- `tsconfig.json`
- `pyproject.toml`
- `.eslintrc*`
- `.golangci.yml`
- `.tflint.hcl`
- `.editorconfig`
- `clippy.toml`
- `rust-toolchain.toml`
- `mypy.ini`
- `setup.cfg`
- `.flake8`
- `eslint.config.*`
- `biome.json`
- `.prettierrc`
- `.shellcheckrc`
- `.stylelintrc*`
- `.yamllint`
- `.markdownlint*`

## Step 3: propose tools

- Inventory tools for every detected language.
- Respect project configuration only for trusted local targets.
- For untrusted remote targets, select config-free offline analyzers with bundled rules.
- Show analyzer names, versions, and dispositions.
- Record each recipe as scoped-files, bounded-history, or repository-wide.
- Mark a recipe skipped when its scope class or supported file types do not match the resolved target.
- Ask for confirmation before installation or analysis.

- A plugin hosted by a framework remains part of its host analyzer. An installed but unconfigured plugin is a coverage gap.

## Step 4: run tools

- Pass the issued capability, manifest ID, and selected recipe ID to `sniff_run_analyzer`.
- Run each selected recipe once. A concurrent or sequential replay is invalid.
- Pass only compatible files from the resolved target to an analyzer. Never substitute `.` for an empty set.
- Use a canonical host executable outside the target root for every probe and execution.
- Revalidate the canonical lease root and files after preflight, immediately before spawn.
- Bound the process timeout by the remaining `maxMinutes` budget.
- Let the tool revalidate the canonical root and every file immediately before execution.
- Reject caller control over analyzer execution.
- Treat missing dependencies as coverage gaps.
- For remote targets, use only host-owned fixed recipes.
- Strip credentials and reject project configuration.
- Do not bootstrap dependencies.
- Project code requires a host-issued sandbox grant.
- The sandbox must have no credentials or network access.
- Do not fall back from an untrusted checkout to in-place execution.

## Step 5: inspect changes

- Compare base and head contracts for a range.
- Compare exported signatures.
- Compare model fields.
- Run breaking-change tools for Protobuf.
- Run breaking-change tools for GraphQL.
- Run breaking-change tools for OpenAPI.
- Report compatibility risk.
- Keep findings inside the resolved target.

## Step 6: adversarial pass

- Run this pass in full mode.
- Skip this pass in quick mode.
- Use bounded security rules from `references/security-scope.md`.
- Do not fuzz.
- Do not exploit.
- Do not run DAST.
- Do not validate live secrets.
- Do not run a threat campaign.

## Step 7: report

- Group findings by objective.
- Include the target.
- Include the intent.
- Include exclusions.
- Include analyzers.
- Include the budget.
- Include defaults.
- Include gaps.
- Include authorization.
- Include confirmation.
- Include the route.
- Include the exact issued run manifest under the `sniff.intake` report extension.
- Pass its capability and manifest ID to `sniff_report`.
- Match the report kind and label to the authenticated manifest.
- Match the report base ref and file count to the authenticated manifest.
- Let the tool validate the manifest and release the lease.
- Keep other report extensions unchanged.
- Save only after explicit confirmation.

## Modes

- In quick mode, check errors.
- In quick mode, check smells.
- In quick mode, check hardcoded values.
- In quick mode, check names.
- Full mode runs every step.
- Plan-only mode runs planning and inspection but never applies changes.
- Debug mode combines with any mode and adds evidence capture.

## Apply boundary

- Plan-only mode never changes files.
- Apply mode needs explicit confirmation.
- Install tools only with confirmation.
- Edit source only with confirmation.
- Push remotes only with confirmation.
- Mutate a remote repository only with confirmation.
