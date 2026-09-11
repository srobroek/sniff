# Targeting

## Core rules

- Before analysis, resolve scope.
- List every file in the resolved target.
- Do not change commit IDs after resolution.
- Use in-place work only for files, working-tree, directory, and module targets.
- A whole-repo target means the committed `HEAD` snapshot, not current uncommitted changes: resolve its full SHA, enumerate `git ls-tree -r --name-only <sha>`, and materialize a temporary checkout.
- Hold each immutable commit, whole-repo, and remote target in a host-owned lease.
- Use `sniff_cancel` for abandoned runs.
- Let lease expiry remove the checkout and isolated analyzer home without another caller action.

## Target kinds

| Kind | Resolution | Materialization |
| Whole repo | committed `HEAD` tree (full SHA and every committed file) | temporary checkout |
| Language or area | matching extensions or area globs | in place or layered |
| Module or directory | subtree glob | in place |
| Files | explicit paths | in place |
| Working tree | unstaged, staged, and untracked paths | in place |
| Commit | commit snapshot and parent | temporary checkout |
| Range | changed paths between base and head | temporary checkout |
| Branch | changed paths from base or default branch | temporary checkout |
| Exact ref | ref tree | temporary checkout |
| Repository | one immutable remote ref | temporary checkout |
| PR or MR | provider changed paths and base/head SHAs | temporary checkout |
| Release or tag | snapshot and optional previous-tag delta | temporary checkout |
| History | commit window and changed paths | temporary checkout |

The core request kind is exact and closed: `whole-repo`, `working-tree`, `files`, `directory`, `module`, `commit`, `range`, `branch`, `ref`, `repository`, `pr`, `mr`, `release`, or `history`. “Whole repo” means the committed snapshot; use `working-tree` only when the user asks for uncommitted changes.

## Git commands

- Working tree: `git diff --name-only`
- Staged paths: `git diff --staged --name-only`
- Untracked paths: `git ls-files --others --exclude-standard`
- Commit paths: `git show --name-only --pretty=format: <sha>`
- Range paths: `git diff --name-only <base>...<head>`
- Ref paths: `git ls-tree -r --name-only <ref>`
- Contract paths: `git diff <base>...<head> -- <public modules>`
- Hunk paths: `git diff -U0`

- Before analysis, resolve each ref.
- Resolve branch names to commit SHAs.
- Peel annotated repository tags.
- Peel annotated tags from history windows.
- Compare and fetch commit SHAs, not tag-object SHAs.
- Use `git clone`, `fetch`, and `checkout --detach` through argv arrays.
- Do not build a shell command string.

- Reject URL userinfo and embedded credentials.
- Reject unsupported repository schemes and whitespace.
- Reject a repository value that starts with a dash.
- Reject leading options in refs, tags, and dates.
- Reject invalid counts, PR numbers, and MR IIDs.
- Use the provider credential store. Do not persist transport credentials.

- When a CLI is absent, report a gap.
- When authentication fails, report a gap.

## File reduction


- Drop vendored directories.
- Drop build directories.
- Drop tool directories.
- Drop scaffolding directories.
- Drop `package-lock.json`.
- Drop `Cargo.lock`.
- Drop `poetry.lock`.
- Drop `uv.lock`.
- Drop `pnpm-lock.yaml`.
- Drop `*.min.js`.
- Drop `*.pb.go`.
- Drop `*_pb2.py`.
- Drop paths marked `linguist-generated` in `.gitattributes`.
- Drop binaries.
- Drop data blobs.
- Drop images.
- Drop `.onnx` files.
- Drop archives.
- Echo counts for first-party files after reduction.

`.gitignore` does not cover committed vendor or generated trees. A language or
area filter can span directories and crates. Detect languages from the reduced
file set, not from prose in the request.

## Tool paths and trust

- Bind the canonical root, analyzable head files, and status-bearing change metadata to the lease.
- Preserve deleted paths as base-side change metadata.
- Do not pass deleted paths to analyzers.
- Revalidate the root and every file after analyzer preflight, immediately before spawn.
- Reject any symlink escape or file-set change.
- Resolve analyzer executables through absolute PATH entries, then use their canonical absolute host paths.
- Reject empty or relative PATH entries and executables inside the target root.
- Treat every remote target as untrusted and run only catalogued config-free recipes with a restricted credential-free environment.
- Do not load executable project configuration, bootstrap dependencies, or run hooks for remote targets.
- Repository-controlled execution requires a separate host-issued sandbox grant without credentials or network access.
- Do not fall back from an untrusted checkout to in-place work.

## Analyzer scope classes

- A scoped-files recipe receives only compatible files from the resolved target.
- A bounded-history recipe receives only the authenticated history window.
- A repository-wide recipe runs only for an explicit `repository` or `whole-repo` target.
- An empty file set selects no file-scoped analyzer.
- Record incompatible recipes as skipped. Never widen the target to make a recipe runnable.

## Analyzer commands

- Ruff: `ruff check --output-format json <files>`
- ESLint: `npx eslint --format json <files>`
- ShellCheck: `shellcheck -f json <files>`
- OpenGrep: `opengrep --config <ruleset> --json <files-or-dirs>`
- Go: `golangci-lint run --out-format json <dirs-of-target-.go-files>`
- Protobuf: `buf breaking --against ".git#ref=<base-ref>,subdir=<proto-dir>"`
- GraphQL: `graphql-inspector diff <base-schema> <head-schema>`
- OpenAPI: use `oasdiff` for base versus head.
- OpenAPI: use `openapi-diff` for base versus head.
- Duplication: run `jscpd` on the target and its directory.
- Filter `golangci-lint` JSON to target paths.
- Report `jscpd` blocks that touch a target file.

## Provider dependencies

- `git` supports local refs.
- `git` supports remote refs.
- `git` supports history.
- `git` supports temporary checkout.
- `gh` supports GitHub PR and release targets.
- `glab` supports GitLab MR and release targets.
- Capture each remote ref as a full commit SHA before materialization.
- Fetch enough ancestry and tags for every requested window.
- Run materialized history commands only against captured SHAs or fetched release tags.
- Date and count windows use the captured head.
- Release windows use the captured release and head commits.
- The context-aware default compares the captured head with its parent.
- A non-Git repository supports file targets.

## Apply boundary

- Plan-only mode never changes files.
- Apply mode needs explicit confirmation.
- Install tools only with confirmation.
- Edit source only with confirmation.
- Push remotes only with confirmation.
- Mutate a remote repository only with confirmation.

## Examples

- For `sniff PR #128`, run `gh pr diff 128 --name-only`.
- For that PR, detect TypeScript and Protobuf.
- For TypeScript, run ESLint.
- For Protobuf, run `buf breaking --against ".git#ref=<base>,subdir=<proto-dir>"`.
- For `sniff the parser module`, use `src/parser/**`.
- For that module, run Rust tools on the crate.
- Filter module paths to `src/parser/`.
- For `sniff since main`, isolate `HEAD`.
- For that history window, run `git diff --name-only main...HEAD`.
- Scope local tools.
- Compare contracts with `main`.
