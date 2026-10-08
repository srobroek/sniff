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
|------|------------|-----------------|
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

## Refs and transport

- Before analysis, resolve each ref. Resolve branch names to commit SHAs, and peel annotated tags in repository and history targets.
- Compare and fetch commit SHAs, not tag-object SHAs.
- Use `git clone`, `fetch`, and `checkout --detach` through argv arrays; do not build a shell command string.
- Reject URL userinfo, embedded credentials, query and fragment values, unsupported schemes, and whitespace.
- Reject a repository value, ref, tag, or date that starts with a dash.
- Reject invalid counts, PR numbers, and MR IIDs.
- Use the provider credential store. Do not persist transport credentials.
- When a CLI is absent or authentication fails, report a gap. `providers.md` lists the failure codes.

## Provider support

- `git` supports local and remote refs, history, and temporary checkout. A non-Git tree supports only `files` and `directory` targets.
- `gh` adds GitHub PR and release targets; `glab` adds GitLab MR and release targets.
- Capture each remote ref as a full commit SHA before materialization, and fetch enough ancestry and tags for every requested window.
- Run history commands only against captured SHAs or fetched release tags. Date and count windows use the captured head; release windows use the captured release and head commits. The default compares the captured head with its parent.

## File reduction

- Drop vendored, build, tool, and scaffolding directories.
- Drop lockfiles (`package-lock.json`, `Cargo.lock`, `poetry.lock`, `uv.lock`, `pnpm-lock.yaml`) and generated code (`*.min.js`, `*.pb.go`, `*_pb2.py`, paths marked `linguist-generated` in `.gitattributes`).
- Drop binaries, data blobs, images, `.onnx` files, and archives.
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

## Sniff recipes

Only these fixed recipes produce Sniff coverage. Pass the recipe ID to `sniff_run_analyzer`; the host supplies the command, rules, and files.

| Recipe ID | Scope class | Covers | Remote targets |
|-----------|-------------|--------|----------------|
| `lizard:complexity` | scoped files | cyclomatic complexity, function length, parameter count | yes |
| `opengrep:hardcoded-values` | scoped files | hardcoded IPs, URLs, paths, connection strings, debug prints, untracked debt markers | yes |
| `gitleaks:tracked-history` | repository-wide | secrets in committed history | no |

Every other dimension, including lint, type checks, duplication, dead code, and contract diffs (`buf breaking`, `graphql-inspector diff`, `oasdiff`), is an operator follow-up. Record it as a `gap` coverage entry and list its command from the language reference. Never run it during a Sniff run.

## Apply boundary

- Plan-only mode never changes files.
- Apply mode needs explicit confirmation.
- Install tools only with confirmation.
- Edit source only with confirmation.
- Push remotes only with confirmation.
- Mutate a remote repository only with confirmation.

## Examples

- `sniff PR #128` resolves to `{"kind":"pr","repository":"<url>","number":"128"}`; `gh` captures the changed paths and base/head SHAs. Run `lizard:complexity` and `opengrep:hardcoded-values`; each receives only its compatible TypeScript and Protobuf files. Skip `gitleaks:tracked-history`, which is repository-wide. Record ESLint and `buf breaking --against ".git#ref=<base>,subdir=<proto-dir>"` as gaps with those commands.
- `sniff the parser module` resolves to `{"kind":"module","root":"<repo-root>","path":"src/parser"}` in place. The scoped-files recipes receive only files under `src/parser/`.
- `sniff since main` resolves to `{"kind":"branch","root":"<repo-root>","branch":"HEAD","base":"main"}`, isolating the changed paths from `git diff --name-only main...HEAD`. Compare contracts with `main` only as recorded follow-ups.
