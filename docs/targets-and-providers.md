# Targets and providers

Before analysis, Sniff resolves every request to an explicit target. Git refs and remote targets use immutable commits. Mutable local files stay in place.

## Local targets

| Target | Request example | Resolution |
| --- | --- | --- |
| Working tree | `Sniff my uncommitted changes.` | Tracked and untracked changes in the current root |
| Files | `Sniff src/a.ts and src/b.ts.` | Named files inside the current root |
| Directory | `Sniff src/parser.` | Files below the named directory |
| Module | `Sniff the parser module.` | Files below the resolved module path |
| Commit | `Sniff commit abc123.` | Full commit SHA in an isolated checkout |
| Range | `Sniff main...HEAD.` | Captured base and head SHAs |
| Branch | `Sniff feature/cache against main.` | Captured branch and base SHAs |
| Ref | `Sniff tag v2.4.0.` | Peeled commit SHA |

Sniff rejects files that resolve outside the selected root. This includes files reached through symbolic-link ancestors.

## Hosted targets

| Target | Provider command | Result |
| --- | --- | --- |
| GitHub pull request | `gh`, `git` | `gh` supplies base SHA, head SHA, and metadata; `git` derives the changed paths |
| GitLab merge request | `glab`, `git` | `glab` supplies base SHA, head SHA, and metadata; `git` derives the changed paths |
| GitHub release | `gh` | Release commit and optional preceding release |
| GitLab release | `glab` | Release commit and optional preceding release |
| Git repository | `git` | Captured commit and snapshot files |

Sniff does not manage provider authentication.

### Pull and merge request change sets

`gh pr view` lists at most 100 files and `glab mr view` lists none, so Sniff never uses a provider file list. It captures the immutable base and head SHAs, fetches both into a temporary checkout (head by SHA, then `refs/pull/<n>/head` or `refs/merge-requests/<iid>/head` if the server refuses the SHA, so fork PRs work), deepens until they share a merge base that shallow history cannot contradict (every shallow boundary reachable from either tip must lie below the candidate; otherwise the base is unresolved and a gap is recorded), and runs `git diff --name-status -z --find-renames <merge-base> <head>`. This happens before the confirmation, so the approval shows the complete file list.

Gaps use `field: "target"`. When git cannot produce the diff (fetch refused, missing commit), or its result disagrees with the provider's `changedFiles` / `changes_count`, the target records a gap (`field`, `reason`, `impact`). Gaps are merged into the manifest's `gaps` and shown through the generic gap path: the approval text, the public intake summary (`gaps`), and the report coverage rows. Files are never dropped silently.

### Checkout fetching

When a selected analyzer walks revisions (`gitleaks:tracked-history`, any recipe whose `scope` is not `scoped-files`), whole-repo and history checkouts fetch the full ancestry of the target; otherwise they stay shallow. The decision uses the same canonical objectives and scope as manifest construction, so a correctness-only audit (which skips gitleaks) stays shallow. Gitleaks scans a confirmed commit set with `--diff-merges=first-parent --no-walk=unsorted <commits>` so merge patches are included. Captured history selections (`commits`, `diffBase`) are host-owned: request windows that carry them are rejected.

A temporary checkout is an empty repository plus `git fetch --depth=1 origin <sha>`; Sniff does not clone. Only when the server refuses an unadvertised SHA does it fall back, first to the provider ref and then to a full fetch of the branches; the lease records which fetch was used. History windows fetch only what they need: `last-commits` fetches `count + 1` commits, `since-date` uses `--shallow-since`, ref and release windows fetch their two endpoints with ancestry, and only `previous-release` fetches tags. Every git command runs with `core.hooksPath=/dev/null` and `GIT_LFS_SKIP_SMUDGE=1`.

An unavailable command stops the request. Authentication failure has the same result. Sniff returns `TargetResolutionError`.

Repository URLs cannot contain user information. They also cannot contain queries or fragments. Store credentials outside the URL.

## History windows

Sniff supports these history requests:

| Window | Request example |
| --- | --- |
| Explicit refs | `Sniff history from v2.3.0 to v2.4.0.` |
| Since date | `Sniff history since 2026-08-01.` |
| Commit count | `Sniff the last 20 commits.` |
| Since release | `Sniff changes since release v2.4.0.` |
| Preceding release | `Sniff release v2.4.0 against its predecessor.` |
| Context default | `Sniff recent history.` |

A remote history run captures the required SHAs before checkout. Sniff fetches the ancestry and tags required by the selected window.

A window resolved from a local repository keeps its exact commit set and diff base through materialization, so a merge does not widen `last-commits`, `since-date`, or the default window. Windows that reach the initial commit use the empty tree as their base, so the root commit's files are included. A root-commit `commit` target is diffed against the empty tree, and a `working-tree` scope in a repository with no commits yet lists its untracked files (`unborn`, base = empty tree). A shallow boundary commit is reported as an error rather than treated as a root.

## Changed and deleted files

Change targets retain deleted paths as target metadata. Analyzers run only against files that exist in the captured head. The report file count excludes deleted paths. If the report needs a deleted path, record it in finding evidence or an extension.

## Temporary materialization

Sniff keeps an isolated checkout alive through analysis and reporting. A report, explicit cancellation, or expiry removes the checkout.
