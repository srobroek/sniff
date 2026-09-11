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
| GitHub pull request | `gh` | Base SHA, head SHA, and changed paths |
| GitLab merge request | `glab` | Base SHA, head SHA, and changed paths |
| GitHub release | `gh` | Release commit and optional preceding release |
| GitLab release | `glab` | Release commit and optional preceding release |
| Git repository | `git` | Captured commit and snapshot files |

Sniff does not manage provider authentication.

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

## Changed and deleted files

Change targets retain deleted paths as target metadata. Analyzers run only against files that exist in the captured head. The report file count excludes deleted paths. If the report needs a deleted path, record it in finding evidence or an extension.

## Temporary materialization

Sniff keeps an isolated checkout alive through analysis and reporting. A report, explicit cancellation, or expiry removes the checkout.
