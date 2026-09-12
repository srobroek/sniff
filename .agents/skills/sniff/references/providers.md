# Repository providers

Sniff uses argv arrays and validates every option-capable positional value. The runtime never builds shell command strings. Tests inject argv runners and do not change remote repositories.

## Provider detection

- Use `gh` for a `github.com` URL.
- Use `glab` for a `gitlab.com` URL.
- Use `git` for another repository URL.
- Probe the selected CLI before a provider query.
- Report `missing-cli` when the executable does not exist.
- Report `authentication-failure` for login errors.
- Report the same failure for token errors.
- Report the same failure for 401 or 403 errors.

## Transport validation

- Allow `https`, `ssh`, and `git` repository URLs.
- Allow the `git@host:path` repository form.
- Reject URL userinfo and embedded credentials.
- Reject URL query and fragment values.
- Reject unsupported schemes and whitespace.
- Reject a repository value that starts with a dash.
- Reject leading dashes in refs and release tags.
- Reject nonnumeric PR numbers and MR IIDs.
- Use provider credential stores for authentication.
- Redact transport credentials from failures and persisted manifests.

## Pull and merge requests

- The GitHub adapter runs `gh pr view` with JSON output.
- It stores the base SHA.
- It stores the head SHA.
- It stores changed paths.
- The GitLab adapter runs `glab mr view` with JSON output.
- It stores the base SHA.
- It stores the head SHA.
- It stores changed paths.

## Releases

- Resolve the exact requested tag.
- For an annotated GitHub tag, follow tag objects until reaching a commit SHA.
- Report `absent-release` when no release has that tag.
- Report `ambiguous-release` for another tag or multiple matches.
- Materialize the release commit before file enumeration.
- Run `git ls-tree` for snapshot paths in the temporary checkout.
- Run the previous-tag delta in the same checkout.
- Propagate snapshot and delta command failures.
- Store the tag and previous-tag commit SHAs.
- Store snapshot files separately from status-bearing delta metadata.

## Checkout

- Use a host-owned temporary checkout lease for remote work.
- Fetch captured commit SHAs plus sufficient ancestry and tags for the requested history window.
- Check out the captured head SHA in detached mode.
- Release the lease exactly once after terminal report success or failure, or through `sniff_cancel`.
