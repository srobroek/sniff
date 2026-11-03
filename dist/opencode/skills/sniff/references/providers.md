# Repository providers

Transport validation and credential rules live in `targeting.md`. This file covers provider routing and the failures to report.

## Routing

- A `github.com` URL uses `gh`. PR and release targets require it.
- A `gitlab.com` URL uses `glab`. MR and release targets require it.
- Any other host, including self-hosted GitLab, uses plain `git`. It supports repository and history targets, but not PR, MR, or release targets.
- Accepted URL forms are `https`, `ssh`, `git`, and `git@host:path`. Authenticate through the provider's credential store, never through the URL.

## Releases

- A release target resolves the exact requested tag and peels annotated tags to their commit.
- Sniff captures the release and optional previous-tag commits before enumerating files.

## Failure codes

Report each failure as a coverage gap with its code; do not guess a snapshot.

| Code | Meaning |
|------|---------|
| `missing-cli` | The selected CLI is not installed. |
| `authentication-failure` | Login, token, 401, or 403 failure. |
| `absent-release` | No release has the requested tag. |
| `ambiguous-release` | The lookup returned another tag, or the ref matched several objects. |
