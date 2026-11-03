# Shell / Bash -- Sniff Reference

One-line scope: shell source -- `.sh`, `.bash`, `.ksh`, files with a `#!/bin/sh`
or `#!/usr/bin/env bash` shebang, and inline `RUN`/`script:` shell in
Dockerfiles and CI (those have their own docs; this covers standalone scripts).

## Detect

How sniff knows shell is present: key files, extensions, config.
- Files/extensions: `*.sh`, `*.bash`, `*.ksh`, extensionless files whose first
  line is `#!/bin/sh`, `#!/bin/bash`, or `#!/usr/bin/env bash`.
- Config that governs it: `.shellcheckrc` (disabled checks, shell dialect),
  `.editorconfig`, `shfmt` flags in CI config or a `.shfmt` wrapper.

## Tools

Operator follow-ups, primary first: Sniff never runs these tools (see
**Execution routing** at the end). Each row is the exact command an operator runs
outside Sniff, with its machine-readable flag.

| Tool | Invocation | Covers | Tier | Installed via |
|------|-----------|--------|------|---------------|
| shellcheck | **Run recipe.** `shellcheck -f json <files>` -- pass the resolved `.sh`/`.bash`/`.ksh` paths explicitly (shellcheck does not recurse; expand the file set yourself). Auto-reads `.shellcheckrc` from the repo root for disabled checks + shell dialect; shell is auto-detected from each shebang (override `-s bash`/`-s sh` only when a file has none). **Exit:** 0 = clean · 1 = issues found → parse the JSON array (each object has `file`/`line`/`code`/`message`/`level`) · 2/3/4 = parse/usage error = INVALID, never "clean". **Gotcha:** when the target is a Dockerfile `RUN` or GHA `run:`, run hadolint/actionlint instead -- they embed shellcheck; don't double-run it standalone. | quoting/word-splitting, unset vars, unchecked `cd`, useless `cat`, `ls` parsing, `[` vs `[[`, sh-vs-bash portability | default-on | operator follow-up (not run by Sniff) |
| shfmt | **Run recipe.** `shfmt -d <files>` from repo root (pass explicit paths) -- `-d` prints a unified diff of the format drift; an empty diff = formatted. **Exit:** 0 = no drift · 1 = drift present (the diff is the finding, advisory only -- it's format, not a logic bug) · 2 = parse error = INVALID. Honor `.editorconfig` if present; otherwise the no-config form is `shfmt -i 2 -ci -d <files>` to state the style being checked (2-space indent, switch-case indent). Never report a parse failure as "no drift". | format drift (advisory); `-i 2 -ci` to enforce style | default-on | operator follow-up (not run by Sniff) |

Notes: shellcheck is the essential analyzer -- it does real dataflow on variable
use and quoting, and it auto-detects the shell from the shebang (override with
`-s bash`/`-s sh`). It is also embedded inside `hadolint` (Dockerfile `RUN`) and
`actionlint` (GHA `run:`), so for those targets prefer the host tool and don't
re-run shellcheck standalone. shfmt only reports formatting; it does not find
logic bugs. **bashate is REDUNDANT here -- its checks are subsumed by
shellcheck + shfmt, so it is not a default-on tool.** No grep fallback -- if
shellcheck is absent, record a coverage gap.

## Smell checklist

| Smell | What it looks like (this language) | Idiomatic alternative |
|-------|-----------------------------------|-----------------------|
| Unquoted variable | `rm -rf $dir`, `cp $src $dst` -- word-splits and globs on whitespace/`*` (SC2086) | Quote every expansion: `rm -rf "$dir"` |
| No strict mode | `set -euo pipefail` absent -- failures and unset vars pass silently. **Grep the WHOLE file for it, not just the top**: a header comment block legitimately pushes it past line 1, so a head-only check false-flags scripts that do set it. shellcheck does not cover this dimension. | With a bash shebang, add `set -euo pipefail` (and `IFS=$'\n\t'` when iterating). For `#!/bin/sh`, use `set -eu`: `pipefail` is not portable to every `sh`, and `$'...'` is a bashism |
| Useless use of cat | `cat file \| grep x` (SC2002) | `grep x file` or `grep x < file` |
| Parsing `ls` | `for f in $(ls *.txt)` -- breaks on spaces/newlines (SC2045) | `for f in *.txt; do ... done` with a nullglob/exists guard |
| `[ ]` over `[[ ]]` | `[ $x = y ]` in bash -- needs quoting, no `&&`/pattern support (SC2292) | `[[ $x == y ]]` in bash scripts |
| Unchecked `cd` | `cd /tmp/build; rm -rf *` -- runs in cwd if `cd` fails (SC2164) | `cd /tmp/build \|\| exit 1` or `set -e` plus quoting |
| Command injection | `eval "$user_input"`, unquoted expansion in a command string | Avoid `eval`; pass args as a quoted array `cmd "${args[@]}"` |
| Backticks | `` files=`find . -type f` `` (SC2006) -- no nesting, escaping pain | `files=$(find . -type f)` |
| Missing `local` | Function assigns plain `tmp=...`, leaking/clobbering global scope (shellcheck does not flag this; SC2168 is the opposite case, `local` outside a function) | `local tmp` inside every function |
| sh with bashisms | `#!/bin/sh` but uses `[[ ]]`, arrays, `local`, `$'...'` (SC2039/SC3xxx) | Use `#!/usr/bin/env bash`, or rewrite to POSIX sh |
| Unhandled pipe failure | `foo \| bar` where `foo` fails silently without `pipefail` | In bash, `set -o pipefail` and check `${PIPESTATUS[@]}` if needed; in POSIX `sh`, split the pipeline or check each stage |

## Idioms & style authorities

- Google Shell Style Guide -- https://google.github.io/styleguide/shellguide.html
- ShellCheck wiki (per-code rationale, e.g. SC2086) -- https://www.shellcheck.net/wiki/
- Key conventions: quote every expansion; prefer `$(...)` over backticks; use
  `[[ ]]` in bash; declare `local` in functions; in bash scripts set `set -euo pipefail` for any
  script that is not throwaway (`set -eu` for POSIX `sh`); prefer `"${arr[@]}"` arrays over space-joined
  strings; reserve `#!/bin/sh` for genuinely POSIX scripts.

## refactoring.guru mappings

The catalog is OO-oriented, so most shell smells above are correctness/safety
issues with no catalog entry -- cite ShellCheck codes for those. The catalog maps
only to the genuine duplication/structure smells:

| This-language smell | refactoring.guru smell | Idiomatic refactoring |
|---------------------|------------------------|-----------------------|
| 100-line `main` doing setup + work + cleanup | Long Method (`/smells/long-method`) | Extract Method (`/refactoring/techniques/composing-methods`) -- split into named functions; bash favors small functions over any class structure |
| Same `curl ... \| jq ...` block pasted across scripts | Duplicate Code (`/smells/duplicate-code`) | Extract Method -- lift into a shared function in a sourced `lib.sh` |
| Repeated literal `8080`, `/var/lib/app` | (no smell entry -- magic value) | Replace Magic Number with Symbolic Constant (`/refactoring/techniques/organizing-data`) -- `readonly PORT=8080` at top |

## Pragmatism notes (for the adversarial pass)

- A 10-line throwaway/one-off script does not need full `set -euo pipefail`
  ceremony, function extraction, or arg arrays -- flag missing strict mode only
  when the script is reused, installed, or run in CI/prod.
- Bashisms (`[[ ]]`, arrays, `local`) are correct and preferred when the shebang
  is `#!/bin/bash` or `#!/usr/bin/env bash`; only flag them under `#!/bin/sh`.
- `set -e` is not a universal good -- scripts that intentionally check exit codes
  (`if ! cmd; then`) or tolerate partial failure may legitimately omit it; don't
  demand it blindly.
- Unquoted expansion is occasionally intentional (deliberate word-splitting of a
  known-safe flag string); shellcheck `# shellcheck disable=SC2086` with a reason
  is a valid, not a smell.

**Execution routing:** Sniff coverage comes only from fixed recipes run through `sniff_run_analyzer` (`lizard:complexity`, `opengrep:hardcoded-values`, `gitleaks:tracked-history`). Every tool in this table is an operator follow-up: never run it during a Sniff run. Record each dimension it would cover as a `gap` coverage entry naming the tool, and list its command as a follow-up the user may run outside Sniff.
