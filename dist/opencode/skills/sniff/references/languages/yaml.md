# YAML (pure format) -- Sniff Reference

One-line scope: YAML **as a format** -- `.yaml`/`.yml` syntax, encoding, and
type-coercion smells. This doc is the format-only reference.

> **Scope split -- read this.** YAML's two biggest *functional* uses have their
> own docs and are OUT OF SCOPE here:
> - Kubernetes manifests → `kubernetes.md` (kube-linter, kubeconform).
> - CI/CD pipelines (GitHub Actions, etc.) → `ci-cd.md` (actionlint, zizmor, pinact).
>
> This doc covers ONLY format/encoding issues that apply to any YAML file
> (config, fixtures, data). For a k8s manifest or a workflow file, also apply
> those docs' checklists and operator follow-ups *in addition to* yamllint.

## Detect

How sniff knows YAML is present: key files, extensions, config.
- Files/extensions: `*.yaml`, `*.yml`; common configs `.yamllint`,
  `docker-compose.yml` (compose is functional but largely covered here for format),
  app config under `config/*.yml`.
- Config that governs it: `.yamllint`/`.yamllint.yaml`/`.yamllint.yml` (rule
  config -- read it so you don't flag intentionally relaxed rules), `.editorconfig`.

## Tools

Operator follow-ups, primary first: Sniff never runs these tools (see
**Execution routing** at the end). Each row is the exact command an operator runs
outside Sniff, with its machine-readable flag.

| Tool | Invocation | Covers | Tier | Installed via |
|------|-----------|--------|------|---------------|
| yamllint | **Run recipe:** if the repo has a `.yamllint`/`.yamllint.yaml`/`.yamllint.yml`, use it: `yamllint -s -f parsable <paths>`. If it has **no** yamllint config, the `default` preset's 80-col `line-length` and `document-start` are NOT the project's rules and produce pure noise (GitHub workflows routinely exceed 80 cols), while the `relaxed` preset disables `truthy` outright -- so start from `relaxed` and re-enable `truthy` explicitly: `yamllint -s -d "{extends: relaxed, rules: {line-length: disable, document-start: disable, truthy: {level: warning, check-keys: false}}}" -f parsable <paths>` (`check-keys: false` keeps GitHub Actions' `on:` key from being flagged). Pass explicit paths, not `.`. **Exit:** without `-s` yamllint exits 0 when only warnings occur, and `relaxed` demotes most rules to warnings, so always pass `-s`: 0 = no errors or warnings · 1 = errors (parse) · 2 = warnings only (parse) · a crash/bad `-d` config = INVALID. **Gotcha:** if the project's own config disables `truthy` (as a bare `extends: relaxed` does), Norway detection is off by project choice -- record it as not covered rather than claiming it. | Norway/truthy coercion, tabs, indent consistency, duplicate keys (NOT line-length/document-start unless the project enables them) | default-on | operator follow-up (not run by Sniff) |
| check-jsonschema | `check-jsonschema --schemafile <schema> <file>` | schema conformance for schema-backed YAML configs | opt-in (only when a schema-backed config is present) | operator follow-up (not run by Sniff) |

Notes: yamllint is the primary and essentially only format analyzer here; the
`truthy` rule catches the Norway problem (only when enabled -- see the row above)
and the `key-duplicates` rule catches duplicate keys. Use `-f parsable` for
machine-readable line:col output, and keep it tuned to the project's `.yamllint`.
check-jsonschema is the conformance
gate when a schema-backed config exists. yq is **NOT a linter** -- it is for
ad-hoc exploration in the analysis itself (`yq eval '<expr>' <file>`), not a
source of findings, and is excluded from the tool tiers. For k8s/CI files, do not
stop at yamllint -- also recommend the functional tools named in `kubernetes.md` /
`ci-cd.md`. No grep fallback; if yamllint is absent, record a coverage gap.

## Smell checklist

| Smell | What it looks like (this format) | Idiomatic alternative |
|-------|----------------------------------|-----------------------|
| Norway problem | `country: NO` → `false`; `enabled: on`/`yes`/`off` coerced to bool (YAML 1.1) | Quote the scalar: `country: "NO"`, `enabled: true` (explicit) |
| Tab indentation | A literal tab used for indent -- invalid YAML, breaks parsers | Spaces only (2-space indent) |
| Inconsistent indentation | Mixed 2- and 4-space, or misaligned block items | One consistent indent width; yamllint `indentation` rule |
| Duplicate keys | Same mapping key twice -- last silently wins | One key per mapping; yamllint `key-duplicates` |
| Anchor/alias overuse | A web of `&a`/`*a`/`<<:` merges that obscures the effective value | Use sparingly; inline or split when readers can't trace the merge |
| Unquoted type-coercing string | `version: 1.20` → float `1.2`; `phone: 0123` → octal; `time: 22:30` → sexagesimal | Quote it: `version: "1.20"`, `phone: "0123"` |
| Multiline scalar misuse | `>` (folded) where newlines matter, or `|` where you wanted folding; missing chomp `-`/`+` | Match block style to intent: `|` keeps newlines, `>` folds; add chomp indicator |
| Overly deep nesting | 6+ mapping levels to reach a value | Flatten or split into referenced files where not inherently hierarchical |
| Unquoted version string | `image_tag: 1.10` reads as `1.1`; `1.30` as `1.3` | Always quote version-like scalars |

## Idioms & style authorities

- YAML specification -- https://yaml.org/spec/
- yamllint documentation (rule reference) -- https://yamllint.readthedocs.io/
- Key conventions: quote any ambiguous scalar (Norway words, version strings,
  leading-zero numbers, time-like values); 2-space indentation, spaces never
  tabs; explicit `true`/`false` over `yes`/`on`; no duplicate keys; keep anchors
  rare and local; choose `|` vs `>` deliberately.

## refactoring.guru mappings

YAML is a data format -- **mappings are mostly format-level**; cite the YAML spec
or yamllint rather than the OO catalog for syntax/coercion findings.

| This-format smell | refactoring.guru smell | Idiomatic refactoring |
|-------------------|------------------------|-----------------------|
| Same block of keys copy-pasted across documents | Duplicate Code (`/smells/duplicate-code`) | Factor with an anchor/alias (`&base`/`<<: *base`) -- **but** weigh against the anchor-overuse smell; readability can beat DRY here |
| Norway/tab/duplicate-key/coercion issues | (no catalog entry) | Cite YAML spec / yamllint -- pure format, not an OO refactor |

## Pragmatism notes (for the adversarial pass)

- Anchors and aliases are fine in moderation -- a couple of `&defaults`/`<<:`
  merges that genuinely cut repetition are good; only flag them when the merge
  chain is hard to trace. Don't recommend anchors *and* then flag overuse on the
  same file.
- Not every string needs quoting -- `name: build`, `region: us-east-1` are
  unambiguous; reserve the quoting demand for genuinely coercion-prone scalars
  (Norway words, version/time/leading-zero values).
- Respect `.yamllint`: if the project relaxed `line-length` or `truthy`, those
  are deliberate choices, not findings.
- **Honor `.editorconfig` before flagging indentation/line-length.** yamllint
  does not read `.editorconfig`, so its defaults (an 80-col `line-length`; any
  indent width as long as each file is consistent) can contradict a repo that
  declares `[*.{yml,yaml}] indent_size = 2` / `max_line_length`. Check
  `.editorconfig` first; a tool-default mismatch with a declared editorconfig
  value is config-driven, not a smell.
- **Functional smells are out of scope here.** Anything about k8s resource
  limits, probes, `runAsNonRoot`, or CI action pinning / injection is NOT a YAML
  format finding -- route it to `kubernetes.md` or `ci-cd.md`. Do not invent
  format objections to functional content.

**Execution routing:** Sniff coverage comes only from fixed recipes run through `sniff_run_analyzer` (`lizard:complexity`, `opengrep:hardcoded-values`, `gitleaks:tracked-history`). Every tool in this table is an operator follow-up: never run it during a Sniff run. Record each dimension it would cover as a `gap` coverage entry naming the tool, and list its command as a follow-up the user may run outside Sniff.
