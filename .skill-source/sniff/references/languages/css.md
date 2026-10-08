# CSS / SCSS -- Sniff Reference

One-line scope: stylesheets -- `.css`, `.scss`/`.sass`, and CSS-in-`<style>`
blocks. Covers selector, specificity, value, and structure smells. This is a
standalone format doc (no base-language parent).

## Detect

How sniff knows CSS/SCSS is present.
- Files/extensions: `.css`, `.scss`, `.sass`; `<style>` blocks in components.
- Config that governs it: `.stylelintrc*` / `stylelint.config.js`;
  `stylelint-config-standard` (+ `-scss` for SCSS) in `package.json`; PostCSS /
  Autoprefixer config (`postcss.config.*`, `browserslist`).

## Tools

Operator follow-ups, primary first: Sniff never runs these tools (see
**Execution routing** at the end). stylelint is the meta-linter. The standard
config is default-on; the `-strict-value` and `-order` plugins are opt-in (they
need per-project config or are organizational preference), and
`@projectwallace/css-analyzer` is opt-in for a deep CSS metrics audit. All of
them are project-local `devDependencies` of the target; never install them
globally or let `npx` fetch them.

| Tool | Invocation | Covers | Tier | Installed via |
|------|-----------|--------|------|---------------|
| stylelint + `stylelint-config-standard` (+ `stylelint-config-recommended-scss` when SCSS) | **Run recipe:** from repo root, using the target's own `devDependencies` (`npx --no` fails instead of downloading a missing package). If the repo has a `.stylelintrc*`/`stylelint.config.*`, run `npx --no stylelint --formatter json "**/*.{css,scss}"` (config auto-used). If it has **no** config, bare stylelint is a HARD ERROR ("No configuration provided"): when `stylelint-config-standard` is already in the target's `devDependencies`, pass a 1-line temp config outside the repo, `npx --no stylelint --config <tmp>/stylelintrc.json --config-basedir "$PWD" --formatter json "**/*.{css,scss}"` with `{"extends":"stylelint-config-standard"}`; otherwise record stylelint as a coverage gap -- never resolve configs from a global npm root. **Exit:** 0 clean · 2 = lint problems (parse JSON) · 1 = fatal error, 64 = invalid CLI usage, 78 = invalid config → INVALID, fix and re-run (never report as clean). | duplicates, invalid/unknown properties and selectors, legacy/longhand redundancy, `selector-id-pattern` naming; `!important`, ID selectors, overqualification, nesting depth and specificity only when the project config enables `declaration-no-important`, `selector-max-id`, `selector-no-qualifying-type`, `max-nesting-depth`, `selector-max-specificity` | default-on | operator follow-up (not run by Sniff) |
| `stylelint-declaration-strict-value` (plugin) | same invocation, rule `scale-unlimited/declaration-strict-value` enabled | magic numbers -- raw colors/sizes that should be custom properties/tokens | opt-in (needs per-property config; noisy without it) | bundled with `css` |
| `stylelint-order` (plugin) | same invocation | declaration-order consistency | opt-in (organizational preference) | bundled with `css` |
| `@projectwallace/css-analyzer` | `npx --no @projectwallace/css-analyzer "**/*.css"` | specificity/complexity metrics -- deep CSS audit | opt-in (deep CSS audit) | target `devDependencies` (`npm i -D @projectwallace/css-analyzer`, with approval) |

Notes: stylelint is the single CSS/SCSS entry point -- one AST parse covers most
dimensions; don't stack regex scanners. **stylelint v15+ is quality-only**
(formatting rules removed); `jscpd` covers CSS duplication if you need a
dedicated dup pass. Neither `stylelint-config-standard` nor
`stylelint-config-recommended` enables `declaration-no-important`,
`selector-max-id`, `selector-no-qualifying-type`, or `max-nesting-depth`, so
`!important` overuse, ID styling, overqualification and deep nesting stay on the
smell checklist unless the project config turns those rules on; add
`stylelint-config-recommended-scss` for SCSS sources. Magic-number detection
requires the strict-value plugin (configure it for `color`/`fill`/spacing
properties -- noisy without that config, hence opt-in). Autoprefixer (PostCSS) --
not stylelint -- is what removes hand-written vendor prefixes; the smell is doing
prefixes by hand when the build pipeline can.

## Smell checklist

Smells beyond what tools auto-flag; several need a configured rule or a
reviewer's judgment about systematization.

| Smell | What it looks like (CSS/SCSS) | Idiomatic alternative |
|-------|-------------------------------|-----------------------|
| `!important` overuse | `!important` sprinkled to win cascade fights | Lower specificity / fix source order; reserve `!important` for true utility overrides |
| Specificity wars | `.nav ul li a.active span { }`, escalating selectors to override | Flatter selectors, single-class targets, a naming methodology (BEM) |
| Deep SCSS nesting | `&` nesting 4+ levels deep, mirroring DOM tree | Keep nesting ≤3; flatten to BEM-style class selectors |
| Magic numbers | `margin: 13px; color: #3a7bd5;` repeated literals | CSS custom properties / design tokens: `var(--space-2)`, `var(--color-primary)` |
| Duplicated color/spacing values | Same hex / pixel value pasted across many rules | Define once as a custom property / SCSS variable; reference it |
| Overqualified selectors | `div.card`, `ul.menu`, `a.btn` -- tag + class | Class alone: `.card`, `.menu`, `.btn` |
| ID selectors for styling | `#header { }` used for visual styling | Class selectors; reserve IDs for anchors/JS hooks |
| z-index chaos | Arbitrary `z-index: 9999`, `z-index: 100001` ad hoc | A named scale via custom properties (`--z-modal`); document layers |
| Unused rules | Selectors matching nothing in the current markup | Delete dead rules (confirm via coverage/usage check) |
| Hand-written vendor prefixes | Manual `-webkit-`/`-moz-` prefix blocks in source | Let Autoprefixer + `browserslist` add prefixes; write unprefixed |

## Idioms & style authorities

- stylelint + `stylelint-config-standard`: https://github.com/stylelint/stylelint-config-standard
- MDN CSS reference: https://developer.mozilla.org/en-US/docs/Web/CSS
- MDN -- Using CSS custom properties: https://developer.mozilla.org/en-US/docs/Web/CSS/Using_CSS_custom_properties
- BEM methodology: https://getbem.com/
- Key conventions:
  - Pick one naming methodology (BEM or equivalent) and apply it consistently.
  - Centralize colors, spacing, and z-index as custom properties / design tokens.
  - Keep specificity low and flat; avoid IDs and overqualification for styling.
  - Cap SCSS nesting depth (≤3); nesting should not mirror the DOM.
  - Vendor prefixing is the build's job (Autoprefixer), not the author's.

## refactoring.guru mappings

| This-language smell | refactoring.guru smell | Idiomatic refactoring |
|---------------------|------------------------|-----------------------|
| Duplicated color/spacing values | Duplicate Code (`/smells/duplicate-code`) | Extract to a CSS custom property / SCSS mixin / utility class |
| Magic numbers (raw values) | Primitive Obsession (`/smells/primitive-obsession`) | Replace Magic Number with Symbolic Constant (`/refactoring/techniques/organizing-data`) → a CSS custom property |
| Specificity wars / deep nesting | Long Method (`/smells/long-method`) (over-grown selector) | Decompose into flat, single-class selectors under a methodology |
| Unused rules | Dead Code (`/smells/dead-code`) | Delete the rule (after a usage/coverage check) |
| `!important` to defeat cascade | Inappropriate Intimacy (`/smells/inappropriate-intimacy`) (rules fighting) | Reduce specificity / fix source order so rules cooperate |

The catalog is OO-flavored; for CSS the load-bearing techniques are Replace
Magic Number with Symbolic Constant (→ custom property) and the duplication →
extraction family (→ mixins, utility classes, tokens).

## Pragmatism notes (for the adversarial pass)

- An occasional `!important` in a genuine utility class (e.g. `.hidden`,
  `.sr-only`) is correct and idiomatic -- not a smell. Flag *patterns* of
  cascade-fighting, not single deliberate overrides.
- Not every literal needs a token. One-off values, true constants (`0`, `100%`,
  `1px` borders), and content-specific sizes don't all belong in the token set.
- Shallow nesting (1 to 2 levels) in SCSS is fine and readable; the smell is depth,
  not nesting itself.
- ID selectors are legitimate as JS hooks and fragment anchors -- flag IDs used
  for *styling*, not their existence.
- A pragmatic mix of methodologies in legacy code may be reality; flag drift and
  inconsistency where it causes specificity pain, not stylistic purity.

**Execution routing:** Sniff coverage comes only from fixed recipes run through `sniff_run_analyzer` (`lizard:complexity`, `opengrep:hardcoded-values`, `gitleaks:tracked-history`). Every tool in this table is an operator follow-up: never run it during a Sniff run. Record each dimension it would cover as a `gap` coverage entry naming the tool, and list its command as a follow-up the user may run outside Sniff.
