# Installer flow

If Sniff cannot find a tool, it records a coverage gap. The run can continue.

Sniff never invokes `sudo`. It keeps trust checks active.

The `sniff_install_tools` tool manages the analyzer catalog. The steps below
govern how an agent uses it.

## First run

1. Run `sniff_install_tools` in `probe` mode. The result lists each tool and its
   installation state.
2. Present every viable tool for the detected stack. Keep each recommended tool
   selected unless the user removes it.
3. Explain overlaps with facts from `references/tooling.md`. Do not replace the
   full selection with lean, full, or custom depth tiers.
4. After the user approves the selection, install each selected tool. Pass
   `bundles` or `all` to `install` mode.
5. When the user asks to inspect commands, pass `dryRun`. A dry run does not
   change tool state.
6. Invoke each selected analyzer through `sniff_run_analyzer`. Installation does
   not authorize analyzer execution.

### Selection format

```text
Detected stack: Go, TypeScript, Dockerfile, GitHub Actions
Installed: golangci-lint [ready], eslint [ready]
Missing and selected: opengrep, hadolint, actionlint
Optional: jscpd
Reason: jscpd adds TypeScript coverage not supplied by the Go duplicate checker.
```

Sniff verifies each command through its catalog route. Managed toolkit entries
use the bundle's mise environment. Before Sniff runs an analyzer, it verifies
that the command can run. An unusable command blocks only that analyzer. The
result records diagnostic details and a repair instruction.

## Bundles

Bundles group catalog entries by target family. They do not define analyzer
manifests or authorize execution. Run `sniff_install_tools` in `list` mode to
read the catalog membership.

## Managed toolkits

Mise manages these catalog routes:

- `brew`
- `pipx`
- `npm`
- `cargo`
- `go`

If installation is not a dry run and the bundle contains managed entries, Sniff
resolves the mise executable. After resolution, Sniff writes the bundle's
`mise.toml`. Set `SNIFF_TOOLKIT_CACHE_DIR` to change the cache location. Before
the configuration exists, managed command checks use the process environment,
and afterward they use the bundle environment. If mise cannot load an existing
configuration, Sniff returns `unavailable-route`. Resolved tool directories
precede shim directories in `PATH` to stop stale shims from winning command
lookup.

OpenGrep uses its verified download route. Project-local npm tools use the target
repository. Rustup components use rustup.

## Project-local tools

The target repository owns JavaScript analyzers in `devDependencies`. The
installer lists the required packages but does not install them globally.
`sniff_run_analyzer` resolves these commands from the target
`node_modules/.bin` directory.

## Rust tools

Use Clippy for standard Rust checks. Offer `cargo-machete` as an extra tool. When
the user requests a deep pass, offer `cargo-udeps`. It requires the nightly Rust
toolchain.
