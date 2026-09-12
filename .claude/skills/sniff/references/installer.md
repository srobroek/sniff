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

Sniff uses mise to verify commands. If the isolated environment cannot run a
command, the installer reports a failure.
Before Sniff runs an analyzer, it verifies that the command can run. An unusable
command blocks only that analyzer. The result records diagnostic details and a
repair instruction.

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

Sniff writes one `mise.toml` for each bundle in its toolkit cache. Set
`SNIFF_TOOLKIT_CACHE_DIR` to change the cache location.

For each probe, Sniff loads the bundle configuration. Diagnose mode and analyzer
preflight use the same environment. If mise is absent, installation returns
`unavailable-route`.
Resolved tool directories precede shim directories in `PATH`. This order stops
stale shims from winning command lookup.

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
