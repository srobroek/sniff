# Bounded security scope

Sniff maps each disposition to a runnable catalog ID and fixed recipe. The tool accepts no caller policy.

## Trusted local targets

- Select only catalogued fixed recipes.
- Use the host-owned Lizard complexity recipe and shipped Semgrep rules for compatible file targets.
- Use the Gitleaks history recipe only for an explicit repository-wide target.
- Do not load project configuration through the shipped analyzer tool.

## Untrusted remote targets

- Treat all remote targets as untrusted.
- Select only config-free offline analyzers with bundled rules by default.
- Do not import a linter configuration that executes code.
- Do not bootstrap dependencies or run repository hooks.
- Do not expose reviewer credentials to an analyzer process.
- Do not let analyzers access the network.
- Repository code runs only with a separate trusted grant.
- The grant requires a sandbox without credentials or network access.
- Resolve each analyzer to a canonical absolute host executable outside the target checkout before any probe.

## Deep static checks

- Deep static tools on a trusted local target need explicit opt-in.
- Record each analyzer as selected, skipped, or unavailable.
- Record the analyzer reason and version when available.
- Keep deep static tools skipped for an untrusted remote target without the sandboxed execution grant.

## Exclusions

- Reject fuzzing and its aliases.
- Reject exploitation and its aliases.
- Reject aliases for DAST.
- Reject live-secret validation.
- Reject threat campaigns.
- Record these exclusions in every manifest.
- Raise a typed intake error for a rejected action.
- Do not replace a rejected action with another scan.
