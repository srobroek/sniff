# Security and trust

Sniff treats target content as untrusted input. Analysis approval does not authorize target code to run.

## Trusted local targets

Local targets may use host-owned analyzer recipes. Sniff still resolves each executable outside the target and confines file arguments to the confirmed root.

A host may grant project-controlled execution only inside a sandbox. The grant is valid only without credentials or network access.

## Remote targets

Every remote target uses the untrusted route. The default route has these rules:

- use config-free analyzer recipes
- use bundled rules
- ignore project config that can execute
- do not install target dependencies
- skip package hooks
- remove unrelated variables
- use an isolated analyzer home
- select only offline recipes

Sniff enforces config-free offline recipes for remote targets. It does not create an operating-system sandbox or network boundary.

## Unattended intake

A model argument never stands in for approval. `interactive: false` skips the interview, but the resolved plan still needs a person's confirmation: MCP form elicitation or OMP `ui.confirm`. Without that channel, intake issues no lease and names `SNIFF_UNATTENDED_INTAKE=1` in its refusal.

Only the operator can lift this, by setting `SNIFF_UNATTENDED_INTAKE=1` (or `true`, `yes`) in the environment of the MCP server or OMP process. Sniff reads it from the server's environment and never from tool arguments. The manifest then records a host or headless actor and a reason that names the opt-in.

Set it where the server process gets its environment:

- Claude Code: export it before starting `claude`, or add it to the `env` map of the `sniff` entry in the MCP configuration (`"env": { "SNIFF_UNATTENDED_INTAKE": "1" }`).
- Codex: export it before starting `codex`, or add `SNIFF_UNATTENDED_INTAKE = "1"` under `[mcp_servers.sniff.env]` in `~/.codex/config.toml`.
- OMP: export it before starting `omp`.
- OpenCode does not read it. Use the plugin option `confirm: false` and `sniff_confirm_intake` permission rules.

Installing tools and saving reports are unaffected. Both refuse headless sessions even with the opt-in.

## Capability boundary

Intake issues an unguessable capability for one manifest. The capability binds these values:

- canonical target root
- exact file set
- trust route
- selected recipes
- confirmation receipt
- analyzer and time budgets

Each recipe is one-shot. Sniff rejects concurrent and completed replay. The final preflight validates the root and files.

## Forbidden security actions

Sniff rejects these requests:

- fuzzing
- exploitation
- DAST
- live-secret validation
- threat campaigns

Deep static analysis needs explicit opt-in on a trusted local target. Sniff records the disposition of every analyzer.

## Credentials

Repository URLs must not contain credentials, queries, or fragments. Command errors redact known secrets.

Provider commands use their own credential stores. Analyzer processes receive a restricted environment for untrusted targets.

## Cleanup

A report closes its capability after success or failure. Explicit cancellation closes an unfinished run. A guarded timer removes abandoned checkouts and analyzer homes.
