# OpenCode

Sniff ships a native OpenCode V2 plugin, `srobroek.sniff`. It runs the portable core inside the OpenCode server. It needs no MCP server and no separate Bun install.

## Install

Install Git. Analyzer bundles that Sniff installs for you also need [mise](https://mise.jdx.dev/).

Add the plugin globally:

```sh
opencode plugin add 'github:srobroek/sniff#main::path:dist/opencode'
```

Or declare it in `~/.config/opencode/opencode.json` or a project's `opencode.json`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["github:srobroek/sniff#main::path:dist/opencode"]
}
```

OpenCode reloads plugins after a config save. Check that the plugin loaded:

```sh
opencode plugin list
```

Update to the latest `main`:

```sh
opencode plugin update 'github:srobroek/sniff#main::path:dist/opencode'
```

To test an unreleased change, pin a branch or commit instead of `main`, for example `github:srobroek/sniff#<sha>::path:dist/opencode`.

## What the plugin registers

- The seven Sniff tools: `sniff_intake`, `sniff_install_tools`, `sniff_run_analyzer`, `sniff_report`, `sniff_read_report_artifact`, `sniff_read_analyzer_artifact`, and `sniff_cancel`. They use OpenCode's default Code Mode, so the model calls them as `tools.sniff_intake(...)` inside `execute`.
- The `sniff` skill. A skill with the same ID that you define yourself takes precedence.
- Two read-only subagents:
  - `bloodhound` scans one language per run. It requests the `strong` model-roles tier.
  - `refactor-challenger` attacks the findings before the report. It requests the `reviewer` tier.

  Both subagents deny every action first. They then allow reads, search, shell diagnostics, the web, and this plugin's skill files. Without the model-roles plugin they inherit the session model. To pin a model, set `agents.bloodhound.model` or `agents.refactor-challenger.model`.

Ask for an audit in plain language, for example `Use sniff to find code smells in src/auth.` The skill drives the interview, analyzers, challenge pass, and report.

## Approvals

Sniff never trusts a tool argument as approval. Each approval is an OpenCode permission request that shows the exact plan:

| Permission action | Asked before | Resource |
| --- | --- | --- |
| `sniff_confirm_intake` | Issuing a run lease for a resolved plan, including `interactive: false` intake | `<target kind>:<root or repository>` |
| `sniff_confirm_install` | Installing analyzer bundles (`mode: "install"` without `dryRun`) | Each bundle name |
| `sniff_confirm_save` | Writing a report to disk (`mode: "save"`) | The canonical report directory |

OpenCode's default policy allows every action, so by default the plugin turns these three into prompts. A configured `deny` still blocks them:

```jsonc
{
  "permissions": [
    { "action": "sniff_confirm_install", "resource": "*", "effect": "deny" }
  ]
}
```

Choosing **Allow always** does not skip later prompts, because each plan is different. A client that auto-accepts permissions, such as `opencode run --auto` or a TUI set to auto-accept, also accepts these prompts.

For unattended runs where configured rules alone should decide, set the plugin's `confirm` option to `false` and allow the actions you accept:

```jsonc
{
  "plugins": [
    { "package": "github:srobroek/sniff#main::path:dist/opencode", "options": { "confirm": false } }
  ],
  "permissions": [
    { "action": "sniff_confirm_intake", "resource": "*", "effect": "allow" },
    { "action": "sniff_confirm_install", "resource": "*", "effect": "deny" },
    { "action": "sniff_confirm_save", "resource": "*", "effect": "deny" }
  ]
}
```

To gate the tools themselves, write rules for their tool names, for example `{ "action": "sniff_run_analyzer", "resource": "*", "effect": "ask" }`.

## Paths and isolation

One OpenCode server serves many projects, so Sniff never uses the server's working directory:

- A relative target `root` resolves against the session's directory. A relative `rootOrRepository` or `repository` does so only when it names an existing local path.
- A relative report save `path` also resolves against the session's directory.
- `sniff_install_tools` probes from the session's directory unless `path` is given. In `install` mode it rejects `path`.
- Run leases are bearer capabilities. When the plugin unloads for a project, it releases only the leases it issued.

## Develop against a local checkout

Point a scratch project at the built package:

```jsonc
{
  "plugins": ["/path/to/sniff/dist/opencode"]
}
```

Rebuild after a change with the pinned Bun from `.tool-versions`:

```sh
mise install
bun run bundles
bun run skills:check
```

Then run `/reload` in OpenCode, or save the config file again.

Check what loaded for a project:

```sh
opencode api get '/api/plugin?location[directory]=/path/to/project'
opencode api get '/api/skill?location[directory]=/path/to/project'
opencode api get '/api/agent?location[directory]=/path/to/project'
```
