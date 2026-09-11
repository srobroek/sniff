# Cross-harness capabilities

Sniff ships one portable core with three adapters.

- OMP loads extension entrypoints.
- Claude Code loads the bundled MCP server from its plugin manifest.
- Codex loads the bundled MCP server from its plugin manifest.

Every adapter exposes exactly five tools:

- `sniff_intake`
- `sniff_install_tools`
- `sniff_run_analyzer`
- `sniff_report`
- `sniff_cancel`

The authored skill in `.skill-source/sniff/` generates native skill trees for each adapter.

## Status labels

- `VERIFIED` marks source and focused-test evidence.
- `NATIVE` marks a fresh harness installation or copied-cache probe.
- `FOCUSED` marks a focused protocol test without a clean-room exercise.
- `ENVIRONMENT-BLOCKED` marks an external model or registry condition.
- `N/A` marks an adapter-specific mechanism outside the portable contract.

The matrix columns are OMP, CC for Claude Code, and CX for Codex.

## Capability matrix

```text
Capability | OMP | CC | CX
Core and five tools | VERIFIED | VERIFIED | VERIFIED
Skill discovery | NATIVE | NATIVE | NATIVE
Generated skill | VERIFIED | VERIFIED | VERIFIED
sniff_intake | NATIVE | NATIVE | NATIVE
sniff_install_tools | NATIVE | NATIVE | NATIVE
sniff_run_analyzer | FOCUSED | FOCUSED | FOCUSED
sniff_report render and save | FOCUSED | FOCUSED | FOCUSED
Approval and denial | NATIVE | NATIVE | NATIVE
Cancellation and cleanup | NATIVE | FOCUSED | FOCUSED
Expiry and replay rejection | FOCUSED | FOCUSED | FOCUSED
Analyzer catalog | VERIFIED | VERIFIED | VERIFIED
MCP transport | N/A | NATIVE | NATIVE
OMP TTSR analyzer redirect | VERIFIED | N/A | N/A
OMP agent definitions | VERIFIED | N/A | N/A
```

`FOCUSED` records behavior covered by protocol tests.

The clean-room probes skipped packages.

The clean-room probes skipped report saving.

## Evidence in the current tree

The portable core lives in `src/core/`.

OMP registration lives in these files:

- `package.json`
- `extensions/sniff-intake-tool.ts`
- `extensions/sniff-install-tool.ts`
- `extensions/sniff-report-tool.ts`
- `extensions/sniff-intake-manifest.ts`
- `extensions/sniff-target-checkout.ts`

MCP registration lives in these files:

- `adapters/mcp/server.ts`
- `adapters/mcp/server.test.ts`
- `.mcp.json`
- `dist/claude/server.js`
- `dist/codex/server.js`

Plugin manifests live in these files:

- `.omp-plugin/plugin.json`
- `.claude-plugin/plugin.json`
- `.agents/plugins/marketplace.json`

Generated skill evidence uses these paths:

- `.skill-source/sniff/`
- `scripts/generate-harness-skills.ts`
- `skills/sniff/`
- `.claude/skills/sniff/`
- `.agents/skills/sniff/`
- `dist/codex/skills/sniff/`

Bundle evidence uses `scripts/build-harness-bundles.ts` and `scripts/packaging-shape.test.ts`.

Run the focused protocol suite with this command:

```sh
bun test extensions/sniff-adaptive-intake.test.ts extensions/sniff-install-tool.test.ts extensions/sniff-runtime-boundaries.test.ts extensions/sniff-report.test.ts extensions/sniff-ttsr-rule.test.ts adapters/mcp/server.test.ts scripts/generate-harness-skills.test.ts scripts/packaging-shape.test.ts
```

The suite covers these paths:

- approval and denial
- analyzer cancellation
- report render and save validation
- expiry and replay
- MCP dispatch
- generated skills
- bundle shape

The suite skips setup.

The suite skips report saving in a clean-room harness.

## Dated clean-room outcomes

The native probes ran on 2026-09-11.

Each probe used a copied local marketplace source or copied installed cache.

Remote publication commands were not tested. The commands in [Getting started](getting-started.md) target the published GitHub repository. The probes used copied local marketplace sources.

### OMP `omp/18.1.17`

A local marketplace add passed.

`omp plugin install sniff@sniff --scope=user` passed in an isolated profile.

The installed cache directory matched the source package SHA-256 `e2a95981a2faf4931470dc2fc4f0d3c87a460b7a081ca5ca72af50654c100560`.

Source-path search found no source checkout.

Fresh Bun imports of cached extension modules registered exactly five tools.

Cached `sniff_install_tools` list returned `ok=true` without mutation.

A noninteractive `plan-only` intake issued a manifest and lease.

`sniff_cancel` released that lease.

The interactive intake ran without UI.

It denied confirmation.

It issued no lease.

The fresh OMP model and skill probe was environment-blocked.

Every `omp -p` attempt stopped at the authorization gateway with `authorization timeout`.

The gateway reported `ready:false` and `reason:not_configured`.

That condition blocks a model-response claim.

It preserves installation evidence.

It preserves registration evidence.

It preserves list evidence.

It preserves lease evidence.

It preserves cancellation evidence.

### Claude Code `2.1.268 (Claude Code)` and toolbox `2.1.268.779`

Strict source-marketplace validation passed.

A copied local marketplace add passed.

`sniff@sniff --scope user --yes` installation passed.

Installed-cache validation passed.

Cache-only startup loaded the inline plugin.

Cache-only startup loaded two `.claude/skills` files.

Direct cached Bun `1.4.2` stdio initialize passed.

The tool listing passed with exactly five names.

The cached bundle SHA-256 was `835cb534f92df897f0fff3dc4d952bbbef6f866260162f3e4a71a3eccef652e2`.

The source bundle had the same hash.

Cached list and dry-run probe returned `ok=true`.

Those operations stayed read-only.

A complete no-capability intake returned `isError=true`.

It returned `sniff_operation_failed`.

It issued no lease.

After a Bedrock third-party probe, the model response probe stopped.

The process exited with `124`.

The probe removed the copied marketplace source.

A native installed-registry fresh load reported `marketplace-load-failed/cache-miss`.

Cache-only `--plugin-dir` startup remained proven.

The cache contained no source-branch path.

Cache startup remains verified.

Skill discovery remains verified.

MCP registration remains verified.

Tool listing remains verified.

### Codex `0.154.0.446`

A local marketplace add passed in an isolated `CODEX_HOME`.

`codex plugin add sniff@sniff` passed.

Cache startup read the plugin `mcp.json`.

Cache startup launched `bun run ${PLUGIN_ROOT}/server.js`.

The server initialized as `sniff` version `0.1.0`.

The tool listing passed with exactly five names.

Cached skill discovery loaded `skills/sniff/SKILL.md`.

It did not fall back to `.agents/skills`.

A fresh `codex exec` model probe called `sniff_install_tools` in `probe` mode.

The probe returned `MCP_CALL=PASS`.

Direct no-UI intake returned `confirmation_required`.

It returned `isError=true`.

It issued no lease.

Source and cache server bundles matched SHA-256 `835cb534f92df897f0fff3dc4d952bbbef6f866260162f3e4a71a3eccef652e2`.

The Codex clean-room removed its plugin and isolated directories.

The CLI uses `codex plugin add`.

The CLI does not provide `codex plugin install`.

The clean-room skipped packages.

It skipped analyzer execution.

It skipped report artifact saving.

The focused suite covers those paths at the protocol boundary.

## Clean-room regression checklist

The checklist columns are Check, Native, and Focused.

```text
Check | Native | Focused
Fresh marketplace and cache startup | OMP, Claude Code, and Codex passed local copied-source startup on 2026-09-11 | Packaging tests validate manifests
Generated skill discovery | Each adapter loaded its copied-cache skill path | Skill generator tests validate every output tree
Five tool registration | Each adapter listed the exact five names | MCP tests validate list and dispatch
Intake approval and denial | OMP denied no-UI interactive intake. Claude and Codex denied no-capability intake | Intake tests validate approval and lease invariants
Read-only list and probe | OMP and Claude passed list and probe. Codex passed a model probe | Installer tests validate probe and authorization boundaries
Analyzer installation and execution | The clean-room skipped this row | Focused tests validate fixed-recipe dispatch and cancellation
Report render and save | The clean-room skipped this row | Report tests validate render, save, receipts, and terminal cleanup
Cancel an unfinished run | OMP issued and canceled a noninteractive lease | Lifecycle tests validate cancellation and materialization cleanup
Expiry and replay rejection | The clean-room skipped this row | Lifecycle tests validate expiry and replay rejection
Cache and temporary-root cleanup | Each adapter removed its isolated probe roots | Cleanup assertions validate terminal release paths
```

A native pass proves the host installation and adapter boundary that it exercises. A focused pass proves the portable contract paths that the clean-room gate does not run.
