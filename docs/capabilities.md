# Cross-harness capabilities

Sniff ships one portable core with four adapters.

- The OMP adapter loads extension entrypoints.
- The Claude Code and Codex adapters load the bundled MCP server from their plugin manifests.
- The OpenCode adapter is a native V2 plugin that registers the tools, the skill, and the two subagents. See [OpenCode](opencode.md).

Every adapter exposes exactly seven tools:

- `sniff_intake`
- `sniff_install_tools`
- `sniff_run_analyzer`
- `sniff_report`
- `sniff_read_report_artifact`
- `sniff_read_analyzer_artifact`
- `sniff_cancel`

The authored skill in `.skill-source/sniff/` generates native skill trees for each adapter.

## Capability matrix

The matrix records the runtime lifecycle run completed on 2026-09-12.

```text
Capability | OMP | Claude Code | Codex
Core and seven tools | VERIFIED | VERIFIED | VERIFIED
Skill discovery | VERIFIED | VERIFIED | VERIFIED
Install list, probe, diagnose, and approval boundary | VERIFIED | VERIFIED | VERIFIED
Adaptive intake and target authentication | VERIFIED | VERIFIED | VERIFIED
OpenGrep execution | VERIFIED | VERIFIED | VERIFIED
Analyzer artifact paging | VERIFIED | VERIFIED | VERIFIED
Report validation and artifact paging | VERIFIED | VERIFIED | VERIFIED
Capability replay rejection | VERIFIED | VERIFIED | VERIFIED
Cancellation and cleanup | VERIFIED | VERIFIED | VERIFIED
Target cleanliness | VERIFIED | VERIFIED | VERIFIED
```

The native adapter uses extension tools. Claude Code and Codex use MCP transport. Adapter-specific transport does not change the portable contract.

OpenCode is not in the matrix yet. On 2026-11-03, OpenCode 2.2.5 loaded the plugin from `dist/opencode` and registered the `sniff` skill and both subagents. A live session listed analyzers, approved and leased an intake, and cancelled it. `adapters/opencode/plugin.test.ts` and `scripts/packaging-shape.test.ts` cover the full lifecycle against a fixture analyzer.

## Evidence in the current tree

The portable core lives in `src/core/`.

These files register the native adapter:

- `package.json`
- `extensions/sniff-intake-tool.ts`
- `extensions/sniff-install-tool.ts`
- `extensions/sniff-report-tool.ts`

MCP registration lives in these files:

- `adapters/mcp/server.ts`
- `tests/adapters/mcp/server.test.ts`
- `claude-mcp.json`
- `dist/claude/server.js`
- `dist/codex/server.js`
- `dist/codex/mcp.json`

Plugin manifests live in these files:

- `.omp-plugin/plugin.json` (declares no MCP servers, so OMP uses only the native extension tools)
- `.omp-plugin/marketplace.json` (OMP catalog; loads the OMP skill tree in `skills/`)
- `.claude-plugin/plugin.json`
- `.claude-plugin/marketplace.json` (Claude Code catalog; loads the Claude skill tree in `.claude/skills/`)
- `.agents/plugins/marketplace.json`
- `dist/codex/plugin.json`
- `dist/opencode/package.json`

The OpenCode adapter lives in `adapters/opencode/` and builds to `dist/opencode/index.js`.

Generated skill evidence uses these paths:

- `.skill-source/sniff/`
- `tools/generate-harness-skills.ts`
- `skills/sniff/`
- `.claude/skills/sniff/`
- `.agents/skills/sniff/`
- `dist/codex/skills/sniff/`
- `dist/opencode/skills/sniff/`

Run the focused protocol suite with this command:

```sh
bun test tests/
```
The suite covers approval, cancellation, expiry, replay, MCP dispatch, generated skills, and bundle shape. Tests live in `tests/` and the skill and bundle generators live in `tools/`; no test or developer-only file ships inside an installed component directory (`extensions/`, `src/`, `adapters/`, `skills/`).

## Cross-harness verification

Run `bun run bundles:check` to verify generated harness bundles and the OpenGrep rule copy. Run `bun run check` before publishing an adapter or portable-core change.

The external matrix directory holds cross-harness evidence because it contains temporary target paths and session records.

## Regression checklist

Before publishing an adapter or portable-core change, run `bun run check`. It validates the generated assets and complete test suite.

If a change affects any following surface, repeat the cross-harness lifecycle matrix:

- public tool schemas
- capability or lease behavior
- target authentication
- analyzer dispatch or artifact paging
- report validation or persistence
- adapter packaging

A focused protocol test does not replace a harness lifecycle run for these surfaces.
