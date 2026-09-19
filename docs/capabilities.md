# Cross-harness capabilities

Sniff ships one portable core with three adapters.

- The native adapter loads extension entrypoints.
- The Claude Code and Codex adapters load the bundled MCP server from their plugin manifests.

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

## Evidence in the current tree

The portable core lives in `src/core/`.

These files register the native adapter:

- `package.json`
- `extensions/sniff-intake-tool.ts`
- `extensions/sniff-install-tool.ts`
- `extensions/sniff-report-tool.ts`
- `extensions/sniff-intake-manifest.ts`
- `extensions/sniff-target-checkout.ts`

MCP registration lives in these files:

- `adapters/mcp/server.ts`
- `adapters/mcp/server.test.ts`
- `claude-mcp.json`
- `dist/claude/server.js`
- `dist/codex/server.js`
- `dist/codex/mcp.json`
Plugin manifests live in these files:

- `.omp-plugin/plugin.json`
- `.claude-plugin/plugin.json`
- `.agents/plugins/marketplace.json`
- `dist/codex/plugin.json`

Generated skill evidence uses these paths:

- `.skill-source/sniff/`
- `scripts/generate-harness-skills.ts`
- `skills/sniff/`
- `.claude/skills/sniff/`
- `.agents/skills/sniff/`
- `dist/codex/skills/sniff/`

Run the focused protocol suite with this command:

```sh
bun test extensions/sniff-adaptive-intake.test.ts extensions/sniff-install-tool.test.ts extensions/sniff-runtime-boundaries.test.ts extensions/sniff-report.test.ts adapters/mcp/server.test.ts scripts/generate-harness-skills.test.ts scripts/packaging-shape.test.ts
```
The suite covers approval, cancellation, expiry, replay, MCP dispatch, generated skills, and bundle shape.
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
