# Cross-harness capabilities

## Scope and status

This matrix covers the OMP adapter at commit `0653793f0b5360f5f24179ecd53a71e0619d9af9`. Claude Code and Codex have no supported adapter. Each adapter needs a clean-room probe from installation through report cleanup.

The matrix keeps five axes separate:

- intent
- objective group
- target
- scope mode
- analyzer family and tier

The frontier asks four questions in order. A run stores scope. [Evidence: `extensions/sniff-intake.ts:13-19,39-60,93-116`, `extensions/sniff-tool-catalog.ts:46-57`, `docs/workflow.md:9-16,20-32`]

Status labels:

- `VERIFIED`: code and targeted evidence cover the behavior.
- `DEGRADED`: the harness exposes part of the behavior. A boundary is caller-mediated or absent.
- `IMPLEMENTABLE`: the contract identifies a harness-native replacement. No adapter ships it.
- `BLOCKED`: no adapter or probe establishes the behavior.
- `NOT APPLICABLE`: an OMP mechanism does not transfer as-is. A replacement still needs evidence.

## Capability matrix

| Capability | OMP | Claude Code | Codex |
| --- | --- | --- | --- |
| Skill discovery | `VERIFIED` [O1] | `BLOCKED` [P] | `BLOCKED` [P] |
| `sniff_intake` | `VERIFIED` [O2] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| `sniff_install_tools` | `VERIFIED` [O3] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| `sniff_run_analyzer` | `VERIFIED` [O4] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| `sniff_report` | `VERIFIED` [O5] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| `sniff_cancel` | `VERIFIED` [O6] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| Long-lived lease state | `VERIFIED` [O6] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| Interactive confirmation | `VERIFIED` [O2] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| Installation approval | `DEGRADED` [O3] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| Analyzer execution | `VERIFIED` [O4] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| Cancellation and expiry | `VERIFIED` [O6] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| TTSR analyzer redirect | `VERIFIED` [O7] | `NOT APPLICABLE` [P] | `NOT APPLICABLE` [P] |
| Agents | `VERIFIED` [O8] | `BLOCKED` [P] | `BLOCKED` [P] |
| MCP transport | `NOT APPLICABLE` [O1] | `IMPLEMENTABLE` [P] | `IMPLEMENTABLE` [P] |
| Marketplace and install shape | `VERIFIED` [O9] | `BLOCKED` [P] | `BLOCKED` [P] |
| Clean-room evidence | `VERIFIED` [T] | `BLOCKED` [P] | `BLOCKED` [P] |

## Evidence keys

- `[O1]` Skill and registration: `skills/sniff/SKILL.md:1-3`, `package.json:12-17`, `extensions/sniff-intake-tool.ts:132-176`, `extensions/sniff-report-tool.ts:88-123`.
- `[O2]` Intake: `extensions/sniff-intake.ts:93-116`, `extensions/sniff-intake-tool.ts:74-129`, `extensions/sniff-adaptive-intake.test.ts:398-428`.
- `[O3]` Installation: `extensions/sniff-install-tool.ts:548-559,718-820,846-902`, `skills/sniff/SKILL.md:24-29,48`, `docs/getting-started.md:56-62`, `extensions/sniff-install-tool.test.ts:485-532`.
- `[O4]` Analyzer: `extensions/sniff-tool-catalog.ts:46-94`, `extensions/sniff-run-registry.ts:106-151,197-230`, `extensions/sniff-install-tool.ts:621-716`, `extensions/sniff-runtime-boundaries.test.ts:285-302`.
- `[O5]` Report: `extensions/sniff-report-tool.ts:67-85`, `docs/reports.md:28-44,58-70`, `extensions/sniff-report.test.ts:265-278`.
- `[O6]` Lease: `extensions/sniff-run-registry.ts:9-10,55-85,186-194,244-255`, `docs/security-and-trust.md:57-59`, `extensions/sniff-runtime-boundaries.test.ts:162-181`.
- `[O7]` TTSR: `rules/quality-sniff-analyzer-redirect.md:1-12`, `extensions/sniff-ttsr-rule.test.ts:23-71`.
- `[O8]` Agents: `agents/bloodhound.md:1-12,21-34`, `agents/refactor-challenger.md:1-12,21-34`, `skills/sniff/SKILL.md:31-47`.
- `[O9]` Install shape: `README.md:11-21`, `docs/getting-started.md:12-22`, `.omp-plugin/plugin.json:1-6`.
- `[P]` Adapter status: `package.json:12-17` contains only OMP entrypoints. The inventory probe `git ls-files '*claude*' '*Claude*' '*codex*' '*Codex*' '*mcp*' '*MCP*'` returned no paths at this commit.
- `[T]` Targeted evidence: `bun test extensions/sniff-adaptive-intake.test.ts extensions/sniff-install-tool.test.ts extensions/sniff-runtime-boundaries.test.ts extensions/sniff-report.test.ts extensions/sniff-ttsr-rule.test.ts`.

The installation registration has no confirmation callback. The skill and guide place approval in the caller workflow. That split makes the OMP cell `DEGRADED`. [Evidence: `[O3]`]

After a terminal event, cleanup removes the target checkout and analyzer home. [Evidence: `[O6]`]

An OMP TTSR rule does not transfer to another harness. An OMP agent definition does not establish a Claude Code or Codex agent. [Evidence: `[O7]`, `[O8]`]

## Clean-room gate

Run these checks for each adapter:

1. Discover the canonical skill after a fresh install.
2. Invoke all five tools. Use one target and one report contract.
3. Confirm intake and reject a denial.
4. Probe tools and reject installation without approval.
5. Run one selected analyzer through its fixed recipe.
6. Render and save a report with receipt hashes.
7. Cancel an unfinished run.
8. Wait for expiry. Reject replay with an expired capability.
9. Exercise the harness-native replacement for OMP TTSR or agents.

A harness-native replacement is not support. Claude Code and Codex remain unsupported until their clean-room probes pass. [Evidence: `[P]`, `README.md:5-10`, `docs/workflow.md:40-72`, `extensions/sniff-run-registry.ts:197-255`]
