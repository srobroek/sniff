# Objective groups


| Group | Scope |
| --- | --- |
| Structure and maintainability | cohesion, coupling, duplication, complexity, names, boundaries |
| Correctness and resilience | bugs, errors, invariants, failure paths |
| Performance and efficiency | avoidable work, allocations, input/output, hotspots |
| Change and release risk | diffs, compatibility, migrations, release deltas |
| Tests, delivery, and tooling | test gaps, CI settings, developer workflow |
| Bounded security smells | checks from `security-scope.md` |
When the choice changes the plan, interactive intake asks for groups.
When no selection exists, noninteractive intake selects all six groups.
The run manifest records that default.
