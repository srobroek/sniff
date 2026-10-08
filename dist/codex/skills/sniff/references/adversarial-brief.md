# Challenge Brief Template

Use this to build the step-6 prompt for `independent challenge reviewer`.
The challenger's whole value comes from **isolation**: give it the findings and
the observable evidence, but NOT your reasoning, your preferred plan, or your
confidence. Let it reach its own verdict so it does not inherit your blind spots.

Spawn one challenger over the consolidated finding set; never split the
challenge across parallel agents. The agent is read-only.

---

```
You are stress-testing a set of refactoring recommendations produced for this
repository. Stay read-only: verify the cited code, but never edit or apply.
For each finding, decide:
- KEEP: the smell is real and the fix earns its cost.
- DOWNGRADE: the smell is real but low-value, or you are unsure the fix earns
  its cost.
- DROP: a false positive, or a fix that would make the code worse.
Bias toward pragmatism and idiom: a real but low-value or non-idiomatic-but-fine
finding should not survive as a high-priority recommendation. Any change to a
public signature, wire format, config key, or documented behavior is never
low-risk.

## Findings under test
For each finding (facts only — verify them yourself):

- **ID:** <n>
- **Location:** <file:line>
- **Smell claimed:** <smell name>
- **Evidence:** <metric / quoted code / tool + rule id that produced it>
- **Proposed refactoring:** <refactoring + refactoring.guru technique>
- **Claimed back-compat:** <safe | breaking: surface>

<repeat per finding>

## Repo context (facts only)
- Languages: <list>
- Conventions / config: <e.g. .golangci.yml present, project uses X idiom>
- Public surfaces to protect: <published API, wire formats, config keys — if known>

## What I am NOT telling you
I am deliberately withholding which findings I think matter most and why. Reach
your own verdicts from the code.

## Return
1. One line: `VERDICT: KEEP|DOWNGRADE|DROP -- K keep / D downgrade / X drop`.
2. A table with one row per finding: ID, finding, verdict, cited evidence
   (file:line, command output, or convention source).
3. For each DOWNGRADE or DROP, one evidence-backed rationale line.
Never reprint code, diffs, or file contents.
```

---

## Filling guidance

- **Withhold your priors.** Do not write "I think #3 is the big one" -- that is
  exactly the framing the challenger exists to test independently.
- **Pass evidence, not conclusions.** "140 lines, ccn 22" is evidence; "this is
  clearly too complex" is a conclusion -- give the former.
- **Name the public surfaces** you know about so the challenger can judge
  back-compat accurately; it cannot always infer what is published.
- **Apply the verdicts** when it returns: DROP → `adversarial.verdict: "drop"`,
  DOWNGRADE → `"downgrade"` with lower priority, KEEP → `"keep"`. Copy each
  rationale into `adversarial.reason`; the report lists drops and downgrades in
  its transparency section.
- **Large finding sets stay in one brief.** Keep every finding's evidence
  complete and let the challenger page through it; cross-language interactions
  are lost when the set is split.
