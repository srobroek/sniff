# Workflow

Sniff uses one authenticated run from intake through reporting. A capability binds each later tool call to the confirmed manifest.

## 1. Resolve intake

Sniff resolves every target to a file set. Immutable Git targets also receive a commit identity and isolated checkout. Mutable local targets remain in place.

The frontier checks decisions in this order:

1. target
2. intent
3. objective groups
4. budget

A complete request skips questions. An incomplete request receives only the first unresolved question.

## 2. Confirm the manifest

The manifest records these values:

- target identity
- intent
- objective groups
- exclusions
- analyzer dispositions
- budgets
- defaults and gaps
- trust route
- confirmation receipt

Sniff issues a capability for that exact manifest. It rejects changed manifests and replayed capabilities.

## 3. Detect the stack

Sniff detects languages from the resolved files. It uses the language references that match the target.

Generated files and vendor files do not determine the stack. Before detection, Sniff removes them from the stack sample.

## 4. Probe analyzers

Sniff probes the host analyzer executable. A probe checks availability and version behavior. It does not authorize a scan.

Before a broad interactive run, Sniff shows available tools. You approve installation separately from analysis.

## 5. Run fixed recipes

Each selected analyzer has a host-owned recipe. The capability limits the recipe to the confirmed target.

Sniff enforces these limits:

- exact file scope
- analyzer count
- file count
- elapsed minutes
- one run for each selected recipe

After preflight, Sniff checks the target again. Sniff blocks a file outside the root.

## 6. Read and challenge findings

Static tools do not cover every structural smell. Sniff reads the remaining target and may divide large targets by language.

In full mode, a separate challenge pass tests each finding for evidence and refactoring value. The pass can keep, downgrade, or drop a finding. Quick mode skips this pass.

## 7. Report or apply

Sniff authenticates the report against the intake manifest. Its target must match the confirmed target.

Render mode returns report content without writing files. Save mode needs an explicit path and writes a JSON report, Markdown report, and receipt.

Applying a refactor needs a separate approval. Plan-only mode never applies changes.

## Cleanup

A successful or failed report closes the capability and removes temporary materialization. Explicit cancellation performs the same cleanup. An expiry timer cleans abandoned runs.
