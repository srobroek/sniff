# Approval gates

Target resolution, stack detection, configuration reads, and read-only availability probes are allowed before tool-set approval. Do not install tools, run substantive scans, or dispatch an independent scout until target and tool-set approval are established.

1. **Target.** If unnamed, ask first for the kind: whole repository, working-tree uncommitted changes, files, directory/module, commit, range/branch/ref, repository, PR/MR, release, or history. Then ask for the required path/ref. Kinds compose. Never infer whole-repository scope from an uncommitted-changes request.

   Map the answer to one exact `TargetRequest` object:

   - whole repository → `{"kind":"whole-repo","root":"<repo-root>"}` (committed `HEAD` snapshot; temporary checkout)
   - uncommitted changes / working tree → `{"kind":"working-tree","root":"<repo-root>"}` (unstaged, staged, and untracked files; in place)
   - explicit files → `{"kind":"files","root":"<repo-root>","paths":["src/a.ts"]}`
   - directory → `{"kind":"directory","root":"<repo-root>","path":"src"}`
   - module → `{"kind":"module","root":"<repo-root>","path":"src/parser"}`
   - commit → `{"kind":"commit","root":"<repo-root>","commit":"<ref>"}`
   - range → `{"kind":"range","root":"<repo-root>","base":"<ref>","head":"<ref>"}`
   - branch → `{"kind":"branch","root":"<repo-root>","branch":"<ref>","base":"<ref>"}` (omit `base` for the default base)
   - exact ref → `{"kind":"ref","root":"<repo-root>","ref":"<ref>"}`
   - repository → `{"kind":"repository","repository":"<url>","ref":"<ref>"}` (omit `ref` for `HEAD`)
   - PR → `{"kind":"pr","repository":"<url>","number":"<number>"}`
   - MR → `{"kind":"mr","repository":"<url>","iid":"<iid>"}`
   - release → `{"kind":"release","repository":"<url>","tag":"<tag>","previousTag":"<tag>"}` (omit `previousTag` when not requested)
   - history → `{"kind":"history","rootOrRepository":"<repo-root-or-url>","window":<history-window>}`

2. **Install set.** After stack detection, use `sniff_install_tools` `probe` and target references to present every viable analyzer. Default-on tools start selected; opt-in tools start unselected with their reason. Wait before install.

For a **non-interactive** run, a delegated brief can name the target and objectives, but it cannot replace the host confirmation boundary: `sniff_intake` obtains authorization from the host and rejects caller-supplied authorization. Use only the recipes intake selects, record missing tools as gaps, and never install tools; headless sessions cannot install. Missing scope remains blocked; unavailability is not consent.

## Skill directory and target directory

Tools run with cwd set to the target repository. Resolve shipped assets against the installed skill directory, never against the target's working directory. The `opengrep:hardcoded-values` recipe loads its rule file host-side, so no tool call needs an asset path.
