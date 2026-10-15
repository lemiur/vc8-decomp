# VC8 matching decompilation

Read VC8_DECOMP_PLAN.md for the target and phase order. Human instructions in the current session take precedence over that plan and the skills. The current campaign requests twelve concurrent workers once matching starts, Sol 6.1 for reasoning, contexts below 400k tokens, and a mechanical-reader model to be resolved because Luna 6.1 is not available.

## Project adapter

Repository: E:/vc8-decomp. Integration branch: master. Lane branches use codex/. Each worker has a separate worktree and build directory. Commit focused changes locally; no push, PR, or network publication. The initial repository has no implementation: commands below are the intended tool interface, not a claim that they already work. Infrastructure workers must document any interface changes.

| verb | command |
|---|---|
| build | python tools/match.py build --binary cl (repeat per configured binary) |
| match | python tools/match.py match --binary cl --unit matching/cl/UNIT.cpp |
| diff | python tools/match.py diff --binary cl --function SYMBOL |
| disasm | python tools/evidence.py disasm --binary cl --symbol SYMBOL |
| xref | python tools/evidence.py xref --binary cl --symbol SYMBOL |
| class | python tools/evidence.py class --binary cl --symbol SYMBOL |
| gate | python tools/gate.py --binary cl --clean |
| rules | python tools/rulecheck.py matching |
| report | python tools/report.py |

Toolchain: installed x86 VC8 SP1, C:/Program Files (x86)/Microsoft Visual Studio 8/VC/bin. Establish the actual file versions and hashes. Flags are provisional until probes establish them. Use /GL and /LTCG for compiler code; C++ EH and /MD where supported by evidence. Do not claim a full source relink from a splice gate. The RTM ISO is a local optional input, never committed or installed over SP1.

## Source and evidence

Dialect: MS C89 for C, VC8 C++ for C++ units. Public PDB spellings are the primary identity evidence; module ownership must distinguish actual module attribution from a guess. Preserve evidence for declarations and names. Source layout is checked because asserts embed __LINE__; do not invent line mappings. The parking marker is // stop:. Annotations use // FUNCTION: <binary> 0x<VA> and // DATA: <binary> 0x<VA>. Mark unresolved identities and invented names explicitly. CRT code may be recovered from the installed era's source when its version and provenance are recorded.

Apply the matcher and decomp-code-rules skills from C:/Users/zimme/.agents/skills. In particular: canonical shared types and globals; evidence-backed owners and calling conventions; no raw offset-cast models, dummy virtuals, fake locals, inline assembly, byte arrays masquerading as source, or padding to force matches. Public names alone do not prove signatures. Record genuine rule exceptions with their byte evidence and an explicit allow entry; otherwise byte-exact rule failures remain MATCH-PENDING.

## Byte gate

Build the all-fallback identity gate before counting any function. Pin each retail binary's SHA-256, image base, version, and PDB GUID/age. The gate must verify those inputs, rebuild candidates into fresh output, independently compare extracted function bytes and ordered referents, splice only admitted source bytes into a retail copy, and hash the complete output. Every substituted byte needs attributable build provenance. A copied retail byte, unresolved relocation, fuzzy match, stale output, or unsupported relocation cannot count as compiled source. Reject overlaps and unexplained size changes. Never mask a referent and count it without independently resolving its identity. Report both rule-admitted functions and source-attributed bytes, with denominators and unresolved boundary caveats. The gate's printed green line is the only authority for banked counts. An all-fallback green result means zero matched.

Clean rebuild and compare against the integration baseline before updating any baseline. A real regression in an edited function blocks merge. Dips in untouched functions are informational. Never build or commit while a rebase has unresolved paths. Merge generated reports by regeneration and score history per function, never by wholesale replacement. Matching candidates use retail comparison rather than behavioral test suites; infrastructure changes get focused tests of their contracts and failure paths.

## Parallel work and bounded reads

Workers own disjoint files and source units. Do not edit another worker's files or shared headers without coordination. Reasoning agents inspect bounded evidence for their assigned reconstruction; bulk extraction and large-text reading belong to mechanical readers. Do not print entire PDB dumps, decompiler exports, disassemblies, or ledgers. Slice raw inputs into at most about 200 KB, cap raw command output near sixty lines, and return summaries under 600 words. Keep contexts below the user's 400k ceiling and hand off before approaching it. The orchestrator consumes summaries, not bulk dumps.

Pass order: plain matching, helper recovery, then a structural pass; permutation requires a diagnosed register/schedule residue. Commit exact work promptly, then report each function's evidence, score, referent verdict, and open leads. Do not declare an untested lead exhausted. The integration owner performs rebase, clean build, regression gate, byte gate, rule checks, report update, and merge.

## Repository hygiene

Never commit Microsoft binaries, PDBs, archives, ISOs, decompiler output, or generated build state. symbols/, ref/, ref-rtm/, decompiled/, and build/ are local ignored inputs/outputs. Configurations and reusable tools may be tracked. Preserve the user's local ISO and all unrelated work. Documentation describes working interfaces and present limitations, not speculative completion. Worktrees do not inherit ignored inputs: resolve them through config/project.json or the primary checkout without duplicating large files.
