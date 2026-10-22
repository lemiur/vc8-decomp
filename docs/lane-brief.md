# Matching-lane brief

One worker owns one reconstruction unit and its header. Do not edit any other
unit, header, shared tool, or the integration branch. Work on your own branch in
your own worktree; commit focused commits there. No push, PR, or publication.

Read `AGENTS.md` first; it takes precedence. Then load the `matcher`,
`decomp-code-rules` and `helper-recovery` skills from
`C:/Users/zimme/.agents/skills` and follow them.

## Inputs

- `build/evidence/lanes/<lane>.tsv` lists the unit's still-unmatched public
  functions: `va<TAB>next_public_gap<TAB>pdb_size<TAB>decorated name`.
  A blank `pdb_size` means no exact PDB length: the gap is only an upper bound.
- `build/evidence/cl.functions.tsv` has the full PDB-owned inventory with
  module attribution and size provenance. Symbols are primary identity
  evidence; a name alone does not prove a signature.
- `python tools/evidence.py disasm --binary cl --symbol SYMBOL --max-lines 60`
  decodes retail at the public start. `xref` and `class` give callers and
  class layout. Decompiler exports are hints, never source.

## Matching loop per function

1. Decode the complete retail body and every ordered referent. Establish the
   exact end (a `ret`, or a jump into a shared tail) and the calling
   convention from the callee/caller evidence. Record the byte length.
2. Identify the real owner and callees. A callee whose body is missing must be
   reconstructed as real source too; the harness never links stubs. Declare
   missing symbols as canonical declarations in the unit header, and add the
   real defining unit under the candidate's `dependencies`.
3. Write the C++ source in the unit with the annotation block:
   `// FUNCTION: cl 0x<VA>` and `// SYMBOL: <decorated name>`. Model real types,
   globals and fields; no offset casts, dummy virtuals, fake locals, padding,
   inline assembly or byte arrays.
4. Register the candidate in `config/cl-candidates.json` (append after the
   existing entries, keep one JSON object per candidate):
   ```json
   {
     "binary": "cl", "symbol": "<decorated>", "retail_va": "0x<va>",
     "size": <N>, "unit": "matching/cl/<unit>.cpp",
     "source_span": {"start": <first source line>, "end": <closing brace line>},
     "boundary": {"status": "verified",
                  "evidence": "Bounded direct retail decoding over exactly <N> bytes: <decoded instructions, every branch, the terminator, all referents>; source owner compared every byte and ordered reference under actual /GL + /LTCG."},
     "dependencies": ["matching/cl/<callee unit>.cpp"],
     "roots": ["<decorated root symbol>"],
     "identity_evidence": "<PDB public start + module contribution + ABI evidence>"
   }
   ```
   Add `"gate_enabled": false` plus `"pending"` instead when the function is
   not byte-exact; disabled entries stay as recorded open work.
5. `python tools/match.py match --binary cl --unit matching/cl/<unit>.cpp`
   writes a comparison and prints per-function `MATCH`/`MATCH-PENDING`/`DIFF`
   scores. Only score 100 with `boundary=verified referents=resolved` is a
   match. `python tools/match.py diff --binary cl --function SYMBOL` shows the
   first divergence.
6. Never accept a fuzzy score. Diagnose the plateau with `wall-identifier`
   before trying a permuter.

## Per-unit compiler flags

Flags are per unit in `config/cl.json` under `"units"`; keep the evidence note
accurate. Do not change the common flags. If a unit needs `/Zc:wchar_t-`,
`/Ob1`, `/GF` or a link library, add it there with the measured reason.

## Review evidence (required before a function can be banked)

For every byte-exact function, append to `config/reviews/cl5-<lane>.json`:

```json
{"schema_version": 1, "binary": "cl", "lane": "<lane>",
 "functions": [{"va": "0x<va>", "symbol": "<decorated>",
   "source_path": "matching/cl/<unit>.cpp",
   "source_span": {"start": N, "end": M}, "size": N,
   "checks": {"R1": "one canonical type/declaration evidence ...",
              "R2": "canonical globals/ownership ...",
              "R4": "real layouts, no offset casts ...",
              "R13": "real vtable evidence or none ...",
              "R17": "authentic locals/statements vs decoded body ...",
              "R18": "ordinary VC8 source, no assembly/byte arrays/padding ..."}}]}
```

Each check text must cite the actual evidence (decoded bytes, the canonical
declaration, the initializer, the caller). The integration owner re-computes
the scope hash and imports these checks; do not edit
`config/rule-exceptions.json` yourself.

## Verification before you report

- `python tools/match.py match --binary cl --unit <unit>` is 100 for every
  claimed function.
- `python tools/rulecheck.py matching` shows your functions as
  `RULE-ADMITTED` only after the integration import; before that they are
  `MATCH-PENDING` and that is expected.
- Never run the whole-binary gate in a lane worktree as evidence for release
  counts; the integration owner runs it on the merged tree.

## Report

Return, per function: VA, decorated name, byte size, final score, referent
verdict, the structural finding that closed it, and any remaining wall with
the lever family already tested. Commit before reporting.
