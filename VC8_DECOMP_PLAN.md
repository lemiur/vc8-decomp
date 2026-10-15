# Byte-matching decompilation plan: Visual C++ 2005 SP1 compiler (14.00.50727.762)

Target install: `C:\Program Files (x86)\Microsoft Visual Studio 8\VC\bin` (x86-hosted, x86-targeting).

## 1. What we are matching (measured, 2026-10-15)

| binary | size | role | how it was built (Rich header, verified empirically) | est. functions | source names in strings |
|---|---|---|---|---|---|
| `cl.exe` | 117 KB | driver | 1 LTCG C++ object + CRT stubs | ~320 | none |
| `c1.dll` | 631 KB | C front end | **87 LTCG C++** objects | ~1,100 | 19 (`F:\SP\VCTOOLS\Compiler\CxxFE\sl\P1\C\`) |
| `c1xx.dll` | 2.29 MB | C++ front end | **120 PGO-optimized C++** objects | ~4,500 (low confidence) | 46 (same tree; 17 shared with c1) |
| `c2.dll` | 2.27 MB | back end (UTC) | **163 LTCG C** objects | ~5,600–6,400 | 66 (`F:\SP\vctools\compiler\utc\src\{P2,Common,x86,wvm}`) |
| `link.exe` | 733 KB | linker | **88 LTCG C++** objects | ~1,600+ | none |

The remaining plain C, C++ and MASM entries in each Rich header (~15 C, ~8 C++, ~14 MASM) match the
`msvcrt.lib` /MD startup objects. All of the compiler's own code went through `/GL`.

**Prodid table, verified by compiling probes with the local VC8 (a full PGO cycle):**
`0x6D C`, `0x6E C++`, `0x71 LTCG_C`, `0x72 LTCG_CPP`, `0x73 POGO_I_C`, `0x74 POGO_I_CPP`, `0x75 POGO_O_C`,
`0x76 POGO_O_CPP`, `0x78 Linker800`, `0x7A Export800`, `0x7B Implib800`, `0x7C Cvtres800`, `0x7D Masm800`,
`0x7E AliasObj800`. Note: `E:\avp3-decomp\tools\rich_header.py` labels 0x71/0x72 as CVTCIL, which is wrong.

Other facts:
- All binaries are timestamped 2006-12-02 (the SP1 build lab).
- All use the dynamic CRT (MSVCR80, plus MSVCP80 for c1/c1xx), /GS, SafeSEH and EH4, with frame pointers
  mostly omitted.
- c1/c1xx/link use C++ EH. c2 is C apart from a few .cpp files (dbg, dll, emit, imeta, oograph, cstream).
- **Asserts embed file names and `__LINE__`.** Source line layout is therefore *[checked]*: it changes bytes
  (decomp-code-rules R23).
- PDB keys for the symbol server:

| PDB | GUID + age |
|---|---|
| `c2.pdb` | `8E3C6AD714BE4E55B528B0DBEB3BABD8` `1` |
| `c1xx.pdb` | `0A900E6195D645CFAF11A3D6C3477C0C` `2` |
| `c1.pdb` | `8C56BD7B882A4B22B2A1FC53891CB1F5` `1` |
| `cl.pdb` | `720089F2F35A4A128093E654DACA5226` `1` |
| `link.pdb` | `9906D3844D8A4D4B89557AC3D0D17195` `1` |

**Total: ~13,000–14,000 functions.** Out of scope at first: `amd64\` and `x86_amd64\` (same sources, other
`#ifdef` targets; reuse later), plus `mspdb80`, `msobj80` and `pgodb80`.

## 2. The hard parts, and how the plan handles each

1. **LTCG everywhere.**
   - Codegen happens at link time over the whole program: cross-unit inlining, custom calling conventions for
     functions whose call sites are all known, and linker-chosen ordering.
   - A function's bytes therefore depend on its callees' bodies and on its callers, not just on its own unit.
   - The match harness compiles each candidate with `/GL` and links `/LTCG` against the real bodies of every
     callee it inlines (and stubs for the rest). It then extracts the function and compares it, with masked
     relocations resolved against the retail symbol map.
   - avp3's `// ltcg: <group>` mechanism (`tools\ltcg.py`) is the precedent.
2. **PGO in c1xx.**
   - Inlining, block layout, hot/cold splitting and speed/size choices per function were driven by a profile
     that is lost.
   - Mitigation: c2 contains the PGO *consumer* (`pogoinline.c`, `pogoopt.c`, `pogocg.c`). Decompiling those
     first tells us exactly which counts drive each decision.
   - c1xx is then matched with a synthesized `.pgd`, written through the `PogoDb*` API in `pgodb80.dll`, that
     reproduces retail's decisions. That is why c1xx comes last.
3. **Bootstrap compiler.**
   - The Rich header records build 50727 but not the QFE (`.42` RTM versus `.762` SP1).
   - Phase 1 A/B-tests the first ~50 matched functions under both builds. Only `.762` is installed, so ask
     whether an RTM `.42` install is available.
4. **Flags are unknown.**
   - Candidates are `/O2` or `/O1`, `/Oy`, `/GS`, `/Gy`, `/GF`, `/EHsc` (C++ units), `/GR` (c1xx has RTTI),
     `/Zp`, `/J`, `/Gz`/`/Gr` and `/GL`.
   - They are recovered in Phase 0 from leaf-function probes, and may vary per binary or per unit.
5. **Line numbers in asserts.** Layout matters, so every function is matched with its real line position
   inside its unit. Units are reconstructed in address/source order, not as isolated snippets.

## 3. Phases

### Phase 0: evidence and infrastructure (no matching yet)

1. **Public symbols (needs your OK, since it is a download).**
   - Query `msdl.microsoft.com/download/symbols` for the five PDBs above with `symchk`.
   - Public PDBs give every function's name and address, along with globals and statics. They turn this from
     a ~14k-function anonymous blob into a named map.
   - If they exist, they become the primary identity evidence (R7). If not, the fallback evidence is strings,
     asserts, exports, RTTI and Ghidra boundaries.
2. **New repository.**
   - Scaffold it from avp3-decomp's layout: `config\`, `matching\<binary>\<unit>.c`, `tools\`,
     `ledger.tsv` and `AGENTS.md` from the matcher template.
   - Fill in the project adapter, and reuse `matchlib.py`, `match.py`, `gate.py`, `rulecheck.py` and the
     ledger tooling.
3. **Ghidra 12.1.3 import.**
   - Import all five binaries, apply the PDBs if any, and run `CreateFunctions.java`.
   - Export a function table (address, size, name, unit guess) per binary, plus raw decompiler output into an
     ignored `decompiled\` (hints only, never source).
4. **Unit map.**
   - Assign functions to the 66 / 46 / 19 known source files using assert-string references (file name and
     `__LINE__`) and address contiguity.
   - Under LTCG, link order is weaker evidence than it is for plain builds, so record the confidence of each
     assignment.
5. **Flag and toolchain probes.**
   - Pick 20 small leaf functions per binary and match them by hand under candidate flag sets.
   - Pin the flags in `config\<binary>.json`.
6. **Byte gate for DLLs.**
   - Extend `gate.py` to splice matched functions into copies of each retail image (DLL image bases
     0x10500000 / 0x10A00000 / 0x10B00000), then hash-compare.
   - Verify that the all-fallback build reproduces each hash before any matching counts.
7. **Project profile (your ruling needed).**
   - Dialect: MS C89 for `.c` units, VC8 C++ for `.cpp`/`.cxx`.
   - Naming style: from PDB names if they exist; otherwise from strings, starting from `style-defaults.md`.
   - Layout: [checked] because of `__LINE__`.
   - Parking marker: `// stop:`, as in avp3.

### Phase 1: pilot on cl.exe (~320 functions)

- It is small and uses all the infrastructure. It proves the LTCG harness, the
  gate and the bootstrap-compiler question end to end.
- The Rich header's single LTCG C++ product does not establish a single original translation unit. The
  public PDB retains seven nonempty compiler input modules with uniquely attributed public starts:
  `mpcl.obj` (62), `util_watson.obj` (8), `loadui.obj` (3), `dos.obj` (7), `util.obj` (36),
  `compile.obj` (13), and `clmain.obj` (71). `config.obj` has no public functions. Object attribution
  supports provisional disjoint lanes; original source filenames and extensions remain unresolved.
- The 267 cl public function entries have 265 unique starts because of aliases; public starts alone do not
  establish function sizes or the complete function denominator.
- Exit criterion: 100% matched under the rules.
- Then attempt a **full relink** of cl.exe from source that reproduces the retail hash. This proves the final
  milestone (ordering, `.rdata` and import layout) is achievable before scaling.

### Phase 2: c2.dll (the back end, ~6,000 functions, LTCG C)

- Lanes by source file, in this order:
  1. utility and leaf units: `hash.c`, `list.c`, `misc.c`, `error.c`, `get_err.c`, `getflags.c`, `sym.c`,
     `tuple.c`;
  2. IR and dataflow: `fg.c`, `dag.c`, `globdf.c`, `ssa_seh.c`;
  3. optimizers: `globopt.c`, `optimize.c`, `inline.c`, `pogo*.c`;
  4. x86 codegen: `cg.c`, `regasg.c`, `color.c`, `emit.cpp`, `lower*.c`, `fp*.c`, `coff*.c`;
  5. EH and debug info.
- Priority inside the lane: `pogoinline.c`, `pogoopt.c` and `pogocg.c` are reached early, because Phase 4
  depends on them.

### Phase 3: c1.dll (C front end, ~1,100 functions, LTCG C++)

- Its 19 units are a subset of c1xx's `P1\C` tree, so matching them here, without PGO noise, pre-builds 17 of
  c1xx's units.

### Phase 4: c1xx.dll (C++ front end, ~4,500 functions, PGO)

1. Port the 17 shared units from Phase 3. They will differ only in PGO-driven decisions.
2. Build the profile synthesizer from the Phase 2 knowledge of `pogo*.c`.
   - Start from a real training run: build a large C++ corpus with an instrumented c1xx rebuild.
   - Then adjust counts per function until the inline, layout and hot/cold decisions match retail.
3. Classify the remaining walls as "profile-driven" (fixed in the `.pgd`) versus "source-driven" (fixed in
   source). `wall-identifier` gets a new class for this.

### Phase 5: link.exe (~1,600+ functions, LTCG C++)

- Optional. It is a separate code base and shares no source names.

### Final milestone per binary

- A full rebuild from source that hashes identically to retail: compile, LTCG link, the same `/ORDER` or
  PGO-driven layout, resources, and the same import and delay-load tables.
- The splice gate measures progress until then. Only the full rebuild proves the build itself.

## 4. Operating rules for agents

Current session ruling (supersedes conflicting model/context/slot instructions below): reasoning workers use
Sol 6.1; keep agent contexts below 400k tokens and maintain twelve concurrent workers once matching begins.
Luna 6.1 was requested for mechanical readers but is not exposed by the available agent tool; model fallback
is pending user preference. The initial twelve lanes perform reasoning work using bounded evidence reads.
The project adapter now lives in `AGENTS.md`; twelve isolated worktree slots replace the original three-slot
proposal. Installed Ghidra 12.0.1 may be used with its version recorded because 12.1.3 was not located.

- **Large files** (Ghidra exports, disassembly dumps, PDB dumps, the ledger, `decompiled\` output) are read
  only by **Haiku 5.5 subagents at max effort** (`model: haiku`, `effort: max`).
  - Each agent's context stays **below 100k tokens**: slice inputs into chunks of ≤ ~50k tokens (≈ 200 KB of
    text), one agent per chunk.
  - Cap every command's output at ~60 lines, and have the agent return a summary of ≤ 600 words.
  - The orchestrator never opens such files directly.
- Matching workers follow the `orchestrator` skill:
  - disjoint lanes per source unit;
  - three fixed worktrees;
  - passes in order: plain matching, then helper recovery, then structural, then finishing;
  - a merge only through rebase, a clean rebuild, the gate and `rules`.
- Report two numbers per binary: **matched under the rules** (the headline) and **bytes matched**.
  `MATCH-PENDING` counts as open work.
- Legal hygiene: keep the repository private, and never commit Microsoft binaries, PDBs or decompiler output.
  The VS2005 EULA restricts reverse engineering beyond what local law permits.

## 5. Decisions needed from you

1. ~~Symbol-server query and download~~ Done 2026-10-15. The PDBs are in `symbols\` (symbol-store layout),
   and their GUIDs match the binaries. The info-stream age is binary age + 1, which is normal for stripped
   public PDBs.

   | PDB | object modules | public functions | public data |
   |---|---|---|---|
   | c2 | 216 | 5,008 | 4,701 |
   | c1xx | 177 | 8,547 | 8,244 |
   | c1 | 134 | 1,832 | 3,744 |
   | cl | 58 | 267 | 1,286 |
   | link | 137 | 2,046 | 2,671 |

   - The module lists are the real `.obj` list for each binary, so they **replace the string-based unit
     guesses in Phase 0.4**.
   - Public functions total ~17,700. File-static functions are not in publics, so the true total is higher.
     This supersedes the heuristic estimates in section 1. c1xx is roughly 2x the earlier guess.
2. Do you have VS2005 RTM (50727.42) for the bootstrap-compiler A/B?
3. A naming and layout style ruling, once Phase 0 shows whether public symbols exist.
4. Where the new repository should live (for example `E:\vc8-decomp`).

   Resolved by the current workspace: `E:\vc8-decomp`.
