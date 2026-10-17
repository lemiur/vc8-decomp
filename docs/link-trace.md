# Link trace

`tools/link_trace.py` traces a link by link 8.00.50727.762 (VC8 SP1) from its input objects to the
output image, so that a decomp project can predict and explain where each function lands, which copy of
a COMDAT survives and why a byte or a referent is what it is. Python stdlib only.

## Commands

| command | what it does |
|---|---|
| `python tools/link_trace.py run --obj a.obj b.obj --flags "/OPT:REF,ICF /ENTRY:..." --out DIR` | links with the pinned toolchain (`config/toolchains.json`, `sp1`), adding `/VERBOSE /MAP /MAPINFO:EXPORTS /OUT`, writes `DIR/model.json`, `DIR/verbose.txt`, `DIR/trace.map`, `DIR/trace.exe`, and checks the layout rules below against the image (`order rule check`) |
| `python tools/link_trace.py explain --model DIR/model.json --rva 0x1012` | the contribution covering an RVA: object, COMDAT section, status and reason, padding before it, fold group, the symbol inside a multi-function section, and every relocation resolved to its target RVA and name |
| `python tools/link_trace.py explain --model DIR/model.json --symbol ?f@@YAHH@Z` | the same for a symbol (every copy: kept, folded, duplicate, removed) |
| `python tools/link_trace.py order --obj a.obj b.obj [--model M] [--root _main] [--json]` | predicts the code layout for an object order without running link: offset, padding, size, section; without `--model`, `/OPT:REF` is approximated by reachability from the roots and identical COMDATs are flagged as `ICF candidates` |
| `python tools/link_trace.py icf-trace --obj a.obj b.obj --flags "/OPT:REF,ICF" --out DIR` | links under the Windows debug API with breakpoints in `ICFAnalysis` and `ICFFold`; writes `DIR/icf.json` (every candidate: object or library member, section, comparator keys, ICF edges; each sort's input and output arrays; each fold as keep/fold) and checks the qsort model against every traced sort |
| `python tools/link_trace.py order --obj a.obj b.obj --icf-trace DIR/icf.json [--json]` | predicts each fold group's survivor for this object order (see "ICF survivor"); the trace may come from any order of the same objects and libraries |
| `python tools/link_trace.py experiment --out DIR` | compiles the test objects with cl 14.00.50727.762 (`/O2 /Oy /Gy /GS /EHsc /GR- /MD /fp:fast /arch:SSE2`) and reruns the experiments behind the tables below (JSON) |

Model fields (`model.json`): `contributions[]` (one per non-debug section of each traced object:
`obj`, `section_index`, `section`, `symbol`, `symbols[]` with offsets, `selection`, `checksum`, `size`,
`align`, `status` = `kept`/`folded`/`removed`/`duplicate`/`absent`/`unnamed`, `reason`, `rva`,
`output_section`, `padding_before`, `padding_bytes`, `fold_group`, `associated_with`, `relocs[]`),
`fold_groups[]` (survivor and members, from `/VERBOSE`), `discarded[]`, `map_groups[]` (the map's
`$`-group table with RVAs), `publics[]`, `image`, `order_check`.

Link 8.00 switches used, confirmed in `link /?`: `/VERBOSE[:{ICF|LIB|REF|SAFESEH}]`, `/MAP[:file]`,
`/MAPINFO:{EXPORTS}` (8.00 has no `MAPINFO:LINES`/`FIXUPS`), `/OPT:{ICF[=iterations]|NOICF|NOREF|NOWIN98|REF|WIN98}`,
`/ORDER:@file`, `/MERGE`, `/SECTION`, `/ALIGN`. `/VERBOSE` alone prints both the `/OPT:REF` discards
(`Discarded X from obj`) and the ICF groups (`Selected symbol:` / `Replaced symbol(s):`).

## Rules established

Evidence: `experiment` (E1: three objects with four fold groups each, all six object orders; E2: two
objects sharing inline functions, a vtable, strings and floats, `#pragma code_seg(".text$aa"/".text$zz")`,
a `try`/`catch`, three orders; E3: one object built `/Gy-`), plus a call-chain probe (E4: `leaf1/2`,
`mid1/2`, `top1/2`, each `noinline`, and two identical `extern const int[4]` tables). Every run's
`order_check` reproduced the image's order of the traced code exactly.

### Layout

| rule | evidence |
|---|---|
| Output sections are built from groups: a section `.text$xx` joins `.text`; within one output section the groups sort by their full name, the plain name first (`.text`, `.text$aa`, `.text$x`, `.text$zz`) | E2 map groups; `.text$aa` follows all of `.text`, including the CRT's |
| Within a group, contributions follow the command-line object order (libraries after the objects, in load order), then each object's **section-table order** | E1/E2, all orders; `order_check` true in 9 of 9 links |
| The section-table order is the compiler's emission order, usually definition order but not always: `a_make` (which expands an inline constructor) was emitted after `a_last`, defined later | E2 `a.obj` sections 36, 38 |
| A COMDAT removed by `/OPT:REF`, replaced by ICF, or a losing duplicate leaves no gap; the survivor stays in its own object's slot | E1, E2 |
| Each contribution starts at its section alignment; VC8 `/O2` code COMDATs are `ALIGN_16BYTES`, string, float and vtable COMDATs `ALIGN_4BYTES`, `__real@...` doubles 8 | section headers; `padding_before` |
| Padding between code contributions is `0xCC` (int3); in `.rdata`/`.xdata` it is `0x00` | `padding_bytes` in every run |
| Without `/Gy` the object's code is one non-COMDAT `.text` section: kept whole (an unreferenced function stays), its functions 16-aligned by the compiler with `0xCC` already in the object | E3: `ng_unused` kept at `+0x10` |
| `.rdata` output order (E2, `/MD` exe): `.idata$5` (IAT), `.CRT$X*`, `.rdata`, `.rdata$r`, `.rdata$sxdata`, `.rtc$*`, `.xdata$x`, `.idata$2/3/4/6`, `.edata`; `.data` then `.bss` | E2 map groups |
| Associative COMDATs (`.text$x` `__ehhandler$`, `.xdata$x` `__ehfuncinfo$`) follow their parent: kept with it, placed in their own group in object order | E2 |

### COMDAT selection and pools

| rule | evidence |
|---|---|
| Same-name COMDATs of selection `any` (inline and virtual functions, `??_G` deleting destructors, `??_7` vtables, `??_C@` string literals, `__real@` float constants, EH `__TI`/`__CT` records): the copy of the **first object on the command line** that defines it is kept, at that object's position; the others are dropped | E2: `shared_inline`, `Get`, `??_G`, `??_7`, `pool both`, `__real@3f400000` move with the first object in all three orders |
| String literals and float constants are therefore merged by name (the name encodes the contents), not by ICF, and laid out in the first definer's `.rdata` slot in its section order | E1, E2 |
| Identical data in a non-COMDAT `.rdata` section is never folded (VC8 has no `/Gw`) | E4: `tbl1`, `tbl2` both kept |
| Relocations resolve to the surviving copy: a call to a replaced function lands on the survivor's address, a reference to a dropped duplicate on the kept copy | `explain` reloc lines; E1 `str_a`/`str_b` |

### /OPT:ICF

| rule | evidence |
|---|---|
| Candidates: COMDATs with identical bytes, size, section flags and identical ordered relocation targets (string literals with one name count as identical) | E1, E2 (`a_str`/`b_str` fold through one `??_C@`) |
| Folding is transitive along calls: callers that differ only by calling functions that fold, fold too, also with `ICF=1` | E4: `leaf`, `mid`, `top` pairs fold under `ICF`, `ICF=1`, `ICF=2` |
| The map lists every member's name at the survivor's address; `/VERBOSE` names the survivor (`Selected symbol`) | E1 |
| The survivor is not the first or last object, nor the smallest or largest name: it changes with object order (E1: first object 9 times, second 6, third 9 over 24 groups) | E1 |

### ICF survivor

Mechanism (link.pdb publics, disassembly of link.exe 8.00.50727.762, confirmed by `icf-trace`):

1. **Array.** `FIncludeComdat` calls `ICFAddPCON` for each included COMDAT that passes
   `CON::FICFCandidate` (non-debug, non-writable, size > 0): objects in command-line order, each in
   section-table order (a same-name `any` COMDAT only from its first definer, an associative one
   with its parent), then the library members in pull order. One array per output group (full
   section name: `.text`, `.text$x`, `.rdata`, `.xdata$x`...); groups are walked in
   `ICFCompareIcfGrp` order.
2. **Keys** (`ICFComparePcon` 0x4538A0, CON/node fields in `IcfRecorder`): under `/OPT:REF` live
   contributions (CON flag 0x2000) first; then not-on-a-cycle first; then ascending relocation
   count, size, edge CRC, COMDAT checksum (the aux-record checksum of the raw bytes). Identical
   copies compare 0. The edge CRC (`CrcEdges` 0x4539F0) is mspdb80 `SigForPbCb` (reflected CRC-32,
   seed 0xFFFFFFFF, no final complement) over the ICF edges: one (0, 0xFFFF) edge per associative
   child, then per relocation (offset, type | storage class << 16 | 0x1000000 for a function
   symbol | 0x4000000 for an import), followed by the target's edge CRC when it is a candidate,
   its ICFId (module number = 1-based input position, section number) when it is not, or an
   import's name; associative targets add nothing. A contribution that reaches a cycle gets the
   cycle byte and three `CrcEdgesLoop` rounds over its cyclic targets.
3. **Sort.** MSVCR80 `qsort` (VC8 `crt/src/qsort.c`: median of three, partition element followed,
   equal elements skipped, smaller side first, `shortsort` max-to-end selection sort for <= 8
   elements; not stable). `ms_qsort` reproduces link's output array in every traced sort (E1 x8
   orders, E2 x3, E4 x2: 38 of 38).
4. **Walk** (`ICFLocateICs` 0x455730): each unfolded element absorbs every later element with the
   same checksum that `FICFIdenticalCONs` finds identical; `FFoldCONsEx` first folds the pair's
   differing dependencies the same way (the keeper's callee keeps). So **the survivor is the
   member at the lowest position of the sorted array, unless the fold of a caller pair reached it
   first, in which case it is the callee of the surviving caller** (E4: `top2` sorts before
   `top1` and drags `mid2` over `mid1`, though `mid1` sorts first).

Because the qsort permutation depends on every candidate (CRT members included) and the keys of
contributions that call library code depend on link's module numbering, `order --icf-trace`
keys the objects' own candidates from the objects (`icf_static_keys`), and takes the library
members' candidates and the edges into library code from a trace of the same inputs in any order.

Validation (cross-prediction: the trace of order T predicts the survivors of every traced order O,
compared with O's `/VERBOSE`): E1 64/64 (8 orders x 4 groups each), E4 4/4 (call chains, a static
table, an import), E2 4/9: the misses are `a_make`/`b_make` (cycle through the vtable) and
`a_str`/`b_str` when the orders differ, because the `.text$x`/`.xdata$x` EH contributions
(`__ehhandler$`, `__ehfuncinfo$`, both associative) do not yet get link's edge CRC: the edge from
the handler to its associative funcinfo hashes something the model does not reproduce, and a
wrong key there moves other elements in the qsort. Self-prediction (T = O) is exact everywhere.

## Limits

- ICF survivor prediction needs an `icf-trace` of the same inputs (library candidates and edges into
  library code); edges from associative EH COMDATs (`__ehhandler$` to `__ehfuncinfo$`) are not
  reproduced, so a unit with C++ EH or with vtable cycles can be mispredicted across orders; only
  iteration 0 of `ICFAnalysis` is modelled (every traced link folded everything there). `icf-trace`
  breakpoints are link.exe 8.00.50727.762 addresses (`LINK_SHA256`).
- `order`'s `/OPT:REF` is a reachability approximation over the traced objects (roots `_main` and the like,
  non-COMDAT sections, weak externals followed to their default); library members are not parsed, so a
  COMDAT reached only from a library is reported unreachable.
- Sizes and padding are exact only for the traced objects' sections; a library contribution is bounded by
  the next map public. Objects are matched to map and verbose lines by file name: two inputs with one file
  name are ambiguous.
- `/GL` objects are not COFF and are refused; trace after LTCG with the code-generation output instead.
- Import thunks (`jmp [__imp_x]` for a call to an import declared without `dllimport`) are placed with
  their import-library member in library load order (`__amsg_exit` between CRT objects in E1); not modelled.
