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
| `python tools/link_trace.py icf-trace --obj a.obj b.obj --flags "/OPT:REF,ICF" --out DIR [--crc]` | links under the Windows debug API with breakpoints in `ICFAnalysis` and `ICFFold`; writes `DIR/icf.json` (every candidate: object or library member, module number, section, comparator keys, ICF edges with their target contribution; each sort's input and output arrays; each fold as keep/fold; the library search, `loads`) and checks the qsort model against every traced sort. `--crc` also breaks at every `SigForPbCb` call of `CrcEdges` and `CrcEdgesLoop` and logs what each contribution hashes (`crc_log`: site, bytes, seed) |
| `python tools/link_trace.py order --obj a.obj b.obj [x.lib] --icf-trace DIR/icf.json [--flags "..."] [--json]` | predicts each fold group's survivor for this link (see "ICF survivor"); the trace may come from any order of the same objects and libraries; without `--flags` and libraries the traced command line is reused with its object slots taking `--obj` in order |
| `python tools/link_trace.py search-trace --obj a.obj x.lib ... --flags "..." --out DIR` | links under the debug API with breakpoints in the library search (`IMAGE::ResolveExternalsInLibs` 0x4729E0, `LIB::Search` 0x48CB90, the return of its `LIB::FGetMember` call 0x48CC9A) and compares every `Search` call (library, each undefined symbol looked up in its dictionary, in order) with `search_libraries`; writes `DIR/search.json`; exit 1 on a difference |
| `python tools/link_trace.py search-check --model DIR/model.json` | simulates the library search of a traced link (`run` or `icf-trace` output) and compares its `Searching` and `Found`/`Loaded` sequences with the folder's `verbose.txt` |
| `python tools/link_trace.py crosscheck --obj a.obj ... --flags "..." --out DIR [--orders given,reversed,rotated]` | `icf-trace`s one link's objects in several orders (libraries keep their slots) and cross-predicts every order from every trace (the table of `experiment`); for real links |
| `python tools/link_trace.py experiment --set E1\|E2\|E4\|L1\|all --out DIR [--json]` | compiles the ICF fixtures (`tests/fixtures/link_trace/e1`, `e2`, `e4`, `l1`; `l1`'s `l?_*.cpp` become the static libraries `l?.lib` through lib.exe) with cl 14.00.50727.762 (`/O2 /Oy /Gy /GS /EHsc /GR- /MD /fp:fast /arch:SSE2`), `icf-trace --crc`s every listed command line and prints the validation table: per (order O, trace T) the fold groups (from the traced `ICFFold` calls, library members' and associative children's included), the qsort replays, the object candidates whose predicted sort key equals O's traced key, the library search (`Loaded` sequence and `Searching` sequence simulated == O's log), and whether every survivor of O is predicted from T; exit 1 on a miss |
| `python tools/link_trace.py experiment --set layout --out DIR` | reruns the layout experiments behind the tables below (E1 orders, E2 layout, E3 `/Gy-`; JSON) |

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
   child, then one per relocation (offset, type | storage class << 16 | 0x1000000 for a function
   symbol | 0x4000000 for an import). After each 8-byte edge comes its target: an import's name;
   for a contribution that is not an ICF candidate (`FICFCandidate` 0x429360: a writable section,
   a library's data, an import thunk, the linker's own module) its ICFId (module number, 1-based
   section number; (-1, -1) for a module flagged 0x800 at +0xAC); **nothing for an associative
   candidate** (selection 5 with a parent, +0x34/+0x3C: the `__ehhandler$` and `__ehfuncinfo$`
   of a function, from its parent and from each other); for any other candidate its own edge
   CRC, or nothing and the cycle flag when the target is on the stack or reaches a cycle. 0
   becomes 1. Weak externals (storage class 105, a vtable's `??_E` slot) resolve to their default.
   `0x453FD0` runs `CrcEdges` over every group, then three `CrcEdgesLoop` rounds (0x453C90) over
   the contributions on cycles: each starts from its own value in one slot (node+4 in rounds 3
   and 1, node+8 in round 2), hashes the values its cyclic candidate targets hold in that slot
   and writes the other slot; node+4 is then cleared.
   **Module numbers** are the objects' 1..N in command-line order, then each library member in
   load order (the `Loaded` lines of `/VERBOSE`), so every ICFId of a library target, and the
   edge CRCs of the library members, depend on the object order and the library order. The load
   order comes from `search_libraries` ("Library search" below), run on the traced command line
   (checked against its `Loaded` sequence) and on the new one; members are matched by library
   and archive offset. The older reordering of the traced sequence (`library_pulls`) remains the
   fallback when the libraries cannot be read.
   **Remix** (0x453E30): before sorting every group but the first, `ICFAnalysis` remixes each
   member's edge CRC with, for each edge in order (imports excluded), the ICFId of the target's
   survivor so far when that target is a candidate of an earlier group (`ICFCompareIcfGrp`
   0x453810: characteristics & 0x1E0, so code before data, then the group name). So the CRCs of
   `.text$x`, `.rdata` (vtables) and `.xdata$x` contributions carry the module numbers of their
   `.text` targets and the folds already made there.
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

5. **Dead copies.** Under `/OPT:REF` a contribution the reference pass discards (key 0 = 0) is
   sorted with the others but never folded: two identical dead copies both stay (avp3
   `audio_effects.obj`: `_sinf` and `?sin@@YAMM@Z`, 7 bytes, no relocations). The roots of the
   reachability model are the usual entry points and every `/INCLUDE` of the command line and the
   objects' directives (the avp3 code DLL roots each annotated function that way).

Because the qsort permutation depends on every candidate (CRT members included), `order
--icf-trace` keys the objects' candidates from the objects and the library members' candidates
from the trace's edges (`icf_static_keys`), renumbering the traced modules for the new link; a
trace of the same inputs in any order serves (the library members' edges, candidacy and keys are
taken from it). An object's relocation to a library member's external resolves to that member's
contribution (the member parsed from its library); to an unresolved or imported name it hashes
the object's own symbol name, with the traced target flags and this relocation's type. An
object COMDAT identical to a library member's (the trace folded them together) shares its
class. Objects are matched to the trace by full path when every traced path is one of them,
else by file name (refused when two objects share one). A cycle of identical callers (vtable
slots, recursion) is folded once (`icf_survivors` does not re-enter a pair on its stack).

Validation (`experiment --set all`: the trace of T predicts the fold groups and survivors of
every traced command line O, compared with O's `ICFFold` calls): E1 64/64 (8 orders x 8 traces),
E2 9/9 (C++ EH, a vtable cycle, `.text$aa`/`.text$zz`, strings and floats), E4 4/4 (call chains,
a static table, an import), L1 49/49 (7 command lines x 7 traces: five static libraries, objects
and libraries reordered, `/DEFAULTLIB` and `/NODEFAULTLIB`; a group of one object, two object
and three library-member copies whose survivor is `_same_a`, `_same_b` or `_same_m` depending on
the line, and a CRT group whose survivor is `__matherr` or `__setargv`); in every pair the
predicted sort key of every object candidate equals O's traced key and the qsort model replays
every traced sort. Real links (`crosscheck`, avp3 code-DLL links from
`tools/vc8_trace.py link` of the avp3 tools-vc8 worktree, `/DLL /NOENTRY /FORCE:UNRESOLVED
/OPT:REF /OPT:ICF`, `/INCLUDE` roots, msvcrt kernel32 user32 winmm ole32 oleaut32 and the
default uuid and OLDNAMES): `platform_audio_streams` + `audio_effects` in 2 orders, 4/4, 17 fold
groups, 183/183 keys; 17 units (`alien_moves_ai` ... `trigger_value`, the two audio units) in 3
orders, 9/9, 48 fold groups (vtables, `.text$x` unwind funclets, `.xdata$x` EH tables,
recursive `Map::ForEach`), 1020/1020 keys, no key left to the trace. Every traced link ran one
`ICFAnalysis` iteration and none had an edge flagged 0x2000000.

### Library search

Mechanism (disassembly of link.exe 8.00.50727.762; every rule confirmed by `search-trace`):

| rule | evidence |
|---|---|
| The undefined externals are one list: each name joins its end when first referenced (the command line's `/INCLUDE`s, then each input module in command-line order: its directives first, so an `/INCLUDE` directive precedes the module's own references, then its symbol table in order) and leaves it once defined | `crtexe.obj`'s `/INCLUDE:__forceCRTManifest` is looked up before crtexe's own references |
| `LIB::Search` walks that list once: each undefined name (a weak external of `IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY` excepted; the compiler's `??_E` vtable-slot weak externals are looked up) is looked up in the library's dictionary; a hit loads the member (its definitions leave the list, its new references join the end, so the same walk reaches them) and the walk goes on after the name that preceded the loaded one (from the head if that one was defined meanwhile) | 10,619 dictionary lookups of the 17-unit avp3 link, in order |
| A weak external in a loaded member defines a name that is still undefined (msvcrt.lib's `almap` members alias `??1type_info@@UAE@XZ`); a member with machine 0 (directives only) is an ordinary member | E2 |
| An import object (`IMPORT_OBJECT_HEADER`) defines `__imp_<name>` and, for code, `<name>` (its `jmp [__imp_<name>]` thunk) and references `__IMPORT_DESCRIPTOR_<dll>` | every `/MD` link |
| `IMAGE::ResolveExternalsInLibs` walks the libraries in command-line order (wherever they stand among the objects); past the last one it opens the next queued default library and searches it; when none is left it starts again from the first library, unless no member loaded so far added a new reference. It stops on reaching the last library whose load added a new reference, as soon as a library leaves nothing undefined, or after a walk in which nothing was added | L1: 32 to 42 `Search` calls per link, up to six passes |
| Default libraries queue in the order they are named (`/DEFAULTLIB` on the command line, then the directives of each module as it is read, library members included); `/NODEFAULTLIB:x` (anywhere) excludes x, `/NODEFAULTLIB` all; a queued library already in the link (`msvcrt.lib` given on the command line, `ld.lib` given explicitly under `/NODEFAULTLIB:ld`) is not opened again. A library given on the command line is searched even when `/NODEFAULTLIB` names it | L1 lines 5 to 7; avp3 links |
| Each `ResolveExternalsInLibs` call ends with `DefineImageBaseSymbol` (`___ImageBase` is defined there); later calls search the symbols the linker adds itself (`__load_config_used`), shown in `/VERBOSE` as `Found` without `Referenced in` | L1, avp3 (`Searching libraries` twice) |

Validation: `search-trace` on L1 (two lines, 36 and 38 `Search` calls, 217 and 172 lookups) and
on the 17-unit avp3 link (20 calls, 10,619 lookups, 51 loads): equal. `search-check` on every
traced link of E1, E2, E4, L1 (68 to 81 loads each) and the two avp3 links (32 and 51 loads):
the `Loaded` and `Searching` sequences equal.

## Limits

- ICF survivor prediction needs an `icf-trace` of the same inputs (the library members'
  candidacy, edges and keys; their identity with the objects' COMDATs comes from its folds).
  Library members are parsed for the search and for their definitions, not keyed from their own
  bytes. Edges flagged 0x2000000 (hashed through 0x455E90) are not modelled and no traced link
  has one (such a contribution would fall back to its traced key); only iteration 0 of
  `ICFAnalysis` is modelled and every traced link folded everything there. `icf-trace` and
  `search-trace` breakpoints are link.exe 8.00.50727.762 addresses (`LINK_SHA256`).
- The library search model reads `/DEFAULTLIB`, `/NODEFAULTLIB` and `/INCLUDE`; other directives
  that create references (`/EXPORT`, `/ALTERNATENAME`, `/ENTRY` of another name) and incremental
  linking are not modelled. The symbols the linker references itself (the entry point
  `_mainCRTStartup`, `__load_config_used`) are taken from the traced log (`Found` without
  `Referenced in`): the entry point joins the list after every input's references, the others
  start the later rounds. A prediction therefore needs a trace with the same entry point.
- Layout: `run`'s `order rule check` (object order, section order, groups) holds on every fixture
  link but not on the avp3 code-DLL links: `/VERBOSE` names a folded static COMDAT (`.text$x`
  unwind funclets) only by its section, so `build_model` cannot tell which copy was replaced and
  keeps several at one address; the 17-unit link also places a run of template COMDATs
  (`Map<...>::FreeNodes`, `ForEach`) differently from the model (first difference at the 257th
  code contribution). Both are open; the fold groups themselves come right from `icf-trace`.
- Import thunks (`jmp [__imp_x]` for a call to an import declared without `dllimport`) are the
  import member's code and are placed with it in load order (`__amsg_exit` between CRT objects in
  E1); their layout is not predicted beyond that order.
- `order`'s `/OPT:REF` is a reachability approximation over the traced objects (roots `_main` and
  the like, `/INCLUDE`s, non-COMDAT sections, weak externals followed to their default); library
  members are not walked, so a COMDAT reached only from a library is reported unreachable.
- Sizes and padding are exact only for the traced objects' sections; a library contribution is
  bounded by the next map public. `run`'s model matches objects to map and verbose lines by file
  name: two inputs with one file name are ambiguous there.
- `/GL` objects are not COFF and are refused; trace after LTCG with the code-generation output instead.
- No vc8-decomp `cl` pilot link was traced: the validation of real links is the avp3 code DLL's.
