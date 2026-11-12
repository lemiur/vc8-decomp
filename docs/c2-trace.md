# c2 decision tracer

`tools/c2_trace.py` runs the pinned SP1 `cl.exe` on one source file under the Windows debug API and logs
selected `c2.dll` routines as they run. It makes register-allocation decisions (and, coarsely, any other public
c2 routine) visible, to explain why two spellings of a function compile differently.

```powershell
python tools/c2_trace.py --source X.cpp --flags "/O2 /GS- /arch:SSE2 /fp:fast" `
    --break OrderGlobregs,ChoosePhysReg [--function Gui_FinishDraw] [--include DIR] `
    [--dump "[[esp+4]]:16"] --out build/trace/x.jsonl
```

Further options: `--break-module REGEX` adds every function public of the matching c2 object modules
(`.` = all ~9000; 50k calls and 15 s for one small function with `--entry-only`), `--exclude` names to leave
out, `--entry-only` (no return breakpoints, no `ret`), `--symtab NAMES` (those entry events carry the c2 symbol
table) and `--tuples NAMES` (they carry the function's instruction tuples, `opcode dsts = srcs`).
`--preset NAME` (repeatable) adds a named set of breaks and tuple points: `color` (OrderGlobregs,
ChoosePhysReg), `immed` (the 64-cycle routines), `reload` (Spill, RegSimpleAssignBody, RegAssign, LoFinalLower,
SsaPeepsMd, tuples at each), `emit` (CgBottomUpOrder, ReadFunction, EmitFunction; module-level, so without
`--function`), `stack` (AddStackElement, ColorStackElements, QSortColors: stack packing, see "Stack
packing"), `globreg` (Spillcosts, SpillcostsFold, OrderGlobregs, ChoosePhysReg: the colouring priority's
terms, see "Spillcosts"), `reguse` (MscRecordInterProcRegInfo, LoAddCallScratchRegs: the
interprocedural register-use summary, see c2-inline-trace.md "Register use at calls"), `flexparams` (MdmFlexParams, MdmAllocateFlexParam,
MdmAllocateXmmFlexParam: each custom-convention parameter register, the callee's entry load that gave it,
and the parameter loads left on the stack, see c2-inline-trace.md "Parameter registers"). The default `--break ChoosePhysReg` applies only when neither `--break` nor a preset
is given. `--link-rsp LINK.rsp [--linker link.exe]` instead of `--source` traces link.exe on a /LTCG link's
response file: its link-time code generation loads the same c2.dll, so every break and preset applies to the
functions the link compiles (`--function` as for cl.exe). A break name may also be an internal point (`INTERNAL_POINTS`: a public plus an offset, its
instruction bytes checked against `c2.dll` before the run); internal points are entry-only.

`python tools/c2_trace.py emit-order --source X.cpp [--flags ...] [--include DIR] --out R.json [--all-sections]
[--no-trace]` compiles the unit with `/Bk` (the IL is kept in `R.work/il_*`), predicts the compile order and
the code and vtable COMDATs from the IL alone, traces `CgBottomUpOrder` and `ReadFunction` over the whole
unit, reads the object's section table and prints the compile order with each function's IL position, the
callees that held it back and the vtables it emits (see "Function emission order"). `R.json` holds the gl
and traced IL orders, the traced and modelled bottom-up orders, the predicted and traced compile orders, the
predicted and obj COMDATs, the vtable slots, the entries never needed, and the sections; the trace goes to
`R.jsonl`. It also predicts the whole section table (`full_predicted` against `full_obj`, "The whole
section table"; `--all-sections` prints both side by side). `--no-trace` skips the debugger and compares the
prediction with the obj only. Exit 0 when the prediction equals the obj's code and vtable COMDATs and its
whole section table (and, traced, the model reproduces `CgBottomUpOrder`,
the code COMDATs follow `ReadFunction` and the prediction equals it), 1 otherwise.

`python tools/c2_trace.py diff A.jsonl B.jsonl [--renumber LOW:HIGH:DELTA] [--all] [--ordinals]` aligns two
traces record by record and prints the first divergent record (or `--all` of them) and any change in the call
sequence. Pointer-like dwords compare as `ptr` (`--ordinals`: by first-seen order instead); `--renumber`
subtracts DELTA from the right trace's values in [LOW, HIGH], so front-end numbers shifted by padding
declarations compare equal. Exit 0 when identical, 1 otherwise.

Run it from PowerShell or cmd. Git Bash rewrites `/O2` into a path; there, write flags as `-O2 -GS-` (cl accepts
both). `--function` matches a substring of the decorated name c2 is compiling (`[[_Entry]+4]`). cl.exe runs
with `/nologo /c` in `<out>.work/` (object, `/FAs` listings and `cl-output.log` land there). Exit status: 0, 1
for a tracer error, 3 when cl.exe failed.

## How it works

`cl.exe` loads `c1xx.dll` and `c2.dll` into its own process. On the `c2.dll` load event the tracer resolves each
`--break` name through `symbols.extract` on the public `c2.pdb` (identity-checked; cached in
`build/c2-trace/c2-publics.json`), adds the load slide and writes `int3` at the entry. On a hit it reads the WOW64
context, logs the entry, plants a temporary `int3` at the return address, restores the byte, single-steps and
re-arms. The return hit (matched by thread and entry ESP, so recursion is fine) completes the same event.
Names may be plain (`ChoosePhysReg`) or decorated (`@ChoosePhysReg@12`). c2 is built with LTCG: most internal
routines take arguments in private registers (ChoosePhysReg takes one in EAX), so `@N` does not tell where
the arguments are; the decoders below are read from the disassembly.

## Output

One JSON object per call, in entry order: `seq`, `break` (plain name), `function` (decorated name being
compiled), `tid`, `depth` (pending traced calls on that thread), the decoder's fields, and `dump` /
`dump_strings` for each `--dump EXPR:COUNT` (COUNT dwords at EXPR; EXPR is a sum of numbers, registers,
c2 public names and `[...]` dereferences, evaluated at entry; `dump_strings` lists dwords that point to ASCII).

Generic decoder (any other routine): `eax`, `ecx`, `edx`, `stack` (four dwords above the return address) at
entry, `ret` (EAX) at return. The inliner predicates (`InlineeIsTooBig`, `ShouldInlineCallTuple`,
`ShouldInlineInlinee`, `InlBadCandidate`, `InlCallTupleIsCandidate`, `InlBenefit`, `ConsiderCandidate`,
`InlCallGraphDecision`) log `ret` signed; their arguments are not decoded yet.

### `OrderGlobregs` (color.obj)

Builds `_SortedGlobregs`, the order in which `Color` assigns registers to one register class. At return the
tracer walks it (`next` at +0x14): `order` = list of globregs with `globreg`, `symnum`, `priority`, `lastref`,
`refs`. `InsertInList` sorts by `priority` descending, then `lastref` descending; on a full tie the globreg
inserted later (higher `_GlobregHash` bucket, i.e. higher globreg number below 1024) goes first.

### `ChoosePhysReg` (color.obj)

Called by `Color` for each globreg in that order. Entry: `class`, `globreg`, `symnum`, `priority`, `lastref`,
`refs`, `prefs` (the globreg's preference list: other globreg and weight), `allowed` (physical register numbers),
`interferes` (globreg numbers). Return: `chosen` (register name from `_RegName`), `candidates` (allowed
registers in `_RegOrders[class]` order with their `_ChoosePhysReg_weights`), `tie` when several share the
lowest weight. The routine adds interfering globregs' preference weights and 100 x cost (+0x40) of interfering
globregs restricted to one register, subtracts the globreg's own preference weights, and keeps the first
register in `_RegOrders` order with the strictly lowest weight: on a tie the earlier register (esi before edi
before ebx before ebp for class 0) wins, so the coloring order decides.

### `Spillcosts` (color.obj): the priority

`Spillcosts([esp+4]=function, [esp+8]=class, [esp+0xC]=bv)`, `ret 0xC`; `Color` calls it per class before
`SpillObvious` and `OrderGlobregs` (0x10B0D155), and again in the split loop (0x10B0D2AB). Entry and exit:
`before` / `after`, every globreg of the class (`_GlobregHash`, 1024 buckets, chain +0x30; class
`_RegClass[word [sym+0x10] >> 12]`, as `OrderGlobregs`) with the `OrderGlobregs` fields, `pending` (+5 bit 0:
not yet in `_SortedGlobregs`; only those accumulate) and `assigned` (+0x10).

The block weight w is 1 without `_Speed`, `count x 10000 / _PogoMaxCount + 1` under PGO (`_PogoFlag` 2,
block+0x190), else `1 << byte [block+0x17E]`, 2^(loop depth) (0x10B10659..0x10B106EC). Per reference (tuple
+9 bit 0, leaf kind 1, the class's globreg of kind 2, unassigned, +5 bit 0) the cost c is added to +0x18
(the block's C), +0x24 (refs) is incremented and c x w added to +0x40 (cost):

- a source leaf: `CmdCanDirectSubstitute` ? `CmdSubCost` : `CmdLoadCost` (0x10B10966); under `_Speed`
  `CmdLoadCost` is 2 for a variable and 1 for an immediate (kind 0xD), `CmdSubCost` 2 for a variable;
- a destination leaf: 2 under `_Speed` when not substitutable (0x10B10FA1);
- opcode 0x296 (exit copy) and 0x295 (enter copy) subtract their cost x w from +0x40 only.

`SpillcostsFold` (internal point Spillcosts+0x1064 = 0x10B11484, `imul edi, ebp`), once per block, entry
only: `n` = EDI, N_b (the globregs referenced in the block plus the bv of already ordered ones), `w` = EBP,
`block` (position from `[[_Function]+8]`), `depth` (byte +0x17E), `loop` (+0x16C), `pgo`, `dead` (ECX: the
globregs whose last use is in the block) and `live` (EBX: those live through it), both linked by +0x14, each
`globreg`, `c` (+0x18) and `assigned`, `live` also `referenced` (+6 bit 0x10); and the block's own tuples
(from its head +0x1C to its end +0x20, linked by +0): `tuples` (instructions), `enter` and `exit` (those with
opcode 0x295, 0x296) and `syms` (the front-end symbols their leaves name, effective addresses opened, as
`name$fe` in first-use order: an inlined body's locals keep their callee's descriptors, which tells inlined
code from the function's own). The code that follows adds
c x N_b x w_b to +0xC of each dead unassigned entry and each referenced live entry, and subtracts N_b x w_b
(w_b under PGO) from each live unreferenced one, so at `/O2`:

    priority = sum over blocks b of N_b x 2^depth_b x (C_b, or -1 when live through b unreferenced)

There is no division by span or degree and no callee-save cost. `BetterToDefer` can later set a globreg's
priority to its components' minimum minus 1 and re-insert it, and `InsertByBenefit` places split globregs, so
`ChoosePhysReg`'s order can differ from the `OrderGlobregs` snapshot.

### Symbols, immediates, globregs, tuples

- `SymAlloc` (exit `symnum`) / `SymFree` (entry `symnum`, `name`, `fe`): per-kind LIFO free lists; a freed
  symbol keeps its number, so tmpreg numbers are reused newest-freed first.
- `GrgImmedTupleHash` (`leaf_kind`, `value` or `name`/`fe`, exit `bucket`): the `_ImmedHashTable` bucket.
- `GrgNewGlobreg` (entry: the symbol; exit `globreg`) and `Spill` (the globreg, its symbol, `base`/`offset`
  for a field).
- `--symtab`: `symnum`, `kind`, and `name` + `fe` (front-end `$N`) or `base` + `offset` (an equivalence:
  a field of a base symbol).
- `RegAssign` (regasg.obj; see "Reloads and local register assignment"): entry `tmpreg`, `opcode`, `tuple`,
  `pref` (`[sym+0x30]`), `int_regs` (`_IntPhysRegs`), `next` (the list from `_NextIntPos`), `busy` (`_RegMap`:
  register -> symbol), `conflicts` (registers whose `_BvConflicts` set holds the tmpreg); exit `chosen`,
  `pref_after`.
- `CgBuildCallGraph`, `CgBottomUpOrder` (cg.obj): `entries` (`_Eentry_list` at entry: name, flags +0x50,
  `node`, `init`, `callees`, `recursive` arcs) and `entries_after` (the list at return).
- `--tuples`: leaves print as `#n` (constant), `&name$fe` (address), `name$fe` / `sN` (symbol, tmpreg; `sN/eax`
  once the local allocator gave the leaf a register: leaf+0x1C, a `_RegSym` entry of the operand's width),
  `[a+b+disp]` (effective address), register names, `kK:...` (other kinds).

### Fields

| field | source (pinned c2.dll 14.00.50727.762) |
|---|---|
| `globreg` | Globreg+0x1C, `_NextGlobregNum` at creation (`GrgNewGlobreg`) |
| `sym`, `symnum` | Globreg+0 (c2 symbol), symbol+0x1C: c2's own symbol number, not c1xx's `$N` listing number |
| `priority` | Globreg+0x0C, the sort key (spill benefit) `InsertInList` compares first |
| `lastref` | Globreg+0x44: `RewriteAsGlobregs` stores its running tuple ordinal at each rewritten def (0x10B5B099; one counter, blocks in list order, tuples backward within a block), so the earliest def in the last block that defines the value |
| `refs` | Globreg+0x24: references counted by `Spillcosts` |
| `cost` | Globreg+0x40: the weighted spill cost (`Spillcosts`: each reference's cost x block weight, less the enter/exit copies) |
| `kind`, `name`, `fe` | the globreg's c2 symbol: kind byte +4 (3 temporary, 4 local, 5 parameter, 0xD immediate), front-end name and number |
| `allowed` | sparse bit vector at Globreg+0x20 (header -> nodes `{base, lo32, hi32, next}`) |
| `chosen` | Globreg+0x10 = `&_RegSym[reg]` (stride 0x60) |
| symbol | `_BESymTab` slot: `[[_BESymTab]+4][n >> 5] + 0xC + (n & 31) * 0x60` (`SymKeyToSym`); +0 front-end descriptor, +4 kind, +8 base symbol, +0x1C number, +0x24 offset in the base |
| `fe` | descriptor+0x28: the front-end number c2 prints in listings (`_rect$2594`); descriptor+4 is the name |
| tuple | +0 next, +4 opcode, +9 bit 0 instruction, +0x28 source leaves, +0x2C destination leaves; leaf +8 kind, +0x18 symbol or constant |

## Example

`Walk` keeps two list cursors live across calls (`first`, `second`). Swapping the two declarations changes
nothing (same trace, same code: c2 numbers symbols by use, not declaration). Swapping the two statements
`first = first->next; second = second->next;` flips ESI/EDI, and the trace shows why:

```
before: OrderGlobregs class=0: g3(sym2,p51,l13) g4(sym3,p51,l12) g5(sym84,p19,l11) g1(sym1,p10,l3)
        g3(sym2) -> esi  [esi:0 edi:0 ebx:0 ebp:0] TIE(esi,edi,ebx,ebp) prio=51 lastref=13
after:  OrderGlobregs class=0: g4(sym3,p51,l13) g3(sym2,p51,l12) g5(sym84,p19,l11) g1(sym1,p10,l3)
        g4(sym3) -> esi  [esi:0 edi:0 ebx:0 ebp:0] TIE(esi,edi,ebx,ebp) prio=51 lastref=13
```

Equal priority, all weights zero: the later last reference is colored first and takes ESI.

## The 64-cycle

Case: `Gui_FinishDraw` (the avp3 note "Symbol-number noise"), `int x = (rect.left + rect.right) / 2` after two
member calls on globals, `g_renderStates.SetAlphaTest(false)` and `g_mouse.ReadDevice(&dx, &dy)`. With N
`extern int` declarations prepended, the add is `mov eax, left / add eax, right` for N = 0..8 and 62..69 and
`mov eax, right / add eax, left` for N = 9..61.

**Rule.** In `Globregs`, `CmdIdentifyImmedCandidates` enregisters immediates (integer constants, addresses of
globals) as globregs in tuple order (`GrgRewriteImmedAsReg`: constants 0 and 10 get g1, g2,
`&g_renderStates` g3, `&g_mouse` g4), each entered in `_ImmedHashTable`, 64 chains, new entries at the head.
The bucket is `GrgImmedTupleHash`: constant -> value & 0x3F; address of a symbol -> its **front-end number**
(`$N`, descriptor+0x28) **& 0x3F**; tmpreg -> c2 number & 0x3F. `CreateGlobregs` then walks the buckets
0..63, each chain head first, and frees (`ColRemoveGlobregFromHashTable` -> `_FreeGlobs`, LIFO through +0x30,
the number kept at +0x1C) every immediate globreg not worth a register (here both addresses; the test is
`[[sym+0x34]+0x14] < 1`). Next it creates the real candidates in c2 symbol-number order (`rect.left` s5, `rect.right` s7, `top`
s10, `bottom` s12), and `GrgNewGlobreg` pops `_FreeGlobs` first: **the first candidate takes the number of the
immediate freed last**, i.e. of the one in the highest bucket (the earlier-inserted one on a bucket tie).
`Color` spills the four field globregs in globreg-number order (`Spill`); the reload tmpregs come from the
tmpreg free list in that order, and the field whose globreg number is lower ends up as the add's destination,
loaded last into EAX.

So `left` is in EAX iff `fe(&g_mouse) & 63 < fe(&g_renderStates) & 63`, or the two are equal (same bucket,
`g_mouse` inserted later is freed first). Both numbers shift together with padding; their order mod 64 flips
when they straddle a multiple of 64. In g8 `g_renderStates` is $2559 (bucket 63) and `g_mouse` $2570 (10); in
g9 $2560 (0) and $2571 (11). Prediction, checked: inserting K externs between the two declarations in g9
leaves `right` in EAX for K = 0, 51, 52, 54, 55 and puts `left` there only for K = 53 (both in bucket 0).

**Trace.** All 9000 publics, entry only, g8 against g9: the same 50,653 calls in the same order; with
`--renumber 2540:2700:1` the first real divergence is `GrgImmedTupleHash` returning 63 instead of 0. The
decoded run (`--break GrgImmedTupleHash,CreateGlobregs,GrgNewGlobreg,Spill`):

```
g8: &g_renderStates$2559 bucket 63 -> g3, &g_mouse$2570 bucket 10 -> g4;  s5(+0) -> g3, s7(+8) -> g4
    Spill g3 s5, g4 s7          -> mov eax, rect.left / add eax, ecx(rect.right)
g9: &g_renderStates$2560 bucket 0  -> g3, &g_mouse$2571 bucket 11 -> g4;  s5(+0) -> g4, s7(+8) -> g3
    Spill g3 s7, g4 s5          -> mov eax, rect.right / add eax, ecx(rect.left)
```

`--tuples` at each phase entry shows the tuple lists identical through `SpillObvious` and different from the
first `Spill` on (`s139 = [s7+s5]` becomes `[s7+s162]` in g8, `[s162+s5]` in g9). Before, the coloring
(`OrderGlobregs`, `ChoosePhysReg`) and `OptHashNode` looked identical because they see the same globreg
numbers; only which symbol holds which number differs.

**Levers.** The decision depends only on the front-end numbers of the globals whose addresses are dropped
immediates (and constants' values), not on the local's number: the `_rect$N` correlation is a side effect of
both shifting with any declaration above. Source-level, what matters is how many front-end symbols are created
between and before those globals' first declarations.

## Reloads and local register assignment

Case: the `Gui_FinishDraw` repro of "The 64-cycle" (g8: `left` ends in EAX; g9: `right`). Traced with
`--preset reload` and `--tuples` at every later phase: the tuple lists of g8 and g9 differ only in which field
each reload reads, from the first `Spill` to `Encode`.

1. **Reload placement.** `Spill` (one call per globreg, in globreg-number order) rewrites each use of the
   spilled field as a new tmpreg loaded immediately before the using tuple (`LoLdsrcTmpreg`), after any reload
   already inserted there. The operand keeps its position in the tuple. So before the add the reloads stand in
   spill order, the lower globreg's first: g8 `s162 = [rect.left]; s161 = [rect.right]; s139 = [s161+s162]`,
   g9 `s162 = [rect.right]; s161 = [rect.left]; s139 = [s162+s161]`. Reload tmpregs come from the tmpreg free
   list newest-freed first (s162, s161, then s160, s137), which decides their numbers but not their registers.
2. **Local assignment.** `RegSimpleAssignBody` walks the tuples forward with `_RegMap` (register -> symbol).
   `RegAssignSrcs` finds each source's register in `_RegMap` and frees it at its last use;
   `RegAssignDsts` calls `RegAssign(leaf, tuple)` for each destination tmpreg not colored yet. `RegAssign`
   takes (a) the preference `[sym+0x30]`, set for a copy (opcodes 1, 0x11F, 0x1FD, 0x17F, 0x181, 0x125, 0x189)
   from a colored tmpreg to that register and for `LEA d,[base+index]` without displacement (and, with an
   index, scale 1) to the base's register, if that register is free, available and not in conflict; else (b) under `/O2`
   (`_Speed`) **round-robin**: from `_NextIntPos`, the first free conflict-free register among the
   `_IntPhysRegs` entries numbered below 4 (eax, ecx, edx), wrapping to eax, and `_NextIntPos` moves past it;
   else (c) the first free conflict-free register of the whole list (esi, edi, ebx, ebp), else `RegSpill` of
   the register whose next use is farthest (`RegFindPhysRegUse`). A preference does not move the cursor.
3. **LEA to ADD.** The add stays `LEA s139,[a+b]` through register allocation; s139 was colored EAX
   globally (it feeds `CDQ`). In `LoFinalLower` (after `LoFinalLEAtoMOV` declines it) an LEA whose destination
   register equals one source becomes `ADD dest, other`, whichever operand position that source holds.
   The scheduler then moves the other reload earlier, so the EAX reload is the last load before the add.

Trace, g8 (g9 identical but for the field):

```
RegAssign s160 [1 s160 = k2:s10] next=ecx,edx,...   -> ecx      top    (y = top + bottom)
RegAssign s137 [1 s137 = k2:s12] next=edx,...       -> edx      bottom; cursor wraps to eax
RegAssign s140 [1 s169 = s170/eax] pref=eax          -> eax      copy preference, cursor unchanged
RegAssign s162 [1 s162 = k2:s5] next=eax,ecx,...     -> eax      g8: rect.left    g9: rect.right
RegAssign s161 [1 s161 = k2:s7] busy=eax:s162        -> ecx      g8: rect.right   g9: rect.left
18 s139/eax = [s161/ecx+s162/eax]  ->  45 s139,cc = s139,ecx    (add eax, ecx)
```

**Rule.** The reload of the field spilled first (the lower globreg number) is inserted first, so it is the
first of the two definitions the forward walk meets and takes the round-robin cursor's register; here the
cursor stood at EAX (it had wrapped after `bottom` took EDX), so that field is in EAX, the LEA's destination
register, and becomes the add's destination; the other field takes the next register (ECX). Which register a
reload gets is the cursor position, i.e. it depends on every round-robin assignment since the function start
(and on the copy preferences that skip it); which operand is the destination is "the source in the LEA
destination's register", not an operand position. With the cursor at ECX instead, the first reload would take
ECX and the LEA would stay an LEA (or the other operand would match).

## Function emission order

`dop2` compiles and emits one function at a time (`ReadFunction`, `dop2_Codegen`, `EmitFunction`), each
`EmitFunction` creating its sections at once, so an object's section table is c2's compile order. That order
is decided in three steps, and `emit-order` predicts all three from the IL alone (`/Bk` keeps it):

1. **IL order (c1xx).** `_Eentry_list` is the list of `gl` definition records (SSR 0E, `cl_trace.parse_gl`) in
   file order: every function body c1xx handed to c2, compiled or not (inline helpers of the headers included).
   c1xx writes them as it finishes each body: definitions in source order, inline and in-class members at
   their definition, virtual members at their class, an implicit special member (`??0Q`, `??_G`) right after
   the function whose body first needed it, template instantiations at the end of the unit. gl spells extern
   "C" names without the cdecl `_` (`IsEqualGUID`); c2's entries have it.
2. **Call-graph order (`CgBuildCallGraph` -> `CgBottomUpOrder`, every `/O1` `/O2` build, also `/Ob0`; not
   `/Od`).** The arcs are each record's call list (callees defined in the unit, in record order; references
   to vtables and external symbols are not arcs). `CgIdentifyRecursion` runs a DFS from each node in reverse
   creation order (`_CGnodes` is built by prepending) and flags every arc to a node on the DFS stack, a
   self-call included, as recursive. `CgBottomUpOrder` then moves entries without a call-graph node to the
   front and makes passes over the rest in list order: an entry is placed when each of its callees is already
   placed (recursive arcs ignored), otherwise it waits for the next pass. Entries flagged init (`fnflags`
   0x4: the dynamic initializers `??__E`, `.text$yc`, and the atexit destructors `??__F`, `.text$yd`) placed
   in a pass go to a second list. `SsrSortInitializerEvalOrder` then walks the initializer pointers
   (`x$initializer$`, gl data in a named segment, `.CRT$XCU`; segments sorted by name, stably, pointers in
   the order of their `in` records, which is source order) and moves the function each one names to the end
   of the main list; what is left of the second list (the `??__F`, which only an `atexit` argument names)
   follows in pass order (`initializer_order`).
3. **Needed set and compile loop.** An entry is compiled only once flagged needed (+0x50 bit 0x20). At the
   start that is every definition whose gl `fnflags` has 0x20 (c1xx sets it for external non-inline
   functions and for `operator new`/`delete`, `??2`/`??3`; not for statics, inline functions or implicit
   template instantiations) and every dynamic initializer (`fnflags` 0x4, `??__E`), closed over the call
   lists: a needed function's callees in the unit are needed, whether or not c2 later inlines every call
   (`Lock`, `??1CriticalSection` are emitted although inlined everywhere). `dop2` then rescans the list from
   its head and compiles the first needed entry not compiled yet (bit 2). Compiling a function emits the
   vtables its call list references that are not emitted yet; each vtable's slots, read from its initializer
   in the `in` file (`07 00 <vtable number>`, then items `<delta> 02 <symbol> <displacement>`), become needed
   with their call-list closure, `??_E` through its vector-dtor record (SSR 10) to the `??_G` it aliases. So a
   slot is compiled at the next rescan, before anything later in the list, even when it stands earlier
   (`curve_tracks`: `GetType@CurveTrackOf<Vector2>`, IL 36, right after the destructor that emits its vtable).

**`/Od`.** Without a call graph the gl header's IL flags lack 0x100 (`cl_trace.IL_CALL_GRAPH`), every
definition record ends after `formals` (no call list), there is no `CgBottomUpOrder`, and c2 marks needs as
it compiles. The list stays in IL order; the needed set starts with the `fnflags` 0x20 definitions and the
functions static data takes the address of, without closure; compiling a function needs what its code
references (the relocations of its code and associated sections, read from the obj: nothing is inlined) and
the slots of the vtables it emits, and the rescan goes on. The init entries are left out of the rescan: once
no other needed entry is left, the next initializer in `initializer_order` is compiled (then the rescan
picks up what it needed: `??__Es_obj` before `??0S`), and the `??__F` come last in list order. So a static or
inline function follows its first caller (`h2`, `helper`; `user`, `il2`, `il1`) and a constructor's vtable
slots come before the callees of those slots (`??0Q`, `V@Q`, `??_GQ`, `~Q`, `~Base`). `/Gy` is needed for the
per-function sections the prediction is checked against.

**The whole section table.** Each `CoffCreateSection` / `CoffCreateComdatSection` call creates the next
section number (traced with `newseg`, `newcomdat`, `EhEmitFuncinfo`, `obj_initializer`; `newcomdat` only
makes the logical COMDAT, most of them at read time). `full_sections` predicts the table from the compile
order and, per function, the relocations of its compiled sections and its associative EH sections (what the
code references is decided by inlining, so it is read from the obj):

1. `obj_start`: `.drectve`, `.debug$S`.
2. `ProcessSegmentInits`, before the first function: the COMDAT literals the static initializers reference
   (`const char* g_name = "..."`), then the plain `.bss`, `.rdata`, `.data` that exist (c2 prepends each
   segment to its list: `_BSS`, `CONST`, `_DATA`). A function whose address a static initializer takes
   (`Fn g_fn = &helper_inl;`, `in` item `02 <symbol>`) is needed from the start, inline or not
   (`static_function_refs`; gl data without `u06` bit 0x20, the on-demand COMDATs, are the static ones;
   an initializer pointer in a named segment is not). Under `/Od` without `/GF` string literals are `$SG`
   symbols in a plain `.rdata`: a `.rdata` holding only those comes first when a static initializer
   references one (`const char* g_s = "y";`), else after the other plain sections; with other constant
   data (`static const int t[2]`) it keeps its place between `.bss` and `.data`. A `.bss` whose symbols are
   all dynamically initialized (gl data flags 0x40: `int dyn = h1(3);`) is not created here.
3. Per function, in `EmitFunction`: its `.text` (a dynamic initializer's is a `.text$yc` COMDAT); its
   `.text$x` when that starts with unwind funclets; the data COMDATs its code references that are not
   emitted yet (`??_C@` strings, `__real@`/`__xmm@` constants, `??_7` vtables, `__TI` throw records),
   **newest reference first** (each is prepended to the function's emit list: `puts("alpha"); puts("beta");
   ... 0.5f ... 3.25f` gives `3.25, 0.5, beta, alpha`); the `.text$x` when it holds only the `__ehhandler$`
   stub (a function whose catch blocks stay in `.text`); `.xdata$x` (`__ehfuncinfo$`, with the
   `__unwindtable$`, `__tryblocktable$` and `__catchsym$` symbols in the same section); then the data the
   emitted data references, last-pushed first, each pushing its own (`__TI1` pushes `__CTA1`, the funcinfo
   pushes the catch type `??_R0`: `??_R0, __CTA1, __CT`); `.sxdata` at the first function with EH data;
   `.debug$F`.
4. `obj_end`: a `.bss` holding only dynamically initialized data (`SsrEmitDelayedInit`), then the
   remaining plain sections, the initializer segments last in name order, the order their initializers
   are evaluated in (`#pragma init_seg(lib)` after a default initializer: `.CRT$XCL`, `.CRT$XCU`;
   `init_seg("mysec")`: `.CRT$XCU`, `mysec`; `compiler` is `.CRT$XCC`, `user` `.CRT$XCU`; a unit may
   switch from the default to one `init_seg` only, C2356 otherwise).

Under `/Zi` each function's associative `.debug$S` follows its `.text` at once (before its `.text$x`,
literals and EH data) and replaces its `.debug$F`; the `.debug$S` of a data COMDAT (the guard `?$S1@` of
a function-local static) comes after the plain sections, and `.debug$T` last. The compile order and the
other sections are those without `/Zi`. A dynamic initializer whose value folds to a constant (`int dyn =
h1(3);` with `h1` inlined) is compiled (`ReadFunction`, traced) but emits nothing: no `.text$yc`, no
`.CRT$XCU`; `folded_initializers` reads that from the obj and the table is predicted without it.

An x87 load of the pooled 1.0 becomes `fld1` in `LoFinalLower` (+0x10c6, `MscFindFloatValue`) after the
constant was put on the emit list: its `__real@3f800000` COMDAT is still emitted there although no
relocation references it, so `fld1` (decoded with capstone) counts as a reference at its offset. A vtable
reached only through an inlined callee is attributed correctly by the IL model too: a callee of a needed
function is needed and stands earlier in the bottom-up list, so it is compiled (and emits the vtable)
first (`make_w` inlines `??0W`, which emits `??_7W`). `/Gy` is implied by `/O2` and does not change the order.

**Rule.** A function is emitted in source order unless it calls (or takes the address of) a function of the
unit whose IL comes later: a later definition (`h1` -> `plain_after`), a template instantiation (`h6` ->
`Box<int>::Get`), an implicit special member generated for it (`a_make` -> `??0Q`), or a function held back
itself (`h4` -> `h3`). Such a function moves after all the functions placed in the same pass, one pass per
level of such dependencies (`k1` -> `k3` -> `k5` gives `... k5, k3, k1` at the end). Recursion does not hold
back the function that the DFS reaches first in a cycle (`m1` <-> `m2` stay in order; in `q1 -> q2 -> q3 -> q1`
only `q2` stays). An inline function is emitted only if a needed function's call list or an emitted vtable
reaches it; it then takes its place in that list order.

**Evidence.** `emit-order` traces `CgBottomUpOrder` and `ReadFunction` and checks the prediction against both
the trace and the obj. With the exact `vc8_trace passes` options (`/O2 /Oy /arch:SSE2 /fp:fast /GS /EHsc
/GR- /MD /Gy /W3 /EHa`), on copies of three avp3 units: `platform_audio_streams.cpp` (58 IL entries, 30
compiled: operator new/delete, `Float_ToInt`, the lock members and the stream destructors before the unit's
13 functions; 3 vtables), `human_moves_idle_cover.cpp` (68 entries, 27 compiled, 6 vtables emitted by
constructors and destructors, the `??_G` slots after the later functions), `curve_tracks.cpp` (92 entries,
58 compiled; explicit and implicit template instantiations, 5 vtables): the gl order
equals the traced list, the modelled arcs and recursive arcs equal the traced ones, and the predicted
compile order and the code and vtable COMDATs equal the trace and the obj's section table; `--no-trace`
predicts their whole tables (81, 98 and 143 sections) exactly, as for two probes with statics, strings,
constants, try/catch with a throw, a dynamic initializer, an initializer taking an inline function's address
and vtables emitted next to literals (50 and 43 sections), and for probe `p4` (five dynamic initializers,
one held back by a later definition, a global with a constructor and destructor: 22 sections; traced, the
modelled bottom-up list equals `CgBottomUpOrder`'s). A probe with later definitions, statics, templates,
implicit constructors, `noinline`, two- and three-node and self recursion and a dynamic initializer agrees at
`/O2` as well. At `/Od /Gy` (same options otherwise) `--no-trace` predicts the three avp3 units' tables (48,
61 and 86 sections) and those of `p1` to `p4` and six small segment probes exactly; traced, `p4`'s compile
order equals `ReadFunction`'s. Under `/Zi` (`/O2` and `/Od`) `--no-trace` predicts the three avp3 units'
tables (82, 99, 144 sections at `/O2`; 79, 89, 145 at `/Od`) and those of `p1` to `p4`. The atexit
destructors and initializer segments: probe `f1` (six globals with destructors, an `int` initializer, a
global whose constructor calls a later definition, a function-local static with a destructor: seven
`??__E`, seven `??__F` in IL order after them, the static's `??__F` among them) and the `init_seg` probes
(`compiler`, `lib`, `user`, `".CRT$XCT"`, and the default followed by `lib`, `".CRT$XCV"` or `"mysec"`)
are predicted exactly at `/O2` and `/Od`, with and without `/Zi`; traced, `f1` and the default-then-`lib`
probe at `/O2` and `f1` at `/Od` give the modelled `CgBottomUpOrder` and `ReadFunction` order.

## Stack packing

`--preset stack` breaks on `AddStackElement`, `ColorStackElements` and `QSortColors` (stack.obj) and decodes
how c2 gives the locals and temporaries of an optimised function their frame offsets.

**Gate.** `StkStackAlloc` calls `StackPacking` when `_Globopt_flag` is set and neither `_FNeedFreshStack`
(`/RTCs`, EnC) nor `_FWvmSafe` is. Otherwise `StkAllocateLocals` gives each local its own slot at its first
reference in tuple order, with no sharing. `StackPacking` returns early when every element is a parameter.

**Elements.** `CollectStackElements` walks every instruction tuple's source (+0x28) and destination (+0x2C)
leaves. It skips tuples with +9 bit 0 clear and opcode 0x2D9. It calls `AddStackElement(EDX=sym)` once for
each counted reference whose base symbol (sym+8) has kind 3 (c2 temporary), 4 (front-end automatic) or
5 (parameter). The decoder labels each call by its return address:

- `leaf`: a symbol leaf, leaf+0x18.
- `address`: the base of an address or memory leaf, leaf+0x24.
- `points-at`: every member of the points-at set (`_PointsAtSets`, through `_PASMap`) of a may-alias leaf
  of a kind-0x16, opcode-0x2CE tuple. In the avp3 trace these are the inline-assembly blocks, each counted
  once for its source leaf and once for its destination leaf; every address-taken local the block may
  touch gets those references.
- `pogo`: PGO only.

`AddStackElement` keeps the symbols in a list (`_symStackElements`, next sym+0x30, prev +0x34). The list is
ordered by size (sym+0x20) ascending, then by reference count (sym+0x38) descending:

- A new symbol goes to the front of its size group with count 1.
- A symbol whose count goes up moves forward past the symbols of its size with a strictly lower count.
- `_CanonLocal` is skipped.
- A symbol with sym+6 bit 0x40 gets bit 4 ("can't pack": its `_bvLiveOnDef` set becomes all elements).

`EnumerateStackElements` numbers the list: sym+0x3C = index, `_symNumToSym[index]` = sym. The per-element
interference set `_bvLiveOnDef[index]` (sparse bit vector) comes from `ComputeLocalLiveness` and
`ComputeLiveOnDef`.

**Colours.** `ColorStackElements([esp+4]=Function, ...)`, ret 8:

1. Each parameter gets its own colour.
2. A local may then join a parameter colour: size <= colour + 8, and no interference.
3. `colorElemental` scans the other colours from the newest down and takes the first that fits: size <=
   2 x colour + 8, the element not in the colour's interference set (+4), and no common bit between the
   element's set and the members (+0). Otherwise it opens a new colour.

A merge adds the member's count to the weight (+0xC) and raises the size (+8) and alignment (+0x14) to the
member's. `_Colort` has a stride of 0x1C:

| offset | field |
|---|---|
| +0 | members |
| +4 | interference set |
| +8 | size |
| +0xC | weight |
| +0x10 | the offset of a parameter colour |
| +0x14 | alignment |
| +0x18 | /GS buffer level byte (`StkGSBufferLevel`) |

`_numOfColors` holds the count.

**Sort.** `QSortColors(ECX=lo, EDX=hi, [esp+4]=dir)`, ret 4, sorts `_Colort[_numOfParameters .. _numOfColors-1]`
with `StkColorCmp`. It runs only when the frame estimate exceeds 0x80 or the function has a /GS buffer
(`_Module+0x44C & 0x20000` with `Function+0x5C`, or `Function+0xAC & 1`). Otherwise the colours keep their
creation order. The sort is a recursive quicksort and is not stable. With dir 0 (dir = `Function+0x64` ==
0x10D0A1B0), lower indices get:

1. a lower /GS level;
2. within a level, a higher density, `weight * 1000 / size` (signed integer division).

**Offsets.** The colours are allocated from the last index down with `allotemp(size, align)`
(`_Alloc_local = -alignup(size - _Alloc_local, align)`), so the frame grows downward. The last colour (the
highest /GS level and lowest density) sits at the top of the frame, and colour 0 sits nearest ESP. Each
member gets the colour's offset:

- kind 4: in descriptor+0x18, with descriptor+0x20 |= 0x800;
- otherwise: in sym+0x28.

All members get sym+5 |= 0x20. A non-zero `_EbpAdj` is then added by `FixOffsetsForEbpAdj`.

**Decoders.**

- `ColorStackElements` reads everything at return, before `StackPacking` frees `_Colort`. It returns
  `elements` and `colors`:
  - each element: `index` (list position), `symnum`, `kind`, `name`, `fe`, `size`, `align`
    (1 << (sym+0x2C - 1)), `refs` (sym+0x38), `offset`, `color`, `live_on_def` and the
    `cant_pack`/`addr_taken`/`allocated` flags;
  - each colour: `members`, `interferes`, `size`, `weight`, `align`, `gs`, `density` and `param_offset`.

  It also returns `num_parameters`, `ebp_adj`, `alloc_local`, `max_align` (Function+0x48) and `dir`.
- `QSortColors` logs `lo`, `hi`, `dir` and `outer`. The outermost call (lo = `_numOfParameters`,
  hi = `_numOfColors - 1`) also carries the colours `before` and `after`.
- `AddStackElement` logs `symnum`, `name`, `fe`, `site` and `tuple_text`.

The addresses of the return sites and of the `dir` object are those of the pinned c2.dll.

## Limits

- The `/Od` model takes each function's references from the obj's relocations, not from its `ex` body
  (the `ex` names symbols the code does not keep, such as an unwind destructor without `/EHsc`). A
  reference c2 marks needed but that leaves no relocation is not seen. The `/Od` segment rules beyond
  the probes are untested.
- `full_sections` takes what each function's code references (relocations, `fld1`) and whether it has EH
  sections from the obj: those are inlining results. A constant whose every use a later pass removes in
  another way than `fld1` (`fldz` is not checked) is reported as `unplaced` with its obj section.
- Which data COMDATs get a `.debug$S` under `/Zi` (a static local's guard did, the static itself did
  not) is read from the obj, not predicted. Whether an initializer folds is an optimization result, read
  from the obj. `/GL` (LTCG) ordering is not modelled: c2 then runs at link time on IL from every
  object, and avp3 builds without `/GL` (`/Gy`, no LTCG), so it is out of scope.
- `_Speed` is bit 23 (0x800000) of the function's optimization word (`[f+0x1c]`, copied by
  `MscProcessPragstat` at each function's start; bit 8 goes to `_DefaultInt`, bit 31 to `_StackCheck`).
  c1xx sets it by default (`/Ot`, implied by `/O2`, `/Ox`, also under `/Og` and `/Od`) and clears it for
  `/O1`, `/Os` and `#pragma optimize("t", off)` (traced: `/O2` 0xA01804, `/O1` 0x201804); under POGO it goes
  to `_PogoSavedFuncSpeedFlag` instead, and `GetInlinee` sets it while it reads an inlinee. Without it
  RegAssign takes step (c) instead of the round-robin, and `LoFinalLower` turns `lea r,[r+1]`/`[r-1]` into
  INC/DEC (opcodes 0x21/0x1E) instead of ADD.
- The LEA to ADD rewrite is not a routine of its own: it is LoFinalLower's LEA case after
  `LoFinalLEAtoMOV` declines (+0x1EE). `lea d,[d+disp]` (leaf 0x27C, base register = destination) becomes
  `ADD d, disp` (+0x205; opcode 0x2D, `TupMakeIntConst`), `lea d,[a+b]` without displacement or scale
  (leaf 0x27D, +0x2EE) becomes `ADD d, other` when either register is the destination's (`TupReplaceSrc`,
  `TupMakePhysReg`, `CCSetUse`). The reload rule covers the integer class (`_IntPhysRegs`), not
  `_GFXPhysRegs`/`_XMMXPhysRegs`.
- Layouts and conventions hold for the pinned `c2.dll` only; they come from its disassembly, not from an API.
- `symnum` is c2's numbering (pool slot, by first use); the front-end number is `fe` (see "The 64-cycle").
- Hot routines (`OptHashNode`: ~1100 calls for one small function) are slow, one debug round trip per call
  and return; use `--function` and `--max-events`.
- Pointer-valued fields (`ret` of routines returning nodes, `sym`) differ between runs; compare decoded fields.
- Windows only; 64-bit Python debugs the 32-bit compiler through `Wow64GetThreadContext`.
