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
lowest weight. The routine adds interfering globregs' preference weights and 100 x refs of interfering
globregs restricted to one register, subtracts the globreg's own preference weights, and keeps the first
register in `_RegOrders` order with the strictly lowest weight: on a tie the earlier register (esi before edi
before ebx before ebp for class 0) wins, so the coloring order decides.

### Symbols, immediates, globregs, tuples

- `SymAlloc` (exit `symnum`) / `SymFree` (entry `symnum`, `name`, `fe`): per-kind LIFO free lists; a freed
  symbol keeps its number, so tmpreg numbers are reused newest-freed first.
- `GrgImmedTupleHash` (`leaf_kind`, `value` or `name`/`fe`, exit `bucket`): the `_ImmedHashTable` bucket.
- `GrgNewGlobreg` (entry: the symbol; exit `globreg`) and `Spill` (the globreg, its symbol, `base`/`offset`
  for a field).
- `--symtab`: `symnum`, `kind`, and `name` + `fe` (front-end `$N`) or `base` + `offset` (an equivalence:
  a field of a base symbol).
- `--tuples`: leaves print as `#n` (constant), `&name$fe` (address), `name$fe` / `sN` (symbol, tmpreg),
  `[a+b+disp]` (effective address), register names, `kK:...` (other kinds).

### Fields

| field | source (pinned c2.dll 14.00.50727.762) |
|---|---|
| `globreg` | Globreg+0x1C, `_NextGlobregNum` at creation (`GrgNewGlobreg`) |
| `sym`, `symnum` | Globreg+0 (c2 symbol), symbol+0x1C: c2's own symbol number, not c1xx's `$N` listing number |
| `priority` | Globreg+0x0C, the sort key (spill benefit) `InsertInList` compares first |
| `lastref` | Globreg+0x44: `RewriteAsGlobregs` stores its running tuple ordinal at each rewritten reference, so the ordinal of the last one |
| `refs` | Globreg+0x40 |
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

## Limits

- Layouts and conventions hold for the pinned `c2.dll` only; they come from its disassembly, not from an API.
- `symnum` is c2's numbering (pool slot, by first use); the front-end number is `fe` (see "The 64-cycle").
- Hot routines (`OptHashNode`: ~1100 calls for one small function) are slow, one debug round trip per call
  and return; use `--function` and `--max-events`.
- Pointer-valued fields (`ret` of routines returning nodes, `sym`) differ between runs; compare decoded fields.
- Windows only; 64-bit Python debugs the 32-bit compiler through `Wow64GetThreadContext`.
