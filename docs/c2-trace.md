# c2 decision tracer

`tools/c2_trace.py` runs the pinned SP1 `cl.exe` on one source file under the Windows debug API and logs
selected `c2.dll` routines as they run. It makes register-allocation decisions (and, coarsely, any other public
c2 routine) visible, to explain why two spellings of a function compile differently.

```powershell
python tools/c2_trace.py --source X.cpp --flags "/O2 /GS- /arch:SSE2 /fp:fast" `
    --break OrderGlobregs,ChoosePhysReg [--function Gui_FinishDraw] [--include DIR] `
    [--dump "[[esp+4]]:16"] --out build/trace/x.jsonl
```

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

## Limits

- Layouts and conventions hold for the pinned `c2.dll` only; they come from its disassembly, not from an API.
- `symnum` is c2's numbering; the front-end number in listings (`_rect$2594`) is elsewhere and not decoded.
  A reproduced 64-cycle case (the `Gui_FinishDraw` operand order of `rect.left + rect.right`, flipping when 9
  extra declarations precede it) is not a register-allocation decision: `OptHashNode` hashes and the
  coloring were identical on both sides, so the deciding routine is still to be found (candidates: tuple
  canonicalization and `lower.obj`).
- Hot routines (`OptHashNode`: ~1100 calls for one small function) are slow, one debug round trip per call
  and return; use `--function` and `--max-events`.
- Pointer-valued fields (`ret` of routines returning nodes, `sym`) differ between runs; compare decoded fields.
- Windows only; 64-bit Python debugs the 32-bit compiler through `Wow64GetThreadContext`.
