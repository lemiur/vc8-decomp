# Tracing the front half of cl.exe

`tools/cl_trace.py` traces what `cl.exe` 14.00.50727.762 does with one command line: the passes it
runs, the intermediate-language (IL) files between them, and the front end's symbol numbers (the
`$NNNNN` suffixes of `/FA` listings). Python stdlib and ctypes only; the toolchain comes from
`config/project.json` (`toolchain_root`) or `--vc`. Unit tests: `python -m unittest tests.test_cl_trace`
(parsers only, no compiler).

```
python tools/cl_trace.py passes  --source X.cpp --flags="/O2 /GR-" [-I DIR] [--dry] [--debug] [--keep DIR] [--json]
python tools/cl_trace.py symbols --source X.cpp --flags="..." [-I DIR] [--function REGEX] [--globals REGEX] [--json]
python tools/cl_trace.py il      --source X.cpp --flags="..." [--records] | --prefix DIR/stem_
python tools/cl_trace.py experiment cost [--flags="..."]
python tools/cl_trace.py experiment flip --source X.cpp --insert-before TEXT --function REGEX
                                         [--local NAME] [--globals REGEX] [--start N --stop M] [--flags="..."] [-I DIR]
```

Write `--flags="..."` with `=` when the value starts with a dash. Run from PowerShell or cmd: Git
Bash rewrites `/O2`-style arguments into paths.

## Driver switches (confirmed on this cl.exe)

Each switch was run against the installed SP1 `cl.exe`; the names also appear in its option table
(`Bd`, `Bk`, `Bt`, `Bv`, `Bz`, and the `astfe:B1` / `astfe:Bx` / `d1` entries).

| switch | effect observed |
|---|---|
| `/Bd` | prints each pass as `` `<dll> argv...' `` and runs it |
| `/Bz` | prints the same lines and runs nothing (no `.obj`) |
| `/Bt` | prints `time(<dll>)=0.009s` per pass |
| `/Bv` | prints the version of cl, c1, c1xx, c2, link, mspdb80 and clui |
| `/Bk<prefix>` | IL file prefix instead of `%TMP%\_CL_xxxxxxxx`; the files are kept (`-il <prefix>` to both passes) |
| `/Bx<dll>` | replaces c1xx (C++ front end) |
| `/B1<dll>` | replaces c1 (C front end); ignored for a `.cpp` |
| `/B2<dll>` | replaces c2 (back end) |
| `/d1<opt>` | passes `-<opt>` to the front end (`/d1nonsense`: `c1xx : fatal error C1007: unrecognized flag '-nonsense' in 'c1xx'`) |
| `/d2<opt>` | passes `-<opt>` to the back end (`... in 'p2'`) |

`/Bk` and `/FAs` leave the `.obj` unchanged apart from its timestamp and the embedded path of the
temporary directory.

## Passes

`cl.exe` starts no process for compilation. It loads `c1xx.dll` (or `c1.dll` for C), calls it, loads
`c2.dll`, calls it, unloads both and deletes the IL files. `passes --debug` records this with Windows
debug events; a `ReadDirectoryChangesW` watcher on a private `TMP` records each file's life. Typical
run (`a.cpp`, `/O2 /EHsc`, times from launch):

| ms | event |
|---|---|
| 6 | process `cl.exe` |
| 31 | load `Common7\IDE\mspdb80.dll` |
| 56 | load `VC\bin\c1xx.dll` |
| 60-61 | `_CL_xxxxxxxxex`, `sy`, `gl`, `in` created (by c1xx) |
| 78 | load `VC\bin\c2.dll` |
| 83 | unload c1xx, unload c2 |
| 84-85 | the four IL files deleted (by cl.exe), process exits |

The game's options `/O2 /Oy /arch:SSE2 /fp:fast /GS /EHsc /GR- /MD /Gy` become (beyond the fixed
`-zm0xFCCA0000 -il ... -f ... -W 1 -Ze -D_MSC_EXTENSIONS -Zp8 -ZB64 -D_INTEGRAL_MAX_BITS=64 -Gs -pc \:/
-Fdvc80.pdb -D_MSC_VER=1400 -D_MSC_FULL_VER=140050727 -D_WIN32 -D_M_IX86=600 -Zc:forScope -Zc:wchar_t`):

| pass | options it receives |
|---|---|
| c1xx | `-GF -Og -Oi -Ot -Oy -D_M_IX86_FP=2 -fpfast -GS -EHs -D_CPPUNWIND -EHc -D_MT -D_DLL`, then `-I` for each `INCLUDE` entry |
| c2 | `-il ... -f ... -W 1 -Gs4096 -dos -Fdvc80.idb -Og -Ob2 -archSSE2 -GS -EHs -MD -Gy -Fo...` |

`/Zi` adds a fifth file, `db`. `/GL` still runs c2, which then writes IL into the `.obj`.

## IL files

| file | contents (as far as read) |
|---|---|
| `ex` | function bodies (expression trees); about 2.8 KB for a one-function unit |
| `gl` | unit-level symbols: 7 signature bytes `11 86 03 29 18 32 01`, then the unit's symbol count (u32), then records `<number> 00 <decorated name> 00 <attrs>` for globals, functions, members and string literals |
| `in` | a 396-byte block present in every unit, plus initialisers |
| `sy` | one block per compiled function, ended by `06`: every parameter, local and compiler temporary with its number |
| `db` | `/Zi` only |

Numbers use one encoding, the one c1xx's `ILSink::loshwrite` name suggests: a u16 below 0x8000, or
`u16(0x8000 | v & 0x7FFF)` followed by `u16(v >> 15)`. The `sy` records:

| tag | layout | meaning |
|---|---|---|
| `03` | `a <n> u16 u8 u8` | compiler temporary |
| `0D` | `level` | scope opened (1 = parameters, 2 = function body, deeper = blocks) |
| `01` | `level <n> 00 name 00 kind <type> storage u8 <size> flags [<extra> if flags & 0x80]` | named symbol; storage 3 = parameter, 1 = automatic |
| `02` | as `01`, then one more byte | array |
| `06` | | end of function |

The layout comes from experiments. The decoder resyncs at unknown bytes and reports what it skipped.
`gl` records are found by a pattern scan (`symbols --globals`), not decoded.

## Symbol numbers

The front end gives every symbol it creates the next number from one unit-wide counter. The counter
starts at about 2,530: the predefined symbols come first. Statics go to `gl`; the listing prints
the suffix only for locals in a nested block (`_inner$2544`), while `_rect$` at function scope has
none. `symbols` reads every number from `sy` and joins it with the listing's frame offsets:

```
f  ?f@@YAHPAUR@@H@Z
     number mod64 kind   lvl name      suffix  frame size
       2537    41 param    1 p                     8 4
       2538    42 param    1 n                    12 4
       2540    44 temp     1 <temp>
       2541    45 local    2 rect                 -8 8
       2544    48 local    5 inner       $2544   -16 8
```

### What a construct costs (`experiment cost`, `/O2 /EHsc /GR-`)

The probe is a block-scope local defined after the construct. The cost is how far its number moves.

| construct | numbers |
|---|---|
| `#define`, empty `namespace` | 0 |
| `int` global, `typedef`, forward `struct S;`, function declaration with no parameters | 1 |
| function declaration: one more per parameter, named or not | 2 / 4 for 1 / 3 parameters |
| enum | 1 + 1 per enumerator |
| global initialised by a string literal | 2 (the literal is a symbol) |
| inline function never called, 1 parameter | 3 |
| function definition, 1 parameter + 1 local | 4 |
| empty struct | 7 (implicit members) |
| struct: data member, method declaration | +1 each |
| struct: inline method | +3 |
| struct: virtual method, or constructor + destructor declarations | +4 |
| class template, not instantiated | 3 |
| first use of `X<int>` as a pointer | +3 |
| first `X<int>` object (complete instantiation) | +11, about the cost of the same struct written out |
| function template, not instantiated | 2 |
| first instantiation `id<int>` | +4; later calls 0; `id<char>` +5 |
| global with a dynamic initialiser (`int u = f(0);`) | 28 |
| a call that c2 inlines | 0 (c2 inlines; the front end creates nothing) |

So a header declaration, an implicit or explicit member, or a template's first instantiation
moves every later number. A macro does not, and neither does an inline call.

## The codegen flip

`experiment flip` inserts N `typedef int cl_trace_padK;` lines (one number each, no code) before a
marker and hashes the function's listing with the `$NNNN` suffixes masked.

1. **Small replica** (a `Gui_FinishDraw`-shaped function with its own `Rect`, `/O2 ... /Gy`): one
   code variant for N in 0-69, for the local's numbers near 2,550 and near 82,282, and with the
   padding before the function, after it, or inside its block. The local's number alone does not
   change c2's output.
2. **The real unit** (`E:\avp3-decomp\matching\gui_pc.cpp`, compiled read-only from a copy, dx9
   flags): two variants. Variant `f81ddba5` swaps the two `_rect$` loads
   (`mov ecx, _rect$[esp+36]` / `mov eax, _rect$[esp+28]` exchange offsets). This is the
   documented symptom.

| padding inserted before | variant f81ddba5 for |
|---|---|
| `#include "include/gui.h"` (whole unit shifts) | N = 16-31 of 0-65, `rect` mod 64 = 43-58 |
| `#define` lines (no numbers) at the same place | never (N = 0-129) |
| any include after `gui.h`, or `void Gui_FinishDraw()` | never: `rect` takes every value mod 64 with no flip |
| `extern RenderStateCache g_renderStates;` in `render.h` | N = 16-47: `g_renderStates` mod 64 = 0-31 |
| the line after that declaration | never |

The decisive number is not `rect`'s. It belongs to the global `g_renderStates`, which only the dx9
body uses. That is why dx9 and dx11 differ the same way. With only `g_renderStates` and later
symbols moved, variant f81 appears exactly when its number mod 64 is below 32. With the whole unit
moved, the window narrows to mod 64 = 0-15. So the effect is relative to at least one symbol
declared before it, probably a member of `RenderStateCache`. The period is 64, but the key is the
number of a global the function references, not the local the listing names.

Practical rule: to read the cause of a symbol-number wall, run `experiment flip` with
`--globals` set to the function's referenced globals. Then bisect the insertion point through the
headers on a copy. Shifting only the function's own locals tells you nothing.
