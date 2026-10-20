# c2 inlining tracer

`tools/c2_inline_trace.py` shows, for every call site c2 looks at while it compiles a function, whether the
callee was inlined, the rule that decided and the numbers it compared. It runs the `c2_trace` debugger
(`docs/c2-trace.md`) on the inliner routines of `inline.obj` in the pinned SP1 `c2.dll` (14.00.50727.762) plus
six probe breakpoints inside `InlCallGraphDecision`.

```powershell
python tools/c2_inline_trace.py --source X.cpp --flags="/O2 /EHsc" [-I DIR ...] [--function NAME] `
    --out build/inl/x.jsonl [--raw build/inl/x.raw.jsonl]
```

`--function` keeps the sites of functions whose decorated name contains NAME; `-I` adds include directories
(also to `INCLUDE`); `--raw` writes the routine events. A short table is printed. Exit 0, 1 (tracer error),
3 (cl.exe failed). Run from PowerShell (Git Bash rewrites `/O2`).

## /LTCG links (`--link-rsp`)

```powershell
python tools/c2_inline_trace.py --link-rsp build/x/link.rsp [--linker C:/vc8/VC/bin/link.exe] `
    [--function NAME] --out build/inl/x.ltcg.jsonl [--raw ...] [--timeout 600]
```

The traced process is `link.exe @RSP` (the response file's folder is the working directory) instead of cl.exe.
A `/LTCG` link of `/GL` objects runs the code generator in-process: link.exe loads the same pinned `c2.dll`,
so the same breakpoints and probes see the whole-program inliner and the output has the same form. `--linker`
names the link.exe (another install of the same version is fine as long as the `c2.dll` it loads is the pinned
one; the tracer slides the breakpoints to wherever it loads). Exit 3 means link.exe failed.

Under `/LTCG` c2 runs `InlInitLtcgSetting`, and the constants differ from a plain compile's: SpeedLimit **84**
(74 plain), FoldCmpSpeedWeight 35 (30), OneCallSizeAdj1/4 45, FewCallSizeAdj 5; SizeLimit stays 9 (`_Ltcg` = 1).
`_InlCurConsts` at the first `InlCallGraphDecision` is written with the call-graph counts to `<out>.extra.json`
(`consts`), in both modes.

With `--link-rsp`, `--function NAME` keeps the sites compiled in a function whose decorated name contains NAME
**and** the sites whose callee contains it; without it every site of the link is kept (a 33-object link: about
25k events, 17 s). `--max-events` (default 2,000,000) caps the inliner events only; `extra.json` reports
`events`, `dropped` and `dropped_by` (per routine) and the tool prints a warning when anything was dropped.

### Link-time conventions (`extra.json` `conventions`)

Every function the link compiles (never filtered by `--function`, never capped) gets one record, decoded from
c2's own data when four routines return:

| routine (when) | decoded |
|---|---|
| `MdmAllowFlexParams` (MscProcessParams, after Lower) | the custom-convention gate: sets entry+0xB4 = 1 or refuses |
| `MscSetDeadParamMap` (dop2_Codegen) | entry: the formal list; exit: entry+0xBC, the dead map (bit 0 valid, bit k clear = parameter number k removed and unlinked) |
| `WpaGenConstParamInfoUse` | exit: the whole-program constant records (call-graph node+0x24, 24 bytes: number, kind, value) that survived |
| `MdmFlexParams` (dop2_CodegenUpdate, after register allocation) | exit: entry+0xB4 (3 bits per remaining parameter at 3n+1, index into `_MdmFlexParamMap` = none, EAX, ECX, EDX, ESI, EDI, EBP, EBX), entry+0xB8 (4 bits per parameter: XMM register), entry+0x44 (stack parameter bytes), the declared convention (entry+0x20 & 0x1C: 0 cdecl, 4 fastcall, 0x10 stdcall, 0x14 thiscall) |

Parameter numbers start at 1 (2 when the context has a hidden parameter, `hidden_param`); the register
record numbers the formals left after the dead ones were unlinked (MdmParamNum). A callee is compiled before
its callers, which pass arguments by its record (MscRemoveDeadArguments drops the dead ones at every direct
call site, so dead and constant decisions are per callee, the same at all sites).

```
{"function", "custom", "declared", "ret_pop", "stack_bytes", "hidden_param", "refused",
 "dead_map", "flex", ["flex_xmm"], ["sites": {"inlined", "not_inlined"}, "inlined_everywhere"],
 "params": [{"index", "name", "type", "size", "location", "dead", "const"}]}
```

- `custom`: entry+0xB4 bit 0 (the gate passed). The registers are then c2's choice per parameter: `location`
  is a register name, `XMMn`, `stack`, or `removed` (dead). A custom thiscall may pass `this` on the stack.
  Without `custom` the location is the declared convention's (thiscall `this` in ECX, fastcall the first two
  small integer formals in ECX/EDX).
- `ret_pop`: `stack_bytes` for fastcall/stdcall/thiscall (callee pops, `ret N`), 0 for cdecl.
- `const`: `{kind: int|float|function address|global address, value | symbol, value_ptr}`; a constant
  parameter is substituted in the callee and normally also `dead` (its argument disappears at the call sites).
- `refused`: from the fields MdmAllowFlexParams tests, in its order: no global optimization; /clr:safe;
  entry+0x20 bit 0x2000 (set on every function referenced from outside the call graph in the test link:
  `/INCLUDE`d, virtual, member-pointer callbacks, initializer tables); entry+0x50 bit 4 (set on every
  recursive function seen); otherwise inline asm in a __fastcall/__thiscall function.
- `sites`/`inlined_everywhere`: the traced call sites of the function (all of them without `--function`).
- `type`: c2's type word (high nibble class, low 12 bits size in bytes; 0x1004 is `this`).

`extra.json` `function_status` (with `--function`): per matching decorated name, `inlined everywhere: no
convention` (with the record c2 wrote when it compiled the body, which no call uses), `out of line (...)` or
`not compiled by the link`. The tool prints the custom conventions that put a parameter in a register, remove
it or fold it, then the status lines. `param_passes` keeps the raw `MscAllowCallingConventionChange`,
`MscRemoveDeadArguments` (caller) and `MscParamIsDead` (inliner query) calls under `--function`.

Test link (AvP `main.both`, 33 objects): 695 functions compiled, 261 custom, 434 refused (409 bit 0x2000, 23
recursive); 62 parameters removed, 50 constant. Checked against the linked image: `StartChild`
(`this`=ESI, `childKind`=EDX: the callee reads both before writing them, the caller sets ESI), `FleeFrom`
(`this`=EDI, `entry`=ESI), `AVP_Behaviour_Sentrygun` constructor (`this` on the stack, `newBrain`=EDI,
`ret 4`), `Map<AnimationEntry>::Walk` (`this` = `g_animations`, callback constant: no arguments, the global
read directly).

## Output

One JSON object per call site, in the order c2 examined them: `caller` (the function being compiled, decorated),
`callee`, `depth` (1 = a call written in the caller, 2 = a call inside a body inlined at depth 1, ...),
`decision` (`inlined` / `not-inlined`), `rule`, `callee_size` (entry+0x54), `callee_traits` (entry+0x50 bits,
below), `budget`, `depth_limit`, `func_size`, and `numbers`:

| key | meaning |
|---|---|
| `limit.size` | the cost model's callee size (entry+0x68; counts EH-state tuples, unlike +0x54) |
| `benefit.*` | `InlBenefit`'s record: `credit` (size credit), `arg_cost`, `const_args`, `addr_args`, `fold_cmps`, `direct_calls`, `opaque_calls`, `caller_penalty` (large-caller term) |
| `speed_cap.cost` | cost before the speed path; > 450 refuses |
| `speed_small.cost`/`limit` | cost after the speed weights; < SizeLimit+5 (14) accepts |
| `speed_loop.loop_term` | the callee's loop share added before the frequency weighting |
| `speed_ratio.weighted`/`limit` | frequency-weighted cost; < SpeedLimit (74) accepts |
| `size_end.cost` | size path (no /Ot): cost < SizeLimit (9) accepts |
| `InlCallGraphDecision.site_weight` | the call block's estimated frequency, 100000000 = once per caller entry |
| `InlCallGraphDecision.cg_callsites` | call sites of the callee in the unit (entry+0x90) |

## The decision chain (/O2 = /Ob2 /Ot /Og)

`DoInline` (per function; sets entry+0x50 bit 0x10 on it) -> `GetInlineCandidates` -> per call
`InlCallTupleIsCandidate` (with `InlMightInlineEntry`) -> per candidate `ConsiderCandidate` ->
`ShouldInlineCallTuple` -> `InlCallGraphDecision` (-> `InlBenefit`, `InlBadCandidate`) -> `GetInlinee` ->
`ShouldInlineInlinee` -> `InlineInlinee`; the inlined body's calls are considered at depth+1.

- **Candidate** (`InlMightInlineEntry`): entry+0x50 must have 0x40. c1xx sets it on every function under /Ob2,
  only on `inline`/in-class/`__forceinline` ones under /Ob1, and never on `__declspec(noinline)`.
  0x80 = declared inline (C4710 if refused), 0x2000 = `__forceinline` (C4714). Refused also: entry+0x50 0x10 (the
  function being compiled or inlined: no self-recursion), 0x200 (EH conflict under global opts without
  `__forceinline`), size >= `_MaxInlineeSize` (128) when not /Ot.
- **ShouldInlineCallTuple** (args: depth, `inline_depth` 0xFE by default, budget 1000): depth > limit refuses
  unless `__forceinline`; `__forceinline` accepts **without any cost model**; a callee with a call-graph node (the
  normal case: c2 compiles a unit's callees before their callers, so the order of definitions does not matter)
  goes to `InlCallGraphDecision`.
- **InlCallGraphDecision**, speed path: `cost = size68 - arg_cost - credit + caller_penalty
  - NoBranchSizeAdj(10, branch-free callee)`; cost > 450 refuses; cost -= the fold/argument speed weights
  (FoldCmpSpeedWeight 30 per foldable compare against a constant argument); if < 14 accept (InlBadCandidate
  permitting); else `cost += loop_term`, then weighted = `(cost*1e8/site_weight + (c-1)*cost)/c` with c = 3 if the
  block runs more than once per entry, else 7; weighted < 74 accepts. Cold call sites (low `site_weight`) cost more.
- The constants are `_InlCurConsts` (45 dwords; names from `InlInitUsrSetting`, defaults from
  `InlInitNativeByte`), all printed by `read_consts` in the module.

## Experiments (/O2 unless stated; `exp/*.cpp` sizes are cost-model sizes)

| case | result | rule / numbers |
|---|---|---|
| `g[i]=g[j]*a+i` x N, one arg, many sites | N<=4 inlined, N>=6 not | size 20/38/74 -> weighted 7/25/61 < 74; N=6: size 110, weighted 97; N>=32 cost > 450 |
| same, `static`, one call site | N=8 not | /3 only feeds the <14 test (43); weighted 129 >= 74 |
| plain, `static`, `inline`, in-class, out-of-class member | all inlined | same cost model; `inline` changes nothing at /Ob2 except the C4710 warning |
| `__forceinline` | inlined | no cost model, no depth limit |
| `__declspec(noinline)` | call | not a candidate (no 0x40) |
| callee defined after the caller | inlined | callees are compiled first; flags show `compiled` |
| /Ob1 | only `inline`/in-class/`__forceinline` inlined | others lack 0x40 |
| callee with a destructor local, /EHsc | not inlined (no EH: inlined) | size 102 vs 38: the EH-state tuples count; weighted 99 vs 35 |
| self-recursive `rec` | caller inlines one level; the inner call stays | inner: entry 0x10 (on the inline stack) |

## avp3 cases (copied units, exact `vc8_trace passes` flags)

- **`Gui_PlaySound`** (gui_elements.cpp): without `__declspec(noinline)` all four calls in
  `GuiCommandList::Execute`/`ExecuteIndex` are inlined: size 58, arg_cost 6, credit 7 (one constant argument
  folds `sound >= GUI_SOUND_COUNT`: fold_cmps 1, -30), cost 45 -> 15, weighted 14 (site_weight 1.25e8) and 16
  (6.25e7) < 74. The game kept the call, so its source made the callee costlier or non-candidate (another
  object, or noinline); with the body visible, VC8 inlines it.
- **`AudioMap::FindInline(key, behind)`** (audio_mixer.cpp), plain `inline`: size 81, arg_cost 10, cost 71, loop
  term +36 -> 107; weighted 85 in `AudioMix_Apply` (site_weight 2.5e8, c=3) and 140 in `AudioMixer_Queue`
  (3.125e7, c=7), both >= 74: refused. `__forceinline` skips the model. The one-argument `FindInline(key)` (size
  17, cost 9 < 14) is inlined either way.

## Limits

- Layouts, probe offsets and constants hold for the pinned c2.dll only (read from its disassembly).
- The rule text is derived from which probes fired; Pogo, Wvm (/clr) and `InlineeIsTooBig` (no call graph)
  paths are decoded only coarsely. LTCG links are traced with `--link-rsp` (the same cost model with the
  link's constants).
- Conventions: the refusal names for entry+0x20 bit 0x2000 and entry+0x50 bit 4 are read from the functions
  that carry them, not from the code that sets them; a constant of kind 2 (float) is read as a double; the
  register record covers the first 10 parameters (c2's limit). Pogo (/LTCG:PGO) paths are not decoded.
- `site_weight` is c2's static block-frequency estimate, not a profile.
