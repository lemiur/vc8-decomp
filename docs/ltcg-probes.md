# Synthetic /LTCG probes

`tools/ltcg_probes.py` builds tiny synthetic programs and links them the way the matching project links an
`// ltcg:` group, then traces the link with `tools/c2_inline_trace.py --link-rsp` (see
[c2-inline-trace.md](c2-inline-trace.md)). Each probe isolates one decision of c2's link-time inliner or of its
custom-convention choice (`MdmAllowFlexParams`), so the rule can be read from a result instead of guessed from
the retail executables. The sources are written in the script; nothing is taken from Microsoft headers or
sources. Output is evidence for diagnosing a wall, never source.

## Running

```powershell
python tools/ltcg_probes.py [P1 P5 P1a_hdr2 ...] [--out build/probes/ltcg_conv] [--no-trace] [--list] [--blocks 120]
```

- Selectors: a probe (`P1`), an exact variant (`P1a_hdr2`) or a longer prefix. No selector runs every variant
  that is on by default (`P5c` and `P5d`, the inline-assembly variants, hang in the LTCG link: name them to run).
- `--list` prints variants and notes without building. `--no-trace` compiles, links and disassembles only
  (seconds per variant); a traced variant takes minutes. `--blocks` sets the number of blocks in `Update`.
- The SP1 toolchain comes from `tools/probe_toolchain.py` (pinned and verified). Exit 1 if a variant fails.

Compile options are the matching project's (`/O2 /Oy /arch:SSE2 /fp:fast /GS /EHsc /GR- /MD /Gy /W3`) plus
`/GL`, except for modules a variant marks native (no `/GL`). The link is
`/DLL /NOENTRY /LTCG /OPT:REF,ICF /NODEFAULTLIB /MACHINE:X86 /MAP` with one `/INCLUDE`d root driver.

Link requirements: with `/NODEFAULTLIB` the runtime names are unresolved, so each is pointed at a stub object
with `/ALTERNATENAME:<name>=_ltcg_probe_stub` (`_ltcg_probe_stub_data` for `__imp_` names). The script retries
the link and adds every reported unresolved name, which covers `@__security_check_cookie@4`,
`___libm_sse2_tan`, `___libm_sse2_cos` and `__fltused`. The names and stubs are listed in each variant's
`objects.txt`.

## Outputs

`build/probes/ltcg_conv/<probe>/<variant>/` holds the sources, objects, `link.rsp`, `link.log`, `probe.map`,
`probe.dll`, `probe.disasm.txt`, the trace files and `<variant>.summary.txt`. The summary lists the link's
inliner setting (link size, `SpeedLimit`, `FoldCmpSpeedWeight`); per studied callee its traced call sites
(caller, depth, decision, rule), its conventions record (custom or not and the refusal, declared convention,
parameter locations, raw `entry+0x20` / `entry+0x50` words) and, from the image, whether it survived, its first
instructions, whether its frame has `and esp,-8`, and its call sites.

## Probes

| probe | what it varies | what it showed |
|---|---|---|
| P1a-e | a header `inline` wrapper around a noinline `Find`, callers all `/GL`; included by 2 or 3 modules, defined in one, or ordinary wrappers; cold sites | inlined everywhere; when kept out of line the callee gets a custom convention (id in EDX) |
| P1f-h | many `Mix` sites; `#pragma inline_depth(1)` (`P1h`) | the budget and `inline_depth(1)` change which sites expand |
| P2a-d | a native (non-`/GL`) caller; a native COMDAT copy; a native caller discarded by `/OPT:REF` | `entry+0x20` bit `0x2000` refuses a custom convention (stack args; the retail 18-byte wrapper shape); a cold site is cut off at cost 15 |
| P3a-d | the address of the function in a table in a `/GL` object (unused, used, selectany, wrapper table) | a data reference from a `/GL` object sets `0x2000` |
| P4a-k | callee module options: `/Ob1`, `/fp:precise`, no `/Gy`, no `/arch:SSE2`, `/Oi-`, `/O1`, noinline, table | module options change the callee body, not the `0x2000` decision |
| P5a-j | x87 C helpers (`Math_Tan`, `Math_Cos`): native init, dead native, table, `/Ob1`, noinline | `P5i` (refused plus `/Ob1`) gives the retail `Math_Tan` bytes and 21 calls; `P5j` (noinline) gives a custom XMM0 convention |
| P6a-c | a mid-size cdecl callee: noinline, `/INCLUDE`, baseline | the cdecl case and what `/INCLUDE` changes |
| P7 | every kind of outside reference (`/INCLUDE`, native, dead native, table, none) with `/Ob1`, noinline, `g_k` placement and address-taken | every `0x2000` trigger gives the same callee body; callers keep the global in XMM0 |
| P8 | object order in the link | object order does not change compile order (callee first) |
| P9a-b | call-graph cycles | cycle behaviour of the register-use summary and the inliner |
| P10a-b | a callee reached through a body inlined from another module or a header | the inlined body's callee is treated as the caller's |
| P11a-b | links of about 3,000 and 9,000 functions | no cap on register-use information |
| P12a-m | callee and caller side options: `g` off, `/Od`, `/Oy-`, `/Os`, `/Ob0`, `optimize` pragmas | which options change the decision |
| P13a-e | `Math_Tan` as a header function, `inline __declspec(noinline)` or `inline`, with `/INCLUDE`, native or no outside reference | `MscRecordInterProcRegInfo` skips the register-use summary for a SELECT_ANY COMDAT, so callers reload; with `0x2000` this is the retail `Math_Tan` shape |
| P14a-n | link size: modules x noinline functions x blocks (`P14j` has no caller) | `InlInitLtcgSetting` steps the constants by the link size, the sum of `entry+0x54` over the compiled entries: up to 50,000 `SpeedLimit` 89 / `FoldCmpSpeedWeight` 40; up to 100,000 84 / 35; up to 500,000 79 / 30; up to 1,500,000 71; up to 2,500,000 69; larger 64 |
