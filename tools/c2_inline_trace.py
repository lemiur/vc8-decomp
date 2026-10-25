"""Trace c2.dll's inlining decisions while cl.exe compiles one source file.

Usage:
  python tools/c2_inline_trace.py --source X.cpp --flags="/O2 /EHsc" [-I DIR] [--function NAME]
         --out trace.jsonl [--raw raw.jsonl]
  python tools/c2_inline_trace.py --link-rsp LINK.rsp [--linker link.exe] [--function NAME]
         --out trace.jsonl [--raw raw.jsonl]

With --link-rsp the traced process is link.exe on that response file (a /LTCG
link of /GL objects): link.exe loads the same c2.dll and runs the link-time
code generator in-process, so the same breakpoints see the whole-program
inliner. The response file's folder is the working directory. It also decodes,
for every function the link compiles, the link-time convention: the register
or stack slot of each parameter, the dead parameters removed and the constant
parameters folded, or why c2 refused a custom convention (<out>.extra.json
"conventions").

For every call site c2 looks at while it compiles a function, one JSON object:
caller, callee, depth (1 = a call written in the caller, 2 = a call inside an
inlined body...), decision (inlined / not-inlined), the rule that decided and
the numbers it compared. It runs the c2_trace debugger (tools/c2_trace.py) on
the inliner routines of inline.obj with decoders read from the pinned
14.00.50727.762 c2.dll disassembly (docs/c2-inline-trace.md); the layouts are
not an API and hold for that c2.dll only.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import c2_trace  # noqa: E402  (the debugger, symbols and memory model; owned by another worker)

ROOT = Path(__file__).resolve().parents[1]

# ------------------------------------------------------------ c2 layouts

# Entry (c2's per-function record, the callee of a call tuple): +4 decorated
# name, +0x20 and +0x50 flag words, +0x54 the callee's size (word: instruction
# count InlCollectInfo stored when the callee was compiled), +0x88 the call
# graph node (Globopt only).
ENTRY_NAME, ENTRY_FLAGS20, ENTRY_FLAGS50, ENTRY_SIZE, ENTRY_CGNODE = 0x04, 0x20, 0x50, 0x54, 0x88

# Entry+0x50 bits named from the routines that test them.
FLAGS50 = {
    0x00000002: "compiled",        # body already compiled: its size and call-graph node are valid
    0x00000010: "on-inline-stack", # set by DoInline on the function whose calls it is inlining: no self-recursion
    0x00000040: "inlinable",       # required by InlMightInlineEntry (/Ob1: only inline-marked; /Ob2: any)
    0x00000080: "inline",          # declared inline (keyword or in-class body): C4710 when refused
    0x00000100: "no-inline-here",  # refused when InlCallTupleIsCandidate's 3rd argument is set
    0x00000200: "eh",              # refused with global opts unless __forceinline ("EH/Global opts conflict")
    0x00002000: "forceinline",     # __forceinline: depth limit and call-graph decision skipped; C4714
    0x00080000: "flags50:0x80000",  # refused by InlMightInlineEntry
}
# Entry+0x20 bits that InlMightInlineEntry refuses.
FLAGS20_REFUSED = {0x40: "flags20:0x40", 0x100: "flags20:0x100", 0x400: "flags20:0x400",
                   0x1000: "flags20:0x1000"}

# _InlCurConsts: 45 dwords, copied by InlSetConsts from _InlNativeByteConsts
# (from _InlNativeConsts under Pogo); InlInitUsrSetting names the offsets
# (each *Usr global, 0 unless overridden) and InlInitNativeByte sets the
# defaults of the zero ones.
CONSTS = {0x00: "SizeLimit", 0x04: "SpeedLimit", 0x08: "FoldCmpSpeedWeight", 0x0C: "FoldInLoopCmpSpeedWeight",
          0x10: "LoopDenom", 0x14: "Denom", 0x18: "NewInnerLoopNumer", 0x1C: "NewInnerLoopDenom",
          0x20: "NewOuterLoopNumer", 0x24: "NewOuterLoopDenom", 0x28: "NewLoopWeighting",
          0x2C: "OneCallSizeAdj1", 0x30: "OneCallSizeAdj2", 0x34: "OneCallSizeAdj3", 0x38: "OneCallSizeAdj4",
          0x3C: "CRMax", 0x40: "FewCallSizeAdj", 0x48: "UserInlineSizeAdj", 0x4C: "NoBranchSizeAdj",
          0x5C: "MaxLoopSizeAllowed", 0x60: "ConstArgSpeedWeight", 0x64: "DataAddrArgSpeedWeight",
          0x68: "CodeAddrArgSpeedWeight", 0x80: "RPUnknownHigh", 0x84: "LifeTimesUnknownMax",
          0x88: "RPNonLeafCalleeAdj", 0x8C: "RPInline2GloboptAdj", 0x90: "RPInline2GloboptLoopAdj",
          0x94: "LifeTimesCritical", 0x98: "LifeTimesMonsterDenom", 0x9C: "LifeTimesFactor",
          0xA0: "LifeTimesFactor2", 0xA4: "RPCritical", 0xA8: "RPMonsterDenom", 0xAC: "RPFactor",
          0xB0: "RPFactor2"}
CONST_COUNT = 45

BREAKS = ("InlCallTupleIsCandidate", "InlMightInlineEntry", "ConsiderCandidate", "ShouldInlineCallTuple",
          "InlCallGraphDecision", "InlBenefit", "InlBadCandidate", "InlCheckInlineeAttribs",
          "ShouldInlineInlinee", "InlineeIsTooBig", "InlineInlinee", "WarnForFailedInline", "InlCollectInfo")
# The link-time parameter passes logged raw with --link-rsp (under --function): the convention gate the
# constant-parameter pass asks, the caller-side dead-argument removal, and the inliner's dead-parameter query.
LTCG_BREAKS = ("MscAllowCallingConventionChange", "MscRemoveDeadArguments", "MscParamIsDead")
# The routines whose results are decoded into per-function conventions (every function, never filtered or
# capped): MdmAllowFlexParams (the custom-convention gate), MscSetDeadParamMap (the dead-parameter map),
# WpaGenConstParamInfoUse (constant parameters) and MdmFlexParams (the register assignment).
CONV_BREAKS = ("MdmAllowFlexParams", "MscSetDeadParamMap", "WpaGenConstParamInfoUse", "MdmFlexParams")
# The register-use summary (c2_trace RegUseModel) with --link-rsp: MscRecordInterProcRegInfo for every function
# (never filtered or capped), LoAddCallScratchRegs per call (under --function: the calls compiled in a matching
# function or to a matching callee).
REGUSE_RECORD, REGUSE_CALL = "MscRecordInterProcRegInfo", "LoAddCallScratchRegs"
REGUSE_BREAKS = (REGUSE_RECORD, REGUSE_CALL)


def flag_names(value, table=FLAGS50):
    return [name for bit, name in sorted(table.items()) if value & bit]


def signed(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & 0x80000000 else value


# ------------------------------------------------------------ memory reads

def callee_of_tuple(u32, tup):
    """Callee entry of a call tuple: source leaf +0x28; leaf kind 4 holds the
    entry at +0x18, otherwise the symbol at +0x18 leads to it through +8 -> +0
    (ShouldInlineCallTuple, InlCallTupleIsCandidate)."""
    if not tup:
        return 0
    leaf = u32(tup + 0x28)
    if not leaf:
        return 0
    if u32(leaf + 8) & 0xFF == 4:
        return u32(leaf + 0x18)
    return u32(u32(u32(leaf + 0x18) + 8))


def entry_info(model, entry):
    if not entry:
        return {}
    flags50, flags20 = model.u32(entry + ENTRY_FLAGS50), model.u32(entry + ENTRY_FLAGS20)
    return {"callee": model.cstr(model.u32(entry + ENTRY_NAME), 512), "callee_size": model.u32(entry + ENTRY_SIZE) & 0xFFFF,
            "callee_flags": "0x%X" % flags50, "callee_traits": flag_names(flags50),
            "callee_flags20": "0x%X" % flags20, "callee_cgnode": bool(model.u32(entry + ENTRY_CGNODE))}


def read_consts(model):
    va = model.sym("_InlCurConsts")
    if va is None:
        return {}
    out = {}
    for i in range(CONST_COUNT):
        out[CONSTS.get(4 * i, "c%02X" % (4 * i))] = signed(model.u32(va + 4 * i))
    return out


def read_global(model, name):
    va = model.sym(name)
    return None if va is None else signed(model.u32(va))


# ------------------------------------------------------------ decoders

class SiteDecoder(c2_trace.Decoder):
    """Base: the call tuple is found by tuple_of(regs, stack); the exit logs ret."""

    def tuple_of(self, model, regs, stack):
        return 0

    def entry(self, model, regs, stack):
        tup = self.tuple_of(model, regs, stack)
        info = {"tuple": "0x%08X" % tup} if tup else {}
        info.update(self.more(model, regs, stack, tup))
        return info, {"tuple": tup}

    def more(self, model, regs, stack, tup):
        return {}

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


class IsCandidateDecoder(SiteDecoder):
    """InlCallTupleIsCandidate([esp+4]=call tuple, [esp+8], [esp+0xC]=depth
    limit, [esp+0x10]); ret 0x10. Refuses tuples flagged +0x30 bit 0, entries
    InlMightInlineEntry refuses, entries flagged 0x100 when [esp+8] is set, EH
    entries (0x200) under global opts unless __forceinline, and, when not
    optimizing for speed, entries of size >= _MaxInlineeSize."""

    def tuple_of(self, model, regs, stack):
        return stack[1]

    def more(self, model, regs, stack, tup):
        info = entry_info(model, callee_of_tuple(model.u32, tup))
        info.update({"tuple_flags30": model.u32(tup + 0x30) & 1, "arg2": stack[2], "depth_limit": stack[3],
                     "globopt": read_global(model, "_Globopt_flag"), "speed": read_global(model, "_Speed"),
                     "max_inlinee_size": read_global(model, "_MaxInlineeSize")})
        return info


class MightInlineDecoder(c2_trace.Decoder):
    """InlMightInlineEntry(EAX=entry, [esp+4]); ret 4."""

    def entry(self, model, regs, stack):
        return entry_info(model, regs["eax"]), {"entry": regs["eax"]}

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


class ConsiderDecoder(c2_trace.Decoder):
    """ConsiderCandidate(ECX=caller context, EDX=depth limit, stack: candidate,
    context, depth, depth limit, ..., candidate index); ret 0x28."""

    def entry(self, model, regs, stack):
        cand = stack[1]
        tup = model.u32(cand + 4) if cand else 0
        return {"tuple": "0x%08X" % tup, "depth": stack[3], "depth_limit": stack[4],
                "index": stack[8] if len(stack) > 8 else None}, {"tuple": tup}

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


class ShouldCallTupleDecoder(c2_trace.Decoder):
    """ShouldInlineCallTuple(EDI=candidate (+4 call tuple), [esp+4]=caller
    context, [esp+8]=inline depth (1 = written in the caller), [esp+0xC]=depth
    limit (#pragma inline_depth; 0xFE by default, 0xFF none), [esp+0x10]=size
    budget without a call graph, [esp+0x14]); ret 0x14. Order: Pogo; recursion
    (InlRecursiveCycleStartDepth: depth - start > 16 or > limit refuses); depth
    > limit refuses unless __forceinline; __forceinline accepts; with a call
    graph node InlCallGraphDecision decides; otherwise _FuncSize > 35000
    refuses, size > budget and size > 40 refuses, a dllimport may refuse."""

    def entry(self, model, regs, stack):
        cand = regs["edi"]
        tup = model.u32(cand + 4) if cand else 0
        info = {"tuple": "0x%08X" % tup, "depth": stack[2], "depth_limit": stack[3], "budget": signed(stack[4]),
                "func_size": read_global(model, "_FuncSize"), "recursive_start": read_global(
                    model, "_InlRecursiveCycleStartDepth"), "globopt": read_global(model, "_Globopt_flag")}
        info.update(entry_info(model, callee_of_tuple(model.u32, tup)))
        return info, {"tuple": tup}

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


class GenericSiteDecoder(SiteDecoder):
    """Routines whose call tuple is in a register or stack slot named by REG."""

    def __init__(self, where):
        self.where = where

    def tuple_of(self, model, regs, stack):
        kind, index = self.where
        return regs[index] if kind == "reg" else stack[index]


# ------------------------------------------------------------ link-time conventions

# A function context (the argument of the dop2 passes): +0 its entry, +4 nonzero when the function has a
# hidden parameter ahead of the formals (it takes parameter number 1 in the dead map and the constant
# records), +8 -> +0 -> +0x1C the tuple list; the tuple of kind 0x18 holds the formal parameter leaves at
# +0x24 (leaf: +0 next, +8 kind byte, +0xA type word, +0x14 flag byte, +0x18 c2 symbol).
# Entry fields read here (pinned c2.dll): +0x20 & 0x1C the declared convention, +0x44 the bytes of stack
# parameters (MscProcessParams), +0x88 call-graph node (node+0x24: constant-parameter records), +0xB4 the
# custom (flex) convention: bit 0 = allowed (MdmAllowFlexParams), 3 bits per parameter at 3n+1 = an index into
# _MdmFlexParamMap (0 = stack), +0xB8 4 bits per parameter at 4n = XMM register - 0x53 (MdmAllocateXmmFlexParam),
# +0xBC the dead-parameter map (MscSetDeadParamMap: bit 0 = valid, bit k clear = parameter number k removed).
ENTRY_CONV, ENTRY_STACK_BYTES, ENTRY_FLEX, ENTRY_FLEX_XMM, ENTRY_DEAD = 0x20, 0x44, 0xB4, 0xB8, 0xBC
CONVENTIONS = {0x00: "cdecl", 0x04: "fastcall", 0x10: "stdcall", 0x14: "thiscall"}
CALLEE_POPS = {"fastcall", "stdcall", "thiscall"}
FLEX_REGS_FALLBACK = (0, 1, 2, 3, 7, 8, 6, 4)   # _MdmFlexParamMap: none, eax, ecx, edx, esi, edi, ebp, ebx
# The constant record (WpaWpaParamIsConst, WpaEqualConstInfo, WpaGenConstParamInfoUse): 24 bytes each,
# +0 parameter number (0 ends the array, 0xFF = dropped), +8 kind byte, +0x10/+0x14 value.
CONST_RECORD, CONST_KINDS = 24, {1: "int", 2: "float", 3: "function address", 4: "global address", 5: "global address"}


def u8(model, address):
    return model.bytes(address, 1)[0]


def u16(model, address):
    raw = model.bytes(address, 2)
    return raw[0] | raw[1] << 8


def entry_name(model, entry):
    return model.cstr(model.u32(entry + ENTRY_NAME), 512) if entry else None


def formal_leaves(model, ctx):
    """The formal parameter leaves of the function in context CTX, in order (MdmFlexParams' walk)."""
    tup = model.u32(model.u32(model.u32(model.u32(ctx + 8)) + 0x1C))
    for _ in range(100000):
        if not tup or u8(model, tup + 8) == 0x18:
            break
        tup = model.u32(tup)
    out, leaf = [], model.u32(tup + 0x24) if tup else 0
    while leaf and len(out) < 64:
        out.append(leaf)
        leaf = model.u32(leaf)
    return out


def formal_info(model, leaf):
    """One formal: its c2 symbol, front-end name and type word (high nibble = class, low 12 bits = bytes)."""
    kind, typ, sym = u8(model, leaf + 8), u16(model, leaf + 0xA), model.u32(leaf + 0x18)
    info = {"kind": kind, "type": "0x%04X" % typ, "size": typ & 0xFFF, "sym": sym}
    if sym and kind in (1, 2):
        base = model.u32(sym + 8) or sym
        info["base"] = base
        desc = model.u32(base)
        name = model.cstr(model.u32(desc + 4), 128) if desc else None
        if name:
            info["name"] = name
        tup = model.u32(sym + 0x14)
        info["skip"] = bool(tup and model.u32(tup + 4) == 0x2DC)   # MdmParamNum does not count these
    return info


class FlexAllowDecoder(c2_trace.Decoder):
    """MdmAllowFlexParams(ECX = context); returns 1 and sets entry+0xB4 = 1 when the function may get a
    custom convention. Refuses (in this order) without global optimization, under /clr:safe, entry+0x20 bits
    0x2400, entry+0x50 bit 4 (set by PogoInlineSplitDataSet), and when MscInlineAsmAssumesCallingConvention
    holds (a __fastcall/__thiscall function whose tuple list has an instruction tuple, i.e. __asm)."""

    def entry(self, model, regs, stack):
        entry = model.u32(regs["ecx"])
        return {"entry_name": entry_name(model, entry), "flags20": model.u32(entry + ENTRY_FLAGS20),
                "flags50": model.u32(entry + ENTRY_FLAGS50), "globopt": read_global(model, "_Globopt_flag"),
                "wvm_safe": read_global(model, "_FWvmSafe")}, None

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


class DeadMapDecoder(c2_trace.Decoder):
    """MscSetDeadParamMap([esp+4] = context); ret 4. Under the same gate as MdmAllowFlexParams it sets
    entry+0xBC to -1 and, walking the formals with k = 1 (2 with a hidden parameter), clears bit k of each
    formal whose symbol is unreferenced and unlinks it from the formal list; callers then drop that argument
    (MscRemoveDeadArguments). The entry logs every formal, the exit the map."""

    def entry(self, model, regs, stack):
        ctx = stack[1]
        entry = model.u32(ctx)
        formals = [formal_info(model, leaf) for leaf in formal_leaves(model, ctx)]
        return {"entry_name": entry_name(model, entry), "hidden": bool(model.u32(ctx + 4)),
                "formals": formals}, {"entry": entry}

    def exit(self, model, regs, state):
        return {"dead_map": model.u32(state["entry"] + ENTRY_DEAD)}


def const_records(model, entry):
    """The constant-parameter records of ENTRY (call-graph node +0x24)."""
    node = model.u32(entry + ENTRY_CGNODE)
    array = model.u32(node + 0x24) if node else 0
    out = []
    for i in range(64):
        if not array:
            break
        rec = array + CONST_RECORD * i
        number = u8(model, rec)
        if number == 0:
            break
        kind = u8(model, rec + 8)
        lo, hi = model.u32(rec + 0x10), model.u32(rec + 0x14)
        item = {"number": number, "kind": kind}
        if kind == 1:
            value = hi << 32 | lo
            item["value"] = value - (1 << 64) if value >> 63 else value
        elif kind == 2:
            item["value_ptr"] = "0x%08X" % lo
            try:
                item["value"] = struct.unpack("<d", model.bytes(lo, 8))[0]
            except (OSError, struct.error, TypeError):
                pass
        else:   # the address of a global: lo is its front-end descriptor (+4 decorated name)
            item["value_ptr"] = "0x%08X" % lo
            try:
                name = model.cstr(model.u32(lo + 4), 512) if lo > 0x10000 else None
                if name:
                    item["symbol"] = name
            except OSError:
                pass
        out.append(item)
    return out


class ConstParamDecoder(c2_trace.Decoder):
    """WpaGenConstParamInfoUse([esp+4] = context); ret 4. Uses the whole-program constant-parameter records
    (call-graph node +0x24) to replace the uses of each constant formal; it drops the records (0xFF) it
    cannot use and empties the array when MscAllowCallingConventionChange refuses and the parameters
    cannot be reordered. The exit logs the surviving records."""

    def entry(self, model, regs, stack):
        entry = model.u32(stack[1])
        return {"entry_name": entry_name(model, entry), "before": const_records(model, entry)}, {"entry": entry}

    def exit(self, model, regs, state):
        return {"after": const_records(model, state["entry"])}


class FlexDecoder(c2_trace.Decoder):
    """MdmFlexParams([esp+4] = context); ret 4. Runs after register allocation (dop2_CodegenUpdate) when
    entry+0xB4 bit 0 is set: each formal whose symbol was given a register keeps it, entry+0xB4/+0xB8
    record the register per parameter number (MdmParamNum: the position in the remaining formal list), and
    MscProcessParams recomputes entry+0x44 for the parameters left on the stack. Callers compiled later
    pass the arguments by that record. The exit logs the record and the formals it numbers."""

    def entry(self, model, regs, stack):
        ctx = stack[1]
        return {"entry_name": entry_name(model, model.u32(ctx))}, {"ctx": ctx}

    def exit(self, model, regs, state):
        ctx = state["ctx"]
        entry = model.u32(ctx)
        table = model.sym("_MdmFlexParamMap")
        flex_map = [model.u32(table + 4 * i) for i in range(8)] if table is not None else list(FLEX_REGS_FALLBACK)
        return {"flex": model.u32(entry + ENTRY_FLEX), "flex_xmm": model.u32(entry + ENTRY_FLEX_XMM),
                "conv": model.u32(entry + ENTRY_CONV) & 0x1C, "stack_bytes": model.u32(entry + ENTRY_STACK_BYTES),
                "flags20": model.u32(entry + ENTRY_FLAGS20), "flags50": model.u32(entry + ENTRY_FLAGS50),
                "hidden": bool(model.u32(ctx + 4)),
                "flex_map": [model.reg_name(r) if r else None for r in flex_map],
                "xmm_names": [model.reg_name(0x53 + i) for i in range(16)],
                "formals": [formal_info(model, leaf) for leaf in formal_leaves(model, ctx)]}


class RawConvGateDecoder(c2_trace.Decoder):
    """MscAllowCallingConventionChange(ECX = context): the convention gate (MdmAllowFlexParams' checks)."""

    def entry(self, model, regs, stack):
        return {"entry_name": entry_name(model, model.u32(regs["ecx"]))}, None

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


class RawRemoveDeadArgsDecoder(c2_trace.Decoder):
    """MscRemoveDeadArguments([esp+4] = context of the caller): drops the arguments of every direct call
    whose callee's dead map (entry+0xBC) clears them."""

    def entry(self, model, regs, stack):
        return {"entry_name": entry_name(model, model.u32(stack[1]))}, None

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


class RawParamIsDeadDecoder(c2_trace.Decoder):
    """MscParamIsDead(ESI = parameter number, [esp+4] = call tuple): the inliner's query of the callee's
    dead map (InlBenefit)."""

    def entry(self, model, regs, stack):
        callee = callee_of_tuple(model.u32, stack[1])
        return {"number": regs["esi"], "entry_name": entry_name(model, callee)}, None

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


def declared_location(conv, index, formal, formals):
    """Where the declared convention passes formal INDEX: thiscall `this` in ECX, fastcall the first two
    integer/pointer formals of at most 4 bytes in ECX and EDX, the rest on the stack."""
    if conv == "thiscall" and index == 0:
        return "ECX"
    if conv == "fastcall":
        small = [i for i, f in enumerate(formals) if (f.get("size") or 0) <= 4 and int(f.get("type") or "0", 16) >> 12 != 5]
        if index in small[:2]:
            return ("ECX", "EDX")[small.index(index)]
    return "stack"


def refusal_reason(ev):
    """Why MdmAllowFlexParams refused, from the fields it tests, in its order."""
    if not ev.get("globopt"):
        return "no global optimization (_Globopt_flag = 0)"
    if ev.get("wvm_safe"):
        return "/clr:safe (_FWvmSafe)"
    flags20, flags50 = ev.get("flags20", 0), ev.get("flags50", 0)
    if flags20 & 0x2000:
        return ("entry+0x20 bit 0x2000: referenced from outside the call graph (seen on /INCLUDE'd, virtual, "
                "member-pointer and initializer-table functions)")
    if flags20 & 0x400:
        return "entry+0x20 bit 0x400"
    if flags50 & 4:
        return "entry+0x50 bit 4: recursive (seen on every directly or mutually recursive function)"
    return "inline asm assumes the declared __fastcall/__thiscall convention (MscInlineAsmAssumesCallingConvention)"


def build_conventions(events, sites=()):
    """One record per compiled function from the CONV_BREAKS events (docs/c2-inline-trace.md)."""
    by_fn, order = {}, []
    for ev in events:
        if ev["break"] not in CONV_BREAKS:
            continue
        name = ev.get("entry_name") or ev.get("function")
        if name not in by_fn:
            by_fn[name] = {}
            order.append(name)
        by_fn[name].setdefault(ev["break"], []).append(ev)
    site_counts = {}
    for site in sites:
        counts = site_counts.setdefault(site.get("callee"), {"inlined": 0, "not_inlined": 0})
        counts["inlined" if site["decision"] == "inlined" else "not_inlined"] += 1
    return [convention(name, by_fn[name], site_counts.get(name)) for name in order]


def convention(name, evs, counts):
    flex = evs.get("MdmFlexParams", [{}])[-1]
    dead_ev = evs.get("MscSetDeadParamMap", [{}])[-1]
    allow = evs.get("MdmAllowFlexParams", [None])[-1]
    consts = evs.get("WpaGenConstParamInfoUse", [{}])[-1]
    hidden = bool(dead_ev.get("hidden", flex.get("hidden")))
    base = 2 if hidden else 1   # the parameter number of the first formal
    formals = dead_ev.get("formals") or flex.get("formals") or []
    dead_map = dead_ev.get("dead_map")
    dead_valid = dead_map is not None and bool(dead_map & 1)
    const_by_number = {c["number"]: c for c in consts.get("after", []) if c["number"] not in (0, 0xFF)}
    flex_word, xmm_word = flex.get("flex"), flex.get("flex_xmm", 0)
    allowed = bool(flex_word & 1) if flex_word is not None else bool(allow and allow.get("ret") == 1)
    flex_map = flex.get("flex_map") or []
    remaining, number = {}, 0   # MdmParamNum over the formals left after the dead ones were unlinked
    for f in flex.get("formals", []):
        if f.get("skip"):
            continue
        remaining[f.get("base") or f.get("sym")] = number
        number += 1
    conv = None
    if "conv" in flex:
        conv = CONVENTIONS.get(flex["conv"], "conv:0x%X" % flex["conv"])
    params = []
    for index, f in enumerate(formals):
        bit = index + base
        dead = dead_valid and bit < 32 and not dead_map & (1 << bit)
        const = const_by_number.get(bit)
        p = {"index": index, "name": f.get("name"), "type": f.get("type"), "size": f.get("size"),
             "dead": bool(dead), "const": None, "location": None}
        if const is not None:
            p["const"] = {k: const[k] for k in ("value", "symbol", "value_ptr") if k in const}
            p["const"]["kind"] = CONST_KINDS.get(const["kind"], const["kind"])
        key = f.get("base") or f.get("sym")
        if dead:
            p["location"] = "removed"
        elif key in remaining and flex_word is not None:
            n = remaining[key]
            field = (flex_word >> (3 * n + 1)) & 7 if allowed and 3 * n + 1 < 32 else 0
            xmm = (xmm_word >> (4 * n)) & 0xF if allowed and 4 * n < 32 else 0
            if field:
                p["location"] = (flex_map[field] or "?").upper() if field < len(flex_map) else "map%d" % field
            elif xmm:
                names = flex.get("xmm_names") or []
                p["location"] = (names[xmm] if xmm < len(names) else "reg%d" % (xmm + 0x53)).upper()
            else:
                p["location"] = "stack"
        if not allowed and not dead:   # the declared convention
            p["location"] = declared_location(conv, index, f, formals)
        params.append(p)
    rec = {"function": name, "custom": allowed, "declared": conv, "params": params,
           "stack_bytes": flex.get("stack_bytes"),
           "ret_pop": (flex.get("stack_bytes") if conv in CALLEE_POPS else 0) if conv else None,
           "hidden_param": hidden, "refused": None,
           "dead_map": None if dead_map is None else "0x%08X" % dead_map,
           "flex": None if flex_word is None else "0x%08X" % flex_word}
    if xmm_word:
        rec["flex_xmm"] = "0x%08X" % xmm_word
    if allow is not None and allow.get("ret") == 0:
        rec["refused"] = refusal_reason(allow)
    elif not allowed and allow is None:
        rec["refused"] = "MdmAllowFlexParams not called (no global optimization, or entry+0xB4 preset)"
    if counts:
        rec["sites"] = counts
        rec["inlined_everywhere"] = counts["not_inlined"] == 0
    return rec


def function_status(name, conventions, sites):
    """For --function NAME: whether the link kept the function NAME out of line."""
    calls = [s for s in sites if s.get("callee") == name]
    inlined = sum(1 for s in calls if s["decision"] == "inlined")
    if calls and inlined == len(calls):
        text = "inlined everywhere: no convention (%d call sites, all inlined)" % inlined
        rec = next((c for c in conventions if c["function"] == name), None)
        if rec is not None and rec["custom"]:
            text += "; c2 had recorded %s when it compiled the body ahead of its callers, unused" % (
                " ".join("%s=%s" % (p.get("name") or "#%d" % p["index"], p["location"]) for p in rec["params"]))
        return text
    if not any(c["function"] == name for c in conventions):
        return "not compiled by the link: no convention"
    return "out of line (%d of %d traced call sites inlined)" % (inlined, len(calls))


def format_conventions(conventions, limit=40):
    lines = []
    shown = [c for c in conventions if c["custom"] and any(
        p["location"] not in ("stack", None) or p["dead"] or p["const"] is not None for p in c["params"])]
    for c in shown[:limit]:
        parts = []
        for p in c["params"]:
            text = "%s=%s" % (p.get("name") or "#%d" % p["index"], p["location"] or "?")
            if p["const"] is not None:
                text += "(const %s)" % p["const"].get("value", p["const"].get("symbol"))
            parts.append(text)
        lines.append("%-56s %-8s ret %-3s %s" % (c["function"][:56], c["declared"], c["ret_pop"], " ".join(parts)))
    if len(shown) > limit:
        lines.append("... %d more" % (len(shown) - limit))
    return lines


class CollectInfoDecoder(c2_trace.Decoder):
    """InlCollectInfo: runs after a function is compiled and records what a
    later caller's decision reads; the exit logs the function's entry fields."""

    def entry(self, model, regs, stack):
        return {}, None

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


CAPTURED_CONSTS = {}


class CallGraphDecoder(c2_trace.Decoder):
    """InlCallGraphDecision([esp+4]=callee's call-graph node (+4 callee entry),
    [esp+8]=candidate (+4 call tuple), [esp+0xC]=caller context, [esp+0x10]);
    ret 0x10. The cost model; its internal values come from the probes."""

    def entry(self, model, regs, stack):
        node, cand = stack[1], stack[2]
        tup = model.u32(cand + 4) if cand else 0
        callee = model.u32(node + 4) if node else 0
        info = {"tuple": "0x%08X" % tup}
        if callee:
            info.update({"cg_size": signed(model.u32(callee + 0x68)), "cg_callsites": model.u32(callee + 0x90),
                         "cg_size60": model.u32(callee + 0x60)})
        info["inl_func_size"] = read_global(model, "_InlFuncSize")
        if not CAPTURED_CONSTS:   # the constants in force (InlInitLtcgSetting sets them under /LTCG)
            CAPTURED_CONSTS.update(read_consts(model))
            CAPTURED_CONSTS["_Ltcg"] = read_global(model, "_Ltcg")
        if cand:   # the call block's estimated frequency, 64-bit, 100000000 = once per caller entry
            info["site_weight"] = model.u32(cand + 0x10) | (model.u32(cand + 0x14) << 32)
        return info, {"tuple": tup}

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


def _benefit(model, ptr):
    """InlBenefit's record: +0 size credit (capped at the callee size), +4,
    +0xC fold-compare counts, +8 argument/setup cost, +0x10 calls through a
    direct entry, +0x14 address arguments, +0x18 constant arguments, +0x1C
    calls without side-effect information."""
    names = ("credit", "fold_cmps", "arg_cost", "fold_loop_cmps", "direct_calls", "addr_args", "const_args",
             "opaque_calls")
    return {n: signed(model.u32(ptr + 4 * i)) for i, n in enumerate(names)}


# Probes: instruction addresses inside InlCallGraphDecision (offsets from its
# entry, pinned c2.dll) where the cost model's values sit in registers.
PROBES = (
    ("limit", 0x88, "cost starts at the callee size: edi = size, compared with SizeLimit",
     lambda m, r: {"size": signed(r["edi"])}),
    ("benefit", 0xD9, "InlBenefit's record in eax (0xD3, the return address, is InlBenefit's return breakpoint); "
     "esi = the large-caller penalty added to the cost",
     lambda m, r: dict(_benefit(m, r["eax"]), caller_penalty=signed(r["esi"]))),
    ("speed_cap", 0x359, "speed path: cost (edi) > 450 refuses",
     lambda m, r: {"cost": signed(r["edi"]), "cap": 450}),
    ("speed_small", 0x418, "speed path: cost (ecx) < SizeLimit + 5 accepts (InlBadCandidate permitting)",
     lambda m, r: {"cost": signed(r["ecx"]), "limit": signed(r["edx"])}),
    ("speed_loop", 0x47F, "speed path: eax = loop term (callee's max loop share x size / 254 / c58) just added to edi",
     lambda m, r: {"cost": signed(r["edi"]), "loop_term": signed(r["eax"])}),
    ("speed_ratio", 0x542, "speed path: weighted cost (eax) < SpeedLimit accepts",
     lambda m, r: {"weighted": signed(r["eax"]), "limit": signed(m.u32(m.sym("_InlCurConsts") + 4))}),
    ("size_end", 0x575, "size path: cost (edi) < SizeLimit accepts",
     lambda m, r: {"cost": signed(r["edi"]), "limit": signed(m.u32(m.sym("_InlCurConsts")))}),
)


class ProbeDecoder(c2_trace.Decoder):
    def __init__(self, label, read):
        self.label, self.read = label, read

    def entry(self, model, regs, stack):
        return self.read(model, regs), None


# Where each site routine holds its call tuple (the decoders above), for --function's callee match.
SITE_TUPLE = {
    "InlCallTupleIsCandidate": lambda m, r, s: s[1],
    "ConsiderCandidate": lambda m, r, s: m.u32(s[1] + 4) if s[1] else 0,
    "ShouldInlineCallTuple": lambda m, r, s: m.u32(r["edi"] + 4) if r["edi"] else 0,
    "InlCallGraphDecision": lambda m, r, s: m.u32(s[2] + 4) if s[2] else 0,
    "InlBenefit": lambda m, r, s: r["ecx"], "InlBadCandidate": lambda m, r, s: r["eax"],
    "ShouldInlineInlinee": lambda m, r, s: r["edx"], "InlineInlinee": lambda m, r, s: r["ecx"],
    REGUSE_CALL: lambda m, r, s: s[1],
}


class InlineTracer(c2_trace.Tracer):
    """c2_trace's Tracer; probe breakpoints (mid-function) log registers and
    plant no return breakpoint. --function keeps the sites compiled in a
    matching function and the sites whose callee matches; the convention
    routines are always logged and do not count against --max-events.
    Events lost to --max-events are counted per routine (dropped_by)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dropped_by, self.cg_wanted = {}, {}

    def _wanted_by_callee(self, dbg, model, regs, tid, name):
        if self.filter is None:
            return False
        if name.startswith("probe:"):
            return self.cg_wanted.get(tid, False)
        if name not in SITE_TUPLE:
            return False
        try:
            function = self.current_function(model)
            if function is not None and self.filter in function:
                wanted = False
            else:
                stack = [dbg.read_u32(regs["esp"] + 4 * i) for i in range(4)]
                callee = entry_name(model, callee_of_tuple(model.u32, SITE_TUPLE[name](model, regs, stack)))
                wanted = bool(callee and self.filter in callee)
        except (OSError, TypeError):
            wanted = False
        if name == "InlCallGraphDecision":
            self.cg_wanted[tid] = wanted
        return wanted

    def _on_entry(self, dbg, model, regs, tid, address, bp, bps, pending):
        name = c2_trace.plain_name(bp["entry"])
        conv = name in CONV_BREAKS or name == REGUSE_RECORD
        unfiltered = conv or self._wanted_by_callee(dbg, model, regs, tid, name)
        saved = self.entry_only, self.filter, self.max_events
        if name.startswith("probe:"):
            self.entry_only = True
        if unfiltered:
            self.filter = None
        if conv:
            self.max_events = float("inf")
        before = self.dropped
        try:
            return super()._on_entry(dbg, model, regs, tid, address, bp, bps, pending)
        finally:
            self.entry_only, self.filter, self.max_events = saved
            if self.dropped > before:
                self.dropped_by[name] = self.dropped_by.get(name, 0) + self.dropped - before


def probe_breaks(table):
    base = c2_trace.resolve_name("InlCallGraphDecision", table)[1]
    return [("probe:" + label, base + offset) for label, offset, _, _ in PROBES]


def install_decoders():
    """Register this tracer's decoders in c2_trace's table (at run time only)."""
    for label, _, _, read in PROBES:
        c2_trace.DECODERS["probe:" + label] = (lambda lab=label, rd=read: ProbeDecoder(lab, rd))
    c2_trace.DECODERS.update({
        "InlCallTupleIsCandidate": IsCandidateDecoder,
        "InlMightInlineEntry": MightInlineDecoder,
        "ConsiderCandidate": ConsiderDecoder,
        "ShouldInlineCallTuple": ShouldCallTupleDecoder,
        "InlCallGraphDecision": CallGraphDecoder,
        "InlBenefit": lambda: GenericSiteDecoder(("reg", "ecx")),
        "InlBadCandidate": lambda: GenericSiteDecoder(("reg", "eax")),
        "ShouldInlineInlinee": lambda: GenericSiteDecoder(("reg", "edx")),
        "InlineInlinee": lambda: GenericSiteDecoder(("reg", "ecx")),
        "InlCollectInfo": CollectInfoDecoder,
    })
    c2_trace.DECODERS.update({
        "MscAllowCallingConventionChange": RawConvGateDecoder,
        "MscRemoveDeadArguments": RawRemoveDeadArgsDecoder,
        "MscParamIsDead": RawParamIsDeadDecoder,
        "MdmAllowFlexParams": FlexAllowDecoder,
        "MscSetDeadParamMap": DeadMapDecoder,
        "WpaGenConstParamInfoUse": ConstParamDecoder,
        "MdmFlexParams": FlexDecoder,
    })


# ------------------------------------------------------------ site assembly

def build_sites(events):
    """Group raw events into call sites. A site starts at InlCallTupleIsCandidate
    (one per call tuple GetInlineCandidates looks at) and collects every later
    event that names the same tuple while the same function is compiled; probe
    events (no tuple) belong to the InlCallGraphDecision running on that thread."""
    sites, open_sites, current = [], {}, {}
    for ev in events:
        name = ev["break"]
        if name.startswith("probe:"):
            site = current.get(ev.get("tid"))
            if site is not None:
                site["events"].append(ev)
            continue
        key = (ev.get("function"), ev.get("tuple"))
        if name == "InlCallTupleIsCandidate":
            site = {"caller": ev.get("function"), "tuple": ev.get("tuple"), "events": []}
            sites.append(site)
            open_sites[key] = site
        site = open_sites.get(key)
        if site is not None:
            site["events"].append(ev)
            if name == "InlCallGraphDecision":
                current[ev.get("tid")] = site
    return [decide(site) for site in sites]


SKIP_FIELDS = ("seq", "break", "function", "tid", "depth", "tuple", "eax", "ecx", "edx", "stack", "ret")


def decide(site):
    evs = site["events"]
    first = evs[0]
    out = {"caller": site["caller"], "callee": first.get("callee"), "callee_size": first.get("callee_size"),
           "callee_traits": first.get("callee_traits"), "callee_flags": first.get("callee_flags")}
    by = {}
    for ev in evs:
        by.setdefault(ev["break"], []).append(ev)

    def ret(name):
        got = by.get(name)
        return got[-1].get("ret") if got else None

    should = by.get("ShouldInlineCallTuple", [None])[-1]
    if should:
        out["depth"] = should.get("depth")
        out.update({k: should.get(k) for k in ("depth_limit", "budget", "func_size") if should.get(k) is not None})
    numbers = {}
    for name in ("InlCallGraphDecision",) + tuple("probe:" + p[0] for p in PROBES):
        for ev in by.get(name, []):
            numbers.update({"%s.%s" % (name.replace("probe:", ""), k): v for k, v in ev.items()
                            if k not in SKIP_FIELDS})
    for name in ("InlCallGraphDecision", "InlBadCandidate", "ShouldInlineInlinee", "InlineeIsTooBig"):
        if name in by:
            numbers[name + ".ret"] = ret(name)
    if numbers:
        out["numbers"] = numbers
    if ret("InlineInlinee") == 1:
        out["decision"] = "inlined"
        out["rule"] = accept_rule(first, by, numbers)
    else:
        out["decision"] = "not-inlined"
        out["rule"] = refusal_rule(first, by, ret, numbers)
    return out


def accept_rule(first, by, numbers):
    traits = set(first.get("callee_traits") or [])
    if "forceinline" in traits and "InlCallGraphDecision" not in by:
        return "forceinline: accepted without the cost model (ShouldInlineCallTuple)"
    if "InlCallGraphDecision" not in by:
        return "no call graph: size within budget (ShouldInlineCallTuple)"
    if "speed_small.cost" in numbers and numbers["speed_small.cost"] < numbers["speed_small.limit"]:
        return "speed: cost %d < SizeLimit+5 = %d" % (numbers["speed_small.cost"], numbers["speed_small.limit"])
    if "speed_ratio.weighted" in numbers and numbers["speed_ratio.weighted"] < numbers["speed_ratio.limit"]:
        return "speed: weighted cost %d < SpeedLimit %d" % (numbers["speed_ratio.weighted"],
                                                            numbers["speed_ratio.limit"])
    if "size_end.cost" in numbers and numbers["size_end.cost"] < numbers["size_end.limit"]:
        return "size: cost %d < SizeLimit %d" % (numbers["size_end.cost"], numbers["size_end.limit"])
    if "limit.size" in numbers:
        return "accepted (InlCallGraphDecision)"
    return "accepted before the cost model (InlCallGraphDecision: __forceinline callee)"


def refusal_rule(first, by, ret, numbers):
    traits = set(first.get("callee_traits") or [])
    if ret("InlCallTupleIsCandidate") == 0:
        if "on-inline-stack" in traits:
            return "recursion: the callee is being compiled or inlined here (entry+0x50 bit 0x10, DoInline)"
        if "inlinable" not in traits:
            return ("not-inlinable: entry+0x50 lacks 0x40 (__declspec(noinline), /Ob1 without inline, /Ob0) "
                    "(InlMightInlineEntry)")
        if "eh" in traits and first.get("globopt") and "forceinline" not in traits:
            return "eh-globopt: callee has EH state (0x200) under global opts (InlCallTupleIsCandidate)"
        if not first.get("speed") and (first.get("callee_size") or 0) >= (first.get("max_inlinee_size") or 0):
            return "size >= _MaxInlineeSize without /Ot (InlCallTupleIsCandidate)"
        if first.get("tuple_flags30"):
            return "call tuple flagged no-inline (+0x30 bit 0)"
        return "not a candidate (InlCallTupleIsCandidate)"
    if "ShouldInlineCallTuple" not in by:
        return "never considered (candidate dropped before ShouldInlineCallTuple)"
    if ret("ShouldInlineCallTuple") == 0:
        should = by["ShouldInlineCallTuple"][-1]
        if should.get("depth_limit") not in (None, 0xFF) and (should.get("depth") or 0) > should["depth_limit"]:
            return "depth %s > inline_depth %s (ShouldInlineCallTuple)" % (should.get("depth"),
                                                                           should["depth_limit"])
        if "InlCallGraphDecision" in by:
            if "speed_cap.cost" in numbers and numbers["speed_cap.cost"] > 450 and \
                    "speed_small.cost" not in numbers:
                return "speed: cost %d > 450 (InlCallGraphDecision)" % numbers["speed_cap.cost"]
            if "speed_small.cost" in numbers and numbers["speed_small.cost"] < numbers["speed_small.limit"]:
                return "speed: cost %d < SizeLimit+5 but InlBadCandidate refused" % numbers["speed_small.cost"]
            if "speed_ratio.weighted" in numbers:
                return "speed: weighted cost %d >= SpeedLimit %d (InlCallGraphDecision)" % (
                    numbers["speed_ratio.weighted"], numbers["speed_ratio.limit"])
            if "size_end.cost" in numbers:
                return "size: cost %d >= SizeLimit %d (InlCallGraphDecision)" % (
                    numbers["size_end.cost"], numbers["size_end.limit"])
            if "speed_small.cost" in numbers:
                return "speed: no profile count, refused (InlCallGraphDecision)"
            return "call-graph decision refused before the cost model (callee too large / cycle)"
        return "no call graph: _FuncSize > 35000 or size > budget and > 40 (ShouldInlineCallTuple)"
    if ret("ShouldInlineInlinee") == 0:
        return "ShouldInlineInlinee refused"
    if ret("InlineeIsTooBig") == 1:
        return "InlineeIsTooBig"
    return "refused after ShouldInlineCallTuple (GetInlinee/PrepareInlinee)"


# ------------------------------------------------------------ driver

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--link-rsp", type=Path, help="trace link.exe @RSP (a /LTCG link) instead of cl.exe")
    parser.add_argument("--linker", type=Path, help="the link.exe to run with --link-rsp (default: the "
                        "toolchain's); it must load the pinned c2.dll")
    parser.add_argument("--timeout", type=int, default=600, help="seconds before the trace is abandoned")
    parser.add_argument("--flags", default="/O2", help="cl options (one string)")
    parser.add_argument("-I", "--include", action="append", default=[], type=Path)
    parser.add_argument("--function", help="only sites in functions, or of callees, whose decorated name "
                        "contains this (the --link-rsp conventions always cover every function)")
    parser.add_argument("--out", type=Path, required=True, help="JSONL, one call site per line")
    parser.add_argument("--raw", type=Path, help="also write the raw routine events (JSONL)")
    parser.add_argument("--toolchain", default="sp1")
    parser.add_argument("--max-events", type=int, default=2000000, help="cap on the logged inliner events "
                        "(the convention events are not capped); events over it are counted as dropped")
    args = parser.parse_args(argv)
    if (args.source is None) == (args.link_rsp is None):
        parser.error("give one of --source and --link-rsp")
    if os.name != "nt":
        print("c2_inline_trace: requires Windows", file=sys.stderr)
        return 2
    import probe_toolchain
    install_decoders()
    try:
        toolchain = probe_toolchain.load_toolchain(args.toolchain)
        probe_toolchain.verify_toolchain(toolchain)
        work = (args.out.parent / (args.out.stem + ".work")).resolve()
        work.mkdir(parents=True, exist_ok=True)
        data = c2_trace.load_symbols(ROOT / "build/c2-trace")
        table = c2_trace.symbol_table(data["rows"])
        breaks = [c2_trace.resolve_name(name, table) for name in BREAKS]
        breaks += probe_breaks(table)
        if args.link_rsp:
            breaks += [c2_trace.resolve_name(name, table) for name in LTCG_BREAKS + CONV_BREAKS + REGUSE_BREAKS]
        tracer = InlineTracer(table, data["image_base"], breaks, args.function, (), args.max_events)
        env = probe_toolchain.toolchain_environment(toolchain)
        if args.link_rsp:
            linker = args.linker or Path(toolchain["bin"]) / "link.exe"
            rsp = args.link_rsp.resolve()
            command, work = [str(linker), "@" + str(rsp)], rsp.parent
        else:
            command = c2_trace.compile_command(toolchain, args.source, args.flags.split(), args.include, work)
            if args.include:
                env["INCLUDE"] = os.pathsep.join([*map(str, args.include), env["INCLUDE"]])
        returncode, log_path = tracer.run(command, work, env, timeout=args.timeout)
    except (c2_trace.TraceError, OSError, ValueError, KeyError) as error:
        print("c2_inline_trace: " + str(error), file=sys.stderr)
        return 1
    sites = build_sites([e for e in tracer.events if e["break"] not in LTCG_BREAKS + CONV_BREAKS + REGUSE_BREAKS])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as stream:
        for site in sites:
            stream.write(json.dumps(site, sort_keys=True) + "\n")
    if args.raw:
        with args.raw.open("w", encoding="utf-8") as stream:
            for event in tracer.events:
                stream.write(json.dumps(event, sort_keys=True) + "\n")
    extras = args.out.with_suffix(".extra.json")
    params = [{k: e.get(k) for k in ("break", "function", "entry_name", "number", "ret") if k in e}
              for e in tracer.events if e["break"] in LTCG_BREAKS]
    extra = {"consts": CAPTURED_CONSTS, "param_passes": params, "dropped": tracer.dropped,
             "dropped_by": tracer.dropped_by, "events": len(tracer.events)}
    conventions = []
    if args.link_rsp:
        conventions = build_conventions(tracer.events, sites)
        extra["conventions"] = conventions
        extra["reg_use"] = build_reg_use(tracer.events, args.function)
        if args.function:
            extra["function_status"] = {name: function_status(name, conventions, sites)
                                        for name in matching_names(args.function, conventions, sites)}
    with extras.open("w", encoding="utf-8") as stream:
        json.dump(extra, stream, indent=1, sort_keys=True)
    print("%s exit %d; %d call sites -> %s (output: %s; constants, conventions and parameter passes: %s)" % (
        "link.exe" if args.link_rsp else "cl.exe", returncode, len(sites), args.out, log_path, extras))
    if tracer.dropped:
        print("WARNING: %d events dropped over --max-events %d: %s" % (
            tracer.dropped, args.max_events, ", ".join("%s %d" % kv for kv in sorted(tracer.dropped_by.items()))))
    for line in format_sites(sites):
        print(line)
    if args.link_rsp:
        custom = sum(1 for c in conventions if c["custom"])
        print("conventions: %d functions compiled, %d with a custom convention, %d refused; registers, dead and "
              "constant parameters:" % (len(conventions), custom, sum(1 for c in conventions if c["refused"])))
        for line in format_conventions(conventions):
            print(line)
        for name, status in extra.get("function_status", {}).items():
            print("%s: %s" % (name, status))
        for line in format_reg_use(extra["reg_use"]):
            print(line)
    return 0 if returncode == 0 else 3


REGUSE_CALL_KEYS = ("function", "callee", "verdict", "summary", "callee_flags20", "callee_flags37", "node_is_entry")
REGUSE_RECORD_KEYS = ("skip", "flags20", "flags37", "comdat_selection", "flags20_after", "cg_node",
                      "node_is_entry", "stored", "summary")


def build_reg_use(events, function_filter=None):
    """extra.json `reg_use`: `summaries` (per function, in compile order: what MscRecordInterProcRegInfo
    stored; with --function only the matching functions and the callees of the kept calls) and `calls`
    (each LoAddCallScratchRegs: the caller, the callee and whether the callee's summary was used)."""
    calls = [{k: e[k] for k in REGUSE_CALL_KEYS if k in e} for e in events if e["break"] == REGUSE_CALL]
    wanted = {c.get("callee") for c in calls} | {c.get("function") for c in calls}
    summaries, order = {}, 0
    for e in events:
        if e["break"] != REGUSE_RECORD:
            continue
        order += 1
        name = e.get("entry_name")
        if function_filter and name not in wanted and not (name and function_filter in name):
            continue
        record = {k: e[k] for k in REGUSE_RECORD_KEYS if k in e}
        record["order"] = order
        summaries[name] = record
    return {"summaries": summaries, "calls": calls}


def format_reg_use(reg_use, limit=40):
    """One line per (caller, callee, verdict) with its count, then the callees' summaries."""
    counts = {}
    for call in reg_use["calls"]:
        key = (call.get("function"), call.get("callee"), call.get("verdict"))
        counts[key] = counts.get(key, 0) + 1
    lines = ["register use at calls (LoAddCallScratchRegs): %d calls" % len(reg_use["calls"])] if counts else []
    for (function, callee, verdict), count in list(counts.items())[:limit]:
        lines.append("  %s -> %s x%d: %s" % (function, callee, count, verdict))
    callees = {c.get("callee") for c in reg_use["calls"]}
    for name, record in reg_use["summaries"].items():
        if name in callees:
            lines.append("  summary of %s (compiled #%d): %s%s" % (
                name, record["order"], ", ".join(record.get("summary") or []) or "none stored",
                " (skipped: %s)" % record["skip"] if record.get("skip") else ""))
    return lines


def matching_names(text, conventions, sites):
    """The decorated names --function TEXT names: itself when it is a full name, else every compiled or
    called function containing it (at most 20)."""
    names = {c["function"] for c in conventions} | {s.get("callee") for s in sites}
    names.discard(None)
    if text in names or text.startswith("?"):
        return [text]
    return sorted(n for n in names if text in n)[:20]


def format_sites(sites, limit=60):
    lines = []
    for site in sites[:limit]:
        lines.append("%-28s %-28s d%s size=%-4s %-11s %s" % (
            (site.get("caller") or "?")[:28], (site.get("callee") or "?")[:28], site.get("depth", "-"),
            site.get("callee_size"), site["decision"], site["rule"]))
    if len(sites) > limit:
        lines.append("... %d more sites" % (len(sites) - limit))
    return lines


if __name__ == "__main__":
    raise SystemExit(main())
