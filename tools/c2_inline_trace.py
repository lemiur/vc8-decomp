"""Trace c2.dll's inlining decisions while cl.exe compiles one source file.

Usage:
  python tools/c2_inline_trace.py --source X.cpp --flags="/O2 /EHsc" [-I DIR] [--function NAME]
         --out trace.jsonl [--raw raw.jsonl]
  python tools/c2_inline_trace.py --link-rsp LINK.rsp [--linker link.exe] [--function NAME]
         --out trace.jsonl [--raw raw.jsonl]

With --link-rsp the traced process is link.exe on that response file (a /LTCG
link of /GL objects): link.exe loads the same c2.dll and runs the link-time
code generator in-process, so the same breakpoints see the whole-program
inliner. The response file's folder is the working directory.

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
# The link-time code generator's whole-program parameter passes (misc.obj, cgi): logged with --link-rsp
# as the function being compiled, ECX/EDX and the return value; their arguments are not decoded further.
LTCG_BREAKS = ("MscAllowCallingConventionChange", "MscSetDeadParamMap", "MscRemoveDeadArguments",
               "MscParamIsDead", "CgiRemoveConstArg")


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


class FastcallDecoder(c2_trace.Decoder):
    """A __fastcall routine (ECX, EDX): both arguments raw and, when ECX names a c2 entry (+4 decorated
    name), that name; the exit logs ret."""

    def entry(self, model, regs, stack):
        info = {"ecx": "0x%08X" % regs["ecx"], "edx": "0x%08X" % regs["edx"]}
        try:
            name = model.cstr(model.u32(regs["ecx"] + ENTRY_NAME), 512) if regs["ecx"] > 0x10000 else None
        except Exception:
            name = None
        if name and name[:1] in "?_@":
            info["entry_name"] = name
        return info, None

    def exit(self, model, regs, state):
        return {"ret": signed(regs["eax"])}


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


class InlineTracer(c2_trace.Tracer):
    """c2_trace's Tracer; probe breakpoints (mid-function) log registers and
    plant no return breakpoint."""

    def _on_entry(self, dbg, model, regs, tid, address, bp, bps, pending):
        if not bp["entry"].startswith("probe:"):
            return super()._on_entry(dbg, model, regs, tid, address, bp, bps, pending)
        saved, self.entry_only = self.entry_only, True
        try:
            return super()._on_entry(dbg, model, regs, tid, address, bp, bps, pending)
        finally:
            self.entry_only = saved


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
    for name in LTCG_BREAKS:
        c2_trace.DECODERS[name] = FastcallDecoder


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
    parser.add_argument("--function", help="only sites in functions whose decorated name contains this")
    parser.add_argument("--out", type=Path, required=True, help="JSONL, one call site per line")
    parser.add_argument("--raw", type=Path, help="also write the raw routine events (JSONL)")
    parser.add_argument("--toolchain", default="sp1")
    parser.add_argument("--max-events", type=int, default=200000)
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
            breaks += [c2_trace.resolve_name(name, table) for name in LTCG_BREAKS]
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
    sites = build_sites(tracer.events)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as stream:
        for site in sites:
            stream.write(json.dumps(site, sort_keys=True) + "\n")
    if args.raw:
        with args.raw.open("w", encoding="utf-8") as stream:
            for event in tracer.events:
                stream.write(json.dumps(event, sort_keys=True) + "\n")
    extras = args.out.with_suffix(".extra.json")
    params = [{k: e.get(k) for k in ("break", "function", "entry_name", "ecx", "edx", "ret") if k in e}
              for e in tracer.events if e["break"] in LTCG_BREAKS]
    with extras.open("w", encoding="utf-8") as stream:
        json.dump({"consts": CAPTURED_CONSTS, "param_passes": params, "dropped": tracer.dropped}, stream,
                  indent=1, sort_keys=True)
    print("%s exit %d; %d call sites -> %s (output: %s; constants and parameter passes: %s)" % (
        "link.exe" if args.link_rsp else "cl.exe", returncode, len(sites), args.out, log_path, extras))
    for line in format_sites(sites):
        print(line)
    return 0 if returncode == 0 else 3


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
