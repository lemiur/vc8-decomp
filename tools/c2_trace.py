"""Trace c2.dll decisions while cl.exe compiles one source file.

Usage:
  python tools/c2_trace.py --source X.cpp --flags "/O2 /Oy" --out trace.jsonl
         [--break ChoosePhysReg[,InlBenefit]] [--function NAME] [--dump EXPR:COUNT]
         [--include DIR] [--summary-only]

cl.exe runs under the Windows debug API (it loads c1xx.dll and c2.dll in its
own process). Public c2.pdb symbols name the breakpoints; an int3 is written at
each requested function entry and at each pending return address, the original
byte is restored and the thread single-stepped before re-arming. Events go to
a JSONL file, one object per call (entry and return values merged), and a
short summary is printed. Decoders for ChoosePhysReg and OrderGlobregs read
c2's own data structures; the inliner predicates log a signed EAX; any other
public function gets a generic register/stack record. Layouts the decoders
read were established from c2.dll disassembly (docs/c2-trace.md); they are not
public API and only hold for the pinned 14.00.50727.762 c2.dll.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "config/project.json"

STATUS_BREAKPOINT = 0x80000003
STATUS_SINGLE_STEP = 0x80000004
STATUS_WX86_SINGLE_STEP = 0x4000001E
STATUS_WX86_BREAKPOINT = 0x4000001F
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
REGS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip")
DEFAULT_BREAKS = ("ChoosePhysReg",)


class TraceError(RuntimeError):
    """Configuration, symbol or debugger failure."""


# ---------------------------------------------------------------- symbols

def plain_name(name):
    """'@ChoosePhysReg@12' / '_fatal' / '?F@@YAXXZ' -> comparable plain name."""
    match = re.fullmatch(r"[@_]?([A-Za-z_$][\w$]*)(@\d+)?", name)
    return match.group(1) if match else name


def symbol_table(rows):
    """rows: dicts with name and va. Returns (by_name, by_plain, by_va)."""
    by_name, by_plain, by_va = {}, {}, {}
    for row in rows:
        if row.get("va") is None:
            continue
        va = int(row["va"])
        by_name[row["name"]] = va
        by_plain.setdefault(plain_name(row["name"]), []).append((row["name"], va))
        by_va.setdefault(va, row["name"])
    return by_name, by_plain, by_va


def resolve_name(name, table):
    by_name, by_plain, _ = table
    if name in by_name:
        return name, by_name[name]
    hits = by_plain.get(plain_name(name), [])
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise TraceError("no c2.dll public symbol named " + name)
    raise TraceError("ambiguous c2.dll symbol %s: %s" % (name, ", ".join(h[0] for h in hits)))


def c2_inputs(project_path=PROJECT):
    project = json.loads(Path(project_path).read_text(encoding="utf-8"))
    binary = Path(project["toolchain_root"]) / "bin" / "c2.dll"
    import symbols
    rsds = symbols.read_pe(binary.read_bytes())["rsds"]
    pdb_name = rsds["path"].replace("\\", "/").split("/")[-1]
    store = Path(project.get("symbols_root") or Path(project.get("primary_checkout") or ROOT) / "symbols")
    pdb = store / pdb_name / (rsds["guid"] + format(rsds["age"], "X")) / pdb_name
    return binary, pdb


def load_symbols(cache_dir):
    """Public c2 symbols (identity-checked by symbols.extract), cached by PDB hash."""
    import symbols
    binary, pdb = c2_inputs()
    cache = Path(cache_dir) / "c2-publics.json"
    key = "%s:%d:%d" % (pdb, pdb.stat().st_size, binary.stat().st_size)
    if cache.is_file():
        data = json.loads(cache.read_text(encoding="utf-8"))
        if data.get("key") == key:
            return data
    result = symbols.extract(binary, pdb)
    data = {"key": key, "image_base": result["identity"]["image_base"],
            "binary_sha256": result["identity"]["binary_sha256"],
            "rows": [{"name": r["name"], "va": r["va"]} for r in result["functions"] + result["data"]]}
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(data), encoding="utf-8")
    return data


# ------------------------------------------------------- dump expressions

TOKEN = re.compile(r"\s*(0x[0-9A-Fa-f]+|\d+|[A-Za-z_@?$][\w@?$]*|[\[\]+\-*])")


def parse_expr(text):
    """'[[esp+4]+0x1c]' -> nested tuples. Grammar: sum of terms; term =
    number | register | c2 symbol | [expr]."""
    tokens = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        match = TOKEN.match(text, pos)
        if not match:
            raise TraceError("bad expression near: " + text[pos:])
        tokens.append(match.group(1))
        pos = match.end()

    def expr(i):
        node, i = term(i)
        while i < len(tokens) and tokens[i] in "+-":
            op = tokens[i]
            rhs, i = term(i + 1)
            node = (op, node, rhs)
        return node, i

    def term(i):
        if i >= len(tokens):
            raise TraceError("truncated expression: " + text)
        tok = tokens[i]
        if tok == "[":
            node, i = expr(i + 1)
            if i >= len(tokens) or tokens[i] != "]":
                raise TraceError("unbalanced [ in " + text)
            return ("deref", node), i + 1
        if re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", tok):
            return ("num", int(tok, 0)), i + 1
        if tok in "[]+-*":
            raise TraceError("unexpected %r in %s" % (tok, text))
        return ("name", tok), i + 1

    node, i = expr(0)
    if i != len(tokens):
        raise TraceError("trailing tokens in " + text)
    return node


def eval_expr(node, regs, read_u32, symbol_va):
    kind = node[0]
    if kind == "num":
        return node[1]
    if kind == "name":
        if node[1].lower() in regs:
            return regs[node[1].lower()]
        return symbol_va(node[1])
    if kind == "deref":
        return read_u32(eval_expr(node[1], regs, read_u32, symbol_va))
    lhs = eval_expr(node[1], regs, read_u32, symbol_va)
    rhs = eval_expr(node[2], regs, read_u32, symbol_va)
    return (lhs + rhs if kind == "+" else lhs - rhs) & 0xFFFFFFFF


def parse_dump(spec):
    """'EXPR:COUNT' -> (text, node, count dwords)."""
    expr, _, count = spec.rpartition(":")
    if not expr or not count.isdigit():
        expr, count = spec, "8"
    return spec, parse_expr(expr), int(count)


# -------------------------------------------------------- c2 structures

def read_sparse_bv(read_u32, header, limit=4096):
    """c2's sparse bit vector: header -> first node; node = {base, lo32, hi32,
    next}. Returns the set bit indices in node order (SbvNext's order)."""
    if not header:
        return []
    bits = []
    node = read_u32(header)
    seen = 0
    while node and seen < limit:
        base, lo, hi, nxt = (read_u32(node + k) for k in (0, 4, 8, 12))
        word = lo | (hi << 32)
        bits.extend(base + b for b in range(64) if word >> b & 1)
        node = nxt
        seen += 1
    return bits


class C2Model:
    """Typed reads of c2 globals at a stop. read_u32/read_bytes are callables
    on target memory; sym maps plain names to VAs in the loaded c2.dll."""

    REGSYM_SIZE = 0x60   # _RegSym entry stride (ChoosePhysReg: lea edx,[ebx*3]; shl edx,5)
    MAX_ORDER = 32

    def __init__(self, read_u32, read_bytes, sym):
        self.u32, self.bytes, self.sym = read_u32, read_bytes, sym
        self._reg_names = {}

    def cstr(self, address, limit=96):
        if not address:
            return None
        try:
            raw = self.bytes(address, limit)
        except OSError:
            return None
        raw = raw.split(b"\0", 1)[0]
        if not raw or any(c < 0x20 or c > 0x7E for c in raw):
            return None
        return raw.decode("latin-1")

    def reg_name(self, number):
        if number not in self._reg_names:
            name = None
            table = self.sym("_RegName")
            if table is not None and 0 <= number < 256:
                name = self.cstr(self.u32(table + 4 * number), 16)
            self._reg_names[number] = name or "r%d" % number
        return self._reg_names[number]

    def reg_order(self, reg_class):
        table = self.u32(self.sym("_RegOrders") + 4 * reg_class)
        order = []
        while table and len(order) < self.MAX_ORDER:
            reg = self.u32(table + 4 * len(order))
            if not reg:
                break
            order.append(reg)
        return order

    def physreg_of(self, regsym_ptr):
        base = self.sym("_RegSym")
        if not regsym_ptr or regsym_ptr < base:
            return None
        delta = regsym_ptr - base
        if delta % self.REGSYM_SIZE:
            return None
        return delta // self.REGSYM_SIZE

    def globreg(self, ptr):
        """Globreg (GrgNewGlobreg): +0 sym, +0x1c number, +0x20 allowed-physreg
        sparse bv, +0x10 assigned _RegSym entry, +0x38 preference list
        {next, Globreg*, weight}, +0x40 reference count."""
        if not ptr:
            return None
        sym = self.u32(ptr)
        info = {"globreg": self.u32(ptr + 0x1C), "sym": "0x%08X" % sym}
        if sym:
            info["symnum"] = self.u32(sym + 0x1C)
            info["name"] = self.cstr(self.u32(sym)) or self.cstr(self.u32(self.u32(sym)))
        info["priority"] = _signed(self.u32(ptr + 0x0C))
        info["lastref"] = self.u32(ptr + 0x44)
        prefs = []
        node = self.u32(ptr + 0x38)
        while node and len(prefs) < 32:
            other = self.u32(node + 4)
            prefs.append({"globreg": self.u32(other + 0x1C) if other else None,
                          "weight": ctypes.c_int32(self.u32(node + 8)).value})
            node = self.u32(node)
        if prefs:
            info["prefs"] = prefs
        info["refs"] = ctypes.c_int32(self.u32(ptr + 0x40)).value
        return info


# ---------------------------------------------------------------- decoders

def _signed(value):
    return ctypes.c_int32(value & 0xFFFFFFFF).value


class Decoder:
    """Generic: registers and the first stack slots at entry, EAX at return."""
    stack_args = 4

    def entry(self, model, regs, stack):
        return {"eax": regs["eax"], "ecx": regs["ecx"], "edx": regs["edx"],
                "stack": stack[1:1 + self.stack_args]}

    def exit(self, model, regs, state):
        return {"ret": regs["eax"]}


class ChoosePhysRegDecoder(Decoder):
    """ChoosePhysReg(EAX=sparse bv of interfering globregs, [esp+4]=Globreg*,
    [esp+8]=register class); ret 8. It zeroes _ChoosePhysReg_weights, adds the
    preference weights of interfering globregs and 100*refs of any whose
    allowed set is a single register, subtracts the globreg's own preference
    weights, then walks _RegOrders[class] keeping the first allowed register
    with the strictly lowest weight, and stores &_RegSym[reg] at Globreg+0x10."""

    def entry(self, model, regs, stack):
        ptr, reg_class = stack[1], stack[2]
        info = {"class": reg_class}
        info.update(model.globreg(ptr) or {})
        info["allowed"] = read_sparse_bv(model.u32, model.u32(ptr + 0x20))
        info["interferes"] = read_sparse_bv(model.u32, regs["eax"])
        return info, {"ptr": ptr, "class": reg_class, "allowed": info["allowed"]}

    def exit(self, model, regs, state):
        reg = model.physreg_of(model.u32(state["ptr"] + 0x10))
        weights_va = model.sym("_ChoosePhysReg_weights")
        candidates = []
        for number in model.reg_order(state["class"]):
            if number in state["allowed"]:
                candidates.append([model.reg_name(number), _signed(model.u32(weights_va + 4 * number))])
        out = {"chosen": model.reg_name(reg) if reg is not None else None, "candidates": candidates}
        best = [c for c in candidates if c[1] == min((w for _, w in candidates), default=None)]
        if len(best) > 1:
            out["tie"] = [c[0] for c in best]
        return out


class OrderGlobregsDecoder(Decoder):
    """OrderGlobregs([esp+4]=register class, [esp+8]=bv); ret 8. Walks
    _GlobregHash (bucket = globreg & 0x3FF, chains newest first), and
    InsertInList builds _SortedGlobregs (next +0x14) ordered by priority (+0xC)
    descending, then +0x44 descending; on a full tie the later insertion goes
    first. Color then calls ChoosePhysReg in this order."""

    def entry(self, model, regs, stack):
        return {"class": stack[1]}, {"class": stack[1]}

    def exit(self, model, regs, state):
        node = model.u32(model.sym("_SortedGlobregs"))
        order = []
        while node and len(order) < 512:
            info = model.globreg(node)
            order.append({k: info[k] for k in ("globreg", "symnum", "name", "priority", "lastref", "refs")
                          if info.get(k) is not None})
            node = model.u32(node + 0x14)
        return {"order": order}


class ReturnDecoder(Decoder):
    """Predicate: log the stack arguments and the boolean/int return."""
    def exit(self, model, regs, state):
        return {"ret": _signed(regs["eax"])}


DECODERS = {"ChoosePhysReg": ChoosePhysRegDecoder, "OrderGlobregs": OrderGlobregsDecoder}
# Inliner predicates: arguments not decoded (LTCG-private conventions), signed EAX logged.
for _name in ("InlineeIsTooBig", "ShouldInlineCallTuple", "ShouldInlineInlinee", "InlBadCandidate",
              "InlCallTupleIsCandidate", "InlBenefit", "ConsiderCandidate", "InlCallGraphDecision"):
    DECODERS[_name] = ReturnDecoder


def decoder_for(name):
    return DECODERS.get(plain_name(name), Decoder)()


# ---------------------------------------------------------------- summary

def summarize(events, limit=40):
    lines = []
    counts = {}
    for event in events:
        counts[event["break"]] = counts.get(event["break"], 0) + 1
    lines.append("calls: " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))
    for event in events:
        if len(lines) > limit:
            lines.append("... (%d events; see the JSONL)" % len(events))
            break
        lines.append(format_event(event))
    return lines


def format_event(event):
    name = plain_name(event["break"])
    func = event.get("function") or "?"
    if name == "ChoosePhysReg" and "chosen" in event:
        cands = " ".join("%s:%d" % (r, w) for r, w in event.get("candidates", []))
        tie = " TIE(%s)" % ",".join(event["tie"]) if event.get("tie") else ""
        prefs = ""
        if event.get("prefs"):
            prefs = " prefs=" + ",".join("g%s:%d" % (p["globreg"], p["weight"]) for p in event["prefs"])
        return "%s  g%s(sym%s) -> %s  [%s]%s prio=%s lastref=%s refs=%s%s" % (
            func, event.get("globreg"), event.get("symnum"), event["chosen"], cands, tie,
            event.get("priority"), event.get("lastref"), event.get("refs"), prefs)
    if name == "OrderGlobregs" and "order" in event:
        return "%s  OrderGlobregs class=%s: %s" % (func, event.get("class"), " ".join(
            "g%s(sym%s,p%s,l%s)" % (g.get("globreg"), g.get("symnum"), g.get("priority"), g.get("lastref"))
            for g in event["order"]))
    fields = {k: v for k, v in event.items() if k not in ("break", "function", "seq", "tid", "depth")}
    return "%s  %s %s" % (func, name, json.dumps(fields, sort_keys=True))


# ---------------------------------------------------------------- debugger

class WowContext(ctypes.Structure):
    """WOW64_CONTEXT (== x86 CONTEXT), WinNT.h of the Platform SDK."""
    _fields_ = [("ContextFlags", ctypes.c_uint32), ("Dr", ctypes.c_uint32 * 6),
                ("FloatSave", ctypes.c_ubyte * 112), ("SegGs", ctypes.c_uint32), ("SegFs", ctypes.c_uint32),
                ("SegEs", ctypes.c_uint32), ("SegDs", ctypes.c_uint32), ("Edi", ctypes.c_uint32),
                ("Esi", ctypes.c_uint32), ("Ebx", ctypes.c_uint32), ("Edx", ctypes.c_uint32),
                ("Ecx", ctypes.c_uint32), ("Eax", ctypes.c_uint32), ("Ebp", ctypes.c_uint32),
                ("Eip", ctypes.c_uint32), ("SegCs", ctypes.c_uint32), ("EFlags", ctypes.c_uint32),
                ("Esp", ctypes.c_uint32), ("SegSs", ctypes.c_uint32), ("Extended", ctypes.c_ubyte * 512)]


CONTEXT_FLAGS = 0x00010003  # CONTEXT_i386 | CONTROL | INTEGER


class Debugger:
    def __init__(self):
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        k, vp, u32 = self.k, ctypes.c_void_p, ctypes.c_uint32
        self.wow = ctypes.sizeof(ctypes.c_void_p) == 8
        get = k.Wow64GetThreadContext if self.wow else k.GetThreadContext
        put = k.Wow64SetThreadContext if self.wow else k.SetThreadContext
        get.argtypes = put.argtypes = [vp, ctypes.POINTER(WowContext)]
        get.restype = put.restype = ctypes.c_int
        self.get_ctx, self.put_ctx = get, put
        k.ReadProcessMemory.argtypes = [vp, vp, vp, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        k.WriteProcessMemory.argtypes = [vp, vp, vp, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        k.ReadProcessMemory.restype = k.WriteProcessMemory.restype = ctypes.c_int
        k.FlushInstructionCache.argtypes = [vp, vp, ctypes.c_size_t]
        k.WaitForDebugEvent.argtypes = [vp, u32]
        k.WaitForDebugEvent.restype = ctypes.c_int
        k.ContinueDebugEvent.argtypes = [u32, u32, u32]
        k.ContinueDebugEvent.restype = ctypes.c_int
        k.GetFinalPathNameByHandleW.argtypes = [vp, ctypes.c_wchar_p, u32, u32]
        k.GetFinalPathNameByHandleW.restype = u32
        k.CloseHandle.argtypes = [vp]
        k.DebugActiveProcessStop.argtypes = [u32]
        self.process = None

    def read(self, address, size):
        buf = ctypes.create_string_buffer(size)
        done = ctypes.c_size_t()
        if not self.k.ReadProcessMemory(self.process, ctypes.c_void_p(address), buf, size, ctypes.byref(done)):
            raise OSError("ReadProcessMemory 0x%08X failed (%d)" % (address, ctypes.get_last_error()))
        return buf.raw[:done.value]

    def read_u32(self, address):
        try:
            return struct.unpack("<I", self.read(address & 0xFFFFFFFF, 4))[0]
        except (OSError, struct.error):
            return 0

    def write(self, address, data):
        done = ctypes.c_size_t()
        if not self.k.WriteProcessMemory(self.process, ctypes.c_void_p(address), data, len(data), ctypes.byref(done)):
            raise OSError("WriteProcessMemory 0x%08X failed (%d)" % (address, ctypes.get_last_error()))
        self.k.FlushInstructionCache(self.process, ctypes.c_void_p(address), len(data))

    def context(self, thread):
        ctx = WowContext()
        ctx.ContextFlags = CONTEXT_FLAGS
        if not self.get_ctx(thread, ctypes.byref(ctx)):
            raise OSError("GetThreadContext failed (%d)" % ctypes.get_last_error())
        return ctx

    def set_context(self, thread, ctx):
        if not self.put_ctx(thread, ctypes.byref(ctx)):
            raise OSError("SetThreadContext failed (%d)" % ctypes.get_last_error())

    def file_path(self, handle):
        buffer = ctypes.create_unicode_buffer(32768)
        if handle and self.k.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0):
            return buffer.value.removeprefix("\\\\?\\")
        return ""


class Tracer:
    def __init__(self, table, image_base, breaks, function_filter=None, dumps=(), max_events=200000,
                 current_function=None):
        self.table, self.image_base = table, image_base
        self.breaks = breaks              # list of (public name, preferred VA)
        self.filter = function_filter
        self.dumps = [parse_dump(d) for d in dumps]
        self.max_events = max_events
        self.current_function = current_function or default_current_function
        self.events, self.dropped = [], 0
        self.seq = 0

    def run(self, command, cwd, env, timeout=600):
        dbg = Debugger()
        self.dbg = dbg
        k = dbg.k
        raw_size = 160 if ctypes.sizeof(ctypes.c_void_p) == 8 else 84

        class DebugEvent(ctypes.Structure):
            _fields_ = [("code", ctypes.c_uint32), ("pid", ctypes.c_uint32), ("tid", ctypes.c_uint32),
                        ("raw", ctypes.c_ubyte * (raw_size + (4 if raw_size == 160 else 0)))]

        ps = ctypes.sizeof(ctypes.c_void_p)
        # DebugEvent union is pointer-aligned: the union starts at 16 on x64, 12 on x86.
        pad = 4 if ps == 8 else 0
        threads = {}
        bps = {}        # va -> {"orig": byte, "entry": name or None, "returns": [frames]}
        stepping = {}   # tid -> va to re-arm
        frames = {}     # (tid) -> list of pending frames
        self.c2_base = None
        log_path = Path(cwd) / "cl-output.log"
        with open(log_path, "wb") as log:
            proc = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW | 0x2)
            deadline = time.monotonic() + timeout
            try:
                while True:
                    if time.monotonic() > deadline:
                        raise TraceError("trace exceeded %d seconds" % timeout)
                    ev = DebugEvent()
                    if not k.WaitForDebugEvent(ctypes.byref(ev), 1000):
                        if ctypes.get_last_error() == 121:
                            continue
                        raise ctypes.WinError(ctypes.get_last_error())
                    raw = bytes(ev.raw)[pad:]
                    ptr = lambda i: int.from_bytes(raw[i * ps:(i + 1) * ps], "little")
                    status = DBG_CONTINUE
                    if ev.code == 3:  # CREATE_PROCESS: hFile, hProcess, hThread, base
                        if ptr(0):
                            k.CloseHandle(ptr(0))
                        dbg.process = ptr(1)
                        threads[ev.tid] = ptr(2)
                    elif ev.code == 2:  # CREATE_THREAD: hThread
                        threads[ev.tid] = ptr(0)
                    elif ev.code == 4:
                        threads.pop(ev.tid, None)
                    elif ev.code == 6:  # LOAD_DLL: hFile, base
                        path = dbg.file_path(ptr(0))
                        if ptr(0):
                            k.CloseHandle(ptr(0))
                        if path.lower().endswith("\\c2.dll") and self.c2_base is None:
                            self.c2_base = ptr(1)
                            self.slide = self.c2_base - self.image_base
                            for name, va in self.breaks:
                                address = va + self.slide
                                bps[address] = {"orig": dbg.read(address, 1), "entry": name, "returns": 0}
                                dbg.write(address, b"\xCC")
                    elif ev.code == 1:  # EXCEPTION
                        code = int.from_bytes(raw[0:4], "little")
                        address = int.from_bytes(raw[8 + ps:8 + 2 * ps], "little") if ps == 8 else \
                            int.from_bytes(raw[12:16], "little")
                        if code in (STATUS_BREAKPOINT, STATUS_WX86_BREAKPOINT) and address in bps:
                            self._on_break(dbg, threads[ev.tid], ev.tid, address, bps, frames, stepping)
                        elif code in (STATUS_SINGLE_STEP, STATUS_WX86_SINGLE_STEP) and ev.tid in stepping:
                            address = stepping.pop(ev.tid)
                            bp = bps.get(address)
                            if bp is not None:
                                dbg.write(address, b"\xCC")
                        elif code in (STATUS_BREAKPOINT, STATUS_WX86_BREAKPOINT):
                            pass  # loader breakpoints
                        else:
                            status = DBG_EXCEPTION_NOT_HANDLED
                    if not k.ContinueDebugEvent(ev.pid, ev.tid, status):
                        raise ctypes.WinError(ctypes.get_last_error())
                    if ev.code == 5:
                        break
                returncode = proc.wait(timeout=10)
            finally:
                if proc.poll() is None:
                    k.DebugActiveProcessStop(proc.pid)
                    proc.terminate()
                    proc.wait(timeout=5)
        if self.c2_base is None:
            raise TraceError("cl.exe never loaded c2.dll (see %s)" % log_path)
        return returncode, log_path

    def symbol(self, name):
        try:
            return resolve_name(name, self.table)[1] + self.slide
        except TraceError:
            return None

    def _on_break(self, dbg, thread, tid, address, bps, frames, stepping):
        bp = bps[address]
        ctx = dbg.context(thread)
        regs = {"eax": ctx.Eax, "ecx": ctx.Ecx, "edx": ctx.Edx, "ebx": ctx.Ebx, "esp": ctx.Esp,
                "ebp": ctx.Ebp, "esi": ctx.Esi, "edi": ctx.Edi, "eip": address}
        model = C2Model(dbg.read_u32, dbg.read, self.symbol)
        pending = frames.setdefault(tid, [])
        # Return breakpoint: the frames whose return address is here and whose entry ESP lies below.
        mine = [f for f in pending if f["ret"] == address and f["esp"] < ctx.Esp]
        if mine:
            frame = max(mine, key=lambda f: f["esp"])
            pending.remove(frame)
            bp["returns"] -= 1
            event = frame["event"]
            if event is not None:
                try:
                    event.update(frame["decoder"].exit(model, regs, frame["state"]))
                except Exception as error:  # a decoder bug must not kill the compile
                    event["exit_error"] = repr(error)
        elif bp["entry"]:
            self._on_entry(dbg, model, regs, tid, address, bp, bps, pending)
        # Step over the original instruction, then re-arm.
        dbg.write(address, bp["orig"])
        ctx.Eip = address
        if bp["entry"] or bp["returns"] > 0:
            ctx.EFlags |= 0x100
            stepping[tid] = address
        else:
            del bps[address]
        dbg.set_context(thread, ctx)

    def _on_entry(self, dbg, model, regs, tid, address, bp, bps, pending):
        name = bp["entry"]
        function = None
        try:
            function = self.current_function(model)
        except Exception:
            function = None
        wanted = self.filter is None or (function is not None and self.filter in function)
        stack = [dbg.read_u32(regs["esp"] + 4 * i) for i in range(8)]
        event, state, decoder = None, None, decoder_for(name)
        if wanted and len(self.events) < self.max_events:
            self.seq += 1
            event = {"seq": self.seq, "break": plain_name(name), "function": function, "tid": tid,
                     "depth": len(pending)}
            try:
                got = decoder.entry(model, regs, stack)
                fields, state = got if isinstance(got, tuple) else (got, None)
                event.update(fields)
            except Exception as error:
                event["entry_error"] = repr(error)
            for text, node, count in self.dumps:
                try:
                    base = eval_expr(node, regs, dbg.read_u32, self.symbol)
                    words = [dbg.read_u32(base + 4 * i) for i in range(count)]
                    event.setdefault("dump", {})[text] = ["%08X" % w for w in words]
                    strings = {"+0x%X" % (4 * i): s for i, w in enumerate(words)
                               if w > 0x10000 and (s := model.cstr(w, 64))}
                    if strings:
                        event.setdefault("dump_strings", {})[text] = strings
                except Exception as error:
                    event.setdefault("dump", {})[text] = repr(error)
            self.events.append(event)
        elif wanted:
            self.dropped += 1
        if event is None:
            return
        ret = stack[0]
        pending.append({"ret": ret, "esp": regs["esp"], "event": event, "decoder": decoder, "state": state})
        if ret not in bps:
            bps[ret] = {"orig": dbg.read(ret, 1), "entry": None, "returns": 0}
            dbg.write(ret, b"\xCC")
        bps[ret]["returns"] += 1


def default_current_function(model):
    """Decorated name of the function c2 is compiling: _Entry -> +4 -> name."""
    va = model.sym("_Entry")
    if va is None:
        return None
    entry = model.u32(va)
    return model.cstr(model.u32(entry + 4), 512) if entry else None


# ---------------------------------------------------------------- driver

def compile_command(toolchain, source, flags, includes, out_dir):
    exe = Path(toolchain["bin"]) / "cl.exe"
    args = [str(exe), "/nologo", "/c", *flags, "/Fo" + str(Path(out_dir) / (Path(source).stem + ".obj"))]
    for inc in includes:
        args.append("/I" + str(inc))
    args.append(str(Path(source).resolve()))
    return args


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--flags", default="/O2", help="cl options (one string)")
    parser.add_argument("--include", action="append", default=[], type=Path)
    parser.add_argument("--break", dest="breaks", default=",".join(DEFAULT_BREAKS),
                        help="comma-separated c2 public names (plain or decorated)")
    parser.add_argument("--function", help="only log while c2 compiles a function whose name contains this")
    parser.add_argument("--dump", action="append", default=[], help="EXPR:COUNT dwords to dump at each entry")
    parser.add_argument("--out", type=Path, required=True, help="JSONL trace")
    parser.add_argument("--work-dir", type=Path, help="cl.exe working directory (default: next to --out)")
    parser.add_argument("--max-events", type=int, default=200000)
    parser.add_argument("--summary-lines", type=int, default=40)
    parser.add_argument("--toolchain", default="sp1")
    args = parser.parse_args(argv)
    if os.name != "nt":
        print("c2_trace: requires Windows", file=sys.stderr)
        return 2
    import probe_toolchain
    try:
        toolchain = probe_toolchain.load_toolchain(args.toolchain)
        probe_toolchain.verify_toolchain(toolchain)
        work = (args.work_dir or args.out.parent / (args.out.stem + ".work")).resolve()
        work.mkdir(parents=True, exist_ok=True)
        data = load_symbols(ROOT / "build/c2-trace")
        table = symbol_table(data["rows"])
        breaks = [resolve_name(name.strip(), table) for name in args.breaks.split(",") if name.strip()]
        tracer = Tracer(table, data["image_base"], breaks, args.function, args.dump, args.max_events)
        command = compile_command(toolchain, args.source, args.flags.split(), args.include, work)
        env = probe_toolchain.toolchain_environment(toolchain)
        if args.include:
            env["INCLUDE"] = os.pathsep.join([*map(str, args.include), env["INCLUDE"]])
        returncode, log_path = tracer.run(command, work, env)
    except (TraceError, OSError, ValueError, KeyError) as error:
        print("c2_trace: " + str(error), file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as stream:
        for event in tracer.events:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
    print("cl.exe exit %d; %d events -> %s (cl output: %s)%s" % (
        returncode, len(tracer.events), args.out, log_path,
        "; %d dropped over --max-events" % tracer.dropped if tracer.dropped else ""))
    for line in summarize(tracer.events, args.summary_lines):
        print(line)
    return 0 if returncode == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
