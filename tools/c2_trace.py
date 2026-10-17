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
PRESETS = {
    "color": {"breaks": "OrderGlobregs,ChoosePhysReg", "doc": "global coloring order and choices"},
    "immed": {"breaks": "GrgImmedTupleHash,CreateGlobregs,GrgNewGlobreg,Spill",
              "doc": "immediate globregs, globreg numbering and spills (the 64-cycle)"},
    "reload": {"breaks": "Spill,RegSimpleAssignBody,RegAssign,LoFinalLower,SsaPeepsMd",
               "tuples": "Spill,RegSimpleAssignBody,LoFinalLower,SsaPeepsMd",
               "doc": "spill reloads, local register assignment, LEA->ADD (tuples at each phase)"},
    "emit": {"breaks": "CgBottomUpOrder,ReadFunction,EmitFunction",
             "doc": "call-graph reordering and the compile/emit loop (unfiltered: omit --function)"},
}


def preset_breaks(breaks, tuples, presets):
    """--break/--tuples text after adding the presets' (the default break only
    when neither --break nor a preset is given)."""
    breaks_text = breaks if breaks is not None else ("" if presets else ",".join(DEFAULT_BREAKS))
    tuples_text = tuples or ""
    for name in presets:
        breaks_text = ",".join(x for x in (breaks_text, PRESETS[name]["breaks"]) if x)
        tuples_text = ",".join(x for x in (tuples_text, PRESETS[name].get("tuples", "")) if x)
    return breaks_text, tuples_text


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


def module_breaks(rows, pattern, exclude=()):
    """(name, va) of every function public whose object module matches the regex
    (e.g. 'lower|tuple'); one entry per address, sorted by address."""
    regex = re.compile(pattern)
    seen, out = set(), []
    for row in sorted(rows, key=lambda r: r.get("va") or 0):
        va, module = row.get("va"), row.get("module")
        if va is None or not module or not row.get("function", True) or va in seen:
            continue
        if regex.search(module) and plain_name(row["name"]) not in exclude:
            seen.add(va)
            out.append((row["name"], int(va)))
    return out


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
    key = "v2:%s:%d:%d" % (pdb, pdb.stat().st_size, binary.stat().st_size)
    if cache.is_file():
        data = json.loads(cache.read_text(encoding="utf-8"))
        if data.get("key") == key:
            return data
    result = symbols.extract(binary, pdb)
    data = {"key": key, "image_base": result["identity"]["image_base"],
            "binary_sha256": result["identity"]["binary_sha256"],
            "rows": [{"name": r["name"], "va": r["va"], "module": (r.get("module") or "").replace("\\", "/")
                      .split("/")[-1] or None, "function": r in result["functions"]}
                     for r in result["functions"] + result["data"]]}
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
        if base is None or not regsym_ptr or regsym_ptr < base:
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

    SYM_SIZE = 0x60      # SymAllocPool: getmem(0xC0C) = 0xC header + 32 symbols of 0x60
    SYM_CHUNK = 32       # SymKeyToSym: chunks[key >> 5] + 0xC + (key & 31) * 0x60

    def sym_address(self, symnum):
        table = self.u32(self.sym("_BESymTab"))
        chunks = self.u32(table + 4)
        chunk = self.u32(chunks + 4 * (symnum // self.SYM_CHUNK))
        return chunk + 0xC + (symnum % self.SYM_CHUNK) * self.SYM_SIZE

    def symbol(self, address):
        """c2 symbol (_BESymTab slot): +0 front-end descriptor (name at +4, the
        front-end '$N' number at +0x28), +4 kind byte, +8 base symbol (itself
        unless an equivalence), +0x1C c2 symbol number, +0x24 offset in the base."""
        desc = self.u32(address)
        info = {"symnum": self.u32(address + 0x1C), "kind": self.u32(address + 4) & 0xFF}
        base = self.u32(address + 8)
        if base and base != address:      # equivalence (a field of a base symbol): SymCmpSym +8, +0x24
            info["base"] = self.u32(base + 0x1C)
            info["offset"] = _signed(self.u32(address + 0x24))
        if desc:
            name = self.cstr(self.u32(desc + 4))
            if name is not None:
                info["name"] = name
                info["fe"] = self.u32(desc + 0x28)
        return info

    def sym_text(self, sym):
        """Short name of a c2 symbol pointer: register, 'name$fe', or 's<symnum>'."""
        reg = self.physreg_of(sym)
        if reg is not None:
            return self.reg_name(reg)
        info = self.symbol(sym)
        if "name" in info:
            return "%s$%d" % (info["name"], info["fe"])
        return "s%d" % info["symnum"]

    def leaf_text(self, leaf, depth=0):
        """Operand leaf (+8 kind): 7 integer constant (+0x18), 5 effective address
        (+0x24 displacement, +0x2C base leaf, +0x30 index leaf), others name the
        symbol at +0x18 (1 register/tmpreg, 3 address of)."""
        kind = self.u32(leaf + 8) & 0xFF
        if kind == 7:
            return "#%d" % _signed(self.u32(leaf + 0x18))
        if kind == 5 and depth < 3:
            parts = [self.leaf_text(p, depth + 1) for p in (self.u32(leaf + 0x2C), self.u32(leaf + 0x30)) if p]
            return "[%s%+d]" % ("+".join(parts), _signed(self.u32(leaf + 0x24)))
        sym = self.u32(leaf + 0x18)
        text = self.sym_text(sym) if sym else "?"
        if kind == 1:
            # +0x1C: the register the leaf was given (RegAssignDsts/RegAssignSrcs store the
            # _RegSym entry of the right width); equal to +0x18 until then (MdTmpregIsColored).
            colored = self.u32(leaf + 0x1C)
            if colored and colored != sym and self.physreg_of(sym) is None:
                reg = self.physreg_of(colored)
                if reg is not None:
                    return "%s/%s" % (text, self.reg_name(reg))
            return text
        if kind == 3:
            return "&" + text
        return "k%d:%s" % (kind, text)

    def tuple_list(self, limit=2000):
        """Instruction tuples of the function being compiled, in list order:
        _Function -> +8 flow graph -> first block +0x1C (head tuple), last block
        +0x20 (end), linked by +0 (LoFinalLower's walk); +9 bit 0 marks an
        instruction, +4 opcode, +0x2C destination leaves, +0x28 source leaves
        (each linked by +0)."""
        func = self.u32(self.sym("_Function"))
        graph = self.u32(func + 8)
        node = self.u32(self.u32(self.u32(graph) + 0x1C))
        end = self.u32(self.u32(graph + 4) + 0x20)
        out = []

        def leaves(head):
            items = []
            while head and len(items) < 8:
                items.append(self.leaf_text(head))
                head = self.u32(head)
            return items
        while node and node != end and len(out) < limit:
            if self.u32(node + 8) & 0x100:
                out.append(self.tuple_text(node))
            node = self.u32(node)
        return out

    def tuple_text(self, node):
        """'opcode dsts = srcs' of one instruction tuple."""
        def leaves(head):
            items = []
            while head and len(items) < 8:
                items.append(self.leaf_text(head))
                head = self.u32(head)
            return items
        return "%d %s = %s" % (self.u32(node + 4), ",".join(leaves(self.u32(node + 0x2C))),
                               ",".join(leaves(self.u32(node + 0x28))))

    REGMAP_SIZE = 0x5C   # RegAssignDsts: cmp esi, 0x5c before indexing _RegMap

    def phys_list(self, va):
        """Zero-terminated register-number list (_IntPhysRegs, a _Next*Pos cursor)."""
        out = []
        while va and len(out) < self.MAX_ORDER:
            reg = self.u32(va + 4 * len(out))
            if not reg:
                break
            out.append(reg)
        return out

    def reg_map(self):
        """_RegMap: physical register number -> symbol it holds (RegSimpleAssignBody's state)."""
        base = self.sym("_RegMap")
        out = {}
        for reg in range(1, self.REGMAP_SIZE):
            sym = self.u32(base + 4 * reg)
            if sym:
                out[self.reg_name(reg)] = self.sym_text(sym)
        return out

    ENTRY_NEXT = 0x80    # dop2: the compile loop walks _Eentry_list by +0x80
    ENTRY_FLAGS = 0x50   # dop2: bit 0x20 = has a body to compile, bit 2 = compiled

    ENTRY_CGNODE = 0x88  # CgAddNode: entry+0x88 = call-graph node, node+4 = entry
    ENTRY_INIT = 0x400000  # CgBottomUpOrder: entry+0x20 bit -> the dynamic-initializer list

    def entry_list(self, limit=20000, edges=False):
        """_Eentry_list in list order: decorated name (+4) and flags (+0x50);
        with edges, the call-graph callees (node+0xC list {+0 next, +4 callee
        node, +0xC bit 0 = recursive arc}, in list order) and whether the entry
        has a node and is a dynamic initializer."""
        head = self.sym("_Eentry_list")
        out = []
        entry = self.u32(head) if head is not None else 0
        while entry and len(out) < limit:
            item = {"name": self.cstr(self.u32(entry + 4), 512), "flags": self.u32(entry + self.ENTRY_FLAGS)}
            if edges:
                node = self.u32(entry + self.ENTRY_CGNODE)
                item["node"] = bool(node)
                item["init"] = bool(self.u32(entry + 0x20) & self.ENTRY_INIT)
                callees, recursive = [], []
                edge = self.u32(node + 0xC) if node else 0
                while edge and len(callees) + len(recursive) < 4096:
                    target = self.u32(edge + 4)
                    name = self.cstr(self.u32(self.u32(target + 4) + 4), 512) if target else None
                    (recursive if self.u32(edge + 0xC) & 1 else callees).append(name)
                    edge = self.u32(edge)
                item["callees"] = callees
                if recursive:
                    item["recursive"] = recursive
            out.append(item)
            entry = self.u32(entry + self.ENTRY_NEXT)
        return out

    def symtab(self, limit=4096):
        """Every allocated c2 symbol slot ([_BESymTab]+0 = next number)."""
        table = self.u32(self.sym("_BESymTab"))
        count = min(self.u32(table), limit)
        return [self.symbol(self.sym_address(n)) for n in range(count)]


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


class SymAllocDecoder(Decoder):
    """SymAlloc(AL=kind): pops the kind's free list ([_BESymTab]+0x2C.., the
    freed symbol keeps its +0x1C number) or takes a new pool slot. Exit: the
    symbol's number, so number reuse is visible."""

    def entry(self, model, regs, stack):
        return {"kind": regs["eax"] & 0xFF}

    def exit(self, model, regs, state):
        return {"symnum": model.u32(regs["eax"] + 0x1C)} if regs["eax"] else {"symnum": None}


class SymFreeDecoder(Decoder):
    """SymFree(EAX=symbol): pushes it on its kind's free list (LIFO)."""

    def entry(self, model, regs, stack):
        info = model.symbol(regs["eax"])
        return {k: info[k] for k in ("symnum", "kind", "name", "fe") if k in info}

    def exit(self, model, regs, state):
        return {}


class ImmedHashDecoder(Decoder):
    """GrgImmedTupleHash(EAX=leaf tuple or 0, [esp+4]=fallback symbol); ret 4.
    Bucket of _ImmedHashTable (64 chains): integer constant (leaf kind 7) ->
    value & 0x3F; address of a symbol (kind 3) -> front-end number & 0x3F;
    tmpreg (kind 1) -> c2 symbol number & 0x3F."""

    def entry(self, model, regs, stack):
        leaf = regs["eax"]
        info = {}
        if leaf:
            info["leaf_kind"] = model.u32(leaf + 8) & 0xFF
            if info["leaf_kind"] == 7:
                info["value"] = _signed(model.u32(leaf + 0x18))
            elif info["leaf_kind"] == 3:
                sym = model.u32(leaf + 0x18)
                desc = model.u32(model.u32(sym + 8))
                info["name"] = model.cstr(model.u32(desc + 4))
                info["fe"] = model.u32(desc + 0x28)
        return info

    def exit(self, model, regs, state):
        return {"bucket": regs["eax"]}


class NewGlobregDecoder(Decoder):
    """GrgNewGlobreg(EAX=symbol or immediate leaf owner): pops _FreeGlobs (a
    LIFO linked by +0x30; a freed globreg keeps its +0x1C number) or takes
    _NextGlobregNum. Exit: the globreg number, so number reuse is visible."""

    def entry(self, model, regs, stack):
        info = model.symbol(regs["eax"]) if regs["eax"] else {}
        return {k: info[k] for k in ("symnum", "name", "fe", "base", "offset") if k in info}

    def exit(self, model, regs, state):
        return {"globreg": model.u32(regs["eax"] + 0x1C) if regs["eax"] else None}


class SpillDecoder(Decoder):
    """Spill(EAX=Globreg): Color spills globregs in globreg-number order; the
    reload tmpregs come from SymAlloc's free list in that order."""

    def entry(self, model, regs, stack):
        info = model.globreg(regs["eax"]) or {}
        out = {k: info[k] for k in ("globreg", "symnum", "name", "priority", "refs") if info.get(k) is not None}
        sym = model.u32(regs["eax"]) if regs["eax"] else 0
        if sym:
            out.update({k: v for k, v in model.symbol(sym).items() if k in ("base", "offset", "fe")})
        return out

    def exit(self, model, regs, state):
        return {}


class RegAssignDecoder(Decoder):
    """RegAssign([esp+4]=destination leaf, [esp+8]=tuple); ret 8. Local
    register assignment (RegSimpleAssignBody walks the tuples forward;
    RegAssignSrcs looks each source up in _RegMap and frees it at its last use,
    RegAssignDsts calls this for a destination tmpreg not in _RegMap yet).
    Order of choice, for the tmpreg sym = [leaf+0x1C]:
    1. preference [sym+0x30]: if unset, a copy (opcode 1, 0x11F, 0x1FD, 0x17F,
       0x181, 0x125, 0x189) from an already colored tmpreg prefers that
       register, and an LEA (0x12) [base+index] with no displacement and
       scale prefers the BASE's register; the preference is taken if the
       register is free in _RegMap, available and has no _BvConflicts bit for
       sym;
    2. /O2 (_Speed): round-robin over _IntPhysRegs from _NextIntPos, only
       registers numbered below 4 (wrapping to the list start), the first free
       one without a conflict; _NextIntPos moves past it;
    3. otherwise the first free conflict-free register in list order, else
       RegSpill of the register whose next use is farthest (RegFindPhysRegUse).
    Entry: tmpreg, opcode and tuple, the preference, the cursor's remaining
    order, the _RegMap occupancy, the registers whose conflict set holds sym.
    Exit: chosen register and the preference after step 1."""

    def entry(self, model, regs, stack):
        leaf, tup = stack[1], stack[2]
        sym = model.u32(leaf + 0x1C)
        info = {"tmpreg": model.sym_text(sym), "symnum": model.u32(sym + 0x1C),
                "opcode": model.u32(tup + 4), "tuple": model.tuple_text(tup)}
        pref = model.u32(sym + 0x30)
        if pref:
            info["pref"] = model.reg_name(model.u32(pref + 0x1C))
        start, cursor = model.sym("_IntPhysRegs"), model.sym("_NextIntPos")
        if start is not None and cursor is not None:
            info["int_regs"] = [model.reg_name(r) for r in model.phys_list(start)]
            info["next"] = [model.reg_name(r) for r in model.phys_list(model.u32(cursor))]
            conflicts_va = model.sym("_BvConflicts")
            if conflicts_va is not None:
                info["conflicts"] = [model.reg_name(r) for r in model.phys_list(start)
                                     if info["symnum"] in read_sparse_bv(model.u32,
                                                                         model.u32(conflicts_va + 4 * r))]
        info["busy"] = model.reg_map()
        return info, {"sym": sym}

    def exit(self, model, regs, state):
        reg = model.physreg_of(regs["eax"])
        out = {"chosen": model.reg_name(reg) if reg is not None else None}
        pref = model.u32(state["sym"] + 0x30)
        if pref:
            out["pref_after"] = model.reg_name(model.u32(pref + 0x1C))
        return out


class EntryListDecoder(Decoder):
    """Module-level routines that build or reorder _Eentry_list (the order in
    which dop2 compiles and emits functions): the list at entry (with the call
    graph's callee edges) and at return. CgBottomUpOrder (called by
    CgBuildCallGraph after CgIdentifyRecursion) is modelled by bottom_up_order."""

    def entry(self, model, regs, stack):
        return {"entries": model.entry_list(edges=True)}

    def exit(self, model, regs, state):
        return {"entries_after": model.entry_list()}


DECODERS = {"ChoosePhysReg": ChoosePhysRegDecoder, "OrderGlobregs": OrderGlobregsDecoder,
            "SymAlloc": SymAllocDecoder, "SymFree": SymFreeDecoder, "GrgImmedTupleHash": ImmedHashDecoder,
            "GrgNewGlobreg": NewGlobregDecoder, "Spill": SpillDecoder, "RegAssign": RegAssignDecoder,
            "CgBuildCallGraph": EntryListDecoder, "CgBottomUpOrder": EntryListDecoder}
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
    if name == "RegAssign" and "tmpreg" in event:
        return "%s  RegAssign %s [%s] pref=%s next=%s busy=%s conflicts=%s -> %s" % (
            func, event["tmpreg"], event.get("tuple"), event.get("pref_after") or event.get("pref"),
            ",".join(event.get("next", [])), ",".join("%s:%s" % kv for kv in sorted(event.get("busy", {}).items())),
            ",".join(event.get("conflicts", [])) or "-", event.get("chosen"))
    fields = {k: v for k, v in event.items() if k not in ("break", "function", "seq", "tid", "depth")}
    return "%s  %s %s" % (func, name, json.dumps(fields, sort_keys=True))


# ---------------------------------------------------------------- diff

DIFF_SKIP = ("seq", "tid", "function", "dump_strings", "symtab", "tuples", "entry_error", "exit_error")


def normalize(value, pointer_floor=0x10000, ordinals=None):
    """Run-independent form of an event value: dwords that look like heap or
    image pointers (pointer_floor..-pointer_floor) become 'ptr', others signed.
    With an ordinals dict (one per trace, filled in event order) each distinct
    pointer becomes 'p<first-seen ordinal>' instead, so a different object at
    the same place in the call sequence shows."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        value &= 0xFFFFFFFF
        if pointer_floor <= value <= 0x100000000 - pointer_floor:
            if ordinals is None:
                return "ptr"
            return "p%d" % ordinals.setdefault(value, len(ordinals))
        return _signed(value)
    if isinstance(value, str) and re.fullmatch(r"[0-9A-F]{8}", value):
        return normalize(int(value, 16), pointer_floor, ordinals)
    if isinstance(value, list):
        return [normalize(v, pointer_floor, ordinals) for v in value]
    if isinstance(value, dict):
        return {k: normalize(value[k], pointer_floor, ordinals) for k in sorted(value)}
    return value


def renumber(value, low, high, delta):
    """Subtract delta from every int (or 8-digit hex dword) in [low, high]: maps
    one side's shifted front-end numbers ('$N', +k per padding declaration) onto
    the other's before comparing."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value - delta if low <= value <= high else value
    if isinstance(value, str) and re.fullmatch(r"[0-9A-F]{8}", value):
        number = int(value, 16)
        return "%08X" % ((number - delta) & 0xFFFFFFFF) if low <= number <= high else value
    if isinstance(value, list):
        return [renumber(v, low, high, delta) for v in value]
    if isinstance(value, dict):
        return {k: renumber(v, low, high, delta) for k, v in value.items()}
    return value


def event_key(event, ignore=(), pointer_floor=0x10000, shift=None, ordinals=None):
    fields = {k: v for k, v in event.items() if k not in DIFF_SKIP and k not in ignore}
    if shift:
        fields = renumber(fields, *shift)
    return json.dumps(normalize(fields, pointer_floor, ordinals), sort_keys=True)


def divergences(left, right, ignore=(), pointer_floor=0x10000, shift=None, ordinals=False):
    """0-based indices where the normalized records differ (lockstep), plus the
    first index past the shorter trace when the lengths differ. ordinals: compare
    pointers by first-seen ordinal (normalize) instead of as 'ptr'."""
    seen_l, seen_r = ({}, {}) if ordinals else (None, None)
    out = [i for i, (a, b) in enumerate(zip(left, right))
           if event_key(a, ignore, pointer_floor, None, seen_l) != event_key(b, ignore, pointer_floor, shift, seen_r)]
    if len(left) != len(right):
        out.append(min(len(left), len(right)))
    return out


def diff_traces(left, right, ignore=(), pointer_floor=0x10000, context=3, shift=None, ordinals=False):
    """First record where two traces of the same function diverge.

    Returns None when the normalized traces are equal, else a dict: index (0-based),
    left/right (the divergent records, or None past an end), before (the shared
    records leading to it), count (divergent records in lockstep), and blocks:
    difflib opcodes over the call sequence (break, depth) that are not 'equal',
    as (tag, left range, right range). shift = (low, high, delta) renumbers the
    right trace (renumber)."""
    import difflib
    found = divergences(left, right, ignore, pointer_floor, shift, ordinals)
    if not found:
        return None
    index = found[0]
    calls_l = ["%s/%s" % (e["break"], e.get("depth")) for e in left]
    calls_r = ["%s/%s" % (e["break"], e.get("depth")) for e in right]
    blocks = [(tag, (i1, i2), (j1, j2)) for tag, i1, i2, j1, j2 in
              difflib.SequenceMatcher(None, calls_l, calls_r, autojunk=False).get_opcodes() if tag != "equal"]
    return {"index": index, "left": left[index] if index < len(left) else None,
            "right": right[index] if index < len(right) else None, "count": len(found),
            "indices": found, "before": left[max(0, index - context):index], "blocks": blocks}


def load_trace(path):
    with open(path, encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def diff_main(argv):
    parser = argparse.ArgumentParser(prog="c2_trace.py diff",
                                     description="first divergent record of two c2_trace JSONL traces")
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--ignore", default="", help="comma-separated event fields not compared")
    parser.add_argument("--pointer-floor", type=lambda t: int(t, 0), default=0x10000,
                        help="dwords at least this far from 0 are pointers (default 0x10000)")
    parser.add_argument("--context", type=int, default=3)
    parser.add_argument("--renumber", help="LOW:HIGH:DELTA: subtract DELTA from the right trace's values in "
                        "[LOW, HIGH] (front-end numbers shifted by padding declarations)")
    parser.add_argument("--limit", type=int, default=40, help="records listed by --all")
    parser.add_argument("--ordinals", action="store_true", help="compare pointers by first-seen ordinal "
                        "(same allocation pattern -> same ordinals; a different object shows)")
    parser.add_argument("--all", action="store_true", help="list every divergent record, not only the first")
    args = parser.parse_args(argv)
    left, right = load_trace(args.left), load_trace(args.right)
    ignore = tuple(f for f in args.ignore.split(",") if f)
    shift = tuple(int(t, 0) for t in args.renumber.split(":")) if args.renumber else None
    if shift is not None and len(shift) != 3:
        parser.error("--renumber takes LOW:HIGH:DELTA")
    result = diff_traces(left, right, ignore, args.pointer_floor, args.context, shift, args.ordinals)
    if result is None:
        print("identical: %d records (normalized)" % len(left))
        return 0
    if args.all:
        for i in result["indices"][:args.limit]:
            for side, trace in (("<", left), (">", right)):
                print("%d %s %s" % (i + 1, side, format_event(trace[i]) if i < len(trace) else "(end of trace)"))
        print("%d divergent records" % result["count"])
        return 1
    print("records: %d vs %d; first divergence at record %d" % (len(left), len(right), result["index"] + 1))
    for event in result["before"]:
        print("  = " + format_event(event))
    for side, event in (("<", result["left"]), (">", result["right"])):
        print("  %s %s" % (side, format_event(event) if event else "(end of trace)"))
    for tag, (i1, i2), (j1, j2) in result["blocks"][:10]:
        names_l = ",".join(e["break"] for e in left[i1:i2][:6])
        names_r = ",".join(e["break"] for e in right[j1:j2][:6])
        print("  call sequence %s: left %d-%d [%s] right %d-%d [%s]" % (tag, i1 + 1, i2, names_l, j1 + 1, j2, names_r))
    return 1


# ---------------------------------------------------------------- emission order

def bottom_up_order(entries):
    """CgBottomUpOrder on _Eentry_list (entries as EntryListDecoder records
    them). First the entries without a call-graph node, in list order; then
    passes over the rest in list order: an entry is placed when every callee
    with an entry still waiting (recursive arcs, flagged by
    CgIdentifyRecursion's DFS, excepted) has been placed, else it waits for the
    next pass. Dynamic initializers placed in a pass go to a second list
    appended at the end (the SsrSortInitializerEvalOrder variant is not
    modelled). Returns the names in the new list order."""
    out = [e["name"] for e in entries if not e.get("node", True)]
    waiting = [e for e in entries if e.get("node", True)]
    names = {e["name"] for e in waiting}
    inits = []
    placed = set(out)
    while waiting:
        rest = []
        for e in waiting:
            if any(c in names and c not in placed for c in e.get("callees", [])):
                rest.append(e)
                continue
            (inits if e.get("init") else out).append(e["name"])
            placed.add(e["name"])
        if len(rest) == len(waiting):   # no progress (cannot happen once recursive arcs are removed)
            out.extend(e["name"] for e in rest)
            break
        waiting = rest
    return out + inits


def blocking_callees(entries):
    """Per entry, the callees that made CgBottomUpOrder hold it back: callees
    placed after the entry's IL position would allow (recursive arcs excepted)."""
    order = bottom_up_order(entries)
    pos = {n: i for i, n in enumerate(order)}
    il = {e["name"]: i for i, e in enumerate(entries)}
    out = {}
    for e in entries:
        late = [c for c in e.get("callees", []) if c in il and (il[c] > il[e["name"]] or c in out)]
        if late and pos.get(e["name"], 0) > 0:
            out[e["name"]] = late
    return out


def read_obj_sections(path):
    """Section table of a COFF object: number, name, size, flags, and for a
    COMDAT the COMDAT symbol, selection and associated section."""
    import struct
    data = Path(path).read_bytes()
    _, nsec, _, table, count, opt, _ = struct.unpack_from("<HHIIIHH", data)
    strings = table + count * 18

    def string_at(offset):
        start = strings + offset
        return data[start:data.index(b"\0", start)].decode("latin-1")
    secs = []
    for i in range(nsec):
        at = 20 + opt + 40 * i
        name = data[at:at + 8].rstrip(b"\0").decode("latin-1")
        if name.startswith("/"):
            name = string_at(int(name[1:]))
        size, = struct.unpack_from("<I", data, at + 16)
        flags, = struct.unpack_from("<I", data, at + 36)
        secs.append({"number": i + 1, "name": name, "size": size, "flags": flags})
    i = 0
    while i < count:
        at = table + 18 * i
        raw = data[at:at + 8]
        if raw[:4] == b"\0\0\0\0":
            name = string_at(struct.unpack_from("<I", raw, 4)[0])
        else:
            name = raw.rstrip(b"\0").decode("latin-1")
        value, sec, _, storage, aux = struct.unpack_from("<IhHBB", data, at + 8)
        if 0 < sec <= nsec:
            entry = secs[sec - 1]
            if storage == 3 and value == 0 and aux and name == entry["name"]:
                if entry["flags"] & 0x1000:     # IMAGE_SCN_LNK_COMDAT: aux = section definition
                    number, selection = struct.unpack_from("<HB", data, table + 18 * (i + 1) + 12)
                    entry["selection"] = selection
                    if selection == 5:
                        entry["assoc"] = number
            elif entry["flags"] & 0x1000 and "comdat" not in entry and storage in (2, 3, 6):
                entry["comdat"] = name
        i += 1 + aux
    return secs


def emit_order_report(events, sections):
    """Join a trace (CgBottomUpOrder + ReadFunction) with the object's section
    table: IL order, bottom-up order (traced and modelled), compile order, the
    code COMDATs in section order, and whether they agree."""
    bu = next((e for e in events if e["break"] == "CgBottomUpOrder" and "entries" in e), None)
    reads = [e.get("function") for e in events if e["break"] == "ReadFunction"]
    il = [e["name"] for e in bu["entries"]] if bu else []
    traced = [e["name"] for e in bu.get("entries_after", [])] if bu else []
    modelled = bottom_up_order(bu["entries"]) if bu else []
    code = [s.get("comdat") for s in sections
            if s["name"].startswith(".text") and s.get("selection") != 5 and s.get("comdat")]
    code_set = set(code)
    return {"il_order": il, "bottom_up_traced": traced, "bottom_up_model": modelled,
            "model_ok": (traced == modelled) if bu else None, "compile_order": reads,
            "blocked_by": blocking_callees(bu["entries"]) if bu else {},
            "code_sections": code, "sections_ok": code == [r for r in reads if r in code_set],
            "sections": sections}


def emit_order_main(argv):
    parser = argparse.ArgumentParser(prog="c2_trace.py emit-order",
                                     description="trace and explain the order c2 compiles and emits a unit's "
                                     "functions")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--flags", default="/O2 /Gy", help="cl options (one string)")
    parser.add_argument("--include", action="append", default=[], type=Path)
    parser.add_argument("--out", type=Path, required=True, help="JSON report (the trace goes next to it)")
    parser.add_argument("--toolchain", default="sp1")
    parser.add_argument("--all-sections", action="store_true", help="also print the whole section table")
    args = parser.parse_args(argv)
    trace = args.out.with_suffix(".jsonl")
    cli = ["--source", str(args.source), "--flags", args.flags, "--break", "CgBottomUpOrder,ReadFunction",
           "--out", str(trace), "--toolchain", args.toolchain, "--summary-lines", "0"]
    for inc in args.include:
        cli += ["--include", str(inc)]
    status = main(cli)
    if status:
        return status
    work = trace.parent / (trace.stem + ".work")
    report = emit_order_report(load_trace(trace), read_obj_sections(work / (args.source.stem + ".obj")))
    args.out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    il_pos = {n: i for i, n in enumerate(report["il_order"])}
    if report["model_ok"] is None:
        model = "no call graph (no CgBottomUpOrder, e.g. /Od): compiled in IL order"
    else:
        model = "bottom-up model %s the traced CgBottomUpOrder" % ("matches" if report["model_ok"] else "DIFFERS FROM")
    print("%s; obj code sections %s the compile order" % (
        model, "follow" if report["sections_ok"] else "DO NOT follow"))
    print("compile order (ReadFunction), IL position, held back by:")
    for i, name in enumerate(report["compile_order"]):
        why = report["blocked_by"].get(name)
        print("  %3d  il %3s  %s%s" % (i + 1, il_pos.get(name, "?"), name, "  <- " + ", ".join(why) if why else ""))
    if args.all_sections:
        for sec in report["sections"]:
            print("  sec %3d %-10s %s%s" % (sec["number"], sec["name"], sec.get("comdat", ""),
                                            " assoc=%d" % sec["assoc"] if "assoc" in sec else ""))
    return 0 if report["model_ok"] is not False and report["sections_ok"] else 1


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
                 current_function=None, entry_only=False, symtab_at=(), tuples_at=()):
        self.tuples_at = set(tuples_at)   # plain names whose entry events carry the tuple list
        self.entry_only = entry_only      # no return breakpoints: faster, no "ret"
        self.symtab_at = set(symtab_at)   # plain names whose entry events carry a symtab walk
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
            if plain_name(name) in self.tuples_at:
                try:
                    event["tuples"] = model.tuple_list()
                except Exception as error:
                    event["tuples"] = repr(error)
            if plain_name(name) in self.symtab_at:
                try:
                    event["symtab"] = [s for s in model.symtab() if "name" in s or "base" in s]
                except Exception as error:
                    event["symtab"] = repr(error)
            self.events.append(event)
        elif wanted:
            self.dropped += 1
        if event is None or self.entry_only:
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
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["diff"]:
        return diff_main(argv[1:])
    if argv[:1] == ["emit-order"]:
        return emit_order_main(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--flags", default="/O2", help="cl options (one string)")
    parser.add_argument("--include", action="append", default=[], type=Path)
    parser.add_argument("--break", dest="breaks", default=None,
                        help="comma-separated c2 public names (plain or decorated; default %s)"
                        % ",".join(DEFAULT_BREAKS))
    parser.add_argument("--preset", action="append", default=[], choices=sorted(PRESETS),
                        help="add a named set of breaks (and --tuples points): " + "; ".join(
                            "%s = %s" % (k, v["doc"]) for k, v in sorted(PRESETS.items())))
    parser.add_argument("--function", help="only log while c2 compiles a function whose name contains this")
    parser.add_argument("--dump", action="append", default=[], help="EXPR:COUNT dwords to dump at each entry")
    parser.add_argument("--out", type=Path, required=True, help="JSONL trace")
    parser.add_argument("--work-dir", type=Path, help="cl.exe working directory (default: next to --out)")
    parser.add_argument("--max-events", type=int, default=200000)
    parser.add_argument("--summary-lines", type=int, default=40)
    parser.add_argument("--toolchain", default="sp1")
    parser.add_argument("--break-module", help="also break on every function public of the c2 object modules "
                        "matching this regex (e.g. 'lower|tuple')")
    parser.add_argument("--exclude", default="", help="comma-separated plain names left out of --break-module")
    parser.add_argument("--entry-only", action="store_true", help="no return breakpoints (no 'ret'; faster)")
    parser.add_argument("--symtab", default="", help="comma-separated break names whose entry events carry "
                        "the c2 symbol table (symnum, kind, name, front-end number)")
    parser.add_argument("--tuples", default="", help="comma-separated break names whose entry events carry "
                        "the function's instruction tuples (opcode, destinations, sources)")
    args = parser.parse_args(argv)
    breaks_text, tuples_text = preset_breaks(args.breaks, args.tuples, args.preset)
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
        breaks, seen = [], set()
        for name in breaks_text.split(","):
            if name.strip() and plain_name(name.strip()) not in seen:
                seen.add(plain_name(name.strip()))
                breaks.append(resolve_name(name.strip(), table))
        if args.break_module:
            have = {va for _, va in breaks}
            exclude = {plain_name(n) for n in args.exclude.split(",") if n}
            breaks += [b for b in module_breaks(data["rows"], args.break_module, exclude) if b[1] not in have]
        symtab_at = [plain_name(n) for n in args.symtab.split(",") if n]
        tracer = Tracer(table, data["image_base"], breaks, args.function, args.dump, args.max_events,
                        entry_only=args.entry_only, symtab_at=symtab_at,
                        tuples_at=[plain_name(n) for n in tuples_text.split(",") if n])
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
