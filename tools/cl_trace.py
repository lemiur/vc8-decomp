"""Trace the front half of a VC8 compilation: driver passes, IL files, symbol numbers.

Usage:
  python tools/cl_trace.py passes  --source X.cpp [--flags "..."] [-I DIR]... [--dry] [--debug] [--keep DIR] [--json]
  python tools/cl_trace.py symbols --source X.cpp [--flags "..."] [-I DIR]... [--function REGEX] [--globals REGEX]
                                   [--check] [--keep DIR] [--json]
  python tools/cl_trace.py il      (--source X.cpp [--flags "..."] [-I DIR]... | --prefix DIR/stem_) [--records] [--json]
  python tools/cl_trace.py experiment cost [--flags "..."]
  python tools/cl_trace.py experiment flip --source X.cpp --insert-before TEXT --function REGEX
                                           [--local NAME] [--globals REGEX] [--start N --stop M] [--flags "..."] [-I DIR]...
(write --flags="-O2 ..." when the value starts with a dash)

The driver switches used are confirmed against this cl.exe (docs/cl-frontend-trace.md):
/Bd prints each pass's argv, /Bz prints them without running, /Bk<prefix> keeps the IL
files as <prefix>{ex,gl,in,sy}, /Bx /B1 /B2 substitute c1xx /c1 /c2, /d1X and /d2X pass
-X to the front end and back end. cl.exe runs its passes in-process (LoadLibrary of
c1xx.dll then c2.dll); --debug observes that with Windows debug events while a
ReadDirectoryChangesW watcher on a private TMP records each intermediate file's life.

Symbol numbers are read from the kept `sy` IL file (one block per function body, every
parameter, local and compiler temporary with its front-end number) and joined with the
/FAs listing (frame offsets; only block-scope locals carry the `$NNNNN` suffix there).
Each block belongs to the function whose `gl` definition record points at it (c1xx's
CurFuncSyOff); globals come from the decoded `gl` records. The record formats are c1xx's
own (the `symdope` table stoil_1 writes from, read with c1xx.pdb's names); the byte layout
of each field was fixed by decoding whole files of real units without a skipped byte.
Python stdlib and ctypes only.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECT = ROOT / "config" / "project.json"
IL_SUFFIXES = ("ex", "gl", "in", "sy")


class TraceError(RuntimeError):
    pass


# ---------------------------------------------------------------- toolchain

def toolchain(vc_root=None):
    if vc_root is None:
        try:
            vc_root = json.loads(PROJECT.read_text(encoding="utf-8-sig"))["toolchain_root"]
        except (OSError, KeyError, ValueError):
            vc_root = "C:/Program Files (x86)/Microsoft Visual Studio 8/VC"
    vc = Path(vc_root)
    tc = {"vc": vc, "bin": vc / "bin", "cl": vc / "bin" / "cl.exe",
          "ide": vc.parent / "Common7" / "IDE",
          "include": [vc / "include", vc / "PlatformSDK" / "include"],
          "lib": [vc / "lib", vc / "PlatformSDK" / "lib"]}
    if not tc["cl"].is_file():
        raise TraceError("cl.exe not found under " + str(vc))
    return tc


def cl_environment(tc, tmp=None):
    env = dict(os.environ)
    for name in ("CL", "_CL_", "LINK", "_LINK_"):
        env.pop(name, None)  # inherited switches would change the passes silently
    env["PATH"] = os.pathsep.join([str(tc["bin"]), str(tc["ide"]), env.get("PATH", "")])
    env["INCLUDE"] = os.pathsep.join(map(str, tc["include"]))
    env["LIB"] = os.pathsep.join(map(str, tc["lib"]))
    if tmp is not None:
        env["TMP"] = env["TEMP"] = str(tmp)
    return env


def split_flags(text):
    """Split a cl flag string the way a Windows command line would (quotes removed)."""
    if not text:
        return []
    return [item[1:-1] if len(item) >= 2 and item[0] == item[-1] == '"' else item
            for item in shlex.split(text, posix=False)]


def compile_args(flags, includes, source):
    args = ["/nologo", "/c", *split_flags(flags)]
    for inc in includes or ():
        args.append("/I" + str(inc))
    args.append(str(Path(source).resolve()))
    return args


# ---------------------------------------------------------------- /Bd parsing

@dataclass
class Pass:
    name: str
    dll: str
    argv: list
    il: str | None = None


def parse_pass_lines(text):
    """Parse the `<dll> args...' lines /Bd and /Bz print, one per pass."""
    passes = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("`"):
            continue
        body = line[1:-1] if line.endswith("'") else line[1:]
        match = re.match(r"(.+?\.(?:dll|exe))(?:\s+|$)(.*)", body, re.IGNORECASE)
        if not match:
            continue
        dll, rest = match.group(1), match.group(2)
        argv = rest.split(" ") if rest else []
        argv = [a for a in argv if a != ""]
        il = None
        for i, arg in enumerate(argv):
            if arg == "-il" and i + 1 < len(argv):
                il = argv[i + 1]
        passes.append(Pass(Path(dll).stem.lower(), dll, argv, il))
    return passes


# ---------------------------------------------------------------- listing parsing

@dataclass
class FrameLocal:
    name: str
    number: int | None
    offset: int
    size: int | None


@dataclass
class ListedFunction:
    decorated: str
    name: str
    frame: list = field(default_factory=list)


_FRAME = re.compile(r"^(?P<sym>_{1,2}\$?[A-Za-z0-9_?@]+?)\$(?P<num>\d*)\s*=\s*(?P<off>-?\d+)\s*(?:;\s*size\s*=\s*(?P<size>\d+))?")
_PROC = re.compile(r"^(?P<dec>\S+)\s+PROC\b[^;]*(?:;\s*(?P<name>[^,\r\n]+))?")


def parse_listing(text):
    """Functions of a /FA listing with the frame symbols listed before each PROC."""
    functions, pending = [], []
    for line in text.splitlines():
        m = _FRAME.match(line)
        if m:
            sym = m.group("sym")
            name = sym[1:] if sym.startswith("_") else sym
            num = int(m.group("num")) if m.group("num") else None
            size = int(m.group("size")) if m.group("size") else None
            pending.append(FrameLocal(name, num, int(m.group("off")), size))
            continue
        m = _PROC.match(line)
        if m and not line.startswith("EXTRN"):
            functions.append(ListedFunction(m.group("dec"), (m.group("name") or m.group("dec")).strip(), pending))
            pending = []
    return functions


# ---------------------------------------------------------------- IL decoding

def read_losh(data, pos):
    """ILSink::loshwrite value: a u16 below 0x8000, else (0x8000|v&0x7fff, v>>15)."""
    if pos + 2 > len(data):
        raise TraceError("truncated losh value at %d" % pos)
    low = data[pos] | data[pos + 1] << 8
    if not low & 0x8000:
        return low, pos + 2
    if pos + 4 > len(data):
        raise TraceError("truncated long losh value at %d" % pos)
    high = data[pos + 2] | data[pos + 3] << 8
    return (low & 0x7FFF) | high << 15, pos + 4


def encode_losh(value):
    if value < 0x8000:
        return value.to_bytes(2, "little")
    return (0x8000 | value & 0x7FFF).to_bytes(2, "little") + (value >> 15).to_bytes(2, "little")


# Every record of the sy and gl files is one SSR (c1xx's SSR_TYPE) that c1xx's stoil_1
# writes from a format string: the IL_INFO table `symdope` (8 bytes per SSR type, at
# 0x106C8E20 in c1xx.dll 14.00.50727.762) gives, per type, the field-writer codes that stoil_1
# dispatches on (jump table at 0x1056B814). The codes, as dumped from that table:
SSR_FORMATS = {
    0x01: "03 07 05 08 09 0d 0b 0c 10 01 02 06 33 31 32 2e",
    0x02: "03 07 05 08 09 0d 0b 0c 10 01 02 06 33 31 32 04 2e",
    0x03: "03 07 05 08 09 0e 0a", 0x04: "03 05 08 09 0d 11 01 02 06 33 2c", 0x05: "03 16 05 01 08 06",
    0x06: "03", 0x07: "03 07 05 09 0d 0b 01 10 13 06 15 04", 0x08: "03 07 05 09 06 0d 0b 01 14",
    0x09: "03 05 09 17 0f 2f", 0x0A: "03 21", 0x0B: "03 07 05 09 0b 06", 0x0D: "03 07",
    0x0E: "03 05 08 09 0d 11 01 02 06 33 2c 18 19 1a 23 2e", 0x0F: "03 1b",
    0x10: "03 05 08 09 0d 11 01 02 06 2c 1c", 0x11: "03 1d 1e 25 20 2a 35", 0x12: "03 22", 0x13: "03 24",
    0x14: "03 05 15 16", 0x15: "03 05 16", 0x16: "03 26", 0x17: "03 27", 0x18: "03 2d",
    0x1A: "03 07 05 0d 01 02 06 33 31", 0x1B: "03 34"}

# Byte layouts of the SSR types these files were seen to contain. Several writers are
# conditional on compiler state the file does not record (codes 2c, 31, 32, and 2e outside a
# definition): they are optional fields, resolved by requiring the rest of the file to decode.
# Field names follow what the values were seen to mean; `u..` fields are unnamed.
_ATTRS = ("kind", "type", "u0c", "storage", "u01", "size", "u06", "flags", "extra")
_FATTRS = ("kind", "type", "u01", "size", "u06", "flags", "extra")
SSR_LAYOUTS = {
    0x01: ("level", "number", "symkind", "name") + _ATTRS + ("?opt31", "?dyninit", "?calls"),
    0x02: ("level", "number", "symkind", "name") + _ATTRS + ("?opt31", "?dyninit", "dim", "?calls"),
    0x03: ("level", "number", "symkind", "name", "u0e", "u0a"),
    0x04: ("number", "symkind", "name") + _FATTRS + ("?opt2c",),
    0x06: (),
    0x09: ("number", "name", "segattr", "class", "u2f"),
    0x0A: ("u16", "directives"),
    0x0D: ("level",),
    0x0E: ("number", "symkind", "name") + _FATTRS + ("?opt2c", "ex_offset", "sy_offset", "ex_nodes",
                                                     "fnflags", "formals", "calls"),
    0x10: ("number", "symkind", "name") + _FATTRS + ("?opt2c", "target"),
    0x12: ("number", "path", "u16"),
    0x18: ("c16a", "u8", "c16b"),
    0x1A: ("level", "number", "kind", "u01", "size", "u06", "flags", "extra", "?opt31"),
}
SSR_NAMES = {0x01: "data", 0x02: "array", 0x03: "temp", 0x04: "function", 0x06: "end", 0x09: "segment", 0x0A: "directives",
             0x0D: "scope", 0x0E: "definition", 0x10: "vector-dtor", 0x11: "header", 0x12: "file",
             0x18: "ssr18", 0x1A: "anonymous"}
GL_HEADER_SIZE = 25
IL_CALL_GRAPH = 0x100   # gl header IL flag: c1xx wrote call lists (absent under /Od)
# Without IL_CALL_GRAPH (/Od) a definition record ends after `formals`.
SSR_LAYOUTS_NO_CALLS = {**SSR_LAYOUTS, 0x0E: SSR_LAYOUTS[0x0E][:-1]}


class _Bad(Exception):
    pass


def _u8(d, p):
    if p >= len(d):
        raise _Bad("eof")
    return d[p], p + 1


def _u16(d, p):
    if p + 2 > len(d):
        raise _Bad("eof")
    return d[p] | d[p + 1] << 8, p + 2


def _losh(d, p):
    try:
        return read_losh(d, p)
    except TraceError as error:
        raise _Bad(str(error))


def _c32(d, p):
    """One byte below 0x80, else 0x80 then a u32 (stoil_1's `test ecx, 0xffffff80` writers)."""
    v, p = _u8(d, p)
    if v != 0x80:
        return v, p
    if p + 4 > len(d):
        raise _Bad("eof")
    return int.from_bytes(d[p:p + 4], "little"), p + 4


def _c16(d, p):
    """One byte below 0x80, else 0x80 then a u16."""
    v, p = _u8(d, p)
    if v != 0x80:
        return v, p
    return _u16(d, p)


def _u32(d, p):
    if p + 4 > len(d):
        raise _Bad("eof")
    return int.from_bytes(d[p:p + 4], "little"), p + 4


def _cstr(d, p):
    end = d.find(b"\0", p)
    if end < 0:
        raise _Bad("unterminated name")
    return d[p:end].decode("latin-1"), end + 1


def _kind(d, p):
    k, p = _u8(d, p)
    if not k & 0x80:
        raise _Bad("kind byte without bit 7")
    if k & 0x40:  # a second kind byte follows (vector and class types)
        ext, p = _u8(d, p)
        return (k, ext), p
    return (k, None), p


def _calls(d, p):
    count, p = _u8(d, p)
    items = []
    for _ in range(count):
        number, p = _losh(d, p)
        times, p = _c16(d, p)
        items.append((number, times))
    return items, p


def _directives(d, p):
    count, p = _u8(d, p)
    items = []
    for _ in range(count):
        kind, p = _u8(d, p)
        text, p = _cstr(d, p)
        items.append((kind, text))
    return items, p


def _extra(d, p, flags):
    """What follows the flags (a u16) when bit 0x80 is set: a byte (`extra`), the losh number of
    the symbol's named segment when bit 0x02 is set (`segment`: `.xdata$x` for the `__CT`/`__TI`
    throw records, `.CRT$XCU` for an initializer pointer), and a byte (`extra2`, 0 so far). Read
    as one losh, a segment number whose low byte is below 0x80 desynchronised the decoder."""
    extra, p = _u8(d, p)
    out = {"extra": extra}
    if flags & 0x02:
        out["segment"], p = _losh(d, p)
    out["extra2"], p = _u8(d, p)
    return out, p


_FIELD = {"level": _u8, "number": _losh, "symkind": _u8, "name": _cstr, "path": _cstr, "kind": _kind,
          "type": _u8, "u0c": _u8, "storage": _u8, "u01": _u8, "size": _c32, "u06": _u8, "flags": _u16,
          "opt31": _losh, "dyninit": _losh, "opt2c": _u8, "dim": _c32, "calls": _calls, "u0e": _u8,
          "u0a": _u8, "ex_offset": _c32, "sy_offset": _c32, "ex_nodes": _c16, "fnflags": _losh,
          "formals": _u8, "target": _losh, "u16": _u16, "u8": _u8, "c16a": _c16, "c16b": _c16,
          "directives": _directives, "segattr": _u8, "class": _cstr, "u2f": _u32}


@dataclass
class IlRecord:
    tag: int
    offset: int
    end: int
    fields: dict

    @property
    def kind(self):
        return SSR_NAMES.get(self.tag, "ssr%02x" % self.tag)


def _record_alternatives(d, pos, optional=True, layouts=None):
    """Every decoding of the record at pos: [(fields, end)], optional fields absent first."""
    tag, p = _u8(d, pos)
    layout = (layouts or SSR_LAYOUTS).get(tag)
    if layout is None:
        raise _Bad("unknown SSR type %#x" % tag)
    states = [({}, p)]
    for name in layout:
        is_optional = name.startswith("?")
        name = name.lstrip("?")
        nxt = []
        for fields, q in states:
            if name == "extra":
                if fields["flags"] & 0x80:
                    try:
                        value, q2 = _extra(d, q, fields["flags"])
                    except _Bad:
                        continue
                    nxt.append((dict(fields, **value), q2))
                else:
                    nxt.append((fields, q))
                continue
            if is_optional:
                nxt.append((fields, q))
                if not optional:
                    continue
            try:
                value, q2 = _FIELD[name](d, q)
            except _Bad:
                continue
            nxt.append((dict(fields, **{name: value}), q2))
        states = nxt
        if not states:
            raise _Bad("SSR %#x: no decoding of field %s" % (tag, name))
    return [(fields, q) for fields, q in states]


def decode_records(data, start=0, end=None, lookahead=4, layouts=None):
    """Decode SSR records in data[start:end]; returns (records, unparsed spans).

    Each record takes, in order of preference: a decoding without optional fields whose next
    `lookahead` records decode; one whose next record decodes (bytes no decoding explains come
    later); a decoding with optional fields whose next `lookahead` records decode (the `dyninit`
    number of an initializer pointer `x$initializer$`); any decoding without optional fields
    (what follows is then reported).
    Bytes no decoding explains are skipped to the next offset that decodes with the full
    lookahead and reported as (offset, hex).
    """
    end = len(data) if end is None else end
    memo, ok_memo = {}, {}

    def alternatives(q, optional):
        key = (q, optional)
        if key not in memo:
            try:
                memo[key] = [(f, q2) for f, q2 in _record_alternatives(data, q, optional, layouts) if q2 <= end]
            except _Bad:
                memo[key] = []
        return memo[key]

    def ok(q, depth):
        if q == end or depth == 0:
            return True
        if q > end:
            return False
        key = (q, depth)
        if key not in ok_memo:
            ok_memo[key] = (any(ok(q2, depth - 1) for _, q2 in alternatives(q, False))
                            or any(ok(q2, depth - 1) for _, q2 in alternatives(q, True)))
        return ok_memo[key]

    records, unparsed, pos = [], [], start
    while pos < end:
        strict = alternatives(pos, False)
        good = ([a for a in strict if ok(a[1], lookahead)] or [a for a in strict if ok(a[1], 1)]
                or [a for a in alternatives(pos, True) if ok(a[1], lookahead)] or strict)
        if good:
            fields, q = good[0]
            records.append(IlRecord(data[pos], pos, q, fields))
            pos = q
            continue
        nxt = pos + 1
        while nxt < end and not ok(nxt, lookahead):
            nxt += 1
        unparsed.append((pos, data[pos:nxt].hex()))
        pos = nxt
    return records, unparsed


@dataclass
class SyRecord:
    kind: str           # param/local/array/temp/anon
    tag: int
    level: int
    number: int
    name: str | None = None
    attrs: dict = field(default_factory=dict)
    offset: int = 0
    scope: int = 0      # index of the scope record (0D) the symbol belongs to, 0 before any


@dataclass
class SyBlock:
    records: list = field(default_factory=list)
    unparsed: list = field(default_factory=list)   # (offset, hex) spans no decoding explains
    offset: int = 0                                 # where the block starts (gl definitions point here)
    scopes: list = field(default_factory=list)      # level of each scope record, in order

    def numbers(self):
        return sorted(r.number for r in self.records)


def _sy_symbol(rec, scope):
    f = rec.fields
    attrs = {k: v for k, v in f.items() if k not in ("level", "number", "name")}
    if "kind" in attrs:
        attrs["class"], ext = attrs.pop("kind")
        if ext is not None:
            attrs["class2"] = ext
    if rec.tag == 0x03:
        kind = "temp"
    elif rec.tag == 0x1A:
        kind = "anon"
    elif f.get("storage") == 3:
        kind = "param"
    elif rec.tag == 0x02:
        kind = "array"
    else:
        kind = "local"
    name = f.get("name") or None
    return SyRecord(kind, rec.tag, f["level"], f["number"], name, attrs, rec.offset, scope)


def parse_sy(data):
    """Split a kept `sy` file into per-function blocks of symbol records.

    A block is the records stoil_1 wrote for one function body, ended by SSR 06: temporaries
    (03), named parameters and locals (01, 02 for arrays), unnamed compiler symbols (1A), and a
    scope record (0D level) before each scope's symbols. Scopes are not closed explicitly; a
    scope record at or below the current level starts a sibling.
    """
    records, unparsed = decode_records(data)
    blocks, block, scope = [], SyBlock(), 0
    spans = list(unparsed)
    for rec in records:
        while spans and spans[0][0] < rec.offset:
            block.unparsed.append(spans.pop(0))
        if not block.records and not block.scopes and not block.unparsed:
            block.offset = rec.offset
        if rec.tag == 0x06:
            blocks.append(block)
            block, scope = SyBlock(offset=rec.end), 0
        elif rec.tag == 0x0D:
            block.scopes.append(rec.fields["level"])
            scope = len(block.scopes)
        elif rec.tag in (0x01, 0x02, 0x03, 0x1A):
            block.records.append(_sy_symbol(rec, scope))
        else:
            block.unparsed.append((rec.offset, data[rec.offset:rec.end].hex()))
    block.unparsed.extend(spans)
    if block.records or block.unparsed:
        blocks.append(block)
    return blocks


def parse_gl_header(data):
    """SSR 11, the gl header: u16 0x386, u32 0x01321829, the unit's symbol count (u32), u8 1,
    the IL flags (u32), five more bytes, and the offset of the trailer (u32)."""
    if len(data) < 11 or data[0] != 0x11:
        raise TraceError("gl file too short or without its header record")
    info = {"signature": data[:7].hex(), "symbol_count": int.from_bytes(data[7:11], "little")}
    if len(data) >= GL_HEADER_SIZE:
        info["il_flags"] = int.from_bytes(data[12:16], "little")
        info["trailer_offset"] = int.from_bytes(data[21:25], "little")
    return info


@dataclass
class GlSymbol:
    kind: str           # data/array/function/definition/vector-dtor
    number: int
    name: str
    level: int = 0
    offset: int = 0
    attrs: dict = field(default_factory=dict)


@dataclass
class GlFile:
    header: dict
    records: list
    unparsed: list
    symbols: list       # GlSymbol, in file order
    files: dict         # number -> path
    directives: list    # (kind, text) of the trailer: 04 default library, 0A linker directive
    segments: dict = field(default_factory=dict)    # number -> name of each segment record (SSR 09)

    def definitions(self):
        return [s for s in self.symbols if s.kind == "definition"]


def parse_gl(data):
    """Decode a kept `gl` file: header, symbol records up to the trailer, trailer directives."""
    header = parse_gl_header(data)
    end = header.get("trailer_offset", len(data))
    if not GL_HEADER_SIZE <= end <= len(data):
        end = len(data)
    layouts = None if header.get("il_flags", IL_CALL_GRAPH) & IL_CALL_GRAPH else SSR_LAYOUTS_NO_CALLS
    records, unparsed = decode_records(data, GL_HEADER_SIZE, end, layouts=layouts)
    if end < len(data):
        tail, more = decode_records(data, end, len(data))
        records += tail
        unparsed += more
    symbols, files, directives, segments = [], {}, [], {}
    for rec in records:
        f = rec.fields
        if rec.tag in (0x01, 0x02, 0x04, 0x0E, 0x10):
            attrs = {k: v for k, v in f.items() if k not in ("number", "name", "level")}
            symbols.append(GlSymbol(rec.kind, f["number"], f["name"], f.get("level", 0), rec.offset, attrs))
        elif rec.tag == 0x12:
            files[f["number"]] = f["path"]
        elif rec.tag == 0x0A:
            directives += f["directives"]
        elif rec.tag == 0x09:
            segments[f["number"]] = f["name"]
    return GlFile(header, records, unparsed, symbols, files, directives, segments)


def scan_gl_names(data):
    """(name, number) of every symbol record of a `gl` file, decoded (see parse_gl)."""
    return [(s.name, s.number) for s in parse_gl(data).symbols]


def il_strings(data, minimum=3):
    return [m.group().decode("latin-1") for m in re.finditer(rb"[A-Za-z_?@$][\x21-\x7e]{%d,}(?=\x00)" % (minimum - 1), data)]


def ex_function_numbers(data):
    """Best-effort function number of each body in an `ex` file, in file order.

    Read from the opening of each body (`4F 23 ...` then `53 53 26 <losh number>`); this is a
    pattern, not a decoder: it only names sy blocks that have no gl definition record.
    """
    numbers = []
    for m in re.finditer(rb"\x4f\x23", data):
        at = data.find(b"\x53\x53\x26", m.end())
        if at < 0:
            break
        try:
            numbers.append(read_losh(data, at + 3)[0])
        except TraceError:
            numbers.append(None)
    return numbers


# ---------------------------------------------------------------- joining

@dataclass
class FunctionSymbols:
    name: str
    decorated: str | None
    symbols: list
    number: int | None = None
    compiled: bool = True       # False: no gl definition, so c2 never reads this body
    sy_offset: int | None = None


# Frame symbols the listing names that are not front-end symbols of the function.
_FRAME_INTERNAL = re.compile(r"^(_\$EHRec|_\$ArrayPad|_\$ReturnUdt|_\$S\d*|tv\d+|\$T\d+|_\$initVBases)")


def join_blocks(blocks, listed, definitions=None, ex_numbers=None, gl_names=None):
    """Attribute sy blocks to functions and attach the listing's frame data.

    With `definitions` (gl definition records), a block belongs to the definition whose
    sy_offset is the block's offset, and the listing function is the one with that decorated
    name. Blocks no definition points at are inline bodies c2 never compiled. Without
    definitions (old callers, tests), blocks pair with listing functions by shared frame names.
    """
    by_offset = {d.attrs.get("sy_offset"): d for d in definitions or ()}
    by_decorated = {fn.decorated: fn for fn in listed}
    by_number = {}
    for name, number in gl_names or ():
        by_number.setdefault(number, name)
    result, used = [], set()
    for index, block in enumerate(blocks):
        fn, number, compiled, label, decorated = None, None, True, None, None
        if definitions is not None:
            d = by_offset.get(block.offset)
            if d is not None:
                decorated, number = d.name, d.number
                fn = by_decorated.get(decorated)
                label = fn.name if fn else decorated
            else:
                compiled = False
                number = ex_numbers[index] if ex_numbers and index < len(ex_numbers) else None
                guess = by_number.get(number)
                label = "#%d inline body%s, not compiled" % (
                    index, " (ex: function $%s%s)" % (number, " " + guess if guess else "") if number else "")
        else:
            fn = _pair_by_names(block, listed, used)
            if fn is not None:
                used.add(id(fn))
                label, decorated = fn.name, fn.decorated
        frame = {}
        for local in fn.frame if fn else ():
            frame.setdefault((local.name, local.number), local)
            frame.setdefault((local.name, None), local)
        # Unnamed parameters are `__formal` in sy and `___formal$` in the listing: pair them in declaration order
        # (ascending number, ascending stack offset) when the counts agree.
        formals = sorted((l for l in (fn.frame if fn else ()) if l.name == "__formal"), key=lambda l: l.offset)
        unnamed = sorted((r for r in block.records if r.kind == "param" and r.name in (None, "__formal")),
                         key=lambda r: r.number)
        by_formal = dict(zip((r.number for r in unnamed), formals)) if len(formals) == len(unnamed) else {}
        rows = []
        for r in sorted(block.records, key=lambda r: r.number):
            local = by_formal.get(r.number) if r.kind == "param" else None
            if r.name and local is None:
                local = frame.get((r.name, r.number)) or frame.get((r.name, None))
            rows.append({"number": r.number, "mod64": r.number % 64, "kind": r.kind, "level": r.level,
                         "scope": r.scope, "name": r.name or "<%s>" % r.kind,
                         "listing_suffix": local.number if local else None,
                         "frame_offset": local.offset if local else None,
                         "size": (local.size if local and local.size is not None else r.attrs.get("size"))})
        result.append(FunctionSymbols(label or "#%d" % index, decorated, rows, number, compiled, block.offset))
    return result


def _pair_by_names(block, listed, used):
    names = {r.name for r in block.records if r.name}
    numbered = {(r.name, r.number) for r in block.records if r.name}
    best, best_score = None, 0
    for fn in listed:
        if id(fn) in used:
            continue
        score = sum(100 if l.number is not None and (l.name, l.number) in numbered else 1 if l.name in names else 0
                    for l in fn.frame)
        if score > best_score:
            best, best_score = fn, score
    return best


def frame_mismatches(function, listed_fn, total=None):
    """(missing, back_end): listing frame names the function's sy block does not hold.

    `back_end` are suffixed names numbered at or above the unit's symbol count (`total`, from
    the gl header): c2 numbered them itself, for the locals of a function it inlined. A local
    that c2 keeps in a register has no frame slot, so only `missing` is a disagreement; the
    compiler's own frame symbols (`__$EHRec$`...) are ignored.
    """
    mine = {(r["name"], r["number"]) for r in function.symbols}
    names = {r["name"] for r in function.symbols}
    paired = {r["frame_offset"] for r in function.symbols if r["name"] in ("<param>", "__formal")}
    missing, back_end = [], []
    for local in listed_fn.frame:
        if _FRAME_INTERNAL.match(local.name) or (local.name == "__formal" and local.offset in paired):
            continue
        if local.number is not None:
            if (local.name, local.number) in mine:
                continue
            label = "%s$%d" % (local.name, local.number)
            (back_end if total is not None and local.number >= total else missing).append(label)
        elif local.name not in names:
            missing.append(local.name)
    return missing, back_end


# ---------------------------------------------------------------- running cl

def run_cl(tc, args, cwd, tmp=None, timeout=300):
    return subprocess.run([str(tc["cl"]), *args], cwd=str(cwd), env=cl_environment(tc, tmp),
                          capture_output=True, text=True, errors="replace", timeout=timeout)


def workdir(keep):
    if keep:
        path = Path(keep).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path, False
    return Path(tempfile.mkdtemp(prefix="cl_trace_")), True


def compile_keep(tc, source, flags, includes, out, listing=True):
    """Compile once with /Bk into `out`; returns (prefix, completed process)."""
    stem = Path(source).stem
    prefix = out / (stem + "_")
    extra = ["/Bk" + str(prefix), "/Fo" + str(out / (stem + ".obj"))]
    if listing:
        extra += ["/FAs", "/Fa" + str(out / (stem + ".asm"))]
    args = compile_args(flags, includes, source)
    args = args[:-1] + extra + args[-1:]
    proc = run_cl(tc, args, out)
    return prefix, proc


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# ---------------------------------------------------------------- live observation (Windows)

class DirectoryWatcher(threading.Thread):
    """ReadDirectoryChangesW on one directory: every create/size/delete with a timestamp."""

    def __init__(self, path, start):
        super().__init__(daemon=True)
        self.path, self.start_time, self.events = str(path), start, []
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.restype = ctypes.c_void_p
        k.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                  ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        k.ReadDirectoryChangesW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                            ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p,
                                            ctypes.c_void_p]
        k.CancelIoEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        self.k = k
        # FILE_LIST_DIRECTORY, share read|write|delete, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS
        self.handle = k.CreateFileW(self.path, 1, 7, None, 3, 0x02000000, None)
        if self.handle in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        self.stopping = False

    def run(self):
        buffer = ctypes.create_string_buffer(65536)
        returned = ctypes.c_uint32()
        actions = {1: "create", 2: "delete", 3: "modify", 4: "rename-from", 5: "rename-to"}
        # FILE_NOTIFY_CHANGE_FILE_NAME | SIZE | LAST_WRITE
        while not self.stopping:
            ok = self.k.ReadDirectoryChangesW(self.handle, buffer, len(buffer), 0, 0x1 | 0x8 | 0x10,
                                              ctypes.byref(returned), None, None)
            if not ok:
                break
            when = time.perf_counter() - self.start_time
            raw, pos = buffer.raw[:returned.value], 0
            while raw:
                nxt, action, length = int.from_bytes(raw[pos:pos + 4], "little"), \
                    int.from_bytes(raw[pos + 4:pos + 8], "little"), int.from_bytes(raw[pos + 8:pos + 12], "little")
                name = raw[pos + 12:pos + 12 + length].decode("utf-16-le")
                try:
                    size = os.path.getsize(os.path.join(self.path, name))
                except OSError:
                    size = None
                self.events.append({"t_ms": round(when * 1000, 2), "action": actions.get(action, str(action)),
                                    "file": name, "size": size})
                if not nxt:
                    break
                pos += nxt

    def stop(self):
        self.stopping = True
        self.k.CancelIoEx(self.handle, None)
        self.join(timeout=5)
        self.k.CloseHandle(self.handle)


def file_lifetimes(events):
    files = {}
    for e in events:
        item = files.setdefault(e["file"], {"file": e["file"], "created_ms": None, "deleted_ms": None,
                                            "max_size": 0, "events": 0})
        item["events"] += 1
        if e["action"] in ("create", "rename-to") and item["created_ms"] is None:
            item["created_ms"] = e["t_ms"]
        if e["action"] in ("delete", "rename-from"):
            item["deleted_ms"] = e["t_ms"]
        if e["size"]:
            item["max_size"] = max(item["max_size"], e["size"])
    return list(files.values())


def debug_run(tc, args, cwd, tmp, timeout=300):
    """Run cl.exe under a read-only debug loop; returns (exit code, output, module timeline)."""
    pointer = ctypes.sizeof(ctypes.c_void_p)

    class DebugInfo(ctypes.Union):
        _fields_ = [("alignment", ctypes.c_void_p), ("raw", ctypes.c_ubyte * (160 if pointer == 8 else 84))]

    class DebugEvent(ctypes.Structure):
        _fields_ = [("code", ctypes.c_uint32), ("pid", ctypes.c_uint32), ("tid", ctypes.c_uint32),
                    ("info", DebugInfo)]

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.WaitForDebugEvent.argtypes = [ctypes.POINTER(DebugEvent), ctypes.c_uint32]
    k.ContinueDebugEvent.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    k.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    k.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.DebugActiveProcessStop.argtypes = [ctypes.c_uint32]
    start = time.perf_counter()
    timeline, bases = [], {}
    log = Path(cwd) / "cl_trace.stdout.txt"

    def path_of(handle):
        if not handle:
            return None
        buffer = ctypes.create_unicode_buffer(32768)
        try:
            if k.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0):
                return buffer.value.removeprefix("\\\\?\\")
        finally:
            k.CloseHandle(handle)
        return None

    with log.open("wb") as out:
        # DEBUG_PROCESS (0x1): children too, should the driver spawn any.
        process = subprocess.Popen([str(tc["cl"]), *args], cwd=str(cwd), env=cl_environment(tc, tmp),
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW | 0x1)
        deadline, live = time.monotonic() + timeout, set()
        try:
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("cl trace exceeded %d s" % timeout)
                event = DebugEvent()
                if not k.WaitForDebugEvent(ctypes.byref(event), 500):
                    if ctypes.get_last_error() == 121:
                        continue
                    raise ctypes.WinError(ctypes.get_last_error())
                raw = bytes(event.info.raw)
                when = round((time.perf_counter() - start) * 1000, 2)
                word = lambda i: int.from_bytes(raw[i * pointer:(i + 1) * pointer], "little")
                status = 0x10002  # DBG_CONTINUE
                if event.code == 3:  # CREATE_PROCESS: hFile, hProcess, hThread, lpBaseOfImage
                    live.add(event.pid)
                    timeline.append({"t_ms": when, "pid": event.pid, "event": "process",
                                     "path": path_of(word(0))})
                elif event.code == 6:  # LOAD_DLL: hFile, lpBaseOfDll
                    name = path_of(word(0))
                    bases[(event.pid, word(1))] = name
                    timeline.append({"t_ms": when, "pid": event.pid, "event": "load", "path": name})
                elif event.code == 7:  # UNLOAD_DLL: lpBaseOfDll
                    timeline.append({"t_ms": when, "pid": event.pid, "event": "unload",
                                     "path": bases.get((event.pid, word(0)))})
                elif event.code == 5:
                    timeline.append({"t_ms": when, "pid": event.pid, "event": "exit",
                                     "code": int.from_bytes(raw[:4], "little")})
                    live.discard(event.pid)
                elif event.code == 1:
                    exc = int.from_bytes(raw[:4], "little")
                    if exc not in (0x80000003, 0x4000001F):  # breakpoint, WOW64 breakpoint
                        status = 0x80010001  # DBG_EXCEPTION_NOT_HANDLED
                if not k.ContinueDebugEvent(event.pid, event.tid, status):
                    raise ctypes.WinError(ctypes.get_last_error())
                if event.code == 5 and not live:
                    break
            code = process.wait(timeout=10)
        finally:
            if process.poll() is None:
                k.DebugActiveProcessStop(process.pid)
                process.terminate()
                process.wait(timeout=5)
    return code, log.read_text(errors="replace"), timeline


# ---------------------------------------------------------------- commands

def describe_il(prefix):
    prefix = Path(prefix)
    files = {}
    for suffix in IL_SUFFIXES + ("db", "lk", "md"):
        path = prefix.with_name(prefix.name + suffix)
        if not path.is_file():
            continue
        data = path.read_bytes()
        info = {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "head": data[:16].hex()}
        if suffix == "gl":
            info.update(parse_gl_header(data))
            info["strings"] = len(il_strings(data))
            gl = parse_gl(data)
            info["named_records"] = len(gl.symbols)
            info["definitions"] = len(gl.definitions())
            info["unparsed_spans"] = len(gl.unparsed)
        elif suffix == "sy":
            blocks = parse_sy(data)
            info["functions"] = len(blocks)
            info["records"] = sum(len(b.records) for b in blocks)
            info["unparsed_spans"] = sum(len(b.unparsed) for b in blocks)
            info["blocks"] = [[asdict(r) for r in b.records] for b in blocks]
            info["block_offsets"] = [b.offset for b in blocks]
        else:
            info["strings"] = len(il_strings(data))
        files[suffix] = info
    return files


def cmd_passes(ns, tc):
    out, temporary = workdir(ns.keep)
    tmp = out / "tmp"
    tmp.mkdir(exist_ok=True)
    args = compile_args(ns.flags, ns.include, ns.source)
    args = args[:-1] + ["/Bz" if ns.dry else "/Bd", "/Fo" + str(out / (Path(ns.source).stem + ".obj"))] + args[-1:]
    result = {"cl": str(tc["cl"]), "args": args, "workdir": str(out)}
    if ns.dry:
        proc = run_cl(tc, args, out)
        code, text, timeline, events = proc.returncode, proc.stdout + proc.stderr, [], []
    else:
        start = time.perf_counter()
        watcher = DirectoryWatcher(tmp, start)
        watcher.start()
        try:
            if ns.debug:
                code, text, timeline = debug_run(tc, args, out, tmp)
            else:
                proc = run_cl(tc, args, out, tmp)
                code, text, timeline = proc.returncode, proc.stdout + proc.stderr, []
            time.sleep(0.05)
        finally:
            watcher.stop()
        events = watcher.events
    result.update({"returncode": code, "passes": [asdict(p) for p in parse_pass_lines(text)],
                   "il_files": file_lifetimes(events), "dir_events": events, "modules": timeline})
    if ns.keep:
        prefix, proc = compile_keep(tc, ns.source, ns.flags, ns.include, out, listing=False)
        result["kept_il"] = describe_il(prefix)
        for item in result["kept_il"].values():
            item.pop("blocks", None)
    if ns.json:
        print(json.dumps(result, indent=2))
    else:
        print("cl %s -> exit %s" % (" ".join(args), code))
        for p in result["passes"]:
            print("pass %-5s %s" % (p["name"], p["dll"]))
            print("    " + " ".join(p["argv"]))
        if result["il_files"]:
            print("intermediate files in private TMP (ReadDirectoryChangesW):")
            for f in result["il_files"]:
                print("    %-24s created %8s ms  deleted %8s ms  max %8d bytes  (%d events)"
                      % (f["file"], f["created_ms"], f["deleted_ms"], f["max_size"], f["events"]))
        elif not ns.dry:
            print("no file appeared in the private TMP")
        for m in timeline:
            if m["event"] in ("process", "exit") or (m.get("path") and re.search(
                    r"\\(c1xx|c1|c2|c1ast|c1xxast|mspdb80|msobj80|link|cl)\.(dll|exe)$", m["path"] or "", re.I)):
                print("    %8.2f ms  %-7s %s" % (m["t_ms"], m["event"], m.get("path") or m.get("code")))
        for suffix, info in result.get("kept_il", {}).items():
            print("kept %-3s %8d bytes  %s" % (suffix, info["size"], info["path"]))
    if temporary:
        shutil.rmtree(out, ignore_errors=True)
    return 0 if code == 0 else 1


@dataclass
class UnitSymbols:
    functions: list         # FunctionSymbols, one per sy block, in file order
    total: int | None       # the unit's symbol count (gl header)
    blocks: list            # SyBlock
    gl: GlFile | None
    listed: list            # ListedFunction of the /FAs listing

    def globals(self):
        return [(s.name, s.number) for s in self.gl.symbols] if self.gl else []

    def unparsed(self):
        return sum(len(b.unparsed) for b in self.blocks), len(self.gl.unparsed) if self.gl else 0


def unit_symbols(prefix, asm=None):
    """Decode the kept IL files at prefix (and the /FAs listing) into per-function symbols."""
    prefix = Path(prefix)
    sy = prefix.with_name(prefix.name + "sy")
    if not sy.is_file():
        raise TraceError("no sy file at " + str(sy))
    blocks = parse_sy(sy.read_bytes())
    listed = parse_listing(Path(asm).read_text(errors="replace")) if asm and Path(asm).is_file() else []
    glp, exp = prefix.with_name(prefix.name + "gl"), prefix.with_name(prefix.name + "ex")
    gl = parse_gl(glp.read_bytes()) if glp.is_file() else None
    ex_numbers = ex_function_numbers(exp.read_bytes()) if exp.is_file() else None
    if ex_numbers is not None and len(ex_numbers) != len(blocks):
        ex_numbers = None  # the pattern disagrees with the sy blocks: name nothing from it
    functions = join_blocks(blocks, listed, gl.definitions() if gl else None, ex_numbers,
                            [(s.name, s.number) for s in gl.symbols] if gl else None)
    total = gl.header["symbol_count"] if gl else None
    return UnitSymbols(functions, total, blocks, gl, listed)


def symbols_of(tc, source, flags, includes, out):
    prefix, proc = compile_keep(tc, source, flags, includes, out)
    if proc.returncode != 0 or not prefix.with_name(prefix.name + "sy").is_file():
        raise TraceError("compile failed:\n" + proc.stdout + proc.stderr)
    return unit_symbols(prefix, out / (Path(source).stem + ".asm"))


def check_frames(unit):
    """{function name: (missing, back_end)} for every compiled function the listing holds."""
    by_decorated = {fn.decorated: fn for fn in unit.listed}
    result = {}
    for f in unit.functions:
        fn = by_decorated.get(f.decorated)
        if f.compiled and fn is not None:
            result[f.name] = frame_mismatches(f, fn, unit.total)
    return result


def cmd_symbols(ns, tc):
    out, temporary = workdir(ns.keep)
    try:
        unit = symbols_of(tc, ns.source, ns.flags, ns.include, out)
    finally:
        if temporary:
            shutil.rmtree(out, ignore_errors=True)
    functions = unit.functions
    if ns.function:
        pattern = re.compile(ns.function)
        functions = [f for f in functions if pattern.search(f.name) or (f.decorated and pattern.search(f.decorated))]
    picked = []
    if ns.globals:
        gpat = re.compile(ns.globals)
        picked = [{"name": s.name, "number": s.number, "mod64": s.number % 64, "kind": s.kind}
                  for s in unit.gl.symbols if gpat.search(s.name)] if unit.gl else []
    sy_unparsed, gl_unparsed = unit.unparsed()
    checks = check_frames(unit) if ns.check else {}
    if ns.json:
        print(json.dumps({"unit_symbol_count": unit.total, "globals": picked,
                          "sy_unparsed": sy_unparsed, "gl_unparsed": gl_unparsed,
                          "frame_mismatches": {k: v[0] for k, v in checks.items() if v[0]},
                          "back_end_frame_symbols": {k: v[1] for k, v in checks.items() if v[1]},
                          "functions": [asdict(f) for f in functions]}, indent=2))
        return 0
    print("unit symbol count (gl header): %s" % unit.total)
    for g in picked:
        print("global %7d mod64 %2d  %-11s %s" % (g["number"], g["mod64"], g["kind"], g["name"]))
    for f in functions:
        print("%s  %s%s" % (f.name, f.decorated or "", "" if f.number is None else "  $%d" % f.number))
        print("    %7s %5s %-6s %3s %3s %-24s %8s %6s %s" % ("number", "mod64", "kind", "lvl", "scp", "name", "suffix",
                                                          "frame", "size"))
        for r in f.symbols:
            print("    %7d %5d %-6s %3d %3d %-24s %8s %6s %s" % (
                r["number"], r["mod64"], r["kind"], r["level"], r["scope"], r["name"],
                "" if r["listing_suffix"] is None else "$%d" % r["listing_suffix"],
                "" if r["frame_offset"] is None else r["frame_offset"], "" if r["size"] is None else r["size"]))
    if ns.check:
        bad = {k: v[0] for k, v in checks.items() if v[0]}
        print("frame check: %d compiled functions with a listing, %d whose frame names a symbol their sy block lacks"
              % (len(checks), len(bad)))
        for name, missing in bad.items():
            print("    %s: %s" % (name, " ".join(missing)))
        for name, (_, back_end) in checks.items():
            if back_end:
                print("    %s: back-end symbols (c2's numbers, past the unit count): %s" % (name, " ".join(back_end)))
    if sy_unparsed or gl_unparsed:
        print("warning: %d sy and %d gl spans not decoded (skipped by resync)" % (sy_unparsed, gl_unparsed))
    return 1 if ns.check and any(v[0] for v in checks.values()) else 0


def cmd_il(ns, tc):
    temporary, out = False, None
    if ns.prefix:
        prefix = Path(ns.prefix)
    else:
        if not ns.source:
            raise TraceError("il needs --source or --prefix")
        out, temporary = workdir(ns.keep)
        prefix, proc = compile_keep(tc, ns.source, ns.flags, ns.include, out, listing=False)
        if proc.returncode != 0:
            raise TraceError("compile failed:\n" + proc.stdout + proc.stderr)
    try:
        files = describe_il(prefix)
    finally:
        if temporary:
            shutil.rmtree(out, ignore_errors=True)
    if ns.json:
        print(json.dumps(files, indent=2))
        return 0
    for suffix, info in files.items():
        line = "%-3s %9d bytes  head %s" % (suffix, info["size"], info["head"])
        if suffix == "gl":
            line += "  symbol_count %d  named %d  definitions %d  unparsed %d" % (
                info["symbol_count"], info["named_records"], info["definitions"], info["unparsed_spans"])
        elif suffix == "sy":
            line += "  functions %d  records %d  unparsed %d" % (info["functions"], info["records"], info["unparsed_spans"])
        else:
            line += "  strings %d" % info["strings"]
        print(line)
    if "sy" in files and ns.records:
        for i, block in enumerate(files["sy"]["blocks"]):
            print("sy function #%d" % i)
            for r in block:
                print("    %7d %-6s lvl %d %-20s %s" % (r["number"], r["kind"], r["level"], r["name"] or "<temp>",
                                                      " ".join("%s=%s" % kv for kv in r["attrs"].items())))
    return 0


COST_CASES = [
    ("int v0;", "int global"), ("extern int e();", "function declaration, no parameters"),
    ("extern int e(int);", "function declaration, 1 parameter"),
    ("extern int e(int a, int b, int c);", "function declaration, 3 parameters"),
    ("typedef int T;", "typedef"), ("#define M 1", "macro"), ("namespace N {}", "empty namespace"),
    ("enum E { A };", "enum, 1 enumerator"), ("enum E { A, B, C, D };", "enum, 4 enumerators"),
    ("struct S;", "struct forward declaration"), ("struct S {};", "empty struct"),
    ("struct S { int a; };", "struct, 1 data member"), ("struct S { int a, b, c, d; };", "struct, 4 data members"),
    ("struct S { void m(); };", "struct, 1 method declaration"),
    ("struct S { int m() { return 0; } };", "struct, 1 inline method"),
    ("struct S { virtual void m(); };", "struct, 1 virtual method"),
    ("struct S { S(); ~S(); };", "struct, constructor + destructor declarations"),
    ("inline int e(int a) { return a; }", "inline function, 1 parameter, never called"),
    ("int e(int a) { int b = a; return b; }", "function definition, 1 parameter + 1 local"),
    ("const char* s = \"abc\";", "global initialised with a string literal"),
    ("int u = cl_trace_g(0);", "global with a dynamic initialiser"),
    ("template<class T> struct X { T a; };", "class template, not instantiated"),
    ("template<class T> struct X { T a; }; X<int>* xp;", "class template + pointer to X<int>"),
    ("template<class T> struct X { T a; }; X<int> xi;", "class template + X<int> object"),
    ("template<class T> T id(T a) { return a; }", "function template, not instantiated"),
    ("int w() { return 1; }", "control: int w() { return 1; }"),
    ("template<class T> T id(T a) { return a; } int w() { return id(1); }", "function template + w() calling id<int>"),
    ("template<class T> T id(T a) { return a; } int w() { return id(1) + id(2); }", "... id<int> called twice"),
    ("inline int e(int a) { return a; } int w() { return e(1); }", "inline e + w() calling e"),
]


def probe_number(tc, prefix, flags, work):
    path = work / "probe.cpp"
    path.write_text("int cl_trace_g(int*);\n" + prefix +
                    "\nint cl_trace_f(int n) { if (n) { int probe = n; return cl_trace_g(&probe); } return 0; }\n")
    functions = symbols_of(tc, path, flags, [], work).functions
    return next(r["number"] for f in functions for r in f.symbols if r["name"] == "probe")


def cmd_experiment(ns, tc):
    out, temporary = workdir(ns.keep)
    try:
        if ns.kind == "cost":
            base = probe_number(tc, "", ns.flags, out)
            print("probe local's number with nothing declared: %d (flags: %s)" % (base, ns.flags or "none"))
            print("%-6s  %s" % ("cost", "construct before the probe function"))
            for text, label in COST_CASES:
                print("%6d  %-48s %s" % (probe_number(tc, text, ns.flags, out) - base, label, text))
            return 0
        # flip: insert N typedefs (one number each, no code) before a marker and hash the function's code.
        if not (ns.source and ns.insert_before and ns.function):
            raise TraceError("flip needs --source, --insert-before and --function")
        source = Path(ns.source).read_text(errors="replace")
        if ns.insert_before not in source:
            raise TraceError("marker not found in source: " + ns.insert_before)
        variants = {}
        # The shifted copy lives in the work directory (never beside the source); the source's
        # directory goes first on the include path so its quoted includes still resolve.
        path = out / ("cl_trace_flip_" + Path(ns.source).name)
        includes = [str(Path(ns.source).resolve().parent), *ns.include]
        for n in range(ns.start, ns.stop):
            pads = "".join("typedef int cl_trace_pad%d;\n" % i for i in range(n))
            path.write_text(source.replace(ns.insert_before, pads + ns.insert_before, 1))
            try:
                unit = symbols_of(tc, path, ns.flags, includes, out)
                functions, globals_ = unit.functions, unit.globals()
            finally:
                path.unlink()
            fn = next(f for f in functions if re.search(ns.function, f.decorated or f.name))
            asm = (out / (path.stem + ".asm")).read_text(errors="replace")
            body = re.search(re.escape(fn.decorated) + r" PROC.*?\n(.*?)" + re.escape(fn.decorated) + " ENDP", asm, re.S)
            lines = [re.sub(r"\$\d+", "$N", l.split(";")[0]).strip() for l in body.group(1).splitlines()]
            digest = hashlib.sha1("\n".join(l for l in lines if l).encode()).hexdigest()[:8]
            variants.setdefault(digest, n)
            note = " ".join("%s=%d(mod64 %d)" % (r["name"], r["number"], r["mod64"])
                            for r in fn.symbols if ns.local and r["name"] == ns.local)
            if ns.globals:
                note += " " + " ".join("%s=%d(mod64 %d)" % (g, v, v % 64) for g, v in globals_ if re.search(ns.globals, g))
            print("pads %4d  code %s  %s" % (n, digest, note), flush=True)
        print("%d distinct code variant(s): %s" % (len(variants), ", ".join("%s from pads %d" % kv for kv in variants.items())))
        return 0
    finally:
        if temporary:
            shutil.rmtree(out, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("passes", "symbols", "il", "experiment"):
        p = sub.add_parser(name)
        if name == "experiment":
            p.add_argument("kind", choices=("cost", "flip"))
            p.add_argument("--insert-before", help="flip: text before which the typedef pads go")
            p.add_argument("--function", help="flip: regex on the decorated name of the function to hash")
            p.add_argument("--local", help="flip: local whose number to print")
            p.add_argument("--globals", help="flip: regex of gl names whose numbers to print")
            p.add_argument("--start", type=int, default=0)
            p.add_argument("--stop", type=int, default=64)
        p.add_argument("--source", required=(name in ("passes", "symbols")))
        p.add_argument("--flags", default="")
        p.add_argument("-I", "--include", action="append", default=[])
        p.add_argument("--keep", help="keep outputs (IL, listing, obj) in this directory")
        p.add_argument("--vc", help="VC root (default: config/project.json toolchain_root)")
        p.add_argument("--json", action="store_true")
        if name == "passes":
            p.add_argument("--dry", action="store_true", help="/Bz: print the passes without running them")
            p.add_argument("--debug", action="store_true", help="observe DLL loads with Windows debug events")
        if name == "symbols":
            p.add_argument("--function", help="regex on the function's name or decorated name")
            p.add_argument("--globals", help="regex: also print gl records (globals, functions, members) by name")
            p.add_argument("--check", action="store_true",
                           help="compare each compiled function's frame symbols (listing) with its sy block")
        if name == "il":
            p.add_argument("--prefix", help="an existing /Bk prefix (dir/stem_)")
            p.add_argument("--records", action="store_true", help="print every sy record")
    ns = parser.parse_args(argv)
    try:
        tc = toolchain(ns.vc)
        return {"passes": cmd_passes, "symbols": cmd_symbols, "il": cmd_il,
                "experiment": cmd_experiment}[ns.command](ns, tc)
    except TraceError as error:
        print("cl_trace: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
