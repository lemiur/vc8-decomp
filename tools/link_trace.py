"""Trace a VC8 link (link 8.00.50727.762) from input objects to the output image.

    python tools/link_trace.py run --obj a.obj b.obj --flags "/OPT:REF,ICF" --out DIR
    python tools/link_trace.py explain --model DIR/model.json --rva 0x1000
    python tools/link_trace.py explain --model DIR/model.json --symbol ?f@@YAHH@Z
    python tools/link_trace.py order --obj a.obj b.obj [--model DIR/model.json] [--root _main]
    python tools/link_trace.py order --obj a.obj b.obj --icf-trace DIR/icf.json   (ICF survivors)
    python tools/link_trace.py icf-trace --obj a.obj b.obj --flags "/OPT:REF,ICF" --out DIR [--crc]
    python tools/link_trace.py experiment --set E1|E2|E4|L1|L2|all|layout --out DIR   (docs/link-trace.md tables)

`run` links the objects with the pinned toolchain, adding /VERBOSE (REF and ICF
decisions), /MAP and /MAPINFO:EXPORTS, then joins four sources into one model:
the objects' COFF section tables, the verbose log, the map and the output PE.
`order` predicts the layout of the objects' code without running link, from the
rules established by `experiment` (docs/link-trace.md). Stdlib only.
"""
import argparse
import itertools
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAINS = ROOT / "config/toolchains.json"

SCN_CNT_CODE = 0x20
SCN_LNK_COMDAT = 0x1000
SCN_LNK_REMOVE = 0x800
SCN_LNK_INFO = 0x200
SCN_MEM_DISCARDABLE = 0x02000000
SCN_MEM_WRITE = 0x80000000
SELECTIONS = {1: "nodup", 2: "any", 3: "same_size", 4: "exact", 5: "associative", 6: "largest"}
REL_I386 = {0x06: "DIR32", 0x07: "DIR32NB", 0x14: "REL32", 0x0A: "SECTION", 0x0B: "SECREL", 0x00: "ABSOLUTE"}


class LinkTraceError(ValueError):
    pass


# ---------------------------------------------------------------- COFF objects

def _cstr(data, start, limit):
    end = data.find(b"\0", start, limit)
    return data[start:(end if end >= 0 else limit)].decode("latin-1")


def parse_obj(data, path="<obj>"):
    """Sections, symbols and relocations of an i386 COFF object.

    Each section gets its COMDAT selection, checksum and associated section
    (from the section-definition auxiliary record) and the symbols defined in it.
    """
    if len(data) < 20:
        raise LinkTraceError(path + ": truncated COFF header")
    machine, nsec, _, symtab, nsym, optsize, _ = struct.unpack_from("<HHIIIHH", data)
    if machine != 0x14C or optsize:
        raise LinkTraceError(path + ": not an i386 COFF object (a /GL object cannot be traced before LTCG)")
    strtab = symtab + nsym * 18
    strsize = struct.unpack_from("<I", data, strtab)[0] if nsym and strtab + 4 <= len(data) else 4

    def long_name(raw):
        if raw[:4] == b"\0\0\0\0":
            return _cstr(data, strtab + struct.unpack_from("<I", raw, 4)[0], strtab + strsize)
        return raw.rstrip(b"\0").decode("latin-1")

    sections = []
    for i in range(nsec):
        at = 20 + i * 40
        raw = data[at:at + 8]
        name = raw.rstrip(b"\0").decode("latin-1")
        if name.startswith("/") and name[1:].isdigit():
            name = _cstr(data, strtab + int(name[1:]), strtab + strsize)
        (_, _, size, rawptr, relptr, _, nrel, _, chars) = struct.unpack_from("<IIIIIIHHI", data, at + 8)
        alignbits = (chars >> 20) & 0xF
        relocs = []
        for r in range(nrel):
            va, sym, kind = struct.unpack_from("<IIH", data, relptr + r * 10)
            relocs.append({"offset": va, "symbol_index": sym, "type": REL_I386.get(kind, hex(kind))})
        sections.append({
            "index": i + 1, "name": name, "size": size, "characteristics": chars,
            "align": (1 << (alignbits - 1)) if alignbits else 16,
            "code": bool(chars & SCN_CNT_CODE), "comdat": bool(chars & SCN_LNK_COMDAT),
            "removed": bool(chars & (SCN_LNK_REMOVE | SCN_LNK_INFO)) or bool(chars & SCN_MEM_DISCARDABLE),
            "selection": None, "checksum": None, "associated": None, "symbols": [],
            "raw": data[rawptr:rawptr + size] if rawptr else b"", "relocs": relocs})
    symbols = []
    i = 0
    while i < nsym:
        at = symtab + i * 18
        name = long_name(data[at:at + 8])
        value, secnum, kind, storage, naux = struct.unpack_from("<IhHBB", data, at + 8)
        sym = {"index": i, "name": name, "value": value, "section": secnum, "function": bool(kind & 0x20),
               "storage": storage, "external": storage == 2}
        symbols.append(sym)
        if storage == 105 and naux:  # IMAGE_SYM_CLASS_WEAK_EXTERNAL: aux TagIndex names the default
            sym["weak_default_index"], sym["weak_search"] = struct.unpack_from("<II", data, at + 18)
        if naux and storage == 3 and value == 0 and 0 < secnum <= nsec and sections[secnum - 1]["name"] == name:
            length, _, _, checksum, number, selection = struct.unpack_from("<IHHIHB", data, at + 18)
            sec = sections[secnum - 1]
            if sec["comdat"]:
                sec["selection"] = SELECTIONS.get(selection, selection)
                sec["checksum"] = checksum
                if selection == 5:
                    sec["associated"] = number
            sym["section_symbol"] = True
        elif 0 < secnum <= nsec:
            sections[secnum - 1]["symbols"].append(sym)
        i += 1 + naux
    by_index = {s["index"]: s for s in symbols}
    for sym in symbols:
        if "weak_default_index" in sym and sym["weak_default_index"] in by_index:
            sym["weak_default"] = by_index[sym["weak_default_index"]]["name"]
    for sec in sections:
        for rel in sec["relocs"]:
            target = by_index.get(rel["symbol_index"])
            rel["symbol"] = target["name"] if target else None
            rel["symbol_section"] = target["section"] if target else None
            rel["weak_default"] = target.get("weak_default") if target else None
            if rel["type"] in ("DIR32", "REL32", "DIR32NB") and rel["offset"] + 4 <= len(sec["raw"]):
                rel["addend"] = struct.unpack_from("<i", sec["raw"], rel["offset"])[0]
    return {"path": str(path), "sections": sections, "symbols": symbols}


def comdat_symbol(section):
    """The COMDAT's own symbol: the first non-section symbol defined at offset 0."""
    for sym in section["symbols"]:
        if not sym.get("section_symbol") and not sym["name"].startswith("$"):
            return sym["name"]
    return None


def group_name(name):
    """Output-section grouping: `.text$x` contributes to `.text`, sorted by full name."""
    return name.split("$", 1)[0]


# ---------------------------------------------------------------- link output

_SYM = r'(?:"(?P<pretty>.*)" \((?P<dec>[^()\s]+)\)|(?P<plain>\S+))'
_SYM_FROM = re.compile(r"^\s*" + _SYM + r" from (?P<origin>.+?)\s*$")
_DISCARDED = re.compile(r"^\s*Discarded " + _SYM + r" from (?P<origin>.+?)\s*$")


def _sym(match):
    return match.group("dec") or match.group("plain")


def split_origin(origin):
    """`MSVCRT.lib(crtexe.obj)` -> ('MSVCRT.lib', 'crtexe.obj'); `a.obj` -> (None, 'a.obj')."""
    m = re.match(r"^(.*)\((.*)\)$", origin)
    return (m.group(1), m.group(2)) if m else (None, origin)


def parse_verbose(text):
    """REF discards and ICF fold groups of a /VERBOSE (or :REF, :ICF) log."""
    discarded, groups, passes = [], [], []
    current = None
    mode = None
    icf_savings = None
    for line in text.splitlines():
        m = _DISCARDED.match(line)
        if m:
            lib, member = split_origin(m.group("origin"))
            discarded.append({"symbol": _sym(m), "pretty": m.group("pretty"), "origin": m.group("origin"),
                              "lib": lib, "member": member})
            mode = None
            continue
        stripped = line.strip()
        if stripped == "Selected symbol:":
            current = {"survivor": None, "replaced": []}
            groups.append(current)
            mode = "selected"
            continue
        if stripped == "Replaced symbol(s):":
            mode = "replaced"
            continue
        m2 = re.match(r"ICF total savings: (\d+) bytes", stripped)
        if m2:
            icf_savings = int(m2.group(1))
            mode = None
            continue
        if stripped.startswith("Starting pass") or stripped.startswith("Finished pass"):
            passes.append(stripped)
            mode = None
            continue
        if mode and current is not None:
            m = _SYM_FROM.match(line)
            if m:
                lib, member = split_origin(m.group("origin"))
                row = {"symbol": _sym(m), "pretty": m.group("pretty"), "origin": m.group("origin"),
                       "lib": lib, "member": member}
                if mode == "selected" and current["survivor"] is None:
                    current["survivor"] = row
                else:
                    current["replaced"].append(row)
                continue
            if stripped:
                mode = None
    return {"discarded": discarded, "fold_groups": groups, "icf_savings": icf_savings, "passes": passes}


_FOUND = re.compile(r"^\s+Found " + _SYM + r"\s*$")
_REFERENCED = re.compile(r"^\s+Referenced in (?P<origin>.+?)\s*$")
_LOADED = re.compile(r"^\s+Loaded (?P<origin>.+?)\s*$")
_SEARCHING = re.compile(r"^\s+Searching (?P<lib>.+?):\s*$")


def parse_loads(text):
    """The library search of a /VERBOSE log: one event per `Found` symbol, in log order, with the
    library searched, the inputs it was `Referenced in` and the member `Loaded` for it (None when
    an already loaded member defines it). Link numbers the modules in this order: the objects
    1..N in command-line order, then each `Loaded` member."""
    events, lib, cur, rnd = [], None, None, -1
    for line in text.splitlines():
        if line.strip() == "Searching libraries":
            rnd += 1
            continue
        m = _SEARCHING.match(line)
        if m:
            lib, cur = m.group("lib"), None
            continue
        m = _FOUND.match(line)
        if m:
            cur = {"symbol": _sym(m), "lib": lib, "refs": [], "loaded": None, "round": max(rnd, 0)}
            events.append(cur)
            continue
        if cur is None:
            continue
        m = _REFERENCED.match(line)
        if m:
            cur["refs"].append(m.group("origin"))
            continue
        m = _LOADED.match(line)
        if m:
            cur["loaded"] = m.group("origin")
            cur = None
    return events


def library_pulls(objs, events):
    """Predict the library modules' load order for this object order from a traced search
    (`parse_loads` of any order of the same inputs). Link walks its unresolved externals in the
    order the objects first referenced them (command-line order, each object's symbol table in
    order), so the members the objects pull are reordered among their own slots of the traced
    sequence; the members pulled for the entry point and for other library members keep their
    traced slots (their order is the library's, the same in E1, E2 and E4). Returns the `Found`
    symbols that load a member, in predicted load order: module number = len(objs) + 1 + position."""
    objnames = {_origin_key(o["path"]) for o in objs}
    first = {}
    for obj in objs:
        for sym in obj["symbols"]:
            if sym["external"] and sym["section"] == 0:
                first.setdefault(sym["name"], len(first))
    seq = [e for e in events if e["loaded"]]
    slots = [i for i, e in enumerate(seq) if any(_origin_key(r) in objnames for r in e["refs"])]
    moved = sorted((seq[i] for i in slots), key=lambda e: first.get(e["symbol"], 1 << 30))
    out = list(seq)
    for i, e in zip(slots, moved):
        out[i] = e
    # A member's own references are searched after those of the members loaded before it: the
    # events first referenced by a member the objects pulled follow that member's new position.
    # Import members share one name (`MSVCRT.lib(MSVCR80.dll)`): an event referenced only by such
    # members (the DLL's import descriptor, referenced by each) follows the first one loaded.
    names = [e["loaded"] for e in out]
    first_of = {}
    for i, e in enumerate(out):
        first_of.setdefault(e["loaded"], i)

    def referencer(e):
        r = e["refs"][0] if e["refs"] else None
        if r is None or r not in first_of or first_of[r] not in set(slots):
            return None
        if names.count(r) == 1 or (len(e["refs"]) > 1 and all(x == r for x in e["refs"])):
            return first_of[r]
        return None

    second = [i for i, e in enumerate(out) if i not in set(slots) and referencer(e) is not None]
    later = sorted((out[i] for i in second), key=referencer)
    for i, e in zip(second, later):
        out[i] = e
    return [e["symbol"] for e in out]


# ---------------------------------------------------------------- library search model

def parse_archive(data, path="<lib>"):
    """Members and dictionary of a COFF archive (.lib): {"path", "members": [{offset, name, data}],
    "dictionary": {symbol: member offset}} from the first linker member (archive order of the
    symbols; the first definer of a symbol wins, as link's lookup in the second member does for
    the unique symbols the libraries here hold)."""
    if data[:8] != b"!<arch>\n":
        raise LinkTraceError(path + ": not a COFF archive")
    at, members, longnames, dictionary, linker = 8, [], b"", {}, 0
    while at + 60 <= len(data):
        head = data[at:at + 60]
        name = head[:16].decode("latin-1").rstrip()
        size = int(head[48:58].decode("latin-1").strip() or 0)
        body = data[at + 60:at + 60 + size]
        if name == "/" and linker == 0:
            count = struct.unpack_from(">I", body)[0]
            offsets = struct.unpack_from(">%dI" % count, body, 4)
            pos = 4 + 4 * count
            for off in offsets:
                end = body.index(b"\0", pos)
                dictionary.setdefault(body[pos:end].decode("latin-1"), off)
                pos = end + 1
            linker = 1
        elif name == "/":
            linker = 2
        elif name == "//":
            longnames = body
        else:
            if name.startswith("/") and name[1:].isdigit():
                start = int(name[1:])
                end = longnames.find(b"\0", start)
                name = longnames[start:end if end >= 0 else None].decode("latin-1").rstrip("\n")
            members.append({"offset": at, "name": name.rstrip("/"), "data": body})
        at += 60 + size + (size & 1)
    return {"path": str(path), "members": members, "dictionary": dictionary}


def _export_symbol(spec, directive=False):
    """The symbol an /EXPORT:entryname[=internalname][,@ordinal[,NONAME]][,DATA] references: the
    internal name, else the entry name; taken as given in a .drectve (`/EXPORT:exp_lib` there is
    LNK2001 `exp_lib`), with `_` prepended on the command line (`/EXPORT:exp_cmd` finds
    `_exp_cmd`) unless it is a C++ name. Only undecorated command-line names were traced."""
    name = spec.split(",", 1)[0]
    name = name.split("=", 1)[1] if "=" in name else name
    if not directive and not name.startswith("?"):
        name = "_" + name
    return name


def parse_directives(text):
    """The options of a .drectve section that the library search reads, in order."""
    out = []
    for tok in shlex.split(text, posix=False):
        tok = tok.strip()
        m = re.match(r'(?i)^[-/](DEFAULTLIB|NODEFAULTLIB|INCLUDE|EXPORT|ALTERNATENAME)(?::(.*))?$', tok)
        if m:
            arg = (m.group(2) or "").strip('"') or None
            if m.group(1).upper() == "EXPORT" and arg:
                arg = _export_symbol(arg, directive=True)
            out.append((m.group(1).upper(), arg))
    return out


def module_symbols(data, path="<obj>"):
    """What one input module gives the library search: its external symbols in symbol-table order
    as (name, defined, weak) and its directives. A short import object (IMPORT_OBJECT_HEADER)
    defines `__imp_<name>` (and `<name>`, the jmp thunk, for code) and references the DLL's
    `__IMPORT_DESCRIPTOR_<dll>`."""
    if len(data) >= 20 and data[:4] == b"\0\0\xff\xff":
        kind = struct.unpack_from("<H", data, 18)[0] & 3
        name, dll = data[20:].split(b"\0")[:2]
        name, dll = name.decode("latin-1"), dll.decode("latin-1")
        syms = [("__imp_" + name, True, False)]
        if kind == 0:
            syms.append((name, True, False))
        syms.append(("__IMPORT_DESCRIPTOR_" + dll.rsplit(".", 1)[0], False, False))
        return {"import": dll, "symbols": syms, "directives": []}
    if data[:2] == b"\0\0":  # IMAGE_FILE_MACHINE_UNKNOWN: a directives-only member (msvcrt.lib's almap)
        data = b"\x4c\x01" + data[2:]
    obj = parse_obj(data, path)
    syms = []
    for s in obj["symbols"]:
        if s["storage"] == 2:
            syms.append((s["name"], s["section"] != 0 or s["value"] != 0, False))
        elif s["storage"] == 105:
            # IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY (1) is not looked up in the libraries; LIBRARY (2,
            # the compiler's ??_E vtable slots) and ALIAS (3) are.
            syms.append((s["name"], False, "nolibrary" if s.get("weak_search") == 1 else "weak"))
    directives = []
    for sec in obj["sections"]:
        if sec["name"] == ".drectve":
            raw = sec["raw"]
            text = raw[3:].decode("utf-8", "replace") if raw[:3] == b"\xef\xbb\xbf" else raw.decode("latin-1")
            directives += parse_directives(text.rstrip("\0"))
    return {"import": None, "symbols": syms, "directives": directives}


def _is_lib(path):
    return str(path).lower().endswith(".lib")


def _lib_key(name):
    base = re.split(r"[\\/]", name)[-1].lower()
    return base if base.endswith(".lib") or "." in base else base + ".lib"


_FILES, _ARCHIVES = {}, {}


def _read_cached(path):
    st = os.stat(path)
    key = (os.path.normcase(os.path.abspath(path)), st.st_size, st.st_mtime_ns)
    if key not in _FILES:
        _FILES[key] = Path(path).read_bytes()
    return _FILES[key]


_MEMBERS = {}


def _lib_member_obj(lib, member):
    """The parsed COFF object of a library member named as link names it (its member name), or
    None (an import object, a library or member not found, two members with that name)."""
    key = (lib, member)
    if key not in _MEMBERS:
        _MEMBERS[key] = _lib_member_parse(lib, member)
    return _MEMBERS[key]


def _lib_member_parse(lib, member):
    try:
        st = os.stat(lib)
        key = (os.path.normcase(os.path.abspath(lib)), st.st_size, st.st_mtime_ns)
        if key not in _ARCHIVES:
            _ARCHIVES[key] = parse_archive(_read_cached(lib), lib)
        found = [m for m in _ARCHIVES[key]["members"] if m["name"].casefold() == (member or "").casefold()]
        if len(found) != 1 or found[0]["data"][:4] == b"\0\0\xff\xff":
            return None
        return parse_obj(found[0]["data"], found[0]["name"])
    except (OSError, LinkTraceError, struct.error):
        return None


def find_library(name, libpath):
    """link's lookup of a library argument or default library: the path itself, else each /LIBPATH
    folder, then each folder of LIB (SzSearchLibEnv)."""
    if not re.search(r"\.[^\\/.]+$", name):
        name += ".lib"
    if os.path.isabs(name) and os.path.isfile(name):
        return name
    if os.path.isfile(name):
        return str(Path(name).resolve())
    for d in libpath:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


def search_libraries(inputs, libpath=(), include=(), defaults=(), rounds=((),), load=None):
    """Simulate link 8.00's library search (IMAGE::ResolveExternalsInLibs 0x4729E0, LIB::Search
    0x48CB90, PlibInstantiateDefaultLib 0x435580) and return the events it prints under /VERBOSE:
    [{"round", "lib", "symbol", "member", "module"}] in order, plus each Search call's library.

    `inputs`: the command line in order, ("obj", path) or ("lib", name). The undefined externals
    form one list, each appended when first referenced (the /INCLUDE symbols, then each object's
    symbol table in order) and removed once defined. A library search walks that list; for each
    non-weak undefined symbol the library's dictionary defines it loads that member (its
    definitions leave the list, its new references join the end, its /DEFAULTLIB directives join
    the default-library queue) and goes on after the symbol before it. The libraries are walked
    in command-line order; at the end of the list the next queued default library (one not
    excluded by /NODEFAULTLIB and not already a library of the link) is opened and searched, and
    when none remains the walk starts again from the first library, if a library has loaded a
    member that added new undefined symbols. The search ends on reaching the last library that
    did so, when a library leaves nothing unresolved, or when a whole walk loads nothing new.
    `rounds`: the symbols each ResolveExternalsInLibs call adds (the linker's own references:
    the entry point in the first, `__load_config_used`), searched the same way; an entry may be
    a function of the search state ({"defined", "undefined", "exports", "alternates"}: the
    modules' /EXPORT and /ALTERNATENAME directives) returning the names, or None when link makes
    no such call."""
    load = load or _read_cached
    undef, known, defined = [], set(), set()
    libs, dls, nodl = [], [], set()
    events, searches = [], []
    exports, alternates = [], {}
    nmod = [0]

    def add_module(info):
        # The directives first (an /INCLUDE joins the list before the module's own references:
        # crtexe.obj's __forceCRTManifest), then the symbol table in order.
        new = False
        for kind, arg in info["directives"]:
            if kind == "DEFAULTLIB" and arg:
                make_default(arg)
            elif kind == "NODEFAULTLIB":
                no_default(arg)
            elif kind == "INCLUDE" and arg and arg not in defined and arg not in known:
                ref(arg)
                new = True
            elif kind == "EXPORT" and arg:
                exports.append(arg)
            elif kind == "ALTERNATENAME" and arg and "=" in arg:
                alternates.setdefault(*arg.split("=", 1))
        for name, is_def, weak in info["symbols"]:
            # A weak external of a module resolves a symbol that is still undefined (msvcrt.lib's
            # almap members alias ??1type_info@@UAE@XZ to its default); otherwise it is a weak
            # reference, which the search skips.
            if weak and name in known and name not in weaks:
                is_def = True
            if is_def:
                if name not in defined:
                    defined.add(name)
                    if name in known:
                        undef.remove(name)
                        known.discard(name)
            elif name not in defined and name not in known:
                undef.append(name)
                known.add(name)
                if weak:
                    weaks[name] = weak
                new = True
        return new

    weaks = {}

    def ref(name):
        if name not in defined and name not in known:
            undef.append(name)
            known.add(name)

    def make_default(name):
        k = _lib_key(name)
        for d in dls:
            if d["key"] == k:
                d["wanted"] = True
                return
        dls.append({"key": k, "name": name, "wanted": True, "excluded": False, "done": False})

    def no_default(name):
        if not name:
            nodl.add(None)
            return
        k = _lib_key(name)
        for d in dls:
            if d["key"] == k:
                d["excluded"] = True
                return
        dls.append({"key": k, "name": name, "wanted": False, "excluded": True, "done": False})

    def open_lib(name, path):
        lib = {"name": name, "path": path, "key": _lib_key(name), "loaded": set()}
        if path:
            st = os.stat(path)
            key = (os.path.normcase(os.path.abspath(path)), st.st_size, st.st_mtime_ns)
            if key not in _ARCHIVES:
                _ARCHIVES[key] = parse_archive(load(path), path)
            lib["archive"] = _ARCHIVES[key]
        libs.append(lib)
        return lib

    def instantiate_default():
        if None in nodl:
            return None
        for d in dls:
            if d["excluded"] or not d["wanted"] or d["done"]:
                continue
            d["done"] = True
            if any(l["key"] == d["key"] for l in libs):
                continue
            return open_lib(d["name"], find_library(d["name"], libpath))
        return None

    for opt, arg in defaults:
        if opt == "NODEFAULTLIB":
            no_default(arg)
        elif arg:
            make_default(arg)
    for name in include:
        ref(name)
    for kind, arg in inputs:
        if kind == "obj":
            nmod[0] += 1
            add_module(module_symbols(load(arg), arg))
        else:
            open_lib(arg, find_library(arg, libpath))

    def search(lib, rnd):
        tried = []
        searches.append({"round": rnd, "lib": lib["path"] or lib["name"], "tried": tried})
        arch = lib.get("archive")
        notfound, added = False, False
        i = 0
        while i < len(undef):
            name = undef[i]
            if weaks.get(name) == "nolibrary":
                i += 1
                continue
            tried.append(name)
            if arch is None or name not in arch["dictionary"]:
                notfound = True
                i += 1
                continue
            off = arch["dictionary"][name]
            member = next(m for m in arch["members"] if m["offset"] == off)
            prev = undef[i - 1] if i else None
            info = module_symbols(member["data"], member["name"])
            nmod[0] += 1
            events.append({"round": rnd, "lib": lib["path"], "symbol": name, "offset": off,
                           "member": info["import"] or member["name"], "module": nmod[0]})
            if add_module(info):
                added = True
            if name in known:  # the member did not define it: link stops (LNK1000-class error)
                raise LinkTraceError("%s(%s) does not define %s" % (lib["path"], member["name"], name))
            i = undef.index(prev) + 1 if prev in known else 0
        return notfound, added

    rnd, seeds = -1, []
    for extra in rounds:
        if callable(extra):
            extra = extra({"defined": defined, "undefined": known, "exports": exports, "alternates": alternates})
            if extra is None:
                continue
        rnd += 1
        seeds.append(list(extra))
        for name in extra:
            ref(name)
        last, cur, walking, notfound = None, None, True, True
        while True:
            if walking:
                at = 0 if cur is None else libs.index(cur) + 1
                cur = libs[at] if at < len(libs) else None
                if cur is None:
                    walking = False
            if not walking:
                cur = instantiate_default()
                if cur is None:
                    if last is not None and notfound:
                        cur, walking = None, True
                        continue
                    break
            if cur is last:
                break
            notfound, added = search(cur, rnd)
            if not notfound:
                break
            if added:
                last = cur
        # Each round ends with IMAGE::DefineImageBaseSymbol: ___ImageBase is the linker's.
        if "___ImageBase" in known:
            undef.remove("___ImageBase")
            known.discard("___ImageBase")
        defined.add("___ImageBase")
    return {"events": events, "searches": searches, "unresolved": list(undef), "seeds": seeds,
            "libraries": [l["path"] or l["name"] for l in libs]}


def parse_searches(text):
    """Each `Searching <lib>:` of a /VERBOSE log with its round (one per `Searching libraries`)."""
    out, rnd = [], -1
    for line in text.splitlines():
        if line.strip() == "Searching libraries":
            rnd += 1
            continue
        m = _SEARCHING.match(line)
        if m:
            out.append({"round": rnd, "lib": m.group("lib")})
    return out


def command_args(command):
    """A link command line's arguments after the program name, response files (`@file`) expanded."""
    args = []
    for a in command[1:]:
        if a.startswith("@"):
            args += shlex.split(Path(a[1:]).read_text(encoding="utf-8", errors="replace"), posix=False)
        else:
            args.append(a)
    return args


def link_inputs(command):
    """The library search's view of a link command line: the inputs in order, /LIBPATH folders,
    /INCLUDE symbols, /DEFAULTLIB and /NODEFAULTLIB options (response files expanded)."""
    inputs, libpath, include, defaults = [], [], [], []
    for a in command_args(command):
        a = a.strip('"')
        m = re.match(r"(?i)^[-/](\w+)(?::(.*))?$", a)
        if m and not os.path.isfile(a):
            opt, val = m.group(1).upper(), (m.group(2) or "").strip('"')
            if opt == "LIBPATH":
                libpath.append(val)
            elif opt == "INCLUDE":
                include.append(val)
            elif opt in ("DEFAULTLIB", "NODEFAULTLIB"):
                defaults.append((opt, val or None))
            continue
        inputs.append(("lib" if a.lower().endswith(".lib") else "obj", a))
    return inputs, libpath, include, defaults


def _round_seeds(loads, include=()):
    """The symbols each ResolveExternalsInLibs call adds itself (`Found` with no `Referenced in`),
    per round; the first round's /INCLUDE symbols excluded."""
    seeds = [[] for _ in range(max([e.get("round", 0) for e in loads] + [0]) + 1)]
    for e in loads:
        if not e["refs"] and e["loaded"]:
            seeds[e.get("round", 0)].append(e["symbol"])
    seeds[0] = [s for s in seeds[0] if s not in include]
    return seeds


ENTRY_BY_MAIN = (("_wWinMain@16", "_wWinMainCRTStartup"), ("_WinMain@16", "_WinMainCRTStartup"),
                 ("_wmain", "_wmainCRTStartup"), ("_main", "_mainCRTStartup"))


def linker_seeds(command, inputs=None):
    """The symbols link references itself, per ResolveExternalsInLibs round, without a trace:
    round 0 the entry point (none under /NOENTRY; `_` + the /ENTRY name; for a /DLL
    `__DllMainCRTStartup@12`; otherwise the CRT startup of the main the objects define, `_main`
    by default), joining the undefined list after every input's references; then, when there are
    exports, the round after the .exp is generated: the `trace.exp` module references every
    exported symbol (command line and directives) in name order; then, when an
    /ALTERNATENAME:a=b has `a` still undefined, a round that references the defaults `b`;
    last `__load_config_used` (x86). `search_check` compares them with every traced log
    (`seeds`)."""
    t_inputs = link_inputs(command)[0]
    # The options as link reads them: a response file's /DLL, /NOENTRY, /ENTRY and /EXPORT count.
    args = [a.strip('"') for a in command_args(command)]
    explicit = [a.split(":", 1)[1].strip('"') for a in args if re.match(r"(?i)^[-/]ENTRY:", a)]
    if any(re.match(r"(?i)^[-/]NOENTRY$", a) for a in args):
        entry = None
    elif explicit:
        entry = "_" + explicit[-1]
    elif any(re.match(r"(?i)^[-/]DLL$", a) for a in args):
        entry = "__DllMainCRTStartup@12"
    else:
        defined = set()
        for kind, path in inputs or t_inputs:
            if kind == "obj" and os.path.isfile(path):
                defined |= {n for n, d, _ in module_symbols(_read_cached(path), path)["symbols"] if d}
        entry = next((e for m, e in ENTRY_BY_MAIN if m in defined), "_mainCRTStartup")
    command_exports = [_export_symbol(a.split(":", 1)[1]) for a in args if re.match(r"(?i)^[-/]EXPORT:", a)]

    def export_round(state):
        names = command_exports + state["exports"]
        if not names:
            return None
        return sorted(dict.fromkeys(names), key=lambda n: n.lstrip("_"))

    def alternate_round(state):
        # The source stays on the undefined list (the walk goes on past the default's library).
        bound = [(a, b) for a, b in state["alternates"].items() if a in state["undefined"]]
        names = [b for _, b in bound if b not in state["defined"]]
        return names or None

    return [[entry] if entry else [], export_round, alternate_round, ["__load_config_used"]]


def simulate_command(command, loads=None, inputs=None, env_lib=None):
    """`search_libraries` for a link command line (response files expanded, /LIBPATH then LIB).
    The linker's own references come from `linker_seeds`, or with `loads` from a traced log
    (`_round_seeds`). `inputs` replaces the command's inputs."""
    t_inputs, libpath, include, defaults = link_inputs(command)
    if env_lib is None:
        env_lib = toolchain_env()[1].get("LIB", "")
    libpath = libpath + [d for d in env_lib.split(os.pathsep) if d]
    seeds = _round_seeds(list(loads), include) if loads is not None else linker_seeds(command, inputs)
    return search_libraries(inputs or t_inputs, libpath, include, defaults, seeds)


def search_check(command, verbose_text, env_lib=None):
    """Simulate the library search of a traced link (`simulate_command`) and compare it with the
    log: the `Searching` sequence and the `Found`/`Loaded` sequence (symbol, member). Returns the
    comparison and the simulation."""
    loads, rounds = parse_loads(verbose_text), parse_searches(verbose_text)
    sim = simulate_command(command, env_lib=env_lib)
    seeds, traced_seeds = sim["seeds"], _round_seeds(loads, link_inputs(command)[2])
    # A seed already defined, or found in no library, leaves no `Found` line: compare the logged ones.
    seeds_equal = len(traced_seeds) <= len(seeds) and all(
        t == [s for s in m if s in t] for m, t in zip(seeds, traced_seeds))
    member = lambda s: re.split(r"[\\/]", s)[-1].lower()
    truth = [(e["symbol"], member(e["loaded"].split("(", 1)[1].rstrip(")")) if "(" in e["loaded"] else
              member(e["loaded"])) for e in loads if e["loaded"]]
    pred = [(e["symbol"], member(e["member"])) for e in sim["events"]]
    t_s = [(r["round"], _lib_key(r["lib"])) for r in rounds]
    p_s = [(r["round"], _lib_key(r["lib"])) for r in sim["searches"]]
    first = next((i for i, (a, b) in enumerate(zip(truth, pred)) if a != b), None)
    if first is None and len(truth) != len(pred):
        first = min(len(truth), len(pred))
    return {"loads": len(truth), "loads_equal": truth == pred, "first_difference": first,
            "truth_at": truth[first:first + 3] if first is not None else None,
            "predicted_at": pred[first:first + 3] if first is not None else None,
            "searches": len(t_s), "searches_equal": t_s == p_s,
            "truth_searches": t_s if t_s != p_s else None, "predicted_searches": p_s if t_s != p_s else None,
            "seeds": seeds, "seeds_equal": seeds_equal, "simulation": sim}


_MAP_SECTION = re.compile(r"^\s*([0-9a-fA-F]{4}):([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})H (\S+)\s+(\S+)\s*$")
_MAP_PUBLIC = re.compile(r"^\s*([0-9a-fA-F]{4}):([0-9a-fA-F]{8})\s+(\S+)\s+([0-9a-fA-F]{8})( f)?( i)?\s+(.*?)\s*$")


def parse_map(text):
    """Section groups, publics, statics, entry point and exports of a link /MAP file."""
    result = {"image_base": None, "timestamp": None, "groups": [], "publics": [], "statics": [],
              "entry": None, "exports": []}
    block = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Preferred load address is"):
            result["image_base"] = int(s.split()[-1], 16)
            continue
        if s.startswith("Timestamp is"):
            result["timestamp"] = int(s.split()[2], 16)
            continue
        if s.startswith("Start") and "Length" in s and "Class" in s:
            block = "groups"
            continue
        if s.startswith("Address") and "Publics by Value" in s:
            block = "publics"
            continue
        if s == "Static symbols":
            block = "statics"
            continue
        if s.startswith("Exports"):
            block = "exports"
            continue
        m = re.match(r"entry point at\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{8})", s)
        if m:
            result["entry"] = {"section": int(m.group(1), 16), "offset": int(m.group(2), 16)}
            block = None
            continue
        if block == "groups":
            m = _MAP_SECTION.match(line)
            if m:
                result["groups"].append({"section": int(m.group(1), 16), "offset": int(m.group(2), 16),
                                         "length": int(m.group(3), 16), "name": m.group(4), "class": m.group(5)})
        elif block in ("publics", "statics"):
            m = _MAP_PUBLIC.match(line)
            if m:
                origin = m.group(7)
                lib, member = None, origin
                if ":" in origin and not origin.startswith("<"):
                    lib, member = origin.split(":", 1)
                result[block].append({"section": int(m.group(1), 16), "offset": int(m.group(2), 16),
                                      "symbol": m.group(3), "va": int(m.group(4), 16),
                                      "function": bool(m.group(5)), "inline": bool(m.group(6)),
                                      "origin": origin, "lib": lib, "member": member})
        elif block == "exports":
            if s and not s.startswith("ordinal"):
                result["exports"].append(s)
    return result


# ---------------------------------------------------------------- PE image

def parse_pe(data):
    if data[:2] != b"MZ":
        raise LinkTraceError("not a PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise LinkTraceError("missing PE signature")
    nsec, timestamp = struct.unpack_from("<HI", data, pe + 6)
    optsize = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    image_base, salign, falign = struct.unpack_from("<III", data, opt + 28)
    sections = []
    for i in range(nsec):
        at = opt + optsize + i * 40
        name = data[at:at + 8].rstrip(b"\0").decode("latin-1")
        vsize, rva, rsize, rptr = struct.unpack_from("<IIII", data, at + 8)
        chars = struct.unpack_from("<I", data, at + 36)[0]
        sections.append({"index": i + 1, "name": name, "rva": rva, "virtual_size": vsize,
                         "raw_size": rsize, "raw_pointer": rptr, "characteristics": chars})
    return {"image_base": image_base, "entry_rva": entry, "timestamp": timestamp,
            "section_alignment": salign, "file_alignment": falign, "sections": sections}


def pe_read(data, pe, rva, size):
    for s in pe["sections"]:
        if s["rva"] <= rva and rva + size <= s["rva"] + max(s["virtual_size"], s["raw_size"]):
            off = rva - s["rva"]
            if off + size > s["raw_size"]:
                return None
            return data[s["raw_pointer"] + off:s["raw_pointer"] + off + size]
    return None


# ---------------------------------------------------------------- model

def _origin_key(name):
    return Path(name).name.casefold()


def _traced_folds(icf):
    """{(object file name, section number): survivor con} from the ICFFold calls of an icf-trace
    (every fold, the associative children's included: /VERBOSE names a folded static COMDAT such
    as a `.text$x` unwind funclet only by its section)."""
    if not icf:
        return None
    cons = {c["id"]: c for c in icf["cons"]}
    keep = {f["fold"]: f["keep"] for f in icf["folds"]}
    out = {}
    for f in keep:
        s = f
        while s in keep:
            s = keep[s]
        c = cons[f]
        if c["lib"] is None and c.get("section_index") is not None:
            out[(_origin_key(c["obj"]), c["section_index"])] = cons[s]
    return out


def build_model(objs, verbose_text, map_text, image, command=None, icf=None):
    """Join the objects, the verbose log, the map and the image into one model. With `icf` (the
    result of `icf_trace` for this link) the folds of the objects' contributions are taken from
    the traced ICFFold calls instead of /VERBOSE's names."""
    traced = _traced_folds(icf)
    verbose = parse_verbose(verbose_text)
    mp = parse_map(map_text)
    pe = parse_pe(image)
    base = pe["image_base"]
    sec_rva = {s["index"]: s["rva"] for s in pe["sections"]}
    sec_name = {s["index"]: s["name"] for s in pe["sections"]}
    discarded = {(d["symbol"], _origin_key(d["origin"])) for d in verbose["discarded"] if d["lib"] is None}
    folded = {}
    groups = []
    for gid, g in enumerate(verbose["fold_groups"]):
        if not g["survivor"]:
            continue
        members = [g["survivor"]] + g["replaced"]
        groups.append({"id": gid, "survivor": g["survivor"]["symbol"], "survivor_origin": g["survivor"]["origin"],
                       "members": [{"symbol": m["symbol"], "origin": m["origin"]} for m in members]})
        for m in g["replaced"]:
            folded[(m["symbol"], _origin_key(m["origin"]))] = (gid, g["survivor"])
    survivors = {(g["survivor"], _origin_key(g["survivor_origin"])): g["id"] for g in groups}
    placed = {}
    for p in mp["publics"] + mp["statics"]:
        placed.setdefault((p["symbol"], _origin_key(p["origin"] if p["lib"] is None else p["member"])), p)
    by_symbol = {}
    for p in mp["publics"] + mp["statics"]:
        by_symbol.setdefault(p["symbol"], []).append(p)
    names = {}
    for p in mp["publics"] + mp["statics"]:
        names.setdefault(p["va"] - base, []).append(p["symbol"])
    contributions = []
    for obj_index, obj in enumerate(objs):
        key = _origin_key(obj["path"])
        for sec in obj["sections"]:
            if sec["removed"] or sec["size"] == 0 or sec["name"].startswith(".debug") or sec["name"] == ".drectve":
                continue
            sym = comdat_symbol(sec)
            row = {"obj": obj["path"], "obj_index": obj_index, "section_index": sec["index"],
                   "section": sec["name"], "symbol": sym, "code": sec["code"], "comdat": sec["comdat"],
                   "symbols": [{"name": x["name"], "offset": x["value"]} for x in sec["symbols"]
                               if not x["name"].startswith("$") and not x.get("section_symbol")],
                   "selection": sec["selection"], "checksum": sec["checksum"], "size": sec["size"],
                   "align": sec["align"], "status": None, "reason": None, "rva": None,
                   "output_section": None, "fold_group": None, "padding_before": None, "padding_bytes": None,
                   "relocs": []}
            parent = obj["sections"][sec["associated"] - 1] if sec["associated"] else None
            row["associated_with"] = comdat_symbol(parent) if parent else None
            if traced is not None and (key, sec["index"]) in traced:
                surv = traced[(key, sec["index"])]
                row.update(status="folded", reason="/OPT:ICF (traced ICFFold): identical to %s #%d from %s, which survives"
                           % (surv.get("symbol"), surv.get("section_index") or 0, Path(surv["obj"] or "?").name))
                row["_survivor"] = (_origin_key(surv["obj"] or ""), surv.get("section_index"), surv.get("symbol"))
                if sym and (sym, key) in folded:
                    row["fold_group"] = folded[(sym, key)][0]
            elif sym and (sym, key) in folded and traced is None:
                gid, surv = folded[(sym, key)]
                row.update(status="folded", fold_group=gid,
                           reason="/OPT:ICF: identical to %s from %s, which survives" % (surv["symbol"], surv["origin"]))
                hit = by_symbol.get(sym)
                if hit:
                    row["rva"] = hit[0]["va"] - base
            elif sym and (sym, key) in discarded:
                row.update(status="removed", reason="/OPT:REF: unreferenced COMDAT")
            elif sym and (sym, key) in placed and (traced is None or (sym, key) not in folded
                                                    or not sec["comdat"]):
                p = placed[(sym, key)]
                row.update(status="kept", rva=p["va"] - base, reason="placed by the map")
                if (sym, key) in survivors:
                    row["fold_group"] = survivors[(sym, key)]
                    row["reason"] = "/OPT:ICF survivor of its fold group"
            elif sym and sym in by_symbol:
                other = by_symbol[sym][0]
                row.update(status="duplicate", rva=other["va"] - base,
                           reason="COMDAT selection %s: the copy from %s was taken" % (sec["selection"], other["origin"]))
            elif not sec["comdat"]:
                row.update(status="kept", reason="non-COMDAT section: always kept; its address is not in the map")
            elif sym:
                row.update(status="absent", reason="not in the map, the discard list or a fold group "
                                                   "(static, inlined away, or a /VERBOSE gap)")
            else:
                row.update(status="unnamed", reason="no symbol at offset 0; placement not observable in the map")
            if row["status"] == "kept" and row["rva"] is not None:
                for s in pe["sections"]:
                    if s["rva"] <= row["rva"] < s["rva"] + max(s["virtual_size"], s["raw_size"]):
                        row["output_section"] = s["name"]
                row["relocs"] = _resolve_relocs(sec, row["rva"], image, pe, names)
            contributions.append(row)
    if traced is not None:
        at = {(_origin_key(c["obj"]), c["section_index"]): c for c in contributions}
        for c in contributions:
            surv = c.pop("_survivor", None)
            if surv is None:
                continue
            target = at.get(surv[:2])
            if target is not None and target["rva"] is not None:
                c["rva"] = target["rva"]
            elif surv[2] in by_symbol:
                c["rva"] = by_symbol[surv[2]][0]["va"] - base
    # Padding between adjacent traced contributions with nothing mapped in between.
    kept = sorted((c for c in contributions if c["status"] == "kept" and c["rva"] is not None), key=lambda c: c["rva"])
    starts = sorted({p["va"] - base for p in mp["publics"] + mp["statics"]})
    import bisect
    for prev, cur in zip(kept, kept[1:]):
        end = prev["rva"] + prev["size"]
        if prev["output_section"] != cur["output_section"] or end > cur["rva"]:
            continue
        i = bisect.bisect_right(starts, prev["rva"])
        if i < len(starts) and starts[i] < cur["rva"]:
            continue
        gap = cur["rva"] - end
        cur["padding_before"] = gap
        if gap:
            raw = pe_read(image, pe, end, gap)
            cur["padding_bytes"] = raw.hex() if raw is not None else "uninitialized"
    groups_out = [{"section": g["section"], "offset": g["offset"], "length": g["length"], "name": g["name"],
                   "class": g["class"], "rva": sec_rva.get(g["section"], 0) + g["offset"],
                   "output_section": sec_name.get(g["section"])} for g in mp["groups"]]
    return {"schema_version": 1, "tool": "link_trace", "command": command,
            "image": {"image_base": base, "entry_rva": pe["entry_rva"], "timestamp": pe["timestamp"],
                      "section_alignment": pe["section_alignment"], "file_alignment": pe["file_alignment"],
                      "sections": pe["sections"]},
            "map_groups": groups_out, "fold_groups": groups, "icf_savings": verbose["icf_savings"],
            "discarded": verbose["discarded"], "contributions": contributions,
            "publics": [{"symbol": p["symbol"], "rva": p["va"] - base, "function": p["function"],
                         "origin": p["origin"], "static": static}
                        for static, rows in ((False, mp["publics"]), (True, mp["statics"])) for p in rows
                        if p["va"] >= base],
            "exports": mp["exports"],
            "limits": ["Sizes and padding are known only for the traced objects' sections; a library member's "
                       "contribution is bounded by the next map public only.",
                       "Objects are matched to map and verbose lines by file name; two inputs with one name are ambiguous."]}


def _resolve_relocs(sec, rva, image, pe, names):
    out = []
    base = pe["image_base"]
    for rel in sec["relocs"]:
        row = {"offset": rel["offset"], "type": rel["type"], "symbol": rel["symbol"], "target_rva": None,
               "target": None}
        word = pe_read(image, pe, rva + rel["offset"], 4)
        if word is not None:
            value = struct.unpack("<I", word)[0]
            if rel["type"] == "DIR32":
                target = value - base - (rel.get("addend") or 0)
            elif rel["type"] == "REL32":
                target = (rva + rel["offset"] + 4 + struct.unpack("<i", word)[0] - (rel.get("addend") or 0)) & 0xFFFFFFFF
            elif rel["type"] == "DIR32NB":
                target = value - (rel.get("addend") or 0)
            else:
                target = None
            if target is not None:
                row["target_rva"] = target
                row["target"] = names.get(target)
        out.append(row)
    return out


# ---------------------------------------------------------------- imports

def _pe_cstr(image, pe, rva, limit=512):
    for sec in pe["sections"]:
        if sec["rva"] <= rva < sec["rva"] + sec["raw_size"]:
            off = sec["raw_pointer"] + rva - sec["rva"]
            raw = image[off:min(off + limit, sec["raw_pointer"] + sec["raw_size"])]
            return raw.split(b"\0")[0].decode("latin-1")
    return ""


def parse_imports(image, pe=None):
    """The import directory of an image: descriptors in table order, each with its DLL name and
    the RVAs of its name, INT (.idata$4) and IAT (.idata$5), and its entries in slot order (slot
    RVA, INT value, hint, name, hint/name RVA; an ordinal import has no name)."""
    pe = pe or parse_pe(image)
    at = struct.unpack_from("<I", image, 0x3C)[0] + 24
    magic = struct.unpack_from("<H", image, at)[0]
    dirs = at + (96 if magic == 0x10B else 112)
    rva, size = struct.unpack_from("<II", image, dirs + 8)
    out = []
    while rva and size:
        raw = pe_read(image, pe, rva + 20 * len(out), 20)
        if raw is None:
            break
        oft, _, _, name_rva, ft = struct.unpack("<IIIII", raw)
        if not (oft or name_rva or ft):
            break
        desc = {"dll": _pe_cstr(image, pe, name_rva), "name_rva": name_rva, "int_rva": oft,
                "iat_rva": ft, "descriptor_rva": rva + 20 * len(out), "entries": []}
        i = 0
        while True:
            word = pe_read(image, pe, (oft or ft) + 4 * i, 4)
            value = struct.unpack("<I", word)[0] if word else 0
            if not value:
                break
            ent = {"slot_rva": ft + 4 * i, "int": value, "hint": None, "name": None, "hint_name_rva": None}
            if not value & 0x80000000:
                hn = pe_read(image, pe, value, 2) or b"\0\0"
                ent.update(hint=struct.unpack("<H", hn)[0], hint_name_rva=value,
                           name=_pe_cstr(image, pe, value + 2))
            desc["entries"].append(ent)
            i += 1
        out.append(desc)
    return out


def _import_hint_name(symbol, name_type):
    """The hint/name string of an import object (IMPORT_OBJECT_NAME_TYPE): 1 the symbol, 2 without
    its first `?`, `@` or `_`, 3 that and truncated at the first `@`; 0 (ordinal) none."""
    if name_type == 0:
        return None
    if name_type >= 2 and symbol[:1] in ("?", "@", "_"):
        symbol = symbol[1:]
    if name_type == 3:
        symbol = symbol.split("@")[0]
    return symbol


def import_members(loads):
    """The library members of a traced link's `Loaded` lines that make up its imports: an
    IMPORT_OBJECT_HEADER member, which link expands (CImplib) into `.idata$5`, `.idata$4`,
    `.idata$6` and, for code, a `.text` thunk; the `__IMPORT_DESCRIPTOR_x` member (`.idata$2` and the
    DLL name in `.idata$6`); the `\\x7fx_NULL_THUNK_DATA` member (the zero `.idata$5`/`$4`
    terminators); `__NULL_IMPORT_DESCRIPTOR` (`.idata$3`). One row per member in load order: kind
    (`import`, `descriptor`, `null_thunk`, `null_descriptor`), `dll` (the member name, which is
    link's module name), the import's `symbol` and `hint_name`, and its load index."""
    rows = []
    for li, e in enumerate([e for e in loads if e["loaded"]]):
        m = re.match(r"^(.*)\((.*)\)$", e["loaded"])
        if not m:
            continue
        member, sym, data = m.group(2), e["symbol"], None
        try:
            lib = parse_archive(_read_cached(e["lib"]), e["lib"]) if e["lib"] else None
        except (OSError, LinkTraceError):
            lib = None
        if lib is not None:
            off = lib["dictionary"].get(sym)
            data = next((x["data"] for x in lib["members"] if x["offset"] == off), None)
        if data is not None and data[:4] == b"\0\0\xff\xff":
            name = data[20:].split(b"\0")[0].decode("latin-1")
            kind = struct.unpack_from("<H", data, 18)[0]
            rows.append({"kind": "import", "dll": member, "symbol": name, "code": kind & 3 == 0,
                         "hint_name": _import_hint_name(name, (kind >> 2) & 7), "load": li})
        elif sym.startswith("__IMPORT_DESCRIPTOR_"):
            rows.append({"kind": "descriptor", "dll": member, "symbol": sym, "load": li})
        elif sym == "__NULL_IMPORT_DESCRIPTOR":
            rows.append({"kind": "null_descriptor", "dll": member, "symbol": sym, "load": li})
        elif sym.lstrip("\x7f").endswith("_NULL_THUNK_DATA"):
            rows.append({"kind": "null_thunk", "dll": member, "symbol": sym, "load": li})
    return rows


def predict_imports(members):
    """The import layout of a link from its import members in load order (IMAGE::ImportSemantics
    0x467530, SortPGRPByPMOD 0x427E80 and its comparator 0x427E30, MoveToEndOfPMODsPCON 0x427F30,
    link 8.00.50727.762): `.idata$2` holds the descriptors in their members' load order, then
    `.idata$3` the null descriptor; `.idata$4` and `.idata$5` (INT and IAT, one order) are their
    groups' contributions in load order passed through MSVCR80 `qsort` by module name (the member
    name, `KERNEL32.dll`, compared with wcscmp: ordinal, case-sensitive; not stable), then each
    DLL's null thunk (CON+0 set) moved to the end of its DLL's run; `.idata$6` (hint/name entries
    and DLL names) is not sorted: load order. The sort runs before /OPT:REF: entries removed later
    take part in it, then leave no slot."""
    thunks = [m for m in members if m["kind"] in ("import", "null_thunk")]
    order = ms_qsort(thunks, lambda a, b: (a["dll"] > b["dll"]) - (a["dll"] < b["dll"]))
    for t in [t for t in order if t["kind"] == "null_thunk"]:
        i = order.index(t)
        order.pop(i)
        j = i
        while j < len(order) and order[j]["dll"] == t["dll"]:
            j += 1
        order.insert(j, t)
    return {"descriptors": [m["dll"] for m in members if m["kind"] == "descriptor"],
            "iat": [(t["dll"], t["hint_name"] if t["kind"] == "import" else None) for t in order],
            "names": [(m["dll"], m["hint_name"] if m["kind"] == "import" else None) for m in members
                      if m["kind"] == "descriptor" or (m["kind"] == "import" and m["hint_name"])],
            "thunks": [m["symbol"] for m in members if m["kind"] == "import" and m["code"]]}


def import_check(image, loads, publics):
    """Compare `predict_imports` with the image's import directory. Which imports survive
    /OPT:REF is taken from the image (library members are not walked), so the predicted orders
    are compared on the surviving entries. `thunks`: the `.text` order of the code imports'
    `jmp [__imp_x]` thunks (map publics of a `.dll` member) against their members' load order."""
    pe = parse_pe(image)
    actual = parse_imports(image, pe)
    pred = predict_imports(import_members(loads))
    a_desc = [d["dll"].casefold() for d in actual]
    p_desc = [x.casefold() for x in pred["descriptors"] if x.casefold() in a_desc]
    a_iat = []
    for d in sorted(actual, key=lambda d: d["iat_rva"]):
        a_iat += [(d["dll"].casefold(), e["name"]) for e in d["entries"]] + [(d["dll"].casefold(), None)]
    present = set(a_iat)
    p_iat = [k for k in ((dll.casefold(), n) for dll, n in pred["iat"]) if k in present]
    six = [(e["hint_name_rva"], (d["dll"].casefold(), e["name"])) for d in actual for e in d["entries"]
           if e["hint_name_rva"]] + [(d["name_rva"], (d["dll"].casefold(), None)) for d in actual]
    a_six = [k for _, k in sorted(six)]
    p_six = [k for k in ((dll.casefold(), n) for dll, n in pred["names"]) if k in set(a_six)]
    int_same = all((pe_read(image, pe, d["iat_rva"] + 4 * i, 4) or b"") == struct.pack("<I", e["int"])
                   for d in actual for i, e in enumerate(d["entries"]))
    base = pe["image_base"]
    rva = {p["symbol"]: p["va"] - base for p in publics
           if p.get("lib") and (p.get("member") or "").lower().endswith(".dll")}
    p_thunks = [s for s in pred["thunks"] if s in rva]
    a_thunks = sorted(p_thunks, key=lambda s: rva[s])
    res = {"descriptors": p_desc == a_desc, "iat": p_iat == a_iat, "int_equals_iat": int_same,
           "names": p_six == a_six, "thunks": p_thunks == a_thunks,
           "dlls": len(actual), "entries": sum(len(d["entries"]) for d in actual),
           "removed": sum(1 for _, n in pred["iat"] if n) - sum(len(d["entries"]) for d in actual)}
    res["predicted_equals_actual"] = all(res[k] for k in ("descriptors", "iat", "int_equals_iat", "names", "thunks"))
    for k, p, a in (("iat", p_iat, a_iat), ("names", p_six, a_six), ("descriptors", p_desc, a_desc),
                    ("thunks", p_thunks, a_thunks)):
        if not res[k]:
            res[k + "_predicted"], res[k + "_actual"] = p, a
    return res


# ---------------------------------------------------------------- explain

def explain(model, rva=None, symbol=None):
    lines = []
    hits = []
    if symbol is not None:
        hits = [c for c in model["contributions"] if c["symbol"] == symbol]
        if not hits:
            pubs = [p for p in model["publics"] if p["symbol"] == symbol]
            if pubs:
                return ["%s at RVA 0x%X from %s (not a traced object's contribution)" % (symbol, pubs[0]["rva"], pubs[0]["origin"])]
            return ["%s: not in the model" % symbol]
    else:
        hits = [c for c in model["contributions"] if c["status"] == "kept" and c["rva"] is not None
                and c["rva"] <= rva < c["rva"] + c["size"]]
        if not hits:
            hits = [c for c in model["contributions"] if c["status"] == "folded" and c["rva"] == rva]
        if not hits:
            before = [p for p in model["publics"] if p["rva"] <= rva]
            if before:
                p = max(before, key=lambda p: p["rva"])
                return ["RVA 0x%X: no traced contribution; nearest public below is %s+0x%X from %s"
                        % (rva, p["symbol"], rva - p["rva"], p["origin"])]
            return ["RVA 0x%X: not in the model" % rva]
    for c in hits:
        where = "RVA 0x%X" % c["rva"] if c["rva"] is not None else "no address"
        lines.append("%s: %s, %s (%s #%d, %s, size 0x%X, align %d) from %s"
                     % (c["symbol"], c["status"], where, c["section"], c["section_index"],
                        c["selection"] or "non-COMDAT", c["size"], c["align"], c["obj"]))
        lines.append("  reason: " + (c["reason"] or "-"))
        if c["padding_before"] is not None:
            lines.append("  padding before: %d byte(s) %s" % (c["padding_before"], c["padding_bytes"] or ""))
        if c["fold_group"] is not None:
            g = next(g for g in model["fold_groups"] if g["id"] == c["fold_group"])
            lines.append("  fold group %d: survivor %s (%s); members %s"
                         % (g["id"], g["survivor"], g["survivor_origin"],
                            ", ".join("%s(%s)" % (m["symbol"], m["origin"]) for m in g["members"])))
        if rva is not None and c["status"] == "kept":
            off = rva - c["rva"]
            inner = [x for x in c.get("symbols", []) if x["offset"] <= off]
            lines.append("  offset in contribution: 0x%X%s" % (off, " (%s+0x%X)" % (
                inner[-1]["name"], off - inner[-1]["offset"]) if len(c.get("symbols", [])) > 1 and inner else ""))
        if len(c.get("symbols", [])) > 1:
            lines.append("  symbols: " + ", ".join("%s+0x%X" % (x["name"], x["offset"]) for x in c["symbols"]))
        for r in c["relocs"]:
            lines.append("  reloc +0x%X %s %s -> %s %s" % (r["offset"], r["type"], r["symbol"],
                         "0x%X" % r["target_rva"] if r["target_rva"] is not None else "?",
                         ",".join(r["target"] or []) or ""))
    return lines


# ---------------------------------------------------------------- order predictor

def predict_order(objs, roots=None, kept=None, folded=None, fill=0xCC, start=0):
    """Predict the code layout of the objects' .text contributions.

    Rules (docs/link-trace.md): contributions follow the command-line object
    order, then each object's section-table order; `$` groups sort by full
    name within one output section; each contribution starts at its section
    alignment, the gap filled with int3 in code. A COMDAT that is removed by
    /OPT:REF or replaced by /OPT:ICF leaves no gap. `kept`/`folded` (sets of
    (obj path, symbol)) come from a model; otherwise /OPT:REF is approximated
    by reachability from `roots` and no folding is assumed.
    """
    if kept is None:
        kept = reachable(objs, roots)
    folded = folded or set()
    seen_any = set()
    rows = []
    for oi, obj in enumerate(objs):
        for sec in obj["sections"]:
            if not sec["code"] or sec["removed"] or sec["size"] == 0:
                continue
            sym = comdat_symbol(sec)
            key = own = (obj["path"], sym if sec["comdat"] else "#%d" % sec["index"])
            if sec["associated"]:
                # Kept with its parent; but folded on its own (an unwind funclet folds into an
                # identical funclet of another function while its parent stays).
                parent = obj["sections"][sec["associated"] - 1]
                key = (obj["path"], comdat_symbol(parent))
                if sym and own in folded:
                    continue
            if sec["comdat"] and sec["selection"] in ("any", "same_size", "exact", "largest"):
                # The first definer's copy is the one selected, whether it is then kept, folded
                # by /OPT:ICF or removed: a later object's duplicate never takes its place.
                if sym in seen_any:
                    continue
                seen_any.add(sym)
            if sec["comdat"] and (key not in kept or key in folded):
                continue
            rows.append({"obj": obj["path"], "obj_index": oi, "section_index": sec["index"], "section": sec["name"],
                         "group": group_name(sec["name"]), "symbol": sym, "size": sec["size"], "align": sec["align"],
                         "icf_key": icf_key(obj, sec) if sec["comdat"] and not sec["associated"] else None})
    # Callers of folded functions fold too (observed with ICF, ICF=1 and ICF=2): refine
    # the keys with each target's group until the grouping is stable.
    rep = {}
    for _ in range(16):
        keys = {}
        for r in rows:
            if r["icf_key"] is not None:
                head, raw, targets = r["icf_key"]
                k = (head, raw, tuple((o, t, rep.get(n, n), a) for o, t, n, a in targets))
                keys.setdefault(k, []).append(r)
        new = {}
        for members in keys.values():
            for m in members:
                new[m["symbol"]] = "<icf:%s>" % members[0]["symbol"]
        if new == rep:
            break
        rep = new
    groups = {}
    for members in keys.values():
        for m in members:
            groups[id(m)] = members
    for r in rows:
        r.pop("icf_key")
        members = groups.get(id(r), [])
        r["icf_candidates"] = [m["symbol"] for m in members] if len(members) > 1 else None
    rows.sort(key=lambda r: (r["group"], r["section"], r["obj_index"], r["section_index"]))
    at = start
    for r in rows:
        pad = (-at) % r["align"]
        r["padding_before"] = pad
        r["padding_bytes"] = ("%02x" % fill) * pad
        r["offset"] = at + pad
        at = r["offset"] + r["size"]
    return rows


def icf_key(obj, sec):
    """Identity of a code COMDAT for /OPT:ICF: bytes with relocated words masked, plus the
    ordered (offset, type, target) of each relocation. Single pass: functions that differ
    only by calls to functions that themselves fold are not grouped (link iterates)."""
    raw = bytearray(sec["raw"])
    targets = []
    by_index = {x["index"]: x for x in obj["symbols"]}
    for rel in sec["relocs"]:
        raw[rel["offset"]:rel["offset"] + 4] = bytes(4)
        t = by_index.get(rel["symbol_index"])
        name = t["name"] if t and (t["external"] or t["name"].startswith(("??_C@", "__real@"))) else None
        if name is None and t:
            name = "%s#%d" % (obj["path"], t["section"])  # a static target: same only within one object
        targets.append((rel["offset"], rel["type"], name, rel.get("addend")))
    return (sec["characteristics"], bytes(raw), tuple(targets))


def reachable(objs, roots=None):
    """/OPT:REF approximation: COMDATs reachable from the roots and from non-COMDAT sections."""
    defs = {}
    for obj in objs:
        for sec in obj["sections"]:
            for sym in sec["symbols"]:
                if sym["external"]:
                    defs.setdefault(sym["name"], (obj["path"], sec["index"]))
    secs = {(obj["path"], sec["index"]): (obj, sec) for obj in objs for sec in obj["sections"]}
    assoc = {}
    for obj in objs:
        for sec in obj["sections"]:
            if sec["associated"]:
                assoc.setdefault((obj["path"], sec["associated"]), []).append((obj["path"], sec["index"]))
    work = []
    for obj in objs:
        for sec in obj["sections"]:
            if not sec["comdat"] and not sec["removed"] and sec["size"]:
                work.append((obj["path"], sec["index"]))
    for name in roots or DEFAULT_ROOTS:
        if name in defs:
            work.append(defs[name])
    live = set()
    while work:
        key = work.pop()
        if key in live or key not in secs:
            continue
        live.add(key)
        obj, sec = secs[key]
        work.extend(assoc.get(key, []))
        for rel in sec["relocs"]:
            if rel["symbol_section"] and rel["symbol_section"] > 0:
                target = obj["symbols"] and next((s for s in obj["symbols"] if s["index"] == rel["symbol_index"]), None)
                if target and not target["external"]:
                    work.append((obj["path"], rel["symbol_section"]))
                    continue
            if rel["symbol"] in defs:
                work.append(defs[rel["symbol"]])
            elif rel.get("weak_default") in defs:
                work.append(defs[rel["weak_default"]])
    out = set()
    for path, index in live:
        obj, sec = secs[(path, index)]
        out.add((path, comdat_symbol(sec) if sec["comdat"] else "#%d" % index))
    return out


def model_sets(model):
    kept, folded = set(), set()
    for c in model["contributions"]:
        key = (c["obj"], c["symbol"])
        if c["status"] in ("kept", "duplicate"):
            kept.add(key)
        if c["status"] == "folded":
            folded.add(key)
            kept.add(key)
    return kept, folded


# ---------------------------------------------------------------- toolchain

def toolchain_env(name="sp1"):
    try:
        sys.path.insert(0, str(ROOT / "tools"))
        import probe_toolchain
        tc = probe_toolchain.load_toolchain(name)
        return Path(tc["bin"]), probe_toolchain.toolchain_environment(tc)
    except Exception:
        tc = json.loads(TOOLCHAINS.read_text(encoding="utf-8-sig"))["toolchains"][name]
        env = {k: v for k, v in os.environ.items() if k not in ("CL", "_CL_", "LINK", "_LINK_")}
        env["PATH"] = os.pathsep.join([tc["bin"], *tc.get("runtime", []), env.get("PATH", "")])
        env["INCLUDE"] = os.pathsep.join(tc.get("include", []))
        env["LIB"] = os.pathsep.join(tc.get("lib", []))
        return Path(tc["bin"]), env


def run_link(objs, flags, out, toolchain="sp1", output_name="trace.exe"):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    bindir, env = toolchain_env(toolchain)
    image = out / output_name
    command = [str(bindir / "link.exe"), "/NOLOGO", "/VERBOSE", "/MAP:" + str(out / "trace.map"),
               "/MAPINFO:EXPORTS", "/OUT:" + str(image), *flags, *[str(Path(o).resolve()) for o in objs]]
    proc = subprocess.run(command, env=env, capture_output=True, text=True, errors="replace", timeout=300)
    (out / "verbose.txt").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    if proc.returncode or not image.is_file():
        raise LinkTraceError("link failed (%d): %s" % (proc.returncode, (proc.stdout + proc.stderr)[-2000:]))
    return command, proc.stdout + proc.stderr, (out / "trace.map").read_text(errors="replace"), image.read_bytes()


def compile_sources(sources, out, flags, toolchain="sp1"):
    bindir, env = toolchain_env(toolchain)
    objs = []
    for name, text in sources:
        src = Path(out) / name
        src.write_text(text, encoding="utf-8")
        obj = src.with_suffix(".obj")
        proc = subprocess.run([str(bindir / "cl.exe"), "/nologo", "/c", *flags, "/Fo" + str(obj), str(src)],
                              env=env, capture_output=True, text=True, errors="replace", timeout=120, cwd=out)
        if proc.returncode:
            raise LinkTraceError("cl failed on %s: %s" % (name, proc.stdout[-2000:]))
        objs.append(obj)
    return objs


def make_lib(objs, path, toolchain="sp1"):
    """lib.exe of the pinned toolchain: a static library of `objs` in this order."""
    bindir, env = toolchain_env(toolchain)
    proc = subprocess.run([str(bindir / "lib.exe"), "/NOLOGO", "/OUT:" + str(path), *[str(o) for o in objs]],
                          env=env, capture_output=True, text=True, errors="replace", timeout=120)
    if proc.returncode:
        raise LinkTraceError("lib failed on %s: %s" % (path, proc.stdout[-2000:]))
    return Path(path)


def _link_is_traceable(toolchain="sp1"):
    import hashlib
    try:
        bindir, _ = toolchain_env(toolchain)
        return hashlib.sha256((bindir / "link.exe").read_bytes()).hexdigest() == LINK_SHA256
    except OSError:
        return False


def trace(objs, flags, out, toolchain="sp1", output_name="trace.exe", debug=None):
    """`run`: link, model, check the layout. With `debug` (default: when link.exe is the build
    whose breakpoints `icf_trace` knows) the link runs under the debugger so that the folds come
    from the ICFFold calls (`icf.json` beside the model)."""
    parsed = [parse_obj(Path(o).read_bytes(), str(Path(o).resolve())) for o in objs if not _is_lib(o)]
    if debug is None:
        debug = _link_is_traceable(toolchain) and sys.platform == "win32"
    icf = None
    if debug:
        out = Path(out).resolve()
        icf = icf_trace(objs, ["/MAPINFO:EXPORTS", *flags], out, toolchain, output_name)
        (out / "icf.json").write_text(json.dumps(icf), encoding="utf-8")
        command, verbose = icf["command"], (out / "verbose.txt").read_text(encoding="utf-8")
        mp, image = (out / "trace.map").read_text(errors="replace"), (out / output_name).read_bytes()
    else:
        command, verbose, mp, image = run_link(objs, flags, out, toolchain, output_name)
    return layout_model(parsed, verbose, mp, image, command, icf)


def layout_model(parsed, verbose, mp, image, command=None, icf=None):
    """`build_model` plus the layout checks of `run`: `order_check` (the traced objects' code
    contributions in `predict_order`'s order, and every alignment gap between two of them that
    are adjacent in the image) and `import_check` (`import_check`)."""
    model = build_model(parsed, verbose, mp, image, command, icf=icf)
    kept, folded = model_sets(model)
    text_rows = [c for c in model["contributions"] if c["status"] == "kept" and c["code"] and c["rva"] is not None]
    if text_rows:
        first = min(c["rva"] for c in text_rows)
        pred = predict_order(parsed, kept=kept, folded=folded)
        actual = sorted(text_rows, key=lambda c: c["rva"])
        p_order = [(r["obj"], r["symbol"]) for r in pred]
        a_order = [(c["obj"], c["symbol"]) for c in actual]
        # Padding: where two contributions are adjacent in the image (nothing mapped between),
        # the predicted alignment gap must be the actual one.
        gaps, bad = 0, []
        if p_order == a_order:
            for i in range(1, len(pred)):
                if actual[i]["padding_before"] is None:
                    continue
                gaps += 1
                end = actual[i - 1]["rva"] + pred[i - 1]["size"]
                if (-end) % pred[i]["align"] != actual[i]["padding_before"]:
                    bad.append(actual[i]["symbol"])
        model["order_check"] = {"predicted_equals_actual": p_order == a_order and not bad,
                                "first_rva": first, "predicted": len(p_order), "actual": len(a_order),
                                "gaps_checked": gaps, "gaps_wrong": bad}
        if p_order != a_order:
            i = next((i for i, (p, a) in enumerate(zip(p_order, a_order)) if p != a), min(len(p_order), len(a_order)))
            model["order_check"]["first_difference"] = {
                "index": i, "predicted": list(p_order[i]) if i < len(p_order) else None,
                "actual": list(a_order[i]) if i < len(a_order) else None}
    loads = parse_loads(verbose)
    if any(e["loaded"] for e in loads):
        model["import_check"] = import_check(image, loads, parse_map(mp)["publics"])
    return model


# ---------------------------------------------------------------- ICF trace (debug API)

# link.exe 8.00.50727.762, preferred base 0x400000. Addresses from the public link.pdb and the
# disassembly of IMAGE::ICFAnalysis, ICFComparePcon, ICFLocateICs and ICFFold (docs/link-trace.md).
LINK_SHA256 = "16beda175e8e83f45187c0cd18eed06d0ec26a401d0bbc3544074c57eeebaff5"
LINK_BASE = 0x400000
BP_QSORT, BP_QSORT_RET, BP_FOLD = 0x4558E2, 0x4558E8, 0x4541C0
PIMAGE = 0x4B2B5C            # ICFCompareContext::pimage (IMAGE*)
# CrcEdges (0x4539F0): entry, every SigForPbCb call site (what it hashes there) and the store of the
# result; CrcEdgesLoop (0x453C90): entry and its one SigForPbCb call.
BP_CRC = 0x4539F0
BP_CRC_SITES = {0x453AE7: "edge", 0x453B1E: "import", 0x453B4F: "value", 0x453BD1: "icfid",
                0x453C08: "crc", 0x453C34: "name", 0x453C40: "name+2c", 0x453C4C: "name+30"}
BP_CRC_DONE = 0x453C6E
BP_LOOP, BP_LOOP_SITE = 0x453C90, 0x453DEE


class LinkDebugger:
    """Runs link.exe under the Windows debug API with int3 breakpoints (c2_trace.Debugger for memory)."""

    def __init__(self, breaks, handler):
        self.breaks, self.handler = breaks, handler

    def run(self, command, env, cwd, timeout=600):
        import ctypes
        import time
        import c2_trace
        dbg = c2_trace.Debugger()
        self.dbg = dbg
        k = dbg.k
        ps = ctypes.sizeof(ctypes.c_void_p)
        raw_size = 160 if ps == 8 else 84

        class DebugEvent(ctypes.Structure):
            _fields_ = [("code", ctypes.c_uint32), ("pid", ctypes.c_uint32), ("tid", ctypes.c_uint32),
                        ("raw", ctypes.c_ubyte * (raw_size + (4 if ps == 8 else 0)))]

        pad = 4 if ps == 8 else 0
        threads, bps, stepping = {}, {}, {}
        brk = (c2_trace.STATUS_BREAKPOINT, c2_trace.STATUS_WX86_BREAKPOINT)
        step = (c2_trace.STATUS_SINGLE_STEP, c2_trace.STATUS_WX86_SINGLE_STEP)
        self.slide = None
        log = Path(cwd) / "link-output.log"
        with open(log, "wb") as out:
            proc = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW | 0x2)
            deadline = time.monotonic() + timeout
            try:
                while True:
                    if time.monotonic() > deadline:
                        raise LinkTraceError("link trace exceeded %d seconds" % timeout)
                    ev = DebugEvent()
                    if not k.WaitForDebugEvent(ctypes.byref(ev), 1000):
                        if ctypes.get_last_error() == 121:
                            continue
                        raise ctypes.WinError(ctypes.get_last_error())
                    raw = bytes(ev.raw)[pad:]
                    ptr = lambda i: int.from_bytes(raw[i * ps:(i + 1) * ps], "little")
                    status = c2_trace.DBG_CONTINUE
                    if ev.code == 3:  # CREATE_PROCESS: hFile, hProcess, hThread, base
                        if ptr(0):
                            k.CloseHandle(ptr(0))
                        dbg.process = ptr(1)
                        threads[ev.tid] = ptr(2)
                        if self.slide is None:
                            self.slide = ptr(3) - LINK_BASE
                            for va in self.breaks:
                                at = va + self.slide
                                bps[at] = (dbg.read(at, 1), va)
                                dbg.write(at, b"\xCC")
                    elif ev.code == 2:
                        threads[ev.tid] = ptr(0)
                    elif ev.code == 4:
                        threads.pop(ev.tid, None)
                    elif ev.code == 6 and ptr(0):
                        k.CloseHandle(ptr(0))
                    elif ev.code == 1:
                        code = int.from_bytes(raw[0:4], "little")
                        address = int.from_bytes(raw[8 + ps:8 + 2 * ps], "little") if ps == 8 else \
                            int.from_bytes(raw[12:16], "little")
                        if code in brk and address in bps:
                            thread = threads[ev.tid]
                            ctx = dbg.context(thread)
                            orig, va = bps[address]
                            self.handler(self, va, ctx)
                            dbg.write(address, orig)
                            ctx.Eip = address
                            ctx.EFlags |= 0x100
                            stepping[ev.tid] = address
                            dbg.set_context(thread, ctx)
                        elif code in step and ev.tid in stepping:
                            dbg.write(stepping.pop(ev.tid), b"\xCC")
                        elif code not in brk:
                            status = c2_trace.DBG_EXCEPTION_NOT_HANDLED
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
        return returncode, log.read_text(errors="replace")

    def u32(self, va):
        return self.dbg.read_u32(va + self.slide)

    def wstr(self, va, limit=520):
        if not va:
            return None
        data = b""
        while len(data) < limit:  # read page by page: the string may end just before an unmapped page
            chunk = self.dbg.read(va + len(data), min(limit - len(data), 0x1000 - ((va + len(data)) & 0xFFF)))
            data += chunk
            end = next((i for i in range(0, len(data) - 1, 2) if data[i:i + 2] == b"\0\0"), None)
            if end is not None:
                return data[:end].decode("utf-16-le", "replace")
        return data.decode("utf-16-le", "replace")


# The library search (docs/link-trace.md "Library search"): IMAGE::ResolveExternalsInLibs entry, LIB::Search
# entry ([esp+4] = LIB*, LIB+0 = its path) and the return of its LIB::FGetMember call (al = found,
# [esp+0x38] = the symbol's name), for every undefined external the walk looks up.
BP_RESOLVE_LIBS, BP_SEARCH, BP_SEARCH_LOOKUP = 0x4729E0, 0x48CB90, 0x48CC9A


class SearchRecorder:
    """Breakpoint handler: each ResolveExternalsInLibs round, each LIB::Search call and the
    dictionary lookups of its walk, in order."""

    def __init__(self):
        self.rounds = -1
        self.searches = []

    def breaks(self):
        return [BP_RESOLVE_LIBS, BP_SEARCH, BP_SEARCH_LOOKUP]

    def __call__(self, d, va, ctx):
        rd = d.dbg.read_u32
        if va == BP_RESOLVE_LIBS:
            self.rounds += 1
        elif va == BP_SEARCH:
            lib = rd(ctx.Esp + 4)
            self.searches.append({"round": max(self.rounds, 0), "lib": d.wstr(rd(lib)), "tried": []})
        elif va == BP_SEARCH_LOOKUP and self.searches:
            ptr, raw = rd(ctx.Esp + 0x38), b""
            while len(raw) < 4096:
                chunk = d.dbg.read(ptr + len(raw), 64)
                if b"\0" in chunk:
                    raw += chunk[:chunk.index(b"\0")]
                    break
                raw += chunk
            self.searches[-1]["tried"].append([raw.decode("latin-1"), bool(ctx.Eax & 0xFF)])


def search_trace(objs, flags, out, toolchain="sp1", output_name="trace.exe"):
    """Link under the debugger with breakpoints in the library search; compare every Search call's
    walk (library, symbols looked up, found or not) with `search_libraries`. Returns
    {"searches": traced, "simulated": ..., "equal": bool, "first_difference": index or None}."""
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    bindir, env = toolchain_env(toolchain)
    import hashlib
    if hashlib.sha256((bindir / "link.exe").read_bytes()).hexdigest() != LINK_SHA256:
        raise LinkTraceError("search-trace breakpoints are for link.exe 8.00.50727.762 (sha256 %s)" % LINK_SHA256)
    image = out / output_name
    command = [str(bindir / "link.exe"), "/NOLOGO", "/VERBOSE", "/OUT:" + str(image), *flags,
               *[str(Path(o).resolve()) for o in objs]]
    rec = SearchRecorder()
    code, log = LinkDebugger(rec.breaks(), rec).run(command, env, out)
    (out / "verbose.txt").write_text(log, encoding="utf-8")
    if code:
        raise LinkTraceError("link failed (%d): %s" % (code, log[-2000:]))
    sim = simulate_command(command, parse_loads(log), env_lib=env.get("LIB", ""))
    norm = lambda s: [(x["round"], _lib_key(x["lib"]), [n for n, _ in x["tried"]] if x["tried"] and
                       isinstance(x["tried"][0], list) else list(x["tried"])) for x in s]
    a, b = norm(rec.searches), norm(sim["searches"])
    first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), None)
    if first is None and len(a) != len(b):
        first = min(len(a), len(b))
    found = sum(1 for s in rec.searches for _, f in s["tried"] if f)
    return {"command": command, "searches": rec.searches, "simulated": sim["searches"], "equal": first is None,
            "first_difference": first, "lookups": sum(len(s["tried"]) for s in rec.searches), "found": found}


class IcfRecorder:
    """Breakpoint handler: the candidate array at each ICFAnalysis qsort, its sorted order, the folds.

    CON (0x40 bytes, link's contribution): +4 flags (section characteristics; 0x4000 = folded),
    +8 size, +0x10 MOD*, +0x14 GRP*, +0x1C size adjustment, +0x20 COMDAT checksum, +0x28 ICF CRC,
    +0x3C fold target. MOD: +8 object name, +0x94 node array (20 bytes each), +0x98 LIB*,
    +0x9C CON array, +0xBC CON count. Node: +8 and +0x11 are comparator keys."""

    def __init__(self, crc=False):
        self.sorts, self.folds, self.cons = [], [], {}
        self._pending = None
        self.crc = crc
        self.crc_log, self._node_con, self._crc_open = [], {}, {}

    def breaks(self):
        out = [BP_QSORT, BP_QSORT_RET, BP_FOLD]
        if self.crc:
            out += [BP_CRC, BP_CRC_DONE, BP_LOOP, BP_LOOP_SITE, *BP_CRC_SITES]
        return out

    @staticmethod
    def node_of(d, pcon):
        rd = d.dbg.read_u32
        mod = rd(pcon + 0x10)
        rgcon, ccon = rd(mod + 0x9C), rd(mod + 0xBC)
        if rgcon <= pcon <= rgcon + (ccon << 6):
            return rd(mod + 0x94) + ((pcon - rgcon) >> 6) * 20
        return pcon + 0x40

    def crc_event(self, d, va, ctx):
        """CrcEdges/CrcEdgesLoop: log each SigForPbCb input (site, bytes, seed) per contribution."""
        rd, esp = d.dbg.read_u32, ctx.Esp
        if va == BP_CRC:
            pcon = rd(esp + 8)
            self._node_con[self.node_of(d, pcon)] = pcon
            return
        if va == BP_LOOP:
            pcon = ctx.Eax
            node = self.node_of(d, pcon)
            self._node_con[node] = pcon
            self._loop = {"con": self.con(d, pcon), "loop": True, "round": d.dbg.read(esp + 8, 1)[0],
                          "chunks": []}
            self.crc_log.append(self._loop)
            return
        if va == BP_LOOP_SITE:
            pb, cb, seed = rd(esp), rd(esp + 4), rd(esp + 8)
            self._loop["chunks"].append(["loop", d.dbg.read(pb, cb).hex(), seed])
            return
        if va == BP_CRC_DONE:
            node = ctx.Eax
            entry = self._crc_open.pop(node, None) or {"con": self.con(d, self._node_con[node]), "chunks": []}
            entry["value"], entry["cyclic"] = ctx.Esi, ctx.Ecx & 0xFF
            self.crc_log.append(entry)
            return
        node = rd(esp + 0x1C)
        entry = self._crc_open.get(node)
        if entry is None:
            entry = self._crc_open[node] = {"con": self.con(d, self._node_con[node]), "chunks": []}
        pb, cb, seed = rd(esp), rd(esp + 4), rd(esp + 8)
        entry["chunks"].append([BP_CRC_SITES[va], d.dbg.read(pb, cb).hex(), seed])

    def con(self, d, pcon):
        if pcon in self.cons:
            return self.cons[pcon]["id"]
        rd = d.dbg.read_u32
        raw = d.dbg.read(pcon, 0x40)
        word = lambda o: struct.unpack_from("<I", raw, o)[0]
        mod = word(0x10)
        rgcon, rgnode, ccon = rd(mod + 0x9C), rd(mod + 0x94), rd(mod + 0xBC)
        if rgcon <= pcon <= rgcon + (ccon << 6):
            index = (pcon - rgcon) >> 6
            node = rgnode + index * 20
        else:
            index, node = None, pcon + 0x40
        nraw = d.dbg.read(node, 20)
        lib = rd(mod + 0x98)
        lib_name = d.wstr(rd(lib)) if lib and not (rd(lib + 0x30) >> 4) & 1 else None
        rec = {"id": len(self.cons), "obj": d.wstr(rd(mod + 8)), "lib": lib_name, "con_index": index,
               "module": rd(mod + 0x4C),
               "flags": word(4), "size": word(8), "size_adjust": word(0x1C), "checksum": word(0x20),
               "node_8": struct.unpack_from("<I", nraw, 8)[0], "node_11": nraw[0x11],
               "mod_ac": struct.unpack_from("<H", d.dbg.read(mod + 0xAC, 2))[0],
               "con_raw": raw.hex(), "node_raw": nraw.hex()}
        grp = word(0x14)
        rec["group"] = self.cstr(d, rd(grp)) if grp else None
        self.cons[pcon] = rec
        return rec["id"]

    @staticmethod
    def cstr(d, va, limit=4096):
        # Page by page: a name that runs past a page boundary is read whole (a single read up to
        # the page end cut `?sub_7C9DD0@AVP_Move@@QAEXH_N@Z` short).
        data = b""
        try:
            while len(data) < limit:
                at = va + len(data)
                chunk = d.dbg.read(at, min(limit - len(data), 0x1000 - (at & 0xFFF)))
                data += chunk
                if b"\0" in chunk or not chunk:
                    break
        except OSError:
            if not data:
                return None
        return data.split(b"\0", 1)[0].decode("latin-1")

    def edges(self, d, pcon):
        """The CON's ICF edges (node+0: blocks of next, count, 12-byte edges: target, offset,
        flags|type); for a target outside the objects, what CrcEdges hashes: an import's name
        (flags 0x4000000, from the IMAGE+0x250 string table) or the ICFId (module, section)."""
        rd = d.dbg.read_u32
        blk, out = rd(self.node_of(d, pcon)), []
        while blk:
            for e in range(min(rd(blk + 4), 4096)):
                t, off, flags = struct.unpack("<III", d.dbg.read(blk + 8 + 12 * e, 12))
                row = {"offset": off, "flags": flags}
                if flags & 0x4000000:
                    row["import"] = self.cstr(d, rd(rd(d.u32(PIMAGE) + 0x250)) + rd(t + 4))
                elif flags & 0x2000000:
                    row["other"] = d.dbg.read(t, 8).hex() if t else None
                elif t:
                    row["con"] = self.con(d, t)
                    tm = rd(t + 0x10)
                    lib = rd(tm + 0x98)
                    row["module"] = rd(tm + 0x4C)
                    row["section"] = ((t - rd(tm + 0x9C)) >> 6) + 1
                    row["library"] = bool(lib and not (rd(lib + 0x30) >> 4) & 1)
                out.append(row)
            blk = rd(blk)
        return out

    @staticmethod
    def keys(d, pcon):
        """ICFComparePcon's keys, read at sort time (the edge CRC changes between iterations):
        [live (flags & 0x2000), cycle byte (node+0x11), reloc count (+0x20, 0 for a mod flagged 0x800
        at +0xAC), size - adjustment, edge CRC (node+8), COMDAT checksum (+0x28)]."""
        rd = d.dbg.read_u32
        raw = d.dbg.read(pcon, 0x40)
        word = lambda o: struct.unpack_from("<I", raw, o)[0]
        mod = word(0x10)
        rgcon, rgnode, ccon = rd(mod + 0x9C), rd(mod + 0x94), rd(mod + 0xBC)
        node = rgnode + ((pcon - rgcon) >> 6) * 20 if rgcon <= pcon <= rgcon + (ccon << 6) else pcon + 0x40
        nraw = d.dbg.read(node, 20)
        modflag = struct.unpack_from("<H", d.dbg.read(mod + 0xAC, 2))[0] >> 11 & 1
        return [1 if word(4) & 0x2000 else 0, nraw[0x11], 0 if modflag else word(0x20),
                (word(8) - word(0x1C)) & 0xFFFFFFFF, struct.unpack_from("<I", nraw, 8)[0], word(0x28)]

    def __call__(self, d, va, ctx):
        esp = ctx.Esp
        rd = d.dbg.read_u32
        if va not in (BP_QSORT, BP_QSORT_RET, BP_FOLD):
            return self.crc_event(d, va, ctx)
        if va == BP_QSORT:
            base, num = rd(esp), rd(esp + 4)
            pcons = [rd(base + 4 * i) for i in range(num)]
            ids = [self.con(d, p) for p in pcons]
            for p in pcons:
                if "edges" not in self.cons[p]:
                    self.cons[p]["edges"] = self.edges(d, p)
            self._pending = {"iteration": rd(esp + 0x34), "group": rd(esp + 0x28), "base": base, "input": ids,
                             "keys": [self.keys(d, p) for p in pcons],
                             "folded": [i for i, p in zip(ids, pcons) if rd(p + 4) & 0x4000],
                             "flag_162": d.dbg.read(d.u32(PIMAGE) + 0x162, 1)[0]}
        elif va == BP_QSORT_RET and self._pending:
            p = self._pending
            p["output"] = [self.cons[rd(p["base"] + 4 * i)]["id"] for i in range(len(p["input"]))]
            del p["base"]
            self.sorts.append(p)
            self._pending = None
        elif va == BP_FOLD:
            self.folds.append({"keep": self.con(d, rd(esp + 4)), "fold": self.con(d, rd(esp + 8)),
                               "sort": len(self.sorts) - 1})


def icf_compare(a, b, ref=True):
    """ICFComparePcon (0x4538A0) on key lists (IcfRecorder.keys). `ref` is the IMAGE+0x162 byte
    (/OPT:REF): live contributions sort first. A cycle byte set sorts last; the other keys ascend
    unsigned. Identical COMDATs compare equal (0)."""
    if ref and a[0] != b[0]:
        return -1 if a[0] else 1
    if a[1] != b[1]:
        return 1 if a[1] else -1
    for x, y in zip(a[2:], b[2:]):
        if x != y:
            return -1 if x < y else 1
    return 0


def ms_qsort(items, cmp):
    """MSVCR80 qsort (VC/crt/src/qsort.c of VC8): median-of-three quicksort with the partition
    element followed when swapped, equal-to-pivot elements skipped, the smaller side pushed,
    and a selection sort (`shortsort`: max to the end) for 8 or fewer elements. Not stable.
    Works on a copy of `items` (indices replace pointers) and returns it."""
    a = list(items)
    if len(a) < 2:
        return a
    c = lambda i, j: cmp(a[i], a[j])

    def swap(i, j):
        if i != j:
            a[i], a[j] = a[j], a[i]

    stack = []
    lo, hi = 0, len(a) - 1
    while True:
        size = hi - lo + 1
        if size <= 8:
            h = hi
            while h > lo:
                mx = lo
                for p in range(lo + 1, h + 1):
                    if c(p, mx) > 0:
                        mx = p
                swap(mx, h)
                h -= 1
        else:
            mid = lo + size // 2
            if c(lo, mid) > 0:
                swap(lo, mid)
            if c(lo, hi) > 0:
                swap(lo, hi)
            if c(mid, hi) > 0:
                swap(mid, hi)
            loguy, higuy = lo, hi
            while True:
                if mid > loguy:
                    loguy += 1
                    while loguy < mid and c(loguy, mid) <= 0:
                        loguy += 1
                if mid <= loguy:
                    loguy += 1
                    while loguy <= hi and c(loguy, mid) <= 0:
                        loguy += 1
                higuy -= 1
                while higuy > mid and c(higuy, mid) > 0:
                    higuy -= 1
                if higuy < loguy:
                    break
                swap(loguy, higuy)
                if mid == higuy:
                    mid = loguy
            higuy += 1
            if mid < higuy:
                higuy -= 1
                while higuy > mid and c(higuy, mid) == 0:
                    higuy -= 1
            if mid >= higuy:
                higuy -= 1
                while higuy > lo and c(higuy, mid) == 0:
                    higuy -= 1
            if higuy - lo >= hi - loguy:
                if lo < higuy:
                    stack.append((lo, higuy))
                if loguy < hi:
                    lo = loguy
                    continue
            else:
                if loguy < hi:
                    stack.append((loguy, hi))
                if lo < higuy:
                    hi = higuy
                    continue
        if not stack:
            return a
        lo, hi = stack.pop()


def icf_replay(sort, ref=True):
    """Sort one traced candidate array with the model; returns the predicted output ids."""
    keys = dict(zip(sort["input"], sort["keys"]))
    return ms_qsort(sort["input"], lambda x, y: icf_compare(keys[x], keys[y], ref))


def icf_survivors(order, keys, identical, deps=lambda x: (), out=None):
    """ICFLocateICs (0x455730) over a sorted array: walking up, each unfolded element x absorbs
    every later unfolded element y with the same checksum that is identical to it
    (FICFIdenticalCONs). FFoldCONsEx folds the pair's differing dependencies the same way first:
    the target of x keeps, the target of y at the same relocation folds into it, recursively. So a
    survivor is the lowest sorted member of its group unless a caller's fold chose it earlier.
    `identical(x, y)` stands for the byte/relocation comparison, `deps(x)` lists x's relocation
    targets in order. `out` ({folded: survivor}) carries folds across groups; returned."""
    out = {} if out is None else out

    def rep(x):
        while x in out:
            x = out[x]
        return x

    active = set()

    def fold(x, y):
        # A pair already being folded further up (a cycle of calls or vtable slots) is not
        # entered again.
        active.add((x, y))
        for tx, ty in zip(deps(x), deps(y)):
            tx, ty = rep(tx), rep(ty)
            if tx != ty and tx in keys and ty in keys and (tx, ty) not in active and identical(tx, ty):
                fold(tx, ty)
        active.discard((x, y))
        out[y] = x

    for i, x in enumerate(order):
        if x in out:
            continue
        for y in order[i + 1:]:
            if keys[y][5] != keys[x][5] and keys[x][5]:
                break
            if y not in out and y != x and x not in out and identical(x, y):
                fold(x, y)
    return out


def icf_trace(objs, flags, out, toolchain="sp1", output_name="trace.exe", crc=False):
    """Link under the debugger; return the recorded ICF sorts and folds, joined to the objects."""
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    bindir, env = toolchain_env(toolchain)
    import hashlib
    if hashlib.sha256((bindir / "link.exe").read_bytes()).hexdigest() != LINK_SHA256:
        raise LinkTraceError("icf-trace breakpoints are for link.exe 8.00.50727.762 (sha256 %s)" % LINK_SHA256)
    image = out / output_name
    command = [str(bindir / "link.exe"), "/NOLOGO", "/VERBOSE", "/MAP:" + str(out / "trace.map"),
               "/OUT:" + str(image), *flags, *[str(Path(o).resolve()) for o in objs]]
    rec = IcfRecorder(crc)
    code, log = LinkDebugger(rec.breaks(), rec).run(command, env, out)
    (out / "verbose.txt").write_text(log, encoding="utf-8")
    if code:
        raise LinkTraceError("link failed (%d): %s" % (code, log[-2000:]))
    parsed = {_origin_key(o): parse_obj(Path(o).read_bytes(), str(Path(o).resolve())) for o in objs if not _is_lib(o)}
    cons = sorted(rec.cons.values(), key=lambda c: c["id"])
    for c in cons:
        obj = parsed.get(_origin_key(c["obj"] or "")) if not c["lib"] else None
        c["symbol"] = None
        if c["lib"] and c["con_index"] is not None:
            obj = _lib_member_obj(c["lib"], c["obj"])
        if obj and c["con_index"] is not None and c["con_index"] < len(obj["sections"]):
            sec = obj["sections"][c["con_index"]]
            c["section_index"] = sec["index"]
            c["symbol"] = comdat_symbol(sec)
    res = {"command": command, "cons": cons, "sorts": rec.sorts, "folds": rec.folds,
           "verbose": parse_verbose(log), "loads": parse_loads(log)}
    if crc:
        res["crc_log"] = rec.crc_log
    return res


# ---------------------------------------------------------------- ICF survivor model

REL_CODE = {v: k for k, v in REL_I386.items()}


def _sig(data, sig):
    """mspdb80 SigForPbCb(pb, cb, sig): reflected CRC-32 update, no final complement."""
    import zlib
    return zlib.crc32(data, sig ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


def icf_candidates(objs, live=None):
    """The objects' ICF candidates in ICFAddPCON order, per output group (full section name).

    FIncludeComdat appends each COMDAT it includes: objects in command-line order, each in
    section-table order; a same-name `any` COMDAT only from its first definer, an associative
    one with its parent. Writable and debug sections are not candidates. Library members follow
    the objects (not parsed here). `live` = set of (path, symbol) kept by /OPT:REF."""
    rows, chosen, seen = [], set(), set()
    for oi, obj in enumerate(objs):
        for sec in obj["sections"]:
            if not sec["comdat"] or sec["size"] == 0 or sec["name"].startswith(".debug") \
                    or sec["characteristics"] & (SCN_LNK_REMOVE | SCN_LNK_INFO):
                continue
            sym = comdat_symbol(sec)
            if sec["associated"]:
                if (oi, sec["associated"]) not in chosen:
                    continue
                parent = comdat_symbol(obj["sections"][sec["associated"] - 1])
            else:
                parent = sym
                if sec["selection"] != "nodup":
                    if sym in seen:
                        continue
                    seen.add(sym)
            chosen.add((oi, sec["index"]))
            if sec["characteristics"] & SCN_MEM_WRITE:
                continue
            rows.append({"obj_index": oi, "obj": obj["path"], "section_index": sec["index"], "section": sec["name"],
                         "symbol": sym, "group": sec["name"],
                         "live": live is None or (obj["path"], parent) in live})
    return rows


class _ObjNames(dict):
    """Object lookup by origin: the full path when every traced object's path is one of this
    order's objects (and no two share one), else the file name (refused when two share one)."""

    def __init__(self, objs, traced=()):
        full = [os.path.normcase(os.path.abspath(o["path"])) for o in objs]
        self.by_path = len(set(full)) == len(full) and all(
            os.path.normcase(os.path.abspath(p)) in full for p in traced)
        if not self.by_path:
            base = [_origin_key(o["path"]) for o in objs]
            if len(set(base)) != len(base):
                raise LinkTraceError("two objects share a file name and the trace's paths are not theirs: "
                                     "objects are matched by name")
        super().__init__((self.key(o["path"]), i) for i, o in enumerate(objs))

    def key(self, path):
        return os.path.normcase(os.path.abspath(path)) if self.by_path else _origin_key(path)

    def find(self, path):
        return self.get(self.key(path)) if path else None


def library_modules(objs, trace, command=None):
    """Each traced library member's module number in this link: {traced module: new module}, from
    `simulate_command` on the trace's command line (checked against its `Loaded` sequence) and on
    this link's `command` (default: the traced line with its object slots taking these objects in
    order). Members are matched by library and archive offset. None when the simulation does not
    reproduce the trace."""
    events = trace.get("loads") or []
    try:
        sim_t = simulate_command(trace["command"], events)
        if [e["symbol"] for e in sim_t["events"]] != [e["symbol"] for e in events if e["loaded"]]:
            return None
        inputs = None
        if command is None:
            it = iter(o["path"] for o in objs)
            inputs = [("obj", next(it)) if k == "obj" else (k, a) for k, a in link_inputs(trace["command"])[0]]
        sim_o = simulate_command(command or trace["command"], events, inputs)
    except (LinkTraceError, OSError, StopIteration, ValueError, KeyError):
        return None
    where = {(_lib_key(e["lib"] or ""), e["offset"]): e["module"] for e in sim_o["events"]}
    return {e["module"]: where.get((_lib_key(e["lib"] or ""), e["offset"])) for e in sim_t["events"]}


def _trace_view(objs, trace, command=None):
    """What a trace of the same inputs (any object order) says about the contributions the objects
    cannot describe: the library members' contributions (their ICF edges, candidacy and keys), the
    edges from the objects to them or to imports, by symbol name, and each traced module's number
    in this object order (objects by path or name, library members by `library_modules`, else by
    the older `library_pulls` reordering)."""
    view = {"cons": {}, "ext": {}, "module": {}, "cand": set(), "keys": {}, "obj_of": {}, "section": {},
            "lib_def": {}}
    if not trace:
        return view
    cons = trace["cons"]
    # The externals each library member's contribution defines (the member parsed from its
    # library): a reference the objects make to one of them targets that contribution.
    for c in cons:
        if c["lib"] and c["con_index"] is not None:
            obj = _lib_member_obj(c["lib"], c["obj"])
            if obj and c["con_index"] < len(obj["sections"]):
                for s in obj["sections"][c["con_index"]]["symbols"]:
                    if s["external"]:
                        view["lib_def"].setdefault(s["name"], c["id"])
    tobjs = [a for k, a in link_inputs(trace["command"])[0] if k == "obj"]
    names = _ObjNames(objs, tobjs)
    nt = len(tobjs)
    events = trace.get("loads") or []
    tseq = [e["symbol"] for e in events if e["loaded"]]
    for m in range(1, nt + 1):
        i = names.find(tobjs[m - 1])
        view["module"][m] = (-1 if i is None else i) + 1
    lm = library_modules(objs, trace, command) if events else None
    view["library_search"] = "simulated" if lm is not None else "reordered"
    if lm is not None:
        for m in range(nt + 1, nt + 1 + len(tseq)):
            view["module"][m] = lm.get(m) or m
    else:
        newpos = {sym: i for i, sym in enumerate(library_pulls(objs, events))} if events else {}
        for m, sym in enumerate(tseq, nt + 1):
            view["module"][m] = len(objs) + 1 + newpos[sym] if sym in newpos else m
    for s in trace["sorts"]:
        if s["iteration"]:
            continue
        for i, k in zip(s["input"], s["keys"]):
            view["cand"].add(i)
            view["keys"][i] = k
    for c in cons:
        view["cons"][c["id"]] = c
        for e in c.get("edges") or ():
            if "con" in e and "section" in e:
                view["section"].setdefault(e["con"], e["section"])
        if not c["lib"] and c["con_index"] is not None and names.find(c["obj"]) is not None:
            view["obj_of"][c["id"]] = (names.find(c["obj"]), c["con_index"] + 1)
    for c in cons:
        sec_index = c.get("section_index")
        if c["lib"] or not c.get("edges") or not sec_index or names.find(c["obj"]) is None:
            continue
        obj = objs[names.find(c["obj"])]
        sec = obj["sections"][sec_index - 1]
        edges = [e for e in c["edges"] if e["flags"] != 0xFFFF]
        if len(sec["relocs"]) != len(edges):
            continue
        by_index = {x["index"]: x for x in obj["symbols"]}
        for rel, edge in zip(sec["relocs"], edges):
            t = by_index.get(rel["symbol_index"])
            if t and t["external"] and ("import" in edge or edge.get("library") or "other" in edge):
                view["ext"].setdefault(t["name"], edge)
    return view


def icf_static_keys(objs, rows, trace=None, log=None, graph=None, command=None):
    """ICFComparePcon keys of the objects' candidates (IcfRecorder.keys order) and, with a trace of
    the same inputs, of the library members' candidates: {node: key or None}. Object nodes are
    (obj_index, section_index), library nodes ("lib", trace con id). None: not modelled (a target
    neither the objects nor the trace describe). `log` ({node: [[site, hex]]}) receives what each
    node hashes, in the form of IcfRecorder's crc_log.

    Edge CRC (CrcEdges 0x4539F0, mspdb80 SigForPbCb): start 0xFFFFFFFF; for each ICF edge in order
    (an (offset 0, 0xFFFF) edge per associative child, then one per relocation: offset, type |
    storage class << 16 | 0x1000000 for a function | 0x4000000 for an import) hash the 8-byte edge,
    then for its target: an import's name; for a contribution that is not an ICF candidate its
    ICFId (module number, 1-based section; (-1, -1) for a module flagged 0x800 at +0xAC); nothing
    for an associative candidate (selection 5 with a parent: `__ehfuncinfo$`, `__ehhandler$`); for
    any other candidate its own edge CRC, or nothing and the cycle flag when it is on or reaches a
    reference cycle. 0 becomes 1. Module numbers: objects 1..N in command-line order, then the
    library members in load order (`library_pulls`)."""
    view = _trace_view(objs, trace, command)
    if graph is not None:
        graph["view"] = view
    defs = {}
    for oi, obj in enumerate(objs):
        for sec in obj["sections"]:
            for s in sec["symbols"]:
                if s["external"]:
                    defs.setdefault(s["name"], (oi, sec["index"]))
    cand = {(r["obj_index"], r["section_index"]): r for r in rows}
    chosen = {}
    for r in rows:
        if r["symbol"]:
            chosen.setdefault(r["symbol"], (r["obj_index"], r["section_index"]))
    children = icf_children(objs)
    tcons = view["cons"]

    def lib_node(cid):
        if cid in view["obj_of"]:
            return view["obj_of"][cid]
        return ("lib", cid) if cid in tcons else None

    def is_cand(n):
        return n in cand if n[0] != "lib" else n[1] in view["cand"]

    def is_assoc(n):
        if n[0] == "lib":
            raw = bytes.fromhex(tcons[n[1]]["con_raw"])
            return raw[0x34] == 5 and struct.unpack_from("<I", raw, 0x3C)[0] != 0
        sec = objs[n[0]]["sections"][n[1] - 1]
        return sec["selection"] == "associative" and bool(sec["associated"])

    def icfid(n):
        if n[0] != "lib":
            return struct.pack("<II", n[0] + 1, n[1])
        c = tcons[n[1]]
        if c["mod_ac"] >> 11 & 1:
            return struct.pack("<ii", -1, -1)
        section = c["con_index"] + 1 if c["con_index"] is not None else view["section"].get(n[1], 0)
        return struct.pack("<II", view["module"].get(c["module"], c["module"]), section)

    def traced_edge(head, e):
        if "import" in e:
            return head, ("import", e["import"])
        if "other" in e:
            return head, (("other",) if e["flags"] & 0x8000000 else None)
        return head, lib_node(e.get("con"))

    def edges_of(n):
        """[(edge bytes, target)]: target ("import", name), ("other",), a node, or None (unknown)."""
        if n[0] == "lib":
            return [traced_edge(struct.pack("<II", e["offset"], e["flags"]), e)
                    for e in tcons[n[1]].get("edges") or ()]
        out = []
        oi, si = n
        obj = objs[oi]
        sec = obj["sections"][si - 1]
        by_index = {x["index"]: x for x in obj["symbols"]}
        for child in children.get(n, ()):
            out.append((struct.pack("<II", 0, 0xFFFF), child))
        for rel in sec["relocs"]:
            t = by_index.get(rel["symbol_index"])
            if t is None:
                out.append((b"", None))
                continue
            d1 = REL_CODE.get(rel["type"], 0) | (t["storage"] << 16) | (0x1000000 if t["function"] else 0)
            target = None
            if t["external"] or t["storage"] == 105:  # 105: weak external (`??_E` to `??_G`)
                target = defs.get(t["name"])
                if target is None and t.get("weak_default"):
                    target = defs.get(t["weak_default"])
                if target is None and t["name"] in view["ext"]:
                    e = view["ext"][t["name"]]
                    # The traced edge gives the target's flags (storage class, function, import);
                    # the relocation type is this relocation's.
                    flags = (e["flags"] & 0xFFFF0000) | REL_CODE.get(rel["type"], 0)
                    head, tgt = traced_edge(struct.pack("<II", rel["offset"], flags), e)
                    if tgt and tgt[0] == "import" and t["name"] != tgt[1] and t["name"].startswith(tgt[1] or ""):
                        tgt = ("import", t["name"])  # a trace recorded before cstr read whole names
                    out.append((head, tgt))
                    continue
                if target is None and t["name"] in view["lib_def"]:
                    target = ("lib", view["lib_def"][t["name"]])
                    out.append((struct.pack("<II", rel["offset"], d1), target))
                    continue
            elif t["section"] > 0:
                target = (oi, t["section"])
            if target is not None:
                tsec = objs[target[0]]["sections"][target[1] - 1]
                if tsec["comdat"] and not tsec["associated"] and comdat_symbol(tsec) in chosen:
                    target = chosen[comdat_symbol(tsec)]
            out.append((struct.pack("<II", rel["offset"], d1), target))
        return out

    memo, active, cyc_edges = {}, set(), {}

    def crc(n):
        """CrcEdges: (CRC, cyclic) or None when an edge is not modelled; "active" while on the stack."""
        if n in memo:
            return memo[n]
        if n in active:
            return "active"
        active.add(n)
        s, cyclic, ok, chunks, loop = 0xFFFFFFFF, False, True, [], []

        def h(site, data):
            nonlocal s
            s = _sig(data, s)
            chunks.append([site, data.hex()])

        for head, target in edges_of(n):
            if target is None or not head:
                ok = False
                chunks.append(["unmodelled", head.hex()])
                break
            h("edge", head)
            if target[0] == "import":
                h("import", target[1].encode("latin-1"))
            elif target[0] == "other":
                pass
            elif not is_cand(target):
                h("icfid", icfid(target))
            elif is_assoc(target):
                pass
            else:
                sub = crc(target)
                if sub is None:
                    ok = False
                    chunks.append(["unmodelled target", repr(target)])
                    break
                loop.append(target)
                if sub == "active" or sub[1]:
                    cyclic = True
                else:
                    h("crc", struct.pack("<I", sub[0]))
        active.discard(n)
        memo[n] = ((s or 1), cyclic) if ok else None
        cyc_edges[n] = loop
        if log is not None:
            log[n] = chunks
        return memo[n]

    nodes = [(r["obj_index"], r["section_index"]) for r in rows]
    nodes += [("lib", i) for i in sorted(view["cand"]) if tcons[i]["lib"]]
    for n in nodes:
        crc(n)
    # CrcEdgesLoop (0x453C90), rounds 3, 2, 1 over the contributions on cycles: each starts from its
    # own value in one slot (node+4 in odd rounds, node+8 in round 2), hashes the values its cyclic
    # candidate targets hold in that slot and writes the other slot.
    done = {k: v for k, v in memo.items() if v and v != "active"}
    slot4 = {k: (v[0] if v[1] else 0) for k, v in done.items()}
    slot8 = {k: v[0] for k, v in done.items()}
    cyc = [k for k in done if done[k][1]]
    unknown = {k for k in cyc if any(memo.get(t) is None for t in cyc_edges.get(k, ()))}
    for rnd in (3, 2, 1):
        src, dst = (slot8, slot4) if not rnd & 1 else (slot4, slot8)
        new = {}
        for k in cyc:
            v = src[k]
            for t in cyc_edges[k]:
                if t in done and done[t][1]:
                    v = _sig(struct.pack("<I", src[t]), v)
            new[k] = v or 1
        dst.update(new)
    out = {}
    for n in nodes:
        v = memo.get(n)
        if not v or v == "active" or n in unknown:
            out[n] = None
            continue
        if n[0] == "lib":
            k = list(view["keys"][n[1]])
            k[1], k[4] = 1 if v[1] else 0, slot8[n]
            out[n] = k
            continue
        r = cand[n]
        sec = objs[n[0]]["sections"][n[1] - 1]
        out[n] = [1 if r["live"] else 0, 1 if v[1] else 0, len(sec["relocs"]), sec["size"], slot8[n],
                  sec["checksum"] or 0]
    if graph is not None:
        def group_key(n):
            """ICFCompareIcfGrp (0x453810) order of a contribution's output group: characteristics
            & 0x1E0 (code before data), then the group name (strcmp)."""
            if n[0] == "lib":
                c = tcons[n[1]]
                return (c["flags"] & 0x1E0, c["group"] or "")
            sec = objs[n[0]]["sections"][n[1] - 1]
            return (sec["characteristics"] & 0x1E0, sec["name"])

        graph.update({"group_key": group_key, "icfid": icfid, "is_cand": is_cand,
                      "targets": {n: [t for head, t in edges_of(n) if t is not None and t[0] not in ("import", "other")
                                      and not struct.unpack_from("<I", head, 4)[0] & 0x6000000]
                                  for n in nodes}})
    return out


def icf_classes(objs, rows):
    """Equivalence classes of FICFIdenticalCONs over the objects' candidates: same characteristics,
    bytes with relocated words masked, and ordered relocations (offset, type, addend) whose targets
    are the same section or candidates of one class (refined to a fixed point, as FSameDependency)."""
    defs = {}
    for oi, obj in enumerate(objs):
        for sec in obj["sections"]:
            for s in sec["symbols"]:
                if s["external"]:
                    defs.setdefault(s["name"], (oi, sec["index"]))
    chosen = {}
    for r in rows:
        chosen.setdefault(r["symbol"], (r["obj_index"], r["section_index"]))
    base = {}
    for r in rows:
        oi, si = r["obj_index"], r["section_index"]
        obj = objs[oi]
        sec = obj["sections"][si - 1]
        by_index = {x["index"]: x for x in obj["symbols"]}
        raw = bytearray(sec["raw"])
        targets = []
        for rel in sec["relocs"]:
            raw[rel["offset"]:rel["offset"] + 4] = bytes(4)
            t = by_index.get(rel["symbol_index"])
            if t and t["external"]:
                tgt = defs.get(t["name"]) or defs.get(t.get("weak_default")) or ("extern", t["name"])
            else:
                tgt = (oi, t["section"]) if t else None
            if isinstance(tgt[0], int):
                tsec = objs[tgt[0]]["sections"][tgt[1] - 1]
                if tsec["comdat"] and not tsec["associated"]:
                    tgt = chosen.get(comdat_symbol(tsec), tgt)
            targets.append((rel["offset"], rel["type"], rel.get("addend"), tgt))
        base[(oi, si)] = (r["group"], sec["characteristics"], bytes(raw), tuple(targets))
    cls = {k: 0 for k in base}
    while True:
        sig = {}
        for k, (grp, ch, raw, targets) in base.items():
            sig[k] = (grp, ch, raw, tuple((o, ty, a, ("c", cls[t]) if t in cls else t) for o, ty, a, t in targets))
        ids = {}
        new = {k: ids.setdefault(v, len(ids)) for k, v in sig.items()}
        if len(set(new.values())) == len(set(cls.values())):
            deps = {k: [t for _, _, _, t in v[3]] for k, v in base.items()}
            return new, deps
        cls = new


def icf_children(objs):
    """Associative children of each section (non-debug), in section order: link's ICF edges
    (0, 0xFFFF) that precede the relocation edges."""
    out = {}
    for oi, obj in enumerate(objs):
        for sec in obj["sections"]:
            if sec["associated"] and not sec["name"].startswith(".debug") and sec["size"]:
                out.setdefault((oi, sec["associated"]), []).append((oi, sec["index"]))
    return out


DEFAULT_ROOTS = ("_main", "_wmain", "_WinMain@16", "_wWinMain@16", "_DllMain@12")


def _ref_roots(objs, command=None):
    """The /OPT:REF roots: the usual entry points, the command line's and the objects' /INCLUDE
    symbols."""
    roots = list(DEFAULT_ROOTS)
    if command:
        roots += link_inputs(command)[2]
    for obj in objs:
        for sec in obj["sections"]:
            if sec["name"] == ".drectve":
                roots += [a for k, a in parse_directives(sec["raw"].decode("latin-1").rstrip("\0")) if k == "INCLUDE" and a]
    return roots


def icf_predict(objs, trace=None, ref=True, command=None):
    """Predict each ICF fold group's survivor for this object order.

    The candidate arrays are rebuilt in ICFAddPCON order (icf_candidates, then the library
    members' candidates of `trace` in their predicted load order), keyed by icf_static_keys over
    the objects and the trace's library contributions and edges (an icf-trace result of the same
    objects and libraries, any order); a key the model cannot compute falls back to the traced one
    (listed as unresolved for an object). Each group is sorted with ms_qsort/icf_compare and walked
    as ICFLocateICs does. Returns {"groups": [...], "unresolved": [...]}."""
    live = reachable(objs, _ref_roots(objs, command or (trace or {}).get("command")))
    rows = icf_candidates(objs, live)
    graph = {}
    keys = icf_static_keys(objs, rows, trace, graph=graph, command=command)
    view = graph.get("view") or _trace_view(objs, trace, command)
    cls, deps = icf_classes(objs, rows)
    traced, libs, lib_class = {}, {}, {}
    if trace:
        ref = bool(trace["sorts"][0]["flag_162"]) if trace["sorts"] else ref
        cons = trace["cons"]
        survivor_of = {f["fold"]: f["keep"] for f in trace["folds"]}
        for s in trace["sorts"]:
            if s["iteration"]:
                continue
            for i, k in zip(s["input"], s["keys"]):
                c = cons[i]
                if c["lib"]:
                    libs.setdefault(c["group"], []).append(("lib", i))
                    traced[("lib", i)] = k
                    root = i
                    while root in survivor_of:
                        root = survivor_of[root]
                    lib_class[("lib", i)] = ("lib", root)
                elif c["id"] in view["obj_of"]:
                    traced[view["obj_of"][c["id"]]] = k
    unresolved = []
    by_group = {}
    rowkey = {}
    for r in rows:
        k = (r["obj_index"], r["section_index"])
        rowkey[k] = r
        key = keys[k]
        if key is None:
            key = traced.get((r["obj_index"], r["section_index"]))
            if key is not None:
                key = [1 if r["live"] else 0] + key[1:]
        if keys[k] is None:
            unresolved.append({"obj": r["obj"], "symbol": r["symbol"], "section": r["section"]})
        if key is None:
            continue
        keys[k] = key
        by_group.setdefault(r["group"], []).append(k)
    for g, members in libs.items():
        c = trace["cons"]
        members = sorted(members, key=lambda m: (view["module"].get(c[m[1]]["module"], c[m[1]]["module"]),
                                                 c[m[1]]["con_index"] or 0))
        by_group.setdefault(g, []).extend(members)
        for m in members:
            if keys.get(m) is None:
                keys[m] = traced[m]
    klass = dict(cls)
    klass.update(lib_class)
    # An object's COMDAT identical to a library member's: the trace folded them into one survivor
    # (identity does not depend on the order), so the member's class takes the object's.
    if trace:
        alias = {}
        for f in trace["folds"]:
            for a, b in ((f["keep"], f["fold"]), (f["fold"], f["keep"])):
                node = view["obj_of"].get(a)
                if node in cls and ("lib", b) in lib_class:
                    alias[lib_class[("lib", b)]] = cls[node]
        for n, root in lib_class.items():
            if root in alias:
                klass[n] = alias[root]
    groups, folds, sorted_arrays = [], {}, {}
    # ICFAnalysis walks the groups in g_rgICFGrp order (ICFCompareIcfGrp: code before data, then by
    # name). A dependency in a later group can be folded from an earlier one. Before sorting every
    # group but the first, it remixes each member's edge CRC (0x453E30): for each edge, in order,
    # to a candidate of an earlier group, the ICFId of that target's survivor so far.
    gk = graph["group_key"]

    def rep(x):
        while x in folds:
            x = folds[x]
        return x

    for gi, g in enumerate(sorted(by_group, key=lambda g: gk(by_group[g][0]))):
        if gi:
            for x in by_group[g]:
                if x not in graph["targets"]:
                    continue
                v = keys[x][4]
                for t in graph["targets"][x]:
                    r = rep(t)
                    if graph["is_cand"](r) and gk(r) < gk(x):
                        v = _sig(graph["icfid"](r), v)
                keys[x] = keys[x][:4] + [v] + keys[x][5:]
        order = ms_qsort(by_group[g], lambda x, y: icf_compare(keys[x], keys[y], ref))
        sorted_arrays[g] = order
        # Under /OPT:REF a contribution /OPT:REF discards (key[0] == 0) is sorted but never folded:
        # two identical dead copies both stay unfolded (avp3 audio_effects: _sinf, ?sin@@YAMM@Z).
        icf_survivors(order, keys, lambda x, y: klass.get(x) == klass.get(y) and klass.get(x) is not None
                      and (not ref or (keys[x][0] and keys[y][0])),
                      lambda x: deps.get(x, ()), folds)
    for g, order in sorted_arrays.items():
        members = {}
        for f, s in folds.items():
            if s in order:
                while s in folds:
                    s = folds[s]
                members.setdefault(s, []).append(f)

        def label(k):
            if k[0] == "lib":
                c = trace["cons"][k[1]]
                return {"obj": c["obj"], "lib": c["lib"], "symbol": c.get("symbol"), "con_index": c["con_index"]}
            r = rowkey[k]
            return {"obj": r["obj"], "symbol": r["symbol"], "section_index": r["section_index"]}

        for s, fs in members.items():
            groups.append({"group": g, "survivor": label(s), "replaced": [label(f) for f in fs],
                           "sorted_positions": [order.index(x) if x in order else None for x in [s] + fs]})
    return {"groups": groups, "unresolved": unresolved, "ref": ref, "library_candidates": bool(libs),
            "keys": [[list(n), keys[n]] for g in sorted_arrays.values() for n in g]}


# ---------------------------------------------------------------- experiments

FLAGS = ["/O2", "/Oy", "/Gy", "/GS", "/EHsc", "/GR-", "/MD", "/fp:fast", "/arch:SSE2"]
FIXTURES = ROOT / "tests/fixtures/link_trace"


def _fixture(sub):
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted((FIXTURES / sub).glob("*.cpp"))]


def experiment(out, toolchain="sp1"):
    """Run the layout rule experiments and return their tables (rows of dicts)."""
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    # E1 ICF survivor: groups of identical functions spread over objects, every object order.
    srcs = _fixture("e1")
    edir = out / "e1"
    edir.mkdir(exist_ok=True)
    objs = compile_sources(srcs, edir, FLAGS, toolchain)
    by = {Path(o).stem: o for o in objs}
    rows = []
    for perm in itertools.permutations(["o0", "o1", "o2"]):
        order = [by["m"]] + [by[p] for p in perm]
        model = trace(order, ["/OPT:REF,ICF"], edir / ("link_" + "".join(p[1] for p in perm)), toolchain)
        for g in model["fold_groups"]:
            rows.append({"order": " ".join(perm), "survivor": g["survivor"], "origin": Path(g["survivor_origin"]).stem,
                         "members": [m["symbol"] for m in g["members"]]})
        rows.append({"order": " ".join(perm), "order_check": model.get("order_check"),
                     "import_check": model.get("import_check")})
    results["icf"] = rows
    results.update(_experiment_layout(out, toolchain))
    return results


E2_NOGY = """
int ng_one(int x) { return x + 11; }
int ng_unused(int x) { return x + 12; }
int ng_two(int x) { return x + 13; }
"""


def _experiment_layout(out, toolchain):
    edir = out / "e2"
    edir.mkdir(exist_ok=True)
    objs = compile_sources(_fixture("e2"), edir, FLAGS, toolchain)
    nogy = compile_sources([("ng.cpp", E2_NOGY + "int ng_main(int x) { return ng_one(x) + ng_two(x); }\n")],
                           edir, [f for f in FLAGS if f != "/Gy"] + ["/Gy-"], toolchain)
    a, b, m = objs
    res = {}
    for label, order in (("m a b", [m, a, b]), ("m b a", [m, b, a]), ("b a m", [b, a, m])):
        model = trace(order, ["/OPT:REF,ICF"], edir / ("link_" + label.replace(" ", "")), toolchain)
        res.setdefault("layout", []).append({"order": label, "order_check": model.get("order_check"),
            "import_check": model.get("import_check"),
            "contributions": [{k: c[k] for k in ("obj", "section", "symbol", "status", "rva", "size", "align",
                                                 "padding_before", "padding_bytes", "selection")}
                              for c in model["contributions"]],
            "groups": [g for g in model["map_groups"]]})
    model = trace([m, a, b], ["/OPT:REF,NOICF"], edir / "link_noicf", toolchain)
    res["noicf_folds"] = len([g for g in model["fold_groups"]])
    # Without /Gy the object's code is one section: kept or dropped whole.
    drv = compile_sources([("d.cpp", "int ng_main(int);\nint main(int c, char**) { return ng_main(c); }\n")],
                          edir, FLAGS, toolchain)
    model = trace([drv[0], nogy[0]], ["/OPT:REF,ICF"], edir / "link_nogy", toolchain)
    res["nogy_checks"] = {"order_check": model.get("order_check"), "import_check": model.get("import_check")}
    res["nogy"] = [{k: c[k] for k in ("section", "symbol", "status", "size", "comdat")} for c in model["contributions"]]
    res["nogy_publics"] = [p["symbol"] for p in model["publics"] if p["symbol"].startswith("?ng_")]
    return res


# The ICF survivor experiments: fixture sources and the object orders traced (docs/link-trace.md).
ICF_SETS = {
    "E1": ("e1", ["m o0 o1 o2", "m o0 o2 o1", "m o1 o0 o2", "m o1 o2 o0", "m o2 o0 o1", "m o2 o1 o0",
                  "o0 o1 o2 m", "o1 m o2 o0"]),
    "E2": ("e2", ["m a b", "m b a", "b a m"]),
    "E4": ("e4", ["c m", "m c"]),
    # Library search: five static libraries built from `l?_*.cpp` (la, lb, lc on the command line;
    # ld and le default libraries named by #pragma comment(lib) in lc's members) with references
    # that need several passes, the real msvcrt.lib (/MD) and OLDNAMES, /NODEFAULTLIB and
    # /DEFAULTLIB on the command line, and libraries placed before and between the objects.
    "L1": ("l1", ["m n la.lib lb.lib lc.lib", "n m la.lib lb.lib lc.lib", "m n lc.lib lb.lib la.lib",
                  "lb.lib m la.lib n lc.lib", "m n la.lib lb.lib lc.lib /DEFAULTLIB:le",
                  "m n la.lib lb.lib lc.lib /NODEFAULTLIB:OLDNAMES",
                  "m n la.lib lb.lib lc.lib ld.lib /NODEFAULTLIB:ld"]),
    # The linker's own references: /EXPORT on the command line and in two objects' directives
    # (the .exp round, name order), /ALTERNATENAME with its source left undefined (the defaults'
    # round) or defined by a library, the entry point of an exe and of a /DLL.
    "L2": ("l2", ["m n lx.lib /EXPORT:exp_zcmd", "n m lx.lib /EXPORT:exp_zcmd", "n lx.lib /DLL"]),
}


def _con_label(c):
    """A contribution's name across traces and predictions: its COMDAT symbol, else (a static
    one, an unnamed section) member or object file name and section number."""
    if c.get("symbol"):
        return c["symbol"]
    index = c.get("section_index") or (c["con_index"] + 1 if c.get("con_index") is not None else None)
    return "%s#%s" % (Path(c.get("obj") or "").name.casefold(), index)


def _traced_fold_sets(trace):
    """The fold groups of a trace from its ICFFold calls (every fold, the associative children's
    included, which /VERBOSE names only by section): {frozenset(labels): survivor label}."""
    cons = trace["cons"]
    keep = {f["fold"]: f["keep"] for f in trace["folds"]}

    def root(x):
        while x in keep:
            x = keep[x]
        return x

    groups = {}
    for f in keep:
        groups.setdefault(root(f), []).append(f)
    return {frozenset([_con_label(cons[s])] + [_con_label(cons[x]) for x in fs]): _con_label(cons[s])
            for s, fs in groups.items()}


def _fold_sets(groups, survivor, members):
    out = {}
    for g in groups:
        s = survivor(g)
        if s is None:
            continue
        out[frozenset([s] + members(g))] = s
    return out


def icf_experiment(name, out, toolchain="sp1", log=print):
    """Compile one ICF fixture set, icf-trace every listed object order and cross-predict: the
    trace of order T predicts the survivors of order O, compared with O's /VERBOSE. Returns rows."""
    sub, orders = ICF_SETS[name]
    edir = Path(out).resolve() / sub
    edir.mkdir(parents=True, exist_ok=True)
    srcs = _fixture(sub)
    objs = {Path(o).stem: o for o in compile_sources(srcs, edir, FLAGS, toolchain)}
    members = {}
    for stem in sorted(objs):
        m = re.match(r"^(l[a-z])_", stem)
        if m:
            members.setdefault(m.group(1), []).append(objs.pop(stem))
    for lib, mobjs in members.items():
        objs[lib + ".lib"] = make_lib(mobjs, edir / (lib + ".lib"), toolchain)
    runs = {}
    for order in orders:
        tag = re.sub(r"[^A-Za-z0-9]+", "", order.replace(".lib", "").replace("NODEFAULTLIB", "N").replace("DEFAULTLIB", "D"))
        paths = [objs[x] for x in order.split() if not x.startswith("/")]
        flags = ["/OPT:REF,ICF"] + (["/LIBPATH:" + str(edir)] if members else []) + \
            [x for x in order.split() if x.startswith("/")]
        if any(x.endswith("/NODEFAULTLIB:ld") for x in flags):
            flags.append("/FORCE:UNRESOLVED")
        runs[order] = _traced_run(name, order, paths, flags, edir / ("t_" + tag), toolchain, log, crc=True)
    return icf_crosscheck(name, runs)


def _traced_run(name, order, paths, flags, out, toolchain, log, crc=False):
    res = icf_trace(paths, flags, out, toolchain, crc=crc)
    (Path(out) / "icf.json").write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    parsed = [parse_obj(Path(p).read_bytes(), str(Path(p).resolve())) for p in paths if not _is_lib(p)]
    replay = sum(icf_replay(srt, srt["flag_162"]) == srt["output"] for srt in res["sorts"])
    verbose = (Path(out) / "verbose.txt").read_text(errors="replace")
    check = search_check(res["command"], verbose)
    check.pop("simulation")
    image = Path(out) / "trace.exe"  # icf_trace's output name, a DLL's included
    if image.is_file() and (Path(out) / "trace.map").is_file():
        lm = layout_model(parsed, verbose, (Path(out) / "trace.map").read_text(errors="replace"),
                          image.read_bytes(), res["command"], res)
        check["layout"] = all(lm.get(k, {"predicted_equals_actual": True})["predicted_equals_actual"]
                              for k in ("order_check", "import_check"))
        check["layout_detail"] = {k: lm.get(k) for k in ("order_check", "import_check")}
    log("%s %s: library search %d/%d loads, %d searches %s; ICF iterations %s" % (
        name, order, check["loads"] if check["loads_equal"] else check["first_difference"] or 0, check["loads"],
        check["searches"], "equal" if check["searches_equal"] else "DIFFERENT",
        sorted({s["iteration"] for s in res["sorts"]})))
    return res, parsed, replay, check


def icf_crosscheck(name, runs):
    """Cross-predict traced runs ({label: _traced_run result}): the trace of T predicts the fold
    groups and survivors of O (command line, objects), compared with O's /VERBOSE. Returns rows."""
    rows = []
    for o_name, (o_trace, o_objs, replay, o_check) in runs.items():
        names = _ObjNames(o_objs, [c["obj"] for c in o_trace["cons"] if not c["lib"] and c["obj"]])
        o_keys = {}
        for srt in o_trace["sorts"]:
            for i, k in zip(srt["input"], srt["keys"]):
                c = o_trace["cons"][i]
                if not srt["iteration"] and not c["lib"] and names.find(c["obj"]) is not None:
                    o_keys[(names.find(c["obj"]), c["con_index"] + 1)] = k
        truth = _traced_fold_sets(o_trace)
        o_members = sorted(e["loaded"] for e in o_trace["loads"] if e["loaded"])
        for t_name, (t_trace, _, _, _) in runs.items():
            if sorted(e["loaded"] for e in t_trace["loads"] if e["loaded"]) != o_members:
                continue  # another set of library members: not a trace of the same inputs
            pred = icf_predict(o_objs, t_trace, command=o_trace["command"])
            got = _fold_sets(pred["groups"], lambda g: _con_label(g["survivor"]),
                             lambda g: [_con_label(x) for x in g["replaced"]])
            wrong = [{"members": sorted(k), "truth": truth.get(k), "predicted": got.get(k)}
                     for k in set(truth) | set(got) if truth.get(k) != got.get(k)]
            rows.append({"set": name, "order": o_name, "trace": t_name, "groups": len(truth),
                         "ok": not wrong and o_check["loads_equal"] and o_check["searches_equal"]
                               and o_check.get("seeds_equal", True) and o_check.get("layout", True),
                         "layout": {True: "ok", False: "MISS", None: "-"}[o_check.get("layout")],
                         "search": "%s/%s" % (o_check["loads"] if o_check["loads_equal"] else "x", o_check["loads"]),
                         "unresolved": len(pred["unresolved"]), "wrong": wrong,
                         "keys": "%d/%d" % (sum(o_keys.get(tuple(n)) == k for n, k in pred["keys"] if n[0] != "lib"),
                                            len(o_keys)),
                         "qsort": "%d/%d" % (replay, len(o_trace["sorts"])),
                         "iterations": len({s["iteration"] for s in o_trace["sorts"]})})
    return rows


def crosscheck(objs, flags, out, orders=("given", "reversed"), toolchain="sp1", log=print):
    """icf-trace one link's objects in several orders (given, reversed, rotated: the objects
    only, libraries keep their slots) and cross-predict them (`icf_crosscheck`)."""
    objs = [str(Path(o).resolve()) for o in objs]
    slots = [i for i, o in enumerate(objs) if not _is_lib(o)]
    only = [objs[i] for i in slots]
    perms = {"given": only, "reversed": only[::-1], "rotated": only[1:] + only[:1]}
    runs = {}
    for label in orders:
        line = list(objs)
        for i, o in zip(slots, perms[label]):
            line[i] = o
        runs[label] = _traced_run("link", label, line, flags, Path(out) / label, toolchain, log)
    return icf_crosscheck("link", runs)


# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--obj", nargs="+", required=True)
    r.add_argument("--flags", default="/OPT:REF,ICF")
    r.add_argument("--out", required=True)
    r.add_argument("--toolchain", default="sp1")
    r.add_argument("--output-name", default="trace.exe")
    e = sub.add_parser("explain")
    e.add_argument("--model", required=True)
    g = e.add_mutually_exclusive_group(required=True)
    g.add_argument("--rva")
    g.add_argument("--symbol")
    o = sub.add_parser("order")
    o.add_argument("--obj", nargs="+", required=True)
    o.add_argument("--model")
    o.add_argument("--root", action="append")
    o.add_argument("--json", action="store_true")
    o.add_argument("--icf-trace", help="icf.json of an icf-trace run (same objects and libraries, any order): "
                   "predict each ICF fold group's survivor")
    o.add_argument("--flags", help="with --icf-trace: this link's options (libraries may be given in --obj); "
                   "default: the traced command line with its object slots taking --obj in order")
    t = sub.add_parser("icf-trace")
    t.add_argument("--obj", nargs="+", required=True)
    t.add_argument("--flags", default="/OPT:REF,ICF")
    t.add_argument("--out", required=True)
    t.add_argument("--toolchain", default="sp1")
    t.add_argument("--crc", action="store_true", help="also log every SigForPbCb input of CrcEdges and "
                   "CrcEdgesLoop (icf.json crc_log)")
    st = sub.add_parser("search-trace")
    st.add_argument("--obj", nargs="+", required=True, help="objects and libraries, in command-line order")
    st.add_argument("--flags", default="/OPT:REF,ICF")
    st.add_argument("--out", required=True)
    st.add_argument("--toolchain", default="sp1")
    cc = sub.add_parser("crosscheck")
    cc.add_argument("--obj", nargs="+", required=True, help="objects and libraries, in command-line order")
    cc.add_argument("--flags", default="/OPT:REF,ICF")
    cc.add_argument("--out", required=True)
    cc.add_argument("--orders", default="given,reversed", help="comma-separated: given, reversed, rotated")
    cc.add_argument("--toolchain", default="sp1")
    cc.add_argument("--json", action="store_true")
    sc = sub.add_parser("search-check")
    sc.add_argument("--model", required=True, help="model.json of `run` or icf.json of `icf-trace`; its "
                    "verbose.txt is read from the same folder")
    x = sub.add_parser("experiment")
    x.add_argument("--set", default="all", choices=["E1", "E2", "E4", "L1", "L2", "layout", "all"],
                   help="E1/E2/E4/L1/L2: ICF survivor cross-prediction tables, with the library search and the layout "
                        "(code order and padding, imports) checked against /VERBOSE and the image; layout: the layout "
                        "rule tables (JSON)")
    x.add_argument("--json", action="store_true")
    x.add_argument("--out", required=True)
    x.add_argument("--toolchain", default="sp1")
    args = ap.parse_args(argv)
    if args.cmd == "run":
        model = trace(args.obj, shlex.split(args.flags, posix=False), args.out, args.toolchain, args.output_name)
        path = Path(args.out) / "model.json"
        path.write_text(json.dumps(model, indent=1) + "\n", encoding="utf-8")
        counts = {}
        for c in model["contributions"]:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        print("model: %s" % path)
        print("contributions: " + ", ".join("%s %d" % kv for kv in sorted(counts.items())))
        print("fold groups: %d, ICF savings %s bytes" % (len(model["fold_groups"]), model["icf_savings"]))
        if "order_check" in model:
            print("order rule check: %s" % ("predicted == actual" if model["order_check"]["predicted_equals_actual"]
                                            else "MISMATCH (see model.json order_check)"))
        if "import_check" in model:
            ic = model["import_check"]
            print("import layout check: %s (%d DLLs, %d entries, %d removed by /OPT:REF)"
                  % ("predicted == actual" if ic["predicted_equals_actual"] else "MISMATCH (see model.json import_check)",
                     ic["dlls"], ic["entries"], ic["removed"]))
        return 0
    if args.cmd == "explain":
        model = json.loads(Path(args.model).read_text(encoding="utf-8"))
        for line in explain(model, int(args.rva, 0) if args.rva else None, args.symbol):
            print(line)
        return 0
    if args.cmd == "icf-trace":
        res = icf_trace(args.obj, shlex.split(args.flags, posix=False), args.out, args.toolchain, crc=args.crc)
        path = Path(args.out) / "icf.json"
        path.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
        cons = res["cons"]
        for srt in res["sorts"]:
            same = icf_replay(srt, srt["flag_162"]) == srt["output"]
            print("sort: iteration %d group %d (%s), %d candidates, qsort model %s" % (
                srt["iteration"], srt["group"], cons[srt["input"][0]]["group"] if srt["input"] else "-",
                len(srt["input"]), "== traced" if same else "MISMATCH"))
        for f in res["folds"]:
            k, x = cons[f["keep"]], cons[f["fold"]]
            print("fold: %s (%s) <- %s (%s)" % (k.get("symbol") or "#%s" % k["con_index"], Path(k["obj"] or "").name,
                                               x.get("symbol") or "#%s" % x["con_index"], Path(x["obj"] or "").name))
        print("trace: %s" % path)
        return 0
    if args.cmd == "order":
        objs = [parse_obj(Path(p).read_bytes(), str(Path(p).resolve())) for p in args.obj if not _is_lib(p)]
        if args.icf_trace:
            command = None
            if args.flags is not None or any(_is_lib(p) for p in args.obj):
                command = ["link.exe", *shlex.split(args.flags or "", posix=False),
                           *[str(Path(p).resolve()) for p in args.obj]]
            pred = icf_predict(objs, json.loads(Path(args.icf_trace).read_text(encoding="utf-8")), command=command)
            if args.json:
                print(json.dumps(pred, indent=1))
                return 0
            for g in pred["groups"]:
                if g["survivor"].get("lib"):
                    continue
                print("%-9s survivor %s (%s)  replaces %s" % (g["group"], g["survivor"]["symbol"],
                      Path(g["survivor"]["obj"]).name, ", ".join("%s (%s)" % (m["symbol"], Path(m["obj"]).name)
                                                                  for m in g["replaced"])))
            for u in pred["unresolved"]:
                print("unresolved key (prediction not exact): %s %s %s" % (Path(u["obj"]).name, u["section"], u["symbol"]))
            return 0
        kept = folded = None
        if args.model:
            kept, folded = model_sets(json.loads(Path(args.model).read_text(encoding="utf-8")))
        rows = predict_order(objs, roots=args.root, kept=kept, folded=folded)
        if args.json:
            print(json.dumps(rows, indent=1))
        else:
            for r in rows:
                fold = ""
                if r["icf_candidates"] and not kept:
                    fold = "  [ICF candidates: %s]" % " ".join(x for x in r["icf_candidates"] if x != r["symbol"])
                print("+0x%05X  pad %2d  size 0x%04X  %-10s %s  %s%s" % (r["offset"], r["padding_before"], r["size"],
                      r["section"], Path(r["obj"]).name, r["symbol"], fold))
        return 0
    if args.cmd == "search-trace":
        res = search_trace(args.obj, shlex.split(args.flags, posix=False), args.out, args.toolchain)
        path = Path(args.out) / "search.json"
        path.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
        print("library search: %d Search calls, %d dictionary lookups (%d found); simulation %s" % (
            len(res["searches"]), res["lookups"], res["found"], "== traced" if res["equal"] else
            "DIFFERS from Search call %d" % res["first_difference"]))
        print("trace: %s" % path)
        return 0 if res["equal"] else 1
    if args.cmd == "crosscheck":
        rows = crosscheck(args.obj, shlex.split(args.flags, posix=False), args.out, args.orders.split(","),
                          args.toolchain)
        _print_rows(rows, args.json)
        return 0 if all(r["ok"] for r in rows) else 1
    if args.cmd == "search-check":
        model = json.loads(Path(args.model).read_text(encoding="utf-8"))
        res = search_check(model["command"], (Path(args.model).parent / "verbose.txt").read_text(errors="replace"))
        sim = res.pop("simulation")
        print("loads: %d traced, simulation %s" % (res["loads"], "== traced" if res["loads_equal"] else
              "differs at %s: traced %s, simulated %s" % (res["first_difference"], res["truth_at"], res["predicted_at"])))
        print("Search calls: %d traced, simulation %s" % (res["searches"], "== traced" if res["searches_equal"] else "DIFFERS"))
        print("unresolved after the search: %d" % len(sim["unresolved"]))
        return 0 if res["loads_equal"] and res["searches_equal"] else 1
    if args.cmd == "experiment":
        if args.set == "layout":
            print(json.dumps(experiment(args.out, args.toolchain), indent=1))
            return 0
        rows = []
        for name in (ICF_SETS if args.set == "all" else [args.set]):
            rows += icf_experiment(name, args.out, args.toolchain)
        _print_rows(rows, args.json)
        bad = [r for r in rows if not r["ok"]]
        return 1 if bad else 0
    return 1


def _print_rows(rows, as_json=False):
    if as_json:
        print(json.dumps(rows, indent=1))
        return
    print("%-4s %-12s %-12s %6s %5s %6s %6s %6s %10s  %s" % ("set", "order", "trace", "groups", "qsort", "keys",
                                                               "search", "layout", "unresolved", "survivors"))
    for r in rows:
        print("%-4s %-12s %-12s %6d %5s %6s %6s %6s %10d  %s" % (r["set"], r["order"], r["trace"], r["groups"],
              r["qsort"], r["keys"], r.get("search", "-"), r.get("layout", "-"), r["unresolved"],
              "OK" if r["ok"] else "MISS " + "; ".join(
                  "%s not %s" % (w["truth"], w["predicted"]) for w in r["wrong"])))
    for name in sorted({r["set"] for r in rows}):
        sel = [r for r in rows if r["set"] == name]
        print("%s: %d/%d cross-predictions exact" % (name, sum(r["ok"] for r in sel), len(sel)))


if __name__ == "__main__":
    sys.exit(main())
