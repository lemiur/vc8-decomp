"""Trace a VC8 link (link 8.00.50727.762) from input objects to the output image.

    python tools/link_trace.py run --obj a.obj b.obj --flags "/OPT:REF,ICF" --out DIR
    python tools/link_trace.py explain --model DIR/model.json --rva 0x1000
    python tools/link_trace.py explain --model DIR/model.json --symbol ?f@@YAHH@Z
    python tools/link_trace.py order --obj a.obj b.obj [--model DIR/model.json] [--root _main]
    python tools/link_trace.py order --obj a.obj b.obj --icf-trace DIR/icf.json   (ICF survivors)
    python tools/link_trace.py icf-trace --obj a.obj b.obj --flags "/OPT:REF,ICF" --out DIR
    python tools/link_trace.py experiment --out DIR      (the docs/link-trace.md rule tables)

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
            sym["weak_default_index"] = struct.unpack_from("<I", data, at + 18)[0]
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


def build_model(objs, verbose_text, map_text, image, command=None):
    """Join the objects, the verbose log, the map and the image into one model."""
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
            if sym and (sym, key) in folded:
                gid, surv = folded[(sym, key)]
                row.update(status="folded", fold_group=gid,
                           reason="/OPT:ICF: identical to %s from %s, which survives" % (surv["symbol"], surv["origin"]))
                hit = by_symbol.get(sym)
                if hit:
                    row["rva"] = hit[0]["va"] - base
            elif sym and (sym, key) in discarded:
                row.update(status="removed", reason="/OPT:REF: unreferenced COMDAT")
            elif sym and (sym, key) in placed:
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
            key = (obj["path"], sym if sec["comdat"] else "#%d" % sec["index"])
            if sec["associated"]:
                parent = obj["sections"][sec["associated"] - 1]
                key = (obj["path"], comdat_symbol(parent))
            if sec["comdat"] and (key not in kept or key in folded):
                continue
            if sec["comdat"] and sec["selection"] in ("any", "same_size", "exact", "largest"):
                if sym in seen_any:
                    continue
                seen_any.add(sym)
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
    for name in roots or ("_main", "_wmain", "_WinMain@16", "_wWinMain@16", "_DllMain@12"):
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


def trace(objs, flags, out, toolchain="sp1", output_name="trace.exe"):
    parsed = [parse_obj(Path(o).read_bytes(), str(Path(o).resolve())) for o in objs]
    command, verbose, mp, image = run_link(objs, flags, out, toolchain, output_name)
    model = build_model(parsed, verbose, mp, image, command)
    kept, folded = model_sets(model)
    text_rows = [c for c in model["contributions"] if c["status"] == "kept" and c["code"] and c["rva"] is not None]
    if text_rows:
        first = min(c["rva"] for c in text_rows)
        pred = predict_order(parsed, kept=kept, folded=folded)
        actual = sorted(text_rows, key=lambda c: c["rva"])
        p_order = [(r["obj"], r["symbol"]) for r in pred]
        a_order = [(c["obj"], c["symbol"]) for c in actual]
        model["order_check"] = {"predicted_equals_actual": p_order == a_order,
                                "first_rva": first, "predicted": len(p_order), "actual": len(a_order)}
    return model


# ---------------------------------------------------------------- ICF trace (debug API)

# link.exe 8.00.50727.762, preferred base 0x400000. Addresses from the public link.pdb and the
# disassembly of IMAGE::ICFAnalysis, ICFComparePcon, ICFLocateICs and ICFFold (docs/link-trace.md).
LINK_SHA256 = "16beda175e8e83f45187c0cd18eed06d0ec26a401d0bbc3544074c57eeebaff5"
LINK_BASE = 0x400000
BP_QSORT, BP_QSORT_RET, BP_FOLD = 0x4558E2, 0x4558E8, 0x4541C0
PIMAGE = 0x4B2B5C            # ICFCompareContext::pimage (IMAGE*)


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


class IcfRecorder:
    """Breakpoint handler: the candidate array at each ICFAnalysis qsort, its sorted order, the folds.

    CON (0x40 bytes, link's contribution): +4 flags (section characteristics; 0x4000 = folded),
    +8 size, +0x10 MOD*, +0x14 GRP*, +0x1C size adjustment, +0x20 COMDAT checksum, +0x28 ICF CRC,
    +0x3C fold target. MOD: +8 object name, +0x94 node array (20 bytes each), +0x98 LIB*,
    +0x9C CON array, +0xBC CON count. Node: +8 and +0x11 are comparator keys."""

    def __init__(self):
        self.sorts, self.folds, self.cons = [], [], {}
        self._pending = None

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
               "flags": word(4), "size": word(8), "size_adjust": word(0x1C), "checksum": word(0x20),
               "node_8": struct.unpack_from("<I", nraw, 8)[0], "node_11": nraw[0x11],
               "mod_ac": struct.unpack_from("<H", d.dbg.read(mod + 0xAC, 2))[0],
               "con_raw": raw.hex(), "node_raw": nraw.hex()}
        grp = word(0x14)
        rec["group"] = self.cstr(d, rd(grp)) if grp else None
        self.cons[pcon] = rec
        return rec["id"]

    @staticmethod
    def cstr(d, va, limit=128):
        try:
            data = d.dbg.read(va, min(limit, 0x1000 - (va & 0xFFF)))
        except OSError:
            return None
        return data.split(b"\0", 1)[0].decode("latin-1")

    def edges(self, d, pcon):
        """The CON's ICF edges (node+0: blocks of next, count, 12-byte edges: target, offset,
        flags|type); for a target outside the objects, what CrcEdges hashes: an import's name
        (flags 0x4000000, from the IMAGE+0x250 string table) or the ICFId (module, section)."""
        rd = d.dbg.read_u32
        mod = rd(pcon + 0x10)
        node = rd(mod + 0x94) + ((pcon - rd(mod + 0x9C)) >> 6) * 20
        blk, out = rd(node), []
        while blk:
            for e in range(min(rd(blk + 4), 4096)):
                t, off, flags = struct.unpack("<III", d.dbg.read(blk + 8 + 12 * e, 12))
                row = {"offset": off, "flags": flags}
                if flags & 0x4000000:
                    row["import"] = self.cstr(d, rd(rd(d.u32(PIMAGE) + 0x250)) + rd(t + 4))
                elif t:
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
        if va == BP_QSORT:
            base, num = rd(esp), rd(esp + 4)
            pcons = [rd(base + 4 * i) for i in range(num)]
            ids = [self.con(d, p) for p in pcons]
            for p in pcons:
                if not self.cons[p]["lib"] and "edges" not in self.cons[p]:
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

    def fold(x, y):
        for tx, ty in zip(deps(x), deps(y)):
            tx, ty = rep(tx), rep(ty)
            if tx != ty and tx in keys and ty in keys and identical(tx, ty):
                fold(tx, ty)
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


def icf_trace(objs, flags, out, toolchain="sp1", output_name="trace.exe"):
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
    rec = IcfRecorder()
    code, log = LinkDebugger((BP_QSORT, BP_QSORT_RET, BP_FOLD), rec).run(command, env, out)
    (out / "verbose.txt").write_text(log, encoding="utf-8")
    if code:
        raise LinkTraceError("link failed (%d): %s" % (code, log[-2000:]))
    parsed = {_origin_key(o): parse_obj(Path(o).read_bytes(), str(Path(o).resolve())) for o in objs}
    cons = sorted(rec.cons.values(), key=lambda c: c["id"])
    for c in cons:
        obj = parsed.get(_origin_key(c["obj"] or "")) if not c["lib"] else None
        c["symbol"] = None
        if obj and c["con_index"] is not None and c["con_index"] < len(obj["sections"]):
            sec = obj["sections"][c["con_index"]]
            c["section_index"] = sec["index"]
            c["symbol"] = comdat_symbol(sec)
    return {"command": command, "cons": cons, "sorts": rec.sorts, "folds": rec.folds,
            "verbose": parse_verbose(log)}


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


def icf_static_keys(objs, rows, externals=None):
    """ICFComparePcon keys computed from the objects (IcfRecorder.keys order), or None for a
    contribution on a reference cycle (CrcEdgesLoop, not modelled) or that references a symbol
    no traced object defines (an import or a library member: its edge hash needs link's view).

    Edge CRC (CrcEdges 0x4539F0): start 0xFFFFFFFF; per relocation, in table order, hash
    (offset, type | storage class << 16 | 0x1000000 for a function symbol), then for a target
    that is itself a candidate its edge CRC, for any other section its ICFId (module number =
    1-based object position, section number); 0 becomes 1."""
    externals = externals or {}
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
    memo, active, edges = {}, set(), {}
    children = icf_children(objs)
    assoc = lambda k: bool(objs[k[0]]["sections"][k[1] - 1]["associated"])

    def crc(key):
        """CrcEdges: (partial CRC, on/reaching a cycle) or None when a target is not modelled."""
        if key in memo:
            return memo[key]
        if key in active:
            return "active"
        active.add(key)
        oi, si = key
        obj = objs[oi]
        sec = obj["sections"][si - 1]
        by_index = {x["index"]: x for x in obj["symbols"]}
        s, cyclic, result, out_edges = 0xFFFFFFFF, False, True, []
        # The associative children come first, as edges (0, 0xFFFF) to each child section.
        for child in children.get(key, ()):
            s = _sig(struct.pack("<II", 0, 0xFFFF), s)
            if child in cand and not assoc(child):
                sub = crc(child)
                if sub is None:
                    result = None
                    break
                out_edges.append(child)
                if sub == "active" or sub[1]:
                    cyclic = True
                else:
                    s = _sig(struct.pack("<I", sub[0]), s)
            else:
                s = _sig(struct.pack("<II", child[0] + 1, child[1]), s)
        for rel in sec["relocs"] if result else ():
            t = by_index.get(rel["symbol_index"])
            if t is None:
                result = None
                break
            d1 = REL_CODE.get(rel["type"], 0) | (t["storage"] << 16) | (0x1000000 if t["function"] else 0)
            if t["external"]:
                target = defs.get(t["name"])
                if target is None and t.get("weak_default"):
                    target = defs.get(t["weak_default"])
            else:
                target = (oi, t["section"]) if t["section"] > 0 else None
            if target is None and t["name"] in externals:
                ext = externals[t["name"]]
                s = _sig(struct.pack("<II", rel["offset"], ext["flags"]), s)
                if "import" in ext:
                    s = _sig(ext["import"].encode("latin-1"), s)
                else:
                    s = _sig(struct.pack("<II", ext["module"], ext["section"]), s)
                continue
            s = _sig(struct.pack("<II", rel["offset"], d1), s)
            if target is None:
                result = None
                break
            tsec = objs[target[0]]["sections"][target[1] - 1]
            if tsec["comdat"] and comdat_symbol(tsec) in chosen and not tsec["associated"]:
                target = chosen[comdat_symbol(tsec)]
                tsec = objs[target[0]]["sections"][target[1] - 1]
            if assoc(target):
                continue  # CrcEdges skips an associative COMDAT (selection 5, parent at +0x3C)
            if target in cand:
                sub = crc(target)
                if sub is None:
                    result = None
                    break
                out_edges.append(target)
                if sub == "active" or sub[1]:
                    cyclic = True
                else:
                    s = _sig(struct.pack("<I", sub[0]), s)
            else:
                s = _sig(struct.pack("<II", target[0] + 1, target[1]), s)
        active.discard(key)
        memo[key] = ((s or 1), cyclic) if result else None
        edges[key] = out_edges
        return memo[key]

    for r in rows:
        crc((r["obj_index"], r["section_index"]))
    # CrcEdgesLoop (0x453C90), three rounds over the contributions on cycles: each starts from its
    # own value in one slot (node+4 or node+8), hashes the other-slot-free values of its cyclic
    # targets read from that slot, and writes the other slot; rounds 3 and 1 write node+8.
    slot4 = {k: (v[0] if v[1] else 0) for k, v in memo.items() if v}
    slot8 = {k: v[0] for k, v in memo.items() if v}
    cyc = [k for k, v in memo.items() if v and v[1]]
    if any(memo.get(t) is None for k in cyc for t in edges[k]):
        cyc = []
    for rnd in (3, 2, 1):
        src, dst = (slot8, slot4) if not rnd & 1 else (slot4, slot8)
        new = {}
        for k in cyc:
            v = src[k]
            for t in edges[k]:
                if memo[t][1]:
                    v = _sig(struct.pack("<I", src[t]), v)
            new[k] = v or 1
        dst.update(new)
    out = {}
    for r in rows:
        k = (r["obj_index"], r["section_index"])
        sec = objs[r["obj_index"]]["sections"][r["section_index"] - 1]
        v = memo.get(k)
        out[k] = None if v is None or (v[1] and k not in cyc) else             [1 if r["live"] else 0, 1 if v[1] else 0, len(sec["relocs"]), sec["size"], slot8[k], sec["checksum"] or 0]
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


def icf_externals(objs, trace):
    """From an icf-trace: what each object relocation to a symbol outside the objects hashes in
    the edge CRC (import name or library ICFId, with link's edge flags), by symbol name."""
    externals = {}
    for c in (trace or {}).get("cons", []):
        sec_index = c.get("section_index")
        path = next((o for o in objs if _origin_key(o["path"]) == _origin_key(c["obj"] or "")), None)
        if c["lib"] or not c.get("edges") or path is None or not sec_index:
            continue
        sec = path["sections"][sec_index - 1]
        edges = [e for e in c["edges"] if e["flags"] != 0xFFFF]
        if len(sec["relocs"]) != len(edges):
            continue
        by_index = {x["index"]: x for x in path["symbols"]}
        for rel, edge in zip(sec["relocs"], edges):
            t = by_index.get(rel["symbol_index"])
            if t and t["external"] and ("import" in edge or edge.get("library")):
                externals.setdefault(t["name"], edge)
    return externals


def icf_predict(objs, trace=None, ref=True):
    """Predict each ICF fold group's survivor for this object order.

    The candidate arrays are rebuilt in ICFAddPCON order (icf_candidates), keyed with the static
    keys; a contribution the static model cannot key (a reference cycle, an import thunk or a
    library member) and the library members' own candidates come from `trace` (an icf-trace result
    of the same objects and libraries, any order). Each group is sorted with ms_qsort/icf_compare
    and walked as ICFLocateICs does. Returns {"groups": [...], "unresolved": [...]}."""
    live = reachable(objs)
    rows = icf_candidates(objs, live)
    externals = icf_externals(objs, trace)
    keys = icf_static_keys(objs, rows, externals)
    cls, deps = icf_classes(objs, rows)
    names = [_origin_key(o["path"]) for o in objs]
    traced, libs, lib_class, group_rank = {}, {}, {}, {}
    if trace:
        ref = bool(trace["sorts"][0]["flag_162"]) if trace["sorts"] else ref
        cons = trace["cons"]
        survivor_of = {f["fold"]: f["keep"] for f in trace["folds"]}
        for s in trace["sorts"]:
            if s["iteration"]:
                continue
            for i, k in zip(s["input"], s["keys"]):
                c = cons[i]
                group_rank.setdefault(c["group"], s["group"])
                if c["lib"]:
                    libs.setdefault(c["group"], []).append(("lib", i))
                    traced[("lib", i)] = k
                    root = i
                    while root in survivor_of:
                        root = survivor_of[root]
                    lib_class[("lib", i)] = ("lib", root)
                else:
                    traced[(_origin_key(c["obj"]), c["con_index"] + 1)] = k
    unresolved = []
    by_group = {}
    rowkey = {}
    for r in rows:
        k = (r["obj_index"], r["section_index"])
        rowkey[k] = r
        key = keys[k]
        if key is None:
            key = traced.get((names[r["obj_index"]], r["section_index"]))
            if key is not None:
                key = [1 if r["live"] else 0] + key[1:]
        if key is None:
            unresolved.append({"obj": r["obj"], "symbol": r["symbol"], "section": r["section"]})
            continue
        keys[k] = key
        by_group.setdefault(r["group"], []).append(k)
    for g, members in libs.items():
        by_group.setdefault(g, []).extend(members)
        for m in members:
            keys[m] = traced[m]
    klass = dict(cls)
    klass.update(lib_class)
    groups, folds, sorted_arrays = [], {}, {}
    # ICFAnalysis walks the groups in g_rgICFGrp order (sorted by ICFCompareIcfGrp): taken from the
    # trace; without one, by name. A dependency in a later group can be folded from an earlier one.
    for g in sorted(by_group, key=lambda g: (group_rank.get(g, 1 << 30), g)):
        order = ms_qsort(by_group[g], lambda x, y: icf_compare(keys[x], keys[y], ref))
        sorted_arrays[g] = order
        icf_survivors(order, keys, lambda x, y: klass.get(x) == klass.get(y) and (x in cls) == (y in cls),
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
    return {"groups": groups, "unresolved": unresolved, "ref": ref, "library_candidates": bool(libs)}


# ---------------------------------------------------------------- experiments

FLAGS = ["/O2", "/Oy", "/Gy", "/GS", "/EHsc", "/GR-", "/MD", "/fp:fast", "/arch:SSE2"]


def _body(k):
    return "{ return x * %d + %d; }" % (3 + k, 1000 + 7 * k)


def experiment(out, toolchain="sp1"):
    """Run the rule experiments and return their tables (rows of dicts)."""
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    # E1 ICF survivor: groups of identical functions spread over objects, every object order.
    names = {"o0": ["f_%s_%d" % (c, k) for k, c in enumerate("pqrs")],
             "o1": ["g_%s_%d" % (c, k) for k, c in enumerate("dcba")],
             "o2": ["h_%s_%d" % (c, k) for k, c in enumerate("mzan")]}
    order_in_obj = {"o0": [0, 1, 2, 3], "o1": [3, 2, 1, 0], "o2": [1, 3, 0, 2]}
    srcs = []
    for o in ("o0", "o1", "o2"):
        lines = ["int %s(int x) %s" % (names[o][k], _body(k)) for k in order_in_obj[o]]
        srcs.append((o + ".cpp", "\n".join(lines) + "\n"))
    calls = " + ".join("%s(argc)" % n for o in names for n in names[o])
    decls = "".join("int %s(int);\n" % n for o in names for n in names[o])
    srcs.append(("m.cpp", decls + "int main(int argc, char**) { return %s; }\n" % calls))
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
        rows.append({"order": " ".join(perm), "order_check": model.get("order_check")})
    results["icf"] = rows
    results.update(_experiment_layout(out, toolchain))
    return results


E2_A = """
#include <stdio.h>
inline __declspec(noinline) int shared_inline(int x) { return x * 41 + 3; }
int a_first(int x) { return shared_inline(x) + 1; }
const char* a_str() { return "pool both"; }
float a_flt(float x) { return x * 0.75f; }
struct Base { virtual int Get() { return 1; } virtual ~Base() {} };
int a_vt(Base* b) { return b->Get(); }
Base* a_make() { return new Base; }
int a_eh(int x) { try { if (x) throw x; } catch (int y) { return y; } return 0; }
#pragma code_seg(".text$zz")
int a_late(int x) { return x - 9; }
#pragma code_seg(".text$aa")
int a_early(int x) { return x - 19; }
#pragma code_seg()
int a_last(int x) { return x * x * x; }
"""
E2_B = """
inline __declspec(noinline) int shared_inline(int x) { return x * 41 + 3; }
int b_first(int x) { return shared_inline(x) + 2; }
const char* b_str() { return "pool both"; }
const char* b_str2() { return "pool b only"; }
float b_flt(float x) { return x * 0.75f + 0.5f; }
struct Base { virtual int Get() { return 1; } virtual ~Base() {} };
Base* b_make() { return new Base; }
#pragma code_seg(".text$aa")
int b_early(int x) { return x - 29; }
#pragma code_seg()
"""
E2_M = """
struct Base { virtual int Get() { return 1; } virtual ~Base() {} };
int a_first(int); const char* a_str(); float a_flt(float); int a_vt(Base*); Base* a_make(); int a_eh(int);
int a_late(int); int a_early(int); int a_last(int);
int b_first(int); const char* b_str(); const char* b_str2(); float b_flt(float); Base* b_make(); int b_early(int);
int main(int argc, char** argv) {
    Base* p = argc > 5 ? a_make() : b_make();
    return a_first(argc) + b_first(argc) + *a_str() + *b_str() + *b_str2() + (int)a_flt((float)argc)
        + (int)b_flt((float)argc) + a_vt(p) + a_eh(argc) + a_late(argc) + a_early(argc) + a_last(argc) + b_early(argc);
}
"""
E2_NOGY = """
int ng_one(int x) { return x + 11; }
int ng_unused(int x) { return x + 12; }
int ng_two(int x) { return x + 13; }
"""


def _experiment_layout(out, toolchain):
    edir = out / "e2"
    edir.mkdir(exist_ok=True)
    objs = compile_sources([("a.cpp", E2_A), ("b.cpp", E2_B), ("m.cpp", E2_M)], edir, FLAGS, toolchain)
    nogy = compile_sources([("ng.cpp", E2_NOGY + "int ng_main(int x) { return ng_one(x) + ng_two(x); }\n")],
                           edir, [f for f in FLAGS if f != "/Gy"] + ["/Gy-"], toolchain)
    a, b, m = objs
    res = {}
    for label, order in (("m a b", [m, a, b]), ("m b a", [m, b, a]), ("b a m", [b, a, m])):
        model = trace(order, ["/OPT:REF,ICF"], edir / ("link_" + label.replace(" ", "")), toolchain)
        res.setdefault("layout", []).append({"order": label, "order_check": model.get("order_check"),
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
    res["nogy"] = [{k: c[k] for k in ("section", "symbol", "status", "size", "comdat")} for c in model["contributions"]]
    res["nogy_publics"] = [p["symbol"] for p in model["publics"] if p["symbol"].startswith("?ng_")]
    return res


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
    t = sub.add_parser("icf-trace")
    t.add_argument("--obj", nargs="+", required=True)
    t.add_argument("--flags", default="/OPT:REF,ICF")
    t.add_argument("--out", required=True)
    t.add_argument("--toolchain", default="sp1")
    x = sub.add_parser("experiment")
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
        return 0
    if args.cmd == "explain":
        model = json.loads(Path(args.model).read_text(encoding="utf-8"))
        for line in explain(model, int(args.rva, 0) if args.rva else None, args.symbol):
            print(line)
        return 0
    if args.cmd == "icf-trace":
        res = icf_trace(args.obj, shlex.split(args.flags, posix=False), args.out, args.toolchain)
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
        objs = [parse_obj(Path(p).read_bytes(), str(Path(p).resolve())) for p in args.obj]
        if args.icf_trace:
            pred = icf_predict(objs, json.loads(Path(args.icf_trace).read_text(encoding="utf-8")))
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
    if args.cmd == "experiment":
        print(json.dumps(experiment(args.out, args.toolchain), indent=1))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
