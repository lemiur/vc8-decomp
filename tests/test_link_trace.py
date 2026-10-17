import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("link_trace", Path(__file__).resolve().parents[1] / "tools" / "link_trace.py")
lt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lt)

ALIGN16 = 0x00500000
CODE = 0x60000020 | ALIGN16
RDATA4 = 0x40000040 | 0x00300000


def make_obj(sections, symbols):
    """sections: [(name, characteristics, raw, relocs[(offset, symindex, type)])];
    symbols: [(name, value, section, type, storage, aux bytes or None)]."""
    strings = bytearray(b"\0\0\0\0")

    def name8(name):
        raw = name.encode("latin-1")
        if len(raw) <= 8:
            return raw.ljust(8, b"\0")
        off = len(strings)
        strings.extend(raw + b"\0")
        return b"\0\0\0\0" + struct.pack("<I", off)

    headers_end = 20 + 40 * len(sections)
    body = bytearray()
    heads = []
    for name, chars, raw, relocs in sections:
        rawptr = headers_end + len(body)
        body.extend(raw)
        relptr = headers_end + len(body)
        for off, sym, kind in relocs:
            body.extend(struct.pack("<IIH", off, sym, kind))
        sec_name = name.encode().ljust(8, b"\0")
        heads.append(sec_name + struct.pack("<IIIIIIHHI", 0, 0, len(raw), rawptr, relptr if relocs else 0, 0,
                                            len(relocs), 0, chars))
    table = bytearray()
    count = 0
    for name, value, section, kind, storage, aux in symbols:
        table.extend(name8(name) + struct.pack("<IhHBB", value, section, kind, storage, 1 if aux else 0))
        count += 1
        if aux:
            table.extend(aux.ljust(18, b"\0"))
            count += 1
    symtab = headers_end + len(body)
    struct.pack_into("<I", strings, 0, len(strings))
    header = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, symtab, count, 0, 0)
    return header + b"".join(heads) + bytes(body) + bytes(table) + bytes(strings)


def secdef(length, nrel, checksum, number, selection):
    return struct.pack("<IHHIHB", length, nrel, 0, checksum, number, selection)


def sample_obj():
    f = b"\x8b\x44\x24\x04\xc3"                      # mov eax,[esp+4]; ret
    g = b"\xe8\x00\x00\x00\x00\xc3"                  # call f; ret
    s = b"hi\0"
    sections = [(".text", CODE | 0x1000, f, []),
                (".text", CODE | 0x1000, g, [(1, 6, 0x14)]),
                (".rdata", RDATA4 | 0x1000, s, []),
                (".text$x", CODE | 0x1000, b"\xc3", [])]
    symbols = [(".text", 0, 1, 0, 3, secdef(5, 0, 0x11, 0, 1)),        # 0,1
               ("?long_function_name@@YAHH@Z", 0, 1, 0x20, 2, None),   # 2
               (".text", 0, 2, 0, 3, secdef(6, 1, 0x22, 0, 1)),        # 3,4
               ("_g", 0, 2, 0x20, 2, None),                            # 5
               ("?long_function_name@@YAHH@Z", 0, 1, 0x20, 2, None),   # 6 (reloc target)
               (".rdata", 0, 3, 0, 3, secdef(3, 0, 0x33, 0, 2)),       # 7,8
               ("??_C@_02hi@", 0, 3, 0, 2, None),                      # 9
               (".text$x", 0, 4, 0, 3, secdef(1, 0, 0, 1, 5)),         # 10,11
               ("__unwind$f", 0, 4, 0x20, 3, None)]                    # 12
    return make_obj(sections, symbols)


def fn_obj(defs, refs, directives=""):
    """An object defining functions `defs` (one COMDAT each) and referencing `refs`."""
    sections, symbols = [], []
    for i, name in enumerate(defs):
        sections.append((".text", CODE | 0x1000, b"\xc3", []))
        symbols.append((".text", 0, i + 1, 0, 3, secdef(1, 0, 0, 0, 2)))
        symbols.append((name, 0, i + 1, 0x20, 2, None))
    if directives:
        sections.append((".drectve", 0x100A00, directives.encode(), []))
    for name in refs:
        symbols.append((name, 0, 0, 0x20, 2, None))
    return make_obj(sections, symbols)


def import_obj(name, dll):
    """A short import object (IMPORT_OBJECT_HEADER) for a code import."""
    tail = name.encode() + b"\0" + dll.encode() + b"\0"
    return struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, 0x14C, 0, len(tail), 0, 0x8) + tail


def make_archive(members):
    """A COFF archive: first linker member (big-endian offsets, symbol names), second linker
    member (empty), then the members [(name, data, [symbols])]."""
    def head(name, size):
        return (name.ljust(16) + "0".ljust(12) + "".ljust(6) + "".ljust(6) + "0".ljust(8) +
                str(size).ljust(10) + "`\n").encode()
    syms = [(s, i) for i, (_, _, ss) in enumerate(members) for s in ss]
    first_size = 4 + 4 * len(syms) + sum(len(s) + 1 for s, _ in syms)
    second = struct.pack("<II", 0, 0)
    at = 8 + 60 + first_size + (first_size & 1) + 60 + len(second)
    offsets = []
    for name, data, _ in members:
        offsets.append(at)
        at += 60 + len(data) + (len(data) & 1)
    first = struct.pack(">I", len(syms)) + b"".join(struct.pack(">I", offsets[i]) for _, i in syms) + \
        b"".join(s.encode() + b"\0" for s, _ in syms)
    out = bytearray(b"!<arch>\n")
    for name, data in [("/", first), ("/", second)] + [(n + "/", d) for n, d, _ in members]:
        out += head(name, len(data)) + data
        if len(data) & 1:
            out += b"\n"
    return bytes(out)


VERBOSE = """Starting pass 1
    Discarded "int __cdecl unused(int)" (?unused@@YAHH@Z) from b.obj
    Discarded _printf from MSVCRT.lib(MSVCR80.dll)

    Selected symbol:
        "int __cdecl mul_a(int)" (?mul_a@@YAHH@Z) from a.obj
    Replaced symbol(s):
        "int __cdecl zz_b(int)" (?zz_b@@YAHH@Z) from b.obj
        _zz_c from C:\\work\\c.obj

    Selected symbol:
        __setargv from MSVCRT.lib(dllargv.obj)
    Replaced symbol(s):
        __matherr from MSVCRT.lib(merr.obj)

    ICF total savings: 45 bytes

Starting pass 2
     b.obj
Finished pass 2
"""

MAP = """ t

 Timestamp is 6ad391f5 (Sat Oct 17 11:19:17 2026)

 Preferred load address is 00400000

 Start         Length     Name                   Class
 0001:00000000 00000948H .text                   CODE
 0002:000000c8 000000a0H .rdata                  DATA

  Address         Publics by Value              Rva+Base       Lib:Object

 0000:00000000       __except_list              00000000     <absolute>
 0001:00000000       ?long_function_name@@YAHH@Z 00401000 f   s.obj
 0001:00000010       _g                         00401010 f   s.obj
 0001:00000413       _mainCRTStartup            00401413 f   MSVCRT:crtexe.obj
 0002:000000c8       ??_C@_02hi@                004020c8     s.obj

 entry point at        0001:00000413

 Static symbols

 0001:00000020       __unwind$f                 00401020 f   s.obj
"""


def make_pe(text, rdata, image_base=0x400000):
    """A two-section PE32 with .text at RVA 0x1000 and .rdata at RVA 0x2000."""
    pe = 0x40
    opt = 224
    sec_table = pe + 24 + opt
    raw_text = 0x200
    raw_rdata = raw_text + 0x200
    data = bytearray(raw_rdata + 0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe)
    data[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, pe + 4, 0x14C, 2, 0x6AD391F5, 0, 0, opt, 0x102)
    struct.pack_into("<I", data, pe + 24 + 16, 0x1413)
    struct.pack_into("<III", data, pe + 24 + 28, image_base, 0x1000, 0x200)
    for i, (name, rva, raw, body, chars) in enumerate(((b".text", 0x1000, raw_text, text, 0x60000020),
                                                       (b".rdata", 0x2000, raw_rdata, rdata, 0x40000040))):
        at = sec_table + i * 40
        data[at:at + 8] = name.ljust(8, b"\0")
        struct.pack_into("<IIII", data, at + 8, 0x200, rva, 0x200, raw)
        struct.pack_into("<I", data, at + 36, chars)
        data[raw:raw + len(body)] = body
    return bytes(data)


class ObjParserTests(unittest.TestCase):
    def setUp(self):
        self.obj = lt.parse_obj(sample_obj(), "s.obj")

    def test_sections_and_comdat_aux(self):
        secs = self.obj["sections"]
        self.assertEqual([s["name"] for s in secs], [".text", ".text", ".rdata", ".text$x"])
        self.assertEqual(secs[0]["selection"], "nodup")
        self.assertEqual(secs[0]["checksum"], 0x11)
        self.assertEqual(secs[0]["align"], 16)
        self.assertEqual(secs[2]["selection"], "any")
        self.assertEqual(secs[2]["align"], 4)
        self.assertEqual(secs[3]["selection"], "associative")
        self.assertEqual(secs[3]["associated"], 1)

    def test_long_names_and_comdat_symbol(self):
        self.assertEqual(lt.comdat_symbol(self.obj["sections"][0]), "?long_function_name@@YAHH@Z")
        self.assertEqual(lt.comdat_symbol(self.obj["sections"][1]), "_g")

    def test_relocations(self):
        rel = self.obj["sections"][1]["relocs"][0]
        self.assertEqual((rel["offset"], rel["type"], rel["symbol"]), (1, "REL32", "?long_function_name@@YAHH@Z"))
        self.assertEqual(rel["addend"], 0)

    def test_rejects_ltcg(self):
        with self.assertRaises(lt.LinkTraceError):
            lt.parse_obj(b"\0\0\xff\xff" + bytes(60), "gl.obj")

    def test_group_name(self):
        self.assertEqual(lt.group_name(".text$x"), ".text")
        self.assertEqual(lt.group_name(".rdata"), ".rdata")


class VerboseParserTests(unittest.TestCase):
    def test_discards_and_fold_groups(self):
        v = lt.parse_verbose(VERBOSE)
        self.assertEqual([(d["symbol"], d["lib"], d["member"]) for d in v["discarded"]],
                         [("?unused@@YAHH@Z", None, "b.obj"), ("_printf", "MSVCRT.lib", "MSVCR80.dll")])
        self.assertEqual(len(v["fold_groups"]), 2)
        g = v["fold_groups"][0]
        self.assertEqual(g["survivor"]["symbol"], "?mul_a@@YAHH@Z")
        self.assertEqual([r["symbol"] for r in g["replaced"]], ["?zz_b@@YAHH@Z", "_zz_c"])
        self.assertEqual(g["replaced"][1]["origin"], "C:\\work\\c.obj")
        self.assertEqual(v["icf_savings"], 45)
        self.assertEqual(v["passes"][0], "Starting pass 1")


class MapParserTests(unittest.TestCase):
    def test_map(self):
        m = lt.parse_map(MAP)
        self.assertEqual(m["image_base"], 0x400000)
        self.assertEqual(m["timestamp"], 0x6AD391F5)
        self.assertEqual(m["groups"][0], {"section": 1, "offset": 0, "length": 0x948, "name": ".text", "class": "CODE"})
        self.assertEqual(m["entry"], {"section": 1, "offset": 0x413})
        crt = next(p for p in m["publics"] if p["symbol"] == "_mainCRTStartup")
        self.assertEqual((crt["lib"], crt["member"], crt["function"]), ("MSVCRT", "crtexe.obj", True))
        self.assertEqual(m["statics"][0]["symbol"], "__unwind$f")
        data = next(p for p in m["publics"] if p["symbol"] == "??_C@_02hi@")
        self.assertFalse(data["function"])


class ModelTests(unittest.TestCase):
    def setUp(self):
        text = bytearray(0x30)
        text[0:5] = b"\x8b\x44\x24\x04\xc3"
        text[5:16] = b"\xcc" * 11
        text[0x10:0x16] = b"\xe8" + struct.pack("<i", 0x1000 - 0x1015) + b"\xc3"
        self.image = make_pe(bytes(text), bytes(0xC8) + b"hi\0")
        self.obj = lt.parse_obj(sample_obj(), "C:/x/s.obj")
        self.model = lt.build_model([self.obj], VERBOSE, MAP, self.image)

    def test_contributions(self):
        rows = {c["symbol"]: c for c in self.model["contributions"]}
        g = rows["_g"]
        self.assertEqual((g["status"], g["rva"], g["padding_before"], g["padding_bytes"]), ("kept", 0x1010, 11, "cc" * 11))
        self.assertEqual(g["relocs"][0]["target_rva"], 0x1000)
        self.assertEqual(g["relocs"][0]["target"], ["?long_function_name@@YAHH@Z"])
        self.assertEqual(rows["??_C@_02hi@"]["rva"], 0x20C8)
        self.assertEqual(rows["__unwind$f"]["associated_with"], "?long_function_name@@YAHH@Z")
        self.assertEqual(self.model["image"]["entry_rva"], 0x1413)

    def test_explain(self):
        lines = lt.explain(self.model, rva=0x1012)
        self.assertIn("_g: kept, RVA 0x1010", lines[0])
        self.assertTrue(any("offset in contribution: 0x2" in line for line in lines))
        self.assertIn("_mainCRTStartup", lt.explain(self.model, rva=0x1500)[0])
        self.assertIn("not in the model", lt.explain(self.model, symbol="_nope")[0])

    def test_folded_and_removed_status(self):
        verbose = VERBOSE.replace("?unused@@YAHH@Z) from b.obj", "?unused@@YAHH@Z) from b.obj\n"
                                  "    Discarded _g from C:\\x\\s.obj")
        model = lt.build_model([self.obj], verbose, MAP, self.image)
        g = next(c for c in model["contributions"] if c["symbol"] == "_g")
        self.assertEqual(g["status"], "removed")


class OrderTests(unittest.TestCase):
    def test_predict_order_alignment_and_groups(self):
        a = lt.parse_obj(sample_obj(), "a.obj")
        b = lt.parse_obj(sample_obj(), "b.obj")
        kept = {("a.obj", "?long_function_name@@YAHH@Z"), ("a.obj", "_g"), ("b.obj", "_g")}
        rows = lt.predict_order([a, b], kept=kept)
        self.assertEqual([(r["obj"], r["symbol"]) for r in rows],
                         [("a.obj", "?long_function_name@@YAHH@Z"), ("a.obj", "_g"), ("b.obj", "_g"),
                          ("a.obj", "__unwind$f")])
        self.assertEqual([r["offset"] for r in rows], [0, 0x10, 0x20, 0x30])
        self.assertEqual(rows[1]["padding_bytes"], "cc" * 11)

    def test_reachability_and_icf_candidates(self):
        a = lt.parse_obj(sample_obj(), "a.obj")
        live = lt.reachable([a], roots=["_g"])
        self.assertIn(("a.obj", "_g"), live)
        self.assertIn(("a.obj", "?long_function_name@@YAHH@Z"), live)
        b = lt.parse_obj(sample_obj(), "b.obj")
        rows = lt.predict_order([a, b], kept={("a.obj", "_g"), ("b.obj", "_g")})
        self.assertEqual(rows[0]["icf_candidates"], ["_g", "_g"])


class IcfSurvivorModel(unittest.TestCase):
    def test_qsort_sorts_and_is_not_stable(self):
        import random
        rng = random.Random(7)
        for n in (0, 1, 2, 8, 9, 40, 200):
            data = [rng.randrange(6) for _ in range(n)]
            items = list(range(n))
            out = lt.ms_qsort(items, lambda x, y: (data[x] > data[y]) - (data[x] < data[y]))
            self.assertEqual(sorted(out), items)
            self.assertEqual([data[i] for i in out], sorted(data))
        # shortsort moves the maximum to the end: two equal keys swap places.
        self.assertEqual(lt.ms_qsort(["a", "b"], lambda x, y: 0), ["b", "a"])

    def test_compare_key_order(self):
        live = [1, 0, 0, 12, 0xFFFFFFFF, 5]
        self.assertEqual(lt.icf_compare(live, [0] + live[1:]), -1)        # live first under /OPT:REF
        self.assertEqual(lt.icf_compare(live, [0] + live[1:], ref=False), 0)
        self.assertEqual(lt.icf_compare(live[:1] + [1] + live[2:], live), 1)  # cycle byte last
        self.assertEqual(lt.icf_compare(live, live[:3] + [13] + live[4:]), -1)  # size ascending
        self.assertEqual(lt.icf_compare(live, list(live)), 0)

    @staticmethod
    def walk(order, keys, edges, out=None):
        call = lambda t: (struct.pack("<II", 4, 0x1010014), t)
        return lt.icf_walk(order, keys, lambda n: [call(t) if len(t) == 1 else t for t in edges.get(n, ())],
                           lambda x, y: True, lambda x, y: False, out)

    def test_survivor_is_lowest_unless_a_caller_folds_first(self):
        keys = {(k,): [1, 0, 1, 16, 9, c] for k, c in (("leaf1", 1), ("leaf2", 1), ("top1", 2), ("top2", 2))}
        edges = {("top1",): [("leaf1",)], ("top2",): [("leaf2",)]}
        # Callers sorted first: top2 absorbs top1 and its callee leaf2 absorbs leaf1.
        out = self.walk([("top2",), ("top1",), ("leaf1",), ("leaf2",)], keys, edges)
        self.assertEqual(out, {("leaf1",): ("leaf2",), ("top1",): ("top2",)})
        out = self.walk([("leaf1",), ("leaf2",), ("top2",), ("top1",)], keys, edges)
        self.assertEqual(out, {("leaf2",): ("leaf1",), ("top1",): ("top2",)})

    def test_identical_children_of_differing_callers_stay_folded(self):
        # avp3 code DLL, /DEBUG, given order: the CSampleXAPOBase<Chorus> and <Flanger> destructors
        # differ (their vtables), but their unwind funclets, compared first as associative children,
        # fold into the copy of the caller sorted first, though the callers never fold.
        child = struct.pack("<II", 0, 0xFFFF)
        keys = {("p1",): [1, 1, 2, 16, 9, 3], ("p2",): [1, 1, 2, 16, 9, 3],
                ("c1",): [1, 0, 1, 8, 5, 4], ("c2",): [1, 0, 1, 8, 5, 4],
                ("v1",): [1, 0, 1, 8, 6, 0], ("v2",): [1, 0, 1, 8, 7, 0]}
        edges = {("p1",): [(child, ("c1",)), ("v1",)], ("p2",): [(child, ("c2",)), ("v2",)]}
        self.assertEqual(self.walk([("p1",), ("p2",)], keys, edges), {("c2",): ("c1",)})
        self.assertEqual(self.walk([("p2",), ("p1",)], keys, edges), {("c1",): ("c2",)})
        # Only a bucket of equal keys (edge CRC included) is compared: no comparison, no fold.
        keys[("p2",)] = [1, 1, 2, 16, 8, 3]
        self.assertEqual(self.walk([("p1",), ("p2",)], keys, edges), {})

    def test_deferred_cycle_folds_with_its_root(self):
        # x -> a -> x and y -> b -> y: the (a, b) comparison reaches (x, y) on the stack, so it is
        # left to the fold of (x, y), whose FoldAssocEdges folds b into a.
        keys = {(n,): [1, 1, 1, 8, 5, 6 if n in "xy" else 7] for n in ("x", "y", "a", "b")}
        edges = {("x",): [("a",)], ("y",): [("b",)], ("a",): [("x",)], ("b",): [("y",)]}
        self.assertEqual(self.walk([("x",), ("y",), ("a",), ("b",)], keys, edges), {("y",): ("x",), ("b",): ("a",)})

    def test_sig_is_pdb_crc32(self):
        self.assertEqual(lt._sig(b"", 0xFFFFFFFF), 0xFFFFFFFF)
        s = 0xFFFFFFFF
        for b in b"abc":   # SigForPbCb: sig = (sig >> 8) ^ T[(sig ^ b) & 0xFF]
            s ^= b
            for _ in range(8):
                s = (s >> 1) ^ (0xEDB88320 if s & 1 else 0)
        self.assertEqual(lt._sig(b"abc", 0xFFFFFFFF), s)

    def test_static_keys_leaf_and_caller(self):
        leaf = b"\x8b\x44\x24\x04\xc3"
        caller = b"\xe8\x00\x00\x00\x00\xc3"
        aux = lambda size, nrel, ck, sel: struct.pack("<IHHIHB3x", size, nrel, 0, ck, 0, sel)
        data = make_obj([(".text", CODE | 0x1000, leaf, []), (".text", CODE | 0x1000, caller, [(1, 4, 0x14)])],
                        [(".text", 0, 1, 0, 3, aux(5, 0, 0x11, 2)), (".text", 0, 2, 0, 3, aux(6, 1, 0x22, 1)),
                         ("_leaf", 0, 1, 0x20, 2, None), ("_caller", 0, 2, 0x20, 2, None)])
        obj = lt.parse_obj(data, "a.obj")
        rows = lt.icf_candidates([obj])
        keys = lt.icf_static_keys([obj], rows)
        self.assertEqual(keys[(0, 1)], [1, 0, 0, 5, 0xFFFFFFFF, 0x11])
        edge = lt._sig(struct.pack("<II", 1, 0x14 | 2 << 16 | 0x1000000), 0xFFFFFFFF)
        self.assertEqual(keys[(0, 2)], [1, 0, 1, 6, lt._sig(struct.pack("<I", 0xFFFFFFFF), edge), 0x22])

    def test_associative_candidate_child_hashes_only_its_edge(self):
        parent = b"\xc3"
        child = b"\xcc\xcc\xcc\xcc"
        aux = lambda size, nrel, ck, sel, assoc=0: struct.pack("<IHHIHB3x", size, nrel, 0, ck, assoc, sel)
        data = make_obj([(".text", CODE | 0x1000, parent, []), (".text$x", CODE | 0x1000, child, [])],
                        [(".text", 0, 1, 0, 3, aux(1, 0, 0x11, 2)), (".text$x", 0, 2, 0, 3, aux(4, 0, 0x22, 5, 1)),
                         ("_parent", 0, 1, 0x20, 2, None)])
        obj = lt.parse_obj(data, "a.obj")
        rows = lt.icf_candidates([obj])
        log = {}
        keys = lt.icf_static_keys([obj], rows, log=log)
        # CrcEdges: the (0, 0xFFFF) edge to the child, nothing for an associative candidate.
        self.assertEqual(log[(0, 1)], [["edge", struct.pack("<II", 0, 0xFFFF).hex()]])
        self.assertEqual(keys[(0, 1)][4], lt._sig(struct.pack("<II", 0, 0xFFFF), 0xFFFFFFFF))

    def test_debug_child_hashes_its_output_section(self):
        # /DEBUG (avp3 2-unit link): a function's .debug$F is a contribution, not a candidate; the
        # parent's edge CRC hashes its (0, 0xFFFF) edge, ".debug" and twice 0x42000040.
        aux = lambda size, ck, sel, assoc=0: struct.pack("<IHHIHB3x", size, 0, 0, ck, assoc, sel)
        data = make_obj([(".text", CODE | 0x1000, b"\xc3", []), (".debug$F", 0x42101040, bytes(16), [])],
                        [(".text", 0, 1, 0, 3, aux(1, 0x11, 2)), (".debug$F", 0, 2, 0, 3, aux(16, 0x22, 5, 1)),
                         ("_parent", 0, 1, 0x20, 2, None)])
        obj = lt.parse_obj(data, "a.obj")
        rows = lt.icf_candidates([obj])
        self.assertEqual(lt.icf_static_keys([obj], rows)[(0, 1)][4], 0xFFFFFFFF)
        self.assertTrue(lt.link_debug(["link.exe", "/dll", "-debug"]))
        self.assertFalse(lt.link_debug(["link.exe", "/DLL", "a.obj"]))
        log = {}
        keys = lt.icf_static_keys([obj], rows, log=log, command=["link.exe", "/DEBUG"])
        flags = struct.pack("<I", 0x42000040)
        self.assertEqual(log[(0, 1)], [["edge", struct.pack("<II", 0, 0xFFFF).hex()], ["name", b".debug".hex()],
                                       ["name+2c", flags.hex()], ["name+30", flags.hex()]])
        crc = 0xFFFFFFFF
        for chunk in (struct.pack("<II", 0, 0xFFFF), b".debug", flags, flags):
            crc = lt._sig(chunk, crc)
        self.assertEqual(keys[(0, 1)][4], crc)

    def test_parse_loads(self):
        text = "\n".join(["Searching libraries", "    Searching C:/lib/MSVCRT.lib:", "      Found __fltused",
                          "        Referenced in m.obj", "        Referenced in a.obj",
                          "        Loaded MSVCRT.lib(dllsupp.obj)", "      Found _mainCRTStartup",
                          "        Loaded MSVCRT.lib(crtexe.obj)"])
        ev = lt.parse_loads(text)
        self.assertEqual([e["symbol"] for e in ev], ["__fltused", "_mainCRTStartup"])
        self.assertEqual(ev[0]["refs"], ["m.obj", "a.obj"])
        self.assertEqual(ev[1]["loaded"], "MSVCRT.lib(crtexe.obj)")

    def test_library_pulls_follow_first_reference(self):
        ext = lambda *names: [{"name": n, "external": True, "section": 0} for n in names]
        ev = lambda sym, refs, loaded: {"symbol": sym, "lib": "L", "refs": refs, "loaded": loaded}
        # Traced with m before c: m pulls ftol2 (which references sse2), c pulls new (an import).
        events = [ev("__ftol2", ["m.obj"], "L(ftol2.obj)"), ev("??2", ["c.obj"], "L(X.dll)"),
                  ev("_entry", [], "L(crtexe.obj)"), ev("__sse2", ["L(ftol2.obj)"], "L(cpu.obj)"),
                  ev("__IMPORT_DESCRIPTOR_X", ["L(X.dll)", "L(X.dll)"], "L(X.dll)")]
        m = {"path": "m.obj", "symbols": ext("__ftol2")}
        c = {"path": "c.obj", "symbols": ext("??2")}
        self.assertEqual(lt.library_pulls([m, c], events), ["__ftol2", "??2", "_entry", "__sse2", "__IMPORT_DESCRIPTOR_X"])
        # c first: its import member loads first, so the descriptor precedes ftol2's own reference.
        self.assertEqual(lt.library_pulls([c, m], events), ["??2", "__ftol2", "_entry", "__IMPORT_DESCRIPTOR_X", "__sse2"])


    def test_parse_archive_and_import_members(self):
        lib = make_archive([("a1.obj", fn_obj(["_a1"], ["_b1"]), ["_a1"]),
                            ("X.dll", import_obj("_imp", "X.dll"), ["__imp__imp", "_imp"])])
        arch = lt.parse_archive(lib, "la.lib")
        self.assertEqual([m["name"] for m in arch["members"]], ["a1.obj", "X.dll"])
        self.assertEqual(set(arch["dictionary"]), {"_a1", "__imp__imp", "_imp"})
        info = lt.module_symbols(arch["members"][1]["data"])
        self.assertEqual(info["import"], "X.dll")
        self.assertEqual([s[0] for s in info["symbols"]], ["__imp__imp", "_imp", "__IMPORT_DESCRIPTOR_X"])

    def test_parse_directives(self):
        self.assertEqual(lt.parse_directives('/DEFAULTLIB:"ld" -defaultlib:MSVCRT /NODEFAULTLIB /INCLUDE:_x /MERGE:a=b'),
                         [("DEFAULTLIB", "ld"), ("DEFAULTLIB", "MSVCRT"), ("NODEFAULTLIB", None), ("INCLUDE", "_x")])

    def test_search_libraries_passes_and_default_libs(self):
        files = {
            "m.obj": fn_obj(["_main"], ["_a1"]),
            "la.lib": make_archive([("a1.obj", fn_obj(["_a1"], ["_b1"]), ["_a1"]),
                                    ("a2.obj", fn_obj(["_a2"], []), ["_a2"])]),
            "lb.lib": make_archive([("b1.obj", fn_obj(["_b1"], ["_d1"], "/DEFAULTLIB:ld"), ["_b1"])]),
            "ld.lib": make_archive([("d1.obj", fn_obj(["_d1"], ["_a2"]), ["_d1"])]),
        }
        load = lambda p: files[p.replace("\\", "/").split("/")[-1]]
        inputs = [("obj", "m.obj"), ("lib", "la.lib"), ("lib", "lb.lib")]
        with tempfile.TemporaryDirectory() as tmp:
            for name in files:
                Path(tmp, name).write_bytes(files[name])
            got = lt.search_libraries([(k, str(Path(tmp, a))) for k, a in inputs], [tmp], load=load)
            # la, lb, then the default library ld (named by b1.obj): each walk goes on through the
            # references its loads appended; a second pass finds a2 in la.
            self.assertEqual([(Path(s["lib"]).name, s["tried"]) for s in got["searches"]],
                             [("la.lib", ["_a1", "_b1"]), ("lb.lib", ["_b1", "_d1"]), ("ld.lib", ["_d1", "_a2"]),
                              ("la.lib", ["_a2"])])
            self.assertEqual([(e["symbol"], e["member"], e["module"]) for e in got["events"]],
                             [("_a1", "a1.obj", 2), ("_b1", "b1.obj", 3), ("_d1", "d1.obj", 4), ("_a2", "a2.obj", 5)])
            # /NODEFAULTLIB:ld: d1 stays unresolved; the second pass ends on reaching lb, the last
            # library whose load added a reference.
            got = lt.search_libraries([(k, str(Path(tmp, a))) for k, a in inputs], [tmp],
                                      defaults=[("NODEFAULTLIB", "ld")], load=load)
            self.assertEqual(got["unresolved"], ["_d1"])
            self.assertEqual([Path(s["lib"]).name for s in got["searches"]], ["la.lib", "lb.lib", "la.lib"])

    def test_round_seeds(self):
        loads = [{"symbol": "_a", "refs": ["m.obj"], "loaded": "L(a.obj)", "round": 0},
                 {"symbol": "__load_config_used", "refs": [], "loaded": "L(loadcfg.obj)", "round": 1}]
        self.assertEqual(lt._round_seeds(loads), [[], ["__load_config_used"]])

    def test_survivors_guard_cycles(self):
        keys = {(x,): [1, 1, 1, 5, 7, 9] for x in "abcd"}
        edges = {("a",): [("a",)], ("b",): [("b",)], ("c",): [("d",)], ("d",): [("c",)]}
        out = self.walk([("a",), ("b",), ("c",), ("d",)], keys, edges)
        self.assertEqual(out[("b",)], ("a",))
        self.assertEqual(out[("d",)], ("c",))


def code_section(index, name, sym, selection="any", associated=0, size=1):
    return {"index": index, "name": name, "code": True, "removed": False, "size": size, "comdat": True,
            "selection": selection, "associated": associated, "align": 16, "raw": b"\xc3" * size,
            "relocs": [], "characteristics": 0x60501020, "symbols": [{"name": sym, "value": 0}]}


class LayoutRuleTests(unittest.TestCase):
    def test_folded_first_definer_keeps_its_slot_from_later_duplicates(self):
        # a's copy of the any-COMDAT _t is selected (first definer) and then folded by ICF: b's
        # duplicate must not take a slot (the avp3 17-unit Map<...>::FreeNodes run).
        a = {"path": "a.obj", "symbols": [], "sections": [code_section(1, ".text", "_f"), code_section(2, ".text", "_t")]}
        b = {"path": "b.obj", "symbols": [], "sections": [code_section(1, ".text", "_t"), code_section(2, ".text", "_g")]}
        kept = {("a.obj", "_f"), ("a.obj", "_t"), ("b.obj", "_t"), ("b.obj", "_g")}
        rows = lt.predict_order([a, b], kept=kept, folded={("a.obj", "_t")})
        self.assertEqual([(r["obj"], r["symbol"]) for r in rows], [("a.obj", "_f"), ("b.obj", "_g")])

    def test_associative_child_folds_on_its_own(self):
        # An unwind funclet folds into another function's identical funclet while its parent stays.
        a = {"path": "a.obj", "symbols": [], "sections": [
            code_section(1, ".text", "_p"), code_section(2, ".text$x", "__unwindfunclet$_p$0", "associative", 1),
            code_section(3, ".text", "_q"), code_section(4, ".text$x", "__unwindfunclet$_q$0", "associative", 3)]}
        kept = {("a.obj", "_p"), ("a.obj", "_q")}
        rows = lt.predict_order([a], kept=kept, folded={("a.obj", "__unwindfunclet$_q$0")})
        self.assertEqual([r["symbol"] for r in rows], ["_p", "_q", "__unwindfunclet$_p$0"])

    def test_traced_folds_name_static_children(self):
        icf = {"cons": [{"id": 0, "obj": "C:/x/a.obj", "lib": None, "section_index": 2, "symbol": "__unwindfunclet$_p$0"},
                        {"id": 1, "obj": "C:/x/a.obj", "lib": None, "section_index": 4, "symbol": "__unwindfunclet$_q$0"},
                        {"id": 2, "obj": "C:/x/b.obj", "lib": None, "section_index": 4, "symbol": "x"}],
               "folds": [{"keep": 0, "fold": 1}, {"keep": 1, "fold": 2}]}
        got = lt._traced_folds(icf)
        self.assertEqual(sorted(got), [("a.obj", 4), ("b.obj", 4)])
        self.assertEqual(got[("b.obj", 4)]["id"], 0)  # the root survivor of a chain of folds
        self.assertIsNone(lt._traced_folds(None))


class ImportLayoutTests(unittest.TestCase):
    def test_iat_is_qsorted_by_dll_name_with_null_thunks_last(self):
        def imp(dll, name, load):
            return {"kind": "import", "dll": dll, "symbol": "_" + name, "hint_name": name, "code": True, "load": load}

        members = [imp("MSVCR80.dll", "m%d" % i, i) for i in range(6)]
        members += [{"kind": "descriptor", "dll": "MSVCR80.dll", "symbol": "__IMPORT_DESCRIPTOR_MSVCR80", "load": 6},
                    {"kind": "null_thunk", "dll": "MSVCR80.dll", "symbol": "\x7fMSVCR80_NULL_THUNK_DATA", "load": 7},
                    imp("MSVCR80.dll", "m6", 8)]
        members += [imp("KERNEL32.dll", "k%d" % i, 9 + i) for i in range(4)]
        members += [{"kind": "descriptor", "dll": "KERNEL32.dll", "symbol": "__IMPORT_DESCRIPTOR_KERNEL32", "load": 13},
                    {"kind": "null_thunk", "dll": "KERNEL32.dll", "symbol": "\x7fKERNEL32_NULL_THUNK_DATA", "load": 14}]
        pred = lt.predict_imports(members)
        self.assertEqual(pred["descriptors"], ["MSVCR80.dll", "KERNEL32.dll"])  # load order
        self.assertEqual([d for d, _ in pred["iat"]], ["KERNEL32.dll"] * 5 + ["MSVCR80.dll"] * 8)  # wcscmp
        self.assertEqual([pred["iat"][4][1], pred["iat"][-1][1]], [None, None])  # null thunk closes each run
        # qsort is not stable: the equal keys do not keep their load order.
        thunks = [(m["dll"], m.get("hint_name")) for m in members if m["kind"] != "descriptor"]
        expect = [x[1] for x in lt.ms_qsort(thunks, lambda a, b: (a[0] > b[0]) - (a[0] < b[0])) if x[1]]
        self.assertEqual([n for _, n in pred["iat"] if n], expect)
        self.assertNotEqual(expect[:4], ["k0", "k1", "k2", "k3"])
        # .idata$6 is not sorted: hint/names and DLL names in load order.
        self.assertEqual([n for _, n in pred["names"]][:7], ["m0", "m1", "m2", "m3", "m4", "m5", None])

    def test_import_hint_name(self):
        self.assertEqual(lt._import_hint_name("_memcpy", 2), "memcpy")
        self.assertEqual(lt._import_hint_name("_Sleep@4", 3), "Sleep")
        self.assertEqual(lt._import_hint_name("?terminate@@YAXXZ", 1), "?terminate@@YAXXZ")
        self.assertIsNone(lt._import_hint_name("_x", 0))

    def test_import_members_from_loads(self):
        lib = make_archive([("X.dll", import_obj("_imp", "X.dll"), ["__imp__imp", "_imp"])])
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x.lib").write_bytes(lib)
            path = str(Path(tmp, "x.lib"))
            loads = [{"symbol": "_imp", "lib": path, "refs": ["m.obj"], "loaded": "x.lib(X.dll)"},
                     {"symbol": "__IMPORT_DESCRIPTOR_X", "lib": path, "refs": [], "loaded": "x.lib(X.dll)"}]
            rows = lt.import_members(loads)
        self.assertEqual([(r["kind"], r["dll"], r["symbol"]) for r in rows],
                         [("import", "X.dll", "_imp"), ("descriptor", "X.dll", "__IMPORT_DESCRIPTOR_X")])
        self.assertEqual((rows[0]["hint_name"], rows[0]["code"]), ("imp", True))


class LinkerSeedTests(unittest.TestCase):
    def test_entry_points(self):
        def seeds(*args):
            return lt.linker_seeds(["link.exe", *args])

        self.assertEqual(seeds("/DLL", "/NOENTRY")[0], [])
        self.assertEqual(seeds("/DLL")[0], ["__DllMainCRTStartup@12"])
        self.assertEqual(seeds("/ENTRY:start")[0], ["_start"])
        self.assertEqual(seeds()[0], ["_mainCRTStartup"])
        self.assertEqual(seeds()[-1], ["__load_config_used"])

    def test_response_file_options(self):
        # vc8_trace links with `@flags.txt`: its /DLL /NOENTRY and /EXPORT are the command's.
        with tempfile.TemporaryDirectory() as d:
            rsp = str(Path(d) / "flags.txt")
            with open(rsp, "w") as f:
                f.write("/DLL /NOENTRY /EXPORT:exp_r")
            rounds = lt.linker_seeds(["link.exe", "@" + rsp])
            self.assertEqual(rounds[0], [])
            self.assertEqual(rounds[1]({"exports": []}), ["_exp_r"])

    def test_export_and_alternatename_rounds(self):
        export_round, alternate_round = lt.linker_seeds(["link.exe", "/EXPORT:exp_zcmd"])[1:3]
        state = {"defined": {"_g_alt"}, "undefined": {"_f_alt"}, "exports": ["_exp_lib", "_exp_alpha"],
                 "alternates": {"_f_alt": "_f_default", "_g_alt": "_g_default"}}
        self.assertEqual(export_round(state), ["_exp_alpha", "_exp_lib", "_exp_zcmd"])
        self.assertEqual(alternate_round(state), ["_f_default"])
        self.assertIsNone(lt.linker_seeds(["link.exe"])[1](dict(state, exports=[])))
        self.assertIsNone(alternate_round(dict(state, undefined=set())))
        self.assertEqual(lt.parse_directives("/EXPORT:_e=_impl,@3 /ALTERNATENAME:_a=_b"),
                         [("EXPORT", "_impl"), ("ALTERNATENAME", "_a=_b")])

    def test_search_skips_rounds_link_does_not_make(self):
        files = {"m.obj": fn_obj(["_main"], ["_f_alt"], "/ALTERNATENAME:_f_alt=_f_default"),
                 "lx.lib": make_archive([("c.obj", fn_obj(["_f_default"], []), ["_f_default"]),
                                         ("l.obj", fn_obj(["__load_config_used"], []), ["__load_config_used"])])}

        def load(p):
            return files[p.replace("\\", "/").split("/")[-1]]

        with tempfile.TemporaryDirectory() as tmp:
            for name in files:
                Path(tmp, name).write_bytes(files[name])
            seeds = lt.linker_seeds(["link.exe", "/NOENTRY", "/DLL"])
            got = lt.search_libraries([("obj", str(Path(tmp, "m.obj"))), ("lib", str(Path(tmp, "lx.lib")))],
                                      [tmp], rounds=seeds, load=load)
        self.assertEqual(got["seeds"], [[], ["_f_default"], ["__load_config_used"]])
        self.assertEqual([(e["round"], e["symbol"]) for e in got["events"]],
                         [(1, "_f_default"), (2, "__load_config_used")])


if __name__ == "__main__":
    unittest.main()
