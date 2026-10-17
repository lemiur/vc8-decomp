import importlib.util
from pathlib import Path
import struct
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


if __name__ == "__main__":
    unittest.main()
