"""c2_trace parsing, decoding and formatting contracts (no debugger needed)."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import c2_trace as ct


class FakeMemory:
    def __init__(self):
        self.words, self.raw = {}, {}

    def put(self, address, *values):
        for i, value in enumerate(values):
            self.words[address + 4 * i] = value & 0xFFFFFFFF

    def u32(self, address):
        return self.words.get(address, 0)

    def bytes(self, address, size):
        if address in self.raw:
            return self.raw[address][:size]
        return b"".join(struct.pack("<I", self.u32(address + i)) for i in range(0, size, 4))[:size]


class NameTests(unittest.TestCase):
    def test_plain_name_strips_fastcall_and_cdecl_decoration(self):
        self.assertEqual(ct.plain_name("@ChoosePhysReg@12"), "ChoosePhysReg")
        self.assertEqual(ct.plain_name("_fatal"), "fatal")
        self.assertEqual(ct.plain_name("?F@@YAXXZ"), "?F@@YAXXZ")

    def test_resolve_exact_plain_missing_and_ambiguous(self):
        table = ct.symbol_table([{"name": "@Color@4", "va": 0x10}, {"name": "_Dup", "va": 0x20},
                                 {"name": "@Dup@8", "va": 0x30}, {"name": "_NoAddr", "va": None}])
        self.assertEqual(ct.resolve_name("Color", table), ("@Color@4", 0x10))
        self.assertEqual(ct.resolve_name("@Dup@8", table), ("@Dup@8", 0x30))
        with self.assertRaisesRegex(ct.TraceError, "ambiguous"):
            ct.resolve_name("Dup", table)
        with self.assertRaisesRegex(ct.TraceError, "no c2.dll public"):
            ct.resolve_name("NoAddr", table)


class ExprTests(unittest.TestCase):
    def test_nested_deref_with_symbols_and_registers(self):
        mem = FakeMemory()
        mem.put(0x1004, 0x2000)
        mem.put(0x201C, 7)
        node = ct.parse_expr("[[esp+4]+0x1c]")
        self.assertEqual(ct.eval_expr(node, {"esp": 0x1000}, mem.u32, lambda n: None), 7)
        mem.put(0x5000, 0x10)
        self.assertEqual(ct.eval_expr(ct.parse_expr("[_Entry] - 8"), {}, mem.u32, {"_Entry": 0x5000}.get), 8)

    def test_bad_expressions_fail(self):
        for text in ("[esp", "esp+", "esp]", "esp % 4"):
            with self.assertRaises(ct.TraceError):
                ct.parse_expr(text)

    def test_dump_spec_count_defaults_to_eight(self):
        self.assertEqual(ct.parse_dump("[eax]:3")[2], 3)
        self.assertEqual(ct.parse_dump("eax")[2], 8)


class StructureTests(unittest.TestCase):
    def test_sparse_bitvector_nodes_in_order(self):
        mem = FakeMemory()
        mem.put(0x100, 0x200)                       # header -> first node
        mem.put(0x200, 0, (1 << 4) | (1 << 7), 0, 0x300)
        mem.put(0x300, 64, 0, 1, 0)                 # bit 32 of the second chunk
        self.assertEqual(ct.read_sparse_bv(mem.u32, 0x100), [4, 7, 96])
        self.assertEqual(ct.read_sparse_bv(mem.u32, 0), [])

    def test_choose_phys_reg_exit_reports_weights_tie_and_choice(self):
        mem = FakeMemory()
        syms = {"_RegName": 0x9000, "_RegOrders": 0x9100, "_RegSym": 0xA000, "_ChoosePhysReg_weights": 0xB000}
        for number, name in ((4, b"esi\0"), (6, b"edi\0"), (7, b"ebx\0")):
            mem.put(0x9000 + 4 * number, 0x9800 + 16 * number)
            mem.raw[0x9800 + 16 * number] = name
        mem.put(0x9100, 0x9200)
        mem.put(0x9200, 4, 6, 7, 0)
        mem.put(0xB000 + 4 * 4, 0)
        mem.put(0xB000 + 4 * 6, 0)
        mem.put(0xB000 + 4 * 7, 3)
        mem.put(0x4010, 0xA000 + 6 * 0x60)          # Globreg+0x10 -> &_RegSym[edi]
        model = ct.C2Model(mem.u32, mem.bytes, syms.get)
        out = ct.ChoosePhysRegDecoder().exit(model, {}, {"ptr": 0x4000, "class": 0, "allowed": [4, 6, 7]})
        self.assertEqual(out["chosen"], "edi")
        self.assertEqual(out["candidates"], [["esi", 0], ["edi", 0], ["ebx", 3]])
        self.assertEqual(out["tie"], ["esi", "edi"])

    def test_globreg_fields(self):
        mem = FakeMemory()
        mem.put(0x4000, 0x6000)
        mem.put(0x400C, 51)
        mem.put(0x401C, 3)
        mem.put(0x4038, 0x7000)
        mem.put(0x4040, 14)
        mem.put(0x4044, 13)
        mem.put(0x601C, 2)
        mem.put(0x7000, 0, 0x8000, 1)
        mem.put(0x801C, 1)
        info = ct.C2Model(mem.u32, mem.bytes, {}.get).globreg(0x4000)
        self.assertEqual((info["globreg"], info["symnum"], info["priority"], info["lastref"], info["refs"]),
                         (3, 2, 51, 13, 14))
        self.assertEqual(info["prefs"], [{"globreg": 1, "weight": 1}])


class SummaryTests(unittest.TestCase):
    def test_format_choose_phys_reg_and_order(self):
        event = {"break": "ChoosePhysReg", "function": "?Walk@@YAXH@Z", "globreg": 3, "symnum": 2,
                 "chosen": "esi", "candidates": [["esi", 0], ["edi", 0]], "tie": ["esi", "edi"],
                 "priority": 51, "lastref": 13, "refs": 14}
        line = ct.format_event(event)
        self.assertIn("g3(sym2) -> esi", line)
        self.assertIn("TIE(esi,edi)", line)
        order = {"break": "OrderGlobregs", "function": "f", "class": 0,
                 "order": [{"globreg": 4, "symnum": 3, "priority": 51, "lastref": 13}]}
        self.assertIn("g4(sym3,p51,l13)", ct.format_event(order))

    def test_summary_counts_and_truncates(self):
        events = [{"break": "X", "function": "f", "ret": i} for i in range(5)]
        lines = ct.summarize(events, limit=2)
        self.assertEqual(lines[0], "calls: X=5")
        self.assertTrue(lines[-1].startswith("... (5 events"))

    def test_compile_command_shape(self):
        cmd = ct.compile_command({"bin": "C:/vc/bin"}, "a.cpp", ["/O2"], ["inc"], "out")
        self.assertEqual(cmd[1:4], ["/nologo", "/c", "/O2"])
        self.assertTrue(cmd[4].startswith("/Fo") and cmd[5] == "/Iinc")


if __name__ == "__main__":
    unittest.main()
