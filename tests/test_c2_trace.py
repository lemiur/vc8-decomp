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


class SymbolTableTests(unittest.TestCase):
    def setUp(self):
        self.mem = mem = FakeMemory()
        mem.put(0x100, 0x2000)                        # _BESymTab -> table
        mem.put(0x2000, 2, 0x2100)                    # next number 2, chunk array
        mem.put(0x2100, 0x3000)                       # chunk 0
        sym0, sym1 = 0x300C, 0x300C + 0x60
        mem.put(sym0, 0x5000)                         # descriptor
        mem.put(sym0 + 4, 4)
        mem.put(sym0 + 8, sym0)                       # its own base
        mem.put(sym0 + 0x1C, 0)
        mem.put(0x5004, 0x5100)
        mem.raw[0x5100] = b"_rect\0"
        mem.put(0x5028, 2594)
        mem.put(sym1 + 4, 4)
        mem.put(sym1 + 8, sym0)                       # equivalence of sym0 at +8
        mem.put(sym1 + 0x1C, 1)
        mem.put(sym1 + 0x24, 8)
        self.model = ct.C2Model(mem.u32, mem.bytes, {"_BESymTab": 0x100}.get)
        self.sym0, self.sym1 = sym0, sym1

    def test_symtab_names_front_end_numbers_and_equivalences(self):
        table = self.model.symtab()
        self.assertEqual(table[0], {"symnum": 0, "kind": 4, "name": "_rect", "fe": 2594})
        self.assertEqual(table[1], {"symnum": 1, "kind": 4, "base": 0, "offset": 8})
        self.assertEqual(self.model.sym_address(1), self.sym1)

    def test_leaf_text_kinds(self):
        mem = self.mem
        mem.put(0x7000, 0, 0, 7, 0, 0, 0, (-5) & 0xFFFFFFFF)          # constant
        mem.put(0x7100, 0, 0, 3, 0, 0, 0, self.sym0)                   # address of
        mem.put(0x7200, 0, 0, 1, 0, 0, 0, self.sym1)                   # tmpreg/register
        mem.put(0x7300, 0, 0, 5)                                       # effective address
        mem.put(0x7324, 4, 0, 0x7200)
        self.assertEqual(self.model.leaf_text(0x7000), "#-5")
        self.assertEqual(self.model.leaf_text(0x7100), "&_rect$2594")
        self.assertEqual(self.model.leaf_text(0x7200), "s1")
        self.assertEqual(self.model.leaf_text(0x7300), "[s1+4]")

    def test_symfree_decoder_reads_symbol(self):
        out = ct.SymFreeDecoder().entry(self.model, {"eax": self.sym0}, [0] * 8)
        self.assertEqual(out, {"symnum": 0, "kind": 4, "name": "_rect", "fe": 2594})

    def test_immed_hash_decoder(self):
        mem = self.mem
        mem.put(0x7000, 0, 0, 3, 0, 0, 0, self.sym0)
        out = ct.ImmedHashDecoder().entry(self.model, {"eax": 0x7000}, [0] * 8)
        self.assertEqual(out, {"leaf_kind": 3, "name": "_rect", "fe": 2594})
        self.assertEqual(ct.ImmedHashDecoder().exit(self.model, {"eax": 2594 & 63}, None), {"bucket": 34})


class ModuleBreakTests(unittest.TestCase):
    def test_selects_function_publics_of_matching_modules_once(self):
        rows = [{"name": "@A@4", "va": 0x20, "module": "lower.obj", "function": True},
                {"name": "_B", "va": 0x10, "module": "tuple.obj", "function": True},
                {"name": "@A2@4", "va": 0x20, "module": "lower.obj", "function": True},
                {"name": "_Tab", "va": 0x30, "module": "lower.obj", "function": False},
                {"name": "@C@4", "va": 0x40, "module": "color.obj", "function": True},
                {"name": "@D@4", "va": 0x50, "module": "lower.obj", "function": True}]
        self.assertEqual(ct.module_breaks(rows, "lower|tuple", exclude={"D"}), [("_B", 0x10), ("@A@4", 0x20)])


class DiffTests(unittest.TestCase):
    def ev(self, name, **fields):
        event = {"break": name, "depth": 0, "seq": 1, "tid": 7, "function": "f"}
        event.update(fields)
        return event

    def test_normalize_pointers_and_signed(self):
        self.assertEqual(ct.normalize([0x2A7B230, 0xFFFFFFFF, 12, "00D94018"]), ["ptr", -1, 12, "ptr"])
        seen = {}
        self.assertEqual(ct.normalize([0x2A7B230, 0x2A7C000, 0x2A7B230], ordinals=seen), ["p0", "p1", "p0"])

    def test_renumber_shifts_one_side(self):
        self.assertEqual(ct.renumber({"ecx": 2595, "x": [5, "00000A23"]}, 2500, 2700, 1),
                         {"ecx": 2594, "x": [5, "00000A22"]})

    def test_identical_after_pointer_normalisation(self):
        left = [self.ev("A", eax=0x2A7B230, ret=1)]
        right = [self.ev("A", eax=0x28E3CC8, ret=1, seq=9, tid=3)]
        self.assertIsNone(ct.diff_traces(left, right))

    def test_first_divergence_and_call_sequence_blocks(self):
        left = [self.ev("A", ret=1), self.ev("B", bucket=63), self.ev("C")]
        right = [self.ev("A", ret=1), self.ev("B", bucket=0), self.ev("D"), self.ev("C")]
        result = ct.diff_traces(left, right)
        self.assertEqual(result["index"], 1)
        self.assertEqual(result["left"]["bucket"], 63)
        self.assertEqual(result["before"][0]["break"], "A")
        self.assertIn(("insert", (2, 2), (2, 3)), result["blocks"])

    def test_renumbered_front_end_numbers_compare_equal(self):
        left = [self.ev("Grg", fe=2559, bucket=63)]
        right = [self.ev("Grg", fe=2560, bucket=63)]
        self.assertIsNotNone(ct.diff_traces(left, right))
        self.assertIsNone(ct.diff_traces(left, right, shift=(2500, 2700, 1)))

    def test_diff_command_exit_codes(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "a.jsonl", Path(tmp) / "b.jsonl"
            a.write_text(json.dumps(self.ev("A", ret=1)) + "\n", encoding="utf-8")
            b.write_text(json.dumps(self.ev("A", ret=2)) + "\n", encoding="utf-8")
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(ct.main(["diff", str(a), str(a)]), 0)
                self.assertEqual(ct.main(["diff", str(a), str(b), "--all"]), 1)
            self.assertIn("1 divergent records", out.getvalue())


if __name__ == "__main__":
    unittest.main()
