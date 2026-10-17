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


class RegAssignTests(unittest.TestCase):
    """Local register assignment: _RegSym entries (stride 0x60, +0x1C number),
    _RegName strings, _IntPhysRegs / _NextIntPos, _RegMap, _BvConflicts."""

    def setUp(self):
        mem = self.mem = FakeMemory()
        self.regsym, names = 0x20000, 0x30000
        syms = {"_RegSym": self.regsym, "_RegName": names, "_IntPhysRegs": 0x31000, "_NextIntPos": 0x31100,
                "_RegMap": 0x32000, "_BvConflicts": 0x33000, "_BESymTab": 0x100}
        for number, name in enumerate(("none", "eax", "ecx", "edx", "esi")):
            mem.put(names + 4 * number, 0x30100 + 0x10 * number)
            mem.raw[0x30100 + 0x10 * number] = name.encode() + b"\0"
            mem.put(self.regsym + 0x60 * number + 0x1C, number)
        mem.put(0x31000, 1, 2, 3, 4, 0)               # eax ecx edx esi
        mem.put(0x31100, 0x31004)                     # cursor at ecx
        mem.put(0x32000 + 4 * 1, self.regsym + 0x60 * 1)   # eax holds itself (a physreg)
        mem.put(0x33000 + 4 * 2, 0x34000)             # ecx conflicts with symbol 162
        mem.put(0x34000, 0x34100)
        mem.put(0x34100, 128, 0, 1 << (162 - 128 - 32), 0)
        self.tmp = 0x40000                            # tmpreg s162, no descriptor
        mem.put(self.tmp + 0x1C, 162)
        mem.put(0x41000, 0, 0, 1, 0, 0, 0, self.tmp, self.tmp)   # leaf: kind 1, +0x18 = +0x1C = tmpreg
        mem.put(0x42000, 0, 1, 0x100, 0, 0, 0, 0, 0, 0, 0, 0x43000, 0x41000)  # tuple: opcode 1, dst, src
        mem.put(0x43000, 0, 0, 7, 0, 0, 0, 5)                    # source #5
        self.model = ct.C2Model(mem.u32, mem.bytes, syms.get)

    def test_entry_and_exit(self):
        dec = ct.RegAssignDecoder()
        info, state = dec.entry(self.model, {}, [0, 0x41000, 0x42000])
        self.assertEqual(info["tmpreg"], "s162")
        self.assertEqual(info["tuple"], "1 s162 = #5")
        self.assertEqual(info["int_regs"], ["eax", "ecx", "edx", "esi"])
        self.assertEqual(info["next"], ["ecx", "edx", "esi"])
        self.assertEqual(info["conflicts"], ["ecx"])
        self.assertEqual(info["busy"], {"eax": "eax"})
        self.assertNotIn("pref", info)
        self.mem.put(self.tmp + 0x30, self.regsym + 0x60 * 3)   # preference set during the call
        out = dec.exit(self.model, {"eax": self.regsym + 0x60 * 3}, state)
        self.assertEqual(out, {"chosen": "edx", "pref_after": "edx"})
        line = ct.format_event({"break": "RegAssign", "function": "F", **info, **out})
        self.assertIn("RegAssign s162 [1 s162 = #5] pref=edx next=ecx,edx,esi", line)
        self.assertTrue(line.endswith("conflicts=ecx -> edx"))

    def test_colored_leaf_shows_its_register(self):
        self.assertEqual(self.model.leaf_text(0x41000), "s162")
        self.mem.put(0x41000 + 0x1C, self.regsym + 0x60 * 1)
        self.assertEqual(self.model.leaf_text(0x41000), "s162/eax")


class PresetTests(unittest.TestCase):
    def test_default_break_only_without_break_or_preset(self):
        self.assertEqual(ct.preset_breaks(None, "", []), ("ChoosePhysReg", ""))
        breaks, tuples = ct.preset_breaks(None, "", ["reload"])
        self.assertIn("RegAssign", breaks.split(","))
        self.assertNotIn("ChoosePhysReg", breaks.split(","))
        self.assertIn("Spill", tuples.split(","))
        breaks, tuples = ct.preset_breaks("Color", "Color", ["emit"])
        self.assertEqual(breaks.split(",")[:2], ["Color", "CgBottomUpOrder"])
        self.assertEqual(tuples, "Color")


def entry(name, *callees, node=True, init=False, recursive=()):
    out = {"name": name, "flags": 0, "node": node, "init": init, "callees": list(callees)}
    if recursive:
        out["recursive"] = list(recursive)
    return out


class EmitOrderTests(unittest.TestCase):
    def test_passes_hold_back_callers_of_later_callees(self):
        # t4.cpp: k1 -> k3 -> k5, all defined in order k1..k5.
        entries = [entry("k1", "k3"), entry("k2"), entry("k3", "k5", "ext"), entry("k4"), entry("k5")]
        self.assertEqual(ct.bottom_up_order(entries), ["k2", "k4", "k5", "k3", "k1"])
        self.assertEqual(ct.blocking_callees(entries), {"k1": ["k3"], "k3": ["k5"]})

    def test_recursive_arcs_do_not_block(self):
        # t5.cpp: q1 -> q2 -> q3 -> q1; the DFS from q3 flags q2 -> q3 recursive.
        entries = [entry("q1", "q2"), entry("qa"), entry("q2", recursive=["q3"]), entry("qb"),
                   entry("q3", "q1")]
        self.assertEqual(ct.bottom_up_order(entries), ["qa", "q2", "qb", "q1", "q3"])

    def test_entries_without_node_first_and_initializers_last(self):
        entries = [entry("a", "c"), entry("init", init=True), entry("nonode", node=False), entry("c")]
        self.assertEqual(ct.bottom_up_order(entries), ["nonode", "c", "a", "init"])

    def test_report_joins_trace_and_sections(self):
        events = [{"break": "CgBottomUpOrder", "entries": [entry("?a@@YAXXZ", "?b@@YAXXZ"), entry("?b@@YAXXZ")],
                   "entries_after": [{"name": "?b@@YAXXZ"}, {"name": "?a@@YAXXZ"}]},
                  {"break": "ReadFunction", "function": "?b@@YAXXZ"},
                  {"break": "ReadFunction", "function": "?a@@YAXXZ"}]
        sections = [{"number": 1, "name": ".text", "comdat": "?b@@YAXXZ", "selection": 1},
                    {"number": 2, "name": ".rdata", "comdat": "__real@3f800000", "selection": 2},
                    {"number": 3, "name": ".text$x", "comdat": "__unwindfunclet$?b@@YAXXZ$0", "selection": 5},
                    {"number": 4, "name": ".text", "comdat": "?a@@YAXXZ", "selection": 1}]
        report = ct.emit_order_report(events, sections)
        self.assertTrue(report["model_ok"])
        self.assertTrue(report["sections_ok"])
        self.assertEqual(report["code_sections"], ["?b@@YAXXZ", "?a@@YAXXZ"])
        self.assertEqual(report["blocked_by"], {"?a@@YAXXZ": ["?b@@YAXXZ"]})
        report = ct.emit_order_report(events[1:], list(reversed(sections)))
        self.assertIsNone(report["model_ok"])
        self.assertFalse(report["sections_ok"])

    def test_read_obj_sections_names_comdats(self):
        import tempfile

        def symbol(name, value, section, storage, aux):
            raw = name.encode().ljust(8, b"\0")
            return raw + struct.pack("<IhHBB", value, section, 0x20 if storage == 2 else 0, storage, aux)
        names = b"?long_function_name@@YAXXZ\0"
        sections = b""
        for name in (b".text", b".text$x"):
            sections += name.ljust(8, b"\0") + struct.pack("<IIIIIIHHI", 0, 0, 0, 0, 0, 0, 0, 0, 0x60501020)
        syms = symbol(".text", 0, 1, 3, 1) + struct.pack("<IHHIHBxxx", 0, 0, 0, 0, 0, 2)
        syms += b"\0\0\0\0" + struct.pack("<I", 4) + struct.pack("<IhHBB", 0, 1, 0x20, 2, 0)
        syms += symbol(".text$x", 0, 2, 3, 1) + struct.pack("<IHHIHBxxx", 0, 0, 0, 0, 1, 5)
        syms += symbol("$unw", 0, 2, 3, 0)
        table = 20 + len(sections)
        data = struct.pack("<HHIIIHH", 0x14C, 2, 0, table, 6, 0, 0) + sections + syms
        data += struct.pack("<I", 4 + len(names)) + names
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.obj"
            path.write_bytes(data)
            secs = ct.read_obj_sections(path)
        self.assertEqual([s["name"] for s in secs], [".text", ".text$x"])
        self.assertEqual((secs[0]["comdat"], secs[0]["selection"]), ("?long_function_name@@YAXXZ", 2))
        self.assertEqual((secs[1]["selection"], secs[1]["assoc"], secs[1]["comdat"]), (5, 1, "$unw"))


class IlModelTests(unittest.TestCase):
    def gl(self):
        import cl_trace
        sym = lambda kind, n, name, **attrs: cl_trace.GlSymbol(kind, n, name, attrs=attrs)
        symbols = [sym("data", 9, "??_7D@@6B@"), sym("function", 8, "ext@4"),
                   sym("definition", 1, "??1D@@UAE@XZ", fnflags=0x18C8, calls=[(9, 1)]),
                   sym("definition", 2, "?V@D@@UAEHXZ", fnflags=0x18C8, calls=[]),
                   sym("definition", 3, "??_GD@@UAEPAXI@Z", fnflags=0x18C8, calls=[(1, 1)]),
                   sym("definition", 4, "?unused@@YAHH@Z", fnflags=0x18C8, calls=[]),
                   sym("definition", 5, "f", fnflags=0x1068, calls=[(6, 1), (8, 1)]),
                   sym("definition", 6, "?st@@YAHH@Z", fnflags=0x1048, calls=[(6, 1), (1, 1)]),
                   sym("vector-dtor", 7, "??_ED@@UAEPAXI@Z", target=3)]
        return cl_trace.GlFile({}, [], [], symbols, {}, [])

    def test_gl_entries_names_refs_and_callees(self):
        entries, vec = ct.gl_entries(self.gl())
        self.assertEqual([e["name"] for e in entries][-2:], ["_f", "?st@@YAHH@Z"])
        self.assertEqual(entries[-2]["refs"], ["?st@@YAHH@Z", "_ext@4"])
        self.assertEqual(entries[-1]["callees"], ["?st@@YAHH@Z", "??1D@@UAE@XZ"])
        self.assertEqual(vec, {"??_ED@@UAEPAXI@Z": "??_GD@@UAEPAXI@Z"})

    def test_in_vtables_reads_address_items(self):
        import cl_trace
        data = (b"\x05\x07\x00" + cl_trace.encode_losh(9) + b"\x00\x02" + cl_trace.encode_losh(7) + b"\x00"
                + b"\x04\x02" + cl_trace.encode_losh(2) + b"\x00\x04\x07\x00c\x00")
        self.assertEqual(ct.in_vtables(data, self.gl()), {"??_7D@@6B@": ["??_ED@@UAEPAXI@Z", "?V@D@@UAEHXZ"]})

    def test_recursive_arcs_from_reverse_creation_order(self):
        entries = [entry("q1", "q2"), entry("q2", "q3"), entry("q3", "q1"), entry("s", "s")]
        arcs = {e["name"]: (e["callees"], e["recursive"]) for e in ct.recursive_arcs(entries)}
        self.assertEqual(arcs, {"q1": (["q2"], []), "q2": ([], ["q3"]), "q3": (["q1"], []), "s": ([], ["s"])})

    def test_needed_closure_and_vtable_slots(self):
        entries, vec = ct.gl_entries(self.gl())
        model = ct.emission_model(entries, vec, {"??_7D@@6B@": ["??_ED@@UAEPAXI@Z", "?V@D@@UAEHXZ"]})
        # f needs st (a static) needs ~D; ~D emits the vtable and its slots V and ??_G become
        # needed; they stand before st and f in the bottom-up list, so the rescan takes them next.
        self.assertEqual([m["name"] for m in model],
                         ["??1D@@UAE@XZ", "?V@D@@UAEHXZ", "??_GD@@UAEPAXI@Z", "?st@@YAHH@Z", "_f"])
        self.assertNotIn("?unused@@YAHH@Z", [m["name"] for m in model])
        self.assertEqual(ct.predicted_sections(model)[:2], ["??1D@@UAE@XZ", "??_7D@@6B@"])

    def test_static_initializer_function_refs_are_needed(self):
        entries, vec = ct.gl_entries(self.gl())
        model = ct.emission_model(entries, vec, {}, static_refs=["?unused@@YAHH@Z"])
        self.assertIn("?unused@@YAHH@Z", [m["name"] for m in model])

    def test_full_sections_places_eh_literals_and_statics(self):
        def sec(n, name, comdat=None, sel=2, assoc=0, relocs=(), fld1=()):
            s = {"number": n, "name": name, "relocs": list(relocs), "reloc_at": list(range(len(relocs))),
                 "fld1": list(fld1)}
            if comdat:
                s["comdat"] = comdat
            if sel:
                s["selection"] = sel
            if assoc:
                s["assoc"] = assoc
            return s
        obj = [sec(1, ".drectve", sel=None), sec(2, ".debug$S", sel=None),
               sec(3, ".rdata", "??_C@s"), sec(4, ".bss", sel=None),
               sec(5, ".data", sel=None, relocs=["??_C@s"]),
               sec(6, ".text", "?f", relocs=["__ehhandler$?f", "??_7A", "??_C@a", "__TI1"]),
               sec(7, ".text$x", "__unwindfunclet$?f$0", 5, 6),
               sec(8, ".xdata$x", "__TI1", relocs=["__CTA1"]),
               sec(9, ".rdata", "??_C@a"), sec(10, ".rdata", "??_7A"),
               sec(11, ".xdata$x", "__ehfuncinfo$?f", 5, 6, relocs=["??_R0"]),
               sec(12, ".data", "??_R0"), sec(13, ".xdata$x", "__CTA1", relocs=["__CT"]),
               sec(14, ".xdata$x", "__CT", relocs=["??_R0"]), sec(15, ".sxdata", sel=None),
               sec(16, ".debug$F", None, 5, 6),
               sec(17, ".text$yc", "??__Ex", fld1=[0]), sec(18, ".rdata", "__real@3f800000"),
               sec(19, ".debug$F", None, 5, 17), sec(20, ".CRT$XCU", sel=None)]
        report = ct.full_sections_report(["?f", "??__Ex"], obj)
        self.assertEqual(report["full_unplaced"], [])
        self.assertTrue(report["full_ok"], report["full_predicted"])
        obj[5]["relocs"] = ["__TI1", "??_C@a", "??_7A"]     # literals referenced in the other order
        self.assertFalse(ct.full_sections_report(["?f", "??__Ex"], obj)["full_ok"])

    def test_initializer_sort_and_atexit_destructors_last(self):
        # p4: d_b waits for `later`, s_obj for its ??__F; SsrSortInitializerEvalOrder moves the
        # initializers in .CRT$XCU order, and the ??__F left in the second list goes last.
        entries = [entry("Ea", init=True), entry("Eb", "later", init=True), entry("S0"),
                   entry("Es", "S0", "Fs", init=True), entry("Fs", init=True), entry("Ec", init=True),
                   entry("later"), entry("Ed", init=True), entry("use")]
        self.assertEqual(ct.bottom_up_order(entries, ["Ea", "Eb", "Es", "Ec", "Ed"]),
                         ["S0", "later", "use", "Ea", "Eb", "Es", "Ec", "Ed", "Fs"])
        self.assertEqual(ct.bottom_up_order(entries)[3:], ["Ea", "Fs", "Ec", "Ed", "Eb", "Es"])

    def test_initializer_order_from_in_records(self):
        import cl_trace
        sym = lambda kind, n, name, **attrs: cl_trace.GlSymbol(kind, n, name, attrs=attrs)
        gl = cl_trace.GlFile({}, [], [], [
            sym("definition", 1, "??__Ea@@YAXXZ", fnflags=0x184C), sym("definition", 2, "??__Eb@@YAXXZ", fnflags=0x184C),
            sym("data", 5, "b$initializer$", segment=9), sym("data", 4, "a$initializer$", segment=9)],
            {}, [], {9: ".CRT$XCU"})
        head = bytes([7, 0])
        item = lambda n, target: (head + cl_trace.encode_losh(n) + bytes([4, 2]) + cl_trace.encode_losh(target)
                                  + bytes([0, 4]))
        self.assertEqual(ct.initializer_order(item(4, 1) + item(5, 2), gl), ["??__Ea@@YAXXZ", "??__Eb@@YAXXZ"])

    def test_od_model_marks_needs_as_it_compiles(self):
        # p1 at /Od: no call lists; a static is compiled at the rescan after its caller, the
        # constructor's vtable slots before its other references, the initializer last.
        e = lambda name, flags: {"name": name, "fnflags": flags, "refs": [], "init": bool(flags & ct.GL_INIT)}
        entries = [e("~B", 0x8C8), e("VB", 0x8C8), e("GB", 0x8C8), e("~Q", 0x8C8), e("VQ", 0x8C8), e("GQ", 0x8C8),
                   e("make", 0x68), e("Q0", 0xDC8), e("B0", 0x8C8), e("helper", 0x48), e("h2", 0x68),
                   e("Edyn", 0x84C), e("user", 0x68)]
        refs = {"make": ["new", "Q0"], "Q0": ["B0", "vtQ"], "GQ": ["~Q", "delete"], "~Q": ["vtQ", "~B"],
                "~B": ["vtB"], "GB": ["~B"], "B0": ["vtB"], "h2": ["helper"], "Edyn": ["h2"]}
        vtables = {"vtQ": ["EQ", "VQ"], "vtB": ["EB", "VB"]}
        model = ct.emission_model(entries, {"EQ": "GQ", "EB": "GB"}, vtables, call_graph=False, code_refs=refs,
                                  init_order=["Edyn"])
        self.assertEqual([m["name"] for m in model],
                         ["make", "Q0", "VQ", "GQ", "~Q", "~B", "VB", "GB", "B0", "h2", "helper", "user", "Edyn"])

    def test_full_sections_delayed_bss_and_literal_rdata(self):
        def sec(n, name, comdat=None, relocs=(), symbols=None):
            s = {"number": n, "name": name, "relocs": list(relocs), "reloc_at": list(range(len(relocs))), "fld1": []}
            if comdat:
                s.update(comdat=comdat, selection=2)
            if symbols:
                s["symbols"] = symbols
            return s
        # /Od p1: the .bss holds only `dyn` (dynamically initialized): created at obj_end.
        obj = [sec(1, ".drectve"), sec(2, ".debug$S"), sec(3, ".data", symbols=["?fp"]), sec(4, ".text", "?h1"),
               sec(5, ".text$yc", "??__Edyn", relocs=["?h1", "?dyn"]), sec(6, ".bss", symbols=["?dyn"]),
               sec(7, ".CRT$XCU", relocs=["??__Edyn"])]
        self.assertTrue(ct.full_sections_report(["?h1", "??__Edyn"], obj, ["?dyn"])["full_ok"])
        self.assertFalse(ct.full_sections_report(["?h1", "??__Edyn"], obj)["full_ok"])
        # /Od p5e and p5b: string literals alone in a plain .rdata come after the plain sections,
        # or first when a static data initializer references one.
        obj = [sec(1, ".drectve"), sec(2, ".debug$S"), sec(3, ".bss", symbols=["?g_b"]),
               sec(4, ".data", symbols=["?g_d"]), sec(5, ".rdata", symbols=["$SG1"]), sec(6, ".text", "?f0"),
               sec(7, ".text", "?f", relocs=["$SG1"])]
        self.assertTrue(ct.full_sections_report(["?f0", "?f"], obj)["full_ok"])
        obj = [sec(1, ".drectve"), sec(2, ".debug$S"), sec(3, ".rdata", symbols=["$SG1"]),
               sec(4, ".bss", symbols=["?g_b"]), sec(5, ".data", relocs=["$SG1"], symbols=["?g_s"]),
               sec(6, ".text", "?f")]
        self.assertTrue(ct.full_sections_report(["?f"], obj)["full_ok"])

    def test_full_sections_zi_and_init_segments(self):
        def sec(n, name, comdat=None, relocs=(), symbols=None, assoc=0):
            s = {"number": n, "name": name, "relocs": list(relocs), "reloc_at": list(range(len(relocs))), "fld1": []}
            if comdat:
                s.update(comdat=comdat, selection=2)
            if assoc:
                s.update(selection=5, assoc=assoc)
            if symbols:
                s["symbols"] = symbols
            return s
        # /Zi probe f1: each function's .debug$S follows its .text, a static local's guard
        # COMDAT has its .debug$S after the plain sections, .debug$T is last; probe s_mix: the
        # initializer segments come in name order (#pragma init_seg(lib): .CRT$XCL first).
        obj = [sec(1, ".drectve"), sec(2, ".debug$S"), sec(3, ".text", "?f", relocs=["?$S1"]),
               sec(4, ".debug$S", assoc=3), sec(5, ".bss", "?$S1"), sec(6, ".text$yc", "??__Ed1"),
               sec(7, ".debug$S", assoc=6), sec(8, ".bss", symbols=["?d1", "?d0"]),
               sec(9, ".CRT$XCL", relocs=["??__Ed1"], symbols=["_d1$initializer$"]),
               sec(10, ".CRT$XCU", relocs=["??__Ed0"], symbols=["_d0$initializer$"]),
               sec(11, ".debug$S", assoc=5), sec(12, ".debug$T")]
        self.assertTrue(ct.full_sections_report(["?f", "??__Ed1"], obj, ["?d1", "?d0"])["full_ok"])
        obj[8]["name"], obj[9]["name"] = ".CRT$XCV", ".CRT$XCU"     # init_seg(".CRT$XCV") after the default
        self.assertFalse(ct.full_sections_report(["?f", "??__Ed1"], obj, ["?d1", "?d0"])["full_ok"])

    def test_folded_initializer(self):
        # /O2 p1: `int dyn = h1(3);` with h1 inlined: ??__Edyn is compiled, no section is emitted.
        model = [{"name": "?h1", "init": False}, {"name": "??__Edyn", "init": True}]
        self.assertEqual(ct.folded_initializers(model, [{"comdat": "?h1"}]), ["??__Edyn"])
        self.assertEqual(ct.folded_initializers(model, [{"comdat": "?h1"}, {"comdat": "??__Edyn"}]), [])

    def test_call_graph_flags(self):
        self.assertTrue(ct.call_graph_flags(["/O2", "/Gy"]))
        self.assertFalse(ct.call_graph_flags(["/O2", "/Od"]))
        self.assertFalse(ct.call_graph_flags(["/GS-"]))
        self.assertTrue(ct.call_graph_flags(["-O1"]))


if __name__ == "__main__":
    unittest.main()
