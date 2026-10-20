"""c2_inline_trace decoding and call-site assembly contracts (no debugger, no cl.exe)."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import c2_inline_trace as it
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


def model(mem, symbols=None):
    symbols = symbols or {}
    return ct.C2Model(mem.u32, mem.bytes, lambda name: symbols.get(name))


def ev(seq, name, tuple_=None, function="?caller@@YAHH@Z", tid=1, **fields):
    out = {"seq": seq, "break": name, "function": function, "tid": tid, "depth": 0}
    if tuple_ is not None:
        out["tuple"] = tuple_
    out.update(fields)
    return out


class Layouts(unittest.TestCase):
    def test_callee_of_tuple_direct_entry_leaf(self):
        mem = FakeMemory()
        mem.put(0x1000 + 0x28, 0x2000)          # call tuple -> source leaf
        mem.put(0x2000 + 8, 4)                  # leaf kind 4: entry at +0x18
        mem.put(0x2000 + 0x18, 0x3000)
        self.assertEqual(it.callee_of_tuple(mem.u32, 0x1000), 0x3000)

    def test_callee_of_tuple_through_symbol(self):
        mem = FakeMemory()
        mem.put(0x1000 + 0x28, 0x2000)
        mem.put(0x2000 + 8, 3)
        mem.put(0x2000 + 0x18, 0x4000)          # symbol
        mem.put(0x4000 + 8, 0x5000)             # -> +8 -> +0 = entry
        mem.put(0x5000, 0x3000)
        self.assertEqual(it.callee_of_tuple(mem.u32, 0x1000), 0x3000)
        self.assertEqual(it.callee_of_tuple(mem.u32, 0), 0)

    def test_entry_info_flags_and_size(self):
        mem = FakeMemory()
        mem.put(0x3000 + 4, 0x6000)
        mem.raw[0x6000] = b"?force@@YAHH@Z\0"
        mem.put(0x3000 + 0x50, 0x38EA)
        mem.put(0x3000 + 0x54, 0xAAAA0019)      # word: 25
        info = it.entry_info(model(mem), 0x3000)
        self.assertEqual(info["callee"], "?force@@YAHH@Z")
        self.assertEqual(info["callee_size"], 25)
        self.assertEqual(info["callee_traits"], ["compiled", "inlinable", "inline", "forceinline"])

    def test_consts_named_from_usr_settings(self):
        mem = FakeMemory()
        values = [9, 74, 30] + [0] * 42
        mem.put(0x7000, *values)
        consts = it.read_consts(model(mem, {"_InlCurConsts": 0x7000}))
        self.assertEqual((consts["SizeLimit"], consts["SpeedLimit"], consts["FoldCmpSpeedWeight"]), (9, 74, 30))
        self.assertEqual(len(consts), it.CONST_COUNT)

    def test_benefit_record(self):
        mem = FakeMemory()
        mem.put(0x8000, 7, 1, 6, 0, 0, 0, 1, 0)
        got = it._benefit(model(mem), 0x8000)
        self.assertEqual((got["credit"], got["fold_cmps"], got["arg_cost"], got["const_args"]), (7, 1, 6, 1))

    def test_probes_are_inside_the_routine(self):
        offsets = [offset for _, offset, _, _ in it.PROBES]
        self.assertEqual(offsets, sorted(offsets))
        self.assertTrue(all(0 < o < 0x590 for o in offsets))   # InlCallGraphDecision is 0x590 bytes
        self.assertNotIn(0xD3, offsets)                          # InlBenefit's return address


class Sites(unittest.TestCase):
    def test_accepted_by_speed_ratio_with_probes(self):
        events = [
            ev(1, "InlCallTupleIsCandidate", "0x00000100", ret=1, callee="?f@@YAHH@Z", callee_size=73,
               callee_traits=["compiled", "inlinable"]),
            ev(2, "ShouldInlineCallTuple", "0x00000100", depth=1, depth_limit=0xFE, budget=1000, ret=1),
            ev(3, "InlCallGraphDecision", "0x00000100", cg_size=58, ret=1),
            ev(4, "probe:limit", size=58),
            ev(5, "probe:speed_small", cost=15, limit=14),
            ev(6, "probe:speed_ratio", weighted=14, limit=74),
            ev(7, "ShouldInlineInlinee", "0x00000100", ret=1),
            ev(8, "InlineInlinee", "0x00000100", ret=1),
        ]
        site, = it.build_sites(events)
        self.assertEqual(site["decision"], "inlined")
        self.assertEqual(site["rule"], "speed: weighted cost 14 < SpeedLimit 74")
        self.assertEqual(site["numbers"]["limit.size"], 58)
        self.assertEqual(site["depth"], 1)

    def test_refused_by_speed_ratio(self):
        events = [
            ev(1, "InlCallTupleIsCandidate", "0x200", ret=1, callee="?g@@YAHH@Z", callee_traits=["inlinable"]),
            ev(2, "ShouldInlineCallTuple", "0x200", depth=2, depth_limit=0xFE, ret=0),
            ev(3, "InlCallGraphDecision", "0x200", ret=0),
            ev(4, "probe:speed_cap", cost=71, cap=450),
            ev(5, "probe:speed_small", cost=71, limit=14),
            ev(6, "probe:speed_ratio", weighted=85, limit=74),
        ]
        site, = it.build_sites(events)
        self.assertEqual(site["decision"], "not-inlined")
        self.assertIn("weighted cost 85 >= SpeedLimit 74", site["rule"])

    def test_cap_and_not_inlinable_and_recursion(self):
        events = [
            ev(1, "InlCallTupleIsCandidate", "0x1", ret=0, callee="?n@@YAHH@Z", callee_traits=["compiled"]),
            ev(2, "InlCallTupleIsCandidate", "0x2", ret=0, callee="?r@@YAHH@Z",
               callee_traits=["compiled", "on-inline-stack", "inlinable"]),
            ev(3, "InlCallTupleIsCandidate", "0x3", ret=1, callee="?b@@YAHH@Z", callee_traits=["inlinable"]),
            ev(4, "ShouldInlineCallTuple", "0x3", depth=1, depth_limit=0xFE, ret=0),
            ev(5, "InlCallGraphDecision", "0x3", ret=0),
            ev(6, "probe:speed_cap", cost=519, cap=450),
        ]
        sites = it.build_sites(events)
        self.assertTrue(sites[0]["rule"].startswith("not-inlinable"))
        self.assertTrue(sites[1]["rule"].startswith("recursion"))
        self.assertEqual(sites[2]["rule"], "speed: cost 519 > 450 (InlCallGraphDecision)")

    def test_forceinline_and_depth(self):
        events = [
            ev(1, "InlCallTupleIsCandidate", "0x1", ret=1, callee="?f@@YAHH@Z",
               callee_traits=["inlinable", "inline", "forceinline"]),
            ev(2, "ShouldInlineCallTuple", "0x1", depth=1, depth_limit=0xFE, ret=1),
            ev(3, "InlineInlinee", "0x1", ret=1),
            ev(4, "InlCallTupleIsCandidate", "0x2", ret=1, callee="?d@@YAHH@Z", callee_traits=["inlinable"]),
            ev(5, "ShouldInlineCallTuple", "0x2", depth=9, depth_limit=8, ret=0),
        ]
        sites = it.build_sites(events)
        self.assertTrue(sites[0]["rule"].startswith("forceinline"))
        self.assertEqual(sites[1]["rule"], "depth 9 > inline_depth 8 (ShouldInlineCallTuple)")

    def test_same_tuple_in_two_functions_are_two_sites(self):
        events = [
            ev(1, "InlCallTupleIsCandidate", "0x1", function="A", ret=0, callee_traits=[]),
            ev(2, "InlCallTupleIsCandidate", "0x1", function="B", ret=0, callee_traits=[]),
        ]
        self.assertEqual([s["caller"] for s in it.build_sites(events)], ["A", "B"])

    def test_format_sites(self):
        lines = it.format_sites([{"caller": "c", "callee": "f", "depth": 1, "callee_size": 3,
                                  "decision": "inlined", "rule": "x"}])
        self.assertEqual(len(lines), 1)
        self.assertIn("inlined", lines[0])


class LinkMode(unittest.TestCase):
    def test_raw_gate_decoder_names_the_entry_of_the_context(self):
        mem = FakeMemory()
        mem.put(0x60000, 0x70000)
        mem.put(0x70000 + it.ENTRY_NAME, 0x71000)
        mem.raw[0x71000] = b"?f@@YAXH@Z\0"
        info, _ = it.RawConvGateDecoder().entry(model(mem), {"ecx": 0x60000}, [0] * 8)
        self.assertEqual(info["entry_name"], "?f@@YAXH@Z")
        self.assertEqual(it.RawConvGateDecoder().exit(model(mem), {"eax": 0xFFFFFFFF}, None), {"ret": -1})

    def _function(self, mem):
        """Context 0x60000 -> entry 0x70000; tuple list: a kind-5 tuple, then the kind-0x18 tuple whose
        formals are `this` (sym 0x82000) and `n` (sym 0x83000)."""
        mem.put(0x60000, 0x70000, 0, 0x61000)
        mem.put(0x61000, 0x62000)
        mem.put(0x62000 + 0x1C, 0x63000)
        mem.put(0x63000, 0x64000)
        mem.raw[0x63008] = b"\x05"
        mem.raw[0x64008] = b"\x18"
        mem.put(0x64000 + 0x24, 0x65000)
        for leaf, sym, nxt, name, typ in ((0x65000, 0x82000, 0x66000, b"_this", 0x1004),
                                          (0x66000, 0x83000, 0, b"_n", 0x2004)):
            mem.put(leaf, nxt)
            mem.raw[leaf + 8] = b"\x01"
            mem.raw[leaf + 0xA] = struct.pack("<H", typ)
            mem.put(leaf + 0x18, sym)
            mem.put(sym + 8, sym)
            mem.put(sym, sym + 0x100)
            mem.put(sym + 0x104, sym + 0x200)
            mem.raw[sym + 0x200] = name + b"\0"
        mem.put(0x70000 + it.ENTRY_NAME, 0x71000)
        mem.raw[0x71000] = b"?f@C@@QAEXH@Z\0"

    def test_dead_map_and_flex_decoders(self):
        mem = FakeMemory()
        self._function(mem)
        info, state = it.DeadMapDecoder().entry(model(mem), {}, [0, 0x60000])
        self.assertEqual([f["name"] for f in info["formals"]], ["_this", "_n"])
        self.assertEqual(info["formals"][1]["size"], 4)
        mem.put(0x70000 + it.ENTRY_DEAD, 0xFFFFFFFB)
        self.assertEqual(it.DeadMapDecoder().exit(model(mem), {}, state), {"dead_map": 0xFFFFFFFB})
        mem.put(0x70000 + it.ENTRY_FLEX, 1 | 4 << 1)          # parameter 0 in map[4]
        mem.put(0x70000 + it.ENTRY_CONV, 0x14)
        _, state = it.FlexDecoder().entry(model(mem), {}, [0, 0x60000])
        out = it.FlexDecoder().exit(model(mem), {}, state)
        self.assertEqual(out["conv"], 0x14)
        self.assertEqual(out["flex"], 9)

    def test_build_conventions(self):
        this = {"name": "_this", "type": "0x1004", "size": 4, "sym": 1, "base": 1}
        n = {"name": "_n", "type": "0x2004", "size": 4, "sym": 2, "base": 2}
        k = {"name": "_k", "type": "0x2004", "size": 4, "sym": 3, "base": 3}
        f = "?f@C@@QAEXHH@Z"
        events = [
            {"break": "MdmAllowFlexParams", "entry_name": f, "ret": 1},
            {"break": "MscSetDeadParamMap", "entry_name": f, "hidden": False, "formals": [this, n, k],
             "dead_map": 0xFFFFFFFF & ~(1 << 2)},                  # parameter number 2 (_n) dead
            {"break": "WpaGenConstParamInfoUse", "entry_name": f, "after": [
                {"number": 2, "kind": 1, "value": 7}, {"number": 0xFF, "kind": 1, "value": 1}]},
            {"break": "MdmFlexParams", "entry_name": f, "flex": 1 | 4 << 1 | 3 << 4, "flex_xmm": 0,
             "conv": 0x14, "stack_bytes": 0, "hidden": False, "formals": [this, k],
             "flex_map": [None, "eax", "ecx", "edx", "esi", "edi", "ebp", "ebx"]},
            {"break": "MdmAllowFlexParams", "entry_name": "?g@@YAXH@Z", "ret": 0, "globopt": 1, "wvm_safe": 0,
             "flags20": 0x2000, "flags50": 0},
            {"break": "MdmFlexParams", "entry_name": "?g@@YAXH@Z", "flex": 0, "conv": 0x10, "stack_bytes": 4,
             "formals": [n]},
        ]
        sites = [{"callee": f, "decision": "not-inlined"}, {"callee": "?g@@YAXH@Z", "decision": "inlined"}]
        conv = {c["function"]: c for c in it.build_conventions(events, sites)}
        rec = conv[f]
        self.assertTrue(rec["custom"])
        self.assertEqual([p["location"] for p in rec["params"]], ["ESI", "removed", "EDX"])
        self.assertEqual(rec["params"][1]["const"], {"value": 7, "kind": "int"})
        self.assertEqual(rec["ret_pop"], 0)
        g = conv["?g@@YAXH@Z"]
        self.assertFalse(g["custom"])
        self.assertIn("0x2000", g["refused"])
        self.assertEqual(g["ret_pop"], 4)
        self.assertEqual(g["params"][0]["location"], "stack")
        self.assertTrue(it.function_status("?g@@YAXH@Z", list(conv.values()), sites).startswith(
            "inlined everywhere: no convention"))
        self.assertTrue(it.function_status(f, list(conv.values()), sites).startswith("out of line"))
        self.assertEqual(len(it.format_conventions(list(conv.values()))), 1)

    def test_source_and_link_rsp_are_exclusive(self):
        with self.assertRaises(SystemExit):
            it.main(["--out", "x.jsonl"])
        with self.assertRaises(SystemExit):
            it.main(["--out", "x.jsonl", "--source", "a.cpp", "--link-rsp", "a.rsp"])

    def test_ltcg_breaks_resolve_in_the_pinned_c2(self):
        cache = Path(__file__).resolve().parents[1] / "build/c2-trace/c2-publics.json"
        if not cache.is_file():
            self.skipTest("no c2 symbol cache")
        import json
        table = ct.symbol_table(json.loads(cache.read_text(encoding="utf-8"))["rows"])
        for name in it.LTCG_BREAKS + it.CONV_BREAKS:
            self.assertTrue(ct.resolve_name(name, table)[1])


if __name__ == "__main__":
    unittest.main()
