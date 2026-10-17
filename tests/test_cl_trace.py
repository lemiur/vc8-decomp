"""Parser contracts of tools/cl_trace.py; none of these tests runs cl.exe."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import cl_trace as t  # noqa: E402

# sy file kept with /Bk for:
#   struct R { int x, y; }; int g(R*);
#   int f(R* p, int n) { R rect = *p; int k = n; if (n) { R inner = rect; k += g(&inner); } return g(&rect) + k; }
# /FAs listed `_inner$2544`; the numbers below were checked against that listing.
SMALL_SY = bytes.fromhex(
    "0303ef091e000101" "0301ec091f000201" "0d01" "0101ea09006e00860100030404000100"
    "0101e909007000860300030404000100" "0d020102ed0900726563740086060001040800a1008000"
    "0102ee09006b00860100010404000100" "0d030d040d050105f00900696e6e65720086060001040800a1008000" "06")

# Same shape after 70000 globals: numbers past 0x7fff use the long losh form.
BIG_SY = bytes.fromhex(
    "0303539b02001e000101" "0301529b02001f000201" "0d01" "0101509b0200006e00860100030404000100"
    "0d020d030d040d050105549b02000070726f6265008601000104040021" "0006")

# An array record (tag 02) carries one trailing byte; flags 0x80 adds a losh.
ARRAY_SY = bytes.fromhex("0d010202030a00617272008606000104100021000401020" "40a00640086060001040400210006")

BD_OUTPUT = """a.cpp
`C:\\VC\\bin\\c1xx.dll -zm0xFCCA0000 -il C:\\Temp\\_CL_6231ce72 -f a.cpp -W 1 -Ze -Foa.obj -Bd -D_MT'
`C:\\VC\\bin\\c2.dll -il C:\\Temp\\_CL_6231ce72 -f a.cpp -W 1 -Gs4096 -dos -Foa.obj -Og -Ob2 -Gy -Bd -MT'
"""

LISTING = """_TEXT\tSEGMENT
_inner$2544 = -16\t\t\t\t\t; size = 8
_rect$ = -8\t\t\t\t\t\t; size = 8
_p$ = 8\t\t\t\t\t\t\t; size = 4
_n$ = 12\t\t\t\t\t\t; size = 4
?f@@YAHPAUR@@H@Z PROC\t\t\t\t\t; f, COMDAT
\tmov\teax, DWORD PTR _p$[esp+12]
?f@@YAHPAUR@@H@Z ENDP\t\t\t\t\t; f
EXTRN\t?g@@YAHPAUR@@@Z:PROC\t\t\t\t; g
__$EHRec$ = -12\t\t\t\t\t\t; size = 12
_x$ = 8\t\t\t\t\t\t\t; size = 4
?h@@YAXH@Z PROC\t\t\t\t\t\t; h
?h@@YAXH@Z ENDP\t\t\t\t\t\t; h
"""


class LoshTests(unittest.TestCase):
    def test_short_and_long_forms(self):
        self.assertEqual(t.read_losh(bytes.fromhex("e909"), 0), (2537, 2))
        self.assertEqual(t.read_losh(bytes.fromhex("549b0200"), 0), (72532, 4))

    def test_round_trip(self):
        for value in (0, 1, 0x7FFF, 0x8000, 72532, 82282, 0x3FFFFFFF):
            data = t.encode_losh(value)
            self.assertEqual(t.read_losh(data, 0), (value, len(data)))

    def test_truncated(self):
        with self.assertRaises(t.TraceError):
            t.read_losh(b"\x01", 0)
        with self.assertRaises(t.TraceError):
            t.read_losh(bytes.fromhex("0080"), 0)


class SyTests(unittest.TestCase):
    def test_small_function(self):
        blocks = t.parse_sy(SMALL_SY)
        self.assertEqual(len(blocks), 1)
        block = blocks[0]
        self.assertEqual(block.unparsed, [])
        named = {r.name: (r.number, r.kind, r.level) for r in block.records if r.name}
        self.assertEqual(named, {"n": (2538, "param", 1), "p": (2537, "param", 1), "rect": (2541, "local", 2),
                                 "k": (2542, "local", 2), "inner": (2544, "local", 5)})
        temps = sorted(r.number for r in block.records if r.kind == "temp")
        self.assertEqual(temps, [2540, 2543])
        rect = next(r for r in block.records if r.name == "rect")
        self.assertEqual((rect.attrs["size"], rect.attrs["flags"], rect.attrs["extra"]), (8, 0xA1, 0x80))

    def test_long_numbers(self):
        blocks = t.parse_sy(BIG_SY)
        self.assertEqual(len(blocks), 1)
        named = {r.name: r.number for r in blocks[0].records if r.name}
        self.assertEqual(named, {"n": 72528, "probe": 72532})
        self.assertEqual(sorted(r.number for r in blocks[0].records if r.kind == "temp"), [72530, 72531])

    def test_array_record(self):
        block = t.parse_sy(ARRAY_SY)[0]
        arr = next(r for r in block.records if r.name == "arr")
        self.assertEqual((arr.kind, arr.number, arr.attrs["size"], arr.attrs["dim"]), ("array", 2563, 16, 4))
        self.assertEqual(next(r for r in block.records if r.name == "d").number, 2564)

    def test_two_functions_and_resync(self):
        data = SMALL_SY + b"\x77\x77" + SMALL_SY
        blocks = t.parse_sy(data)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[1].unparsed, [(len(SMALL_SY), "7777")])
        self.assertEqual(blocks[1].numbers(), blocks[0].numbers())


class GlTests(unittest.TestCase):
    def test_header(self):
        data = bytes.fromhex("1186032918320155 1b0100 0001".replace(" ", ""))
        self.assertEqual(t.parse_gl_header(data)["symbol_count"], 0x11B55)
        with self.assertRaises(t.TraceError):
            t.parse_gl_header(b"\x11\x86")

    def test_named_records(self):
        # Captured from a gui unit's gl file: long and short losh numbers before the name.
        data = (bytes.fromhex("0100b09c020000") + b"?g_renderStates@@3VRenderStateCache@@A\x00\x86\x06"
                + bytes.fromhex("01eb0900") + b"?f@@YAXXZ\x00\x82\x02")
        self.assertEqual(t.scan_gl_names(data), [("?g_renderStates@@3VRenderStateCache@@A", 72880),
                                                 ("?f@@YAXXZ", 2539)])

    def test_strings(self):
        self.assertEqual(t.il_strings(b"\x01\x02rect\x00ab\x00?f@@YAXXZ\x00"), ["rect", "?f@@YAXXZ"])


class DriverTests(unittest.TestCase):
    def test_pass_lines(self):
        passes = t.parse_pass_lines(BD_OUTPUT)
        self.assertEqual([p.name for p in passes], ["c1xx", "c2"])
        self.assertEqual(passes[0].il, "C:\\Temp\\_CL_6231ce72")
        self.assertEqual(passes[1].argv[-1], "-MT")
        self.assertIn("-Ob2", passes[1].argv)

    def test_split_flags(self):
        self.assertEqual(t.split_flags('/O2 "/Ic:\\a b" /GR-'), ["/O2", "/Ic:\\a b", "/GR-"])
        self.assertEqual(t.split_flags(""), [])

    def test_compile_args(self):
        args = t.compile_args("/O2 /GR-", ["inc"], "x.cpp")
        self.assertEqual(args[:4], ["/nologo", "/c", "/O2", "/GR-"])
        self.assertEqual(args[4], "/Iinc")
        self.assertTrue(args[-1].endswith("x.cpp"))

    def test_file_lifetimes(self):
        events = [{"t_ms": 1.0, "action": "create", "file": "_CL_1ex", "size": 0},
                  {"t_ms": 2.0, "action": "modify", "file": "_CL_1ex", "size": 300},
                  {"t_ms": 9.0, "action": "delete", "file": "_CL_1ex", "size": None}]
        (item,) = t.file_lifetimes(events)
        self.assertEqual((item["created_ms"], item["deleted_ms"], item["max_size"], item["events"]), (1.0, 9.0, 300, 3))


class ListingTests(unittest.TestCase):
    def test_frames(self):
        functions = t.parse_listing(LISTING)
        self.assertEqual([f.name for f in functions], ["f", "h"])
        f = functions[0]
        self.assertEqual(f.decorated, "?f@@YAHPAUR@@H@Z")
        self.assertEqual([(l.name, l.number, l.offset, l.size) for l in f.frame],
                         [("inner", 2544, -16, 8), ("rect", None, -8, 8), ("p", None, 8, 4), ("n", None, 12, 4)])
        self.assertEqual([l.name for l in functions[1].frame], ["_$EHRec", "x"])

    def test_join(self):
        functions = t.join_blocks(t.parse_sy(SMALL_SY), t.parse_listing(LISTING))
        self.assertEqual(len(functions), 1)
        f = functions[0]
        self.assertEqual(f.name, "f")
        inner = next(r for r in f.symbols if r["name"] == "inner")
        self.assertEqual((inner["number"], inner["mod64"], inner["listing_suffix"], inner["frame_offset"]),
                         (2544, 2544 % 64, 2544, -16))
        self.assertEqual([r["number"] for r in f.symbols], sorted(r["number"] for r in f.symbols))


if __name__ == "__main__":
    unittest.main()
