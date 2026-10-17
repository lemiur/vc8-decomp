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

# Blocks captured from the sy file of avp3's matching/platform_audio_streams.cpp (dx9 flags):
# StreamFile::Reset (one `this`, two temporaries, scopes 1-4), the scalar deleting destructor
# of a class (`__flags`, whose symbol-kind byte is 0x26), and an inline SSE helper whose
# unnamed temporaries are SSR 1A records with a two-byte kind (c8 81 / ca 81, __m64 / __m128).
RESET_SY = bytes.fromhex(
    "0303668302001e0001010301658302001f0001010d010101648302000074686973008603000304040001000d020d030d0406")
DTOR_SY = bytes.fromhex(
    "0302e3fc01001e0001010301e2fc01001f0001010d010101e0fc0100265f5f666c616773008602000304040001000101e1fc"
    "01000074686973008603000304040001000d0206")
SSE_SY = bytes.fromhex(
    "1a02eafa0100c8810d0800800088001a02e9fa0100c8810d0800800088001a02edfa0100ca810d1000800088001a02ecfa01"
    "00c8810d0800800088001a02ebfa0100ca810d1000800088001a02f0fa0100ca810d1000800088001a02effa0100c8810d08"
    "00800088001a02eefa0100ca810d1000800088000301e6fa01001f0001010d010101e4fa0100006100c8810d000304080081"
    "0088000d020102e8fa0100006578745f76616c00c8810d0001040800810088000102e7fa010000746d7000ca810d00010410"
    "008100880006")

# gl records captured from the same unit and from gui_pc.cpp (dx9): pragma-state records (SSR
# 18), a function declaration, g_mouse (kind c6 88: the record the old name scan missed),
# g_cameras (an array: size 0x570 and dimension 348 in the 0x80+u32 form), g_renderStates,
# the definition of StreamFile::Reset (ex and sy offsets, call list), the definition of
# Gui_InitPads (a callee called 0x9e times, in the 0x80+u16 form), and a trailer of a default
# library and a linker directive. The header is the unit's own with its trailer offset
# (bytes 21-24) rewritten for this shorter file.
GL_HEADER = bytes.fromhex("118603291832010704010001120100000e008027c6")
GL_RECORDS = bytes.fromhex(
    "18560d80ffff" "188005010080ffff" "04870a007374726e6c656e0086020a04000800"
    "0100ab9a0200003f675f6d6f757365404033564d6f75736540404100c688060002021400a1008000"
    "0200cf9c0200003f675f63616d6572617340403350415543616d6572614040410086060002028070050000002100805c010000"
    "0100bb9c0200003f675f72656e6465725374617465734040335652656e646572537461746543616368654040410086060002026000"
    "a1008000"
    "0e73820200003f52657365744053747265616d46696c65404051414558585a008207050014000080629a000080ce2200007668100101"
    "e40c01"
    "0e66ae0200003f4775695f496e6974506164734040594158585a0082070500000000808672010080194f000080080a6815000f4c0001"
    "4ff501000155f5010001a391020001a791020002a991020001b791020002c091020008d2910200010d9b0200012a9b020001d6ad0200"
    "0165ae0200809e00f7ae02000ef8ae020001")
GL_TRAILER = bytes.fromhex("0a000002") + b"\x04uuid.lib\x00" + b"\x0a/manifestdependency:x\x00"
# Probe p2 (/O2): the `__CT` throw record (flags 0xA3: the named-segment number 0x0A5D, `.xdata$x`, after
# the extra byte), the vtable `??_7W` it used to hide, an initializer pointer with its `dyninit` number,
# and the `__TI`/`__CTA` records. A segment number whose low byte is below 0x80 desynchronised the decoder.
THROW_GL = bytes.fromhex(
    "0100600a265f43543f3f5f52303f41555468726f776e40404038340086060002011ca0a300805d0a000200090a263f3f5f37"
    "57404036424000860600040108a021000401003c0a2464796e5f696e69745f76616c756524696e697469616c697a657224"
    "0086040002040480838000390a00210a01005c0a265f5449313f41555468726f776e404000860600020110a0a300805d0a00"
    "01005e0a265f435441313f41555468726f776e404000860600020108a0a300805d0a00")
SEGMENT_GL = bytes.fromhex("095d0a2e786461746124780004434f4e53540000000000")
GL_FILE = GL_HEADER + (len(GL_HEADER) + 4 + len(GL_RECORDS)).to_bytes(4, "little") + GL_RECORDS + GL_TRAILER

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

    def test_captured_blocks_decode_completely(self):
        blocks = t.parse_sy(RESET_SY + DTOR_SY + SSE_SY)
        self.assertEqual([b.offset for b in blocks], [0, len(RESET_SY), len(RESET_SY) + len(DTOR_SY)])
        self.assertEqual([b.unparsed for b in blocks], [[], [], []])
        reset, dtor, sse = blocks
        self.assertEqual([(r.kind, r.number, r.name) for r in reset.records],
                         [("temp", 66406, None), ("temp", 66405, None), ("param", 66404, "this")])
        self.assertEqual(reset.scopes, [1, 2, 3, 4])
        flags = next(r for r in dtor.records if r.name == "__flags")
        self.assertEqual((flags.kind, flags.number, flags.attrs["symkind"]), ("param", 64736, 0x26))
        anon = [r for r in sse.records if r.kind == "anon"]
        self.assertEqual(len(anon), 8)
        self.assertEqual((anon[0].attrs["class"], anon[0].attrs["class2"], anon[0].attrs["size"]), (0xC8, 0x81, 8))
        self.assertEqual({r.name: (r.kind, r.level, r.scope) for r in sse.records if r.name},
                         {"a": ("param", 1, 1), "ext_val": ("local", 2, 2), "tmp": ("local", 2, 2)})
        self.assertEqual(sse.records[-1].attrs["extra"], 0x88)

    def test_ssr_formats_cover_the_layouts(self):
        for tag in t.SSR_LAYOUTS:
            self.assertIn(tag, t.SSR_FORMATS)


class GlTests(unittest.TestCase):
    def test_throw_records_keep_the_next_record(self):
        records, unparsed = t.decode_records(THROW_GL)
        self.assertEqual(unparsed, [])
        self.assertEqual([(r.kind, r.fields["name"], r.fields["number"]) for r in records], [
            ("data", "_CT??_R0?AUThrown@@@84", 2656), ("array", "??_7W@@6B@", 2569),
            ("data", "dyn_init_value$initializer$", 2620), ("data", "_TI1?AUThrown@@", 2652),
            ("data", "_CTA1?AUThrown@@", 2654)])
        ct, _, init = (r.fields for r in records[:3])
        self.assertEqual((ct["flags"], ct["extra"], ct["segment"], ct["extra2"]), (0xA3, 0x80, 0x0A5D, 0))
        self.assertEqual((init["flags"], init["extra"], init["segment"], init["dyninit"]), (0x8083, 0, 0x0A39, 0x0A21))

    def test_od_definitions_have_no_call_list(self):
        # Probe p1 at /Od: the header's IL flags lack IL_CALL_GRAPH (0x112 -> 0x12) and each
        # definition record ends after `formals`.
        records = bytes.fromhex(
            "0eec09263f3f5f4742617365404055414550415849405a008603050434200080780b00004028c808020ef809003f3f31"
            "51404055414540585a008207050034000080510c00007e25c80d01")
        header = GL_HEADER[:12] + (0x12).to_bytes(4, "little") + GL_HEADER[16:]
        gl = t.parse_gl(header + (len(header) + 4 + len(records)).to_bytes(4, "little") + records)
        self.assertEqual(gl.unparsed, [])
        self.assertEqual([(s.name, s.attrs["sy_offset"], s.attrs["fnflags"], s.attrs["formals"], "calls" in s.attrs)
                          for s in gl.definitions()],
                         [("??_GBase@@UAEPAXI@Z", 0x40, 0x8C8, 2, False), ("??1Q@@UAE@XZ", 0x7E, 0xDC8, 1, False)])

    def test_segment_record(self):
        records, unparsed = t.decode_records(SEGMENT_GL + SEGMENT_GL)
        self.assertEqual(unparsed, [])
        self.assertEqual((records[0].kind, records[0].fields["number"], records[0].fields["name"],
                          records[0].fields["segattr"], records[0].fields["class"]),
                         ("segment", 0x0A5D, ".xdata$x", 4, "CONST"))
        data = (GL_HEADER + (len(GL_HEADER) + 4 + len(SEGMENT_GL + THROW_GL)).to_bytes(4, "little")
                + SEGMENT_GL + THROW_GL)
        gl = t.parse_gl(data)
        self.assertEqual((gl.unparsed, gl.segments), ([], {0x0A5D: ".xdata$x"}))
        self.assertIn(("??_7W@@6B@", 2569), t.scan_gl_names(data))

    def test_header(self):
        data = bytes.fromhex("1186032918320155 1b0100 0001".replace(" ", ""))
        self.assertEqual(t.parse_gl_header(data)["symbol_count"], 0x11B55)
        with self.assertRaises(t.TraceError):
            t.parse_gl_header(b"\x11\x86")

    def test_header_of_a_captured_file(self):
        info = t.parse_gl_header(GL_FILE)
        self.assertEqual((info["symbol_count"], info["il_flags"]), (66567, 0x112))
        self.assertEqual(info["trailer_offset"], len(GL_HEADER) + 4 + len(GL_RECORDS))

    def test_decoded_records(self):
        gl = t.parse_gl(GL_FILE)
        self.assertEqual(gl.unparsed, [])
        self.assertEqual([(s.kind, s.name, s.number) for s in gl.symbols], [
            ("function", "strnlen", 2695), ("data", "?g_mouse@@3VMouse@@A", 72363),
            ("array", "?g_cameras@@3PAUCamera@@A", 72911),
            ("data", "?g_renderStates@@3VRenderStateCache@@A", 72891),
            ("definition", "?Reset@StreamFile@@QAEXXZ", 66163), ("definition", "?Gui_InitPads@@YAXXZ", 77414)])
        mouse = gl.symbols[1]
        self.assertEqual((mouse.attrs["kind"], mouse.attrs["size"], mouse.attrs["flags"], mouse.attrs["extra"]),
                         ((0xC6, 0x88), 0x14, 0xA1, 0x80))
        self.assertEqual((gl.symbols[2].attrs["size"], gl.symbols[2].attrs["dim"]), (0x570, 348))
        reset = gl.symbols[4].attrs
        self.assertEqual((reset["ex_offset"], reset["sy_offset"], reset["formals"], reset["calls"]),
                         (0x9A62, 0x22CE, 1, [(0x0CE4, 1)]))
        pads = gl.symbols[5].attrs
        self.assertEqual(len(pads["calls"]), 15)
        self.assertIn((0x12E65, 0x9E), pads["calls"])
        self.assertEqual(gl.directives, [(4, "uuid.lib"), (0x0A, "/manifestdependency:x")])
        self.assertEqual(t.scan_gl_names(GL_FILE)[1], ("?g_mouse@@3VMouse@@A", 72363))

    def test_resync_reports_garbage(self):
        records, unparsed = t.decode_records(GL_RECORDS[:6] + b"\xff\xfe" + GL_RECORDS[6:])
        self.assertEqual(unparsed, [(6, "fffe")])
        self.assertEqual(len(records), 8)

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


class AttributionTests(unittest.TestCase):
    LISTED = """_this$ = -4\t\t\t\t\t\t; size = 4
?Reset@StreamFile@@QAEXXZ PROC\t\t\t\t; StreamFile::Reset, COMDAT
?Reset@StreamFile@@QAEXXZ ENDP\t\t\t\t; StreamFile::Reset
_result$66881 = 8\t\t\t\t\t\t; size = 4
___formal$ = 12\t\t\t\t\t\t; size = 4
?h@@YAXH@Z PROC\t\t\t\t\t\t; h
?h@@YAXH@Z ENDP\t\t\t\t\t\t; h
"""

    def test_definitions_pick_the_block(self):
        # The inline body (SMALL_SY) comes first and has no gl definition: it must not take
        # Reset's listing, as the old pairing in order did.
        blocks = t.parse_sy(SMALL_SY + RESET_SY)
        definitions = [t.GlSymbol("definition", 66163, "?Reset@StreamFile@@QAEXXZ",
                                  attrs={"sy_offset": len(SMALL_SY)})]
        functions = t.join_blocks(blocks, t.parse_listing(self.LISTED), definitions, [2539, 66163],
                                  [("?f@@YAHPAUR@@H@Z", 2539)])
        inline, reset = functions
        self.assertFalse(inline.compiled)
        self.assertIn("?f@@YAHPAUR@@H@Z", inline.name)
        self.assertEqual((reset.name, reset.decorated, reset.number, reset.compiled),
                         ("StreamFile::Reset", "?Reset@StreamFile@@QAEXXZ", 66163, True))
        this = next(r for r in reset.symbols if r["name"] == "this")
        self.assertEqual((this["number"], this["frame_offset"]), (66404, -4))

    def test_frame_check(self):
        listed = t.parse_listing(self.LISTED)[1]
        block = t.parse_sy(bytes.fromhex("0d01" "0101e909005f5f666f726d616c00860100030404000100" "06"))[0]
        (function,) = t.join_blocks([block], [listed], [t.GlSymbol("definition", 2538, "?h@@YAXH@Z",
                                                                      attrs={"sy_offset": 0})])
        self.assertEqual(function.symbols[0]["frame_offset"], 12)
        self.assertEqual(t.frame_mismatches(function, listed, total=66567), ([], ["result$66881"]))
        self.assertEqual(t.frame_mismatches(function, listed, total=None), (["result$66881"], []))


if __name__ == "__main__":
    unittest.main()
