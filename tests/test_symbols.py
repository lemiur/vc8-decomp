"""PDB reader contract tests; fixtures contain invented records, no retail bytes."""

import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("symbols", Path(__file__).resolve().parents[1] / "tools/symbols.py")
symbols = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(symbols)


def public(name, offset=0, segment=1, flags=2):
    body = struct.pack("<HIIH", 0x110E, flags, offset, segment) + name.encode() + b"\0"
    return struct.pack("<H", len(body)) + body


def module(name, obj):
    result = bytearray(64)
    struct.pack_into("<H", result, 34, 0xFFFF)
    result += name.encode() + b"\0" + obj.encode() + b"\0"
    return bytes(result) + b"\0" * (-len(result) % 4)


def dbi(modules=b"", contributions=b"", age=1):
    result = bytearray(64)
    struct.pack_into("<iII", result, 0, -1, 19990903, age)
    struct.pack_into("<H", result, 20, 4)
    struct.pack_into("<ii", result, 24, len(modules), len(contributions))
    return bytes(result) + modules + contributions


def msf(streams):
    block_size = 512
    pages = [None, b"", b""]
    directory = bytearray(struct.pack("<I", len(streams)))
    directory += b"".join(struct.pack("<I", len(s) if s is not None else 0xFFFFFFFF) for s in streams)
    for stream in streams:
        if stream is None:
            continue
        for start in range(0, len(stream), block_size):
            directory += struct.pack("<I", len(pages))
            pages.append(stream[start:start + block_size])
    directory_blocks = []
    for start in range(0, len(directory), block_size):
        directory_blocks.append(len(pages))
        pages.append(directory[start:start + block_size])
    pages[2] = struct.pack("<" + "I" * len(directory_blocks), *directory_blocks)
    pages[0] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0" + struct.pack("<6I", block_size, 1, len(pages), len(directory), 0, 2)
    return b"".join(p.ljust(block_size, b"\0") for p in pages)


GUID = bytes(range(16))


def pe():
    result = bytearray(1024)
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, 0x80)
    result[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", result, 0x84, 0x14C, 1, 12345, 0, 0, 224, 0)
    struct.pack_into("<H", result, 0x98, 0x10B)
    struct.pack_into("<I", result, 0x98 + 28, 0x400000)
    struct.pack_into("<I", result, 0x98 + 92, 16)
    struct.pack_into("<II", result, 0x98 + 144, 0x1000, 28)
    struct.pack_into("<8sIIII", result, 0x178, b".text\0\0\0", 512, 0x1000, 512, 512)
    struct.pack_into("<IIHHIIII", result, 512, 0, 0, 0, 0, 2, 30, 0x1040, 576)
    result[576:606] = b"RSDS" + GUID + struct.pack("<I", 1) + b"x.pdb\0"
    return bytes(result)


def pdb(age=2, dbi_age=1, guid=GUID):
    info = struct.pack("<III", 20000404, 12345, age) + guid
    contributions = struct.pack("<IHHIIIHHII", 0xF12EBA2D, 1, 0, 128, 64, 0x20, 0, 0, 0, 0)
    return msf([b"", info, None, dbi(module("one.obj", "lib.lib"), contributions, dbi_age),
                public("alpha", 128) + public("alias", 128) + public("datum", 200, flags=0)])


class SymbolsTests(unittest.TestCase):
    def test_msf_empty_absent_and_multiblock_stream(self):
        reader = symbols.MSF(msf([b"", None, b"z" * 1200]))
        self.assertEqual(reader.stream(0), b"")
        self.assertEqual(reader.stream(2), b"z" * 1200)
        with self.assertRaises(symbols.SymbolError):
            reader.stream(1)

    def test_msf_rejects_truncation_and_bad_page(self):
        with self.assertRaises(symbols.SymbolError):
            symbols.MSF(msf([b"a"])[:-1])
        broken = bytearray(msf([b"a"]))
        struct.pack_into("<I", broken, 52, 99999)
        with self.assertRaises(symbols.SymbolError):
            symbols.MSF(broken)

    def test_public_names_aliases_flags_and_unknown_record(self):
        rows = symbols.read_publics(public("a") + struct.pack("<HH", 2, 0x9999) + public("alias"))
        self.assertEqual([r["name"] for r in rows], ["a", "alias"])
        self.assertEqual(rows[0]["flags"], 2)
        self.assertEqual(rows[1]["symbol_record_offset"], len(public("a")) + 4)

    def test_public_truncation_and_unterminated_name_rejected(self):
        for broken in (b"\x02", public("a")[:-1], public("a")[:-1] + b"x", b"\0\0\0\0"):
            with self.subTest(broken=broken), self.assertRaises(symbols.SymbolError):
                symbols.read_publics(broken)

    def test_module_inventory_and_contribution(self):
        result = symbols.read_dbi(symbols.MSF(pdb()).stream(3))
        self.assertEqual(result["modules"][0]["name"], "one.obj")
        self.assertEqual(result["modules"][0]["object_file"], "lib.lib")
        self.assertIsNone(result["modules"][0]["stream"])
        self.assertEqual(result["contributions"][0]["module_index"], 0)

    def test_invalid_contribution_module_rejected(self):
        contributions = struct.pack("<IHHIIIHHII", 0xF12EBA2D, 1, 0, 0, 10, 0, 1, 0, 0, 0)
        with self.assertRaises(symbols.SymbolError):
            symbols.read_dbi(dbi(module("only.obj", ""), contributions))

    def extract_fixture(self, pdb_data=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name)
        (path / "x.exe").write_bytes(pe())
        (path / "x.pdb").write_bytes(pdb() if pdb_data is None else pdb_data)
        return symbols.extract(path / "x.exe", path / "x.pdb")

    def test_extract_preserves_aliases_and_uncertain_lengths(self):
        result = self.extract_fixture()
        self.assertEqual(result["summary"]["functions"], 2)
        self.assertEqual(result["functions"][0]["rva"], 0x1080)
        self.assertEqual(result["functions"][0]["va"], 0x401080)
        self.assertEqual(result["functions"][0]["next_public_rva"], 0x10C8)
        self.assertIsNone(result["functions"][0]["size"])
        self.assertEqual(result["functions"][0]["module"], "one.obj")
        self.assertIsNone(result["data"][0]["module"])
        self.assertEqual(result["identity"]["age_verdict"], "stripped-public-info-age-plus-one")

    def test_identity_guid_dbi_age_info_age_rejected_independently(self):
        for bad in (pdb(guid=b"x" * 16), pdb(dbi_age=2), pdb(age=3), pdb(age=0)):
            with self.subTest(bad=bad[:32]), self.assertRaises(symbols.SymbolError):
                self.extract_fixture(bad)
        self.assertEqual(self.extract_fixture(pdb(age=1))["identity"]["age_verdict"], "exact")

    def test_pe_rva_and_pointer_must_agree(self):
        broken = bytearray(pe())
        struct.pack_into("<I", broken, 512 + 24, 577)
        with self.assertRaises(symbols.SymbolError):
            symbols.read_pe(broken)

    def test_outputs_roundtrip_and_no_fake_sizes(self):
        result = self.extract_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            symbols.write_map(result, temporary)
            path = Path(temporary)
            saved = json.loads((path / "x.symbols.json").read_text())
            self.assertIsNone(saved["functions"][0]["size"])
            self.assertIn("boundary_status", (path / "x.functions.tsv").read_text().splitlines()[0])
            self.assertTrue((path / "x.data.tsv").is_file())
            self.assertTrue((path / "x.modules.tsv").is_file())


if __name__ == "__main__":
    unittest.main()
