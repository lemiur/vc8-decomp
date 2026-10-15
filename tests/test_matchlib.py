"""Contract tests use synthetic PE inputs; no Microsoft bytes are checked in."""
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from matchlib import (IdentityError, OrderedReference, PEError, PEImage, Retail,
                      load_binary_config, load_config, ordered_referents,
                      resolve_referent, sha256_of)


def image_bytes():
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHI", data, 0x84, 0x14C, 1, 123)
    struct.pack_into("<H", data, 0x94, 224)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<II", data, opt + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, opt + 92, 16)
    data[0x178:0x180] = b".text\0\0\0"
    struct.pack_into("<IIII", data, 0x180, 0x600, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", data, 0x19C, 0x60000020)
    data[0x200:0x204] = b"CODE"
    return data


def directory(data, index, rva, size):
    struct.pack_into("<II", data, 0x98 + 96 + index * 8, rva, size)


class PEContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "candidate.dll"

    def image(self, data=None, retail=False):
        self.path.write_bytes(data if data is not None else image_bytes())
        return Retail({"path": str(self.path)}) if retail else PEImage(self.path)

    def test_round_trip_va_rva_raw_and_headers(self):
        image = self.image()
        self.assertEqual(image.read_va(0x401000, 4), b"CODE")
        self.assertEqual(image.va_to_rva(0x401002), 0x1002)
        self.assertEqual(image.rva_to_va(0x1002), 0x401002)
        self.assertEqual(image.offset_of(0x401002), 0x202)
        self.assertEqual(image.offset_to_va(0x202), 0x401002)
        self.assertEqual(image.offset_to_rva(0x202), 0x1002)
        self.assertEqual(image.read_va(0x400000, 2), b"MZ")
        self.assertEqual(image.sha256(), sha256_of(self.path))

    def test_virtual_tail_gap_and_cross_boundary_rejected(self):
        image = self.image()
        for va, size in [(0x401400, 1), (0x400300, 1), (0x4013FF, 2),
                         (0x4001FF, 2), (0x3FFFFF, 1), (0x402000, 1)]:
            with self.subTest(va=va, size=size), self.assertRaises(PEError):
                image.read_va(va, size)
        with self.assertRaises(PEError):
            image.offset_to_rva(0x600)

    def test_missing_signatures_truncation_and_architecture_rejected(self):
        for mutation in (lambda d: d.__setitem__(slice(0, 2), b"XX"),
                         lambda d: d.__setitem__(slice(0x80, 0x84), b"NOPE"),
                         lambda d: struct.pack_into("<H", d, 0x84, 0x8664),
                         lambda d: struct.pack_into("<H", d, 0x98, 0x20B),
                         lambda d: struct.pack_into("<I", d, 0x98 + 92, 17)):
            data = image_bytes()
            mutation(data)
            with self.assertRaises(PEError):
                self.image(data)
        with self.assertRaises(PEError):
            self.image(image_bytes()[:128])

    def test_overlapping_sections_rejected(self):
        for rva, raw in [(0x1000, 0x500), (0x1600, 0x200)]:
            data = image_bytes()
            struct.pack_into("<H", data, 0x86, 2)
            struct.pack_into("<IIII", data, 0x1A8, 0x100, rva, 0x100, raw)
            with self.subTest(rva=rva, raw=raw), self.assertRaisesRegex(PEError, "overlapping"):
                self.image(data)

    def test_rsds_guid_byte_order_and_raw_rva_agreement(self):
        data = image_bytes()
        directory(data, 6, 0x1100, 28)
        blob = b"RSDS" + uuid.UUID("720089f2-f35a-4a12-8093-e654daca5226").bytes_le
        blob += struct.pack("<I", 2) + b"pilot.pdb\0"
        struct.pack_into("<IIII", data, 0x300 + 12, 2, len(blob), 0x1140, 0x340)
        data[0x340:0x340 + len(blob)] = blob
        self.assertEqual(self.image(data).pdb,
                         dict(guid="720089F2F35A4A128093E654DACA5226", age=2, path="pilot.pdb"))
        struct.pack_into("<I", data, 0x300 + 20, 0x1141)
        with self.assertRaisesRegex(PEError, "disagree"):
            self.image(data).pdb

    def test_relocations_order_types_and_bad_blocks(self):
        data = image_bytes()
        directory(data, 5, 0x1100, 16)
        struct.pack_into("<IIHHHH", data, 0x300, 0x1000, 16, 0x3020, 0x1010, 0, 0xF030)
        records = self.image(data).base_relocations()
        self.assertEqual([x["rva"] for x in records], [0x1010, 0x1020, 0x1030])
        self.assertEqual([x["type"] for x in records], [1, 3, 15])
        self.assertIsNone(records[2]["width"])
        self.assertEqual(self.image(data).relocs, [0x401020])
        struct.pack_into("<I", data, 0x304, 7)
        with self.assertRaisesRegex(PEError, "invalid base"):
            self.image(data).base_relocations()

    def test_duplicate_relocation_rejected(self):
        data = image_bytes()
        directory(data, 5, 0x1100, 12)
        struct.pack_into("<IIHH", data, 0x300, 0x1000, 12, 0x3020, 0x3020)
        with self.assertRaisesRegex(PEError, "duplicate"):
            self.image(data).base_relocations()

    def test_named_and_ordinal_imports(self):
        data = image_bytes()
        directory(data, 1, 0x1100, 40)
        struct.pack_into("<IIIII", data, 0x300, 0x1140, 0, 0, 0x1180, 0x1160)
        struct.pack_into("<III", data, 0x340, 0x11A0, 0x80000005, 0)
        data[0x380:0x38D] = b"KERNEL32.dll\0"
        data[0x3A0:0x3A7] = b"\0\0Exit\0"
        imports = self.image(data).import_records()
        self.assertEqual([x["identity"] for x in imports], ["kernel32.dll!Exit", "kernel32.dll!#5"])
        self.assertEqual(self.image(data).imports["Exit"], 0x401160)

    def test_unterminated_import_descriptors_rejected(self):
        data = image_bytes()
        directory(data, 1, 0x1100, 20)
        struct.pack_into("<IIIII", data, 0x300, 0x1140, 0, 0, 0x1180, 0x1160)
        data[0x380:0x382] = b"X\0"
        with self.assertRaisesRegex(PEError, "unterminated import descriptor"):
            self.image(data).import_records()

    def test_identity_requires_all_pins(self):
        retail = self.image(retail=True)
        with self.assertRaisesRegex(IdentityError, "missing retail identity pins"):
            retail.verify_identity()

    def test_installed_pins_roundtrip_and_individual_tampering(self):
        config = load_config()
        if not Path(config["builds"]["cl"]["path"]).exists():
            self.skipTest("installed VC8 toolchain unavailable")
        for name, build in config["builds"].items():
            with self.subTest(binary=name):
                retail = Retail(build)
                self.assertEqual(retail.verify_identity()["sha256"], build["sha256"])
                self.assertTrue(retail.import_records())
                self.assertTrue(retail.sections)
        retail = Retail(config["builds"]["cl"])
        for field in ("sha256", "size", "machine", "image_base", "timestamp", "version", "pdb"):
            altered = copy.deepcopy(retail.build)
            if field == "pdb":
                altered[field]["age"] += 1
            else:
                altered[field] = 0 if isinstance(altered[field], int) else "invalid"
            with self.subTest(field=field), self.assertRaises(IdentityError):
                retail.verify_identity(altered)

    def test_binary_codegen_profiles_remain_provisional(self):
        for name in ("cl", "c1", "c1xx", "c2", "link"):
            profile = load_binary_config(name)
            self.assertEqual(profile["options"]["status"], "provisional")
            self.assertIn("/GL", profile["flags"]["compile"])
            self.assertIn("/LTCG", profile["flags"]["link"])
        with self.assertRaises(ValueError):
            load_binary_config("unknown")


class ReferentContracts(unittest.TestCase):
    def test_operand_order_and_repeated_target_preserved(self):
        refs = [OrderedReference(8, "rel32", 123, "callee"),
                OrderedReference(1, "dir32", 123, "callee")]
        actual = ordered_referents(refs)
        self.assertEqual([x["offset"] for x in actual], [1, 8])
        self.assertEqual([x["identity"] for x in actual], ["callee", "callee"])

    def test_overlapping_negative_or_invalid_reference_rejected(self):
        for refs in ([OrderedReference(0, "dir32", 1), OrderedReference(2, "dir32", 2)],
                     [OrderedReference(-1, "dir32", 1)],
                     [OrderedReference(0, "dir32", 1, width=0)],
                     [OrderedReference(0, "", 1)]):
            with self.assertRaises(ValueError):
                ordered_referents(refs)

    def test_unresolved_and_aliased_identity_are_explicit(self):
        self.assertEqual(resolve_referent(4, {4: ["b", "a"]}), ["a", "b"])
        self.assertEqual(resolve_referent(5, {4: "symbol"}), [])
        self.assertEqual(resolve_referent(4, {}, [{"va": 4, "identity": "dll!fn"}]), ["dll!fn"])


if __name__ == "__main__":
    unittest.main()
