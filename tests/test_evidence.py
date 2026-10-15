import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("evidence", Path(__file__).resolve().parents[1] / "tools/evidence.py")
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class EvidenceTests(unittest.TestCase):
    def test_symbol_identity_and_ambiguity(self):
        symbols = {"functions": [{"name": "duplicate", "rva": 0x10}, {"name": "duplicate", "rva": 0x20}], "data": []}
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            evidence.resolve_symbol(symbols, "duplicate", 0x400000)
        self.assertEqual(evidence.resolve_symbol(symbols, "0x400020", 0x400000)["rva"], 0x20)
        self.assertEqual(evidence.resolve_symbol(symbols, "0x400030", 0x400000)["boundary_status"], "address-only")

    def test_bounded_output_consumes_only_one_lookahead(self):
        seen = []
        def lines():
            for number in range(1000):
                seen.append(number)
                yield str(number)
        result = list(evidence.bounded(lines(), 60))
        self.assertEqual(len(result), 60)
        self.assertIn("truncated", result[-1])
        self.assertEqual(len(seen), 61)
        self.assertEqual(list(evidence.bounded(["a", "b", "c", "d"], 4)), ["a", "b", "c", "d"])

    def test_map_must_be_verified_and_match_image(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "build/evidence").mkdir(parents=True)
            image = root / "test.bin"
            image.write_bytes(b"fixture")
            path = root / "build/evidence/cl.symbols.json"
            def write(identity):
                path.write_text(json.dumps({"identity": identity}))
            write({})
            with self.assertRaisesRegex(ValueError, "verified identity"):
                evidence.load_symbols(root, "cl", image)
            write({"verified": True, "binary_sha256": "0" * 64})
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                evidence.load_symbols(root, "cl", image)
            write({"verified": True, "binary_sha256": hashlib.sha256(b"fixture").hexdigest()})
            self.assertEqual(evidence.load_symbols(root, "cl", image)[1], path)

    def test_decode_direct_and_memory_references(self):
        try:
            instructions = list(evidence.decode(bytes.fromhex("e8fb0f0000 ff1500204000 c3"), 0x401000))
        except ValueError as error:
            self.skipTest(str(error))
        self.assertEqual([item.mnemonic for item in instructions], ["call", "call", "ret"])
        self.assertEqual(list(evidence.references(instructions[0]))[0][0], 0x402000)
        self.assertEqual(list(evidence.references(instructions[1]))[0][0], 0x402000)

    def test_ghidra_diagnostics_and_version(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            with self.assertRaisesRegex(ValueError, "installation missing"):
                evidence.ghidra_version(home)
            (home / "Ghidra").mkdir()
            (home / "Ghidra/application.properties").write_text("application.version=12.0.1\n")
            self.assertEqual(evidence.ghidra_version(home), "12.0.1")


if __name__ == "__main__":
    unittest.main()
