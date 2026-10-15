"""Focused evidence-selector contract tests; no Microsoft fixture files required."""
import importlib.util
import json
import contextlib
import io
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("c2_priority", ROOT / "tools/c2_priority.py")
priority = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(priority)


class SelectorTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "config/c2-priority.json").read_text())

    def test_name_hint_does_not_establish_ownership_or_signature(self):
        result = priority.select([{"name": "PogoInlineCost", "va": 0x1000}], self.config)
        self.assertEqual(result[0]["selection"][0]["basis"], "name-hint")
        self.assertEqual(result[0]["ownership"]["status"], "unresolved")
        self.assertIn("unresolved", result[0]["signature"])

    def test_explicit_module_evidence_is_distinguished(self):
        records = [{"name": "helper", "va": 0x1000, "module": r"F:\src\pogocg.obj", "module_evidence": "DBI section contribution"},
                   {"name": "helper2", "va": 0x1008, "module": "hash.obj"}]
        result = priority.select(records, self.config)
        self.assertEqual(result[0]["ownership"]["status"], "attributed")
        self.assertEqual(result[1]["ownership"]["status"], "unresolved")
        self.assertEqual(result[1]["selection"][0]["basis"], "unverified-module")

    def test_data_filtered_and_order_stable(self):
        records = [{"name": "PogoInlineData", "va": 0x1000, "kind": "data"},
                   {"name": "PogoOptB", "va": 0x2000}, {"name": "PogoOptA", "va": 0x1010}]
        self.assertEqual([row["name"] for row in priority.select(records, self.config)], ["PogoOptA", "PogoOptB"])

    def test_ambiguous_module_is_not_attributed(self):
        result = priority.select([{"name": "helper", "va": 0x1000, "module": "hash.obj", "module_evidence": "DBI", "module_candidates": [2, 3]}], self.config)
        self.assertEqual(result[0]["ownership"]["status"], "unresolved")

    def test_binary_hash_mismatch_rejected_before_disassembly(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            binary, symbols = directory / "c2.dll", directory / "symbols.json"
            binary.write_bytes(b"not the pinned image")
            symbols.write_text(json.dumps({"binary": "c2", "identity": {"binary_sha256": "0" * 64}, "functions": []}))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                priority.main(["--symbols", str(symbols), "--binary", str(binary)])
            self.assertEqual(error.exception.code, 2)

    def test_unrelated_binary_symbol_document_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "symbols.json"
            path.write_text(json.dumps({"binary": "cl", "functions": []}))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                priority.main(["--symbols", str(path)])
            self.assertEqual(error.exception.code, 2)

    def test_addresses_require_va_instead_of_inventing_base(self):
        with self.assertRaises(ValueError):
            priority.normalize_symbols({"symbols": [{"name": "PogoInline", "rva": 0x100}]})
        rows = priority.normalize_symbols({"publics": [{"name": "PogoInline", "address": "0x1000"}]})
        self.assertEqual(rows[0]["va"], 0x1000)


class BoundedDisassemblyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import capstone
        except ImportError:
            raise unittest.SkipTest("optional capstone dependency unavailable")
        cls.cs = capstone

    def image(self, data):
        image = priority.ImageEvidence.__new__(priority.ImageEvidence)
        image.capstone = self.cs
        image.base, image.image_end = 0x1000, 0x3000
        image.names = {0x1000: ["entry"], 0x2000: ["callee"]}
        image.relocs, image.imports = {}, {}
        decoder = self.cs.Cs(self.cs.CS_ARCH_X86, self.cs.CS_MODE_32)
        decoder.detail = True
        image.instruction = lambda va: next(decoder.disasm(data[va - 0x1000:va - 0x1000 + 15], va, count=1), None) if 0x1000 <= va < 0x1000 + len(data) else None
        return image

    def test_leaf_ret_pop_is_observation_not_signature(self):
        result = self.image(bytes.fromhex("8b442404c20400")).inspect(0x1000)
        self.assertFalse(result["has_out_of_line_call"])
        self.assertEqual(result["returns"][0]["stack_pop"], 4)
        self.assertIn("unresolved", result["abi"])
        self.assertEqual(result["decoded_byte_count"], 7)
        self.assertNotIn("function_size", result)

    def test_call_target_not_recursively_followed(self):
        result = self.image(bytes.fromhex("e8fb0f0000c3")).inspect(0x1000)
        self.assertTrue(result["has_out_of_line_call"])
        self.assertEqual(result["referents"][0]["names"], ["callee"])
        self.assertEqual(result["decoded_instruction_count"], 2)

    def test_limit_and_indirect_jump_remain_unresolved(self):
        result = self.image(bytes.fromhex("90ebfd")).inspect(0x1000, max_instructions=1)
        self.assertEqual(result["stops"][0]["reason"], "instruction-limit")
        result = self.image(bytes.fromhex("ffe0")).inspect(0x1000)
        self.assertEqual(result["stops"][0]["reason"], "indirect-branch")
        self.assertEqual(result["unresolved_referent_count"], 1)

    def test_next_public_is_a_barrier_not_size(self):
        image = self.image(bytes.fromhex("9090c3"))
        image.names[0x1001] = ["another"]
        result = image.inspect(0x1000)
        self.assertEqual(result["decoded_byte_count"], 1)
        self.assertEqual(result["stops"][0]["reason"], "other-public-entry")

    def test_absolute_indexed_memory_without_base_relocation(self):
        result = self.image(bytes.fromhex("8b8080200000c3")).inspect(0x1000)
        reference = result["referents"][0]
        self.assertEqual(reference["kind"], "memory-address-base")
        self.assertEqual(reference["va"], "0x00002080")
        self.assertTrue(reference["indexed"])
        self.assertEqual(result["unresolved_referent_count"], 1)


if __name__ == "__main__":
    unittest.main()
