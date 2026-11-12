import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import evidence_index as index


class EvidenceIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.run = self.root / "run"
        (self.run / "functions").mkdir(parents=True)
        self.database = self.root / "lookup.sqlite"
        self.identity = "a" * 64
        self.symbols = {"identity": {"binary_sha256": self.identity, "image_base": 0x400000}, "_input_sha256": "b" * 64,
                        "functions": [{"name": "ExactPublic", "rva": 0x1000, "size": 16, "boundary_status": "pdb-fpo-procedure-size",
                                       "module": "clmain.obj", "module_evidence": "DBI contribution"}],
                        "data": [{"name": "ExactData", "rva": 0x3000, "size": None}],
                        "modules": [{"index": 11, "name": "clmain.obj", "object_file": "clmain.obj"}],
                        "sections": [{"index": 2, "rva": 0x3000}],
                        "section_contributions": [{"section": 2, "offset": 0, "size": 256, "module_index": 11}]}
        (self.run / "manifest.json").write_text(json.dumps({"binary": "cl", "binary_sha256": self.identity,
            "ghidra_version": "12.0.1", "status": "complete", "returncode": 0}))
        (self.run / "export-complete.json").write_text(json.dumps({"binary_sha256": self.identity, "ghidra_version": "12.0.1"}))
        (self.run / "functions.tsv").write_text("va\trva\tname\tbody_bytes\trange_count\tdecompile_status\n00401000\t0x1000\tAnalysisName\t16\t1\tfailed\n")
        (self.run / "ranges.tsv").write_text("function_va\tstart_va\tend_va_inclusive\n00401000\t00401000\t0040100f\n")
        (self.run / "references.tsv").write_text("function_va\tsite_va\ttarget_va\ttype\n00401000\t00401004\t00403000\tDATA\n00401000\t00401008\tEXTERNAL:0000000d\tCALL\n")
        (self.run / "functions/00401000.asm").write_text("assembly evidence")
        (self.run / "functions/00401000.json").write_text(json.dumps({"rva": "0x1000", "binary_sha256": self.identity,
            "status": "failed", "timed_out": True, "error": "process: timeout"}))

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, **kwargs):
        return index.build_index(self.database, "cl", self.run, self.symbols, self.root / "symbols.json", **kwargs)

    def test_exact_identities_owners_ranges_and_refs(self):
        result = self.build()
        self.assertEqual(result["indexed_entries"], 2)
        text = "\n".join(index.lookup(self.database, "cl", symbol="ExactPublic"))
        self.assertIn("RVA=0x1000 VA=0x401000 ExactPublic", text)
        self.assertIn("status=failed timeout=True", text)
        self.assertIn("EXTERNAL:0000000d", text)
        self.assertIn("Inferred containing bodies: 0x401000", text)
        arbitrary = "\n".join(index.lookup(self.database, "cl", rva=0x3020))
        self.assertIn("module 11 clmain.obj", arbitrary)
        incoming = "\n".join(index.lookup(self.database, "cl", symbol="ExactData"))
        self.assertIn("0x401004 -> 00403000 DATA", incoming)
        self.assertIn("ExactData", "\n".join(index.lookup(self.database, "cl", va=0x403000)))

    def test_forged_result_keeps_prior_index(self):
        self.build()
        path = self.run / "functions/00401000.json"
        result = json.loads(path.read_text()); result["binary_sha256"] = "c" * 64
        path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, "per-function identity mismatch"):
            self.build()
        self.assertIn("ExactPublic", "\n".join(index.lookup(self.database, "cl", symbol="ExactPublic")))

    def test_partial_metadata_requires_explicit_opt_in(self):
        path = self.run / "manifest.json"
        manifest = json.loads(path.read_text()); manifest.update(status="running", returncode=None)
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.build()
        (self.run / "metadata-complete.json").write_text(json.dumps({"binary_sha256": self.identity}))
        self.assertTrue(self.build(allow_pending=True)["partial_snapshot"])
        self.assertIn("partial=True", "\n".join(index.lookup(self.database, "cl", symbol="ExactPublic")))

    def test_bad_completion_and_reference_roll_back(self):
        self.build()
        path = self.run / "export-complete.json"
        result = json.loads(path.read_text()); result["binary_sha256"] = "d" * 64
        path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, "completion identity mismatch"):
            self.build()
        result["binary_sha256"] = self.identity
        path.write_text(json.dumps(result))
        (self.run / "references.tsv").write_text("function_va\tsite_va\ttarget_va\ttype\n00401000\tINVALID\t00403000\tDATA\n")
        with self.assertRaisesRegex(ValueError, "invalid RAM"):
            self.build()
        self.assertIn("ExactPublic", "\n".join(index.lookup(self.database, "cl", symbol="ExactPublic")))

    def test_output_clips_long_symbols(self):
        self.symbols["functions"][0]["name"] = "X" * 100000
        self.build()
        text = "\n".join(index.lookup(self.database, "cl", contains="XXX"))
        self.assertIn("[truncated]", text)
        self.assertLess(len(text.encode()), 10000)


if __name__ == "__main__":
    unittest.main()
