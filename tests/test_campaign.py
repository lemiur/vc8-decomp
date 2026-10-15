import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import campaign
import match

HASH = "a" * 64


class CampaignTests(unittest.TestCase):
    def export_fixture(self, directory, status="complete"):
        path = Path(directory)
        (path / "manifest.json").write_text(json.dumps({"status": status, "returncode": 0,
            "binary_sha256": HASH, "ghidra_version": "12.0.1"}))
        (path / "export-complete.json").write_text(json.dumps({"binary_sha256": HASH,
            "ghidra_version": "12.0.1", "functions": 5, "decompiled": 3, "failed": 2}))
        return path

    def test_completed_export_can_have_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            result = campaign.export_state(self.export_fixture(directory))
            self.assertTrue(result["complete"])
            self.assertEqual(result["counts"], {"functions": 5, "decompiled": 3, "failed": 2})

    def test_running_manifest_overrides_stale_completion_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.export_fixture(directory, "running")
            result = campaign.export_state(path)
            self.assertFalse(result["complete"])
            self.assertEqual(result["status"], "running")

    def test_completion_identity_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.export_fixture(directory)
            data = json.loads((path / "export-complete.json").read_text())
            data["binary_sha256"] = "b" * 64
            (path / "export-complete.json").write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "binary hash"):
                campaign.export_state(path)

    def test_wrong_retail_identity_cannot_count_as_completed_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.export_fixture(directory)
            with self.assertRaisesRegex(ValueError, "pinned retail"):
                campaign.export_state(path, expected_sha256="b" * 64)

    def source_fixture(self, directory):
        root = Path(directory)
        (root / "matching/cl").mkdir(parents=True)
        (root / "config").mkdir()
        source = root / "matching/cl/test.cpp"
        source.write_text("// FUNCTION: cl 0x401000\nint banked() { return 0; }\n"
                          "// FUNCTION: cl 0x401010\n// stop: wall: CFG; complete source still differs.\nint parked() { return 1; }\n"
                          "// FUNCTION: cl 0x401020\nint disabled() { return 2; }\n")
        (root / "config/cl-candidates.json").write_text(json.dumps({"schema_version": 1, "candidates": [
            {"binary": "cl", "symbol": "disabled", "retail_va": "0x401020", "unit": "matching/cl/test.cpp", "gate_enabled": False}]}))
        functions = [{"binary": "cl", "va": hex(0x401000 + index * 16), "name": name,
                      "source_path": "matching/cl/test.cpp", "admitted": index == 0,
                      "status": "RULE-ADMITTED" if index == 0 else "MATCH-PENDING"}
                     for index, name in enumerate(("banked", "parked", "disabled"))]
        rules = {"functions": functions, "summary": {"match_pending": 2}, "scope_sha256": HASH}
        annotation = match.parse_annotations(source)[0]
        lines = source.read_text().splitlines()
        source_hash = hashlib.sha256("\n".join(lines[annotation.start - 1:annotation.end]).encode()).hexdigest()
        return root, rules, {("cl", 0x401000): {"function_source_sha256": source_hash}}

    def test_open_census_includes_parked_unregistered_and_disabled_without_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            root, rules, banked = self.source_fixture(directory)
            with patch.object(campaign.rulecheck, "check", return_value=rules):
                result = campaign.open_work(root, ["cl"], banked)
            self.assertEqual(result["annotated_functions"], 3)
            self.assertEqual(result["registered_functions"], 1)
            self.assertEqual(len(result["pending"]), 2)
            self.assertEqual(result["pending"][0]["wall"], "CFG")
            self.assertIn("parked source", result["pending"][0]["reasons"])

    def test_stale_diagnosis_is_not_attached(self):
        with tempfile.TemporaryDirectory() as directory:
            root, rules, banked = self.source_fixture(directory)
            evidence = root / "build/evidence"
            evidence.mkdir(parents=True)
            (evidence / "test-wall.json").write_text(json.dumps({"binary": "cl", "retail_va": "0x401020",
                "function_source_sha256": HASH, "wall": "register/schedule"}))
            with patch.object(campaign.rulecheck, "check", return_value=rules):
                result = campaign.open_work(root, ["cl"], banked, evidence)
            self.assertEqual(result["pending"][1]["wall"], "unclassified")
            self.assertEqual(len(result["parse_errors"]), 1)

    def test_red_gate_never_produces_counts_and_bootstrap_stays_unresolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root, rules, _ = self.source_fixture(directory)
            build = root / "build"
            (build / "gate").mkdir(parents=True)
            (build / "gate/latest.json").write_text(json.dumps({"schema_version": 1, "gate_kind": "retail-splice",
                "run_id": "failed", "status": "RED", "errors": ["failed"], "authority": None}))
            project = {"binaries": {"cl": {"phase": 1}}}
            with patch.object(campaign.rulecheck, "check", return_value=rules):
                status = campaign.collect(project, root, build)
            self.assertIsNone(status["coverage"][0]["matched_under_rules"])
            self.assertIsNone(status["coverage"][0]["function_denominator"])
            self.assertEqual(status["bootstrap"]["status"], "unavailable")
            self.assertEqual(status["phases"][0]["exit_status"], "not proven")
            output = campaign.render(status)
            self.assertLessEqual(len(output.splitlines()), 60)
            self.assertNotIn("%", output)
            self.assertIn("full source relink remains unproven", output)

    def test_summary_input_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "huge.json"
            path.write_text(" " * 100)
            with self.assertRaisesRegex(ValueError, "bounded-input"):
                campaign.small_json(path, 10)

    def test_bootstrap_summary_is_observational_and_hash_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root, rules, _ = self.source_fixture(directory)
            build = root / "build"
            ab = build / "toolchain-ab"
            ab.mkdir(parents=True)
            evidence = ab / "evidence.json"
            evidence.write_text("{}")
            summary = {"schema_version": 1, "kind": "bootstrap-ab-observations", "observational_only": True,
                       "unique_source_function_identities_observed": 46,
                       "verdict": {"bootstrap_identity": "unresolved"},
                       "provenance": [{"path": str(evidence), "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}]}
            (ab / "summary.json").write_text(json.dumps(summary))
            project = {"binaries": {"cl": {"phase": 1}}}
            with patch.object(campaign.rulecheck, "check", return_value=rules):
                status = campaign.collect(project, root, build)
                self.assertEqual(status["bootstrap"]["status"], "available")
                self.assertIsNone(status["coverage"][0]["matched_under_rules"])
                self.assertIn("inconclusive", status["bootstrap"]["conclusion"])
                evidence.write_text("changed")
                invalid = campaign.collect(project, root, build)
                self.assertEqual(invalid["bootstrap"]["status"], "invalid")
                self.assertIsNone(invalid["coverage"][0]["matched_under_rules"])


if __name__ == "__main__":
    unittest.main()
