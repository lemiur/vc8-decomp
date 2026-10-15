import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import ledger
import report

HASH = "a" * 64
OTHER = "b" * 64


def observation(score=100, source=HASH, build="build-1", day=1, **changes):
    row = {"observed_at": f"2026-10-{day:02d}T12:00:00Z", "binary": "cl", "va": "0x00401000",
           "symbol": "function", "function_source_sha256": source, "unit": "matching/cl/driver.cpp",
           "build_id": build, "score": score, "bytes_exact": score == 100,
           "referents": "resolved", "rules": "pass", "gate_sha256": HASH}
    row.update(changes)
    return row


def green(source=True):
    admitted = [{"symbol": "function", "retail_va": "0x00401000", "size": 4,
                 "unit": "matching/cl/driver.cpp", "source_sha256": HASH,
                 "function_source_sha256": OTHER, "build_id": "run-1", "image_sha256": HASH,
                 "rules": {"status": "passed"}, "referents": 0, "referents_status": "resolved",
                 "bytes_exact": True, "artifacts": [{"kind": "linked-image", "sha256": HASH}],
                 "boundary": {"status": "verified", "evidence": "fixture"}}] if source else []
    return {"schema_version": 1, "gate_kind": "retail-splice", "run_id": "run-1",
            "observed_at": "2026-10-15T12:00:00Z", "status": "GREEN",
            "authority": f"BANKED cl functions={len(admitted)} source_bytes={len(admitted) * 4}/100",
            "errors": [], "binaries": {"cl": {"input_sha256": HASH, "fallback_sha256": HASH,
                "output_sha256": HASH, "image_bytes": 100, "functions": len(admitted),
                "source_bytes": len(admitted) * 4, "function_denominator": None,
                "source_byte_denominator": 100, "admitted": admitted, "status": "GREEN"}}}


class LedgerTests(unittest.TestCase):
    def test_current_best_historical_and_recovery(self):
        rows = [observation(100), observation(91, build="b2", day=2),
                observation(80, source=OTHER, build="b3", day=3)]
        snapshot = ledger.snapshots(rows)[0]
        self.assertEqual((snapshot["current"], snapshot["best"], snapshot["historical"]), (80, 80, 100))
        self.assertTrue(snapshot["lost_match"])
        rows.append(observation(70, source=OTHER, build="b4", day=4))
        snapshot = ledger.snapshots(rows)[0]
        self.assertEqual((snapshot["current"], snapshot["best"], snapshot["historical"]), (70, 80, 100))
        rows.append(observation(95, build="b5", day=5))
        self.assertEqual(ledger.snapshots(rows)[0]["best"], 100)

    def test_merge_is_deterministic_deduplicated_and_persistent(self):
        first, second = observation(), observation(source=OTHER, build="b2", day=2)
        self.assertEqual(ledger.merge([first, second]), ledger.merge([second], [first, second]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.tsv"
            ledger.write(path, [second, first])
            original = path.read_bytes()
            ledger.write(path, ledger.read(path))
            self.assertEqual(path.read_bytes(), original)

    def test_conflict_and_bad_score_rejected(self):
        with self.assertRaisesRegex(ValueError, "conflicting"):
            ledger.merge([observation(90), observation(95)])
        for value in (float("nan"), float("inf"), -1, 101):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ledger.normalize(observation(value))

    def test_tracked_rows_need_gate_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "gate attribution"):
                ledger.write(Path(directory) / "ledger.tsv", [observation(gate_sha256="")])

    def test_tracked_history_is_compact_and_excludes_raw_scores(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.tsv"
            ledger.write(path, [observation(), observation(build="b2", day=2),
                                observation(source=OTHER, build="b3", day=3)])
            rows = ledger.read(path)
            self.assertEqual(len(rows), 2)
            self.assertEqual({row["build_id"] for row in rows}, {"b2", "b3"})
            with self.assertRaisesRegex(ValueError, "gate-admitted"):
                ledger.write(path, [observation(90)])

    def test_exact_rule_or_referent_failure_is_pending(self):
        for changes in ({"rules": "fail"}, {"referents": "unresolved"}):
            with self.subTest(changes=changes):
                self.assertEqual(ledger.snapshots([observation(**changes)])[0]["candidate_status"], "MATCH-PENDING")

    def test_gate_recording_has_no_fallback_rows_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            target, gate_file = Path(directory) / "ledger.tsv", Path(directory) / "gate.json"
            gate_file.write_text(json.dumps(green(False)))
            self.assertEqual(ledger.main(["--ledger", str(target), "record-gate", str(gate_file)]), 0)
            self.assertEqual(ledger.read(target), [])
            gate_file.write_text(json.dumps(green()))
            for _ in range(2):
                ledger.main(["--ledger", str(target), "record-gate", str(gate_file)])
            rows = ledger.read(target)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["function_source_sha256"], OTHER)
            self.assertEqual(rows[0]["gate_sha256"], report.file_sha256(gate_file))

    def test_red_gate_cannot_modify_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            target, gate_file = Path(directory) / "ledger.tsv", Path(directory) / "gate.json"
            ledger.write(target, [])
            original = target.read_bytes()
            gate = green()
            gate["status"] = "RED"
            gate_file.write_text(json.dumps(gate))
            with self.assertRaises(SystemExit) as raised:
                ledger.main(["--ledger", str(target), "record-gate", str(gate_file)])
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(target.read_bytes(), original)


class ReportTests(unittest.TestCase):
    def test_match_diagnostics_are_pending_and_never_admissions(self):
        comparisons = [{"symbol": "function", "retail_va": "0x00401000", "observed_at": "2026-10-15T12:00:00Z",
                        "source_path": "matching/cl/unit.cpp", "function_source_sha256": HASH,
                        "build_id": "candidate", "score": 100, "raw_bytes_equal": True,
                        "referents_status": "resolved", "rule_status": "pending", "status": "MATCH-PENDING"}]
        rows, unscored = report.diagnostic_observations("cl", comparisons)
        self.assertEqual(unscored, [])
        result = report.report_binary("cl", green(False), observations=rows)
        self.assertEqual(result["candidate_scores"][0]["candidate_status"], "MATCH-PENDING")
        self.assertEqual(result["matched_under_rules"], 0)
        comparisons[0]["score"] = None
        rows, unscored = report.diagnostic_observations("cl", comparisons)
        self.assertEqual(rows, [])
        self.assertEqual(len(unscored), 1)

    def test_missing_gate_cannot_count_even_exact_scores(self):
        result = report.report_binary("cl", observations=[observation()])
        self.assertIsNone(result["matched_under_rules"])
        self.assertIsNone(result["source_attributed_bytes"])

    def test_all_fallback_green_is_zero(self):
        result = report.report_binary("cl", green(False))
        self.assertEqual(result["matched_under_rules"], 0)
        self.assertEqual(result["source_attributed_bytes"], 0)
        self.assertIsNone(result["function_percent"])
        self.assertEqual(result["byte_percent"], 0)

    def test_source_counts_and_unknown_function_denominator(self):
        result = report.report_binary("cl", green())
        self.assertEqual(result["matched_under_rules"], 1)
        self.assertEqual(result["source_attributed_bytes"], 4)
        self.assertEqual(result["byte_percent"], 4)
        self.assertEqual(result["byte_denominator_kind"], "complete-retail-file")
        self.assertIsNone(result["function_denominator"])
        self.assertTrue(result["boundary_caveats"])

    def test_gate_failure_paths(self):
        mutators = [lambda gate: gate.update(status="RED"), lambda gate: gate.update(authority=None),
                    lambda gate: gate.update(authority="BANKED cl functions=0 source_bytes=0/100"),
                    lambda gate: gate.update(errors=["bad"]),
                    lambda gate: gate["binaries"]["cl"].update(output_sha256=OTHER),
                    lambda gate: gate["binaries"]["cl"].update(source_bytes=8),
                    lambda gate: gate["binaries"]["cl"]["admitted"][0].update(bytes_exact=False),
                    lambda gate: gate["binaries"]["cl"]["admitted"][0].update(referents_status="unresolved"),
                    lambda gate: gate["binaries"]["cl"]["admitted"][0].update(rules={"status": "failed"}),
                    lambda gate: gate["binaries"]["cl"]["admitted"][0].update(build_id="stale"),
                    lambda gate: gate["binaries"]["cl"]["admitted"][0].update(artifacts=[]),
                    lambda gate: gate["binaries"]["cl"]["admitted"][0].update(boundary={"status": "unknown"})]
        for index, mutate in enumerate(mutators):
            with self.subTest(index=index):
                gate = green()
                mutate(gate)
                with self.assertRaises(ValueError):
                    report.report_binary("cl", gate)

    def test_overlapping_spans_rejected(self):
        gate = green()
        second = copy.deepcopy(gate["binaries"]["cl"]["admitted"][0])
        second["retail_va"] = "0x00401002"
        gate["binaries"]["cl"]["admitted"].append(second)
        gate["binaries"]["cl"].update(functions=2, source_bytes=8)
        with self.assertRaisesRegex(ValueError, "overlapping"):
            report.report_binary("cl", gate)

    def test_public_start_inventory_does_not_create_denominator(self):
        inventory = {"functions": [{"va": "0x00401000", "size": None, "boundary_status": "public-start-only"}],
                     "summary": {"functions": 267}}
        result = report.report_binary("cl", green(), inventory=inventory)
        self.assertIsNone(result["function_denominator"])

    def test_cli_produces_stable_reports_without_fabricated_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            project, target, gate_file = path / "project.json", path / "ledger.tsv", path / "gate.json"
            project.write_text(json.dumps({"primary_checkout": str(path), "binaries": {"cl": {}}}))
            ledger.write(target, [])
            gate_file.write_text(json.dumps(green(False)))
            command = [sys.executable, str(ROOT / "tools/report.py"), "--project", str(project),
                       "--gate", str(gate_file), "--ledger", str(target), "--output-dir", str(path / "reports")]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            first = (path / "reports/cl.json").read_bytes()
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(first, (path / "reports/cl.json").read_bytes())
            self.assertEqual(json.loads(first)["matched_under_rules"], 0)


if __name__ == "__main__":
    unittest.main()
