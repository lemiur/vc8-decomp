import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import integrate_lanes  # noqa: E402


def candidate(symbol, va, size=8, unit="matching/cl/unit.cpp", enabled=True):
    entry = {"binary": "cl", "symbol": symbol, "retail_va": va, "unit": unit, "size": size,
             "source_span": {"start": 1, "end": 3},
             "boundary": {"status": "verified", "evidence": "decoded"},
             "identity_evidence": "public start"}
    if not enabled:
        entry["gate_enabled"] = False
        entry["boundary"] = {"status": "unverified", "evidence": "map span"}
    return entry


class IntegrateLanesTests(unittest.TestCase):
    def lane(self, temp, name, candidates, referents=None):
        root = Path(temp) / name
        (root / "config/reviews").mkdir(parents=True)
        (root / "config/cl-candidates.json").write_text(json.dumps({
            "schema_version": 1, "binary": "cl", "candidates": candidates,
            "referents": referents or {}}), encoding="utf-8")
        return root

    def base(self, temp, candidates):
        path = Path(temp) / "base.json"
        path.write_text(json.dumps({"schema_version": 1, "binary": "cl", "note": "keep",
                                    "candidates": candidates, "referents": {}}), encoding="utf-8")
        return path

    def test_union_preserves_base_order_and_appends_sorted(self):
        with tempfile.TemporaryDirectory() as temp:
            base = self.base(temp, [candidate("?b", "0x2000")])
            lane = self.lane(temp, "lane", [candidate("?a", "0x3000"), candidate("?c", "0x1000")])
            merged = integrate_lanes.merge_candidates(json.loads(base.read_text()), [lane])
            self.assertEqual([entry["symbol"] for entry in merged["candidates"]], ["?b", "?c", "?a"])
            self.assertEqual(merged["note"], "keep")

    def test_identical_duplicate_collapses(self):
        with tempfile.TemporaryDirectory() as temp:
            base = self.base(temp, [candidate("?a", "0x1000")])
            lane = self.lane(temp, "lane", [candidate("?a", "0x1000")])
            merged = integrate_lanes.merge_candidates(json.loads(base.read_text()), [lane])
            self.assertEqual(len(merged["candidates"]), 1)

    def test_conflicting_symbol_aborts(self):
        with tempfile.TemporaryDirectory() as temp:
            base = self.base(temp, [candidate("?a", "0x1000")])
            lane = self.lane(temp, "lane", [candidate("?a", "0x1010")])
            with self.assertRaisesRegex(ValueError, "conflicts with an existing entry"):
                integrate_lanes.merge_candidates(json.loads(base.read_text()), [lane])

    def test_prefer_base_keeps_shifted_span(self):
        with tempfile.TemporaryDirectory() as temp:
            base = self.base(temp, [candidate("?a", "0x1000")])
            shifted = candidate("?a", "0x1000")
            shifted["source_span"] = {"start": 2, "end": 4}
            lane = self.lane(temp, "lane", [shifted])
            with self.assertRaises(ValueError):
                integrate_lanes.merge_candidates(json.loads(base.read_text()), [lane])
            merged = integrate_lanes.merge_candidates(json.loads(base.read_text()), [lane], prefer_base=True)
            self.assertEqual(merged["candidates"][0]["source_span"], {"start": 1, "end": 3})

    def test_two_symbols_at_one_address_aborts(self):
        with tempfile.TemporaryDirectory() as temp:
            base = self.base(temp, [candidate("?a", "0x1000")])
            lane = self.lane(temp, "lane", [candidate("?b", "0x1000")])
            with self.assertRaisesRegex(ValueError, "already is"):
                integrate_lanes.merge_candidates(json.loads(base.read_text()), [lane])

    def test_enabled_candidate_requires_verified_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            base = self.base(temp, [])
            bad = candidate("?a", "0x1000")
            bad["boundary"] = {"status": "unverified"}
            lane = self.lane(temp, "lane", [bad])
            with self.assertRaisesRegex(ValueError, "verified boundary"):
                integrate_lanes.merge_candidates(json.loads(base.read_text()), [lane])

    def test_referents_are_merged_and_conflicts_abort(self):
        with tempfile.TemporaryDirectory() as temp:
            base = self.base(temp, [])
            lane = self.lane(temp, "lane", [], {"cl": {"?g": {"va": "0x10"}}})
            merged = integrate_lanes.merge_candidates(json.loads(base.read_text()), [lane])
            self.assertEqual(merged["referents"]["cl"]["?g"]["va"], "0x10")
            other = self.lane(temp, "other", [], {"cl": {"?g": {"va": "0x20"}}})
            with self.assertRaisesRegex(ValueError, "referent"):
                integrate_lanes.merge_candidates(json.loads(base.read_text()), [lane, other])

    def test_review_claims_must_be_disjoint(self):
        with tempfile.TemporaryDirectory() as temp:
            def fragment(name, va):
                root = Path(temp) / name / "config"
                (root / "reviews").mkdir(parents=True)
                (root / ("reviews/cl5-%s.json" % name)).write_text(json.dumps({
                    "schema_version": 1, "binary": "cl", "functions": [{
                        "va": va, "symbol": "?a", "source_path": "matching/cl/unit.cpp",
                        "checks": {rule: rule for rule in integrate_lanes.RULES}}]}), encoding="utf-8")
                return root / ("reviews/cl5-%s.json" % name)
            first = fragment("one", "0x1000")
            second = fragment("two", "0x1000")
            with self.assertRaisesRegex(ValueError, "claimed by both"):
                integrate_lanes.merge_reviews([first, second])


if __name__ == "__main__":
    unittest.main()
