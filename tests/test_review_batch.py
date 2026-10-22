import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import review_batch  # noqa: E402
import rulecheck  # noqa: E402

FUNCTION = """// FUNCTION: cl 0x1000
// SYMBOL: ?alpha@@YAHXZ
int alpha()
{
    return 1;
}

// FUNCTION: cl 0x1010
// SYMBOL: ?beta@@YAHXZ
int beta()
{
    return 2;
}
"""


class ReviewBatchTests(unittest.TestCase):
    def fixture(self, temp, candidates=None):
        root = Path(temp)
        (root / "config/reviews").mkdir(parents=True)
        (root / "matching/cl").mkdir(parents=True)
        (root / "include").mkdir()
        (root / "config/project.json").write_text(json.dumps({
            "binaries": {"cl": {"filename": "cl.exe", "language": "c++"}},
            "project": {"binaries": ["cl"]}}), encoding="utf-8")
        (root / "matching/cl/unit.cpp").write_text(FUNCTION, encoding="utf-8")
        (root / "config/rule-exceptions.json").write_text(json.dumps(
            {"schema_version": 1, "reviews": [], "exceptions": []}), encoding="utf-8")
        (root / "config/cl-candidates.json").write_text(json.dumps({
            "schema_version": 1, "binary": "cl", "referents": {},
            "candidates": candidates if candidates is not None else [
                {"binary": "cl", "symbol": "?alpha@@YAHXZ", "retail_va": "0x1000",
                 "unit": "matching/cl/unit.cpp", "gate_enabled": True},
                {"binary": "cl", "symbol": "?beta@@YAHXZ", "retail_va": "0x1010",
                 "unit": "matching/cl/unit.cpp", "gate_enabled": True}]}), encoding="utf-8")
        return root

    def fragment(self, root, va="0x1000", symbol="?alpha@@YAHXZ"):
        path = root / "config/reviews/cl5-lane.json"
        path.write_text(json.dumps({
            "schema_version": 1, "binary": "cl", "lane": "lane",
            "functions": [{"va": va, "symbol": symbol, "source_path": "matching/cl/unit.cpp",
                           "checks": {rule: rule + " review text" for rule in review_batch.MATCH_RULES}}]}),
            encoding="utf-8")
        return path

    def test_import_admits_only_reviewed_and_borrows_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.fixture(temp, candidates=[
                {"binary": "cl", "symbol": "?alpha@@YAHXZ", "retail_va": "0x1000",
                 "unit": "matching/cl/unit.cpp", "gate_enabled": True}])
            fragment = self.fragment(root)
            result = review_batch.write_policy(root, [fragment])
            self.assertEqual(result["reviews"], 1)
            self.assertEqual(result["reviewed"], 1)
            policy = json.loads((root / "config/rule-exceptions.json").read_text(encoding="utf-8"))
            self.assertEqual(policy["reviews"][0]["va"], "0x1000")
            report = rulecheck.check([root / "matching"], root=root)
            self.assertEqual(report["scope_sha256"], result["scope_sha256"])
            admitted = [fn for fn in report["functions"] if fn["admitted"]]
            self.assertEqual([fn["va"] for fn in admitted], ["0x1000"])

    def test_enabled_candidate_without_review_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.fixture(temp)
            with self.assertRaisesRegex(ValueError, "without a lane review"):
                review_batch.build_batch(root, [self.fragment(root)])

    def test_parked_function_needs_no_review(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.fixture(temp, candidates=[
                {"binary": "cl", "symbol": "?alpha@@YAHXZ", "retail_va": "0x1000",
                 "unit": "matching/cl/unit.cpp", "gate_enabled": True},
                {"binary": "cl", "symbol": "?beta@@YAHXZ", "retail_va": "0x1010",
                 "unit": "matching/cl/unit.cpp", "gate_enabled": False}])
            build = review_batch.build_batch(root, [self.fragment(root)])
            self.assertEqual(len(build["records"]), 1)
            self.assertEqual(build["borrowed"], [])

    def test_changed_body_cannot_borrow_stale_review(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.fixture(temp)
            fragment = self.fragment(root)
            data = json.loads(fragment.read_text(encoding="utf-8"))
            data["functions"].append({"va": "0x1010", "symbol": "?beta@@YAHXZ",
                                      "source_path": "matching/cl/unit.cpp",
                                      "checks": {rule: "beta " + rule for rule in review_batch.MATCH_RULES}})
            fragment.write_text(json.dumps(data), encoding="utf-8")
            review_batch.write_policy(root, [fragment])
            source = root / "matching/cl/unit.cpp"
            source.write_text(FUNCTION.replace("return 1;", "return 3;"), encoding="utf-8")
            data["functions"] = data["functions"][:1]
            fragment.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "without a lane review"):
                review_batch.build_batch(root, [fragment])

    def test_fragment_for_unregistered_function_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.fixture(temp, candidates=[])
            with self.assertRaisesRegex(ValueError, "not an enabled gate candidate"):
                review_batch.build_batch(root, [self.fragment(root)])


if __name__ == "__main__":
    unittest.main()
