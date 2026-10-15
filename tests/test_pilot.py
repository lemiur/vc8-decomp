import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("pilot", Path(__file__).resolve().parents[1] / "tools" / "pilot.py")
pilot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)


class PilotTests(unittest.TestCase):
    def setUp(self):
        self.catalogue = {"schema_version": 1, "binary": "cl", "lanes": [{"id": "driver"}], "functions": [{
            "name": "example", "va": "0x401000", "lane": "driver", "score": None,
            "boundary": {"status": "unresolved", "size": None}, "match_ready": False}]}

    def test_unresolved_evidence_is_allowed(self):
        self.assertEqual(pilot.validate(self.catalogue), [])

    def test_next_public_gap_cannot_prove_boundary(self):
        self.catalogue["functions"][0]["boundary"] = {"status": "proven", "size": 10,
            "methods": ["next-public-gap"], "terminal": "ret", "evidence": "test"}
        self.assertTrue(any("bounded disassembly" in error for error in pilot.validate(self.catalogue)))

    def test_unresolved_boundary_cannot_supply_size(self):
        self.catalogue["functions"][0]["boundary"]["size"] = 10
        self.assertTrue(any("cannot supply" in error for error in pilot.validate(self.catalogue)))

    def test_ready_requires_resolved_abi_and_referents(self):
        self.catalogue["functions"][0]["match_ready"] = True
        self.assertEqual(len(pilot.validate(self.catalogue)), 3)

    def test_overlapping_functions_rejected(self):
        first = self.catalogue["functions"][0]
        first["boundary"] = {"status": "proven", "size": 10, "methods": ["bounded-disassembly"],
                             "terminal": "ret", "evidence": "test"}
        second = copy.deepcopy(first)
        second.update(name="overlap", va="0x401005")
        self.catalogue["functions"].append(second)
        self.assertTrue(any("overlaps" in error for error in pilot.validate(self.catalogue)))

    def test_evidence_catalogue_cannot_award_score(self):
        self.catalogue["functions"][0]["score"] = 100
        self.assertTrue(any("score null" in error for error in pilot.validate(self.catalogue)))


if __name__ == "__main__":
    unittest.main()
