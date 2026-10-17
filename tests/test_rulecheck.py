"""Admission-contract and failure-path tests; no retail fixtures or behavior tests."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


MODULE = Path(__file__).resolve().parents[1] / "tools/rulecheck.py"
SPEC = importlib.util.spec_from_file_location("vc8_rulecheck", MODULE)
rulecheck = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rulecheck)


class RulecheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "matching/cl").mkdir(parents=True)
        (self.root / "config").mkdir()
        binaries = {name: {} for name in ("cl", "c1", "c1xx", "c2", "link")}
        (self.root / "config/project.json").write_text(json.dumps({"binaries": binaries}), encoding="utf-8")
        self.policy ={"schema_version": 1, "reviews": [], "exceptions": []}
        self.write_policy()

    def write_policy(self):
        (self.root / "config/rule-exceptions.json").write_text(json.dumps(self.policy), encoding="utf-8")

    def source(self, code, name="matching/cl/unit.cpp"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")
        return path

    def scan(self, paths=None):
        return rulecheck.check(paths, root=self.root)

    def evidence(self):
        path = self.root / "evidence/review.txt"
        path.parent.mkdir(exist_ok=True)
        path.write_text("Synthetic test attestation only; not actual VC8 evidence.\n", encoding="utf-8")
        return [{"path": "evidence/review.txt", "sha256": rulecheck.sha256(path.read_bytes()), "description": "contract test fixture"}]

    def review(self, fn, exception=None):
        evidence = self.evidence()
        review = {key: fn[key] for key in ("binary", "va", "source_path", "source_sha256", "scope_sha256")}
        review.update(reviewer="test fixture", checks={rule: {"verdict": "exception" if rule == exception else "pass", "evidence": evidence} for rule in rulecheck.MATCH_RULES})
        self.policy["reviews"].append(review)
        self.write_policy()
        return review

    def assert_rule(self, code, rule, name="matching/cl/unit.cpp"):
        self.source(code, name)
        report = self.scan()
        self.assertTrue(any(item["rule"] == rule and item["severity"] == "blocking" for item in report["findings"]), report)
        self.assertFalse(report["passed"])
        return report

    def test_empty_tree_zero_admissions(self):
        report = self.scan()
        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["rule_admitted"], 0)

    def test_missing_tree_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "does not exist"):
            self.scan(["absent"])

    def test_clean_scan_requires_review(self):
        self.source("// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n")
        fn = self.scan()["functions"][0]
        self.assertEqual(fn["review_required"], list(rulecheck.MATCH_RULES))
        self.assertEqual(fn["status"], "MATCH-PENDING")
        self.assertFalse(fn["admitted"])

    def test_placeholder_naming_does_not_block_reviewed_function(self):
        self.source("// FUNCTION: cl 0x401000\nint FUN_00401000(int param_1) { return param_1; }\n")
        self.review(self.scan()["functions"][0])
        report = self.scan()
        self.assertTrue(report["passed"])
        self.assertEqual(report["functions"][0]["status"], "RULE-ADMITTED")
        self.assertTrue(all(item["rule"] == "R7" for item in report["findings"]))

    def test_source_edit_invalidates_review(self):
        path = self.source("// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n")
        self.review(self.scan()["functions"][0])
        path.write_text(path.read_text() + "// changed source layout\n")
        self.assertFalse(self.scan()["functions"][0]["admitted"])

    def test_header_edit_invalidates_review(self):
        self.source("struct Item { int value; };\n", "matching/cl/shared.h")
        self.source('#include "shared.h"\n// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n')
        self.review(self.scan()["functions"][0])
        self.source("struct Item { long value; };\n", "matching/cl/shared.h")
        self.assertFalse(self.scan()["functions"][0]["admitted"])

    def test_quoted_header_outside_matching_is_hashed(self):
        header = self.source("struct Item { int value; };\n", "include/shared.h")
        self.source('#include "shared.h"\n// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n')
        report = self.scan()
        self.assertIn("include/shared.h", {item["path"] for item in report["files"]})
        self.review(report["functions"][0])
        self.assertTrue(self.scan()["passed"])
        header.write_text("struct Item { long value; };\n")
        self.assertFalse(self.scan()["passed"])

    def test_unresolved_quoted_include_fails_closed(self):
        self.source('#include "missing.h"\n')
        with self.assertRaisesRegex(ValueError, "unresolved quoted include"):
            self.scan()

    def test_commented_include_does_not_trigger_dependency_lookup(self):
        self.source('/*\n#include "missing.h"\n*/\n')
        self.assertTrue(self.scan()["passed"])

    def test_changed_evidence_fails_closed(self):
        self.source("// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n")
        self.review(self.scan()["functions"][0])
        (self.root / "evidence/review.txt").write_text("changed")
        self.assertFalse(self.scan()["passed"])

    def test_duplicate_reviews_not_arbitrarily_selected(self):
        self.source("// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n")
        review = self.review(self.scan()["functions"][0])
        self.policy["reviews"].append(review)
        self.write_policy()
        self.assertFalse(self.scan()["passed"])

    def test_partial_review_missing_match_rule_blocks(self):
        self.source("// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n")
        review = self.review(self.scan()["functions"][0])
        del review["checks"]["R13"]
        self.write_policy()
        self.assertEqual(self.scan()["functions"][0]["review_required"], ["R13"])

    def test_comment_and_literal_patterns_do_not_fire(self):
        self.source('/* __asm volatile dummy pad0 */\n// FUNCTION: cl 0x401000\nint Count(void) { const char *message = "__asm volatile dummy"; return message[0]; }\n')
        self.assertEqual(self.scan()["findings"], [])

    def test_fake_annotations_inside_block_comments_ignored(self):
        self.source("/*\n// FUNCTION: cl 0x401000\n*/\n")
        self.assertEqual(self.scan()["functions"], [])

    def test_line_spliced_comment_cannot_manufacture_annotation(self):
        self.source("// continued \\\n// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n")
        self.assertEqual(self.scan()["functions"], [])

    def test_function_bounds_ignore_literal_braces(self):
        self.source('// FUNCTION: cl 0x401000\nconst char *Get(void) { return "} {"; }\n// FUNCTION: cl 0x401010\nint Count(void) { return 2; }\n')
        functions = self.scan()["functions"]
        self.assertEqual(len(functions), 2)
        self.assertEqual(functions[0]["end_line"], 2)

    def test_typedef_in_unit_blocks(self):
        self.assert_rule("typedef unsigned long Flags;\n", "R1")

    def test_type_in_unit_blocks(self):
        self.assert_rule("struct Item { int count; };\n", "R1")

    def test_duplicate_header_types_and_keyword_mismatch(self):
        self.source("class Item;\nstruct Item { int value; };\n", "matching/cl/shared.h")
        self.assertTrue(any(item["rule"] == "R1" for item in self.scan()["findings"]))
        self.source("struct Item { int value; };\n", "matching/cl/other.h")
        self.assertTrue(any("duplicate type" in item["message"] for item in self.scan()["findings"]))

    def test_global_extern_in_unit_blocks(self):
        self.assert_rule("extern int g_count;\n", "R2")

    def test_conflicting_global_declarations_block(self):
        self.source("extern int g_count;\n", "matching/cl/a.h")
        self.source("extern long g_count;\n", "matching/cl/b.h")
        self.assertFalse(self.scan()["passed"])

    def test_canonical_header_no_syntax_findings(self):
        self.source("struct Item { int value; };\nextern Item *g_item;\n", "matching/cl/shared.h")
        self.assertEqual(self.scan()["findings"], [])

    def test_offset_cast_forms_block(self):
        forms = ["return *(int *)((char *)obj + 0x10);", "return *((int *)(obj + 16));", "return ((int *)this)[0];", "return reinterpret_cast<int *>(this)[0];", "return *(reinterpret_cast<char *>(obj) + 16);", "return (int)this;"]
        for body in forms:
            with self.subTest(body=body):
                self.assert_rule("// FUNCTION: cl 0x401000\nint Count(void *obj) { " + body + " }\n", "R4")

    def test_macro_offset_cast_not_hidden_by_preprocessor(self):
        self.assert_rule("#define FIELD(p) (*(int *)((char *)p + 16))\n", "R4")

    def test_dummy_virtual_blocks(self):
        self.assert_rule("struct Item { virtual void slot3(); };\n", "R13", "matching/cl/shared.h")

    def test_volatile_and_unused_locals_block(self):
        self.assert_rule("// FUNCTION: cl 0x401000\nint Count(void) { volatile int carry = 1; return carry; }\n", "R17")
        self.assert_rule("// FUNCTION: cl 0x401000\nint Count(void) { int carry; return 1; }\n", "R17")

    def test_byte_array_masquerade_blocks(self):
        self.assert_rule("unsigned char body[] = {0x55, 0x8b, 0xec};\n", "R17")

    def test_asm_tokens_block(self):
        for token in ["__asm { nop }", "_asm nop", 'asm ("nop")', "INCLUDE_ASM(Count)", "__emit(0x90)"]:
            with self.subTest(token=token):
                self.assert_rule("// FUNCTION: cl 0x401000\nvoid Count(void) { " + token + "; }\n", "R18")

    def test_vc8_cpp_and_ms_c89_dialects(self):
        self.assert_rule("// FUNCTION: cl 0x401000\nvoid Count(void) { auto p = nullptr; }\n", "R22")
        self.assert_rule("// FUNCTION: c2 0x401000\nvoid Count(void) { for (int i = 0; i < 4; ++i) {} }\n", "R22", "matching/c2/count.c")

    def test_stop_marker_blocks_incomplete_function(self):
        self.assert_rule("// FUNCTION: cl 0x401000\nint Count(void) {\n// stop: untested lead\nreturn 1;\n}\n", "STOP")

    def test_missing_body_and_malformed_annotations_block(self):
        self.assert_rule("// FUNCTION: cl 0x401000\nint Count(void);\n", "ANNOTATION")
        self.assert_rule("// FUNCTION: cl not-an-address\n", "ANNOTATION")

    def test_duplicate_address_blocks_both_functions(self):
        self.source("// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n// FUNCTION: cl 0x401000\nint Other(void) { return 2; }\n")
        for fn in self.scan()["functions"]:
            self.assertIn("ANNOTATION", fn["blocking_rules"])

    def test_duplicate_address_in_separate_units_blocks_both(self):
        self.source("// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n")
        self.source("// FUNCTION: cl 0x401000\nint Other(void) { return 2; }\n", "matching/cl/other.cpp")
        for fn in self.scan()["functions"]:
            self.assertIn("ANNOTATION", fn["blocking_rules"])

    def test_pass_attestation_does_not_override_detected_violation(self):
        self.source("// FUNCTION: cl 0x401000\nvoid Count(void) { __asm { nop } }\n")
        self.review(self.scan()["functions"][0])
        self.assertIn("R18", self.scan()["functions"][0]["blocking_rules"])

    def test_exception_needs_allow_evidence_and_source_marker(self):
        self.source("// FUNCTION: cl 0x401000\n// RULE-EXCEPTION: R18, original helper bytes establish the instruction\nvoid Count(void) { __asm { nop } }\n")
        fn = self.scan()["functions"][0]
        self.review(fn, exception="R18")
        self.assertFalse(self.scan()["passed"])
        entry = {key: fn[key] for key in ("binary", "va", "source_path", "source_sha256", "scope_sha256")}
        entry.update(rule="R18", allow=True, reviewer="test fixture", reason="synthetic original-helper byte evidence", evidence=self.evidence())
        self.policy["exceptions"].append(entry)
        self.write_policy()
        report = self.scan()
        self.assertTrue(report["passed"])
        self.assertEqual(report["functions"][0]["allowed_exceptions"], ["R18"])
        self.assertTrue(any(item["rule"] == "R18" for item in report["findings"]))

    def test_exception_comment_alone_does_not_waive_violation(self):
        self.assert_rule("// FUNCTION: cl 0x401000\n// RULE-EXCEPTION: R18, convenient\nvoid Count(void) { __asm { nop } }\n", "R18")

    def test_exception_cannot_leak_to_next_function(self):
        self.source("// FUNCTION: cl 0x401000\n// RULE-EXCEPTION: R18, byte evidence\nvoid Count(void) { __asm { nop } }\n// FUNCTION: cl 0x401010\nvoid Other(void) { __asm { nop } }\n")
        first, second = self.scan()["functions"]
        self.review(first, exception="R18")
        self.review(second)
        entry = {key: first[key] for key in ("binary", "va", "source_path", "source_sha256", "scope_sha256")}
        entry.update(rule="R18", allow=True, reviewer="test", reason="byte evidence", evidence=self.evidence())
        self.policy["exceptions"].append(entry)
        self.write_policy()
        report = self.scan()
        self.assertTrue(report["functions"][0]["admitted"])
        self.assertFalse(report["functions"][1]["admitted"])

    def test_header_findings_block_reviewed_candidate(self):
        self.source("struct Item { virtual void pad0(); };\n", "matching/cl/shared.h")
        self.source("// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n")
        self.review(self.scan()["functions"][0])
        self.assertIn("R13", self.scan()["functions"][0]["blocking_rules"])

    def test_review_evidence_cannot_escape_repository(self):
        self.assertFalse(rulecheck.evidence_valid([{"path": "../escape.txt", "sha256": "a" * 64, "description": "escape"}], self.root))

    def test_invalid_policy_not_silently_accepted(self):
        self.policy["exceptions"] = [{"allow": True, "rule": "R18"}]
        self.write_policy()
        with self.assertRaises(ValueError):
            self.scan()

    def test_unterminated_lexical_input_fails(self):
        self.source("/* unterminated")
        with self.assertRaises(ValueError):
            self.scan()

    def test_cli_json_root_independent_and_exit_codes(self):
        (self.root / "tools").mkdir()
        shutil.copyfile(MODULE, self.root / "tools/rulecheck.py")
        shutil.copyfile(MODULE.with_name("matchlib.py"), self.root / "tools/matchlib.py")
        command = [sys.executable, str(self.root / "tools/rulecheck.py"), "matching", "--json", "-"]
        completed = subprocess.run(command, cwd=self.root.parent, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["summary"]["functions"], 0)
        self.source("// FUNCTION: cl 0x401000\nint Count(void) { return 1; }\n")
        completed = subprocess.run(command, cwd=self.root.parent, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(completed.stdout)["functions"][0]["admitted"])
        command[2] = "missing"
        completed = subprocess.run(command, cwd=self.root.parent, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("error", json.loads(completed.stdout))

    def test_cli_writes_json_file(self):
        (self.root / "tools").mkdir()
        shutil.copyfile(MODULE, self.root / "tools/rulecheck.py")
        shutil.copyfile(MODULE.with_name("matchlib.py"), self.root / "tools/matchlib.py")
        target = self.root / "result.json"
        completed = subprocess.run([sys.executable, str(self.root / "tools/rulecheck.py"), "matching", "--json", str(target)], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(target.read_text())["passed"])
        self.assertIn("Rule-admitted: 0/0", completed.stdout)


if __name__ == "__main__":
    unittest.main()
