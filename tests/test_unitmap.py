import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("unitmap", ROOT / "tools/unitmap.py")
unitmap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(unitmap)


class UnitMapTests(unittest.TestCase):
    def fixture(self):
        return {
            "binary": "cl", "modules": [
                {"index": 0, "module_name": "driver.obj", "object_name": "F:/build/driver.obj"},
                {"index": 1, "module_name": "crt.lib(startup.obj)", "source_files": ["crt/crtexe.c"]},
            ],
            "publics": [
                {"name": "DriverMain", "rva": 4096, "kind": "function"},
                {"name": "mainCRTStartup", "rva": 8192, "kind": "function"},
                {"name": "data", "rva": 12288, "kind": "data"},
            ],
        }

    def test_inventory_never_attributes_or_invents_source(self):
        result = unitmap.build_map(self.fixture(), "cl")
        self.assertEqual(result["statistics"]["module_unresolved_symbols"], 2)
        self.assertEqual(result["modules"][0]["source_files"], [])
        self.assertTrue(all(f["source_owner"] is None for f in result["functions"]))
        self.assertEqual(result["modules"][1]["source_files"], ["crt/crtexe.c"])

    def test_direct_procedure_and_unique_contribution(self):
        data = self.fixture()
        data["module_symbols"] = [{"module_index": 0, "rva": 4096, "kind": "procedure"}]
        data["section_contributions"] = [{"module_index": 1, "rva": 8192, "size": 32}]
        result = unitmap.build_map(data, "cl")
        self.assertEqual([f["module_index"] for f in result["functions"]], [0, 1])
        self.assertEqual([f["module_confidence"] for f in result["functions"]], ["direct", "contribution"])
        self.assertEqual(result["statistics"]["proven_source_owners"], 0)

    def test_overlap_is_ambiguous_and_end_is_exclusive(self):
        data = self.fixture()
        data["section_contributions"] = [
            {"module_index": 0, "rva": 4096, "size": 4096},
            {"module_index": 1, "rva": 4096, "size": 8},
        ]
        functions = unitmap.build_map(data, "cl")["functions"]
        self.assertEqual(functions[0]["module_status"], "ambiguous")
        self.assertEqual(functions[0]["candidate_modules"], [0, 1])
        self.assertEqual(functions[1]["module_status"], "unresolved")

    def test_conflicting_direct_record_and_contribution_are_unresolved(self):
        data = self.fixture()
        data["module_symbols"] = [{"module_index": 0, "rva": 4096, "is_function": True}]
        data["section_contributions"] = [{"module_index": 1, "rva": 4096, "size": 32}]
        function = unitmap.build_map(data, "cl")["functions"][0]
        self.assertEqual(function["module_status"], "conflicting_evidence")
        self.assertIsNone(function["module_index"])

    def test_section_offsets_work_without_rvas(self):
        data = {"modules": [{"index": 3}], "publics": [
            {"name": "f", "section": 1, "offset": 16, "is_function": True},
            {"name": "g", "section": 2, "offset": 16, "is_function": True},
        ], "section_contributions": [{"module_index": 3, "section": 1, "offset": 0, "size": 32}]}
        functions = unitmap.build_map(data, "cl")["functions"]
        self.assertEqual([f["module_index"] for f in functions], [3, None])

    def test_assert_is_qualified_and_requires_exact_known_boundary(self):
        reference = {"function_rva": 4096, "file": "F:/compiler/file.c", "line": 42,
                     "evidence": {"xref_rva": 4101, "method": "decoded_push_argument"}}
        result = unitmap.build_map(self.fixture(), "cl", {"references": [reference]})
        self.assertEqual(result["functions"][0]["source_status"], "qualified_assert_reference")
        self.assertIsNone(result["functions"][0]["source_owner"])
        reference["function_rva"] += 1
        with self.assertRaisesRegex(unitmap.EvidenceError, "exact public function start"):
            unitmap.build_map(self.fixture(), "cl", {"references": [reference]})

    def test_aliases_are_symbols_and_unique_starts_are_separate(self):
        data = self.fixture()
        data["publics"].append({"name": "DriverAlias", "rva": 4096, "kind": "function"})
        stats = unitmap.build_map(data, "cl")["statistics"]
        self.assertEqual(stats["public_function_symbols"], 3)
        self.assertEqual(stats["unique_public_function_starts"], 2)

    def test_invalid_evidence_rejected(self):
        for bad in [-1, True, 3.5, None, "garbage"]:
            with self.subTest(value=bad), self.assertRaises(unitmap.EvidenceError):
                unitmap.integer(bad, "value")
        data = self.fixture()
        data["modules"].append({"index": 0})
        with self.assertRaisesRegex(unitmap.EvidenceError, "duplicate"):
            unitmap.build_map(data, "cl")
        data = self.fixture()
        data["module_symbols"] = [{"module_index": 9, "rva": 4096, "is_function": True}]
        with self.assertRaisesRegex(unitmap.EvidenceError, "missing module"):
            unitmap.build_map(data, "cl")

    def test_cli_writes_provenance_and_fails_without_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            project = base / "project.json"
            symbols = base / "cl.symbols.json"
            config = base / "units.json"
            output = base / "out.units.json"
            project.write_text(json.dumps({"binaries": {"cl": {}}, "primary_checkout": temporary}))
            symbols.write_text(json.dumps(self.fixture()))
            config.write_text("{}")
            self.assertEqual(unitmap.main(["--binary", "cl", "--project", str(project), "--config", str(config), "--symbols", str(symbols), "--output", str(output)]), 0)
            result = json.loads(output.read_text())
            self.assertEqual(len(result["input"]["sha256"]), 64)
            self.assertEqual(unitmap.main(["--binary", "bad", "--project", str(project)]), 2)
            self.assertEqual(unitmap.main(["--binary", "cl", "--project", str(project)]), 2)

    def test_symbols_schema_and_library_members(self):
        data = {"binary": "cl", "sections": [{"index": 1, "rva": 4096}],
                "modules": [{"index": 0, "name": "crt/startup.obj", "object_file": "msvcrt.lib"},
                            {"index": 1, "name": "MSVCR80.dll", "object_file": "msvcrt.lib"}],
                "functions": [{"name": "f", "rva": 4096, "section_index": 1, "section_offset": 0},
                              {"name": "thunk", "rva": 4100, "section_index": 1, "section_offset": 4}],
                "section_contributions": [{"module_index": 0, "section": 1, "offset": 0, "size": 4},
                                          {"module_index": 1, "section": 1, "offset": 4, "size": 6}]}
        result = unitmap.build_map(data, "cl")
        self.assertEqual(result["modules"][0]["object_name"], "crt/startup.obj")
        self.assertEqual(result["modules"][0]["container_file"], "msvcrt.lib")
        self.assertEqual(result["statistics"]["import_module_symbols"], 1)
        self.assertEqual([f["module_index"] for f in result["functions"]], [0, 1])

    def test_lane_pin_overlap_and_import_rejection(self):
        data = self.fixture()
        data["module_symbols"] = [{"module_index": 0, "rva": 4096, "kind": "procedure"}]
        mapped = unitmap.build_map(data, "cl")
        config = {"binaries": {"cl": {"object_lanes": [{"id": "driver", "module_indices": [0]}]}}}
        unitmap.apply_lanes(mapped, config)
        self.assertEqual(mapped["object_lanes"][0]["function_names"], ["DriverMain"])
        config["binaries"]["cl"]["object_lanes"].append({"id": "overlap", "module_indices": [0]})
        with self.assertRaisesRegex(unitmap.EvidenceError, "overlap"):
            unitmap.apply_lanes(mapped, config)
        config["binaries"]["cl"]["object_lanes"] = [{"id": "not-object", "module_indices": [1]}]
        with self.assertRaisesRegex(unitmap.EvidenceError, "not an evidenced object"):
            unitmap.apply_lanes(mapped, config)
        config["binaries"]["cl"]["binary_sha256"] = "1234"
        with self.assertRaisesRegex(unitmap.EvidenceError, "SHA-256"):
            unitmap.apply_lanes(mapped, config)

    def test_embedded_source_inventory_requires_hash_and_never_infers_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "input.bin"
            payload = b"\0F:\\src\\file.c\0F:\\src\\object.obj\0" + "F:\\src\\wide.cpp".encode("utf-16le") + b"\0\0"
            binary.write_bytes(payload)
            identity = {"binary_path": str(binary), "binary_sha256": hashlib.sha256(payload).hexdigest()}
            inventory = unitmap.source_path_inventory(identity, [{"raw_offset": 0, "raw_size": len(payload), "rva": 4096}])
            self.assertEqual(inventory["unique_paths"], 2)
            self.assertEqual({f["path"] for f in inventory["paths"]}, {"F:\\src\\file.c", "F:\\src\\wide.cpp"})
            self.assertTrue(all(f["rva"] == 4096 + f["file_offset"] for f in inventory["paths"]))
            identity["binary_sha256"] = "wrong"
            with self.assertRaisesRegex(unitmap.EvidenceError, "SHA-256 mismatch"):
                unitmap.source_path_inventory(identity, [])

    def test_cli_filtered_lane_is_an_exact_function_list(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            data = self.fixture()
            data["module_symbols"] = [{"module_index": 0, "rva": 4096, "kind": "procedure"}]
            paths = {name: base / (name + ".json") for name in ("project", "symbols", "config", "output")}
            paths["project"].write_text(json.dumps({"binaries": {"cl": {}}, "primary_checkout": temporary}))
            paths["symbols"].write_text(json.dumps(data))
            paths["config"].write_text(json.dumps({"binaries": {"cl": {"object_lanes": [{"id": "driver", "module_indices": [0]}]}}}))
            args = ["--binary", "cl", "--lane", "driver"]
            for name, path in paths.items():
                args.extend(["--" + name, str(path)])
            self.assertEqual(unitmap.main(args), 0)
            result = json.loads(paths["output"].read_text())
            self.assertEqual([f["name"] for f in result["functions"]], ["DriverMain"])
            self.assertEqual([m["module_index"] for m in result["modules"]], [0])
            self.assertEqual(result["selection"]["public_function_symbols"], 1)


if __name__ == "__main__":
    unittest.main()
