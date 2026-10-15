"""Focused gate contract tests; fixtures are synthetic, never retail payloads."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "tools" / "gate.py"
spec = importlib.util.spec_from_file_location("gate", MODULE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class Image:
    def __init__(self, base, code, relocations=()):
        self.base, self.data, self.relocations = base, code, relocations
        self.sections = [{"va": base, "rawsize": len(code), "chars": 0x60000020}]

    def read(self, va, size):
        gate.require(self.base <= va and va + size <= self.base + len(self.data), "not file backed")
        return self.data[va - self.base:va - self.base + size]

    def offset_of(self, va, size=1):
        self.read(va, size)
        return va - self.base

    def base_relocations(self):
        return self.relocations

    def sha256(self):
        return gate.digest(self.data)

    def verify_identity(self):
        pass


class GateTests(unittest.TestCase):
    def setUp(self):
        self.retail = Image(0x1000, b"\xb8" + struct.pack("<I", 0x2000) + b"\xe8" + struct.pack("<i", 0x3000 - 0x100a) + b"\xc3",
                            [{"va": 0x1001, "type": 3, "width": 4}])
        self.built = Image(0x4000, b"\xb8" + struct.pack("<I", 0x5000) + b"\xe8" + struct.pack("<i", 0x6000 - 0x400a) + b"\xc3",
                           [{"va": 0x4001, "type": 3, "width": 4}])
        self.request = {"retail_va": "0x1000", "size": 11,
                        "boundary": {"status": "verified", "evidence": "synthetic fixture extent"}}
        self.claim = {"retail_va": "0x1000", "candidate_va": "0x4000", "size": 11,
                      "boundary": self.request["boundary"], "bytes_sha256": gate.digest(self.built.data),
                      "referents": [{"offset": 1, "width": 4, "kind": "abs32", "target": 0x5000, "identity": "datum", "resolved": True},
                                    {"offset": 6, "width": 4, "kind": "rel32", "target": 0x6000, "identity": "callee", "resolved": True}]}
        self.identities = {"datum": {"va": "0x2000", "evidence": "fixture"},
                           "callee": {"va": "0x3000", "evidence": "fixture"}}

    def compare(self, claim=None, built=None):
        return gate.compare_candidate(self.retail, built or self.built, claim or self.claim, self.request, self.identities,
                                      {0x5000: {"datum"}, 0x6000: {"callee"}})

    def test_exact_compiled_bytes_and_referents(self):
        code, refs = self.compare()
        self.assertEqual(code, self.retail.data)
        self.assertEqual(refs, 2)

    def test_tampered_manifest_target_rejected(self):
        claim = copy.deepcopy(self.claim)
        claim["referents"][1]["target"] += 1
        with self.assertRaisesRegex(gate.GateError, "decoded emitted"):
            self.compare(claim)

    def test_omitted_or_unresolved_referent_rejected(self):
        for mutate in (lambda c: c["referents"].pop(), lambda c: c["referents"][0].update(resolved=False)):
            claim = copy.deepcopy(self.claim)
            mutate(claim)
            with self.assertRaises(gate.GateError):
                self.compare(claim)

    def test_wrong_identity_rejected_even_if_masked_bytes_equal(self):
        self.identities["callee"]["va"] = "0x3001"
        with self.assertRaisesRegex(gate.GateError, "target differs"):
            self.compare()

    def test_wrong_body_rejected(self):
        bad = Image(0x4000, self.built.data[:-1] + b"\x90", self.built.relocations)
        claim = copy.deepcopy(self.claim)
        claim["bytes_sha256"] = gate.digest(bad.data)
        with self.assertRaisesRegex(gate.GateError, "byte comparison"):
            self.compare(claim, bad)

    def test_unsupported_relocation_and_size_rejected(self):
        bad = Image(0x4000, self.built.data, [{"va": 0x4001, "type": 5, "width": None}])
        with self.assertRaisesRegex(gate.GateError, "unsupported PE"):
            self.compare(built=bad)
        claim = copy.deepcopy(self.claim)
        claim["size"] = 10
        with self.assertRaisesRegex(gate.GateError, "size change"):
            self.compare(claim)

    def test_overlapping_splices_rejected_including_aliases(self):
        image, spans = bytearray(16), []
        gate.splice(image, spans, 4, b"1234")
        for offset in (3, 4, 7):
            with self.assertRaisesRegex(gate.GateError, "overlapping"):
                gate.splice(image, spans, offset, b"ab")
        with self.assertRaises(gate.GateError):
            gate.splice(image, spans, 15, b"ab")

    def test_stale_and_copied_retail_manifests_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"schema_version": 1, "binary": "cl", "build_id": "old", "candidates": []}
            with self.assertRaisesRegex(gate.GateError, "stale"):
                gate.validate_manifest(manifest, "cl", "fresh", root, root)
            manifest.update(build_id="fresh", status="built", candidates=[{"symbol": "copied-retail"}])
            with self.assertRaisesRegex(gate.GateError, "source/toolchain"):
                gate.validate_manifest(manifest, "cl", "fresh", root, root)

    def test_all_five_fallback_hashes_zero_counts_and_fresh_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config" / "gate-allow.json").write_text('{"schema_version":1,"candidates":[],"referents":{}}')
            calls = []
            def load(name, root=None):
                calls.append(name)
                return name
            class Retail(Image):
                def __init__(self, name):
                    super().__init__(0x1000, (name + " fixture").encode())
            module = types.SimpleNamespace(load_binary_config=load, Retail=Retail)
            result = gate.execute_gate("all", root, module)
            second = gate.execute_gate("cl", root, module)
            self.assertEqual(result["status"], "GREEN")
            self.assertNotEqual(result["run_id"], second["run_id"])
            self.assertEqual(calls, list(gate.BINARIES) * 2)
            self.assertIn("BANKED", result["authority"])
            for item in result["binaries"].values():
                self.assertEqual(item["functions"], 0)
                self.assertEqual(item["source_bytes"], 0)
                self.assertEqual(item["input_sha256"], item["output_sha256"])
            latest = json.loads((root / "build" / "gate" / "latest.json").read_text())
            self.assertEqual(latest["run_id"], second["run_id"])

    def test_bad_reference_pin_blocks_every_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config" / "gate-allow.json").write_text('{"schema_version":1,"candidates":[]}')
            class Retail(Image):
                def __init__(self, cfg):
                    super().__init__(0x1000, b"fixture")
                def verify_identity(self):
                    raise gate.GateError("tampered reference pin")
            module = types.SimpleNamespace(load_binary_config=lambda *a, **k: {}, Retail=Retail)
            result = gate.execute_gate("all", root, module)
            self.assertEqual(result["status"], "RED")
            self.assertIsNone(result["authority"])

    def manifest_fixture(self, root):
        (root / "config").mkdir()
        output = root / "fresh"
        output.mkdir()
        source, compiler, linker = root / "unit.cpp", root / "cl.exe", root / "link.exe"
        obj, image, mapfile = output / "source.obj", output / "candidate.dll", output / "candidate.map"
        for path in (source, compiler, linker, obj, image):
            path.write_bytes((path.name + " synthetic").encode())
        mapfile.write_text(" 0001:00000000 _fixture 10001000 f source.obj\n")
        def item(path, kind=None):
            record = {"path": str(path), "sha256": gate.digest(path.read_bytes())}
            if kind:
                record["kind"] = kind
            return record
        tools = [item(compiler), item(linker)]
        (root / "config" / "toolchains.json").write_text(json.dumps({"toolchains": {"fixture": {"files": tools}}}))
        manifest = {"schema_version": 1, "binary": "cl", "build_id": "fresh", "status": "built",
                    "source_inputs": [item(source)], "toolchain": tools,
                    "commands": [{"argv": [str(compiler), "/GL", "/Fo" + str(obj), str(source)], "cwd": str(root),
                                  "returncode": 0, "produced": [str(obj)]},
                                 {"argv": [str(linker), "/LTCG", "/OUT:" + str(image), "/MAP:" + str(mapfile), str(obj)],
                                  "cwd": str(root), "returncode": 0, "produced": [str(image), str(mapfile)]}],
                    "artifacts": [item(obj, "ltcg-object"), item(image, "linked-image"), item(mapfile, "linker-map")],
                    "candidates": [{"symbol": "_fixture", "candidate_va": "0x10001000", "image_path": str(image), "source_path": str(source)}]}
        return output, manifest

    def test_pinned_manifest_and_independent_map_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, manifest = self.manifest_fixture(root)
            sources, artifacts = gate.validate_manifest(manifest, "cl", "fresh", output, root)
            self.assertEqual(len(sources), 1)
            gate.verify_linked_symbol(manifest["candidates"][0], manifest, artifacts, root)
            manifest["candidates"][0]["candidate_va"] = "0x10001001"
            with self.assertRaisesRegex(gate.GateError, "symbol identity/address"):
                gate.verify_linked_symbol(manifest["candidates"][0], manifest, artifacts, root)

    def test_tampered_manifest_provenance_failure_paths(self):
        mutations = [
            ("did not finish", lambda m: m.update(status="failed")),
            ("duplicate provenance", lambda m: m["source_inputs"].append(m["source_inputs"][0])),
            ("configured pins", lambda m: m["toolchain"].pop()),
            ("attribution", lambda m: m["commands"][0].update(produced=[])),
            ("preceding compiled", lambda m: m["commands"].reverse()),
            ("/GL", lambda m: m["commands"][0]["argv"].remove("/GL")),
            ("/LTCG", lambda m: m["commands"][1]["argv"].remove("/LTCG")),
        ]
        for message, mutate in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output, manifest = self.manifest_fixture(root)
                mutate(manifest)
                with self.assertRaisesRegex(gate.GateError, message):
                    gate.validate_manifest(manifest, "cl", "fresh", output, root)

    def test_relocation_cannot_mask_instruction_opcode(self):
        image = Image(0x4000, b"\xb8\x00\x50\x00\x00\xc3", [{"va": 0x4000, "width": 4, "type": 3}])
        with self.assertRaisesRegex(gate.GateError, "decoded operand field"):
            gate.scan_referents(image, 0x4000, image.data)

    def test_exe_immediate_referent_without_base_relocation(self):
        image = Image(0x4000, b"\xb8\x05\x40\x00\x00\xc3")
        self.assertEqual(gate.scan_referents(image, 0x4000, image.data),
                         [{"offset": 1, "width": 4, "kind": "abs32", "target": 0x4005}])

    def test_relabeling_wrong_emitted_target_cannot_pass(self):
        claim = copy.deepcopy(self.claim)
        wrong = Image(0x4000, self.built.data[:6] + struct.pack("<i", 0x7000 - 0x400a) + b"\xc3", self.built.relocations)
        claim["bytes_sha256"] = gate.digest(wrong.data)
        claim["referents"][1]["target"] = 0x7000
        with self.assertRaisesRegex(gate.GateError, "independently identify"):
            gate.compare_candidate(self.retail, wrong, claim, self.request, self.identities,
                                   {0x5000: {"datum"}, 0x7000: {"different_callee"}})

    def test_dependency_object_cannot_be_claimed_as_another_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, manifest = self.manifest_fixture(root)
            _, artifacts = gate.validate_manifest(manifest, "cl", "fresh", output, root)
            manifest["candidates"][0]["source_path"] = str(root / "other.cpp")
            with self.assertRaisesRegex(gate.GateError, "different source unit"):
                gate.verify_linked_symbol(manifest["candidates"][0], manifest, artifacts, root)

    def test_per_binary_descriptors_merge_and_conflicts_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.mkdir()
            (config / "gate-allow.json").write_text('{"schema_version":1,"candidates":[],"referents":{}}')
            descriptor = {"schema_version": 1, "candidates": [{"binary": "cl", "symbol": "_f", "retail_va": "0x401000"}],
                          "referents": {"cl": {"_data": {"va": "0x402000", "evidence": "fixture"}}}}
            (config / "cl-candidates.json").write_text(json.dumps(descriptor))
            self.assertEqual(len(gate.load_registry(root)["candidates"]), 1)
            (config / "gate-allow.json").write_text(json.dumps(descriptor))
            with self.assertRaisesRegex(gate.GateError, "duplicate candidate"):
                gate.load_registry(root)
            descriptor["candidates"] = []
            descriptor["referents"]["cl"]["_data"]["va"] = "0x402001"
            (config / "gate-allow.json").write_text(json.dumps(descriptor))
            with self.assertRaisesRegex(gate.GateError, "conflicting referent"):
                gate.load_registry(root)
            (config / "gate-allow.json").write_text('{"schema_version":1,"candidates":[]}')
            descriptor["candidates"] = [{"binary": "cl", "symbol": "_f", "retail_va": "0x401000", "gate_enabled": "false"}]
            (config / "cl-candidates.json").write_text(json.dumps(descriptor))
            with self.assertRaisesRegex(gate.GateError, "must be a boolean"):
                gate.load_registry(root)

    def test_complete_source_admission_has_fresh_persisted_byte_witnesses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("config", "matching/cl", "tools", "toolbin"):
                (root / name).mkdir(parents=True)
            source = root / "matching/cl/unit.cpp"
            source.write_text("// FUNCTION: cl 0x1000\nvoid fixture(void) {}\n")
            source_hash = gate.digest(source.read_bytes())
            function_hash = gate.digest(b"void fixture(void) {}")
            boundary = {"status": "verified", "evidence": "synthetic one-instruction fixture"}
            request = {"binary": "cl", "symbol": "_fixture", "retail_va": "0x1000", "size": 1,
                       "unit": "matching/cl/unit.cpp", "source_span": {"start": 2, "end": 2}, "boundary": boundary}
            (root / "config/gate-allow.json").write_text(json.dumps({"schema_version": 1, "candidates": [request]}))
            for name in ("match.py", "rulecheck.py"):
                (root / "tools" / name).write_text("# synthetic trusted-runner fixture\n")
            compiler, linker = root / "toolbin/cl.exe", root / "toolbin/link.exe"
            for tool in (compiler, linker):
                tool.write_bytes(b"synthetic tool fixture")
            def item(path, kind=None):
                record = {"path": str(path), "sha256": gate.digest(path.read_bytes())}
                if kind:
                    record["kind"] = kind
                return record
            tools = [item(compiler), item(linker)]
            (root / "config/toolchains.json").write_text(json.dumps({"toolchains": {"fixture": {"files": tools}}}))
            def runner(argv, **kwargs):
                if Path(argv[1]).name == "match.py":
                    output = Path(argv[argv.index("--output-dir") + 1])
                    token = argv[argv.index("--build-id") + 1]
                    obj, image, mapfile = output / "source.obj", output / "candidate.dll", output / "candidate.map"
                    obj.write_bytes(b"synthetic compiler object")
                    image.write_bytes(b"\xc3")
                    mapfile.write_text(" 0001:00000000 _fixture 00001000 f source.obj\n")
                    manifest = {"schema_version": 1, "binary": "cl", "build_id": token, "status": "built",
                        "source_inputs": [item(source)], "toolchain": tools,
                        "commands": [{"argv": [str(compiler), "/GL", "/Fo" + str(obj), str(source)], "cwd": str(root), "returncode": 0, "produced": [str(obj)]},
                                     {"argv": [str(linker), "/LTCG", "/OUT:" + str(image), "/MAP:" + str(mapfile), str(obj)], "cwd": str(root), "returncode": 0, "produced": [str(image), str(mapfile)]}],
                        "artifacts": [item(obj, "ltcg-object"), item(image, "linked-image"), item(mapfile, "linker-map")],
                        "candidates": [{"symbol": "_fixture", "retail_va": "0x1000", "candidate_va": "0x1000", "size": 1,
                            "boundary": boundary, "source_path": str(source), "source_sha256": source_hash,
                            "function_source_sha256": function_hash, "source_span": request["source_span"],
                            "image_path": str(image), "image_sha256": gate.digest(image.read_bytes()),
                            "bytes_sha256": gate.digest(b"\xc3"), "referents": []}]}
                    Path(argv[argv.index("--manifest") + 1]).write_text(json.dumps(manifest))
                else:
                    report = {"schema_version": 1, "functions": [{"binary": "cl", "va": "0x1000",
                        "source_path": str(source), "source_sha256": source_hash,
                        "status": "RULE-ADMITTED", "admitted": True}]}
                    Path(argv[-1]).write_text(json.dumps(report))
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            class Retail(Image):
                def __init__(self, cfg):
                    super().__init__(0x1000, b"\xc3")
            module = types.SimpleNamespace(Retail=Retail, PEImage=lambda path: Image(0x1000, Path(path).read_bytes()),
                                           load_binary_config=lambda *args, **kwargs: {})
            with patch.object(gate.subprocess, "run", side_effect=runner):
                result = gate.execute_gate("cl", root, module)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["status"], "GREEN")
            record = result["binaries"]["cl"]
            self.assertEqual((record["functions"], record["source_bytes"]), (1, 1))
            self.assertEqual(record["input_sha256"], record["output_sha256"])
            admission = record["admitted"][0]
            self.assertEqual(admission["retail_file_offset"], 0)
            self.assertEqual(admission["function_source_sha256"], function_hash)
            self.assertEqual(gate.digest(Path(admission["manifest_path"]).read_bytes()), admission["manifest_sha256"])
            self.assertIn("cl functions=1 source_bytes=1/1", result["authority"])


if __name__ == "__main__":
    unittest.main()
