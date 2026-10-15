"""Contract/failure tests. Tiny bytes here are fixtures, never counted source."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import audit

GATE_PATH = Path(os.environ.get("VC8_AUDIT_GATE", TOOLS / "gate.py"))
gate = None
if GATE_PATH.is_file():
    gate_spec = importlib.util.spec_from_file_location("audited_gate", GATE_PATH)
    gate = importlib.util.module_from_spec(gate_spec)
    gate_spec.loader.exec_module(gate)


class FixtureImage:
    def __init__(self):
        self.data = b"HEADER00ABCDEFGHtail"
        self.sections = [{"va": 0x401000, "raw": 8, "rawsize": 8}]

    def offset_of(self, va, size=1):
        return 8 + va - 0x401000

    def offset_to_va(self, off, size=1):
        return 0x401000 + off - 8


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / "out"
        self.out.mkdir()
        self.source = self.root / "fixture.cpp"
        self.source.write_text("int fixture(void) { return 1; }\n")
        self.harness = self.root / "fixture_builder.py"
        self.harness.write_text("from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('{}')\n")
        self.run = audit.RunSnapshot.capture(self.out, "fresh-run",
            [self.source, self.harness, sys.executable])
        self.receipt, _ = audit.observe_build(self.run,
            [sys.executable, str(self.harness), str(self.out / "manifest.json")],
            self.out / "manifest.json", self.root)
        self.artifact = self.out / "candidate.dll"
        self.artifact.write_bytes(b"ABCDEFGH")
        self.image = FixtureImage()
        self.candidate = {"id": "fixture", "va": 0x401000, "size": 4,
            "candidate_va": 0x701000,
            "kind": "compiled_source", "run_id": self.run.run_id,
            "artifact": "candidate.dll", "artifact_sha256": audit.digest(self.artifact.read_bytes()),
            "artifact_offset": 0, "bytes_sha256": audit.digest(b"ABCD"),
            "source": str(self.source), "source_sha256": audit.digest(self.source.read_bytes()),
            "retail_referents": [], "candidate_referents": []}
        # Source fixture downstream tests mock the approval token; separate
        # manifest tests exercise the trusted-observation contract itself.
        self.provenance = audit.ManifestAudit(self.receipt, frozenset({(
            "fixture", self.source.resolve(), self.candidate["source_sha256"],
            self.artifact.resolve(), self.candidate["artifact_sha256"], 0x401000, 4, 0x701000)}))
        self.built = FixtureImage()
        self.built.data = b"ABCDEFGH"
        self.built.sections = [{"va": 0x701000, "raw": 0, "rawsize": 8}]
        self.built.offset_of = lambda va, size=1: va - 0x701000
        self.built.offset_to_va = lambda off, size=1: off + 0x701000

    def check(self, candidates=None, planned=None, output=None, receipt=True):
        return audit.audit_splice(self.image, audit.digest(self.image.data),
            planned if planned is not None else [self.candidate],
            candidates if candidates is not None else [self.candidate],
            self.image.data if output is None else output, self.run,
            self.receipt if receipt else None, self.provenance, {self.artifact.resolve(): self.built})

    def test_fallback_identity_is_zero(self):
        result = audit.audit_splice(self.image, audit.digest(self.image.data), [], [], self.image.data)
        self.assertEqual(result["verified_candidate_functions"], 0)
        self.assertEqual(result["source_attributed_bytes"], 0)

    def test_observed_fixture_source_accounting(self):
        result = self.check()
        self.assertEqual(result["source_attributed_bytes"], 4)

    def test_copy_only_fallback_rejected(self):
        candidate = dict(self.candidate, kind="fallback")
        with self.assertRaisesRegex(audit.AuditError, "fallback"):
            self.check([candidate])

    def test_no_trusted_execution_rejected(self):
        with self.assertRaisesRegex(audit.AuditError, "trusted compiler"):
            self.check(receipt=False)

    def test_stale_run_rejected(self):
        with self.assertRaisesRegex(audit.AuditError, "stale"):
            self.check([dict(self.candidate, run_id="old-run")])

    def test_wrong_retail_hash_rejected(self):
        with self.assertRaisesRegex(audit.AuditError, "retail"):
            audit.audit_splice(self.image, "0" * 64, [], [], self.image.data)

    def test_omitted_and_duplicate_candidates_rejected(self):
        for candidates in ([], [self.candidate, self.candidate]):
            with self.subTest(candidates=len(candidates)), self.assertRaises(audit.AuditError):
                self.check(candidates)

    def test_overlap_rejected(self):
        second = dict(self.candidate, id="second", va=0x401002)
        with self.assertRaisesRegex(audit.AuditError, "overlap"):
            self.check([self.candidate, second], [self.candidate, second])

    def test_virtual_tail_and_cross_section_rejected(self):
        for va, size in ((0x401008, 1), (0x401007, 2), (0x400000, 1)):
            with self.subTest(va=va), self.assertRaises(audit.AuditError):
                audit.checked_mapping(self.image, va, size)

    def test_ambiguous_and_inconsistent_mapping_rejected(self):
        self.image.sections *= 2
        with self.assertRaisesRegex(audit.AuditError, "ambiguous"):
            audit.checked_mapping(self.image, 0x401000, 4)
        self.image.sections = self.image.sections[:1]
        self.image.offset_to_va = lambda off, size=1: 0
        with self.assertRaisesRegex(audit.AuditError, "round trip"):
            audit.checked_mapping(self.image, 0x401000, 4)

    def test_masks_and_bad_referents_rejected(self):
        cases = [dict(self.candidate, masks=[{"offset": 0, "width": 4}]),
            dict(self.candidate, retail_referents=[{"offset": 0, "kind": "REL32", "target": "A"}],
                 candidate_referents=[{"offset": 0, "kind": "REL32", "target": "B"}]),
            dict(self.candidate, retail_referents=[{"offset": 0, "kind": "UNKNOWN", "target": "A"}])]
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(audit.AuditError):
                self.check([candidate])

    def test_changed_inputs_and_artifact_rejected(self):
        self.source.write_text("changed")
        with self.assertRaisesRegex(audit.AuditError, "input changed"):
            self.check()
        self.source.write_text("int fixture(void) { return 1; }\n")
        self.artifact.write_bytes(b"forged")
        with self.assertRaisesRegex(audit.AuditError, "artifact hash"):
            self.check()

    def test_unattributed_output_and_size_changes_rejected(self):
        for output in (self.image.data + b"x", b"changed" + self.image.data[7:]):
            with self.subTest(output=output), self.assertRaises(audit.AuditError):
                self.check(output=output)

    def test_artifact_escape_rejected(self):
        outside = self.root / "outside.dll"
        outside.write_bytes(self.artifact.read_bytes())
        with self.assertRaisesRegex(audit.AuditError, "escapes"):
            self.check([dict(self.candidate, artifact=str(outside))])

    def test_dirty_snapshot_rejected(self):
        with self.assertRaisesRegex(audit.AuditError, "not fresh"):
            audit.RunSnapshot.capture(self.out, "new", [self.source])

    def test_manifest_changed_after_invocation_rejected(self):
        with self.assertRaisesRegex(audit.AuditError, "changed"):
            audit.audit_manifest({"schema_version": 1}, "cl", self.receipt, {}, self.root)

    def test_saved_fallback_record_rechecks_actual_outputs(self):
        run_id = "a" * 32
        directory = self.root / "build" / "gate" / run_id
        (directory / "cl").mkdir(parents=True)
        (directory / "cl.fallback.bin").write_bytes(self.image.data)
        output = directory / "cl" / "splice.bin"
        output.write_bytes(self.image.data)
        sha = audit.digest(self.image.data)
        result = {"functions": 0, "source_bytes": 0, "admitted": [], "status": "GREEN",
            "input_sha256": sha, "fallback_sha256": sha, "output_sha256": sha, "image_bytes": len(self.image.data)}
        record = {"schema_version": 1, "gate_kind": "retail-splice", "run_id": run_id,
            "status": "GREEN", "errors": [], "binaries": {"cl": result}}
        self.assertEqual(audit.audit_fallback_record(record, self.root, {"cl": self.image})["source_bytes"], 0)
        output.write_bytes(b"corrupt")
        with self.assertRaisesRegex(audit.AuditError, "spliced output"):
            audit.audit_fallback_record(record, self.root, {"cl": self.image})
        result["functions"] = 1
        with self.assertRaisesRegex(audit.AuditError, "live provenance"):
            audit.audit_fallback_record(record, self.root, {"cl": self.image})


class ManifestContractTests(unittest.TestCase):
    def fixture(self, mutate=lambda manifest: None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        out = root / "out"
        out.mkdir()
        source = root / "fixture.cpp"
        source.write_text("int fixture(void) { return 1; }\n")
        compiler, linker = root / "cl.exe", root / "link.exe"
        compiler.write_bytes(b"compiler-pin-fixture")
        linker.write_bytes(b"linker-pin-fixture")
        record = lambda path, data: {"path": str(path), "sha256": audit.digest(data)}
        manifest = {"schema_version": 1, "binary": "cl", "build_id": "fixture-run", "status": "built",
            "source_inputs": [record(source, source.read_bytes())],
            "toolchain": [record(compiler, compiler.read_bytes()), record(linker, linker.read_bytes())],
            "artifacts": [dict(record(out / "fixture.obj", b"obj"), kind="ltcg-object"),
                          dict(record(out / "candidate.dll", b"ABCD"), kind="linked-image")],
            "commands": [{"argv": [str(compiler), "/GL", "/Fo" + str(out / "fixture.obj"), str(source)],
                          "cwd": str(out), "returncode": 0, "log_path": str(out / "compile.log"),
                          "log_sha256": audit.digest(b"")},
                         {"argv": [str(linker), "/LTCG", "/OUT:" + str(out / "candidate.dll"), str(out / "fixture.obj")],
                          "cwd": str(out), "returncode": 0, "log_path": str(out / "link.log"),
                          "log_sha256": audit.digest(b"")}],
            "candidates": [{"symbol": "fixture", "source_path": str(source),
                            "source_sha256": audit.digest(source.read_bytes()), "image_path": str(out / "candidate.dll"),
                            "image_sha256": audit.digest(b"ABCD"), "retail_va": 0x401000, "size": 4}]}
        manifest["candidates"][0]["candidate_va"] = 0x701000
        mutate(manifest)
        specification = root / "fixture.json"
        specification.write_text(json.dumps(manifest))
        harness = root / "trusted_fixture_builder.py"
        harness.write_text("from pathlib import Path\nimport sys\n"
            "out = Path(sys.argv[1])\n"
            "for name, data in [('fixture.obj', b'obj'), ('candidate.dll', b'ABCD'), ('compile.log', b''), ('link.log', b'')]:\n"
            "    (out / name).write_bytes(data)\n"
            "(out / 'manifest.json').write_bytes(Path(sys.argv[2]).read_bytes())\n")
        snapshot = audit.RunSnapshot.capture(out, "fixture-run", [source, compiler, linker,
            harness, specification, sys.executable])
        receipt, _ = audit.observe_build(snapshot, [sys.executable, str(harness), str(out), str(specification)],
            out / "manifest.json", root)
        pins = {compiler: audit.digest(compiler.read_bytes()), linker: audit.digest(linker.read_bytes())}
        return root, manifest, receipt, pins

    def test_observed_manifest_produces_bound_approval(self):
        root, manifest, receipt, pins = self.fixture()
        result = audit.audit_manifest(manifest, "cl", receipt, pins, root)
        self.assertIsInstance(result, audit.ManifestAudit)
        self.assertEqual(len(result.origins), 1)

    def test_malformed_source_provenance_rejected(self):
        mutations = [lambda m: m.update(status="failed"),
            lambda m: m.update(build_id="stale"),
            lambda m: m["source_inputs"].append(copy.deepcopy(m["source_inputs"][0])),
            lambda m: m["toolchain"].append(copy.deepcopy(m["toolchain"][0])),
            lambda m: m["artifacts"].append(copy.deepcopy(m["artifacts"][0])),
            lambda m: m["commands"][0]["argv"].remove("/GL"),
            lambda m: m["commands"][1]["argv"].pop(2),
            lambda m: m["commands"][0].update(returncode=1),
            lambda m: m["commands"][1].update(log_sha256="0" * 64),
            lambda m: m["artifacts"][1].update(kind="retail-copy")]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                root, manifest, receipt, pins = self.fixture(mutate)
                with self.assertRaises(audit.AuditError):
                    audit.audit_manifest(manifest, "cl", receipt, pins, root)

    def test_manifest_toolchain_cannot_pin_itself(self):
        root, manifest, receipt, pins = self.fixture()
        pins[next(iter(pins))] = "0" * 64
        with self.assertRaisesRegex(audit.AuditError, "unconfigured toolchain"):
            audit.audit_manifest(manifest, "cl", receipt, pins, root)


@unittest.skipIf(gate is None, "gate module not integrated yet; set VC8_AUDIT_GATE to audit a lane")
class IntegratedGateTests(unittest.TestCase):
    def test_overlap_and_boolean_address_rejected(self):
        image, spans = bytearray(b"abcdefgh"), []
        gate.splice(image, spans, 2, b"cd")
        with self.assertRaises(gate.GateError):
            gate.splice(image, spans, 3, b"d")
        with self.assertRaises(gate.GateError):
            gate.integer(True)

    def test_failed_source_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gate.GateError):
                gate.validate_manifest({"schema_version": 1, "binary": "cl", "build_id": "run",
                    "status": "failed", "candidates": [{"symbol": "test"}]},
                    "cl", "run", Path(directory), Path(directory))

    def test_relabelled_external_referent_rejected(self):
        class Image:
            def __init__(self, va, target):
                self.va = va
                self.code = b"\xe8" + struct.pack("<i", target - (va + 5)) + b"\xc3"
                self.sections = [{"va": va, "rawsize": len(self.code), "chars": 0x20000000}]

            def read(self, va, size):
                if va != self.va or size > len(self.code):
                    raise ValueError("unmapped")
                return self.code[:size]

            def base_relocations(self):
                return []

        retail = Image(0x401000, 0x402000)
        built = Image(0x701000, 0x703000)  # Emitted call names a different callee.
        boundary = {"status": "verified", "evidence": "test fixture"}
        claim = {"retail_va": retail.va, "candidate_va": built.va, "size": 6,
            "boundary": boundary, "bytes_sha256": audit.digest(built.code),
            "referents": [{"offset": 1, "width": 4, "kind": "rel32", "target": 0x703000,
                           "identity": "desired_callee", "resolved": True}]}
        request = {"retail_va": retail.va, "size": 6, "boundary": boundary}
        identities = {"desired_callee": {"va": 0x402000, "evidence": "test fixture"}}
        with self.assertRaises(gate.GateError):
            gate.compare_candidate(retail, built, claim, request, identities)


if __name__ == "__main__":
    unittest.main()
