"""Focused infrastructure contracts; these are not source matching tests."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import probe_toolchain as probe
import rtm


class ToolchainTests(unittest.TestCase):
    def test_environment_drops_injected_switches_and_sets_paths(self):
        tc = {"bin": "compiler", "runtime": ["runtime"], "include": ["inc"], "lib": ["lib"]}
        env = probe.toolchain_environment(tc, {"PATH": "original", "CL": "/wrong", "_CL_": "/wrong", "LINK": "/wrong"})
        self.assertNotIn("CL", env)
        self.assertNotIn("_CL_", env)
        self.assertNotIn("LINK", env)
        self.assertEqual(env["PATH"].split(probe.os.pathsep), ["compiler", "runtime", "original"])
        self.assertEqual(env["INCLUDE"], "inc")
        self.assertEqual(env["LIB"], "lib")

    def test_pin_mismatch_and_incomplete_core_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cl.exe"
            path.write_bytes(b"fake tool for hashing contract")
            tc = {"bin": temp, "files": [{"path": str(path), "sha256": probe.sha256(path)}]}
            with self.assertRaisesRegex(ValueError, "not all pinned"):
                probe.verify_toolchain(tc)
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "pin mismatch"):
                probe.verify_toolchain(tc)
            with self.assertRaisesRegex(ValueError, "no pinned files"):
                probe.verify_toolchain({"files": []})

    def test_run_tool_missing_executable_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FileNotFoundError):
                probe.run_tool({"bin": temp}, "missing.exe", [])

    def test_run_tool_rejects_unpinned_requested_program(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "unlisted.exe").write_bytes(b"do not execute")
            with mock.patch.object(probe, "verify_toolchain"), mock.patch.object(probe.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "requested executable is not pinned"):
                    probe.run_tool({"bin": temp, "files": []}, "unlisted.exe", [])
                run.assert_not_called()

    def test_section_hashes_rejects_non_pe(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.dll"
            path.write_bytes(b"not a PE")
            with self.assertRaisesRegex(ValueError, "invalid probe PE"):
                probe.section_hashes(path)

    def test_runtime_trace_rejects_unpinned_program(self):
        with mock.patch.object(probe, "verify_toolchain"):
            with self.assertRaisesRegex(ValueError, "requested executable is not pinned"):
                probe.trace_tool_runtime({"bin": "absent", "files": []}, "unlisted.exe", [], "unused")

    def test_inventory_preserves_observed_runtime_dependency(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "observed-crt.dll"
            path.write_bytes(b"observed runtime hash contract")
            with mock.patch.object(probe, "file_version", return_value="test"):
                files = probe.inventory({"bin": str(Path(temp) / "missing"), "observed_runtime_files": [str(path)]})
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0]["sha256"], probe.sha256(path))

    def test_inventory_pins_consumed_advapi_import_library(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "advapi32.lib"
            path.write_bytes(b"import library hash contract")
            files = probe.inventory({"bin": str(Path(temp) / "missing"), "lib": [temp]})
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0]["sha256"], probe.sha256(path))

    def test_layout_witness_rejects_stale_output(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "stale.dll").write_bytes(b"not attributable")
            with mock.patch.object(probe, "verify_toolchain"):
                with self.assertRaisesRegex(ValueError, "layout output must be empty"):
                    probe.build_layout_witness({}, temp)

    def test_layout_witness_rejects_unregistered_type(self):
        with self.assertRaisesRegex(ValueError, "unsupported layout witness type"):
            probe.build_layout_witness({}, "unused", type_name="invented-layout")

    def test_layout_witness_requires_included_header_provenance(self):
        import ltcg
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "toolchains.json"
            config.write_text("{}")
            def fake_compile(argv, cwd, env, commands, produced):
                Path(produced[0]).write_bytes(b"test object; not source admission")
                return probe.subprocess.CompletedProcess(argv, 0, "", "")
            tc = {"bin": temp, "runtime": [], "include": [], "lib": []}
            with mock.patch.object(probe, "verify_toolchain"), mock.patch.object(ltcg, "run_command", side_effect=fake_compile):
                with self.assertRaisesRegex(ValueError, "did not report included SDK headers"):
                    probe.build_layout_witness(tc, Path(temp) / "fresh", config)

    def test_failed_compile_removes_stale_output_and_skips_link(self):
        with tempfile.TemporaryDirectory() as temp:
            for language in ("c", "cpp"):
                folder = Path(temp) / language
                folder.mkdir()
                (folder / "stale.dll").write_bytes(b"retail is not compiled source")
            failed = probe.subprocess.CompletedProcess([], 1, "compile failed", "")
            with mock.patch.object(probe, "verify_toolchain"), mock.patch.object(probe, "run_tool", return_value=failed) as run:
                report = probe.run_probes({"name": "fake", "files": []}, temp)
            self.assertEqual(run.call_count, 2)
            self.assertTrue(all(not item["supported"] for item in report["probes"]))
            self.assertFalse(list(Path(temp).rglob("*.dll")))

    def test_msi_long_names_and_path_traversal(self):
        self.assertEqual(rtm.safe_filename("SHORT|mspdb80.dll"), "mspdb80.dll")
        for name in ("../outside", "C:/outside", "..", "folder\\outside", ""):
            with self.assertRaises(ValueError):
                rtm.safe_filename(name)


if __name__ == "__main__":
    unittest.main()
