"""Project adapter contracts with a PDB-less, non-/GL two-binary fixture project."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import ltcg
import match
import matchlib
from matchlib import IdentityError, PEError, Retail, adapter_of, load_adapter, load_project, primary_checkout, unit_gl
from test_matchlib import image_bytes


def load_tool(name):
    spec = importlib.util.spec_from_file_location("adapter_" + name, Path(matchlib.__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load_tool("gate")
rulecheck = load_tool("rulecheck")

# A game built with VC8 SP1: two executables, no PDB, plain objects, /OPT:REF,ICF.
GAME = {
    "toolchain_root": "unused",
    "binaries": {"game": {"filename": "Game.exe"}, "game_dx11": {"filename": "Game_DX11.exe"}},
    "project": {
        "pdb_required": False,
        "gl": False,
        "link_flags": ["/OPT:REF,ICF"],
        "annotation": {"pattern": r"^\s*//\s*match\s+(?P<binary>\w+)\s+(?P<va>0x[0-9a-fA-F]+)\s*$",
                       "prefix": r"//\s*match\b"},
    },
}


def write_game(root):
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config/project.json").write_text(json.dumps(GAME), encoding="utf-8")


class AdapterConfig(unittest.TestCase):
    def test_defaults_keep_the_strict_vc8_policy(self):
        adapter = adapter_of({"binaries": {"b": {}, "a": {}}})
        self.assertEqual(adapter["binaries"], ["b", "a"])
        self.assertTrue(adapter["pdb_required"])
        self.assertTrue(adapter["gl"])
        self.assertEqual(adapter["link_flags"], ["/OPT:NOREF,NOICF"])
        self.assertEqual(adapter["annotation"]["function"], "FUNCTION")

    def test_invalid_adapter_fails_closed(self):
        for block, message in (({"typo": 1}, "unknown project adapter key"),
                               ({"binaries": ["other"]}, "unconfigured binary"),
                               ({"annotation": {"pattern": r"// (\w+)"}}, "named groups")):
            with self.subTest(block=block), self.assertRaisesRegex(ValueError, message):
                adapter_of({"binaries": {"game": {}}, "project": block})

    def test_game_project_file_and_derived_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            write_game(root)
            adapter = load_adapter(root)
            self.assertEqual(adapter["binaries"], ["game", "game_dx11"])
            self.assertFalse(adapter["pdb_required"])
            self.assertEqual(adapter["annotation"]["function"], "FUNCTION")
            project = load_project(root)
            self.assertEqual(Path(project["primary_checkout"]), root)
            self.assertEqual(Path(project["symbols_root"]), root / "symbols")

    def test_worktree_resolves_its_primary_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            primary, worktree = Path(temp).resolve() / "primary", Path(temp).resolve() / "primary/.worktrees/lane"
            metadata = primary / ".git/worktrees/lane"
            metadata.mkdir(parents=True)
            (metadata / "commondir").write_text("../..\n")
            worktree.mkdir(parents=True)
            (worktree / ".git").write_text("gitdir: " + str(metadata) + "\n")
            self.assertEqual(primary_checkout(worktree), primary)
            write_game(worktree)
            self.assertEqual(Path(load_project(worktree)["symbols_root"]), primary / "symbols")

    def test_gl_mode_unit_over_binary_over_project(self):
        adapter = adapter_of(GAME)
        self.assertFalse(unit_gl(adapter, {}, "matching/game/a.cpp"))
        self.assertTrue(unit_gl(adapter, {"gl": True}, "matching/game/a.cpp"))
        self.assertFalse(unit_gl(adapter, {"gl": True, "units": {"matching/game/a.cpp": {"gl": False}}}, "matching/game/a.cpp"))


class PdbLessIdentity(unittest.TestCase):
    def test_retail_without_rsds_verifies_only_when_no_pdb_is_required(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Game.exe"
            path.write_bytes(image_bytes())
            pins = dict(path=str(path), size=0x600, machine=0x14C, image_base=0x400000, timestamp=123,
                        version=None, sha256=matchlib.sha256_of(path))
            self.assertEqual(Retail(dict(pins, project=GAME)).verify_identity()["pdb"], None)
            with self.assertRaisesRegex(IdentityError, "missing retail identity pins: pdb"):
                Retail(dict(pins, project={"binaries": GAME["binaries"]})).verify_identity()
            with self.assertRaisesRegex(PEError, "RSDS"):
                Retail(dict(pins, project=GAME, pdb={"guid": "0", "age": 1, "path": "x"})).verify_identity()


class AdapterSources(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        write_game(self.root)
        (self.root / "config/rule-exceptions.json").write_text('{"schema_version": 1, "reviews": [], "exceptions": []}')
        (self.root / "matching/game").mkdir(parents=True)
        self.unit = self.root / "matching/game/unit.cpp"
        self.unit.write_text("// match game 0x401000\nint Count(void) { return 1; }\n"
                             "// FUNCTION: cl 0x402000\nint Other(void) { return 2; }\n", encoding="utf-8")

    def test_match_reads_the_configured_annotation(self):
        annotations = match.parse_annotations(self.unit, adapter_of(GAME))
        self.assertEqual([(a.binary, a.retail_va, a.source_name) for a in annotations], [("game", 0x401000, "Count")])

    def test_rulecheck_reads_the_configured_annotation_and_binaries(self):
        report = rulecheck.check(root=self.root)
        self.assertEqual([(f["binary"], f["va"]) for f in report["functions"]], [("game", "0x401000")])
        self.unit.write_text("// match other 0x401000\nint Count(void) { return 1; }\n", encoding="utf-8")
        report = rulecheck.check(root=self.root)
        self.assertEqual(report["functions"], [])
        self.assertTrue(any(f["rule"] == "ANNOTATION" for f in report["findings"]))


class PlainBuild(unittest.TestCase):
    def test_plain_compile_and_link_commands(self):
        argvs = []
        def run(argv, cwd, env, commands, produced):
            argvs.append(argv)
            for path in produced:
                Path(path).write_bytes(b"synthetic")
            return types.SimpleNamespace(stdout="", stderr="")
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(ltcg, "run_command", side_effect=run):
            out = Path(temp)
            match.compile_unit(out / "unit.cpp", out / "unit.obj", out, ["/O2"], {}, [], "cl.exe", gl=False)
            ltcg.link(out, [out / "unit.obj"], ["_Count"], out, {}, [], ltcg=False, base_flags=["/OPT:REF,ICF"])
        compile_argv, link_argv = argvs
        self.assertEqual(Path(compile_argv[0]).name, "cl.exe")
        self.assertIn("/GL-", compile_argv)
        self.assertNotIn("/GL", compile_argv)
        self.assertNotIn("/LTCG", link_argv)
        self.assertIn("/OPT:REF,ICF", link_argv)
        self.assertNotIn("/OPT:NOREF,NOICF", link_argv)


class PlainGate(unittest.TestCase):
    def fixture(self, root, compile_flags=(), link_flags=(), kind="object"):
        (root / "config").mkdir(exist_ok=True)
        output = root / "fresh"
        output.mkdir(exist_ok=True)
        source, compiler, linker = root / "unit.cpp", root / "cl.exe", root / "link.exe"
        obj, image, mapfile = output / "source.obj", output / "candidate.dll", output / "candidate.map"
        for path in (source, compiler, linker, obj, image, mapfile):
            path.write_bytes((path.name + " synthetic").encode())
        item = lambda path, kind=None: dict({"path": str(path), "sha256": gate.digest(path.read_bytes())},
                                            **({"kind": kind} if kind else {}))
        tools = [item(compiler), item(linker)]
        (root / "config/toolchains.json").write_text(json.dumps({"toolchains": {"fixture": {"files": tools}}}))
        return {"schema_version": 1, "binary": "game", "build_id": "fresh", "status": "built",
                "source_inputs": [item(source)], "toolchain": tools,
                "commands": [{"argv": [str(compiler), *compile_flags, "/Fo" + str(obj), str(source)], "cwd": str(root),
                              "returncode": 0, "produced": [str(obj)]},
                             {"argv": [str(linker), *link_flags, "/OUT:" + str(image), "/MAP:" + str(mapfile), str(obj)],
                              "cwd": str(root), "returncode": 0, "produced": [str(image), str(mapfile)]}],
                "artifacts": [item(obj, kind), item(image, "linked-image"), item(mapfile, "linker-map")],
                "candidates": [{"symbol": "_Count"}]}, output

    def test_plain_objects_follow_the_adapter_gl_mode(self):
        adapter = adapter_of(GAME)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            manifest, output = self.fixture(root)
            gate.validate_manifest(manifest, "game", "fresh", output, root, adapter, lambda source: False)
            with self.assertRaisesRegex(gate.GateError, "differs from the project adapter"):
                gate.validate_manifest(manifest, "game", "fresh", output, root, adapter, lambda source: True)
            for flags, kind, message in (((), "ltcg-object", "did not use /GL"), (("/GL",), "object", "plain candidate object used /GL")):
                manifest, output = self.fixture(root, flags, ("/LTCG",), kind)
                with self.subTest(kind=kind), self.assertRaisesRegex(gate.GateError, message):
                    gate.validate_manifest(manifest, "game", "fresh", output, root, adapter)
            manifest, output = self.fixture(root, ("/GL",), (), "ltcg-object")
            with self.assertRaisesRegex(gate.GateError, "/LTCG"):
                gate.validate_manifest(manifest, "game", "fresh", output, root, adapter)

    def test_fallback_gate_covers_the_configured_binaries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_game(root)
            (root / "config/gate-allow.json").write_text('{"schema_version":1,"candidates":[],"referents":{}}')
            calls = []
            class Image:
                def __init__(self, name):
                    calls.append(name)
                    self.data = (name + " fixture").encode()
                def verify_identity(self):
                    pass
                def sha256(self):
                    return gate.digest(self.data)
            module = types.SimpleNamespace(load_binary_config=lambda name, root=None: name, Retail=Image)
            result = gate.execute_gate("all", root, module)
            self.assertEqual(result["status"], "GREEN", result["errors"])
            self.assertEqual(calls, ["game", "game_dx11"])
            self.assertEqual(sorted(result["binaries"]), ["game", "game_dx11"])
            self.assertEqual(gate.execute_gate("cl", root, module)["status"], "RED")


if __name__ == "__main__":
    unittest.main()
