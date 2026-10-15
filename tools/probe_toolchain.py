"""Pin local VC8 tools and run bounded C/C++ /GL -> /LTCG smoke probes.

`inventory` updates config/toolchains.json; `probe --toolchain sp1` writes only
ignored build output. Probe success establishes flag support, never retail flags
or a reconstructed source match. PATH follows avp3-decomp/tools/vc8_build.py.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config/toolchains.json"
PIN_NAMES = ("cl.exe", "c1.dll", "c1xx.dll", "c2.dll", "link.exe", "cvtres.exe",
             "mspdb80.dll", "mspdbcore.dll", "mspdbsrv.exe", "msobj80.dll", "pgodb80.dll",
             "pgort80.dll", "pgort80ui.dll", "msvcr80.dll", "msvcp80.dll",
             "clui.dll", "linkui.dll", "dumpbin.exe", "lib.exe", "undname.exe")
PIN_NAMES += ("cl.exe.config", "link.exe.config", "Microsoft.VC80.CRT.manifest")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def file_version(path):
    """Read fixed PE version resource through Windows, without executing the file."""
    version = ctypes.windll.version
    size = version.GetFileVersionInfoSizeW(str(path), None)
    if not size:
        return None
    data = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(str(path), 0, size, data):
        raise OSError("GetFileVersionInfoW failed: " + str(path))
    ptr = ctypes.c_void_p()
    count = ctypes.c_uint()
    if not version.VerQueryValueW(data, "\\", ctypes.byref(ptr), ctypes.byref(count)):
        return None
    words = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_uint32))
    ms, ls = words[2], words[3]
    return ".".join(str(x) for x in (ms >> 16, ms & 65535, ls >> 16, ls & 65535))


def load_toolchain(name="sp1", config_path=None):
    data = json.loads(Path(config_path or CONFIG).read_text(encoding="utf-8-sig"))
    result = dict(data["toolchains"][name])
    result["name"] = name
    return result


def toolchain_environment(toolchain, base=None):
    env = dict(os.environ if base is None else base)
    # CL/_CL_/LINK inject options silently; disallow inherited compiler switches.
    for name in ("CL", "_CL_", "LINK", "_LINK_"):
        env.pop(name, None)
    env["PATH"] = os.pathsep.join([toolchain["bin"], *toolchain.get("runtime", []), env.get("PATH", "")])
    env["INCLUDE"] = os.pathsep.join(toolchain.get("include", []))
    env["LIB"] = os.pathsep.join(toolchain.get("lib", []))
    return env


def run_tool(toolchain, tool, args, cwd=None):
    exe = Path(toolchain["bin"]) / tool
    if not exe.is_file():
        raise FileNotFoundError(exe)
    verify_toolchain(toolchain)
    if str(exe.resolve()).casefold() not in {str(Path(item["path"]).resolve()).casefold() for item in toolchain["files"]}:
        raise ValueError("requested executable is not pinned: " + str(exe))
    return subprocess.run([str(exe), *map(str, args)], cwd=cwd,
                          env=toolchain_environment(toolchain), capture_output=True,
                          text=True, errors="replace", timeout=120)


def inventory(toolchain):
    paths = [Path(toolchain["bin"]), Path(toolchain["bin"]) / "1033", *map(Path, toolchain.get("runtime", []))]
    out = []
    for name in PIN_NAMES:
        found = next((folder / name for folder in paths if (folder / name).is_file()), None)
        if found:
            out.append({"path": found.as_posix(), "size": found.stat().st_size,
                        "version": file_version(found), "sha256": sha256(found)})
    for folder in map(Path, toolchain.get("lib", [])):
        for name in ("msvcrt.lib", "msvcprt.lib", "oldnames.lib", "kernel32.lib"):
            found = folder / name
            if found.is_file():
                out.append({"path": found.as_posix(), "size": found.stat().st_size,
                            "version": None, "sha256": sha256(found)})
    return out


def verify_toolchain(toolchain):
    files = toolchain.get("files", [])
    if not files:
        raise ValueError("toolchain has no pinned files")
    for item in files:
        path = Path(item["path"])
        if not path.is_file() or sha256(path) != item["sha256"]:
            raise ValueError("toolchain pin mismatch: " + str(path))
    required = {str((Path(toolchain["bin"]) / name).resolve()).casefold()
                for name in ("cl.exe", "c1.dll", "c1xx.dll", "c2.dll", "link.exe")}
    pinned = {str(Path(item["path"]).resolve()).casefold() for item in files}
    if not required <= pinned:
        raise ValueError("toolchain core executables are not all pinned")
    return True


PROBES = {
    "c": "__declspec(dllexport) int probe(int x) { return x * 3 + 7; }\n",
    "cpp": 'extern "C" __declspec(dllexport) int probe(int x) { try { if (x) throw x; } catch (int v) { return v + 7; } return 0; }\n',
}
MATRIX = {
    "baseline": [], "size": ["/O1"], "frame_pointer": ["/Oy-"],
    "no_stack_cookie": ["/GS-"], "function_sections": ["/Gy"],
    "string_pool": ["/GF"], "cdecl": ["/Gd"], "stdcall": ["/Gz"],
    "fastcall": ["/Gr"], "unsigned_char": ["/J"], "pack1": ["/Zp1"], "pack8": ["/Zp8"],
}
MATRIX_SOURCE = ("struct Probe { char tag; int value; };\n"
                 "__declspec(dllexport) int probe(struct Probe *p, char value, int x) "
                 "{ return p->value + value * 3 + x; }\n")


def section_hashes(path):
    """Hash initialized section bytes; omit changing PE timestamp/checksum fields."""
    data = Path(path).read_bytes()
    if data[:2] != b"MZ" or len(data) < 64:
        raise ValueError("invalid probe PE")
    at = struct.unpack_from("<I", data, 60)[0]
    if data[at:at + 4] != b"PE\0\0":
        raise ValueError("invalid probe PE signature")
    count = struct.unpack_from("<H", data, at + 6)[0]
    size = struct.unpack_from("<H", data, at + 20)[0]
    result = {}
    for index in range(count):
        header = at + 24 + size + index * 40
        name = data[header:header + 8].rstrip(b"\0").decode("ascii")
        virtual_size, _, raw_size, raw_at = struct.unpack_from("<IIII", data, header + 8)
        length = min(virtual_size, raw_size)
        if raw_at + length > len(data):
            raise ValueError("truncated probe PE section")
        result[name] = {"size": length, "sha256": hashlib.sha256(data[raw_at:raw_at + length]).hexdigest()}
    return result


def run_probes(toolchain, output, matrix=False):
    verify_toolchain(toolchain)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    results = []
    cases = [(language, source, language, []) for language, source in PROBES.items()]
    if matrix:
        cases += [("matrix_" + name, MATRIX_SOURCE, "c", flags) for name, flags in MATRIX.items()]
    for case, source, language, extra_flags in cases:
        folder = output / case
        folder.mkdir(exist_ok=True)
        path = folder / ("probe.c" if language == "c" else "probe.cpp")
        path.write_text(source, encoding="ascii")
        # Fresh names per invocation prevent stale output from implying success.
        for pattern in ("*.obj", "*.dll", "*.lib", "*.exp", "*.map", "*.manifest"):
            for old in folder.glob(pattern):
                old.unlink()
        flags = ["/nologo", "/c", "/O2", "/GL", "/MD", "/GS", "/Fo" + str(folder / "probe.obj")]
        if language == "cpp":
            flags.append("/EHsc")
        flags.extend(extra_flags)
        commands = []
        for tool, args in (("cl.exe", [*flags, str(path)]),
                           ("link.exe", ["/nologo", "/DLL", "/NOENTRY", "/LTCG", "/INCREMENTAL:NO",
                                         "/OUT:" + str(folder / "probe.dll"), "/MAP:" + str(folder / "probe.map"),
                                         str(folder / "probe.obj"), "kernel32.lib"])):
            run = run_tool(toolchain, tool, args, folder)
            commands.append({"tool": tool, "args": args, "returncode": run.returncode,
                             "stdout": run.stdout, "stderr": run.stderr})
            if run.returncode:
                break
        dll = folder / "probe.dll"
        success = len(commands) == 2 and all(c["returncode"] == 0 for c in commands) and dll.is_file()
        results.append({"case": case, "language": language, "supported": success, "commands": commands,
                        "output_sha256": sha256(dll) if success else None,
                        "sections": section_hashes(dll) if success else None})
    report = {"schema_version": 1, "toolchain": toolchain["name"], "purpose": "flag support only; retail flags unproven",
              "tool_files": toolchain["files"], "probes": results}
    (output / "probe-results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inventory", "verify", "probe"))
    parser.add_argument("--toolchain", default="sp1")
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--matrix", action="store_true", help="also compile one-control-at-a-time C ABI/flag variants")
    parser.add_argument("--repeat", type=int, choices=range(1, 5), default=2,
                        help="fresh builds to compare for stable .text (default: 2)")
    args = parser.parse_args()
    tc = load_toolchain(args.toolchain, args.config)
    if args.action == "inventory":
        data = json.loads(args.config.read_text(encoding="utf-8-sig"))
        data["toolchains"][args.toolchain]["files"] = inventory(tc)
        args.config.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print("Pinned %d files for %s" % (len(data["toolchains"][args.toolchain]["files"]), args.toolchain))
    elif args.action == "verify":
        verify_toolchain(tc)
        print("Toolchain pins verified: " + args.toolchain)
    else:
        output = args.out or ROOT / "build" / "toolchain" / args.toolchain
        runs = [run_probes(tc, output, args.matrix) for _ in range(args.repeat)]
        report = runs[-1]
        report["fresh_build_count"] = args.repeat
        for index, item in enumerate(report["probes"]):
            item["stable_text"] = all(run["probes"][index]["supported"] and
                                      run["probes"][index]["sections"][".text"] == item["sections"][".text"]
                                      for run in runs) if item["supported"] else False
        (output / "probe-results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        for item in report["probes"]:
            print("%s %s /GL /LTCG support: %s; stable .text: %s" %
                  (args.toolchain, item["case"], item["supported"], item["stable_text"]))
            if not item["supported"]:
                print((item["commands"][-1]["stdout"] + item["commands"][-1]["stderr"])[-3000:])
        return 0 if all(item["supported"] and item["stable_text"] for item in report["probes"]) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
