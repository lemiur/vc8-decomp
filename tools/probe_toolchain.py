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
import time
import uuid

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
        for name in ("msvcrt.lib", "msvcprt.lib", "oldnames.lib", "kernel32.lib", "advapi32.lib"):
            found = folder / name
            if found.is_file():
                out.append({"path": found.as_posix(), "size": found.stat().st_size,
                            "version": None, "sha256": sha256(found)})
    seen = {str(Path(item["path"]).resolve()).casefold() for item in out}
    for name in toolchain.get("observed_runtime_files", []):
        found = Path(name)
        if str(found.resolve()).casefold() not in seen:
            out.append({"path": found.as_posix(), "size": found.stat().st_size,
                        "version": file_version(found), "sha256": sha256(found)})
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


def trace_tool_runtime(toolchain, tool, args, output):
    """Observe loaded DLL files of a child tool through Windows debug events.

    Every event is continued; no memory or executable changes are made. This
    observes actual SxS resolution, unlike inspecting an available CRT folder.
    The log and observation are local evidence, not function match admission.
    """
    verify_toolchain(toolchain)
    exe = Path(toolchain["bin"]) / tool
    pinned = {str(Path(item["path"]).resolve()).casefold() for item in toolchain["files"]}
    if str(exe.resolve()).casefold() not in pinned:
        raise ValueError("requested executable is not pinned: " + str(exe))
    if os.name != "nt":
        raise OSError("runtime tracing requires Windows")
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    pointer_size = ctypes.sizeof(ctypes.c_void_p)

    class DebugInfo(ctypes.Union):
        _fields_ = [("alignment", ctypes.c_void_p),
                    ("raw", ctypes.c_ubyte * (160 if pointer_size == 8 else 84))]

    class DebugEvent(ctypes.Structure):
        _fields_ = [("code", ctypes.c_uint32), ("pid", ctypes.c_uint32),
                    ("tid", ctypes.c_uint32), ("info", DebugInfo)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.WaitForDebugEvent.argtypes = [ctypes.POINTER(DebugEvent), ctypes.c_uint32]
    kernel.WaitForDebugEvent.restype = ctypes.c_int
    kernel.ContinueDebugEvent.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    kernel.ContinueDebugEvent.restype = ctypes.c_int
    kernel.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    kernel.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.DebugActiveProcessStop.argtypes = [ctypes.c_uint32]
    kernel.DebugActiveProcessStop.restype = ctypes.c_int
    modules = {}
    command = [str(exe), *map(str, args)]
    log_path = output / "runtime-command.log"
    with log_path.open("wb") as log:
        # DEBUG_ONLY_THIS_PROCESS is 0x2 (installed PlatformSDK WinBase.h).
        process = subprocess.Popen(command, cwd=output, env=toolchain_environment(toolchain),
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW | 0x2)
        deadline = time.monotonic() + 120
        try:
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("runtime trace exceeded 120 seconds")
                event = DebugEvent()
                if not kernel.WaitForDebugEvent(ctypes.byref(event), 1000):
                    if ctypes.get_last_error() == 121:  # ERROR_SEM_TIMEOUT
                        continue
                    raise ctypes.WinError(ctypes.get_last_error())
                raw = bytes(event.info.raw)
                if event.code in (3, 6):  # CREATE_PROCESS / LOAD_DLL
                    handle = int.from_bytes(raw[:pointer_size], "little")
                    if handle:
                        try:
                            buffer = ctypes.create_unicode_buffer(32768)
                            if kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0):
                                path = Path(buffer.value.removeprefix("\\\\?\\"))
                                modules[str(path).casefold()] = {
                                    "path": path.as_posix(), "version": file_version(path), "sha256": sha256(path)}
                        finally:
                            kernel.CloseHandle(handle)
                status = 0x10002  # DBG_CONTINUE
                if event.code == 1 and int.from_bytes(raw[:4], "little") != 0x80000003:
                    status = 0x80010001  # DBG_EXCEPTION_NOT_HANDLED; preserve tool exceptions
                if not kernel.ContinueDebugEvent(event.pid, event.tid, status):
                    raise ctypes.WinError(ctypes.get_last_error())
                if event.code == 5:  # EXIT_PROCESS
                    break
            exit_code = process.wait(timeout=5)
        finally:
            if process.poll() is None:
                # Detach on an observer failure so a pending debug event cannot
                # prevent the child from completing termination.
                kernel.DebugActiveProcessStop(process.pid)
                process.terminate()
                process.wait(timeout=5)
    verify_toolchain(toolchain)
    result = {"toolchain": toolchain["name"], "command": command, "returncode": exit_code,
              "method": "read-only Windows child debug-event module observation", "modules": list(modules.values()),
              "log_path": str(log_path), "log_sha256": sha256(log_path)}
    (output / "runtime-observations.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


LAYOUT_FIELDS = ("nLength", "lpSecurityDescriptor", "bInheritHandle")
LAYOUT_SYMBOL = "vc8_layout_SECURITY_ATTRIBUTES"
LAYOUT_TYPES = {
    "SECURITY_ATTRIBUTES": {"header": "windows.h", "fields": LAYOUT_FIELDS,
                            "symbol": LAYOUT_SYMBOL, "alignment": False},
    "__timeb64": {"header": "sys/timeb.h", "fields": ("time", "millitm", "timezone", "dstflag"),
                  "symbol": "vc8_layout___timeb64", "alignment": True},
}


def build_layout_witness(toolchain, output, config_path=CONFIG, type_name="SECURITY_ATTRIBUTES"):
    """Build an independently extractable SDK aggregate layout witness.

    The exported DWORD array contains sizeof(type), then ordered offset/width
    pairs. No expected numeric layout is injected into the source or bytes.
    Gate/audit must independently extract the array and approve its named record.
    """
    import ltcg
    from matchlib import PEImage
    if type_name not in LAYOUT_TYPES:
        raise ValueError("unsupported layout witness type: " + type_name)
    specification = LAYOUT_TYPES[type_name]
    fields = specification["fields"]
    symbol = specification["symbol"]
    verify_toolchain(toolchain)
    output = Path(output).resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("layout output must be empty for a fresh build")
    output.mkdir(parents=True, exist_ok=True)
    source = output / "layout.cpp"
    expressions = ["sizeof(%s)" % type_name]
    for field in fields:
        expressions += ["offsetof(%s, %s)" % (type_name, field),
                        "sizeof(((%s *)0)->%s)" % (type_name, field)]
    source_text = '#include <' + specification["header"] + '>\n#include <stddef.h>\n'
    source_text += ('extern "C" __declspec(dllexport) const unsigned long ' + symbol +
                    '[] = {\n    ' + ',\n    '.join(expressions) + '\n};\n')
    roots = ["_" + symbol]
    if specification["alignment"]:
        source_text += ('extern "C" __declspec(dllexport) const unsigned long ' + symbol +
                        '_alignment = __alignof(' + type_name + ');\n')
        roots.append("_" + symbol + "_alignment")
    source.write_text(source_text, encoding="ascii")
    inputs = {str(source): sha256(source)}
    config_path = Path(config_path).resolve()
    inputs[str(config_path)] = sha256(config_path)
    commands = []
    obj = output / "layout.obj"
    flags = ["/nologo", "/c", "/showIncludes", "/O1", "/MD", "/EHsc", "/GL"]
    toolroot = Path(toolchain["bin"]).parent
    env = toolchain_environment(toolchain)
    compiled = ltcg.run_command([str(Path(toolchain["bin"]) / "cl.exe"), *flags,
                                 "/Fo" + str(obj), str(source)], output, env, commands, [obj])
    if not obj.is_file():
        raise ValueError("layout compiler did not produce a fresh object")
    for line in (compiled.stdout + compiled.stderr).splitlines():
        if "Note: including file:" in line:
            header = Path(line.split("Note: including file:", 1)[1].strip()).resolve()
            inputs[str(header)] = sha256(header)
    if len(inputs) <= 2:
        raise ValueError("layout compiler did not report included SDK headers")
    image_path, map_path = ltcg.link(toolroot, [obj], roots, output, env, commands)
    image = PEImage(image_path)
    exports = [entry for entry in image.export_records() if symbol in entry.get("names", [])]
    if len(exports) != 1 or exports[0].get("va") is None:
        raise ValueError("layout export did not resolve to one image-backed array")
    array_va = exports[0]["va"]
    count = 1 + len(fields) * 2
    values = struct.unpack("<" + "I" * count, image.read_va(array_va, count * 4))
    observations = {"size": values[0], "members": {field: {"offset": values[1 + index * 2],
                       "size": values[2 + index * 2]} for index, field in enumerate(fields)}}
    for path, digest in inputs.items():
        if sha256(path) != digest:
            raise ValueError("layout input changed during build: " + path)
    verify_toolchain(toolchain)
    artifacts = [{"path": str(path), "sha256": sha256(path), "kind": kind}
                 for path, kind in ((obj, "ltcg-object"), (image_path, "linked-image"), (map_path, "linker-map"))]
    result = {"schema_version": 1, "kind": "offsetof-sizeof", "binary": "cl", "build_id": str(uuid.uuid4()),
              "status": "built", "type": type_name, "fields": list(fields),
              "source_inputs": [{"path": path, "sha256": digest} for path, digest in sorted(inputs.items())],
              "toolchain_name": toolchain["name"], "toolchain": toolchain["files"], "commands": commands,
              "artifacts": artifacts, "image": {"path": str(image_path), "sha256": sha256(image_path)},
              "symbol": symbol, "export": {"va": array_va, "size": count * 4},
              "observations": observations,
              "purpose": "Compiler-produced aggregate layout witness only; no function or byte matching count"}
    if specification["alignment"]:
        alignment_symbol = symbol + "_alignment"
        alignment_exports = [entry for entry in image.export_records() if alignment_symbol in entry.get("names", [])]
        if len(alignment_exports) != 1 or alignment_exports[0].get("va") is None:
            raise ValueError("layout alignment export did not resolve to one image-backed DWORD")
        alignment_va = alignment_exports[0]["va"]
        alignment = struct.unpack("<I", image.read_va(alignment_va, 4))[0]
        result["alignment"] = {"symbol": alignment_symbol, "va": alignment_va, "size": 4, "value": alignment,
                               "expression": "__alignof(" + type_name + ")"}
    record = output / "layout-witness.json"
    record.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result, record


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
    parser.add_argument("action", choices=("inventory", "verify", "probe", "trace", "layout"))
    parser.add_argument("--toolchain", default="sp1")
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--matrix", action="store_true", help="also compile one-control-at-a-time C ABI/flag variants")
    parser.add_argument("--repeat", type=int, choices=range(1, 5), default=2,
                        help="fresh builds to compare for stable .text (default: 2)")
    parser.add_argument("--tool", default="cl.exe", help="pinned executable for trace (default: cl.exe)")
    parser.add_argument("--tool-arg", action="append", help="one argument for trace; default: /?")
    parser.add_argument("--layout-type", choices=tuple(LAYOUT_TYPES), default="SECURITY_ATTRIBUTES")
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
    elif args.action == "layout":
        output = args.out or ROOT / "build/toolchain-layout" / args.toolchain / str(uuid.uuid4())
        result, record = build_layout_witness(tc, output, args.config, args.layout_type)
        print("Compiled %s layout: %s; record: %s" % (result["type"], result["observations"], record))
    elif args.action == "trace":
        output = args.out or ROOT / "build/toolchain" / args.toolchain / "runtime"
        result = trace_tool_runtime(tc, args.tool, args.tool_arg or ["/?"], output)
        print("Observed %d loaded files; command exit %d; %s" %
              (len(result["modules"]), result["returncode"], output / "runtime-observations.json"))
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
