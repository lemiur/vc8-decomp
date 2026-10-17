"""Trace the front half of a VC8 compilation: driver passes, IL files, symbol numbers.

Usage:
  python tools/cl_trace.py passes  --source X.cpp [--flags "..."] [-I DIR]... [--dry] [--debug] [--keep DIR] [--json]
  python tools/cl_trace.py symbols --source X.cpp [--flags "..."] [-I DIR]... [--function NAME] [--keep DIR] [--json]
  python tools/cl_trace.py il      (--source X.cpp [--flags "..."] [-I DIR]... | --prefix DIR/stem_) [--records] [--json]
  python tools/cl_trace.py experiment cost [--flags "..."]
  python tools/cl_trace.py experiment flip --source X.cpp --insert-before TEXT --function REGEX
                                           [--local NAME] [--globals REGEX] [--start N --stop M] [--flags "..."] [-I DIR]...
(write --flags="-O2 ..." when the value starts with a dash)

The driver switches used are confirmed against this cl.exe (docs/cl-frontend-trace.md):
/Bd prints each pass's argv, /Bz prints them without running, /Bk<prefix> keeps the IL
files as <prefix>{ex,gl,in,sy}, /Bx /B1 /B2 substitute c1xx /c1 /c2, /d1X and /d2X pass
-X to the front end and back end. cl.exe runs its passes in-process (LoadLibrary of
c1xx.dll then c2.dll); --debug observes that with Windows debug events while a
ReadDirectoryChangesW watcher on a private TMP records each intermediate file's life.

Symbol numbers are read from the kept `sy` IL file (one block per function, every
parameter, local and compiler temporary with its front-end number) and joined with the
/FAs listing (frame offsets; only block-scope locals carry the `$NNNNN` suffix there).
The sy record layout is inferred from experiments and from the c1xx ILSink writer names
(chwrite, shwrite, lowrite, loshwrite, szwrite); it is a reading aid, not a specification.
Python stdlib and ctypes only.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECT = ROOT / "config" / "project.json"
IL_SUFFIXES = ("ex", "gl", "in", "sy")


class TraceError(RuntimeError):
    pass


# ---------------------------------------------------------------- toolchain

def toolchain(vc_root=None):
    if vc_root is None:
        try:
            vc_root = json.loads(PROJECT.read_text(encoding="utf-8-sig"))["toolchain_root"]
        except (OSError, KeyError, ValueError):
            vc_root = "C:/Program Files (x86)/Microsoft Visual Studio 8/VC"
    vc = Path(vc_root)
    tc = {"vc": vc, "bin": vc / "bin", "cl": vc / "bin" / "cl.exe",
          "ide": vc.parent / "Common7" / "IDE",
          "include": [vc / "include", vc / "PlatformSDK" / "include"],
          "lib": [vc / "lib", vc / "PlatformSDK" / "lib"]}
    if not tc["cl"].is_file():
        raise TraceError("cl.exe not found under " + str(vc))
    return tc


def cl_environment(tc, tmp=None):
    env = dict(os.environ)
    for name in ("CL", "_CL_", "LINK", "_LINK_"):
        env.pop(name, None)  # inherited switches would change the passes silently
    env["PATH"] = os.pathsep.join([str(tc["bin"]), str(tc["ide"]), env.get("PATH", "")])
    env["INCLUDE"] = os.pathsep.join(map(str, tc["include"]))
    env["LIB"] = os.pathsep.join(map(str, tc["lib"]))
    if tmp is not None:
        env["TMP"] = env["TEMP"] = str(tmp)
    return env


def split_flags(text):
    """Split a cl flag string the way a Windows command line would (quotes removed)."""
    if not text:
        return []
    return [item[1:-1] if len(item) >= 2 and item[0] == item[-1] == '"' else item
            for item in shlex.split(text, posix=False)]


def compile_args(flags, includes, source):
    args = ["/nologo", "/c", *split_flags(flags)]
    for inc in includes or ():
        args.append("/I" + str(inc))
    args.append(str(Path(source).resolve()))
    return args


# ---------------------------------------------------------------- /Bd parsing

@dataclass
class Pass:
    name: str
    dll: str
    argv: list
    il: str | None = None


def parse_pass_lines(text):
    """Parse the `<dll> args...' lines /Bd and /Bz print, one per pass."""
    passes = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("`"):
            continue
        body = line[1:-1] if line.endswith("'") else line[1:]
        match = re.match(r"(.+?\.(?:dll|exe))(?:\s+|$)(.*)", body, re.IGNORECASE)
        if not match:
            continue
        dll, rest = match.group(1), match.group(2)
        argv = rest.split(" ") if rest else []
        argv = [a for a in argv if a != ""]
        il = None
        for i, arg in enumerate(argv):
            if arg == "-il" and i + 1 < len(argv):
                il = argv[i + 1]
        passes.append(Pass(Path(dll).stem.lower(), dll, argv, il))
    return passes


# ---------------------------------------------------------------- listing parsing

@dataclass
class FrameLocal:
    name: str
    number: int | None
    offset: int
    size: int | None


@dataclass
class ListedFunction:
    decorated: str
    name: str
    frame: list = field(default_factory=list)


_FRAME = re.compile(r"^(?P<sym>_{1,2}\$?[A-Za-z0-9_?@]+?)\$(?P<num>\d*)\s*=\s*(?P<off>-?\d+)\s*(?:;\s*size\s*=\s*(?P<size>\d+))?")
_PROC = re.compile(r"^(?P<dec>\S+)\s+PROC\b[^;]*(?:;\s*(?P<name>[^,\r\n]+))?")


def parse_listing(text):
    """Functions of a /FA listing with the frame symbols listed before each PROC."""
    functions, pending = [], []
    for line in text.splitlines():
        m = _FRAME.match(line)
        if m:
            sym = m.group("sym")
            name = sym[1:] if sym.startswith("_") else sym
            num = int(m.group("num")) if m.group("num") else None
            size = int(m.group("size")) if m.group("size") else None
            pending.append(FrameLocal(name, num, int(m.group("off")), size))
            continue
        m = _PROC.match(line)
        if m and not line.startswith("EXTRN"):
            functions.append(ListedFunction(m.group("dec"), (m.group("name") or m.group("dec")).strip(), pending))
            pending = []
    return functions


# ---------------------------------------------------------------- IL decoding

def read_losh(data, pos):
    """ILSink::loshwrite value: a u16 below 0x8000, else (0x8000|v&0x7fff, v>>15)."""
    if pos + 2 > len(data):
        raise TraceError("truncated losh value at %d" % pos)
    low = data[pos] | data[pos + 1] << 8
    if not low & 0x8000:
        return low, pos + 2
    if pos + 4 > len(data):
        raise TraceError("truncated long losh value at %d" % pos)
    high = data[pos + 2] | data[pos + 3] << 8
    return (low & 0x7FFF) | high << 15, pos + 4


def encode_losh(value):
    if value < 0x8000:
        return value.to_bytes(2, "little")
    return (0x8000 | value & 0x7FFF).to_bytes(2, "little") + (value >> 15).to_bytes(2, "little")


@dataclass
class SyRecord:
    kind: str           # param/local/array/temp
    tag: int
    level: int
    number: int
    name: str | None = None
    attrs: dict = field(default_factory=dict)
    offset: int = 0


@dataclass
class SyBlock:
    records: list = field(default_factory=list)
    unparsed: list = field(default_factory=list)   # (offset, hex) spans skipped on resync

    def numbers(self):
        return sorted(r.number for r in self.records)


_TAGS = {0x01, 0x02, 0x03, 0x06, 0x0D}


def _named(data, pos, tag):
    level = data[pos + 1]
    number, p = read_losh(data, pos + 2)
    if data[p] != 0:
        raise TraceError("named record without its 00 byte at %d" % p)
    end = data.index(b"\0", p + 1)
    name = data[p + 1:end].decode("latin-1")
    p = end + 1
    kind_byte = data[p]
    if not kind_byte & 0x80:
        raise TraceError("unknown attribute kind %#x at %d" % (kind_byte, p))
    type_index, p = read_losh(data, p + 1)
    storage, unknown = data[p], data[p + 1]
    size, p = read_losh(data, p + 2)
    flags = data[p] | data[p + 1] << 8
    p += 2
    attrs = {"class": kind_byte, "type": type_index, "storage": storage, "u": unknown,
             "size": size, "flags": flags}
    if flags & 0x80:
        attrs["extra"], p = read_losh(data, p)
    if tag == 0x02:
        attrs["dim"] = data[p]
        p += 1
    if storage == 3:
        kind = "param"
    elif tag == 0x02:
        kind = "array"
    else:
        kind = "local"
    return SyRecord(kind, tag, level, number, name, attrs, pos), p


def parse_sy(data):
    """Split a kept `sy` file into per-function blocks of symbol records.

    Records: 03 a <losh n> u16 u8 u8 (compiler temporary); 0D lvl (scope open);
    01|02 lvl <losh n> 00 name 00 <class|0x80> <losh type> storage u8 <losh size>
    u16 flags [<losh> if flags&0x80] [u8 if tag 02]; 06 ends a function. Unknown
    bytes are skipped to the next plausible record and kept in SyBlock.unparsed.
    """
    blocks, block, pos = [], SyBlock(), 0
    while pos < len(data):
        tag = data[pos]
        try:
            if tag == 0x06:
                blocks.append(block)
                block, pos = SyBlock(), pos + 1
                continue
            if tag == 0x0D:
                pos += 2
                continue
            if tag == 0x03:
                number, p = read_losh(data, pos + 2)
                b = data[p] | data[p + 1] << 8
                rec = SyRecord("temp", tag, data[p + 3], number, None,
                               {"a": data[pos + 1], "b": b, "c": data[p + 2]}, pos)
                if p + 4 > len(data):
                    raise TraceError("truncated temp record")
                block.records.append(rec)
                pos = p + 4
                continue
            if tag in (0x01, 0x02):
                rec, pos = _named(data, pos, tag)
                block.records.append(rec)
                continue
            raise TraceError("unknown tag %#x" % tag)
        except (TraceError, ValueError, IndexError):
            nxt = pos + 1
            while nxt < len(data) and data[nxt] not in _TAGS:
                nxt += 1
            block.unparsed.append((pos, data[pos:nxt].hex()))
            pos = nxt
    if block.records or block.unparsed:
        blocks.append(block)
    return blocks


def parse_gl_header(data):
    """The `gl` file opens with 7 signature bytes then the unit's symbol count (u32)."""
    if len(data) < 11:
        raise TraceError("gl file too short")
    return {"signature": data[:7].hex(), "symbol_count": int.from_bytes(data[7:11], "little")}


_GL_NAME = re.compile(rb"\x00([?_A-Za-z][\x21-\x7e]*)\x00[\x80-\x8f]")


def scan_gl_names(data):
    """Heuristic (name, number) pairs of `gl` records: <losh number> 00 name 00 <0x8X attrs>.

    The long losh form is taken when the u16 four bytes before the 00 has bit 15 set;
    a short form whose preceding byte happens to have bit 7 set would be misread.
    """
    result = []
    for m in _GL_NAME.finditer(data):
        i = m.start()
        if i >= 4 and data[i - 3] & 0x80 and not data[i - 1] & 0x80:
            number = (data[i - 4] | (data[i - 3] & 0x7F) << 8) | (data[i - 2] | data[i - 1] << 8) << 15
        elif i >= 2 and not data[i - 1] & 0x80:
            number = data[i - 2] | data[i - 1] << 8
        else:
            continue
        result.append((m.group(1).decode("latin-1"), number))
    return result


def il_strings(data, minimum=3):
    return [m.group().decode("latin-1") for m in re.finditer(rb"[A-Za-z_?@$][\x21-\x7e]{%d,}(?=\x00)" % (minimum - 1), data)]


# ---------------------------------------------------------------- joining

@dataclass
class FunctionSymbols:
    name: str
    decorated: str | None
    symbols: list


def join_blocks(blocks, listed):
    """Pair sy blocks with listing functions by shared names; listing frame data attached."""
    result, used = [], set()
    for index, block in enumerate(blocks):
        names = {r.name for r in block.records if r.name}
        numbered = {(r.name, r.number) for r in block.records if r.name}
        best, best_score = None, 0
        for j, fn in enumerate(listed):
            if j in used:
                continue
            score = 0
            for local in fn.frame:
                if local.number is not None and (local.name, local.number) in numbered:
                    score += 100
                elif local.name in names:
                    score += 1
            if score > best_score:
                best, best_score = j, score
        if best is None:
            # Unnamed block (no frame symbols in common): take the next unused listing in order.
            for j in range(len(listed)):
                if j not in used and not listed[j].frame:
                    best = j
                    break
        fn = listed[best] if best is not None else None
        if best is not None:
            used.add(best)
        frame = {l.name: l for l in fn.frame} if fn else {}
        rows = []
        for r in sorted(block.records, key=lambda r: r.number):
            local = frame.get(r.name) if r.name else None
            rows.append({"number": r.number, "mod64": r.number % 64, "kind": r.kind, "level": r.level,
                         "name": r.name or "<temp>", "listing_suffix": local.number if local else None,
                         "frame_offset": local.offset if local else None,
                         "size": (local.size if local and local.size is not None else r.attrs.get("size"))})
        result.append(FunctionSymbols(fn.name if fn else "#%d" % index, fn.decorated if fn else None, rows))
    return result


# ---------------------------------------------------------------- running cl

def run_cl(tc, args, cwd, tmp=None, timeout=300):
    return subprocess.run([str(tc["cl"]), *args], cwd=str(cwd), env=cl_environment(tc, tmp),
                          capture_output=True, text=True, errors="replace", timeout=timeout)


def workdir(keep):
    if keep:
        path = Path(keep).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path, False
    return Path(tempfile.mkdtemp(prefix="cl_trace_")), True


def compile_keep(tc, source, flags, includes, out, listing=True):
    """Compile once with /Bk into `out`; returns (prefix, completed process)."""
    stem = Path(source).stem
    prefix = out / (stem + "_")
    extra = ["/Bk" + str(prefix), "/Fo" + str(out / (stem + ".obj"))]
    if listing:
        extra += ["/FAs", "/Fa" + str(out / (stem + ".asm"))]
    args = compile_args(flags, includes, source)
    args = args[:-1] + extra + args[-1:]
    proc = run_cl(tc, args, out)
    return prefix, proc


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# ---------------------------------------------------------------- live observation (Windows)

class DirectoryWatcher(threading.Thread):
    """ReadDirectoryChangesW on one directory: every create/size/delete with a timestamp."""

    def __init__(self, path, start):
        super().__init__(daemon=True)
        self.path, self.start_time, self.events = str(path), start, []
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.restype = ctypes.c_void_p
        k.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                  ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        k.ReadDirectoryChangesW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                            ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p,
                                            ctypes.c_void_p]
        k.CancelIoEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        self.k = k
        # FILE_LIST_DIRECTORY, share read|write|delete, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS
        self.handle = k.CreateFileW(self.path, 1, 7, None, 3, 0x02000000, None)
        if self.handle in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        self.stopping = False

    def run(self):
        buffer = ctypes.create_string_buffer(65536)
        returned = ctypes.c_uint32()
        actions = {1: "create", 2: "delete", 3: "modify", 4: "rename-from", 5: "rename-to"}
        # FILE_NOTIFY_CHANGE_FILE_NAME | SIZE | LAST_WRITE
        while not self.stopping:
            ok = self.k.ReadDirectoryChangesW(self.handle, buffer, len(buffer), 0, 0x1 | 0x8 | 0x10,
                                              ctypes.byref(returned), None, None)
            if not ok:
                break
            when = time.perf_counter() - self.start_time
            raw, pos = buffer.raw[:returned.value], 0
            while raw:
                nxt, action, length = int.from_bytes(raw[pos:pos + 4], "little"), \
                    int.from_bytes(raw[pos + 4:pos + 8], "little"), int.from_bytes(raw[pos + 8:pos + 12], "little")
                name = raw[pos + 12:pos + 12 + length].decode("utf-16-le")
                try:
                    size = os.path.getsize(os.path.join(self.path, name))
                except OSError:
                    size = None
                self.events.append({"t_ms": round(when * 1000, 2), "action": actions.get(action, str(action)),
                                    "file": name, "size": size})
                if not nxt:
                    break
                pos += nxt

    def stop(self):
        self.stopping = True
        self.k.CancelIoEx(self.handle, None)
        self.join(timeout=5)
        self.k.CloseHandle(self.handle)


def file_lifetimes(events):
    files = {}
    for e in events:
        item = files.setdefault(e["file"], {"file": e["file"], "created_ms": None, "deleted_ms": None,
                                            "max_size": 0, "events": 0})
        item["events"] += 1
        if e["action"] in ("create", "rename-to") and item["created_ms"] is None:
            item["created_ms"] = e["t_ms"]
        if e["action"] in ("delete", "rename-from"):
            item["deleted_ms"] = e["t_ms"]
        if e["size"]:
            item["max_size"] = max(item["max_size"], e["size"])
    return list(files.values())


def debug_run(tc, args, cwd, tmp, timeout=300):
    """Run cl.exe under a read-only debug loop; returns (exit code, output, module timeline)."""
    pointer = ctypes.sizeof(ctypes.c_void_p)

    class DebugInfo(ctypes.Union):
        _fields_ = [("alignment", ctypes.c_void_p), ("raw", ctypes.c_ubyte * (160 if pointer == 8 else 84))]

    class DebugEvent(ctypes.Structure):
        _fields_ = [("code", ctypes.c_uint32), ("pid", ctypes.c_uint32), ("tid", ctypes.c_uint32),
                    ("info", DebugInfo)]

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.WaitForDebugEvent.argtypes = [ctypes.POINTER(DebugEvent), ctypes.c_uint32]
    k.ContinueDebugEvent.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    k.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    k.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.DebugActiveProcessStop.argtypes = [ctypes.c_uint32]
    start = time.perf_counter()
    timeline, bases = [], {}
    log = Path(cwd) / "cl_trace.stdout.txt"

    def path_of(handle):
        if not handle:
            return None
        buffer = ctypes.create_unicode_buffer(32768)
        try:
            if k.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0):
                return buffer.value.removeprefix("\\\\?\\")
        finally:
            k.CloseHandle(handle)
        return None

    with log.open("wb") as out:
        # DEBUG_PROCESS (0x1): children too, should the driver spawn any.
        process = subprocess.Popen([str(tc["cl"]), *args], cwd=str(cwd), env=cl_environment(tc, tmp),
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW | 0x1)
        deadline, live = time.monotonic() + timeout, set()
        try:
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("cl trace exceeded %d s" % timeout)
                event = DebugEvent()
                if not k.WaitForDebugEvent(ctypes.byref(event), 500):
                    if ctypes.get_last_error() == 121:
                        continue
                    raise ctypes.WinError(ctypes.get_last_error())
                raw = bytes(event.info.raw)
                when = round((time.perf_counter() - start) * 1000, 2)
                word = lambda i: int.from_bytes(raw[i * pointer:(i + 1) * pointer], "little")
                status = 0x10002  # DBG_CONTINUE
                if event.code == 3:  # CREATE_PROCESS: hFile, hProcess, hThread, lpBaseOfImage
                    live.add(event.pid)
                    timeline.append({"t_ms": when, "pid": event.pid, "event": "process",
                                     "path": path_of(word(0))})
                elif event.code == 6:  # LOAD_DLL: hFile, lpBaseOfDll
                    name = path_of(word(0))
                    bases[(event.pid, word(1))] = name
                    timeline.append({"t_ms": when, "pid": event.pid, "event": "load", "path": name})
                elif event.code == 7:  # UNLOAD_DLL: lpBaseOfDll
                    timeline.append({"t_ms": when, "pid": event.pid, "event": "unload",
                                     "path": bases.get((event.pid, word(0)))})
                elif event.code == 5:
                    timeline.append({"t_ms": when, "pid": event.pid, "event": "exit",
                                     "code": int.from_bytes(raw[:4], "little")})
                    live.discard(event.pid)
                elif event.code == 1:
                    exc = int.from_bytes(raw[:4], "little")
                    if exc not in (0x80000003, 0x4000001F):  # breakpoint, WOW64 breakpoint
                        status = 0x80010001  # DBG_EXCEPTION_NOT_HANDLED
                if not k.ContinueDebugEvent(event.pid, event.tid, status):
                    raise ctypes.WinError(ctypes.get_last_error())
                if event.code == 5 and not live:
                    break
            code = process.wait(timeout=10)
        finally:
            if process.poll() is None:
                k.DebugActiveProcessStop(process.pid)
                process.terminate()
                process.wait(timeout=5)
    return code, log.read_text(errors="replace"), timeline


# ---------------------------------------------------------------- commands

def describe_il(prefix):
    prefix = Path(prefix)
    files = {}
    for suffix in IL_SUFFIXES + ("db", "lk", "md"):
        path = prefix.with_name(prefix.name + suffix)
        if not path.is_file():
            continue
        data = path.read_bytes()
        info = {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "head": data[:16].hex()}
        if suffix == "gl":
            info.update(parse_gl_header(data))
            info["strings"] = len(il_strings(data))
            info["named_records"] = len(scan_gl_names(data))
        elif suffix == "sy":
            blocks = parse_sy(data)
            info["functions"] = len(blocks)
            info["records"] = sum(len(b.records) for b in blocks)
            info["unparsed_spans"] = sum(len(b.unparsed) for b in blocks)
            info["blocks"] = [[asdict(r) for r in b.records] for b in blocks]
        else:
            info["strings"] = len(il_strings(data))
        files[suffix] = info
    return files


def cmd_passes(ns, tc):
    out, temporary = workdir(ns.keep)
    tmp = out / "tmp"
    tmp.mkdir(exist_ok=True)
    args = compile_args(ns.flags, ns.include, ns.source)
    args = args[:-1] + ["/Bz" if ns.dry else "/Bd", "/Fo" + str(out / (Path(ns.source).stem + ".obj"))] + args[-1:]
    result = {"cl": str(tc["cl"]), "args": args, "workdir": str(out)}
    if ns.dry:
        proc = run_cl(tc, args, out)
        code, text, timeline, events = proc.returncode, proc.stdout + proc.stderr, [], []
    else:
        start = time.perf_counter()
        watcher = DirectoryWatcher(tmp, start)
        watcher.start()
        try:
            if ns.debug:
                code, text, timeline = debug_run(tc, args, out, tmp)
            else:
                proc = run_cl(tc, args, out, tmp)
                code, text, timeline = proc.returncode, proc.stdout + proc.stderr, []
            time.sleep(0.05)
        finally:
            watcher.stop()
        events = watcher.events
    result.update({"returncode": code, "passes": [asdict(p) for p in parse_pass_lines(text)],
                   "il_files": file_lifetimes(events), "dir_events": events, "modules": timeline})
    if ns.keep:
        prefix, proc = compile_keep(tc, ns.source, ns.flags, ns.include, out, listing=False)
        result["kept_il"] = describe_il(prefix)
        for item in result["kept_il"].values():
            item.pop("blocks", None)
    if ns.json:
        print(json.dumps(result, indent=2))
    else:
        print("cl %s -> exit %s" % (" ".join(args), code))
        for p in result["passes"]:
            print("pass %-5s %s" % (p["name"], p["dll"]))
            print("    " + " ".join(p["argv"]))
        if result["il_files"]:
            print("intermediate files in private TMP (ReadDirectoryChangesW):")
            for f in result["il_files"]:
                print("    %-24s created %8s ms  deleted %8s ms  max %8d bytes  (%d events)"
                      % (f["file"], f["created_ms"], f["deleted_ms"], f["max_size"], f["events"]))
        elif not ns.dry:
            print("no file appeared in the private TMP")
        for m in timeline:
            if m["event"] in ("process", "exit") or (m.get("path") and re.search(
                    r"\\(c1xx|c1|c2|c1ast|c1xxast|mspdb80|msobj80|link|cl)\.(dll|exe)$", m["path"] or "", re.I)):
                print("    %8.2f ms  %-7s %s" % (m["t_ms"], m["event"], m.get("path") or m.get("code")))
        for suffix, info in result.get("kept_il", {}).items():
            print("kept %-3s %8d bytes  %s" % (suffix, info["size"], info["path"]))
    if temporary:
        shutil.rmtree(out, ignore_errors=True)
    return 0 if code == 0 else 1


def symbols_of(tc, source, flags, includes, out):
    prefix, proc = compile_keep(tc, source, flags, includes, out)
    sy = prefix.with_name(prefix.name + "sy")
    if proc.returncode != 0 or not sy.is_file():
        raise TraceError("compile failed:\n" + proc.stdout + proc.stderr)
    blocks = parse_sy(sy.read_bytes())
    asm = out / (Path(source).stem + ".asm")
    listed = parse_listing(asm.read_text(errors="replace")) if asm.is_file() else []
    gl = prefix.with_name(prefix.name + "gl")
    total = parse_gl_header(gl.read_bytes())["symbol_count"] if gl.is_file() else None
    globals_ = scan_gl_names(gl.read_bytes()) if gl.is_file() else []
    return join_blocks(blocks, listed), total, blocks, globals_


def cmd_symbols(ns, tc):
    out, temporary = workdir(ns.keep)
    try:
        functions, total, blocks, globals_ = symbols_of(tc, ns.source, ns.flags, ns.include, out)
    finally:
        if temporary:
            shutil.rmtree(out, ignore_errors=True)
    if ns.function:
        pattern = re.compile(ns.function)
        functions = [f for f in functions if pattern.search(f.name) or (f.decorated and pattern.search(f.decorated))]
    picked = []
    if ns.globals:
        gpat = re.compile(ns.globals)
        picked = [{"name": n, "number": v, "mod64": v % 64} for n, v in globals_ if gpat.search(n)]
    if ns.json:
        print(json.dumps({"unit_symbol_count": total, "globals": picked,
                          "functions": [asdict(f) for f in functions]}, indent=2))
        return 0
    print("unit symbol count (gl header): %s" % total)
    for g in picked:
        print("global %7d mod64 %2d  %s" % (g["number"], g["mod64"], g["name"]))
    for f in functions:
        print("%s  %s" % (f.name, f.decorated or ""))
        print("    %7s %5s %-6s %3s %-24s %8s %6s %s" % ("number", "mod64", "kind", "lvl", "name", "suffix", "frame", "size"))
        for r in f.symbols:
            print("    %7d %5d %-6s %3d %-24s %8s %6s %s" % (
                r["number"], r["mod64"], r["kind"], r["level"], r["name"],
                "" if r["listing_suffix"] is None else "$%d" % r["listing_suffix"],
                "" if r["frame_offset"] is None else r["frame_offset"], "" if r["size"] is None else r["size"]))
    unparsed = sum(len(b.unparsed) for b in blocks)
    if unparsed:
        print("warning: %d sy spans not decoded (records skipped by resync)" % unparsed)
    return 0


def cmd_il(ns, tc):
    temporary, out = False, None
    if ns.prefix:
        prefix = Path(ns.prefix)
    else:
        if not ns.source:
            raise TraceError("il needs --source or --prefix")
        out, temporary = workdir(ns.keep)
        prefix, proc = compile_keep(tc, ns.source, ns.flags, ns.include, out, listing=False)
        if proc.returncode != 0:
            raise TraceError("compile failed:\n" + proc.stdout + proc.stderr)
    try:
        files = describe_il(prefix)
    finally:
        if temporary:
            shutil.rmtree(out, ignore_errors=True)
    if ns.json:
        print(json.dumps(files, indent=2))
        return 0
    for suffix, info in files.items():
        line = "%-3s %9d bytes  head %s" % (suffix, info["size"], info["head"])
        if suffix == "gl":
            line += "  symbol_count %d  named %d  strings %d" % (info["symbol_count"], info["named_records"], info["strings"])
        elif suffix == "sy":
            line += "  functions %d  records %d  unparsed %d" % (info["functions"], info["records"], info["unparsed_spans"])
        else:
            line += "  strings %d" % info["strings"]
        print(line)
    if "sy" in files and ns.records:
        for i, block in enumerate(files["sy"]["blocks"]):
            print("sy function #%d" % i)
            for r in block:
                print("    %7d %-6s lvl %d %-20s %s" % (r["number"], r["kind"], r["level"], r["name"] or "<temp>",
                                                      " ".join("%s=%s" % kv for kv in r["attrs"].items())))
    return 0


COST_CASES = [
    ("int v0;", "int global"), ("extern int e();", "function declaration, no parameters"),
    ("extern int e(int);", "function declaration, 1 parameter"),
    ("extern int e(int a, int b, int c);", "function declaration, 3 parameters"),
    ("typedef int T;", "typedef"), ("#define M 1", "macro"), ("namespace N {}", "empty namespace"),
    ("enum E { A };", "enum, 1 enumerator"), ("enum E { A, B, C, D };", "enum, 4 enumerators"),
    ("struct S;", "struct forward declaration"), ("struct S {};", "empty struct"),
    ("struct S { int a; };", "struct, 1 data member"), ("struct S { int a, b, c, d; };", "struct, 4 data members"),
    ("struct S { void m(); };", "struct, 1 method declaration"),
    ("struct S { int m() { return 0; } };", "struct, 1 inline method"),
    ("struct S { virtual void m(); };", "struct, 1 virtual method"),
    ("struct S { S(); ~S(); };", "struct, constructor + destructor declarations"),
    ("inline int e(int a) { return a; }", "inline function, 1 parameter, never called"),
    ("int e(int a) { int b = a; return b; }", "function definition, 1 parameter + 1 local"),
    ("const char* s = \"abc\";", "global initialised with a string literal"),
    ("int u = cl_trace_g(0);", "global with a dynamic initialiser"),
    ("template<class T> struct X { T a; };", "class template, not instantiated"),
    ("template<class T> struct X { T a; }; X<int>* xp;", "class template + pointer to X<int>"),
    ("template<class T> struct X { T a; }; X<int> xi;", "class template + X<int> object"),
    ("template<class T> T id(T a) { return a; }", "function template, not instantiated"),
    ("int w() { return 1; }", "control: int w() { return 1; }"),
    ("template<class T> T id(T a) { return a; } int w() { return id(1); }", "function template + w() calling id<int>"),
    ("template<class T> T id(T a) { return a; } int w() { return id(1) + id(2); }", "... id<int> called twice"),
    ("inline int e(int a) { return a; } int w() { return e(1); }", "inline e + w() calling e"),
]


def probe_number(tc, prefix, flags, work):
    path = work / "probe.cpp"
    path.write_text("int cl_trace_g(int*);\n" + prefix +
                    "\nint cl_trace_f(int n) { if (n) { int probe = n; return cl_trace_g(&probe); } return 0; }\n")
    functions = symbols_of(tc, path, flags, [], work)[0]
    return next(r["number"] for f in functions for r in f.symbols if r["name"] == "probe")


def cmd_experiment(ns, tc):
    out, temporary = workdir(ns.keep)
    try:
        if ns.kind == "cost":
            base = probe_number(tc, "", ns.flags, out)
            print("probe local's number with nothing declared: %d (flags: %s)" % (base, ns.flags or "none"))
            print("%-6s  %s" % ("cost", "construct before the probe function"))
            for text, label in COST_CASES:
                print("%6d  %-48s %s" % (probe_number(tc, text, ns.flags, out) - base, label, text))
            return 0
        # flip: insert N typedefs (one number each, no code) before a marker and hash the function's code.
        if not (ns.source and ns.insert_before and ns.function):
            raise TraceError("flip needs --source, --insert-before and --function")
        source = Path(ns.source).read_text(errors="replace")
        if ns.insert_before not in source:
            raise TraceError("marker not found in source: " + ns.insert_before)
        variants = {}
        # The shifted copy lives in the work directory (never beside the source); the source's
        # directory goes first on the include path so its quoted includes still resolve.
        path = out / ("cl_trace_flip_" + Path(ns.source).name)
        includes = [str(Path(ns.source).resolve().parent), *ns.include]
        for n in range(ns.start, ns.stop):
            pads = "".join("typedef int cl_trace_pad%d;\n" % i for i in range(n))
            path.write_text(source.replace(ns.insert_before, pads + ns.insert_before, 1))
            try:
                functions, total, _, globals_ = symbols_of(tc, path, ns.flags, includes, out)
            finally:
                path.unlink()
            fn = next(f for f in functions if re.search(ns.function, f.decorated or f.name))
            asm = (out / (path.stem + ".asm")).read_text(errors="replace")
            body = re.search(re.escape(fn.decorated) + r" PROC.*?\n(.*?)" + re.escape(fn.decorated) + " ENDP", asm, re.S)
            lines = [re.sub(r"\$\d+", "$N", l.split(";")[0]).strip() for l in body.group(1).splitlines()]
            digest = hashlib.sha1("\n".join(l for l in lines if l).encode()).hexdigest()[:8]
            variants.setdefault(digest, n)
            note = " ".join("%s=%d(mod64 %d)" % (r["name"], r["number"], r["mod64"])
                            for r in fn.symbols if ns.local and r["name"] == ns.local)
            if ns.globals:
                note += " " + " ".join("%s=%d(mod64 %d)" % (g, v, v % 64) for g, v in globals_ if re.search(ns.globals, g))
            print("pads %4d  code %s  %s" % (n, digest, note), flush=True)
        print("%d distinct code variant(s): %s" % (len(variants), ", ".join("%s from pads %d" % kv for kv in variants.items())))
        return 0
    finally:
        if temporary:
            shutil.rmtree(out, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("passes", "symbols", "il", "experiment"):
        p = sub.add_parser(name)
        if name == "experiment":
            p.add_argument("kind", choices=("cost", "flip"))
            p.add_argument("--insert-before", help="flip: text before which the typedef pads go")
            p.add_argument("--function", help="flip: regex on the decorated name of the function to hash")
            p.add_argument("--local", help="flip: local whose number to print")
            p.add_argument("--globals", help="flip: regex of gl names whose numbers to print")
            p.add_argument("--start", type=int, default=0)
            p.add_argument("--stop", type=int, default=64)
        p.add_argument("--source", required=(name in ("passes", "symbols")))
        p.add_argument("--flags", default="")
        p.add_argument("-I", "--include", action="append", default=[])
        p.add_argument("--keep", help="keep outputs (IL, listing, obj) in this directory")
        p.add_argument("--vc", help="VC root (default: config/project.json toolchain_root)")
        p.add_argument("--json", action="store_true")
        if name == "passes":
            p.add_argument("--dry", action="store_true", help="/Bz: print the passes without running them")
            p.add_argument("--debug", action="store_true", help="observe DLL loads with Windows debug events")
        if name == "symbols":
            p.add_argument("--function", help="regex on the function's name or decorated name")
            p.add_argument("--globals", help="regex: also print gl records (globals, functions, members) by name")
        if name == "il":
            p.add_argument("--prefix", help="an existing /Bk prefix (dir/stem_)")
            p.add_argument("--records", action="store_true", help="print every sy record")
    ns = parser.parse_args(argv)
    try:
        tc = toolchain(ns.vc)
        return {"passes": cmd_passes, "symbols": cmd_symbols, "il": cmd_il,
                "experiment": cmd_experiment}[ns.command](ns, tc)
    except TraceError as error:
        print("cl_trace: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
