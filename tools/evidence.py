"""Bounded, read-only retail evidence and reproducible local Ghidra imports.

PDB starts and Ghidra bodies are evidence, never gate-admitted boundaries.
Requires pefile and capstone for disasm/xref/class; Ghidra for ghidra-import.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def project_paths(binary, config=None):
    config = Path(config or ROOT / "config/project.json")
    project = read_json(config)
    entry = project["binaries"][binary]
    primary = Path(project.get("primary_checkout", ROOT))
    image = Path(entry.get("path", Path(project["toolchain_root"]) / "bin" / entry["filename"]))
    return project, entry, primary, image


def load_symbols(primary, binary, image):
    path = primary / "build/evidence" / (binary + ".symbols.json")
    if not path.is_file():
        raise ValueError("symbol map missing: %s; run tools/symbols.py first" % path)
    raw = path.read_bytes()
    result = json.loads(raw.decode("utf-8-sig"))
    result["_input_sha256"] = hashlib.sha256(raw).hexdigest()
    identity = result.get("identity", {})
    expected = identity.get("binary_sha256") or identity.get("sha256")
    if not identity.get("verified") or not expected:
        raise ValueError("symbol map lacks verified identity and binary SHA-256")
    if expected.lower() != hashlib.sha256(image.read_bytes()).hexdigest():
        raise ValueError("symbol map binary SHA-256 mismatch")
    return result, path


def symbol_rows(symbols):
    return symbols.get("functions", []) + symbols.get("data", [])


def resolve_symbol(symbols, name, base):
    rows = symbol_rows(symbols)
    exact = [row for row in rows if row["name"] == name]
    if not exact:
        try:
            address = number(name)
        except ValueError:
            raise ValueError("unknown symbol: " + name) from None
        rva = address - base if address >= base else address
        exact = [row for row in rows if number(row["rva"]) == rva]
        if not exact:
            return {"name": "<address; identity unresolved>", "rva": rva,
                    "size": None, "boundary_status": "address-only"}
    addresses = {number(row["rva"]) for row in exact}
    if len(addresses) != 1:
        raise ValueError("ambiguous symbol; use its RVA or VA")
    return exact[0]


def decode(data, address):
    try:
        import capstone
    except ImportError:
        raise ValueError("capstone unavailable; install in the selected Python environment") from None
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    yield from engine.disasm(data, address)


def references(insn):
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM
    for operand in insn.operands:
        if operand.type == X86_OP_IMM:
            yield operand.imm & 0xffffffff, "immediate (address interpretation requires evidence)"
        elif operand.type == X86_OP_MEM and operand.mem.base == 0 and operand.mem.index == 0:
            yield operand.mem.disp & 0xffffffff, "absolute memory"


def disassembly(pe, row, symbols, max_bytes):
    rva = number(row["rva"])
    section = pe.get_section_by_rva(rva)
    if section is None or not section.Characteristics & 0x20000000:
        raise ValueError("selected address is not in an executable section")
    end = section.VirtualAddress + section.SizeOfRawData
    if rva >= end:
        raise ValueError("selected executable address has no physical section bytes")
    starts = [number(x["rva"]) for x in symbol_rows(symbols) if number(x["rva"]) > rva]
    if starts:
        end = min(end, min(starts))
    if row.get("size") is not None:
        end = min(end, rva + number(row["size"]))
    data = pe.get_data(rva, max(0, min(end - rva, max_bytes)))
    base = pe.OPTIONAL_HEADER.ImageBase
    names = {base + number(x["rva"]): x["name"] for x in symbol_rows(symbols)}
    yield "boundary=%s; display bound only; no exact-length claim" % row.get("boundary_status", "unresolved")
    for insn in decode(data, base + rva):
        annotations = [names[target] for target, _kind in references(insn) if target in names]
        yield "%08x  %-24s %-8s %s%s" % (insn.address, insn.bytes.hex(" "), insn.mnemonic,
               insn.op_str, " ; " + ", ".join(annotations) if annotations else "")


def xrefs(pe, row, symbols):
    base = pe.OPTIONAL_HEADER.ImageBase
    target = base + number(row["rva"])
    yield "Capstone linear executable-section scan; direct immediates/absolute operands only"
    yield "Instruction boundaries may include data; indirect references and computed targets are unresolved"
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        # Restart after undecodable bytes, retaining an explicit linear-scan caveat.
        data = section.get_data()
        cursor = 0
        while cursor < len(data):
            previous = cursor
            for insn in decode(data[cursor:], base + section.VirtualAddress + cursor):
                cursor = insn.address + insn.size - base - section.VirtualAddress
                for value, kind in references(insn):
                    if value == target:
                        yield "%08x  %-8s %s ; %s" % (insn.address, insn.mnemonic, insn.op_str, kind)
            if cursor == previous:
                cursor += 1


def class_evidence(pe, row, symbols):
    base = pe.OPTIONAL_HEADER.ImageBase
    target = base + number(row["rva"])
    name = row["name"]
    yield "Public spellings and pointer candidates; no signature/layout inference is admitted"
    yield "selected: %s; module=%s; module_evidence=%s" % (name, row.get("module"), row.get("module_evidence"))
    stem = name.split("@@", 1)[0] if "@@" in name else name
    for other in symbol_rows(symbols):
        if other is not row and stem in other["name"]:
            yield "related-spelling %08x %s" % (base + number(other["rva"]), other["name"])
    needle = target.to_bytes(4, "little")
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            continue
        data = section.get_data()
        for offset in range(0, max(0, len(data) - 3), 4):
            if data[offset:offset + 4] == needle:
                yield "pointer-candidate %08x -> %08x; vtable membership unresolved" % (
                    base + section.VirtualAddress + offset, target)


def bounded(lines, limit):
    iterator = iter(lines)
    for _ in range(limit - 1):
        try:
            yield next(iterator)
        except StopIteration:
            return
    try:
        tail = next(iterator)
    except StopIteration:
        return
    try:
        next(iterator)
    except StopIteration:
        yield tail
    else:
        yield "... output truncated; select a narrower symbol or increase --max-lines (up to 60)"


def ghidra_version(home):
    properties = home / "Ghidra/application.properties"
    if not properties.is_file():
        raise ValueError("Ghidra installation missing Ghidra/application.properties: " + str(home))
    for line in properties.read_text().splitlines():
        if line.startswith("application.version="):
            return line.partition("=")[2]
    raise ValueError("Ghidra version unavailable")


def analysis_timed_out(log_path):
    with Path(log_path).open(encoding="utf-8", errors="replace") as log:
        return any("REPORT: Analysis timed out at " in line for line in log)


def import_ghidra(args):
    project, entry, primary, image = project_paths(args.binary, args.config)
    home = Path(args.ghidra_home or os.environ.get("GHIDRA_HOME", ""))
    version = ghidra_version(home)
    symbols, symbol_file = load_symbols(primary, args.binary, image)
    out = primary / "build/ghidra" / args.binary / uuid.uuid4().hex
    out.mkdir(parents=True)
    seed = out / "public-starts.tsv"
    seed.write_text("".join("%x\t%s\n" % (number(row["va"]), row["name"].replace("\t", " ").replace("\n", " "))
                            for row in symbols.get("functions", [])), encoding="utf-8")
    manifest = {"schema_version": 1, "binary": args.binary, "binary_path": str(image),
                "binary_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
                "ghidra_home": str(home), "ghidra_version": version,
                "requested_version": "12.1.3", "version_deviation": version != "12.1.3",
                "symbol_map": str(symbol_file), "symbol_map_sha256": symbols["_input_sha256"],
                "pdb_application": "not_requested", "status": "running", "export_limit": args.limit,
                "analysis_timeout_seconds": args.analysis_timeout}
    pdb = Path(args.pdb) if args.pdb else None
    if pdb:
        expected = symbols.get("identity", {}).get("pdb_sha256")
        if not expected or hashlib.sha256(pdb.read_bytes()).hexdigest() != expected:
            raise ValueError("PDB application requires matching pdb_sha256 from validated symbol map")
        manifest["pdb_application"] = "requested; see pdb-status.json"
        manifest["pdb_path"] = str(pdb)
        manifest["pdb_sha256"] = expected
    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    script = ROOT / "tools/ghidra"
    manifest["scripts_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in sorted(script.glob("*.java"))}
    java = str(Path(args.java_home) / "bin/java.exe") if args.java_home else shutil.which("java")
    if not java:
        raise ValueError("Java not found; provide --java-home")
    vmargs = subprocess.run([java, "-cp", str(home / "support/LaunchSupport.jar"), "LaunchSupport", str(home), "-vmargs"],
                            capture_output=True, text=True, check=True).stdout.splitlines()
    # Launch the same Java entry point as analyzeHeadless.bat. Passing an argv list directly
    # avoids its cmd.exe expansion bug on image paths containing '(x86)'.
    command = [java, *vmargs, "-Xmx2G", "-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2", "-cp",
               str(home / "Ghidra/Framework/Utility/lib/Utility.jar"), "ghidra.Ghidra",
               "ghidra.app.util.headless.AnalyzeHeadless", str(out), "vc8", "-import", str(image),
               "-scriptPath", str(script), "-preScript", "PrepareEvidence.java", str(pdb) if pdb else "-",
               str(out / "pdb-status.json"), "-postScript", "CreateFunctions.java", str(seed),
               str(out / "create-functions.tsv"), "-postScript", "ExportEvidence.java", str(out),
               str(args.limit), "-analysisTimeoutPerFile", str(args.analysis_timeout), "-max-cpu", "2"]
    manifest["command"] = command
    environment = os.environ.copy()
    if args.java_home:
        environment["JAVA_HOME_OVERRIDE"] = args.java_home
    print("Ghidra %s%s; logs/export: %s" % (version, " (plan requests 12.1.3)" if version != "12.1.3" else "", out), flush=True)
    with (out / "headless.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=environment, check=False)
    pdb_status_path = out / "pdb-status.json"
    pdb_status = read_json(pdb_status_path).get("status") if pdb_status_path.is_file() else "missing"
    manifest["pdb_application"] = pdb_status
    success = (result.returncode == 0 and (out / "export-complete.json").is_file()
               and (out / "create-functions.tsv").is_file()
               and pdb_status == ("applied_local_validated_pdb" if pdb else "not_requested"))
    timed_out = analysis_timed_out(out / "headless.log")
    manifest.update(status=("complete_with_analysis_timeout" if timed_out else "complete") if success else "failed",
                    returncode=result.returncode, analysis_timed_out=timed_out)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("GHIDRA %s: %s" % (manifest["status"].upper(), manifest_path))
    return 0 if success else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="verb", required=True)
    for verb in ("disasm", "xref", "class"):
        cmd = sub.add_parser(verb)
        cmd.add_argument("--binary", required=True)
        cmd.add_argument("--symbol", required=True)
        cmd.add_argument("--config", type=Path)
        cmd.add_argument("--max-lines", type=int, choices=range(4, 61), default=60, metavar="4..60")
        cmd.add_argument("--max-bytes", type=int, choices=range(1, 200001), default=4096, metavar="1..200000")
    cmd = sub.add_parser("ghidra-import", help="fresh isolated project and ignored export; never admits matches")
    cmd.add_argument("--binary", required=True)
    cmd.add_argument("--config", type=Path)
    cmd.add_argument("--ghidra-home")
    cmd.add_argument("--java-home")
    cmd.add_argument("--pdb", help="local PDB verified against validated symbols map")
    cmd.add_argument("--limit", type=int, default=0, help="export first N function bodies; 0 exports all")
    cmd.add_argument("--analysis-timeout", type=int, default=600)
    args = parser.parse_args(argv)
    try:
        if args.verb == "ghidra-import":
            if args.limit < 0:
                raise ValueError("--limit must be nonnegative")
            return import_ghidra(args)
        import pefile
        _project, _entry, primary, image = project_paths(args.binary, args.config)
        symbols, _path = load_symbols(primary, args.binary, image)
        with pefile.PE(str(image)) as pe:
            if pe.FILE_HEADER.Machine != 0x14c:
                raise ValueError("only x86 retail PE images are supported")
            row = resolve_symbol(symbols, args.symbol, pe.OPTIONAL_HEADER.ImageBase)
            header = "%s %s RVA=0x%x VA=0x%x" % (args.binary, row["name"], number(row["rva"]), pe.OPTIONAL_HEADER.ImageBase + number(row["rva"]))
            lines = (disassembly(pe, row, symbols, args.max_bytes) if args.verb == "disasm" else
                     xrefs(pe, row, symbols) if args.verb == "xref" else class_evidence(pe, row, symbols))
            print("\n".join(bounded(_prepend(header, lines), args.max_lines)))
        return 0
    except (ValueError, OSError, KeyError, ImportError, subprocess.SubprocessError) as error:
        print("EVIDENCE ERROR: " + str(error), file=sys.stderr)
        return 2


def _prepend(header, lines):
    yield header
    yield from lines


if __name__ == "__main__":
    raise SystemExit(main())
