"""Local bounded PDB/Ghidra lookup. Indexes evidence, never source admissions."""
from __future__ import annotations

import argparse
from contextlib import closing
import csv
import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

from evidence import bounded, load_symbols, number, project_paths

SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata(binary TEXT PRIMARY KEY,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entries(binary TEXT,rva INTEGER,va INTEGER,payload TEXT NOT NULL,PRIMARY KEY(binary,rva));
CREATE TABLE IF NOT EXISTS names(binary TEXT,rva INTEGER,name TEXT,source TEXT);
CREATE INDEX IF NOT EXISTS names_exact ON names(binary,name);
CREATE TABLE IF NOT EXISTS ranges(binary TEXT,function_rva INTEGER,start_rva INTEGER,end_rva INTEGER);
CREATE INDEX IF NOT EXISTS ranges_start ON ranges(binary,start_rva);
CREATE TABLE IF NOT EXISTS refs(binary TEXT,function_rva INTEGER,site_va INTEGER,target_va INTEGER,target TEXT,type TEXT,ordinal INTEGER);
CREATE INDEX IF NOT EXISTS refs_from ON refs(binary,function_rva,site_va,ordinal);
CREATE INDEX IF NOT EXISTS refs_to ON refs(binary,target_va,site_va,ordinal);
CREATE TABLE IF NOT EXISTS contributions(binary TEXT,start_rva INTEGER,end_rva INTEGER,module_index INTEGER,module TEXT,object_file TEXT);
CREATE INDEX IF NOT EXISTS contribution_start ON contributions(binary,start_rva);
"""


def address(text):
    """Ghidra address text is hex without 0x; non-RAM targets remain unresolved."""
    try:
        return int(text, 16)
    except ValueError:
        return None


def required_address(text):
    value = address(text)
    if value is None:
        raise ValueError("invalid RAM source address: " + clipped(text))
    return value


def rows(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as source:
        yield from csv.DictReader(source, delimiter="\t")


def connect(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript(SCHEMA)
    return connection


def build_index(database, binary, run, symbols, symbols_path, allow_pending=False):
    run = Path(run).resolve()
    raw = (run / "manifest.json").read_bytes()
    manifest = json.loads(raw.decode("utf-8-sig"))
    expected = symbols["identity"]["binary_sha256"]
    if manifest.get("binary") != binary or manifest.get("binary_sha256") != expected:
        raise ValueError("export and validated symbol-map binary identities differ")
    complete_path = run / "export-complete.json"
    complete = manifest.get("status") in ("complete", "complete_with_analysis_timeout") and manifest.get("returncode") == 0 and complete_path.is_file()
    if complete:
        completion = json.loads(complete_path.read_text())
        if completion.get("binary_sha256", expected) != expected or completion.get("ghidra_version") != manifest.get("ghidra_version"):
            raise ValueError("export completion identity mismatch")
    if not complete and not (allow_pending and manifest.get("status") == "running" and (run / "metadata-complete.json").is_file()):
        raise ValueError("export is incomplete; --allow-pending requires completed metadata and a running manifest")
    if not complete:
        metadata_marker = json.loads((run / "metadata-complete.json").read_text())
        if metadata_marker.get("binary_sha256") != expected:
            raise ValueError("partial metadata identity mismatch")
    base = number(symbols["identity"]["image_base"])
    metadata = {"schema_version": 1, "binary": binary, "binary_sha256": expected,
                "image_base": base, "symbol_map": str(symbols_path), "symbol_map_sha256": symbols["_input_sha256"],
                "export_run": str(run), "export_manifest_sha256": hashlib.sha256(raw).hexdigest(),
                "ghidra_version": manifest.get("ghidra_version"), "partial_snapshot": not complete,
                "built_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "admission": "Evidence only; inferred Ghidra bodies are not source denominators."}
    entries = {}
    names = []
    for kind in ("functions", "data"):
        for public in symbols.get(kind, []):
            rva = number(public["rva"])
            entry = entries.setdefault(rva, {"public": [], "ghidra": None})
            entry["public"].append(dict(public, record_group=kind))
            names.append((binary, rva, public["name"], "PDB S_PUB32"))
    for function in rows(run / "functions.tsv"):
        rva = number(function["rva"])
        entry = entries.setdefault(rva, {"public": [], "ghidra": None})
        entry["ghidra"] = function
        names.append((binary, rva, function["name"], "Ghidra analysis"))
        stem = function["va"]
        result_path = run / "functions" / (stem + ".json")
        result = None
        if result_path.is_file():
            try:
                result = json.loads(result_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                if complete:
                    raise ValueError("invalid completed per-function JSON: " + str(result_path)) from None
            if result and (result.get("binary_sha256") != expected or number(result["rva"]) != rva):
                raise ValueError("per-function identity mismatch: " + str(result_path))
        entry["result"] = result
        entry["paths"] = {suffix: str(run / "functions" / (stem + "." + suffix))
                          for suffix in ("c", "asm", "json") if (run / "functions" / (stem + "." + suffix)).is_file()}
    modules = {int(module["index"]): module for module in symbols.get("modules", [])}
    sections = {int(section["index"]): section for section in symbols.get("sections", [])}
    with closing(connect(database)) as connection, connection:
        for table in ("metadata", "entries", "names", "ranges", "refs", "contributions"):
            connection.execute("DELETE FROM " + table + " WHERE binary=?", (binary,))
        connection.execute("INSERT INTO metadata VALUES(?,?)", (binary, json.dumps(metadata)))
        connection.executemany("INSERT INTO entries VALUES(?,?,?,?)", ((binary, rva, base + rva, json.dumps(entry)) for rva, entry in entries.items()))
        connection.executemany("INSERT INTO names VALUES(?,?,?,?)", names)
        connection.executemany("INSERT INTO ranges VALUES(?,?,?,?)", ((binary, required_address(row["function_va"]) - base,
            required_address(row["start_va"]) - base, required_address(row["end_va_inclusive"]) - base) for row in rows(run / "ranges.tsv")))
        connection.executemany("INSERT INTO refs VALUES(?,?,?,?,?,?,?)", ((binary, required_address(row["function_va"]) - base,
            required_address(row["site_va"]), address(row["target_va"]), row["target_va"], row["type"], ordinal)
            for ordinal, row in enumerate(rows(run / "references.tsv"))))
        contributions = []
        for contribution in symbols.get("section_contributions", []):
            section = sections.get(int(contribution["section"]))
            module = modules.get(int(contribution["module_index"]), {})
            size = int(contribution["size"])
            if section and size > 0:
                start = int(section["rva"]) + int(contribution["offset"])
                contributions.append((binary, start, start + size - 1, contribution["module_index"], module.get("name"), module.get("object_file")))
        connection.executemany("INSERT INTO contributions VALUES(?,?,?,?,?,?)", contributions)
    return dict(metadata, indexed_entries=len(entries), indexed_names=len(names))


def clipped(value, limit=240):
    value = str(value).replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return value if len(value) <= limit else value[:limit] + " [truncated]"


def lookup(database, binary, symbol=None, rva=None, contains=None, limit=5, va=None):
    connection = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        stored = connection.execute("SELECT payload FROM metadata WHERE binary=?", (binary,)).fetchone()
        if not stored:
            raise ValueError("binary not indexed: " + binary)
        metadata = json.loads(stored[0])
        base = metadata["image_base"]
        yield "%s evidence snapshot partial=%s sha256=%s" % (binary, metadata["partial_snapshot"], metadata["binary_sha256"])
        yield "Ghidra boundaries are inferred; lookup provides no source-admission verdict."
        if va is not None:
            if number(va) < base:
                raise ValueError("VA is below image base")
            selected = [number(va) - base]
        elif rva is not None:
            selected = [number(rva)]
        elif symbol is not None:
            selected = [row[0] for row in connection.execute("SELECT DISTINCT rva FROM names WHERE binary=? AND name=? ORDER BY rva LIMIT ?", (binary, symbol, limit))]
        else:
            selected = [row[0] for row in connection.execute("SELECT DISTINCT rva FROM names WHERE binary=? AND instr(lower(name),lower(?))>0 ORDER BY rva LIMIT ?", (binary, contains, limit))]
        if not selected:
            yield "No exact entry found; query uses public spelling, Ghidra spelling, or --rva."
        for selected_rva in selected:
            stored = connection.execute("SELECT payload FROM entries WHERE binary=? AND rva=?", (binary, selected_rva)).fetchone()
            entry = json.loads(stored[0]) if stored else {"public": [], "ghidra": None}
            public = entry["public"]
            ghidra = entry["ghidra"]
            name = public[0]["name"] if public else ghidra["name"] if ghidra else "<no public or exact Ghidra entry>"
            yield "RVA=0x%x VA=0x%x %s" % (selected_rva, base + selected_rva, clipped(name))
            if public:
                yield "  PDB aliases: " + "; ".join(clipped(row["name"]) for row in public[:3]) + ("; more aliases omitted" if len(public) > 3 else "")
                yield "  PDB boundary: " + "; ".join(clipped("%s size=%s provenance=%s" % (row.get("boundary_status"), row.get("size"), row.get("size_provenance", row.get("boundary_provenance")))) for row in public[:2])
                yield "  PDB owner evidence: " + "; ".join(clipped("%s [%s]" % (row.get("module"), row.get("module_evidence"))) for row in public[:2])
            owners = connection.execute("SELECT module_index,module,object_file FROM contributions WHERE binary=? AND start_rva<=? AND end_rva>=? LIMIT 4", (binary, selected_rva, selected_rva)).fetchall()
            yield "  DBI contributions containing address: " + ("; ".join(clipped("module %s %s object=%s" % owner) for owner in owners) if owners else "unresolved")
            if ghidra:
                result = entry.get("result") or {}
                yield "  Ghidra: body_bytes=%s ranges=%s status=%s timeout=%s error=%s" % (ghidra["body_bytes"], ghidra["range_count"], result.get("status", ghidra["decompile_status"]), result.get("timed_out", "not captured"), clipped(result.get("error", "")))
                for suffix, path in entry.get("paths", {}).items():
                    yield "  %s: %s" % (suffix, clipped(path, 400))
            containing = connection.execute("SELECT DISTINCT function_rva FROM ranges WHERE binary=? AND start_rva<=? AND end_rva>=? ORDER BY function_rva LIMIT 4", (binary, selected_rva, selected_rva)).fetchall()
            if containing:
                yield "  Inferred containing bodies: " + ", ".join("0x%x" % (base + row[0]) for row in containing)
            outgoing = connection.execute("SELECT site_va,target,type FROM refs WHERE binary=? AND function_rva=? ORDER BY site_va,ordinal LIMIT 4", (binary, selected_rva)).fetchall()
            incoming = connection.execute("SELECT site_va,target,type FROM refs WHERE binary=? AND target_va=? ORDER BY site_va,ordinal LIMIT 4", (binary, base + selected_rva)).fetchall()
            for direction, references in (("out", outgoing), ("in", incoming)):
                yield "  Ghidra %s refs (up to 4; export order, not relocation verdict): %s" % (direction, "; ".join("0x%x -> %s %s" % (site, clipped(target), clipped(kind, 48)) for site, target, kind in references) or "none recorded")
    finally:
        connection.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="verb", required=True)
    build = sub.add_parser("build")
    build.add_argument("--run", type=Path, required=True)
    build.add_argument("--allow-pending", action="store_true")
    build.add_argument("--config", type=Path)
    find = sub.add_parser("lookup")
    query = find.add_mutually_exclusive_group(required=True)
    query.add_argument("--symbol")
    query.add_argument("--rva", type=number)
    query.add_argument("--va", type=number)
    query.add_argument("--contains")
    find.add_argument("--limit", type=int, choices=range(1, 11), default=5)
    find.add_argument("--max-lines", type=int, choices=range(4, 61), default=60)
    for command in (build, find):
        command.add_argument("--binary", required=True)
        command.add_argument("--database", type=Path, default=Path("E:/vc8-decomp/build/evidence/lookup.sqlite"))
    args = parser.parse_args(argv)
    try:
        if args.verb == "build":
            _project, _entry, primary, image = project_paths(args.binary, args.config)
            symbols, path = load_symbols(primary, args.binary, image)
            result = build_index(args.database, args.binary, args.run, symbols, path, args.allow_pending)
            print(json.dumps({key: result[key] for key in ("binary", "indexed_entries", "indexed_names", "partial_snapshot", "export_run")}))
        else:
            print("\n".join(bounded(lookup(args.database, args.binary, args.symbol, args.rva, args.contains, args.limit, args.va), args.max_lines)))
        return 0
    except (OSError, ValueError, KeyError, sqlite3.Error) as error:
        print("EVIDENCE INDEX ERROR: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
