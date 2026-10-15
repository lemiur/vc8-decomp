"""Map public functions to *evidenced* PDB modules, without inventing sources.

python tools/unitmap.py --binary cl [--symbols FILE] [--assert-refs FILE]

Writes build/evidence/<binary>.units.json in the current checkout. The default
symbols input is the primary checkout's build/evidence/<binary>.symbols.json.
--lane filters the JSON artifact to one configured provisional object lane and
writes <binary>.<lane>.units.json; stdout always remains a bounded summary.
Optional assert references use {"references": [{"function_rva": int,
"file": str, "line": int | null, "evidence": object}]}. A reference must name
an exact public function start; callers must independently prove that boundary.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import sys


class EvidenceError(ValueError):
    """Evidence is malformed or cannot safely support the requested map."""


def integer(value, label):
    if isinstance(value, bool):
        raise EvidenceError(f"{label} must be an integer")
    try:
        result = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        raise EvidenceError(f"{label} must be an integer") from None
    if result < 0 or isinstance(value, float):
        raise EvidenceError(f"{label} must be a nonnegative integer")
    return result


def module_key(module):
    return integer(module.get("index", module.get("module_index")), "module index")


def location(record, sections=None):
    """Preserve section offsets when RVA evidence is unavailable."""
    if record.get("rva") is not None:
        return ("rva", integer(record["rva"], "rva"))
    section = record.get("section_index", record.get("section"))
    offset = record.get("section_offset", record.get("offset"))
    if section is not None and offset is not None:
        section = integer(section, "section")
        offset = integer(offset, "offset")
        if sections and section in sections:
            return ("rva", sections[section] + offset)
        return ("section", section, offset)
    return None


def is_function(symbol):
    return symbol.get("is_function") is True or symbol.get("kind") in ("function", "procedure")


def build_map(symbols, binary, assert_refs=None):
    if symbols.get("binary") not in (None, binary):
        raise EvidenceError("symbols binary does not match requested binary")
    sections = {integer(s["index"], "section index"): integer(s["rva"], "section rva") for s in symbols.get("sections", [])}
    raw_modules = symbols.get("modules", [])
    modules = {}
    for raw in raw_modules:
        key = module_key(raw)
        if key in modules:
            raise EvidenceError(f"duplicate module index {key}")
        name = raw.get("module_name", raw.get("name"))
        container = raw.get("object_name", raw.get("object_file", raw.get("object_file_name")))
        suffix = (name or container or "").lower()
        object_name = name if name and name.lower().endswith(".obj") else container if container and container.lower().endswith(".obj") else None
        category = "object" if suffix.endswith(".obj") else "import_module" if suffix.endswith(".dll") else "resource" if suffix.endswith(".res") else "synthetic_or_unknown"
        modules[key] = {
            "module_index": key,
            "module_name": name, "object_name": object_name, "container_file": container,
            "category": category, "source_name": None,
            "source_files": sorted(set(raw.get("source_files", []))),
            "function_rvas": [],
            "attributed_public_functions": 0,
            "ownership_status": "inventory_only",
        }

    # Each entry carries its source of attribution. No object basename inference.
    starts = {}
    contributions = []
    module_records = list(symbols.get("module_symbols", []))
    for raw in raw_modules:
        key = module_key(raw)
        module_records.extend(dict(record, module_index=key) for record in raw.get("symbol_records", []))
        contributions.extend(dict(record, module_index=key) for record in raw.get("section_contributions", []))
    contributions.extend(symbols.get("section_contributions", []))
    for record in module_records:
        if not is_function(record):
            continue
        key = module_key(record)
        if key not in modules:
            raise EvidenceError(f"module symbol refers to missing module {key}")
        loc = location(record, sections)
        if loc is not None:
            starts.setdefault(loc, []).append((key, record))
    ranges = []
    for record in contributions:
        key = module_key(record)
        if key not in modules:
            raise EvidenceError(f"contribution refers to missing module {key}")
        loc = location(record, sections)
        size = integer(record.get("size", record.get("length")), "contribution size")
        if loc is not None and size:
            ranges.append((loc, size, key, record))
    range_index = {}
    for loc, size, key, record in ranges:
        range_index.setdefault(loc[:-1], []).append((loc[-1], loc[-1] + size, key))
    for prefix, entries in range_index.items():
        entries.sort()
        maximum = 0
        ends = []
        for start, end, key in entries:
            maximum = max(maximum, end)
            ends.append(maximum)
        range_index[prefix] = (entries, [e[0] for e in entries], ends)

    public_functions = symbols.get("functions")
    if public_functions is None:
        public_functions = [s for s in symbols.get("publics", []) if is_function(s)]
    references = {}
    known_rvas = {integer(s["rva"], "rva") for s in public_functions if s.get("rva") is not None}
    for ref in (assert_refs or {}).get("references", []):
        rva = integer(ref.get("function_rva"), "assert reference function_rva")
        if rva not in known_rvas:
            raise EvidenceError(f"assert reference 0x{rva:x} is not an exact public function start")
        if not isinstance(ref.get("file"), str) or not ref["file"] or not ref.get("evidence"):
            raise EvidenceError("assert references require a file and nonempty evidence")
        if ref.get("line") is not None:
            integer(ref["line"], "assert line")
        references.setdefault(rva, []).append(ref)

    functions = []
    for symbol in public_functions:
        loc = location(symbol, sections)
        direct = starts.get(loc, []) if loc else []
        covered = []
        if loc and loc[:-1] in range_index:
            entries, starts_index, maximum_ends = range_index[loc[:-1]]
            pos = bisect_right(starts_index, loc[-1]) - 1
            while pos >= 0 and maximum_ends[pos] > loc[-1]:
                start, end, key = entries[pos]
                if end > loc[-1]:
                    covered.append((key, None))
                pos -= 1
        direct_keys = {key for key, _ in direct}
        covered_keys = {key for key, _ in covered}
        conflict = bool(direct_keys and covered_keys and not direct_keys.issubset(covered_keys))
        candidates = direct_keys | covered_keys if conflict else direct_keys or covered_keys
        owner = next(iter(candidates)) if len(candidates) == 1 and not conflict else None
        evidence = []
        if direct:
            evidence.append({"kind": "module_procedure_record", "module_indices": sorted(direct_keys)})
        if covered:
            evidence.append({"kind": "section_contribution", "module_indices": sorted(covered_keys), "scope": "function_start_only"})
        rva = integer(symbol["rva"], "rva") if symbol.get("rva") is not None else None
        source_refs = references.get(rva, [])
        function = {
            "name": symbol.get("name"), "rva": rva,
            "va": symbol.get("va"), "size": symbol.get("size"),
            "section": symbol.get("section_index", symbol.get("section")), "offset": symbol.get("section_offset", symbol.get("offset")),
            "boundary_status": symbol.get("boundary_status", "unverified"),
            "boundary_provenance": symbol.get("boundary_provenance"),
            "module_index": owner, "candidate_modules": sorted(candidates),
            "module_confidence": "direct" if owner is not None and direct else "contribution" if owner is not None else "unresolved",
            "module_status": "conflicting_evidence" if conflict else "ambiguous" if len(candidates) > 1 else "attributed" if owner is not None else "unresolved",
            "module_evidence": evidence,
            "source_status": "qualified_assert_reference" if source_refs else "unresolved",
            "source_references": source_refs,
            "source_owner": None,
        }
        functions.append(function)
        if owner is not None:
            modules[owner]["attributed_public_functions"] += 1
            if rva is not None:
                modules[owner]["function_rvas"].append(rva)
            modules[owner]["ownership_status"] = "object_attribution_only"
    for module in modules.values():
        module["function_rvas"] = sorted(set(module["function_rvas"]))
        module["unique_public_function_starts"] = len(module["function_rvas"])
    functions.sort(key=lambda f: (f["rva"] is None, f["rva"] or 0, f["name"] or ""))
    unresolved = sum(f["module_index"] is None for f in functions)
    return {
        "schema_version": 1, "binary": binary, "identity": symbols.get("identity"),
        "limitations": [
            "Public functions are an incomplete census; file-static functions may be absent.",
            "An object attribution does not prove the original translation unit after LTCG.",
            "Section contributions establish ownership of the symbol start, not an independently verified function extent.",
            "Assert file references can originate in macros or inlined code; source_owner remains unresolved.",
            "DBI inventory, public names, and address proximity never establish function ownership.",
        ],
        "statistics": {
            "modules": len(modules), "public_function_symbols": len(functions),
            "unique_public_function_starts": len({location(s, sections) for s in public_functions if location(s, sections) is not None}),
            "module_attributed_symbols": len(functions) - unresolved,
            "module_unresolved_symbols": unresolved,
            "qualified_assert_symbols": sum(bool(f["source_references"]) for f in functions),
            "proven_source_owners": 0,
            "nonempty_object_modules": sum(m["category"] == "object" and m["attributed_public_functions"] > 0 for m in modules.values()),
            "import_module_symbols": sum(m["attributed_public_functions"] for m in modules.values() if m["category"] == "import_module"),
        },
        "modules": [modules[key] for key in sorted(modules)], "functions": functions,
    }


def apply_lanes(mapped, configuration):
    """Resolve configured object groups without claiming a source filename."""
    binary_config = configuration.get("binaries", {}).get(mapped["binary"], {})
    expected_hash = binary_config.get("binary_sha256")
    actual_hash = (mapped.get("identity") or {}).get("binary_sha256")
    if expected_hash and actual_hash != expected_hash:
        raise EvidenceError("lane configuration binary SHA-256 does not match symbols identity")
    modules = {m["module_index"]: m for m in mapped["modules"]}
    used = set()
    lanes = []
    for lane in binary_config.get("object_lanes", []):
        indices = [integer(i, "lane module index") for i in lane["module_indices"]]
        if len(indices) != len(set(indices)) or used.intersection(indices):
            raise EvidenceError("configured lanes overlap module ownership")
        for index in indices:
            if index not in modules or modules[index]["category"] != "object":
                raise EvidenceError(f"lane module {index} is not an evidenced object module")
        used.update(indices)
        selected = [f for f in mapped["functions"] if f["module_index"] in indices]
        # Same-start aliases must not create distinct owners in parallel lanes.
        selected_locations = {(f["section"], f["offset"], f["rva"]) for f in selected}
        if any((f["section"], f["offset"], f["rva"]) in selected_locations and f["module_index"] not in indices for f in mapped["functions"]):
            raise EvidenceError("same-start aliases cross configured lane boundary")
        lanes.append({
            "id": lane["id"], "module_indices": indices,
            "module_names": [modules[i]["module_name"] for i in indices],
            "public_function_symbols": len(selected),
            "unique_public_function_starts": len(selected_locations),
            "function_names": [f["name"] for f in selected],
            "function_rvas": sorted({f["rva"] for f in selected if f["rva"] is not None}),
            "source_name": None, "status": "provisional_object_lane",
        })
    mapped["object_lanes"] = lanes


def source_path_inventory(identity, sections):
    """Inventory literal paths only; never label them function/source owners."""
    if not identity or not identity.get("binary_path") or not identity.get("binary_sha256"):
        raise EvidenceError("source string inventory requires a pinned binary path and SHA-256")
    try:
        payload = Path(identity["binary_path"]).read_bytes()
    except OSError as exc:
        raise EvidenceError(f"cannot read source inventory binary: {exc}") from exc
    digest = hashlib.sha256(payload).hexdigest()
    if digest != identity["binary_sha256"]:
        raise EvidenceError("source inventory binary SHA-256 mismatch")
    path_pattern = re.compile(r"[A-Za-z]:[\\/][ -~]*\.(?:cpp|cxx|cc|c|hpp|hxx|hh|h|inl|asm|inc|y|yy|yxx|l)$", re.IGNORECASE)
    findings = []
    for encoding, pattern, width in (("ascii", rb"[\x20-\x7e]{4,}", 1), ("utf-16le", rb"(?:[\x20-\x7e]\x00){4,}", 2)):
        for match in re.finditer(pattern, payload):
            text_value = match[0].decode(encoding)
            path_match = path_pattern.search(text_value)
            if not path_match:
                continue
            offset = match.start() + path_match.start() * width
            rva = None
            for section in sections:
                raw = integer(section["raw_offset"], "section raw offset")
                size = integer(section["raw_size"], "section raw size")
                if raw <= offset < raw + size:
                    rva = integer(section["rva"], "section rva") + offset - raw
                    break
            findings.append({"path": path_match[0], "encoding": encoding, "file_offset": offset, "rva": rva,
                             "evidence": "literal embedded source path; no code reference or ownership inferred"})
    findings.sort(key=lambda f: (f["file_offset"], f["encoding"]))
    return {"binary_sha256": digest, "unique_paths": len({f["path"].casefold() for f in findings}),
            "occurrences": len(findings), "paths": findings,
            "limitation": "ASCII absolute paths with C/C++/header/inline/assembly/grammar extensions only; bare names excluded; absence is not evidence of no source file."}


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1] / "config/project.json")
    parser.add_argument("--symbols", type=Path)
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config/units.json")
    parser.add_argument("--assert-refs", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--lane", help="write the exact function records for one configured object lane")
    parser.add_argument("--source-strings", action="store_true", help="inventory embedded source paths in the SHA-256-verified binary")
    args = parser.parse_args(argv)
    try:
        project = read_json(args.project)
        if args.binary not in project["binaries"]:
            raise EvidenceError(f"unknown binary {args.binary}")
        source = args.symbols or Path(project["primary_checkout"]) / f"build/evidence/{args.binary}.symbols.json"
        stem = args.binary + (f".{args.lane}" if args.lane else "")
        output = args.output or args.project.resolve().parents[1] / f"build/evidence/{stem}.units.json"
        symbols = read_json(source)
        mapped = build_map(symbols, args.binary, read_json(args.assert_refs) if args.assert_refs else None)
        if args.source_strings:
            mapped["embedded_source_paths"] = source_path_inventory(symbols.get("identity"), symbols.get("sections", []))
            mapped["statistics"]["embedded_unique_source_paths"] = mapped["embedded_source_paths"]["unique_paths"]
        apply_lanes(mapped, read_json(args.config))
        lane = None
        if args.lane:
            lane = next((l for l in mapped["object_lanes"] if l["id"] == args.lane), None)
            if lane is None:
                raise EvidenceError(f"unknown lane {args.lane}")
        mapped["input"] = {"path": str(source.resolve()), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
        if args.assert_refs:
            mapped["assert_input"] = {"path": str(args.assert_refs.resolve()), "sha256": hashlib.sha256(args.assert_refs.read_bytes()).hexdigest()}
        if lane:
            mapped["input_statistics"] = mapped.pop("statistics")
            mapped["selection"] = lane
            mapped["modules"] = [m for m in mapped["modules"] if m["module_index"] in lane["module_indices"]]
            mapped["functions"] = [f for f in mapped["functions"] if f["module_index"] in lane["module_indices"]]
            mapped["object_lanes"] = [lane]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(mapped, indent=2) + "\n", encoding="utf-8")
        if lane:
            print(json.dumps({"output": str(output), "lane": lane["id"], "public_function_symbols": lane["public_function_symbols"], "unique_public_function_starts": lane["unique_public_function_starts"]}, sort_keys=True))
        else:
            print(json.dumps({"output": str(output), **mapped["statistics"]}, sort_keys=True))
        return 0
    except (EvidenceError, KeyError, TypeError) as exc:
        print(f"unitmap: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
