"""Extract evidence-backed VC8 public symbols without external PDB tools.

Usage: python tools/symbols.py --binary cl [--output-dir build/evidence]
       python tools/symbols.py --all

Outputs schema-v1 JSON plus function/data/module TSVs. S_PUB32 records prove
names and starts, not signatures or function lengths. A next-public address is
only an upper bound; aliases remain separate rows. DBI section contributions
identify object modules, which need not be original source units after LTCG.
Exact-start old-FPO procedure lengths are retained only without contradictory
overlaps or interior public starts; NewFPO frame-state ranges remain nonexact.
No symbol map is emitted when PE/PDB identity validation fails.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling tools when loaded by path
from matchlib import checkout_paths

class SymbolError(ValueError):
    """Malformed, unsupported, or mismatched input evidence."""


def require(condition, message):
    if not condition:
        raise SymbolError(message)


def unpack(fmt, data, offset=0):
    size = struct.calcsize(fmt)
    require(0 <= offset <= len(data) - size, "truncated structure")
    return struct.unpack_from(fmt, data, offset)


def cstring(data, offset, end=None):
    end = len(data) if end is None else end
    require(0 <= offset < end <= len(data), "invalid string range")
    stop = data.find(b"\0", offset, end)
    require(stop >= 0, "unterminated string")
    # Latin-1 is lossless for the byte spellings in these era PDBs.
    return data[offset:stop].decode("latin-1"), stop + 1


def digest(data):
    return hashlib.sha256(data).hexdigest()


def guid_string(raw):
    return uuid.UUID(bytes_le=raw).hex.upper()


class MSF:
    """Strict MSF 7 stream directory reader (Microsoft public PDB format)."""

    def __init__(self, data):
        require(data[:32] == b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", "not an MSF 7 PDB")
        self.data = data
        self.block_size, _, self.block_count, directory_size, reserved, block_map = unpack("<6I", data, 32)
        require(self.block_size in (512, 1024, 2048, 4096), "unsupported MSF block size")
        require(self.block_count * self.block_size == len(data), "MSF file size disagrees with superblock")
        require(reserved == 0, "nonzero MSF reserved field")
        directory_count = (directory_size + self.block_size - 1) // self.block_size
        require(directory_count * 4 <= self.block_size, "multi-block MSF directory map unsupported")
        directory_blocks = unpack("<" + "I" * directory_count, self.block(block_map))
        directory = b"".join(self.block(n) for n in directory_blocks)[:directory_size]
        count, = unpack("<I", directory)
        require(count <= (len(directory) - 4) // 4, "invalid MSF stream count")
        sizes = unpack("<" + "I" * count, directory, 4)
        cursor = 4 + count * 4
        self.streams = []
        for size in sizes:
            if size == 0xFFFFFFFF:
                self.streams.append(None)
                continue
            require(size <= len(data), "invalid MSF stream size")
            pages = (size + self.block_size - 1) // self.block_size
            blocks = unpack("<" + "I" * pages, directory, cursor)
            cursor += pages * 4
            self.streams.append((size, blocks))
        require(cursor == len(directory), "unexplained MSF directory bytes")

    def block(self, number):
        require(0 <= number < self.block_count, "MSF block outside file")
        start = number * self.block_size
        return self.data[start:start + self.block_size]

    def stream(self, number):
        require(0 <= number < len(self.streams), "PDB stream index outside directory")
        item = self.streams[number]
        require(item is not None, "required PDB stream is absent")
        size, blocks = item
        return b"".join(self.block(n) for n in blocks)[:size]


def read_pe(data):
    require(data[:2] == b"MZ", "not a PE image")
    pe, = unpack("<I", data, 0x3C)
    require(data[pe:pe + 4] == b"PE\0\0", "invalid PE signature")
    machine, count, timestamp, _, _, opt_size, _ = unpack("<HHIIIHH", data, pe + 4)
    opt = pe + 24
    magic, = unpack("<H", data, opt)
    require(magic == 0x10B and machine == 0x14C, "expected x86 PE32")
    require(opt_size >= 152, "PE optional header lacks debug directory")
    image_base, = unpack("<I", data, opt + 28)
    directory_count, = unpack("<I", data, opt + 92)
    require(directory_count > 6, "PE debug directory missing")
    debug_rva, debug_size = unpack("<II", data, opt + 96 + 6 * 8)
    sections = []
    for index in range(count):
        at = opt + opt_size + index * 40
        name, virtual_size, rva, raw_size, raw_offset = unpack("<8sIIII", data, at)
        characteristics, = unpack("<I", data, at + 36)
        require(raw_offset + raw_size <= len(data), "PE section outside file")
        sections.append(dict(index=index + 1, name=name.rstrip(b"\0").decode("latin-1"), rva=rva,
                             virtual_size=virtual_size, raw_size=raw_size, raw_offset=raw_offset,
                             characteristics=characteristics))

    def file_offset(rva, size):
        matches = [s for s in sections if s["rva"] <= rva and rva + size <= s["rva"] + s["raw_size"]]
        require(len(matches) == 1, "PE RVA not uniquely backed by file bytes")
        s = matches[0]
        return s["raw_offset"] + rva - s["rva"]

    require(debug_size and debug_size % 28 == 0, "invalid PE debug directory size")
    debug_offset = file_offset(debug_rva, debug_size)
    identities = []
    for at in range(debug_offset, debug_offset + debug_size, 28):
        _, _, _, _, kind, size, address, pointer = unpack("<IIHHIIII", data, at)
        if kind != 2:
            continue
        require(size >= 25 and pointer + size <= len(data), "invalid CodeView record extent")
        require(file_offset(address, size) == pointer, "CodeView RVA/file pointer disagree")
        record = data[pointer:pointer + size]
        require(record[:4] == b"RSDS", "expected RSDS CodeView identity")
        age, = unpack("<I", record, 20)
        path, _ = cstring(record, 24)
        identities.append(dict(guid=guid_string(record[4:20]), age=age, path=path))
    require(len(identities) == 1, "expected exactly one RSDS identity")
    return dict(image_base=image_base, timestamp=timestamp, machine=machine, sections=sections, rsds=identities[0])


def read_dbi(data):
    require(len(data) >= 64, "truncated DBI header")
    signature, version, age = unpack("<iII", data)
    require(signature == -1 and version == 19990903, "unsupported DBI version")
    symbol_stream, = unpack("<H", data, 20)
    sizes = unpack("<5i", data, 24)
    optional_size, ec_size = unpack("<ii", data, 48)
    require(all(size >= 0 for size in sizes + (optional_size, ec_size)), "negative DBI substream size")
    require(64 + sum(sizes) + optional_size + ec_size <= len(data), "DBI substreams exceed stream")
    module_size, contribution_size = sizes[:2]
    modules = []
    cursor, end = 64, 64 + module_size
    while cursor < end:
        require(cursor + 64 <= end, "truncated DBI module record")
        stream, = unpack("<H", data, cursor + 34)
        symbol_bytes, c11_bytes, c13_bytes = unpack("<III", data, cursor + 36)
        file_count, = unpack("<H", data, cursor + 48)
        name, next_at = cstring(data, cursor + 64, end)
        object_file, next_at = cstring(data, next_at, end)
        modules.append(dict(index=len(modules), name=name, object_file=object_file,
                            stream=None if stream == 0xFFFF else stream, symbol_bytes=symbol_bytes,
                            c11_bytes=c11_bytes, c13_bytes=c13_bytes, source_file_count=file_count))
        cursor = (next_at + 3) & ~3
    require(cursor == end, "misaligned DBI module records")
    contributions = []
    if contribution_size:
        cursor = end
        contribution_version, = unpack("<I", data, cursor)
        require(contribution_version in (0xF12EBA2D, 0xF13151E4), "unsupported DBI section contribution version")
        stride = 28 if contribution_version == 0xF12EBA2D else 32
        require((contribution_size - 4) % stride == 0, "misaligned DBI section contributions")
        for at in range(cursor + 4, cursor + contribution_size, stride):
            section, _, offset, size, characteristics, module = unpack("<HHIIIH", data, at)
            require(module < len(modules), "DBI contribution module index out of range")
            contributions.append(dict(section=section, offset=offset, size=size,
                                      characteristics=characteristics, module_index=module))
    return dict(age=age, symbol_stream=symbol_stream, modules=modules, contributions=contributions)


def read_frame_ranges(msf, dbi_data):
    """Read DBI FPO debug streams; NewFPO describes frame states, not bodies."""
    sizes = unpack("<5i", dbi_data, 24)
    optional_size, ec_size = unpack("<ii", dbi_data, 48)
    require(optional_size % 2 == 0, "odd DBI optional debug header size")
    start = 64 + sum(sizes) + ec_size
    indices = unpack("<" + "H" * (optional_size // 2), dbi_data, start)
    result = dict(fpo=[], new_fpo=[], debug_streams={}, optional_debug_stream_indices=list(indices))
    for kind, stride, key in ((0, 16, "fpo"), (9, 32, "new_fpo")):
        if kind >= len(indices) or indices[kind] == 0xFFFF:
            continue
        stream_index = indices[kind]
        data = msf.stream(stream_index)
        require(len(data) % stride == 0, "misaligned " + key + " stream")
        result["debug_streams"][key] = dict(stream_index=stream_index, size=len(data))
        for at in range(0, len(data), stride):
            rva, size = unpack("<II", data, at)
            row = dict(rva=rva, size=size, stream_index=stream_index, record_offset=at)
            if kind == 0:
                locals_words, params_words, bits = unpack("<IHH", data, at + 8)
                row.update(locals_words=locals_words, params_words=params_words,
                           prolog_size=bits & 0xFF, saved_register_count=(bits >> 8) & 7,
                           has_seh=bool(bits & 0x800), uses_bp=bool(bits & 0x1000), frame_type=bits >> 14,
                           provenance="DBI FPO_DATA.cbProcSize")
            else:
                local_size, param_size, max_stack_size, frame_func, prolog_size, saved_regs_size, flags = unpack("<IIIIHHI", data, at + 8)
                row.update(local_size=local_size, param_size=param_size, max_stack_size=max_stack_size,
                           frame_func=frame_func, prolog_size=prolog_size, saved_regs_size=saved_regs_size,
                           flags=flags, provenance="DBI NewFPO frame-state range (not function extent)")
            result[key].append(row)
    return result


def validate_address_mapping(msf, frames, sections):
    """Reject OMAP; verify PDB/PE section identities without assuming resources stayed unchanged."""
    indices = frames["optional_debug_stream_indices"]
    for kind in (3, 4):
        require(kind >= len(indices) or indices[kind] == 0xFFFF or not msf.stream(indices[kind]),
                "PDB OMAP address translation is unsupported")
    if len(indices) <= 5 or indices[5] == 0xFFFF:
        return dict(status="section-header-stream-absent", omap_present=False)
    data = msf.stream(indices[5])
    require(len(data) == len(sections) * 40, "PDB/PE section counts disagree")
    pdb_sections = []
    for index, section in enumerate(sections):
        name, virtual_size, rva, raw_size, raw_offset = unpack("<8sIIII", data, index * 40)
        name = name.rstrip(b"\0").decode("latin-1")
        require(name == section["name"] and rva == section["rva"], "PDB/PE section address mappings disagree")
        pdb_sections.append(dict(index=index + 1, name=name, rva=rva, virtual_size=virtual_size,
                                 raw_size=raw_size, raw_offset=raw_offset))
    return dict(status="PDB/PE-section-names-and-RVAs-agree", omap_present=False,
                section_header_stream=indices[5], pdb_sections=pdb_sections,
                note="Section size differences are retained; postlink resources may differ.")


def apply_fpo_boundaries(functions, sections, frames):
    """Admit an old-FPO extent only with no contradictory boundary evidence."""
    by_rva = {}
    for frame in frames["fpo"]:
        by_rva.setdefault(frame["rva"], []).append(frame)
    starts = sorted({row["rva"] for row in functions})
    section_by_index = {s["index"]: s for s in sections}
    distinct_ranges = sorted({(r["rva"], r["rva"] + r["size"]) for r in frames["fpo"] if r["size"]})
    for row in functions:
        records = by_rva.get(row["rva"], [])
        row["fpo_records"] = [dict(stream_index=r["stream_index"], record_offset=r["record_offset"],
                                   rva=r["rva"], size=r["size"]) for r in records]
        row["size_provenance"] = None
        if not records:
            continue
        sizes = {r["size"] for r in records}
        reason = None
        if len(sizes) != 1 or 0 in sizes:
            reason = "conflicting-or-zero-FPO-sizes"
        else:
            size = next(iter(sizes))
            start, end = row["rva"], row["rva"] + size
            section = section_by_index[row["section_index"]]
            if not section["characteristics"] & 0x20000000:
                reason = "FPO-range-not-executable"
            elif end > section["rva"] + min(section["raw_size"], section["virtual_size"]):
                reason = "FPO-range-outside-section-file-bytes"
            elif any(start < other < end for other in starts):
                reason = "interior-public-function-start"
            elif any(other_start < end and start < other_end and (start, end) != (other_start, other_end)
                     for other_start, other_end in distinct_ranges):
                reason = "overlapping-distinct-FPO-ranges"
            else:
                row.update(size=size, boundary_status="pdb-fpo-procedure-size",
                           boundary_provenance="PDB FPO_DATA.cbProcSize at exact public start; no padding added",
                           size_provenance="PDB FPO_DATA.cbProcSize")
        if reason:
            row["boundary_status"] = "public-start-only-FPO-conflict"
            row["fpo_boundary_rejection"] = reason


def read_publics(data):
    result = []
    cursor = 0
    while cursor < len(data):
        length, kind = unpack("<HH", data, cursor)
        require(length >= 2 and cursor + length + 2 <= len(data), "invalid CodeView symbol record length")
        end = cursor + length + 2
        if kind == 0x110E:  # S_PUB32
            require(length >= 13, "truncated S_PUB32")
            flags, offset, segment = unpack("<IIH", data, cursor + 4)
            name, _ = cstring(data, cursor + 14, end)
            result.append(dict(name=name, offset=offset, segment=segment, flags=flags,
                               symbol_record_offset=cursor, symbol_record_kind="S_PUB32"))
        cursor = end
    return result


def extract(binary_path, pdb_path):
    binary_path, pdb_path = Path(binary_path), Path(pdb_path)
    binary_data, pdb_data = binary_path.read_bytes(), pdb_path.read_bytes()
    pe = read_pe(binary_data)
    msf = MSF(pdb_data)
    info = msf.stream(1)
    version, signature, age = unpack("<III", info)
    require(version == 20000404 and len(info) >= 28, "unsupported PDB info version")
    info_guid = guid_string(info[12:28])
    dbi_data = msf.stream(3)
    dbi = read_dbi(dbi_data)
    frames = read_frame_ranges(msf, dbi_data)
    address_mapping = validate_address_mapping(msf, frames, pe["sections"])
    rsds = pe["rsds"]
    require(info_guid == rsds["guid"], "PDB GUID disagrees with binary RSDS")
    require(dbi["age"] == rsds["age"], "PDB DBI age disagrees with binary RSDS")
    require(age in (rsds["age"], rsds["age"] + 1), "PDB info age is neither binary age nor stripped-public age +1")
    require(pdb_path.name.lower() == rsds["path"].replace("\\", "/").split("/")[-1].lower(), "PDB filename disagrees with RSDS")
    rows = read_publics(msf.stream(dbi["symbol_stream"]))
    sections = {s["index"]: s for s in pe["sections"]}
    functions, data, unresolved = [], [], []
    for public in rows:
        section = sections.get(public["segment"])
        row = dict(name=public["name"], rva=None, va=None, section=None,
                   section_index=public["segment"], section_offset=public["offset"], size=None,
                   boundary_status="public-start-only", boundary_provenance="PDB S_PUB32 (no length)",
                   module=None, module_index=None, module_evidence="unknown", module_candidates=[],
                   next_public_rva=None, public_flags=public["flags"],
                   symbol_record_offset=public["symbol_record_offset"], symbol_record_kind="S_PUB32")
        if section is None or public["offset"] >= max(section["virtual_size"], section["raw_size"]):
            row["boundary_status"] = "unresolved-section"
            unresolved.append(row)
            continue
        row.update(rva=section["rva"] + public["offset"], section=section["name"])
        row["va"] = pe["image_base"] + row["rva"]
        candidates = sorted({c["module_index"] for c in dbi["contributions"]
                             if c["section"] == public["segment"] and c["offset"] <= public["offset"] < c["offset"] + c["size"]})
        row["module_candidates"] = candidates
        if len(candidates) == 1:
            module = dbi["modules"][candidates[0]]
            row.update(module=module["name"], module_index=module["index"],
                       module_evidence="DBI section contribution contains public start")
        elif candidates:
            row["module_evidence"] = "ambiguous DBI section contributions"
        (functions if public["flags"] & 2 else data).append(row)
    for group in (functions, data, unresolved):
        group.sort(key=lambda r: (r["rva"] if r["rva"] is not None else 0xFFFFFFFF, r["name"]))
    apply_fpo_boundaries(functions, pe["sections"], frames)
    # Upper bounds include all distinct publics, including data labels in code.
    for section in sections.values():
        same_section = [r for r in functions + data if r["section_index"] == section["index"]]
        addresses = sorted({r["rva"] for r in same_section})
        following = dict(zip(addresses, addresses[1:]))
        for row in same_section:
            row["next_public_rva"] = following.get(row["rva"])
    return dict(schema_version=1, binary=binary_path.stem,
                identity=dict(binary_path=str(binary_path.resolve()), binary_sha256=digest(binary_data),
                              pdb_path=str(pdb_path.resolve()), pdb_sha256=digest(pdb_data),
                              image_base=pe["image_base"], timestamp=pe["timestamp"], rsds=rsds,
                              pdb_info=dict(version=version, signature=signature, guid=info_guid, age=age),
                              dbi_age=dbi["age"], verified=True,
                              address_mapping=address_mapping,
                              age_verdict="exact" if age == rsds["age"] else "stripped-public-info-age-plus-one"),
                limitations=["Public names do not prove signatures or calling conventions.",
                             "Public starts and next_public_rva do not prove function lengths.",
                             "DBI modules are object attribution, not guaranteed source-file ownership.",
                             "Public-symbol totals are not a complete function or byte denominator."],
                sections=pe["sections"], modules=dbi["modules"], section_contributions=dbi["contributions"],
                frame_ranges=frames,
                functions=functions, data=data, unresolved=unresolved,
                summary=dict(functions=len(functions), data=len(data), unresolved=len(unresolved),
                             modules=len(dbi["modules"]), contributions=len(dbi["contributions"]),
                             functions_with_module=sum(r["module"] is not None for r in functions),
                             functions_with_fpo_size=sum(r["size"] is not None for r in functions),
                             unique_functions_with_fpo_size=len({r["rva"] for r in functions if r["size"] is not None})))


TSV_FIELDS = ("name", "rva", "va", "section", "section_index", "section_offset", "size", "boundary_status",
              "boundary_provenance", "next_public_rva", "module", "module_index", "module_evidence", "public_flags",
              "symbol_record_offset", "size_provenance")


def write_map(result, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stem = result["binary"]
    (directory / (stem + ".symbols.json")).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for kind in ("functions", "data", "modules"):
        fields = TSV_FIELDS if kind != "modules" else ("index", "name", "object_file", "stream", "symbol_bytes", "source_file_count")
        with (directory / (stem + "." + kind + ".tsv")).open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fields, delimiter="\t", extrasaction="ignore", lineterminator="\n")
            writer.writeheader()
            writer.writerows(result[kind])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--binary")
    choice.add_argument("--all", action="store_true")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config/project.json")
    parser.add_argument("--pdb", type=Path, help="explicit PDB (one binary only)")
    parser.add_argument("--binary-path", type=Path, help="explicit installed binary (one binary only)")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        project = json.loads(args.config.read_text(encoding="utf-8"))
        names = list(project["binaries"]) if args.all else [args.binary]
        require(not args.all or not (args.pdb or args.binary_path), "explicit input paths require --binary")
        primary, symbols_root = checkout_paths(project, args.config.resolve().parents[1])
        output = args.output_dir or primary / "build/evidence"
        for name in names:
            require(name in project["binaries"], "unknown configured binary: " + name)
            filename = project["binaries"][name]["filename"]
            binary = args.binary_path or Path(project["toolchain_root"]) / "bin" / filename
            pe = read_pe(binary.read_bytes())
            rsds = pe["rsds"]
            pdb_name = rsds["path"].replace("\\", "/").split("/")[-1]
            pdb = args.pdb or symbols_root / pdb_name / (rsds["guid"] + format(rsds["age"], "X")) / pdb_name
            result = extract(binary, pdb)
            write_map(result, output)
            print(name + ": " + json.dumps(result["summary"], sort_keys=True) + " identity=" + result["identity"]["age_verdict"])
        return 0
    except (OSError, KeyError, json.JSONDecodeError, SymbolError) as error:
        print("symbols: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
