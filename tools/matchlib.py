"""Shared, fail-closed PE32 and reference primitives for the VC8 campaign.

No disassembly, guessed function boundaries, or relocation masking happens here.
PEImage reads candidate or retail images; Retail adds a pinned identity contract.
Addresses are preferred-image VAs. File reads reject zero-filled virtual tails.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Iterable, Mapping
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE_REL_I386_DIR32 = 6
IMAGE_REL_I386_DIR32NB = 7
IMAGE_REL_I386_REL32 = 20
IMAGE_SCN_CNT_CODE = 0x20
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80


class PEError(ValueError):
    """Malformed, unsupported, ambiguous, or non-file-backed PE input."""


class IdentityError(PEError):
    """A retail input does not meet the checked-in identity contract."""


def _number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# The project adapter: what one VC8 matching project asks of these tools. The
# "project" block of config/project.json overrides any key (dicts key by key);
# docs/match-harness.md documents each. The defaults are VC8 toolchain facts
# and the strictest policies: a pinned PDB, /GL for every unit.
ADAPTER_DEFAULTS = {
    "binaries": None,  # ordered target binaries; default: the keys of "binaries"
    "compiler": "cl.exe",
    "linker": "link.exe",
    "pdb_required": True,
    "gl": True,  # /GL + /LTCG; per binary or unit: "gl" in config/<binary>.json
    "annotation": {
        "pattern": r"^\s*//\s*(?P<kind>FUNCTION|DATA):\s+(?P<binary>[a-zA-Z0-9_]+)\s+(?P<va>0x[0-9a-fA-F]+)\s*$",
        "prefix": r"//\s*(FUNCTION|DATA):",
        "function": "FUNCTION",
    },
    "link_flags": ["/OPT:NOREF,NOICF"],
    "toolchain_pins": ["cl.exe", "c1.dll", "c1xx.dll", "c2.dll", "link.exe", "cvtres.exe",
                       "mspdb80.dll", "mspdbcore.dll", "mspdbsrv.exe", "msobj80.dll", "pgodb80.dll",
                       "pgort80.dll", "pgort80ui.dll", "msvcr80.dll", "msvcp80.dll",
                       "clui.dll", "linkui.dll", "dumpbin.exe", "lib.exe", "undname.exe",
                       "cl.exe.config", "link.exe.config", "Microsoft.VC80.CRT.manifest"],
    "toolchain_core": ["cl.exe", "c1.dll", "c1xx.dll", "c2.dll", "link.exe"],
    "rtm": {"iso": None, "out": "ref-rtm", "seven_zip": "7z", "platform_sdk": None},
}


def primary_checkout(root):
    """The checkout holding the ignored shared inputs: for a git worktree, its main one."""
    root = Path(root).resolve()
    marker = root / ".git"
    if marker.is_file():
        text = marker.read_text(encoding="utf-8").strip()
        if text.startswith("gitdir:"):
            gitdir = (root / text[len("gitdir:"):].strip()).resolve()
            common = gitdir / "commondir"
            if common.is_file():
                return (gitdir / common.read_text(encoding="utf-8").strip()).resolve().parent
    return root


def checkout_paths(project, root):
    """Primary checkout and symbol store: explicit keys, else derived from the checkout."""
    root = Path(root).resolve()
    primary = (root / project["primary_checkout"]).resolve() if "primary_checkout" in project else primary_checkout(root)
    symbols = (primary / project.get("symbols_root", "symbols")).resolve()
    return primary, symbols


def adapter_of(project):
    """Merge a loaded project.json's "project" block over ADAPTER_DEFAULTS."""
    result = json.loads(json.dumps(ADAPTER_DEFAULTS))
    for key, value in project.get("project", {}).items():
        if key not in result:
            raise ValueError("unknown project adapter key: " + key)
        result[key] = dict(result[key], **value) if isinstance(result[key], dict) else value
    configured = list(project.get("binaries", {}))
    if result["binaries"] is None:
        result["binaries"] = configured
    if not set(result["binaries"]) <= set(configured):
        raise ValueError("adapter names an unconfigured binary")
    pattern = re.compile(result["annotation"]["pattern"], re.M)
    if not {"binary", "va"} <= set(pattern.groupindex):
        raise ValueError("annotation pattern needs named groups binary and va")
    return result


def load_adapter(root=None):
    return adapter_of(load_project(root))


def annotation_pattern(adapter):
    return re.compile(adapter["annotation"]["pattern"], re.M)


def unit_gl(adapter, options, unit):
    """Whether a unit compiles with /GL: unit option, else binary option, else project."""
    return options.get("units", {}).get(unit, {}).get("gl", options.get("gl", adapter["gl"]))


def load_project(root=None):
    root = Path(root or ROOT).resolve()
    with (root / "config/project.json").open(encoding="utf-8") as stream:
        project = json.load(stream)
    project["root"] = str(root)
    if "toolchain_root" in project:
        project["toolchain_root"] = str((root / project["toolchain_root"]).resolve())
    primary, symbols = checkout_paths(project, root)
    project["primary_checkout"], project["symbols_root"] = str(primary), str(symbols)
    return project


def load_config(root=None):
    project = load_project(root)
    root = Path(project["root"])
    with (root / "config/retail.json").open(encoding="utf-8") as stream:
        config = json.load(stream)
    config["project"] = project
    for name, build in config["builds"].items():
        build["name"] = name
        build["path"] = str(Path(project["toolchain_root"]) / "bin" / build["filename"])
    config["binaries"] = config["builds"]
    return config


def load_binary_config(binary, root=None):
    config = load_config(root)
    if binary not in config["builds"]:
        raise ValueError("unknown binary: " + binary)
    result = dict(config["builds"][binary])
    filename = Path(config["project"]["root"]) / "config" / (binary + ".json")
    if filename.exists():
        with filename.open(encoding="utf-8") as stream:
            options = json.load(stream)
        # Identity pins cannot be replaced by per-binary compiler options.
        result["options"] = options
        result["flags"] = options.get("flags", {})
    result["project"] = config["project"]
    return result


class PEImage:
    """Strict x86 PE32 reader with explicit raw/virtual address separation."""

    def __init__(self, path):
        self.path = str(path)
        self.name = Path(path).stem
        self.data = Path(path).read_bytes()
        if self._slice(0, 2) != b"MZ":
            raise PEError("missing DOS signature")
        pe = self._u32(0x3C)
        if self._slice(pe, 4) != b"PE\0\0":
            raise PEError("missing PE signature")
        self.machine, count, self.timestamp = self._unpack("<HHI", pe + 4)
        if self.machine != 0x14C:
            raise PEError("only IMAGE_FILE_MACHINE_I386 is supported")
        optional_size = self._u16(pe + 20)
        opt = pe + 24
        self._slice(opt, optional_size)
        if optional_size < 96 or self._u16(opt) != 0x10B:
            raise PEError("only complete PE32 optional headers are supported")
        self.base = self.image_base = self._u32(opt + 28)
        self.size_of_image = self._u32(opt + 56)
        self.size_of_headers = self._u32(opt + 60)
        if not self.size_of_headers or self.size_of_headers > len(self.data):
            raise PEError("invalid SizeOfHeaders")
        directory_count = self._u32(opt + 92)
        if directory_count > 16 or 96 + directory_count * 8 > optional_size:
            raise PEError("invalid data directory count")
        self.directories = [self._unpack("<II", opt + 96 + i * 8)
                            for i in range(directory_count)]
        self.sections = []
        section_table = opt + optional_size
        if section_table + 40 * count > self.size_of_headers:
            raise PEError("section table exceeds headers")
        for i in range(count):
            at = section_table + 40 * i
            name = self._slice(at, 8).rstrip(b"\0").decode("ascii", errors="replace")
            vsize, rva, rawsize, raw = self._unpack("<IIII", at + 8)
            chars = self._u32(at + 36)
            if rawsize:
                self._slice(raw, rawsize)
                if raw < self.size_of_headers:
                    raise PEError("section raw range overlaps headers")
            extent = max(vsize, rawsize)
            if rva < self.size_of_headers or rva + extent > self.size_of_image:
                raise PEError("invalid section virtual range")
            section = dict(name=name, va=self.base + rva, rva=rva, vsize=vsize,
                           rawsize=rawsize, raw=raw, chars=chars)
            for previous in self.sections:
                if _overlap(rva, extent, previous["rva"], max(previous["vsize"], previous["rawsize"])):
                    raise PEError("overlapping section virtual ranges")
                if rawsize and previous["rawsize"] and _overlap(raw, rawsize, previous["raw"], previous["rawsize"]):
                    raise PEError("overlapping section raw ranges")
            self.sections.append(section)
        text = next((s for s in self.sections if s["name"] == ".text"), None)
        self.text_start = text["va"] if text else None
        self.text_end = text["va"] + text["vsize"] if text else None

    def _slice(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise PEError("truncated or invalid file range")
        return self.data[offset:offset + size]

    def _unpack(self, fmt, offset):
        return struct.unpack(fmt, self._slice(offset, struct.calcsize(fmt)))

    def _u16(self, offset):
        return self._unpack("<H", offset)[0]

    def _u32(self, offset):
        return self._unpack("<I", offset)[0]

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def section_of(self, va):
        for section in self.sections:
            if section["va"] <= va < section["va"] + max(section["vsize"], section["rawsize"]):
                return section
        return None

    def va_to_rva(self, va):
        rva = va - self.base
        if not 0 <= rva < self.size_of_image:
            raise PEError("VA outside image")
        return rva

    def rva_to_va(self, rva):
        if not 0 <= rva < self.size_of_image:
            raise PEError("RVA outside image")
        return self.base + rva

    def rva_to_offset(self, rva, size=1):
        if size < 0 or rva < 0:
            raise PEError("invalid RVA range")
        if rva < self.size_of_headers:
            if rva + size <= self.size_of_headers:
                return rva
            raise PEError("read crosses header boundary")
        section = self.section_of(self.base + rva)
        if section is None or rva - section["rva"] + size > section["rawsize"]:
            raise PEError("RVA range is not file-backed in one section")
        return section["raw"] + rva - section["rva"]

    def offset_of(self, va, size=1):
        return self.rva_to_offset(self.va_to_rva(va), size)

    va_to_offset = offset_of

    def offset_to_rva(self, offset, size=1):
        self._slice(offset, size)
        if offset < self.size_of_headers and offset + size <= self.size_of_headers:
            return offset
        for section in self.sections:
            if section["raw"] <= offset < section["raw"] + section["rawsize"]:
                if offset + size <= section["raw"] + section["rawsize"]:
                    return section["rva"] + offset - section["raw"]
        raise PEError("file range has no unique image mapping")

    def offset_to_va(self, offset, size=1):
        return self.base + self.offset_to_rva(offset, size)

    def read(self, va, size):
        return self._slice(self.offset_of(va, size), size)

    read_va = read

    def read_rva(self, rva, size):
        return self._slice(self.rva_to_offset(rva, size), size)

    def read_u32(self, va):
        return struct.unpack("<I", self.read(va, 4))[0]

    def cstring(self, rva, limit=4096):
        # Checking each byte prevents a string from crossing a virtual/raw boundary.
        result = bytearray()
        for i in range(limit):
            byte = self.read_rva(rva + i, 1)[0]
            if not byte:
                return result.decode("ascii", errors="strict")
            result.append(byte)
        raise PEError("unterminated string")

    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()

    def section_sha256(self, name):
        section = next((s for s in self.sections if s["name"] == name), None)
        return hashlib.sha256(self._slice(section["raw"], section["rawsize"])).hexdigest() if section else None

    def codeview_records(self):
        rva, size = self.directory(6)
        if not rva and not size:
            return []
        if not rva or size % 28:
            raise PEError("malformed debug directory")
        records = []
        for at in range(0, size, 28):
            entry = self.read_rva(rva + at, 28)
            kind, length, data_rva, raw = struct.unpack_from("<IIII", entry, 12)
            if kind != 2:
                continue
            blob = self._slice(raw, length)
            if data_rva and self.read_rva(data_rva, length) != blob:
                raise PEError("debug RVA and raw pointer disagree")
            if blob[:4] != b"RSDS" or len(blob) < 25:
                raise PEError("unsupported CodeView record")
            if b"\0" not in blob[24:]:
                raise PEError("unterminated PDB path")
            records.append(dict(guid=uuid.UUID(bytes_le=blob[4:20]).hex.upper(),
                                age=struct.unpack_from("<I", blob, 20)[0],
                                path=blob[24:].split(b"\0", 1)[0].decode("utf-8")))
        return records

    @property
    def pdb(self):
        records = self.codeview_records()
        if len(records) != 1:
            raise PEError("expected exactly one RSDS identity")
        return records[0]

    def _version_blobs(self):
        rva, size = self.directory(2)
        if not rva:
            return []
        def local(offset, length):
            if offset < 0 or offset + length > size:
                raise PEError("resource directory exceeds bounds")
            return self.read_rva(rva + offset, length)
        def walk(offset, depth, seen):
            if depth > 3 or offset in seen:
                raise PEError("cyclic or too-deep resource directory")
            head = local(offset, 16)
            named, numbered = struct.unpack_from("<HH", head, 12)
            entries = local(offset + 16, 8 * (named + numbered))
            blobs = []
            for i in range(named + numbered):
                identity, child = struct.unpack_from("<II", entries, i * 8)
                if depth == 0 and identity != 16:
                    continue
                if child & 0x80000000:
                    blobs.extend(walk(child & 0x7FFFFFFF, depth + 1, seen | {offset}))
                else:
                    data_rva, length = struct.unpack_from("<II", local(child, 16))
                    blobs.append(self.read_rva(data_rva, length))
            return blobs
        return walk(0, 0, set())

    @property
    def version(self):
        versions = set()
        for blob in self._version_blobs():
            if len(blob) < 6:
                raise PEError("truncated version resource")
            total, value_length, kind = struct.unpack_from("<HHH", blob)
            key = "VS_VERSION_INFO\0".encode("utf-16-le")
            if total > len(blob) or blob[6:6 + len(key)] != key:
                raise PEError("invalid root version resource")
            at = (6 + len(key) + 3) & ~3
            if value_length < 52 or at + value_length > total:
                raise PEError("missing fixed file version")
            signature, structure, ms, ls = struct.unpack_from("<IIII", blob, at)
            if signature != 0xFEEF04BD or structure != 0x10000 or kind != 0:
                raise PEError("invalid fixed file version")
            versions.add("%d.%d.%d.%d" % (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF))
        if len(versions) > 1:
            raise PEError("conflicting file versions")
        return next(iter(versions), None)

    def base_relocations(self):
        rva, size = self.directory(5)
        if not rva and not size:
            return []
        blob = self.read_rva(rva, size)
        result, at, sites = [], 0, set()
        while at < len(blob):
            if at + 8 > len(blob):
                raise PEError("truncated base relocation block")
            page, length = struct.unpack_from("<II", blob, at)
            if page & 0xFFF or length < 8 or length % 4 or at + length > len(blob):
                raise PEError("invalid base relocation block")
            entry_at = at + 8
            while entry_at < at + length:
                word = struct.unpack_from("<H", blob, entry_at)[0]
                entry_at += 2
                kind, offset = word >> 12, word & 0xFFF
                if kind == 0:  # ABSOLUTE padding has no referent.
                    continue
                site = page + offset
                if site in sites:
                    raise PEError("duplicate base relocation site")
                sites.add(site)
                width = {1: 2, 2: 2, 3: 4, 4: 2, 10: 8}.get(kind)
                self.rva_to_offset(site, width or 1)
                record = dict(rva=site, va=self.base + site, type=kind, width=width)
                if kind == 4:  # HIGHADJ consumes a second WORD, which is NOT a relocation.
                    if entry_at + 2 > at + length:
                        raise PEError("missing HIGHADJ adjustment word")
                    record["adjustment"] = struct.unpack_from("<h", blob, entry_at)[0]
                    entry_at += 2
                result.append(record)
            at += length
        return sorted(result, key=lambda item: item["rva"])

    @property
    def relocs(self):
        return [item["va"] for item in self.base_relocations() if item["type"] == 3]

    def import_records(self):
        rva, size = self.directory(1)
        if not rva and not size:
            return []
        result = []
        for offset in range(0, size - 19, 20):
            fields = struct.unpack("<IIIII", self.read_rva(rva + offset, 20))
            if fields == (0, 0, 0, 0, 0):
                return result
            original, _, _, name_rva, first = fields
            dll = self.cstring(name_rva)
            if not first:
                raise PEError("missing import address table")
            lookup = original or first
            for index in range(self.size_of_image // 4):
                value = struct.unpack("<I", self.read_rva(lookup + index * 4, 4))[0]
                if not value:
                    break
                name = "#%d" % (value & 0xFFFF) if value & 0x80000000 else self.cstring(value + 2)
                slot = self.rva_to_va(first + index * 4)
                self.read(slot, 4)
                result.append(dict(dll=dll, name=name, va=slot,
                                   identity=dll.lower() + "!" + name))
            else:
                raise PEError("unterminated import lookup table")
        raise PEError("unterminated import descriptor table")

    @property
    def imports(self):
        result = {}
        for record in self.import_records():
            name = record["name"]
            if name in result and result[name] != record["va"]:
                raise PEError("ambiguous unqualified import: " + name)
            result[name] = record["va"]
        return result

    def export_records(self):
        """Read EAT slots, preserving ordinal-only exports, aliases and forwarders.

        Forwarders have va=None and a forwarder string; they are not local code.
        Names are exact export spellings, not signature or ownership evidence.
        """
        rva, size = self.directory(0)
        if not rva and not size:
            return []
        if not rva or size < 40:
            raise PEError("invalid export directory")
        self.read_rva(rva, size)
        directory = self.read_rva(rva, 40)
        ordinal_base, function_count, name_count, functions_rva, names_rva, ordinals_rva = struct.unpack_from("<IIIIII", directory, 16)
        addresses = self.read_rva(functions_rva, function_count * 4) if function_count else b""
        name_table = self.read_rva(names_rva, name_count * 4) if name_count else b""
        ordinal_table = self.read_rva(ordinals_rva, name_count * 2) if name_count else b""
        names, spellings = {}, set()
        for index in range(name_count):
            ordinal_index = struct.unpack_from("<H", ordinal_table, index * 2)[0]
            if ordinal_index >= function_count:
                raise PEError("export name ordinal is outside address table")
            name = self.cstring(struct.unpack_from("<I", name_table, index * 4)[0])
            if name in spellings:
                raise PEError("duplicate export name")
            spellings.add(name)
            names.setdefault(ordinal_index, []).append(name)
        result = []
        for index in range(function_count):
            target = struct.unpack_from("<I", addresses, index * 4)[0]
            if not target:
                if index in names:
                    raise PEError("named export has an empty address slot")
                continue
            forwarder = None
            if rva <= target < rva + size:
                forwarder = self.cstring(target, rva + size - target)
                va = None
            else:
                # An export can name a zero-filled datum, so require an image
                # mapping here rather than wrongly requiring file-backed bytes.
                va = self.rva_to_va(target)
                if self.section_of(va) is None:
                    raise PEError("export target is not in a section")
            result.append(dict(ordinal=ordinal_base + index, names=names.get(index, []),
                               rva=target, va=va, forwarder=forwarder))
        return result

    @property
    def exports(self):
        """Named local export VAs. Use export_records() to include forwarders."""
        return {name: record["va"] for record in self.export_records() if record["va"] is not None
                for name in record["names"]}

    def metadata(self, pdb=True):
        return dict(filename=Path(self.path).name, size=len(self.data), sha256=self.sha256(),
                    machine=self.machine, image_base=self.base, timestamp=self.timestamp,
                    version=self.version, pdb=self.pdb if pdb else None)


class Retail(PEImage):
    def __init__(self, build):
        self.build = build
        super().__init__(build["path"])
        self.name = build.get("name", self.name)

    def verify_identity(self, expected=None):
        expected = self.build if expected is None else expected
        required = ("sha256", "size", "machine", "image_base", "timestamp", "version")
        # A PDB-less project pins no RSDS record; a pinned one is always checked.
        if "pdb" in expected or adapter_of(self.build.get("project", {}))["pdb_required"]:
            required += ("pdb",)
        missing = [key for key in required if key not in expected]
        if missing:
            raise IdentityError("missing retail identity pins: " + ", ".join(missing))
        actual = self.metadata(pdb="pdb" in required)
        for key in required:
            wanted = expected[key]
            if key in ("size", "machine", "image_base", "timestamp"):
                wanted = _number(wanted)
            if key == "pdb":
                for field in ("guid", "age", "path"):
                    if field not in wanted or actual[key][field] != wanted[field]:
                        raise IdentityError("retail PDB identity mismatch: " + field)
            elif actual[key] != wanted:
                raise IdentityError("retail identity mismatch: " + key)
        return actual


def _overlap(start, size, other, other_size):
    return size > 0 and other_size > 0 and start < other + other_size and other < start + size


@dataclass(frozen=True)
class OrderedReference:
    """Operand order matters. Identity must be independently proven by caller.

    offset is relative to the function, target is an absolute preferred-image VA,
    kind distinguishes e.g. rel32, dir32, and dir32nb. An absent identity is open.
    """
    offset: int
    kind: str
    target: int
    identity: str | None = None
    width: int = 4


def ordered_referents(references: Iterable[OrderedReference | dict]):
    result = [asdict(item) if isinstance(item, OrderedReference) else dict(item) for item in references]
    result.sort(key=lambda item: item["offset"])
    end = 0
    for item in result:
        if item["offset"] < end or item["width"] <= 0:
            raise ValueError("overlapping or invalid reference operands")
        if not item.get("kind") or not isinstance(item.get("target"), int):
            raise ValueError("reference requires kind and numeric target")
        end = item["offset"] + item["width"]
    return result


def resolve_referent(target, symbols: Mapping[int, str | list[str]], imports=None):
    """Resolve only exact addresses; no nearest-symbol or content heuristics.

    Multiple aliases remain explicit instead of choosing one arbitrarily. Imports
    accept address->identity, or PE import_records() dictionaries.
    """
    identities = set()
    value = symbols.get(target)
    if isinstance(value, str):
        identities.add(value)
    elif value:
        identities.update(value)
    if isinstance(imports, Mapping):
        value = imports.get(target)
        if value:
            identities.add(value)
    elif imports:
        identities.update(item["identity"] for item in imports if item["va"] == target)
    return sorted(identities)
