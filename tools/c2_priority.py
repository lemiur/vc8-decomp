"""Select c2 evidence candidates; optionally inspect bounded reachable instructions.

Run from any worktree: python tools/c2_priority.py --symbols PATH --limit 20
  [--binary PATH/TO/c2.dll] [--output build/evidence/c2-priority.json]

The symbol adapter accepts a list or a document containing symbols/publics/functions.
Each record needs name and va/address (integer or 0x string). Explicit module plus
module_evidence records attribution; a bare module field is retained as unverified.
No public-address delta is ever interpreted as a function length. JSON output is
local evidence, not admission to the match gate. Requires capstone/pefile only when
--binary is requested. Bounded CFG observations are not authoritative boundaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def normalize_symbols(document):
    records = document if isinstance(document, list) else next(
        (document[key] for key in ("symbols", "publics", "functions") if key in document), None)
    if not isinstance(records, list):
        raise ValueError("symbol document must contain a symbols/publics/functions list")
    result = []
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            raise ValueError("each symbol requires a string name")
        address = record.get("va", record.get("address"))
        if address is None:
            raise ValueError("symbol requires va/address; RVA alone requires an image base")
        result.append({**record, "va": number(address)})
    return result


def module_basename(value):
    return str(value).replace("\\", "/").rsplit("/", 1)[-1].lower()


def select(symbols, config):
    candidates = []
    for symbol in symbols:
        # Explicit data records must never become function candidates.
        kind = str(symbol.get("kind", symbol.get("type", ""))).lower()
        if kind in ("data", "public_data", "s_gdata32", "s_ldata32") or symbol.get("is_function") is False:
            continue
        module = symbol.get("module", symbol.get("object_module"))
        evidence = symbol.get("module_evidence")
        module_candidates = symbol.get("module_candidates", symbol.get("candidate_modules", []))
        attributed = bool(module and evidence and len(module_candidates) <= 1)
        associations = []
        for family in config["families"]:
            by_module = module is not None and module_basename(module) in family["modules"]
            by_name = re.search(family["name_regex"], symbol["name"]) is not None
            if by_module or by_name:
                associations.append({"family": family["id"], "priority": family["priority"],
                                     "basis": "module" if by_module and attributed else "name-hint" if by_name else "unverified-module"})
        if not associations:
            continue
        associations.sort(key=lambda item: (-item["priority"], item["family"]))
        candidates.append({"name": symbol["name"], "va": f"0x{symbol['va']:08X}",
                           "selection": associations, "priority": associations[0]["priority"],
                           "ownership": {"module": module, "evidence": evidence,
                                         "status": "attributed" if attributed else "unresolved", "candidate_modules": module_candidates,
                                         "source_file": None, "source_status": "unresolved; object attribution alone is insufficient"},
                           "signature": "unresolved; public spelling alone is insufficient"})
    return sorted(candidates, key=lambda item: (-item["priority"], number(item["va"]), item["name"]))


class ImageEvidence:
    def __init__(self, path, symbols):
        import capstone
        import pefile
        self.capstone = capstone
        self.pe = pefile.PE(str(path))
        if self.pe.FILE_HEADER.Machine != 0x14C:
            raise ValueError("only x86 PE images are supported")
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.image_end = self.base + self.pe.OPTIONAL_HEADER.SizeOfImage
        self.names = {}
        for symbol in symbols:
            self.names.setdefault(symbol["va"], []).append(symbol["name"])
        self.decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.decoder.detail = True
        self.relocs = {self.base + entry.rva: entry.type for block in getattr(self.pe, "DIRECTORY_ENTRY_BASERELOC", []) for entry in block.entries if entry.type}
        self.imports = {entry.address: (entry.name or b"ordinal").decode("ascii", errors="replace") for dll in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []) for entry in dll.imports}

    def instruction(self, va):
        rva = va - self.base
        section = self.pe.get_section_by_rva(rva)
        if section is None or not section.Characteristics & 0x20000000:
            return None
        offset = self.pe.get_offset_from_rva(rva)
        return next(self.decoder.disasm(bytes(self.pe.__data__[offset:offset + 15]), va, count=1), None)

    def target(self, address):
        return {"va": f"0x{address:08X}", "names": self.names.get(address, []),
                "import": self.imports.get(address),
                "identity": "public" if address in self.names else "import" if address in self.imports else "unresolved"}

    def inspect(self, entry, max_instructions=160, max_span=2048):
        cs = self.capstone
        pending, decoded, edges, stops, referents, returns = [entry], {}, [], [], [], []
        while pending and len(decoded) < max_instructions:
            address = pending.pop()
            if address in decoded:
                continue
            if not entry <= address < entry + max_span:
                stops.append({"va": f"0x{address:08X}", "reason": "span-limit"})
                continue
            if address != entry and address in self.names:
                stops.append({"va": f"0x{address:08X}", "reason": "other-public-entry"})
                continue
            insn = self.instruction(address)
            if insn is None:
                stops.append({"va": f"0x{address:08X}", "reason": "unmapped/non-executable/undecodable"})
                continue
            decoded[address] = insn
            next_address = address + insn.size
            direct = insn.operands[0].imm if insn.operands and insn.operands[0].type == cs.x86.X86_OP_IMM else None
            is_call = insn.group(cs.CS_GRP_CALL)
            is_jump = insn.group(cs.CS_GRP_JUMP)
            if is_call or is_jump:
                if direct is not None:
                    referents.append({"instruction_va": f"0x{address:08X}", "kind": "call" if is_call else "branch", **self.target(direct)})
                else:
                    refs = [op.mem.disp for op in insn.operands if op.type == cs.x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0]
                    referents.append({"instruction_va": f"0x{address:08X}", "kind": "indirect-call" if is_call else "indirect-branch", "operand": insn.op_str, "slot": self.target(refs[0]) if refs else None})
            # Fixed-base EXEs need not have base relocations. Indexed image
            # displacements still expose a static table base, not a local field.
            for operand in insn.operands:
                if operand.type == cs.x86.X86_OP_MEM and self.base <= operand.mem.disp < self.image_end:
                    referents.append({"instruction_va": f"0x{address:08X}", "kind": "memory-address-base",
                                      "indexed": bool(operand.mem.base or operand.mem.index), "operand": insn.op_str,
                                      **self.target(operand.mem.disp)})
            for offset in range(insn.size):
                if address + offset in self.relocs:
                    location = address + offset
                    reloc_type = self.relocs[location]
                    target = None
                    if reloc_type == 3:
                        raw = self.pe.get_data(location - self.base, 4)
                        target = self.target(int.from_bytes(raw, "little"))
                    referents.append({"instruction_va": f"0x{address:08X}", "kind": "base-relocation", "location": f"0x{location:08X}", "relocation_type": reloc_type, "target": target})
            if insn.group(cs.CS_GRP_RET):
                returns.append({"va": f"0x{address:08X}", "instruction": insn.mnemonic + " " + insn.op_str, "stack_pop": direct or 0})
                continue
            if insn.mnemonic in ("int3", "ud2", "hlt"):
                stops.append({"va": f"0x{address:08X}", "reason": insn.mnemonic})
                continue
            if is_jump:
                if direct is None:
                    stops.append({"va": f"0x{address:08X}", "reason": "indirect-branch"})
                else:
                    edges.append((address, direct, "branch"))
                    pending.append(direct)
                if insn.mnemonic == "jmp":
                    continue
            edges.append((address, next_address, "fallthrough"))
            pending.append(next_address)
        if pending:
            stops.append({"reason": "instruction-limit", "pending_addresses": [f"0x{x:08X}" for x in sorted(set(pending))]})
        ordered = [decoded[key] for key in sorted(decoded)]
        unresolved = [ref for ref in referents if ref.get("kind") in ("indirect-call", "indirect-branch") or ref.get("identity") == "unresolved" and number(ref["va"]) not in decoded or ref.get("kind") == "base-relocation" and (ref["target"] is None or ref["target"]["identity"] == "unresolved")]
        return {"boundary_status": "bounded-reachable-observation; not an admitted function extent", "decoded_instruction_count": len(ordered),
                "decoded_byte_count": sum(insn.size for insn in ordered), "has_out_of_line_call": any(insn.group(cs.CS_GRP_CALL) for insn in ordered),
                "returns": returns, "edges": [{"from": f"0x{a:08X}", "to": f"0x{b:08X}", "kind": kind} for a, b, kind in sorted(edges)],
                "stops": stops, "referents": sorted(referents, key=lambda item: (number(item["instruction_va"]), item["kind"])),
                "unresolved_referent_count": len(unresolved), "abi": "ret pops are observed; parameters, return type and calling convention remain unresolved",
                "instructions": [{"va": f"0x{insn.address:08X}", "bytes": insn.bytes.hex(), "text": insn.mnemonic + " " + insn.op_str} for insn in ordered]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--symbols", required=True, type=Path)
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config/c2-priority.json")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--family", action="append", help="restrict to a configured family (repeatable)")
    parser.add_argument("--module", action="append", help="restrict to object module basename (repeatable)")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 200:
        parser.error("--limit must be between 1 and 200")
    config = json.loads(args.config.read_text(encoding="utf-8-sig"))
    document = json.loads(args.symbols.read_text(encoding="utf-8-sig"))
    if isinstance(document, dict) and document.get("binary", "c2") != "c2":
        parser.error("symbol document must describe c2")
    symbols = normalize_symbols(document)
    candidates = select(symbols, config)
    if args.family:
        unknown = set(args.family) - {family["id"] for family in config["families"]}
        if unknown:
            parser.error("unknown family: " + ", ".join(sorted(unknown)))
        candidates = [candidate for candidate in candidates if any(item["family"] in args.family for item in candidate["selection"])]
    if args.module:
        modules = {module_basename(module) for module in args.module}
        candidates = [candidate for candidate in candidates if module_basename(candidate["ownership"]["module"]) in modules]
    candidates = candidates[:args.limit]
    result = {"schema_version": 1, "binary": "c2", "matching_authorized": False,
              "symbol_input_sha256": hashlib.sha256(args.symbols.read_bytes()).hexdigest(), "candidates": candidates}
    if args.binary:
        binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
        identity = document.get("identity", {}) if isinstance(document, dict) else {}
        if identity.get("binary_sha256") and identity["binary_sha256"].lower() != binary_hash:
            parser.error("binary SHA-256 differs from symbol document identity")
        data_symbols = normalize_symbols(document["data"]) if isinstance(document, dict) and isinstance(document.get("data"), list) else []
        image = ImageEvidence(args.binary, symbols + data_symbols)
        if identity.get("image_base") is not None and number(identity["image_base"]) != image.base:
            parser.error("binary image base differs from symbol document identity")
        result["binary_sha256"] = binary_hash
        result["image_base"] = f"0x{image.base:08X}"
        for candidate in candidates:
            candidate["observations"] = image.inspect(number(candidate["va"]), config["max_instructions"], config["max_span"])
    payload = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"wrote {len(candidates)} evidence candidates to {args.output}; no matched counts claimed")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
