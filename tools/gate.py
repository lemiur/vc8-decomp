"""Independent PE splice/hash gate. This is not a full source relink.

Every invocation checks all five pinned retail images before admitting any source.
Candidate requests and evidence live in config/gate-allow.json. A fresh build is
requested from match.py with --output-dir, --manifest and --build-id. Manifests
are observations, never authority for bytes, referents, boundaries or code rules.
Execution trusts the local compiler and repository build runner. Configured and
observed runtime files are hashed; Windows SxS binding is not retraced per build.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("cl", "c1", "c1xx", "c2", "link")


class GateError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise GateError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def integer(value):
    require(not isinstance(value, bool), "boolean is not an address")
    return int(value, 0) if isinstance(value, str) else int(value)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def resolve(path, root=ROOT):
    p = Path(path)
    return (p if p.is_absolute() else root / p).resolve()


def contained(path, directory):
    try:
        path.relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def checked_file(record, root=ROOT, directory=None):
    path = resolve(record["path"], root)
    require(directory is None or contained(path, directory), "artifact escapes fresh output directory")
    require(path.is_file(), "missing provenance file: " + str(path))
    require(digest(path.read_bytes()) == record.get("sha256"), "provenance hash mismatch: " + str(path))
    return path


def snapshot_inputs(root):
    """Catch changes during the trusted builder's invocation, including headers."""
    result = {}
    for directory in ("matching", "include", "config", "tools"):
        for path in sorted((root / directory).rglob("*")):
            if path.is_file() and path.suffix.lower() in (".c", ".cpp", ".cxx", ".h", ".hpp", ".json", ".py"):
                result[str(path.resolve())] = digest(path.read_bytes())
    return result


def load_registry(root):
    """Merge the global policy and canonical per-binary candidate descriptors."""
    documents = [(root / "config" / "gate-allow.json", None)]
    documents += [(root / "config" / (name + "-candidates.json"), name) for name in BINARIES
                  if (root / "config" / (name + "-candidates.json")).is_file()]
    result = {"schema_version": 1, "candidates": [], "referents": {}}
    seen_symbols, seen_addresses = set(), set()
    for path, only_binary in documents:
        document = read_json(path)
        require(document.get("schema_version") == 1, "wrong admission registry schema: " + str(path))
        for candidate in document.get("candidates", []):
            name = candidate.get("binary")
            require(name in BINARIES and (only_binary is None or name == only_binary), "candidate descriptor names wrong binary")
            require(type(candidate.get("gate_enabled", True)) is bool, "gate_enabled must be a boolean")
            symbol_key, address_key = (name, candidate["symbol"]), (name, integer(candidate["retail_va"]))
            require(symbol_key not in seen_symbols and address_key not in seen_addresses, "duplicate candidate admission descriptor")
            seen_symbols.add(symbol_key)
            seen_addresses.add(address_key)
            result["candidates"].append(candidate)
        for name, bindings in document.get("referents", {}).items():
            require(name in BINARIES and (only_binary is None or name == only_binary), "referent descriptor names wrong binary")
            destination = result["referents"].setdefault(name, {})
            for identity, binding in bindings.items():
                require(identity not in destination or destination[identity] == binding, "conflicting referent identity descriptors")
                destination[identity] = binding
    return result


def splice(image, spans, offset, code):
    require(offset >= 0 and code and offset + len(code) <= len(image), "splice outside file or empty")
    end = offset + len(code)
    require(all(end <= lo or offset >= hi for lo, hi in spans), "overlapping candidate ranges")
    spans.append((offset, end))
    image[offset:end] = code


def scan_referents(image, va, code):
    """Decode the entire x86 body and enumerate operands; never mask blindly."""
    try:
        import capstone as cs
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    except ImportError as error:
        raise GateError("capstone is required to admit compiled candidates") from error
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    decoder.detail = True
    sites = {}
    fixup_fields = set()
    decoded = 0
    for ins in decoder.disasm(code, va):
        require(ins.address == va + decoded, "non-contiguous instruction decoding")
        decoded += ins.size
        branch = ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_CALL)
        if branch and ins.operands and ins.operands[0].type == X86_OP_IMM:
            width = ins.imm_size
            require(width in (1, 4), "unsupported relative branch width")
            offset = ins.address - va + ins.imm_offset
            sites[offset] = {"offset": offset, "width": width, "kind": "rel%d" % (width * 8),
                             "target": ins.operands[0].imm & 0xffffffff}
        for operand in ins.operands:
            if operand.type == X86_OP_IMM and not branch and ins.imm_size == 4:
                fixup_fields.add(ins.address - va + ins.imm_offset)
            if operand.type == X86_OP_MEM and ins.disp_size == 4:
                fixup_fields.add(ins.address - va + ins.disp_offset)
            if operand.type == X86_OP_MEM and not operand.mem.base:
                require(ins.disp_size == 4, "unsupported absolute memory operand")
                offset = ins.address - va + ins.disp_offset
                sites[offset] = {"offset": offset, "width": 4, "kind": "abs32",
                                 "target": operand.mem.disp & 0xffffffff}
            elif operand.type == X86_OP_IMM and not branch and ins.imm_size == 4:
                # EXEs may have no relocation table. Treat an immediate that
                # names file-backed image storage conservatively as a referent.
                target = operand.imm & 0xffffffff
                try:
                    image.read(target, 1)
                except (ValueError, KeyError):
                    continue
                offset = ins.address - va + ins.imm_offset
                sites[offset] = {"offset": offset, "width": 4, "kind": "abs32", "target": target}
    require(decoded == len(code), "incomplete instruction decoding or embedded data")
    for relocation in image.base_relocations():
        site = integer(relocation["va"])
        width = relocation.get("width")
        if va <= site < va + len(code):
            require(relocation["type"] == 3 and width == 4, "unsupported PE relocation")
            offset = site - va
            require(offset + 4 <= len(code), "relocation crosses function boundary")
            require(offset in fixup_fields, "PE relocation is not a decoded operand field")
            item = {"offset": offset, "width": 4, "kind": "abs32",
                    "target": struct.unpack_from("<I", code, offset)[0]}
            require(offset not in sites or sites[offset] == item, "conflicting operand and PE relocation")
            sites[offset] = item
    ordered = [sites[key] for key in sorted(sites)]
    require(all(a["offset"] + a["width"] <= b["offset"] for a, b in zip(ordered, ordered[1:])),
            "overlapping referent operands")
    return ordered


def import_identity(image, target):
    """Resolve an actual IAT slot, preserving DLL identity and exact export name."""
    records = [item for item in image.import_records() if integer(item["va"]) == target]
    require(len(records) == 1, "referent does not identify one PE import slot")
    return records[0]["dll"].lower() + "!" + records[0]["name"]


def literal_bytes(binding, claim):
    """Derive a bounded literal object from an exact token in the hashed unit."""
    token, encoding = binding.get("source_literal", ""), binding.get("encoding")
    require(encoding in ("ascii", "utf-16le"), "unsupported literal encoding")
    require(isinstance(token, str) and bool(re.fullmatch(r'L?"(?:\\.|[^"\\])*"', token)), "unsupported source literal expression")
    require(token.startswith('L"') == (encoding == "utf-16le"), "literal prefix and encoding disagree")
    path = Path(claim["source_path"])
    require(digest(path.read_bytes()) == claim.get("source_sha256"), "literal source hash differs from build input")
    source = path.read_text(encoding="utf-8-sig")
    tokens = re.findall(r'//[^\n]*|/\*.*?\*/|L?"(?:\\.|[^"\\])*"', source, re.S)
    require(token in [part for part in tokens if not part.startswith("//") and not part.startswith("/*")],
            "literal token absent from hashed source expressions")
    body = token[2:-1] if token.startswith('L"') else token[1:-1]
    escapes = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11,
               "\\": 92, "'": 39, '"': 34, "?": 63}
    chars, position = [], 0
    while position < len(body):
        char = body[position]
        position += 1
        if char != "\\":
            require(ord(char) < 128, "non-ASCII source literal requires execution-character-set evidence")
            chars.append(ord(char))
            continue
        require(position < len(body), "incomplete source escape")
        char = body[position]
        position += 1
        if char in escapes:
            chars.append(escapes[char])
        elif char in "01234567":
            digits = char
            while position < len(body) and len(digits) < 3 and body[position] in "01234567":
                digits += body[position]
                position += 1
            chars.append(int(digits, 8))
        elif char == "x":
            start = position
            while position < len(body) and body[position] in "0123456789abcdefABCDEF":
                position += 1
            require(position > start, "empty hex escape")
            chars.append(int(body[start:position], 16))
        else:
            raise GateError("unsupported source literal escape")
    require(all(value <= (127 if encoding == "ascii" else 0xffff) for value in chars), "literal code unit outside supported encoding")
    chars.append(0)
    data = bytes(chars) if encoding == "ascii" else b"".join(struct.pack("<H", value) for value in chars)
    require(0 < len(data) <= 65536 and integer(binding.get("size", 0)) == len(data), "literal extent differs from source object")
    require(digest(data) == binding.get("bytes_sha256"), "literal hash differs from source expression")
    return data


def verify_literal_storage(image, target, data):
    require(any(integer(section["va"]) <= target and target + len(data) <= integer(section["va"]) + integer(section["rawsize"]) and
                integer(section["chars"]) & 0x40000000 and not integer(section["chars"]) & 0x80000000
                for section in image.sections), "literal storage is not a single read-only file-backed span")
    require(image.read(target, len(data)) == data, "referenced literal bytes differ from source expression")


def compare_candidate(retail, candidate_image, claim, request, identities, emitted_identities=None):
    """Return emitted source bytes with only independently resolved fixups."""
    va, built_va, size = map(integer, (request["retail_va"], claim["candidate_va"], request["size"]))
    require(size > 0 and integer(claim["size"]) == size, "unexplained function size change")
    require(integer(claim["retail_va"]) == va, "retail address differs from admission registry")
    require(request.get("boundary", {}).get("status") == "verified" and
            bool(request["boundary"].get("evidence")), "unverified function boundary")
    require(claim.get("boundary") == request["boundary"], "boundary evidence differs from registry")
    for image, start in ((retail, va), (candidate_image, built_va)):
        require(any(integer(section["va"]) <= start and start + size <= integer(section["va"]) + integer(section["rawsize"]) and
                    integer(section["chars"]) & 0x20000000 for section in image.sections),
                "candidate span is not in a single executable file-backed section")
    code = candidate_image.read(built_va, size)
    expected = retail.read(va, size)
    require(digest(code) == claim.get("bytes_sha256"), "candidate byte hash mismatch")
    emitted_refs = scan_referents(candidate_image, built_va, code)
    retail_refs = scan_referents(retail, va, expected)
    claimed_refs = claim.get("referents")
    require(isinstance(claimed_refs, list) and len(claimed_refs) == len(emitted_refs) == len(retail_refs),
            "incomplete ordered referent inventory")
    resolved = bytearray(code)
    for built, reference, advertised in zip(emitted_refs, retail_refs, claimed_refs):
        require({k: integer(advertised[k]) if k in ("offset", "width", "target") else advertised[k]
                 for k in ("offset", "width", "kind", "target")} == built,
                "manifest referent differs from decoded emitted operand")
        require(all(built[k] == reference[k] for k in ("offset", "width", "kind")),
                "ordered referent sites differ from retail")
        identity = advertised.get("identity", "")
        require(advertised.get("resolved") is True, "unresolved referent")
        if built_va <= built["target"] < built_va + size:
            delta = built["target"] - built_va
            require(identity == "self+0x%x" % delta, "wrong internal referent identity")
            target = va + delta
        else:
            binding = identities.get(identity, {})
            require(binding.get("evidence") and "va" in binding, "unproven external referent identity")
            target = integer(binding["va"])
            kind = binding.get("kind", "symbol")
            if kind == "import":
                canonical = str(binding.get("dll", "")).lower() + "!" + str(binding.get("name", ""))
                require(identity == canonical and built["kind"] == "abs32", "import identity or operand kind differs")
                require(import_identity(candidate_image, built["target"]) == canonical and
                        import_identity(retail, target) == canonical, "PE import DLL/name differs between source and retail")
            elif kind == "literal":
                data = literal_bytes(binding, claim)
                require(identity == "literal:sha256:" + digest(data) and built["kind"] == "abs32", "literal identity or operand kind differs")
                verify_literal_storage(candidate_image, built["target"], data)
                verify_literal_storage(retail, target, data)
            elif kind == "symbol":
                require(emitted_identities is not None and emitted_identities.get(built["target"]) == {identity},
                        "emitted external target does not independently identify advertised referent")
            else:
                raise GateError("unsupported external referent evidence kind")
        require(target == reference["target"], "ordered referent target differs from retail")
        offset, width = built["offset"], built["width"]
        value = target if built["kind"] == "abs32" else target - (va + offset + width)
        if built["kind"] == "abs32":
            struct.pack_into("<I", resolved, offset, value)
        else:
            require(-(1 << (width * 8 - 1)) <= value < 1 << (width * 8 - 1), "branch displacement overflow")
            resolved[offset:offset + width] = value.to_bytes(width, "little", signed=True)
    require(bytes(resolved) == expected, "independent function byte comparison failed")
    return bytes(resolved), len(emitted_refs)


def validate_manifest(manifest, binary, build_id, output_dir, root=ROOT):
    require(manifest.get("schema_version") == 1 and manifest.get("binary") == binary, "wrong manifest schema/binary")
    require(manifest.get("build_id") == build_id, "stale build manifest")
    candidates = manifest.get("candidates")
    require(isinstance(candidates, list), "missing candidate inventory")
    if not candidates:
        return {}, {}
    require(manifest.get("status") == "built", "candidate build did not finish successfully")
    def inventory(records):
        result = {}
        for item in records:
            path = str(checked_file(item, root))
            require(path not in result, "duplicate provenance input")
            result[path] = item["sha256"]
        return result
    sources = inventory(manifest.get("source_inputs", []))
    toolchain = inventory(manifest.get("toolchain", []))
    require(sources and toolchain, "missing source/toolchain build provenance")
    pins = read_json(root / "config" / "toolchains.json").get("toolchains", {})
    pinned_sets = [{str(resolve(item["path"], root)): item["sha256"] for item in tc.get("files", [])}
                   for tc in pins.values()]
    require(any(toolchain == pinned for pinned in pinned_sets), "toolchain inventory differs from configured pins")
    commands = manifest.get("commands", [])
    require(commands and all(c.get("returncode") == 0 and c.get("argv") for c in commands), "failed or absent build commands")
    invoked = {str(resolve(c["argv"][0], root)) for c in commands}
    require(invoked <= toolchain.keys(), "build command executable lacks hashed provenance")
    require(any(Path(p).name.lower() in ("cl", "cl.exe") for p in invoked) and
            any(Path(p).name.lower() in ("link", "link.exe") for p in invoked), "compiler and linker commands required")
    artifacts = {}
    for item in manifest.get("artifacts", []):
        path = checked_file(item, root, output_dir)
        require(str(path) not in artifacts, "duplicate build artifact")
        artifacts[str(path)] = item
    require(artifacts, "missing compiler output artifacts")
    objects = {p for p, item in artifacts.items() if item.get("kind") == "ltcg-object"}
    images = {p for p, item in artifacts.items() if item.get("kind") == "linked-image"}
    require(objects and images, "compiled LTCG objects and linked image required")
    produced, used_objects = set(), set()
    for command in commands:
        argv = command["argv"]
        executable = Path(argv[0]).name.lower()
        cwd = resolve(command.get("cwd", ""), root)
        require(cwd.is_dir(), "build command working directory missing")
        outputs = {str(resolve(p, root)) for p in command.get("produced", [])}
        require(outputs <= artifacts.keys(), "command produces an unrecorded artifact")
        if executable in ("cl", "cl.exe"):
            output_args = [arg[3:] for arg in argv[1:] if arg.lower().startswith("/fo")]
            produced_objects = {str(resolve(p, cwd)) for p in output_args}
            require(bool(outputs) and outputs <= produced_objects, "compiler output has no command attribution")
            if outputs.intersection(objects):
                require("/gl" in [arg.lower() for arg in argv], "candidate object did not use /GL")
            require(any(str(resolve(arg, cwd)) in sources for arg in argv[1:] if not arg.startswith("/")),
                    "compiler command has no hashed source input")
        elif executable in ("link", "link.exe"):
            require(any(arg.lower() == "/ltcg" or arg.lower().startswith("/ltcg:") for arg in argv), "candidate link did not use /LTCG")
            output_args = [arg[5:] for arg in argv[1:] if arg.lower().startswith("/out:")]
            require(images.intersection(outputs) <= {str(resolve(p, cwd)) for p in output_args} and
                    bool(images.intersection(outputs)), "linked image has no command attribution")
            consumed = {str(resolve(arg, cwd)) for arg in argv[1:] if not arg.startswith("/")}
            consumed_objects = consumed.intersection(objects)
            require(consumed_objects and consumed_objects <= produced, "link lacks preceding compiled-object provenance")
            used_objects.update(consumed_objects)
        produced.update(outputs)
    require(objects | images <= produced, "unattributed candidate output")
    require(objects <= used_objects, "compiled object is not consumed by candidate link")
    return sources, artifacts


def verify_linked_symbol(claim, manifest, artifacts, root):
    image = str(resolve(claim["image_path"], root))
    links = [command for command in manifest["commands"] if image in
             {str(resolve(path, root)) for path in command.get("produced", [])}]
    require(len(links) == 1, "candidate image has ambiguous link provenance")
    maps = [str(resolve(path, root)) for path in links[0].get("produced", [])
            if artifacts.get(str(resolve(path, root)), {}).get("kind") == "linker-map"]
    require(len(maps) == 1, "candidate image needs independently readable linker MAP")
    declared_maps = {str(resolve(arg[5:], resolve(links[0].get("cwd", ""), root)))
                     for arg in links[0]["argv"] if arg.lower().startswith("/map:")}
    require(maps[0] in declared_maps, "linker MAP lacks command attribution")
    matches, identities = [], {}
    pattern = re.compile(r"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8,16})\s+f\s+(.+?)\s*$")
    any_symbol = re.compile(r"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8,16})(?:\s+.*)?$")
    compiled_objects = [str(resolve(path, root)) for path in links[0].get("argv", [])
                        if artifacts.get(str(resolve(path, root)), {}).get("kind") == "ltcg-object"]
    for line in Path(maps[0]).read_text(encoding="utf-8", errors="replace").splitlines():
        symbol = any_symbol.match(line)
        if symbol:
            identities.setdefault(int(symbol[2], 16), set()).add(symbol[1])
        match = pattern.match(line)
        if match and match[1] == claim["symbol"]:
            owners = [path for path in compiled_objects if Path(path).name.lower() == match[3].strip().lower()]
            require(len(owners) == 1, "candidate symbol has no unique compiled source object owner")
            compilers = [command for command in manifest["commands"] if owners[0] in
                         {str(resolve(path, root)) for path in command.get("produced", [])} and
                         Path(command["argv"][0]).name.lower() in ("cl", "cl.exe")]
            require(len(compilers) == 1, "candidate object has ambiguous compiler attribution")
            command = compilers[0]
            source_args = {str(resolve(arg, resolve(command.get("cwd", ""), root))) for arg in command["argv"][1:]
                           if not arg.startswith("/")}
            require(str(resolve(claim["source_path"], root)) in source_args,
                    "candidate object was compiled from a different source unit")
            matches.append(int(match[2], 16))
    require(matches == [integer(claim["candidate_va"])], "linked symbol identity/address does not match candidate")
    return identities


def check_rules(root, output_dir):
    checker = root / "tools" / "rulecheck.py"
    require(checker.is_file(), "rule checker unavailable; compiled candidates remain MATCH-PENDING")
    log = output_dir / "rules.log"
    report = output_dir / "rules.json"
    run = subprocess.run([sys.executable, str(checker), "matching", "--json", str(report)], cwd=root, capture_output=True, text=True)
    log.write_text(run.stdout + run.stderr, encoding="utf-8")
    require(run.returncode in (0, 1), "code rule checker failed; see " + str(log))
    require(report.is_file(), "rule checker emitted no structured admissions")
    result = read_json(report)
    require(result.get("schema_version") == 1 and isinstance(result.get("functions"), list), "invalid rule admission report")
    return result


def execute_gate(binary="all", root=ROOT, matchlib_module=None):
    if matchlib_module is None:
        import matchlib as matchlib_module
    run_id = uuid.uuid4().hex
    out = root / "build" / "gate" / run_id
    out.mkdir(parents=True, exist_ok=False)
    record = {"schema_version": 1, "gate_kind": "retail-splice", "run_id": run_id,
              "observed_at": datetime.now(timezone.utc).isoformat(),
              "build_provenance": {"trust_boundary": "trusted local compiler and repository build runner",
                  "runtime_scope": "configured and previously observed runtime files are hashed; Windows SxS policy may change; dynamic binding is not retraced per build"},
              "status": "RED", "authority": None, "binaries": {}, "errors": []}
    selected = BINARIES if binary == "all" else (binary,)
    try:
        registry = load_registry(root)
        retail_images = {}
        # All-five fallback proof precedes every possible source admission.
        for name in BINARIES:
            cfg = matchlib_module.load_binary_config(name, root=root)
            retail = matchlib_module.Retail(cfg)
            retail.verify_identity()
            retail_images[name] = retail
            copied = bytes(bytearray(retail.data))
            fallback = out / (name + ".fallback.bin")
            fallback.write_bytes(copied)
            require(digest(fallback.read_bytes()) == retail.sha256(), "all-fallback identity hash failed: " + name)
            record["binaries"][name] = {"input_sha256": retail.sha256(), "fallback_sha256": digest(copied),
                "output_sha256": None, "image_bytes": len(copied), "functions": 0, "source_bytes": 0,
                "function_denominator": None, "function_denominator_caveat": "public symbols do not establish all function boundaries",
                "source_byte_denominator": len(copied), "admitted": [], "pending": [], "status": "fallback-verified"}
        for name in selected:
            requests = [r for r in registry.get("candidates", []) if r.get("binary") == name and r.get("gate_enabled", True)]
            require(len({r["symbol"] for r in requests}) == len(requests), "duplicate candidate admission requests")
            build_dir = out / name
            build_dir.mkdir()
            manifest_path = build_dir / "manifest.json"
            harness = root / "tools" / "match.py"
            if harness.is_file():
                inputs_before = snapshot_inputs(root)
                command = [sys.executable, str(harness), "build", "--binary", name, "--output-dir", str(build_dir),
                           "--manifest", str(manifest_path), "--build-id", run_id]
                run = subprocess.run(command, cwd=root, capture_output=True, text=True)
                (build_dir / "build.log").write_text(run.stdout + run.stderr, encoding="utf-8")
                require(inputs_before == snapshot_inputs(root), "build inputs changed during fresh rebuild")
                require(run.returncode == 0, "fresh rebuild failed: " + name + "; see " + str(build_dir / "build.log"))
                require(manifest_path.is_file(), "fresh rebuild produced no manifest")
                manifest = read_json(manifest_path)
                manifest_hash = digest(manifest_path.read_bytes())
            else:
                require(not requests, "candidate rebuild harness unavailable")
                manifest = {"schema_version": 1, "binary": name, "build_id": run_id, "candidates": []}
            sources, artifacts = validate_manifest(manifest, name, run_id, build_dir, root)
            all_claims = manifest["candidates"]
            require(len({c["symbol"] for c in all_claims}) == len(all_claims) and
                    len({integer(c["retail_va"]) for c in all_claims}) == len(all_claims), "duplicate manifest candidate identity")
            requested_symbols = {r["symbol"] for r in requests}
            require(requested_symbols <= {c["symbol"] for c in all_claims}, "candidate inventory omits admission request")
            claims = [c for c in all_claims if c["symbol"] in requested_symbols]
            rules = check_rules(root, build_dir) if claims else {"functions": []}
            image, spans = bytearray(retail_images[name].data), []
            result = record["binaries"][name]
            result["pending"] = [{"symbol": c["symbol"], "retail_va": c["retail_va"],
                                  "reason": "no gate admission request"} for c in all_claims if c["symbol"] not in requested_symbols]
            for claim in claims:
                request = next(r for r in requests if r["symbol"] == claim["symbol"])
                source = resolve(claim["source_path"], root)
                require(source == resolve(request["unit"], root), "candidate unit differs from registry")
                require(contained(source, root / "matching"), "candidate source is outside matching tree")
                require(sources.get(str(source)) == claim.get("source_sha256"), "source is absent from hashed build inputs")
                span = request.get("source_span", {})
                require(0 < integer(span.get("start", 0)) <= integer(span.get("end", 0)) <= len(source.read_text(encoding="utf-8").splitlines()),
                        "unverified source line span")
                require(claim.get("source_span") == span, "source line span differs from registry")
                function_hash = digest("\n".join(source.read_text(encoding="utf-8-sig").splitlines()[integer(span["start"])-1:integer(span["end"])]).encode("utf-8"))
                require(claim.get("function_source_sha256") == function_hash, "function source identity differs from verified span")
                admissions = [r for r in rules["functions"] if r.get("binary") == name and
                              integer(r.get("va", -1)) == integer(request["retail_va"]) and
                              resolve(r.get("source_path", ""), root) == source]
                require(len(admissions) == 1 and admissions[0].get("admitted") is True and
                        admissions[0].get("status") == "RULE-ADMITTED" and
                        admissions[0].get("source_sha256") == claim["source_sha256"],
                        "function lacks evidence-backed rule admission")
                image_path = resolve(claim["image_path"], root)
                artifact = artifacts.get(str(image_path), {})
                require(artifact.get("kind") == "linked-image" and artifact.get("sha256") == claim.get("image_sha256"),
                        "candidate lacks linked-image provenance")
                emitted_identities = verify_linked_symbol(claim, manifest, artifacts, root)
                built = matchlib_module.PEImage(image_path)
                code, refs = compare_candidate(retail_images[name], built, claim, request,
                                               registry.get("referents", {}).get(name, {}), emitted_identities)
                offset = retail_images[name].offset_of(integer(request["retail_va"]), len(code))
                splice(image, spans, offset, code)
                result["admitted"].append({"symbol": claim["symbol"], "retail_va": request["retail_va"], "size": len(code),
                    "unit": request["unit"], "source_sha256": claim["source_sha256"], "build_id": run_id,
                    "function_source_sha256": function_hash,
                    "source_span": span, "candidate_va": claim["candidate_va"], "image_path": str(image_path),
                    "bytes_sha256": claim["bytes_sha256"], "retail_file_offset": offset,
                    "spliced_bytes_sha256": digest(code), "manifest_path": str(manifest_path), "manifest_sha256": manifest_hash,
                    "image_sha256": claim["image_sha256"], "rules": {"status": "passed", "admission": admissions[0]},
                    "referents": refs, "referents_status": "resolved", "bytes_exact": True,
                    "artifacts": list(artifacts.values()),
                    "boundary": request["boundary"]})
            # The rule review and comparison must describe the same headers,
            # sources and toolchain that produced the fresh artifact.
            for item in manifest.get("source_inputs", []) + manifest.get("toolchain", []) + manifest.get("artifacts", []):
                checked_file(item, root)
            if claims:
                require(digest(manifest_path.read_bytes()) == manifest_hash, "build manifest changed during admission")
            output = build_dir / "splice.bin"
            output.write_bytes(image)
            result["output_sha256"] = digest(output.read_bytes())
            require(result["output_sha256"] == result["input_sha256"], "complete spliced image hash differs: " + name)
            result["functions"] = len(result["admitted"])
            result["source_bytes"] = sum(item["size"] for item in result["admitted"])
            result["status"] = "GREEN"
        record["status"] = "GREEN"
        record["authority"] = "BANKED " + "; ".join("%s functions=%d source_bytes=%d/%d" %
            (name, record["binaries"][name]["functions"], record["binaries"][name]["source_bytes"],
             record["binaries"][name]["image_bytes"]) for name in selected)
    except (GateError, OSError, KeyError, ValueError, TypeError, struct.error) as error:
        record["errors"].append(str(error))
        # A failed whole gate authorizes no counts, including earlier successful binaries.
        for result in record["binaries"].values():
            result["functions"] = result["source_bytes"] = 0
    (out / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    # One atomic aggregate latest result avoids partial per-binary success snapshots.
    latest = root / "build" / "gate" / "latest.json"
    temporary = latest.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    temporary.replace(latest)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", choices=(*BINARIES, "all"), default="all")
    parser.add_argument("--clean", action="store_true", help="accepted for adapter compatibility; builds are always fresh")
    parser.add_argument("--json", type=Path, help="additional report destination")
    args = parser.parse_args(argv)
    try:
        record = execute_gate(args.binary)
    except (ImportError, OSError) as error:
        print("RED: " + str(error))
        return 1
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    if record["status"] == "GREEN":
        print("GREEN: " + record["authority"])
        print("Splice identity verified; this does not establish a full source relink.")
        return 0
    for error in record["errors"]:
        print("RED: " + error)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
