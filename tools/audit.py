"""Independent, fail-closed checks on a gate's claimed source-byte accounting.

The build runner is trusted to execute the pinned compiler. This checker does
not turn a JSON assertion that a compiler ran into proof of execution. It does
verify the artifact bytes, input hashes, fresh run directory and full candidate
census independently of the comparison/splicing implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling tools when loaded by path
from matchlib import ADAPTER_DEFAULTS


class AuditError(ValueError):
    """A source-byte claim lacks independently checkable evidence."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require(condition, message):
    if not condition:
        raise AuditError(message)


def _integer(value, label, minimum=0):
    _require(type(value) is int and value >= minimum, "invalid " + label)
    return value


def _census(records, label):
    result = {}
    for record in records:
        identity = record.get("id")
        _require(isinstance(identity, str) and identity, "invalid " + label + " id")
        _require(identity not in result, "duplicate " + label + ": " + identity)
        result[identity] = record
    return result


@dataclass(frozen=True)
class RunSnapshot:
    """Pre-build state captured in-process, never reconstructed from JSON.

    Call capture before running the trusted build harness, passing its newly
    created empty output directory and the exact source/toolchain inputs.
    """
    run_id: str
    root: Path
    inputs: tuple[tuple[Path, str], ...]

    @classmethod
    def capture(cls, root, run_id, inputs):
        directory = Path(root).resolve(strict=True)
        _require(directory.is_dir(), "build root is not a directory")
        _require(not any(directory.iterdir()), "build directory is not fresh")
        _require(isinstance(run_id, str) and bool(run_id), "missing run id")
        paths = [Path(path).resolve(strict=True) for path in inputs]
        _require(len(paths) == len(set(paths)), "duplicate build inputs")
        _require(bool(paths), "source builds require pinned inputs")
        for path in paths:
            _require(path.is_file() and not path.is_relative_to(directory),
                     "build inputs must be files outside output directory")
        return cls(run_id, directory, tuple((path, digest(path.read_bytes())) for path in paths))

    def check_inputs(self):
        for path, expected in self.inputs:
            _require(path.is_file() and digest(path.read_bytes()) == expected,
                     "build input changed: " + str(path))

    def artifact(self, relative_path, expected_sha256):
        path = (self.root / relative_path).resolve(strict=True)
        _require(path.is_relative_to(self.root) and path != self.root,
                 "artifact escapes fresh build directory")
        _require(path.is_file(), "artifact is not a file")
        data = path.read_bytes()
        _require(digest(data) == expected_sha256, "artifact hash mismatch")
        return data


@dataclass(frozen=True)
class BuildReceipt:
    """In-process observation of the trusted harness, never loaded from JSON."""
    run: RunSnapshot
    argv: tuple[str, ...]
    returncode: int
    manifest_sha256: str
    manifest_path: Path


@dataclass(frozen=True)
class ManifestAudit:
    """In-process approval binding source origins to an observed manifest."""
    receipt: BuildReceipt
    origins: frozenset[tuple]


def observe_build(run, argv, manifest_path, cwd, env=None):
    """Execute the trusted Python build harness against the captured empty root.

    The caller chooses its trusted harness and Python runtime. Their paths must
    be among the pre-build pinned inputs. This does not permit arbitrary JSON
    command assertions to substitute for an invocation the gate controlled.
    """
    pinned = dict(run.inputs)
    _require(len(argv) >= 2 and Path(argv[0]).resolve() in pinned and
             Path(argv[1]).resolve() in pinned, "unobserved build runtime or harness")
    manifest = Path(manifest_path).resolve()
    _require(manifest.is_relative_to(run.root) and not manifest.exists(),
             "manifest is stale or outside the fresh build root")
    _require(not any(run.root.iterdir()), "build output changed before invocation")
    run.check_inputs()
    completed = subprocess.run([str(a) for a in argv], cwd=cwd, env=env,
                               capture_output=True, text=True, errors="replace")
    _require(completed.returncode == 0, "trusted build invocation failed")
    run.check_inputs()
    _require(manifest.is_file(), "trusted build produced no manifest")
    return BuildReceipt(run, tuple(str(a) for a in argv), completed.returncode,
                        digest(manifest.read_bytes()), manifest), completed


def audit_manifest(manifest, binary, receipt, toolchain_pins, root, adapter=None, gl_for=None):
    """gl_for(source) gives a unit's /GL mode; default: the adapter's project mode."""
    adapter = adapter or ADAPTER_DEFAULTS
    gl_for = gl_for or (lambda source: adapter["gl"])
    compiler, linker = adapter["compiler"].lower(), adapter["linker"].lower()
    """Independently validate schema-1 match.py build output and pinned tools.

    toolchain_pins is an authoritative mapping of absolute path -> SHA-256,
    obtained from checked-in toolchain inventory, never from this manifest.
    """
    _require(isinstance(receipt, BuildReceipt) and receipt.returncode == 0,
             "source provenance requires trusted build invocation")
    run = receipt.run
    manifest_bytes = receipt.manifest_path.read_bytes()
    _require(digest(manifest_bytes) == receipt.manifest_sha256 and
             json.loads(manifest_bytes) == manifest, "manifest changed after trusted invocation")
    _require(manifest.get("schema_version") == 1 and manifest.get("binary") == binary,
             "wrong manifest schema or binary")
    _require(manifest.get("status") == "built", "build manifest is not successful")
    _require(manifest.get("build_id") == run.run_id, "stale build manifest")
    root = Path(root).resolve()
    run.check_inputs()

    def files(records, label, artifacts=False):
        _require(isinstance(records, list), "missing " + label)
        found = {}
        for record in records:
            path = (root / record["path"]).resolve(strict=True)
            _require(path not in found, "duplicate " + label)
            _require(path.is_file(), "invalid " + label + " file")
            _require(digest(path.read_bytes()) == record.get("sha256"), label + " hash mismatch")
            if artifacts:
                _require(path.is_relative_to(run.root), "artifact escapes fresh output")
            found[path] = record
        return found

    sources = files(manifest.get("source_inputs"), "source inputs")
    tools = files(manifest.get("toolchain"), "toolchain")
    artifacts = files(manifest.get("artifacts"), "artifacts", True)
    candidates = manifest.get("candidates")
    _require(isinstance(candidates, list), "missing candidate census")
    if not candidates:
        return ManifestAudit(receipt, frozenset())
    _require(bool(sources) and bool(tools) and bool(artifacts), "missing source-byte provenance")
    pins = {Path(path).resolve(): sha for path, sha in toolchain_pins.items()}
    _require(bool(pins), "missing authoritative toolchain pins")
    for path, record in tools.items():
        _require(pins.get(path) == record["sha256"], "unconfigured toolchain file")
    commands = manifest.get("commands")
    _require(isinstance(commands, list) and bool(commands), "missing compiler execution records")
    invoked = set()
    outputs = set()
    compiled_sources = {}  # source -> compiled with /GL at least once
    for command in commands:
        argv = command.get("argv")
        _require(isinstance(argv, list) and bool(argv) and command.get("returncode") == 0,
                 "failed or missing compiler command")
        executable = (root / argv[0]).resolve(strict=True)
        _require(executable in tools and executable in pins, "unconfigured command executable")
        invoked.add(executable.name.lower())
        directory = (root / command["cwd"]).resolve(strict=True)
        _require(directory.is_relative_to(run.root), "command ran outside fresh build directory")
        log = (root / command["log_path"]).resolve(strict=True)
        _require(log.is_relative_to(run.root) and digest(log.read_bytes()) == command["log_sha256"],
                 "command log provenance mismatch")
        for argument in argv[1:]:
            for prefix in ("/Fo", "/OUT:"):
                if argument.lower().startswith(prefix.lower()) and len(argument) > len(prefix):
                    outputs.add((directory / argument[len(prefix):]).resolve())
            source_argument = (directory / argument).resolve()
            if executable.name.lower() == compiler and source_argument in sources:
                compiled_sources[source_argument] = compiled_sources.get(source_argument, False) or "/GL" in argv
    _require({compiler, linker} <= invoked, "compiler and linker were not both invoked")
    for path, record in artifacts.items():
        if record.get("kind") in ("linked-image", "ltcg-object", "object"):
            _require(path in outputs, "artifact is not an observed command output")
    identities = set()
    origins = set()
    for candidate in candidates:
        symbol = candidate.get("symbol")
        _require(isinstance(symbol, str) and symbol and symbol not in identities, "duplicate or invalid candidate")
        identities.add(symbol)
        source = (root / candidate["source_path"]).resolve(strict=True)
        _require(source in sources and sources[source]["sha256"] == candidate["source_sha256"],
                 "candidate source lacks hashed provenance")
        _require(source in compiled_sources, "candidate source was not compiled")
        _require(compiled_sources[source] or not gl_for(source), "candidate source was not compiled with /GL")
        _require(dict(run.inputs).get(source) == candidate["source_sha256"],
                 "candidate source lacks pre-build input snapshot")
        image = (root / candidate["image_path"]).resolve(strict=True)
        _require(image in artifacts and artifacts[image].get("kind") == "linked-image" and
                 artifacts[image]["sha256"] == candidate["image_sha256"],
                 "copy-only candidate lacks compiler-linked output provenance")
        origins.add((symbol, source, candidate["source_sha256"], image,
                     candidate["image_sha256"], candidate["retail_va"], candidate["size"],
                     candidate["candidate_va"]))
    return ManifestAudit(receipt, frozenset(origins))


def checked_mapping(image, va, size):
    """Cross-check PEImage's VA mapping directly against its raw sections."""
    _integer(va, "VA")
    _integer(size, "range size", 1)
    _require(va + size <= 0x100000000, "VA range overflows x86 address space")
    sections = []
    for section in image.sections:
        start = section["va"]
        if start <= va and va + size <= start + section["rawsize"]:
            sections.append(section)
    _require(len(sections) == 1, "range is ambiguous or not file-backed by a section")
    section = sections[0]
    offset = section["raw"] + va - section["va"]
    _require(0 <= offset and offset + size <= len(image.data), "mapped range exceeds file")
    _require(image.offset_of(va, size) == offset, "PE mapping disagrees with section table")
    _require(image.offset_to_va(offset, size) == va, "PE mapping does not round trip")
    return offset


def audit_splice(retail, expected_sha256: str, expected_candidates: Sequence[Mapping],
                 candidates: Sequence[Mapping], output: bytes, run: RunSnapshot | None = None,
                 receipt: BuildReceipt | None = None, provenance: ManifestAudit | None = None,
                 candidate_images: Mapping | None = None):
    """Check exact-only source substitutions and return independently counted bytes.

    Both candidate sequences are required: the first is the pre-build configured
    census, the second is the builder/gate's admission result. A candidate has
    id, va, size, kind='compiled_source', run_id, artifact, artifact_sha256,
    artifact_offset, source, source_sha256, bytes_sha256, and two ordered lists
    retail_referents/candidate_referents. Every reference has offset, kind and
    target identity; only equal, explicit resolved lists are accepted. Nonempty
    masks and transformed/relocated payloads are deliberately unsupported.
    """
    _require(digest(retail.data) == expected_sha256, "wrong retail SHA-256")
    _require(len(output) == len(retail.data), "whole-image size changed")
    expected = _census(expected_candidates, "configured candidate")
    admitted = _census(candidates, "admitted candidate")
    _require(set(expected) == set(admitted), "omitted or unexpected candidate")
    if admitted:
        _require(isinstance(run, RunSnapshot), "source candidates require pre-build snapshot")
        _require(isinstance(receipt, BuildReceipt) and receipt.run is run and receipt.returncode == 0,
                 "source candidates require trusted compiler build execution")
        _require(isinstance(provenance, ManifestAudit) and provenance.receipt is receipt,
                 "source candidates require independently audited build provenance")
        run.check_inputs()
    result = bytearray(retail.data)
    ranges = []
    source_bytes = 0
    for identity, candidate in admitted.items():
        planned = expected[identity]
        _require(candidate.get("kind") == "compiled_source", "fallback cannot count as source")
        _require(not candidate.get("masks"), "opaque relocation masks are not admitted")
        _require(candidate.get("run_id") == run.run_id, "stale candidate run id")
        va = _integer(candidate.get("va"), "candidate VA")
        size = _integer(candidate.get("size"), "candidate size", 1)
        _require(va == planned.get("va") and size == planned.get("size"),
                 "candidate address or size changed from pre-build census")
        at = checked_mapping(retail, va, size)
        _require(not any(at < end and start < at + size for start, end in ranges),
                 "overlapping candidate ranges")
        ranges.append((at, at + size))
        artifact = run.artifact(candidate["artifact"], candidate["artifact_sha256"])
        off = _integer(candidate.get("artifact_offset"), "artifact offset")
        _require(off + size <= len(artifact), "candidate extraction exceeds artifact")
        payload = artifact[off:off + size]
        _require(digest(payload) == candidate.get("bytes_sha256"), "candidate byte hash mismatch")
        source = Path(candidate["source"]).resolve(strict=True)
        pinned = dict(run.inputs)
        _require(source in pinned and pinned[source] == candidate.get("source_sha256"),
                 "candidate source was not a pinned build input")
        origin = (identity, source, candidate["source_sha256"],
                  (run.root / candidate["artifact"]).resolve(), candidate["artifact_sha256"], va, size,
                  candidate.get("candidate_va"))
        _require(origin in provenance.origins, "source range is absent from audited compiler manifest")
        built = (candidate_images or {}).get(origin[3])
        _require(built is not None and built.data == artifact, "missing independently parsed candidate image")
        _require(checked_mapping(built, candidate["candidate_va"], size) == off,
                 "candidate extraction offset differs from PE mapping")
        _require(payload == retail.data[at:at + size], "source bytes differ from retail")
        left = candidate.get("retail_referents")
        right = candidate.get("candidate_referents")
        _require(isinstance(left, list) and isinstance(right, list), "missing ordered referents")
        for references in (left, right):
            previous = -1
            for reference in references:
                offset = reference.get("offset")
                _integer(offset, "referent offset")
                _require(previous < offset < size, "unordered or duplicate referents")
                _require(reference.get("kind") in ("REL32", "DIR32", "DIR32NB"),
                         "unsupported reference kind")
                _require(isinstance(reference.get("target"), str) and reference["target"],
                         "unresolved referent identity")
                _require(offset + 4 <= size, "referent operand exceeds candidate")
                previous = offset
        _require(left == right, "ordered referent identities differ")
        result[at:at + size] = payload
        source_bytes += size
    _require(bytes(result) == output, "output contains unattributed substituted bytes")
    _require(digest(output) == expected_sha256, "whole-image output hash differs")
    return {"verified_candidate_functions": len(admitted), "source_attributed_bytes": source_bytes,
            "output_sha256": digest(output)}


def audit_fallback_record(record, root, retail_images):
    """Reopen every all-fallback image independently; reject source claims.

    A saved JSON cannot recover an in-process execution receipt. Source-bearing
    records require the live provenance API and are intentionally refused here.
    """
    _require(record.get("schema_version") == 1 and record.get("gate_kind") == "retail-splice" and
             record.get("status") == "GREEN" and record.get("errors") == [], "gate record is not successful")
    run_id = record.get("run_id")
    _require(isinstance(run_id, str) and len(run_id) == 32 and
             all(c in "0123456789abcdef" for c in run_id), "invalid gate run id")
    binaries = record.get("binaries", {})
    _require(set(binaries) == set(retail_images), "incomplete binary inventory")
    directory = Path(root).resolve() / "build" / "gate" / run_id
    for name, retail in retail_images.items():
        result = binaries[name]
        _require(result.get("functions") == 0 and result.get("source_bytes") == 0 and
                 result.get("admitted") == [], "saved source claims require live provenance audit")
        expected = digest(retail.data)
        _require(result.get("input_sha256") == expected and result.get("image_bytes") == len(retail.data),
                 "gate retail identity differs from pinned image")
        fallback = (directory / (name + ".fallback.bin")).read_bytes()
        _require(fallback == retail.data and result.get("fallback_sha256") == expected,
                 "fallback bytes differ from retail")
        if result.get("status") == "GREEN":
            output = (directory / name / "splice.bin").read_bytes()
            _require(output == retail.data and result.get("output_sha256") == expected,
                     "spliced output bytes differ from retail")
        else:
            _require(result.get("status") == "fallback-verified", "unverified binary output status")
    return {"binaries": len(binaries), "functions": 0, "source_bytes": 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Independent fail-closed VC8 gate audit")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--gate-record", type=Path, help="default: ROOT/build/gate/latest.json")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        sys.path.insert(0, str(root / "tools"))
        import matchlib
        retails = {}
        for name in matchlib.load_adapter(root)["binaries"]:
            image = matchlib.Retail(matchlib.load_binary_config(name, root=root))
            image.verify_identity()
            retails[name] = image
        path = args.gate_record or root / "build" / "gate" / "latest.json"
        result = audit_fallback_record(json.loads(path.read_text(encoding="utf-8-sig")), root, retails)
        print("AUDIT PASS: %d fallback images verified; source functions=0 bytes=0" % result["binaries"])
        return 0
    except (AuditError, OSError, ValueError, KeyError, TypeError, ImportError) as error:
        print("AUDIT FAIL: " + str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
