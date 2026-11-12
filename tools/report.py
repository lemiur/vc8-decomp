"""Report coverage from a successful byte gate, never from candidate score claims."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling tools when loaded by path
from matchlib import checkout_paths

import ledger


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def diagnostic_observations(binary, comparisons):
    """Adapt match.py observations without promoting them to admission records."""
    scored, unscored = [], []
    for candidate in comparisons:
        if candidate.get("score") is None:
            unscored.append({"binary": binary, "symbol": candidate["symbol"],
                             "va": candidate["retail_va"], "status": candidate["status"]})
            continue
        verdict = candidate.get("referents_status", "unresolved")
        scored.append(ledger.normalize({"observed_at": candidate["observed_at"], "binary": binary,
            "va": candidate["retail_va"], "symbol": candidate["symbol"],
            "function_source_sha256": candidate["function_source_sha256"], "unit": candidate["source_path"],
            "build_id": candidate["build_id"], "score": candidate["score"],
            "bytes_exact": candidate["raw_bytes_equal"],
            "referents": verdict if verdict in ("resolved", "mismatch", "unsupported") else "unresolved",
            "rules": {"passed": "pass", "pass": "pass", "failed": "fail", "fail": "fail"}.get(candidate.get("rule_status"), "unknown")}))
    return scored, unscored


def gate_admissions(gate, binary):
    """Fail closed on malformed, non-green or inconsistent gate provenance."""
    if gate.get("schema_version") != 1 or gate.get("gate_kind") != "retail-splice":
        raise ValueError("gate schema or kind mismatch")
    if not isinstance(gate.get("run_id"), str) or not gate["run_id"]:
        raise ValueError("gate lacks a run identity")
    if gate.get("status") != "GREEN" or gate.get("errors") or not str(gate.get("authority", "")).startswith("BANKED "):
        raise ValueError("gate is not GREEN")
    result = gate.get("binaries", {}).get(binary, {})
    if result.get("status") != "GREEN":
        raise ValueError("binary was not admitted by this gate")
    retail = result.get("input_sha256", "")
    if not ledger.HEX64.fullmatch(retail) or result.get("output_sha256") != retail or result.get("fallback_sha256") != retail:
        raise ValueError("gate did not reproduce the pinned retail hash")
    admitted = result.get("admitted")
    if not isinstance(admitted, list):
        raise ValueError("gate lacks admitted_functions")
    addresses = set()
    ranges = []
    for function in admitted:
        va = function.get("retail_va")
        va = va if isinstance(va, int) else int(str(va), 0)
        size = function.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise ValueError("admitted function lacks a positive exact size")
        if isinstance(va, bool) or va in addresses or not 0 <= va <= 0xffffffff or va + size > 0x100000000:
            raise ValueError("duplicate or invalid admitted address")
        addresses.add(va)
        ranges.append((va, va + size))
        if function.get("rules", {}).get("status") != "passed" or function.get("referents_status") != "resolved" or function.get("bytes_exact") is not True:
            raise ValueError("admission lacks rules, bytes or ordered referent verification")
        if not ledger.HEX64.fullmatch(str(function.get("source_sha256", ""))):
            raise ValueError("admission lacks source attribution")
        if function.get("build_id") != gate.get("run_id") or not ledger.HEX64.fullmatch(str(function.get("image_sha256", ""))) or not function.get("artifacts"):
            raise ValueError("admission lacks attributable fresh build provenance")
        if not any(item.get("kind") == "linked-image" and item.get("sha256") == function["image_sha256"] for item in function["artifacts"]):
            raise ValueError("admission image is absent from build artifacts")
        if function.get("boundary", {}).get("status") != "verified" or not function["boundary"].get("evidence"):
            raise ValueError("admission lacks verified boundary evidence")
    ranges.sort()
    if any(previous[1] > current[0] for previous, current in zip(ranges, ranges[1:])):
        raise ValueError("overlapping admitted functions")
    total = sum(function["size"] for function in admitted)
    if result.get("source_bytes") != total or result.get("functions") != len(admitted):
        raise ValueError("gate source byte count disagrees with admissions")
    denominator = result.get("source_byte_denominator")
    if not isinstance(denominator, int) or isinstance(denominator, bool) or denominator < total or denominator != result.get("image_bytes"):
        raise ValueError("invalid gate byte denominator")
    authority_claim = f"{binary} functions={len(admitted)} source_bytes={total}/{denominator}"
    if authority_claim not in gate["authority"][len("BANKED "):].split("; "):
        raise ValueError("counts are absent from the printed gate authority")
    return admitted


def report_binary(binary, gate=None, gate_path=None, observations=(), inventory=None):
    result = {"binary": binary, "gate_status": "UNAVAILABLE", "matched_under_rules": None,
              "source_attributed_bytes": None, "function_denominator": None,
              "byte_denominator": None, "function_percent": None, "byte_percent": None,
              "boundary_caveats": ["No complete function boundary census supplied."],
              "candidate_scores": [row for row in ledger.snapshots(observations) if row["binary"] == binary]}
    if inventory is not None:
        # A producer must explicitly certify census completeness. Public aliases
        # and next-symbol gaps cannot supply an exact function denominator.
        census = inventory.get("coverage_denominator", {})
        if census.get("boundaries_complete") is True:
            for input_key, output_key in (("functions", "function_denominator"), ("code_bytes", "byte_denominator")):
                value = census.get(input_key)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError("invalid certified census denominator")
                result[output_key] = value
            result["boundary_caveats"] = list(census.get("caveats", []))
        else:
            result["boundary_caveats"] = list(census.get("caveats", result["boundary_caveats"]))
    if gate is not None:
        admitted = gate_admissions(gate, binary)
        gated = gate["binaries"][binary]
        result.update(gate_status="GREEN", matched_under_rules=len(admitted),
                      source_attributed_bytes=sum(row["size"] for row in admitted),
                      retail_sha256=gated["input_sha256"], output_sha256=gated["output_sha256"],
                      gate_run_id=gate["run_id"], gate_authority=gate["authority"],
                      gate_observed_at=gate.get("observed_at"), byte_denominator=gated["source_byte_denominator"],
                      byte_denominator_kind="complete-retail-file")
        result["boundary_caveats"].append("Source byte denominator is the complete retail file, including data and headers; code-byte coverage is unresolved.")
        if gated.get("function_denominator") is None:
            result["boundary_caveats"].append(gated.get("function_denominator_caveat", "Function denominator unresolved."))
        if gate_path is not None:
            result["gate_report"] = str(Path(gate_path).resolve())
            result["gate_report_sha256"] = file_sha256(gate_path)
        for numerator, denominator, percentage in (("matched_under_rules", "function_denominator", "function_percent"),
                                                     ("source_attributed_bytes", "byte_denominator", "byte_percent")):
            total = result[denominator]
            if total is not None:
                if result[numerator] > total:
                    raise ValueError("gate count exceeds certified denominator")
                result[percentage] = 100 * result[numerator] / total if total else None
    return result


def markdown(reports):
    lines = ["# VC8 source progress", "", "Coverage is banked only by a GREEN byte gate. The splice gate does not prove a full source relink.", "",
             "| Binary | Gate | Matched under rules | Source bytes | Function denominator | Retail file bytes |",
             "| --- | --- | ---: | ---: | ---: | ---: |"]
    display = lambda value: "unknown" if value is None else str(value)
    for report in reports:
        lines.append("| " + " | ".join(display(report[key]) for key in ("binary", "gate_status", "matched_under_rules", "source_attributed_bytes", "function_denominator", "byte_denominator")) + " |")
    for report in reports:
        lines.extend(["", f"## {report['binary']}", ""])
        lines.extend(f"- {note}" for note in report["boundary_caveats"])
        if report.get("gate_run_id"):
            lines.append(f"- Coverage snapshot: gate `{report['gate_run_id']}` at {report.get('gate_observed_at') or 'unspecified time'}.")
        candidates = report["candidate_scores"]
        lines.append(f"- Score observations: {len(candidates)}; pending score observations: {sum(row['candidate_status'] == 'MATCH-PENDING' for row in candidates)}; lost matches: {sum(row['lost_match'] for row in candidates)}.")
        lines.append("- Open source functions are inventoried separately by `python tools/campaign.py`; missing score observations do not imply no pending work.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=root / "config/project.json")
    parser.add_argument("--binary", action="append")
    parser.add_argument("--gate", type=Path, default=root / "build/gate/latest.json")
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--output-dir", type=Path, default=root / "build/reports")
    parser.add_argument("--ledger", type=Path, default=root / "ledger.tsv")
    parser.add_argument("--scores", action="append", default=[], metavar="BINARY=COMPARISON_JSON",
                        help="optional ignored match.py diagnostic observations; never admissions")
    args = parser.parse_args(argv)
    try:
        config = read_json(args.project)
        binaries = args.binary or list(config["binaries"])
        unknown = set(binaries) - set(config["binaries"])
        if unknown:
            raise ValueError("unconfigured binaries: " + ", ".join(sorted(unknown)))
        evidence_dir = args.evidence_dir or checkout_paths(config, args.project.resolve().parents[1])[0] / "build/evidence"
        rows = ledger.read(args.ledger)
        unscored = []
        for argument in args.scores:
            name, separator, filename = argument.partition("=")
            if not separator or name not in binaries:
                raise ValueError("--scores requires a configured selected BINARY=PATH")
            observations, unknown_scores = diagnostic_observations(name, read_json(filename))
            keys = {(row["binary"], row["va"], row["build_id"]) for row in observations}
            rows = [row for row in rows if (row["binary"], row["va"], row["build_id"]) not in keys] + observations
            unscored.extend(unknown_scores)
        gate = read_json(args.gate) if args.gate.exists() else None
        reports = []
        for binary in binaries:
            symbols_path = evidence_dir / f"{binary}.symbols.json"
            selected_gate = gate if gate is not None and gate.get("binaries", {}).get(binary, {}).get("status") != "fallback-verified" else None
            result = report_binary(binary, selected_gate,
                                   args.gate if selected_gate is not None else None, rows,
                                   read_json(symbols_path) if symbols_path.exists() else None)
            result["unscored_candidates"] = [row for row in unscored if row["binary"] == binary]
            reports.append(result)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for report in reports:
            (args.output_dir / f"{report['binary']}.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (args.output_dir / "progress.md").write_text(markdown(reports), encoding="utf-8")
        for report in reports:
            count = report["matched_under_rules"]
            print(f"{report['binary']}: gate={report['gate_status']} banked={'unknown' if count is None else count} source_bytes={report['source_attributed_bytes']}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"report: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
