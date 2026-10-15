"""Regenerate bounded campaign status from local authority and evidence artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

import match
import report
import rulecheck


def small_json(path, limit=200_000):
    path = Path(path)
    if path.stat().st_size > limit:
        raise ValueError("summary exceeds bounded-input limit: " + str(path))
    return report.read_json(path)


def artifact(path):
    return {"path": str(Path(path).resolve()), "sha256": report.file_sha256(path)}


def export_state(directory, expected_binary=None, expected_sha256=None):
    """Read completion authority, never infer completion from a summary snapshot."""
    directory = Path(directory)
    manifest_path = directory / "manifest.json"
    manifest = small_json(manifest_path)
    if expected_binary is not None and manifest.get("binary") != expected_binary:
        raise ValueError("Ghidra manifest binary identity disagrees with summary")
    if expected_sha256 is not None and manifest.get("binary_sha256") != expected_sha256:
        raise ValueError("Ghidra manifest binary hash disagrees with pinned retail identity")
    result = {"status": manifest.get("status", "unknown"), "complete": False,
              "manifest": artifact(manifest_path), "version": manifest.get("ghidra_version")}
    completion_path = directory / "export-complete.json"
    if manifest.get("status") in ("complete", "complete_with_analysis_timeout") and manifest.get("returncode") == 0 and completion_path.is_file():
        completion = small_json(completion_path)
        if completion.get("ghidra_version") != manifest.get("ghidra_version"):
            raise ValueError("Ghidra completion version disagrees with manifest")
        if completion.get("binary_sha256", manifest.get("binary_sha256")) != manifest.get("binary_sha256"):
            raise ValueError("Ghidra completion binary hash disagrees with manifest")
        for key in ("functions", "decompiled", "failed"):
            if type(completion.get(key)) is not int or completion[key] < 0:
                raise ValueError("invalid Ghidra completion census")
        if completion["functions"] != completion["decompiled"] + completion["failed"]:
            raise ValueError("inconsistent Ghidra completion census")
        counts = {key: completion[key] for key in ("functions", "decompiled", "failed")}
        for key in ("timed_out", "workers"):
            if key in completion:
                if type(completion[key]) is not int or completion[key] < 0:
                    raise ValueError("invalid Ghidra timeout/worker census")
                counts[key] = completion[key]
        if counts.get("timed_out", 0) > counts["failed"]:
            raise ValueError("Ghidra timeouts exceed failures")
        result.update(complete=True, counts=counts,
                      completion=artifact(completion_path))
    return result


def ghidra_status(path, binaries, retail_hashes=None):
    result = {"status": "unavailable", "original_exports": [], "followups": [],
              "caveat": "Inferred Ghidra bodies are evidence counts, never source-function denominators."}
    if not Path(path).is_file():
        return result
    summary = small_json(path)
    result.update(status="available", summary=artifact(path), requested_version=summary.get("requested_ghidra_version"),
                  actual_version=summary.get("actual_ghidra_version"))
    by_binary = {row["binary"]: row for row in summary.get("runs", [])}
    for binary in binaries:
        row = by_binary.get(binary)
        state = {"binary": binary, "status": "unavailable", "complete": False}
        if row:
            try:
                state.update(export_state(row["run"], binary, (retail_hashes or {}).get(binary)))
                saved = Path(row.get("saved_program_source", row["run"]))
                state["saved_project_present"] = any(saved.glob("*.gpr"))
                state["saved_project_source"] = str(saved)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                state.update(status="invalid", error=str(exc))
        result["original_exports"].append(state)
    result["all_original_exports_complete"] = all(row["complete"] for row in result["original_exports"])
    for row in summary.get("followup_exports", []):
        state = {"binary": row["binary"], "purpose": row.get("purpose")}
        try:
            state.update(export_state(Path(row["manifest_authority"]).parent, row["binary"], (retail_hashes or {}).get(row["binary"])))
            if state["complete"] and row.get("failure_classification"):
                try:
                    classification_path = Path(row["failure_classification"])
                    classification = small_json(classification_path)
                    if classification.get("export_manifest_sha256") != state["manifest"]["sha256"]:
                        raise ValueError("failure classification is not bound to the current export manifest")
                    if any(classification.get("completion", {}).get(key) != value for key, value in state["counts"].items()):
                        raise ValueError("failure classification census disagrees with export completion")
                    state["failure_classification"] = {"artifact": artifact(classification_path),
                        "classes": classification.get("failure_classes", {}),
                        "same_failure_addresses_as_original": classification.get("same_failure_addresses_as_original_serial_export")}
                except (ValueError, OSError, KeyError, TypeError) as exc:
                    state["classification_error"] = str(exc)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            state.update(status="invalid", complete=False, error=str(exc))
        result["followups"].append(state)
    return result


def open_work(source_root, binaries, admitted, evidence_root=None):
    """Union current source/rule and registry census; ledger absence is irrelevant."""
    source_root = Path(source_root)
    errors = []
    try:
        rules = rulecheck.check(root=source_root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        rules = {"functions": [], "summary": {"match_pending": None}, "scope_sha256": None}
        errors.append({"path": str(source_root / "matching"), "error": str(exc)})
    registry = {}
    for binary in binaries:
        for entry in match.registry_entries(source_root, binary):
            registry[(binary, match.integer(entry["retail_va"]))] = entry
    functions = {(row["binary"], int(row["va"], 0)): dict(row) for row in rules["functions"]}
    spans = {}
    for path in sorted((source_root / "matching").rglob("*")):
        if path.suffix.lower() not in (".c", ".cpp", ".cxx"):
            continue
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines()
            for annotation in match.parse_annotations(path):
                key = (annotation.binary, annotation.retail_va)
                body = "\n".join(lines[annotation.start - 1:annotation.end])
                notes = re.findall(r"//\s*stop:\s*([^\n]*)", "\n".join(lines[annotation.line - 1:annotation.end]))
                spans[key] = {"function_source_sha256": hashlib.sha256(body.encode()).hexdigest(),
                              "stop_notes": notes, "symbol": annotation.symbol or annotation.source_name}
        except (ValueError, OSError, UnicodeError) as exc:
            errors.append({"path": str(path), "error": str(exc)})
    diagnoses = {}
    if evidence_root is not None:
        for path in sorted(Path(evidence_root).glob("*-wall.json")):
            try:
                row = small_json(path)
                key = (row["binary"], match.integer(row["retail_va"]))
                if key not in spans:
                    continue
                if row.get("function_source_sha256") == spans.get(key, {}).get("function_source_sha256"):
                    diagnoses[key] = {"wall": row["wall"], "open_leads": row.get("open_leads", row.get("open", [])), "artifact": artifact(path)}
                else:
                    errors.append({"path": str(path), "error": "stale or unbound wall diagnosis ignored"})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                errors.append({"path": str(path), "error": str(exc)})
    pending = []
    for key in sorted(set(functions) | set(registry)):
        fn, entry, span = functions.get(key, {}), registry.get(key, {}), spans.get(key, {})
        banked = admitted.get(key)
        reasons = []
        if not banked:
            reasons.append("not in gate admission snapshot")
        if entry.get("gate_enabled") is False:
            reasons.append("registry disabled")
        if span.get("stop_notes"):
            reasons.append("parked source")
        if fn and not fn.get("admitted"):
            reasons.append("current source rules pending")
        if banked and span.get("function_source_sha256") != banked.get("function_source_sha256"):
            reasons.append("function source changed since gate")
        if not reasons:
            continue
        note = " ".join(span.get("stop_notes", []))
        # A complete CFG note or a fuzzy-score dip cannot diagnose a CFG wall.
        wall = "unclassified"
        if re.search(r"register[/ -]+schedule", note, re.I):
            wall = "register/schedule"
        else:
            diagnosis = re.search(r"(?:wall|diagnosis)\s*:\s*(referent|inline/call set|CFG)\b", note, re.I)
            if diagnosis:
                wall = diagnosis[1]
        diagnosis = diagnoses.get(key, {})
        pending.append({"binary": key[0], "va": f"0x{key[1]:08X}",
                        "symbol": entry.get("symbol") or span.get("symbol") or fn.get("name"),
                        "unit": fn.get("source_path") or entry.get("unit"), "reasons": reasons,
                        "wall": diagnosis.get("wall", wall), "wall_evidence": diagnosis.get("artifact"),
                        "open_leads": diagnosis.get("open_leads", []), "stop_notes": span.get("stop_notes", []),
                        "rule_status": fn.get("status", "unscanned"), "banked_snapshot": banked is not None})
    pending.sort(key=lambda row: (row["banked_snapshot"], row["binary"], row["va"]))
    return {"annotated_functions": len(functions) if rules["scope_sha256"] else None, "registered_functions": len(registry),
            "rule_summary": rules["summary"], "scope_sha256": rules["scope_sha256"],
            "pending": pending, "parse_errors": errors}


def collect(project, source_root, build_root):
    binaries = list(project["binaries"])
    gate_path = build_root / "gate/latest.json"
    # The provenance-rich gate may be large; process it programmatically, never
    # print it or treat it as a bounded human-readable evidence summary.
    gate = report.read_json(gate_path) if gate_path.is_file() else None
    counts, admitted = [], {}
    for binary in binaries:
        try:
            selected_gate = gate
            if gate and gate.get("binaries", {}).get(binary, {}).get("status") == "fallback-verified":
                selected_gate = None
            row = report.report_binary(binary, selected_gate, gate_path if selected_gate else None)
            if selected_gate:
                for fn in report.gate_admissions(gate, binary):
                    admitted[(binary, match.integer(fn["retail_va"]))] = fn
            counts.append({key: row.get(key) for key in ("binary", "gate_status", "matched_under_rules", "source_attributed_bytes", "function_denominator", "byte_denominator", "gate_run_id", "gate_observed_at")})
        except (ValueError, TypeError, KeyError) as exc:
            counts.append({"binary": binary, "gate_status": "UNAVAILABLE", "matched_under_rules": None,
                           "source_attributed_bytes": None, "function_denominator": None, "error": str(exc)})
    retail_path = source_root / "config/retail.json"
    retail = small_json(retail_path) if retail_path.is_file() else {}
    retail_hashes = {name: data["sha256"] for name, data in retail.get("builds", {}).items()}
    ghidra = ghidra_status(build_root / "ghidra/summary.json", binaries, retail_hashes)
    bootstrap_path = build_root / "toolchain-ab/summary.json"
    bootstrap = {"status": "unavailable", "conclusion": "Bootstrap compiler identity is unresolved; no bounded A/B summary is available."}
    if bootstrap_path.is_file():
        observations = small_json(bootstrap_path)
        valid = observations.get("schema_version") == 1 and observations.get("kind") == "bootstrap-ab-observations" and observations.get("observational_only") is True and bool(observations.get("provenance"))
        for provenance in observations.get("provenance", []):
            path = Path(provenance["path"])
            valid = valid and path.is_file() and report.file_sha256(path) == provenance.get("sha256")
        bootstrap = {"status": "available" if valid else "invalid", "summary": artifact(bootstrap_path), "observations": observations,
                     "conclusion": "Bootstrap compiler identity remains inconclusive; A/B observations confer no gate coverage."}
        if not valid:
            bootstrap["conclusion"] = "Bootstrap summary provenance is invalid; identity remains unresolved."
        elif observations.get("verdict", {}).get("bootstrap_identity") != "unresolved":
            bootstrap["conclusion"] = "Bootstrap summary reports a new verdict requiring review; no identity is certified by this status tool."
    work = open_work(source_root, binaries, admitted, build_root / "evidence")
    phases, provisional = [], []
    for binary, config in sorted(project["binaries"].items(), key=lambda item: item[1]["phase"]):
        profile_path = source_root / "config" / f"{binary}.json"
        profile = small_json(profile_path) if profile_path.is_file() else {}
        if profile.get("status") != "pinned":
            provisional.append(binary)
        phases.append({"phase": config["phase"], "binary": binary, "optional": config.get("optional", False),
                       "exit_status": "not proven", "exit_criteria": "Match all functions under source rules with a complete boundary census, then reproduce the retail hash by a full source rebuild."})
    plan_path = source_root / "VC8_DECOMP_PLAN.md"
    return {"schema_version": 1, "coverage": counts, "gate": artifact(gate_path) if gate else None,
            "retail_identity": artifact(retail_path) if retail_path.is_file() else None,
            "phase_plan": artifact(plan_path) if plan_path.is_file() else None, "phases": phases,
            "phase_zero": {"all_original_exports_complete": ghidra.get("all_original_exports_complete", False),
                           "provisional_binary_profiles": provisional, "exit_status": "not fully certified",
                           "remaining": "Export completion alone does not certify all infrastructure, flag, identity and unit-map requirements."},
            "ghidra": ghidra, "open_work": work, "bootstrap": bootstrap,
            "caveats": ["Gate coverage is a snapshot of compiled source substitutions into a retail copy, not a full source relink.",
                        "Ghidra and public-symbol counts are not complete source-function denominators; no speculative percentage is emitted.",
                        "Open source work comes from current source/rules/registry, independently of banked ledger score observations."]}


def render(status, limit=8):
    lines = ["# VC8 campaign status", "", "Gate snapshot: compiled source substitutions; full source relink remains unproven.", "",
             "| Binary | Gate | Banked functions | Source bytes |", "| --- | --- | ---: | ---: |"]
    for row in status["coverage"]:
        show = lambda key: "unknown" if row.get(key) is None else str(row[key])
        lines.append(f"| {row['binary']} | {row['gate_status']} | {show('matched_under_rules')} | {show('source_attributed_bytes')} |")
    snapshot = next((row for row in status["coverage"] if row.get("gate_run_id")), None)
    if snapshot:
        lines.append(f"Gate run: {snapshot['gate_run_id']} at {snapshot.get('gate_observed_at') or 'unspecified time'}.")
    lines.extend(["", "Phases: " + " -> ".join(f"{row['phase']} {row['binary']}{' (optional)' if row['optional'] else ''}" for row in status["phases"]),
                  "Exit: all functions matched under rules with a complete census, followed by a full source rebuild reproducing the retail hash. No phase exit is proven.",
                  "Phase 0: original exports complete=" + str(status["phase_zero"]["all_original_exports_complete"]) + "; provisional profiles=" + ",".join(status["phase_zero"]["provisional_binary_profiles"]) + ".", "",
                  "Ghidra original exports (evidence bodies / decompiled / failed; never source denominators):"])
    for row in status["ghidra"]["original_exports"]:
        values = row.get("counts", {})
        lines.append(f"- {row['binary']}: {row['status']}; {values.get('functions', '?')} / {values.get('decompiled', '?')} / {values.get('failed', '?')}; saved project={row.get('saved_project_present', False)}")
    ghidra = status["ghidra"]
    lines.append(f"Analyzer requested={ghidra.get('requested_version', '?')}; actual={ghidra.get('actual_version', '?')}.")
    for row in ghidra["followups"][:5]:
        values = row.get("counts", {})
        details = f"{values.get('functions', '?')} / {values.get('decompiled', '?')} / {values.get('failed', '?')}; timed out={values.get('timed_out', '?')}" if row.get("complete") else "completion pending"
        lines.append(f"- Refinement {row['binary']}: {row['status']}; {details}.")
    work = status["open_work"]
    lines.extend(["", f"Open source work: {len(work['pending'])}; annotated={work['annotated_functions']}; registered={work['registered_functions']}; rule-pending={work['rule_summary']['match_pending']}."])
    for row in work["pending"][:limit]:
        note = " ".join(row["stop_notes"]) or "; ".join(row["reasons"])
        wall = " ".join(str(row["wall"]).split())
        lines.append(f"- {row['binary']} {row['va']} {row['symbol']}: {wall[:100]}; {note[:160]}")
    if len(work["pending"]) > limit:
        lines.append(f"- {len(work['pending']) - limit} more open entries are retained in campaign.json.")
    if work["parse_errors"]:
        lines.append(f"Source/evidence warnings: {len(work['parse_errors'])}; see campaign.json.")
    lines.extend(["", "Bootstrap A/B: " + status["bootstrap"]["conclusion"], "",
                  "Evidence paths and hashes, phase criteria, pending reasons, and bootstrap observations are retained in campaign.json."])
    observations = status["bootstrap"].get("observations", {})
    if observations:
        lines.insert(-2, f"A/B baseline={observations.get('baseline_commit', '?')}; identities={observations.get('unique_source_function_identities_observed', '?')}; paired={observations.get('latest_production_comparison_pairs', '?')}; raw equal={observations.get('latest_raw_bytes_equal_pairs', '?')}; independently resolved equal={observations.get('latest_independently_resolved_bytes_equal_pairs', '?')} (observational only).")
    return "\n".join(lines) + "\n"


def main(argv=None):
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=root / "config/project.json")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--output-dir", type=Path, default=root / "build/reports")
    parser.add_argument("--limit", type=int, default=8)
    args = parser.parse_args(argv)
    try:
        if not 0 <= args.limit <= 12:
            raise ValueError("open-work display limit must be between 0 and 12")
        project = small_json(args.project)
        source = args.source_root or Path(project["primary_checkout"])
        build = args.build_root or Path(project["primary_checkout"]) / "build"
        status = collect(project, source, build)
        output = render(status, args.limit)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "campaign.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (args.output_dir / "campaign.md").write_text(output, encoding="utf-8")
        print(output, end="")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"campaign: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
