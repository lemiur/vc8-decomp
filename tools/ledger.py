"""Deterministic per-function score observations; scores never establish coverage."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
from pathlib import Path
import re

FIELDS = ("observation_id", "observed_at", "binary", "va", "symbol",
          "function_source_sha256", "unit", "build_id", "score", "bytes_exact",
          "referents", "rules", "gate_sha256")
HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")


def normalize(raw):
    """Validate and canonicalize an observation before hashing or merging it."""
    row = {key: str(raw.get(key, "")) for key in FIELDS if key != "observation_id"}
    if not row["binary"] or not row["symbol"] or not row["build_id"]:
        raise ValueError("binary, symbol and build_id are required")
    va = raw.get("va")
    address = va if isinstance(va, int) else int(str(va), 0)
    if isinstance(va, bool) or not 0 <= address <= 0xffffffff:
        raise ValueError("va must be an x86 address")
    row["va"] = f"0x{address:08X}"
    if not HEX64.fullmatch(row["function_source_sha256"]):
        raise ValueError("function_source_sha256 must identify the function's source")
    row["function_source_sha256"] = row["function_source_sha256"].lower()
    when = datetime.fromisoformat(row["observed_at"].replace("Z", "+00:00"))
    if when.tzinfo is None:
        raise ValueError("observed_at requires a timezone")
    row["observed_at"] = when.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    score = float(row["score"])
    if not math.isfinite(score) or not 0 <= score <= 100:
        raise ValueError("score must be finite and between 0 and 100")
    row["score"] = format(score, ".12g")
    exact = raw.get("bytes_exact")
    if type(exact) is not bool and exact not in ("true", "false"):
        raise ValueError("bytes_exact must be true or false")
    row["bytes_exact"] = "true" if exact in (True, "true") else "false"
    if row["referents"] not in ("resolved", "unresolved", "mismatch", "unsupported"):
        raise ValueError("invalid referents verdict")
    if row["rules"] not in ("pass", "fail", "unknown"):
        raise ValueError("invalid rules verdict")
    payload = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    row["observation_id"] = hashlib.sha256(payload.encode()).hexdigest()
    supplied = raw.get("observation_id")
    if supplied and supplied != row["observation_id"]:
        raise ValueError("observation_id does not match its contents")
    return row


def merge(*collections):
    by_id = {}
    builds = {}
    for collection in collections:
        for raw in collection:
            row = normalize(raw)
            key = (row["binary"], row["va"], row["build_id"])
            old = builds.get(key)
            if old and old != row["observation_id"]:
                raise ValueError("conflicting observations for the same function and build")
            builds[key] = row["observation_id"]
            by_id[row["observation_id"]] = row
    return sorted(by_id.values(), key=lambda row: (row["observed_at"], row["build_id"], row["observation_id"]))


def read(path):
    path = Path(path)
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError("unsupported ledger header")
        rows = merge(reader)
        validate_tracked(rows)
        return rows


def validate_tracked(rows):
    for row in rows:
        if not HEX64.fullmatch(row["gate_sha256"]):
            raise ValueError("tracked ledger row lacks gate attribution")
        if row["score"] != "100" or row["bytes_exact"] != "true" or row["referents"] != "resolved" or row["rules"] != "pass":
            raise ValueError("tracked history is limited to gate-admitted exact source")


def write(path, observations):
    path = Path(path)
    rows = merge(observations)
    validate_tracked(rows)
    # One latest successful observation per source revision retains recovery
    # history without accumulating an entry on every unchanged clean gate.
    revisions = {}
    for row in rows:
        revisions[(row["binary"], row["va"], row["function_source_sha256"])] = row
    rows = merge(revisions.values())
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(stream.getvalue(), encoding="utf-8", newline="")
    temporary.replace(path)


def snapshots(observations):
    grouped = {}
    for row in merge(observations):
        grouped.setdefault((row["binary"], row["va"]), []).append(row)
    result = []
    for key, history in sorted(grouped.items()):
        latest = history[-1]
        current_source = [row for row in history if row["function_source_sha256"] == latest["function_source_sha256"]]
        current = float(latest["score"])
        best = max(float(row["score"]) for row in current_source)
        historical = max(float(row["score"]) for row in history)
        pending = latest["bytes_exact"] == "true" and (latest["rules"] != "pass" or latest["referents"] != "resolved")
        result.append({**latest, "current": current, "best": best, "historical": historical,
                       "lost_match": historical > best,
                       "candidate_status": "MATCH-PENDING" if pending else "CANDIDATE"})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=Path(__file__).resolve().parents[1] / "ledger.tsv")
    sub = parser.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("import", help="merge tracked TSV histories by observation identity")
    ingest.add_argument("inputs", nargs="+", type=Path)
    record = sub.add_parser("record-gate", help="record only source admitted by a GREEN gate")
    record.add_argument("gate", type=Path)
    record.add_argument("--observed-at", help="required only for gate schemas without an observed_at timestamp")
    summary = sub.add_parser("summary", help="emit bounded score snapshots, never banked coverage")
    summary.add_argument("--binary")
    summary.add_argument("--limit", type=int, default=20)
    summary.add_argument("--output", type=Path, help="save complete JSON snapshots without printing them")
    args = parser.parse_args(argv)
    try:
        rows = read(args.ledger)
        if args.command == "import":
            for path in args.inputs:
                if not path.is_file():
                    raise ValueError("history input is missing or not a file: " + str(path))
                incoming = read(path)
                rows = merge(rows, incoming)
            write(args.ledger, rows)
        elif args.command == "record-gate":
            from report import file_sha256, gate_admissions, read_json
            gate = read_json(args.gate)
            incoming = []
            for binary, result in gate.get("binaries", {}).items():
                if result.get("status") == "fallback-verified":
                    continue
                for function in gate_admissions(gate, binary):
                    source_hash = function.get("function_source_sha256")
                    if not source_hash:
                        raise ValueError("gate lacks per-function source identity; unit hash cannot track source history")
                    incoming.append({"observed_at": args.observed_at or gate.get("observed_at"),
                                     "binary": binary, "va": function["retail_va"], "symbol": function["symbol"],
                                     "function_source_sha256": source_hash, "unit": function["unit"],
                                     "build_id": function["build_id"], "score": 100, "bytes_exact": True,
                                     "referents": "resolved", "rules": "pass", "gate_sha256": file_sha256(args.gate)})
            # Validate even an empty all-fallback aggregate; RED authorizes nothing.
            if gate.get("status") != "GREEN" or not str(gate.get("authority", "")).startswith("BANKED "):
                raise ValueError("gate is not GREEN")
            write(args.ledger, merge(rows, incoming))
        else:
            if not 0 <= args.limit <= 40:
                raise ValueError("summary limit must be between 0 and 40")
            scores = [row for row in snapshots(rows) if not args.binary or row["binary"] == args.binary]
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(scores, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"score snapshots={len(scores)} displayed={min(len(scores), args.limit)}; coverage requires gate")
            for row in scores[:args.limit]:
                print(f"{row['binary']} {row['va']} current={row['current']:g} best={row['best']:g} historical={row['historical']:g} {row['candidate_status']}")
    except (ValueError, OSError, TypeError, KeyError) as exc:
        parser.exit(2, f"ledger: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
