"""Union per-lane candidate registries and review fragments without hand merges.

Every matching lane starts from the current integration branch in its own
worktree and appends to its own ``config/cl-candidates.json`` and writes
``config/reviews/cl5-<lane>.json``. Git cannot merge those JSON files cleanly, so
this tool performs the union instead:

* ``candidates`` unions the base registry with each lane's registry. The base
  order is preserved; lane-only entries are appended sorted by retail VA.
  Identical duplicate entries collapse. A conflicting duplicate (one symbol or
  one retail address with different content) aborts with both lane names.
* ``reviews`` validates each lane fragment and copies it next to the base
  fragments; a function claimed by two lanes aborts.

Both actions are read-only unless ``--out``/``--out-dir`` is given, and
``--check`` never writes.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ("R1", "R2", "R4", "R13", "R17", "R18")
FIELDS = ("binary", "symbol", "retail_va", "unit", "size", "source_span", "boundary")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def lane_file(lane: Path, name: str) -> Path:
    return lane if lane.is_file() else lane / "config" / name


def validate(entry, where):
    if not isinstance(entry, dict):
        raise ValueError(where + ": candidate is not an object")
    missing = [field for field in FIELDS if field not in entry]
    if missing:
        raise ValueError(where + ": candidate lacks " + ",".join(missing))
    if not isinstance(entry["symbol"], str) or not entry["symbol"]:
        raise ValueError(where + ": bad symbol")
    try:
        int(entry["retail_va"], 16)
    except (TypeError, ValueError):
        raise ValueError(where + ": retail_va is not hexadecimal: " + repr(entry["retail_va"]))
    if not isinstance(entry["size"], int) or entry["size"] <= 0:
        raise ValueError(where + ": size must be a positive integer")
    span = entry["source_span"]
    if not isinstance(span, dict) or not isinstance(span.get("start"), int) or not isinstance(span.get("end"), int) \
            or span["start"] <= 0 or span["start"] > span["end"]:
        raise ValueError(where + ": source_span needs start<=end and positive start")
    boundary = entry["boundary"]
    if entry.get("gate_enabled", True):
        if not isinstance(boundary, dict) or boundary.get("status") != "verified" or \
                not isinstance(boundary.get("evidence"), str) or not boundary["evidence"].strip():
            raise ValueError(where + ": enabled candidate needs a verified boundary with evidence")


def merge_candidates(base: dict, lanes: list[Path]) -> dict:
    if not isinstance(base.get("candidates"), list):
        raise ValueError("base registry lacks candidates array")
    merged = [dict(entry) for entry in base["candidates"]]
    by_symbol = {entry["symbol"]: entry for entry in merged}
    by_va = {int(entry["retail_va"], 16): entry for entry in merged}
    referents = {key: dict(value) for key, value in (base.get("referents") or {}).items()}
    extra, origins = [], {}
    for lane in lanes:
        data = read_json(lane_file(lane, "cl-candidates.json"))
        if data.get("binary") != "cl" or not isinstance(data.get("candidates"), list):
            raise ValueError(str(lane) + ": not a cl candidate registry")
        for entry in data["candidates"]:
            entry = dict(entry)
            validate(entry, str(lane))
            symbol, va = entry["symbol"], int(entry["retail_va"], 16)
            known = by_symbol.get(symbol)
            if known is not None:
                if known != entry:
                    raise ValueError("%s: lane %s conflicts with an existing entry for %s" %
                                     (symbol, lane, origins.get(symbol, "the base registry")))
                continue
            same_va = by_va.get(va)
            if same_va is not None:
                raise ValueError("0x%x: lane %s puts %s where %s already is" %
                                 (va, lane, symbol, same_va["symbol"]))
            by_symbol[symbol] = entry
            by_va[va] = entry
            origins[symbol] = str(lane)
            extra.append(entry)
        for binary, records in (data.get("referents") or {}).items():
            target = referents.setdefault(binary, {})
            for identity, record in records.items():
                if identity in target and target[identity] != record:
                    raise ValueError("referent %s conflicts between lanes" % identity)
                target[identity] = record
    extra.sort(key=lambda entry: (int(entry["retail_va"], 16), entry["symbol"]))
    result = {key: value for key, value in base.items() if key not in ("candidates", "referents")}
    result["candidates"] = merged + extra
    result["referents"] = referents
    return result


def candidate_diff(base: dict, merged: dict) -> list[str]:
    old = {entry["symbol"]: entry for entry in base["candidates"]}
    new = {entry["symbol"]: entry for entry in merged["candidates"]}
    lines = []
    for symbol in sorted(new):
        if symbol not in old:
            lines.append("+ " + symbol)
        elif old[symbol] != new[symbol]:
            lines.append("~ " + symbol)
    for symbol in sorted(set(old) - set(new)):
        lines.append("- " + symbol)
    return lines


def fragment_path(lane: Path) -> Path:
    if lane.is_file():
        return lane
    directory = lane / "config/reviews"
    files = sorted(directory.glob("cl5-*.json")) if directory.is_dir() else []
    if len(files) != 1:
        raise ValueError(str(lane) + ": expected exactly one config/reviews/cl5-*.json fragment")
    return files[0]


def merge_reviews(lanes: list[Path]) -> dict[str, dict]:
    fragments, owners = {}, {}
    for lane in lanes:
        path = fragment_path(lane)
        data = read_json(path)
        if data.get("schema_version") != 1 or data.get("binary") != "cl" or not isinstance(data.get("functions"), list):
            raise ValueError(str(lane) + ": invalid review fragment header")
        for item in data["functions"]:
            if not isinstance(item, dict) or "va" not in item or "source_path" not in item:
                raise ValueError(str(lane) + ": review record lacks va/source_path")
            key = "0x%x" % int(item["va"], 16)
            if key in fragments:
                raise ValueError("%s: claimed by both %s and %s" % (key, owners[key], lane))
            checks = item.get("checks")
            if not isinstance(checks, dict) or any(not isinstance(checks.get(rule), str) or not checks[rule].strip()
                                                   for rule in RULES):
                raise ValueError("%s %s: each of %s needs nonempty text" % (lane, key, ",".join(RULES)))
            owners[key] = str(lane)
            fragments[key] = item
    return fragments


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("candidates", "reviews"))
    parser.add_argument("--base", type=Path, default=ROOT / "config/cl-candidates.json")
    parser.add_argument("--lane", type=Path, action="append", required=True,
                        help="lane worktree root or a JSON file (repeatable)")
    parser.add_argument("--out", type=Path, help="candidates: destination (default: report only)")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "config/reviews",
                        help="reviews: destination directory (default: config/reviews)")
    parser.add_argument("--check", action="store_true", help="validate and report without writing")
    args = parser.parse_args(argv)
    try:
        if args.action == "candidates":
            base = read_json(args.base)
            merged = merge_candidates(base, args.lane)
            for line in candidate_diff(base, merged):
                print(line)
            print("candidates=%d added=%d" % (len(merged["candidates"]),
                                               len(merged["candidates"]) - len(base["candidates"])))
            if args.out and not args.check:
                args.out.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
                print("wrote " + str(args.out))
            return 0
        fragments = merge_reviews(args.lane)
        for key in sorted(fragments, key=lambda value: int(value, 16)):
            print("+ %s %s" % (key, fragments[key].get("symbol", "")))
        print("review functions=%d" % len(fragments))
        if not args.check:
            for lane in args.lane:
                source = fragment_path(lane)
                data = read_json(source)
                (args.out_dir / ("cl5-%s.json" % source.stem[len("cl5-"):])).write_text(
                    json.dumps(data, indent=2) + "\n", encoding="utf-8")
            print("wrote fragments to " + str(args.out_dir))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("integrate_lanes: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
