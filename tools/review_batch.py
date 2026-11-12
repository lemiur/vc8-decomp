"""Import matching-lane review fragments into the tracked rule policy.

Each lane worker writes ``config/reviews/cl5-<lane>.json`` with per-function
R1/R2/R4/R13/R17/R18 checks. This tool freezes those fragments into one batch
file, re-scopes the already reviewed functions that are unchanged in the current
tree, and rewrites the ``reviews`` array of ``config/rule-exceptions.json``.

The batch file and every review entry are bound to the current rulecheck scope
and to each function's declaration-through-closing-brace source hash, so the
gate can reject stale reviews. Functions that are new or whose body changed and
that no fragment covers make the import fail; they stay MATCH-PENDING.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import rulecheck  # noqa: E402

MATCH_RULES = tuple(rulecheck.MATCH_RULES)
REVIEWER = "independent audit lane /root/audit"
BATCH = "config/reviews/cl-fifth-batch.json"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def fragment_files(root: Path) -> list[Path]:
    return sorted((root / "config/reviews").glob("cl5-*.json"))


def merge_fragments(root: Path, paths: list[Path]) -> dict:
    """Validate lane fragments and merge their function records."""
    entries, positions, problems, fragments = {}, {}, [], []
    layout_witnesses, entry_alias_proofs = [], []
    for path in paths:
        data = read_json(path)
        if data.get("schema_version") != 1 or data.get("binary", "cl") != "cl" or not isinstance(data.get("functions"), list):
            problems.append(str(path) + ": invalid lane review header")
            continue
        for key, target in (("layout_witnesses", layout_witnesses), ("entry_alias_proofs", entry_alias_proofs)):
            for record in data.get(key, []) or []:
                if isinstance(record, dict) and "path" in record and "sha256" in record:
                    target.append({"path": record["path"], "sha256": record["sha256"]})
                else:
                    problems.append(str(path) + ": malformed " + key + " record")
        fragments.append({"path": path.relative_to(root).as_posix(), "sha256": sha256(path.read_bytes())})
        for item in data["functions"]:
            if not isinstance(item, dict) or "va" not in item or "source_path" not in item:
                problems.append(path.name + ": function record lacks va/source_path")
                continue
            key = (item["source_path"], "0x%x" % int(item["va"], 16))
            if key in positions:
                problems.append("%s %s: function reviewed in both %s and %s" % (key[0], key[1], positions[key], path.name))
                continue
            positions[key] = path.name
            checks = item.get("checks")
            if not isinstance(checks, dict) or any(not isinstance(checks.get(rule), str) or not checks[rule].strip()
                                                   for rule in MATCH_RULES):
                problems.append("%s %s: each of %s needs a nonempty check text" % (key[0], key[1], ",".join(MATCH_RULES)))
                continue
            record = {"va": key[1], "symbol": item.get("symbol", ""), "source_path": item["source_path"],
                      "source_span": item.get("source_span", {}), "size": item.get("size"),
                      "reviewer": item.get("reviewer") or data.get("reviewer")
                      or ("matching lane " + str(data.get("lane", "unknown"))),
                      "checks": {rule: checks[rule] for rule in MATCH_RULES}}
            entries[("cl", int(key[1], 16))] = record
    if problems:
        raise ValueError("; ".join(problems))
    return {"entries": entries, "fragments": fragments,
            "layout_witnesses": layout_witnesses, "entry_alias_proofs": entry_alias_proofs}


def build_batch(root: Path, fragments: list[Path]) -> dict:
    merged = merge_fragments(root, fragments)
    scanned = rulecheck.check([root / "matching"], root=root)
    scope = scanned["scope_sha256"]
    functions = {(fn["binary"], int(fn["va"], 16)): fn for fn in scanned["functions"]}
    policy = read_json(root / "config/rule-exceptions.json")
    prior = {(entry["binary"], int(entry["va"], 16)): entry for entry in policy["reviews"]}
    registry = read_json(root / "config/cl-candidates.json")
    enabled = {(entry["unit"], int(entry["retail_va"], 16)) for entry in registry["candidates"]
               if entry.get("binary") == "cl" and entry.get("gate_enabled", True)}
    registered = {(entry["unit"], int(entry["retail_va"], 16)) for entry in registry["candidates"]
                  if entry.get("binary") == "cl"}

    records, borrowed, uncovered = [], [], []
    for key, fn in sorted(functions.items()):
        reviewed = merged["entries"].get(key)
        if reviewed is not None:
            if reviewed["source_path"] != fn["source_path"]:
                raise ValueError("%s 0x%x: fragment source_path differs from scanned source" %
                                 (fn["source_path"], int(fn["va"], 16)))
            if (reviewed["source_path"], int(reviewed["va"], 16)) not in registered:
                raise ValueError("%s 0x%x: reviewed function has no candidate registry entry" %
                                 (reviewed["source_path"], int(reviewed["va"], 16)))
            reviewed = dict(reviewed, source_sha256=fn["source_sha256"])
            records.append(reviewed)
            continue
        previous = prior.get(key)
        if previous is not None and previous.get("source_sha256") == fn["source_sha256"] and previous.get("checks"):
            borrowed.append(previous)
            continue
        if (fn["source_path"], int(fn["va"], 16)) in enabled:
            uncovered.append("%s 0x%x %s" % (fn["source_path"], int(fn["va"], 16), fn.get("name", "")))
    if uncovered:
        raise ValueError("admission candidates changed or new without a lane review: " + "; ".join(uncovered))
    return {"scope": scope, "records": records, "borrowed": borrowed, "fragments": merged["fragments"],
            "layout_witnesses": merged["layout_witnesses"], "entry_alias_proofs": merged["entry_alias_proofs"]}


def write_policy(root: Path, fragments: list[Path]) -> dict:
    build = build_batch(root, fragments)
    batch = {"schema_version": 1, "reviewer": REVIEWER, "review_round": "fifth",
             "scope_sha256": build["scope"],
             "authority_limit": "Source-rule approval only; the fresh complete gate alone banks compiled functions/bytes.",
             "fragments": build["fragments"],
             "layout_witnesses": build["layout_witnesses"],
             "entry_alias_proofs": build["entry_alias_proofs"],
             "reviewed_functions": build["records"],
             "unchanged_prior_rounds": build["borrowed"]}
    batch = json.loads(json.dumps(batch))
    for item in batch["reviewed_functions"]:
        item.pop("source_sha256", None)
    batch_path = root / BATCH
    batch_text = json.dumps(batch, indent=2, sort_keys=True) + "\n"
    batch_path.write_text(batch_text, encoding="utf-8")
    batch_sha = sha256(batch_path.read_bytes())

    entries = []
    for item in build["records"]:
        entries.append({"binary": "cl", "va": item["va"], "source_path": item["source_path"],
                        "source_sha256": item["source_sha256"], "scope_sha256": build["scope"],
                        "reviewer": item.get("reviewer") or REVIEWER,
                        "checks": {rule: {"verdict": "pass", "evidence": [{
                            "path": BATCH, "sha256": batch_sha,
                            "description": "%s review for %s in the frozen current source/header scope." %
                                           (rule, item.get("symbol") or item["va"])}]} for rule in MATCH_RULES}})
    for entry in build["borrowed"]:
        entry = dict(entry)
        entry["scope_sha256"] = build["scope"]
        entries.append(entry)
    entries.sort(key=lambda entry: (entry["source_path"], int(entry["va"], 16)))
    policy = read_json(root / "config/rule-exceptions.json")
    policy["reviews"] = entries
    temporary = (root / "config/rule-exceptions.json").with_suffix(".tmp")
    temporary.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(root / "config/rule-exceptions.json")
    return {"scope_sha256": build["scope"], "reviews": len(entries),
            "reviewed": len(build["records"]), "reused": len(build["borrowed"]), "batch": str(batch_path)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--fragment", type=Path, action="append", help="lane review fragment (repeatable; default cl5-*.json)")
    parser.add_argument("--check", action="store_true", help="validate and report without writing")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        fragments = [path if path.is_absolute() else root / path for path in (args.fragment or [])] or fragment_files(root)
        if not fragments:
            raise ValueError("no cl5-*.json lane review fragments found")
        if args.check:
            build = build_batch(root, fragments)
            print("scope=%s reviewed=%d reused=%d fragments=%d" %
                  (build["scope"], len(build["records"]), len(build["borrowed"]), len(build["fragments"])))
            return 0
        result = write_policy(root, fragments)
        print("scope=%s reviews=%d reviewed=%d reused=%d" %
              (result["scope_sha256"], result["reviews"], result["reviewed"], result["reused"]))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("review_batch: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
