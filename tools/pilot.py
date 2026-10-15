"""Inspect the curated cl pilot evidence catalogue; this is not a byte gate.

The catalogue deliberately records unresolved boundaries and ownership. A public
start (or the gap to the next public) never supplies an admitted function size.
Run `python tools/pilot.py check` for structural consistency and `list` for a
bounded summary. The tool does not compile candidates or award match counts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


DEFAULT_CATALOGUE = Path(__file__).resolve().parents[1] / "config" / "cl-pilot.json"


def address(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def validate(catalogue):
    """Check evidence-record consistency, not the truth of uninspected claims."""
    errors = []
    if catalogue.get("schema_version") != 1:
        errors.append("unsupported schema_version")
    if catalogue.get("binary") != "cl":
        errors.append("catalogue binary must be cl")
    lanes = {lane["id"] for lane in catalogue.get("lanes", [])}
    identities = set()
    extents = []
    for function in catalogue.get("functions", []):
        name = function.get("name", "<missing>")
        if name in identities:
            errors.append(f"{name}: duplicate identity")
        identities.add(name)
        if function.get("lane") not in lanes:
            errors.append(f"{name}: unknown lane")
        if function.get("score") is not None:
            errors.append(f"{name}: evidence-only catalogue must leave score null")
        boundary = function.get("boundary", {})
        if boundary.get("status") == "proven":
            try:
                start = address(function["va"])
                size = address(boundary["size"])
                if size <= 0:
                    raise ValueError("nonpositive size")
                extents.append((start, start + size, name))
            except (KeyError, TypeError, ValueError):
                errors.append(f"{name}: proven boundary needs positive size and VA")
            methods = boundary.get("methods", [])
            if "bounded-disassembly" not in methods:
                errors.append(f"{name}: proven boundary lacks bounded disassembly")
            if not boundary.get("terminal") or not boundary.get("evidence"):
                errors.append(f"{name}: proven boundary needs terminal and evidence record")
        elif boundary.get("size") is not None:
            errors.append(f"{name}: unresolved boundary cannot supply function size")
        if function.get("match_ready"):
            if boundary.get("status") != "proven":
                errors.append(f"{name}: ready function needs proven boundary")
            if function.get("referents", {}).get("status") != "resolved":
                errors.append(f"{name}: ready function has unresolved referents")
            if function.get("abi", {}).get("status") != "resolved":
                errors.append(f"{name}: ready function has unresolved ABI")
    extents.sort()
    for previous, current in zip(extents, extents[1:]):
        if current[0] < previous[1]:
            errors.append(f"{current[2]} overlaps {previous[2]} (represent aliases in one record)")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("list", "check"))
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--limit", type=int, default=40)
    args = parser.parse_args(argv)
    try:
        catalogue = json.loads(args.catalogue.read_text(encoding="utf-8"))
        errors = validate(catalogue)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"pilot: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors[:50]:
            print(f"pilot: {error}", file=sys.stderr)
        return 1
    if args.command == "check":
        print(f"Evidence catalogue consistent: {len(catalogue['functions'])} functions; no match counts awarded")
        return 0
    print("VA         size  lane                 symbol / boundary status")
    for function in catalogue["functions"][:max(0, min(args.limit, 50))]:
        boundary = function["boundary"]
        size = str(boundary.get("size") or "?")
        print(f"{function['va']:10} {size:>5} {function['lane']:<20} {function['name']} / {boundary['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
