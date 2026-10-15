"""Conservative VC8 source-admission checks, independent of byte matching.

CLI: python tools/rulecheck.py matching --json result.json
     python tools/rulecheck.py matching --json -
Exit 0: every annotated function is rule-admitted (possibly zero functions).
Exit 1: blocking findings or MATCH-PENDING functions. Exit 2: invalid input.

JSON schema_version=1 identifies functions by binary, va, source_path and binds
them to source_sha256 plus scope_sha256 (all scanned C/C++/header files). The
gate must check admitted AND those identities/hashes against its own inputs.
RULE-ADMITTED says nothing about compiled bytes, referents, or banked counts.

This lexer/regex scan ports core patterns from E:/avp3-decomp/tools/rulecheck.py;
it does not parse/preprocess C++ or prove semantic rules. Therefore each function
also needs a trusted, explicit manual review in config/rule-exceptions.json.
Reviews cover R1/R2 canonical declarations and ownership, R4 real object layouts,
R13 actual vtables, R17 authentic locals/statements, and R18 source provenance.
The review evidence must cover included headers, macros/conditional branches,
ABI/signatures and source-line provenance where relevant. A signature cannot be
proved by public naming alone. Scanner omissions cannot waive these obligations.

Review entries: binary, va, source_path, source_sha256, scope_sha256, reviewer,
checks={Rn: {verdict: 'pass'|'exception', evidence: [{path, sha256, description}]}}.
Evidence paths are repository-relative, verified files (never remote URLs).
Each exception verdict additionally requires an exceptions entry with the same
identity/hashes, rule, allow=true, reason, reviewer and evidence, plus a matching
// RULE-EXCEPTION: Rn, byte-based reason comment inside that function. An allow
does not apply to another function or file-wide/header findings. No pending/stop
marker silently suppresses a rule. Changes to any scanned source invalidate all
reviews; this is intentionally conservative. Evidence is an attestation backed
by pinned files, not an automatic proof that its author's conclusions are true.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MATCH_RULES = ("R1", "R2", "R4", "R13", "R17", "R18")
EXTENSIONS = {".c", ".cpp", ".cxx", ".cc", ".h", ".hpp", ".hxx", ".inl"}
HEADERS = {".h", ".hpp", ".hxx", ".inl"}
ANNOTATION = re.compile(r"^\s*//\s*(FUNCTION|DATA):\s+([a-zA-Z0-9_]+)\s+(0x[0-9a-fA-F]+)\s*$", re.M)
TYPE = re.compile(r"\b(struct|class|union|enum)\s+([A-Za-z_]\w*)\s*(?::[^;{}]*)?\s*([;{])")
TYPEDEF = re.compile(r"\btypedef\b[^;{}]+;", re.S)
EXTERN = re.compile(r"\bextern\s+([^;{}()]+?)\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*;", re.S)
PLACEHOLDER = re.compile(r"\b(?:FUN_[0-9a-fA-F]+|DAT_[0-9a-fA-F]+|sub_[0-9a-fA-F]+|unk_\w+|local_\d+|param_\d+|[iupfdcbs]Var\d+|[iupfdcbs]Stack\w*|var\d+|field_0x[0-9a-fA-F]+|m_[Uu]nk\w*|[A-Za-z_]+_[0-9a-fA-F]{6,8})\b")
OFFSET_PATTERNS = (
    r"\(\s*(?:unsigned\s+)?(?:char|BYTE|uint8|uint8_t|u8|int8)\s*\*\s*\)\s*\w+(?:\s*(?:->|\.)\s*\w+)*\s*[+-]",
    r"\(\s*[\w:]+(?:\s+[\w:]+)*\s*[*&]+\s*\)\s*this\b",
    r"(?:reinterpret_cast|static_cast|const_cast)\s*<[^>]+>\s*\(\s*this\s*\)",
    r"\*\s*(?:\(\s*)?\(\s*[\w:]+(?:\s+[\w:]+)*\s*\*+\s*\)\s*\(\s*(?:\([^)]*\)\s*)?\w+\s*[+-]\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)",
    r"reinterpret_cast\s*<\s*(?:unsigned\s+)?(?:char|BYTE|uint8_t|u8)\s*\*\s*>\s*\([^)]*\)\s*[+-]",
    r"\(\s*(?:unsigned\s+)?(?:int|long|__int32|DWORD|uintptr_t|size_t)\s*\)\s*this\b",
)
PATTERNS = (
    *(("R4", pattern, "raw offset access or cast of this; recover the canonical object layout") for pattern in OFFSET_PATTERNS),
    ("R13", r"\bvirtual\b[^;{}]*\b(?:[Uu]nk\w*|[Pp]ad\w*|[Dd]ummy\w*|[Rr]eserved\w*|slot\d+|vf\d+|vfn\d+)\s*\(", "placeholder virtual slot; actual vtable evidence is required"),
    ("R17", r"\bvolatile\b", "volatile carrier requires evidence of authentic source use"),
    ("R17", r"\b(?:dummy\w*|fake\w*|padding\w*|pad\d+|unused\w*|probe\w*|forceRegister\w*)\b", "possible fake local, probe, or padding"),
    ("R17", r"\b(?:unsigned\s+char|BYTE|uint8_t)\s+\w+\s*\[[^\]]*\]\s*=\s*\{\s*(?:0x[0-9a-fA-F]+|\d+)\s*,\s*(?:0x[0-9a-fA-F]+|\d+)\s*,\s*(?:0x[0-9a-fA-F]+|\d+)", "byte-array payload requires evidence that it is data, not disguised source"),
    ("R18", r"\b(?:__asm|_asm|asm|INCLUDE_ASM|__emit|_emit)\b|\b__declspec\s*\(\s*naked\s*\)", "assembly/emitted-byte body is not admitted source without a proven original helper exception"),
    ("R22", r"\b(?:nullptr|constexpr|decltype|noexcept|thread_local|static_assert|char16_t|char32_t)\b|\benum\s+class\b|\bauto\s+[A-Za-z_]\w*\s*=", "construct is outside the VC8 dialect"),
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def blank_code(raw):
    """Blank comments/string/character literals preserving offsets and newlines.

    Return actual line comments separately: annotations inside strings or block
    comments must never manufacture function identity or exception permission.
    Preprocessor text stays visible so unsafe macro bodies are also checked.
    """
    out, comments, i = list(raw), [], 0
    while i < len(raw):
        start = i
        if raw.startswith("//", i):
            end = raw.find("\n", i)
            while end >= 0 and raw[start:end].rstrip("\r").endswith("\\"):
                end = raw.find("\n", end + 1)
            i = len(raw) if end < 0 else end
            comments.append((start, raw[start:i]))
        elif raw.startswith("/*", i):
            end = raw.find("*/", i + 2)
            if end < 0:
                raise ValueError("unterminated block comment")
            i = end + 2
        elif raw[i] in "\"'":
            quote = raw[i]
            i += 1
            while i < len(raw) and raw[i] != quote:
                i += 2 if raw[i] == "\\" else 1
            if i >= len(raw):
                raise ValueError("unterminated string/character literal")
            i += 1
        else:
            i += 1
            continue
        for k in range(start, i):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out), comments


def line_at(raw, offset):
    return raw.count("\n", 0, offset) + 1


def find_functions(source, findings):
    raw, code, comments = source["raw"], source["code"], source["comments"]
    functions = []
    annotations = []
    for offset, comment in comments:
        if re.match(r"//\s*(FUNCTION|DATA):", comment):
            match = ANNOTATION.fullmatch(comment)
            if not match or (match and match[2] not in {"cl", "c1", "c1xx", "c2", "link"}):
                findings.append(finding(source, offset, "ANNOTATION", "blocking", "malformed FUNCTION/DATA annotation"))
            else:
                annotations.append((offset, match))
    for index, (offset, match) in enumerate(annotations):
        if match[1] != "FUNCTION":
            continue
        end_limit = annotations[index + 1][0] if index + 1 < len(annotations) else len(code)
        start = offset + len(match[0])
        brace = code.find("{", start, end_limit)
        semi = code.find(";", start, end_limit)
        head = code[start:brace] if brace >= 0 else ""
        # Be conservative on declarations and constructs beyond this bounded reader.
        names = re.findall(r"((?:~?[A-Za-z_]\w*::)*(?:~?[A-Za-z_]\w*|operator\s*[^\s(]+))\s*\(", head)
        name = next((name for name in names if name not in {"__declspec", "sizeof", "if", "for", "while"}), None)
        valid = brace >= 0 and (semi < 0 or brace < semi) and name is not None and not head.lstrip().startswith("#")
        end = brace
        if valid:
            depth = 1
            while depth and end + 1 < end_limit:
                end += 1
                depth += (code[end] == "{") - (code[end] == "}")
            valid = depth == 0
        if not valid:
            findings.append(finding(source, offset, "ANNOTATION", "blocking", "annotation has no supported complete function definition"))
            end = end_limit - 1
        functions.append({"binary": match[2], "va": hex(int(match[3], 16)),
                          "source_path": source["path"], "source_sha256": source["sha256"],
                          "line": line_at(raw, offset), "end_line": line_at(raw, max(offset, end)),
                          "name": name or "?", "_start": offset, "_end": max(offset, end), "_valid": valid})
    return functions


def finding(source, offset, rule, severity, message):
    return {"source_path": source["path"], "line": line_at(source["raw"], offset),
            "rule": rule, "severity": severity, "message": message}


def evidence_valid(items, root):
    if not isinstance(items, list) or not items:
        return False
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("description"), str) or not item["description"].strip():
            return False
        path = item.get("path")
        if not isinstance(path, str) or Path(path).is_absolute():
            return False
        target = (root / path).resolve()
        if not target.is_relative_to(root.resolve()) or not target.is_file():
            return False
        if sha256(target.read_bytes()) != item.get("sha256"):
            return False
    return True


def load_policy(path):
    policy = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise ValueError("rule policy requires schema_version=1")
    if any(not isinstance(policy.get(key), list) for key in ("reviews", "exceptions")):
        raise ValueError("rule policy requires reviews and exceptions arrays")
    for collection in ("reviews", "exceptions"):
        for entry in policy[collection]:
            if not isinstance(entry, dict):
                raise ValueError("rule policy entries must be objects")
            required = ("binary", "va", "source_path", "source_sha256", "scope_sha256", "reviewer")
            if any(not isinstance(entry.get(key), str) or not entry[key].strip() for key in required):
                raise ValueError("rule policy entry lacks identity/hash/reviewer fields")
            if not re.fullmatch(r"0x[0-9a-fA-F]+", entry["va"]):
                raise ValueError("rule policy va must be hexadecimal")
            entry["va"] = hex(int(entry["va"], 16))
            if collection == "reviews" and not isinstance(entry.get("checks"), dict):
                raise ValueError("review requires checks object")
            if collection == "exceptions" and (entry.get("allow") is not True or entry.get("rule") not in MATCH_RULES or not isinstance(entry.get("reason"), str) or not entry["reason"].strip()):
                raise ValueError("exception requires allow=true, match rule and byte-based reason")
    return policy


def identity(entry):
    return tuple(entry[key] for key in ("binary", "va", "source_path", "source_sha256", "scope_sha256"))


def check(paths=None, *, root=ROOT, policy_path=None):
    """Return schema-v1 report. Callers still need independent compiled-byte gates."""
    root = Path(root).resolve()
    paths = [root / "matching"] if paths is None else [Path(path) for path in paths]
    files = set()
    for path in paths:
        path = path if path.is_absolute() else root / path
        path = path.resolve()
        if not path.exists():
            raise ValueError("scan path does not exist: " + str(path))
        if not path.is_relative_to(root):
            raise ValueError("scan path is outside repository: " + str(path))
        files.update(p.resolve() for p in path.rglob("*") if p.is_file() and p.suffix.lower() in EXTENSIONS) if path.is_dir() else files.add(path)
    sources = []
    pending = sorted(files)
    while pending:
        path = pending.pop(0)
        if not path.is_relative_to(root) or path.suffix.lower() not in EXTENSIONS:
            raise ValueError("unsupported/outside source path: " + str(path))
        data = path.read_bytes()
        raw = data.decode("utf-8-sig")
        code, comments = blank_code(raw)
        sources.append({"path": path.relative_to(root).as_posix(), "sha256": sha256(data), "raw": raw,
                        "code": code, "comments": comments, "header": path.suffix.lower() in HEADERS})
        # Follow quoted local includes so a review cannot survive edits to a
        # canonical header merely because it lives outside matching/. SDK angle
        # includes remain the pinned build/review evidence's responsibility.
        for include in re.finditer(r'^\s*#\s*include\s*"([^"\n]+)"', raw, re.M):
            if not re.match(r"\s*#\s*include\b", code[include.start():include.end()]):
                continue
            name = include[1]
            candidates = [path.parent / name, root / name, root / "matching" / name, root / "include" / name]
            target = next((candidate.resolve() for candidate in candidates if candidate.is_file()), None)
            if target is None:
                matches = [candidate for candidate in files if candidate.as_posix().endswith("/" + name.replace("\\", "/"))]
                target = matches[0] if len(matches) == 1 else None
            if target is None:
                raise ValueError("unresolved quoted include: " + name + " from " + str(path))
            if not target.is_relative_to(root) or target.suffix.lower() not in EXTENSIONS:
                raise ValueError("quoted include escapes repository or has unsupported extension: " + str(target))
            if target not in files:
                files.add(target)
                pending.append(target)
    sources.sort(key=lambda source: source["path"])
    scope = sha256(json.dumps([{key: source[key] for key in ("path", "sha256")} for source in sources], sort_keys=True, separators=(",", ":")).encode())
    policy_file = Path(policy_path) if policy_path is not None else root / "config/rule-exceptions.json"
    if not policy_file.is_absolute():
        policy_file = root / policy_file
    policy = load_policy(policy_file)
    findings, functions, types, externs = [], [], {}, {}
    for source in sources:
        functions.extend(find_functions(source, findings))
        for rule, pattern, message in PATTERNS:
            for match in re.finditer(pattern, source["code"], re.S):
                findings.append(finding(source, match.start(), rule, "blocking", message))
        for match in PLACEHOLDER.finditer(source["code"]):
            findings.append(finding(source, match.start(), "R7", "advisory", "unresolved/invented name: " + match[0]))
        for match in TYPE.finditer(source["code"]):
            types.setdefault(match[2], []).append((source, match))
            if match[3] == "{" and not source["header"]:
                findings.append(finding(source, match.start(), "R1", "blocking", "type definition must live in its canonical shared header"))
        for match in TYPEDEF.finditer(source["code"]):
            if not source["header"]:
                findings.append(finding(source, match.start(), "R1", "blocking", "typedef must live in its canonical shared header"))
        for match in EXTERN.finditer(source["code"]):
            externs.setdefault(match[2], []).append((source, match))
            if not source["header"]:
                findings.append(finding(source, match.start(), "R2", "blocking", "global extern declaration must live in its canonical shared header"))
        if Path(source["path"]).suffix.lower() == ".c":
            for match in re.finditer(r"\bfor\s*\(\s*(?:int|unsigned|long|short|char|float|double|size_t)\s+\w+|\b(?:class|namespace|template|bool|new|delete|try|catch)\b", source["code"]):
                findings.append(finding(source, match.start(), "R22", "blocking", "construct is outside MS C89; compile/dialect review still required"))
        for offset, comment in source["comments"]:
            if re.match(r"//\s*stop:", comment):
                findings.append(finding(source, offset, "STOP", "blocking", "parked/incomplete reconstruction cannot be admitted"))
    for name, declarations in types.items():
        definitions = [(source, match) for source, match in declarations if match[3] == "{"]
        kinds = {match[1] for _, match in declarations}
        if len(definitions) > 1 or ("class" in kinds and "struct" in kinds):
            for source, match in declarations:
                findings.append(finding(source, match.start(), "R1", "blocking", "duplicate type definition or class/struct mismatch: " + name))
    for name, declarations in externs.items():
        if len(declarations) > 1:
            for source, match in declarations:
                findings.append(finding(source, match.start(), "R2", "blocking", "global has multiple canonical declarations: " + name))
    identities = Counter((fn["binary"], fn["va"]) for fn in functions)
    duplicates = {key for key, count in identities.items() if count > 1}
    for fn in functions:
        if (fn["binary"], fn["va"]) in duplicates:
            findings.append({"source_path": fn["source_path"], "line": fn["line"], "rule": "ANNOTATION", "severity": "blocking", "message": "duplicate binary/VA annotation"})
        source = next(source for source in sources if source["path"] == fn["source_path"])
        body = source["code"][fn["_start"]:fn["_end"] + 1]
        # Scalar/pointer locals only: a once-named class object may have a real
        # destructor and is not mechanically an unused/fake local.
        for match in re.finditer(r"(?:[;{}]\s*|^\s*)(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:int|long|short|char|float|double|__int64|__int32)\s+\**\s*([A-Za-z_]\w*)\s*(?:=[^;]*|)\s*;", body):
            if len(re.findall(r"\b" + re.escape(match[1]) + r"\b", body)) == 1:
                findings.append(finding(source, fn["_start"] + match.start(1), "R17", "blocking", "unused scalar/pointer local requires authentic source evidence: " + match[1]))
    # Findings outside annotated functions conservatively affect every candidate,
    # including header/macro/type findings. They cannot be waived per function.
    for item in findings:
        owners = [fn for fn in functions if fn["source_path"] == item["source_path"] and fn["line"] <= item["line"] <= fn["end_line"]]
        item["function_va"] = owners[0]["va"] if len(owners) == 1 else None
    for fn in functions:
        fn["scope_sha256"] = scope
        matching_reviews = [review for review in policy["reviews"] if identity(review) == identity(fn)]
        checks = matching_reviews[0]["checks"] if len(matching_reviews) == 1 else {}
        review_required, allowed = [], []
        source = next(source for source in sources if source["path"] == fn["source_path"])
        comments = [comment for offset, comment in source["comments"] if fn["_start"] <= offset <= fn["_end"]]
        for rule in MATCH_RULES:
            review = checks.get(rule)
            if not isinstance(review, dict) or review.get("verdict") not in ("pass", "exception") or not evidence_valid(review.get("evidence"), root):
                review_required.append(rule)
                continue
            if review["verdict"] == "exception":
                exceptions = [entry for entry in policy["exceptions"] if identity(entry) == identity(fn) and entry["rule"] == rule]
                marker = any(re.search(r"//\s*RULE-EXCEPTION:\s*" + rule + r"\s*,\s*\S.+", comment) for comment in comments)
                if len(exceptions) != 1 or not marker or not evidence_valid(exceptions[0].get("evidence"), root):
                    review_required.append(rule)
                else:
                    allowed.append(rule)
        blockers = set()
        for item in findings:
            if item["severity"] != "blocking":
                continue
            local = item["source_path"] == fn["source_path"] and item["function_va"] == fn["va"]
            global_finding = item["function_va"] is None
            if local and item["rule"] in allowed:
                continue
            if local or global_finding or (item["rule"] == "ANNOTATION" and item["message"] == "duplicate binary/VA annotation" and fn["va"] == item["function_va"]):
                blockers.add(item["rule"])
        if not fn["_valid"]:
            blockers.add("ANNOTATION")
        fn["review_required"], fn["blocking_rules"], fn["allowed_exceptions"] = review_required, sorted(blockers), allowed
        fn["admitted"] = not blockers and not review_required
        fn["status"] = "RULE-ADMITTED" if fn["admitted"] else "MATCH-PENDING"
        for key in ("_start", "_end", "_valid"):
            del fn[key]
    global_blocks = [item for item in findings if item["severity"] == "blocking" and item["function_va"] is None]
    passed = not global_blocks and all(fn["admitted"] for fn in functions)
    return {"schema_version": 1, "scope_sha256": scope, "files": [{key: source[key] for key in ("path", "sha256")} for source in sources],
            "policy_sha256": sha256(policy_file.read_bytes()), "functions": functions, "findings": sorted(findings, key=lambda item: (item["source_path"], item["line"], item["rule"])),
            "passed": passed, "summary": {"functions": len(functions), "rule_admitted": sum(fn["admitted"] for fn in functions), "match_pending": sum(not fn["admitted"] for fn in functions), "advisory_findings": sum(item["severity"] == "advisory" for item in findings)},
            "limitations": ["Lexical heuristics do not prove semantic rules; pinned explicit manual reviews are required.", "Source-admission only: no byte, referent, boundary, or build-provenance verdict.", "Scan all project source/header dependencies; reviews attest included macros, layouts, ABI, and line provenance."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", help="repository-relative C/C++ files/directories (default matching)")
    parser.add_argument("--json", metavar="PATH", help="write structured report; '-' writes JSON to stdout")
    parser.add_argument("--policy", type=Path, help="explicit review/exception policy (default config/rule-exceptions.json)")
    args = parser.parse_args(argv)
    try:
        result = check(args.paths or None, policy_path=args.policy)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        result = {"schema_version": 1, "passed": False, "functions": [], "error": str(exc)}
        code = 2
    else:
        code = 0 if result["passed"] else 1
    if args.json:
        serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.json == "-":
            print(serialized, end="")
        else:
            try:
                Path(args.json).write_text(serialized, encoding="utf-8")
            except OSError as exc:
                print("rulecheck: cannot write JSON: " + str(exc), file=sys.stderr)
                return 2
    if args.json != "-":
        if "error" in result:
            print("rulecheck: " + result["error"], file=sys.stderr)
        else:
            for item in result["findings"]:
                print("{source_path}:{line}: {rule} ({severity}) {message}".format(**item))
            for fn in result["functions"]:
                print("{source_path}:{line}: {status} {binary} {va} {name}".format(**fn))
            print("Rule-admitted: {rule_admitted}/{functions}; MATCH-PENDING: {match_pending}; naming/advisory: {advisory_findings}.".format(**result["summary"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
