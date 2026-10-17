# VC8 candidate harness

`python tools/match.py build --binary cl` compiles annotated matching units
with VC8 `/GL`, links each unit and its explicit real source dependencies with
`/LTCG`, and writes a fresh ignored `build/cl/<UUID>/manifest.json`. It does
not admit functions or update banked counts. The gate owns admission.

`match --binary cl --unit matching/cl/unit.cpp` additionally writes byte and
ordered-referent comparisons to `comparison.json`. `diff --binary cl --function DECORATED_NAME`
uses the unit registered in `config/gate-allow.json` and shows at most 24
instructions from each side. When every ordered operand encoding and retail
identity binding agrees, comparison resolves those operands before comparing
bytes. Missing bindings or different targets remain unresolved or mismatched;
the diagnostic score then uses raw bytes. These comparisons do not admit source
or replace the gate's independent checks.

The build interface also accepts `--output-dir ABS --manifest ABS
--build-id UUID`. A supplied output directory must be empty; stale files are
never reused or deleted. A failed build writes `status: failed` and an error
to its manifest, then exits nonzero. An empty candidate census writes a
`status: built` manifest with zero candidates and no compiler commands.

Annotations precede the function definition:

```cpp
// FUNCTION: cl 0x00401234
// SYMBOL: ?example@@YAHH@Z
int example(int value) { return value; }
```

`SYMBOL` is optional when the plain discovery object's symbols identify one
unique function with the source spelling. Overloads and ambiguous member
names require the explicit decorated name. Discovery objects are compiled
with `/GL-` only to enumerate symbols and included headers. Their bytes are
never extracted as candidates. Source files and included headers are hashed
before the `/GL` compile and checked again after linking. Source text is
compiled in place; no line directives or synthetic source wrappers are added.

`config/<binary>.json` supplies `flags.compile`, `flags.link`, and optionally
`dependencies: {"matching/cl/unit.cpp": ["matching/cl/callee.cpp"]}`. The
registry's per-candidate `dependencies` and `roots` are also honored.
Per-unit `units: {"matching/cl/unit.cpp": {"compile_flags": ["/O1"]}}`
appends experimental controls after the common compile flags; optional
`remove_compile_flags` removes exact common switches first. The final `/GL`
and output path remain controlled by the harness. `--toolchain sp1` or `rtm`
selects a pinned toolchain for one isolated build without changing config.
Per-unit `link_flags` are combined for the primary source and every explicitly
linked dependency, so genuine API import libraries accompany their users.

Candidate descriptors are combined from `config/gate-allow.json` and
`config/<binary>-candidates.json`. Duplicate symbol or retail address entries
are rejected. The gate independently loads and verifies those descriptors.

All dependency units are compiled with `/GL`; missing definitions fail the link.
No synthetic callee stubs or retail code are linked. The default experimental
link is a `/DLL /NOENTRY /OPT:NOREF,NOICF` image with `/INCLUDE` roots.
Keeping these roots does not reproduce retail's whole-program custom calling
conventions, caller context, inlining budgets, or PGO profile.

The toolchain inventory in `config/toolchains.json`, when present, selects
and verifies every pinned tool/library file before and after the build.
Until that inventory exists, the installed toolchain root is usable for
diagnostic builds but explicitly marked unpinned. Ambient `CL`, `_CL_`,
`LINK`, and `_LINK_` options are removed.

The manifest records hashes of source/include/config inputs, toolchain files,
actual command arguments and logs, `/GL` objects, linked images, and MAPs.
Each candidate records its annotation/source span, lexical function hash,
full source hash, image/span hashes, and decoded ordered referents.
References include internal relative branches, external relative branches,
HIGHLOW relocations, and absolute memory operands. Unsupported relocations or
undecodable bytes leave referents unresolved. MAP names provide candidate
function/data identities; actual PE IAT slots supply import identities. Literal
bindings require exact bounded content hashes. The gate independently verifies
import DLL/name and both literal payloads, read-only storage, final terminators,
and ownership by the genuine source literal token. Referenced data bytes are
never counted as source code.

Named SDK-member references use a single canonical aggregate symbol plus a
member name, offset, width, and compiler layout witness. The scanner distinguishes
an immediate/LEA pointer to the whole object from a memory access to its first
field at offset zero. Indexed or oversized member accesses stay unresolved.
Only the gate independently validates the witness, SDK field layout, source and
retail base identities, bounds, actual access width, and matching rule review.

MAP starts establish locations, not exact function ends. Registered candidate
sizes and boundary evidence come from `config/gate-allow.json`. Without those,
the next MAP symbol supplies only an unverified inspection span; a function
with no following symbol has size zero. Such candidates cannot be admitted.
The harness never prints the gate's green line.

## Project adapter

The tools read one project's policy from the `"project"` block of
`config/project.json`; `matchlib.ADAPTER_DEFAULTS` supplies every key it omits,
and an unknown key is an error. This repository's block restates the policy
keys at their default values.

| key | default | meaning |
|---|---|---|
| `binaries` | keys of `"binaries"` | ordered targets the gate, audit, rule checker and pilot accept |
| `compiler`, `linker` | `cl.exe`, `link.exe` | executables under the toolchain's `bin/` |
| `pdb_required` | `true` | retail identity must pin one RSDS record; `false` pins none (a pinned one is still checked) |
| `gl` | `true` | compile with `/GL` and link with `/LTCG`; `config/<binary>.json` may set `"gl"` for a binary or under `"units"` for one unit |
| `annotation` | `FUNCTION`/`DATA` form | `pattern` with named groups `binary`, `va` and optionally `kind`; `prefix` marks comments that must parse; `function` is the `kind` that annotates functions |
| `link_flags` | `["/OPT:NOREF,NOICF"]` | base candidate link options |
| `toolchain_pins`, `toolchain_core` | VC8 file names | files `probe_toolchain.py inventory` pins; files every pinned toolchain must contain |
| `rtm` | `out: ref-rtm`, `seven_zip: 7z` | `rtm.py` defaults; `iso` and `out` are relative to the primary checkout; `platform_sdk` defaults to the toolchain root's `PlatformSDK` |

A unit without `/GL` builds a plain `object` candidate; a group with no `/GL`
object links without `/LTCG`. The gate checks each compile's `/GL` use against
its unit's configured mode. `primary_checkout` and `symbols_root` are optional:
the primary checkout is derived from git worktree metadata and the symbol store
defaults to its `symbols/`. `probe_toolchain.py layout --type T --field F ...
[--header H] [--binary B]` builds a compiler layout witness for any aggregate.
