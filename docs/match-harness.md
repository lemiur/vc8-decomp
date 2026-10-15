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
identities; independently verified retail identities remain the gate's job.

MAP starts establish locations, not exact function ends. Registered candidate
sizes and boundary evidence come from `config/gate-allow.json`. Without those,
the next MAP symbol supplies only an unverified inspection span; a function
with no following symbol has size zero. Such candidates cannot be admitted.
The harness never prints the gate's green line.
