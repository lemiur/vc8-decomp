# Visual C++ 2005 SP1 matching decompilation

Targets: the x86-hosted `cl.exe`, `c2.dll`, `c1.dll`, `c1xx.dll`, and optional `link.exe` from Visual C++
2005 SP1. See [VC8_DECOMP_PLAN.md](VC8_DECOMP_PLAN.md) for phase order and [AGENTS.md](AGENTS.md) for source,
verification, and collaboration rules.

The matching infrastructure is operational; the compiler-driver reconstruction is partial. A public
PDB gives symbol identities, but a public
symbol's start alone does not establish its full byte extent or source-unit ownership.

Local Microsoft binaries, public PDBs, the RTM ISO, decompiler output, and build artifacts are ignored and
must never be committed. `config/project.json` locates the installed toolchain and primary symbol store.
Each worker uses its own build directory and resolves shared read-only inputs through that configuration.

Run the verified-source gate from a clean checkout:

```powershell
python tools/gate.py --binary all --clean
python tools/report.py --gate build/gate/latest.json --evidence-dir build/evidence --output-dir build/reports
```

The gate performs fresh VC8 compilation and LTCG linking, checks source-rule reviews, resolves ordered
references independently, and compares the complete substituted images. The current source census and
per-unit experimental profiles live in `config/cl-candidates.json` and `config/cl.json`. Unadmitted
candidates remain explicit open work. `python tools/rulecheck.py matching` reports those as MATCH-PENDING
and returns nonzero; the gate requires rule admission for each selected function individually.

Infrastructure checks use `python -m unittest discover -s tests`. Source reconstruction is verified by
retail comparison and the byte gate, rather than behavioral tests. `tools/symbols.py`, `tools/unitmap.py`,
and `tools/evidence.py` provide identity-checked, bounded evidence. Generated reports and raw Ghidra
exports are local ignored artifacts. Ghidra 12.0.1 is used with its version recorded; inferred Ghidra body
ranges are not automatically accepted as exact function boundaries.

`config/toolchains.json` pins SP1 and the RTM toolchain extracted locally from the supplied ISO. RTM uses
the installed Platform SDK. Observed SxS CRT dependencies are recorded separately from private payloads.
The actual pilot A/B results do not yet distinguish the compiler that built retail; matching one leaf is
not a general bootstrap or flag verdict.

Only an actual clean compiler build, independent byte/referent comparison, source-rule admission, and a
whole-image hash gate can bank reconstructed source. An all-fallback hash check proves the gate's identity
path and represents zero source coverage. A splice gate is progress evidence; the final milestone remains
a complete source rebuild that reproduces the retail hash.
