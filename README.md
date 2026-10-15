# Visual C++ 2005 SP1 matching decompilation

Targets: the x86-hosted `cl.exe`, `c2.dll`, `c1.dll`, `c1xx.dll`, and optional `link.exe` from Visual C++
2005 SP1. See [VC8_DECOMP_PLAN.md](VC8_DECOMP_PLAN.md) for phase order and [AGENTS.md](AGENTS.md) for source,
verification, and collaboration rules.

The repository is being bootstrapped. Infrastructure availability is established by running its commands;
the plan is not a claim of completed reconstruction. A public PDB gives symbol identities, but a public
symbol's start alone does not establish its full byte extent or source-unit ownership.

Local Microsoft binaries, public PDBs, the RTM ISO, decompiler output, and build artifacts are ignored and
must never be committed. `config/project.json` locates the installed toolchain and primary symbol store.
Each worker uses its own build directory and resolves shared read-only inputs through that configuration.

Only an actual clean compiler build, independent byte/referent comparison, source-rule admission, and a
whole-image hash gate can bank reconstructed source. An all-fallback hash check proves the gate's identity
path and represents zero source coverage. A splice gate is progress evidence; the final milestone remains
a complete source rebuild that reproduces the retail hash.
