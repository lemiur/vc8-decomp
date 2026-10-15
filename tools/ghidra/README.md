# Retail evidence exporter

`python tools/evidence.py disasm|xref|class --binary cl --symbol SYMBOL` consumes
the validated PDB map at the configured primary checkout's
`build/evidence/cl.symbols.json`. It verifies the binary hash before reading.
Names must be exact PDB spellings; an RVA or VA is also accepted. Output defaults
to, and is capped at, 60 lines; `--max-bytes` limits disassembly display bytes.
Python packages `capstone` and `pefile` are required.

Publics prove starts, not function lengths. Disassembly stops at the next public,
section end, explicit map size, or byte limit, whichever comes first. These are
display bounds. The xref command scans executable sections linearly and reports
direct immediates and absolute memory operands; it cannot prove indirect targets
or distinguish every embedded datum. The class command provides related public
spellings and aligned non-code pointer candidates, with unresolved layout and
vtable membership explicitly stated.

Run a fresh local import/export with:

```
python tools/evidence.py ghidra-import --binary cl --ghidra-home GHIDRA_DIR --java-home JDK_DIR --pdb LOCAL_PDB
```

`--pdb` requires its hash to equal the validated map's PDB hash. Automatic PDB
analyzers are disabled to prevent symbol-server lookup; PrepareEvidence applies
only the supplied local PDB through Ghidra's universal reader. The Java launcher
uses Ghidra's LaunchSupport VM options and headless entry point directly, avoiding
Windows batch expansion of compiler installation paths containing parentheses.

The requested analyzer is 12.1.3. The locally found and executed installation is
12.0.1 at `E:/Downloads/ghidra_12.0.1_PUBLIC_20260114/ghidra_12.0.1_PUBLIC`.
Every run records the exact version and the plan deviation. No download is needed.

Each run writes a unique isolated project and outputs under the primary checkout's
ignored `build/ghidra/BINARY/RUN_ID/`. A manifest pins binary, PDB and symbol-map
hashes, command, analyzer version, exit code, and completion status. A run is
complete only with script completion outputs and the requested PDB status.
An analysis timeout is recorded separately and changes the manifest status to
`complete_with_analysis_timeout`; successful exports can still contain incomplete
analysis evidence in that case.
Failed runs remain for diagnosis; no stale output is reused.

- `create-functions.tsv`: public starts, creation status, conflicts with a
  containing function, and explicit start/body provenance. Existing containing
  bodies are never split to force PDB starts.
- `functions.tsv`: analyzer names, entry addresses, total body bytes, range count,
  signature provenance, and decompilation status. Unit ownership is unresolved in
  this table; consume actual DBI contributions from the symbol map separately.
- `ranges.tsv`: every inclusive body range, including noncontiguous bodies.
- `references.tsv`: Ghidra's recorded outgoing reference sites/types/targets.
- `functions/VA.c` and `.asm`: individual hints and assembly. `--limit N` bounds
  body exports while preserving the full table; default zero exports all bodies.
- `headless.log`, `pdb-status.json`, `export-complete.json`: execution evidence.

Ghidra analysis boundaries/signatures remain inferred evidence. Exporting a body
does not establish a contiguous complete retail function, a source signature, or
gate admission. All exports and projects are ignored and must never be committed.
