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

The exporter uses `--workers 1..4` independent native decompilers (default four),
with at most that many functions active. It completes tables, recorded ranges,
references, and selected assembly before decompilation, marked by
`metadata-complete.json`. A metadata marker does not imply decompilation finished.
Every selected function receives a JSON identity/result record, including errors
and its independent timeout verdict. `decompile-status.tsv` is flushed as results
arrive; the final function table remains in address order.

Reuse a completed saved import without reanalysis or project modification:

```
python tools/evidence.py ghidra-export --binary cl --source-run SAVED_IMPORT_RUN --ghidra-home GHIDRA_DIR --java-home JDK_DIR --workers 4
```

This uses `-process -noanalysis -readOnly`, pins the source manifest hash and
inherited PDB provenance, and writes a fresh output directory with current script
hashes. The loaded program's executable hash must match the configured retail
image. Running imports cannot be reused: Ghidra saves a newly imported program
after its post-scripts return, so stopping an import during body export may lose
its in-memory analysis. Never stop such an import just to release a project lock.
Each invocation copies Java scripts into its fresh ignored `script-snapshot/`,
hashes those exact bytes, and invokes that snapshot. Checkout rebases cannot
change the scripts used by an already launched run.

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
- `functions/VA.c`, `.asm`, and `.json`: individual hints, assembly, and result/identity metadata. `--limit N` bounds
  body exports while preserving the full table; default zero exports all bodies.
- `headless.log`, `pdb-status.json`, `export-complete.json`: execution evidence.

Ghidra analysis boundaries/signatures remain inferred evidence. Exporting a body
does not establish a contiguous complete retail function, a source signature, or
gate admission. All exports and projects are ignored and must never be committed.

## Bounded lookup index

`tools/evidence_index.py` builds the ignored SQLite index at
`E:/vc8-decomp/build/evidence/lookup.sqlite`. Each binary is replaced atomically;
other binaries remain available. It joins exact addresses, preserves public
aliases and their actual DBI ownership evidence, indexes inclusive Ghidra body
ranges and recorded references, and links hint/assembly/result files. A datum
inside a DBI contribution gets contribution evidence rather than an invented
source owner or table type.

```
python tools/evidence_index.py build --binary c2 --run COMPLETED_EXPORT_RUN
python tools/evidence_index.py lookup --binary c2 --symbol "EXACT_PUBLIC_SPELLING"
python tools/evidence_index.py lookup --binary c1xx --contains "AliasHash"
python tools/evidence_index.py lookup --binary cl --va 0x412570
```

`--rva` accepts an RVA; `--va` accepts a VA. Queries show up to five entries,
three public aliases, and four references per direction, capped at 60 lines with
long names clipped. `--limit` and `--max-lines` may reduce that output. Reference
order is Ghidra's recorded order, not an independently resolved relocation verdict.
Full identities remain in the local database; exports remain the underlying
evidence. Complete result records must match the retail hash and RVA. Failed
updates preserve the previous index.

`build --allow-pending` explicitly permits a running export only after its complete
metadata marker matches the retail identity. Such a lookup is a dated partial
snapshot, including any completed per-function results available during indexing.
Rebuild after export completion for final failure/timeout status. Original serial
exports did not capture per-function timeout causes; the lookup reports that as
`not captured` instead of inferring a verdict.
