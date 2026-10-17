# Progress and score history

`python tools/report.py` writes deterministic per-binary JSON and `progress.md`
under ignored `build/reports/`. It consumes local `build/gate/latest.json`, the
tracked `ledger.tsv`, and shared public-symbol maps from
the primary checkout's `build/evidence/` (`config/project.json`'s
`primary_checkout`, else derived from git worktree metadata). It does not
run the gate, change a baseline, or update the tracked ledger. Use `--gate`,
`--ledger`, `--evidence-dir`, `--output-dir`, and `--project` to select inputs.
Repeat `--binary cl` to limit selected binaries.

## Banked coverage

The producer is `tools/gate.py`, schema version 1, `gate_kind: retail-splice`.
The report requires aggregate `status: GREEN`, no errors, the printed `BANKED`
authority text, and a GREEN record for the selected binary. It requires equal
input, all-fallback and complete-output SHA-256 values. Admission counts must
agree with the admission list and the summed function sizes. Each admitted
range must have exact bytes, resolved ordered referents, passed source rules,
verified boundary evidence, a source hash, the gate run's build ID, and a
hashed linked image in its artifact provenance. Duplicate or overlapping
ranges, failed admission checks, stale build IDs, and inconsistent counts
produce exit status 2. Candidate scores cannot authorize coverage.

Reports are snapshots of the identified gate run. JSON includes its run ID,
timestamp, authority text, input/output hashes, absolute report path and report
file SHA-256. A report does not attest that the working tree still equals that
run. Rerun the clean gate before making a present-source claim. A splice gate
does not prove a full source relink.

A successful all-fallback gate has zero matched functions and zero source
bytes. Missing gate evidence produces `UNAVAILABLE` with null counts; it does
not invent a zero-result gate. Unselected `fallback-verified` records have no
banked coverage snapshot. A RED aggregate authorizes no banking even if an
earlier per-binary operation succeeded.

The source-byte denominator supplied by this gate is the complete retail file,
including headers and data, and JSON labels it `complete-retail-file`.
Source bytes divided by that size are not a code-only percentage. Public PDB
aliases and start addresses do not establish function lengths, so the current
function denominator and function percentage remain null. A future inventory
may explicitly certify `coverage_denominator: {boundaries_complete: true,
functions: N, code_bytes: N, caveats: [...]}`; current public-start maps do not
make this assertion. Do not turn the next public address into a function end.

## Tracked achieved-source history

`ledger.tsv` initially contains only its header. It is not a function census
and never supplies banked counts. Its tab-separated columns are:

`observation_id observed_at binary va symbol function_source_sha256 unit build_id score bytes_exact referents rules gate_sha256`

`python tools/ledger.py record-gate build/gate/latest.json` records only source
actually admitted by a GREEN gate. All-fallback adds no rows. Per-function
source identity is required separately from the gate's whole-unit hash.
Canonical function spans use UTF-8 text, normalized newline separators and no
final newline. Gate `observed_at` is used for ordering; older producer records
without it require explicit `--observed-at TIME`. The gate report SHA-256 is
persisted with the observation, so history survives cleaning `build/` or
cloning the repository. Retain the ignored gate artifacts locally when an
independent re-audit of that particular build is needed.

Only exact, rule-admitted, referent-resolved observations may be written to the
tracked ledger. The latest successful observation per binary, address and
function-source hash is retained; repeated gates of unchanged source do not
grow the ledger indefinitely. Observation IDs hash canonical content.
`python tools/ledger.py import OTHER.tsv ...` merges histories by identity,
rejects missing inputs and conflicting observations for the same function/build, and compacts
achieved source revisions. Regenerate history and reports during integration;
do not replace a concurrent ledger wholesale. An import of TSV history is a
history merge, not an independent rerun of its original byte gate.

`python tools/ledger.py summary` prints at most 20 concise score rows. Use
`--binary`, `--limit` (0–40), and `--output PATH.json` for filtering or a complete
machine-readable export without a bulk terminal dump. The calculation uses:

- **current**: the latest observed score;
- **best**: the best score for the current function-source hash;
- **historical**: the best score across all observed source hashes.

`historical > best` marks a lost match. An unchanged-source current dip does
not reset best. Tracked achieved observations are 100; lower or pending
candidate scores belong to ignored diagnostics. History therefore preserves
achieved source revisions, without pretending to preserve every experiment.

## Candidate diagnostics

Use `python tools/report.py --scores cl=build/PATH/comparison.json` to include
match.py diagnostics. Repeat the option for more files or binaries. Arrays
contain `symbol`, `retail_va`, `observed_at`, `source_path`,
`function_source_sha256`, `build_id`, `score`, `raw_bytes_equal`,
`referents_status`, `rule_status`, and `status`. A null score remains an
unscored candidate. Exact bytes with unresolved referents or pending/failed
rules are shown as `MATCH-PENDING`. No candidate record becomes matched merely
by scoring 100. Raw observations are never written to tracked history by the
report tool. Supply retained diagnostic files explicitly if their intermediate
scores should contribute to current/best/historical navigation.

## Validation

`python -m unittest discover -s tests -p test_report.py -v` exercises the report
and history contracts, including all-fallback zero, missing evidence, RED gate
rejection, hash/count disagreement, bad provenance, overlap, pending rules and
referents, deterministic history merge, source changes, lost-match recovery,
history persistence, compaction and deterministic CLI output. These are
infrastructure tests; they do not establish a reconstructed function match.
