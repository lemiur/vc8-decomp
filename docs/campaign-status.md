# Local campaign status

Run `python tools/campaign.py` for a bounded status view and regenerated ignored
`build/reports/campaign.md` and `campaign.json`. It writes no source, policy,
ledger, baseline, Ghidra export, or gate output. The display defaults to eight
open entries; `--limit 0..12` controls it. Full open-work details remain in JSON.
No source-function percentage is calculated.

Inputs resolve through `config/project.json`'s primary checkout, so managed
worktrees consume the shared local evidence without copying binaries or dumps.
Outputs default to the calling checkout. `--project`, `--source-root`,
`--build-root`, and `--output-dir` allow explicit local fixture or alternate-run
selection. Running the same command against unchanged artifacts is deterministic.

The view combines these independent records:

- **Gate coverage:** `build/gate/latest.json`, validated by the report consumer.
  Only GREEN admission records and their exact printed BANKED counts supply
  functions and source bytes. RED or inconsistent records produce unknown
  counts. The view identifies the gate run and time. Coverage measures source
  substitutions into a retail copy; it is not a full source relink.
- **Phase criteria:** order and optional phases come from project configuration;
  the plan's hash is retained. Matching every function under the source rules
  requires a complete boundary census. The per-binary final milestone additionally
  requires a full source rebuild reproducing the retail hash. This command does
  not certify phase exits or accept splice equality as full-rebuild evidence.
  Profile configuration status determines the displayed provisional flag list.
- **Original Ghidra exports:** the small `build/ghidra/summary.json` locates runs.
  Each current manifest and completion marker is read independently; completion
  requires an accepted complete status, zero return code, consistent version and
  binary identity, and a valid body/decompiled/failed census. Nonzero decompiler
  failures can coexist with a completed export. Saved-project presence is checked.
  Follow-up manifests are reread live rather than trusting `status_at_snapshot`.
  These inferred evidence-body counts never become source-function denominators.
- **Open source work:** a fresh in-process rule scan and the canonical candidate
  registries supply the census, independently of score-history rows. Disabled
  candidates, parked annotations, unbanked source, changed function bodies, and
  pending current source reviews remain visible. Thus a banked-only ledger cannot
  incorrectly imply that no MATCH-PENDING source exists. No bulk Ghidra function
  census is inserted into the ledger.
- **Wall diagnoses:** source `// stop:` notes are retained. A taxonomy remains
  unclassified unless explicitly stated in a note or a hash-bound ignored
  `build/evidence/*-wall.json` record. Records use `binary`, `retail_va`,
  `function_source_sha256`, `wall`, and optional `open` or `open_leads`. The source
  hash follows match.py's declaration-through-closing-brace span, normalized
  newlines with no final newline. Stale diagnoses are ignored with a warning;
  diagnoses for not-yet-integrated source are not applied to existing functions.
- **Bootstrap observations:** the bounded `build/toolchain-ab/summary.json`
  producer provides its source baseline, identity/pair counts, and unresolved
  bootstrap verdict. Referenced artifacts are hash-checked without printing raw
  reports. Raw byte equality and independently resolved equality remain separate.
  A/B observations supply no source coverage and do not identify the bootstrap
  compiler when both measured toolchains agree. A new claimed resolution needs
  explicit review; this consumer does not certify it automatically.

Summary JSON reads are bounded to 200 KB. The provenance-rich gate is processed
programmatically without dumping it. The command never reads bulk decompiler
exports or raw A/B comparison reports. Missing or invalid evidence stays explicit.
The concise display may omit open rows, but always states how many are omitted.

Focused checks: `python -m unittest discover -s tests -p test_campaign.py -v`.
The existing report/history contract checks remain in `test_report.py`.
