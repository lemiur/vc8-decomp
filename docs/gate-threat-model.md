# Gate audit: trust boundary and executable checks

The gate is a retail-copy splice gate. Only its complete successful green line
authorizes banked counts. A fallback run proves file identity and contributes
zero compiled functions and zero source bytes. It does not prove a source relink.

## Trusted execution

The trusted computing base comprises the checked-out Python gate/build/PE/rule
tools, Python and its imported libraries, the configured local compiler/linker,
and checked-in identity and toolchain pins. Python code can fabricate records;
this design does not provide cryptographic attestation against hostile changes
to trusted tooling, the operating system, or simultaneous filesystem tampering.

The gate owns the fresh UUID directory and invokes the trusted build harness.
A JSON `commands` list is an observation, not independent proof that a compiler
ran. Tool paths and hashes must agree with `config/toolchains.json`; a manifest
cannot authorize a replacement executable by hashing it itself. Source and
configuration inputs must remain stable across the build. Actual compiler
outputs, link inputs, linked-image output, and the fresh linker MAP must form
one attributable chain. The root function's MAP owner must be the object
compiled from its claimed source unit.

## Independent executable audit

Run after a successful all-fallback gate:

```powershell
python tools/audit.py --root .
```

The default input is `build/gate/latest.json`; `--gate-record PATH` selects a
saved run. The auditor loads and verifies all five pinned retail images, opens
the actual run's fallback and selected splice files, compares complete bytes
and hashes, checks the full binary census, and requires zero source claims.
It prints `AUDIT PASS`, never the gate's banked green authority. Saved records
claiming source bytes fail closed: JSON cannot recover an execution receipt.

For live provenance verification, `tools.audit` provides:

- `RunSnapshot.capture(empty_output_dir, run_id, inputs)` captures pre-build
  input hashes. Include the Python executable, trusted harness, and candidate
  source units in the input list.
- `observe_build(snapshot, argv, manifest_path, cwd, env=None)` executes the
  trusted harness and returns an in-process `BuildReceipt` and completed process.
- `audit_manifest(manifest, binary, receipt, authoritative_toolchain_pins, root)`
  returns a `ManifestAudit`. It rejects changed/failed/stale manifests, duplicate
  inventories, unpinned tools, altered sources/artifacts/logs, missing compiler
  and linker execution records, outputs absent from command arguments, source
  units absent from `/GL` compiler arguments, and candidates without a linked
  artifact. Pins are an absolute-path-to-SHA-256 mapping from tracked inventory.
- `audit_splice(retail_image, expected_sha256, expected_candidates, candidates,
  output_bytes, snapshot, receipt, provenance, candidate_images)` checks an
  exact-only substitution census. The configured and built inventories must be
  separately supplied and equal, with no duplicate IDs. Candidate origins must
  be approved by the observed manifest. Candidate images are independently parsed
  `PEImage` objects keyed by their absolute artifact paths. The verifier checks
  extraction offsets against raw-section mapping in both directions, overlaps,
  artifact/source hashes, byte equality, reference ordering/equality, and every
  byte of the final image. It rejects nonempty masks and size changes.

The live API supplements the gate; it is not wired in as the gate's authority.
It accepts caller-supplied reference inventories and does not replace the gate's
independent instruction decoding, linker-MAP/import identity resolution, verified
function boundaries, or per-function source rule admission. Its counts are
named `verified_candidate_functions`, not rule-admitted matches. General
relocation/fixup auditing is intentionally unsupported in this exact-only API.

## Defects exercised by infrastructure tests

`python -m unittest discover -s tests -p test_audit.py -v` tests fresh-run
requirements, wrong retail hashes, stale run IDs, copied fallback claims,
missing observed execution, omitted/duplicate candidates and inventories,
unconfigured tool pins, changed inputs/artifacts/logs, output escape, opaque
masks, unresolved or reordered references, overlap, invalid/ambiguous PE
mapping, changed whole-image bytes, and saved-record source claims.

When `tools/gate.py` is integrated, the same suite exercises its actual
`validate_manifest`, `splice`, and `compare_candidate` functions. Before
integration, set `VC8_AUDIT_GATE` to the other lane's absolute `tools/gate.py`
path; absent a gate module, only these integration cases are explicitly skipped.
An adversarial test originally demonstrated that a wrong emitted external call
could be mislabeled with the desired retail callee and patched to exact bytes.
It passes after the gate independently binds the emitted target to fresh linker
MAP identities. That identity check must remain in place even when all normalized
bytes compare equal.

Fixtures that simulate source bytes or tool executables are temporary test data;
they never run through the production gate or count as recovered source.

## Integration smoke sequence

Run the full `unittest` infrastructure suite after merging tools. Then run
`python tools/match.py build --binary NAME` for each configured binary and inspect
successful manifests without claiming matches. Run `python tools/gate.py
--binary all --clean`, followed by the independent fallback audit above. Run
`python tools/rulecheck.py matching` and `python tools/report.py`; verify reported
counts come from the same successful gate run and remain zero in Phase 0.
Exercise `build`, `match`, `diff`, `disasm`, `xref`, and `class` help/invalid-input
paths without starting source reconstruction. Toolchain pin drift, a missing
retail input, or an unavailable rule checker with requested source must produce
a non-success result rather than bank a partial run. The integration owner runs
these smokes on the actual merged checkout and regenerates reports there.

## Remaining limits

Public symbol names do not establish signatures or all function boundaries.
Unverified MAP/FPO boundaries remain diagnostic. Shared functions, linker
aliases, overlapping functions, unsupported relocations, ambiguous identity,
and source rule failures must remain uncounted until supported explicitly.
All-fallback verification cannot exercise every future nonempty candidate path;
the focused synthetic failure tests cover those contracts until evidence-backed
matching candidates exist.
