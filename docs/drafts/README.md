# Draft sources outside the reconstruction tree

These files are reconstructed drafts that are **not** translation units: they
carry no `// FUNCTION:` annotations, are never compiled or linked, and are not
scanned by `tools/rulecheck.py` or the gate. A `// stop:` note in a file under
`matching/` outside an annotated function is a global blocking finding, so such
drafts live here while their required real definitions are still missing.

Their exact status, required bindings and open leads are recorded in the
`pending` field of their disabled entries in `config/cl-candidates.json`.

- `compile.pending.cpp`: module 9 drafts (module_extension, limit_batch_files).
