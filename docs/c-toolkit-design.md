# C toolkit: design

Status: design only; nothing below exists yet. This document plans how a set of C tools written for another
matching decompilation (the "source project", a Visual C++ 2005 SP1 game decompilation by the same author) is
contributed to vc8-decomp as a self-contained, project-neutral toolkit. It fixes the layout, the build, the core
library, the project adapter that replaces the source project's hard-coded assumptions, each tool's port, the test
strategy, the work packages, the scrub checklist and the licence.

## 1. Scope

**In.** Tools that are useful to any VC8 matching decompilation and that vc8-decomp does not already have:

| tier | tool or library | what it gives vc8-decomp |
|---|---|---|
| 1 | `rich_header` | lists a PE Rich header's tool records (product id, build, object count) |
| 1 | `coff` (library) | VC8 COFF i386 object reader and writer |
| 1 | `pdb` (library) + `pdb_dump` | PDB 7.0 MSF, DBI (modules, section contributions, publics, module symbols, C11/C13 lines) and TPI reader |
| 1 | `xmatch` (library) + `xmatch` | masked-byte cross-image function finder (SP1 against RTM, one binary against another) |
| 1 | `lane_lock`, `slot_lock` | worktree lane claims and a machine-wide slot lock for parallel workers |
| 1 | `text_checks` | BOM and conflict-marker checks over configured paths |
| 2 | `disasm` | retail disassembly with names, cross-references, thunks, data words |
| 2 | `cfg_diff` | basic-block graphs of ours and the retail function aligned, structural differences named |
| 2 | `eq2` | symbolic x86 lockstep equivalence of ours against retail |
| 2 | `float_order` | float operation trees compared, spellings that reproduce the retail order searched |
| 2 | `frame` | stack-frame layout of ours against retail (plus `frame_slots`) |
| 2 | `flag_sweep` | every annotated function of a unit under one-option variants of its flags |
| 2 | `residue` (library) | register renames and difference classes of a compared function |
| 2 | `unitcmp` (new, thin) | the adapter's own compare CLI: hosts `--residue`, `--frame`, and the cross-check against `tools/match.py` |

**Out.** The source project's ports of vc8-decomp's own Python tracers (`c2_trace`, `c2_inline_trace`, `cl_trace`,
`link_trace`, `symbols`, `probe_toolchain`) and everything that depends on them: `c2_site_weights` (it links the
C ports of `c2_trace`, `c2_inline_trace`, `c2_toolchain`, `c2_symbols` and `vc8_root`; see question Q1). Also out:
the source project's match/gate/report front ends, LTCG group ranges, library-object claims, vtable and data
comparison, RTTI/COM/server naming, permuter, witness and console tools, `frame_diff` (a rendered-frame diff, not
a stack-frame tool), `eq2_classify` (its test corpus is project-derived; may return later with synthetic tests).

**Never moves:** retail addresses, the source project's names and mangled names, its configuration keys, and any
test corpus generated from its executables.

## 2. Layout

Everything lives in one new top-level directory, `ctools/`, so the licence boundary is a directory boundary.

```
ctools/
  LICENSE                 CC BY 4.0 legal code (section 10)
  NOTICE                  attribution line, scope statement, third-party summary
  README.md               build, configuration, one line per tool (written by WP0, extended per WP)
  CMakeLists.txt          project(decompkit LANGUAGES C)
  CMakePresets.json
  cmake/                  entry_points.cmake, tools_stamp.cmake, scrub.cmake, import_rename.cmake
  core/include/dk/*.h     runtime library headers (renamed from the source project's avp/)
  core/src/*.c
  core/tests/*_test.c     core unit tests (synthetic corpora only)
  lib/*.c, lib/*.h        tool modules; usage text in lib/<name>_doc.inc
  tools/<name>_main.c     one executable per tool, entered through DK_MAIN
  tests/*_test.c          tool tests
  tests/fixtures/         C fixture writers (synth_coff.h, synth_pe.h, synth_pdb.h), fake toolchain sources
  third_party/            capstone 5.0.7, PCRE2; NOTICES.txt; CMakeLists.txt
```

Executables land in `<repo>/build/ctools/bin/` (debug: `build/ctools/bin/debug/`); `build/` is already ignored.
CMake build trees go to `build/ctools-cmake[-debug]`. Registration is by glob (`lib/*.c` into one static library
`dktools`, `tools/*_main.c` into one executable each, `tests/*_test.c` and `core/tests/*_test.c` into one CTest
each), so work packages that add files never edit `CMakeLists.txt`.

### 2.1 Build requirements and presets

- CMake 3.25 or later; MSVC 19.30 or later (Visual Studio 2022 or newer), x64 host and target; C17
  (`/std:c17`). Other compilers are refused at configure time, as the code uses MSVC intrinsics, `<windows.h>`
  (INIT_ONCE, process and debugger APIs) and dbghelp.
- Our code: `/W4 /WX /utf-8 /Zc:preprocessor /Oi /Gy`, Release adds `/GL` and links `/LTCG /OPT:REF /OPT:ICF`.
  The source project's `/d2:-scheduler-` link workaround for MSVC 14.51 is kept only under
  `if(MSVC_VERSION GREATER_EQUAL 1950)` together with its regression test (`core/tests/struct_cond_test.c`).
- Static CRT (`MultiThreaded[Debug]`); system libraries: `bcrypt shlwapi advapi32 dbghelp`.
- Presets: a hidden `base` (x64, cache variables), configure presets `ctools` (Release) and `ctools-debug` that
  inherit it with no fixed generator, plus `ctools-vs2022` / `ctools-vs2026` convenience presets naming the
  Visual Studio generator. Workflows: `ctools-build` (configure, build), `ctools` (configure, build, test),
  `ctools-debug`. Run from `ctools/`: `cmake --workflow --preset ctools`.
- Built-in CTests besides the unit tests: `entry_points` (every executable enters through `DK_MAIN`, nothing
  defines `main`), `scrub` (section 9, over `ctools/` minus `third_party/`).

### 2.2 Finding the repository and the configuration

`dk_root()` resolves, in order: `--root DIR` (every tool accepts it), the environment variable `DECOMPKIT_ROOT`,
then the executable's location walked up to the directory holding `ctools/CMakeLists.txt`, then the current
directory walked up to the first directory holding `config/ctools.json`. The project configuration is
`<root>/config/ctools.json` (or `--config FILE`), merged with an ignored `<root>/config/ctools.local.json` for
machine paths. For a git worktree, `${primary}` (the main checkout, found through `.git` -> `commondir` exactly as
`tools/matchlib.py primary_checkout` does) locates ignored shared inputs such as `symbols/`.

## 3. Core library

The source project's core is about 26k lines across 27 modules. The kept modules are the transitive closure of
what the chosen tools include (computed by grepping `#include` in the chosen `lib/` files and in the core's own
headers and sources):

| keep | files | why |
|---|---|---|
| base, arena, vec, str | `base.c arena.c vec.c str.c str_parse.c str_unicode.c str_base64.c` + tables | everything |
| map, sort | `map.c map_pyintset.c sort.c` | everything |
| fmt | `fmt_float.c fmt_math.c fmt_pct.c fmt_repr.c fmt_spec.c fmt_unitab.c` | everything |
| json | `json.c json_read.c json_write.c` | adapter, manifests, reports |
| csv | `csv.c csv_tsv.c` | TSV symbol sources (section 5.5) |
| hash | `hash.c` minus `crc32` | objcache keys (sha256, file digest) |
| cache | `cache.c` | objcache memo files |
| proc, pool, clock | `proc.c pool.c clock.c` | running cl/link, worker pools, timeouts |
| fs, win | `fs_*.c win.c win_err.c` | everything |
| re | `re.c re_translate.c` (PCRE2) | annotations; `re_translate` accepts Python syntax, so vc8-decomp's existing patterns are reused verbatim |
| difflib | `difflib.c` | cfg_diff, residue, float_order |
| disasm | `disasm.c` (capstone, x86 modes only) | every diagnostic |
| pe | `pe.c pe_coff.c pe_ordlookup.c` | images, imports, `dk_undecorate_symbol` (dbghelp) |
| args | `args.c args_format.c` | every CLI |

**Dropped:** `http`, `mcp*`, `zip*`, `pyrandom`, the version file `avpcore.c` (replaced by `dkcore.c`), the PPC
disassembly modes and their test, `avp_crc32`. With them go three of the four third-party packages: zlib-ng (only
crc32 and zip used it), SQLite (only the MCP index) leave; capstone is built with the X86 architecture only and
PCRE2 stays as is. The umbrella header `dk/dk.h` loses the dropped includes.

**Core tests kept** only where the corpus is synthetic (generated from CPython semantics or hand-written):
arena, args, base, cache, clock, csv, difflib, fmt, fs_*, hash (crc32 cases removed), hypot, json, map*, pool,
proc, re, sort, str*, struct_cond, win. `pe_test` is kept only after its corpus is checked to be synthetic, else
rewritten on `synth_pe.h`. `disasm_test` (whole-image digests of the source project's executables) is replaced
by a synthetic x86 sweep in the style of the dropped PPC test.

### 3.1 Rename

The prefix becomes `dk_` ("decomp kit"; `vk_` was rejected because `VK_` is Vulkan's macro namespace and the
toolkit should read as project-neutral so the source project can later consume it back). Applied mechanically by
`cmake/import_rename.cmake` (`cmake -DFILES=... -P`), whole-token, case-sensitive, in this order:

| from | to |
|---|---|
| `AVP3_ROOT` | `DECOMPKIT_ROOT` |
| `AVP3_OBJ_CACHE` | `DECOMPKIT_OBJ_CACHE` |
| `"avp/` (include path) | `"dk/` |
| `avp.h` | `dk.h` |
| `avpcore`, `avptools` | `dkcore`, `dktools` |
| `AVP_` (macro prefix) | `DK_` |
| `Avp` (type prefix, at a token start) | `Dk` |
| `avp_` (function prefix) | `dk_` |

Before the rename, each importing work package deletes the source-project-only macros it meets (`AVP_DX9`,
`AVP_DX11`, `AVP_TEST(retail)` blocks) rather than renaming them; the `scrub` test then proves no `avp`
spelling of any case remains. Provenance comments of the form "ported from tools/x.py" are rewritten to
"behaviour defined by its tests" (section 9).

## 4. Tool modules that the adapter replaces

The source project's `matchlib` (about 8k lines across `matchlib.h` and four `matchlib_*.c` files) is not
ported as such. It hard-codes two builds (`MATCHLIB_NBUILDS == 2`, names `dx9`/`dx11`, macros
`AVP_DX9`/`AVP_DX11`), a two-address annotation grammar, its project's config keys (`builds.*.exe`,
`ghidra_export`, `compiler.roots`, `sdk_include`, `lib_roots`, `referents`, `vtable_strict`, `data_strict`), a
Ghidra-export name index, its toolchain discovery (`VC8` environment variable, `VC\bin\cl.exe`), library-object
claims, LTCG group ranges, a copy-protection stub decoder and a security-cookie byte pattern. The adapter of
section 5 keeps its generic machinery (PE image model, COFF function extraction, relocation cutting, the
relocation-resolution ladder, result model) and replaces every assumption by configuration.

`objcache` moves with the adapter: its key (sha256 of version, compiler identity, options, source path and
digest) is generic; the compiler identity files become `compiler.identity_files` in the config, the cache root
`DECOMPKIT_OBJ_CACHE` or `%LOCALAPPDATA%\decompkit-objcache`. `unit_paths` (unit discovery under `matching/`,
excluding `matching/include/`) becomes `units.roots` / `units.exclude` in the config.

## 5. The project adapter

### 5.1 Concepts

- **Target:** one reference image to match (vc8-decomp: `cl`, `c1`, `c1xx`, `c2`, `link`; the source project
  would declare `dx9` and `dx11`). Up to `DK_MAX_TARGETS` (8). Each target has an image path, pinned sha256,
  optional image base, optional per-target preprocessor defines, and a symbol source.
- **Unit:** one source file with per-unit compile options. A unit is compiled once, or once per target when its
  text tests a per-target define (the source project's per-build switch, generalised).
- **Annotation:** a marker line matched by a configured regex; it names a kind, one or more targets and their
  addresses. Optional companion lines (stop, pending, symbol, flags) are configured regexes too.
- **Backend:** how a function's candidate bytes are obtained. `object` (compile, read the function from the COFF
  object; the source project's model), `link` (compile with the unit's flags, link with a configured linker
  command, find the function through the linker map in the linked image; vc8-decomp's /GL + /LTCG model) or
  `manifest` (read the candidates of a `tools/match.py build` manifest; no compile at all).
- **Result:** per annotation and target: status (`MATCH`, `DIFF`, `SIZE`, `REFERENT`, `UNRESOLVED`, `ERROR`,
  `MISSING`), our bytes and relocations, retail bytes and relocations, each relocation's verdict.

### 5.2 Configuration schema (`config/ctools.json`)

Values may be literals or **references** into the project's existing configuration, so nothing is duplicated:
`{"$from": "config/retail.json#/builds/cl/sha256"}` is replaced by that JSON value (RFC 6901 JSON Pointer). Strings
interpolate `${name}` from `vars` and the built-ins `${root}`, `${primary}`, `${target}`, `${unit}`, `${out}`.

```
{
  "schema": "decompkit-project/1",
  "vars":        { name: string | $from },
  "targets":     { name: {
                     "image": path,                    required
                     "sha256": hex | $from,            pinned; mismatch is an error
                     "image_base": int | $from,        optional check
                     "defines": [ "NAME=1", ... ],     optional per-target macros
                     "symbols": [ symbol-source ... ], section 5.5
                     "units": unit-map | $from         optional, merged into "units"
                   } },
  "units":       { "roots": [dir], "exclude": [dir], "extensions": [".c", ".cpp"],
                   "map": unit-map | $from },          explicit list wins over discovery
  "unit-map":    { "<path>": { "compile_flags": [..], "remove_compile_flags": [..],
                               "link_flags": [..], "gl": bool, "flags_line": bool } },
  "compiler":    { "cl": path, "env": { NAME: value }, "path_prepend": [dir],
                   "base_flags": [..] | $from, "c_flags": [..], "cpp_flags": [..],
                   "include": [dir], "identity_files": [path], "show_includes": bool,
                   "flag_variants": [[..], ..] },      flag_sweep's list; built-in default otherwise
  "backend":     { "kind": "object" | "link" | "manifest",
                   "link": { "linker": path, "argv": [..] | $from, "roots": "annotations",
                             "map": "msvc", "discovery_compile": bool },
                   "manifest": { "command": [..], "path": path } },
  "annotations": { "marker": regex | $from,            named groups below
                   "kinds": { "<text>": "function"|"data"|"decl"|"vtable" },
                   "addr_groups": "target+addr" | "per-target",
                   "name": "declaration" | "next_line",
                   "symbol": regex,                    explicit decorated name, group 1
                   "stop": regex, "pending": regex,    groups: reason, optional target
                   "flags": regex, "flags_lines": int },
  "referents":   [ { "file": path, "format": "json-symbols" | "tsv" } ],
  "well_known":  { "imports": bool, "symbols": [ name ] },
  "build_dir":   path,                                 default ${root}/build/ctools
  "text_checks": { "paths": [dir], "no_bom": [glob] }
}
```

The marker regex uses named groups: `kind`; then either `target` and `addr` (one target per line, vc8-decomp)
or `addr_<target>` per declared target (several addresses per line, the source project's `// match: <a> <b>`,
where `0` means "no copy in that target"). Python-style `(?P<name>...)` is accepted (PCRE2 supports it; the
core's `re_translate` covers the rest of Python syntax), so vc8-decomp's existing pattern is used unchanged.

Name rules: `declaration` takes the first identifier before `(` between the marker and the body's `{` and binds
it to a compiled symbol by the MSVC rules vc8-decomp already uses (`_name`, `_name@N`, `?name@...`), an explicit
symbol line winning; `next_line` takes a qualified name from the line after the marker and binds it through
undecoration (the source project's `symbol_matches`, ported). Ambiguity is an error naming the line.

### 5.3 C API (`lib/project.h`, sketch)

```c
#define DK_MAX_TARGETS 8
#define DK_NO_ADDR 0u

typedef enum { DK_ANN_FUNCTION, DK_ANN_DATA, DK_ANN_DECL, DK_ANN_VTABLE } DkAnnKind;
typedef enum { DK_BACKEND_OBJECT, DK_BACKEND_LINK, DK_BACKEND_MANIFEST } DkBackendKind;
typedef enum { DK_MATCH, DK_DIFF, DK_SIZE, DK_REFERENT, DK_UNRESOLVED, DK_MISSING, DK_ERROR } DkStatus;

typedef struct DkProject DkProject;          /* opaque: config, targets, units, compiler, caches */
typedef struct DkImage DkImage;              /* a mapped PE: sections, relocs, imports, symbols */

typedef struct {
    const char *name; const char *image_path; u8 sha256[32]; u32 image_base;
    DkStrVec defines; DkImage *image;        /* image opened lazily by dk_target_image */
} DkTarget;

typedef struct {
    const char *path;                        /* repository-relative, forward slashes */
    DkStrVec compile_flags, remove_flags, link_flags; bool gl; bool per_target;
} DkUnit;

typedef struct {
    DkAnnKind kind; const DkUnit *unit; int line, body_start, body_end;
    u32 addr[DK_MAX_TARGETS];                /* DK_NO_ADDR where the target has no copy */
    const char *name, *symbol;               /* source name; bound decorated name or NULL */
    u32 stop_mask; const char *stop_reason;  /* bit t: parked for target t */
    const char *pending, *flags;
} DkAnnot;

typedef struct { u32 offset; u16 type; const char *symbol; i32 addend; } DkReloc;
typedef struct { const char *symbol; DkStr code; DkReloc *relocs; size_t n_relocs; u32 va; } DkFunc;

typedef enum { DK_REF_SAME, DK_REF_OTHER, DK_REF_UNRESOLVED } DkRefVerdict;
typedef struct { u32 offset; u32 ours, theirs; const char *name; DkRefVerdict verdict; } DkRefCheck;

typedef struct {
    const DkAnnot *ann; int target; DkStatus status;
    DkFunc ours; DkStr theirs; u32 theirs_va;
    DkRefCheck *refs; size_t n_refs; const char *error;
} DkResult;

/* configuration */
DkProject  *dk_project_load(DkArena *a, const char *root, const char *config, DkErr *err);
size_t      dk_project_ntargets(const DkProject *p);
const DkTarget *dk_project_target(const DkProject *p, int index);
int         dk_project_target_index(const DkProject *p, const char *name);   /* -1 if unknown */
const DkUnit *dk_project_units(const DkProject *p, size_t *n);
const DkUnit *dk_project_unit(const DkProject *p, const char *path_or_stem);
const char *dk_project_build_dir(const DkProject *p, const char *tool);

/* reference images and names */
DkImage    *dk_target_image(DkProject *p, int target, DkErr *err);           /* verifies sha256 */
bool        dk_image_read(const DkImage *im, u32 va, size_t n, DkStr *out);
const char *dk_image_name_at(const DkImage *im, u32 va, u32 *start);       /* symbol sources */
bool        dk_image_function_size(const DkImage *im, u32 va, u32 *size);
const DkReloc *dk_image_relocs(const DkImage *im, u32 va, size_t n, size_t *count);

/* annotations */
DkAnnot    *dk_annotations(DkProject *p, const DkUnit *u, size_t *n, DkErr *err);
const DkAnnot *dk_find_annotation(DkProject *p, const DkUnit *u, const char *name, u32 addr);
bool        dk_stopped(const DkAnnot *a, int target);

/* building and comparing */
typedef struct { DkStrVec extra_flags; const char *source_override; bool use_cache; } DkBuildOpts;
DkFunc     *dk_build_unit(DkProject *p, const DkUnit *u, int target, const DkBuildOpts *o,
                          size_t *n, DkStr *log, DkErr *err);     /* every function of the unit */
DkResult   *dk_compare(DkProject *p, const DkAnnot *a, int target, const DkFunc *ours, DkErr *err);
DkResult   *dk_compare_unit(DkProject *p, const DkUnit *u, int target, const DkBuildOpts *o,
                            size_t *n, DkErr *err);               /* build + compare all */
const char *dk_status_name(DkStatus s);
```

`dk_compare` is the source project's comparison: relocated fields masked, the remaining bytes compared, then
every relocation resolved on both sides. The ladder is kept with project items made configurable: weak external,
defined symbol in our build mapped through the annotations and the symbol sources, same-section and other
function targets, compiler-made data compared by content (depth 16), `referents` files, then `well_known`
(imports by `__imp_` name, listed symbols looked up in the target's symbol source). Unresolved stays
`UNRESOLVED`, never a match.

### 5.4 Backends

- `object`: `cl` + `base_flags` (minus `remove_compile_flags`) + unit `compile_flags` + target `defines` +
  `/I` + `/showIncludes` + `/Fo`; functions cut from the COFF object (symbol value to the next function symbol or
  section end); relocations from the object. Cached by `objcache`.
- `link`: as `object` with the unit's `gl` setting, then the configured linker argv (`${out}`, `${objects}`,
  `${roots}` expand), the map parsed for each bound symbol, bytes read from the linked image, the end taken from
  the next map symbol of the same section (reported as an unverified boundary, as `tools/match.py` does);
  relocations recovered from the image's base relocations plus decoded `rel32` branches, both named through the
  map. With `discovery_compile`, a `/GL-` compile first supplies the symbol names used as link roots.
- `manifest`: runs `backend.manifest.command` (or reads an existing manifest) and takes `symbol`, `retail_va`,
  `candidate_va`, `size` and `image_path` of each candidate; relocations as in `link`. Read-only use of
  vc8-decomp's existing manifest format; no Python change is needed.

### 5.5 Symbol sources

Ordered list per target; the first that names an address wins:
`{"kind": "tsv", "path": ..., "name": "name", "va": "va", "size": "size"}` (vc8-decomp's
`symbols/<binary>.functions.tsv` from `tools/symbols.py`), `{"kind": "pdb", "path": ...}` (the ported reader:
publics and module procedures), `{"kind": "map", "path": ...}` (an MSVC linker map). The source project's Ghidra
`index.tsv` is just a `tsv` source with its own column names. Annotation names are layered on top.

### 5.6 vc8-decomp's configuration

```json
{
  "schema": "decompkit-project/1",
  "vars": {
    "toolchain_root": {"$from": "config/project.json#/toolchain_root"},
    "symbols": "${primary}/symbols"
  },
  "targets": {
    "cl":   {"image": "${toolchain_root}/bin/cl.exe",
             "sha256": {"$from": "config/retail.json#/builds/cl/sha256"},
             "image_base": {"$from": "config/retail.json#/builds/cl/image_base"},
             "symbols": [{"kind": "tsv", "path": "${symbols}/cl.functions.tsv"}],
             "units": {"$from": "config/cl.json#/units"}},
    "c1":   {"image": "${toolchain_root}/bin/c1.dll",   "sha256": {"$from": "config/retail.json#/builds/c1/sha256"},
             "symbols": [{"kind": "tsv", "path": "${symbols}/c1.functions.tsv"}]},
    "c1xx": {"image": "${toolchain_root}/bin/c1xx.dll", "sha256": {"$from": "config/retail.json#/builds/c1xx/sha256"},
             "symbols": [{"kind": "tsv", "path": "${symbols}/c1xx.functions.tsv"}]},
    "c2":   {"image": "${toolchain_root}/bin/c2.dll",   "sha256": {"$from": "config/retail.json#/builds/c2/sha256"},
             "symbols": [{"kind": "tsv", "path": "${symbols}/c2.functions.tsv"}]},
    "link": {"image": "${toolchain_root}/bin/link.exe", "sha256": {"$from": "config/retail.json#/builds/link/sha256"},
             "symbols": [{"kind": "tsv", "path": "${symbols}/link.functions.tsv"}]}
  },
  "units": {"roots": ["matching"], "extensions": [".c", ".cpp"]},
  "compiler": {
    "cl": "${toolchain_root}/bin/cl.exe",
    "base_flags": ["/nologo", "/c"],
    "cpp_flags": ["/EHsc"],
    "identity_files": ["${toolchain_root}/bin/cl.exe", "${toolchain_root}/bin/c1.dll",
                       "${toolchain_root}/bin/c1xx.dll", "${toolchain_root}/bin/c2.dll"],
    "show_includes": true
  },
  "backend": {
    "kind": "link",
    "link": {"linker": "${toolchain_root}/bin/link.exe",
             "argv": ["/nologo", "/DLL", "/NOENTRY", "/LTCG", "/MACHINE:X86", "/INCREMENTAL:NO",
                      {"$from": "config/project.json#/project/link_flags"}, "/MANIFEST:NO",
                      "/OUT:${out}/candidate.dll", "/MAP:${out}/candidate.map", "${roots}", "${objects}",
                      "kernel32.lib"],
             "roots": "annotations", "map": "msvc", "discovery_compile": true},
    "manifest": {"command": ["python", "tools/match.py", "build", "--binary", "${target}"]}
  },
  "annotations": {
    "marker": {"$from": "config/project.json#/project/annotation/pattern"},
    "kinds": {"FUNCTION": "function", "DATA": "data"},
    "addr_groups": "target+addr",
    "name": "declaration",
    "symbol": "^\\s*//\\s*SYMBOL:\\s*(\\S+)\\s*$",
    "stop": "^\\s*//\\s*stop:\\s*(?P<reason>.*)$"
  },
  "well_known": {"imports": true, "symbols": ["___security_cookie"]},
  "text_checks": {"paths": ["matching"], "no_bom": ["matching/**"]}
}
```

The per-binary `compile`/`link` flag lists of `config/<binary>.json` (`flags.compile`, `flags.link`) are joined
the same way (`"base_flags": {"$from": "config/c2.json#/flags/compile"}` on a target-level `compiler` override,
allowed per target). The `$from` pointer into an array splices its elements. The vc8-decomp tools keep the
authority: `tools/match.py` and `tools/gate.py` decide what is banked; the C tools are diagnostics. A local
cross-check (section 7.3) proves the `link` backend agrees with `tools/match.py` on every annotated function.

For comparison, the source project would declare `"targets": {"dx9": {..., "defines": ["AVP_DX9=1"]}, "dx11":
{...}}`, `"addr_groups": "per-target"` with groups `addr_dx9` and `addr_dx11`, `"name": "next_line"` and
`"backend": {"kind": "object"}`. That instance stays in the source project.

## 6. Per tool: what moves, what is cut

Each row: source files (from the source project's `tools/c`), cuts, coupling changes, tests.

**rich_header** (`tools/rich_header_main.c`, 103 lines). Moves whole. Test: `synth_pe.h` writes a PE with a
known Rich header (XOR key, `DanS`, records); the expected listing is hand-computed. The source project's
fixture directory and its generator are not taken.

**coff** (`lib/coff.c/.h`, 556 lines). Moves whole. `coff_test` moves after a check that its inputs are
synthetic; its object builder becomes `tests/fixtures/synth_coff.h` (used by every later test).

**pdb** (new `lib/pdb.c`, `lib/pdb_types.c`, `lib/pdb.h`; from `proto_extract_pdb.c` lines 1-640 and
`proto_extract_types.c`). Moves: the byte helpers of `proto_extract_internal.h` (lines 12-44), MSF open/stream,
PDB info stream, DBI modules and publics, module symbols, C13 and C11 line blocks, TPI records with names, sizes
and method classes. Cut: AES/BCrypt and XEX image code (lines 641-778), PE section and `.pdata` helpers, the TSV
writers, `px_extract_*`, every console/other-game output name and config key; the `ProtoPdb`/`ProtoTypes`
structs become `DkPdb`/`DkPdbTypes` in `pdb.h`. New CLI `pdb_dump <pdb> publics|modules|procs|lines|types
[--tsv]`. Tests: `tests/fixtures/synth_pdb.h` writes a minimal MSF 7.0 with a PDB info stream, a DBI with two
modules, a publics stream and a TPI with a struct, a pointer and a procedure; the test reads them back. vc8-decomp
gains an independent second reader to cross-check `tools/symbols.py` locally.

**xmatch** (`lib/xmatch*.c`, about 1.6k lines, `xmatch_x86_tables.h`). Moves whole minus the research-script
references. Coupling: `xmatch.h` includes `matchlib.h` only for the COFF function types; it gets its own
`XmFunc` (code, relocations) and the adapter provides `dk_func_to_xm`. New CLI `xmatch <imageA> <va> [--size N]
<imageB> [--top K]`: find a function of one image in another (SP1 against RTM, or `c1` against `c1xx`). Test:
`xmatch_test` (synthetic instruction bytes) moves; add a two-image `synth_pe.h` case.

**lane_lock, slot_lock** (`lib/lane_lock.c`, `lib/slot_lock.c`, mains). Generic already: locks live under the
git common directory and `<root>/.slot_lock`. Cuts: help text naming the source project's files; `avp_root` ->
`dk_root`. Tests: `lane_lock_test` (replace its sample path), `slot_lock_test`.

**text_checks** (`lib/text_checks.c`, main). The hard-coded `matching/` becomes `text_checks.paths` /
`no_bom`. New `text_checks_test` on a temporary tree (BOM file, conflict marker, clean file).

**disasm** (`lib/disasm.c`, main, 914 + 45 lines). Moves: retail disassembly, bounds, `--xref`, `--name`,
`--thunks`, `--data`, `--words`. Cut: RTTI labels (`rtti.h`), COM slot names (`com_slots.h`), generated-referent
labels (`generated.h`), the copy-protection stub decoder, the Ghidra index (replaced by the target's symbol
sources), `coverage.h` (replaced by `dk_annotations` over all units). CLI: `disasm <target> <va> [...]` where
`<target>` is any configured target. Test: `disasm_lib_test` already uses a synthetic 96-byte image; switch it to
`synth_pe.h` plus a TSV symbol source.

**cfg_diff** (`lib/cfg_diff.c/.h`, 3.2k lines, main). Moves whole. Couplings: `matchlib` -> adapter;
`stops.h` -> new `lib/walls.c/.h` (the generic half of the source project's `stops.c`: call tokens, branch
targets, moves, relocation verdicts, game window, build wall; 466 lines, no project strings); the unused
`slot_lock.h` include dropped. `--build dx9|dx11|both` becomes `--target T|all`; batch mode iterates the
adapter's non-`MATCH` results instead of a stops JSON file; output under `build_dir/cfg_diff`. Tests:
`cfg_diff_test` and its corpus (hand-assembled byte pairs) move after the scrub; results built with
`dk_result_new` and no image.

**eq2** (`lib/eq2_{front,sim,expr,alu,fpu,big,checker}.c`, headers, main). Moves. Couplings: adapter for
results, images and stop marks; default target = first annotated target of the function. Cut: `eq2_classify`
and its corpus; the `retail` test block. Tests: `eq2_test` with `eq2_corpus.h` (random expressions and random
small x86 programs; synthetic) after the scrub.

**float_order** (`lib/float_order*.c`, main). Moves analysis, tree classification and search. Couplings: the five
text helpers it uses from the source project's `permute.c` (`permute_reg_full`, `permute_calls`,
`permute_written`, `permute_read`, `permute_atomic`) move into `lib/ctext.c/.h` (C-expression text helpers);
the `PermuteScorer` (compile, measure, resolve, state key, score compare) is replaced by `lib/scorer.c/.h`, a
small scorer on the adapter (`dk_build_unit` with `source_override`, `dk_compare`, score = status, differing
bytes, difflib ratio); its LTCG link, trace distance and colour report are cut; `priority.c` (process priority
lowering) moves as `lib/priority.c`. `--build` -> `--target`; `--batch` reads the adapter's results. Tests: the
existing corpus is project-derived and does not move; new `float_order_test` with hand-written x87/SSE sequences
and expressions, and a scorer test on the fake toolchain (7.2).

**frame** (`lib/frame.c/.h`, `lib/frame_slots.c/.h`). `frame.c` is generic (disasm and PE only); its
"imports from a `msvcr*` DLL are cdecl" rule becomes a list in `compiler` (`cdecl_import_dlls`, default
`msvcr*`). `frame_slots` needs `cfg_diff`. No CLI of its own: reached through `unitcmp --frame`. Cut:
`frame_diff`. Tests: the source project's corpus is project-derived; new `frame_test` on hand-assembled
prologues (`push ebp`/`sub esp`, `/Oy` frames, `__chkstk`, `/GS` cookie slots).

**flag_sweep** (`lib/flag_sweep.c/.h`, main). Moves. Couplings: adapter build with `extra_flags` and
`remove_flags`; the built-in option list stays as the default, overridable by `compiler.flag_variants`;
`--builds dx9,dx11` -> `--targets`. Test (new; none existed): the fake toolchain answers flag variants with
different canned objects; the expected per-variant verdict table is checked.

**residue** (`lib/residue.c`, `residue_text.c`). Moves. Couplings: `match_disassemble` and `match_normalise`
(the first 140 lines of the source project's `match.c`) move into `lib/insn_text.c/.h`; `stops.h` -> `walls.h`.
Reached through `unitcmp --residue`. Tests: `residue_test`, `residue_values_test`, `residue_compare_test`
(synthetic) move after the scrub.

**unitcmp** (new `tools/unitcmp_main.c`, `lib/unitcmp.c`). `unitcmp <unit> [--target T|all] [--function N]
[--summary] [--diff] [--residue] [--frame] [--json FILE]`. It is the adapter's front end and acceptance harness,
not a replacement for `tools/match.py`.

## 7. Test strategy

### 7.1 Rules

Tests use synthetic fixtures only. Nothing in `ctools/` is a Microsoft binary, header or PDB, or derived from
one; nothing is derived from the source project's executables or names. Binary fixtures are written at test time
by C fixture writers (`.exe`, `.obj`, `.pdb` are ignored by the repository anyway). A moved corpus header is
moved only after the scrub (section 9) and a reading of its provenance comment shows it was generated from
synthetic inputs; otherwise it is replaced.

### 7.2 Fixture writers and the fake toolchain

- `tests/fixtures/synth_coff.h`: builds i386 COFF objects (sections, symbols, relocations) through `coff.c`'s
  writer.
- `tests/fixtures/synth_pe.h`: builds PE32 images (sections, base relocations, imports, Rich header).
- `tests/fixtures/synth_pdb.h`: builds MSF 7.0 PDBs (section 6, pdb).
- `tests/fakecl/fakecl_main.c`, `tests/fakecl/fakelink_main.c`: test-only executables (not installed). `fakecl`
  parses `/Fo`, `/D`, `/I`, `/GL[-]` and a flag set, hashes the source text and flags, and writes the canned
  object a test registered for that key (through `synth_coff.h`); `fakelink` writes a PE and an MSVC-format map
  from its inputs. Adapter, `unitcmp`, `flag_sweep`, `float_order`'s scorer and `cfg_diff` batch tests run the
  whole pipeline on a temporary repository with a `config/ctools.json` pointing at them.

### 7.3 Local cross-check (not in CI)

CTest label `local`, skipped unless `DECOMPKIT_LOCAL=1`: on a real vc8-decomp checkout with the toolchain and
`symbols/` present, `unitcmp --target all --json` over every unit is compared with `python tools/match.py match`
for every annotated function (status, size, referent verdicts). Disagreement is a bug in the adapter. Nothing it
reads or writes is committed.

## 8. Work packages

Each package owns the files it lists (file-disjoint), runs `cmake/import_rename.cmake` on what it imports,
deletes before renaming (section 3.1), and commits on its own branch. **Acceptance for every package:**
`cmake --workflow --preset ctools` passes from a clean `build/ctools-cmake` (so `/W4 /WX` clean and every test
green, including `entry_points` and `scrub`), and the section 9 manual review list is empty for its files.

| # | package | owns | depends on | extra acceptance |
|---|---|---|---|---|
| WP0 | skeleton, core, build, licence | `ctools/{CMakeLists.txt,CMakePresets.json,LICENSE,NOTICE,README.md}`, `ctools/cmake/*`, `ctools/core/**`, `ctools/third_party/**`, `.gitignore` line for `config/ctools.local.json` | none | core tests listed in section 3 pass; capstone X86-only; zlib-ng and SQLite absent; `scrub` and `entry_points` tests exist and fail on a planted `avp_` / `main` (checked once, not committed) |
| WP1 | rich_header | `tools/rich_header_main.c`, `tests/rich_header_test.c`, `tests/fixtures/synth_pe.h` | WP0 | synthetic Rich header decoded |
| WP2 | coff | `lib/coff.*`, `tests/coff_test.c`, `tests/fixtures/synth_coff.h` | WP0 | round trip write/read |
| WP3 | pdb | `lib/pdb*.{c,h}`, `tools/pdb_dump_main.c`, `tests/pdb_test.c`, `tests/fixtures/synth_pdb.h` | WP0 | no XEX/AES code; synthetic PDB read back |
| WP4 | xmatch | `lib/xmatch*`, `tools/xmatch_main.c`, `tests/xmatch_test.c` | WP0 (WP1 for its two-image case, else hand-built bytes) | no `matchlib.h` |
| WP5 | locks, text checks | `lib/{lane_lock,slot_lock,text_checks}.*`, their mains and tests | WP0 | text_checks reads its paths from config (stub reader until WP6 lands: a `--paths` option) |
| WP6 | adapter: config, targets, units, annotations, symbol sources | `lib/project.h`, `lib/project_config.c`, `lib/project_annot.c`, `lib/project_symbols.c`, `lib/objcache*`, `tests/project_*_test.c` | WP0, WP2, WP3 | the section 5.6 config loads against a synthetic copy of vc8-decomp's config files; both grammars (target+addr and per-target) parse their fixtures |
| WP7 | adapter: images, backends, compare | `lib/project_image.c`, `lib/project_build.c`, `lib/project_compare.c`, `tests/fakecl/**`, `tests/project_compare_test.c` | WP6, WP1 | object and link backends match canned candidates; each relocation verdict and each status reached by a test; manifest backend reads a synthetic manifest |
| WP8 | shared diagnostics libraries, unitcmp | `lib/{walls,insn_text,ctext,priority,unitcmp}.*`, `tools/unitcmp_main.c`, their tests | WP7 | `unitcmp` end to end on the fake toolchain; local cross-check passes on vc8-decomp |
| WP9 | disasm | `lib/disasm.*`, `lib/disasm_doc.inc`, `tools/disasm_main.c`, `tests/disasm_lib_test.c` | WP8 | names from a TSV source; no RTTI/COM code |
| WP10 | cfg_diff | `lib/cfg_diff*`, `tools/cfg_diff_main.c`, `tests/cfg_diff_*` | WP8 | batch mode over adapter results |
| WP11 | eq2 | `lib/eq2*`, `tools/eq2_main.c`, `tests/eq2_test.c`, `tests/eq2_corpus.h` | WP8 | no classify, no retail block |
| WP12 | float_order | `lib/float_order*`, `lib/scorer.*`, `tools/float_order_main.c`, `tests/float_order_*`, `tests/scorer_test.c` | WP8 | new synthetic corpus; scorer on fakecl |
| WP13 | flag_sweep | `lib/flag_sweep*`, `tools/flag_sweep_main.c`, `tests/flag_sweep_test.c` | WP8 | variant table on fakecl |
| WP14 | frame, residue | `lib/{frame,frame_slots,residue,residue_text}.*`, `tests/{frame,residue}*_test.c`, and the `--frame`/`--residue` hooks in `lib/unitcmp.c` (handed over from WP8) | WP10 | synthetic prologue corpus |

Order: WP0; then WP1-WP5 in parallel; WP6 once WP2 and WP3 are in; WP7; WP8; then WP9-WP13 in parallel; WP14
after WP10. A final integration step (the owner's) runs the whole workflow, the scrub and the local cross-check,
and updates `ctools/README.md` and vc8-decomp's `README.md` with one paragraph pointing at the toolkit.

## 9. Scrub checklist

`cmake/scrub.cmake` (the `scrub` CTest) fails on the **blocking** patterns over `ctools/` excluding
`third_party/`. The **review** patterns are printed for a person or reviewer agent to clear by hand before each
commit of ported code; a cleared hit needs no marker if it is plainly generic (for example an x86 opcode).

Blocking (case-insensitive unless noted):

```
\bavp\b|avp3|avp_|avpcore|avptools|AVP_[A-Z]|\bAvp[A-Z]          old prefix and project name
\bdx9\b|\bdx11\b|_dx9|_dx11|d3d9|d3d11|direct3d                   the source project's builds
asura|rebellion|predator|\balien|marine|xeno|sniper|simpsons|rogue warrior|shellshock
\bxex\b|x360|xbox|ps3|eboot|\bwii\b|dolphin|codewarrior|xdk
steam|steam_api|\bceg\b|steamstub
decompiled_dx11|ghidra_export|datarefs\.tsv
rtti_vtables|rtti_classes|server_map|referents\.json|lib_objects|sections\.tsv|console_map|proto_names
retail\.local\.json|matching/include|ltcg_ranges|stops\.json
[A-Z]:[\\/](avp|asura|steamlibrary)|[\\/]users[\\/]               machine paths and user profile folders
\b(stops|witness|permute|draft_loop|promote|match_report)\.(py|exe)\b  the source project's tools
```

Review (print and clear):

```
0x[0-9A-Fa-f]{6,8}\b            every long hex constant: must be synthetic or an x86/PE/PDB format constant
\?[A-Za-z_]\w*@@|\?\?[0-9_]     mangled names: must be synthetic test names
\.py\b                          Python references: only vc8-decomp's own tools/*.py may be named
ported from|port of|python      provenance comments: rewrite to describe behaviour
lemiur                          allowed only in LICENSE/NOTICE/SPDX headers
decompiled[/\\]|index\.tsv      Ghidra export paths: only in a configured symbol source, never hard-coded
```

Before the first commit of a package, its moved test corpora are also opened at their head comment to confirm a
synthetic origin (7.1).

## 10. Licensing

- Licence: **Creative Commons Attribution 4.0 International (CC BY 4.0)**, chosen by the user.
- `ctools/LICENSE` holds the CC BY 4.0 legal code verbatim, fetched by WP0 from
  `https://creativecommons.org/licenses/by/4.0/legalcode.txt` (not paraphrased, not abridged).
- `ctools/NOTICE` holds the attribution: `Copyright (c) lemiur and contributors. Licensed under CC BY 4.0
  (see LICENSE).`, a scope sentence (below) and a summary pointing at `third_party/NOTICES.txt`.
- Every source file the toolkit owns (`.c`, `.h`, `.inc`, `.cmake`, `CMakeLists.txt`, `CMakePresets.json` cannot
  carry comments and is covered by the directory notice) starts with:

  ```c
  /* SPDX-License-Identifier: CC-BY-4.0
   * Copyright (c) lemiur and contributors */
  ```

  (`#` comments in CMake files). The `scrub` test also checks that every owned source file carries the SPDX line.
- `ctools/third_party/` keeps each package's own licence files (capstone: BSD-3-Clause; PCRE2: BSD-3-Clause with
  its binary-like-libraries exception) and `third_party/NOTICES.txt` listing them with versions; no SPDX header is
  added to vendored files.
- **Scope:** the licence covers only `ctools/`. It does not cover vc8-decomp's reconstructed compiler sources
  (`matching/`), its Python tools, its configuration or documentation outside `ctools/`; the NOTICE says so, and no
  repository-wide LICENSE is added or changed by this work.
- Note for the owner: Creative Commons advises against its licences for software (no patent grant, no source
  requirement). The choice is the user's and stands; this note is only recorded here.

## 11. Open questions

- **Q1 (blocking for `c2_site_weights` only).** It needs the source project's C ports of vc8-decomp's own tracers
  (`c2_trace`, `c2_inline_trace`, `c2_toolchain`, `c2_symbols`, `vc8_root`). Contribute those ports too (they
  would duplicate `tools/c2_trace.py` and `tools/c2_inline_trace.py`), or leave `c2_site_weights` out? Default in
  this plan: out.
- **Q2.** Prefix `dk_` and project name `decompkit` (proposed) or another name.
- **Q3.** Whether to add a Windows CI job building `ctools/` (vc8-decomp has none today; AGENTS.md forbids
  network publication by workers, so the owner would add it). Default: no CI change.
- **Q4.** Confirm the ported files are solely the user's work (they become "lemiur and contributors" under CC BY
  4.0); any file with an outside author is held back until cleared.
