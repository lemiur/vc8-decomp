# ctools: the decompiler toolkit

A set of C tools and a runtime library for matching decompilation with Visual C++ 2005 SP1 (see
`docs/c-toolkit-design.md`). This directory is self-contained and licensed under CC BY 4.0 (`LICENSE`, `NOTICE`);
vendored libraries keep their own licences (`third_party/NOTICES.txt`).

The tools are **diagnostics**: they build a unit, compare it with the reference image and explain the difference
(control flow, frames, register renames, float order, compiler options, symbolic equivalence). They never decide
what is matched. In vc8-decomp that authority stays with `tools/match.py` (the retail comparison) and
`tools/gate.py` (the byte gate); a `MATCH` from `unitcmp` is a lead until the gate banks it.

## Build

Requirements: CMake 3.25 or later and MSVC 19.30 or later (Visual Studio 2022 or newer), x64. From this directory
(in a developer command prompt, or after `VsDevCmd.bat -arch=x64` when cmake and cl are not on `PATH`):

    cmake --workflow --preset ctools-build     configure and build (Release, no tests)
    cmake --workflow --preset ctools           configure, build and run every test
    cmake --workflow --preset ctools-debug     the same in Debug

Presets `ctools-vs2022` and `ctools-vs2026` name the Visual Studio generator explicitly. Executables land in
`<repo>/build/ctools/bin/` (Debug: `build/ctools/bin/debug/`), CMake build trees in `build/ctools-cmake[-debug]`.
The code builds with `/W4 /WX`. Sources are registered by glob: `core/src/*.c` (library `dkcore`), `lib/*.c`
(library `dktools`), `tools/<name>_main.c` (one executable each), `core/tests/*.c` and `tests/*.c` (one CTest each).
Besides the unit tests, the CTest tests `entry_points` (every executable enters through `DK_MAIN`) and `scrub`
(the toolkit names no project, build or machine path, and every owned source file carries its SPDX line) run.
Every test corpus is synthetic: no Microsoft binary, header or PDB is checked in.

## Layout

    core/include/dk/*.h, core/src/*.c   runtime library dkcore (strings, containers, JSON, CSV, hashing, processes,
                                        file system, regular expressions, diff, x86 disassembly, PE reader, arguments)
    core/tests/                         core unit tests (synthetic or language-semantics corpora only)
    lib/                                the project adapter (project*.c: configuration, annotations, symbol sources,
                                        images, build backends, comparison), COFF and PDB readers, the tool modules
    tools/<name>_main.c                 one executable per tool
    tests/                              tool tests, a fake compiler and linker (tests/fakecl) and synthetic corpora
    cmake/                              entry_points.cmake, scrub.cmake, tools_stamp.cmake
    third_party/                        capstone (x86 only), PCRE2

## Tools

Every tool prints its full usage with `--help` (`rich_header` takes only paths). The tools that read the project
take `--root DIR` (the repository) and `--config FILE` (default `<root>/config/ctools.json`); `<unit>` is a
repository-relative path or a unique stem, `<target>` a target of the configuration.

| tool | purpose | command line |
|---|---|---|
| `unitcmp` | build units with the configured backend and compare every annotated function with the reference image: status per function and target (`MATCH`, `DIFF`, `SIZE`, `REFERENT`, `UNRESOLVED`, `MISSING`, `ERROR`), the wall class, a side-by-side diff, the stack frames, the residue's register renames | `unitcmp [units... \| --all] [--target T] [--function NAME] [--summary] [--diff [--max-rows N]] [--json FILE] [--frame] [--residue] [--no-cache]` |
| `disasm` | disassembly and cross references of a target's reference image, named through its symbol sources and the annotations | `disasm <target> 0x<va> [--size 0x..] [--no-bytes]`; `--xref`; `--data --words N`; `disasm <target> --name REGEX`; `--thunks [0x<start> --size 0x<n>] [--all]` |
| `cfg_diff` | align the basic-block graphs of ours and the reference's and name each structural difference (inverted branch, block order, loop rotation, merged or duplicated tail, switch lowering...) with the source lever | `cfg_diff <unit> <Name> [--target T\|all] [--address 0x..] [--html] [--dot] [-v]`; `cfg_diff --batch [units... \| --all] [--select REGEX] [--all-walls] [--stopped] [--out DIR]` |
| `eq2` | symbolic equivalence: run ours and the reference in lockstep on symbolic inputs and compare branches, calls, stores and returns path by path | `eq2 <unit> <Function>[,<Function>... \| ALL] [--target T] [-v]` |
| `float_order` | the float expression trees of ours and the reference's, each node classified, and the spellings that reproduce the reference's order | `float_order <unit> <Name> [--target T] [--address 0x..] [--minutes 5] [--workers N]`; `float_order --batch [--select REGEX] [--units a,b] [--minutes 3] [--jobs N]` |
| `flag_sweep` | build a unit under one-option variants of its compiler options and show which variants still match (does a unit's flags line matter, and is it the only one that matches) | `flag_sweep <unit> [--targets a,b\|all] [--variants default\|extended] [--no-cache] [--json FILE]` |
| `xmatch` | find a function of one PE32 image in another by masked bytes | `xmatch <image_a> <va> <image_b> [--size N] [--top K]` |
| `pdb_dump` | list the publics, modules, procedures, lines or types of a PDB 7.00 | `pdb_dump [--tsv] [--legacy] <pdb> {publics,modules,procs,lines,types}` |
| `rich_header` | decode the Rich header of PE files (the tools and builds that produced their objects) | `rich_header <file>...` |
| `text_checks` | a UTF-8 BOM under the configured folders, merge conflict markers, over the tracked files | `text_checks [--paths P...] [--bom-under P...]` |
| `lane_lock` | checkout locks and the lane registry (which session works in which checkout, branch and units) | `lane_lock claim\|release\|status\|check ...` |
| `slot_lock` | the slot lock of one worktree (which agent works in it) | `slot_lock take --agent ID [--note TEXT] [--force]`; `status`; `release --agent ID \| --force` |

## Configuration

The root of the repository is, in order: `--root DIR`, the environment variable `DECOMPKIT_ROOT`, the folder above the
executable that holds `ctools/CMakeLists.txt`, the nearest folder at or above the current directory that holds
`config/ctools.json`. The configuration is `config/ctools.json`, deep-merged with the ignored
`config/ctools.local.json` (objects member by member, anything else replaced): machine paths go in the local file.
Unknown keys are errors, named with their path.

**References and variables.** Any value may be `{"$from": "config/file.json#/json/pointer", "default": value}`:
the value that RFC 6901 pointer names in another file of the repository (`default` when the file or the member is
missing); a reference inside a list splices a list's elements. Strings interpolate `${name}` from `vars` and the
built-ins `${root}` (the repository), `${primary}` (for a git worktree, the main checkout: shared ignored inputs such
as a symbol store), `${target}`, `${unit}` and `${out}` (the build folder of one unit).

**Targets** (`targets`, at most 8): `image` (required), `sha256` (pinned; a mismatch is an error), `image_base`
(optional check), `defines` (per-target macros), `symbols` (the symbol sources, below), `units` and `link_with`
(merged into the project's), `compiler` (laid over the project's compiler block member by member).

**Units** (`units`): `roots`, `exclude`, `extensions` discover the sources; `map` (a unit map, `{"<path>":
{...}}`) gives per-unit options: `compile_flags`, `remove_compile_flags`, `link_flags`, `gl` (the `/GL` setting of
the link backend), `flags_line`, `link_with` (sources linked with the unit) and `link_roots` (extra decorated
`/INCLUDE:` roots). `link_with` at `units` or target level takes a project's existing files as they are: a map
`{"<unit>": ["<source>", ...]}` or a list of `{"unit", "dependencies", "roots"}` entries (other members ignored).
Each source linked with a unit is compiled with its own unit options (else with the compiler's flags alone) and
its own `/GL` setting, never with a tool's extra flags, and linked after the unit in path order.

**Symbol sources** (per target, in order; the first source that names an address wins, a later one adds new
addresses and fills unknown sizes; annotation names are laid on top):

| kind | reads | options |
|---|---|---|
| `tsv` | a header row, then one row per symbol; the address is the VA column, else the RVA column plus the image base; decimal or `0x` hex; an empty size is unknown | `name`, `va`, `rva`, `size`: the column names (defaults `name`, `va`, `rva`, `size`) |
| `pdb` | the publics (decorated names), then the module procedures for addresses no public names. `path` is a PDB file or a symbol store folder `<name>.pdb/<GUID><age>/<name>.pdb`: the entry the image's CodeView record asks for, else the folder's only entry | none |
| `map` | the "Publics by Value" and "Static symbols" tables of an MSVC linker map (VAs; sizes unknown) | none |
| `candidates` | the named objects and functions of a candidates file `{"referents": {"<binary>": {"<name>": {"va", "kind", "size"}}}}` | `name`: the binary, when the file lists several |

**Compiler** (`compiler`): `cl`, `env` (`INCLUDE`, `LIB` and other variables for the compiler and linker),
`path_prepend`, `base_flags`, `c_flags`, `cpp_flags`, `include`, `identity_files` (hashed into the object cache's
key), `show_includes`, `flag_variants` (`flag_sweep`'s list of option lists, each applied over the baseline; the
built-in list otherwise) and `cdecl_import_dlls` (import libraries whose functions are cdecl, shell patterns, for
the frame report; `msvcr*` when unset).

**Backend** (`backend.kind`): `object` (compile, cut each function from the COFF object), `link` (compile with the
unit's `/GL` setting and link with `backend.link.argv`, where `${objects}`, `${roots}` and `${out}` expand; with
`discovery_compile` a `/GL-` compile first names the link roots; each function is read from the linked image up to
the next map symbol, an unverified boundary) or `manifest` (the candidates of a build manifest, from
`backend.manifest.command` or `backend.manifest.path`).

**Annotations** (`annotations`): `marker` (a regex with named groups `kind` and either `target` and `addr`, or one
`addr_<target>` per target: `addr_groups` is `target+addr` or `per-target`), `kinds` (marker text to `function`,
`data`, `decl` or `vtable`), `name` (`declaration` or `next_line`), and the companion-line regexes `symbol`, `stop`,
`pending`, `flags` (`flags_lines`). Python-style `(?P<name>...)` groups are accepted.

Also: `referents` (`[{"file", "format": "json-symbols" | "tsv"}]`), `well_known` (`imports`: resolve `__imp_`
names through the import table; `symbols`: names looked up in the symbol sources), `build_dir` (default
`${root}/build/ctools`) and `text_checks` (`paths`, `no_bom`).

### Worked example: vc8-decomp's `matching/cl` units

The configuration below compares the units of `matching/cl` with `cl.exe` through the `link` backend (`/GL` and
`/LTCG`, as `tools/match.py` links them). Everything project-specific is a reference into vc8-decomp's own files:
the toolchain root, the pinned hash and image base, the units, their link dependencies (`config/cl.json` and the
candidate census `config/cl-candidates.json`), the compile and link flags and the annotation pattern.

`config/ctools.json`:

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
             "symbols": [{"kind": "pdb", "path": "${symbols}/cl.pdb"},
                         {"kind": "candidates", "path": "${root}/config/cl-candidates.json", "name": "cl"}],
             "units": {"$from": "config/cl.json#/units"},
             "link_with": {"$from": "config/cl.json#/dependencies", "default": {}}}
  },
  "units": {"roots": ["matching"], "extensions": [".c", ".cpp"],
            "link_with": {"$from": "config/cl-candidates.json#/candidates", "default": []}},
  "compiler": {
    "cl": "${toolchain_root}/bin/cl.exe",
    "base_flags": ["/c", {"$from": "config/cl.json#/flags/compile"}],
    "cpp_flags": [],
    "env": {"INCLUDE": "${toolchain_root}/include;${toolchain_root}/PlatformSDK/include",
            "LIB": "${toolchain_root}/lib;${toolchain_root}/PlatformSDK/lib"},
    "path_prepend": ["${toolchain_root}/bin", "${toolchain_root}/../Common7/IDE"],
    "identity_files": ["${toolchain_root}/bin/cl.exe", "${toolchain_root}/bin/c1.dll",
                       "${toolchain_root}/bin/c1xx.dll", "${toolchain_root}/bin/c2.dll"],
    "show_includes": true
  },
  "referents": [],
  "backend": {
    "kind": "link",
    "link": {"linker": "${toolchain_root}/bin/link.exe",
             "argv": ["/nologo", "/DLL", "/NOENTRY", "/LTCG", "/MACHINE:X86", "/INCREMENTAL:NO",
                      {"$from": "config/project.json#/project/link_flags"}, "/MANIFEST:NO",
                      "/OUT:${out}/candidate.dll", "/MAP:${out}/candidate.map", "${roots}", "${objects}",
                      "kernel32.lib"],
             "roots": "annotations", "map": "msvc", "discovery_compile": true}
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

`config/ctools.local.json` (ignored) holds what differs per machine; for example a toolchain installed elsewhere
than `config/project.json` says, its Platform SDK, and a symbol store outside the main checkout:

```json
{
  "vars": {"toolchain_root": "<VC8 root>/VC", "symbols": "<symbol store>"},
  "compiler": {"env": {"INCLUDE": "<VC8 root>/VC/include;<Platform SDK>/include",
                       "LIB": "<VC8 root>/VC/lib;<Platform SDK>/lib"}}
}
```

When the objects do not name the C runtime themselves, add `/NODEFAULTLIB` and the import library (`msvcrt.lib`)
to the link `argv`. Then, from the repository:

    build/ctools/bin/unitcmp.exe --all --target cl --summary
    build/ctools/bin/unitcmp.exe matching/cl/util.cpp --function strqlen --diff
    build/ctools/bin/cfg_diff.exe matching/cl/util.cpp strqlen --target cl
    build/ctools/bin/disasm.exe cl 0x<va>

On the 17 units of `matching/cl` this configuration agrees with `tools/match.py` on every annotated function (106
of 106: `unitcmp` reports `MATCH` exactly where `match.py` reports `MATCH-PENDING`, an exact candidate awaiting rule
admission and the gate).

## Licence

CC BY 4.0 (`LICENSE`; the copyright holders are named in `NOTICE`). The licence covers `ctools/`
only (not `third_party/`, which keeps each package's own licence, and nothing else of the repository).
