# ctools: the decompiler toolkit

A set of C tools and a runtime library for matching decompilation with Visual C++ 2005 SP1 (see
`docs/c-toolkit-design.md`). This directory is self-contained and licensed under CC BY 4.0 (`LICENSE`, `NOTICE`);
vendored libraries keep their own licences (`third_party/NOTICES.txt`).

## Build

Requirements: CMake 3.25 or later and MSVC 19.30 or later (Visual Studio 2022 or newer), x64. From this directory:

    cmake --workflow --preset ctools-build     configure and build (Release, no tests)
    cmake --workflow --preset ctools           configure, build and run every test
    cmake --workflow --preset ctools-debug     the same in Debug

Presets `ctools-vs2022` and `ctools-vs2026` name the Visual Studio generator explicitly. Executables land in
`<repo>/build/ctools/bin/` (Debug: `build/ctools/bin/debug/`), CMake build trees in `build/ctools-cmake[-debug]`.
The code builds with `/W4 /WX`. Sources are registered by glob: `core/src/*.c` (library `dkcore`), `lib/*.c`
(library `dktools`), `tools/<name>_main.c` (one executable each), `core/tests/*.c` and `tests/*.c` (one CTest each).
Besides the unit tests, the CTest tests `entry_points` (every executable enters through `DK_MAIN`) and `scrub`
(the toolkit names no project, build or machine path, and every owned source file carries its SPDX line) run.

## Layout

    core/include/dk/*.h, core/src/*.c   runtime library dkcore (strings, containers, JSON, CSV, hashing, processes,
                                        file system, regular expressions, diff, x86 disassembly, PE reader, arguments)
    core/tests/                         core unit tests (synthetic or language-semantics corpora only)
    lib/, tools/, tests/                tool modules, executables and tool tests (added by later work packages)
    cmake/                              entry_points.cmake, scrub.cmake, tools_stamp.cmake
    third_party/                        capstone (x86 only), PCRE2

## Configuration

The root of the repository is, in order: `--root DIR`, the environment variable `DECOMPKIT_ROOT`, the folder above the
executable that holds `ctools/CMakeLists.txt`, the nearest folder at or above the current directory that holds
`config/ctools.json`. Machine-specific settings go in the ignored `config/ctools.local.json`.

## Tools

None yet: the tools are added by later work packages, one line each below.
