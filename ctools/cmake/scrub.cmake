# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) lemiur, TheCloakedCoder and contributors
#
# CTest test scrub (cmake -DROOT=<ctools> -P scrub.cmake): the toolkit must stay project-neutral. Fails when a
# blocking pattern (the names of the project the toolkit was written for, its builds, its machine paths) appears in
# any owned file, or when an owned source file lacks the SPDX line. third_party/ and build output are excluded.
if(NOT ROOT)
    message(FATAL_ERROR "scrub: pass -DROOT=<ctools>")
endif()

# Blocking patterns (the short tokens d3d9, d3d11, x360 and ps3 must not follow a letter or digit: hex data holds them),
# matched on the lower-cased text with CMake regular expressions.
set(blocking
    "(^|[^a-z0-9_])avp([^a-z0-9]|$)" "avp3" "avp_" "avpcore" "avptools"
    "(^|[^a-z0-9_])dx9([^a-z0-9]|$)" "(^|[^a-z0-9_])dx11([^a-z0-9]|$)" "_dx9" "_dx11" "(^|[^a-z0-9])d3d9" "(^|[^a-z0-9])d3d11" "direct3d"
    "asura" "rebellion" "predator" "(^|[^a-z0-9_])alien" "marine" "xeno" "sniper" "simpsons" "rogue warrior"
    "shellshock"
    "(^|[^a-z0-9_])xex([^a-z0-9]|$)" "(^|[^a-z0-9])x360" "xbox" "(^|[^a-z0-9])ps3" "eboot" "(^|[^a-z0-9_])wii([^a-z0-9]|$)" "dolphin"
    "codewarrior" "xdk"
    "steam" "(^|[^a-z0-9_])ceg([^a-z0-9]|$)" "steamstub"
    "decompiled_dx11" "ghidra_export" "datarefs[.]tsv"
    "rtti_vtables" "rtti_classes" "server_map" "referents[.]json" "lib_objects" "sections[.]tsv" "console_map"
    "proto_names"
    "retail[.]local[.]json" "matching/include" "ltcg_ranges" "stops[.]json"
    "[a-z]:[\\\\/](avp|asura|steamlibrary)" "[\\\\/]users[\\\\/]"
    "(^|[^a-z0-9_])(stops|witness|permute|draft_loop|promote|match_report)[.](py|exe)([^a-z0-9]|$)")

file(GLOB_RECURSE all_files "${ROOT}/*")
set(problems "")
set(scanned 0)
foreach(f ${all_files})
    file(RELATIVE_PATH rel "${ROOT}" "${f}")
    if(rel MATCHES "^(third_party|build)/" OR rel MATCHES "(^|/)(CMakeFiles|gen)/" OR rel STREQUAL "LICENSE"
       OR rel STREQUAL "cmake/scrub.cmake" OR rel MATCHES "[.](exe|obj|pdb|dll|lib)$")
        continue()
    endif()
    math(EXPR scanned "${scanned}+1")
    file(READ "${f}" text)
    string(TOLOWER "${text}" low)
    foreach(pat IN LISTS blocking)
        if(low MATCHES "${pat}")
            list(APPEND problems "${rel}: blocking pattern '${pat}'")
        endif()
    endforeach()
    if(rel MATCHES "[.](c|h|inc|cmake)$" OR rel MATCHES "(^|/)CMakeLists[.]txt$")
        if(NOT text MATCHES "SPDX-License-Identifier: CC-BY-4[.]0")
            list(APPEND problems "${rel}: no SPDX-License-Identifier: CC-BY-4.0 line")
        endif()
    endif()
endforeach()

if(problems)
    list(LENGTH problems n)
    string(REPLACE ";" "\n  " msg "${problems}")
    message(FATAL_ERROR "scrub: FAILED (${n} problems)\n  ${msg}")
endif()
message(STATUS "scrub: OK (${scanned} files scanned)")
