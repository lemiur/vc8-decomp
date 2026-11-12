# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) lemiur, TheCloakedCoder and contributors
# CTest test entry_points (cmake -DROOT=<ctools> -P entry_points.cmake): the enforcement half of the crash and hang
# policy (core/include/dk/base.h). Every executable must enter through DK_MAIN -> dk_start, whose first statement is
# dk_crash_quiet_init(); so no .c/.h under ctools (third_party and build output excluded) may define main, wmain,
# WinMain, wWinMain or DllMain itself, and dk_start must begin with that call.
if(NOT ROOT)
    message(FATAL_ERROR "entry_points: pass -DROOT=<ctools>")
endif()

# A definition (or declaration) with an entry point's return type at the start of a line (so a Python snippet quoted
# in a corpus header does not count).
set(entry_re "(^|\n)[ \t]*(static[ \t]+)?(int|BOOL|INT)[ \t]+((WINAPI|APIENTRY|CALLBACK|__stdcall)[ \t]+)?(wmain|main|WinMain|wWinMain|DllMain)[ \t]*[(]")
# The one legitimate definition: the DK_MAIN macro in base.h (its wmain line follows the #define's backslash).
set(macro_re "define DK_MAIN[(]run_fn, tool_name[)] .\n[ 	]*int wmain[(]")

file(GLOB_RECURSE sources "${ROOT}/*.c" "${ROOT}/*.h")
set(problems "")
set(scanned 0)
foreach(f ${sources})
    file(RELATIVE_PATH rel "${ROOT}" "${f}")
    if(rel MATCHES "^(third_party|build)/" OR rel MATCHES "(^|/)(CMakeFiles|gen)/")
        continue()
    endif()
    math(EXPR scanned "${scanned}+1")
    file(READ "${f}" text)
    string(REPLACE "\r\n" "\n" text "${text}")
    if(rel STREQUAL "core/include/dk/base.h")
        string(REGEX REPLACE "${macro_re}" "DK_MAIN_DEFINITION(" text "${text}")
    endif()
    if(text MATCHES "${entry_re}")
        list(APPEND problems "${rel}: defines ${CMAKE_MATCH_6} itself; use DK_MAIN (dk/base.h)")
    endif()
endforeach()

file(READ "${ROOT}/core/src/base.c" base_c)
set(start_re "int dk_start[(][^{]*[{][ \t\r\n]*dk_crash_quiet_init[(][)];")
if(NOT base_c MATCHES "${start_re}")
    list(APPEND problems "core/src/base.c: the first statement of dk_start is not the dk_crash_quiet_init() call")
endif()
file(READ "${ROOT}/core/include/dk/base.h" base_h)
if(NOT base_h MATCHES [=[int wmain[(]int argc, wchar_t [*][*]wargv[)] [{] return dk_start[(]]=])
    list(APPEND problems "core/include/dk/base.h: DK_MAIN no longer defines wmain through dk_start")
endif()

if(problems)
    string(REPLACE ";" "\n  " msg "${problems}")
    message(FATAL_ERROR "entry_points: FAILED\n  ${msg}")
endif()
message(STATUS "entry_points: OK (${scanned} files scanned)")
