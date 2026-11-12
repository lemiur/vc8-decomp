# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) lemiur, TheCloakedCoder and contributors
#
# The decompiler toolkit (ctools): the runtime library dkcore, the tool modules dktools, one executable per tool,
# the unit tests. Build from this directory (a Visual Studio 2022 or newer developer prompt has cmake on the PATH):
#     cmake --workflow --preset ctools-build      configure and build (Release, no tests)
#     cmake --workflow --preset ctools            configure, build and run the tests
# The executables land in <repo>/build/ctools/bin/ (preset ctools-debug: build/ctools/bin/debug/).
cmake_minimum_required(VERSION 3.25)
project(decompkit LANGUAGES C)

if(NOT MSVC OR MSVC_VERSION LESS 1930)
    message(FATAL_ERROR "decompkit: built with MSVC 19.30 or later (Visual Studio 2022 or newer) only")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "decompkit: build the toolkit as x64 (use a preset of CMakePresets.json)")
endif()

get_filename_component(DK_REPO "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(DK_TOOLS_OUT "${DK_REPO}/build/ctools/bin" CACHE PATH "where the tool executables go")
# $<0:> keeps multi-config generators from adding a per-configuration folder.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${DK_TOOLS_OUT}$<0:>")
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Vendored code builds with its own flags; ours is C17.
add_subdirectory(third_party)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Our code: /W4 clean, warnings are errors.
set(DK_C_FLAGS /W4 /WX /utf-8 /Zc:preprocessor /Oi /Gy $<$<CONFIG:Release>:/GL>)
set(DK_C_DEFS WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
add_link_options($<$<CONFIG:Release>:/LTCG> $<$<CONFIG:Release>:/OPT:REF> $<$<CONFIG:Release>:/OPT:ICF>)
if(MSVC_VERSION GREATER_EQUAL 1950)
    # /d2:-scheduler-: under /LTCG the instruction scheduler of MSVC 14.51 moves a store past a load of the same stack
    # slot when a struct-valued ?: has an inlined arm (the result keeps an old pointer; core/tests/struct_cond_test.c).
    add_link_options($<$<CONFIG:Release>:/d2:-scheduler->)
endif()

file(GLOB DKCORE_SOURCES CONFIGURE_DEPENDS core/src/*.c)
# dk_tools_stamp(): the hash of the toolkit's C sources (cmake/tools_stamp.cmake), regenerated when any of them changes.
file(GLOB_RECURSE DK_STAMPED_SOURCES CONFIGURE_DEPENDS core/src/* core/include/* lib/*)
set(DK_TOOLS_STAMP_C ${CMAKE_CURRENT_BINARY_DIR}/gen/tools_stamp.c)
add_custom_command(OUTPUT ${DK_TOOLS_STAMP_C}
    COMMAND ${CMAKE_COMMAND} -DROOT=${CMAKE_CURRENT_SOURCE_DIR} -DOUT=${DK_TOOLS_STAMP_C}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tools_stamp.cmake
    DEPENDS ${DK_STAMPED_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tools_stamp.cmake
    COMMENT "tools stamp" VERBATIM)
add_library(dkcore STATIC ${DKCORE_SOURCES} ${DK_TOOLS_STAMP_C})
target_include_directories(dkcore PUBLIC core/include)
target_compile_options(dkcore PRIVATE ${DK_C_FLAGS})
target_compile_definitions(dkcore PUBLIC ${DK_C_DEFS})
target_link_libraries(dkcore PUBLIC dk_capstone dk_pcre2 bcrypt shlwapi advapi32 dbghelp wer)

# The tool modules: lib/<module>*.c, usage text in lib/<module>_doc.inc.
file(GLOB DKTOOLS_SOURCES CONFIGURE_DEPENDS lib/*.c)
if(DKTOOLS_SOURCES)
    add_library(dktools STATIC ${DKTOOLS_SOURCES})
    target_include_directories(dktools PUBLIC lib)
    target_compile_options(dktools PRIVATE ${DK_C_FLAGS})
    target_link_libraries(dktools PUBLIC dkcore)
else()
    add_library(dktools INTERFACE)
    target_link_libraries(dktools INTERFACE dkcore)
endif()

# One executable per tool: tools/<tool>_main.c -> <tool>.exe
file(GLOB DK_TOOL_MAINS CONFIGURE_DEPENDS tools/*_main.c)
foreach(main ${DK_TOOL_MAINS})
    get_filename_component(name "${main}" NAME_WE)
    string(REGEX REPLACE "_main$" "" name "${name}")
    add_executable(${name} ${main})
    target_compile_options(${name} PRIVATE ${DK_C_FLAGS})
    target_link_libraries(${name} PRIVATE dktools)
endforeach()

# Unit tests: core/tests/<name>.c and tests/<name>.c -> tests/test_<name>.exe, each one a CTest test run from the
# repository root.
enable_testing()
set(DK_TEST_TIMEOUT 600 CACHE STRING "seconds a CTest test may run before CTest kills it")
file(GLOB DK_TESTS CONFIGURE_DEPENDS core/tests/*.c tests/*.c)
foreach(src ${DK_TESTS})
    get_filename_component(name "${src}" NAME_WE)
    add_executable(test_${name} ${src})
    set_target_properties(test_${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${DK_TOOLS_OUT}/tests$<0:>")
    target_compile_options(test_${name} PRIVATE ${DK_C_FLAGS})
    target_link_libraries(test_${name} PRIVATE dktools)
    add_test(NAME ${name} COMMAND test_${name} WORKING_DIRECTORY "${DK_REPO}")
    # A test that runs past this was waiting for something: CTest kills it (crash and hang policy, base.h).
    set_tests_properties(${name} PROPERTIES TIMEOUT ${DK_TEST_TIMEOUT})
endforeach()

# Every executable enters through DK_MAIN -> dk_start -> dk_crash_quiet_init (cmake/entry_points.cmake).
add_test(NAME entry_points COMMAND ${CMAKE_COMMAND} -DROOT=${CMAKE_CURRENT_SOURCE_DIR}
         -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/entry_points.cmake)
set_tests_properties(entry_points PROPERTIES TIMEOUT ${DK_TEST_TIMEOUT})

# The toolkit stays project-neutral and every owned source file carries its licence line (cmake/scrub.cmake).
add_test(NAME scrub COMMAND ${CMAKE_COMMAND} -DROOT=${CMAKE_CURRENT_SOURCE_DIR}
         -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/scrub.cmake)
set_tests_properties(scrub PROPERTIES TIMEOUT ${DK_TEST_TIMEOUT})
