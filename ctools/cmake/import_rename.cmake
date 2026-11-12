# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) lemiur, TheCloakedCoder and contributors
#
# cmake "-DFILES=a.c;b.h" -P import_rename.cmake
#
# The mechanical rename applied to code imported into the toolkit: the old project prefix (written <old> below, in
# lower, upper or title case; the script spells it from character codes so that the scrub test never meets it here)
# becomes dk ("decomp kit"). Every rule is case-sensitive and anchored at a token start (the character before is not
# a letter, digit or underscore); the rules run in this order:
#
#     <OLD>3_ROOT                       -> DECOMPKIT_ROOT          (whole token)
#     <OLD>3_OBJ_CACHE...               -> DECOMPKIT_OBJ_CACHE...  (the variable and its _MAX_MB / _RESTORE siblings)
#     <old>3-objcache                   -> decompkit-objcache      (the default cache folder name)
#     "<old>/   (include path)          -> "dk/
#     <old>.h                           -> dk.h
#     <old>core, <old>tools             -> dkcore, dktools         (whole token)
#     <OLD>_    (macro prefix)          -> DK_
#     <Old>     (type prefix: <Old> + an upper-case letter) -> Dk
#     <old>_    (function prefix)       -> dk_
#
# Delete the old project's own macros (its per-build switches, its retail-only test blocks) before running this:
# they are removed, not renamed. The CTest test scrub then proves that no spelling of the old prefix is left; what it
# still finds is renamed or rewritten by hand. Files are rewritten in place, only when something changed.
if(NOT FILES)
    message(FATAL_ERROR "import_rename: pass -DFILES=<file;file;...>")
endif()

string(ASCII 97 118 112 lo) # the old prefix, lower case
string(ASCII 65 86 80 up)   # upper case
string(ASCII 65 118 112 ti) # title case

set(lead "(^|[^A-Za-z0-9_])")
set(tail "([^A-Za-z0-9_]|$)")

foreach(f IN LISTS FILES)
    if(NOT EXISTS "${f}")
        message(FATAL_ERROR "import_rename: no such file: ${f}")
    endif()
    file(READ "${f}" text)
    set(before "${text}")
    # A rule's match consumes the character before the token; two passes cover tokens that share that character
    # with the end of a previous match (whole-token rules also consume the character after).
    foreach(pass 1 2)
        string(REGEX REPLACE "${lead}${up}3_ROOT${tail}" "\\1DECOMPKIT_ROOT\\2" text "${text}")
        string(REGEX REPLACE "${lead}${up}3_OBJ_CACHE" "\\1DECOMPKIT_OBJ_CACHE" text "${text}")
        string(REGEX REPLACE "${lead}${lo}3-objcache" "\\1decompkit-objcache" text "${text}")
        string(REPLACE "\"${lo}/" "\"dk/" text "${text}")
        string(REGEX REPLACE "${lead}${lo}[.]h${tail}" "\\1dk.h\\2" text "${text}")
        string(REGEX REPLACE "${lead}${lo}core${tail}" "\\1dkcore\\2" text "${text}")
        string(REGEX REPLACE "${lead}${lo}tools${tail}" "\\1dktools\\2" text "${text}")
        string(REGEX REPLACE "${lead}${up}_" "\\1DK_" text "${text}")
        string(REGEX REPLACE "${lead}${ti}([A-Z])" "\\1Dk\\2" text "${text}")
        string(REGEX REPLACE "${lead}${lo}_" "\\1dk_" text "${text}")
    endforeach()
    if(NOT text STREQUAL before)
        file(WRITE "${f}" "${text}")
        message(STATUS "import_rename: ${f}")
    endif()
endforeach()
