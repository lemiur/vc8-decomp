# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) lemiur, TheCloakedCoder and contributors
# Vendored libraries (NOTICES.txt). Built with their own warning level: /W4 applies to the toolkit's code only.
# Each package keeps its own licence files; no toolkit licence header is added to vendored files.

# capstone 5.0.7, x86 only
file(GLOB CS_ARCH_SOURCES capstone/arch/X86/*.c)
add_library(dk_capstone STATIC capstone/cs.c capstone/Mapping.c capstone/MCInst.c capstone/MCInstrDesc.c
    capstone/MCRegisterInfo.c capstone/SStream.c capstone/utils.c ${CS_ARCH_SOURCES})
target_include_directories(dk_capstone PUBLIC capstone/include PRIVATE capstone)
target_compile_definitions(dk_capstone PUBLIC CAPSTONE_HAS_X86 PRIVATE CAPSTONE_USE_SYS_DYN_MEM
    _CRT_SECURE_NO_WARNINGS)
target_compile_options(dk_capstone PRIVATE /W0 /utf-8)

# PCRE2 10.44, 8-bit, Unicode, JIT (pcre2_jit_match.c and pcre2_jit_misc.c are included by pcre2_jit_compile.c)
set(P pcre2/src)
add_library(dk_pcre2 STATIC ${P}/pcre2_auto_possess.c ${P}/pcre2_chartables.c ${P}/pcre2_chkdint.c
    ${P}/pcre2_compile.c ${P}/pcre2_config.c ${P}/pcre2_context.c ${P}/pcre2_convert.c ${P}/pcre2_dfa_match.c
    ${P}/pcre2_error.c ${P}/pcre2_extuni.c ${P}/pcre2_find_bracket.c ${P}/pcre2_jit_compile.c
    ${P}/pcre2_maketables.c ${P}/pcre2_match.c ${P}/pcre2_match_data.c ${P}/pcre2_newline.c ${P}/pcre2_ord2utf.c
    ${P}/pcre2_pattern_info.c ${P}/pcre2_script_run.c ${P}/pcre2_serialize.c ${P}/pcre2_string_utils.c
    ${P}/pcre2_study.c ${P}/pcre2_substitute.c ${P}/pcre2_substring.c ${P}/pcre2_tables.c ${P}/pcre2_ucd.c
    ${P}/pcre2_valid_utf.c ${P}/pcre2_xclass.c)
target_include_directories(dk_pcre2 PUBLIC ${P})
target_compile_definitions(dk_pcre2 PUBLIC PCRE2_CODE_UNIT_WIDTH=8 PCRE2_STATIC
    PRIVATE HAVE_CONFIG_H SUPPORT_UNICODE SUPPORT_JIT HAVE_MEMMOVE HAVE_STDINT_H HAVE_INTTYPES_H HAVE_LIMITS_H
    HAVE_STRERROR HAVE_WINDOWS_H _CRT_SECURE_NO_WARNINGS)
target_compile_options(dk_pcre2 PRIVATE /W0 /utf-8)
