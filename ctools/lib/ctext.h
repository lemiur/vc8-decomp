// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* ctext: text helpers over C and C++ statements and x86 register names, shared by the source-rewriting tools
 * (float_order's spellings, the scorer's candidates). They read one statement or expression as text, with regular
 * expressions and bracket counting: no parser, so they answer for the simple statements a function body is made of
 * (declarations, assignments, calls, returns) and conservatively otherwise.
 *
 * Sets are heap sets (dk_set_free); strings are views into the argument. */
#pragma once
#include "dk/map.h"
#include "dk/str.h"

/* An operand-like token: a name with member accesses, subscripts and "()" calls, a hex or decimal literal. */
#define DK_CTEXT_TOKEN \
    "[A-Za-z_][\\w]*(?:(?:\\.|->)[A-Za-z_]\\w*|\\[[^\\[\\]]*\\]|\\(\\))*|0x[0-9A-Fa-f]+|\\d+(?:\\.\\d*)?f?"
/* A declaration's type: qualifiers, a (scoped, templated) name, then pointers or a reference. */
#define DK_CTEXT_TYPE "(?:const\\s+)?(?:unsigned\\s+|signed\\s+)?[A-Za-z_][\\w:]*(?:<[^;=()]*>)?(?:\\s*\\*+|\\s*&)?"
#define DK_CTEXT_DECL_INIT_PAT "^(\\s*)(" DK_CTEXT_TYPE "\\s+\\**)([A-Za-z_]\\w*) = (.+);\\s*$"
#define DK_CTEXT_DECL_ONLY_PAT "^(\\s*)(" DK_CTEXT_TYPE "\\s+\\**)([A-Za-z_]\\w*);\\s*$"
#define DK_CTEXT_CONTROL_PAT \
    "^(if|else|for|while|do|switch|case|default|return|break|continue|goto|try|catch|\\}|\\{|#)\\b"
#define DK_CTEXT_CALL_PAT "[A-Za-z_]\\w*\\s*\\("
#define DK_CTEXT_NOT_CALLS_PAT "\\b(?:if|for|while|switch|return|sizeof|static_cast|const_cast)\\s*\\("
#define DK_CTEXT_REG_PAT "\\b(e?[abcd]x|[abcd][lh]|e?(?:si|di|bp|sp)|xmm[0-7]|st\\(\\d\\)|st|mm[0-7])\\b"

/* ---- registers ---- */
/* The 32-bit register of an 8- or 16-bit general register name (al, ah, ax -> eax; si -> esi; sp -> esp), r itself
 * otherwise. */
const char *dk_ctext_reg_full(const char *r);
/* The register's allocation class: "xmm", "st", "mm", "esp"/"sp" (the stack pointer, not allocated: r itself),
 * "r32", "r8" or "r16". */
const char *dk_ctext_reg_class(const char *r);

/* ---- statements ---- */
/* The line without its "//" comment, stripped. */
DkStr dk_ctext_code_of(DkStr line);
/* The number of calls in text: "name(" sites once if/for/while/switch/return/sizeof/static_cast/const_cast heads are
 * removed. */
i64 dk_ctext_calls(DkStr text);
/* The names a simple statement writes: a declared name, the left side of each (compound) assignment (its last member
 * for a member access, subscripts dropped) and each incremented or decremented name. */
DkSet *dk_ctext_written(DkStr text);
/* Every identifier the text names (a superset of what it reads). */
DkSet *dk_ctext_read(DkStr text);
/* Whether a word cannot start a declaration's type (return, delete, goto, else, case, throw, new). */
bool dk_ctext_not_type(DkStr first_word);
/* Splits text at the first sep at bracket depth 0 (":" never splits "::"); false when there is none. A bracket
 * character only changes the depth, so a sep that starts with a bracket never splits. */
bool dk_ctext_split_top(DkStr text, const char *sep, DkStr *left, DkStr *right);
/* Whether expr needs no parentheses as an operand: a token (DK_CTEXT_TOKEN). An expression in parentheses is not
 * atomic: its closing parenthesis is looked for with dk_ctext_split_top, which never splits at a bracket, so callers
 * that wrap a non-atomic operand wrap it again (harmless for the compiler; the spellings the search tools generate depend on it). */
bool dk_ctext_atomic(DkStr expr);
