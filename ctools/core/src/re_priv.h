// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore re: private interface between re.c (matching, templates, cache) and re_translate.c (the Python-regex to
 * PCRE2 translator). Not part of the public API. */
#pragma once
#include "dk/re.h"

/* The result of translating a Python pattern. All memory is malloc'd (the translated text, the name and parent
 * tables) and owned by the DkRe that keeps this struct. */
typedef struct ReTrans {
    char *pcre;      /* the PCRE2 pattern, NUL-terminated */
    size_t pcre_len;
    int ngroups;     /* capturing groups */
    char **names;    /* [0..ngroups]: the group's name or NULL; names[0] is NULL */
    int *parent;     /* [0..ngroups]: the enclosing capturing group (0 = none) */
    bool bytes;      /* a bytes pattern: no UTF, no UCP */
    bool caseless;   /* PCRE2_CASELESS for the whole pattern (global i flag) */
    bool ucp;        /* PCRE2_UCP: Unicode \w \d \s \b (a str pattern without the ASCII flag) */
    int pyflags;     /* Python's re.flags of the pattern (given flags, the global inline ones, U for str) */
} ReTrans;

/* Translates `pattern` (UTF-8 for a str pattern, raw bytes with DK_RE_BYTES in flags). false: err holds
 * Python's re.error text. */
bool re_translate(DkStr pattern, int flags, ReTrans *out, char *err, size_t errcap);
void re_trans_free(ReTrans *t);

/* Formats Python's str(re.error(msg, pattern, pos)): "<msg> at position N" and " (line L, column C)" when the
 * pattern holds a newline. pos is a byte offset into pattern (converted to a code point index for str). */
void re_format_error(char *dst, size_t cap, const char *msg, DkStr pattern, size_t bytepos, bool bytes);
/* The same without position, for errors Python raises as another exception (IndexError "unknown group name"). */
