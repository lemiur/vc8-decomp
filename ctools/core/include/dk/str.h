// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Strings. Text is UTF-8 everywhere (files, arguments, output). DkStr is a view (pointer + byte length, not
 * necessarily NUL-terminated); DkBuf builds strings. The functions follow the Python str methods they are named
 * after, including the edge cases (negative indices clamp as slices do, split() without a separator splits on runs of
 * whitespace and drops empty fields, splitlines() knows Python's line boundaries). Comparisons are by bytes, which for
 * UTF-8 is the code point order Python's str comparison uses.
 *
 * Python's whitespace (str.isspace / split() / strip()) is the Unicode one: ASCII \t \n \v \f \r space, \x1c-\x1f,
 * and U+0085, U+00A0, U+1680, U+2000-U+200A, U+2028, U+2029, U+202F, U+205F, U+3000; the functions below use that set.
 *
 * Results that are views (strip, slice, partition, split fields) point into the input. Results that are new
 * strings are allocated from the arena given. */
#pragma once
#include "arena.h"
#include "vec.h"

typedef struct {
    const char *p;
    size_t n;
} DkStr;
typedef DK_VEC(DkStr) DkStrVec;

#define DK_S(lit) ((DkStr){"" lit, sizeof(lit) - 1}) /* a string literal as an DkStr */
#define DK_SF(s) (int)(s).n, (s).p                    /* printf("%.*s", DK_SF(s)) */

DkStr dk_str(const char *cz); /* NULL gives the empty string */
DkStr dk_strn(const char *p, size_t n);
char *dk_cz(DkArena *a, DkStr s); /* a NUL-terminated copy */
DkStr dk_str_dup(DkArena *a, DkStr s);

bool dk_str_eq(DkStr a, DkStr b);
bool dk_str_eqz(DkStr a, const char *cz);
int dk_str_cmp(DkStr a, DkStr b); /* <0, 0, >0: byte order (code point order) */
bool dk_str_startswith(DkStr s, DkStr prefix);
bool dk_str_endswith(DkStr s, DkStr suffix);
bool dk_str_contains(DkStr hay, DkStr needle);
/* find/rfind/count over [start, end) byte offsets with slice semantics (negative counts from the end; end ==
 * DK_END for the end); find and rfind return the byte offset or -1. */
#define DK_END ((i64)INT64_MAX)
i64 dk_str_find(DkStr hay, DkStr needle, i64 start, i64 end);
i64 dk_str_rfind(DkStr hay, DkStr needle, i64 start, i64 end);
size_t dk_str_count(DkStr hay, DkStr needle);
i64 dk_str_findc(DkStr s, char c); /* first byte c or -1 */

/* s[i:j] on bytes, slice semantics (negative from the end, clamped; j == DK_END for the end). */
DkStr dk_str_slice(DkStr s, i64 i, i64 j);

DkStr dk_str_strip(DkStr s);  /* Python whitespace */
DkStr dk_str_lstrip(DkStr s);
DkStr dk_str_rstrip(DkStr s);
DkStr dk_str_strip_chars(DkStr s, DkStr chars); /* s.strip(chars): chars is a set of code points */
DkStr dk_str_lstrip_chars(DkStr s, DkStr chars);
DkStr dk_str_rstrip_chars(DkStr s, DkStr chars);
DkStr dk_str_removeprefix(DkStr s, DkStr prefix);
DkStr dk_str_removesuffix(DkStr s, DkStr suffix);

/* split: sep.n == 0 is split() / split(None) (whitespace runs, no empty fields); maxsplit < 0 is no limit. */
DkStrVec dk_str_split(DkStr s, DkStr sep, int maxsplit);
DkStrVec dk_str_rsplit(DkStr s, DkStr sep, int maxsplit);
DkStrVec dk_str_splitlines(DkStr s, bool keepends); /* \n \r \r\n \v \f \x1c \x1d \x1e U+0085 U+2028 U+2029 */
/* partition/rpartition: true when sep was found; *before, *after as Python. Not found: partition gives before = s,
 * after = empty; rpartition gives before = empty, after = s. sep must not be empty (Python raises ValueError). */
bool dk_str_partition(DkStr s, DkStr sep, DkStr *before, DkStr *after);
bool dk_str_rpartition(DkStr s, DkStr sep, DkStr *before, DkStr *after);

DkStr dk_str_replace(DkArena *a, DkStr s, DkStr old, DkStr new_, int count); /* count < 0: all */
DkStr dk_str_join(DkArena *a, DkStr sep, const DkStr *items, size_t count);
DkStr dk_str_concat(DkArena *a, DkStr x, DkStr y);
DkStr dk_str_repeat(DkArena *a, DkStr s, size_t times);
/* str.lower() / str.upper() over all of Unicode, as CPython 3.14 (full mappings: multi-character results and the final
 * sigma included). */
DkStr dk_str_lower(DkArena *a, DkStr s);
DkStr dk_str_upper(DkArena *a, DkStr s);
/* str.casefold(): full Unicode case folding per code point (U+00DF gives "ss", U+03C2 gives U+03C3). */
DkStr dk_str_casefold(DkArena *a, DkStr s);
DkStr dk_str_expandtabs(DkArena *a, DkStr s, int tabsize);
/* ljust/rjust/center/zfill pad to a width counted in code points, as Python does. */
DkStr dk_str_ljust(DkArena *a, DkStr s, size_t width, u32 fill);
DkStr dk_str_rjust(DkArena *a, DkStr s, size_t width, u32 fill);
DkStr dk_str_center(DkArena *a, DkStr s, size_t width, u32 fill);
DkStr dk_str_zfill(DkArena *a, DkStr s, size_t width);

/* Python's str predicates (false for the empty string, as Python). */
bool dk_str_isdigit(DkStr s);   /* ASCII digits and the Unicode Nd/No digits Python counts */
bool dk_str_isdecimal(DkStr s);
bool dk_str_isalpha(DkStr s);
bool dk_str_isalnum(DkStr s);
bool dk_str_isspace(DkStr s);
bool dk_str_isupper(DkStr s);
bool dk_str_islower(DkStr s);
bool dk_str_isidentifier(DkStr s);
bool dk_str_isascii(DkStr s);   /* true for the empty string, as Python */
bool dk_cp_isspace(u32 cp);

/* Python int(s, base) and float(s): surrounding whitespace allowed, underscores between digits, base 0 reads the
 * 0x/0o/0b prefixes, float accepts inf/nan/infinity in any case. False when Python would raise ValueError, or when
 * an int does not fit in 64 bits (*overflow set when non-NULL). */
bool dk_parse_int(DkStr s, int base, i64 *out, bool *overflow);
bool dk_parse_uint(DkStr s, int base, u64 *out);
bool dk_parse_float(DkStr s, double *out);

/* ---- UTF-8 ---- */
size_t dk_u8_len(DkStr s);                      /* code points (len() of the Python str) */
DkStr dk_u8_slice(DkStr s, i64 i, i64 j);      /* s[i:j] counted in code points, slice semantics */
u32 dk_u8_next(const char **p, const char *end); /* decodes one code point; invalid bytes give U+FFFD, one byte each */
size_t dk_u8_put(char out[4], u32 cp);           /* encodes; returns the byte count */
bool dk_u8_valid(DkStr s);
/* UTF-16 for the Win32 W APIs (NUL-terminated), and back (n < 0: up to the NUL). Unpaired surrogates become
 * U+FFFD. */
wchar_t *dk_to_w(DkArena *a, DkStr s);
wchar_t *dk_to_wz(DkArena *a, const char *cz);
DkStr dk_from_w(DkArena *a, const wchar_t *w, i64 n);

/* base64.b64encode(data): the standard alphabet with '=' padding, no line breaks. */
DkStr dk_base64_encode(DkArena *a, const void *data, size_t n);

/* ---- builder ----
 * buf.a == NULL: heap memory (dk_buf_free); else the arena's. A zeroed DkBuf is a valid empty heap builder.
 * The content is always NUL-terminated (buf.p[buf.n] == 0) once anything was added. */
typedef struct {
    char *p;
    size_t n;
    size_t cap;
    DkArena *a;
} DkBuf;
void dk_buf_init(DkBuf *b, DkArena *a);
void dk_buf_put(DkBuf *b, DkStr s);
void dk_buf_putz(DkBuf *b, const char *cz);
void dk_buf_putn(DkBuf *b, const void *p, size_t n);
void dk_buf_putc(DkBuf *b, char c);
void dk_buf_putcp(DkBuf *b, u32 cp); /* one code point as UTF-8 */
void dk_buf_printf(DkBuf *b, DK_PRINTF_FMT const char *fmt, ...); /* C printf rules */
void dk_buf_vprintf(DkBuf *b, const char *fmt, va_list ap);
void dk_buf_reserve(DkBuf *b, size_t extra);
void dk_buf_clear(DkBuf *b);
DkStr dk_buf_str(const DkBuf *b);
char *dk_buf_cz(DkBuf *b); /* the NUL-terminated content ("" when empty) */
void dk_buf_free(DkBuf *b);
