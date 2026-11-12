// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore str: Unicode character properties and case mapping, as Python's str exposes them.
 *
 * The tables (str_unicode_tables.h) are generated from CPython 3.14 for every code point, with the script quoted at
 * the top of that file: whitespace, alphabetic, alphanumeric, digit, decimal, lower/upper/titlecase letters,
 * identifier start and continue, the Cased and Case_Ignorable properties of the Final_Sigma rule, and the full
 * (multi-character) lower and upper case maps. The header declares the mappings for ASCII, Latin-1, Latin
 * Extended-A, Greek and Cyrillic; the tables cover all of Unicode, so every code point maps as Python's does. */
#include "dk/dk.h"

#include "str_internal.h"
#include "str_unicode_tables.h"
#include "str_casefold_tables.h"

#define NPAIRS(t) (DK_ARRAY_LEN(t) / 2)

bool dk__in_ranges(const u32 *r, size_t npairs, u32 cp) {
    size_t lo = 0, hi = npairs;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cp < r[2 * mid]) hi = mid;
        else if (cp > r[2 * mid + 1]) lo = mid + 1;
        else return true;
    }
    return false;
}

#define IN(tab, cp) dk__in_ranges(tab, NPAIRS(tab), (cp))

int dk__cp_decimal(u32 cp) {
    if (cp < 0x80) return (cp >= '0' && cp <= '9') ? (int)(cp - '0') : -1;
    size_t lo = 0, hi = NPAIRS(tab_decimal);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cp < tab_decimal[2 * mid]) hi = mid;
        else if (cp > tab_decimal[2 * mid + 1]) lo = mid + 1;
        else return (int)((cp - tab_decimal[2 * mid]) % 10); /* the generator checks that runs start at a zero digit */
    }
    return -1;
}

bool dk_cp_isspace(u32 cp) {
    if (cp < 0x80) return cp == ' ' || (cp >= 9 && cp <= 13) || (cp >= 0x1C && cp <= 0x1F);
    return IN(tab_space, cp);
}

/* ---- string predicates --------------------------------------------------------------------------------------------- */

/* Calls test for each code point of s; false for the empty string. */
#define ALL_CP(s, test)                                    \
    do {                                                   \
        if ((s).n == 0) return false;                      \
        const char *p_ = (s).p, *e_ = (s).p + (s).n;       \
        while (p_ < e_) {                                  \
            u32 cp = (u8)*p_ < 0x80 ? (u32)(u8)*p_++ : dk_u8_next(&p_, e_); \
            if (!(test)) return false;                     \
        }                                                  \
        return true;                                       \
    } while (0)

bool dk_str_isspace(DkStr s) { ALL_CP(s, dk_cp_isspace(cp)); }
bool dk_str_isalpha(DkStr s) { ALL_CP(s, cp < 0x80 ? ((cp | 0x20) >= 'a' && (cp | 0x20) <= 'z') : IN(tab_alpha, cp)); }
bool dk_str_isalnum(DkStr s) {
    ALL_CP(s, cp < 0x80 ? (((cp | 0x20) >= 'a' && (cp | 0x20) <= 'z') || (cp >= '0' && cp <= '9')) : IN(tab_alnum, cp));
}
bool dk_str_isdigit(DkStr s) { ALL_CP(s, cp < 0x80 ? (cp >= '0' && cp <= '9') : IN(tab_digit, cp)); }
bool dk_str_isdecimal(DkStr s) { ALL_CP(s, cp < 0x80 ? (cp >= '0' && cp <= '9') : IN(tab_decimal, cp)); }

bool dk_str_isascii(DkStr s) {
    for (size_t i = 0; i < s.n; i++)
        if ((u8)s.p[i] >= 0x80) return false;
    return true;
}

/* str.isupper(): at least one cased character, and no lowercase or titlecase one (CPython's unicode_isupper). */
bool dk_str_isupper(DkStr s) {
    bool cased = false;
    const char *p = s.p, *e = s.p + s.n;
    while (p < e) {
        u32 cp = (u8)*p < 0x80 ? (u32)(u8)*p++ : dk_u8_next(&p, e);
        if (IN(tab_lowercase, cp) || IN(tab_titlecase, cp)) return false;
        if (!cased && IN(tab_uppercase, cp)) cased = true;
    }
    return cased;
}

bool dk_str_islower(DkStr s) {
    bool cased = false;
    const char *p = s.p, *e = s.p + s.n;
    while (p < e) {
        u32 cp = (u8)*p < 0x80 ? (u32)(u8)*p++ : dk_u8_next(&p, e);
        if (IN(tab_uppercase, cp) || IN(tab_titlecase, cp)) return false;
        if (!cased && IN(tab_lowercase, cp)) cased = true;
    }
    return cased;
}

/* str.isidentifier(): XID_Start or '_' first, XID_Continue after. */
bool dk_str_isidentifier(DkStr s) {
    if (s.n == 0) return false;
    const char *p = s.p, *e = s.p + s.n;
    bool first = true;
    while (p < e) {
        u32 cp = (u8)*p < 0x80 ? (u32)(u8)*p++ : dk_u8_next(&p, e);
        if (!(first ? IN(tab_ident_start, cp) : IN(tab_ident_continue, cp))) return false;
        first = false;
    }
    return true;
}

/* ---- case mapping -------------------------------------------------------------------------------------------------- */

/* Appends the mapping of cp from a {code point, mapping} table, or cp itself when it has none. */
static void put_mapped(DkBuf *b, const u32 (*map)[2], size_t n, const u32 *multi, u32 cp) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cp < map[mid][0]) hi = mid;
        else if (cp > map[mid][0]) lo = mid + 1;
        else {
            u32 to = map[mid][1];
            if (!(to & 0x80000000u)) {
                dk_buf_putcp(b, to);
            } else {
                size_t idx = (to & 0x7FFFFFFFu) >> 4, len = to & 0xF;
                for (size_t i = 0; i < len; i++) dk_buf_putcp(b, multi[idx + i]);
            }
            return;
        }
    }
    dk_buf_putcp(b, cp);
}

/* Python's Final_Sigma rule for U+03A3 at p: a cased letter before it (skipping case-ignorable ones) and none after. */
static bool final_sigma(const char *begin, const char *p, const char *end) {
    const char *q = p;
    bool before = false;
    while (q > begin) {
        u32 c = dk__u8_prev(begin, &q);
        if (IN(tab_case_ignorable, c)) continue;
        before = IN(tab_cased, c);
        break;
    }
    if (!before) return false;
    q = p + 2; /* U+03A3 is two bytes in UTF-8 */
    while (q < end) {
        u32 c = dk_u8_next(&q, end);
        if (IN(tab_case_ignorable, c)) continue;
        return !IN(tab_cased, c);
    }
    return true;
}

DkStr dk_str_lower(DkArena *a, DkStr s) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_reserve(&b, s.n);
    const char *p = s.p, *e = s.p + s.n;
    while (p < e) {
        u8 c = (u8)*p;
        if (c < 0x80) {
            dk_buf_putc(&b, (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c);
            p++;
            continue;
        }
        const char *at = p;
        u32 cp = dk_u8_next(&p, e);
        if (cp == 0x3A3) dk_buf_putcp(&b, final_sigma(s.p, at, e) ? 0x3C2 : 0x3C3);
        else put_mapped(&b, map_lower, DK_ARRAY_LEN(map_lower), multi_lower, cp);
    }
    dk_buf_putn(&b, "", 0);
    return dk_buf_str(&b);
}

DkStr dk_str_upper(DkArena *a, DkStr s) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_reserve(&b, s.n);
    const char *p = s.p, *e = s.p + s.n;
    while (p < e) {
        u8 c = (u8)*p;
        if (c < 0x80) {
            dk_buf_putc(&b, (c >= 'a' && c <= 'z') ? (char)(c - 32) : (char)c);
            p++;
            continue;
        }
        u32 cp = dk_u8_next(&p, e);
        put_mapped(&b, map_upper, DK_ARRAY_LEN(map_upper), multi_upper, cp);
    }
    dk_buf_putn(&b, "", 0);
    return dk_buf_str(&b);
}

/* str.casefold(): the full Unicode case folding of each code point on its own (no context rule: the final sigma stays
 * what it is, U+00DF becomes "ss"). Used where Python compares names or paths case-insensitively. */
DkStr dk_str_casefold(DkArena *a, DkStr s) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_reserve(&b, s.n);
    const char *p = s.p, *e = s.p + s.n;
    while (p < e) {
        u8 c = (u8)*p;
        if (c < 0x80) {
            dk_buf_putc(&b, (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c);
            p++;
            continue;
        }
        u32 cp = dk_u8_next(&p, e);
        put_mapped(&b, map_casefold, DK_ARRAY_LEN(map_casefold), multi_casefold, cp);
    }
    dk_buf_putn(&b, "", 0);
    return dk_buf_str(&b);
}
