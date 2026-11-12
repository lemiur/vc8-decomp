// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore str: Python's int(str, base) and float(str).
 *
 * Both first strip surrounding whitespace (the Unicode set) and read every Unicode decimal digit (Arabic-Indic and
 * so on) as its ASCII value, as CPython's _PyUnicode_TransformDecimalAndSpaceToASCII does; any other non-ASCII
 * character is an error. Underscores are allowed only between digits (and once right after a base prefix). */
#include "dk/dk.h"

#include <math.h>
#include <stdlib.h>

#include "str_internal.h"

/* The stripped text as ASCII in the arena's scratch space; false when it holds a character that is not ASCII and not
 * a decimal digit, or an embedded NUL. */
static bool to_ascii(DkArena *sc, DkStr s, char **out, size_t *n) {
    s = dk_str_strip(s);
    char *t = (char *)dk_alloc_noz(sc, s.n + 1);
    size_t len = 0;
    const char *p = s.p, *e = s.p + s.n;
    while (p < e) {
        u32 cp = (u8)*p < 0x80 ? (u32)(u8)*p++ : dk_u8_next(&p, e);
        if (cp >= 0x80) {
            int d = dk__cp_decimal(cp);
            if (d < 0) return false;
            cp = (u32)('0' + d);
        } else if (cp == 0) {
            return false;
        }
        t[len++] = (char)cp;
    }
    t[len] = 0;
    *out = t;
    *n = len;
    return true;
}

static int digit_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    return 99;
}

enum { PARSE_OK, PARSE_SYNTAX, PARSE_OVERFLOW };

/* The sign and magnitude of int(s, base) when it is valid; PARSE_OVERFLOW when the magnitude exceeds 64 bits. */
static int parse_magnitude(DkStr s, int base, bool *neg, u64 *mag) {
    if (base != 0 && (base < 2 || base > 36)) return PARSE_SYNTAX;
    DkArena *sc = dk_scratch();
    DkArenaMark mark = dk_arena_mark(sc);
    char *t;
    size_t n;
    int rc = PARSE_SYNTAX;
    if (!to_ascii(sc, s, &t, &n)) goto done;
    size_t i = 0;
    *neg = false;
    if (i < n && (t[i] == '+' || t[i] == '-')) *neg = t[i++] == '-';
    size_t dstart = i;
    bool base0 = base == 0, prefixed = false;
    if (i + 1 < n && t[i] == '0') {
        char c = (char)(t[i + 1] | 0x20);
        int pb = c == 'x' ? 16 : c == 'o' ? 8 : c == 'b' ? 2 : 0;
        if (pb && (base0 || base == pb)) {
            base = pb;
            i += 2;
            prefixed = true;
            if (i < n && t[i] == '_') i++; /* one underscore is allowed after the prefix */
        }
    }
    if (base0 && !prefixed) base = 10;
    if (i >= n || t[i] == '_') goto done;
    u64 acc = 0;
    bool ovf = false;
    char prev = 0;
    bool nonzero = false;
    for (; i < n; i++) {
        char c = t[i];
        if (c == '_') {
            if (prev == '_') goto done;
        } else {
            int d = digit_value(c);
            if (d >= base) goto done;
            if (d != 0) nonzero = true;
            if (acc > (UINT64_MAX - (u64)d) / (u64)base) ovf = true;
            else acc = acc * (u64)base + (u64)d;
        }
        prev = c;
    }
    if (prev == '_') goto done;
    /* int("0_7", 0), int("007", 0): a decimal literal may not have leading zeros unless it is all zeros. */
    if (base0 && !prefixed && t[dstart] == '0' && nonzero) goto done;
    *mag = acc;
    rc = ovf ? PARSE_OVERFLOW : PARSE_OK;
done:
    dk_arena_reset(sc, mark);
    return rc;
}

bool dk_parse_int(DkStr s, int base, i64 *out, bool *overflow) {
    if (overflow) *overflow = false;
    bool neg = false;
    u64 mag = 0;
    int rc = parse_magnitude(s, base, &neg, &mag);
    if (rc == PARSE_SYNTAX) return false;
    if (rc == PARSE_OK) {
        if (neg ? mag <= (u64)1 << 63 : mag <= (u64)INT64_MAX) {
            *out = neg ? (i64)(0 - mag) : (i64)mag;
            return true;
        }
    }
    if (overflow) *overflow = true;
    return false;
}

bool dk_parse_uint(DkStr s, int base, u64 *out) {
    bool neg = false;
    u64 mag = 0;
    if (parse_magnitude(s, base, &neg, &mag) != PARSE_OK) return false;
    if (neg && mag != 0) return false;
    *out = mag;
    return true;
}

/* ---- float -------------------------------------------------------------------------------------------------------- */

static bool ieq(const char *t, size_t n, const char *word) {
    size_t w = strlen(word);
    if (n != w) return false;
    for (size_t i = 0; i < n; i++)
        if ((t[i] | 0x20) != word[i]) return false;
    return true;
}

/* Copies a run of digits with single underscores between digits to out; false when the run is not valid or empty. */
static bool digit_run(const char *t, size_t n, size_t *i, char *out, size_t *on) {
    size_t start = *i;
    while (*i < n && ((t[*i] >= '0' && t[*i] <= '9') || t[*i] == '_')) {
        if (t[*i] == '_') {
            if (*i == start || !(t[*i - 1] >= '0' && t[*i - 1] <= '9')) return false;
            if (*i + 1 >= n || !(t[*i + 1] >= '0' && t[*i + 1] <= '9')) return false;
        } else {
            out[(*on)++] = t[*i];
        }
        (*i)++;
    }
    return *i > start;
}

bool dk_parse_float(DkStr s, double *out) {
    DkArena *sc = dk_scratch();
    DkArenaMark mark = dk_arena_mark(sc);
    char *t;
    size_t n;
    bool ok = false;
    if (!to_ascii(sc, s, &t, &n) || n == 0) goto done;
    size_t i = 0;
    bool neg = false;
    if (t[i] == '+' || t[i] == '-') neg = t[i++] == '-';
    if (ieq(t + i, n - i, "inf") || ieq(t + i, n - i, "infinity")) {
        *out = neg ? -HUGE_VAL : HUGE_VAL;
        ok = true;
        goto done;
    }
    if (ieq(t + i, n - i, "nan")) {
        /* The quiet NaN CPython makes (_Py_dg_stdnan), with the sign bit of a leading '-'. */
        u64 bits = 0x7FF8000000000000ull | (neg ? 0x8000000000000000ull : 0);
        memcpy(out, &bits, sizeof bits);
        ok = true;
        goto done;
    }
    char *clean = (char *)dk_alloc_noz(sc, n + 2);
    size_t cn = 0;
    if (neg) clean[cn++] = '-';
    bool digits = false;
    if (i < n && t[i] != '.') {
        if (!digit_run(t, n, &i, clean, &cn)) goto done;
        digits = true;
    }
    if (i < n && t[i] == '.') {
        clean[cn++] = '.';
        i++;
        if (i < n && t[i] >= '0' && t[i] <= '9') {
            if (!digit_run(t, n, &i, clean, &cn)) goto done;
            digits = true;
        }
    }
    if (!digits) goto done;
    if (i < n && (t[i] == 'e' || t[i] == 'E')) {
        clean[cn++] = 'e';
        i++;
        if (i < n && (t[i] == '+' || t[i] == '-')) clean[cn++] = t[i++];
        if (i >= n || !digit_run(t, n, &i, clean, &cn)) goto done;
    }
    if (i != n) goto done;
    clean[cn] = 0;
    char *endp;
    /* The CRT's strtod rounds correctly (the tests check the hard cases); overflow gives infinity as Python's float. */
    double v = strtod(clean, &endp);
    if (*endp != 0) goto done;
    *out = v;
    ok = true;
done:
    dk_arena_reset(sc, mark);
    return ok;
}
