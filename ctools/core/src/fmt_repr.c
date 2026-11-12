// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* repr() of str and of containers built from item reprs (Objects/unicodeobject.c unicode_repr, listobject.c,
 * tupleobject.c, dictobject.c, setobject.c). */
#include "dk/fmt.h"

void dk_buf_repr_str(DkBuf *b, DkStr s) {
    bool squote = false, dquote = false;
    for (size_t i = 0; i < s.n; i++) {
        if (s.p[i] == '\'') squote = true;
        else if (s.p[i] == '"') dquote = true;
    }
    /* Single quotes unless the text has a ' and no ": then double quotes. */
    char quote = (squote && !dquote) ? '"' : '\'';
    dk_buf_putc(b, quote);
    const char *p = s.p, *end = s.p + s.n;
    static const char hex[] = "0123456789abcdef";
    while (p < end) {
        const char *at = p;
        u32 cp = dk_u8_next(&p, end);
        if (cp == (u32)quote || cp == '\\') {
            dk_buf_putc(b, '\\');
            dk_buf_putc(b, (char)cp);
        } else if (cp == '\t') {
            dk_buf_putn(b, "\\t", 2);
        } else if (cp == '\n') {
            dk_buf_putn(b, "\\n", 2);
        } else if (cp == '\r') {
            dk_buf_putn(b, "\\r", 2);
        } else if (cp < 0x20 || cp == 0x7f) {
            char e[4] = {'\\', 'x', hex[cp >> 4], hex[cp & 15]};
            dk_buf_putn(b, e, 4);
        } else if (cp < 0x7f) {
            dk_buf_putc(b, (char)cp);
        } else if (dk_cp_isprintable(cp)) {
            dk_buf_putn(b, at, (size_t)(p - at));
        } else {
            char e[10];
            size_t n = 0;
            e[n++] = '\\';
            int digits;
            if (cp <= 0xff) {
                e[n++] = 'x';
                digits = 2;
            } else if (cp <= 0xffff) {
                e[n++] = 'u';
                digits = 4;
            } else {
                e[n++] = 'U';
                digits = 8;
            }
            for (int sh = (digits - 1) * 4; sh >= 0; sh -= 4) e[n++] = hex[(cp >> sh) & 15];
            dk_buf_putn(b, e, n);
        }
    }
    dk_buf_putc(b, quote);
}

static DkStr finish(DkBuf *b) {
    char *z = dk_buf_cz(b);
    return dk_strn(z, b->n);
}

DkStr dk_repr_str(DkArena *a, DkStr s) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_repr_str(&b, s);
    return finish(&b);
}

DkStr dk_repr_i64(DkArena *a, i64 v) {
    char d[64];
    size_t n = dk_u64_digits(d, v < 0 ? 0 - (u64)v : (u64)v, 10, false);
    DkBuf b;
    dk_buf_init(&b, a);
    if (v < 0) dk_buf_putc(&b, '-');
    dk_buf_putn(&b, d, n);
    return finish(&b);
}

DkStr dk_repr_bool(bool v) { return v ? DK_S("True") : DK_S("False"); }

static DkStr seq(DkArena *a, char open, char close, const DkStr *items, size_t n, bool one_comma) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_putc(&b, open);
    for (size_t i = 0; i < n; i++) {
        if (i) dk_buf_putn(&b, ", ", 2);
        dk_buf_put(&b, items[i]);
    }
    if (n == 1 && one_comma) dk_buf_putc(&b, ',');
    dk_buf_putc(&b, close);
    return finish(&b);
}

DkStr dk_repr_list(DkArena *a, const DkStr *items, size_t n) { return seq(a, '[', ']', items, n, false); }
DkStr dk_repr_tuple(DkArena *a, const DkStr *items, size_t n) { return seq(a, '(', ')', items, n, true); }

DkStr dk_repr_set(DkArena *a, const DkStr *items, size_t n) {
    if (n == 0) return dk_str_dup(a, DK_S("set()"));
    return seq(a, '{', '}', items, n, false);
}

DkStr dk_repr_dict(DkArena *a, const DkStr *keys, const DkStr *vals, size_t n) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_putc(&b, '{');
    for (size_t i = 0; i < n; i++) {
        if (i) dk_buf_putn(&b, ", ", 2);
        dk_buf_put(&b, keys[i]);
        dk_buf_putn(&b, ": ", 2);
        dk_buf_put(&b, vals[i]);
    }
    dk_buf_putc(&b, '}');
    return finish(&b);
}
