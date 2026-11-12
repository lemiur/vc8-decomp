// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The format-spec mini-language of str.format / f-strings / format(): a port of CPython 3.14's
 * Python/formatter_unicode.c for int, float and str values with the C locale ('n' is 'd'/'g', separators only
 * through , and _). The same field layout as CPython, so the padding, the zero fill with grouping and the
 * sign/prefix placement come out equal: |lpadding|sign|prefix|spadding|digits|decimal|remainder|rpadding|. */
#include "dk/fmt.h"
#include <limits.h>
#include <math.h>

typedef struct {
    u32 fill;
    char align; /* < > ^ = */
    char sign;  /* '\0', '+', '-', ' ' */
    bool no_neg_0;
    bool alt;
    i64 width; /* -1: none */
    char sep;  /* '\0', ',' or '_' */
    i64 prec;  /* -1: none */
    u32 type;  /* '\0' when absent and the default is empty */
} FmtSpec;

static bool is_align(u32 c) { return c == '<' || c == '>' || c == '=' || c == '^'; }

static i64 get_integer(const char **p, const char *end) {
    const char *q = *p;
    i64 v = 0;
    bool any = false;
    while (q < end && *q >= '0' && *q <= '9') {
        if (v > (INT64_MAX - 9) / 10) dk_throw(DK_ERR_OTHER, "Too many decimal digits in format string");
        v = v * 10 + (*q - '0');
        q++;
        any = true;
    }
    *p = q;
    return any ? v : -1;
}

/* parse_internal_render_format_spec. default_type 0 means "none given" (floats). */
static void parse_spec(const char *spec, char default_align, u32 default_type, const char *tname, FmtSpec *f) {
    const char *p = spec, *end = spec + strlen(spec);
    f->fill = ' ';
    f->align = default_align;
    f->sign = 0;
    f->no_neg_0 = f->alt = false;
    f->width = f->prec = -1;
    f->sep = 0;
    f->type = default_type;
    bool fill_given = false, align_given = false;
    if (p < end) {
        const char *q = p;
        u32 c0 = dk_u8_next(&q, end);
        if (q < end) {
            const char *q2 = q;
            u32 c1 = dk_u8_next(&q2, end);
            if (is_align(c1)) {
                f->fill = c0;
                f->align = (char)c1;
                fill_given = align_given = true;
                p = q2;
            }
        }
        if (!align_given && is_align(c0)) {
            f->align = (char)c0;
            align_given = true;
            p = q;
        }
    }
    if (p < end && (*p == '+' || *p == '-' || *p == ' ')) f->sign = *p++;
    if (p < end && *p == 'z') {
        f->no_neg_0 = true;
        p++;
    }
    if (p < end && *p == '#') {
        f->alt = true;
        p++;
    }
    if (!fill_given && p < end && *p == '0') {
        f->fill = '0';
        if (!align_given && default_align == '>') f->align = '=';
        p++;
    }
    f->width = get_integer(&p, end);
    if (p < end && *p == ',') {
        f->sep = ',';
        p++;
    }
    if (p < end && *p == '_') {
        if (f->sep) dk_throw(DK_ERR_OTHER, "Cannot specify both ',' and '_'.");
        f->sep = '_';
        p++;
    }
    if (p < end && *p == ',' && f->sep == '_') dk_throw(DK_ERR_OTHER, "Cannot specify both ',' and '_'.");
    if (p < end && *p == '.') {
        p++;
        f->prec = get_integer(&p, end);
        if (f->prec < 0) dk_throw(DK_ERR_OTHER, "Format specifier missing precision");
    }
    if (p < end) {
        const char *q = p;
        u32 t = dk_u8_next(&q, end);
        if (q < end)
            dk_throw(DK_ERR_OTHER, "Invalid format specifier '%s' for object of type '%s'", spec, tname);
        f->type = t;
    }
    if (f->sep) {
        switch (f->type) {
        case 'd': case 'e': case 'f': case 'g': case 'E': case 'G': case '%': case 'F': case 0: break;
        case 'b': case 'o': case 'x': case 'X':
            if (f->sep == '_') break;
            /* fall through */
        default: {
            char tb[8] = {0};
            dk_u8_put(tb, f->type);
            dk_throw(DK_ERR_OTHER, "Cannot specify '%c' with '%s'.", f->sep, tb);
        }
        }
    }
}

static DK_NORETURN void unknown_type(u32 type, const char *tname) {
    char tb[8] = {0};
    dk_u8_put(tb, type);
    dk_throw(DK_ERR_OTHER, "Unknown format code '%s' for object of type '%s'", tb, tname);
}

static void put_fill(DkBuf *b, u32 cp, i64 n) {
    if (cp < 0x80) {
        for (; n > 0; n--) dk_buf_putc(b, (char)cp);
    } else {
        for (; n > 0; n--) dk_buf_putcp(b, cp);
    }
}

/* _PyUnicode_InsertThousandsGrouping for a constant group size g (3 for decimal, 4 for the _ of b/o/x): the digits
 * ds[0..nd) grouped from the right, with zeros added in front until min_width characters are reached (the
 * separators inside the zero fill count towards min_width). out == NULL only counts. Returns the char count. */
static size_t insert_grouping(char *out, const char *ds, size_t nd, i64 min_width, char sep, i64 g) {
    if (min_width < 0) min_width = 0;
    i64 remaining = (i64)nd;
    size_t count = 0;
    bool use_sep = false;
    size_t bp = 0;
    if (out) bp = insert_grouping(NULL, ds, nd, min_width, sep, g); /* total length: fill right to left */
    i64 dpos = (i64)nd;
    for (;;) {
        i64 l = g;
        i64 need = DK_MAX(DK_MAX(remaining, min_width), 1);
        if (l > need) l = need;
        i64 n_zeros = DK_MAX(0, l - remaining);
        i64 n_chars = DK_MAX(0, DK_MIN(remaining, l));
        count += (use_sep ? 1u : 0u) + (size_t)n_zeros + (size_t)n_chars;
        if (out) {
            if (use_sep) out[--bp] = sep;
            bp -= (size_t)n_chars;
            dpos -= n_chars;
            memcpy(out + bp, ds + dpos, (size_t)n_chars);
            bp -= (size_t)n_zeros;
            memset(out + bp, '0', (size_t)n_zeros);
        }
        use_sep = true;
        remaining -= n_chars;
        min_width -= l;
        if (remaining <= 0 && min_width <= 0) break;
        min_width -= 1; /* the separator's width */
    }
    return count;
}

/* calc_number_widths + fill_number. digits: the integer part (grouped), then the decimal point if has_decimal,
 * then the remainder (fraction, exponent, %, or the 'inf'/'nan' text, or the character of 'c'). */
static void emit_number(DkBuf *out, const FmtSpec *f, const char *prefix, char sign_char, const char *digits,
                        size_t n_digits, bool has_decimal, const char *rem, size_t n_rem, size_t n_rem_cp) {
    size_t n_prefix = prefix ? strlen(prefix) : 0;
    char sign = 0;
    if (sign_char == '-') sign = '-';
    else if (f->sign == '+' || f->sign == ' ') sign = f->sign;
    i64 n_sign = sign ? 1 : 0;
    i64 n_non = n_sign + (i64)n_prefix + (has_decimal ? 1 : 0) + (i64)n_rem_cp;
    i64 min_width = (f->fill == '0' && f->align == '=') ? f->width - n_non : 0;
    i64 g = f->sep ? (f->sep == '_' && (f->type == 'b' || f->type == 'o' || f->type == 'x' || f->type == 'X') ? 4 : 3)
                   : INT64_MAX;
    size_t n_grouped = n_digits ? insert_grouping(NULL, digits, n_digits, min_width, f->sep, g) : 0;
    i64 n_pad = f->width - (n_non + (i64)n_grouped);
    i64 lpad = 0, spad = 0, rpad = 0;
    if (n_pad > 0) {
        switch (f->align) {
        case '<': rpad = n_pad; break;
        case '^': lpad = n_pad / 2; rpad = n_pad - lpad; break;
        case '=': spad = n_pad; break;
        default: lpad = n_pad; break;
        }
    }
    put_fill(out, f->fill, lpad);
    if (sign) dk_buf_putc(out, sign);
    if (n_prefix) dk_buf_putn(out, prefix, n_prefix);
    put_fill(out, f->fill, spad);
    if (n_grouped) {
        dk_buf_reserve(out, n_grouped);
        size_t at = out->n;
        out->n += n_grouped;
        insert_grouping(out->p + at, digits, n_digits, min_width, f->sep, g);
        out->p[out->n] = 0;
    }
    if (has_decimal) dk_buf_putc(out, '.');
    if (n_rem) dk_buf_putn(out, rem, n_rem);
    put_fill(out, f->fill, rpad);
}

static void format_float_internal(DkBuf *out, double val, const FmtSpec *f) {
    int flags = 0;
    int type = (int)f->type;
    int default_prec = 6;
    bool add_pct = false;
    if (f->alt) flags |= DK_DTSF_ALT;
    if (f->no_neg_0) flags |= DK_DTSF_NO_NEG_0;
    if (type == 0) {
        flags |= DK_DTSF_ADD_DOT_0;
        type = 'r';
        default_prec = 0;
    }
    if (type == 'n') type = 'g';
    if (type == '%') {
        type = 'f';
        val *= 100;
        add_pct = true;
    }
    int prec;
    if (f->prec < 0) {
        prec = default_prec;
    } else {
        prec = f->prec > INT_MAX ? INT_MAX : (int)f->prec;
        if (type == 'r') type = 'g';
    }
    DkBuf t = {0}; /* a heap builder: out may grow while t is read */
    dk_float_to_string(&t, val, (char)type, prec, flags);
    if (add_pct) dk_buf_putc(&t, '%');
    const char *s = dk_buf_cz(&t);
    size_t len = t.n, idx = 0;
    char sign_char = 0;
    if (s[0] == '-') {
        sign_char = '-';
        idx = 1;
    }
    size_t pos = idx;
    while (pos < len && s[pos] >= '0' && s[pos] <= '9') pos++;
    bool has_decimal = pos < len && s[pos] == '.';
    size_t rem_at = pos + (has_decimal ? 1 : 0);
    emit_number(out, f, NULL, sign_char, s + idx, pos - idx, has_decimal, s + rem_at, len - rem_at, len - rem_at);
    dk_buf_free(&t);
}

static void format_long_internal(DkBuf *out, bool neg, u64 mag, const FmtSpec *f) {
    if (f->prec != -1) dk_throw(DK_ERR_OTHER, "Precision not allowed in integer format specifier");
    if (f->no_neg_0) dk_throw(DK_ERR_OTHER, "Negative zero coercion (z) not allowed in integer format specifier");
    if (f->type == 'c') {
        if (f->sign) dk_throw(DK_ERR_OTHER, "Sign not allowed with integer format specifier 'c'");
        if (f->alt) dk_throw(DK_ERR_OTHER, "Alternate form (#) not allowed with integer format specifier 'c'");
        if (neg || mag > 0x10ffff) dk_throw(DK_ERR_OTHER, "%%c arg not in range(0x110000)");
        char tmp[4];
        size_t n = dk_u8_put(tmp, (u32)mag);
        emit_number(out, f, NULL, 0, NULL, 0, false, tmp, n, 1);
        return;
    }
    int base = 10;
    const char *prefix = NULL;
    switch (f->type) {
    case 'b': base = 2; prefix = "0b"; break;
    case 'o': base = 8; prefix = "0o"; break;
    case 'x': base = 16; prefix = "0x"; break;
    case 'X': base = 16; prefix = "0X"; break;
    default: break;
    }
    if (!f->alt) prefix = NULL;
    char digits[64];
    size_t n = dk_u64_digits(digits, mag, base, f->type == 'X');
    emit_number(out, f, prefix, neg ? '-' : 0, digits, n, false, NULL, 0, 0);
}

static void format_int_common(DkBuf *out, bool neg, u64 mag, const char *spec) {
    if (!*spec) {
        char digits[64];
        size_t n = dk_u64_digits(digits, mag, 10, false);
        if (neg) dk_buf_putc(out, '-');
        dk_buf_putn(out, digits, n);
        return;
    }
    FmtSpec f;
    parse_spec(spec, '>', 'd', "int", &f);
    switch (f.type) {
    case 'b': case 'c': case 'd': case 'o': case 'x': case 'X': case 'n':
        format_long_internal(out, neg, mag, &f);
        break;
    case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case '%': {
        double v = (double)mag;
        format_float_internal(out, neg ? -v : v, &f);
        break;
    }
    default:
        unknown_type(f.type, "int");
    }
}

void dk_buf_format_i64(DkBuf *b, i64 v, const char *spec) {
    format_int_common(b, v < 0, v < 0 ? 0 - (u64)v : (u64)v, spec);
}

void dk_buf_format_u64(DkBuf *b, u64 v, const char *spec) { format_int_common(b, false, v, spec); }

void dk_buf_format_f64(DkBuf *b, double v, const char *spec) {
    if (!*spec) {
        char tmp[32];
        size_t n = dk_float_repr(v, tmp);
        dk_buf_putn(b, tmp, n);
        return;
    }
    FmtSpec f;
    parse_spec(spec, '>', 0, "float", &f);
    switch (f.type) {
    case 0: case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'n': case '%':
        format_float_internal(b, v, &f);
        break;
    default:
        unknown_type(f.type, "float");
    }
}

void dk_buf_format_str(DkBuf *b, DkStr s, const char *spec) {
    if (!*spec) {
        dk_buf_put(b, s);
        return;
    }
    FmtSpec f;
    parse_spec(spec, '<', 's', "str", &f);
    if (f.type != 's') unknown_type(f.type, "str");
    if (f.sign == ' ') dk_throw(DK_ERR_OTHER, "Space not allowed in string format specifier");
    if (f.sign) dk_throw(DK_ERR_OTHER, "Sign not allowed in string format specifier");
    if (f.no_neg_0) dk_throw(DK_ERR_OTHER, "Negative zero coercion (z) not allowed in string format specifier");
    if (f.alt) dk_throw(DK_ERR_OTHER, "Alternate form (#) not allowed in string format specifier");
    if (f.align == '=') dk_throw(DK_ERR_OTHER, "'=' alignment not allowed in string format specifier");
    i64 len = (i64)dk_u8_len(s);
    if (f.prec >= 0 && len >= f.prec) {
        s = dk_u8_slice(s, 0, f.prec);
        len = f.prec;
    }
    i64 total = f.width > len ? f.width : len;
    i64 lpad = 0, rpad = 0;
    switch (f.align) {
    case '>': lpad = total - len; break;
    case '^': lpad = (total - len) / 2; rpad = total - len - lpad; break;
    default: rpad = total - len; break;
    }
    put_fill(b, f.fill, lpad);
    dk_buf_put(b, s);
    put_fill(b, f.fill, rpad);
}

static DkStr finish(DkBuf *b) {
    char *z = dk_buf_cz(b);
    return dk_strn(z, b->n);
}

DkStr dk_format_i64(DkArena *a, i64 v, const char *spec) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_format_i64(&b, v, spec);
    return finish(&b);
}

DkStr dk_format_u64(DkArena *a, u64 v, const char *spec) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_format_u64(&b, v, spec);
    return finish(&b);
}

DkStr dk_format_f64(DkArena *a, double v, const char *spec) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_format_f64(&b, v, spec);
    return finish(&b);
}

DkStr dk_format_str(DkArena *a, DkStr s, const char *spec) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_format_str(&b, s, spec);
    return finish(&b);
}
