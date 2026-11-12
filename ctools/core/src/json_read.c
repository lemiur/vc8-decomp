// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore json reader: json.loads (CPython 3.14's scanner, _json.c) with Python's error messages and positions.
 * The parse is iterative (an explicit stack of open containers), so deep nesting costs heap, not C stack. */
#include "json_internal.h"
#include "dk/arena.h"
#include <stdlib.h>
#include <locale.h>
#include <math.h>
#include <windows.h>

#define DK_JSON_MAX_DEPTH 10000 /* CPython stops at about 14000-16000 levels, depending on its C stack */
#define DK_JSON_INT_MAX_DIGITS 4300 /* sys.get_int_max_str_digits() */

typedef struct {
    bool is_obj;
    size_t base; /* first item/member of this container on the value/member stack */
    DkStr key;  /* object: the key read, waiting for its value */
    u32 *tab;    /* object with more than 8 members: its index while being built (heap) */
    u32 tabcap;
} Frame;

typedef struct {
    DkArena *a;
    unsigned flags;
    const char *base, *end; /* the text after a skipped BOM */
    int err_kind;
    DkStr err_msg;
    const char *err_at;
    DK_VEC(Frame) frames;
    DK_VEC(DkJson *) vs;
    DK_VEC(DkJsonMember) ms;
    DkBuf sb; /* decoded string under construction (strings with escapes) */
} Parser;

#define PEEK(P_, p_) ((p_) < (P_)->end ? (int)(unsigned char)*(p_) : -1)

static bool fail(Parser *P, int kind, const char *msg, const char *at) {
    P->err_kind = kind;
    P->err_msg = dk_str(msg);
    P->err_at = at;
    return false;
}

static bool fail_value(Parser *P, DkStr msg) {
    P->err_kind = DK_JSON_E_VALUE;
    P->err_msg = msg;
    P->err_at = NULL;
    return false;
}

static const char *skip_ws(const Parser *P, const char *p) {
    while (p < P->end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

/* ---- numbers ---- */
static const double pow10_exact[23] = {1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,  1e8,  1e9,  1e10, 1e11,
                                       1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22};

static _locale_t c_locale(void) {
    static volatile _locale_t loc;
    _locale_t l = loc;
    if (!l) {
        l = _create_locale(LC_ALL, "C");
        if (InterlockedCompareExchangePointer((void *volatile *)&loc, l, NULL) != NULL) {
            _free_locale(l);
            l = loc;
        }
    }
    return l;
}

/* float(lexeme) for a JSON float literal, correctly rounded. Clinger's exact fast path for up to 15 significant
 * digits and a small power of ten, the C runtime's strtod (also correctly rounded) otherwise. */
static double lexeme_to_double(const char *s, size_t n) {
    const char *p = s, *e = s + n;
    bool neg = false;
    if (*p == '-') {
        neg = true;
        p++;
    }
    u64 w = 0;
    int digits = 0, frac = 0;
    bool leading = true;
    for (; p < e && is_digit(*p); p++) {
        if (leading && *p == '0') continue;
        leading = false;
        w = w * 10 + (u64)(*p - '0');
        digits++;
        if (digits > 15) goto slow;
    }
    if (p < e && *p == '.') {
        for (p++; p < e && is_digit(*p); p++) {
            frac++;
            if (leading && *p == '0') continue;
            leading = false;
            w = w * 10 + (u64)(*p - '0');
            digits++;
            if (digits > 15) goto slow;
        }
    }
    {
        int ex = 0;
        if (p < e && (*p == 'e' || *p == 'E')) {
            bool eneg = false;
            p++;
            if (p < e && (*p == '+' || *p == '-')) eneg = (*p++ == '-');
            for (; p < e; p++) {
                ex = ex * 10 + (*p - '0');
                if (ex > 10000) goto slow;
            }
            if (eneg) ex = -ex;
        }
        ex -= frac;
        if (w == 0) return neg ? -0.0 : 0.0;
        double d = (double)w;
        if (ex >= 0 && ex <= 22) d *= pow10_exact[ex];
        else if (ex < 0 && ex >= -22) d /= pow10_exact[-ex];
        else goto slow;
        return neg ? -d : d;
    }
slow:;
    char stackbuf[128];
    char *buf = n < sizeof stackbuf ? stackbuf : (char *)dk_xmalloc(n + 1);
    memcpy(buf, s, n);
    buf[n] = 0;
    double d = _strtod_l(buf, NULL, c_locale());
    if (buf != stackbuf) dk_xfree(buf);
    return d;
}

/* The number at start (a digit or '-'), following _match_number_unicode. false: not a number ("Expecting value"). */
static bool parse_number(Parser *P, const char *start, const char **endp, DkJson **out) {
    const char *end = P->end, *p = start;
    bool neg = false;
    if (*p == '-') {
        neg = true;
        p++;
        if (p >= end) return fail(P, DK_JSON_E_DECODE, "Expecting value", start);
    }
    if (*p >= '1' && *p <= '9') {
        p++;
        while (p < end && is_digit(*p)) p++;
    } else if (*p == '0') {
        p++;
    } else {
        return fail(P, DK_JSON_E_DECODE, "Expecting value", start);
    }
    bool isf = false;
    if (p + 1 < end && *p == '.' && is_digit(p[1])) {
        isf = true;
        p += 2;
        while (p < end && is_digit(*p)) p++;
    }
    if (p + 1 < end && (*p == 'e' || *p == 'E')) {
        const char *estart = p;
        p++;
        if (p + 1 < end && (*p == '-' || *p == '+')) p++;
        while (p < end && is_digit(*p)) p++;
        if (is_digit(p[-1])) isf = true;
        else p = estart;
    }
    *endp = p;
    size_t n = (size_t)(p - start);
    if (isf) {
        double d = lexeme_to_double(start, n);
        if ((P->flags & DK_JSON_REJECT_NONFINITE) && !(d - d == 0.0)) return fail_value(P, DK_S("nonfinite JSON number"));
        *out = dk_json_float(P->a, d);
        return true;
    }
    size_t nd = n - (neg ? 1 : 0);
    if (nd > DK_JSON_INT_MAX_DIGITS) {
        P->err_kind = DK_JSON_E_VALUE;
        P->err_msg = dk_str(dk_sprintf(P->a,
                                         "Exceeds the limit (4300 digits) for integer string conversion: value has %zu "
                                         "digits; use sys.set_int_max_str_digits() to increase the limit",
                                         nd));
        P->err_at = NULL;
        return false;
    }
    *out = dk_json_int_digits(P->a, dk_strn(start, n));
    return true;
}

/* ---- strings ---- */
static int hex_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Reads 4 hex digits at p (p + 4 <= end required by the caller); -1 when one is not a hex digit. */
static int hex4(const char *p) {
    int v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hex_val((unsigned char)p[i]);
        if (h < 0) return -1;
        v = v * 16 + h;
    }
    return v;
}

/* True when at least n code points start at p. */
static bool has_cps(const Parser *P, const char *p, int n) {
    while (n > 0) {
        if (p >= P->end) return false;
        p++;
        while (p < P->end && ((unsigned char)*p & 0xC0) == 0x80) p++;
        n--;
    }
    return true;
}

/* The string whose opening quote is at q (scanstring_unicode). On success *out is the decoded string, allocated
 * from the arena, and *endp points after the closing quote. */
static bool scan_string(Parser *P, const char *q, const char **endp, DkStr *out) {
    const char *end = P->end, *p = q + 1, *seg = p;
    bool used = false;
    for (;;) {
        while (p < end && (unsigned char)*p >= 0x20 && *p != '"' && *p != '\\') p++;
        if (p >= end) return fail(P, DK_JSON_E_DECODE, "Unterminated string starting at", q);
        unsigned char c = (unsigned char)*p;
        if (c == '"') {
            if (!used) {
                *out = dk_str_dup(P->a, dk_strn(seg, (size_t)(p - seg)));
            } else {
                dk_buf_putn(&P->sb, seg, (size_t)(p - seg));
                *out = dk_str_dup(P->a, dk_buf_str(&P->sb));
            }
            *endp = p + 1;
            return true;
        }
        if (c < 0x20) return fail(P, DK_JSON_E_DECODE, "Invalid control character at", p);
        /* a backslash */
        if (!used) {
            dk_buf_clear(&P->sb);
            used = true;
        }
        dk_buf_putn(&P->sb, seg, (size_t)(p - seg));
        const char *bs = p;
        p++;
        if (p >= end) return fail(P, DK_JSON_E_DECODE, "Unterminated string starting at", q);
        char e = *p;
        if (e != 'u') {
            char r;
            switch (e) {
            case '"': r = '"'; break;
            case '\\': r = '\\'; break;
            case '/': r = '/'; break;
            case 'b': r = '\b'; break;
            case 'f': r = '\f'; break;
            case 'n': r = '\n'; break;
            case 'r': r = '\r'; break;
            case 't': r = '\t'; break;
            default: return fail(P, DK_JSON_E_DECODE, "Invalid \\escape", bs);
            }
            dk_buf_putc(&P->sb, r);
            p++;
            seg = p;
            continue;
        }
        const char *upos = p;
        p++;
        /* four digits (a string that ends right after them is "Unterminated string", not an escape error) */
        if (p + 4 > end) return fail(P, DK_JSON_E_DECODE, "Invalid \\uXXXX escape", upos);
        int cp = hex4(p);
        if (cp < 0) return fail(P, DK_JSON_E_DECODE, "Invalid \\uXXXX escape", upos);
        p += 4;
        if (cp >= 0xD800 && cp < 0xDC00 && has_cps(P, p, 7) && p[0] == '\\' && p[1] == 'u') {
            int lo = hex4(p + 2);
            if (lo < 0) return fail(P, DK_JSON_E_DECODE, "Invalid \\uXXXX escape", p + 1);
            if (lo >= 0xDC00 && lo < 0xE000) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                p += 6;
            }
        }
        char enc[4];
        size_t k = dk_json__put_cp(enc, (u32)cp);
        dk_buf_putn(&P->sb, enc, k);
        seg = p;
    }
}

/* ---- containers ---- */
static DkJson *finish_array(Parser *P, const Frame *f) {
    size_t n = P->vs.n - f->base;
    DkJson *j = dk_json_arr_cap(P->a, n);
    if (n) memcpy(j->u.arr.v, &P->vs.v[f->base], n * sizeof(DkJson *));
    j->u.arr.n = n;
    P->vs.n = f->base;
    return j;
}

static DkJson *finish_object(Parser *P, Frame *f) {
    size_t n = P->ms.n - f->base;
    DkJson *j = dk_json_obj(P->a);
    if (n) {
        j->u.obj.v = DK_NEWN(P->a, DkJsonMember, n);
        memcpy(j->u.obj.v, &P->ms.v[f->base], n * sizeof(DkJsonMember));
        j->u.obj.n = j->u.obj.cap = n;
    }
    if (f->tab) {
        j->u.obj.index = (u32 *)dk_memdup(P->a, f->tab, (size_t)f->tabcap * sizeof(u32));
        j->u.obj.index_cap = f->tabcap;
        dk_xfree(f->tab);
        f->tab = NULL;
    }
    P->ms.n = f->base;
    return j;
}

/* Adds f->key: v to the object under construction (dict semantics for a repeated key). */
static bool add_member(Parser *P, Frame *f, DkJson *v) {
    size_t count = P->ms.n - f->base;
    DkJsonMember *mem = P->ms.v ? &P->ms.v[f->base] : NULL;
    i64 i = count ? dk_json__find(mem, count, f->tab, f->tabcap, f->key) : -1;
    if (i >= 0) {
        if (P->flags & DK_JSON_REJECT_DUP_KEYS) {
            DkStr m = dk_str(dk_sprintf(P->a, "duplicate JSON key: %.*s", DK_SF(f->key)));
            return fail_value(P, m);
        }
        mem[i].val = v;
        return true;
    }
    DkJsonMember *m = dk_vec_push_zero(&P->ms);
    m->key = f->key;
    m->val = v;
    count++;
    if (f->tab) {
        if ((size_t)f->tabcap < count * 2) {
            dk_xfree(f->tab);
            f->tabcap = dk_json__index_cap_for(count);
            f->tab = (u32 *)dk_xcalloc(f->tabcap, sizeof(u32));
            for (size_t k = 0; k < count; k++)
                dk_json__index_put(f->tab, f->tabcap, dk_json__hash(P->ms.v[f->base + k].key), (u32)k);
        } else {
            dk_json__index_put(f->tab, f->tabcap, dk_json__hash(f->key), (u32)(count - 1));
        }
    } else if (count > DK_JSON_LINEAR_MAX) {
        f->tabcap = dk_json__index_cap_for(count);
        f->tab = (u32 *)dk_xcalloc(f->tabcap, sizeof(u32));
        for (size_t k = 0; k < count; k++)
            dk_json__index_put(f->tab, f->tabcap, dk_json__hash(P->ms.v[f->base + k].key), (u32)k);
    }
    return true;
}

/* At a '"' that starts an object key: reads the key, the ':' and the whitespace after it into f. */
static bool read_key(Parser *P, Frame *f, const char **pp) {
    const char *p = *pp;
    if (!scan_string(P, p, &p, &f->key)) return false;
    p = skip_ws(P, p);
    if (PEEK(P, p) != ':') return fail(P, DK_JSON_E_DECODE, "Expecting ':' delimiter", p);
    p = skip_ws(P, p + 1);
    *pp = p;
    return true;
}

static bool match_word(const Parser *P, const char *p, const char *w, size_t n) {
    return (size_t)(P->end - p) >= n && memcmp(p, w, n) == 0;
}

/* The scalar at p (not a container): sets *out and *pp after it. */
static bool parse_scalar(Parser *P, const char **pp, DkJson **out) {
    const char *p = *pp;
    int c = PEEK(P, p);
    switch (c) {
    case '"': {
        DkStr s;
        if (!scan_string(P, p, &p, &s)) return false;
        *out = dk_json_str_ref(P->a, s);
        *pp = p;
        return true;
    }
    case 'n':
        if (match_word(P, p, "null", 4)) {
            *out = dk_json_null();
            *pp = p + 4;
            return true;
        }
        break;
    case 't':
        if (match_word(P, p, "true", 4)) {
            *out = dk_json_bool(true);
            *pp = p + 4;
            return true;
        }
        break;
    case 'f':
        if (match_word(P, p, "false", 5)) {
            *out = dk_json_bool(false);
            *pp = p + 5;
            return true;
        }
        break;
    case 'N':
    case 'I':
    case '-': {
        const char *w = c == 'N' ? "NaN" : c == 'I' ? "Infinity" : "-Infinity";
        size_t wn = strlen(w);
        if ((c != '-' || (p + 1 < P->end && p[1] == 'I')) && match_word(P, p, w, wn)) {
            if (P->flags & DK_JSON_REJECT_CONSTANTS) {
                return fail_value(P, dk_str(dk_sprintf(P->a, "invalid JSON constant: %s", w)));
            }
            *out = dk_json_float(P->a, c == 'N' ? NAN : (c == 'I' ? INFINITY : -INFINITY));
            *pp = p + wn;
            return true;
        }
        break;
    }
    default: break;
    }
    if (c == '-' || (c >= '0' && c <= '9')) return parse_number(P, p, pp, out);
    return fail(P, DK_JSON_E_DECODE, "Expecting value", p);
}

static bool utf8_valid(const char *s, size_t n, size_t *bad, const char **why) {
    const unsigned char *p = (const unsigned char *)s, *end = p + n;
    while (p < end) {
        /* eight ASCII bytes at a time */
        while (p + 8 <= end) {
            u64 w;
            memcpy(&w, p, 8);
            if (w & 0x8080808080808080ull) break;
            p += 8;
        }
        if (p >= end) break;
        unsigned char c = *p;
        if (c < 0x80) {
            p++;
            continue;
        }
        size_t len, off = (size_t)(p - (const unsigned char *)s);
        unsigned char lo = 0x80, hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF) len = 2;
        else if (c >= 0xE0 && c <= 0xEF) {
            len = 3;
            if (c == 0xE0) lo = 0xA0;
            if (c == 0xED) hi = 0x9F;
        } else if (c >= 0xF0 && c <= 0xF4) {
            len = 4;
            if (c == 0xF0) lo = 0x90;
            if (c == 0xF4) hi = 0x8F;
        } else {
            *bad = off;
            *why = "invalid start byte";
            return false;
        }
        if (p + 1 >= end) {
            *bad = off;
            *why = "unexpected end of data";
            return false;
        }
        if (p[1] < lo || p[1] > hi) {
            *bad = off;
            *why = "invalid continuation byte";
            return false;
        }
        for (size_t i = 2; i < len; i++) {
            if (p + i >= end) {
                *bad = off;
                *why = "unexpected end of data";
                return false;
            }
            if ((p[i] & 0xC0) != 0x80) {
                *bad = off;
                *why = "invalid continuation byte";
                return false;
            }
        }
        p += len;
    }
    return true;
}

static void free_temps(Parser *P) {
    for (size_t i = 0; i < P->frames.n; i++) dk_xfree(P->frames.v[i].tab);
    dk_vec_free(&P->frames);
    dk_vec_free(&P->vs);
    dk_vec_free(&P->ms);
    dk_buf_free(&P->sb);
}

static DkJson *parse_value_tree(Parser *P, const char *p, bool *ok) {
    DkJson *v = NULL, *result = NULL;
    *ok = false;
    for (;;) {
        int c = PEEK(P, p);
        if (c == '{') {
            if (P->frames.n >= DK_JSON_MAX_DEPTH) {
                fail(P, DK_JSON_E_RECURSION, "Stack overflow (used 2912 kB) while decoding a JSON object from a unicode string", p);
                return NULL;
            }
            Frame *f = dk_vec_push_zero(&P->frames);
            f->is_obj = true;
            f->base = P->ms.n;
            p = skip_ws(P, p + 1);
            c = PEEK(P, p);
            if (c == '}') {
                p++;
                v = finish_object(P, f);
                P->frames.n--;
                goto have_value;
            }
            if (c != '"') {
                fail(P, DK_JSON_E_DECODE, "Expecting property name enclosed in double quotes", p);
                return NULL;
            }
            if (!read_key(P, f, &p)) return NULL;
            continue;
        }
        if (c == '[') {
            if (P->frames.n >= DK_JSON_MAX_DEPTH) {
                fail(P, DK_JSON_E_RECURSION, "Stack overflow (used 2912 kB) while decoding a JSON array from a unicode string", p);
                return NULL;
            }
            Frame *f = dk_vec_push_zero(&P->frames);
            f->base = P->vs.n;
            p = skip_ws(P, p + 1);
            if (PEEK(P, p) == ']') {
                p++;
                v = finish_array(P, f);
                P->frames.n--;
                goto have_value;
            }
            continue;
        }
        if (!parse_scalar(P, &p, &v)) return NULL;
    have_value:
        for (;;) {
            if (!P->frames.n) {
                result = v;
                goto top_done;
            }
            Frame *f = &P->frames.v[P->frames.n - 1];
            p = skip_ws(P, p);
            c = PEEK(P, p);
            if (!f->is_obj) {
                dk_vec_push(&P->vs, v);
                if (c == ']') {
                    p++;
                    v = finish_array(P, f);
                    P->frames.n--;
                    continue;
                }
                if (c != ',') {
                    fail(P, DK_JSON_E_DECODE, "Expecting ',' delimiter", p);
                    return NULL;
                }
                const char *comma = p;
                p = skip_ws(P, p + 1);
                if (PEEK(P, p) == ']') {
                    fail(P, DK_JSON_E_DECODE, "Illegal trailing comma before end of array", comma);
                    return NULL;
                }
                break;
            }
            if (!add_member(P, f, v)) return NULL;
            if (c == '}') {
                p++;
                v = finish_object(P, f);
                P->frames.n--;
                continue;
            }
            if (c != ',') {
                fail(P, DK_JSON_E_DECODE, "Expecting ',' delimiter", p);
                return NULL;
            }
            const char *comma = p;
            p = skip_ws(P, p + 1);
            c = PEEK(P, p);
            if (c != '"') {
                if (c == '}') fail(P, DK_JSON_E_DECODE, "Illegal trailing comma before end of object", comma);
                else fail(P, DK_JSON_E_DECODE, "Expecting property name enclosed in double quotes", p);
                return NULL;
            }
            if (!read_key(P, f, &p)) return NULL;
            break;
        }
    }
top_done:
    p = skip_ws(P, p);
    if (p != P->end) {
        fail(P, DK_JSON_E_DECODE, "Extra data", p);
        return NULL;
    }
    *ok = true;
    return result;
}

/* Fills *err from the failure recorded in P: positions are code points of the text (after a skipped BOM). */
static void report(Parser *P, DkJsonError *err) {
    err->kind = P->err_kind;
    err->msg = P->err_msg;
    err->lineno = err->colno = err->pos = 0;
    if (P->err_kind != DK_JSON_E_DECODE) return;
    i64 pos = 0, line = 1, col = 1;
    for (const char *q = P->base; q < P->err_at; q++) {
        unsigned char c = (unsigned char)*q;
        if ((c & 0xC0) == 0x80) continue;
        if (c == '\n') {
            line++;
            col = 0;
        }
        pos++;
        col++;
    }
    err->pos = pos;
    err->lineno = line;
    err->colno = col;
}

DkJson *dk_json_parse_ex(DkArena *a, DkStr text, unsigned flags, DkJsonError *err) {
    DkJsonError local;
    Parser ps = {0}, *P = &ps;
    P->a = a;
    P->flags = flags;
    P->base = text.p;
    P->end = text.p + text.n;
    P->sb.a = NULL;
    DkJson *result = NULL;
    bool ok = false;

    size_t bad = 0;
    const char *why = "";
    if (!utf8_valid(text.p, text.n, &bad, &why)) {
        P->err_kind = DK_JSON_E_UNICODE;
        P->err_msg = dk_str(dk_sprintf(a, "'utf-8' codec can't decode byte 0x%02x in position %zu: %s",
                                        (unsigned)(unsigned char)text.p[bad], bad, why));
        goto report;
    }
    if (text.n >= 3 && memcmp(text.p, "\xEF\xBB\xBF", 3) == 0) {
        if (flags & (DK_JSON_STRIP_BOM | DK_JSON_BYTES)) {
            P->base += 3;
        } else {
            P->err_kind = DK_JSON_E_DECODE;
            P->err_msg = DK_S("Unexpected UTF-8 BOM (decode using utf-8-sig)");
            P->err_at = P->base;
            goto report;
        }
    }
    result = parse_value_tree(P, skip_ws(P, P->base), &ok);
    if (ok) {
        free_temps(P);
        return result;
    }
report:
    free_temps(P);
    report(P, err ? err : &local);
    if (!err) {
        DkStr m = dk_json_error_str(a, &local);
        dk_throw(DK_ERR_FORMAT, "%.*s", DK_SF(m));
    }
    return NULL;
}

DkJson *dk_json_parse(DkArena *a, DkStr text, DkJsonError *err) { return dk_json_parse_ex(a, text, 0, err); }
