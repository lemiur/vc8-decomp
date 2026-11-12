// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore json writer: json.dumps / json.dump byte for byte (the escapes, separators, indent, sort_keys and float
 * rules of Lib/json/encoder.py), as a tree walk and as a streaming writer. */
#include "json_internal.h"
#include "dk/arena.h"
#include "dk/fmt.h"
#include <math.h>
#include <stdlib.h>

/* ---- low-level output: writes straight into the DkBuf's memory ---- */
static char *room(DkBuf *b, size_t n) {
    dk_buf_reserve(b, n + 1);
    return b->p + b->n;
}

static void commit(DkBuf *b, size_t n) {
    b->n += n;
    b->p[b->n] = 0;
}

static void put(DkBuf *b, const char *s, size_t n) {
    if (!n) return;
    memcpy(room(b, n), s, n);
    commit(b, n);
}

static const char HEX[] = "0123456789abcdef";

static size_t put_u_escape(char *d, unsigned v) {
    d[0] = '\\';
    d[1] = 'u';
    d[2] = HEX[(v >> 12) & 15];
    d[3] = HEX[(v >> 8) & 15];
    d[4] = HEX[(v >> 4) & 15];
    d[5] = HEX[v & 15];
    return 6;
}

/* Decodes one code point of generalized UTF-8 (surrogates allowed) at p; invalid bytes give U+FFFD, one byte. */
static u32 next_cp(const unsigned char **pp, const unsigned char *end) {
    const unsigned char *p = *pp;
    unsigned c = *p;
    if (c < 0x80) {
        *pp = p + 1;
        return c;
    }
    if (c >= 0xC2 && c <= 0xDF && p + 1 < end && (p[1] & 0xC0) == 0x80) {
        *pp = p + 2;
        return ((c & 0x1F) << 6) | (p[1] & 0x3F);
    }
    if (c >= 0xE0 && c <= 0xEF && p + 2 < end && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
        u32 cp = ((c & 0x0F) << 12) | ((u32)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
        if (cp >= 0x800) {
            *pp = p + 3;
            return cp;
        }
    }
    if (c >= 0xF0 && c <= 0xF4 && p + 3 < end && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
        u32 cp = ((c & 0x07) << 18) | ((u32)(p[1] & 0x3F) << 12) | ((u32)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
        if (cp >= 0x10000 && cp <= 0x10FFFF) {
            *pp = p + 4;
            return cp;
        }
    }
    *pp = p + 1;
    return 0xFFFD;
}

/* One piece of json.dumps(s): the escapes of py_encode_basestring_ascii (or py_encode_basestring when raw_unicode).
 * The piece must not end inside a UTF-8 sequence. */
static void put_string_piece(DkBuf *out, const unsigned char *p, const unsigned char *end, bool raw_unicode) {
    /* worst case: every byte becomes a 6-byte \u00XX escape, a 4-byte code point two escapes (12) */
    char *d = room(out, (size_t)(end - p) * 6);
    char *start = d;
    while (p < end) {
        unsigned c = *p;
        if (c >= 0x20 && c != '"' && c != '\\' && c < 0x7F) {
            const unsigned char *q = p + 1;
            while (q < end && *q >= 0x20 && *q != '"' && *q != '\\' && *q < 0x7F) q++;
            memcpy(d, p, (size_t)(q - p));
            d += q - p;
            p = q;
            continue;
        }
        if (c < 0x80) {
            p++;
            switch (c) {
            case '"': *d++ = '\\'; *d++ = '"'; break;
            case '\\': *d++ = '\\'; *d++ = '\\'; break;
            case '\n': *d++ = '\\'; *d++ = 'n'; break;
            case '\r': *d++ = '\\'; *d++ = 'r'; break;
            case '\t': *d++ = '\\'; *d++ = 't'; break;
            case '\b': *d++ = '\\'; *d++ = 'b'; break;
            case '\f': *d++ = '\\'; *d++ = 'f'; break;
            case 0x7F:
                if (raw_unicode) *d++ = (char)c;
                else d += put_u_escape(d, c);
                break;
            default: d += put_u_escape(d, c); break;
            }
            continue;
        }
        if (raw_unicode) {
            /* non-ASCII bytes pass through unchanged (valid UTF-8, lone surrogates in their 3-byte form) */
            const unsigned char *q = p + 1;
            while (q < end && *q >= 0x80) q++;
            memcpy(d, p, (size_t)(q - p));
            d += q - p;
            p = q;
            continue;
        }
        u32 cp = next_cp(&p, end);
        if (cp >= 0x10000) {
            cp -= 0x10000;
            d += put_u_escape(d, 0xD800 | (cp >> 10));
            d += put_u_escape(d, 0xDC00 | (cp & 0x3FF));
        } else {
            d += put_u_escape(d, cp);
        }
    }
    commit(out, (size_t)(d - start));
}

/* json.dumps(s) (ensure_ascii) or json.dumps(s, ensure_ascii=False), quotes included. */
void dk_json_put_string(DkBuf *out, DkStr s, bool raw_unicode) {
    const unsigned char *p = (const unsigned char *)s.p, *end = p + s.n;
    put(out, "\"", 1);
    while (p < end) {
        const unsigned char *q = (size_t)(end - p) > 4096 ? p + 4096 : end;
        while (q < end && (*q & 0xC0) == 0x80) q++;
        put_string_piece(out, p, q, raw_unicode);
        p = q;
    }
    put(out, "\"", 1);
}

static void put_i64(DkBuf *b, i64 v) {
    char tmp[24];
    char *e = tmp + sizeof tmp, *p = e;
    u64 u = v < 0 ? 0u - (u64)v : (u64)v;
    do {
        *--p = (char)('0' + u % 10);
        u /= 10;
    } while (u);
    if (v < 0) *--p = '-';
    put(b, p, (size_t)(e - p));
}

static void put_u64(DkBuf *b, u64 u) {
    char tmp[24];
    char *e = tmp + sizeof tmp, *p = e;
    do {
        *--p = (char)('0' + u % 10);
        u /= 10;
    } while (u);
    put(b, p, (size_t)(e - p));
}

/* ---- the streaming writer ---- */
enum { ST_ARRAY = 1, ST_OBJECT = 2, ST_HAS_ITEM = 0x80, ST_KEY_PENDING = 0x40, ST_KIND = 0x3F };

void dk_jsonw_init(DkJsonW *w, DkBuf *out, const DkJsonDumpOpts *opts) {
    memset(w, 0, sizeof *w);
    w->out = out;
    if (opts) w->o = *opts;
    if (w->o.custom_separators) {
        w->item_sep = w->o.item_sep;
        w->key_sep = w->o.key_sep;
    } else {
        w->item_sep = w->o.indented ? DK_S(",") : DK_S(", ");
        w->key_sep = DK_S(": ");
    }
    if (w->o.indented) {
        if (w->o.indent.p) {
            w->indent_unit = w->o.indent;
        } else {
            /* ' ' * width: a static run of spaces long enough for any sane width, else built in the buffer on use */
            w->indent_unit = (DkStr){NULL, w->o.indent_width > 0 ? (size_t)w->o.indent_width : 0};
        }
    }
    w->stack = w->inline_stack;
    w->stack_cap = sizeof w->inline_stack;
}

void dk_jsonw_set_spill(DkJsonW *w, size_t threshold, DkJsonSpillFn fn, void *ctx) {
    w->spill_threshold = threshold;
    w->spill = fn;
    w->spill_ctx = ctx;
}

static void maybe_spill(DkJsonW *w) {
    if (w->spill && w->out->n >= w->spill_threshold) {
        if (!w->spill(w->spill_ctx, w->out->p, w->out->n)) w->failed = true;
        dk_buf_clear(w->out);
    }
}

bool dk_jsonw_finish(DkJsonW *w) {
    if (w->spill && w->out->n) {
        if (!w->spill(w->spill_ctx, w->out->p, w->out->n)) w->failed = true;
        dk_buf_clear(w->out);
    }
    if (w->stack != w->inline_stack) dk_xfree(w->stack);
    w->stack = w->inline_stack;
    w->stack_cap = sizeof w->inline_stack;
    return !w->failed;
}

static void put_newline_indent(DkJsonW *w, size_t levels) {
    DkBuf *b = w->out;
    size_t unit = w->indent_unit.n;
    char *d = room(b, 1 + unit * levels);
    *d++ = '\n';
    if (w->indent_unit.p) {
        for (size_t i = 0; i < levels; i++) {
            memcpy(d, w->indent_unit.p, unit);
            d += unit;
        }
    } else {
        memset(d, ' ', unit * levels);
        d += unit * levels;
    }
    commit(b, (size_t)(d - (b->p + b->n)));
}

/* Called before every value: the separator and indentation of an array item, or checks that a key is pending. */
static bool before_value(DkJsonW *w) {
    if (w->failed) return false;
    if (w->depth == 0) return true;
    u8 *top = &w->stack[w->depth - 1];
    if ((*top & ST_KIND) == ST_OBJECT) {
        DK_ASSERT(*top & ST_KEY_PENDING);
        *top &= (u8)~ST_KEY_PENDING;
        return true;
    }
    if (*top & ST_HAS_ITEM) put(w->out, w->item_sep.p, w->item_sep.n);
    if (w->o.indented) put_newline_indent(w, w->depth);
    *top |= ST_HAS_ITEM;
    return true;
}

static void after_value(DkJsonW *w) { maybe_spill(w); }

static void push(DkJsonW *w, u8 kind) {
    if (w->depth == w->stack_cap) {
        size_t cap = w->stack_cap * 2;
        u8 *n = (u8 *)dk_xmalloc(cap);
        memcpy(n, w->stack, w->depth);
        if (w->stack != w->inline_stack) dk_xfree(w->stack);
        w->stack = n;
        w->stack_cap = cap;
    }
    w->stack[w->depth++] = kind;
}

static void begin(DkJsonW *w, u8 kind, char open) {
    if (!before_value(w)) return;
    put(w->out, &open, 1);
    push(w, kind);
}

static void end(DkJsonW *w, u8 kind, char close) {
    if (w->failed) return;
    DK_ASSERT(w->depth > 0 && (w->stack[w->depth - 1] & ST_KIND) == kind && !(w->stack[w->depth - 1] & ST_KEY_PENDING));
    u8 st = w->stack[--w->depth];
    if ((st & ST_HAS_ITEM) && w->o.indented) put_newline_indent(w, w->depth);
    put(w->out, &close, 1);
    after_value(w);
}

void dk_jsonw_begin_object(DkJsonW *w) { begin(w, ST_OBJECT, '{'); }
void dk_jsonw_end_object(DkJsonW *w) { end(w, ST_OBJECT, '}'); }
void dk_jsonw_begin_array(DkJsonW *w) { begin(w, ST_ARRAY, '['); }
void dk_jsonw_end_array(DkJsonW *w) { end(w, ST_ARRAY, ']'); }

void dk_jsonw_key(DkJsonW *w, DkStr key) {
    if (w->failed) return;
    DK_ASSERT(w->depth > 0);
    u8 *top = &w->stack[w->depth - 1];
    DK_ASSERT((*top & ST_KIND) == ST_OBJECT && !(*top & ST_KEY_PENDING));
    if (*top & ST_HAS_ITEM) put(w->out, w->item_sep.p, w->item_sep.n);
    if (w->o.indented) put_newline_indent(w, w->depth);
    *top |= ST_HAS_ITEM | ST_KEY_PENDING;
    dk_json_put_string(w->out, key, w->o.raw_unicode);
    put(w->out, w->key_sep.p, w->key_sep.n);
}

void dk_jsonw_null(DkJsonW *w) {
    if (!before_value(w)) return;
    put(w->out, "null", 4);
    after_value(w);
}

void dk_jsonw_bool(DkJsonW *w, bool b) {
    if (!before_value(w)) return;
    if (b) put(w->out, "true", 4);
    else put(w->out, "false", 5);
    after_value(w);
}

void dk_jsonw_i64(DkJsonW *w, i64 v) {
    if (!before_value(w)) return;
    put_i64(w->out, v);
    after_value(w);
}

void dk_jsonw_u64(DkJsonW *w, u64 v) {
    if (!before_value(w)) return;
    put_u64(w->out, v);
    after_value(w);
}

void dk_jsonw_int_digits(DkJsonW *w, DkStr digits) {
    if (!before_value(w)) return;
    i64 v;
    if (dk_json__int_fits(digits, &v)) put_i64(w->out, v); /* "-0" is 0 */
    else put(w->out, digits.p, digits.n);
    after_value(w);
}

void dk_jsonw_f64(DkJsonW *w, double v) {
    if (!before_value(w)) return;
    if (isnan(v) || isinf(v)) {
        if (w->o.reject_nan) {
            w->failed = true;
            if (w->o.err) {
                w->o.err->kind = DK_JSON_E_VALUE;
                w->o.err->msg = isnan(v) ? DK_S("Out of range float values are not JSON compliant: nan")
                                         : v > 0 ? DK_S("Out of range float values are not JSON compliant: inf")
                                                 : DK_S("Out of range float values are not JSON compliant: -inf");
                w->o.err->lineno = w->o.err->colno = w->o.err->pos = 0;
            }
            return;
        }
        if (isnan(v)) put(w->out, "NaN", 3);
        else if (v > 0) put(w->out, "Infinity", 8);
        else put(w->out, "-Infinity", 9);
    } else {
        char buf[32];
        size_t n = dk_float_repr(v, buf);
        put(w->out, buf, n);
    }
    after_value(w);
}

void dk_jsonw_str(DkJsonW *w, DkStr s) {
    if (!before_value(w)) return;
    dk_json_put_string(w->out, s, w->o.raw_unicode);
    after_value(w);
}

void dk_jsonw_strz(DkJsonW *w, const char *cz) { dk_jsonw_str(w, dk_str(cz)); }

void dk_jsonw_kv_str(DkJsonW *w, const char *key, DkStr s) {
    dk_jsonw_key(w, dk_str(key));
    dk_jsonw_str(w, s);
}
void dk_jsonw_kv_i64(DkJsonW *w, const char *key, i64 v) {
    dk_jsonw_key(w, dk_str(key));
    dk_jsonw_i64(w, v);
}
void dk_jsonw_kv_f64(DkJsonW *w, const char *key, double v) {
    dk_jsonw_key(w, dk_str(key));
    dk_jsonw_f64(w, v);
}
void dk_jsonw_kv_bool(DkJsonW *w, const char *key, bool b) {
    dk_jsonw_key(w, dk_str(key));
    dk_jsonw_bool(w, b);
}

/* ---- trees ---- */
typedef struct {
    const DkJson *node;
    size_t i;
    const DkJsonMember **order; /* sorted members of an object when sort_keys (heap), else NULL */
} TFrame;

static int cmp_member(const void *x, const void *y) {
    const DkJsonMember *a = *(const DkJsonMember *const *)x, *b = *(const DkJsonMember *const *)y;
    size_t n = a->key.n < b->key.n ? a->key.n : b->key.n;
    int c = n ? memcmp(a->key.p, b->key.p, n) : 0; /* UTF-8 byte order is code point order */
    if (c) return c;
    return a->key.n < b->key.n ? -1 : a->key.n > b->key.n;
}

static void write_scalar(DkJsonW *w, const DkJson *v) {
    switch (v->kind) {
    case DK_JSON_NULL: dk_jsonw_null(w); break;
    case DK_JSON_BOOL: dk_jsonw_bool(w, v->b); break;
    case DK_JSON_INT:
        if (v->big) dk_jsonw_int_digits(w, v->u.str);
        else dk_jsonw_i64(w, v->u.i);
        break;
    case DK_JSON_FLOAT: dk_jsonw_f64(w, v->u.f); break;
    case DK_JSON_STRING: dk_jsonw_str(w, v->u.str); break;
    default: DK_ASSERT(false);
    }
}

void dk_jsonw_tree(DkJsonW *w, const DkJson *root) {
    DK_VEC(TFrame) st = {0};
    const DkJson *v = root ? root : dk_json_null();
    for (;;) {
        /* write v: scalars at once, containers open and push */
        if (v->kind == DK_JSON_ARRAY || v->kind == DK_JSON_OBJECT) {
            bool obj = v->kind == DK_JSON_OBJECT;
            if (obj) dk_jsonw_begin_object(w);
            else dk_jsonw_begin_array(w);
            TFrame *f = dk_vec_push_zero(&st);
            f->node = v;
            if (obj && w->o.sort_keys && v->u.obj.n > 1) {
                f->order = (const DkJsonMember **)dk_xmalloc(v->u.obj.n * sizeof(DkJsonMember *));
                for (size_t i = 0; i < v->u.obj.n; i++) f->order[i] = &v->u.obj.v[i];
                qsort(f->order, v->u.obj.n, sizeof(DkJsonMember *), cmp_member);
            }
        } else {
            write_scalar(w, v);
        }
        /* find the next value to write, closing finished containers */
        for (;;) {
            if (!st.n) {
                dk_vec_free(&st);
                return;
            }
            TFrame *f = &st.v[st.n - 1];
            const DkJson *n = f->node;
            bool obj = n->kind == DK_JSON_OBJECT;
            size_t count = obj ? n->u.obj.n : n->u.arr.n;
            if (f->i == count) {
                if (obj) dk_jsonw_end_object(w);
                else dk_jsonw_end_array(w);
                dk_xfree(f->order);
                st.n--;
                continue;
            }
            if (obj) {
                const DkJsonMember *m = f->order ? f->order[f->i] : &n->u.obj.v[f->i];
                dk_jsonw_key(w, m->key);
                v = m->val;
            } else {
                v = n->u.arr.v[f->i];
            }
            f->i++;
            break;
        }
        if (w->failed) {
            for (size_t i = 0; i < st.n; i++) dk_xfree(st.v[i].order);
            dk_vec_free(&st);
            return;
        }
    }
}

/* ---- one-shot dumps ---- */
bool dk_json_dump_buf(DkBuf *out, const DkJson *v, const DkJsonDumpOpts *opts) {
    DkJsonW w;
    dk_jsonw_init(&w, out, opts);
    dk_jsonw_tree(&w, v);
    return dk_jsonw_finish(&w);
}

DkStr dk_json_dumps(DkArena *a, const DkJson *v, const DkJsonDumpOpts *opts) {
    DkBuf b = {0};
    DkStr r = {NULL, 0};
    if (dk_json_dump_buf(&b, v, opts)) r = dk_str_dup(a, dk_buf_str(&b));
    dk_buf_free(&b);
    return r;
}

static bool spill_to_file(void *ctx, const char *p, size_t n) { return fwrite(p, 1, n, (FILE *)ctx) == n; }

bool dk_json_dump_file(FILE *f, const DkJson *v, const DkJsonDumpOpts *opts) {
    DkBuf b = {0};
    DkJsonW w;
    dk_jsonw_init(&w, &b, opts);
    dk_jsonw_set_spill(&w, 1 << 16, spill_to_file, f);
    dk_jsonw_tree(&w, v);
    bool ok = dk_jsonw_finish(&w);
    dk_buf_free(&b);
    return ok;
}
