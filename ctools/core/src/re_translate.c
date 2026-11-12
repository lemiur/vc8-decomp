// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore re: the translator from Python's regular expression syntax to PCRE2's. It parses the pattern the way
 * CPython's re._parser does (same tokens, same errors, same messages) and writes an equivalent PCRE2 pattern:
 * everything where the two dialects differ is rewritten here, so the PCRE2 compile options only carry UTF, UCP and
 * CASELESS. See re.h for the list of differences. */
#include "re_priv.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

/* what the last parsed item of the current alternative allows next (Python: "nothing to repeat" / "multiple
 * repeat") */
enum { LAST_NONE, LAST_ATOM, LAST_AT, LAST_REPEAT };

typedef struct {
    const u8 *p;
    size_t n;
    size_t i;
    bool bytes;
    DkBuf out;
    bool ascii_global; /* no UCP: \w \d \s \b are ASCII in the PCRE2 pattern */
    bool caseless;
    int ngroups;
    char **gname;
    int *gparent;
    u8 *gopen;
    size_t gcap;
    int cur_group;
    int cond_refs_max;     /* highest numeric conditional reference seen */
    size_t cond_refs_pos;
    int depth;
    jmp_buf *jb; /* heap-allocated: jmp_buf is 16-byte aligned and would pad this struct (C4324) */
    char msg[256];
    size_t errpos;
} Tr;

#define F_I DK_RE_I
#define F_M DK_RE_M
#define F_S DK_RE_S
#define F_X DK_RE_X
#define F_A DK_RE_A

DK_NORETURN static void tr_err(Tr *t, size_t pos, DK_PRINTF_FMT const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(t->msg, sizeof t->msg, fmt, ap);
    va_end(ap);
    t->errpos = pos;
    longjmp(*t->jb, 1);
}

static bool at_end(const Tr *t) { return t->i >= t->n; }

static u32 peek_cp(const Tr *t, size_t *len) {
    const u8 *p = t->p + t->i;
    size_t left = t->n - t->i;
    if (t->bytes || p[0] < 0x80 || left < 2) { *len = 1; return p[0]; }
    u32 c = p[0];
    size_t k = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : 2;
    if (k > left) { *len = 1; return c; }
    u32 v = c & (0x7F >> k);
    for (size_t j = 1; j < k; j++) v = (v << 6) | (p[j] & 0x3F);
    *len = k;
    return v;
}

static u32 next_cp(Tr *t) {
    size_t len;
    u32 c = peek_cp(t, &len);
    t->i += len;
    return c;
}

static int peek_byte(const Tr *t) { return t->i < t->n ? t->p[t->i] : -1; }

static bool is_digit(int c) { return c >= '0' && c <= '9'; }
static bool is_octdigit(int c) { return c >= '0' && c <= '7'; }
static bool is_hexdigit(int c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static int hexval(int c) { return is_digit(c) ? c - '0' : (c | 0x20) - 'a' + 10; }
static bool is_ascii_letter(u32 c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

/* ---- output ---------------------------------------------------------------------------------------------- */

/* A literal code point: ASCII letters and digits as they are, anything else as \x{...} so that no character can
 * change meaning in PCRE2 (inside or outside a class). */
static void emit_lit(Tr *t, u32 v) {
    if ((v >= '0' && v <= '9') || (v >= 'a' && v <= 'z') || (v >= 'A' && v <= 'Z')) dk_buf_putc(&t->out, (char)v);
    else dk_buf_printf(&t->out, "\\x{%X}", (unsigned)v);
}

/* Python's str.isspace set (PCRE2's \s also holds U+180E, Python's does not). */
#define UNI_SPACE "\\t-\\r\\x{1C}-\\x{20}\\x{85}\\x{A0}\\x{1680}\\x{2000}-\\x{200A}\\x{2028}\\x{2029}\\x{202F}\\x{205F}\\x{3000}"

/* Python's \d \D \s \S \w \W for the scope's mode (ASCII or Unicode) in a pattern whose PCRE2 mode is
 * t->ascii_global. in_class: the text goes inside [...]. PCRE2's Unicode \s differs from Python's only by
 * U+180E, so it is spelled out; PCRE2 10.43+ counts combining marks (Mn) and connector punctuation (Pc) as word
 * characters, Python does not, so a Unicode \w is spelled out as letters, numbers and underscore. A negated
 * shorthand inside a class that has to be spelled out cannot be a member of a PCRE2 class: emit_cat then returns
 * the body of the class it negates (parse_class combines it with the rest of the class). */
static const char *emit_cat(Tr *t, u32 fl, int cat, bool in_class) {
    bool scope_ascii = t->bytes || (fl & F_A) != 0;
    bool neg = cat >= 'A' && cat <= 'Z';
    int kind = cat | 0x20; /* d s w */
    DkBuf *o = &t->out;
    if ((scope_ascii && t->ascii_global) || (kind == 'd' && !scope_ascii && !t->ascii_global)) {
        /* the same text in PCRE2: ASCII classes of a non-UCP pattern, \d of a UCP pattern (\p{Nd}) */
        dk_buf_putc(o, '\\');
        dk_buf_putc(o, (char)cat);
        return NULL;
    }
    const char *body;
    if (scope_ascii) body = kind == 'd' ? "0-9" : kind == 'w' ? "0-9A-Za-z_" : " \\t\\n\\x{0B}\\f\\r";
    else body = kind == 'd' ? "\\p{Nd}" : kind == 'w' ? "\\p{L}\\p{N}_" : UNI_SPACE;
    if (in_class) {
        if (neg) return body;
        dk_buf_putz(o, body);
    } else {
        dk_buf_putz(o, neg ? "[^" : "[");
        dk_buf_putz(o, body);
        dk_buf_putc(o, ']');
    }
    return NULL;
}

static void emit_boundary(Tr *t, u32 fl, bool negated) {
    bool scope_ascii = t->bytes || (fl & F_A) != 0;
    if (scope_ascii && t->ascii_global) {
        dk_buf_putz(&t->out, negated ? "\\B" : "\\b");
        return;
    }
    const char *W = scope_ascii ? "[0-9A-Za-z_]" : "[\\p{L}\\p{N}_]";
    if (!negated) dk_buf_printf(&t->out, "(?:(?<=%s)(?!%s)|(?<!%s)(?=%s))", W, W, W, W);
    else dk_buf_printf(&t->out, "(?:(?<=%s)(?=%s)|(?<!%s)(?!%s))", W, W, W, W);
}

/* ---- groups ---------------------------------------------------------------------------------------------- */

static int open_group(Tr *t, const char *name, size_t name_len, size_t namepos) {
    int g = ++t->ngroups;
    if ((size_t)g >= t->gcap) {
        size_t nc = t->gcap ? t->gcap * 2 : 16;
        t->gname = dk_xrealloc(t->gname, nc * sizeof *t->gname);
        t->gparent = dk_xrealloc(t->gparent, nc * sizeof *t->gparent);
        t->gopen = dk_xrealloc(t->gopen, nc * sizeof *t->gopen);
        t->gcap = nc;
    }
    t->gname[g] = NULL;
    t->gparent[g] = t->cur_group;
    t->gopen[g] = 1;
    if (name) {
        for (int j = 1; j < g; j++) {
            if (t->gname[j] && strlen(t->gname[j]) == name_len && memcmp(t->gname[j], name, name_len) == 0)
                tr_err(t, namepos, "redefinition of group name '%.*s' as group %d; was group %d", (int)name_len, name,
                       g, j);
        }
        char *c = dk_xmalloc(name_len + 1);
        memcpy(c, name, name_len);
        c[name_len] = 0;
        t->gname[g] = c;
    }
    return g;
}

static int find_group(const Tr *t, const char *name, size_t len) {
    for (int j = 1; j <= t->ngroups; j++)
        if (t->gname[j] && strlen(t->gname[j]) == len && memcmp(t->gname[j], name, len) == 0) return j;
    return -1;
}

/* str.isidentifier for a group name (bytes patterns: ASCII only) */
static bool is_identifier(const Tr *t, const u8 *s, size_t n) {
    if (n == 0) return false;
    for (size_t k = 0; k < n; k++) {
        u8 c = s[k];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (k > 0 && is_digit(c)) ||
                  (c >= 0x80 && !t->bytes);
        if (!ok) return false;
    }
    return true;
}

/* source.getuntil(term, "group name"): the text up to term (consumed). Python's two errors. */
static void get_until(Tr *t, char term, const char *what, const u8 **s, size_t *len) {
    size_t st = t->i;
    while (t->i < t->n && t->p[t->i] != (u8)term) t->i++;
    if (t->i >= t->n) {
        if (t->i == st) tr_err(t, t->i, "missing %s", what);
        tr_err(t, st, "missing %c, unterminated name", term);
    }
    if (t->i == st) tr_err(t, t->i, "missing %s", what);
    *s = t->p + st;
    *len = t->i - st;
    t->i++;
}

/* ---- escapes --------------------------------------------------------------------------------------------- */

typedef enum { E_LIT, E_CAT, E_AT, E_REF } EscKind;
typedef struct {
    EscKind kind;
    u32 v; /* E_LIT: the code point / byte; E_CAT: the letter; E_AT: the letter; E_REF: the group */
} Esc;

static void bad_escape(Tr *t, size_t bs) {
    size_t save = t->i;
    char buf[16];
    size_t len = save - bs;
    if (len > 12) len = 12;
    memcpy(buf, t->p + bs, len);
    buf[len] = 0;
    tr_err(t, bs, "bad escape %s", buf);
}

/* Parses the escape after a backslash at index bs (t->i is just after the backslash) the way
 * re._parser._escape (outside a class) and _class_escape (in a class) do. */
static void parse_escape(Tr *t, size_t bs, bool in_class, Esc *e) {
    if (at_end(t)) tr_err(t, bs, "bad escape (end of pattern)");
    u32 c = next_cp(t);
    e->kind = E_LIT;
    switch (c) {
    case 'a': e->v = 7; return;
    case 'f': e->v = 12; return;
    case 'n': e->v = 10; return;
    case 'r': e->v = 13; return;
    case 't': e->v = 9; return;
    case 'v': e->v = 11; return;
    case '\\': e->v = '\\'; return;
    case 'b':
        if (in_class) { e->v = 8; return; }
        e->kind = E_AT; e->v = 'b';
        return;
    case 'A': case 'Z': case 'B':
        if (in_class) bad_escape(t, bs);
        e->kind = E_AT; e->v = c;
        return;
    case 'd': case 'D': case 's': case 'S': case 'w': case 'W':
        e->kind = E_CAT; e->v = c;
        return;
    case 'x': case 'u': case 'U': {
        if (c != 'x' && t->bytes) bad_escape(t, bs);
        int want = c == 'x' ? 2 : c == 'u' ? 4 : 8, got = 0;
        u64 v = 0;
        while (got < want && is_hexdigit(peek_byte(t))) { v = v * 16 + (u64)hexval(t->p[t->i]); t->i++; got++; }
        if (got != want) {
            char buf[16];
            size_t len = t->i - bs;
            memcpy(buf, t->p + bs, len < 12 ? len : 12);
            buf[len < 12 ? len : 12] = 0;
            tr_err(t, bs, "incomplete escape %s", buf);
        }
        if (v > 0x10FFFF) bad_escape(t, bs);
        e->v = (u32)v;
        return;
    }
    case 'N':
        if (t->bytes) bad_escape(t, bs);
        tr_err(t, bs, "unsupported \\N{...} escape (dkcore has no Unicode name database)");
    case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
        break;
    default:
        if (c < 0x80 && is_ascii_letter(c)) bad_escape(t, bs);
        e->v = c;
        return;
    }
    /* digits */
    if (c == '0' || (in_class && is_octdigit((int)c))) {
        u32 v = c - '0';
        int more = 0;
        while (more < 2 && is_octdigit(peek_byte(t))) { v = v * 8 + (u32)(t->p[t->i] - '0'); t->i++; more++; }
        if (v > 0377) tr_err(t, bs, "octal escape value %.*s outside of range 0-0o377", (int)(t->i - bs), t->p + bs);
        e->v = v;
        return;
    }
    if (in_class) bad_escape(t, bs); /* \8 \9 */
    /* an octal escape or a decimal group reference */
    u32 group = c - '0';
    if (is_digit(peek_byte(t))) {
        int d2 = t->p[t->i];
        t->i++;
        group = group * 10 + (u32)(d2 - '0');
        if (is_octdigit((int)c) && is_octdigit(d2) && is_octdigit(peek_byte(t))) {
            u32 v = (c - '0') * 64 + (u32)(d2 - '0') * 8 + (u32)(t->p[t->i] - '0');
            t->i++;
            if (v > 0377) tr_err(t, bs, "octal escape value %.*s outside of range 0-0o377", (int)(t->i - bs), t->p + bs);
            e->v = v;
            return;
        }
    }
    if ((int)group <= t->ngroups) {
        if (t->gopen[group]) tr_err(t, bs, "cannot refer to an open group");
        e->kind = E_REF;
        e->v = group;
        return;
    }
    tr_err(t, bs + 1, "invalid group reference %u", group);
}

/* ---- character classes ----------------------------------------------------------------------------------- */

/* A character class, parsed the way re._parser does it. Items go into a body text; negated shorthands that have
 * to be spelled out (see emit_cat) are collected apart and the class becomes an alternation:
 *   [P\W]    ->  (?:[P]|[^W-body])            [^P\W]  ->  (?:(?![P])(?=[W-body])(?s:.)) */
#define MAX_NEG_BODIES 6

static void class_item(Tr *t, u32 fl, const Esc *e, const char **neg, int *nneg, size_t tok) {
    if (e->kind == E_CAT) {
        const char *nb = emit_cat(t, fl, (int)e->v, true);
        if (nb) {
            if (*nneg == MAX_NEG_BODIES) tr_err(t, tok, "too many negated classes in a character set");
            neg[(*nneg)++] = nb;
        }
    } else {
        emit_lit(t, e->v);
    }
}

static void parse_class(Tr *t, u32 fl, size_t here) {
    /* t->i is just after '[' */
    DkBuf saved = t->out;
    t->out = (DkBuf){0};
    bool negate = false;
    if (peek_byte(t) == '^') { t->i++; negate = true; }
    const char *neg[MAX_NEG_BODIES];
    int nneg = 0;
    bool any = false;
    for (;;) {
        if (at_end(t)) tr_err(t, here, "unterminated character set");
        size_t tok = t->i;
        u32 this_ = next_cp(t);
        if (this_ == ']' && any) break;
        Esc e1;
        if (this_ == '\\') parse_escape(t, tok, true, &e1);
        else { e1.kind = E_LIT; e1.v = this_; }
        any = true;
        if (peek_byte(t) == '-') {
            t->i++;
            if (at_end(t)) tr_err(t, here, "unterminated character set");
            size_t tok2 = t->i;
            u32 that = next_cp(t);
            if (that == ']') {
                class_item(t, fl, &e1, neg, &nneg, tok);
                dk_buf_putz(&t->out, "\\x{2D}");
                break;
            }
            Esc e2;
            if (that == '\\') parse_escape(t, tok2, true, &e2);
            else { e2.kind = E_LIT; e2.v = that; }
            if (e1.kind != E_LIT || e2.kind != E_LIT || e2.v < e1.v)
                tr_err(t, tok, "bad character range %.*s-%.*s", (int)(tok2 - 1 - tok), t->p + tok, (int)(t->i - tok2),
                       t->p + tok2);
            emit_lit(t, e1.v);
            dk_buf_putc(&t->out, '-');
            emit_lit(t, e2.v);
        } else {
            class_item(t, fl, &e1, neg, &nneg, tok);
        }
    }
    DkBuf body = t->out;
    t->out = saved;
    DkBuf *o = &t->out;
    if (nneg == 0) {
        dk_buf_putz(o, negate ? "[^" : "[");
        dk_buf_putn(o, body.p, body.n);
        dk_buf_putc(o, ']');
    } else if (!negate) {
        dk_buf_putz(o, "(?:");
        bool sep = false;
        if (body.n) {
            dk_buf_putc(o, '[');
            dk_buf_putn(o, body.p, body.n);
            dk_buf_putc(o, ']');
            sep = true;
        }
        for (int k = 0; k < nneg; k++) {
            if (sep) dk_buf_putc(o, '|');
            dk_buf_printf(o, "[^%s]", neg[k]);
            sep = true;
        }
        dk_buf_putc(o, ')');
    } else {
        dk_buf_putz(o, "(?:");
        if (body.n) {
            dk_buf_putz(o, "(?![");
            dk_buf_putn(o, body.p, body.n);
            dk_buf_putz(o, "])");
        }
        for (int k = 0; k < nneg; k++) dk_buf_printf(o, "(?=[%s])", neg[k]);
        dk_buf_putz(o, "(?s:.))");
    }
    dk_buf_free(&body);
}

/* ---- groups and branches --------------------------------------------------------------------------------- */

static void parse_sub(Tr *t, u32 *fl, bool nested_top);

/* One alternative. `first` is true for the first alternative of the whole pattern (where global flags may
 * stand). Returns at '|', ')' or the end. */
static void parse_branch(Tr *t, u32 *flp, bool first);

static bool skip_group_end(Tr *t, size_t start) {
    if (peek_byte(t) != ')') tr_err(t, start, "missing ), unterminated subpattern");
    t->i++;
    return true;
}

static void parse_flags_group(Tr *t, size_t start, u32 *flp, bool first, int *last, bool *is_group, u32 *sub_fl,
                              bool *add_i, bool *del_i, u32 c) {
    /* c is the first flag character (already consumed) */
    u32 add = 0, del = 0;
    u32 fl = *flp;
    *is_group = false;
    bool saw_type = false;
    u32 type_flag = 0;
    if (c != '-') {
        for (;;) {
            u32 f = 0;
            switch (c) {
            case 'a': f = F_A; break;
            case 'i': f = F_I; break;
            case 'L': f = DK_RE_L; break;
            case 'm': f = F_M; break;
            case 's': f = F_S; break;
            case 'u': f = DK_RE_U; break;
            case 'x': f = F_X; break;
            default: break;
            }
            if (!f) tr_err(t, t->i - 1, "unknown flag"); /* only reached for the first flag */
            if (!t->bytes && c == 'L') tr_err(t, t->i, "bad inline flags: cannot use 'L' flag with a str pattern");
            if (t->bytes && c == 'u') tr_err(t, t->i, "bad inline flags: cannot use 'u' flag with a bytes pattern");
            if (c == 'L') tr_err(t, t->i, "bad inline flags: the 'L' flag is not supported");
            add |= f;
            if (f == F_A || f == DK_RE_U) {
                if (saw_type && type_flag != f) tr_err(t, t->i, "bad inline flags: flags 'a', 'u' and 'L' are incompatible");
                saw_type = true;
                type_flag = f;
            }
            if (at_end(t)) tr_err(t, t->n, "missing -, : or )");
            c = next_cp(t);
            if (c == ')' || c == '-' || c == ':') break;
            if (!(c == 'a' || c == 'i' || c == 'L' || c == 'm' || c == 's' || c == 'u' || c == 'x'))
                tr_err(t, t->i - 1, (c < 0x80 && is_ascii_letter(c)) ? "unknown flag" : "missing -, : or )");
        }
        if (c == ')') {
            /* global flags */
            if (!first || *last != LAST_NONE) tr_err(t, start, "global flags not at the start of the expression");
            if (add & F_A) { fl |= F_A; t->ascii_global = true; }
            if (add & DK_RE_U) { fl &= ~(u32)F_A; t->ascii_global = t->bytes; }
            if (add & F_I) t->caseless = true;
            fl |= add & (F_I | F_M | F_S | F_X);
            *flp = fl;
            return;
        }
    }
    *is_group = true;
    if (c == '-') {
        if (at_end(t)) tr_err(t, t->n, "missing flag");
        c = next_cp(t);
        for (;;) {
            u32 f = 0;
            switch (c) {
            case 'i': f = F_I; break;
            case 'm': f = F_M; break;
            case 's': f = F_S; break;
            case 'x': f = F_X; break;
            case 'a': case 'L': case 'u':
                tr_err(t, t->i, "bad inline flags: cannot turn off flags 'a', 'u' and 'L'");
            default: break;
            }
            if (!f) tr_err(t, t->i - 1, (c < 0x80 && is_ascii_letter(c)) ? "unknown flag" : "missing flag");
            del |= f;
            if (at_end(t)) tr_err(t, t->n, "missing :");
            c = next_cp(t);
            if (c == ':') break;
            if (!(c == 'a' || c == 'i' || c == 'L' || c == 'm' || c == 's' || c == 'u' || c == 'x'))
                tr_err(t, t->i - 1, (c < 0x80 && is_ascii_letter(c)) ? "unknown flag" : "missing :");
        }
    }
    if (add & del) tr_err(t, t->i - 1, "bad inline flags: flag turned on and off");
    u32 nfl = fl;
    if (add & F_A) nfl |= F_A;
    if (add & DK_RE_U) nfl &= ~(u32)F_A;
    nfl |= add & (F_I | F_M | F_S | F_X);
    nfl &= ~del;
    *sub_fl = nfl;
    *add_i = (add & F_I) != 0;
    *del_i = (del & F_I) != 0;
}

static void parse_group(Tr *t, size_t start, u32 fl, bool first_top, u32 *flp, int *last) {
    /* t->i is just after '(' */
    DkBuf *o = &t->out;
    u32 sub_fl = fl;
    int gnum = 0;
    const char *opener = "(?:";
    char flagopen[16];
    bool lookaround = false;
    if (peek_byte(t) == '?') {
        t->i++;
        if (at_end(t)) tr_err(t, t->n, "unexpected end of pattern");
        size_t cpos = t->i;
        u32 c = next_cp(t);
        if (c == 'P') {
            if (peek_byte(t) == '<') {
                t->i++;
                const u8 *name; size_t nl;
                get_until(t, '>', "group name", &name, &nl);
                if (!is_identifier(t, name, nl))
                    tr_err(t, (size_t)(name - t->p), "bad character in group name '%.*s'", (int)nl, name);
                gnum = open_group(t, (const char *)name, nl, (size_t)(name - t->p));
                opener = "(";
            } else if (peek_byte(t) == '=') {
                t->i++;
                const u8 *name; size_t nl;
                get_until(t, ')', "group name", &name, &nl);
                size_t npos = (size_t)(name - t->p);
                if (!is_identifier(t, name, nl)) tr_err(t, npos, "bad character in group name '%.*s'", (int)nl, name);
                int g = find_group(t, (const char *)name, nl);
                if (g < 0) tr_err(t, npos, "unknown group name '%.*s'", (int)nl, name);
                if (t->gopen[g]) tr_err(t, npos, "cannot refer to an open group");
                dk_buf_printf(o, "\\g{%d}", g);
                *last = LAST_ATOM;
                return;
            } else {
                if (at_end(t)) tr_err(t, t->n, "unexpected end of pattern");
                size_t l2;
                u32 c2 = peek_cp(t, &l2);
                (void)c2;
                tr_err(t, cpos - 1, "unknown extension ?P%.*s", (int)l2, t->p + t->i);
            }
        } else if (c == ':') {
            opener = "(?:";
        } else if (c == '#') {
            while (t->i < t->n && t->p[t->i] != ')') t->i += t->p[t->i] == '\\' ? 2 : 1;
            if (t->i >= t->n) tr_err(t, start, "missing ), unterminated comment");
            t->i++;
            return; /* no item */
        } else if (c == '=' || c == '!') {
            opener = c == '=' ? "(?=" : "(?!";
            lookaround = true;
        } else if (c == '<') {
            if (at_end(t)) tr_err(t, t->n, "unexpected end of pattern");
            size_t l2;
            u32 c2 = peek_cp(t, &l2);
            if (c2 != '=' && c2 != '!') tr_err(t, cpos - 1, "unknown extension ?<%.*s", (int)l2, t->p + t->i);
            t->i += l2;
            opener = c2 == '=' ? "(?<=" : "(?<!";
            lookaround = true;
        } else if (c == '>') {
            opener = "(?>";
        } else if (c == '(') {
            /* conditional: (?(name-or-number)yes|no) */
            const u8 *name; size_t nl;
            get_until(t, ')', "group name", &name, &nl);
            size_t npos = (size_t)(name - t->p);
            int cond;
            if (is_identifier(t, name, nl)) {
                cond = find_group(t, (const char *)name, nl);
                if (cond < 0) tr_err(t, npos, "unknown group name '%.*s'", (int)nl, name);
            } else {
                bool digits = nl > 0;
                for (size_t k = 0; k < nl; k++) if (!is_digit(name[k])) digits = false;
                if (!digits) tr_err(t, npos, "bad character in group name '%.*s'", (int)nl, name);
                long long v = 0;
                for (size_t k = 0; k < nl && v < 1000000; k++) v = v * 10 + (name[k] - '0');
                if (v == 0) tr_err(t, npos, "bad group number");
                if (v >= 100000) tr_err(t, npos, "invalid group reference %lld", v);
                cond = (int)v;
                if (cond > t->cond_refs_max) { t->cond_refs_max = cond; t->cond_refs_pos = npos; }
            }
            dk_buf_printf(o, "(?(%d)", cond);
            int l2 = LAST_NONE;
            parse_branch(t, &fl, false);
            (void)l2;
            if (peek_byte(t) == '|') {
                t->i++;
                dk_buf_putc(o, '|');
                parse_branch(t, &fl, false);
                if (peek_byte(t) == '|') tr_err(t, t->i, "conditional backref with more than two branches");
            }
            skip_group_end(t, start);
            dk_buf_putc(o, ')');
            *last = LAST_ATOM;
            return;
        } else if (c == 'a' || c == 'i' || c == 'L' || c == 'm' || c == 's' || c == 'u' || c == 'x' || c == '-') {
            bool is_group, add_i = false, del_i = false;
            parse_flags_group(t, start, flp, first_top, last, &is_group, &sub_fl, &add_i, &del_i, c);
            if (!is_group) return; /* global flags: no item */
            snprintf(flagopen, sizeof flagopen, "(?%s%s:", add_i ? "i" : "", del_i ? "-i" : "");
            opener = flagopen;
        } else {
            size_t l2 = (size_t)(t->i - cpos);
            tr_err(t, cpos - 1, "unknown extension ?%.*s", (int)l2, t->p + cpos);
        }
    } else {
        gnum = open_group(t, NULL, 0, start);
        opener = "(";
    }
    (void)lookaround;
    dk_buf_putz(o, opener);
    int saved_group = t->cur_group;
    if (gnum) t->cur_group = gnum;
    if (++t->depth > 400) tr_err(t, start, "pattern is nested too deeply");
    u32 inner = sub_fl;
    parse_sub(t, &inner, false);
    t->depth--;
    skip_group_end(t, start);
    dk_buf_putc(o, ')');
    if (gnum) {
        t->gopen[gnum] = 0;
        t->cur_group = saved_group;
    }
    *last = LAST_ATOM;
}

static void emit_quant(Tr *t, bool has_lo, u64 lo, bool has_hi, u64 hi, bool single, char kind) {
    DkBuf *o = &t->out;
    if (kind == '*' || kind == '+' || kind == '?') { dk_buf_putc(o, kind); return; }
    (void)has_lo; (void)has_hi;
    if (single) dk_buf_printf(o, "{%llu}", (unsigned long long)lo);
    else if (hi == UINT64_MAX) dk_buf_printf(o, "{%llu,}", (unsigned long long)lo);
    else dk_buf_printf(o, "{%llu,%llu}", (unsigned long long)lo, (unsigned long long)hi);
}

static void parse_branch(Tr *t, u32 *flp, bool first) {
    DkBuf *o = &t->out;
    int last = LAST_NONE;
    for (;;) {
        if (at_end(t)) break;
        u8 b = t->p[t->i];
        if (b == '|' || b == ')') break;
        size_t tok = t->i;
        u32 fl = *flp;
        u32 c = next_cp(t);
        if (fl & F_X) {
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0x0B || c == '\f') continue;
            if (c == '#') {
                while (t->i < t->n) {
                    u8 ch = t->p[t->i++];
                    if (ch == '\n') break;
                }
                continue;
            }
        }
        switch (c) {
        case '\\': {
            Esc e;
            parse_escape(t, tok, false, &e);
            switch (e.kind) {
            case E_LIT: emit_lit(t, e.v); last = LAST_ATOM; break;
            case E_CAT: emit_cat(t, fl, (int)e.v, false); last = LAST_ATOM; break;
            case E_REF: dk_buf_printf(o, "\\g{%u}", e.v); last = LAST_ATOM; break;
            case E_AT:
                if (e.v == 'A') dk_buf_putz(o, "\\A");
                else if (e.v == 'Z') dk_buf_putz(o, "\\z");
                else emit_boundary(t, fl, e.v == 'B');
                last = LAST_AT;
                break;
            }
            break;
        }
        case '[':
            parse_class(t, fl, tok);
            last = LAST_ATOM;
            break;
        case '(':
            parse_group(t, tok, fl, first, flp, &last);
            break;
        case '.':
            dk_buf_putz(o, (fl & F_S) ? "(?s:.)" : ".");
            last = LAST_ATOM;
            break;
        case '^':
            dk_buf_putz(o, (fl & F_M) ? "(?<![^\\n])" : "^");
            last = LAST_AT;
            break;
        case '$':
            dk_buf_putz(o, (fl & F_M) ? "(?![^\\n])" : "$");
            last = LAST_AT;
            break;
        case '*': case '+': case '?': case '{': {
            u64 lo = 0, hi = UINT64_MAX;
            bool single = false, has_lo = false, has_hi = false;
            char kind = (char)c;
            if (c == '{') {
                if (peek_byte(t) == '}') { dk_buf_putz(o, "\\x{7B}"); last = LAST_ATOM; break; }
                size_t save = t->i;
                size_t d0 = t->i;
                while (is_digit(peek_byte(t))) t->i++;
                size_t d1 = t->i;
                size_t e0 = 0, e1 = 0;
                bool comma = false;
                if (peek_byte(t) == ',') {
                    comma = true;
                    t->i++;
                    e0 = t->i;
                    while (is_digit(peek_byte(t))) t->i++;
                    e1 = t->i;
                }
                if (peek_byte(t) != '}') {
                    t->i = save;
                    dk_buf_putz(o, "\\x{7B}");
                    last = LAST_ATOM;
                    break;
                }
                t->i++;
                has_lo = d1 > d0;
                if (has_lo) {
                    if (d1 - d0 > 10) tr_err(t, (size_t)-1, "the repetition number is too large");
                    lo = strtoull((const char *)t->p + d0, NULL, 10);
                }
                if (comma) {
                    has_hi = e1 > e0;
                    if (has_hi) {
                        if (e1 - e0 > 10) tr_err(t, (size_t)-1, "the repetition number is too large");
                        hi = strtoull((const char *)t->p + e0, NULL, 10);
                    }
                } else {
                    hi = lo;
                    single = true;
                }
                if (lo >= 0xFFFFFFFFull || (hi != UINT64_MAX && hi >= 0xFFFFFFFFull))
                    tr_err(t, (size_t)-1, "the repetition number is too large");
                if (hi != UINT64_MAX && hi < lo) tr_err(t, tok + 1, "min repeat greater than max repeat");
            }
            if (last == LAST_NONE || last == LAST_AT) tr_err(t, tok, "nothing to repeat");
            if (last == LAST_REPEAT) tr_err(t, tok, "multiple repeat");
            emit_quant(t, has_lo, lo, has_hi, hi, single, kind);
            if (peek_byte(t) == '?') { t->i++; dk_buf_putc(o, '?'); }
            else if (peek_byte(t) == '+') { t->i++; dk_buf_putc(o, '+'); }
            last = LAST_REPEAT;
            break;
        }
        default: {
            size_t len = t->i - tok;
            if (c < 0x80) {
                emit_lit(t, c);
            } else if (t->bytes) {
                emit_lit(t, c);
            } else {
                dk_buf_putn(o, t->p + tok, len);
            }
            last = LAST_ATOM;
            break;
        }
        }
        first = first && last == LAST_NONE;
    }
}

static void parse_sub(Tr *t, u32 *fl, bool top) {
    bool first = top;
    for (;;) {
        parse_branch(t, fl, first);
        if (peek_byte(t) == '|') {
            t->i++;
            dk_buf_putc(&t->out, '|');
            first = false;
            continue;
        }
        break;
    }
}

/* ---- errors ---------------------------------------------------------------------------------------------- */

void re_format_error(char *dst, size_t cap, const char *msg, DkStr pattern, size_t bytepos, bool bytes) {
    if (bytepos > pattern.n) bytepos = pattern.n;
    size_t pos = bytepos;
    if (!bytes) {
        pos = 0;
        for (size_t k = 0; k < bytepos; k++) if ((pattern.p[k] & 0xC0) != 0x80) pos++;
    }
    size_t line = 1, last_nl = (size_t)-1;
    bool has_nl = false;
    for (size_t k = 0; k < pattern.n; k++) {
        if (pattern.p[k] == '\n') {
            has_nl = true;
            if (k < bytepos) { line++; last_nl = k; }
        }
    }
    if (has_nl) {
        size_t col;
        if (last_nl == (size_t)-1) col = pos + 1;
        else {
            col = 0;
            for (size_t k = last_nl + 1; k < bytepos; k++) if (bytes || (pattern.p[k] & 0xC0) != 0x80) col++;
            col += 1;
        }
        snprintf(dst, cap, "%s at position %zu (line %zu, column %zu)", msg, pos, line, col);
    } else {
        snprintf(dst, cap, "%s at position %zu", msg, pos);
    }
}

void re_trans_free(ReTrans *t) {
    if (t->names) {
        for (int g = 1; g <= t->ngroups; g++) dk_xfree(t->names[g]);
    }
    dk_xfree(t->names);
    dk_xfree(t->parent);
    dk_xfree(t->pcre);
    memset(t, 0, sizeof *t);
}

bool re_translate(DkStr pattern, int flags, ReTrans *out, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    bool bytes = (flags & DK_RE_BYTES) != 0;
    flags &= ~DK_RE_BYTES;
    if (bytes && (flags & DK_RE_U)) { snprintf(err, errcap, "cannot use UNICODE flag with a bytes pattern"); return false; }
    if (flags & DK_RE_L) {
        snprintf(err, errcap, bytes ? "the LOCALE flag is not supported" : "cannot use LOCALE flag with a str pattern");
        return false;
    }
    if (!bytes && (flags & DK_RE_A) && (flags & DK_RE_U)) { snprintf(err, errcap, "ASCII and UNICODE flags are incompatible"); return false; }
    if (!bytes && !dk_u8_valid(pattern)) { snprintf(err, errcap, "pattern is not valid UTF-8"); return false; }

    Tr t;
    memset(&t, 0, sizeof t);
    t.p = (const u8 *)pattern.p;
    t.n = pattern.n;
    t.bytes = bytes;
    t.caseless = (flags & DK_RE_I) != 0;
    t.ascii_global = bytes || (flags & DK_RE_A) != 0;
    t.out.a = NULL;
    t.gcap = 0;
    open_group(&t, NULL, 0, 0); /* slot 0 is the whole match */
    t.ngroups = 0;
    t.gopen[0] = 0;
    u32 fl = (u32)flags & (DK_RE_I | DK_RE_M | DK_RE_S | DK_RE_X | DK_RE_A);
    if (bytes) fl |= DK_RE_A;
    t.jb = dk_xmalloc(sizeof(jmp_buf));
    if (setjmp(*t.jb) == 0) {
        parse_sub(&t, &fl, true);
        if (!at_end(&t)) tr_err(&t, t.i, "unbalanced parenthesis");
        if (t.cond_refs_max > t.ngroups) tr_err(&t, t.cond_refs_pos, "invalid group reference %d", t.cond_refs_max);
    } else {
        if (t.errpos == (size_t)-1) snprintf(err, errcap, "%s", t.msg); /* Python raises OverflowError: no position */
        else re_format_error(err, errcap, t.msg, pattern, t.errpos, bytes);
        dk_buf_free(&t.out);
        dk_xfree(t.jb);
        for (int g = 1; g <= t.ngroups; g++) dk_xfree(t.gname[g]);
        dk_xfree(t.gname); dk_xfree(t.gparent); dk_xfree(t.gopen);
        return false;
    }
    dk_xfree(t.jb);
    out->pcre_len = t.out.n;
    out->pcre = dk_xmalloc(t.out.n + 1);
    if (t.out.n) memcpy(out->pcre, t.out.p, t.out.n);
    out->pcre[t.out.n] = 0;
    dk_buf_free(&t.out);
    out->ngroups = t.ngroups;
    out->names = dk_xcalloc((size_t)t.ngroups + 1, sizeof *out->names);
    out->parent = dk_xcalloc((size_t)t.ngroups + 1, sizeof *out->parent);
    for (int g = 1; g <= t.ngroups; g++) {
        out->names[g] = t.gname[g];
        out->parent[g] = t.gparent[g];
    }
    dk_xfree(t.gname); dk_xfree(t.gparent); dk_xfree(t.gopen);
    out->bytes = bytes;
    out->caseless = t.caseless;
    out->ucp = !t.ascii_global;
    out->pyflags = flags | (bytes || (flags & DK_RE_A) ? 0 : DK_RE_U);
    if (t.caseless) out->pyflags |= DK_RE_I;
    return true;
}
