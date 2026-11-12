// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* C-statement text helpers (ctext.h). */
#include "ctext.h"

#include "dk/arena.h"
#include "dk/re.h"

#include <string.h>

/* ---- registers ---- */

static const struct {
    const char *r, *full;
} FULL[] = {{"al", "eax"}, {"ah", "eax"}, {"ax", "eax"}, {"bl", "ebx"}, {"bh", "ebx"}, {"bx", "ebx"},
            {"cl", "ecx"}, {"ch", "ecx"}, {"cx", "ecx"}, {"dl", "edx"}, {"dh", "edx"}, {"dx", "edx"},
            {"si", "esi"}, {"di", "edi"}, {"bp", "ebp"}, {"sp", "esp"}};

const char *dk_ctext_reg_full(const char *r) {
    for (size_t i = 0; i < DK_ARRAY_LEN(FULL); i++)
        if (strcmp(r, FULL[i].r) == 0) return FULL[i].full;
    return r;
}

const char *dk_ctext_reg_class(const char *r) {
    if (strncmp(r, "xmm", 3) == 0) return "xmm";
    if (strncmp(r, "st", 2) == 0) return "st";
    if (strncmp(r, "mm", 2) == 0) return "mm";
    if (strcmp(r, "esp") == 0 || strcmp(r, "sp") == 0) return r;
    if (strlen(r) == 3) return "r32";
    return (r[1] == 'l' || r[1] == 'h') ? "r8" : "r16";
}

/* ---- statements ---- */

DkStr dk_ctext_code_of(DkStr line) {
    i64 k = dk_str_find(line, DK_S("//"), 0, DK_END);
    if (k >= 0) line.n = (size_t)k;
    return dk_str_strip(line);
}

i64 dk_ctext_calls(DkStr text) {
    DkArena *scratch = dk_scratch();
    DkArenaMark mark = dk_arena_mark(scratch);
    DkStr clean = dk_re_sub(scratch, dk_re(DK_CTEXT_NOT_CALLS_PAT, 0), DK_S(""), text, 0);
    i64 n = 0;
    DkReIter it;
    DkReMatch m;
    dk_re_iter_init(&it, dk_re(DK_CTEXT_CALL_PAT, 0), clean, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) n++;
    dk_arena_reset(scratch, mark);
    return n;
}

bool dk_ctext_not_type(DkStr w) {
    static const char *const words[] = {"return", "delete", "goto", "else", "case", "throw", "new"};
    for (size_t i = 0; i < DK_ARRAY_LEN(words); i++)
        if (dk_str_eqz(w, words[i])) return true;
    return false;
}

static bool blank(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }

static DkStr first_word(DkStr s) {
    s = dk_str_lstrip(s);
    size_t n = 0;
    while (n < s.n && !blank(s.p[n])) n++;
    s.n = n;
    return s;
}

/* The text after the last ".", "->" (and "[" when with_bracket). */
static DkStr last_piece(DkStr s, bool with_bracket) {
    size_t start = 0;
    for (size_t i = 0; i < s.n; i++) {
        char c = s.p[i];
        if (c == '.' || (with_bracket && c == '[')) {
            start = i + 1;
        } else if (c == '-' && i + 1 < s.n && s.p[i + 1] == '>') {
            start = i + 2;
            i++;
        }
    }
    DkStr out = {s.p + start, s.n - start};
    return out;
}

DkSet *dk_ctext_written(DkStr text) {
    DkSet *out = dk_set_new();
    DkReMatch m;
    bool ok = dk_re_match(dk_re(DK_CTEXT_DECL_INIT_PAT, 0), text, 0, DK_END, &m) ||
              dk_re_match(dk_re(DK_CTEXT_DECL_ONLY_PAT, 0), text, 0, DK_END, &m);
    if (ok && !dk_ctext_not_type(first_word(dk_re_group(&m, 2)))) dk_set_add(out, dk_re_group(&m, 3));
    DkReIter it;
    dk_re_iter_init(&it, dk_re("([A-Za-z_][\\w.\\->\\[\\]]*)\\s*(?:[-+*/%&|^]|<<|>>)?=(?!=)", 0), text, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) {
        DkStr lhs = dk_re_group(&m, 1);
        if (dk_str_contains(lhs, DK_S("->")) || dk_str_contains(lhs, DK_S("."))) {
            DkStr piece = last_piece(lhs, true);
            while (piece.n && piece.p[piece.n - 1] == ']') piece.n--;
            dk_set_add(out, piece);
        } else {
            dk_set_add(out, lhs);
        }
    }
    dk_re_iter_init(&it, dk_re("(?:\\+\\+|--)([A-Za-z_][\\w.\\->]*)|([A-Za-z_][\\w.\\->]*)(?:\\+\\+|--)", 0), text, 0,
                    DK_END);
    while (dk_re_iter_next(&it, &m)) {
        DkStr v = dk_re_matched(&m, 1) ? dk_re_group(&m, 1) : dk_re_group(&m, 2);
        dk_set_add(out, last_piece(v, false));
    }
    return out;
}

DkSet *dk_ctext_read(DkStr text) {
    DkSet *out = dk_set_new();
    DkReIter it;
    DkReMatch m;
    dk_re_iter_init(&it, dk_re("[A-Za-z_]\\w*", 0), text, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) dk_set_add(out, dk_re_group(&m, 0));
    return out;
}

bool dk_ctext_split_top(DkStr text, const char *sep, DkStr *left, DkStr *right) {
    size_t sl = strlen(sep);
    bool colon = strcmp(sep, ":") == 0;
    int depth = 0;
    for (size_t i = 0; i < text.n; i++) {
        char c = text.p[i];
        if (c == '(' || c == '[' || c == '{') {
            depth++;
        } else if (c == ')' || c == ']' || c == '}') {
            depth--;
        } else if (depth == 0 && i + sl <= text.n && memcmp(text.p + i, sep, sl) == 0 &&
                   !(colon && i + 1 < text.n && text.p[i + 1] == ':') && !(colon && i > 0 && text.p[i - 1] == ':')) {
            if (left) *left = (DkStr){text.p, i};
            if (right) *right = (DkStr){text.p + i + sl, text.n - i - sl};
            return true;
        }
    }
    return false;
}

bool dk_ctext_atomic(DkStr expr) {
    expr = dk_str_strip(expr);
    if (dk_re_fullmatch(dk_re(DK_CTEXT_TOKEN, 0), expr, 0, DK_END, NULL)) return true;
    if (!dk_str_startswith(expr, DK_S("("))) return false;
    DkStr l, r;
    return dk_ctext_split_top(dk_str_slice(expr, 1, DK_END), ")", &l, &r) && r.n == 0;
}
