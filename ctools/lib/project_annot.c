// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Annotations: the marker lines of a unit (a configured regex naming a kind, targets and addresses), their companion
 * comment lines (symbol, stop, pending), the declaration each marker stands for, and the binding of an annotation to
 * a compiled symbol.
 *
 * Parsing. The text is searched for markers (multi-line regex, in text order). A copy of the text with comments and
 * string and character literals blanked (newlines kept) is used to find declarations, so braces and parentheses in
 * literals and comments do not count. Each marker's declaration lies between the marker and the next marker:
 *   declaration rule   function: the first "{" after the marker is the body, brace-matched; the name is the first
 *                      identifier followed by "(" in between (__declspec, __attribute__ and throw skipped). data: the
 *                      last identifier before "=", ";", "[" or "{" (a function pointer's own name first).
 *   next_line rule     the declaration starts at the first code after the companion lines and ends at its body's "}"
 *                      or at ";" (a body is optional); the name is the qualified name of the declaration: functions
 *                      and methods with templates, destructors and operators, data, or the class of a vtable.
 * The explicit symbol line is searched between the marker and the declaration's "{" or ";".
 *
 * Binding. The declaration rule takes the MSVC spellings of a plain name (_name, _name@N, ?name@...). The next_line
 * rule undecorates each candidate and compares the undecorated name as a whole: the qualified name must appear as the
 * function's name (an unqualified annotation never matches a qualified symbol), template arguments compared without
 * class/struct keywords and blanks, overloads told apart by the parameter count and, where the types are plain
 * built-in types or class names, by the parameter types of the annotated declaration. */
#include "project.h"

#include "dk/fs.h"
#include "dk/sort.h"
#include "pdb.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ---- regex building blocks ------------------------------------------------------------------------------------- */

#define ARG_CHAR "(?:[^<>;{}()\\n]|\\([^()\\n]*\\))"
#define TEMPLATE_ARGS "<(?:" ARG_CHAR "|<(?:" ARG_CHAR "|<" ARG_CHAR "*>)*>)*>"
#define FUNC_NAME_PAT                                                                                       \
    "((?:~?[A-Za-z_]\\w*(?:\\s*" TEMPLATE_ARGS ")?\\s*::\\s*)*(?:~?[A-Za-z_]\\w*(?:" TEMPLATE_ARGS        \
    ")?|operator\\s*[^\\s(]+))\\s*\\("
#define DATA_NAME_PAT                                                                                       \
    "((?:[A-Za-z_]\\w*(?:\\s*" TEMPLATE_ARGS ")?\\s*::\\s*)*[A-Za-z_]\\w*)\\s*(?:\\[[^\\]]*\\]\\s*)*(?:=|;|,)"
#define DATA_CTOR_NAME_PAT                                                                                  \
    "^\\s*(?:(?:static|extern|const|volatile)\\s+)*(?!(?:static|extern|const|volatile)\\b)[A-Za-z_][\\w:]*(?:\\s*" \
    TEMPLATE_ARGS ")?\\s*[*&\\s]\\s*([A-Za-z_]\\w*)\\s*\\("
#define FUNCTION_POINTER_PAT "\\(\\s*\\*\\s*([A-Za-z_]\\w*)\\s*\\)"
#define CLASS_NAME_PAT "^(?=[A-Z]\\w*[a-z])[A-Z]\\w*$"
#define CLASS_TEMPLATE_PAT "^(?=[A-Z]\\w*[a-z])[A-Z]\\w*\\s*<"

static bool has_byte(DkStr s, char c) { return s.n && memchr(s.p, c, s.n) != NULL; }
static bool contains(DkStr hay, DkStr needle) { return dk_str_contains(hay, needle); }
static bool starts_at(DkStr s, size_t at, DkStr w) {
    return at <= s.n && s.n - at >= w.n && (w.n == 0 || memcmp(s.p + at, w.p, w.n) == 0);
}
static bool is_word_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '$' ||
           (unsigned char)c >= 0x80;
}

static void fail(DkErr *err, int code, DK_PRINTF_FMT const char *fmt, ...) {
    if (!err) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    dk_err_set(err, code, "%s", buf);
}

/* ---- configuration ----------------------------------------------------------------------------------------------- */

static bool compile_pattern(const char *key, const char *pattern, DkRe **out, DkErr *err) {
    *out = NULL;
    if (!pattern) return true;
    char msg[512];
    if (!dk_re_compile(dk_str(pattern), DK_RE_M, out, msg, sizeof msg)) {
        fail(err, DK_ERR_REGEX, "annotations.%s: %s", key, msg);
        return false;
    }
    return true;
}

/* The group named first (or, when absent, second) in re; -1 when neither exists. */
static int group_of(const DkRe *re, const char *first, const char *second) {
    int g = dk_re_group_index(re, first);
    if (g < 0 && second) g = dk_re_group_index(re, second);
    return g;
}

bool dk_annot_config_compile(DkAnnotConfig *c, const char *const *target_names, size_t ntargets, DkErr *err) {
    dk_err_clear(err);
    if (!c->marker || !c->marker[0]) {
        fail(err, DK_ERR_FORMAT, "annotations.marker: not configured");
        return false;
    }
    if (ntargets > DK_MAX_TARGETS) {
        fail(err, DK_ERR_FORMAT, "annotations: %zu targets, at most %d", ntargets, DK_MAX_TARGETS);
        return false;
    }
    if (!compile_pattern("marker", c->marker, &c->re_marker, err) ||
        !compile_pattern("symbol", c->symbol, &c->re_symbol, err) ||
        !compile_pattern("stop", c->stop, &c->re_stop, err) ||
        !compile_pattern("pending", c->pending, &c->re_pending, err) ||
        !compile_pattern("flags", c->flags, &c->re_flags, err))
        return false;
    c->ntargets = (int)ntargets;
    for (int t = 0; t < DK_MAX_TARGETS; t++) {
        c->target_names[t] = (size_t)t < ntargets ? target_names[t] : NULL;
        c->g_addr_target[t] = -1;
    }
    c->g_kind = group_of(c->re_marker, c->group_kind ? c->group_kind : "kind", NULL);
    if (c->group_kind && c->g_kind < 0) {
        fail(err, DK_ERR_FORMAT, "annotations.marker: no group named '%s'", c->group_kind);
        return false;
    }
    c->g_target = c->g_addr = -1;
    if (c->addr_groups == DK_ADDR_TARGET_ADDR) {
        c->g_target = c->group_target ? group_of(c->re_marker, c->group_target, NULL)
                                      : group_of(c->re_marker, "target", "binary");
        c->g_addr = c->group_addr ? group_of(c->re_marker, c->group_addr, NULL) : group_of(c->re_marker, "addr", "va");
        if (c->g_target < 0 || c->g_addr < 0) {
            fail(err, DK_ERR_FORMAT, "annotations.marker: the target+addr grammar needs the groups %s and %s",
                 c->group_target ? c->group_target : "target (or binary)", c->group_addr ? c->group_addr : "addr (or va)");
            return false;
        }
    } else {
        int found = 0;
        for (size_t t = 0; t < ntargets; t++) {
            char name[256];
            snprintf(name, sizeof name, "addr_%s", target_names[t]);
            c->g_addr_target[t] = dk_re_group_index(c->re_marker, name);
            found += c->g_addr_target[t] >= 0;
        }
        if (!found) {
            fail(err, DK_ERR_FORMAT, "annotations.marker: the per-target grammar needs a group addr_<target>");
            return false;
        }
    }
    return true;
}

/* ---- text helpers ------------------------------------------------------------------------------------------------ */

/* The text with // and block comments and string and character literals blanked: every byte but a newline becomes a
 * space, so offsets and line numbers are the text's. An unterminated literal or comment is left as it is. */
static char *blank_code(DkArena *a, DkStr text) {
    char *out = (char *)dk_alloc_noz(a, text.n + 1);
    memcpy(out, text.p, text.n);
    out[text.n] = 0;
    size_t i = 0;
    while (i < text.n) {
        char c = text.p[i];
        size_t end = i;
        if (c == '/' && i + 1 < text.n && text.p[i + 1] == '/') {
            end = i + 2;
            while (end < text.n && text.p[end] != '\n') end++;
        } else if (c == '/' && i + 1 < text.n && text.p[i + 1] == '*') {
            size_t k = i + 2;
            while (k + 1 < text.n && !(text.p[k] == '*' && text.p[k + 1] == '/')) k++;
            if (k + 1 < text.n) end = k + 2;
        } else if (c == '"' || c == '\'') {
            size_t k = i + 1;
            while (k < text.n && text.p[k] != c) k += text.p[k] == '\\' && k + 1 < text.n ? 2 : 1;
            if (k < text.n) end = k + 1;
        }
        if (end == i) {
            i++;
            continue;
        }
        for (size_t k = i; k < end; k++)
            if (out[k] != '\n') out[k] = ' ';
        i = end;
    }
    return out;
}

typedef struct {
    DkStr text;
    size_t *nl; /* offsets of the newlines */
    size_t nnl;
} Lines;

static void lines_init(Lines *L, DkArena *a, DkStr text) {
    L->text = text;
    L->nnl = 0;
    for (size_t i = 0; i < text.n; i++) L->nnl += text.p[i] == '\n';
    L->nl = DK_NEWN(a, size_t, L->nnl + 1);
    size_t k = 0;
    for (size_t i = 0; i < text.n; i++)
        if (text.p[i] == '\n') L->nl[k++] = i;
}
/* The 1-based line of a byte offset. */
static int line_of(const Lines *L, size_t off) {
    size_t lo = 0, hi = L->nnl;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (L->nl[mid] < off) lo = mid + 1;
        else hi = mid;
    }
    return (int)lo + 1;
}
static size_t line_start(const Lines *L, int line) { return line <= 1 ? 0 : L->nl[line - 2] + 1; }
static size_t line_end(const Lines *L, int line) { return (size_t)line <= L->nnl ? L->nl[line - 1] : L->text.n; }
static int nlines(const Lines *L) { return (int)L->nnl + 1; }

static DkStr collapse(DkArena *a, DkStr s) {
    s = dk_str_strip(s);
    if (!s.n) return s;
    return dk_re_sub(a, dk_re("\\s+", 0), DK_S(" "), s, 0);
}

/* name.split("::")[-1], splitting only outside template arguments. */
static DkStr last_component(DkStr s) {
    int depth = 0;
    size_t from = 0;
    for (size_t i = 0; i + 1 < s.n; i++) {
        if (s.p[i] == '<') depth++;
        else if (s.p[i] == '>' && depth > 0) depth--;
        else if (depth == 0 && s.p[i] == ':' && s.p[i + 1] == ':') from = i + 2;
    }
    return dk_strn(s.p + from, s.n - from);
}

static bool parse_hex(DkStr s, u32 *out) {
    s = dk_str_strip(s);
    if (s.n >= 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X')) s = dk_str_slice(s, 2, DK_END);
    if (!s.n) return false;
    u64 v = 0;
    for (size_t i = 0; i < s.n; i++) {
        char c = s.p[i];
        int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (d < 0) return false;
        v = v * 16 + (u64)d;
        if (v > 0xFFFFFFFFull) return false;
    }
    *out = (u32)v;
    return true;
}

/* ---- names ------------------------------------------------------------------------------------------------------- */

static bool keyword(DkStr w) {
    static const char *const words[] = {
        "if", "for", "while", "switch", "return", "sizeof", "else", "do", "case", "new", "delete", "static_cast",
        "reinterpret_cast", "const_cast", "dynamic_cast", "throw", "catch", "typedef", "extern", "static", "inline",
        "virtual", "const", "struct", "class", "union", "enum", "public", "private", "protected", "__declspec",
        "__attribute__", "void", "bool", "char", "short", "int", "long", "float", "double", "signed", "unsigned"};
    for (size_t i = 0; i < DK_ARRAY_LEN(words); i++)
        if (dk_str_eqz(w, words[i])) return true;
    return false;
}

/* A declared name without its blanks, but for one between two words of a template argument. */
static DkStr compact_name(DkArena *a, DkStr text) {
    DkStr t = dk_re_sub(a, dk_re("\\s+", 0), DK_S(" "), dk_str_strip(text), 0);
    t = dk_re_sub(a, dk_re("\\s*(::|[<>,*&()\\[\\]])\\s*", 0), DK_S("\\1"), t, 0);
    char *out = (char *)dk_alloc_noz(a, t.n + 1);
    size_t k = 0;
    int depth = 0;
    for (size_t i = 0; i < t.n; i++) {
        char ch = t.p[i];
        if (ch == '<') depth++;
        else if (ch == '>') depth--;
        else if (ch == ' ' && depth <= 0) continue;
        out[k++] = ch;
    }
    out[k] = 0;
    return dk_strn(out, k);
}

/* The position after a balanced template argument list starting at text[start] == '<', or -1. */
static i64 balanced_template_end(DkStr text, size_t start) {
    int depth = 0;
    for (size_t i = start; i < text.n; i++) {
        if (text.p[i] == '<') depth++;
        else if (text.p[i] == '>' && --depth == 0) return (i64)i + 1;
    }
    return -1;
}

/* The class a class head declares (`template <...> class Name<Args> : ...`, `struct Outer::Inner`), with its
 * template arguments compacted. */
static bool class_name(DkArena *a, DkStr text, DkStr *out) {
    text = dk_str_lstrip(text);
    while (dk_re_match(dk_re("template\\b", 0), text, 0, DK_END, NULL)) {
        DkReMatch pm;
        if (!dk_re_match(dk_re("template\\s*<", 0), text, 0, DK_END, &pm)) {
            text = dk_str_lstrip(dk_str_slice(text, 8, DK_END));
            break;
        }
        i64 end = balanced_template_end(text, (size_t)dk_re_end(&pm, 0) - 1);
        if (end < 0) return false;
        text = dk_str_lstrip(dk_str_slice(text, end, DK_END));
    }
    DkReMatch m;
    if (!dk_re_match(dk_re("(?:class|struct|union)\\s+([A-Za-z_]\\w*)", 0), text, 0, DK_END, &m)) return false;
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_put(&b, dk_re_group(&m, 1));
    DkStr tail = dk_str_lstrip(dk_str_slice(text, dk_re_end(&m, 0), DK_END));
    if (tail.n && tail.p[0] == '<') {
        i64 end = balanced_template_end(tail, 0);
        if (end < 0) return false;
        dk_buf_put(&b, dk_re_sub(a, dk_re("\\s*(::|[<>,*&])\\s*", 0), DK_S("\\1"), dk_str_slice(tail, 0, end), 0));
        tail = dk_str_lstrip(dk_str_slice(tail, end, DK_END));
    }
    while (dk_re_match(dk_re("::\\s*([A-Za-z_]\\w*)", 0), tail, 0, DK_END, &m)) {
        dk_buf_putz(&b, "::");
        dk_buf_put(&b, dk_re_group(&m, 1));
        tail = dk_str_lstrip(dk_str_slice(tail, dk_re_end(&m, 0), DK_END));
    }
    *out = dk_buf_str(&b);
    return true;
}

/* The qualified name a function declaration head declares: the first function name that is not a keyword. */
static bool function_name(DkArena *a, DkStr head, DkStr *out) {
    DkReIter it;
    DkReMatch m;
    dk_re_iter_init(&it, dk_re(FUNC_NAME_PAT, 0), head, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) {
        DkStr cand = compact_name(a, dk_re_group(&m, 1));
        DkStr last = last_component(cand);
        i64 lt = dk_str_findc(last, '<');
        if (lt >= 0) last = dk_strn(last.p, (size_t)lt);
        last = dk_str_lstrip_chars(last, DK_S("~"));
        if (keyword(last)) continue;
        *out = cand;
        return true;
    }
    return false;
}

/* The qualified name a data declaration declares (head: the declaration up to its ";", "=" or "["). */
static bool data_name(DkArena *a, DkStr head, DkStr *out) {
    DkReMatch m;
    if (dk_re_search(dk_re(FUNCTION_POINTER_PAT, 0), head, 0, DK_END, &m)) {
        *out = dk_re_group(&m, 1);
        return true;
    }
    if (dk_re_match(dk_re(DATA_CTOR_NAME_PAT, 0), head, 0, DK_END, &m)) {
        *out = dk_re_group(&m, 1);
        return true;
    }
    DkStr hs = dk_str_concat(a, head, DK_S(";"));
    if (dk_re_search(dk_re(DATA_NAME_PAT, 0), hs, 0, DK_END, &m)) {
        *out = dk_re_sub(a, dk_re("\\s*(::|[<>,*&()])\\s*", 0), DK_S("\\1"), dk_re_group(&m, 1), 0);
        return true;
    }
    return false;
}

/* The declaration rule's plain names: the first identifier followed by "(" (function), the last identifier before the
 * terminator (data). */
static bool first_call_name(DkStr decl, DkStr *out) {
    DkReIter it;
    DkReMatch m;
    dk_re_iter_init(&it, dk_re("([A-Za-z_$][\\w$]*)\\s*\\(", 0), decl, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) {
        DkStr w = dk_re_group(&m, 1);
        if (dk_str_eqz(w, "__declspec") || dk_str_eqz(w, "__attribute__") || dk_str_eqz(w, "throw")) continue;
        *out = w;
        return true;
    }
    return false;
}
static bool last_identifier(DkStr decl, DkStr *out) {
    DkReMatch m;
    if (dk_re_search(dk_re(FUNCTION_POINTER_PAT, 0), decl, 0, DK_END, &m)) {
        *out = dk_re_group(&m, 1);
        return true;
    }
    DkReIter it;
    bool found = false;
    dk_re_iter_init(&it, dk_re("[A-Za-z_$][\\w$]*", 0), decl, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) {
        *out = dk_re_group(&m, 0);
        found = true;
    }
    return found;
}

/* ---- parsing ----------------------------------------------------------------------------------------------------- */

static const char *unit_path(const DkUnit *u) { return u && u->path ? u->path : "<text>"; }

/* The first offset at or after from (before limit) whose byte is in chars, at parenthesis depth 0; -1 when none. */
static i64 find_terminator(const char *clean, size_t from, size_t limit, const char *chars) {
    int depth = 0;
    for (size_t i = from; i < limit; i++) {
        char c = clean[i];
        if (c == '(') depth++;
        else if (c == ')' && depth > 0) depth--;
        else if (depth == 0 && strchr(chars, c)) return (i64)i;
    }
    return -1;
}

/* The "}" closing the "{" at open, before limit; -1 when unbalanced. */
static i64 brace_close(const char *clean, size_t open, size_t limit) {
    int depth = 0;
    for (size_t i = open; i < limit; i++) {
        if (clean[i] == '{') depth++;
        else if (clean[i] == '}' && --depth == 0) return (i64)i;
    }
    return -1;
}

/* The ";" that ends a data definition (brace depth 0) from from, before limit; -1 when none. */
static i64 data_end(const char *clean, size_t from, size_t limit) {
    int depth = 0;
    for (size_t i = from; i < limit; i++) {
        if (clean[i] == '{') depth++;
        else if (clean[i] == '}' && depth > 0) depth--;
        else if (clean[i] == ';' && depth == 0) return (i64)i;
    }
    return -1;
}

static DkStr group_or_empty(const DkReMatch *m, int g) {
    if (g < 0 || !dk_re_matched(m, g)) return dk_strn(NULL, 0);
    return dk_re_group(m, g);
}

static int target_index(const DkAnnotConfig *c, DkStr name) {
    for (int t = 0; t < c->ntargets; t++)
        if (dk_str_eqz(name, c->target_names[t])) return t;
    return -1;
}

/* A stop or pending line: its reason and target mask. */
static bool companion_mark(const DkAnnotConfig *c, const DkRe *re, DkStr text, size_t s, size_t e, DkAnnot *an,
                           u32 *mask, const char **reason, DkArena *a, const DkUnit *u, int line, DkErr *err) {
    DkReMatch m;
    dk_re_assume_valid(text);
    if (!re || !dk_re_search(re, text, (i64)s, (i64)e, &m)) return true;
    int gr = dk_re_group_index(re, "reason");
    if (gr < 0 && dk_re_groups(re) >= 1) gr = 1;
    int gt = dk_re_group_index(re, "target");
    DkStr tname = group_or_empty(&m, gt);
    u32 bits = an->target_mask;
    if (tname.p && dk_str_strip(tname).n) {
        int t = target_index(c, dk_str_strip(tname));
        if (t < 0) {
            fail(err, DK_ERR_FORMAT, "%s:%d: unknown target '%.*s'", unit_path(u), line, DK_SF(tname));
            return false;
        }
        bits = 1u << t;
    }
    *mask |= bits;
    if (!*reason) {
        DkStr r = gr >= 0 ? group_or_empty(&m, gr) : dk_strn(NULL, 0);
        *reason = dk_cz(a, dk_str_strip(r));
    }
    return true;
}

typedef struct {
    i64 start, end;
    DkReMatch m;
} Marker;

DkAnnot *dk_annot_parse(DkArena *a, const DkAnnotConfig *c, const DkUnit *u, DkStr text, size_t *n, DkErr *err) {
    dk_err_clear(err);
    if (n) *n = 0;
    if (!c->re_marker) {
        fail(err, DK_ERR_FORMAT, "annotations: the configuration is not compiled");
        return NULL;
    }
    if (text.n >= 3 && memcmp(text.p, "\xEF\xBB\xBF", 3) == 0) text = dk_str_slice(text, 3, DK_END);
    if (!dk_u8_valid(text)) {
        fail(err, DK_ERR_FORMAT, "%s: not UTF-8", unit_path(u));
        return NULL;
    }
    const char *path = unit_path(u);
    Lines L;
    lines_init(&L, a, text);
    const char *clean = blank_code(a, text);
    const char *flags = (!u || u->flags_line) ? dk_annot_flags_line(a, c, text) : NULL;

    DK_VEC(Marker) markers = {0};
    DkReIter it;
    DkReMatch m;
    dk_re_iter_init(&it, c->re_marker, text, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) {
        Marker mk = {dk_re_start(&m, 0), dk_re_end(&m, 0), m};
        dk_vec_push(&markers, mk);
    }
    DkAnnot *out = DK_NEWN(a, DkAnnot, markers.n ? markers.n : 1);
    bool ok = true;
    for (size_t i = 0; i < markers.n && ok; i++) {
        const Marker *mk = &markers.v[i];
        DkAnnot *an = &out[i];
        memset(an, 0, sizeof *an);
        an->unit = u;
        an->flags = flags;
        size_t start = (size_t)mk->start, mend = (size_t)mk->end;
        size_t limit = i + 1 < markers.n ? (size_t)markers.v[i + 1].start : text.n;
        /* a pattern's leading \s* may start the match on a blank line before the marker: the marker's line is the
         * line of its first visible character */
        size_t first = start;
        while (first + 1 < mend && (text.p[first] == ' ' || text.p[first] == '\t' || text.p[first] == '\n' ||
                                    text.p[first] == '\r' || text.p[first] == '\f' || text.p[first] == '\v'))
            first++;
        an->line = line_of(&L, first);
        int line = an->line;

        /* kind */
        an->kind = DK_ANN_FUNCTION;
        if (c->g_kind >= 0 && c->n_kinds && dk_re_matched(&mk->m, c->g_kind)) {
            DkStr kt = dk_re_group(&mk->m, c->g_kind);
            size_t k = 0;
            while (k < c->n_kinds && !dk_str_eqz(kt, c->kinds[k].text)) k++;
            if (k == c->n_kinds) {
                fail(err, DK_ERR_FORMAT, "%s:%d: unknown annotation kind '%.*s'", path, line, DK_SF(kt));
                ok = false;
                break;
            }
            an->kind = c->kinds[k].kind;
        }

        /* addresses */
        if (c->addr_groups == DK_ADDR_TARGET_ADDR) {
            DkStr tn = group_or_empty(&mk->m, c->g_target), at = group_or_empty(&mk->m, c->g_addr);
            int t = tn.p ? target_index(c, tn) : -1;
            if (t < 0) {
                fail(err, DK_ERR_FORMAT, "%s:%d: unknown target '%.*s'", path, line, DK_SF(tn));
                ok = false;
                break;
            }
            u32 va;
            if (!at.p || !parse_hex(at, &va)) {
                fail(err, DK_ERR_FORMAT, "%s:%d: bad address '%.*s'", path, line, DK_SF(at));
                ok = false;
                break;
            }
            an->addr[t] = va;
            if (va != DK_NO_ADDR) an->target_mask |= 1u << t;
        } else {
            for (int t = 0; t < c->ntargets && ok; t++) {
                if (c->g_addr_target[t] < 0 || !dk_re_matched(&mk->m, c->g_addr_target[t])) continue;
                DkStr at = dk_re_group(&mk->m, c->g_addr_target[t]);
                u32 va;
                if (!parse_hex(at, &va)) {
                    fail(err, DK_ERR_FORMAT, "%s:%d: bad address '%.*s' for target %s", path, line, DK_SF(at),
                         c->target_names[t]);
                    ok = false;
                    break;
                }
                an->addr[t] = va;
                if (va != DK_NO_ADDR) an->target_mask |= 1u << t;
            }
            if (!ok) break;
        }

        /* duplicates: one target and address once (the per-target grammar allows folded copies: several
         * declarations at one address, never the same declaration twice) */
        for (size_t j = 0; j < i && ok; j++) {
            const DkAnnot *o = &out[j];
            u32 common = o->target_mask & an->target_mask;
            for (int t = 0; t < c->ntargets && ok; t++) {
                if (!(common >> t & 1) || o->addr[t] != an->addr[t]) continue;
                if (c->addr_groups == DK_ADDR_PER_TARGET) continue; /* decided below, once the name is known */
                fail(err, DK_ERR_FORMAT, "%s:%d: duplicate address %s 0x%X (line %d)", path, line, c->target_names[t],
                     an->addr[t], o->line);
                ok = false;
            }
        }
        if (!ok) break;

        /* companion lines: the // lines right after the marker */
        size_t last = mend > start ? mend - 1 : start;
        while (last > start && (text.p[last] == '\n' || text.p[last] == '\r' || text.p[last] == ' ' || text.p[last] == '\t'))
            last--;
        int cl = line_of(&L, last) + 1;
        int first_comp = cl;
        while (cl <= nlines(&L) && line_start(&L, cl) < limit) {
            DkStr ln = dk_str_lstrip(dk_strn(text.p + line_start(&L, cl), line_end(&L, cl) - line_start(&L, cl)));
            if (!dk_str_startswith(ln, DK_S("//"))) break;
            cl++;
        }
        size_t comp_end = cl <= nlines(&L) ? line_start(&L, cl) : text.n;
        if (comp_end > limit) comp_end = limit;
        for (int k = first_comp; k < cl && ok; k++) {
            size_t s = line_start(&L, k), e = line_end(&L, k);
            if (e > s && text.p[e - 1] == '\r') e--;
            ok = companion_mark(c, c->re_stop, text, s, e, an, &an->stop_mask, &an->stop_reason, a, u, k, err) &&
                 companion_mark(c, c->re_pending, text, s, e, an, &an->pending_mask, &an->pending, a, u, k, err);
        }
        if (!ok) break;

        /* the declaration */
        size_t ds = comp_end;
        while (ds < limit && (clean[ds] == ' ' || clean[ds] == '\t' || clean[ds] == '\n' || clean[ds] == '\r' ||
                              clean[ds] == '\f' || clean[ds] == '\v'))
            ds++;
        bool has_decl = ds < limit;
        DkStr name = {0};
        size_t decl_stop = ds; /* where the symbol line search ends: the "{" or ";" */
        if (c->name == DK_NAME_DECLARATION && an->kind == DK_ANN_FUNCTION) {
            const char *open = memchr(clean + mend, '{', limit > mend ? limit - mend : 0);
            if (!open) {
                fail(err, DK_ERR_FORMAT, "%s:%d: function annotation has no body", path, line);
                ok = false;
                break;
            }
            size_t o = (size_t)(open - clean);
            i64 close = brace_close(clean, o, limit);
            if (close < 0) {
                fail(err, DK_ERR_FORMAT, "%s:%d: unbalanced function body", path, line);
                ok = false;
                break;
            }
            DkStr decl = dk_strn(clean + mend, o - mend);
            first_call_name(decl, &name);
            size_t lead = decl.n - dk_str_lstrip(decl).n;
            an->body_start = line_of(&L, mend + lead);
            an->body_end = line_of(&L, (size_t)close);
            an->decl = dk_cz(a, collapse(a, decl));
            decl_stop = o;
        } else if (has_decl) {
            an->body_start = line_of(&L, ds);
            if (an->kind == DK_ANN_DATA) {
                i64 cut = find_terminator(clean, ds, limit, c->name == DK_NAME_DECLARATION ? "=;[{" : "=;[");
                size_t hend = cut < 0 ? limit : (size_t)cut;
                DkStr head = dk_strn(clean + ds, hend - ds);
                if (c->name == DK_NAME_DECLARATION) last_identifier(head, &name);
                else data_name(a, head, &name);
                i64 dt = find_terminator(clean, ds, limit, "{;");
                an->decl = dk_cz(a, collapse(a, dk_strn(clean + ds, (dt < 0 ? limit : (size_t)dt) - ds)));
                i64 se = data_end(clean, ds, limit);
                an->body_end = line_of(&L, se < 0 ? hend : (size_t)se);
                decl_stop = dt < 0 ? limit : (size_t)dt;
            } else {
                i64 t = find_terminator(clean, ds, limit, "{;");
                if (t < 0 && an->kind == DK_ANN_FUNCTION) {
                    fail(err, DK_ERR_FORMAT, "%s:%d: function annotation has no body or ';'", path, line);
                    ok = false;
                    break;
                }
                size_t te = t < 0 ? limit : (size_t)t;
                DkStr head = dk_strn(clean + ds, te - ds);
                an->decl = dk_cz(a, collapse(a, head));
                decl_stop = te;
                if (an->kind == DK_ANN_VTABLE) {
                    if (!class_name(a, head, &name)) last_identifier(head, &name);
                } else if (c->name == DK_NAME_DECLARATION) {
                    first_call_name(head, &name);
                } else if (!function_name(a, head, &name) && an->kind == DK_ANN_DECL) {
                    data_name(a, head, &name);
                }
                if (t >= 0 && clean[t] == '{') {
                    i64 close = brace_close(clean, te, limit);
                    if (close < 0 && an->kind == DK_ANN_FUNCTION) {
                        fail(err, DK_ERR_FORMAT, "%s:%d: unbalanced function body", path, line);
                        ok = false;
                        break;
                    }
                    an->body_end = line_of(&L, close < 0 ? limit : (size_t)close);
                } else {
                    an->body_end = line_of(&L, te);
                }
            }
        } else if (an->kind == DK_ANN_FUNCTION) {
            fail(err, DK_ERR_FORMAT, "%s:%d: function annotation has no declaration", path, line);
            ok = false;
            break;
        }
        an->name = name.n ? dk_cz(a, name) : NULL;

        /* the explicit symbol line, between the marker and the declaration's "{" or ";" */
        if (c->re_symbol) {
            DkReMatch sm;
            dk_re_assume_valid(text);
            if (dk_re_search(c->re_symbol, text, (i64)mend, (i64)(decl_stop > mend ? decl_stop : mend), &sm)) {
                int g = dk_re_group_index(c->re_symbol, "symbol");
                if (g < 0) g = dk_re_groups(c->re_symbol) >= 1 ? 1 : 0;
                DkStr s = dk_str_strip(group_or_empty(&sm, g));
                if (s.n) an->symbol = dk_cz(a, s);
            }
        }
        if (an->kind == DK_ANN_FUNCTION && !an->name && !an->symbol) {
            fail(err, DK_ERR_FORMAT, "%s:%d: function annotation without a name", path, line);
            ok = false;
            break;
        }
        if (c->addr_groups == DK_ADDR_PER_TARGET) {
            for (size_t j = 0; j < i && ok; j++) {
                const DkAnnot *o = &out[j];
                u32 common = o->target_mask & an->target_mask;
                for (int t = 0; t < c->ntargets && ok; t++) {
                    if (!(common >> t & 1) || o->addr[t] != an->addr[t]) continue;
                    bool same = o->kind == an->kind && dk_str_eqz(dk_str(o->name), an->name ? an->name : "") &&
                                dk_str_eqz(dk_str(o->decl), an->decl ? an->decl : "");
                    if (!same) continue;
                    fail(err, DK_ERR_FORMAT, "%s:%d: duplicate address %s 0x%X (line %d)", path, line,
                         c->target_names[t], an->addr[t], o->line);
                    ok = false;
                }
            }
        }
    }
    size_t count = markers.n;
    dk_vec_free(&markers);
    if (!ok) return NULL;
    if (n) *n = count;
    return out;
}

const char *dk_annot_flags_line(DkArena *a, const DkAnnotConfig *c, DkStr text) {
    if (!c->re_flags) return NULL;
    if (text.n >= 3 && memcmp(text.p, "\xEF\xBB\xBF", 3) == 0) text = dk_str_slice(text, 3, DK_END);
    int nl = c->flags_lines > 0 ? c->flags_lines : 8;
    size_t end = 0;
    int seen = 0;
    while (end < text.n && seen < nl) {
        if (text.p[end] == '\n') seen++;
        end++;
    }
    if (seen == nl && end > 0) end--; /* the last line's newline is not searched */
    DkReMatch m;
    if (!dk_u8_valid(text) || !dk_re_search(c->re_flags, text, 0, (i64)end, &m)) return NULL;
    int g = dk_re_group_index(c->re_flags, "flags");
    if (g < 0) g = dk_re_groups(c->re_flags) >= 1 ? 1 : 0;
    DkStr f = dk_str_strip(group_or_empty(&m, g));
    return f.n ? dk_cz(a, f) : NULL;
}

DkAnnot *dk_annotations(DkProject *p, const DkUnit *u, size_t *n, DkErr *err) {
    DkArena *a = dk_project_arena(p);
    if (n) *n = 0;
    char *path = dk_project_path(a, p, u->path);
    DkStr text;
    if (!dk_read_text(a, path, DK_TM_UTF8_SIG, &text)) {
        fail(err, DK_ERR_IO, "%s: cannot read the unit", path);
        return NULL;
    }
    const DkAnnotConfig *c = dk_project_annot_config(p);
    if (!c) {
        fail(err, DK_ERR_FORMAT, "annotations: not configured");
        return NULL;
    }
    return dk_annot_parse(a, c, u, text, n, err);
}

static bool name_is(const char *annotated, const char *name) {
    if (!annotated || !name) return false;
    if (strcmp(annotated, name) == 0) return true;
    DkStr last = last_component(dk_str(annotated));
    return last.n != strlen(annotated) && dk_str_eqz(last, name);
}

const DkAnnot *dk_find_annotation(DkProject *p, const DkUnit *u, const char *name, u32 addr) {
    size_t n;
    DkAnnot *v = dk_annotations(p, u, &n, NULL);
    if (!v) return NULL;
    for (size_t i = 0; i < n; i++) {
        if (name && !name_is(v[i].name, name)) continue;
        if (addr == DK_NO_ADDR) return &v[i];
        for (int t = 0; t < DK_MAX_TARGETS; t++)
            if ((v[i].target_mask >> t & 1) && v[i].addr[t] == addr) return &v[i];
    }
    return NULL;
}

bool dk_stopped(const DkAnnot *a, int target) {
    return a && target >= 0 && target < DK_MAX_TARGETS && (a->stop_mask >> target & 1);
}

/* ---- symbol matching --------------------------------------------------------------------------------------------- */

/* Whether the character that ends at byte b is whitespace, "*" or "&" (or also "(" with paren): the boundary before a
 * name. */
static bool prev_is_boundary(DkStr s, size_t b, bool paren) {
    unsigned char c = (unsigned char)s.p[b - 1];
    if (c < 0x80) return c == '*' || c == '&' || (paren && c == '(') || dk_cp_isspace(c);
    size_t j = b - 1;
    while (j > 0 && ((unsigned char)s.p[j] & 0xC0) == 0x80) j--;
    const char *q = s.p + j;
    return dk_cp_isspace(dk_u8_next(&q, s.p + b));
}

/* The leftmost match of `(?:^|[\s*&])(?:[A-Za-z_]\w*::)*(name)(TEMPLATE_ARGS)?\s*\(` in plain: q is where the name
 * starts, has_args whether template arguments follow it. The name is a literal: the starts are tried in order, each
 * with its qualifier chain longest first. */
static bool find_function_name(DkStr plain, DkStr name, size_t *q_out, bool *has_args) {
    if (!contains(plain, name)) return false;
    const DkRe *chain_re = dk_re("[A-Za-z_]\\w*::", 0);
    const DkRe *post = dk_re("(" TEMPLATE_ARGS ")?\\s*\\(", 0);
    DK_VEC(size_t) chain = {0};
    bool found = false;
    for (size_t b = 0; b <= plain.n && !found; b++) {
        if (b > 0 && (b == plain.n || ((unsigned char)plain.p[b] & 0xC0) == 0x80)) continue;
        if (b > 0 && !prev_is_boundary(plain, b, false)) continue;
        chain.n = 0;
        dk_vec_push(&chain, b);
        size_t cur = b;
        DkReMatch cm;
        while (dk_re_match(chain_re, plain, (i64)cur, DK_END, &cm)) {
            cur = (size_t)dk_re_end(&cm, 0);
            dk_vec_push(&chain, cur);
        }
        for (size_t j = chain.n; j-- > 0 && !found;) {
            size_t q = chain.v[j];
            if (!starts_at(plain, q, name)) continue;
            DkReMatch pm;
            if (dk_re_match(post, plain, (i64)(q + name.n), DK_END, &pm)) {
                *q_out = q;
                *has_args = dk_re_matched(&pm, 1);
                found = true;
            }
        }
    }
    dk_vec_free(&chain);
    return found;
}

/* A global's name in an undecorated name: after whitespace, "*", "&" or "(", followed by array bounds and the end or
 * a ")". */
static bool find_data_name(DkStr plain, DkStr name) {
    i64 at = 0;
    for (;;) {
        at = dk_str_find(plain, name, at, DK_END);
        if (at < 0) return false;
        size_t q = (size_t)at;
        at++;
        if (q > 0 && !prev_is_boundary(plain, q, true)) continue;
        size_t p = q + name.n;
        for (;;) {
            if (p >= plain.n || plain.p[p] != '[') break;
            size_t k = p + 1;
            while (k < plain.n && plain.p[k] >= '0' && plain.p[k] <= '9') k++;
            if (k >= plain.n || plain.p[k] != ']') break;
            p = k + 1;
        }
        while (p < plain.n) {
            const char *c = plain.p + p;
            u32 cp = dk_u8_next(&c, plain.p + plain.n);
            if (!dk_cp_isspace(cp)) break;
            p = (size_t)(c - plain.p);
        }
        if (p >= plain.n || plain.p[p] == ')') return true;
    }
}

/* A function-local static's decorated name: `?name@?` then a digit, or A-P letters and "@", then `??`. */
static bool local_static_scope(DkStr sym, DkStr name) {
    if (sym.n < 1 + name.n + 4 || sym.p[0] != '?' || !starts_at(sym, 1, name)) return false;
    size_t p = 1 + name.n;
    if (sym.p[p] != '@' || sym.p[p + 1] != '?') return false;
    p += 2;
    if (p < sym.n && sym.p[p] >= '0' && sym.p[p] <= '9') {
        p++;
    } else {
        size_t k = p;
        while (k < sym.n && sym.p[k] >= 'A' && sym.p[k] <= 'P') k++;
        if (k == p || k >= sym.n || sym.p[k] != '@') return false;
        p = k + 1;
    }
    return p + 1 < sym.n && sym.p[p] == '?' && sym.p[p + 1] == '?';
}

/* The rest of a C symbol after the name: nothing, or "@" and digits (the argument size). */
static bool c_tail_ok(DkStr rest, DkStr name, bool need_at) {
    if (!starts_at(rest, 0, name)) return false;
    DkStr t = dk_str_slice(rest, (i64)name.n, DK_END);
    if (need_at) {
        if (!t.n || t.p[0] != '@') return false;
    } else if (!t.n) {
        return true;
    } else if (t.p[0] != '@') {
        return false;
    }
    DkStr digits = dk_str_slice(t, 1, DK_END);
    if (!digits.n) return false;
    for (size_t i = 0; i < digits.n; i++)
        if (digits.p[i] < '0' || digits.p[i] > '9') return false;
    return true;
}

/* _name, name, _name@N, name@N or @name@N. */
static bool c_symbol_matches(DkStr sym, DkStr name) {
    if (sym.n && sym.p[0] == '_' && c_tail_ok(dk_str_slice(sym, 1, DK_END), name, false)) return true;
    if (c_tail_ok(sym, name, false)) return true;
    return sym.n && sym.p[0] == '@' && c_tail_ok(dk_str_slice(sym, 1, DK_END), name, true);
}

/* The text between the parentheses that follow the start of text; false when there is no "(" or it is never closed. */
static bool balanced_inner(DkStr text, DkStr *inner) {
    i64 at = dk_str_findc(text, '(');
    if (at < 0) return false;
    int depth = 0;
    for (size_t i = (size_t)at; i < text.n; i++) {
        char ch = text.p[i];
        if (ch == '(') {
            depth++;
        } else if (ch == ')' && --depth == 0) {
            *inner = dk_strn(text.p + at + 1, i - (size_t)at - 1);
            return true;
        }
    }
    return false;
}

static int param_count(DkStr text) {
    DkStr inner;
    if (!balanced_inner(text, &inner)) return -1;
    DkStr body = dk_str_strip(inner);
    if (body.n == 0 || dk_str_eqz(body, "void")) return 0;
    int depth = 0, count = 1;
    for (size_t i = 0; i < body.n; i++) {
        char ch = body.p[i];
        if (ch == '(' || ch == '<' || ch == '[') depth++;
        else if (ch == ')' || ch == '>' || ch == ']') depth--;
        else if (ch == ',' && depth == 0) count++;
    }
    return count;
}

static const char *const TYPE_WORDS[] = {"unsigned", "signed", "int", "char", "short", "long", "float", "double",
                                         "bool", "void", "wchar_t", "__int64", "__int32", "__int16", "__int8"};
static const char *const DROP_WORDS[] = {"const", "volatile", "struct", "class", "union", "enum", "__cdecl",
                                         "__stdcall", "__thiscall", "__fastcall", "__ptr64", "__w64", "*", "&"};
static bool in_list(const char *const *list, size_t n, DkStr w) {
    for (size_t i = 0; i < n; i++)
        if (dk_str_eqz(w, list[i])) return true;
    return false;
}
static bool is_type_word(DkStr w) { return in_list(TYPE_WORDS, DK_ARRAY_LEN(TYPE_WORDS), w); }

/* The base type of each parameter of a parameter list: qualifiers, "*" and "&", default arguments and (from_source)
 * the parameter's name dropped. false when a parameter is a function pointer or an array, or has no type. */
static bool base_types(DkArena *a, DkStr param_list, bool from_source, DkStrVec *out) {
    DkStr body = dk_str_strip(param_list);
    if (body.n == 0 || dk_str_eqz(body, "void")) return true;
    DkStrVec params = {0};
    int depth = 0;
    size_t from = 0;
    for (size_t i = 0; i < body.n; i++) {
        char ch = body.p[i];
        if (ch == '(' || ch == '<' || ch == '[') depth++;
        else if (ch == ')' || ch == '>' || ch == ']') depth--;
        if (ch == ',' && depth == 0) {
            dk_vec_push(&params, dk_strn(body.p + from, i - from));
            from = i + 1;
        }
    }
    dk_vec_push(&params, dk_strn(body.p + from, body.n - from));
    bool ok = true;
    for (size_t k = 0; k < params.n && ok; k++) {
        DkStr p = params.v[k];
        if (has_byte(p, '(') || has_byte(p, '[')) {
            ok = false;
            break;
        }
        p = dk_re_sub(a, dk_re("=[^,]*$", 0), DK_S(""), p, 0);
        p = dk_re_sub(a, dk_re("([*&])", 0), DK_S(" \\1 "), p, 0);
        DkStrVec toks = dk_str_split(p, DK_S(""), -1);
        DkStrVec kept = {0};
        for (size_t t = 0; t < toks.n; t++)
            if (!in_list(DROP_WORDS, DK_ARRAY_LEN(DROP_WORDS), toks.v[t])) dk_vec_push(&kept, toks.v[t]);
        dk_vec_free(&toks);
        if (from_source && kept.n >= 2 && !is_type_word(kept.v[kept.n - 1])) kept.n--;
        if (kept.n == 0) ok = false;
        else dk_vec_push(out, dk_str_join(a, DK_S(" "), kept.v, kept.n));
        dk_vec_free(&kept);
    }
    dk_vec_free(&params);
    return ok;
}

static bool strvec_eq(const DkStrVec *x, const DkStrVec *y) {
    if (x->n != y->n) return false;
    for (size_t i = 0; i < x->n; i++)
        if (!dk_str_eq(x->v[i], y->v[i])) return false;
    return true;
}

static bool is_class(DkStr t) { return dk_re_match(dk_re(CLASS_NAME_PAT, 0), t, 0, DK_END, NULL); }
static bool is_class_template(DkStr t) { return dk_re_match(dk_re(CLASS_TEMPLATE_PAT, 0), t, 0, DK_END, NULL); }
static bool all_builtin(DkStr t) {
    DkStrVec w = dk_str_split(t, DK_S(""), -1);
    bool all = true;
    for (size_t i = 0; i < w.n && all; i++) all = is_type_word(w.v[i]);
    dk_vec_free(&w);
    return all;
}

/* The words of a type, without its trailing qualifiers and the class/struct/union/enum keywords, sorted. */
static DkStrVec type_words(DkArena *a, DkStr t) {
    t = dk_re_sub(a, dk_re("(?:\\s*\\b(?:const|volatile))+$", 0), DK_S(""), t, 0);
    DkStrVec out = {0};
    DkReIter it;
    DkReMatch m;
    dk_re_iter_init(&it, dk_re("\\w+", 0), t, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) {
        DkStr w = dk_re_group(&m, 0);
        if (dk_str_eqz(w, "class") || dk_str_eqz(w, "struct") || dk_str_eqz(w, "union") || dk_str_eqz(w, "enum"))
            continue;
        dk_vec_push(&out, w);
    }
    dk_sort_strs(out.v, out.n);
    return out;
}

/* false when one pair of parameter types (the annotation's, the symbol's) names different overloads. */
static bool param_types_agree(DkArena *a, DkStr signature, DkStr plain, size_t q, bool has_args) {
    DkStrVec want = {0}, have = {0};
    DkStr have_list;
    bool ok = base_types(a, signature, true, &want) && balanced_inner(dk_str_slice(plain, (i64)q, DK_END), &have_list) &&
              base_types(a, have_list, false, &have);
    bool agree = true;
    if (ok) {
        size_t n = DK_MIN(want.n, have.n);
        for (size_t i = 0; i < n && agree; i++) {
            DkStr wt = want.v[i], ht = have.v[i];
            bool wb = all_builtin(wt), hb = all_builtin(ht);
            bool wc = is_class(wt), hc = is_class(ht);
            bool wtt = is_class_template(wt), htt = is_class_template(ht);
            bool differs = !dk_str_eq(wt, ht);
            /* two different types, each built-in or a class name, are different overloads (a typedef such as an
             * all-capitals or lower-case alias undecorates to its underlying type and is not compared) */
            if (differs && (wb || wc) && (hb || hc)) agree = false;
            /* a built-in type against a class template's instance, or a symbol's class against an annotated instance */
            else if (differs && ((wb && htt) || ((hb || hc) && wtt))) agree = false;
            else if (differs && hc && wtt) agree = false;
            /* two class templates' instances whose words differ (a member type of a template is not compared) */
            else if (differs && wtt && htt && !contains(wt, DK_S(">::")) && !contains(ht, DK_S(">::"))) {
                DkStrVec ww = type_words(a, wt), hw = type_words(a, ht);
                if (!strvec_eq(&ww, &hw)) agree = false;
                dk_vec_free(&ww);
                dk_vec_free(&hw);
            }
            /* a function template's instance taking a class template's instance where the source names a class */
            if (agree && differs && has_args && wc && htt) agree = false;
        }
    }
    dk_vec_free(&want);
    dk_vec_free(&have);
    return agree;
}

static void const_after_cb(void *ctx, const DkReMatch *m, DkBuf *out) {
    DkArena *a = (DkArena *)ctx;
    dk_buf_put(out, dk_re_sub(a, dk_re("([<,]\\s*)const ((?:(?:unsigned|signed|short|long) )*\\w+)", 0),
                              DK_S("\\1\\2 const"), dk_re_group(m, 0), 0));
}
/* A template argument's leading "const" written after its type, as undecorated names have it. */
static DkStr const_after(DkArena *a, DkStr text) {
    if (!contains(text, DK_S("const"))) return text;
    return dk_re_sub_fn(a, dk_re("<[^()]*>", 0), const_after_cb, a, text, 0, NULL);
}
/* An annotated templated name as undecorated names spell it. */
static DkStr template_name(DkArena *a, DkStr name) { return const_after(a, compact_name(a, name)); }
/* An undecorated name without class/struct/union/enum and the blanks around punctuation. */
static DkStr template_plain(DkArena *a, DkStr plain) {
    DkStr out = dk_re_sub(a, dk_re("\\b(?:class|struct|union|enum)\\s+", 0), DK_S(""), plain, 0);
    out = dk_re_sub(a, dk_re("\\s*(::|[<>,*&()])\\s*", 0), DK_S("\\1"), out, 0);
    return const_after(a, out);
}

/* The parameter list of the annotated declaration: the parentheses after the name's last component in decl. */
static bool decl_param_text(DkStr decl, DkStr name, DkStr *from_name) {
    if (!decl.p || !decl.n) return false;
    DkStr last = last_component(name);
    i64 lt = dk_str_findc(last, '<');
    if (lt > 0) last = dk_strn(last.p, (size_t)lt);
    DkStr word = last;
    if (dk_str_startswith(last, DK_S("operator"))) word = DK_S("operator");
    else word = dk_str_lstrip_chars(last, DK_S("~"));
    if (!word.n) return false;
    i64 at = 0;
    for (;;) {
        at = dk_str_find(decl, word, at, DK_END);
        if (at < 0) return false;
        size_t q = (size_t)at, e = q + word.n;
        at++;
        if (q > 0 && is_word_char(decl.p[q - 1])) continue;
        if (e < decl.n && is_word_char(decl.p[e])) continue;
        if (word.n == 8 && dk_str_eqz(word, "operator")) {
            /* the operator's symbol, then the parameters */
            while (e < decl.n && decl.p[e] == ' ') e++;
            if (e + 1 < decl.n && decl.p[e] == '(' && decl.p[e + 1] == ')') e += 2;
            else
                while (e < decl.n && decl.p[e] != '(' && decl.p[e] != ' ') e++;
        } else {
            while (e < decl.n && decl.p[e] == ' ') e++;
            if (e < decl.n && decl.p[e] == '<') {
                i64 te = balanced_template_end(decl, e);
                if (te < 0) continue;
                e = (size_t)te;
                while (e < decl.n && decl.p[e] == ' ') e++;
            }
            if (e >= decl.n || decl.p[e] != '(') continue;
        }
        *from_name = dk_str_slice(decl, (i64)e, DK_END);
        return true;
    }
}

static bool symbol_matches(DkArena *a, const DkAnnot *an, DkStr sym, DkStr plain) {
    DkStr name = dk_str(an->name);
    if (has_byte(name, '<')) {
        name = template_name(a, name);
        plain = template_plain(a, plain);
    }
    if (an->kind == DK_ANN_VTABLE) {
        DkBuf nb;
        dk_buf_init(&nb, a);
        dk_buf_putz(&nb, "const ");
        dk_buf_put(&nb, name);
        dk_buf_putz(&nb, "::`vftable'");
        DkStr needle = dk_buf_str(&nb);
        i64 at = dk_str_find(plain, needle, 0, DK_END);
        if (at < 0) return false;
        /* a class with several bases has one table per base, `{for `Base'}`: only the main one is the class's */
        DkStr rest = dk_str_slice(plain, at + (i64)needle.n, DK_END);
        return !starts_at(rest, 0, DK_S("{for `"));
    }
    if (sym.n && sym.p[0] == '?') {
        /* a data annotation of a function-local static names it by its local name */
        if (an->kind == DK_ANN_DATA && dk_re_fullmatch(dk_re("\\w+", 0), name, 0, DK_END, NULL) &&
            local_static_scope(sym, name))
            return true;
        /* a function's local static or its guard is not the function */
        if (dk_re_search(dk_re("'::`\\d+'::", 0), plain, 0, DK_END, NULL)) return false;
        size_t q;
        bool has_args;
        if (find_function_name(plain, name, &q, &has_args)) {
            if (an->kind == DK_ANN_DATA) return false;
            if (!contains(name, DK_S("::"))) {
                DkStr before = dk_strn(plain.p, q);
                if (dk_re_search(dk_re("[A-Za-z_]\\w*::$", 0), before, 0, DK_END, NULL)) return false;
            }
            DkStr from_name;
            if (decl_param_text(dk_str(an->decl), dk_str(an->name), &from_name)) {
                int want = param_count(from_name);
                int have = param_count(dk_str_slice(plain, (i64)q, DK_END));
                if (want >= 0 && have >= 0 && have != want) return false;
                DkStr signature;
                if (balanced_inner(from_name, &signature) && !param_types_agree(a, signature, plain, q, has_args))
                    return false;
            }
            return true;
        }
        return find_data_name(plain, name) && (an->kind == DK_ANN_DATA || an->kind == DK_ANN_DECL);
    }
    return c_symbol_matches(sym, name);
}

bool dk_symbol_matches(const DkAnnot *an, const char *decorated) {
    if (!an || !an->name || !an->name[0] || !decorated || !decorated[0]) return false;
    DkStr sym = dk_str(decorated);
    DkStr plain = sym;
    if (decorated[0] == '?') {
        plain = dk_str(dk_pdb_undecorate(decorated, 0));
        if (!plain.n) return false;
    }
    DkArena *a = dk_scratch();
    DkArenaMark mark = dk_arena_mark(a);
    DkStr name = dk_str(an->name);
    bool verdict;
    /* every way of answering yes finds the (rewritten) name in the (rewritten) undecorated or the decorated name */
    if (has_byte(name, '<')) {
        DkStr wanted = template_name(a, name);
        verdict = contains(template_plain(a, plain), wanted) || contains(sym, wanted);
    } else {
        verdict = contains(plain, name) || contains(sym, name);
    }
    if (verdict) verdict = symbol_matches(a, an, sym, plain);
    dk_arena_reset(a, mark);
    return verdict;
}

/* ---- binding ----------------------------------------------------------------------------------------------------- */

/* _name, _name@<digits> or ?name@... */
static bool declaration_spelling(const char *sym, DkStr name) {
    DkStr s = dk_str(sym);
    if (s.n > name.n + 1 && s.p[0] == '?' && starts_at(s, 1, name) && s.p[1 + name.n] == '@') return true;
    if (!s.n || s.p[0] != '_' || !starts_at(s, 1, name)) return false;
    DkStr t = dk_str_slice(s, (i64)(1 + name.n), DK_END);
    if (!t.n) return true;
    if (t.p[0] != '@' || t.n < 2) return false;
    for (size_t i = 1; i < t.n; i++)
        if (t.p[i] < '0' || t.p[i] > '9') return false;
    return true;
}

const char *dk_annot_bind(const DkAnnot *an, DkNameRule rule, const char *const *symbols, size_t n, DkErr *err) {
    dk_err_clear(err);
    const char *path = unit_path(an->unit);
    if (an->symbol) {
        for (size_t i = 0; i < n; i++)
            if (symbols[i] && strcmp(symbols[i], an->symbol) == 0) return symbols[i];
        fail(err, DK_ERR_OTHER, "%s:%d: the explicit symbol %s is not defined by the unit", path, an->line, an->symbol);
        return NULL;
    }
    if (!an->name) {
        fail(err, DK_ERR_OTHER, "%s:%d: the annotation has no name to bind; add a symbol line", path, an->line);
        return NULL;
    }
    const char *found = NULL;
    size_t count = 0;
    DkStr name = dk_str(an->name);
    for (size_t i = 0; i < n; i++) {
        if (!symbols[i]) continue;
        bool hit = rule == DK_NAME_DECLARATION ? declaration_spelling(symbols[i], name) : dk_symbol_matches(an, symbols[i]);
        if (hit) {
            if (!count) found = symbols[i];
            count++;
        }
    }
    if (count == 1) return found;
    fail(err, DK_ERR_OTHER, "%s:%d: cannot bind %s to a unique symbol (%zu candidates); add a symbol line", path,
         an->line, an->name, count);
    return NULL;
}
