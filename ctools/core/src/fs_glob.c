// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* fnmatch and glob of CPython 3.14. fnmatch compiles the shell pattern the way fnmatch.translate does (including the
 * range merging of 3.14 and the set-operator escaping) into tokens and matches them directly instead of through a
 * regular expression; glob follows glob.py function by function, so the order of the results is the same. */
#include "fs_priv.h"

/* ---- fnmatch ---------------------------------------------------------------------------------------------------- */

enum { T_STAR, T_ANY, T_CHAR, T_SET, T_NEVER };

typedef struct {
    u32 lo, hi;
} Range;

typedef struct {
    int kind;
    u32 c;            /* T_CHAR */
    bool neg;         /* T_SET */
    Range *ranges;    /* T_SET */
    size_t nranges;
} Token;

typedef struct {
    Token *t;
    size_t n;
    DkArena *a;
} Pattern;

static u32 *to_cps(DkArena *a, const char *s, size_t *n) {
    size_t len = strlen(s);
    u32 *out = (u32 *)dk_alloc_noz(a, (len + 1) * sizeof(u32));
    const char *p = s, *end = s + len;
    size_t k = 0;
    while (p < end) out[k++] = dk_fs_u8_next(&p, end);
    *n = k;
    return out;
}

static void add_tok(Pattern *pt, Token t) {
    pt->t[pt->n++] = t;
}

/* Parses the body of a regex character class as sre_parse does for the strings fnmatch builds: backslash escapes
 * one character, "x-y" is a range unless the '-' is last. */
static void parse_class(Pattern *pt, Token *tok, const u32 *s, size_t n) {
    Range *r = (Range *)dk_alloc(pt->a, (n + 1) * sizeof(Range));
    size_t nr = 0, i = 0;
    while (i < n) {
        u32 c = s[i++];
        if (c == '\\' && i < n) c = s[i++];
        if (i + 1 < n && s[i] == '-') {
            u32 hi = s[i + 1];
            size_t adv = 2;
            if (hi == '\\' && i + 2 < n) {
                hi = s[i + 2];
                adv = 3;
            }
            i += adv;
            if (hi >= c) {
                r[nr].lo = c;
                r[nr].hi = hi;
                nr++;
            }
            continue;
        }
        r[nr].lo = r[nr].hi = c;
        nr++;
    }
    tok->ranges = r;
    tok->nranges = nr;
}

/* The code points of the characters that are escaped in a class: backslash, hyphen (chunk interiors) and the set
 * operators & ~ |. out receives the escaped sequence. */
static void push_cp(u32 **out, size_t *n, u32 c) { (*out)[(*n)++] = c; }

static Pattern compile(DkArena *a, const char *pat) {
    size_t n;
    u32 *P = to_cps(a, pat, &n);
    Pattern pt = {(Token *)dk_alloc(a, (n + 1) * sizeof(Token)), 0, a};
    size_t i = 0;
    while (i < n) {
        u32 c = P[i++];
        if (c == '*') {
            Token t = {T_STAR};
            add_tok(&pt, t);
            while (i < n && P[i] == '*') i++;
        } else if (c == '?') {
            Token t = {T_ANY};
            add_tok(&pt, t);
        } else if (c == '[') {
            size_t j = i;
            if (j < n && P[j] == '!') j++;
            if (j < n && P[j] == ']') j++;
            while (j < n && P[j] != ']') j++;
            if (j >= n) {
                Token t = {T_CHAR, '['};
                add_tok(&pt, t);
                continue;
            }
            /* stuff = pat[i:j], rebuilt as fnmatch does */
            u32 *stuff = (u32 *)dk_alloc_noz(a, (4 * (j - i) + 8) * sizeof(u32));
            size_t sn = 0;
            bool has_hyphen = false;
            for (size_t q = i; q < j; q++)
                if (P[q] == '-') has_hyphen = true;
            if (!has_hyphen) {
                for (size_t q = i; q < j; q++) {
                    if (P[q] == '\\') push_cp(&stuff, &sn, '\\');
                    push_cp(&stuff, &sn, P[q]);
                }
            } else {
                /* chunks = pieces between hyphens (the hyphen at the start of the set is part of the first chunk) */
                size_t nchunks = 0;
                size_t *cs = (size_t *)dk_alloc(a, (j - i + 2) * sizeof(size_t) * 2);
                size_t *ce = cs + (j - i + 2);
                size_t ii = i;
                size_t k = (P[ii] == '!') ? ii + 2 : ii + 1;
                for (;;) {
                    size_t f = (size_t)-1;
                    for (size_t q = k; q < j; q++)
                        if (P[q] == '-') {
                            f = q;
                            break;
                        }
                    if (f == (size_t)-1) break;
                    cs[nchunks] = ii;
                    ce[nchunks] = f;
                    nchunks++;
                    ii = f + 1;
                    k = f + 3;
                }
                /* the last chunk: pat[ii:j], or the previous chunk plus a literal hyphen when empty */
                u32 **chunk = (u32 **)dk_alloc(a, (nchunks + 2) * sizeof(u32 *));
                size_t *cl = (size_t *)dk_alloc(a, (nchunks + 2) * sizeof(size_t));
                size_t m = 0;
                for (size_t q = 0; q < nchunks; q++) {
                    cl[m] = ce[q] - cs[q];
                    chunk[m] = (u32 *)dk_alloc_noz(a, (cl[m] + 2) * sizeof(u32));
                    memcpy(chunk[m], P + cs[q], cl[m] * sizeof(u32));
                    m++;
                }
                if (ii < j) {
                    cl[m] = j - ii;
                    chunk[m] = (u32 *)dk_alloc_noz(a, (cl[m] + 2) * sizeof(u32));
                    memcpy(chunk[m], P + ii, cl[m] * sizeof(u32));
                    m++;
                } else if (m) {
                    /* chunks[-1] += '-' */
                    u32 *nc = (u32 *)dk_alloc_noz(a, (cl[m - 1] + 2) * sizeof(u32));
                    memcpy(nc, chunk[m - 1], cl[m - 1] * sizeof(u32));
                    nc[cl[m - 1]++] = '-';
                    chunk[m - 1] = nc;
                }
                /* remove empty ranges: for k in range(len-1, 0, -1) */
                for (size_t q = m; q-- > 1;) {
                    if (cl[q - 1] && cl[q] && chunk[q - 1][cl[q - 1] - 1] > chunk[q][0]) {
                        cl[q - 1] -= 1;
                        memcpy(chunk[q - 1] + cl[q - 1], chunk[q] + 1, (cl[q] - 1) * sizeof(u32));
                        cl[q - 1] += cl[q] - 1;
                        for (size_t z = q; z + 1 < m; z++) {
                            chunk[z] = chunk[z + 1];
                            cl[z] = cl[z + 1];
                        }
                        m--;
                    }
                }
                u32 *buf = (u32 *)dk_alloc_noz(a, (j - i + 8 + 2 * m) * sizeof(u32) * 2);
                stuff = buf;
                sn = 0;
                for (size_t q = 0; q < m; q++) {
                    if (q) push_cp(&stuff, &sn, '-');
                    for (size_t z = 0; z < cl[q]; z++) {
                        u32 ch = chunk[q][z];
                        if (ch == '\\' || ch == '-') push_cp(&stuff, &sn, '\\');
                        push_cp(&stuff, &sn, ch);
                    }
                }
            }
            i = j + 1;
            if (sn == 0) {
                Token t = {T_NEVER};
                add_tok(&pt, t);
            } else if (sn == 1 && stuff[0] == '!') {
                Token t = {T_ANY};
                add_tok(&pt, t);
            } else {
                Token t = {T_SET};
                size_t start = 0;
                if (stuff[0] == '!') {
                    t.neg = true;
                    start = 1;
                }
                parse_class(&pt, &t, stuff + start, sn - start);
                add_tok(&pt, t);
            }
        } else {
            Token t = {T_CHAR, c};
            add_tok(&pt, t);
        }
    }
    return pt;
}

static bool tok_matches(const Token *t, u32 c) {
    switch (t->kind) {
    case T_ANY: return true;
    case T_CHAR: return t->c == c;
    case T_SET: {
        bool in = false;
        for (size_t i = 0; i < t->nranges; i++)
            if (c >= t->ranges[i].lo && c <= t->ranges[i].hi) {
                in = true;
                break;
            }
        return in != t->neg;
    }
    default: return false;
    }
}

static bool match_cps(const Pattern *pt, const u32 *s, size_t n) {
    size_t ti = 0, si = 0, star_t = (size_t)-1, star_s = 0;
    while (si < n) {
        if (ti < pt->n && pt->t[ti].kind == T_STAR) {
            star_t = ti++;
            star_s = si;
        } else if (ti < pt->n && tok_matches(&pt->t[ti], s[si])) {
            ti++;
            si++;
        } else if (star_t != (size_t)-1) {
            ti = star_t + 1;
            si = ++star_s;
        } else return false;
    }
    while (ti < pt->n && pt->t[ti].kind == T_STAR) ti++;
    return ti == pt->n;
}

static bool fnmatch_prepared(DkArena *a, const Pattern *pt, const char *name) {
    size_t n;
    u32 *s = to_cps(a, name, &n);
    return match_cps(pt, s, n);
}

bool dk_fnmatchcase(const char *name, const char *pat) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    Pattern pt = compile(sc, pat);
    bool r = fnmatch_prepared(sc, &pt, name);
    fs_tmp_done(sc, mk);
    return r;
}

bool dk_fnmatch(const char *name, const char *pat) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    bool r = dk_fnmatchcase(dk_path_normcase(sc, name), dk_path_normcase(sc, pat));
    fs_tmp_done(sc, mk);
    return r;
}

DkStrVec dk_fnmatch_filter(const DkStrVec *names, const char *pat) {
    DkStrVec out = {0};
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    Pattern pt = compile(sc, dk_path_normcase(sc, pat));
    for (size_t i = 0; i < names->n; i++) {
        DkArenaMark m2 = dk_arena_mark(sc);
        char *z = fs_cz(sc, names->v[i]);
        if (fnmatch_prepared(sc, &pt, dk_path_normcase(sc, z))) dk_vec_push(&out, names->v[i]);
        dk_arena_reset(sc, m2);
    }
    fs_tmp_done(sc, mk);
    return out;
}

/* ---- glob ------------------------------------------------------------------------------------------------------- */

bool dk_glob_has_magic(const char *s) { return strpbrk(s, "*?[") != NULL; }

char *dk_glob_escape(DkArena *a, const char *s) {
    DkStr d, r;
    dk_path_splitdrive(s, &d, &r);
    FsBuf b;
    fsb_init(&b, a);
    fsb_put(&b, d.p, d.n);
    for (size_t i = 0; i < r.n; i++) {
        char c = r.p[i];
        if (c == '*' || c == '?' || c == '[') {
            fsb_putc(&b, '[');
            fsb_putc(&b, c);
            fsb_putc(&b, ']');
        } else fsb_putc(&b, c);
    }
    return fsb_cz(&b);
}

typedef struct {
    DkArena *a;
    bool recursive, include_hidden;
    DkStrVec *out;
} Glob;

static const char *gjoin(Glob *g, const char *dir, const char *base) {
    if (!*dir || !*base) return *dir ? dir : base;
    return dk_path_join(g->a, dir, base);
}

static bool is_hidden(const char *s) { return s[0] == '.'; }

/* _listdir: names of dirname (or the current folder when empty); dironly keeps folders (is_dir follows links). */
static DkStrVec glob_listdir(Glob *g, const char *dirname, bool dironly) {
    DkStrVec names = {0};
    DkDirEntries es;
    if (!dk_scandir(g->a, *dirname ? dirname : ".", &es)) return names;
    for (size_t i = 0; i < es.n; i++)
        if (!dironly || es.v[i].is_dir) dk_vec_push(&names, es.v[i].name);
    dk_vec_free(&es);
    return names;
}

static void out_push(Glob *g, const char *s) {
    DkStr v = {s, strlen(s)};
    dk_vec_push(g->out, v);
}

static void rlistdir(Glob *g, const char *dirname, bool dironly, const char *prefix) {
    /* yields each name x (joined to prefix) and recursively below it */
    DkStrVec names = glob_listdir(g, dirname, dironly);
    for (size_t i = 0; i < names.n; i++) {
        const char *x = names.v[i].p;
        if (!(g->include_hidden || !is_hidden(x))) continue;
        out_push(g, gjoin(g, prefix, x));
        const char *path = *dirname ? dk_path_join(g->a, dirname, x) : x;
        rlistdir(g, path, dironly, gjoin(g, prefix, x));
    }
    dk_vec_free(&names);
}

static void glob2(Glob *g, const char *dirname, bool dironly, DkStrVec *res) {
    if (!*dirname || dk_isdir(dirname)) {
        DkStr e = {"", 0};
        dk_vec_push(res, e);
    }
    DkStrVec tmp = {0};
    DkStrVec *save = g->out;
    g->out = &tmp;
    rlistdir(g, dirname, dironly, "");
    g->out = save;
    for (size_t i = 0; i < tmp.n; i++) dk_vec_push(res, tmp.v[i]);
    dk_vec_free(&tmp);
}

static void glob1(Glob *g, const char *dirname, const char *pattern, bool dironly, DkStrVec *res) {
    DkStrVec names = glob_listdir(g, dirname, dironly);
    if (!(g->include_hidden || is_hidden(pattern))) {
        size_t w = 0;
        for (size_t i = 0; i < names.n; i++)
            if (!is_hidden(names.v[i].p)) names.v[w++] = names.v[i];
        names.n = w;
    }
    DkStrVec f = dk_fnmatch_filter(&names, pattern);
    for (size_t i = 0; i < f.n; i++) dk_vec_push(res, f.v[i]);
    dk_vec_free(&f);
    dk_vec_free(&names);
}

static void glob0(Glob *g, const char *dirname, const char *basename, DkStrVec *res) {
    (void)g;
    if (*basename) {
        if (dk_lexists(gjoin(g, dirname, basename))) {
            DkStr v = {basename, strlen(basename)};
            dk_vec_push(res, v);
        }
    } else if (dk_isdir(dirname)) {
        DkStr v = {basename, 0};
        dk_vec_push(res, v);
    }
}

static bool is_recursive(const char *s) { return s[0] == '*' && s[1] == '*' && s[2] == 0; }

static void iglob(Glob *g, const char *pathname, const char *root_dir, bool dironly) {
    DkStr dn, bn;
    dk_path_split(pathname, &dn, &bn);
    const char *dirname = fs_cz(g->a, dn), *basename = fs_cz(g->a, bn);
    if (!dk_glob_has_magic(pathname)) {
        if (*basename) {
            if (dk_lexists(gjoin(g, root_dir, pathname))) out_push(g, pathname);
        } else if (dk_isdir(gjoin(g, root_dir, dirname))) out_push(g, pathname);
        return;
    }
    if (!*dirname) {
        DkStrVec res = {0};
        if (g->recursive && is_recursive(basename)) glob2(g, root_dir, dironly, &res);
        else glob1(g, root_dir, basename, dironly, &res);
        for (size_t i = 0; i < res.n; i++) dk_vec_push(g->out, res.v[i]);
        dk_vec_free(&res);
        return;
    }
    DkStrVec dirs = {0};
    if (strcmp(dirname, pathname) != 0 && dk_glob_has_magic(dirname)) {
        DkStrVec *save = g->out;
        g->out = &dirs;
        iglob(g, dirname, root_dir, true);
        g->out = save;
    } else {
        DkStr d = {dirname, strlen(dirname)};
        dk_vec_push(&dirs, d);
    }
    bool magic_base = dk_glob_has_magic(basename);
    for (size_t i = 0; i < dirs.n; i++) {
        const char *d = dirs.v[i].p;
        DkStrVec res = {0};
        const char *where = gjoin(g, root_dir, d);
        if (magic_base) {
            if (g->recursive && is_recursive(basename)) glob2(g, where, dironly, &res);
            else glob1(g, where, basename, dironly, &res);
        } else glob0(g, where, basename, &res);
        for (size_t k = 0; k < res.n; k++) out_push(g, dk_path_join(g->a, d, res.v[k].p));
        dk_vec_free(&res);
    }
    dk_vec_free(&dirs);
}

DkStrVec dk_glob_ex(DkArena *a, const char *pattern, const DkGlobOpts *opts) {
    DkStrVec out = {0};
    Glob g = {a, opts ? opts->recursive : false, opts ? opts->include_hidden : false, &out};
    const char *root = opts && opts->root_dir ? opts->root_dir : "";
    iglob(&g, pattern, root, false);
    if ((!*pattern || (g.recursive && pattern[0] == '*' && pattern[1] == '*')) && out.n && out.v[0].n == 0)
        dk_vec_remove(&out, 0);
    return out;
}

DkStrVec dk_glob(DkArena *a, const char *pattern, bool recursive) {
    DkGlobOpts o = {NULL, recursive, false};
    return dk_glob_ex(a, pattern, &o);
}
