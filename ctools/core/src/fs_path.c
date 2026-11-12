// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* os.path for Windows (ntpath) of CPython 3.14: the same results for the same strings. The functions work on UTF-8
 * bytes; a "character" in Python's slicing (a code point) matters only where the algorithm looks at the first
 * characters of a path (the drive letter, isabs), and those are handled by code point. */
#include "fs_priv.h"

#include <stdio.h>

#define IS_SEP(c) ((c) == '\\' || (c) == '/')

static size_t cp_len_at(const char *p) {
    unsigned char c = (unsigned char)p[0];
    if (c < 0x80) return 1;
    size_t k = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC2 ? 2 : 1;
    for (size_t i = 1; i < k; i++)
        if (((unsigned char)p[i] & 0xC0) != 0x80) return i;
    return k;
}

/* ---- splitroot and friends --------------------------------------------------------------------------------------- */

static bool unc_prefix_at(const char *p) {
    static const char pre[] = "\\\\?\\UNC\\";
    for (int i = 0; i < 8; i++) {
        char c = p[i];
        if (c == 0) return false;
        if (c == '/') c = '\\';
        if (c >= 'a' && c <= 'z') c = (char)(c - 32);
        if (c != pre[i]) return false;
    }
    return true;
}

void dk_path_splitroot(const char *p, DkStr *drive, DkStr *root, DkStr *tail) {
    size_t n = strlen(p);
    DkStr d = {p, 0}, r = {p, 0}, t = {p, n};
    if (n > 0 && IS_SEP(p[0])) {
        if (n > 1 && IS_SEP(p[1])) {
            size_t start = unc_prefix_at(p) ? 8 : 2;
            size_t index = n, index2 = n;
            for (size_t i = start; i < n; i++)
                if (IS_SEP(p[i])) {
                    index = i;
                    break;
                }
            if (index == n) {
                d.n = n;
                t.p = p + n;
                t.n = 0;
                r.p = p + n;
                goto done;
            }
            for (size_t i = index + 1; i < n; i++)
                if (IS_SEP(p[i])) {
                    index2 = i;
                    break;
                }
            if (index2 == n) {
                d.n = n;
                t.p = p + n;
                t.n = 0;
                r.p = p + n;
                goto done;
            }
            d.n = index2;
            r.p = p + index2;
            r.n = 1;
            t.p = p + index2 + 1;
            t.n = n - index2 - 1;
        } else {
            r.n = 1;
            t.p = p + 1;
            t.n = n - 1;
        }
    } else if (n > 0) {
        size_t l0 = cp_len_at(p);
        if (l0 < n && p[l0] == ':') {
            size_t dl = l0 + 1;
            d.n = dl;
            r.p = p + dl;
            if (dl < n && IS_SEP(p[dl])) {
                r.n = 1;
                t.p = p + dl + 1;
                t.n = n - dl - 1;
            } else {
                t.p = p + dl;
                t.n = n - dl;
            }
        }
    }
done:
    if (drive) *drive = d;
    if (root) *root = r;
    if (tail) *tail = t;
}

void dk_path_splitdrive(const char *p, DkStr *drive, DkStr *rest) {
    DkStr d, r, t;
    dk_path_splitroot(p, &d, &r, &t);
    if (drive) *drive = d;
    if (rest) {
        rest->p = p + d.n;
        rest->n = r.n + t.n;
    }
}

void dk_path_split(const char *p, DkStr *head, DkStr *tail) {
    DkStr d, r, t;
    dk_path_splitroot(p, &d, &r, &t);
    size_t i = t.n;
    while (i && !IS_SEP(t.p[i - 1])) i--;
    size_t h = i;
    while (h && IS_SEP(t.p[h - 1])) h--; /* head.rstrip(seps) */
    if (head) {
        head->p = p;
        head->n = d.n + r.n + h;
    }
    if (tail) {
        tail->p = t.p + i;
        tail->n = t.n - i;
    }
}

DkStr dk_path_basename(const char *p) {
    DkStr h, t;
    dk_path_split(p, &h, &t);
    return t;
}

DkStr dk_path_dirname(const char *p) {
    DkStr h, t;
    dk_path_split(p, &h, &t);
    return h;
}

void dk_path_splitext(const char *p, DkStr *root, DkStr *ext) {
    size_t n = strlen(p);
    i64 sep_index = -1, dot_index = -1;
    for (size_t i = 0; i < n; i++) {
        if (IS_SEP(p[i])) sep_index = (i64)i;
        else if (p[i] == '.') dot_index = (i64)i;
    }
    if (dot_index > sep_index) {
        i64 fi = sep_index + 1;
        while (fi < dot_index) {
            if (p[fi] != '.') {
                if (root) {
                    root->p = p;
                    root->n = (size_t)dot_index;
                }
                if (ext) {
                    ext->p = p + dot_index;
                    ext->n = n - (size_t)dot_index;
                }
                return;
            }
            fi++;
        }
    }
    if (root) {
        root->p = p;
        root->n = n;
    }
    if (ext) {
        ext->p = p + n;
        ext->n = 0;
    }
}

bool dk_path_isabs(const char *p) {
    /* s = s[:3].replace('/', '\\'); s.startswith(':\\', 1) or s.startswith('\\\\') */
    if (IS_SEP(p[0]) && IS_SEP(p[1]) && p[0] && p[1]) return true;
    if (!p[0]) return false;
    size_t l0 = cp_len_at(p);
    return p[l0] == ':' && IS_SEP(p[l0 + 1]) && p[l0 + 1];
}

/* ---- case ----------------------------------------------------------------------------------------------------- */

char *dk_path_normcase(DkArena *a, const char *p) {
    if (!*p) return dk_strdup(a, p);
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *w = dk_fs_u8_to_w(sc, p);
    size_t n = wcslen(w);
    for (size_t i = 0; i < n; i++)
        if (w[i] == L'/') w[i] = L'\\';
    wchar_t *out = (wchar_t *)dk_alloc_noz(sc, (n + 1) * sizeof(wchar_t));
    int got = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, w, (int)n, out, (int)n + 1, NULL, NULL, 0);
    if (got <= 0) {
        memcpy(out, w, n * sizeof(wchar_t));
        got = (int)n;
    }
    char *res = dk_fs_w_to_u8(a, out, got);
    fs_tmp_done(sc, mk);
    return res;
}

/* str.lower() of a path component (drive comparisons, commonpath). */
static char *py_lower(DkArena *a, const char *p, size_t n) {
    char *z = (char *)dk_alloc_noz(a, n + 1);
    memcpy(z, p, n);
    z[n] = 0;
    bool ascii = true;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)z[i] >= 0x80) ascii = false;
    if (ascii) {
        for (size_t i = 0; i < n; i++)
            if (z[i] >= 'A' && z[i] <= 'Z') z[i] = (char)(z[i] + 32);
        return z;
    }
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *w = dk_fs_u8_to_w(sc, z);
    size_t wn = wcslen(w);
    CharLowerBuffW(w, (DWORD)wn);
    char *res = dk_fs_w_to_u8(a, w, (i64)wn);
    fs_tmp_done(sc, mk);
    return res;
}

/* ---- join ----------------------------------------------------------------------------------------------------- */

char *dk_path_joinv(DkArena *a, size_t count, const char *const *parts) {
    DkStr rd, rr, rp;
    dk_path_splitroot(parts[0], &rd, &rr, &rp);
    /* Pieces are views into the inputs; the result path is built in a builder when parts are appended. */
    FsBuf path;
    fsb_init(&path, a);
    fsb_put(&path, rp.p, rp.n);
    for (size_t k = 1; k < count; k++) {
        DkStr pd, pr, pp;
        dk_path_splitroot(parts[k], &pd, &pr, &pp);
        if (pr.n) {
            /* second path is absolute */
            if (pd.n || !rd.n) rd = pd;
            rr = pr;
            path.n = 0;
            fsb_put(&path, pp.p, pp.n);
            continue;
        }
        if (pd.n && !(pd.n == rd.n && memcmp(pd.p, rd.p, pd.n) == 0)) {
            DkArena *sc = fs_tmp();
            DkArenaMark mk = dk_arena_mark(sc);
            bool same = strcmp(py_lower(sc, pd.p, pd.n), py_lower(sc, rd.p, rd.n)) == 0;
            fs_tmp_done(sc, mk);
            if (!same) {
                /* different drives: ignore the first path entirely */
                rd = pd;
                rr = pr;
                path.n = 0;
                fsb_put(&path, pp.p, pp.n);
                continue;
            }
            rd = pd; /* same drive in a different case */
        }
        if (path.n && !IS_SEP(path.p[path.n - 1])) fsb_putc(&path, '\\');
        fsb_put(&path, pp.p, pp.n);
    }
    FsBuf out;
    fsb_init(&out, a);
    bool unc_sep = path.n && !rr.n && rd.n && !(rd.p[rd.n - 1] == ':' || IS_SEP(rd.p[rd.n - 1]));
    fsb_put(&out, rd.p, rd.n);
    if (unc_sep) fsb_putc(&out, '\\');
    fsb_put(&out, rr.p, rr.n);
    fsb_put(&out, path.p, path.n);
    if (!a) dk_xfree(path.p);
    return fsb_cz(&out);
}

char *dk_path_join(DkArena *a, const char *first, const char *second) {
    const char *parts[2] = {first, second};
    return dk_path_joinv(a, 2, parts);
}

/* ---- normpath / abspath ------------------------------------------------------------------------------------------ */

char *dk_path_normpath(DkArena *a, const char *p) {
    size_t n = strlen(p);
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    char *q = (char *)dk_alloc_noz(sc, n + 1);
    for (size_t i = 0; i <= n; i++) q[i] = p[i] == '/' ? '\\' : p[i];
    DkStr d, r, t;
    dk_path_splitroot(q, &d, &r, &t);
    /* components of the tail, processed like the Python list algorithm with a stack of views */
    DK_VEC(DkStr) comps = {0};
    const char *s = t.p, *end = t.p + t.n;
    while (s <= end) {
        const char *e = s;
        while (e < end && *e != '\\') e++;
        size_t len = (size_t)(e - s);
        if (len == 0 || (len == 1 && s[0] == '.')) {
            /* dropped */
        } else if (len == 2 && s[0] == '.' && s[1] == '.') {
            if (comps.n > 0 && !(comps.v[comps.n - 1].n == 2 && comps.v[comps.n - 1].p[0] == '.' && comps.v[comps.n - 1].p[1] == '.'))
                comps.n--;
            else if (comps.n == 0 && r.n) {
                /* ".." directly under the root disappears */
            } else {
                DkStr c = {s, len};
                dk_vec_push(&comps, c);
            }
        } else {
            DkStr c = {s, len};
            dk_vec_push(&comps, c);
        }
        if (e >= end) break;
        s = e + 1;
    }
    FsBuf out;
    fsb_init(&out, a);
    fsb_put(&out, d.p, d.n);
    fsb_put(&out, r.p, r.n);
    if (d.n + r.n == 0 && comps.n == 0) fsb_putc(&out, '.');
    for (size_t i = 0; i < comps.n; i++) {
        if (i) fsb_putc(&out, '\\');
        fsb_put(&out, comps.v[i].p, comps.v[i].n);
    }
    dk_vec_free(&comps);
    fs_tmp_done(sc, mk);
    return fsb_cz(&out);
}

static bool full_path(DkArena *a, const char *p, char **out) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *w = dk_fs_u8_to_w(sc, p);
    DWORD need = GetFullPathNameW(w, 0, NULL, NULL);
    bool ok = false;
    if (need) {
        wchar_t *buf = (wchar_t *)dk_alloc_noz(sc, ((size_t)need + 1) * sizeof(wchar_t));
        DWORD got = GetFullPathNameW(w, need, buf, NULL);
        if (got && got < need) {
            *out = dk_fs_w_to_u8(a, buf, (i64)got);
            ok = true;
        }
    }
    fs_tmp_done(sc, mk);
    return ok;
}

char *dk_path_abspath(DkArena *a, const char *p) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    char *norm = dk_path_normpath(sc, p), *res = NULL;
    if (full_path(a, norm, &res)) {
        fs_tmp_done(sc, mk);
        return res;
    }
    /* ntpath's fallback when GetFullPathNameW fails */
    if (!dk_path_isabs(p)) {
        DkStr d, r, t;
        dk_path_splitroot(p, &d, &r, &t);
        char *joined;
        if (d.n || r.n) {
            char *dr = fs_cz(sc, (DkStr){p, d.n + r.n}), *fp = NULL;
            if (full_path(sc, dr, &fp)) joined = dk_path_join(sc, fp, fs_cz(sc, t));
            else joined = dk_path_join(sc, "\\", fs_cz(sc, t)); /* drive + sep + path */
        } else joined = dk_path_join(sc, dk_getcwd(sc), p);
        res = dk_path_normpath(a, joined);
    } else res = dk_path_normpath(a, p);
    fs_tmp_done(sc, mk);
    return res;
}

/* ---- relpath / commonpath ------------------------------------------------------------------------------------------ */

bool dk_path_relpath(DkArena *a, const char *p, const char *start, char **out) {
    if (!*p) {
        dk_fs_fail_value("no path specified");
        return false;
    }
    if (!start) start = ".";
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    char *start_abs = dk_path_abspath(sc, start), *path_abs = dk_path_abspath(sc, p);
    DkStr sd, sr, st, pd, pr, pt;
    dk_path_splitroot(start_abs, &sd, &sr, &st);
    dk_path_splitroot(path_abs, &pd, &pr, &pt);
    char *nsd = dk_path_normcase(sc, fs_cz(sc, sd)), *npd = dk_path_normcase(sc, fs_cz(sc, pd));
    if (strcmp(nsd, npd) != 0) {
        FsBuf b;
        fsb_init(&b, NULL);
        fsb_putz(&b, "path is on mount ");
        dk_fs_repr(&b, fs_cz(sc, pd));
        fsb_putz(&b, ", start on mount ");
        dk_fs_repr(&b, fs_cz(sc, sd));
        dk_fs_fail_value("%s", fsb_cz(&b));
        dk_xfree(b.p);
        fs_tmp_done(sc, mk);
        return false;
    }
    /* split on '\' (both are normalised by abspath) */
    DK_VEC(DkStr) sl = {0}, pl = {0};
    for (int which = 0; which < 2; which++) {
        DkStr rest = which ? pt : st;
        if (rest.n == 0) continue;
        const char *s = rest.p, *end = rest.p + rest.n;
        for (;;) {
            const char *e = s;
            while (e < end && *e != '\\') e++;
            DkStr c = {s, (size_t)(e - s)};
            if (which) dk_vec_push(&pl, c);
            else dk_vec_push(&sl, c);
            if (e >= end) break;
            s = e + 1;
        }
    }
    size_t i = 0;
    while (i < sl.n && i < pl.n) {
        char *x = dk_path_normcase(sc, fs_cz(sc, sl.v[i])), *y = dk_path_normcase(sc, fs_cz(sc, pl.v[i]));
        if (strcmp(x, y) != 0) break;
        i++;
    }
    FsBuf b;
    fsb_init(&b, a);
    size_t ups = sl.n - i, items = 0;
    for (size_t k = 0; k < ups; k++) {
        if (items++) fsb_putc(&b, '\\');
        fsb_putz(&b, "..");
    }
    for (size_t k = i; k < pl.n; k++) {
        if (items++) fsb_putc(&b, '\\');
        fsb_put(&b, pl.v[k].p, pl.v[k].n);
    }
    if (items == 0) fsb_putc(&b, '.');
    *out = fsb_cz(&b);
    dk_vec_free(&sl);
    dk_vec_free(&pl);
    fs_tmp_done(sc, mk);
    return true;
}

typedef DK_VEC(DkStr) StrList;

static void split_sep(StrList *l, const char *s, size_t n) {
    const char *end = s + n;
    for (;;) {
        const char *e = s;
        while (e < end && *e != '\\') e++;
        DkStr c = {s, (size_t)(e - s)};
        dk_vec_push(l, c);
        if (e >= end) break;
        s = e + 1;
    }
}

bool dk_path_commonpath(DkArena *a, const char *const *paths, size_t n, char **out) {
    if (n == 0) {
        dk_fs_fail_value("commonpath() arg is an empty iterable");
        return false;
    }
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    DkStr *drv = (DkStr *)dk_alloc(sc, n * sizeof(DkStr)), *rt = (DkStr *)dk_alloc(sc, n * sizeof(DkStr));
    StrList *lists = (StrList *)dk_alloc(sc, n * sizeof(StrList));
    for (size_t i = 0; i < n; i++) {
        size_t len = strlen(paths[i]);
        char *q = (char *)dk_alloc_noz(sc, len + 1);
        for (size_t k = 0; k <= len; k++) q[k] = paths[i][k] == '/' ? '\\' : paths[i][k];
        char *lo = py_lower(sc, q, len);
        DkStr t;
        dk_path_splitroot(lo, &drv[i], &rt[i], &t);
        split_sep(&lists[i], t.p, t.n);
        /* drop empty and '.' components */
        size_t w = 0;
        for (size_t k = 0; k < lists[i].n; k++) {
            DkStr c = lists[i].v[k];
            if (c.n == 0 || (c.n == 1 && c.p[0] == '.')) continue;
            lists[i].v[w++] = c;
        }
        lists[i].n = w;
    }
    bool ok = true;
    for (size_t i = 1; i < n && ok; i++)
        if (drv[i].n != drv[0].n || memcmp(drv[i].p, drv[0].p, drv[0].n) != 0) {
            dk_fs_fail_value("Paths don't have the same drive");
            ok = false;
        }
    for (size_t i = 1; i < n && ok; i++)
        if (rt[i].n != rt[0].n) {
            dk_fs_fail_value(drv[0].n ? "Can't mix absolute and relative paths" : "Can't mix rooted and not-rooted paths");
            ok = false;
        }
    if (ok) {
        size_t len = strlen(paths[0]);
        char *q = (char *)dk_alloc_noz(sc, len + 1);
        for (size_t k = 0; k <= len; k++) q[k] = paths[0][k] == '/' ? '\\' : paths[0][k];
        DkStr d, r, t;
        dk_path_splitroot(q, &d, &r, &t);
        StrList common = {0};
        split_sep(&common, t.p, t.n);
        size_t w = 0;
        for (size_t k = 0; k < common.n; k++) {
            DkStr c = common.v[k];
            if (c.n == 0 || (c.n == 1 && c.p[0] == '.')) continue;
            common.v[w++] = c;
        }
        common.n = w;
        /* the common prefix of the lower-cased component lists */
        size_t cp = lists[0].n;
        for (size_t i = 1; i < n; i++) {
            size_t k = 0;
            while (k < cp && k < lists[i].n && lists[i].v[k].n == lists[0].v[k].n &&
                   memcmp(lists[i].v[k].p, lists[0].v[k].p, lists[0].v[k].n) == 0)
                k++;
            cp = k;
        }
        if (cp > common.n) cp = common.n;
        FsBuf b;
        fsb_init(&b, a);
        fsb_put(&b, d.p, d.n);
        fsb_put(&b, r.p, r.n);
        for (size_t k = 0; k < cp; k++) {
            if (k) fsb_putc(&b, '\\');
            fsb_put(&b, common.v[k].p, common.v[k].n);
        }
        *out = fsb_cz(&b);
        dk_vec_free(&common);
    }
    for (size_t i = 0; i < n; i++) dk_vec_free(&lists[i]);
    fs_tmp_done(sc, mk);
    return ok;
}

/* ---- expanduser / samefile / as_posix --------------------------------------------------------------------------------- */

char *dk_path_expanduser(DkArena *a, const char *p) {
    if (p[0] != '~') return dk_strdup(a, p);
    size_t i = 1, n = strlen(p);
    while (i < n && !IS_SEP(p[i])) i++;
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    char *userhome = dk_getenv(sc, "USERPROFILE");
    if (!userhome) {
        char *hp = dk_getenv(sc, "HOMEPATH");
        if (!hp) {
            fs_tmp_done(sc, mk);
            return dk_strdup(a, p);
        }
        char *hd = dk_getenv(sc, "HOMEDRIVE");
        userhome = dk_path_join(sc, hd ? hd : "", hp);
    }
    if (i != 1) { /* ~user */
        char *target = (char *)dk_alloc_noz(sc, i);
        memcpy(target, p + 1, i - 1);
        target[i - 1] = 0;
        char *cur = dk_getenv(sc, "USERNAME");
        if (!cur || strcmp(target, cur) != 0) {
            DkStr bn = dk_path_basename(userhome);
            if (!cur || bn.n != strlen(cur) || memcmp(bn.p, cur, bn.n) != 0) {
                fs_tmp_done(sc, mk);
                return dk_strdup(a, p);
            }
            DkStr dn = dk_path_dirname(userhome);
            userhome = dk_path_join(sc, fs_cz(sc, dn), target);
        }
    }
    size_t ul = strlen(userhome);
    char *res = (char *)dk_alloc_noz(a, ul + (n - i) + 1);
    memcpy(res, userhome, ul);
    memcpy(res + ul, p + i, n - i + 1);
    fs_tmp_done(sc, mk);
    return res;
}

bool dk_path_samefile(const char *x, const char *y) {
    DkStat a, b;
    if (!dk_stat(x, &a) || !dk_stat(y, &b)) return false;
    return a.ino == b.ino && a.ino_hi == b.ino_hi && a.dev == b.dev;
}

char *dk_path_as_posix(DkArena *a, const char *p) {
    char *r = dk_strdup(a, p);
    for (char *c = r; *c; c++)
        if (*c == '\\') *c = '/';
    return r;
}

/* ---- realpath ----------------------------------------------------------------------------------------------------- */

/* nt._getfinalpathname: CreateFile + GetFinalPathNameByHandle (VOLUME_NAME_DOS); fails with the Win32 error. */
static bool final_path(DkArena *a, const char *p, char **out, unsigned *werr) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *w = dk_fs_u8_to_w(sc, p);
    HANDLE h = CreateFileW(w, 0, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    bool ok = false;
    if (h == INVALID_HANDLE_VALUE) *werr = GetLastError();
    else {
        DWORD need = GetFinalPathNameByHandleW(h, NULL, 0, VOLUME_NAME_DOS);
        if (need == 0) *werr = GetLastError();
        else {
            wchar_t *buf = (wchar_t *)dk_alloc_noz(sc, ((size_t)need + 1) * sizeof(wchar_t));
            DWORD got = GetFinalPathNameByHandleW(h, buf, need + 1, VOLUME_NAME_DOS);
            if (got == 0 || got > need) *werr = GetLastError();
            else {
                *out = dk_fs_w_to_u8(a, buf, (i64)got);
                ok = true;
            }
        }
        CloseHandle(h);
    }
    fs_tmp_done(sc, mk);
    return ok;
}

static bool in_list(unsigned w, const unsigned *l, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (l[i] == w) return true;
    return false;
}

/* os.readlink without recording errors: the substitute name, or NULL */
static char *readlink_quiet(DkArena *a, const char *p, unsigned *werr) {
    DkIoErr saved = *dk_io_err();
    char *r = NULL;
    if (!dk_readlink(a, p, &r)) {
        *werr = (unsigned)dk_io_err()->winerror;
        r = NULL;
    }
    (void)saved;
    return r;
}

static char *readlink_deep(DkArena *a, const char *path, bool *failed) {
    static const unsigned allowed[] = {1, 2, 3, 5, 21, 32, 50, 67, 87, 4390, 4392, 4393};
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    DK_VEC(char *) seen = {0};
    char *cur = dk_strdup(a, path);
    *failed = false;
    for (;;) {
        char *nc = dk_path_normcase(sc, cur);
        bool dup = false;
        for (size_t i = 0; i < seen.n; i++)
            if (strcmp(seen.v[i], nc) == 0) dup = true;
        if (dup) break;
        dk_vec_push(&seen, nc);
        unsigned we = 0;
        char *old = cur;
        char *t = readlink_quiet(a, cur, &we);
        if (!t) {
            if (!in_list(we, allowed, DK_ARRAY_LEN(allowed))) *failed = true;
            break;
        }
        cur = t;
        if (!dk_path_isabs(cur)) {
            if (!dk_islink(old)) {
                cur = old;
                break;
            }
            DkStr dn = dk_path_dirname(old);
            cur = dk_path_normpath(a, dk_path_join(a, fs_cz(a, dn), cur));
        }
    }
    dk_vec_free(&seen);
    fs_tmp_done(sc, mk);
    return cur;
}

static char *join_nt(DkArena *a, const char *path, const char *tail) {
    size_t pl = strlen(path), tl = strlen(tail);
    char *r = (char *)dk_alloc_noz(a, pl + tl + 2);
    memcpy(r, path, pl);
    size_t k = pl;
    if (!(pl && path[pl - 1] == '\\') && tl) r[k++] = '\\';
    memcpy(r + k, tail, tl);
    r[k + tl] = 0;
    return r;
}

static char *final_nonstrict(DkArena *a, const char *path0) {
    static const unsigned allowed[] = {1, 2, 3, 5, 21, 32, 50, 53, 65, 67, 87, 123, 161, 1005, 1920, 1921};
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    char *path = dk_strdup(sc, path0), *tail = dk_strdup(sc, "");
    char *result = NULL;
    while (*path) {
        char *fin = NULL;
        unsigned we = 0;
        if (final_path(sc, path, &fin, &we)) {
            result = join_nt(a, fin, tail);
            goto done;
        }
        if (!in_list(we, allowed, DK_ARRAY_LEN(allowed))) {
            result = join_nt(a, path, tail); /* CPython raises here; the tools never get this far */
            goto done;
        }
        bool failed;
        char *np = readlink_deep(sc, path, &failed);
        if (!failed && strcmp(np, path) != 0) {
            result = join_nt(a, np, tail);
            goto done;
        }
        DkStr head = {0}, name = {0};
        static const unsigned find_codes[] = {1, 5, 32, 50, 87, 1920, 1921};
        bool used_find = false;
        if (in_list(we, find_codes, DK_ARRAY_LEN(find_codes))) {
            WIN32_FIND_DATAW fd;
            HANDLE fh = FindFirstFileW(dk_fs_wpath(sc, path), &fd);
            if (fh != INVALID_HANDLE_VALUE) {
                FindClose(fh);
                dk_path_split(path, &head, &name);
                name.p = dk_fs_w_to_u8(sc, fd.cFileName, -1);
                name.n = strlen(name.p);
                used_find = true;
            }
        }
        if (!used_find) dk_path_split(path, &head, &name);
        path = fs_cz(sc, head);
        if (*path && name.n == 0) {
            result = join_nt(a, path, tail);
            goto done;
        }
        tail = join_nt(sc, fs_cz(sc, name), tail);
    }
    result = dk_strdup(a, tail);
done:
    fs_tmp_done(sc, mk);
    return result;
}

char *dk_path_realpath(DkArena *a, const char *p0) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    char *path = dk_path_normpath(sc, p0);
    if (strcmp(dk_path_normcase(sc, path), "nul") == 0) {
        fs_tmp_done(sc, mk);
        return dk_strdup(a, "\\\\.\\NUL");
    }
    bool had_prefix = strncmp(path, "\\\\?\\", 4) == 0;
    if (!had_prefix && !dk_path_isabs(path)) path = dk_path_abspath(sc, path);
    char *fin = NULL;
    unsigned we = 0, initial = 0;
    if (final_path(sc, path, &fin, &we)) path = fin;
    else {
        initial = we;
        path = final_nonstrict(sc, path);
    }
    if (!had_prefix && strncmp(path, "\\\\?\\", 4) == 0) {
        char *spath = NULL;
        if (strncmp(path, "\\\\?\\UNC\\", 8) == 0) {
            size_t k = strlen(path + 8);
            spath = (char *)dk_alloc_noz(sc, k + 4);
            spath[0] = spath[1] = '\\';
            memcpy(spath + 2, path + 8, k + 1);
        } else if (path[4] && path[5] == ':' && path[6] == '\\') spath = path + 4;
        if (spath) {
            char *chk = NULL;
            unsigned we2 = 0;
            if (final_path(sc, spath, &chk, &we2)) {
                if (strcmp(chk, path) == 0) path = spath;
            } else if (we2 == initial) path = spath;
        }
    }
    char *res = dk_strdup(a, path);
    fs_tmp_done(sc, mk);
    return res;
}
