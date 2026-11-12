// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Files, folders, stat, errors, os.walk, glob, shutil and tempfile against CPython 3.14 (fs_dir_expect.h): the test
 * rebuilds the generator's tree in a fresh temporary folder and compares with what Python returned for it. */
#include "dk/dk.h"
#include "dk/fs.h"
#include "dk/test.h"
#include "dk/win.h"
#include "dk/proc.h"
#include "dk/pool.h"

#include "fs_dir_expect.h"

#include <ctype.h>
#include <stdio.h>

static char g_root[1024];
static DkArena *g_a;
static bool g_ordered; /* the volume lists names in sorted order (NTFS, ReFS) */

static char *rel(const char *r) { return dk_path_join(g_a, g_root, r); }

static void put(const char *r, const char *data) {
    char *p = rel(r);
    DkStr d = dk_path_dirname(p);
    char *dz = (char *)dk_alloc_noz(g_a, d.n + 1);
    memcpy(dz, d.p, d.n);
    dz[d.n] = 0;
    dk_makedirs(dz, true);
    CHECK(dk_write_file(p, data, strlen(data)));
}

static void make_tree(void) {
    g_a = dk_arena_new(0);
    char *r = dk_mkdtemp(g_a, "avptest_", "", NULL);
    snprintf(g_root, sizeof g_root, "%s", r);
    put("a.txt", "abc");
    put("B.txt", "");
    put("c.TXT", "x");
    put(".hidden", "");
    put("readme.md", "");
    put("sub\\x.cpp", "");
    put("sub\\Y.cpp", "");
    put("sub\\.dot.cpp", "");
    put("sub\\z.h", "");
    put("sub\\deep\\z.cpp", "");
    put("sub\\deep\\w.h", "");
    put("sub\\deep\\.z.cpp", "");
    put("Zdir\\q.h", "");
    dk_makedirs(rel("emptydir"), false);
    put(".dotdir\\in.txt", "");
    CHECK(dk_junction_create(rel("jn"), rel("sub")));
    put("rodir\\f.txt", "ro");
    CHECK(dk_chmod(rel("rodir\\f.txt"), 0400));
    u32 serial;
    char *fsname;
    g_ordered = dk_volume_info(g_a, g_root, &serial, &fsname) && (strcmp(fsname, "NTFS") == 0 || strcmp(fsname, "ReFS") == 0);
}

static void drop_tree(void) {
    dk_rmtree(g_root, DK_RMTREE_CLEAR_READONLY | DK_RMTREE_IGNORE_ERRORS);
    dk_arena_free(g_a);
    g_a = NULL;
}

/* '@' in an expectation is the temporary folder; dbl: with doubled backslashes as repr() prints it */
static char *at(const char *tmpl, bool dbl) {
    size_t n = strlen(tmpl), rl = strlen(g_root);
    char *out = (char *)dk_alloc_noz(g_a, n * (rl * 2 + 1) + 1);
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (tmpl[i] == '@') {
            for (size_t j = 0; j < rl; j++) {
                out[k++] = g_root[j];
                if (dbl && g_root[j] == '\\') out[k++] = '\\';
            }
        } else out[k++] = tmpl[i];
    }
    out[k] = 0;
    return out;
}

static char *join_vec(const DkStrVec *v, char sep) {
    size_t total = 1;
    for (size_t i = 0; i < v->n; i++) total += v->v[i].n + 1;
    char *out = (char *)dk_alloc_noz(g_a, total);
    size_t k = 0;
    for (size_t i = 0; i < v->n; i++) {
        if (i) out[k++] = sep;
        memcpy(out + k, v->v[i].p, v->v[i].n);
        k += v->v[i].n;
    }
    out[k] = 0;
    return out;
}

static void expect_eq(const char *what, const char *got, const char *want) {
    if (strcmp(got, want) != 0) dk_test__fail(__FILE__, __LINE__, "%s: got [%s] want [%s]", what, got, want);
}

DK_TEST(listing_and_scandir) {
    make_tree();
    DkStrVec names;
    CHECK(dk_listdir(g_a, g_root, &names));
    if (g_ordered) expect_eq("listdir root", join_vec(&names, '\x1f'), k_listdir_root);
    CHECK(dk_listdir(g_a, rel("sub"), &names));
    if (g_ordered) expect_eq("listdir sub", join_vec(&names, '\x1f'), k_listdir_sub);
    DkDirEntries es;
    CHECK(dk_scandir(g_a, g_root, &es));
    char buf[2048];
    size_t k = 0;
    for (size_t i = 0; i < es.n; i++) {
        if (i) buf[k++] = '\x1f';
        k += (size_t)snprintf(buf + k, sizeof buf - k, "%.*s\x1e%d%d%d", (int)es.v[i].name.n, es.v[i].name.p, es.v[i].is_dir,
                              es.v[i].is_file, es.v[i].is_symlink * 2 + es.v[i].is_junction);
    }
    if (g_ordered) expect_eq("scandir flags", buf, k_scandir_root);
    CHECK(es.n > 0 && es.v[0].path.p[es.v[0].path.n] == 0); /* path is NUL-terminated */
    drop_tree();
}

static char *walk_all(const char *top, bool topdown, bool prune) {
    DkWalk *w = dk_walk_open(top, topdown);
    DkWalkItem it;
    size_t cap = 1 << 16, k = 0;
    char *out = (char *)dk_alloc(g_a, cap);
    bool first = true;
    while (dk_walk_next(w, &it)) {
        if (!first) out[k++] = '\x1d';
        first = false;
        DkArena *tmp = dk_arena_new(0);
        char *d = (char *)dk_alloc_noz(tmp, it.dirpath.n + 1);
        memcpy(d, it.dirpath.p, it.dirpath.n);
        d[it.dirpath.n] = 0;
        if (prune) {
            size_t wr = 0;
            for (size_t i = 0; i < it.dirs.n; i++) {
                DkStr s = it.dirs.v[i];
                if ((s.n == 4 && !memcmp(s.p, "deep", 4)) || (s.n == 7 && !memcmp(s.p, ".dotdir", 7)) || (s.n == 2 && !memcmp(s.p, "jn", 2))) continue;
                it.dirs.v[wr++] = s;
            }
            it.dirs.n = wr;
        }
        char *dj = join_vec(&it.dirs, '\x1f'), *fj = join_vec(&it.files, '\x1f');
        k += (size_t)snprintf(out + k, cap - k, "%s\x1e%s\x1e%s", d, dj, fj);
        dk_arena_free(tmp);
    }
    dk_walk_close(w);
    return out;
}

DK_TEST(walk_orders) {
    make_tree();
    if (g_ordered) {
        expect_eq("walk topdown", walk_all(g_root, true, false), at(k_walk_top, false));
        expect_eq("walk bottom-up", walk_all(g_root, false, false), at(k_walk_bottom, false));
        expect_eq("walk pruned", walk_all(g_root, true, true), at(k_walk_pruned, false));
    }
    /* a missing top yields nothing; a file top yields nothing */
    CHECK_CZ(walk_all(rel("nope"), true, false), "");
    CHECK_CZ(walk_all(rel("a.txt"), true, false), "");
    drop_tree();
}

DK_TEST(glob_table) {
    make_tree();
    int bad = 0;
    if (g_ordered)
        for (size_t i = 0; i < DK_ARRAY_LEN(k_glob) && bad < 8; i++) {
            DkGlobOpts o = {k_glob[i].root_dir ? g_root : NULL, k_glob[i].recursive != 0, k_glob[i].hidden != 0};
            DkStrVec r = dk_glob_ex(g_a, at(k_glob[i].pattern, false), &o);
            const char *got = join_vec(&r, '\x1f'), *want = at(k_glob[i].out, false);
            if (strcmp(got, want) != 0) {
                bad++;
                dk_test__fail(__FILE__, __LINE__, "glob(%s, rec=%d hid=%d rd=%d): got [%s] want [%s]", k_glob[i].pattern, k_glob[i].recursive, k_glob[i].hidden, k_glob[i].root_dir, got, want);
            }
            dk_vec_free(&r);
        }
    CHECK(bad == 0);
    CHECK(dk_glob_has_magic("a*") && dk_glob_has_magic("[x]") && !dk_glob_has_magic("plain"));
    CHECK_CZ(dk_glob_escape(g_a, "C:\\a*b?c[d]"), "C:\\a[*]b[?]c[[]d]");
    drop_tree();
}

DK_TEST(stat_fields) {
    make_tree();
    DkStat st;
    char *a = rel("a.txt");
    CHECK(dk_utime_ns(a, 1700000000123456789LL, 1700000001987654321LL));
    CHECK(dk_stat(a, &st));
    CHECK_EQ_I64(st.size, k_stat_a.size);
    CHECK_EQ_I64(st.atime_ns, k_stat_a.atime_ns);
    CHECK_EQ_I64(st.mtime_ns, k_stat_a.mtime_ns);
    CHECK_EQ_U64(st.mode, k_stat_a.mode);
    CHECK_EQ_U64(st.file_attributes, k_stat_a.attrs);
    char rb[64];
    CHECK(st.mtime == 1700000001.9876542);
    snprintf(rb, sizeof rb, "%.17g", st.mtime);
    double want_mtime = 1700000001.9876542;
    CHECK_EQ_F64(st.mtime, want_mtime);
    double m;
    CHECK(dk_getmtime(a, &m));
    CHECK_EQ_F64(m, want_mtime);
    i64 sz;
    CHECK(dk_getsize(a, &sz) && sz == 3);
    CHECK(dk_stat(rel("sub"), &st));
    CHECK_EQ_U64(st.mode, k_stat_dir_mode);
    CHECK(dk_stat(rel("rodir\\f.txt"), &st));
    CHECK_EQ_U64(st.mode, 33060);
    CHECK_EQ_U64(st.file_attributes, 33);
    CHECK(dk_lstat(rel("jn"), &st));
    CHECK_EQ_U64(st.mode, k_lstat_jn_mode);
    CHECK_EQ_U64(st.file_attributes, k_lstat_jn_attrs);
    CHECK_EQ_U64(st.reparse_tag, k_lstat_jn_tag);
    char *link = NULL;
    CHECK(dk_readlink(g_a, rel("jn"), &link));
    expect_eq("readlink junction", link, at(k_readlink_jn, false));
    char *jn = rel("jn");
    CHECK_EQ_I64(dk_islink(jn), k_junction_flags[0]);
    CHECK_EQ_I64(dk_isjunction(jn), k_junction_flags[1]);
    CHECK_EQ_I64(dk_isdir(jn), k_junction_flags[2]);
    CHECK_EQ_I64(dk_exists(jn), k_junction_flags[3]);
    CHECK_EQ_I64(dk_lexists(jn), k_junction_flags[4]);
    CHECK_EQ_I64(dk_isfile(jn), k_junction_flags[5]);
    /* same file by two paths: same ino and dev */
    DkStat s2 = {0};
    CHECK(dk_stat(rel("sub\\x.cpp"), &st) && dk_stat(rel("jn\\x.cpp"), &s2));
    CHECK(st.ino == s2.ino && st.dev == s2.dev && st.ino != 0);
    CHECK(dk_path_samefile(rel("sub\\x.cpp"), rel("jn\\x.cpp")));
    CHECK(!dk_path_samefile(rel("sub\\x.cpp"), rel("sub\\Y.cpp")));
    /* utime(None) is "now" */
    CHECK(dk_utime_now(a));
    CHECK(dk_stat(a, &st) && st.mtime_ns > 1700000002000000000LL);
    drop_tree();
}

typedef struct {
    const char *name;
    bool (*fn)(void);
} ErrOp;

static bool op_open_missing(void) { DkFileView v; return dk_view_open(rel("nope.txt"), &v); }
static bool op_open_dir(void) { DkFileView v; return dk_view_open(rel("sub"), &v); }
static bool op_open_w_dir(void) { return dk_write_file(rel("sub"), "", 0); }
static bool op_open_w_noparent(void) { return dk_write_file(rel("nodir\\f.txt"), "", 0); }
static bool op_open_x_exists(void) { DkFile *f = dk_fopen(rel("a.txt"), "x", DK_TM_UTF8); if (f) dk_fclose(f); return f != NULL; }
static bool op_listdir_missing(void) { DkStrVec v; return dk_listdir(g_a, rel("nope"), &v); }
static bool op_listdir_file(void) { DkStrVec v; return dk_listdir(g_a, rel("a.txt"), &v); }
static bool op_remove_missing(void) { return dk_remove(rel("nope")); }
static bool op_remove_dir(void) { return dk_remove(rel("emptydir")); }
static bool op_rmdir_missing(void) { return dk_rmdir(rel("nope")); }
static bool op_rmdir_nonempty(void) { return dk_rmdir(rel("sub")); }
static bool op_mkdir_exists(void) { return dk_mkdir(rel("sub")); }
static bool op_mkdir_noparent(void) { return dk_mkdir(rel("nodir\\x")); }
static bool op_makedirs_through_file(void) { return dk_makedirs(rel("a.txt\\z"), false); }
static bool op_makedirs_exists(void) { return dk_makedirs(rel("sub"), false); }
static bool op_replace_missing(void) { return dk_replace(rel("nope"), rel("x")); }
static bool op_rename_exists(void) { return dk_rename(rel("B.txt"), rel("a.txt")); }
static bool op_stat_missing(void) { DkStat s; return dk_stat(rel("nope"), &s); }
static bool op_getsize_missing(void) { i64 s; return dk_getsize(rel("nope"), &s); }
static bool op_getmtime_missing(void) { double s; return dk_getmtime(rel("nope"), &s); }
static bool op_chdir_missing(void) { return dk_chdir(rel("nope")); }
static bool op_readlink_plain(void) { char *o; return dk_readlink(g_a, rel("a.txt"), &o); }
static bool op_utime_missing(void) { return dk_utime_now(rel("nope")); }
static bool op_chmod_missing(void) { return dk_chmod(rel("nope"), 0200); }
static bool op_copyfile_missing(void) { return dk_copyfile(rel("nope"), rel("copy_out\\x")); }
static bool op_copyfile_same(void) { return dk_copyfile(rel("a.txt"), rel("a.txt")); }
static bool op_copyfile_to_dir(void) { return dk_copyfile(rel("a.txt"), rel("sub")); }
static bool op_copy2_missing(void) { return dk_copy2(rel("nope"), rel("copy_out\\x")); }
static bool op_rmtree_missing(void) { return dk_rmtree(rel("nope"), 0); }
static bool op_rmtree_junction(void) { return dk_rmtree(rel("jn"), 0); }
static bool op_copytree_missing(void) { return dk_copytree(rel("nope"), rel("copy_out\\t"), NULL); }
static bool op_copytree_exists(void) { return dk_copytree(rel("emptydir"), rel("copy_out"), NULL); }
static bool op_relpath_empty(void) { char *o; return dk_path_relpath(g_a, "", NULL, &o); }
static bool op_relpath_mounts(void) { char *o; return dk_path_relpath(g_a, "C:\\a", "D:\\b", &o); }
static bool op_commonpath_empty(void) { char *o; return dk_path_commonpath(g_a, NULL, 0, &o); }
static bool op_commonpath_mixed(void) { char *o; const char *p[2] = {"C:\\a", "a"}; return dk_path_commonpath(g_a, p, 2, &o); }
static bool op_symlink_exists(void) { return dk_symlink(rel("a.txt"), rel("B.txt"), false); }
static bool op_rmtree_readonly(void) { return dk_rmtree(rel("rodir"), 0); }
static bool op_scandir_missing(void) { DkDirEntries e; return dk_scandir(g_a, rel("nope"), &e); }

static const ErrOp k_ops[] = {
    {"open_missing", op_open_missing}, {"open_dir", op_open_dir}, {"open_w_dir", op_open_w_dir},
    {"open_w_noparent", op_open_w_noparent}, {"open_x_exists", op_open_x_exists}, {"listdir_missing", op_listdir_missing},
    {"listdir_file", op_listdir_file}, {"scandir_missing", op_scandir_missing}, {"remove_missing", op_remove_missing},
    {"remove_dir", op_remove_dir}, {"rmdir_missing", op_rmdir_missing}, {"rmdir_nonempty", op_rmdir_nonempty},
    {"mkdir_exists", op_mkdir_exists}, {"mkdir_noparent", op_mkdir_noparent}, {"makedirs_through_file", op_makedirs_through_file},
    {"makedirs_exists", op_makedirs_exists}, {"replace_missing", op_replace_missing}, {"rename_exists", op_rename_exists},
    {"stat_missing", op_stat_missing}, {"getsize_missing", op_getsize_missing}, {"getmtime_missing", op_getmtime_missing},
    {"chdir_missing", op_chdir_missing}, {"readlink_plain", op_readlink_plain}, {"utime_missing", op_utime_missing},
    {"chmod_missing", op_chmod_missing}, {"copyfile_missing", op_copyfile_missing}, {"copyfile_same", op_copyfile_same},
    {"copyfile_to_dir", op_copyfile_to_dir}, {"copy2_missing", op_copy2_missing}, {"rmtree_missing", op_rmtree_missing},
    {"rmtree_junction", op_rmtree_junction}, {"copytree_missing", op_copytree_missing}, {"copytree_exists", op_copytree_exists},
    {"relpath_empty", op_relpath_empty}, {"relpath_mounts", op_relpath_mounts}, {"commonpath_empty", op_commonpath_empty},
    {"commonpath_mixed", op_commonpath_mixed}, {"symlink_exists", op_symlink_exists}, {"rmtree_readonly", op_rmtree_readonly},
};

DK_TEST(realpath_and_pathlib_glob) {
    make_tree();
    int bad = 0;
    for (size_t i = 0; i < DK_ARRAY_LEN(k_realpath); i++) {
        const char *in = k_realpath[i].in;
        char *q = at(in, false);
        if (strncmp(in, "@UPPER", 6) == 0) { /* the root in upper case, as the generator tested it */
            size_t rl = strlen(g_root);
            char *up = (char *)dk_alloc_noz(g_a, rl + strlen(in) + 1);
            for (size_t j = 0; j < rl; j++) up[j] = (char)toupper((unsigned char)g_root[j]);
            strcpy(up + rl, in + 6);
            q = up;
        }
        char *rp = dk_path_realpath(g_a, q), *rs = dk_pl_resolve(g_a, q);
        const char *w1 = at(k_realpath[i].realpath, false), *w2 = at(k_realpath[i].resolve, false);
        if (strcmp(rp, w1) != 0 || strcmp(rs, w2) != 0) {
            bad++;
            dk_test__fail(__FILE__, __LINE__, "realpath(%s): got [%s] / resolve [%s], want [%s] / [%s]", q, rp, rs, w1, w2);
        }
    }
    CHECK(bad == 0);
    bad = 0;
    for (size_t i = 0; i < DK_ARRAY_LEN(k_plglob); i++) {
        for (int rec = 0; rec < 2; rec++) {
            DkStrVec r = rec ? dk_pl_rglob(g_a, g_root, k_plglob[i].pattern) : dk_pl_glob(g_a, g_root, k_plglob[i].pattern);
            for (size_t k = 0; k < r.n; k++) { /* the pathlib results are sorted by the caller: by str, as sorted(Path) would */
                for (size_t m = k; m > 0 && dk_pl_cmp(r.v[m].p, r.v[m - 1].p) < 0; m--) { DkStr t = r.v[m]; r.v[m] = r.v[m - 1]; r.v[m - 1] = t; }
            }
            /* Python sorted() above compared the str() text; compare as sets by joining in the C order after a text sort */
            for (size_t k = 1; k < r.n; k++)
                for (size_t m = k; m > 0 && strcmp(r.v[m].p, r.v[m - 1].p) < 0; m--) { DkStr t = r.v[m]; r.v[m] = r.v[m - 1]; r.v[m - 1] = t; }
            const char *got = join_vec(&r, ''), *want = at(rec ? k_plglob[i].rglob : k_plglob[i].glob, false);
            if (strcmp(got, want) != 0 && bad++ < 6)
                dk_test__fail(__FILE__, __LINE__, "%sglob(%s): got [%s] want [%s]", rec ? "r" : "", k_plglob[i].pattern, got, want);
            dk_vec_free(&r);
        }
    }
    CHECK(bad == 0);
    drop_tree();
}

DK_TEST(error_messages_match_python) {
    make_tree();
    dk_makedirs(rel("copy_out"), false);
    int bad = 0;
    for (size_t i = 0; i < DK_ARRAY_LEN(k_errors); i++) {
        const ErrOp *op = NULL;
        for (size_t k = 0; k < DK_ARRAY_LEN(k_ops); k++)
            if (strcmp(k_ops[k].name, k_errors[i].name) == 0) op = &k_ops[k];
        if (!op) {
            if (strcmp(k_errors[i].name, "open_dir") != 0) { dk_test__fail(__FILE__, __LINE__, "no C op for %s", k_errors[i].name); bad++; }
            continue;
        }
        dk_io_clear();
        bool ok = op->fn();
        if (ok) {
            dk_test__fail(__FILE__, __LINE__, "%s: succeeded, Python raised %s", op->name, k_errors[i].cls);
            bad++;
            continue;
        }
        const char *cls = dk_io_err_class();
        char *text = (char *)dk_io_err_str(g_a).p;
        const char *want = at(k_errors[i].text, true);
        if (strcmp(cls, k_errors[i].cls) != 0 || strcmp(text, want) != 0) {
            dk_test__fail(__FILE__, __LINE__, "%s: got %s [%s] want %s [%s]", op->name, cls, text, k_errors[i].cls, want);
            bad++;
        }
    }
    CHECK(bad == 0);
    drop_tree();
}

DK_TEST(rmtree_keeps_junction_targets) {
    make_tree();
    /* a tree with a junction to sub: removing it removes the junction only */
    put("rm1\\file.txt", "x");
    put("rm1\\inner\\f2.txt", "y");
    CHECK(dk_junction_create(rel("rm1\\link"), rel("sub")));
    CHECK(dk_rmtree(rel("rm1"), 0));
    CHECK(!dk_exists(rel("rm1")));
    CHECK(dk_isfile(rel("sub\\x.cpp")) && dk_isfile(rel("sub\\deep\\z.cpp")));
    /* a read-only file stops rmtree like Python, then the clear-read-only mode removes it */
    CHECK(!dk_rmtree(rel("rodir"), 0));
    CHECK(dk_isfile(rel("rodir\\f.txt")));
    CHECK(dk_rmtree(rel("rodir"), DK_RMTREE_CLEAR_READONLY));
    CHECK(!dk_exists(rel("rodir")));
    /* ignore_errors leaves what it cannot remove */
    put("ro2\\f.txt", "x");
    CHECK(dk_chmod(rel("ro2\\f.txt"), 0400));
    CHECK(dk_rmtree(rel("ro2"), DK_RMTREE_IGNORE_ERRORS));
    CHECK(dk_exists(rel("ro2\\f.txt")));
    CHECK(dk_rmtree(rel("nope"), DK_RMTREE_IGNORE_ERRORS));
    drop_tree();
}

DK_TEST(copy_functions) {
    make_tree();
    char *a = rel("a.txt");
    CHECK(dk_utime_ns(a, 1700000000123456789LL, 1700000001987654321LL));
    CHECK(dk_copyfile(a, rel("c1.txt")));
    DkBytes b;
    CHECK(dk_read_all(g_a, rel("c1.txt"), &b) && b.n == 3 && memcmp(b.v, "abc", 3) == 0);
    DkStat st;
    CHECK(dk_copy2(a, rel("c2.txt")));
    CHECK(dk_stat(rel("c2.txt"), &st) && st.mtime_ns == k_stat_a.mtime_ns);
    /* copy2 into a folder keeps the base name */
    CHECK(dk_copy2(a, rel("emptydir")));
    CHECK(dk_isfile(rel("emptydir\\a.txt")));
    /* read-only attribute travels with copy2, not with copyfile */
    CHECK(dk_copy2(rel("rodir\\f.txt"), rel("c3.txt")));
    CHECK(dk_stat(rel("c3.txt"), &st) && (st.mode & 0200) == 0);
    CHECK(dk_copyfile(rel("rodir\\f.txt"), rel("c4.txt")));
    CHECK(dk_stat(rel("c4.txt"), &st) && (st.mode & 0200) != 0);
    /* copystat */
    CHECK(dk_copystat(a, rel("c4.txt")));
    CHECK(dk_stat(rel("c4.txt"), &st) && st.mtime_ns == k_stat_a.mtime_ns);
    /* copytree with ignore patterns */
    const char *ign[2] = {"*.CPP", "deep"};
    DkCopytreeOpts o = {ign, 2, false, false};
    CHECK(dk_copytree(rel("sub"), rel("copy_t"), &o));
    if (g_ordered) expect_eq("copytree walk", walk_all(rel("copy_t"), true, false), at(k_copytree_walk, false));
    const char *ign2[1] = {"*.h"};
    DkCopytreeOpts o2 = {ign2, 1, true, false};
    CHECK(dk_copytree(rel("sub"), rel("copy_t"), &o2));
    if (g_ordered) expect_eq("copytree walk 2", walk_all(rel("copy_t"), true, false), at(k_copytree_walk2, false));
    CHECK(!dk_copytree(rel("sub"), rel("copy_t"), &o));
    CHECK(dk_io_is(EEXIST));
    /* move */
    CHECK(dk_move(rel("c1.txt"), rel("moved.txt")));
    CHECK(!dk_exists(rel("c1.txt")) && dk_isfile(rel("moved.txt")));
    drop_tree();
}

DK_TEST(which_matches_python) {
    make_tree();
    put("bin\\tool.exe", "");
    put("bin\\tool2.bat", "");
    put("bin\\plain", "");
    put("bin\\Sub.CMD", "");
    put("bin\\tool.txt", "");
    dk_makedirs(rel("bin\\dironly.exe"), false);
    char *bin = rel("bin");
    char *up = (char *)dk_alloc_noz(g_a, strlen(bin) + 1);
    for (size_t i = 0; bin[i]; i++) up[i] = (char)toupper((unsigned char)bin[i]);
    up[strlen(bin)] = 0;
    char path[4096];
    snprintf(path, sizeof path, "%s;%s;%s", bin, up, rel("nonexistent"));
    char *old_path = dk_getenv(g_a, "PATH"), *old_ext = dk_getenv(g_a, "PATHEXT");
    CHECK(dk_setenv("PATH", path));
    CHECK(dk_setenv("PATHEXT", ".EXE;.BAT;.CMD"));
    char *want = at(k_which, false);
    char *p = want;
    int bad = 0;
    while (*p) {
        char *rs = strchr(p, '\x1e'), *gs = strchr(p, '\x1d');
        size_t cl = (size_t)(rs - p);
        char *cmd = (char *)dk_alloc_noz(g_a, cl + 1);
        memcpy(cmd, p, cl);
        cmd[cl] = 0;
        size_t rl = gs ? (size_t)(gs - rs - 1) : strlen(rs + 1);
        char *exp = (char *)dk_alloc_noz(g_a, rl + 1);
        memcpy(exp, rs + 1, rl);
        exp[rl] = 0;
        char *got = dk_which(g_a, cmd, NULL, NULL);
        if (strcmp(got ? got : "", exp) != 0) {
            bad++;
            dk_test__fail(__FILE__, __LINE__, "which(%s): got [%s] want [%s]", cmd, got ? got : "", exp);
        }
        p = gs ? gs + 1 : rs + 1 + rl;
    }
    CHECK(bad == 0);
    dk_setenv("PATH", old_path ? old_path : "");
    dk_setenv("PATHEXT", old_ext ? old_ext : "");
    drop_tree();
}

DK_TEST_MAIN("fs_dir")
