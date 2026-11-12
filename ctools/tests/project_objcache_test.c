// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* objcache against damaged cache files, plus the cache identity and the unit roots (no compiler, no executables
 * needed). A crash can leave a file that was being written zero-filled or cut short (its size reached the disk, its
 * bytes did not). The cache must take every such file for a miss: never fail, never restore its bytes. damaged_files
 * plants each kind of damage in a private cache folder and checks that: a zero-filled, truncated or malformed entry
 * is a miss; an object or link output whose bytes no longer hash to its name is never put in the build folder (it is
 * deleted, and the next store writes it again); a zero-filled or truncated memo starts afresh. identity_files checks
 * that the compiler's identity files and include folders enter the cache identity; unit_roots that the shadow check
 * and the "outside the unit roots" rule follow the configured roots. The corpus is synthetic: byte patterns and
 * made-up file names written to a temporary folder. */
#include "dk/dk.h"
#include "dk/test.h"
#include "objcache_internal.h"
#include <stdio.h>

static void check(bool ok, const char *what) { CHECK_MSG(ok, "%s", what); }
static const char *J(const char *a, const char *b) { return dk_join(dk_arena(), a, b); }

static void write_bytes(const char *path, const void *p, size_t n) {
    if (!dk_write_file(path, p, n)) dk_panic(__FILE__, __LINE__, "cannot write %s", path);
}

static void zero_fill(const char *path) {
    i64 size = 0;
    dk_getsize(path, &size);
    u8 *z = (u8 *)dk_alloc(dk_arena(), (size_t)size + 1);
    DkFile *f = dk_fopen(path, "r+b", DK_TM_UTF8);
    dk_fwrite(f, z, (size_t)size);
    dk_fclose(f);
}

static void truncate_half(const char *path) {
    i64 size = 0;
    dk_getsize(path, &size);
    DkFile *f = dk_fopen(path, "r+b", DK_TM_UTF8);
    dk_ftruncate(f, DK_MAX(1, size / 2));
    dk_fclose(f);
}

typedef void (*DamageFn)(const char *);
static const DamageFn damages[2] = {zero_fill, truncate_half};
static const char *const damage_names[2] = {"zero_fill", "truncate"};

static const char *g_root, *g_folder, *g_compiler_bin;

/* A cache for the checkout of the test, whose unit root is the folder "units". */
static void use_unit_root(ObjcacheObjCache *c) {
    static const char *const roots[1] = {"units"};
    objcache_obj_cache_set_unit_roots(c, roots, 1);
}

static ObjcacheObjCache *fresh(void) {
    const char *err = NULL;
    ObjcacheObjCache *c = objcache_obj_cache_new_with(g_root, g_folder, g_compiler_bin, "", "test", &err);
    if (!c) dk_panic(__FILE__, __LINE__, "cannot make the cache: %s", err);
    use_unit_root(c);
    return c;
}

static DkBytes read_file(const char *path, bool *ok) {
    DkBytes b = {0};
    *ok = dk_read_all(dk_arena(), path, &b);
    return b;
}

static bool file_equals(const char *path, const void *p, size_t n) {
    bool ok;
    DkBytes b = read_file(path, &ok);
    return ok && b.n == n && (n == 0 || memcmp(b.v, p, n) == 0);
}

static const char *g_build;
static u8 g_obj_bytes[256 * 64];

static void compile_and_store(ObjcacheObjCache *cache, const char *key) {
    const char *obj = J(g_build, "unit.obj");
    write_bytes(obj, g_obj_bytes, sizeof g_obj_bytes);
    objcache_obj_cache_store(cache, key, obj, g_root, DK_S("unit.cpp\nNote: including file: units\\include\\unit.h\n"),
                             DK_S("unit.cpp\n"));
}

/* restore(key): (hit, data-or-none) */
static void restore(const char *key, bool *hit, bool *has_data, DkBytes *data) {
    const char *obj = J(g_build, "unit.obj");
    objcache_remove_file(obj);
    DkStr text;
    *hit = objcache_obj_cache_lookup(fresh(), key, obj, &text);
    *has_data = false;
    if (dk_exists(obj)) *data = read_file(obj, has_data);
}

static bool restored_ok(const char *key) {
    bool hit, has;
    DkBytes d = {0};
    restore(key, &hit, &has, &d);
    return hit && has && d.n == sizeof g_obj_bytes && memcmp(d.v, g_obj_bytes, d.n) == 0;
}
static bool missed(const char *key) {
    bool hit, has;
    DkBytes d = {0};
    restore(key, &hit, &has, &d);
    return !hit && !has;
}

static bool all_missing(const char *const *paths, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (dk_exists(paths[i])) return false;
    return true;
}

/* A cache.h container of the entry kind with the given payload, standing in for a malformed JSON entry. */
static void write_entry_container(const char *path, const char *kind, const DkCacheWriter *w) {
    dk_cache_write_w(path, kind, 1, NULL, 0, w);
}

static const char *blob_of(const ObjcacheObjCache *cache, const char *hex, const char *ext) {
    return J(cache->objs, dk_sprintf(dk_arena(), "%s%s", hex, ext));
}

DK_TEST(damaged_files) {
    DkArena *A = dk_arena();
    for (size_t i = 0; i < sizeof g_obj_bytes; i++) g_obj_bytes[i] = (u8)(i % 256);
    dk_unsetenv(OBJCACHE_ENV_CACHE);
    const char *work = dk_mkdtemp(A, "objcache-test-", "", NULL);
    REQUIRE(work != NULL);
    {
        g_root = J(work, "checkout");
        dk_makedirs(J(g_root, "units\\include"), true);
        const char *source = J(g_root, "units\\unit.cpp");
        const char *text1 = "#include \"include/unit.h\"\nint f() { return 1; }\n";
        write_bytes(source, text1, strlen(text1));
        write_bytes(J(g_root, "units\\include\\unit.h"), "int f();\n", 9);
        g_build = J(g_root, "build");
        dk_makedirs(g_build, true);
        g_folder = J(work, "cache");
        g_compiler_bin = J(work, "fake-cl.exe");
        write_bytes(g_compiler_bin, "compiler executable", 19);

        ObjcacheObjCache *cache = fresh();
        const char *opts[2] = {"/c", "/O2"};
        const char *key = objcache_obj_cache_key(cache, opts, 2, source);
        DK_ASSERT(key != NULL);
        compile_and_store(cache, key);
        check(restored_ok(key), "a stored object is restored with its bytes");
        const char *entry = objcache__entry_path(cache, key);
        const char *blob = blob_of(cache, objcache__digest_bytes(g_obj_bytes, sizeof g_obj_bytes), ".obj");
        check(dk_isfile(entry) && dk_isfile(blob), "the entry and the blob are on disk");

        /* damaged entries: a miss, no exception */
        DkBytes good_entry = {0};
        dk_read_all(A, entry, &good_entry);
        for (int d = 0; d < 2; d++) {
            damages[d](entry);
            check(missed(key), dk_sprintf(A, "entry %s: a miss, nothing restored", damage_names[d]));
            write_bytes(entry, good_entry.v, good_entry.n);
        }
        for (int bad = 0; bad < 5; bad++) {
            const char *label = "";
            DkCacheWriter w;
            dk_cw_init(&w);
            const char *kind = OBJCACHE_ENTRY_KIND;
            switch (bad) {
            case 0: /* a record cut short: one entry whose record holds a single u32 */
                label = "a record without its fields";
                dk_cw_count(&w, 1);
                dk_cw_u32(&w, 4);
                dk_cw_u32(&w, 5);
                break;
            case 1: /* not a cache file at all */
                label = "text instead of a cache file";
                dk_cw_cz(&w, "{\"entries\": {\"obj\": \"x\"}}");
                write_bytes(entry, "{\"entries\": {\"obj\": \"x\"}}", 25);
                break;
            case 2: /* a cache file of another kind */
                label = "a file of another kind";
                kind = "objcache/other";
                dk_cw_count(&w, 0);
                break;
            case 3: /* a count larger than the bytes that follow */
                label = "a count past the end";
                dk_cw_count(&w, 1000000);
                break;
            default: /* a well-formed record naming a blob that is not a digest */
            {
                label = "an entry whose object is not a digest";
                dk_cw_count(&w, 1);
                size_t rec = dk_cw_begin(&w);
                dk_cw_count(&w, 1);
                size_t dep = dk_cw_begin(&w);
                dk_cw_cz(&w, "units/include/unit.h");
                dk_cw_cz(&w, "y");
                dk_cw_end(&w, dep);
                dk_cw_count(&w, 0);
                dk_cw_cz(&w, "x");
                dk_cw_cz(&w, "");
                dk_cw_f64(&w, 0.0);
                dk_cw_end(&w, rec);
                break;
            }
            }
            if (bad != 1) write_entry_container(entry, kind, &w);
            dk_cw_free(&w);
            check(missed(key), dk_sprintf(A, "malformed entry (%s): a miss", label));
        }
        write_bytes(entry, good_entry.v, good_entry.n);
        check(restored_ok(key), "the entry put back restores again");

        /* damaged blobs: never restored, deleted, written again by the next store */
        for (int d = 0; d < 2; d++) {
            damages[d](blob);
            check(missed(key), dk_sprintf(A, "blob %s: a miss, nothing restored", damage_names[d]));
            check(!dk_exists(blob), dk_sprintf(A, "blob %s: deleted", damage_names[d]));
            compile_and_store(fresh(), key);
            const char *h = NULL;
            DkStr bn = dk_path_basename(blob);
            check(objcache__digest_file(blob, &h) && bn.n > 4 && memcmp(h, bn.p, bn.n - 4) == 0,
                  dk_sprintf(A, "blob %s: stored again", damage_names[d]));
            check(restored_ok(key), dk_sprintf(A, "blob %s: restored after the new store", damage_names[d]));
        }
        /* a blob damaged while it still exists is rewritten by a store that finds it */
        zero_fill(blob);
        compile_and_store(fresh(), key);
        {
            const char *h = NULL;
            DkStr bn = dk_path_basename(blob);
            check(objcache__digest_file(blob, &h) && memcmp(h, bn.p, bn.n - 4) == 0,
                  "a store rewrites a damaged blob in place");
        }

        /* link outputs */
        cache = fresh();
        const char *outputs[2] = {J(g_build, "group.dll"), J(g_build, "group.map")};
        DkBytes wanted[2];
        for (int i = 0; i < 2; i++) {
            DkBytes body = {0};
            dk_vec_extend(&body, g_obj_bytes + i, sizeof g_obj_bytes - (size_t)i);
            dk_vec_extend(&body, "link", 4);
            write_bytes(outputs[i], body.v, body.n);
            wanted[i] = body;
        }
        const char *link_key = "test-link-key";
        objcache_obj_cache_link_store(cache, link_key, outputs, 2, NULL);
        for (int i = 0; i < 2; i++) dk_remove(outputs[i]);
        {
            DkStr ft;
            bool ok = objcache_obj_cache_link_lookup(fresh(), link_key, outputs, 2, &ft) == OBJCACHE_LINK_HIT &&
                      file_equals(outputs[0], wanted[0].v, wanted[0].n) &&
                      file_equals(outputs[1], wanted[1].v, wanted[1].n);
            check(ok, "a stored link is restored");
        }
        const char *link_blob = blob_of(cache, objcache__digest_bytes(wanted[1].v, wanted[1].n), ".bin");
        for (int d = 0; d < 2; d++) {
            DkStr ft;
            damages[d](link_blob);
            check(objcache_obj_cache_link_lookup(fresh(), link_key, outputs, 2, &ft) == OBJCACHE_LINK_MISS &&
                      all_missing(outputs, 2),
                  dk_sprintf(A, "link blob %s: a miss, no output left", damage_names[d]));
            for (int i = 0; i < 2; i++) write_bytes(outputs[i], wanted[i].v, wanted[i].n);
            objcache_obj_cache_link_store(fresh(), link_key, outputs, 2, NULL);
            for (int i = 0; i < 2; i++) dk_remove(outputs[i]);
            bool ok = objcache_obj_cache_link_lookup(fresh(), link_key, outputs, 2, &ft) == OBJCACHE_LINK_HIT &&
                      file_equals(outputs[0], wanted[0].v, wanted[0].n) &&
                      file_equals(outputs[1], wanted[1].v, wanted[1].n);
            check(ok, dk_sprintf(A, "link blob %s: restored after the new store", damage_names[d]));
        }
        const char *link_entry = objcache__entry_path(cache, dk_sprintf(A, "link-%s", link_key));
        for (int d = 0; d < 2; d++) {
            DkBytes good = {0};
            dk_read_all(A, link_entry, &good);
            DkStr ft;
            damages[d](link_entry);
            check(objcache_obj_cache_link_lookup(fresh(), link_key, outputs, 2, &ft) == OBJCACHE_LINK_MISS,
                  dk_sprintf(A, "link entry %s: a miss", damage_names[d]));
            write_bytes(link_entry, good.v, good.n);
        }

        /* PickleMemo */
        dk_setenv(OBJCACHE_ENV_CACHE, g_folder);
        ObjcachePickleMemo *memo = objcache_pickle_memo_new("test", "v1");
        objcache_pickle_memo_put_i64(memo, DK_S("a"), 1);
        objcache_pickle_memo_save(memo);
        i64 got = 0;
        check(objcache_pickle_memo_get_i64(objcache_pickle_memo_new("test", "v1"), DK_S("a"), &got) && got == 1,
              "a memo answer is read back");
        const char *memo_path = objcache_pickle_memo_path(memo);
        for (int d = 0; d < 2; d++) {
            damages[d](memo_path);
            ObjcachePickleMemo *again = objcache_pickle_memo_new("test", "v1");
            check(!objcache_pickle_memo_get_i64(again, DK_S("a"), &got),
                  dk_sprintf(A, "memo %s: starts afresh", damage_names[d]));
            objcache_pickle_memo_put_i64(again, DK_S("a"), 2);
            objcache_pickle_memo_save(again);
            check(objcache_pickle_memo_get_i64(objcache_pickle_memo_new("test", "v1"), DK_S("a"), &got) && got == 2,
                  dk_sprintf(A, "memo %s: saved again", damage_names[d]));
        }
        /* a valid log of something other than this memo (another kind) */
        dk_log_write_file(memo_path, "objcache/other", 1, "test-v1", 7, NULL, 0);
        check(!objcache_pickle_memo_get_i64(objcache_pickle_memo_new("test", "v1"), DK_S("a"), &got),
              "a memo file that is not this memo's log: afresh");

        /* pruning: least recently used first (a hit touches the blob and its entry), never a young file, stale
         * temporary files deleted, a pruned blob or entry is a miss, once an hour unless forced */
        cache = fresh();
        compile_and_store(cache, key);
        const char *old = blob_of(cache, "0000000000000000000000000000000000000000000000000000000000000000", ".obj");
        {
            u8 x[4096];
            memset(x, 'x', sizeof x);
            write_bytes(old, x, sizeof x);
        }
        const char *tmp = J(cache->objs, "dead.tmp");
        write_bytes(tmp, "t", 1);
        i64 long_ago_ns = (i64)1000000000 * 1000000000;
        const char *aged[4] = {old, tmp, blob, entry};
        for (int i = 0; i < 4; i++) dk_utime_ns(aged[i], long_ago_ns, long_ago_ns);
        bool hit_now, has_now;
        DkBytes dummy = {0};
        restore(key, &hit_now, &has_now, &dummy); /* touches blob and entry: now the most recently used */
        {
            double mb = 0, me = 0;
            dk_getmtime(blob, &mb);
            dk_getmtime(entry, &me);
            check(hit_now && mb > 1000000000.0 && me > 1000000000.0, "a hit touches its blob and its entry");
        }
        ObjcachePruneResult pr;
        bool done = objcache_obj_cache_prune(cache, 0, true, &pr);
        check(done && !dk_exists(old) && !dk_exists(tmp),
              "prune deletes the least recently used file and a stale temporary file");
        check(dk_exists(blob) && dk_exists(entry), "prune keeps files younger than PRUNE_MIN_AGE");
        check(!objcache_obj_cache_prune(cache, 0, false, &pr), "prune runs at most once an hour without force");
        double saved_age = objcache_prune_min_age;
        objcache_prune_min_age = -1;
        objcache_obj_cache_prune(cache, 0, true, &pr);
        objcache_prune_min_age = saved_age;
        check(!dk_exists(blob), "prune to 0 MB deletes every old enough file");
        check(missed(key), "a pruned blob is a miss");
        compile_and_store(fresh(), key);
        check(restored_ok(key), "stored again after the prune");
    }
    dk_tempdir_cleanup(work);
}

static DkCompiler test_compiler(const char *cl, const char *identity_file, const char *include_dir) {
    DkCompiler c;
    memset(&c, 0, sizeof c);
    c.cl = cl;
    if (identity_file) dk_vec_push(&c.identity_files, dk_str(identity_file));
    if (include_dir) dk_vec_push(&c.include, dk_str(include_dir));
    return c;
}

static const char *identity_of(const char *root, const char *folder, const DkCompiler *compiler) {
    const char *err = NULL;
    ObjcacheObjCache *c = objcache_obj_cache_new(root, compiler, folder, &err);
    if (!c) dk_panic(__FILE__, __LINE__, "cannot make the cache: %s", err);
    return c->identity;
}

DK_TEST(identity_files) {
    DkArena *A = dk_arena();
    const char *work = dk_mkdtemp(A, "objcache-ident-", "", NULL);
    REQUIRE(work != NULL);
    const char *folder = J(work, "cache");
    const char *cl = J(work, "cl.exe"), *id = J(work, "front.dll"), *inc = J(work, "inc");
    dk_makedirs(inc, true);
    write_bytes(cl, "cl one", 6);
    write_bytes(id, "front one", 9);
    write_bytes(J(inc, "a.h"), "int a;\n", 7);
    DkCompiler comp = test_compiler(cl, id, inc);

    const char *base = identity_of(work, folder, &comp);
    CHECK(base != NULL && strlen(base) == 64);
    CHECK_CZ(identity_of(work, folder, &comp), base);

    write_bytes(id, "front two", 9);
    CHECK_MSG(strcmp(identity_of(work, folder, &comp), base) != 0, "an identity file's bytes enter the identity");
    write_bytes(id, "front one", 9);
    CHECK_CZ(identity_of(work, folder, &comp), base);

    write_bytes(cl, "cl two", 6);
    CHECK_MSG(strcmp(identity_of(work, folder, &comp), base) != 0, "the compiler executable enters the identity");
    write_bytes(cl, "cl one", 6);

    write_bytes(J(inc, "b.h"), "int b;\n", 7);
    CHECK_MSG(strcmp(identity_of(work, folder, &comp), base) != 0, "the files under the include folders enter it");
    dk_remove(J(inc, "b.h"));
    CHECK_CZ(identity_of(work, folder, &comp), base);

    /* an INCLUDE entry of the environment stands for the include folders */
    DkCompiler by_env = test_compiler(cl, id, NULL);
    dk_vec_push(&by_env.env_names, DK_S("INCLUDE"));
    dk_vec_push(&by_env.env_values, dk_str(inc));
    CHECK_CZ(identity_of(work, folder, &by_env), base);

    /* no compiler: the empty identity of objcache_obj_cache_new_with */
    const char *err = NULL;
    ObjcacheObjCache *none = objcache_obj_cache_new_with(work, folder, "", "", "", &err);
    REQUIRE(none != NULL);
    CHECK_CZ(identity_of(work, folder, NULL), none->identity);
    CHECK_MSG(strcmp(none->identity, base) != 0, "a compiler changes the identity");

    /* the identity is part of the key */
    ObjcacheObjCache *c1 = objcache_obj_cache_new(work, &comp, folder, &err);
    ObjcacheObjCache *c2 = objcache_obj_cache_new(work, NULL, folder, &err);
    REQUIRE(c1 != NULL && c2 != NULL);
    const char *opts[1] = {"/c"};
    const char *src = J(work, "unit.cpp");
    write_bytes(src, "int x;\n", 7);
    const char *k1 = objcache_obj_cache_key(c1, opts, 1, src), *k2 = objcache_obj_cache_key(c2, opts, 1, src);
    CHECK(k1 != NULL && k2 != NULL && strcmp(k1, k2) != 0);
    /* an option outside the safe list makes the compile uncacheable */
    const char *unsafe[1] = {"/Fo:out.obj"};
    CHECK(objcache_obj_cache_key(c1, unsafe, 1, src) == NULL);
    dk_tempdir_cleanup(work);
}

DK_TEST(unit_roots) {
    DkArena *A = dk_arena();
    const char *work = dk_mkdtemp(A, "objcache-roots-", "", NULL);
    REQUIRE(work != NULL);
    const char *root = J(work, "checkout"), *build = J(root, "build"), *folder = J(work, "cache");
    dk_makedirs(J(root, "units\\sub"), true);
    dk_makedirs(J(root, "other"), true);
    dk_makedirs(build, true);
    write_bytes(J(root, "units\\a.h"), "int a;\n", 7);
    write_bytes(J(root, "units\\sub\\a.h"), "int sub_a;\n", 11);
    write_bytes(J(root, "other\\b.h"), "int b;\n", 7);
    write_bytes(J(root, "units\\u.cpp"), "int u;\n", 7);
    const char *obj = J(build, "u.obj");

    const char *err = NULL;
    ObjcacheObjCache *c = objcache_obj_cache_new_with(root, folder, "", "", "t", &err);
    REQUIRE(c != NULL);
    const char *opts[1] = {"/c"};

    /* the default root is "matching": the files of units\ are not covered, so a compile that read them is not
     * cached */
    const char *key = objcache_obj_cache_key(c, opts, 1, J(root, "units\\u.cpp"));
    REQUIRE(key != NULL);
    write_bytes(obj, "obj1", 4);
    objcache_obj_cache_store(c, key, obj, root, DK_S("Note: including file: units\\a.h\n"), DK_S(""));
    CHECK_EQ_I64(c->uncacheable, 1);

    static const char *const roots[1] = {"units/"};
    objcache_obj_cache_set_unit_roots(c, roots, 1);
    objcache_obj_cache_store(c, key, obj, root, DK_S("Note: including file: units\\a.h\n"), DK_S(""));
    CHECK_EQ_I64(c->uncacheable, 1);
    DkStr text;
    dk_remove(obj);
    CHECK(objcache_obj_cache_lookup(c, key, obj, &text));
    CHECK_CZ(objcache_obj_cache_rel(c, obj), "build/u.obj");

    /* the shadow list holds every file of the roots named like a dependency, in both folders */
    const char *deps[1] = {"include/A.H"};
    DkStrVec shadow = objcache_obj_cache_shadow(c, deps, 1);
    REQUIRE(shadow.n == 2);
    CHECK_STR(shadow.v[0], "units/a.h");
    CHECK_STR(shadow.v[1], "units/sub/a.h");

    const char *opts2[2] = {"/c", "/O2"};
    const char *key2 = objcache_obj_cache_key(c, opts2, 2, J(root, "units\\u.cpp"));
    /* a dependency outside the roots makes the compile uncacheable until its folder is a root */
    ObjcacheObjCache *c2 = objcache_obj_cache_new_with(root, folder, "", "", "t", &err);
    objcache_obj_cache_set_unit_roots(c2, roots, 1);
    write_bytes(obj, "obj2", 4);
    objcache_obj_cache_store(c2, key2, obj, root, DK_S("Note: including file: other\\b.h\n"), DK_S(""));
    CHECK_EQ_I64(c2->uncacheable, 1);
    static const char *const both[2] = {"units", "other"};
    objcache_obj_cache_set_unit_roots(c2, both, 2);
    objcache_obj_cache_store(c2, key2, obj, root, DK_S("Note: including file: other\\b.h\n"), DK_S(""));
    CHECK_EQ_I64(c2->uncacheable, 1);
    ObjcacheObjCache *c3 = objcache_obj_cache_new_with(root, folder, "", "", "t", &err);
    objcache_obj_cache_set_unit_roots(c3, both, 2);
    dk_remove(obj);
    CHECK(objcache_obj_cache_lookup(c3, key2, obj, &text));
    /* a file that appears under a root with the name of a dependency invalidates the entries that read it */
    write_bytes(J(root, "units\\b.h"), "int b2;\n", 8);
    ObjcacheObjCache *c4 = objcache_obj_cache_new_with(root, folder, "", "", "t", &err);
    objcache_obj_cache_set_unit_roots(c4, both, 2);
    dk_remove(obj);
    CHECK_MSG(!objcache_obj_cache_lookup(c4, key2, obj, &text), "a new file named like a dependency is a miss");

    /* an object that names a folder of the checkout under a root is kept under the rooted key */
    ObjcacheObjCache *c5 = objcache_obj_cache_new_with(root, folder, "", "", "t", &err);
    objcache_obj_cache_set_unit_roots(c5, roots, 1);
    char body[512];
    int n = sprintf(body, "debug info: %s\\units\\u.cpp", root);
    write_bytes(obj, body, (size_t)n);
    const char *key5 = objcache_obj_cache_key(c5, opts, 1, J(root, "units\\a.h"));
    REQUIRE(key5 != NULL);
    objcache_obj_cache_store(c5, key5, obj, root, DK_S("Note: including file: units\\a.h\n"), DK_S(""));
    CHECK(!dk_isfile(objcache__entry_path(c5, key5)));
    CHECK(dk_isfile(objcache__entry_path(c5, objcache_obj_cache_rooted(c5, key5))));
    dk_remove(obj);
    CHECK(objcache_obj_cache_lookup(c5, key5, obj, &text));
    dk_tempdir_cleanup(work);
}

DK_TEST_MAIN("project_objcache")
