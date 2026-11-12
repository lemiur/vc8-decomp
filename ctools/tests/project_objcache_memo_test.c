// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* objcache memo tables and a cache shared by threads: several memo instances (standing for several processes: each
 * has its own table and its own append handle) saving into one log at the same time lose no record; a memo over its
 * limit compacts to the keys it used; the typed helpers refuse a blob of another tag; a cache shared by compile
 * threads stores and restores without mixing entries. The corpus is synthetic (generated keys and byte strings). */
#include "dk/dk.h"
#include "dk/test.h"
#include "objcache_internal.h"
#include <windows.h>

typedef struct {
    int id;
    const char *folder;
} Worker;

static DWORD WINAPI memo_worker(void *arg) {
    Worker *w = (Worker *)arg;
    ObjcachePickleMemo *m = objcache_pickle_memo_new("shared", "v1");
    for (int i = 0; i < 200; i++) {
        char key[32];
        sprintf(key, "k%d-%d", w->id, i);
        objcache_pickle_memo_put_i64(m, dk_str(key), w->id * 1000 + i);
        if (i % 50 == 49) objcache_pickle_memo_save(m);
    }
    objcache_pickle_memo_save(m);
    return 0;
}

DK_TEST(memo_concurrent_appends) {
    const char *dir = dk_mkdtemp(dk_arena(), "objcache-memo-", "", NULL);
    REQUIRE(dir != NULL);
    dk_setenv(OBJCACHE_ENV_CACHE, dir);
    enum { N = 6 };
    HANDLE th[N];
    Worker ws[N];
    for (int i = 0; i < N; i++) {
        ws[i].id = i;
        ws[i].folder = dir;
        th[i] = CreateThread(NULL, 0, memo_worker, &ws[i], 0, NULL);
    }
    WaitForMultipleObjects(N, th, TRUE, INFINITE);
    for (int i = 0; i < N; i++) CloseHandle(th[i]);
    ObjcachePickleMemo *reader = objcache_pickle_memo_new("shared", "v1");
    int missing = 0;
    for (int id = 0; id < N; id++)
        for (int i = 0; i < 200; i++) {
            char key[32];
            sprintf(key, "k%d-%d", id, i);
            i64 v = -1;
            if (!objcache_pickle_memo_get_i64(reader, dk_str(key), &v) || v != id * 1000 + i) missing++;
        }
    CHECK_EQ_I64(missing, 0);
    dk_tempdir_cleanup(dir);
}

DK_TEST(memo_limit_compacts_to_used_keys) {
    const char *dir = dk_mkdtemp(dk_arena(), "objcache-memo-", "", NULL);
    REQUIRE(dir != NULL);
    dk_setenv(OBJCACHE_ENV_CACHE, dir);
    ObjcachePickleMemo *a = objcache_pickle_memo_new("lim", "v1");
    for (int i = 0; i < 20; i++) {
        char key[16];
        sprintf(key, "old%d", i);
        objcache_pickle_memo_put_str(a, dk_str(key), DK_S("x"));
    }
    objcache_pickle_memo_save(a);
    ObjcachePickleMemo *b = objcache_pickle_memo_new("lim", "v1");
    objcache_pickle_memo_set_limit(b, 10);
    DkStr v;
    CHECK(objcache_pickle_memo_get_str(b, DK_S("old3"), &v));
    objcache_pickle_memo_put_str(b, DK_S("new"), DK_S("y"));
    objcache_pickle_memo_save(b);
    ObjcachePickleMemo *c = objcache_pickle_memo_new("lim", "v1");
    CHECK(objcache_pickle_memo_get_str(c, DK_S("new"), &v));
    CHECK(objcache_pickle_memo_get_str(c, DK_S("old3"), &v));
    CHECK(!objcache_pickle_memo_get_str(c, DK_S("old4"), &v));
    dk_tempdir_cleanup(dir);
}

DK_TEST(memo_typed_values) {
    const char *dir = dk_mkdtemp(dk_arena(), "objcache-memo-", "", NULL);
    REQUIRE(dir != NULL);
    dk_setenv(OBJCACHE_ENV_CACHE, dir);
    ObjcachePickleMemo *m = objcache_pickle_memo_new("typed", "v1");
    DkStr strs[2] = {DK_S("plain"), DK_S("")};
    u32 idx[3] = {4, 5, 6};
    objcache_pickle_memo_put_strs(m, DK_S("s"), strs, 2);
    objcache_pickle_memo_put_strs(m, DK_S("empty"), NULL, 0);
    objcache_pickle_memo_put_bool(m, DK_S("b"), true);
    objcache_pickle_memo_put_u32s(m, DK_S("u"), idx, 3);
    objcache_pickle_memo_put_str(m, DK_S("t"), DK_S("text"));
    objcache_pickle_memo_save(m);
    ObjcachePickleMemo *r = objcache_pickle_memo_new("typed", "v1");
    DkStrVec sv = {0};
    CHECK(objcache_pickle_memo_get_strs(r, DK_S("s"), &sv) && sv.n == 2);
    CHECK_STR(sv.v[0], "plain");
    CHECK_EQ_U64(sv.v[1].n, 0);
    DkStrVec ev = {0};
    CHECK(objcache_pickle_memo_get_strs(r, DK_S("empty"), &ev) && ev.n == 0); /* () is a stored value */
    bool b = false;
    CHECK(objcache_pickle_memo_get_bool(r, DK_S("b"), &b) && b);
    DkU32Vec uv = {0};
    CHECK(objcache_pickle_memo_get_u32s(r, DK_S("u"), &uv) && uv.n == 3 && uv.v[2] == 6);
    i64 n;
    CHECK(!objcache_pickle_memo_get_i64(r, DK_S("t"), &n)); /* another tag is a miss */
    DkStr missing;
    CHECK(!objcache_pickle_memo_get_str(r, DK_S("nokey"), &missing));
    dk_tempdir_cleanup(dir);
}

typedef struct {
    ObjcacheObjCache *cache;
    const char *root, *build;
    int id;
    int failures;
} StoreJob;

static DWORD WINAPI store_worker(void *arg) {
    StoreJob *j = (StoreJob *)arg;
    DkArena *a = dk_arena();
    for (int round = 0; round < 15; round++) {
        const char *obj = dk_join(a, j->build, dk_sprintf(a, "u%d.obj", j->id));
        char body[64];
        int n = sprintf(body, "object %d round %d", j->id, round);
        FILE *f = fopen(obj, "wb");
        fwrite(body, 1, (size_t)n, f);
        fclose(f);
        const char *src = dk_join(a, j->root, dk_sprintf(a, "units/src%d.cpp", j->id));
        const char *opts[1] = {"/c"};
        const char *key = objcache_obj_cache_key(j->cache, opts, 1, src);
        objcache_obj_cache_store(j->cache, key, obj, j->root, DK_S("Note: including file: units/shared.h\n"),
                                 DK_S(""));
        dk_remove(obj);
        DkStr text;
        if (!objcache_obj_cache_lookup(j->cache, key, obj, &text)) j->failures++;
        DkBytes got = {0};
        if (!dk_read_all(a, obj, &got) || got.n != (size_t)n || memcmp(got.v, body, got.n) != 0) j->failures++;
    }
    return 0;
}

DK_TEST(cache_shared_by_threads) {
    const char *dir = dk_mkdtemp(dk_arena(), "objcache-thr-", "", NULL);
    REQUIRE(dir != NULL);
    const char *root = dk_join(dk_arena(), dir, "checkout");
    dk_makedirs(dk_join(dk_arena(), root, "units"), true);
    const char *build = dk_join(dk_arena(), root, "build");
    dk_makedirs(build, true);
    dk_write_file(dk_join(dk_arena(), root, "units/shared.h"), "int s;\n", 7);
    enum { N = 6 };
    for (int i = 0; i < N; i++) {
        const char *s = dk_join(dk_arena(), root, dk_sprintf(dk_arena(), "units/src%d.cpp", i));
        dk_write_file(s, "int x;\n", 7);
    }
    const char *err = NULL;
    ObjcacheObjCache *cache = objcache_obj_cache_new_with(root, dk_join(dk_arena(), dir, "cache"), "", "", "test", &err);
    REQUIRE(cache != NULL);
    {
        static const char *const roots[1] = {"units"};
        objcache_obj_cache_set_unit_roots(cache, roots, 1);
    }
    HANDLE th[N];
    StoreJob jobs[N];
    for (int i = 0; i < N; i++) {
        jobs[i] = (StoreJob){cache, root, build, i, 0};
        th[i] = CreateThread(NULL, 0, store_worker, &jobs[i], 0, NULL);
    }
    WaitForMultipleObjects(N, th, TRUE, INFINITE);
    int bad = 0;
    for (int i = 0; i < N; i++) {
        CloseHandle(th[i]);
        bad += jobs[i].failures;
    }
    CHECK_EQ_I64(bad, 0);
    CHECK_EQ_I64(cache->hits, N * 15);
    dk_tempdir_cleanup(dir);
}

DK_TEST_MAIN("objcache_memo")
