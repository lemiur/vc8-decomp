// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Arena, vector and allocator tests. */
#include "dk/dk.h"
#include "dk/test.h"

#include <windows.h>

DK_TEST(alloc_alignment_and_zero) {
    DkArena *a = dk_arena_new(4096);
    for (size_t n = 0; n < 300; n++) {
        u8 *p = (u8 *)dk_alloc(a, n);
        REQUIRE(p != NULL);
        CHECK(((uintptr_t)p & 15) == 0);
        for (size_t i = 0; i < n; i++) CHECK(p[i] == 0);
        memset(p, 0xAB, n);
    }
    dk_arena_free(a);
}

DK_TEST(alloc_zero_gives_unique_pointers) {
    DkArena *a = dk_arena_new(0);
    void *p = dk_alloc(a, 0), *q = dk_alloc(a, 0);
    CHECK(p != NULL && q != NULL && p != q);
    dk_arena_free(a);
}

DK_TEST(default_arena_virtual_blocks_are_zero) {
    DkArena *a = dk_arena_new(0);
    for (int round = 0; round < 40; round++) {
        u8 *p = (u8 *)dk_alloc(a, 100000);
        for (size_t i = 0; i < 100000; i += 997) CHECK(p[i] == 0);
        memset(p, 0xCD, 100000);
    }
    dk_arena_free(a);
}

DK_TEST(mark_reset_reuses_and_rezeroes) {
    DkArena *a = dk_arena_new(0);
    u8 *keep = (u8 *)dk_alloc(a, 64);
    memset(keep, 1, 64);
    DkArenaMark m = dk_arena_mark(a);
    u8 *x = (u8 *)dk_alloc(a, 1000);
    memset(x, 0x77, 1000);
    dk_arena_reset(a, m);
    u8 *y = (u8 *)dk_alloc(a, 1000);
    CHECK(y == x);
    for (int i = 0; i < 1000; i++) CHECK(y[i] == 0);
    for (int i = 0; i < 64; i++) CHECK(keep[i] == 1);
    dk_arena_free(a);
}

DK_TEST(reset_frees_later_blocks) {
    DkArena *a = dk_arena_new(4096);
    void *first = dk_alloc(a, 100);
    DkArenaMark m = dk_arena_mark(a);
    for (int i = 0; i < 200; i++) memset(dk_alloc(a, 1500), 0x11, 1500);
    dk_arena_reset(a, m);
    void *again = dk_alloc(a, 100);
    CHECK((u8 *)again == (u8 *)first + 112);
    dk_arena_free(a);
}

DK_TEST(big_requests_get_own_block_and_reset_frees_them) {
    DkArena *a = dk_arena_new(4096);
    u8 *small1 = (u8 *)dk_alloc(a, 32);
    u8 *big1 = (u8 *)dk_alloc(a, 100000); /* before the mark: survives the reset */
    memset(big1, 5, 100000);
    DkArenaMark m = dk_arena_mark(a);
    u8 *big2 = (u8 *)dk_alloc(a, 50000);
    memset(big2, 6, 50000);
    dk_arena_reset(a, m);
    CHECK(big1[0] == 5 && big1[99999] == 5);
    CHECK(small1 != NULL);
    /* Many cycles must not leak or crash. */
    for (int i = 0; i < 100; i++) {
        DkArenaMark mm = dk_arena_mark(a);
        memset(dk_alloc(a, 70000), 9, 70000);
        memset(dk_alloc(a, 10), 9, 10);
        dk_arena_reset(a, mm);
    }
    CHECK(big1[50000] == 5);
    dk_arena_free(a);
}

DK_TEST(realloc_grows_in_place_when_last) {
    DkArena *a = dk_arena_new(0);
    char *p = (char *)dk_alloc(a, 16);
    memcpy(p, "0123456789abcde", 16);
    char *q = (char *)dk_arena_realloc(a, p, 16, 5000);
    CHECK(q == p);
    CHECK_MEM(q, "0123456789abcde", 16);
    for (int i = 16; i < 5000; i++) q[i] = 'x';
    char *other = (char *)dk_alloc(a, 8);
    CHECK(other != NULL);
    char *r = (char *)dk_arena_realloc(a, q, 5000, 9000);
    CHECK(r != q); /* no longer the last allocation: moved */
    CHECK_MEM(r, "0123456789abcde", 16);
    CHECK(r[4999] == 'x');
    char *s = (char *)dk_arena_realloc(a, r, 9000, 8);
    CHECK(s == r);
    dk_arena_free(a);
}

DK_TEST(realloc_null_and_block_overflow) {
    DkArena *a = dk_arena_new(4096);
    char *p = (char *)dk_arena_realloc(a, NULL, 0, 100);
    CHECK(p != NULL);
    memset(p, 'a', 100);
    p = (char *)dk_arena_realloc(a, p, 100, 1000);
    p = (char *)dk_arena_realloc(a, p, 1000, 1900);
    p = (char *)dk_arena_realloc(a, p, 1900, 30000); /* grows past a block */
    for (int i = 0; i < 100; i++) CHECK(p[i] == 'a');
    dk_arena_free(a);
}

DK_TEST(string_helpers) {
    DkArena *a = dk_arena_new(0);
    char *s = dk_strdup(a, "hello");
    CHECK_CZ(s, "hello");
    char *f = dk_sprintf(a, "%d-%s-%05.1f", 42, "x", 3.14159);
    CHECK_CZ(f, "42-x-003.1");
    char *big = dk_sprintf(a, "%*s", 5000, "z");
    CHECK(strlen(big) == 5000 && big[4999] == 'z');
    u8 raw[3] = {1, 2, 3};
    u8 *d = (u8 *)dk_memdup(a, raw, 3);
    CHECK_MEM(d, raw, 3);
    CHECK(dk_memdup(a, raw, 0) != NULL);
    dk_arena_free(a);
}

DK_TEST(thread_arenas_are_distinct_and_stable) {
    DkArena *a = dk_arena(), *s = dk_scratch();
    CHECK(a != s);
    CHECK(a == dk_arena());
    CHECK(s == dk_scratch());
    DkArenaMark m = dk_arena_mark(s);
    char *t = dk_strdup(s, "scratch");
    CHECK_CZ(t, "scratch");
    dk_arena_reset(s, m);
}

static DWORD WINAPI thread_main(void *arg) {
    DkArena **out = (DkArena **)arg;
    *out = dk_arena();
    for (int i = 0; i < 1000; i++) memset(dk_alloc(*out, 5000), 1, 5000);
    return 0;
}

DK_TEST(thread_local_arena_per_thread) {
    DkArena *other = NULL;
    HANDLE h = CreateThread(NULL, 0, thread_main, &other, 0, NULL);
    REQUIRE(h != NULL);
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    CHECK(other != NULL && other != dk_arena());
}

DK_TEST(vec_push_insert_remove) {
    DkI32Vec v = {0};
    for (i32 i = 0; i < 1000; i++) dk_vec_push(&v, i);
    CHECK_EQ_U64(v.n, 1000);
    CHECK(v.cap >= 1000);
    dk_vec_insert(&v, 0, -1);
    dk_vec_insert(&v, v.n, 5000);
    CHECK_EQ_I64(v.v[0], -1);
    CHECK_EQ_I64(dk_vec_last(&v), 5000);
    dk_vec_remove(&v, 0);
    CHECK_EQ_I64(v.v[0], 0);
    CHECK_EQ_I64(dk_vec_pop(&v), 5000);
    i32 ext[3] = {7, 8, 9};
    dk_vec_extend(&v, ext, 3);
    CHECK_EQ_U64(v.n, 1003);
    CHECK_EQ_I64(v.v[1002], 9);
    dk_vec_clear(&v);
    CHECK_EQ_U64(v.n, 0);
    dk_vec_free(&v);
    CHECK(v.v == NULL && v.cap == 0);
}

DK_TEST(vec_push_zero_and_struct) {
    typedef struct {
        int a;
        double b;
    } Pair;
    DK_VEC(Pair) v = {0};
    Pair *p = dk_vec_push_zero(&v);
    CHECK(p->a == 0 && p->b == 0.0);
    p->a = 3;
    dk_vec_push(&v, ((Pair){4, 2.5}));
    CHECK_EQ_U64(v.n, 2);
    CHECK(v.v[1].b == 2.5 && v.v[0].a == 3);
    dk_vec_reserve(&v, 100000);
    CHECK(v.cap >= 100000 && v.v[0].a == 3);
    dk_vec_free(&v);
}

DK_TEST(xalloc_family) {
    char *p = (char *)dk_xmalloc(0);
    CHECK(p != NULL);
    p = (char *)dk_xrealloc(p, 100);
    memset(p, 1, 100);
    dk_xfree(p);
    int *z = (int *)dk_xcalloc(10, sizeof(int));
    for (int i = 0; i < 10; i++) CHECK(z[i] == 0);
    dk_xfree(z);
    dk_xfree(NULL);
}

DK_TEST_MAIN("arena")
