// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Tests of map.h: Python dict/set insertion-order semantics against a naive model, and DkPyIntSet against the
 * iteration orders CPython 3.14.8 produced (map_pyintset_corpus.h, generator in its comment). */
#include "dk/map.h"
#include "dk/test.h"
#include "map_pyintset_corpus.h"

static u64 lcg_next(u64 *x) {
    *x = *x * 6364136223846793005ull + 1442695040888963407ull;
    return *x;
}

static bool str_is(DkStr s, const char *lit) { return s.n == strlen(lit) && memcmp(s.p, lit, s.n) == 0; }

DK_TEST(map_basic) {
    DkMap *m = dk_map_new();
    CHECK_EQ_U64(dk_map_len(m), 0);
    CHECK(dk_map_get(m, DK_S("a")) == NULL);
    CHECK(!dk_map_del(m, DK_S("a")));
    bool created = false;
    dk_map_put(m, DK_S("a"), &created)->i = 1;
    CHECK(created);
    dk_map_put(m, DK_S("b"), &created)->i = 2;
    dk_map_put(m, DK_S("c"), NULL)->i = 3;
    CHECK_EQ_U64(dk_map_len(m), 3);
    dk_map_put(m, DK_S("a"), &created)->i += 10; /* Counter: updating keeps the position */
    CHECK(!created);
    CHECK_EQ_I64(dk_map_get(m, DK_S("a"))->i, 11);
    CHECK(dk_map_has(m, DK_S("b")) && !dk_map_has(m, DK_S("d")));

    /* delete then reinsert goes to the end, as in a dict */
    CHECK(dk_map_del(m, DK_S("a")));
    CHECK(!dk_map_del(m, DK_S("a")));
    dk_map_put(m, DK_S("a"), &created)->i = 5;
    CHECK(created);
    const char *want[] = {"b", "c", "a"};
    DkMapIter it = {0};
    size_t i = 0;
    while (dk_map_next(m, &it)) {
        REQUIRE(i < 3);
        CHECK(str_is(it.key, want[i]));
        i++;
    }
    CHECK_EQ_U64(i, 3);
    DkStrVec keys = dk_map_keys(m);
    CHECK_EQ_U64(keys.n, 3);
    CHECK(str_is(keys.v[2], "a"));
    dk_vec_free(&keys);
    dk_map_clear(m);
    CHECK_EQ_U64(dk_map_len(m), 0);
    CHECK(!dk_map_has(m, DK_S("b")));
    dk_map_put(m, DK_S("z"), NULL)->i = 1;
    CHECK_EQ_U64(dk_map_len(m), 1);
    dk_map_free(m);
}

DK_TEST(map_keys_are_copied_and_binary_safe) {
    DkMap *m = dk_map_new();
    char buf[8] = {'k', 'e', 'y', 0, 'x', 0, 0, 0};
    dk_map_put(m, dk_strn(buf, 5), NULL)->i = 1; /* "key\0x" */
    dk_map_put(m, dk_strn(buf, 3), NULL)->i = 2; /* "key" */
    dk_map_put(m, dk_strn(buf, 0), NULL)->i = 3; /* "" */
    dk_map_put(m, dk_strn(NULL, 0), NULL)->i += 10; /* the same empty key */
    memset(buf, 'Z', sizeof buf);                    /* the map must not depend on the caller's buffer */
    CHECK_EQ_U64(dk_map_len(m), 3);
    CHECK_EQ_I64(dk_map_get(m, dk_strn("key\0x", 5))->i, 1);
    CHECK_EQ_I64(dk_map_get(m, DK_S("key"))->i, 2);
    CHECK_EQ_I64(dk_map_get(m, DK_S(""))->i, 13);
    CHECK(dk_map_get(m, dk_strn("key\0y", 5)) == NULL);
    DkMapIter it = {0};
    CHECK(dk_map_next(m, &it));
    CHECK(it.key.n == 5 && memcmp(it.key.p, "key\0x", 5) == 0 && it.key.p[5] == 0);
    dk_map_free(m);
}

/* ---- model-based tests ---- */
typedef struct {
    char key[40];
    size_t len;
    i64 val;
    bool live;
} ModelEntry;

typedef struct {
    ModelEntry *e;
    size_t n, cap;
} Model;

static ModelEntry *model_find(Model *m, const char *k, size_t len) {
    for (size_t i = 0; i < m->n; i++)
        if (m->e[i].live && m->e[i].len == len && memcmp(m->e[i].key, k, len) == 0) return &m->e[i];
    return NULL;
}

static void make_key(char *buf, size_t *len, u64 r, u64 range) {
    u64 id = (r >> 33) % range;
    *len = (size_t)snprintf(buf, 40, "k%llu_%s", (unsigned long long)id, (id % 3 == 0) ? "a_longer_suffix_for_hashing" : "");
}

DK_TEST(map_model_random_ops) {
    for (u64 range = 5; range <= 3000; range *= 7) {
        u64 x = range * 12345;
        DkMap *m = dk_map_new();
        Model model = {0};
        model.cap = 40000;
        model.e = dk_xcalloc(model.cap, sizeof(ModelEntry));
        size_t nlive = 0;
        for (int step = 0; step < 20000; step++) {
            u64 r = lcg_next(&x);
            char k[40];
            size_t len;
            make_key(k, &len, r, range);
            DkStr key = dk_strn(k, len);
            ModelEntry *me = model_find(&model, k, len);
            switch ((r >> 20) & 3) {
            case 0:
            case 1: { /* put / increment */
                bool created;
                DkVal *v = dk_map_put(m, key, &created);
                CHECK(created == (me == NULL));
                if (me) {
                    me->val++;
                    v->i++;
                } else {
                    REQUIRE(model.n < model.cap);
                    ModelEntry *ne = &model.e[model.n++];
                    memcpy(ne->key, k, len);
                    ne->len = len;
                    ne->val = (i64)step;
                    ne->live = true;
                    v->i = (i64)step;
                    nlive++;
                }
                break;
            }
            case 2: { /* delete */
                bool had = dk_map_del(m, key);
                CHECK(had == (me != NULL));
                if (me) {
                    me->live = false;
                    nlive--;
                }
                break;
            }
            default: { /* lookup */
                DkVal *v = dk_map_get(m, key);
                CHECK((v != NULL) == (me != NULL));
                if (v && me) CHECK_EQ_I64(v->i, me->val);
                break;
            }
            }
            if (step % 500 == 0) {
                CHECK_EQ_U64(dk_map_len(m), nlive);
                DkMapIter it = {0};
                size_t j = 0;
                bool ok = true;
                while (dk_map_next(m, &it)) {
                    while (j < model.n && !model.e[j].live) j++;
                    if (j >= model.n || it.key.n != model.e[j].len || memcmp(it.key.p, model.e[j].key, it.key.n) != 0 ||
                        it.val->i != model.e[j].val)
                        ok = false;
                    j++;
                }
                while (j < model.n && !model.e[j].live) j++;
                CHECK_MSG(ok && j == model.n, "iteration order differs at step %d (range %llu)", step,
                          (unsigned long long)range);
            }
        }
        dk_xfree(model.e);
        dk_map_free(m);
    }
}

DK_TEST(map_many_keys_and_churn) {
    DkMap *m = dk_map_new_cap(10);
    char k[32];
    for (int i = 0; i < 200000; i++) {
        int n = snprintf(k, sizeof k, "key-%d", i);
        dk_map_put(m, dk_strn(k, (size_t)n), NULL)->i = i;
    }
    CHECK_EQ_U64(dk_map_len(m), 200000);
    for (int i = 0; i < 200000; i += 2) {
        int n = snprintf(k, sizeof k, "key-%d", i);
        CHECK(dk_map_del(m, dk_strn(k, (size_t)n)));
    }
    CHECK_EQ_U64(dk_map_len(m), 100000);
    /* churn: the dead entries must be compacted away without losing order */
    for (int round = 0; round < 5; round++)
        for (int i = 0; i < 200000; i += 2) {
            int n = snprintf(k, sizeof k, "key-%d", i);
            dk_map_put(m, dk_strn(k, (size_t)n), NULL)->i = i;
            CHECK(dk_map_del(m, dk_strn(k, (size_t)n)));
        }
    DkMapIter it = {0};
    i64 expect = 1;
    size_t seen = 0;
    while (dk_map_next(m, &it)) {
        CHECK_EQ_I64(it.val->i, expect);
        expect += 2;
        seen++;
    }
    CHECK_EQ_U64(seen, 100000);
    dk_map_free(m);
}

DK_TEST(imap_basic_and_model) {
    DkIMap *m = dk_imap_new_cap(4);
    u64 x = 99;
    u64 order[4000];
    bool live[4000];
    i64 vals[4000];
    size_t n = 0, nlive = 0;
    for (int step = 0; step < 30000; step++) {
        u64 r = lcg_next(&x);
        u64 key = ((r >> 33) % 1500) * 0x100000001ull; /* keys with equal low halves */
        size_t at = n;
        for (size_t i = 0; i < n; i++)
            if (live[i] && order[i] == key) at = i;
        switch ((r >> 20) & 3) {
        case 0:
        case 1: {
            bool created;
            DkVal *v = dk_imap_put(m, key, &created);
            CHECK(created == (at == n));
            if (at == n) {
                if (n < 4000) {
                    order[n] = key;
                    live[n] = true;
                    vals[n] = step;
                    n++;
                    nlive++;
                }
                v->i = step;
            } else {
                v->i++;
                vals[at]++;
            }
            if (n == 4000) { /* the model is full: restart both */
                dk_imap_clear(m);
                n = nlive = 0;
            }
            break;
        }
        case 2:
            CHECK(dk_imap_del(m, key) == (at != n));
            if (at != n) {
                live[at] = false;
                nlive--;
            }
            break;
        default:
            CHECK(dk_imap_has(m, key) == (at != n));
            break;
        }
    }
    CHECK_EQ_U64(dk_imap_len(m), nlive);
    DkIMapIter it = {0};
    size_t j = 0;
    bool ok = true;
    while (dk_imap_next(m, &it)) {
        while (j < n && !live[j]) j++;
        if (j >= n || it.key != order[j] || it.val->i != vals[j]) ok = false;
        j++;
    }
    CHECK(ok);
    dk_imap_free(m);
}

DK_TEST(sets) {
    DkSet *s = dk_set_new();
    CHECK(dk_set_add(s, DK_S("pear")));
    CHECK(dk_set_add(s, DK_S("apple")));
    CHECK(!dk_set_add(s, DK_S("pear")));
    CHECK(dk_set_add(s, DK_S("fig")));
    CHECK(dk_set_has(s, DK_S("fig")) && !dk_set_has(s, DK_S("kiwi")));
    CHECK(dk_set_del(s, DK_S("apple")) && !dk_set_del(s, DK_S("apple")));
    CHECK_EQ_U64(dk_set_len(s), 2);
    size_t pos = 0;
    DkStr m;
    CHECK(dk_set_next(s, &pos, &m) && str_is(m, "pear"));
    CHECK(dk_set_next(s, &pos, &m) && str_is(m, "fig"));
    CHECK(!dk_set_next(s, &pos, &m));
    dk_set_add(s, DK_S("banana"));
    dk_set_add(s, DK_S(""));
    DkStrVec sorted = dk_set_sorted(s);
    REQUIRE(sorted.n == 4);
    CHECK(str_is(sorted.v[0], "") && str_is(sorted.v[1], "banana") && str_is(sorted.v[2], "fig") &&
          str_is(sorted.v[3], "pear"));
    dk_vec_free(&sorted);
    dk_set_free(s);

    DkISet *is = dk_iset_new();
    CHECK(dk_iset_add(is, 30) && dk_iset_add(is, 10) && dk_iset_add(is, 20) && !dk_iset_add(is, 10));
    CHECK(dk_iset_has(is, 20) && !dk_iset_has(is, 21));
    CHECK(dk_iset_del(is, 10) && !dk_iset_del(is, 10));
    CHECK(dk_iset_add(is, 10)); /* back at the end */
    size_t p = 0;
    u64 v;
    CHECK(dk_iset_next(is, &p, &v) && v == 30);
    CHECK(dk_iset_next(is, &p, &v) && v == 20);
    CHECK(dk_iset_next(is, &p, &v) && v == 10);
    CHECK(!dk_iset_next(is, &p, &v));
    dk_iset_add(is, 0);
    dk_iset_add(is, (u64)-1);
    DkU64Vec su = dk_iset_sorted(is);
    REQUIRE(su.n == 5);
    CHECK(su.v[0] == 0 && su.v[1] == 10 && su.v[2] == 20 && su.v[3] == 30 && su.v[4] == (u64)-1);
    dk_vec_free(&su);
    dk_iset_free(is);
}

/* ---- DkPyIntSet against CPython ---- */
static u64 fnv_fold(u64 h, u64 x) { return (h ^ x) * 0x100000001b3ull; }

static i64 pis_value(u64 r, const PisScenario *sc) {
    u64 v = (r >> 33) % sc->mod;
    if (sc->collide) return ((i64)(v % 6) - 2) * (i64)(((u64)1 << 61) - 1) + (i64)((v / 6) % 40);
    return (i64)v + sc->off;
}

static void run_scenario(size_t index) {
    const PisScenario *sc = &pis_scenarios[index];
    u64 x = sc->seed;
    u64 h = 0xcbf29ce484222325ull;
    DkPyIntSet *s;
    if (sc->mode == 'L') {
        i64 *vals = dk_xmalloc((sc->count + 1) * sizeof(i64));
        for (u32 i = 0; i < sc->count; i++) vals[i] = pis_value(lcg_next(&x), sc);
        s = dk_pyintset_from(vals, sc->count);
        dk_xfree(vals);
    } else {
        s = dk_pyintset_new();
        for (u32 i = 0; i < sc->count; i++) {
            u64 r = lcg_next(&x);
            i64 v = pis_value(r, sc);
            if (((r >> 20) & 255) < sc->addprob) {
                size_t before = dk_pyintset_len(s);
                dk_pyintset_add(s, v);
                h = fnv_fold(h, dk_pyintset_len(s) - before);
            } else {
                h = fnv_fold(h, 2 + (dk_pyintset_has(s, v) ? 1 : 0));
                dk_pyintset_discard(s, v);
            }
        }
    }
    for (int i = 0; i < 200; i++) h = fnv_fold(h, dk_pyintset_has(s, pis_value(lcg_next(&x), sc)) ? 1 : 0);
    size_t pos = 0, n = 0;
    i64 m;
    bool first_ok = true;
    while (dk_pyintset_next(s, &pos, &m)) {
        if (n < sc->nfirst && sc->first[n] != m) first_ok = false;
        h = fnv_fold(h, (u64)m);
        n++;
    }
    h = fnv_fold(h, dk_pyintset_len(s));
    CHECK_MSG(n == sc->len && dk_pyintset_len(s) == sc->len, "scenario %zu: length %zu, expected %zu", index, n, sc->len);
    CHECK_MSG(first_ok, "scenario %zu: first elements in the wrong order", index);
    CHECK_MSG(h == sc->hash, "scenario %zu (mode %c, count %u, mod %llu): checksum differs", index, sc->mode, sc->count,
              (unsigned long long)sc->mod);
    dk_pyintset_free(s);
}

DK_TEST(pyintset_corpus_from_list) {
    for (size_t i = 0; i < DK_ARRAY_LEN(pis_scenarios); i++)
        if (pis_scenarios[i].mode == 'L') run_scenario(i);
}

DK_TEST(pyintset_corpus_add_discard) {
    for (size_t i = 0; i < DK_ARRAY_LEN(pis_scenarios); i++)
        if (pis_scenarios[i].mode == 'O') run_scenario(i);
}

DK_TEST(pyintset_known_orders) {
    /* python -c "print(list(set([5,3,8,1])), list(set([-1,-2])), list(set([16,8,0])))" gives
     * [8, 1, 3, 5] [-1, -2] [16, 8, 0]: 8 lands in slot 0, hash(-1) is -2 */
    DkPyIntSet *s = dk_pyintset_new();
    i64 in[] = {5, 3, 8, 1};
    for (int i = 0; i < 4; i++) dk_pyintset_add(s, in[i]);
    size_t pos = 0;
    i64 v;
    i64 want[] = {8, 1, 3, 5};
    for (int i = 0; i < 4; i++) {
        REQUIRE(dk_pyintset_next(s, &pos, &v));
        CHECK_EQ_I64(v, want[i]);
    }
    CHECK(!dk_pyintset_next(s, &pos, &v));
    dk_pyintset_free(s);
    s = dk_pyintset_new();
    dk_pyintset_add(s, -1);
    dk_pyintset_add(s, -2);
    pos = 0;
    CHECK(dk_pyintset_next(s, &pos, &v) && v == -1);
    CHECK(dk_pyintset_next(s, &pos, &v) && v == -2);
    dk_pyintset_free(s);
    s = dk_pyintset_from(in, 4);
    CHECK(dk_pyintset_has(s, 8) && !dk_pyintset_has(s, 9));
    CHECK(dk_pyintset_discard(s, 8) && !dk_pyintset_discard(s, 8));
    CHECK_EQ_U64(dk_pyintset_len(s), 3);
    dk_pyintset_free(s);
}

DK_TEST_MAIN("map")
