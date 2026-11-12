// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Tests of dk_pyintset_copy / dk_pyintset_update / dk_pyintset_or (CPython's set_merge): the iteration order of
 * {f} | A | B | C for 300 generated cases, expected values from CPython 3.14.8 (map_pyintset_or_corpus.h; the
 * generator is a Python snippet: random.Random(20261103), lists of addresses added in order to a set, the listed
 * values discarded afterwards, then list({f} | A | B | C)). */
#include "dk/map.h"
#include "dk/test.h"
#include "map_pyintset_or_corpus.h"

static DkPyIntSet *build(const long long *add, int na, const long long *del, int nd) {
    DkPyIntSet *s = dk_pyintset_new();
    for (int i = 0; i < na; i++) dk_pyintset_add(s, add[i]);
    if (na > 4)
        for (int i = 0; i < nd; i++) dk_pyintset_discard(s, del[i]);
    return s;
}

DK_TEST(pyintset_or_matches_cpython) {
    for (size_t k = 0; k < sizeof or_cases / sizeof or_cases[0]; k++) {
        const OrCase *c = &or_cases[k];
        DkPyIntSet *a = build(c->a, c->na, c->da, c->nda), *b = build(c->b, c->nb, c->db, c->ndb),
                    *cc = build(c->c, c->nc, c->dc, c->ndc);
        DkPyIntSet *lit = dk_pyintset_new();
        dk_pyintset_add(lit, c->f);
        DkPyIntSet *r = dk_pyintset_or(lit, a);
        DkPyIntSet *r2 = dk_pyintset_or(r, b);
        DkPyIntSet *r3 = dk_pyintset_or(r2, cc);
        size_t pos = 0, n = 0;
        i64 m;
        bool ok = dk_pyintset_len(r3) == (size_t)c->nr;
        while (dk_pyintset_next(r3, &pos, &m)) {
            if (n >= (size_t)c->nr || m != c->r[n]) ok = false;
            n++;
        }
        CHECK_MSG(ok && n == (size_t)c->nr, "case %zu", k);
    }
}

DK_TEST_MAIN("map_pyintset_or")
