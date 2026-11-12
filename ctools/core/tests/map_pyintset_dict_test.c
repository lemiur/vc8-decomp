// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Tests of dk_pyintset_from_dict (CPython's set(d) for a dict d: set_update_internal presizes the table for a dict
 * source, which changes the iteration order from set(list) once the dict is larger than the load limit): the order of
 * set(d) and of set(d1) | set(d2) for 300 generated cases, expected values from CPython 3.14.8
 * (map_pyintset_dict_corpus.h; the generator is a Python snippet in its head comment). */
#include "dk/map.h"
#include "dk/test.h"
#include "map_pyintset_dict_corpus.h"

DK_TEST(pyintset_from_dict_matches_cpython) {
    for (size_t k = 0; k < sizeof dict_cases / sizeof dict_cases[0]; k++) {
        const DictCase *c = &dict_cases[k];
        DkI64Vec k1 = {0}, k2 = {0};
        for (int i = 0; i < c->n1; i++) dk_vec_push(&k1, c->k1[i]);
        for (int i = 0; i < c->n2; i++) dk_vec_push(&k2, c->k2[i]);
        DkPyIntSet *s1 = dk_pyintset_from_dict(k1.v, k1.n);
        DkPyIntSet *s2 = dk_pyintset_from_dict(k2.v, k2.n);
        size_t pos = 0, n = 0;
        i64 m;
        bool ok = dk_pyintset_len(s1) == (size_t)c->ne1;
        while (dk_pyintset_next(s1, &pos, &m)) {
            if (n >= (size_t)c->ne1 || m != c->e1[n]) ok = false;
            n++;
        }
        CHECK_MSG(ok && n == (size_t)c->ne1, "set(d) case %zu", k);
        DkPyIntSet *u = dk_pyintset_or(s1, s2);
        pos = 0;
        n = 0;
        ok = dk_pyintset_len(u) == (size_t)c->ne2;
        while (dk_pyintset_next(u, &pos, &m)) {
            if (n >= (size_t)c->ne2 || m != c->e2[n]) ok = false;
            n++;
        }
        CHECK_MSG(ok && n == (size_t)c->ne2, "set(d1) | set(d2) case %zu", k);
        dk_pyintset_free(s1);
        dk_pyintset_free(s2);
        dk_pyintset_free(u);
        dk_vec_free(&k1);
        dk_vec_free(&k2);
    }
}

DK_TEST_MAIN("map_pyintset_dict")
