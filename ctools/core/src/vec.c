// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore vectors: the growth step behind the dk_vec_* macros (heap-backed, doubling, like a Python list's
 * amortised append). */
#include "dk/dk.h"

void dk_vec__grow(void **v, size_t *cap, size_t need, size_t elem) {
    if (need <= *cap) return;
    size_t ncap = *cap < 4 ? 4 : *cap * 2;
    if (ncap < need) ncap = need;
    if (elem && ncap > SIZE_MAX / elem) dk_fatal("out of memory (vector of %zu elements)", ncap);
    *v = dk_xrealloc(*v, ncap * elem);
    *cap = ncap;
}
