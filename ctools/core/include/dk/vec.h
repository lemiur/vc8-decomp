// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Typed dynamic arrays (heap-backed, grow by doubling). A vector is a struct { T *v; size_t n, cap; }; a zeroed
 * one is empty and valid. The macros take a pointer to the vector.
 *     DkStrVec names = {0};
 *     dk_vec_push(&names, dk_str("x"));
 *     for (size_t i = 0; i < names.n; i++) use(names.v[i]);
 * Vectors are not thread-safe; free them with dk_vec_free (or never, in a short-lived tool). */
#pragma once
#include "base.h"

#define DK_VEC(T) \
    struct {       \
        T *v;      \
        size_t n;  \
        size_t cap; \
    }

/* Makes room for need elements of size elem (internal). */
void dk_vec__grow(void **v, size_t *cap, size_t need, size_t elem);

#define dk_vec_reserve(vp, count) \
    dk_vec__grow((void **)&(vp)->v, &(vp)->cap, (count), sizeof(*(vp)->v))
#define dk_vec_push(vp, x) \
    (dk_vec_reserve((vp), (vp)->n + 1), (vp)->v[(vp)->n++] = (x))
/* Appends a zeroed element and returns a pointer to it. */
#define dk_vec_push_zero(vp) \
    (dk_vec_reserve((vp), (vp)->n + 1), memset(&(vp)->v[(vp)->n], 0, sizeof(*(vp)->v)), &(vp)->v[(vp)->n++])
#define dk_vec_pop(vp) ((vp)->v[--(vp)->n])
#define dk_vec_last(vp) ((vp)->v[(vp)->n - 1])
#define dk_vec_clear(vp) ((vp)->n = 0)
#define dk_vec_free(vp) (dk_xfree((vp)->v), (vp)->v = NULL, (vp)->n = (vp)->cap = 0)
/* Python list.insert(i, x) for 0 <= i <= n, and del list[i]. */
#define dk_vec_insert(vp, i, x)                                                                   \
    (dk_vec_reserve((vp), (vp)->n + 1),                                                            \
     memmove(&(vp)->v[(i) + 1], &(vp)->v[(i)], ((vp)->n - (size_t)(i)) * sizeof(*(vp)->v)),          \
     (vp)->v[(i)] = (x), (vp)->n++)
#define dk_vec_remove(vp, i)                                                                       \
    (memmove(&(vp)->v[(i)], &(vp)->v[(i) + 1], ((vp)->n - (size_t)(i) - 1) * sizeof(*(vp)->v)), (vp)->n--)
/* Appends count elements from the array src. */
#define dk_vec_extend(vp, src, count)                                                              \
    (dk_vec_reserve((vp), (vp)->n + (count)),                                                      \
     memcpy(&(vp)->v[(vp)->n], (src), (size_t)(count) * sizeof(*(vp)->v)), (vp)->n += (count))

typedef DK_VEC(u8) DkBytes;
typedef DK_VEC(i32) DkI32Vec;
typedef DK_VEC(u32) DkU32Vec;
typedef DK_VEC(i64) DkI64Vec;
typedef DK_VEC(u64) DkU64Vec;
typedef DK_VEC(double) DkF64Vec;
typedef DK_VEC(void *) DkPtrVec;
typedef DK_VEC(char *) DkCzVec; /* NUL-terminated strings */
/* DkStrVec (a vector of DkStr views) is in str.h. */
