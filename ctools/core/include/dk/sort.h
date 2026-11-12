// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Sorting as Python's list.sort / sorted: stable (equal keys keep their order), so a port that sorts by the same
 * key gives the same order. reverse=True is a stable sort with the comparison inverted, as Python does (equal keys
 * still keep their original order). Also bisect and heapq. */
#pragma once
#include "str.h"

typedef int (*DkCmp)(const void *x, const void *y, void *ctx);

/* Stable merge sort of count elements of size bytes. reverse: Python's reverse=True. */
void dk_sort(void *base, size_t count, size_t size, DkCmp cmp, void *ctx, bool reverse);

void dk_sort_strs(DkStr *items, size_t count);   /* sorted() of str: code point order */
void dk_sort_i64(i64 *items, size_t count);
void dk_sort_u64(u64 *items, size_t count);
void dk_sort_f64(double *items, size_t count);    /* Python order for finite values; NaN as CPython's timsort leaves it is not reproduced */

/* Comparison helpers for building key-tuple comparators: return <0, 0, >0. */
int dk_cmp_i64(i64 a, i64 b);
int dk_cmp_u64(u64 a, u64 b);
int dk_cmp_f64(double a, double b);
int dk_cmp_str(DkStr a, DkStr b);

/* bisect.bisect_left / bisect_right over a sorted array; cmp is called as cmp(probe, element, ctx). */
size_t dk_bisect_left(const void *base, size_t count, size_t size, const void *probe, DkCmp cmp, void *ctx);
size_t dk_bisect_right(const void *base, size_t count, size_t size, const void *probe, DkCmp cmp, void *ctx);
size_t dk_bisect_left_u64(const u64 *items, size_t count, u64 probe);
size_t dk_bisect_right_u64(const u64 *items, size_t count, u64 probe);
size_t dk_bisect_left_i64(const i64 *items, size_t count, i64 probe);
size_t dk_bisect_right_i64(const i64 *items, size_t count, i64 probe);

/* heapq over an array (min-heap by cmp), with CPython's sift order so ties pop in the same order. */
void dk_heap_push(void *base, size_t *count, size_t size, const void *item, DkCmp cmp, void *ctx);
void dk_heap_pop(void *base, size_t *count, size_t size, void *out, DkCmp cmp, void *ctx);
void dk_heapify(void *base, size_t count, size_t size, DkCmp cmp, void *ctx);
