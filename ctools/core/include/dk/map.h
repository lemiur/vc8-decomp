// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Hash maps and sets with Python dict iteration order: insertion order; updating an existing key keeps its
 * position; deleting a key and inserting it again puts it at the end. Keys are byte strings (DkMap, DkSet; the
 * map keeps its own copy of each key) or 64-bit integers (DkIMap, DkISet). Values are an DkVal union, so a map
 * holds a pointer, an integer or a double without a cast dance.
 *
 *     DkMap *m = dk_map_new();
 *     bool created;
 *     dk_map_put(m, key, &created)->i += 1;              // Counter / defaultdict(int)
 *     DkVal *v = dk_map_get(m, key);                    // NULL when absent
 *     DkMapIter it = {0};
 *     while (dk_map_next(m, &it)) use(it.key, it.val);   // insertion order
 *
 * Pointers returned by get/put stay valid until the next put or del on the same map. Not thread-safe.
 *
 * DkPyIntSet reproduces CPython 3.14's set of ints, including its iteration order (the table size, the
 * linear probes and the perturbation of setobject.c): use it only where a Python set of ints is iterated into an
 * output (mark the site with a py: set order comment). Its hash is CPython's hash(int) (the value modulo 2**61-1,
 * -1 mapped to -2). */
#pragma once
#include "str.h"

typedef union {
    void *p;
    i64 i;
    u64 u;
    double f;
} DkVal;

/* ---- string keys ---- */
typedef struct DkMap DkMap;
typedef struct {
    size_t pos; /* internal cursor: zero it to start */
    DkStr key;
    DkVal *val;
} DkMapIter;

DkMap *dk_map_new(void);
DkMap *dk_map_new_cap(size_t expected);
void dk_map_free(DkMap *m);
void dk_map_clear(DkMap *m);
size_t dk_map_len(const DkMap *m);
DkVal *dk_map_get(const DkMap *m, DkStr key);
bool dk_map_has(const DkMap *m, DkStr key);
/* Returns the value slot of key, inserting it (value zeroed, *created = true) when absent. created may be NULL. */
DkVal *dk_map_put(DkMap *m, DkStr key, bool *created);
bool dk_map_del(DkMap *m, DkStr key);
bool dk_map_next(const DkMap *m, DkMapIter *it);
/* The keys in insertion order (views into the map's own copies). */
DkStrVec dk_map_keys(const DkMap *m);

/* ---- integer keys ---- */
typedef struct DkIMap DkIMap;
typedef struct {
    size_t pos;
    u64 key;
    DkVal *val;
} DkIMapIter;

DkIMap *dk_imap_new(void);
DkIMap *dk_imap_new_cap(size_t expected);
void dk_imap_free(DkIMap *m);
void dk_imap_clear(DkIMap *m);
size_t dk_imap_len(const DkIMap *m);
DkVal *dk_imap_get(const DkIMap *m, u64 key);
bool dk_imap_has(const DkIMap *m, u64 key);
DkVal *dk_imap_put(DkIMap *m, u64 key, bool *created);
bool dk_imap_del(DkIMap *m, u64 key);
bool dk_imap_next(const DkIMap *m, DkIMapIter *it);

/* ---- sets (insertion order) ---- */
typedef struct DkSet DkSet;   /* string members */
typedef struct DkISet DkISet; /* integer members */
DkSet *dk_set_new(void);
void dk_set_free(DkSet *s);
size_t dk_set_len(const DkSet *s);
bool dk_set_add(DkSet *s, DkStr member); /* true when it was new */
bool dk_set_has(const DkSet *s, DkStr member);
bool dk_set_del(DkSet *s, DkStr member);
bool dk_set_next(const DkSet *s, size_t *pos, DkStr *member);
DkStrVec dk_set_sorted(const DkSet *s); /* sorted(s) */

DkISet *dk_iset_new(void);
void dk_iset_free(DkISet *s);
size_t dk_iset_len(const DkISet *s);
bool dk_iset_add(DkISet *s, u64 member);
bool dk_iset_has(const DkISet *s, u64 member);
bool dk_iset_del(DkISet *s, u64 member);
bool dk_iset_next(const DkISet *s, size_t *pos, u64 *member);
DkU64Vec dk_iset_sorted(const DkISet *s);

/* ---- CPython's set of ints, iteration order included ---- */
typedef struct DkPyIntSet DkPyIntSet;
DkPyIntSet *dk_pyintset_new(void);
void dk_pyintset_free(DkPyIntSet *s);
size_t dk_pyintset_len(const DkPyIntSet *s);
bool dk_pyintset_add(DkPyIntSet *s, i64 member);
bool dk_pyintset_has(const DkPyIntSet *s, i64 member);
bool dk_pyintset_discard(DkPyIntSet *s, i64 member);
bool dk_pyintset_next(const DkPyIntSet *s, size_t *pos, i64 *member); /* CPython's iteration order */
/* set(list) built from an array in order: for a list source CPython adds the items one by one, so this equals repeated
 * dk_pyintset_add (set(dict) and set(set) presize or copy differently and are not reproduced). */
DkPyIntSet *dk_pyintset_from(const i64 *items, size_t count);
/* set(d) for a dict d with these keys in insertion order: CPython's set_update_internal presizes the table for a dict
 * source ((fill + len) * 5 >= mask * 3 -> one resize to (used + len) * 2), so the order differs from set(list) once the
 * dict passes the load limit. */
DkPyIntSet *dk_pyintset_from_dict(const i64 *keys, size_t count);
/* set.copy(), set.update(other_set) and a | b for sets of ints, with CPython's set_merge: the result's table size and
 * therefore its iteration order are those of the Python set (the target is presized when the sum passes the load
 * limit, an empty target of the same size gets the table copied slot by slot). */
DkPyIntSet *dk_pyintset_copy(const DkPyIntSet *s);
void dk_pyintset_update(DkPyIntSet *dst, const DkPyIntSet *src);
DkPyIntSet *dk_pyintset_or(const DkPyIntSet *a, const DkPyIntSet *b);
