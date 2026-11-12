// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* DkPyIntSet: CPython 3.14's set of ints (Objects/setobject.c), reproduced so that iterating it gives the order
 * Python gives. What decides the order, and is copied here:
 *
 *   - hash(int): the value modulo 2**61-1 (sign kept), -1 mapped to -2. Distinct ints can share a hash (x and
 *     x + 2**61-1); as in CPython both live in the table and are told apart by comparing the ints.
 *   - the table has a power-of-two size, 8 at first; slot i is hash & mask; a probe examines slot i and, when
 *     i + 9 <= mask, the nine slots after it (LINEAR_PROBES), then moves on with perturb >>= 5 and
 *     i = i * 5 + 1 + perturb (perturb starts as the hash read as an unsigned 64-bit number).
 *   - an add reuses a dummy (deleted) slot met before the first empty one, the LAST such dummy of the probe
 *     sequence (measured against CPython 3.14.8: a first-dummy rule gives other orders); only taking an empty slot
 *     counts into fill, and when fill * 5 >= mask * 3 the table is rebuilt at the smallest power of two above
 *     used * 4 (used * 2 when used > 50000). The rebuild drops the dummies and re-inserts the live entries in the
 *     old table's slot order.
 *   - discard turns the entry into a dummy; the table never shrinks.
 *   - set(list) is a plain loop of adds (set_update_internal only presizes when the source is a dict or a set).
 *
 * An entry needs no stored hash: it is a function of the key, so equal hashes never decide anything the key
 * comparison would not. */
#include "dk/map.h"

enum { ST_EMPTY = 0, ST_ACTIVE = 1, ST_DUMMY = 2 };

typedef struct {
    i64 key;
    u8 state;
} PEntry;

struct DkPyIntSet {
    PEntry *table;
    size_t mask;
    size_t fill; /* active + dummy */
    size_t used; /* active */
};

#define LINEAR_PROBES 9
#define PERTURB_SHIFT 5
#define SET_MINSIZE 8
#define HASH_MODULUS ((((u64)1) << 61) - 1)

/* hash(int) for a 64-bit value. */
static i64 py_hash_i64(i64 x) {
    u64 m = x < 0 ? (u64)0 - (u64)x : (u64)x;
    u64 r = (m & HASH_MODULUS) + (m >> 61);
    if (r >= HASH_MODULUS) r -= HASH_MODULUS;
    i64 h = x < 0 ? -(i64)r : (i64)r;
    return h == -1 ? -2 : h;
}

/* Walks the probe sequence of key. Stops at the entry holding the key (*found = true) or at the first empty slot
 * (*found = false); *dummy is the last dummy met on the way (NULL if none). */
static PEntry *probe(const struct DkPyIntSet *s, i64 key, bool *found, PEntry **dummy) {
    i64 hash = py_hash_i64(key);
    size_t mask = s->mask;
    size_t perturb = (size_t)hash;
    size_t i = (size_t)hash & mask;
    *dummy = NULL;
    for (;;) {
        PEntry *e = &s->table[i];
        size_t probes = (i + LINEAR_PROBES <= mask) ? LINEAR_PROBES : 0;
        do {
            if (e->state == ST_EMPTY) {
                *found = false;
                return e;
            }
            if (e->state == ST_ACTIVE) {
                if (e->key == key) {
                    *found = true;
                    return e;
                }
            } else {
                *dummy = e;
            }
            e++;
        } while (probes--);
        perturb >>= PERTURB_SHIFT;
        i = (i * 5 + 1 + perturb) & mask;
    }
}

/* Inserts into a table that has no dummies and room for it (CPython's set_insert_clean). */
static void insert_clean(PEntry *table, size_t mask, i64 key) {
    i64 hash = py_hash_i64(key);
    size_t perturb = (size_t)hash;
    size_t i = (size_t)hash & mask;
    for (;;) {
        PEntry *e = &table[i];
        size_t probes = (i + LINEAR_PROBES <= mask) ? LINEAR_PROBES : 0;
        do {
            if (e->state == ST_EMPTY) {
                e->key = key;
                e->state = ST_ACTIVE;
                return;
            }
            e++;
        } while (probes--);
        perturb >>= PERTURB_SHIFT;
        i = (i * 5 + 1 + perturb) & mask;
    }
}

/* set_table_resize: the smallest power of two above minused, live entries moved in old slot order. */
static void table_resize(struct DkPyIntSet *s, size_t minused) {
    size_t newsize = SET_MINSIZE;
    while (newsize <= minused) newsize <<= 1;
    PEntry *nt = dk_xcalloc(newsize, sizeof(PEntry));
    PEntry *old = s->table;
    size_t oldn = s->mask + 1;
    for (size_t i = 0; i < oldn; i++)
        if (old[i].state == ST_ACTIVE) insert_clean(nt, newsize - 1, old[i].key);
    dk_xfree(old);
    s->table = nt;
    s->mask = newsize - 1;
    s->fill = s->used;
}

DkPyIntSet *dk_pyintset_new(void) {
    DkPyIntSet *s = dk_xcalloc(1, sizeof *s);
    s->table = dk_xcalloc(SET_MINSIZE, sizeof(PEntry));
    s->mask = SET_MINSIZE - 1;
    return s;
}

void dk_pyintset_free(DkPyIntSet *s) {
    if (!s) return;
    dk_xfree(s->table);
    dk_xfree(s);
}

size_t dk_pyintset_len(const DkPyIntSet *s) { return s->used; }

bool dk_pyintset_add(DkPyIntSet *s, i64 member) {
    bool found;
    PEntry *dummy;
    PEntry *e = probe(s, member, &found, &dummy);
    if (found) return false;
    if (dummy) {
        dummy->key = member;
        dummy->state = ST_ACTIVE;
        s->used++;
        return true;
    }
    e->key = member;
    e->state = ST_ACTIVE;
    s->fill++;
    s->used++;
    if (s->fill * 5 >= s->mask * 3) table_resize(s, s->used > 50000 ? s->used * 2 : s->used * 4);
    return true;
}

bool dk_pyintset_has(const DkPyIntSet *s, i64 member) {
    bool found;
    PEntry *dummy;
    probe(s, member, &found, &dummy);
    return found;
}

bool dk_pyintset_discard(DkPyIntSet *s, i64 member) {
    bool found;
    PEntry *dummy;
    PEntry *e = probe(s, member, &found, &dummy);
    if (!found) return false;
    e->state = ST_DUMMY;
    s->used--;
    return true;
}

bool dk_pyintset_next(const DkPyIntSet *s, size_t *pos, i64 *member) {
    while (*pos <= s->mask) {
        const PEntry *e = &s->table[(*pos)++];
        if (e->state == ST_ACTIVE) {
            *member = e->key;
            return true;
        }
    }
    return false;
}

DkPyIntSet *dk_pyintset_from(const i64 *items, size_t count) {
    DkPyIntSet *s = dk_pyintset_new();
    for (size_t i = 0; i < count; i++) dk_pyintset_add(s, items[i]);
    return s;
}

DkPyIntSet *dk_pyintset_from_dict(const i64 *keys, size_t count) {
    DkPyIntSet *s = dk_pyintset_new();
    if ((s->fill + count) * 5 >= s->mask * 3) table_resize(s, (s->used + count) * 2);
    for (size_t i = 0; i < count; i++) dk_pyintset_add(s, keys[i]);
    return s;
}

/* set_merge (the heart of set.update(other_set), set.copy() and a | b for sets): a presize when the sum would pass
 * the load limit, then one of three ways in: an exact copy of the table (empty target of the same size, no dummies
 * in the source), insertion without checks (empty target), or ordinary adds in the source's slot order. */
static void set_merge(struct DkPyIntSet *so, const struct DkPyIntSet *other) {
    if (other == so || other->used == 0) return;
    if ((so->fill + other->used) * 5 >= so->mask * 3) table_resize(so, (so->used + other->used) * 2);
    if (so->fill == 0 && so->mask == other->mask && other->fill == other->used) {
        for (size_t i = 0; i <= other->mask; i++)
            if (other->table[i].state == ST_ACTIVE) so->table[i] = other->table[i];
        so->fill = other->fill;
        so->used = other->used;
        return;
    }
    if (so->fill == 0) {
        so->fill = other->used;
        so->used = other->used;
        for (size_t i = 0; i <= other->mask; i++)
            if (other->table[i].state == ST_ACTIVE) insert_clean(so->table, so->mask, other->table[i].key);
        return;
    }
    for (size_t i = 0; i <= other->mask; i++)
        if (other->table[i].state == ST_ACTIVE) dk_pyintset_add(so, other->table[i].key);
}

DkPyIntSet *dk_pyintset_copy(const DkPyIntSet *s) {
    DkPyIntSet *r = dk_pyintset_new();
    set_merge(r, s);
    return r;
}

void dk_pyintset_update(DkPyIntSet *dst, const DkPyIntSet *src) { set_merge(dst, src); }

DkPyIntSet *dk_pyintset_or(const DkPyIntSet *a, const DkPyIntSet *b) {
    DkPyIntSet *r = dk_pyintset_copy(a);
    set_merge(r, b);
    return r;
}
