// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Insertion-ordered hash maps and sets (map.h). One table implementation serves the four public kinds:
 *
 *   entries   an array in insertion order: {hash, key word 0, key word 1, value}; a deleted entry stays in place
 *             (key tag 0) until the next growth compacts the array, so iteration order is Python's dict order and
 *             the pointers handed out stay valid until the next put.
 *   index     an open-addressing table of 64-bit slots {hash high 32 bits, entry number + 1}, linear probing,
 *             tombstones for deleted keys, never more than half full (counting dead entries), so a probe almost
 *             always ends at the first or second slot and rejects a mismatch without touching the entries.
 *
 * String keys are copied into a chunked arena owned by the map (the entry points into it). Integer keys live in
 * the entry itself. The hash of a byte string is a wyhash-style 128-bit-multiply mix (not Python's hash: no output
 * depends on it, since iteration is in insertion order). */
#include "dk/map.h"
#include "dk/sort.h"
#include <intrin.h>

typedef struct {
    u64 hash;
    u64 k0;  /* string key: pointer; integer key: the key */
    u64 k1;  /* key tag: string length + 1, or 1 for an integer key; 0 marks a deleted entry */
    DkVal val;
} Entry;

typedef struct Chunk {
    struct Chunk *next;
    size_t cap, used;
    /* the bytes follow */
} Chunk;

typedef struct {
    Entry *e;
    u64 *idx;
    size_t n;        /* entries used, dead ones included */
    size_t cap;      /* entries allocated: a power of two, or 0 before the first put */
    size_t live;
    size_t mask;     /* index size - 1 */
    bool str;
    Chunk *chunks;   /* string key storage, newest first */
} Tab;

#define SLOT_TOMB 0xFFFFFFFFull /* entry number field of a deleted key's slot */
#define SLOT_LOW 0xFFFFFFFFull
#define SLOT_HIGH 0xFFFFFFFF00000000ull
#define MIN_CAP 8

static inline u64 mum(u64 a, u64 b) {
    u64 hi;
    u64 lo = _umul128(a, b, &hi);
    return lo ^ hi;
}
static inline u64 rd8(const u8 *p) { u64 v; memcpy(&v, p, 8); return v; }
static inline u64 rd4(const u8 *p) { u32 v; memcpy(&v, p, 4); return v; }

static const u64 S0 = 0xa0761d6478bd642full, S1 = 0xe7037ed1a0b428dbull, S2 = 0x8ebc6af09c88c6e3ull,
                 S3 = 0x589965cc75374cc3ull;

static u64 hash_bytes(const char *s, size_t n) {
    const u8 *p = (const u8 *)s;
    u64 seed = S0, a, b;
    if (n <= 16) {
        if (n >= 4) {
            a = (rd4(p) << 32) | rd4(p + ((n >> 3) << 2));
            b = (rd4(p + n - 4) << 32) | rd4(p + n - 4 - ((n >> 3) << 2));
        } else if (n > 0) {
            a = ((u64)p[0] << 16) | ((u64)p[n >> 1] << 8) | p[n - 1];
            b = 0;
        } else {
            a = b = 0;
        }
    } else {
        size_t i = n;
        if (i > 48) {
            u64 see1 = seed, see2 = seed;
            do {
                seed = mum(rd8(p) ^ S1, rd8(p + 8) ^ seed);
                see1 = mum(rd8(p + 16) ^ S2, rd8(p + 24) ^ see1);
                see2 = mum(rd8(p + 32) ^ S3, rd8(p + 40) ^ see2);
                p += 48;
                i -= 48;
            } while (i > 48);
            seed ^= see1 ^ see2;
        }
        while (i > 16) {
            seed = mum(rd8(p) ^ S1, rd8(p + 8) ^ seed);
            i -= 16;
            p += 16;
        }
        a = rd8(p + i - 16);
        b = rd8(p + i - 8);
    }
    return mum(S1 ^ n, mum(a ^ S1, b ^ seed));
}

static inline u64 hash_int(u64 k) { return mum(k ^ S0, S1 ^ 0x9e3779b97f4a7c15ull); }

static Tab *tab_new(bool str, size_t expected) {
    Tab *t = dk_xcalloc(1, sizeof *t);
    t->str = str;
    if (expected > 0) {
        size_t cap = MIN_CAP;
        while (cap < expected) cap <<= 1;
        t->cap = cap;
        t->e = dk_xmalloc(cap * sizeof(Entry));
        t->mask = cap * 2 - 1;
        t->idx = dk_xcalloc(cap * 2, sizeof(u64));
    }
    return t;
}

static void chunks_free(Chunk *c) {
    while (c) {
        Chunk *next = c->next;
        dk_xfree(c);
        c = next;
    }
}

static void tab_free(Tab *t) {
    if (!t) return;
    chunks_free(t->chunks);
    dk_xfree(t->e);
    dk_xfree(t->idx);
    dk_xfree(t);
}

static void tab_clear(Tab *t) {
    chunks_free(t->chunks);
    t->chunks = NULL;
    t->n = t->live = 0;
    if (t->idx) memset(t->idx, 0, (t->mask + 1) * sizeof(u64));
}

/* Copies a key into the map's storage and appends a NUL after it. */
static const char *key_store(Tab *t, const char *s, size_t n) {
    Chunk *c = t->chunks;
    if (!c || c->cap - c->used < n + 1) {
        size_t cap = c ? c->cap * 2 : 4096;
        if (cap > ((size_t)1 << 20)) cap = (size_t)1 << 20;
        if (cap < n + 1) cap = n + 1;
        Chunk *nc = dk_xmalloc(sizeof(Chunk) + cap);
        nc->next = t->chunks;
        nc->cap = cap;
        nc->used = 0;
        t->chunks = nc;
        c = nc;
    }
    char *dst = (char *)(c + 1) + c->used;
    if (n) memcpy(dst, s, n);
    dst[n] = 0;
    c->used += n + 1;
    return dst;
}

static inline bool key_eq(const Tab *t, const Entry *e, u64 k0, u64 k1) {
    if (!t->str) return e->k0 == k0;
    return e->k1 == k1 &&
           (k1 == 1 || memcmp((const void *)(uintptr_t)e->k0, (const void *)(uintptr_t)k0, (size_t)(k1 - 1)) == 0);
}

/* Finds the entry of a key; returns NULL when absent. */
static Entry *tab_find(const Tab *t, u64 h, u64 k0, u64 k1) {
    if (!t->cap) return NULL;
    u64 tag = h >> 32;
    size_t i = (size_t)h & t->mask;
    for (;;) {
        u64 s = t->idx[i];
        if (s == 0) return NULL;
        if ((s & SLOT_LOW) != SLOT_TOMB && (s >> 32) == tag) {
            Entry *e = &t->e[(s & SLOT_LOW) - 1];
            if (e->hash == h && key_eq(t, e, k0, k1)) return e;
        }
        i = (i + 1) & t->mask;
    }
}

/* Rebuilds the entries (compacted, same order) and the index at the given entry capacity. */
static void tab_rebuild(Tab *t, size_t cap) {
    DK_ASSERT(cap < SLOT_TOMB);
    Entry *ne = dk_xmalloc(cap * sizeof(Entry));
    size_t m = 0;
    for (size_t i = 0; i < t->n; i++)
        if (t->e[i].k1) ne[m++] = t->e[i];
    dk_xfree(t->e);
    dk_xfree(t->idx);
    t->e = ne;
    t->n = m;
    t->cap = cap;
    t->mask = cap * 2 - 1;
    t->idx = dk_xcalloc(cap * 2, sizeof(u64));
    for (size_t i = 0; i < m; i++) {
        size_t j = (size_t)ne[i].hash & t->mask;
        while (t->idx[j]) j = (j + 1) & t->mask;
        t->idx[j] = (ne[i].hash & SLOT_HIGH) | (u64)(i + 1);
    }
}

/* Appends a new entry for a key known to be absent. */
static Entry *tab_append(Tab *t, u64 h, u64 k0, u64 k1) {
    if (t->n == t->cap) {
        if (!t->cap) tab_rebuild(t, MIN_CAP);
        else if (t->live * 4 < t->n * 3) tab_rebuild(t, t->cap); /* a quarter or more is dead: compact in place */
        else tab_rebuild(t, t->cap * 2);
    }
    size_t j = (size_t)h & t->mask;
    while (t->idx[j] != 0 && (t->idx[j] & SLOT_LOW) != SLOT_TOMB) j = (j + 1) & t->mask;
    Entry *e = &t->e[t->n];
    e->hash = h;
    e->k0 = k0;
    e->k1 = k1;
    e->val.u = 0;
    t->idx[j] = (h & SLOT_HIGH) | (u64)(t->n + 1);
    t->n++;
    t->live++;
    return e;
}

static Entry *tab_put(Tab *t, u64 h, u64 k0, u64 k1, bool *created) {
    Entry *e = tab_find(t, h, k0, k1);
    if (created) *created = (e == NULL);
    return e ? e : tab_append(t, h, k0, k1);
}

static bool tab_del(Tab *t, u64 h, u64 k0, u64 k1) {
    if (!t->cap) return false;
    u64 tag = h >> 32;
    size_t i = (size_t)h & t->mask;
    for (;;) {
        u64 s = t->idx[i];
        if (s == 0) return false;
        if ((s & SLOT_LOW) != SLOT_TOMB && (s >> 32) == tag) {
            Entry *e = &t->e[(s & SLOT_LOW) - 1];
            if (e->hash == h && key_eq(t, e, k0, k1)) {
                e->k1 = 0;
                t->idx[i] = SLOT_TOMB;
                t->live--;
                return true;
            }
        }
        i = (i + 1) & t->mask;
    }
}

/* Entry operations by key kind. A string key is copied into the map when it is inserted. An empty key points at a
 * literal so that the key word is never NULL. */
static inline u64 skey_k0(DkStr k) { return (u64)(uintptr_t)(k.n ? k.p : ""); }

static Entry *sfind(const Tab *t, DkStr k) {
    return tab_find(t, hash_bytes(k.p, k.n), skey_k0(k), (u64)k.n + 1);
}

static Entry *sput(Tab *t, DkStr k, bool *created) {
    u64 h = hash_bytes(k.p, k.n);
    Entry *e = tab_find(t, h, skey_k0(k), (u64)k.n + 1);
    if (created) *created = (e == NULL);
    if (e) return e;
    const char *own = key_store(t, k.p, k.n); /* the new entry points at the map's own bytes */
    return tab_append(t, h, (u64)(uintptr_t)own, (u64)k.n + 1);
}

static bool sdel(Tab *t, DkStr k) { return tab_del(t, hash_bytes(k.p, k.n), skey_k0(k), (u64)k.n + 1); }

static inline DkStr entry_str(const Entry *e) {
    return (DkStr){(const char *)(uintptr_t)e->k0, (size_t)(e->k1 - 1)};
}

/* The next live entry at or after *pos, or NULL. */
static const Entry *tab_next(const Tab *t, size_t *pos) {
    while (*pos < t->n) {
        const Entry *e = &t->e[(*pos)++];
        if (e->k1) return e;
    }
    return NULL;
}

/* ---- DkMap ---- */
struct DkMap { Tab t; };
DkMap *dk_map_new(void) { return (DkMap *)tab_new(true, 0); }
DkMap *dk_map_new_cap(size_t expected) { return (DkMap *)tab_new(true, expected); }
void dk_map_free(DkMap *m) { if (m) tab_free(&m->t); }
void dk_map_clear(DkMap *m) { tab_clear(&m->t); }
size_t dk_map_len(const DkMap *m) { return m->t.live; }
DkVal *dk_map_get(const DkMap *m, DkStr key) {
    Entry *e = sfind(&m->t, key);
    return e ? &e->val : NULL;
}
bool dk_map_has(const DkMap *m, DkStr key) { return sfind(&m->t, key) != NULL; }
DkVal *dk_map_put(DkMap *m, DkStr key, bool *created) { return &sput(&m->t, key, created)->val; }
bool dk_map_del(DkMap *m, DkStr key) { return sdel(&m->t, key); }
bool dk_map_next(const DkMap *m, DkMapIter *it) {
    const Entry *e = tab_next(&m->t, &it->pos);
    if (!e) return false;
    it->key = entry_str(e);
    it->val = (DkVal *)&e->val;
    return true;
}
DkStrVec dk_map_keys(const DkMap *m) {
    DkStrVec v = {0};
    dk_vec_reserve(&v, m->t.live);
    for (size_t i = 0; i < m->t.n; i++)
        if (m->t.e[i].k1) v.v[v.n++] = entry_str(&m->t.e[i]);
    return v;
}

/* ---- DkIMap ---- */
struct DkIMap { Tab t; };
DkIMap *dk_imap_new(void) { return (DkIMap *)tab_new(false, 0); }
DkIMap *dk_imap_new_cap(size_t expected) { return (DkIMap *)tab_new(false, expected); }
void dk_imap_free(DkIMap *m) { if (m) tab_free(&m->t); }
void dk_imap_clear(DkIMap *m) { tab_clear(&m->t); }
size_t dk_imap_len(const DkIMap *m) { return m->t.live; }
DkVal *dk_imap_get(const DkIMap *m, u64 key) {
    Entry *e = tab_find(&m->t, hash_int(key), key, 1);
    return e ? &e->val : NULL;
}
bool dk_imap_has(const DkIMap *m, u64 key) { return tab_find(&m->t, hash_int(key), key, 1) != NULL; }
DkVal *dk_imap_put(DkIMap *m, u64 key, bool *created) {
    return &tab_put(&m->t, hash_int(key), key, 1, created)->val;
}
bool dk_imap_del(DkIMap *m, u64 key) { return tab_del(&m->t, hash_int(key), key, 1); }
bool dk_imap_next(const DkIMap *m, DkIMapIter *it) {
    const Entry *e = tab_next(&m->t, &it->pos);
    if (!e) return false;
    it->key = e->k0;
    it->val = (DkVal *)&e->val;
    return true;
}

/* ---- DkSet / DkISet ---- */
struct DkSet { Tab t; };
struct DkISet { Tab t; };
DkSet *dk_set_new(void) { return (DkSet *)tab_new(true, 0); }
void dk_set_free(DkSet *s) { if (s) tab_free(&s->t); }
size_t dk_set_len(const DkSet *s) { return s->t.live; }
bool dk_set_add(DkSet *s, DkStr member) {
    bool created;
    sput(&s->t, member, &created);
    return created;
}
bool dk_set_has(const DkSet *s, DkStr member) { return sfind(&s->t, member) != NULL; }
bool dk_set_del(DkSet *s, DkStr member) { return sdel(&s->t, member); }
bool dk_set_next(const DkSet *s, size_t *pos, DkStr *member) {
    const Entry *e = tab_next(&s->t, pos);
    if (!e) return false;
    *member = entry_str(e);
    return true;
}
DkStrVec dk_set_sorted(const DkSet *s) {
    DkStrVec v = {0};
    dk_vec_reserve(&v, s->t.live);
    for (size_t i = 0; i < s->t.n; i++)
        if (s->t.e[i].k1) v.v[v.n++] = entry_str(&s->t.e[i]);
    dk_sort_strs(v.v, v.n);
    return v;
}

DkISet *dk_iset_new(void) { return (DkISet *)tab_new(false, 0); }
void dk_iset_free(DkISet *s) { if (s) tab_free(&s->t); }
size_t dk_iset_len(const DkISet *s) { return s->t.live; }
bool dk_iset_add(DkISet *s, u64 member) {
    bool created;
    tab_put(&s->t, hash_int(member), member, 1, &created);
    return created;
}
bool dk_iset_has(const DkISet *s, u64 member) { return tab_find(&s->t, hash_int(member), member, 1) != NULL; }
bool dk_iset_del(DkISet *s, u64 member) { return tab_del(&s->t, hash_int(member), member, 1); }
bool dk_iset_next(const DkISet *s, size_t *pos, u64 *member) {
    const Entry *e = tab_next(&s->t, pos);
    if (!e) return false;
    *member = e->k0;
    return true;
}
DkU64Vec dk_iset_sorted(const DkISet *s) {
    DkU64Vec v = {0};
    dk_vec_reserve(&v, s->t.live);
    for (size_t i = 0; i < s->t.n; i++)
        if (s->t.e[i].k1) v.v[v.n++] = s->t.e[i].k0;
    dk_sort_u64(v.v, v.n);
    return v;
}
