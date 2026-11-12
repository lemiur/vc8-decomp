// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The expression algebra: the interned values (Ex) the expressions are made of, the engine's error plumbing, the
 * insertion-ordered dict (ExMap), and the functions that build, simplify, compare and print expressions and
 * conditions: C, lin, mklin, add, scale, comm, signed, short, lo8, zx8, b8, eqv, canon_e, canon_c, cond_eq, subst,
 * eval_const_cond, add_fact, cond_subst, make_cond, negate_cond, dbl_to_f32 and const_from_symbol. See
 * eq2_internal.h for the representation. */
#include "eq2_internal.h"
#include <windows.h>
#include <intrin.h>
#include <stdlib.h>

/* ----------------------------------------------------------------------------------------------- atoms, strs */
Eq2Atoms eq2_A;

typedef struct StrTab {
    Ex **slot;
    u32 cap, count;
} StrTab;
static StrTab g_strs;
static SRWLOCK g_strs_lock = SRWLOCK_INIT;
static INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT;

static u32 hash_bytes(const char *s, size_t n) {
    u32 h = 2166136261u;
    for (size_t i = 0; i < n; i++) h = (h ^ (u8)s[i]) * 16777619u;
    return h;
}

static void *eq2_alloc_node(size_t n) { return dk_xcalloc(1, n); }

static Ex *str_intern_locked(const char *s, size_t n) {
    if (g_strs.count * 2 >= g_strs.cap) {
        u32 ncap = g_strs.cap ? g_strs.cap * 2 : 1024;
        Ex **ns = dk_xcalloc(ncap, sizeof(Ex *));
        for (u32 i = 0; i < g_strs.cap; i++) {
            Ex *e = g_strs.slot[i];
            if (!e) continue;
            u32 j = e->hash & (ncap - 1);
            while (ns[j]) j = (j + 1) & (ncap - 1);
            ns[j] = e;
        }
        dk_xfree(g_strs.slot);
        g_strs.slot = ns;
        g_strs.cap = ncap;
    }
    u32 h = hash_bytes(s, n);
    u32 j = h & (g_strs.cap - 1);
    while (g_strs.slot[j]) {
        Ex *e = g_strs.slot[j];
        if (e->hash == h && e->n == n && memcmp(e->s, s, n) == 0) return e;
        j = (j + 1) & (g_strs.cap - 1);
    }
    Ex *e = eq2_alloc_node(sizeof(Ex) + n + 1);
    char *txt = (char *)(e + 1);
    memcpy(txt, s, n);
    txt[n] = 0;
    e->kind = EX_STR;
    e->n = (u32)n;
    e->hash = h;
    e->s = txt;
    g_strs.slot[j] = e;
    g_strs.count++;
    return e;
}

Ex *ex_strn(const char *s, size_t n) {
    AcquireSRWLockExclusive(&g_strs_lock);
    Ex *e = str_intern_locked(s, n);
    ReleaseSRWLockExclusive(&g_strs_lock);
    return e;
}
Ex *ex_str(const char *s) { return ex_strn(s, strlen(s)); }

static Ex *g_fsets[16];

static BOOL CALLBACK init_cb(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    DK_UNUSED(once);
    DK_UNUSED(param);
    DK_UNUSED(ctx);
#define X(f, s) eq2_A.a_##f = ex_str(s);
    EQ2_ATOMS(X)
#undef X
    Ex *none = eq2_alloc_node(sizeof(Ex));
    none->kind = EX_NONE;
    none->hash = 0x5eed0001u;
    none->repr = "None";
    none->repr_len = 4;
    eq2_A.none = none;
    for (unsigned m = 0; m < 16; m++) {
        Ex *e = eq2_alloc_node(sizeof(Ex));
        e->kind = EX_FSET;
        e->i = m;
        e->hash = 0xf5e70000u + m;
        g_fsets[m] = e;
    }
    return TRUE;
}

void eq2_init(void) { InitOnceExecuteOnce(&g_init_once, init_cb, NULL, NULL); }

Ex *ex_none(void) { return eq2_A.none; }
Ex *ex_fset(unsigned mask) { return g_fsets[mask & 15]; }

/* ---------------------------------------------------------------------------- the per-thread universe (tuples, ints) */
typedef struct Universe {
    Ex **slot;
    u32 cap, count;
    char *blk;
    size_t blk_left;
} Universe;
static DK_THREAD_LOCAL Universe U;

static void *uni_alloc(size_t n) {
    n = (n + 15) & ~(size_t)15;
    if (U.blk_left < n) {
        size_t sz = n > (1u << 20) ? n : (1u << 20);
        U.blk = dk_xmalloc(sz);
        U.blk_left = sz;
    }
    void *p = U.blk;
    U.blk += n;
    U.blk_left -= n;
    memset(p, 0, n);
    return p;
}

static void uni_grow(void) {
    u32 ncap = U.cap ? U.cap * 2 : 4096;
    Ex **ns = dk_xcalloc(ncap, sizeof(Ex *));
    for (u32 i = 0; i < U.cap; i++) {
        Ex *e = U.slot[i];
        if (!e) continue;
        u32 j = e->hash & (ncap - 1);
        while (ns[j]) j = (j + 1) & (ncap - 1);
        ns[j] = e;
    }
    dk_xfree(U.slot);
    U.slot = ns;
    U.cap = ncap;
}

static u32 mix32(u64 x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return (u32)x;
}

static Ex *int_intern(u64 v, bool big) {
    u32 h = mix32(v ^ 0x1234567ull) ^ (big ? 0x9e3779b9u : 0);
    if (U.count * 2 >= U.cap) uni_grow();
    u32 j = h & (U.cap - 1);
    while (U.slot[j]) {
        Ex *e = U.slot[j];
        if (e->kind == EX_INT && e->hash == h && !e->s && (u64)e->i == v && e->big == big) return e;
        j = (j + 1) & (U.cap - 1);
    }
    Ex *e = uni_alloc(sizeof(Ex));
    e->kind = EX_INT;
    e->big = big;
    e->i = (i64)v;
    e->hash = h;
    U.slot[j] = e;
    U.count++;
    return e;
}
Ex *ex_int_text(const char *txt) {
    size_t n = strlen(txt);
    u32 h = hash_bytes(txt, n) ^ 0x7e57u;
    if (U.count * 2 >= U.cap) uni_grow();
    u32 j = h & (U.cap - 1);
    while (U.slot[j]) {
        Ex *e = U.slot[j];
        if (e->kind == EX_INT && e->s && e->hash == h && !strcmp(e->s, txt)) return e;
        j = (j + 1) & (U.cap - 1);
    }
    Ex *e = uni_alloc(sizeof(Ex) + n + 1);
    char *copy = (char *)(e + 1);
    memcpy(copy, txt, n + 1);
    e->kind = EX_INT;
    e->s = copy;
    e->hash = h;
    U.slot[j] = e;
    U.count++;
    return e;
}

Ex *ex_uint(u64 v) { return int_intern(v, v > (u64)INT64_MAX); }
Ex *ex_int(i64 v) { return int_intern((u64)v, false); }

Ex *ex_tup(Ex *const *el, size_t n) {
    u64 hh = 0x9e3779b97f4a7c15ull ^ n;
    for (size_t i = 0; i < n; i++) hh = (hh ^ (u64)(uintptr_t)el[i]) * 0x100000001b3ull + (hh >> 29);
    u32 h = mix32(hh);
    if (U.count * 2 >= U.cap) uni_grow();
    u32 j = h & (U.cap - 1);
    while (U.slot[j]) {
        Ex *e = U.slot[j];
        if (e->kind == EX_TUP && e->hash == h && e->n == n && (n == 0 || memcmp(e->el, el, n * sizeof(Ex *)) == 0)) return e;
        j = (j + 1) & (U.cap - 1);
    }
    Ex *e = uni_alloc(sizeof(Ex) + n * sizeof(Ex *));
    e->kind = EX_TUP;
    e->n = (u32)n;
    e->hash = h;
    e->el = (Ex **)(e + 1);
    if (n) memcpy(e->el, el, n * sizeof(Ex *));
    U.slot[j] = e;
    U.count++;
    return e;
}
Ex *ex_t1(Ex *a) { Ex *v[1] = {a}; return ex_tup(v, 1); }
Ex *ex_t2(Ex *a, Ex *b) { Ex *v[2] = {a, b}; return ex_tup(v, 2); }
Ex *ex_t3(Ex *a, Ex *b, Ex *c) { Ex *v[3] = {a, b, c}; return ex_tup(v, 3); }
Ex *ex_t4(Ex *a, Ex *b, Ex *c, Ex *d) { Ex *v[4] = {a, b, c, d}; return ex_tup(v, 4); }
Ex *ex_t5(Ex *a, Ex *b, Ex *c, Ex *d, Ex *e) { Ex *v[5] = {a, b, c, d, e}; return ex_tup(v, 5); }

Ex *ex_tagn(const char *tag, size_t n, Ex *const *rest) {
    Ex *v[8];
    DK_ASSERT(n < 8);
    v[0] = ex_str(tag);
    for (size_t i = 0; i < n; i++) v[i + 1] = rest[i];
    return ex_tup(v, n + 1);
}

Ex *ex_c(u64 n) { return ex_t2(EA(c), ex_uint(n & EQ2_M32)); }
Ex *ex_craw(u64 n) { return ex_t2(EA(c), ex_uint(n)); }

/* --------------------------------------------------------------------------------------------------------- repr */
static void repr_into(DkBuf *b, Ex *e) {
    switch (e->kind) {
    case EX_NONE: dk_buf_putz(b, "None"); return;
    case EX_INT:
        if (e->s) dk_buf_putz(b, e->s);
        else if (e->big) dk_buf_pyfmt(b, "%Ud", (unsigned long long)e->i);
        else dk_buf_pyfmt(b, "%d", e->i);
        return;
    case EX_STR: {
        DkArena *a = dk_scratch();
        DkArenaMark mk = dk_arena_mark(a);
        DkStr r = dk_repr_str(a, dk_strn(e->s, e->n));
        dk_buf_put(b, r);
        dk_arena_reset(a, mk);
        return;
    }
    case EX_FSET: {
        if (!e->i) { dk_buf_putz(b, "frozenset()"); return; }
        static const struct { unsigned bit; const char *name; } names[4] = {{OUT_EQ, "'eq'"}, {OUT_GT, "'gt'"}, {OUT_LT, "'lt'"}, {OUT_UN, "'un'"}};
        dk_buf_putz(b, "frozenset({");
        bool first = true;
        for (int i = 0; i < 4; i++) {
            if (!(e->i & names[i].bit)) continue;
            if (!first) dk_buf_putz(b, ", ");
            dk_buf_putz(b, names[i].name);
            first = false;
        }
        dk_buf_putz(b, "})");
        return;
    }
    case EX_TUP:
        if (e->repr) { dk_buf_putn(b, e->repr, e->repr_len); return; }
        dk_buf_putc(b, '(');
        for (u32 i = 0; i < e->n; i++) {
            if (i) dk_buf_putz(b, ", ");
            repr_into(b, e->el[i]);
        }
        if (e->n == 1) dk_buf_putc(b, ',');
        dk_buf_putc(b, ')');
        return;
    }
}

const char *ex_repr(Ex *e) {
    if (e->repr) return e->repr;
    DkBuf b = {0};
    repr_into(&b, e);
    size_t n = b.n;
    char *cz = dk_xmalloc(n + 1);
    memcpy(cz, dk_buf_cz(&b), n + 1);
    dk_buf_free(&b);
    e->repr = cz;
    e->repr_len = (u32)n;
    return cz;
}

int ex_repr_cmp(Ex *a, Ex *b) {
    if (a == b) return 0;
    return strcmp(ex_repr(a), ex_repr(b));
}

void eq2_sort2(Ex **a, Ex **b) {
    /* sorted([a, b], key=repr) is stable: equal reprs keep their order */
    if (ex_repr_cmp(*b, *a) < 0) {
        Ex *t = *a;
        *a = *b;
        *b = t;
    }
}

void ex_str_of(DkBuf *b, const Ex *e) {
    if (e->kind == EX_STR) dk_buf_putn(b, e->s, e->n);
    else repr_into(b, (Ex *)e);
}

void eq2_repr_list(DkBuf *b, const char *const *items, size_t n) {
    DkArena *a = dk_scratch();
    DkArenaMark mk = dk_arena_mark(a);
    dk_buf_putc(b, '[');
    for (size_t i = 0; i < n; i++) {
        if (i) dk_buf_putz(b, ", ");
        dk_buf_put(b, dk_repr_str(a, dk_str(items[i])));
    }
    dk_buf_putc(b, ']');
    dk_arena_reset(a, mk);
}

/* short(e, depth) */
void eq2_short(DkBuf *b, const Ex *e, int depth) {
    if (depth > 5) { dk_buf_putz(b, ".."); return; }
    if (e->kind != EX_TUP) { ex_str_of(b, e); return; }
    if (ex_is(e, EA(c))) {
        const Ex *v = e->el[1];
        if (v->big) dk_buf_pyfmt(b, "%#Ux", (unsigned long long)v->i);
        else dk_buf_pyfmt(b, "%#x", v->i);
        return;
    }
    if (ex_is(e, EA(L))) {
        dk_buf_putc(b, '(');
        const Ex *terms = e->el[1];
        for (u32 i = 0; i < terms->n; i++) {
            const Ex *kv = terms->el[i];
            if (i) dk_buf_putc(b, '+');
            eq2_short(b, kv->el[0], depth + 1);
            if (kv->el[1] != ex_int(1)) {
                dk_buf_putc(b, '*');
                ex_str_of(b, kv->el[1]);
            }
        }
        dk_buf_pyfmt(b, "+%#x)", e->el[2]->i);
        return;
    }
    dk_buf_putc(b, '(');
    for (u32 i = 0; i < e->n; i++) {
        if (i) dk_buf_putc(b, ' ');
        eq2_short(b, e->el[i], depth + 1);
    }
    dk_buf_putc(b, ')');
}

char *eq2_short_cz(DkArena *a, const Ex *e) {
    DkBuf b = {0};
    eq2_short(&b, e, 0);
    char *r = dk_strdup(a, dk_buf_cz(&b));
    dk_buf_free(&b);
    return r;
}

/* ------------------------------------------------------------------------------------------------ exceptions */
static DK_THREAD_LOCAL Eq2Catch *g_catch;

void eq2_catch_push(Eq2Catch *c) {
    c->prev = g_catch;
    g_catch = c;
}
void eq2_catch_end(Eq2Catch *c) {
    DK_ASSERT(g_catch == c);
    g_catch = c->prev;
}

static DK_NORETURN void eq2_raise(int kind, const char *fmt, va_list ap) {
    Eq2Catch *c = g_catch;
    if (!c) dk_panic(__FILE__, __LINE__, "eq2: exception outside a catcher");
    c->kind = kind;
    vsnprintf(c->msg, sizeof c->msg, fmt, ap);
    g_catch = c->prev;
    longjmp(c->jb, 1);
}
void eq2_unsupported(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    eq2_raise(EQ2_EXC_UNSUPPORTED, fmt, ap);
}
void eq2_crash(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    eq2_raise(EQ2_EXC_CRASH, fmt, ap);
}
void eq2_rethrow(const Eq2Catch *c) {
    Eq2Catch *top = g_catch;
    if (!top) dk_panic(__FILE__, __LINE__, "eq2: exception outside a catcher");
    top->kind = c->kind;
    memcpy(top->msg, c->msg, sizeof top->msg);
    g_catch = top->prev;
    longjmp(top->jb, 1);
}

/* -------------------------------------------------------------------------------------------- ordered dict */
static u32 hslot(u64 key, u32 mask) { return (u32)((key * 0x9E3779B97F4A7C15ull) >> 32) & mask; }

static void exmap_index(ExMap *m, u32 i) {
    u32 mask = m->idx_cap - 1;
    u32 s = hslot(m->ent[i].key, mask);
    while (m->idx[s]) s = (s + 1) & mask;
    m->idx[s] = i + 1;
}

static void exmap_rebuild(ExMap *m, u32 new_cap) {
    ExEnt *ne = dk_xmalloc((size_t)new_cap * sizeof(ExEnt));
    u32 j = 0;
    for (u32 i = 0; i < m->n_ent; i++)
        if (m->ent[i].live) ne[j++] = m->ent[i];
    dk_xfree(m->ent);
    dk_xfree(m->idx);
    m->ent = ne;
    m->n_ent = j;
    m->cap_ent = new_cap;
    u32 ic = 16;
    while (ic < new_cap * 2) ic <<= 1;
    m->idx_cap = ic;
    m->idx = dk_xcalloc(ic, sizeof(u32));
    for (u32 i = 0; i < j; i++) exmap_index(m, i);
}

void exmap_free(ExMap *m) {
    dk_xfree(m->ent);
    dk_xfree(m->idx);
    memset(m, 0, sizeof *m);
}

void exmap_clear(ExMap *m) {
    m->n_ent = 0;
    m->n_live = 0;
    if (m->idx) memset(m->idx, 0, (size_t)m->idx_cap * sizeof(u32));
}

void exmap_copy(ExMap *dst, const ExMap *src) {
    memset(dst, 0, sizeof *dst);
    if (!src->n_live) return;
    u32 cap = src->n_live < 6 ? 8 : src->n_live + src->n_live / 2;
    dst->ent = dk_xmalloc((size_t)cap * sizeof(ExEnt));
    u32 j = 0;
    for (u32 i = 0; i < src->n_ent; i++)
        if (src->ent[i].live) dst->ent[j++] = src->ent[i];
    dst->n_ent = dst->n_live = j;
    dst->cap_ent = cap;
    u32 ic = 16;
    while (ic < cap * 2) ic <<= 1;
    dst->idx_cap = ic;
    dst->idx = dk_xcalloc(ic, sizeof(u32));
    for (u32 i = 0; i < j; i++) exmap_index(dst, i);
}

ExVal *exmap_get(const ExMap *m, u64 key) {
    if (!m->n_live) return NULL;
    u32 mask = m->idx_cap - 1;
    for (u32 s = hslot(key, mask);; s = (s + 1) & mask) {
        u32 v = m->idx[s];
        if (!v) return NULL;
        ExEnt *e = &m->ent[v - 1];
        if (e->live && e->key == key) return &e->val;
    }
}

ExVal *exmap_put(ExMap *m, u64 key, bool *created) {
    ExVal *v = exmap_get(m, key);
    if (v) {
        if (created) *created = false;
        return v;
    }
    if (m->n_ent == m->cap_ent) {
        u32 nc = m->cap_ent ? (m->n_live * 2 > m->cap_ent ? m->cap_ent * 2 : m->cap_ent) : 8;
        exmap_rebuild(m, nc);
    }
    ExEnt *e = &m->ent[m->n_ent];
    e->key = key;
    e->val.n = 0;
    e->val.e = NULL;
    e->live = true;
    exmap_index(m, m->n_ent);
    m->n_ent++;
    m->n_live++;
    if (created) *created = true;
    return &e->val;
}

bool exmap_del(ExMap *m, u64 key) {
    if (!m->n_live) return false;
    u32 mask = m->idx_cap - 1;
    for (u32 s = hslot(key, mask);; s = (s + 1) & mask) {
        u32 v = m->idx[s];
        if (!v) return false;
        ExEnt *e = &m->ent[v - 1];
        if (e->live && e->key == key) {
            e->live = false;
            m->n_live--;
            return true;
        }
    }
}

/* ------------------------------------------------------------------------------------------------- the algebra */
i64 eq2_signed(u64 n) {
    n &= EQ2_M32;
    return n & 0x80000000u ? (i64)n - ((i64)1 << 32) : (i64)n;
}

void terms_init(Terms *t, DkArena *a) {
    t->v = NULL;
    t->n = t->cap = 0;
    t->a = a;
}
Ex **terms_slot(Terms *t, Ex *k) {
    for (size_t i = 0; i < t->n; i++)
        if (t->v[i].k == k) return &t->v[i].v;
    if (t->n == t->cap) {
        size_t nc = t->cap ? t->cap * 2 : 8;
        Term *nv = dk_alloc_noz(t->a, nc * sizeof(Term));
        if (t->n) memcpy(nv, t->v, t->n * sizeof(Term));
        t->v = nv;
        t->cap = nc;
    }
    t->v[t->n].k = k;
    t->v[t->n].v = ex_int(0);
    return &t->v[t->n++].v;
}

void eq2_lin(Ex *e, Terms *t, u64 *c) {
    if (ex_is(e, EA(c))) {
        *c = ex_cval(e);
        return;
    }
    if (ex_is(e, EA(L))) {
        Ex *tl = e->el[1];
        for (u32 i = 0; i < tl->n; i++) *terms_slot(t, tl->el[i]->el[0]) = tl->el[i]->el[1];
        *c = (u64)e->el[2]->i;
        return;
    }
    *terms_slot(t, e) = ex_int(1);
    *c = 0;
}

static int pair_cmp(const void *a, const void *b) { return ex_repr_cmp(*(Ex *const *)a, *(Ex *const *)b); }

Ex *eq2_mklin(Terms *t, u64 constant) {
    size_t j = 0;
    for (size_t i = 0; i < t->n; i++) {
        Term tm = t->v[i];
        if (ex_is(tm.k, EA(c))) {
            constant += ex_cval(tm.k) * eq2_coef_lo64(tm.v);
            continue;
        }
        if (tm.v == ex_int(0)) continue;
        t->v[j++] = tm;
    }
    t->n = j;
    constant &= EQ2_M32;
    if (!t->n) return ex_c(constant);
    if (t->n == 1 && constant == 0 && t->v[0].v == ex_int(1)) return t->v[0].k;
    DkArena *a = dk_scratch();
    DkArenaMark mk = dk_arena_mark(a);
    Ex **pairs = dk_alloc_noz(a, t->n * sizeof(Ex *));
    for (size_t i = 0; i < t->n; i++) pairs[i] = ex_t2(t->v[i].k, t->v[i].v);
    if (t->n > 1) qsort(pairs, t->n, sizeof(Ex *), pair_cmp);
    Ex *r = ex_t3(EA(L), ex_tup(pairs, t->n), ex_uint(constant));
    dk_arena_reset(a, mk);
    return r;
}

Ex *eq2_add(Ex *a, Ex *b, int sign) {
    DkArena *ar = dk_scratch();
    DkArenaMark mk = dk_arena_mark(ar);
    Terms ta, tb;
    terms_init(&ta, ar);
    terms_init(&tb, ar);
    u64 ca = 0, cb = 0;
    eq2_lin(a, &ta, &ca);
    eq2_lin(b, &tb, &cb);
    for (size_t i = 0; i < tb.n; i++) {
        Ex **s = terms_slot(&ta, tb.v[i].k);
        *s = eq2_coef_add(*s, sign > 0 ? tb.v[i].v : eq2_coef_mul(tb.v[i].v, ex_int(sign)));
    }
    Ex *r = eq2_mklin(&ta, ca + (sign > 0 ? cb : (u64)0 - cb));
    dk_arena_reset(ar, mk);
    return r;
}

Ex *eq2_scale_ex(Ex *a, Ex *k) {
    DkArena *ar = dk_scratch();
    DkArenaMark mk = dk_arena_mark(ar);
    Terms t;
    terms_init(&t, ar);
    u64 c = 0;
    eq2_lin(a, &t, &c);
    for (size_t i = 0; i < t.n; i++) t.v[i].v = eq2_coef_mul(t.v[i].v, k);
    Ex *r = eq2_mklin(&t, c * eq2_coef_lo64(k));
    dk_arena_reset(ar, mk);
    return r;
}
Ex *eq2_scale(Ex *a, i64 k) { return eq2_scale_ex(a, ex_int(k)); }
Ex *eq2_scale_u(Ex *a, u64 k) { return eq2_scale_ex(a, ex_uint(k)); }

Ex *eq2_lo8(Ex *v) {
    if (ex_is(v, EA(c))) return ex_c(ex_cval(v) & 0xff);
    if (ex_is(v, EA(ins8))) return v->el[2];
    if (ex_is(v, EA(zx8))) return v->el[1];
    return ex_t2(EA(lo8), v);
}

Ex *eq2_zx8(Ex *v) {
    if (ex_is(v, EA(c))) return ex_c(ex_cval(v) & 0xff);
    return ex_t2(EA(zx8), v);
}

Ex *eq2_b8(Ex *x) {
    if (x->kind == EX_TUP && (ex_is(x, EA(ins8)) || ex_is(x, EA(zx8))))
        return ex_t2(EA(b8), ex_is(x, EA(ins8)) ? x->el[2] : x->el[1]);
    return x;
}

static Ex *ld_to4(Ex *x) {   /* ('ld', 4) + x[2:] */
    Ex *v[16];
    DK_ASSERT(x->n <= 16);
    v[0] = EA(ld);
    v[1] = ex_int(4);
    for (u32 i = 2; i < x->n; i++) v[i] = x->el[i];
    return ex_tup(v, x->n);
}

Ex *eq2_comm(Ex *op, Ex *a, Ex *b) {
    if (ex_isc(a) && ex_isc(b)) {
        if (op == EA(and)) return ex_c(ex_cval(a) & ex_cval(b));
        if (op == EA(or)) return ex_c(ex_cval(a) | ex_cval(b));
        if (op == EA(xor)) return ex_c(ex_cval(a) ^ ex_cval(b));
    }
    Ex *cm32 = ex_c(EQ2_M32), *c0 = ex_c(0);
    if (op == EA(and) && (a == cm32 || b == cm32)) return a == cm32 ? b : a;
    if (op == EA(and)) {
        for (int pass = 0; pass < 2; pass++) {
            Ex *c_ = pass ? b : a, *x_ = pass ? a : b;
            if (ex_isc(c_) && ex_cval(c_) && (ex_cval(c_) & (ex_cval(c_) - 1)) == 0) {
                u64 cv = ex_cval(c_);
                unsigned long k_l;
                _BitScanReverse64(&k_l, cv);
                int k_ = (int)k_l;
                if (ex_is(x_, EA(lo8))) x_ = x_->el[1];
                if (ex_is(x_, EA(ld)) && (x_->el[1]->i == 1 || x_->el[1]->i == 2) && k_ < 8) x_ = ld_to4(x_);
                if ((ex_is(x_, EA(shr)) || ex_is(x_, EA(sar))) && ex_isc(x_->el[2]) && cv == 1)
                    return ex_t3(EA(bit), x_->el[1], x_->el[2]->el[1]);
                if (cv == 1 || !ex_is(x_, EA(shr))) {
                    if (ex_is(x_, EA(ld)) && (x_->el[1]->i == 1 || x_->el[1]->i == 2) && k_ < 8) x_ = ld_to4(x_);
                    return ex_t3(EA(bit), x_, ex_int(k_));
                }
            }
        }
    }
    if (op == EA(or) && (a == cm32 || b == cm32)) return cm32;
    if (op == EA(and) && (a == c0 || b == c0)) return c0;
    if ((op == EA(or) || op == EA(xor)) && (a == c0 || b == c0)) return a == c0 ? b : a;
    if (op == EA(xor) && a == b) return c0;
    eq2_sort2(&a, &b);
    return ex_t3(op, a, b);
}

bool eq2_eqv(Ex *a, Ex *b) {
    if (a == b) return true;
    if (ex_is(a, EA(lo8)) && eq2_eqv(a->el[1], b)) return true;
    if (ex_is(b, EA(lo8)) && eq2_eqv(b->el[1], a)) return true;
    if (a->kind == EX_TUP && b->kind == EX_TUP) {
        if (ex_is(a, EA(clob)) || ex_is(a, EA(clobx)) || ex_is(b, EA(clob)) || ex_is(b, EA(clobx))) return true;
        if (a->n != b->n) return false;
        if (ex_is(a, EA(ld)) && a->n == 4) return a->el[0] == b->el[0] && a->el[1] == b->el[1] && eq2_eqv(a->el[2], b->el[2]);
        for (u32 i = 0; i < a->n; i++)
            if (!eq2_eqv(a->el[i], b->el[i])) return false;
        return true;
    }
    return false;
}

Ex *eq2_canon_e(Ex *e) {
    if (e->kind != EX_TUP || !e->n) return e;
    DkArena *ar = dk_scratch();
    DkArenaMark mk = dk_arena_mark(ar);
    Ex **v = dk_alloc_noz(ar, e->n * sizeof(Ex *));
    for (u32 i = 0; i < e->n; i++) v[i] = e->el[i]->kind == EX_TUP ? eq2_canon_e(e->el[i]) : e->el[i];
    e = ex_tup(v, e->n);
    dk_arena_reset(ar, mk);
    if (ex_is(e, EA(zx16)) && e->el[1]->kind == EX_TUP && ex_is(e->el[1], EA(lo16)) && e->el[1]->el[1]->kind == EX_TUP &&
        ex_is(e->el[1]->el[1], EA(zx16)))
        return e->el[1]->el[1];
    if (ex_is(e, EA(and)) && e->n == 3) {
        Ex *c1 = ex_c(1), *l1 = ex_t2(EA(lo8), c1);
        for (int pass = 0; pass < 2; pass++) {
            Ex *p = pass ? e->el[2] : e->el[1], *q = pass ? e->el[1] : e->el[2];
            if ((p == l1 || p == c1) && q->kind == EX_TUP && ex_is(q, EA(lo8))) q = q->el[1];
            if ((p == l1 || p == c1) && q->kind == EX_TUP && ex_is(q, EA(shr)) && ex_isc(q->el[2]))
                return ex_t3(EA(bit), q->el[1], q->el[2]->el[1]);
        }
    }
    return e;
}

static int popcount64(u64 x) {
    int n = 0;
    for (; x; x &= x - 1) n++;
    return n;
}

static Ex *mkcond(Ex *dom, unsigned outs, Ex *a, Ex *b) { return ex_t4(dom, ex_fset(outs), a, b); }

static unsigned swap_outs(unsigned o) {   /* {SW[o] for o in outs}: lt <-> gt */
    unsigned r = o & (OUT_EQ | OUT_UN);
    if (o & OUT_LT) r |= OUT_GT;
    if (o & OUT_GT) r |= OUT_LT;
    return r;
}

Ex *eq2_canon_c(Ex *c) {
    Ex *dom = c->el[0];
    unsigned outs = (unsigned)c->el[1]->i;
    Ex *a = eq2_canon_e(c->el[2]), *b = eq2_canon_e(c->el[3]);
    if (dom == EA(d_s) && a->kind == EX_TUP && ex_is(a, EA(bit)) && a->el[2]->i == 31 && b == ex_c(0) &&
        (outs == OUT_EQ || outs == (OUT_LT | OUT_GT))) {
        Ex *x = a->el[1];
        if (outs == OUT_EQ) return mkcond(EA(d_s), OUT_EQ | OUT_LT, ex_c(0), x);
        return mkcond(EA(d_s), OUT_GT, ex_c(0), x);
    }
    if ((dom == EA(d_s) || dom == EA(d_u)) && ex_repr_cmp(a, b) > 0) {
        Ex *t = a;
        a = b;
        b = t;
        outs = swap_outs(outs);
    }
    return mkcond(dom, outs, a, b);
}

bool eq2_cond_eq(Ex *c1, Ex *c2) {
    if (c1->el[0] == c2->el[0] && c1->el[1] == c2->el[1] && eq2_eqv(c1->el[2], c2->el[2]) && eq2_eqv(c1->el[3], c2->el[3])) return true;
    Ex *d1 = eq2_canon_c(c1), *d2 = eq2_canon_c(c2);
    return d1->el[0] == d2->el[0] && d1->el[1] == d2->el[1] && eq2_eqv(d1->el[2], d2->el[2]) && eq2_eqv(d1->el[3], d2->el[3]);
}

/* subst: _subst_old with the override of L1818-1830 applied at every level (the old function calls the global name). */
static Ex *subst_fix(Ex *r) {
    if (r->kind == EX_TUP && r->n == 4 && ex_is(r, EA(sbb)) && r->el[1] == r->el[2] && r->el[3]->kind == EX_TUP &&
        r->el[3]->n && ex_is(r->el[3], EA(negflags))) {
        Ex *x = r->el[3]->el[1];
        if (x->kind == EX_TUP && ex_is(x, EA(c))) return ex_c(ex_cval(x) == 0 ? 0 : EQ2_M32);
        if (x->kind == EX_TUP && ex_is(x, EA(bit))) return eq2_scale(x, -1);
    }
    return r;
}

Ex *eq2_subst(Ex *e, const ExMap *facts) {
    Ex *r = e;
    if (facts->n_live && e->kind == EX_TUP) {
        ExVal *f = exmap_get(facts, exkey(e));
        if (f) {
            r = f->e;
        } else if (ex_is(e, EA(c))) {
            r = e;
        } else if (ex_is(e, EA(L))) {
            r = ex_c((u64)e->el[2]->i);
            Ex *tl = e->el[1];
            for (u32 i = 0; i < tl->n; i++) r = eq2_add(r, eq2_scale_ex(eq2_subst(tl->el[i]->el[0], facts), tl->el[i]->el[1]), 1);
        } else if (e->n) {
            DkArena *ar = dk_scratch();
            DkArenaMark mk = dk_arena_mark(ar);
            Ex **v = dk_alloc_noz(ar, e->n * sizeof(Ex *));
            for (u32 i = 0; i < e->n; i++) v[i] = e->el[i]->kind == EX_TUP ? eq2_subst(e->el[i], facts) : e->el[i];
            r = ex_tup(v, e->n);
            dk_arena_reset(ar, mk);
        }
    }
    return subst_fix(r);
}

Ex *eq2_cond_subst(Ex *c, const ExMap *facts) {
    return ex_t4(c->el[0], c->el[1], eq2_subst(c->el[2], facts), eq2_subst(c->el[3], facts));
}

int eq2_eval_const_cond(Ex *c) {
    Ex *dom = c->el[0];
    Ex *a = c->el[2], *b = c->el[3];
    if ((dom != EA(d_s) && dom != EA(d_u)) || !ex_isc(a) || !ex_isc(b)) return -1;
    u64 x = ex_cval(a), y = ex_cval(b);
    int o;
    if (dom == EA(d_s)) {
        i64 sx = eq2_signed(x), sy = eq2_signed(y);
        o = sx < sy ? OUT_LT : (sx == sy ? OUT_EQ : OUT_GT);
    } else {
        o = x < y ? OUT_LT : (x == y ? OUT_EQ : OUT_GT);
    }
    return (c->el[1]->i & o) != 0;
}

void eq2_add_fact(ExMap *facts, Ex *c, bool taken) {
    Ex *dom = c->el[0];
    Ex *a = c->el[2], *b = c->el[3];
    if (dom != EA(d_s) && dom != EA(d_u)) return;
    unsigned outs = taken ? (unsigned)c->el[1]->i : (unsigned)((OUT_LT | OUT_EQ | OUT_GT) & ~c->el[1]->i);
    if (outs == (OUT_LT | OUT_GT)) {
        for (int pass = 0; pass < 2; pass++) {
            Ex *x_ = pass ? b : a, *y_ = pass ? a : b;
            if (y_ == ex_c(0) && x_->kind == EX_TUP && ex_is(x_, EA(bit))) exmap_put(facts, exkey(x_), NULL)->e = ex_c(1);
        }
    }
    if (outs == OUT_EQ) {
        if (ex_isc(a) && !ex_isc(b)) exmap_put(facts, exkey(b), NULL)->e = a;
        else if (ex_isc(b) && !ex_isc(a)) exmap_put(facts, exkey(a), NULL)->e = b;
    }
}

/* JCC / JCC_F / SETCC / CMOV */
typedef struct { const char *mn; int dom; unsigned outs; } JccEnt;   /* dom: 0 i, 1 s, 2 u, 3 sg */
static const JccEnt JCC[] = {
    {"je", 0, OUT_EQ}, {"jne", 0, OUT_LT | OUT_GT}, {"jz", 0, OUT_EQ}, {"jnz", 0, OUT_LT | OUT_GT},
    {"jl", 1, OUT_LT}, {"jle", 1, OUT_LT | OUT_EQ}, {"jg", 1, OUT_GT}, {"jge", 1, OUT_GT | OUT_EQ},
    {"jb", 2, OUT_LT}, {"jbe", 2, OUT_LT | OUT_EQ}, {"ja", 2, OUT_GT}, {"jae", 2, OUT_GT | OUT_EQ},
    {"js", 3, OUT_LT}, {"jns", 3, OUT_GT | OUT_EQ},
};
static const struct { const char *mn; unsigned outs; } JCC_F[] = {
    {"ja", OUT_GT}, {"jae", OUT_GT | OUT_EQ}, {"jb", OUT_LT | OUT_UN}, {"jbe", OUT_LT | OUT_EQ | OUT_UN},
    {"je", OUT_EQ | OUT_UN}, {"jz", OUT_EQ | OUT_UN}, {"jne", OUT_GT | OUT_LT}, {"jnz", OUT_GT | OUT_LT},
    {"jp", OUT_UN}, {"jnp", OUT_GT | OUT_LT | OUT_EQ},
};
static const char *const SETCC[][2] = {
    {"sete", "je"}, {"setne", "jne"}, {"setl", "jl"}, {"setle", "jle"}, {"setg", "jg"}, {"setge", "jge"},
    {"setb", "jb"}, {"setbe", "jbe"}, {"seta", "ja"}, {"setae", "jae"}, {"sets", "js"}, {"setns", "jns"},
    {"setp", "jp"}, {"setnp", "jnp"}, {"setz", "jz"}, {"setnz", "jnz"},
};
static const char *const CMOV[][2] = {
    {"cmove", "je"}, {"cmovne", "jne"}, {"cmovl", "jl"}, {"cmovle", "jle"}, {"cmovg", "jg"}, {"cmovge", "jge"},
    {"cmovb", "jb"}, {"cmovbe", "jbe"}, {"cmova", "ja"}, {"cmovae", "jae"}, {"cmovs", "js"}, {"cmovns", "jns"},
    {"cmovz", "je"}, {"cmovnz", "jne"}, {"cmovp", "jp"}, {"cmovnp", "jnp"},
};

static const JccEnt *jcc_find(const char *mn) {
    for (size_t i = 0; i < DK_ARRAY_LEN(JCC); i++)
        if (!strcmp(JCC[i].mn, mn)) return &JCC[i];
    return NULL;
}
static int jccf_find(const char *mn) {
    for (size_t i = 0; i < DK_ARRAY_LEN(JCC_F); i++)
        if (!strcmp(JCC_F[i].mn, mn)) return (int)i;
    return -1;
}
bool eq2_cond_mnemonic(const char *mn) { return jcc_find(mn) || jccf_find(mn) >= 0; }
const char *eq2_setcc_jname(const char *mn) {
    for (size_t i = 0; i < DK_ARRAY_LEN(SETCC); i++)
        if (!strcmp(SETCC[i][0], mn)) return SETCC[i][1];
    return NULL;
}
const char *eq2_cmov_jname(const char *mn) {
    for (size_t i = 0; i < DK_ARRAY_LEN(CMOV); i++)
        if (!strcmp(CMOV[i][0], mn)) return CMOV[i][1];
    return NULL;
}

Ex *eq2_make_cond(Ex *flags, const char *jname) {
    if (!flags) eq2_unsupported("branch without flags");
    Ex *kind = flags->el[0];
    Ex *a, *b, *dom;
    unsigned outs;
    if (kind == EA(fahmask)) {
        static const struct { unsigned o; unsigned bits; } enc[4] = {{OUT_GT, 0}, {OUT_LT, 0x01}, {OUT_EQ, 0x40}, {OUT_UN, 0x45}};
        u64 mask = (u64)flags->el[3]->i;
        outs = 0;
        for (int i = 0; i < 4; i++) {
            u64 res = enc[i].bits & mask;
            bool par_even = (popcount64(res) % 2) == 0;
            bool taken;
            if (!strcmp(jname, "je") || !strcmp(jname, "jz")) taken = res == 0;
            else if (!strcmp(jname, "jne") || !strcmp(jname, "jnz")) taken = res != 0;
            else if (!strcmp(jname, "jp")) taken = par_even;
            else if (!strcmp(jname, "jnp")) taken = !par_even;
            else eq2_unsupported("branch after lahf test %s", jname);
            if (taken) outs |= enc[i].o;
        }
        a = flags->el[1];
        b = flags->el[2];
        if (ex_repr_cmp(a, b) > 0) {
            Ex *t = a;
            a = b;
            b = t;
            outs = swap_outs(outs);
        }
        return mkcond(EA(d_f), outs, a, b);
    }
    if (kind == EA(fcmp)) {
        int fi = jccf_find(jname);
        if (fi < 0) eq2_unsupported("float branch %s", jname);
        outs = JCC_F[fi].outs;
        a = flags->el[1];
        b = flags->el[2];
        dom = EA(d_f);
    } else {
        const JccEnt *j = jcc_find(jname);
        if (!j) eq2_unsupported("branch %s", jname);
        outs = j->outs;
        dom = j->dom == 2 ? EA(d_u) : EA(d_s);   /* 'i' and 'sg' become 's' in both the cmp and the res forms */
        if (kind == EA(cmp)) {
            a = flags->el[1];
            b = flags->el[2];
        } else {
            a = flags->el[1];
            b = ex_c(0);
        }
    }
    if (ex_repr_cmp(a, b) > 0) {
        Ex *t = a;
        a = b;
        b = t;
        outs = swap_outs(outs);
    }
    return mkcond(dom, outs, a, b);
}

Ex *eq2_negate_cond(Ex *c) {
    unsigned all = OUT_LT | OUT_EQ | OUT_GT | (c->el[0] == EA(d_f) ? OUT_UN : 0);
    return ex_t4(c->el[0], ex_fset(all & ~(unsigned)c->el[1]->i), c->el[2], c->el[3]);
}

/* dbl_to_f32(n) */
Ex *eq2_dbl_to_f32(u64 n) {
    double d;
    memcpy(&d, &n, 8);
    float f = (float)d;
    if ((double)f == d) {
        u32 bits;
        memcpy(&bits, &f, 4);
        return ex_c(bits);
    }
    return ex_craw(n);
}

static bool parse_hex_lower(const char *s, size_t *len, u64 *val, bool *overflow) {
    size_t i = 0;
    u64 v = 0;
    *overflow = false;
    while ((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')) {
        unsigned d = s[i] <= '9' ? (unsigned)(s[i] - '0') : (unsigned)(s[i] - 'a' + 10);
        if (v >> 60) *overflow = true;
        v = (v << 4) | d;
        i++;
    }
    *len = i;
    *val = v;
    return i > 0 && s[i] == 0;   /* the regex's `[0-9a-f]+$` */
}

Ex *eq2_const_from_symbol(const char *sym, int size) {
    DK_UNUSED(size);
    size_t len;
    u64 v;
    bool ovf;
    if (!strncmp(sym, "__real@", 7) && parse_hex_lower(sym + 7, &len, &v, &ovf)) {
        if (len > 8) {
            /* n >= 2**64: struct.pack('<Q', n) raises outside dbl_to_f32's try */
            if (ovf) eq2_crash("error(\"'Q' format requires 0 <= number <= 18446744073709551615\")");
            return eq2_dbl_to_f32(v);
        }
        return ex_craw(v);
    }
    if (!strncmp(sym, "__xmm@", 6) && parse_hex_lower(sym + 6, &len, &v, &ovf)) {
        /* only the low 32 bits matter: parse the last 8 digits */
        const char *tail = sym + 6 + (len > 8 ? len - 8 : 0);
        u64 w = 0;
        for (const char *p = tail; *p; p++) w = (w << 4) | (u64)(*p <= '9' ? *p - '0' : *p - 'a' + 10);
        return ex_craw(w & EQ2_M32);
    }
    if (strstr(sym, "AbsFloat")) return ex_c(0x7fffffff);
    if (strstr(sym, "NegFloat") || strstr(sym, "SignFloat")) return ex_c(0x80000000u);
    return ex_t2(EA(sym), ex_str(sym));
}
