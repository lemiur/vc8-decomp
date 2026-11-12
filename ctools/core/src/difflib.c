// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* difflib.h: Python 3.14's SequenceMatcher and unified_diff. The control flow of find_longest_match,
 * get_matching_blocks, get_opcodes, get_grouped_opcodes, ratio and quick_ratio is CPython's, line for line; only the
 * data structures differ (dense element ids, a CSR table for b2j and arrays for j2len instead of dicts). */
#include "dk/difflib.h"

#include <stdlib.h>

const DkSeqOpts dk_seqm_no_autojunk = {true, NULL, NULL};

enum { FLAG_JUNK = 1, FLAG_POPULAR = 2 };

struct DkSeqMatcher {
    DkArena *arena;
    size_t la, lb;
    u32 *a, *b;        /* dense element ids */
    u32 nids;          /* distinct elements over a and b */
    u32 *b2j_start;    /* nids + 1 offsets into b2j_idx; the range of a junk or popular element is empty */
    u32 *b2j_idx;      /* indices into b, increasing within an element */
    u8 *flags;         /* per id: FLAG_JUNK (isjunk), FLAG_POPULAR (autojunk) */
    u32 *bcount;       /* per id: occurrences in b (fullbcount) */
    u32 *j2len[2];     /* find_longest_match's scratch, all zero between calls; entry j + 1 is for b[j] */
    DkMatch *blocks;
    size_t nblocks;
    bool have_blocks;
    DkOpcode *ops;
    size_t nops;
    bool have_ops;
};

const char *dk_op_name(DkOpTag tag) {
    switch (tag) {
    case DK_OP_REPLACE: return "replace";
    case DK_OP_DELETE: return "delete";
    case DK_OP_INSERT: return "insert";
    default: return "equal";
    }
}

/* ---- interning ------------------------------------------------------------------------------------------------- */
static u64 mix64(u64 h) {
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

static u64 hash_bytes(const char *p, size_t n) {
    u64 h = 0x9E3779B97F4A7C15ULL ^ (u64)n;
    while (n >= 8) {
        u64 w;
        memcpy(&w, p, 8);
        h = (h ^ w) * 0x9FB21C651E98DF25ULL;
        h ^= h >> 29;
        p += 8;
        n -= 8;
    }
    u64 w = 0;
    if (n) memcpy(&w, p, n);
    h = (h ^ w) * 0x9FB21C651E98DF25ULL;
    return mix64(h);
}

static size_t table_size(size_t count) {
    size_t cap = 16;
    while (cap < count * 2 + 2) cap <<= 1;
    return cap;
}

typedef struct {
    u64 hash;
    const char *p;
    size_t n;
    u32 id1; /* id + 1; 0 = empty slot */
} StrSlot;

/* Gives every distinct string of a and b a dense id (equal bytes, equal id). Returns the number of ids. */
static u32 intern_strs(const DkStr *a, size_t na, const DkStr *b, size_t nb, u32 *ida, u32 *idb) {
    size_t cap = table_size(na + nb);
    StrSlot *tab = (StrSlot *)dk_xcalloc(cap, sizeof(StrSlot));
    size_t mask = cap - 1;
    u32 next = 0;
    for (int pass = 0; pass < 2; pass++) {
        const DkStr *seq = pass ? b : a;
        size_t count = pass ? nb : na;
        u32 *out = pass ? idb : ida;
        for (size_t i = 0; i < count; i++) {
            u64 h = hash_bytes(seq[i].p, seq[i].n);
            size_t s = (size_t)h & mask;
            for (;;) {
                StrSlot *e = &tab[s];
                if (!e->id1) {
                    e->hash = h;
                    e->p = seq[i].p;
                    e->n = seq[i].n;
                    e->id1 = ++next;
                    out[i] = next - 1;
                    break;
                }
                if (e->hash == h && e->n == seq[i].n && (e->n == 0 || memcmp(e->p, seq[i].p, e->n) == 0)) {
                    out[i] = e->id1 - 1;
                    break;
                }
                s = (s + 1) & mask;
            }
        }
    }
    dk_xfree(tab);
    return next;
}

typedef struct {
    u64 key;
    u32 id1;
} IntSlot;

/* The same for u64 values; vals (nids entries, may be NULL) receives the value of every id. */
static u32 intern_u64s(const u64 *a, size_t na, const u64 *b, size_t nb, u32 *ida, u32 *idb, u64 *vals) {
    size_t cap = table_size(na + nb);
    IntSlot *tab = (IntSlot *)dk_xcalloc(cap, sizeof(IntSlot));
    size_t mask = cap - 1;
    u32 next = 0;
    for (int pass = 0; pass < 2; pass++) {
        const u64 *seq = pass ? b : a;
        size_t count = pass ? nb : na;
        u32 *out = pass ? idb : ida;
        for (size_t i = 0; i < count; i++) {
            size_t s = (size_t)mix64(seq[i]) & mask;
            for (;;) {
                IntSlot *e = &tab[s];
                if (!e->id1) {
                    e->key = seq[i];
                    e->id1 = ++next;
                    out[i] = next - 1;
                    if (vals) vals[next - 1] = seq[i];
                    break;
                }
                if (e->key == seq[i]) {
                    out[i] = e->id1 - 1;
                    break;
                }
                s = (s + 1) & mask;
            }
        }
    }
    dk_xfree(tab);
    return next;
}

/* SequenceMatcher.__chain_b: b2j without the junk and the popular elements. vals is the value of every id (for
 * isjunk) or NULL. */
static void chain_b(DkSeqMatcher *m, const DkSeqOpts *opts, const u64 *vals) {
    DkArena *ar = m->arena;
    u32 nids = m->nids;
    size_t lb = m->lb;
    m->bcount = DK_NEWN(ar, u32, nids + 1);
    for (size_t j = 0; j < lb; j++) m->bcount[m->b[j]]++;
    m->flags = DK_NEWN(ar, u8, nids + 1);
    u32 *cnt = (u32 *)dk_xcalloc((size_t)nids + 1, sizeof(u32));
    memcpy(cnt, m->bcount, sizeof(u32) * nids);
    if (opts && opts->isjunk && vals) {
        for (u32 id = 0; id < nids; id++) {
            if (cnt[id] && opts->isjunk(opts->ctx, vals[id])) {
                m->flags[id] |= FLAG_JUNK;
                cnt[id] = 0;
            }
        }
    }
    bool autojunk = !(opts && opts->no_autojunk);
    if (autojunk && lb >= 200) {
        size_t ntest = lb / 100 + 1;
        for (u32 id = 0; id < nids; id++) {
            if (cnt[id] > ntest) {
                m->flags[id] |= FLAG_POPULAR;
                cnt[id] = 0;
            }
        }
    }
    m->b2j_start = DK_NEWN(ar, u32, nids + 2);
    u32 total = 0;
    for (u32 id = 0; id < nids; id++) {
        m->b2j_start[id] = total;
        total += cnt[id];
    }
    m->b2j_start[nids] = total;
    m->b2j_idx = DK_NEWN(ar, u32, (size_t)total + 1);
    /* fill in b order: cnt becomes the write cursor of each id */
    for (u32 id = 0; id < nids; id++) cnt[id] = m->b2j_start[id];
    for (size_t j = 0; j < lb; j++) {
        u32 id = m->b[j];
        if (m->flags[id]) continue;
        m->b2j_idx[cnt[id]++] = (u32)j;
    }
    dk_xfree(cnt);
    m->j2len[0] = DK_NEWN(ar, u32, lb + 2);
    m->j2len[1] = DK_NEWN(ar, u32, lb + 2);
}

static DkSeqMatcher *seqm_alloc(DkArena *arena, size_t na, size_t nb) {
    DK_ASSERT(na < UINT32_MAX && nb < UINT32_MAX);
    if (!arena) arena = dk_arena();
    DkSeqMatcher *m = DK_NEW(arena, DkSeqMatcher);
    m->arena = arena;
    m->la = na;
    m->lb = nb;
    m->a = DK_NEWN(arena, u32, na + 1);
    m->b = DK_NEWN(arena, u32, nb + 1);
    return m;
}

DkSeqMatcher *dk_seqm_new_str(DkArena *arena, const DkStr *a, size_t na, const DkStr *b, size_t nb,
                                const DkSeqOpts *opts) {
    DkSeqMatcher *m = seqm_alloc(arena, na, nb);
    m->nids = intern_strs(a, na, b, nb, m->a, m->b);
    chain_b(m, opts, NULL);
    return m;
}

DkSeqMatcher *dk_seqm_new_u64(DkArena *arena, const u64 *a, size_t na, const u64 *b, size_t nb,
                                const DkSeqOpts *opts) {
    DkSeqMatcher *m = seqm_alloc(arena, na, nb);
    u64 *vals = (u64 *)dk_xmalloc((na + nb + 1) * sizeof(u64));
    m->nids = intern_u64s(a, na, b, nb, m->a, m->b, vals);
    chain_b(m, opts, vals);
    dk_xfree(vals);
    return m;
}

DkSeqMatcher *dk_seqm_new_u32(DkArena *arena, const u32 *a, size_t na, const u32 *b, size_t nb,
                                const DkSeqOpts *opts) {
    u64 *wide = (u64 *)dk_xmalloc((na + nb + 1) * sizeof(u64));
    for (size_t i = 0; i < na; i++) wide[i] = a[i];
    for (size_t j = 0; j < nb; j++) wide[na + j] = b[j];
    DkSeqMatcher *m = dk_seqm_new_u64(arena, wide, na, wide + na, nb, opts);
    dk_xfree(wide);
    return m;
}

static u32 *decode_cps(const char *p, size_t n, size_t *count) {
    u32 *out = (u32 *)dk_xmalloc((n + 1) * sizeof(u32));
    size_t k = 0;
    const char *end = p + n;
    while (p < end) out[k++] = dk_u8_next(&p, end);
    *count = k;
    return out;
}

DkSeqMatcher *dk_seqm_new_text(DkArena *arena, DkStr a, DkStr b, const DkSeqOpts *opts) {
    size_t na, nb;
    u32 *ca = decode_cps(a.p, a.n, &na);
    u32 *cb = decode_cps(b.p, b.n, &nb);
    DkSeqMatcher *m = dk_seqm_new_u32(arena, ca, na, cb, nb, opts);
    dk_xfree(ca);
    dk_xfree(cb);
    return m;
}

size_t dk_seqm_len_a(const DkSeqMatcher *m) { return m->la; }
size_t dk_seqm_len_b(const DkSeqMatcher *m) { return m->lb; }

/* ---- find_longest_match ---------------------------------------------------------------------------------------- */
DkMatch dk_seqm_find_longest_match(DkSeqMatcher *m, size_t alo, size_t ahi, size_t blo, size_t bhi) {
    if (ahi == DK_SEQ_END) ahi = m->la;
    if (bhi == DK_SEQ_END) bhi = m->lb;
    const u32 *a = m->a, *b = m->b;
    const u32 *start = m->b2j_start, *idx = m->b2j_idx;
    const u8 *flags = m->flags;
    size_t besti = alo, bestj = blo, bestsize = 0;

    /* j2len[j + 1] = length of the longest junk-free match ending with a[i-1] and b[j] (prev), and the same for
     * a[i] (cur); entry 0 stays zero so that j - 1 == -1 reads 0. Only the entries set in an iteration are cleared
     * in the next one, so a call costs what CPython's dicts cost. */
    u32 *prev = m->j2len[0], *cur = m->j2len[1];
    u32 prev_lo = 0, prev_hi = 0; /* the b2j_idx range set in prev */
    for (size_t i = alo; i < ahi; i++) {
        u32 id = a[i];
        u32 s = start[id], e = start[id + 1];
        /* skip the indices below blo (CPython's `if j < blo: continue`) with a binary search */
        u32 lo = s, hi = e;
        while (lo < hi) {
            u32 mid = lo + (hi - lo) / 2;
            if (idx[mid] < blo) lo = mid + 1;
            else hi = mid;
        }
        u32 p = lo;
        for (; p < e; p++) {
            size_t j = idx[p];
            if (j >= bhi) break; /* CPython: `if j >= bhi: break` */
            u32 k = prev[j] + 1;
            cur[j + 1] = k;
            if (k > bestsize) {
                besti = i - k + 1;
                bestj = j - k + 1;
                bestsize = k;
            }
        }
        /* prev becomes the next iteration's scratch: clear what it held */
        for (u32 q = prev_lo; q < prev_hi; q++) prev[idx[q] + 1] = 0;
        u32 *t = prev;
        prev = cur;
        cur = t;
        prev_lo = lo;
        prev_hi = p;
    }
    for (u32 q = prev_lo; q < prev_hi; q++) prev[idx[q] + 1] = 0;

    /* Extend the best by non-junk elements on each end ("popular" elements are not in b2j), then by junk. */
    while (besti > alo && bestj > blo && !(flags[b[bestj - 1]] & FLAG_JUNK) && a[besti - 1] == b[bestj - 1]) {
        besti--;
        bestj--;
        bestsize++;
    }
    while (besti + bestsize < ahi && bestj + bestsize < bhi && !(flags[b[bestj + bestsize]] & FLAG_JUNK) &&
           a[besti + bestsize] == b[bestj + bestsize])
        bestsize++;
    while (besti > alo && bestj > blo && (flags[b[bestj - 1]] & FLAG_JUNK) && a[besti - 1] == b[bestj - 1]) {
        besti--;
        bestj--;
        bestsize++;
    }
    while (besti + bestsize < ahi && bestj + bestsize < bhi && (flags[b[bestj + bestsize]] & FLAG_JUNK) &&
           a[besti + bestsize] == b[bestj + bestsize])
        bestsize++;
    DkMatch r = {besti, bestj, bestsize};
    return r;
}

/* ---- get_matching_blocks --------------------------------------------------------------------------------------- */
static int match_cmp(const void *x, const void *y) {
    const DkMatch *p = (const DkMatch *)x, *q = (const DkMatch *)y;
    /* tuple order (a, b, size), as matching_blocks.sort() */
    if (p->a != q->a) return p->a < q->a ? -1 : 1;
    if (p->b != q->b) return p->b < q->b ? -1 : 1;
    if (p->size != q->size) return p->size < q->size ? -1 : 1;
    return 0;
}

typedef struct {
    size_t alo, ahi, blo, bhi;
} Range4;

const DkMatch *dk_seqm_matching_blocks(DkSeqMatcher *m, size_t *count) {
    if (!m->have_blocks) {
        size_t la = m->la, lb = m->lb;
        DK_VEC(Range4) queue = {0};
        DK_VEC(DkMatch) found = {0};
        Range4 whole = {0, la, 0, lb};
        dk_vec_push(&queue, whole);
        while (queue.n) {
            Range4 q = dk_vec_pop(&queue);
            DkMatch x = dk_seqm_find_longest_match(m, q.alo, q.ahi, q.blo, q.bhi);
            size_t i = x.a, j = x.b, k = x.size;
            if (k) { /* if k is 0, there was no matching block */
                dk_vec_push(&found, x);
                if (q.alo < i && q.blo < j) {
                    Range4 l = {q.alo, i, q.blo, j};
                    dk_vec_push(&queue, l);
                }
                if (i + k < q.ahi && j + k < q.bhi) {
                    Range4 r = {i + k, q.ahi, j + k, q.bhi};
                    dk_vec_push(&queue, r);
                }
            }
        }
        if (found.n > 1) qsort(found.v, found.n, sizeof(DkMatch), match_cmp);
        /* collapse adjacent equal blocks */
        DkMatch *out = DK_NEWN(m->arena, DkMatch, found.n + 1);
        size_t no = 0;
        size_t i1 = 0, j1 = 0, k1 = 0;
        for (size_t t = 0; t < found.n; t++) {
            size_t i2 = found.v[t].a, j2 = found.v[t].b, k2 = found.v[t].size;
            if (i1 + k1 == i2 && j1 + k1 == j2) {
                k1 += k2;
            } else {
                if (k1) {
                    DkMatch nm = {i1, j1, k1};
                    out[no++] = nm;
                }
                i1 = i2;
                j1 = j2;
                k1 = k2;
            }
        }
        if (k1) {
            DkMatch nm = {i1, j1, k1};
            out[no++] = nm;
        }
        DkMatch sentinel = {la, lb, 0};
        out[no++] = sentinel;
        m->blocks = out;
        m->nblocks = no;
        m->have_blocks = true;
        dk_vec_free(&queue);
        dk_vec_free(&found);
    }
    *count = m->nblocks;
    return m->blocks;
}

/* ---- get_opcodes, get_grouped_opcodes -------------------------------------------------------------------------- */
const DkOpcode *dk_seqm_opcodes(DkSeqMatcher *m, size_t *count) {
    if (!m->have_ops) {
        size_t nb;
        const DkMatch *blocks = dk_seqm_matching_blocks(m, &nb);
        DkOpcode *out = DK_NEWN(m->arena, DkOpcode, nb * 2 + 1);
        size_t no = 0, i = 0, j = 0;
        for (size_t t = 0; t < nb; t++) {
            size_t ai = blocks[t].a, bj = blocks[t].b, size = blocks[t].size;
            bool tagged = true;
            DkOpTag tag = DK_OP_EQUAL;
            if (i < ai && j < bj) tag = DK_OP_REPLACE;
            else if (i < ai) tag = DK_OP_DELETE;
            else if (j < bj) tag = DK_OP_INSERT;
            else tagged = false;
            if (tagged) {
                DkOpcode op = {tag, i, ai, j, bj};
                out[no++] = op;
            }
            i = ai + size;
            j = bj + size;
            if (size) {
                DkOpcode op = {DK_OP_EQUAL, ai, i, bj, j};
                out[no++] = op;
            }
        }
        m->ops = out;
        m->nops = no;
        m->have_ops = true;
    }
    *count = m->nops;
    return m->ops;
}

static i64 i64max(i64 x, i64 y) { return x > y ? x : y; }
static i64 i64min(i64 x, i64 y) { return x < y ? x : y; }

const DkOpGroup *dk_seqm_grouped_opcodes(DkSeqMatcher *m, i64 n, size_t *ngroups) {
    size_t nc;
    const DkOpcode *orig = dk_seqm_opcodes(m, &nc);
    DkArena *ar = m->arena;
    DkOpcode *codes = DK_NEWN(ar, DkOpcode, nc + 1);
    if (nc) memcpy(codes, orig, nc * sizeof(DkOpcode));
    else {
        DkOpcode dummy = {DK_OP_EQUAL, 0, 1, 0, 1}; /* `if not codes: codes = [("equal", 0, 1, 0, 1)]` */
        codes[0] = dummy;
        nc = 1;
    }
    /* Fixup leading and trailing groups if they show no changes. */
    if (codes[0].tag == DK_OP_EQUAL) {
        i64 i1 = (i64)codes[0].i1, i2 = (i64)codes[0].i2, j1 = (i64)codes[0].j1, j2 = (i64)codes[0].j2;
        codes[0].i1 = (size_t)i64max(i1, i2 - n);
        codes[0].j1 = (size_t)i64max(j1, j2 - n);
    }
    if (codes[nc - 1].tag == DK_OP_EQUAL) {
        i64 i1 = (i64)codes[nc - 1].i1, i2 = (i64)codes[nc - 1].i2, j1 = (i64)codes[nc - 1].j1,
            j2 = (i64)codes[nc - 1].j2;
        codes[nc - 1].i2 = (size_t)i64min(i2, i1 + n);
        codes[nc - 1].j2 = (size_t)i64min(j2, j1 + n);
    }
    i64 nn = n + n;
    DkOpcode *pool = DK_NEWN(ar, DkOpcode, nc * 2 + 2);
    DkOpGroup *groups = DK_NEWN(ar, DkOpGroup, nc + 2);
    size_t np = 0, ng = 0, gstart = 0;
    for (size_t c = 0; c < nc; c++) {
        DkOpTag tag = codes[c].tag;
        i64 i1 = (i64)codes[c].i1, i2 = (i64)codes[c].i2, j1 = (i64)codes[c].j1, j2 = (i64)codes[c].j2;
        /* End the current group and start a new one whenever there is a large range with no changes. */
        if (tag == DK_OP_EQUAL && i2 - i1 > nn) {
            DkOpcode op = {tag, (size_t)i1, (size_t)i64min(i2, i1 + n), (size_t)j1, (size_t)i64min(j2, j1 + n)};
            pool[np++] = op;
            groups[ng].ops = pool + gstart;
            groups[ng].n = np - gstart;
            ng++;
            gstart = np;
            i1 = i64max(i1, i2 - n);
            j1 = i64max(j1, j2 - n);
        }
        DkOpcode op = {tag, (size_t)i1, (size_t)i2, (size_t)j1, (size_t)j2};
        pool[np++] = op;
    }
    size_t glen = np - gstart;
    if (glen && !(glen == 1 && pool[gstart].tag == DK_OP_EQUAL)) {
        groups[ng].ops = pool + gstart;
        groups[ng].n = glen;
        ng++;
    }
    *ngroups = ng;
    return groups;
}

/* ---- ratios ---------------------------------------------------------------------------------------------------- */
static double calculate_ratio(size_t matches, size_t length) {
    if (length) return 2.0 * (double)matches / (double)length;
    return 1.0;
}

double dk_seqm_ratio(DkSeqMatcher *m) {
    size_t nb;
    const DkMatch *blocks = dk_seqm_matching_blocks(m, &nb);
    size_t matches = 0;
    for (size_t t = 0; t < nb; t++) matches += blocks[t].size;
    return calculate_ratio(matches, m->la + m->lb);
}

double dk_seqm_quick_ratio(DkSeqMatcher *m) {
    /* viewing a and b as multisets, matches is the cardinality of their intersection */
    i32 *avail = (i32 *)dk_xmalloc(((size_t)m->nids + 1) * sizeof(i32));
    for (u32 id = 0; id < m->nids; id++) avail[id] = (i32)m->bcount[id];
    size_t matches = 0;
    for (size_t i = 0; i < m->la; i++) {
        i32 numb = avail[m->a[i]];
        avail[m->a[i]] = numb - 1;
        if (numb > 0) matches++;
    }
    dk_xfree(avail);
    return calculate_ratio(matches, m->la + m->lb);
}

double dk_seqm_real_quick_ratio(DkSeqMatcher *m) {
    return calculate_ratio(DK_MIN(m->la, m->lb), m->la + m->lb);
}

double dk_ratio_str(const DkStr *a, size_t na, const DkStr *b, size_t nb, bool autojunk) {
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkSeqOpts o = {!autojunk, NULL, NULL};
    double r = dk_seqm_ratio(dk_seqm_new_str(sc, a, na, b, nb, &o));
    dk_arena_reset(sc, mk);
    return r;
}

double dk_ratio_u64(const u64 *a, size_t na, const u64 *b, size_t nb, bool autojunk) {
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkSeqOpts o = {!autojunk, NULL, NULL};
    double r = dk_seqm_ratio(dk_seqm_new_u64(sc, a, na, b, nb, &o));
    dk_arena_reset(sc, mk);
    return r;
}

double dk_ratio_text(DkStr a, DkStr b, bool autojunk) {
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkSeqOpts o = {!autojunk, NULL, NULL};
    double r = dk_seqm_ratio(dk_seqm_new_text(sc, a, b, &o));
    dk_arena_reset(sc, mk);
    return r;
}

/* ---- unified_diff ---------------------------------------------------------------------------------------------- */
typedef DK_VEC(size_t) SizeVec;

/* Appends the pieces of one output line; ends records where the line stops (NULL for the joined output). */
static void put_line_end(DkBuf *out, SizeVec *ends) {
    if (ends) dk_vec_push(ends, out->n);
}

/* _format_range_unified(start, stop) */
static void put_range_unified(DkBuf *out, i64 start, i64 stop) {
    i64 beginning = start + 1; /* lines start numbering with one */
    i64 length = stop - start;
    if (length == 1) {
        dk_buf_printf(out, "%lld", (long long)beginning);
        return;
    }
    if (!length) beginning -= 1; /* empty ranges begin at line just before the range */
    dk_buf_printf(out, "%lld,%lld", (long long)beginning, (long long)length);
}

static void udiff_core(DkBuf *out, SizeVec *ends, const DkStr *a, size_t na, const DkStr *b, size_t nb,
                       const DkUdiff *o) {
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkSeqMatcher *m = dk_seqm_new_str(sc, a, na, b, nb, NULL); /* SequenceMatcher(None, a, b): autojunk on */
    size_t ngroups;
    const DkOpGroup *groups = dk_seqm_grouped_opcodes(m, o->n, &ngroups);
    for (size_t g = 0; g < ngroups; g++) {
        if (g == 0) {
            dk_buf_putz(out, "--- ");
            dk_buf_put(out, o->fromfile);
            if (o->fromfiledate.n) {
                dk_buf_putc(out, '\t');
                dk_buf_put(out, o->fromfiledate);
            }
            dk_buf_put(out, o->lineterm);
            put_line_end(out, ends);
            dk_buf_putz(out, "+++ ");
            dk_buf_put(out, o->tofile);
            if (o->tofiledate.n) {
                dk_buf_putc(out, '\t');
                dk_buf_put(out, o->tofiledate);
            }
            dk_buf_put(out, o->lineterm);
            put_line_end(out, ends);
        }
        const DkOpcode *first = &groups[g].ops[0], *last = &groups[g].ops[groups[g].n - 1];
        dk_buf_putz(out, "@@ -");
        put_range_unified(out, (i64)first->i1, (i64)last->i2);
        dk_buf_putz(out, " +");
        put_range_unified(out, (i64)first->j1, (i64)last->j2);
        dk_buf_putz(out, " @@");
        dk_buf_put(out, o->lineterm);
        put_line_end(out, ends);
        for (size_t t = 0; t < groups[g].n; t++) {
            const DkOpcode *op = &groups[g].ops[t];
            if (op->tag == DK_OP_EQUAL) {
                for (size_t i = op->i1; i < op->i2; i++) {
                    dk_buf_putc(out, ' ');
                    dk_buf_put(out, a[i]);
                    put_line_end(out, ends);
                }
                continue;
            }
            if (op->tag == DK_OP_REPLACE || op->tag == DK_OP_DELETE) {
                for (size_t i = op->i1; i < op->i2; i++) {
                    dk_buf_putc(out, '-');
                    dk_buf_put(out, a[i]);
                    put_line_end(out, ends);
                }
            }
            if (op->tag == DK_OP_REPLACE || op->tag == DK_OP_INSERT) {
                for (size_t j = op->j1; j < op->j2; j++) {
                    dk_buf_putc(out, '+');
                    dk_buf_put(out, b[j]);
                    put_line_end(out, ends);
                }
            }
        }
    }
    dk_arena_reset(sc, mk);
}

void dk_unified_diff(DkBuf *out, const DkStr *a, size_t na, const DkStr *b, size_t nb, const DkUdiff *o) {
    udiff_core(out, NULL, a, na, b, nb, o);
}

DkStrVec dk_unified_diff_lines(DkArena *arena, const DkStr *a, size_t na, const DkStr *b, size_t nb,
                                 const DkUdiff *o) {
    if (!arena) arena = dk_arena();
    DkBuf buf;
    dk_buf_init(&buf, NULL); /* heap: the views are made on an arena copy below */
    SizeVec ends = {0};
    udiff_core(&buf, &ends, a, na, b, nb, o);
    char *text = (char *)dk_alloc_noz(arena, buf.n + 1);
    if (buf.n) memcpy(text, buf.p, buf.n);
    text[buf.n] = 0;
    DkStrVec lines = {0};
    size_t pos = 0;
    for (size_t t = 0; t < ends.n; t++) {
        dk_vec_push(&lines, dk_strn(text + pos, ends.v[t] - pos));
        pos = ends.v[t];
    }
    dk_buf_free(&buf);
    dk_vec_free(&ends);
    return lines;
}
