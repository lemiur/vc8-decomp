// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* xmatch exact masked search (exact search, resolve, plain search, exact_at, first_diff, the
 * relocation fingerprint), see xmatch.h. */
#include "xmatch.h"

#include <stdlib.h>
#include <string.h>

static u32 rd32(const u8 *p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }

/* Unmasked runs of a pattern, for fast verification. */
typedef struct {
    u32 off, len;
} Run;

typedef struct {
    Run *runs;
    size_t nruns;
} Runs;

static Runs make_runs(const DkXmFn *fn) {
    Runs r = {dk_xmalloc(((fn->size + 1) / 2 + 1) * sizeof(Run)), 0};
    size_t i = 0;
    while (i < fn->size) {
        if (fn->mask[i]) {
            i++;
            continue;
        }
        size_t j = i;
        while (j < fn->size && !fn->mask[j])
            j++;
        r.runs[r.nruns].off = (u32)i;
        r.runs[r.nruns].len = (u32)(j - i);
        r.nruns++;
        i = j;
    }
    return r;
}

static bool verify(const DkXmFn *fn, const Runs *r, const u8 *at) {
    for (size_t k = 0; k < r->nruns; k++)
        if (memcmp(at + r->runs[k].off, fn->code + r->runs[k].off, r->runs[k].len) != 0)
            return false;
    return true;
}

typedef bool (*match_cb)(void *ctx, u32 va);

/* Every non-overlapping (leftmost, as a regex scan) masked match, sections in order, ascending; stops when cb returns false. */
static void for_each_match(const DkXmImage *img, const DkXmFn *fn, match_cb cb, void *ctx) {
    size_t L = fn->size;
    if (!L)
        return; /* never asked for (empty functions are not made) */
    Runs r = make_runs(fn);
    size_t nexec = dk_xm_image_exec_count(img);
    /* anchor: the unmasked 4-byte window with the fewest key positions */
    long best_j = -1;
    size_t best_n = SIZE_MAX;
    for (size_t k = 0; k < r.nruns && best_n; k++) {
        if (r.runs[k].len < 4)
            continue;
        for (u32 j = r.runs[k].off; j + 4 <= r.runs[k].off + r.runs[k].len; j++) {
            u32 key = rd32(fn->code + j);
            size_t tot = 0;
            for (size_t s = 0; s < nexec && tot < best_n; s++)
                tot += dk_xm_image_key_positions(img, s, key, NULL);
            if (tot < best_n) {
                best_n = tot;
                best_j = (long)j;
                if (!tot)
                    break;
            }
        }
    }
    bool stop = false;
    for (size_t s = 0; s < nexec && !stop; s++) {
        const DkXmSpan *sp = dk_xm_image_exec(img, s);
        if (sp->len < L)
            continue;
        const u8 *d = sp->data;
        size_t last = sp->len - L; /* last possible start */
        size_t next_ok = 0;        /* first start not inside the previous kept match */
        if (best_j >= 0) {
            if (!best_n)
                break;
            const u32 *pos;
            size_t np = dk_xm_image_key_positions(img, s, rd32(fn->code + best_j), &pos);
            for (size_t i = 0; i < np && !stop; i++) {
                if (pos[i] < (u32)best_j)
                    continue;
                size_t p = pos[i] - (u32)best_j;
                if (p > last)
                    break;
                if (p < next_ok)
                    continue;
                if (verify(fn, &r, d + p)) {
                    next_ok = p + L;
                    if (!cb(ctx, sp->va + (u32)p))
                        stop = true;
                }
            }
        } else if (r.nruns) {
            u32 u = r.runs[0].off;
            u8 ub = fn->code[u];
            size_t p = 0;
            while (p <= last && !stop) {
                const u8 *q = memchr(d + p + u, ub, last - p + 1);
                if (!q)
                    break;
                p = (size_t)(q - d) - u;
                if (verify(fn, &r, d + p)) {
                    if (!cb(ctx, sp->va + (u32)p))
                        stop = true;
                    p += L;
                } else {
                    p++;
                }
            }
        } else {
            for (size_t p = 0; p <= last && !stop; p += L)
                if (!cb(ctx, sp->va + (u32)p))
                    stop = true;
        }
        (void)next_ok;
    }
    free(r.runs);
}

bool dk_xm_resolve(const DkXmImage *img, const DkXmFn *fn, u32 start, DkXmResolved **res, size_t *n_res) {
    DkXmResolved *v = NULL;
    size_t n = 0, cap = 0;
    bool ok = true;
    for (size_t k = 0; k < fn->n_relocs && ok; k++) {
        const DkXmFnReloc *rl = &fn->relocs[k];
        if (rl->size != 4)
            continue;
        u32 at = start + rl->offset;
        u8 w[4] = {0, 0, 0, 0};
        size_t got;
        const u8 *b = dk_xm_image_read(img, at, 4, &got);
        if (b)
            memcpy(w, b, got);
        u32 val = rd32(w), s;
        if (rl->type == DK_REL_I386_REL32) {
            u32 dest = dk_xm_image_follow(img, at + 4 + val);
            if (!dk_xm_image_in_exec(img, dest)) {
                ok = false;
                break;
            }
            s = dest - rl->addend;
        } else if (rl->type == DK_REL_I386_DIR32) {
            if (!dk_xm_image_in_image(img, val) || (dk_xm_image_has_relocs(img) && !dk_xm_image_is_reloc(img, at))) {
                ok = false;
                break;
            }
            s = val - rl->addend;
        } else {
            continue;
        }
        size_t e = 0;
        while (e < n && strcmp(v[e].sym, rl->sym) != 0)
            e++;
        if (e < n) {
            if (v[e].addr != s)
                ok = false;
            continue;
        }
        if (n == cap) {
            cap = cap ? cap * 2 : 8;
            v = dk_xrealloc(v, cap * sizeof(DkXmResolved));
        }
        v[n].sym = rl->sym;
        v[n].addr = s;
        n++;
    }
    if (!ok) {
        free(v);
        if (res)
            *res = NULL;
        if (n_res)
            *n_res = 0;
        return false;
    }
    if (res)
        *res = v;
    else
        free(v);
    if (n_res)
        *n_res = n;
    return true;
}

typedef struct {
    const DkXmImage *img;
    const DkXmFn *fn;
    DkXmHit *hits;
    size_t n;
    bool want;
} exact_ctx;

static bool exact_cb(void *p, u32 va) {
    exact_ctx *c = p;
    if (va % (c->fn->align ? c->fn->align : 1))
        return true;
    DkXmResolved *res = NULL;
    size_t n_res = 0;
    if (!dk_xm_resolve(c->img, c->fn, va, c->want ? &res : NULL, &n_res))
        return true;
    if (c->want) {
        c->hits[c->n].addr = va;
        c->hits[c->n].res = res;
        c->hits[c->n].n_res = n_res;
    }
    c->n++;
    return c->n < DK_XM_MAX_HITS;
}

size_t dk_xm_exact_search(const DkXmImage *img, const DkXmFn *fn, DkXmHit **hits) {
    exact_ctx c = {img, fn, NULL, 0, hits != NULL};
    if (hits)
        c.hits = dk_xcalloc(DK_XM_MAX_HITS, sizeof(DkXmHit));
    for_each_match(img, fn, exact_cb, &c);
    if (hits)
        *hits = c.hits;
    return c.n;
}

void dk_xm_hits_free(DkXmHit *hits, size_t n) {
    if (!hits)
        return;
    for (size_t i = 0; i < n; i++)
        free(hits[i].res);
    free(hits);
}

typedef struct {
    u32 *out;
    size_t n, limit;
} plain_ctx;

static bool plain_cb(void *p, u32 va) {
    plain_ctx *c = p;
    if (c->n >= c->limit)
        return false;
    c->out[c->n++] = va;
    return c->n < c->limit;
}

size_t dk_xm_search_plain(const DkXmImage *img, const DkXmFn *fn, size_t limit, u32 *out) {
    plain_ctx c = {out, 0, limit};
    if (!limit)
        return 0;
    for_each_match(img, fn, plain_cb, &c);
    return c.n;
}

bool dk_xm_exact_at(const DkXmImage *img, const DkXmFn *fn, u32 addr) {
    size_t got;
    const u8 *b = dk_xm_image_read(img, addr, fn->size, &got);
    if (!b || got != fn->size)
        return false;
    for (size_t i = 0; i < got; i++)
        if (!fn->mask[i] && b[i] != fn->code[i])
            return false;
    return dk_xm_resolve(img, fn, addr, NULL, NULL);
}

long dk_xm_first_diff(const DkXmImage *img, const DkXmFn *fn, u32 addr) {
    size_t got;
    const u8 *b = dk_xm_image_read(img, addr, fn->size, &got);
    if (!b)
        return -1;
    for (size_t i = 0; i < got; i++)
        if (!fn->mask[i] && b[i] != fn->code[i])
            return (long)i;
    return -1;
}

size_t dk_xm_reloc_fp_search(const DkXmImage *img, const u32 *offs, size_t k, u32 len, u32 align,
                            u32 *out, size_t max) {
    if (k < 3)
        return 0;
    if (!align)
        align = 1;
    size_t nR;
    const u32 *R = dk_xm_image_text_relocs(img, &nR);
    const u32 *idx;
    size_t ni = dk_xm_image_reloc_gap_lookup(img, offs[1] - offs[0], offs[2] - offs[1], &idx);
    size_t n = 0;
    u32 base = dk_xm_image_base(img);
    for (size_t t = 0; t < ni; t++) {
        size_t i = idx[t];
        if (i + k > nR)
            continue;
        i64 S = (i64)R[i] - offs[0];
        if (((S % align) + align) % align)
            continue;
        bool ok = true;
        for (size_t j = 3; j < k && ok; j++)
            if (R[i + j] - R[i] != offs[j] - offs[0])
                ok = false;
        if (!ok)
            continue;
        if (i > 0 && (i64)R[i - 1] >= S)
            continue;
        if (i + k < nR && (i64)R[i + k] < S + len)
            continue;
        if (n < max)
            out[n] = (u32)(base + S);
        n++;
    }
    return n;
}
