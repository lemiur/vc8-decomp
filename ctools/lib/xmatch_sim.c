// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* xmatch tokens and similarity, see xmatch.h. */
#include "xmatch.h"

#include <stdlib.h>
#include <string.h>

/* ---- tokens ---- */
#define TOK_BRANCH 0x8000000000000000ull
#define TOK_HASH_MASK 0x7FFFFFFFFFFFFFFFull

static u32 rd32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* FNV-1a (64-bit). See: https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function */
static u64 fnv1a64(const u8 *s, size_t n) {
    u64 h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) {
        h ^= s[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

static u64 branch_tok(unsigned cls, bool inside) {
    return TOK_BRANCH | ((u64)cls << 1) | (inside ? 1u : 0u);
}

static u64 hash_tok(const u8 *b, size_t n) {
    return fnv1a64(b, n) & TOK_HASH_MASK;
}

/* "call 5": a branch whose target capstone prints in decimal is a text token of (mnemonic, target) */
static u64 small_target_tok(unsigned cls, u32 target) {
    u8 k[6] = {0xB7, 0x7B, (u8)cls, (u8)target, 0x5A, 0xA5};
    return hash_tok(k, sizeof k);
}

DkXmTokens dk_xm_tokenise(const u8 *code, size_t n, const u8 *zero, u32 start, bool is_ours,
                            const DkXmImage *img) {
    DkXmTokens t = {NULL, 0};
    u8 *c = dk_xmalloc(n ? n : 1);
    if (n) memcpy(c, code, n);
    if (zero)
        for (size_t i = 0; i < n; i++)
            if (zero[i]) c[i] = 0;
    size_t cap = n / 2 + 16;
    t.t = dk_xmalloc(cap * sizeof(u64));
    size_t at = 0;
    while (at < n) {
        DkXmInsn insn;
        int dl = dk_xm_x86_decode(c + at, n - at, (u32)at, &insn);
        if (dl <= 0) break;
        const DkXmInsn *in = &insn;
        size_t l = (size_t)dl;
        u8 b[16];
        memcpy(b, c + at, l);
        if (!is_ours && img) {
            if (in->disp_off && in->disp_size == 4 && in->disp_off + 4u <= l) {
                u32 v = rd32(b + in->disp_off);
                if (dk_xm_image_in_image(img, v) || dk_xm_image_is_reloc(img, start + (u32)at + in->disp_off))
                    memset(b + in->disp_off, 0, 4);
            }
            if (in->imm_off && in->imm_size == 4 && in->imm_off + 4u <= l) {
                u32 v = rd32(b + in->imm_off);
                if (dk_xm_image_in_image(img, v) || dk_xm_image_is_reloc(img, start + (u32)at + in->imm_off))
                    memset(b + in->imm_off, 0, 4);
            }
        }
        u64 tok;
        bool jumpgrp = in->rel && in->branch != DK_XM_BR_LOOP && in->branch != DK_XM_BR_LOOPE &&
                       in->branch != DK_XM_BR_LOOPNE;
        if (jumpgrp && in->target > 9) {
            bool inside = in->target < n;
            if (is_ours && zero && inside)
                for (size_t k = 0; k < l; k++)
                    if (zero[at + k]) {
                        inside = false;
                        break;
                    }
            tok = branch_tok(in->branch, inside);
        } else if (jumpgrp) {
            tok = small_target_tok(in->branch, in->target);
        } else if ((in->branch == DK_XM_BR_CALLFAR || in->branch == DK_XM_BR_JMPFAR) && in->far_sel_imm) {
            tok = branch_tok(in->branch, false);
        } else {
            tok = hash_tok(b, l);
        }
        if (t.n == cap) {
            cap *= 2;
            t.t = dk_xrealloc(t.t, cap * sizeof(u64));
        }
        t.t[t.n++] = tok;
        at += l;
    }
    free(c);
    return t;
}

DkXmTokens dk_xm_tokens_ours(const DkXmFn *fn) {
    return dk_xm_tokenise(fn->code, fn->size, fn->mask, 0, true, NULL);
}

DkXmTokens dk_xm_tokens_target(const DkXmImage *img, u32 start, size_t want) {
    const u8 *p;
    size_t n = dk_xm_image_extent(img, start, want, &p);
    if (!p || !n) {
        DkXmTokens t = {dk_xmalloc(sizeof(u64)), 0};
        return t;
    }
    return dk_xm_tokenise(p, n, NULL, start, false, img);
}

void dk_xm_tokens_free(DkXmTokens *t) {
    if (!t) return;
    free(t->t);
    t->t = NULL;
    t->n = 0;
}

/* ---- SequenceMatcher (difflib.h) ---- */
double dk_xm_similarity(const u64 *a, size_t na, const u64 *b, size_t nb) {
    if (!na || !nb) return 0.0;
    return dk_ratio_u64(a, na, b, nb, false);
}

static size_t copy_blocks(DkSeqMatcher *m, DkXmMatchBlock **blocks) {
    size_t n;
    const DkMatch *mb = dk_seqm_matching_blocks(m, &n);
    DkXmMatchBlock *o = dk_xmalloc((n ? n : 1) * sizeof(DkXmMatchBlock));
    for (size_t i = 0; i < n; i++) {
        o[i].a = (u32)mb[i].a;
        o[i].b = (u32)mb[i].b;
        o[i].size = (u32)mb[i].size;
    }
    *blocks = o;
    return n;
}

static u32 *widen(DkArena *a, const u8 *p, size_t n) {
    u32 *v = dk_alloc_noz(a, (n ? n : 1) * sizeof(u32));
    for (size_t i = 0; i < n; i++) v[i] = p[i];
    return v;
}

size_t dk_xm_bytes_matching_blocks(const u8 *a, size_t na, const u8 *b, size_t nb, DkXmMatchBlock **blocks) {
    DkArena *s = dk_scratch();
    DkArenaMark mk = dk_arena_mark(s);
    DkSeqMatcher *m = dk_seqm_new_u32(s, widen(s, a, na), na, widen(s, b, nb), nb, &dk_seqm_no_autojunk);
    size_t n = copy_blocks(m, blocks);
    dk_arena_reset(s, mk);
    return n;
}

size_t dk_xm_tokens_matching_blocks(const u64 *a, size_t na, const u64 *b, size_t nb, DkXmMatchBlock **blocks) {
    DkArena *s = dk_scratch();
    DkArenaMark mk = dk_arena_mark(s);
    DkSeqMatcher *m = dk_seqm_new_u64(s, a, na, b, nb, &dk_seqm_no_autojunk);
    size_t n = copy_blocks(m, blocks);
    dk_arena_reset(s, mk);
    return n;
}

double dk_xm_bytes_ratio(const u8 *a, size_t na, const u8 *b, size_t nb) {
    if (!na && !nb) return 1.0;
    DkArena *s = dk_scratch();
    DkArenaMark mk = dk_arena_mark(s);
    DkSeqMatcher *m = dk_seqm_new_u32(s, widen(s, a, na), na, widen(s, b, nb), nb, &dk_seqm_no_autojunk);
    double r = dk_seqm_ratio(m);
    dk_arena_reset(s, mk);
    return r;
}
