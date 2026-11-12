// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Synthetic PE32 image writer for tests: a DOS header, an optional Rich header between it and the NT headers, and
 * one empty section header. Written from the PE format's documented layout; nothing is read from disk. */
#pragma once
#include "dk/dk.h"

#include <string.h>

typedef struct {
    u32 compid; /* product id << 16 | build number */
    u32 count;
} SynthRichEntry;

static inline void synth_pe_put32(u8 *p, size_t at, u32 v) {
    for (int i = 0; i < 4; i++) p[at + (size_t)i] = (u8)(v >> (8 * i));
}

/* Writes the image into out (cleared first). rich_n < 0: no Rich header; otherwise the header with the records
 * (xored with key) sits at 0x80, in the layout "DanS" ^ key, three zero words ^ key, the records, "Rich", key. */
static inline void synth_pe_build(DkBytes *out, const SynthRichEntry *rich, int rich_n, u32 key) {
    size_t rich_size = rich_n < 0 ? 0 : 16 + 8 * (size_t)rich_n + 8;
    size_t nt = 0x80 + ((rich_size + 7) & ~(size_t)7);
    size_t total = nt + 4 + 20 + 224 + 40;
    out->n = 0;
    dk_vec_reserve(out, total);
    memset(out->v, 0, total);
    out->n = total;
    u8 *p = out->v;
    p[0] = 'M';
    p[1] = 'Z';
    synth_pe_put32(p, 0x3C, (u32)nt);
    if (rich_n >= 0) {
        size_t at = 0x80;
        synth_pe_put32(p, at, 0x536E6144u ^ key);
        for (int i = 1; i < 4; i++) synth_pe_put32(p, at + 4 * (size_t)i, key);
        at += 16;
        for (int i = 0; i < rich_n; i++, at += 8) {
            synth_pe_put32(p, at, rich[i].compid ^ key);
            synth_pe_put32(p, at + 4, rich[i].count ^ key);
        }
        memcpy(p + at, "Rich", 4);
        synth_pe_put32(p, at + 4, key);
    }
    memcpy(p + nt, "PE\0\0", 4);
    p[nt + 4] = 0x4C;
    p[nt + 5] = 0x01; /* i386 */
    p[nt + 6] = 1;    /* one section */
    p[nt + 20] = 224; /* size of optional header */
    p[nt + 24] = 0x0B;
    p[nt + 25] = 0x01; /* PE32 magic */
}
