// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* xmatch masked functions: built from caller data, from an image, and their relocation fingerprint; see xmatch.h. */
#include "xmatch.h"

#include <stdlib.h>
#include <string.h>

static char *heap_strndup(const char *s, size_t n) {
    char *d = dk_xmalloc(n + 1);
    memcpy(d, s, n);
    d[n] = 0;
    return d;
}

static char *heap_strdup(const char *s) { return heap_strndup(s, strlen(s)); }

static void apply_mask(DkXmFn *fn) {
    for (size_t r = 0; r < fn->n_relocs; r++) {
        size_t off = fn->relocs[r].offset;
        size_t end = off + fn->relocs[r].size;
        if (end > fn->size) end = fn->size;
        for (size_t k = off; k < end; k++) fn->mask[k] = 1;
    }
}

DkXmFn *dk_xm_fn_new(const char *name, const char *unit, const u8 *code, size_t size, const DkXmFnReloc *relocs,
                     size_t n_relocs, u32 align) {
    if (!code || !size) return NULL;
    DkXmFn *fn = dk_xcalloc(1, sizeof(DkXmFn));
    fn->name = heap_strdup(name ? name : "");
    fn->unit = heap_strdup(unit ? unit : "");
    fn->size = size;
    fn->code = dk_xmalloc(size);
    memcpy(fn->code, code, size);
    fn->mask = dk_xcalloc(size, 1);
    fn->align = align ? align : 1;
    fn->ndup = 1;
    /* the names: one pool for every relocation symbol, freed through relocs[0].sym */
    size_t total = 2;
    for (size_t r = 0; r < n_relocs; r++) total += (relocs[r].sym ? strlen(relocs[r].sym) : 1) + 1;
    fn->relocs = dk_xcalloc(n_relocs ? n_relocs : 1, sizeof(DkXmFnReloc));
    char *pool = dk_xmalloc(total);
    size_t at = 0;
    for (size_t r = 0; r < n_relocs; r++) {
        DkXmFnReloc *o = &fn->relocs[r];
        *o = relocs[r];
        const char *nm = relocs[r].sym ? relocs[r].sym : "?";
        size_t n = strlen(nm);
        memcpy(pool + at, nm, n);
        pool[at + n] = 0;
        o->sym = pool + at;
        at += n + 1;
    }
    fn->n_relocs = n_relocs;
    if (!fn->n_relocs) free(pool);
    apply_mask(fn);
    return fn;
}

DkXmFn *dk_xm_fn_from_image(const DkXmImage *img, u32 addr, size_t size) {
    size_t got;
    const u8 *code = dk_xm_image_read(img, addr, size, &got);
    if (!code) return NULL;
    DkXmFn *fn = dk_xcalloc(1, sizeof(DkXmFn));
    char name[32];
    snprintf(name, sizeof name, "retail_%08X", addr);
    fn->name = heap_strdup(name);
    fn->unit = heap_strdup("retail");
    fn->size = got;
    fn->code = dk_xmalloc(got ? got : 1);
    if (got) memcpy(fn->code, code, got);
    fn->mask = dk_xcalloc(got ? got : 1, 1);
    fn->align = 16;
    fn->ndup = 1;
    for (size_t k = 0; k + 3 < got; k++)
        if (dk_xm_image_is_reloc(img, addr + (u32)k))
            for (size_t j = k; j < k + 4 && j < got; j++) fn->mask[j] = 1;
    size_t at = 0;
    while (at < got) {
        DkXmInsn insn;
        int l = dk_xm_x86_decode(code + at, got - at, addr + (u32)at, &insn);
        if (l <= 0) break;
        const DkXmInsn *in = &insn;
        /* call / jmp / any j* with a numeric target ("0x..."), length >= 5 */
        if (in->rel && in->len >= 5 && in->branch != DK_XM_BR_LOOP && in->branch != DK_XM_BR_LOOPE &&
            in->branch != DK_XM_BR_LOOPNE && in->target > 9) {
            u64 t = in->target;
            if (!(t >= addr && t < (u64)addr + size)) {
                size_t off = at + in->len - 4;
                for (size_t j = off; j < off + 4 && j < got; j++) fn->mask[j] = 1;
            }
        }
        at += (size_t)l;
    }
    return fn;
}

void dk_xm_fn_free(DkXmFn *fn) {
    if (!fn) return;
    if (fn->n_relocs) free((void *)fn->relocs[0].sym);
    free(fn->relocs);
    free(fn->code);
    free(fn->mask);
    free(fn->name);
    free(fn->unit);
    free(fn);
}

static int cmp_u32(const void *a, const void *b) {
    u32 x = *(const u32 *)a, y = *(const u32 *)b;
    return x < y ? -1 : x > y;
}

size_t dk_xm_fn_fingerprint(const DkXmFn *fn, u32 **offs) {
    u32 *v = dk_xmalloc((fn->n_relocs ? fn->n_relocs : 1) * sizeof(u32));
    size_t n = 0;
    for (size_t r = 0; r < fn->n_relocs; r++)
        if (fn->relocs[r].type == DK_REL_I386_DIR32) v[n++] = fn->relocs[r].offset;
    qsort(v, n, sizeof(u32), cmp_u32);
    *offs = v;
    return n;
}
