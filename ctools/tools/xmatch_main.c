// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* xmatch.exe <imageA> <va> <imageB> [--size N] [--top K]: find a function of one PE32 image in another (lib/xmatch*). */
#include "dk/args.h"
#include "dk/dk.h"
#include "xmatch.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct {
    u32 addr;
    double sim;
} Cand;

static int cand_cmp(const void *a, const void *b) {
    const Cand *x = a, *y = b;
    if (x->sim != y->sim) return x->sim < y->sim ? 1 : -1;
    return x->addr < y->addr ? -1 : x->addr > y->addr;
}

static DkXmImage *open_or_die(const char *path) {
    char *err = NULL;
    DkXmImage *img = dk_xm_image_open(path, &err);
    if (!img) {
        fprintf(stderr, "xmatch: %s: %s\n", path, err ? err : "cannot open");
        free(err);
    }
    return img;
}

static int run(int argc, char **argv) {
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "xmatch",
        .description = "Find a function of one PE32 image in another by masked bytes."});
    dk_arg(ap, &(DkArgDesc){.names = "image_a", .help = "image holding the function"});
    dk_arg(ap, &(DkArgDesc){.names = "va", .help = "virtual address of the function in image_a (0x.. accepted)"});
    dk_arg(ap, &(DkArgDesc){.names = "image_b", .help = "image to search"});
    dk_arg(ap, &(DkArgDesc){.names = "--size", .type = DK_T_INT0, .dflt = DK_DEF_INT(0), .metavar = "N",
                            .help = "function size in bytes (default: up to the next probable function start)"});
    dk_arg(ap, &(DkArgDesc){.names = "--top", .type = DK_T_INT, .dflt = DK_DEF_INT(5), .metavar = "K",
                            .help = "similar candidates to list when no exact hit exists"});
    const DkArgs *r = dk_args_parse(ap, argc, argv);
    char *a_path = dk_cz(dk_arena(), dk_args_str(r, "image_a"));
    char *b_path = dk_cz(dk_arena(), dk_args_str(r, "image_b"));
    char *va_s = dk_cz(dk_arena(), dk_args_str(r, "va"));
    char *end = NULL;
    unsigned long long va = strtoull(va_s, &end, 0);
    if (!*va_s || *end || va > 0xFFFFFFFFull) {
        fprintf(stderr, "xmatch: bad address '%s'\n", va_s);
        return 2;
    }
    size_t size = (size_t)dk_args_int(r, "size");
    i64 top = dk_args_int(r, "top");

    DkXmImage *a = open_or_die(a_path);
    if (!a) return 1;
    DkXmImage *b = open_or_die(b_path);
    if (!b) {
        dk_xm_image_close(a);
        return 1;
    }
    int rc = 0;
    if (!dk_xm_image_in_exec(a, (u32)va)) {
        fprintf(stderr, "xmatch: 0x%08X is not in an executable section of %s\n", (u32)va, a_path);
        rc = 1;
        goto done;
    }
    if (!size) {
        const u8 *p;
        size = dk_xm_image_extent(a, (u32)va, 256, &p);
    }
    DkXmFn *fn = dk_xm_fn_from_image(a, (u32)va, size);
    if (!fn) {
        fprintf(stderr, "xmatch: no bytes at 0x%08X\n", (u32)va);
        rc = 1;
        goto done;
    }
    size_t masked = 0;
    for (size_t i = 0; i < fn->size; i++) masked += fn->mask[i];
    printf("function 0x%08X in %s: %zu bytes, %zu masked\n", (u32)va, a_path, fn->size, masked);

    u32 hits[DK_XM_MAX_HITS];
    size_t nh = dk_xm_search_plain(b, fn, DK_XM_MAX_HITS, hits);
    for (size_t i = 0; i < nh; i++) printf("exact 0x%08X\n", hits[i]);
    if (!nh) {
        puts("no exact hit");
        DkXmTokens ta = dk_xm_tokens_target(a, (u32)va, fn->size);
        size_t ns;
        const u32 *st = dk_xm_image_starts(b, &ns);
        Cand *c = dk_xmalloc((ns ? ns : 1) * sizeof(Cand));
        size_t nc = 0;
        for (size_t i = 0; i < ns; i++) {
            DkXmTokens tb = dk_xm_tokens_target(b, st[i], fn->size);
            if (tb.n && ta.n && tb.n * 2 >= ta.n && ta.n * 2 >= tb.n) {
                c[nc].addr = st[i];
                c[nc].sim = dk_xm_similarity(ta.t, ta.n, tb.t, tb.n);
                nc++;
            }
            dk_xm_tokens_free(&tb);
        }
        qsort(c, nc, sizeof(Cand), cand_cmp);
        for (size_t i = 0; i < nc && (i64)i < top; i++) printf("similar 0x%08X %.3f\n", c[i].addr, c[i].sim);
        free(c);
        dk_xm_tokens_free(&ta);
        rc = 1;
    }
    dk_xm_fn_free(fn);
done:
    dk_xm_image_close(b);
    dk_xm_image_close(a);
    return rc;
}

DK_MAIN(run, "xmatch")
