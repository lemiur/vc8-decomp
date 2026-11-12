// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* xmatch.h on synthetic buffers: the length decoder, instruction tokens, similarity, and the search semantics
 * (leftmost selection, masks, alignment, resolve, the call index and the starts) over a small PE32 image built in
 * memory. */
#include "dk/dk.h"
#include "dk/test.h"
#include "xmatch.h"

#include <stdlib.h>
#include <string.h>

static u64 fnv_masked(const u8 *s, size_t n) {
    u64 h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) {
        h ^= s[i];
        h *= 0x100000001b3ull;
    }
    return h & 0x7FFFFFFFFFFFFFFFull;
}

DK_TEST(decoder_fields) {
    /* mov dword [0x00405000], 0x12345678: disp at 2 (4 bytes), imm at 6 (4 bytes); then jmp short back */
    static const u8 code[] = {0xC7, 0x05, 0x00, 0x50, 0x40, 0x00, 0x78, 0x56, 0x34, 0x12, 0xEB, 0xF4};
    DkXmInsn in;
    REQUIRE(dk_xm_x86_decode(code, sizeof code, 0x401000, &in) == 10);
    CHECK_EQ_U64(in.disp_off, 2);
    CHECK_EQ_U64(in.disp_size, 4);
    CHECK_EQ_U64(in.imm_off, 6);
    CHECK_EQ_U64(in.imm_size, 4);
    CHECK(!in.rel);
    REQUIRE(dk_xm_x86_decode(code + 10, 2, 0x40100A, &in) == 2);
    CHECK(in.rel);
    CHECK_EQ_U64(in.branch, DK_XM_BR_JMP);
    CHECK_EQ_U64(in.target, 0x401000);
    /* moffs: mov eax, [0x00405000] */
    static const u8 mo[] = {0xA1, 0x00, 0x50, 0x40, 0x00};
    REQUIRE(dk_xm_x86_decode(mo, sizeof mo, 0, &in) == 5);
    CHECK(in.disp_off == 1 && in.disp_size == 4);
    /* invalid: lea with a register operand, a VEX form, a truncated call */
    static const u8 lea[] = {0x8D, 0xC0}, vex[] = {0xC5, 0xF8, 0x77}, cut[] = {0xE8, 0x00, 0x00};
    CHECK_EQ_I64(dk_xm_x86_decode(lea, sizeof lea, 0, &in), 0);
    CHECK_EQ_I64(dk_xm_x86_decode(vex, sizeof vex, 0, &in), 0);
    CHECK_EQ_I64(dk_xm_x86_decode(cut, sizeof cut, 0, &in), 0);
}

DK_TEST(tokens_basic) {
    /* push ebp; mov ebp, esp; push ebp; pop ebp; ret */
    static const u8 code[] = {0x55, 0x8B, 0xEC, 0x55, 0x5D, 0xC3};
    DkXmTokens t = dk_xm_tokenise(code, sizeof code, NULL, 0, true, NULL);
    REQUIRE(t.n == 5);
    CHECK_EQ_U64(t.t[0], fnv_masked(code, 1));
    CHECK_EQ_U64(t.t[1], fnv_masked(code + 1, 2));
    CHECK_EQ_U64(t.t[0], t.t[2]);
    CHECK(t.t[3] != t.t[0]);
    dk_xm_tokens_free(&t);
}

DK_TEST(tokens_branches) {
    u8 code[32];
    memset(code, 0x90, sizeof code);
    /* 12 nops, jmp short to offset 10 (inside, target > 9) */
    code[12] = 0xEB;
    code[13] = 0xFC;
    /* call rel32 far outside */
    code[14] = 0xE8;
    code[15] = 0x00;
    code[16] = 0x10;
    code[17] = 0x00;
    code[18] = 0x00;
    /* je rel32 far outside */
    code[19] = 0x0F;
    code[20] = 0x84;
    code[21] = 0x00;
    code[22] = 0x20;
    code[23] = 0x00;
    code[24] = 0x00;
    DkXmTokens t = dk_xm_tokenise(code, 25, NULL, 0, true, NULL);
    REQUIRE(t.n == 15);
    CHECK_EQ_U64(t.t[12], 0x8000000000000000ull | (DK_XM_BR_JMP << 1) | 1);
    CHECK_EQ_U64(t.t[13], 0x8000000000000000ull | (DK_XM_BR_CALL << 1));
    CHECK_EQ_U64(t.t[14], 0x8000000000000000ull | ((DK_XM_BR_JCC + 4) << 1));
    dk_xm_tokens_free(&t);
    /* ours: a masked byte (zeroed: jmp to 14, still > 9) makes the jmp an outside branch */
    u8 zero[32] = {0};
    zero[13] = 1;
    t = dk_xm_tokenise(code, 25, zero, 0, true, NULL);
    REQUIRE(t.n == 15);
    CHECK_EQ_U64(t.t[12], 0x8000000000000000ull | (DK_XM_BR_JMP << 1));
    dk_xm_tokens_free(&t);
    /* call to offset 5 (capstone printed it in decimal): a (class, target) token */
    static const u8 small[] = {0xE8, 0x00, 0x00, 0x00, 0x00};
    t = dk_xm_tokenise(small, sizeof small, NULL, 0, true, NULL);
    REQUIRE(t.n == 1);
    static const u8 key[] = {0xB7, 0x7B, DK_XM_BR_CALL, 5, 0x5A, 0xA5};
    CHECK_EQ_U64(t.t[0], fnv_masked(key, sizeof key));
    dk_xm_tokens_free(&t);
}

DK_TEST(tokens_stop_at_invalid) {
    /* nop; FF /7 (invalid); nop */
    static const u8 code[] = {0x90, 0xFF, 0xFF, 0x90};
    DkXmTokens t = dk_xm_tokenise(code, sizeof code, NULL, 0, true, NULL);
    CHECK_EQ_U64(t.n, 1);
    dk_xm_tokens_free(&t);
    /* a truncated instruction ends the walk too */
    static const u8 cut[] = {0x90, 0xE8, 0x00};
    t = dk_xm_tokenise(cut, sizeof cut, NULL, 0, true, NULL);
    CHECK_EQ_U64(t.n, 1);
    dk_xm_tokens_free(&t);
}

DK_TEST(similarity) {
    static const u64 a[] = {1, 2, 3, 4}, b[] = {1, 2, 4};
    CHECK_EQ_F64(dk_xm_similarity(a, 4, b, 3), 2.0 * 3 / 7);
    CHECK_EQ_F64(dk_xm_similarity(a, 4, a, 4), 1.0);
    CHECK_EQ_F64(dk_xm_similarity(a, 0, b, 0), 0.0);
    CHECK_EQ_F64(dk_xm_similarity(a, 4, b, 0), 0.0);
    CHECK_EQ_F64(dk_xm_bytes_ratio((const u8 *)"abcd", 4, (const u8 *)"bcde", 4), 0.75);
    CHECK_EQ_F64(dk_xm_bytes_ratio(NULL, 0, NULL, 0), 1.0);
    DkXmMatchBlock *bl;
    size_t n = dk_xm_bytes_matching_blocks((const u8 *)"abxcd", 5, (const u8 *)"abcd", 4, &bl);
    REQUIRE(n == 3);
    CHECK(bl[0].a == 0 && bl[0].b == 0 && bl[0].size == 2);
    CHECK(bl[1].a == 3 && bl[1].b == 2 && bl[1].size == 2);
    CHECK(bl[2].a == 5 && bl[2].b == 4 && bl[2].size == 0);
    free(bl);
    n = dk_xm_tokens_matching_blocks(a, 4, b, 3, &bl);
    REQUIRE(n == 3);
    CHECK(bl[0].a == 0 && bl[0].b == 0 && bl[0].size == 2);
    CHECK(bl[1].a == 3 && bl[1].b == 2 && bl[1].size == 1);
    free(bl);
}

/* ---- a PE32 image in memory: .text at 0x401000 (0x1000 bytes), .reloc at 0x402000 ---- */
enum { TEXT_RAW = 0x200, RELOC_RAW = 0x1200, FILE_SIZE = 0x1400 };
static u8 g_file[FILE_SIZE];

static void w16(u8 *p, u16 v) {
    p[0] = (u8)v;
    p[1] = (u8)(v >> 8);
}
static void w32(u8 *p, u32 v) {
    w16(p, (u16)v);
    w16(p + 2, (u16)(v >> 16));
}

static u8 *text(void) { return g_file + TEXT_RAW; }

static void build_file(const u16 *reloc_offs, size_t nrel) {
    memset(g_file, 0, sizeof g_file);
    u8 *f = g_file;
    f[0] = 'M';
    f[1] = 'Z';
    w32(f + 0x3C, 0x40);
    memcpy(f + 0x40, "PE\0\0", 4);
    u8 *fh = f + 0x44;
    w16(fh, 0x14C);
    w16(fh + 2, 2);
    w16(fh + 16, 0xE0);
    w16(fh + 18, 0x0102);
    u8 *oh = fh + 20;
    w16(oh, 0x10B);
    w32(oh + 16, 0x1000);
    w32(oh + 20, 0x1000);
    w32(oh + 24, 0x2000);
    w32(oh + 28, 0x400000);
    w32(oh + 32, 0x1000);
    w32(oh + 36, 0x200);
    w16(oh + 40, 4);
    w16(oh + 48, 4);
    w32(oh + 56, 0x3000);
    w32(oh + 60, 0x200);
    w16(oh + 68, 2);
    w32(oh + 92, 16);
    u32 bsize = 8 + 2 * (u32)((nrel + 1) & ~(size_t)1);
    w32(oh + 96 + 5 * 8, 0x2000);
    w32(oh + 96 + 5 * 8 + 4, bsize);
    u8 *sh = oh + 0xE0;
    memcpy(sh, ".text", 5);
    w32(sh + 8, 0x1000);
    w32(sh + 12, 0x1000);
    w32(sh + 16, 0x1000);
    w32(sh + 20, TEXT_RAW);
    w32(sh + 36, 0x60000020);
    sh += 40;
    memcpy(sh, ".reloc", 6);
    w32(sh + 8, 0x200);
    w32(sh + 12, 0x2000);
    w32(sh + 16, 0x200);
    w32(sh + 20, RELOC_RAW);
    w32(sh + 36, 0x42000040);
    /* the code: pseudo-random bytes below 0x80 (no E8, no CC, entropy about 7 bits) */
    u32 x = 12345;
    for (size_t i = 0; i < 0x1000; i++) {
        x = x * 1103515245u + 12345u;
        text()[i] = (u8)((x >> 16) & 0x7F);
    }
    u8 *rb = f + RELOC_RAW;
    w32(rb, 0x1000);
    w32(rb + 4, bsize);
    for (size_t i = 0; i < nrel; i++) w16(rb + 8 + 2 * i, (u16)(0x3000 | reloc_offs[i]));
}

static void put(size_t off, const u8 *b, size_t n) { memcpy(text() + off, b, n); }

static void put_call(size_t off, u32 target_va) {
    u8 b[5] = {0xE8};
    w32(b + 1, target_va - (0x401000 + (u32)off + 5));
    put(off, b, 5);
}

typedef struct {
    DkArena *arena;
    DkXmImage *img;
} TestImage;

static TestImage open_image(void) {
    static const u16 rel[] = {0x401, 0x802, 0x80A, 0x812};
    build_file(rel, DK_ARRAY_LEN(rel));
    static const u8 rep[] = {0x90, 0x91, 0x90, 0x91, 0x90, 0x91};
    put(0x200, rep, sizeof rep);
    static const u8 m[] = {0xC1, 0xC2, 0x11, 0x22, 0x33, 0x44, 0xC3, 0xC4, 0xC5, 0xC6};
    put(0x300, m, sizeof m);
    put(0x310, m, sizeof m);
    put(0x328, m, sizeof m);
    text()[0x312] = 0x55; /* a masked byte differs */
    static const u8 ld[] = {0xA1, 0x00, 0x18, 0x40, 0x00, 0xB1, 0xB2, 0xB3, 0xB4};
    put(0x400, ld, sizeof ld);
    put(0x420, ld, sizeof ld); /* no base relocation at 0x421 */
    put_call(0x500, 0x401600);
    put_call(0x510, 0x401604);
    put_call(0x520, 0x401604);
    put_call(0x530, 0x401604);
    memset(text() + 0x6F0, 0xCC, 16);
    for (int k = 0; k < 3; k++) w32(text() + 0x802 + 8 * k, 0x11111111);
    TestImage t;
    t.arena = dk_arena_new(0);
    t.img = dk_xm_image_from_pe(dk_pe_parse(t.arena, g_file, sizeof g_file));
    return t;
}

static void close_image(TestImage *t) {
    dk_xm_image_close(t->img);
    dk_arena_free(t->arena);
}

static DkXmFn make_fn(u8 *code, u8 *mask, size_t n, u32 align) {
    DkXmFn f;
    memset(&f, 0, sizeof f);
    f.name = "f";
    f.unit = "u";
    f.code = code;
    f.mask = mask;
    f.size = n;
    f.align = align;
    f.ndup = 1;
    return f;
}

DK_TEST(image_basics) {
    TestImage t = open_image();
    DkXmImage *img = t.img;
    CHECK_EQ_U64(dk_xm_image_base(img), 0x400000);
    CHECK_EQ_U64(dk_xm_image_exec_count(img), 1);
    CHECK_EQ_U64(dk_xm_image_data_count(img), 1);
    CHECK_CZ(dk_xm_image_exec(img, 0)->name, ".text");
    CHECK(dk_xm_image_in_exec(img, 0x401FFF) && !dk_xm_image_in_exec(img, 0x402000));
    CHECK(dk_xm_image_in_image(img, 0x402FFF) && !dk_xm_image_in_image(img, 0x403000));
    CHECK(dk_xm_image_is_reloc(img, 0x401401) && !dk_xm_image_is_reloc(img, 0x401421));
    size_t got;
    CHECK(dk_xm_image_read(img, 0x401FFE, 8, &got) != NULL && got == 2);
    const u32 *sites;
    CHECK_EQ_U64(dk_xm_image_callers(img, 0x401604, &sites), 3);
    CHECK_EQ_U64(sites[0], 0x401510);
    CHECK_EQ_U64(dk_xm_image_callers(img, 0x401600, NULL), 1);
    size_t ns;
    const u32 *st = dk_xm_image_starts(img, &ns);
    static const u32 want[] = {0x401600, 0x401604, 0x401700, 0x401800};
    REQUIRE(ns == DK_ARRAY_LEN(want));
    CHECK_MEM(st, want, sizeof want);
    u32 s;
    CHECK(dk_xm_image_containing(img, 0x401650, &s) && s == 0x401604);
    CHECK(!dk_xm_image_containing(img, 0x401000, &s));
    /* find_all overlaps, the search does not */
    u32 out[8];
    CHECK_EQ_U64(dk_xm_image_find_all(img, "\x90\x91\x90\x91", 4, DK_XM_SPANS_EXEC, 8, out), 2);
    CHECK(out[0] == 0x401200 && out[1] == 0x401202);
    close_image(&t);
}

DK_TEST(search_semantics) {
    TestImage t = open_image();
    DkXmImage *img = t.img;
    u8 rep[] = {0x90, 0x91, 0x90, 0x91}, rm[4] = {0};
    DkXmFn f = make_fn(rep, rm, 4, 1);
    u32 out[8];
    CHECK_EQ_U64(dk_xm_search_plain(img, &f, 8, out), 1); /* leftmost match: 0x401202 is inside the first match */
    CHECK_EQ_U64(out[0], 0x401200);
    /* masked bytes: three placements, two 16-aligned */
    u8 code[] = {0xC1, 0xC2, 0, 0, 0, 0, 0xC3, 0xC4, 0xC5, 0xC6};
    u8 mask[] = {0, 0, 1, 1, 1, 1, 0, 0, 0, 0};
    f = make_fn(code, mask, sizeof code, 16);
    REQUIRE(dk_xm_search_plain(img, &f, 8, out) == 3);
    CHECK(out[0] == 0x401300 && out[1] == 0x401310 && out[2] == 0x401328);
    CHECK_EQ_U64(dk_xm_search_plain(img, &f, 2, out), 2);
    DkXmHit *hits;
    size_t n = dk_xm_exact_search(img, &f, &hits);
    REQUIRE(n == 2);
    CHECK(hits[0].addr == 0x401300 && hits[1].addr == 0x401310 && hits[0].n_res == 0);
    dk_xm_hits_free(hits, n);
    CHECK(dk_xm_exact_at(img, &f, 0x401328));
    CHECK(!dk_xm_exact_at(img, &f, 0x401FFA)); /* runs past the section */
    CHECK_EQ_I64(dk_xm_first_diff(img, &f, 0x401300), -1);
    mask[2] = 0;
    CHECK_EQ_I64(dk_xm_first_diff(img, &f, 0x401300), 2);
    CHECK_EQ_I64(dk_xm_first_diff(img, &f, 0x402000), -1);
    close_image(&t);
}

DK_TEST(search_resolve) {
    TestImage t = open_image();
    DkXmImage *img = t.img;
    u8 code[] = {0xA1, 0, 0, 0, 0, 0xB1, 0xB2, 0xB3, 0xB4};
    u8 mask[] = {0, 1, 1, 1, 1, 0, 0, 0, 0};
    DkXmFn f = make_fn(code, mask, sizeof code, 1);
    DkXmFnReloc r = {1, 4, "g", DK_REL_I386_DIR32, 0};
    f.relocs = &r;
    f.n_relocs = 1;
    u32 out[8];
    CHECK_EQ_U64(dk_xm_search_plain(img, &f, 8, out), 2);
    DkXmHit *hits;
    size_t n = dk_xm_exact_search(img, &f, &hits);
    REQUIRE(n == 1);
    CHECK_EQ_U64(hits[0].addr, 0x401400);
    REQUIRE(hits[0].n_res == 1);
    CHECK_CZ(hits[0].res[0].sym, "g");
    CHECK_EQ_U64(hits[0].res[0].addr, 0x401800);
    dk_xm_hits_free(hits, n);
    CHECK(!dk_xm_exact_at(img, &f, 0x401420)); /* the site is not a base relocation */
    /* the relocation fingerprint */
    DkXmFnReloc rs[3] = {{2, 4, "a", DK_REL_I386_DIR32, 0}, {18, 4, "c", DK_REL_I386_DIR32, 0},
                          {10, 4, "b", DK_REL_I386_DIR32, 0}};
    DkXmFn g = make_fn(code, mask, sizeof code, 16);
    g.relocs = rs;
    g.n_relocs = 3;
    u32 *offs;
    size_t k = dk_xm_fn_fingerprint(&g, &offs);
    REQUIRE(k == 3);
    CHECK(offs[0] == 2 && offs[1] == 10 && offs[2] == 18);
    CHECK_EQ_U64(dk_xm_reloc_fp_search(img, offs, k, 0x20, 16, out, 8), 1);
    CHECK_EQ_U64(out[0], 0x401800);
    CHECK_EQ_U64(dk_xm_reloc_fp_search(img, offs, 2, 0x20, 16, out, 8), 0);
    free(offs);
    close_image(&t);
}

DK_TEST(fn_from_image) {
    TestImage t = open_image();
    /* the call at 0x401500 leaves [0x401500, +5): its rel32 is masked; the base relocation at 0x401401 too */
    DkXmFn *f = dk_xm_fn_from_image(t.img, 0x401500, 5);
    REQUIRE(f != NULL);
    CHECK_CZ(f->name, "retail_00401500");
    CHECK(f->mask[0] == 0 && f->mask[1] && f->mask[4]);
    dk_xm_fn_free(f);
    f = dk_xm_fn_from_image(t.img, 0x401400, 9);
    REQUIRE(f != NULL);
    CHECK(f->mask[0] == 0 && f->mask[1] && f->mask[4] && !f->mask[5]);
    dk_xm_fn_free(f);
    CHECK(dk_xm_fn_from_image(t.img, 0x402000, 4) == NULL);
    close_image(&t);
}

DK_TEST(fn_new) {
    static const u8 code[] = {0xA1, 0x00, 0x10, 0x40, 0x00, 0xC3};
    DkXmFnReloc rl = {1, 4, "g", DK_REL_I386_DIR32, 0};
    DkXmFn *f = dk_xm_fn_new("f", "u", code, sizeof code, &rl, 1, 0);
    REQUIRE(f != NULL);
    CHECK_CZ(f->name, "f");
    CHECK_CZ(f->relocs[0].sym, "g");
    CHECK(f->align == 1 && f->ndup == 1);
    CHECK(!f->mask[0] && f->mask[1] && f->mask[4] && !f->mask[5]);
    u32 *offs;
    CHECK_EQ_U64(dk_xm_fn_fingerprint(f, &offs), 1);
    CHECK_EQ_U64(offs[0], 1);
    free(offs);
    dk_xm_fn_free(f);
    CHECK(dk_xm_fn_new("f", "u", code, 0, NULL, 0, 1) == NULL);
}

/* The function of one image found in another image: a different base-relocated word and a different place. */
DK_TEST(two_images) {
    static const u16 rel_a[] = {0x401};
    static const u16 rel_b[] = {0x701};
    static const u8 ld[] = {0xA1, 0x00, 0x18, 0x40, 0x00, 0xB1, 0xB2, 0xB3, 0xB4};
    static u8 file_a[sizeof g_file];
    build_file(rel_a, DK_ARRAY_LEN(rel_a));
    put(0x400, ld, sizeof ld);
    memcpy(file_a, g_file, sizeof file_a);
    build_file(rel_b, DK_ARRAY_LEN(rel_b));
    put(0x700, ld, sizeof ld);
    w32(text() + 0x701, 0x00402000);
    DkArena *aa = dk_arena_new(0), *ab = dk_arena_new(0);
    DkXmImage *a = dk_xm_image_from_pe(dk_pe_parse(aa, file_a, sizeof file_a));
    DkXmImage *b = dk_xm_image_from_pe(dk_pe_parse(ab, g_file, sizeof g_file));
    DkXmFn *f = dk_xm_fn_from_image(a, 0x401400, sizeof ld);
    REQUIRE(f != NULL);
    u32 out[4];
    CHECK_EQ_U64(dk_xm_search_plain(b, f, 4, out), 1);
    CHECK_EQ_U64(out[0], 0x401700);
    CHECK(dk_xm_exact_at(b, f, 0x401700));
    CHECK_EQ_I64(dk_xm_first_diff(b, f, 0x401400), 0);
    DkXmTokens ta = dk_xm_tokens_target(a, 0x401400, sizeof ld);
    DkXmTokens tb = dk_xm_tokens_target(b, 0x401700, sizeof ld);
    /* the target extent runs to the next function start, so only the function's own instructions are compared */
    REQUIRE(ta.n >= 3 && tb.n >= 3);
    CHECK(ta.t[0] == tb.t[0] && ta.t[1] == tb.t[1] && ta.t[2] == tb.t[2]);
    dk_xm_tokens_free(&ta);
    dk_xm_tokens_free(&tb);
    dk_xm_fn_free(f);
    dk_xm_image_close(a);
    dk_xm_image_close(b);
    dk_arena_free(aa);
    dk_arena_free(ab);
}

DK_TEST_MAIN("xmatch")
