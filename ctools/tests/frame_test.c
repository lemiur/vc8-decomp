// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* frame.h on hand-assembled prologues (synthetic bytes, no compiler): an ebp frame, an /Oy frame, an aligned frame
 * (`and esp, -16`), __chkstk, the /GS cookie slot, the exception registration, the stack effect of a call (a callee's
 * `ret n` read from the reference image, an import from a cdecl library against a stdcall one, the configured library
 * patterns), the report text and the slot map (pairing, moved slots, swaps). */
#include "dk/dk.h"
#include "dk/test.h"
#include "fakecl/fake_pe.h"
#include "frame.h"

#include <string.h>

static DkStr bytes(const u8 *p, size_t n) { return dk_strn((const char *)p, n); }
#define CODE(...) bytes((const u8[]){__VA_ARGS__}, sizeof((const u8[]){__VA_ARGS__}))

static const DkFrameSlot *slot(const DkFrame *f, DkFrameBase base, i64 offset) {
    for (size_t i = 0; i < f->n_slots; i++)
        if (f->slots[i]->base == base && f->slots[i]->offset == offset) return f->slots[i];
    return NULL;
}

static bool has_size(const DkFrameSlot *s, unsigned n) { return (s->size_mask[n >> 6] >> (n & 63)) & 1; }

/* ---- prologues ------------------------------------------------------------------------------------------------- */

DK_TEST(ebp_frame) {
    /* push ebp; mov ebp, esp; sub esp, 0x10; mov eax, [ebp + 8]; mov [ebp - 4], eax; mov esp, ebp; pop ebp; ret */
    DkStr code = CODE(0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x8B, 0x45, 0x08, 0x89, 0x45, 0xFC, 0x8B, 0xE5, 0x5D, 0xC3);
    DkFrame *f = dk_frame_analyse(dk_arena(), code, 0x401000, NULL, NULL, 0, false);
    CHECK_EQ_I64((i64)f->n_saved, 1);
    CHECK_STR(f->saved[0], "ebp");
    CHECK_EQ_I64(f->locals, 0x10);
    CHECK(f->has_frame_pointer);
    CHECK_EQ_I64(f->frame_pointer, -4); /* the ESP offset EBP was set to */
    CHECK(!f->has_align && !f->has_cookie && !f->eh);
    CHECK_EQ_I64((i64)f->n_slots, 2);
    const DkFrameSlot *arg = slot(f, DK_FRAME_ENTRY, 4), *local = slot(f, DK_FRAME_ENTRY, -8);
    REQUIRE(arg && local);
    CHECK_EQ_I64(arg->reads, 1);
    CHECK_EQ_I64(arg->writes, 0);
    CHECK(has_size(arg, 4));
    CHECK_EQ_I64(local->writes, 1);
    CHECK_EQ_I64(local->acc[0].at, 9);
    CHECK(local->acc[0].kind == 'w' && local->acc[0].size == 4);
}

DK_TEST(oy_frame) {
    /* sub esp, 8; mov eax, [esp + 0xC]; mov [esp + 4], eax; lea ecx, [esp]; add esp, 8; ret */
    DkStr code = CODE(0x83, 0xEC, 0x08, 0x8B, 0x44, 0x24, 0x0C, 0x89, 0x44, 0x24, 0x04, 0x8D, 0x0C, 0x24, 0x83, 0xC4,
                      0x08, 0xC3);
    DkFrame *f = dk_frame_analyse(dk_arena(), code, 0x401000, NULL, NULL, 0, false);
    CHECK_EQ_I64(f->locals, 8);
    CHECK(!f->has_frame_pointer && f->n_saved == 0);
    CHECK_EQ_I64((i64)f->n_slots, 3);
    const DkFrameSlot *arg = slot(f, DK_FRAME_ENTRY, 4), *w = slot(f, DK_FRAME_ENTRY, -4), *a = slot(f, DK_FRAME_ENTRY, -8);
    REQUIRE(arg && w && a);
    CHECK_EQ_I64(arg->reads, 1);
    CHECK_EQ_I64(w->writes, 1);
    CHECK_EQ_I64(a->addrs, 1); /* the lea takes the address, access size 0 */
    CHECK(a->acc[0].kind == 'a' && a->acc[0].size == 0);
}

DK_TEST(aligned_frame) {
    /* push ebp; mov ebp, esp; and esp, -16; sub esp, 8; mov eax, [esp + 4]; mov ecx, [ebp + 8]; mov esp, ebp; pop ebp; ret */
    DkStr code = CODE(0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0, 0x83, 0xEC, 0x08, 0x8B, 0x44, 0x24, 0x04, 0x8B, 0x4D, 0x08,
                      0x8B, 0xE5, 0x5D, 0xC3);
    DkFrame *f = dk_frame_analyse(dk_arena(), code, 0x401000, NULL, NULL, 0, false);
    CHECK(f->has_align);
    CHECK_EQ_I64(f->align, 16);
    CHECK(f->has_frame_pointer);
    /* after `and esp, -16` the esp-relative slots count from the aligned esp; the ebp-relative one stays on entry */
    const DkFrameSlot *al = slot(f, DK_FRAME_ALIGNED, -4), *arg = slot(f, DK_FRAME_ENTRY, 4);
    CHECK(al != NULL);
    CHECK(arg != NULL);
}

DK_TEST(chkstk_frame) {
    /* mov eax, 0x2000; call __chkstk (rel32); mov [esp + 4], ecx; ret */
    DkStr code = CODE(0xB8, 0x00, 0x20, 0x00, 0x00, 0xE8, 0xF6, 0x00, 0x00, 0x00, 0x89, 0x4C, 0x24, 0x04, 0xC3);
    DkFrame *f = dk_frame_analyse(dk_arena(), code, 0x401000, NULL, NULL, 0, false);
    CHECK_EQ_I64(f->locals, 0x2000);
    CHECK_EQ_I64(f->unknown_calls, 0); /* the probe call pops nothing and needs no guess */
    CHECK(slot(f, DK_FRAME_ENTRY, 4 - 0x2000) != NULL);
}

DK_TEST(cookie_slot) {
    /* sub esp, 8; mov eax, [0x403000]; xor eax, esp; mov [esp + 4], eax; add esp, 8; ret */
    DkStr code = CODE(0x83, 0xEC, 0x08, 0xA1, 0x00, 0x30, 0x40, 0x00, 0x33, 0xC4, 0x89, 0x44, 0x24, 0x04, 0x83, 0xC4,
                      0x08, 0xC3);
    DkFrame *f = dk_frame_analyse(dk_arena(), code, 0x401000, NULL, NULL, 0, false);
    CHECK(f->has_cookie);
    CHECK(f->cookie_base == DK_FRAME_ENTRY);
    CHECK_EQ_I64(f->cookie_offset, -4);
    CHECK(slot(f, DK_FRAME_ENTRY, -4) != NULL);

    /* the same with an ebp frame: the cookie is stored through ebp */
    DkStr code2 = CODE(0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0xA1, 0x00, 0x30, 0x40, 0x00, 0x33, 0xC5, 0x89, 0x45, 0xFC,
                       0x8B, 0xE5, 0x5D, 0xC3);
    DkFrame *g = dk_frame_analyse(dk_arena(), code2, 0x401000, NULL, NULL, 0, false);
    CHECK(g->has_cookie);
    CHECK_EQ_I64(g->cookie_offset, -8);
}

DK_TEST(eh_registration) {
    /* push -1; push 0x402000; mov eax, fs:[0]; push eax; sub esp, 8; ... ret */
    DkStr code = CODE(0x6A, 0xFF, 0x68, 0x00, 0x20, 0x40, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x83, 0xEC,
                      0x08, 0x83, 0xC4, 0x08, 0x58, 0x83, 0xC4, 0x08, 0xC3);
    DkFrame *f = dk_frame_analyse(dk_arena(), code, 0x401000, NULL, NULL, 0, false);
    CHECK(f->eh);
    CHECK(!f->has_cookie);
}

/* ---- the stack effect of a call --------------------------------------------------------------------------------- */

typedef struct {
    u32 base;
    DkStr bytes;
} Mem;

static DkStr mem_read(void *ctx, i64 va, i64 n) {
    const Mem *m = ctx;
    if (va < (i64)m->base || va >= (i64)m->base + (i64)m->bytes.n) return (DkStr){"", 0};
    size_t off = (size_t)(va - m->base), len = m->bytes.n - off;
    if ((i64)len > n) len = (size_t)n;
    return dk_strn(m->bytes.p + off, len);
}

DK_TEST(callee_pops) {
    /* the reference holds `ret 4` at 0x401100 and `ret` at 0x401110; an address outside reads as nothing */
    u8 image[0x40] = {0xC2, 0x04, 0x00, 0xCC};
    image[0x10] = 0xC3;
    Mem mem = {0x401100, bytes(image, sizeof image)};
    DkFrameRetail rt = {"none.exe", mem_read, &mem, 0x401000, 0x402000, NULL, 0};
    i64 pops = -1;
    CHECK(dk_frame_callee_pops(&rt, true, 0x401100, &pops));
    CHECK_EQ_I64(pops, 4);
    CHECK(dk_frame_callee_pops(&rt, true, 0x401110, &pops));
    CHECK_EQ_I64(pops, 0);
    CHECK(!dk_frame_callee_pops(&rt, true, 0x401800, &pops)); /* text but nothing readable: no ret found */
    CHECK(!dk_frame_callee_pops(&rt, true, 0x500000, &pops)); /* outside .text */
    CHECK(!dk_frame_callee_pops(&rt, false, 0, &pops));
    CHECK(!dk_frame_callee_pops(NULL, true, 0x401100, &pops));

    /* push 1; push 2; call rel32 (resolved to 0x401100); mov eax, [esp + 4]; ret: the callee pops 4 of the 8 pushed */
    DkStr code = CODE(0x6A, 0x01, 0x6A, 0x02, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x44, 0x24, 0x04, 0xC3);
    DkFrameReloc rel = {5, true, 0x401100};
    DkFrame *known = dk_frame_analyse(dk_arena(), code, 0x401000, &rt, &rel, 1, true);
    CHECK_EQ_I64(known->unknown_calls, 0);
    CHECK(slot(known, DK_FRAME_ENTRY, 0) != NULL); /* esp is 4 below the entry after the call: [esp + 4] is entry + 0 */
    /* without the reference the pops are guessed (the pushes since the previous call) */
    DkFrame *guess = dk_frame_analyse(dk_arena(), code, 0x401000, NULL, &rel, 1, true);
    CHECK_EQ_I64(guess->unknown_calls, 1);
    CHECK(slot(guess, DK_FRAME_ENTRY, 0) == NULL);
    CHECK(slot(guess, DK_FRAME_ENTRY, 4) != NULL);
}

static const char *write_dll_pe(const char *dir, const char *file, const char *dll, const u8 *code, size_t n) {
    FakePe pe;
    fake_pe_init(&pe, 0x00400000u);
    fake_pe_section(&pe, ".text", 0x60000020u, code, n);
    fake_pe_import(&pe, dll, "fn");
    const char *path = dk_join(dk_arena(), dir, file);
    DK_ASSERT(fake_pe_write(&pe, path));
    return path;
}

DK_TEST(import_conventions) {
    const char *dir = dk_mkdtemp(dk_arena(), "frame-", "", NULL);
    /* push eax; call [IAT]; mov ecx, [esp + 8]; ret. The IAT slot is the first import: .idata follows .text. */
    u32 iat = 0x00400000u + 0x2000u + 40 + 4 * 2;
    u8 text[16] = {0x50, 0xFF, 0x15, (u8)iat, (u8)(iat >> 8), (u8)(iat >> 16), (u8)(iat >> 24), 0x8B, 0x4C, 0x24, 0x08,
                   0xC3};
    DkStr code = bytes(text, 12);
    Mem mem = {0x401000, bytes(text, sizeof text)};

    DkFrameRetail msvcr = {write_dll_pe(dir, "c.exe", "MSVCR80.dll", text, sizeof text), mem_read, &mem, 0x401000,
                           0x402000, NULL, 0};
    /* a cdecl import pops nothing: esp is 4 below the entry, [esp + 8] is the first argument (entry + 4) */
    DkFrame *f = dk_frame_analyse(dk_arena(), code, 0x401000, &msvcr, NULL, 0, false);
    CHECK_EQ_I64(f->unknown_calls, 0);
    CHECK(slot(f, DK_FRAME_ENTRY, 4) != NULL);
    CHECK(slot(f, DK_FRAME_ENTRY, 8) == NULL);

    /* any other library is stdcall: the callee pops the pushed argument, [esp + 8] is entry + 8 */
    DkFrameRetail k32 = {write_dll_pe(dir, "s.exe", "KERNEL32.dll", text, sizeof text), mem_read, &mem, 0x401000,
                         0x402000, NULL, 0};
    DkFrame *g = dk_frame_analyse(dk_arena(), code, 0x401000, &k32, NULL, 0, false);
    CHECK(slot(g, DK_FRAME_ENTRY, 4) == NULL);
    CHECK(slot(g, DK_FRAME_ENTRY, 8) != NULL);

    /* the configured patterns replace the default: "kernel32*" makes the second cdecl, "msvcr*" no longer applies */
    static const char *const pats[] = {"kernel32*"};
    k32.cdecl_dlls = pats;
    k32.n_cdecl_dlls = 1;
    DkFrame *h = dk_frame_analyse(dk_arena(), code, 0x401000, &k32, NULL, 0, false);
    CHECK(slot(h, DK_FRAME_ENTRY, 4) != NULL);
    msvcr.cdecl_dlls = pats;
    msvcr.n_cdecl_dlls = 1;
    DkFrame *i = dk_frame_analyse(dk_arena(), code, 0x401000, &msvcr, NULL, 0, false);
    CHECK(slot(i, DK_FRAME_ENTRY, 8) != NULL);
}

/* ---- the report ---------------------------------------------------------------------------------------------------- */

static bool contains(DkStr s, const char *needle) { return dk_str_contains(s, dk_str(needle)); }

DK_TEST(report_text) {
    DkStr ours = CODE(0x83, 0xEC, 0x08, 0x8B, 0x44, 0x24, 0x0C, 0x89, 0x44, 0x24, 0x04, 0x83, 0xC4, 0x08, 0xC3);
    DkStr ref = CODE(0x83, 0xEC, 0x10, 0x8B, 0x44, 0x24, 0x14, 0x89, 0x44, 0x24, 0x04, 0x83, 0xC4, 0x10, 0xC3);
    DkFrameResult r = {"t0", 0x401000, "f", "?f@@YAXXZ", ours, NULL, 0, ref};
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    dk_frame_format(&b, &r, NULL);
    DkStr text = dk_buf_str(&b);
    CHECK(contains(text, "t0 frame of f at 00401000"));
    CHECK(contains(text, "reference"));
    CHECK(contains(text, "!")); /* the frame size differs */
    CHECK(contains(text, "slot(s) ours"));

    /* no reference bytes: one line */
    r.game = (DkStr){NULL, 0};
    dk_buf_init(&b, dk_arena());
    dk_frame_format(&b, &r, NULL);
    CHECK(contains(dk_buf_str(&b), "not available"));
}

/* ---- the slot map -------------------------------------------------------------------------------------------------- */

static DkIMap *identity_map(DkStr code) {
    DkIMap *m = dk_imap_new();
    for (size_t i = 0; i < code.n; i++) dk_imap_put(m, i, NULL)->i = (i64)i;
    return m;
}

DK_TEST(slot_map_moved_and_swapped) {
    /* ours: two locals written at -4 (+3) and -8 (+7); the reference writes them the other way round */
    DkStr ours = CODE(0x83, 0xEC, 0x08, 0x89, 0x44, 0x24, 0x04, 0x89, 0x0C, 0x24, 0x83, 0xC4, 0x08, 0xC3);
    DkStr ref = CODE(0x83, 0xEC, 0x08, 0x89, 0x0C, 0x24, 0x90, 0x89, 0x44, 0x24, 0x04, 0x83, 0xC4, 0x08, 0xC3);
    /* the instruction map pairs +3 with +3 and +7 with +7: ours -4 meets the reference's -8 and the reverse */
    DkFrame *fo = dk_frame_analyse(dk_arena(), ours, 0x401000, NULL, NULL, 0, false);
    DkFrame *fg = dk_frame_analyse(dk_arena(), ref, 0x401000, NULL, NULL, 0, false);
    DkIMap *map = dk_imap_new();
    dk_imap_put(map, 0, NULL)->i = 0;
    dk_imap_put(map, 3, NULL)->i = 3;
    dk_imap_put(map, 7, NULL)->i = 7;
    DkFramePair *rows;
    size_t n = dk_frame_pair(dk_arena(), fo, fg, map, &rows);
    CHECK_EQ_I64((i64)n, 2);
    for (size_t i = 0; i < n; i++) {
        REQUIRE(rows[i].ours && rows[i].game);
        CHECK(rows[i].ours->offset != rows[i].game->offset); /* each pair crossed */
        CHECK(rows[i].votes > 0);
    }
    /* ours first: the higher offset (-4) before -8 */
    CHECK_EQ_I64(rows[0].ours->offset, -4);
    CHECK_EQ_I64(rows[0].game->offset, -8);

    DkFrameName names[] = {{-4, 0, "first"}, {-8, -4, "second"}};
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    dk_frame_slotmap(&b, fo, fg, map, names, 2);
    DkStr text = dk_buf_str(&b);
    CHECK(contains(text, "2 paired"));
    CHECK(contains(text, "2 row(s) differ"));
    CHECK(contains(text, "swap: ours"));
    CHECK(contains(text, "first"));
}

DK_TEST(slot_map_identity_and_unpaired) {
    DkStr code = CODE(0x83, 0xEC, 0x08, 0x89, 0x44, 0x24, 0x04, 0x83, 0xC4, 0x08, 0xC3);
    DkFrame *f = dk_frame_analyse(dk_arena(), code, 0x401000, NULL, NULL, 0, false);
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    dk_frame_slotmap(&b, f, f, identity_map(code), NULL, 0);
    DkStr text = dk_buf_str(&b);
    CHECK(contains(text, "1 paired, 0 row(s) differ"));
    CHECK(!contains(text, "swap:"));

    /* a slot the reference lacks: ours only; one ours lacks: reference only */
    DkStr more = CODE(0x83, 0xEC, 0x08, 0x89, 0x44, 0x24, 0x04, 0x89, 0x0C, 0x24, 0x83, 0xC4, 0x08, 0xC3);
    DkFrame *g = dk_frame_analyse(dk_arena(), more, 0x401000, NULL, NULL, 0, false);
    dk_buf_init(&b, dk_arena());
    dk_frame_slotmap(&b, g, f, identity_map(more), NULL, 0);
    CHECK(contains(dk_buf_str(&b), "(ours only)"));
    dk_buf_init(&b, dk_arena());
    dk_frame_slotmap(&b, f, g, identity_map(more), NULL, 0);
    CHECK(contains(dk_buf_str(&b), "(reference only)"));
}

DK_TEST_MAIN("frame")
