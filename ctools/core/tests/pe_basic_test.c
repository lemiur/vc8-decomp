// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* pe.h on a hand-built PE32 image: one section, the optional header's fields, RVA and file-offset conversions and
 * data access. The image is written by this test from the PE format's documented layout; nothing is read from disk. */
#include "dk/dk.h"
#include "dk/test.h"

#include <string.h>

static void put16(u8 *p, size_t at, u32 v) {
    p[at] = (u8)v;
    p[at + 1] = (u8)(v >> 8);
}

static void put32(u8 *p, size_t at, u32 v) {
    put16(p, at, v & 0xFFFFu);
    put16(p, at + 2, v >> 16);
}

enum { IMAGE_SIZE = 0x400, NT = 0x40, OPT = NT + 4 + 20, SEC = OPT + 224 };

static void build_pe32(u8 *img) {
    memset(img, 0, IMAGE_SIZE);
    img[0] = 'M';
    img[1] = 'Z';
    put32(img, 0x3C, NT);
    memcpy(img + NT, "PE\0\0", 4);
    put16(img, NT + 4, 0x14C);            /* machine: i386 */
    put16(img, NT + 6, 1);                /* one section */
    put32(img, NT + 8, 0x12345678);       /* time date stamp */
    put16(img, NT + 20, 224);             /* size of optional header */
    put16(img, NT + 22, 0x0102);          /* characteristics: executable, 32-bit machine */
    put16(img, OPT, 0x10B);               /* magic: PE32 */
    put32(img, OPT + 16, 0x1000);         /* entry point */
    put32(img, OPT + 28, 0x400000);       /* image base */
    put32(img, OPT + 32, 0x1000);         /* section alignment */
    put32(img, OPT + 36, 0x200);          /* file alignment */
    put32(img, OPT + 56, 0x2000);         /* size of image */
    put32(img, OPT + 60, 0x200);          /* size of headers */
    put16(img, OPT + 68, 3);              /* subsystem: console */
    put32(img, OPT + 92, 16);             /* number of data directories */
    memcpy(img + SEC, ".text\0\0\0", 8);
    put32(img, SEC + 8, 0x10);            /* virtual size */
    put32(img, SEC + 12, 0x1000);         /* virtual address */
    put32(img, SEC + 16, 0x200);          /* size of raw data */
    put32(img, SEC + 20, 0x200);          /* pointer to raw data */
    put32(img, SEC + 36, 0x60000020);     /* characteristics: code, execute, read */
    for (int i = 0; i < 16; i++) img[0x200 + i] = (u8)(0xA0 + i);
}

DK_TEST(parse_headers_and_section) {
    u8 img[IMAGE_SIZE];
    build_pe32(img);
    DkArena *a = dk_arena_new(0);
    DkPe *pe = dk_pe_parse(a, img, sizeof img);
    CHECK(pe != NULL);
    if (pe) {
        CHECK_EQ_U64(pe->machine, 0x14C);
        CHECK_EQ_U64(pe->number_of_sections, 1);
        CHECK_EQ_U64(pe->time_date_stamp, 0x12345678u);
        CHECK_EQ_U64(pe->magic, 0x10B);
        CHECK_EQ_U64(pe->image_base, 0x400000);
        CHECK_EQ_U64(pe->address_of_entry_point, 0x1000);
        CHECK_EQ_U64(pe->section_alignment, 0x1000);
        CHECK_EQ_U64(pe->file_alignment, 0x200);
        CHECK_EQ_U64(pe->size_of_image, 0x2000);
        CHECK_EQ_U64(pe->n_sections, 1);
        if (pe->n_sections == 1) {
            const DkPeSection *s = &pe->sections[0];
            CHECK_STR(s->name, ".text");
            CHECK_EQ_U64(s->virtual_address, 0x1000);
            CHECK_EQ_U64(s->pointer_to_raw_data, 0x200);
            CHECK_EQ_U64(s->characteristics, 0x60000020u);
            CHECK(dk_pe_section_by_rva(pe, 0x1008) == s);
            CHECK(dk_pe_section_by_rva(pe, 0x3000) == NULL);
            CHECK(dk_pe_section_by_offset(pe, 0x208) == s);
        }
    }
    dk_arena_free(a);
}

DK_TEST(rva_offset_and_data) {
    u8 img[IMAGE_SIZE];
    build_pe32(img);
    DkArena *a = dk_arena_new(0);
    DkPe *pe = dk_pe_parse(a, img, sizeof img);
    CHECK(pe != NULL);
    if (pe) {
        u64 off = 0, rva = 0;
        CHECK(dk_pe_offset_from_rva(pe, 0x1004, &off));
        CHECK_EQ_U64(off, 0x204);
        CHECK(dk_pe_rva_from_offset(pe, 0x204, &rva));
        CHECK_EQ_U64(rva, 0x1004);
        u32 dw = 0;
        CHECK(dk_pe_dword_at_rva(pe, 0x1000, &dw));
        CHECK_EQ_U64(dw, 0xA3A2A1A0u);
        DkPeSpan sp = {0};
        CHECK(dk_pe_try_get_data(pe, 0x1002, 4, &sp));
        CHECK_EQ_U64(sp.n, 4);
        if (sp.n == 4) CHECK_EQ_U64(sp.p[0], 0xA2);
    }
    dk_arena_free(a);
}

DK_TEST_MAIN("pe_basic")
