// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* rich_header on synthetic images built by tests/fixtures/synth_pe.h: the listings are computed by hand. */
#define DK_RICH_HEADER_AS_LIBRARY
#include "../tools/rich_header_main.c"
#include "dk/test.h"
#include "fixtures/synth_pe.h"

static DkStr describe(const DkBytes *img) {
    DkBuf out;
    dk_buf_init(&out, dk_arena());
    rich_header_describe(&out, "x.exe", *img);
    return (DkStr){out.p, out.n};
}

DK_TEST(decodes_records) {
    static const SynthRichEntry recs[] = {
        {(0x006Eu << 16) | 50727u, 12},
        {(0x0078u << 16) | 8u, 1},
        {(0x7777u << 16) | 65535u, 123456},
    };
    DkBytes img = {0};
    synth_pe_build(&img, recs, 3, 0xA5C3E1F7u);
    DkStr s = describe(&img);
    CHECK_STR(s,
              "== x.exe\n"
              "   product 006E build 50727  x12    Utc1400_CPP (VS2005 C++)\n"
              "   product 0078 build     8  x1     Linker800 (VS2005)\n"
              "   product 7777 build 65535  x123456 ?\n");
    dk_vec_free(&img);
}

DK_TEST(other_key) {
    static const SynthRichEntry recs[] = {{(0x0001u << 16) | 0u, 7}};
    DkBytes img = {0};
    synth_pe_build(&img, recs, 1, 0x00000001u);
    CHECK_STR(describe(&img),
              "== x.exe\n"
              "   product 0001 build     0  x7     Import0 (imports without a tool)\n");
    dk_vec_free(&img);
}

DK_TEST(empty_header) {
    DkBytes img = {0};
    synth_pe_build(&img, NULL, 0, 0x12345678u);
    CHECK_STR(describe(&img), "== x.exe\n");
    dk_vec_free(&img);
}

DK_TEST(no_rich_header) {
    DkBytes img = {0};
    synth_pe_build(&img, NULL, -1, 0);
    CHECK_STR(describe(&img), "== x.exe\n   no Rich header\n");
    dk_vec_free(&img);
}

DK_TEST(help_exits_zero) {
    DkStr argv[] = {DK_S("--help")};
    DkArgsExit ex = {0};
    DkArgs *r = dk_args_try_parse(rich_header_parser(), argv, 1, false, &ex);
    CHECK(r == NULL);
    CHECK_EQ_I64(ex.code, 0);
    CHECK(dk_str_contains(ex.out, DK_S("usage: rich_header.exe")));
    CHECK(ex.err.n == 0);
}

DK_TEST_MAIN("rich_header")
