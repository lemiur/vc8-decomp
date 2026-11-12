// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Tests of lib/coff.c on synthetic objects. The expected bytes are lower-case hex of objects described in the
 * comments below (a hand-checked layout, 20-byte header, 40-byte section headers, 18-byte symbols, 10-byte
 * relocations, a trailing string table); the fixture writer tests/fixtures/synth_coff.h builds the same objects
 * from a description, and the rewriters' results are compared with the expected objects byte for byte.
 *     ABS   absolute_object: _a, ?long_name@@YAXXZ, exactly8, nine_char (long names go to the string table)
 *     TAB   table_object(".longsection", "_hooks", [1, (_f,4), (@,0x10), (_g?long_extern,-1), (_f,0), -5], "abc\0de")
 *     TAB2  table_object(".d", "_p", [], "")
 *     CODE  code_object(55 8b ec c3 90)
 *     OBJ   one .text section of 16 NOPs with 5 relocations; symbols .text (+aux), _fn defined, _ext undefined, _fn
 *           undefined (the twin), ??_Gvery_long_destructor defined, _local static
 *     RED   redirect(OBJ, {_fn: _alias_fn_that_is_long, ??_Gvery_long_destructor: _g}, {_ext: __imp_ext_alias, _fn: _abs_fn})
 *     RED2  redirect(OBJ, {_fn: _z}, no aliases)
 *     REN   rename_symbols(OBJ, {_fn: _renamed_function_long, _ext: _e2, _local: _l});  REN2: an empty mapping */
#include "dk/dk.h"
#include "dk/test.h"
#include "../lib/coff.h"
#include "fixtures/synth_coff.h"

static const char *const ABS =
    "4c010000000000001400000004000000000000005f6100000000000000104000ffff0000020000000000040000007856"
    "3412ffff0000020065786163746c793807000000ffff000002000000000016000000ffffffffffff0000020020000000"
    "3f6c6f6e675f6e616d654040594158585a006e696e655f6368617200";
static const char *const TAB =
    "4c010100000000008400000005000000000000002e6c6f6e677365630000000000000000200000003c0000005c000000"
    "0000000004000000400030c0010000000400000010000000ffffffff00000000fbffffff616263006465000004000000"
    "030000000600080000000000000006000c00000004000000060010000000030000000600000000000400000000000000"
    "0100000003012000000004000000000000000000000000005f686f6f6b730000000000000100000002005f6600000000"
    "000000000000000020000200000000001100000000000000000020000200200000002e6c6f6e6773656374696f6e005f"
    "673f6c6f6e675f65787465726e00";
static const char *const TAB2 =
    "4c010100000000003c00000003000000000000002e640000000000000000000000000000000000003c0000003c000000"
    "0000000000000000400030c02e6400000000000000000000010000000301000000000000000000000000000000000000"
    "5f700000000000000000000001000000020004000000";
static const char *const CODE =
    "4c010100000000004100000003000000000000002e746578740000000000000000000000050000003c00000000000000"
    "000000000000000020005060558becc3902e746578740000000000000001000000030105000000000000000000000000"
    "00000000005f636f64650000000000000001002000020004000000";
static const char *const OBJ =
    "4c010100000000007e00000007000000000000002e746578740000000000000000000000100000003c0000004c000000"
    "000000000500000020005060909090909090909090909090909090900000000003000000060004000000020000001400"
    "080000000200000006000c0000000400000007000e0000000300000014002e7465787400000000000000010000000301"
    "1000000005000000000000000000000000005f666e0000000000000000000100200002005f6578740000000000000000"
    "0000200002005f666e0000000000000000000000200002000000000004000000000000000100200002005f6c6f63616c"
    "0000040000000100000003001d0000003f3f5f47766572795f6c6f6e675f64657374727563746f7200";
static const char *const RED =
    "4c010100000000007e0000000b000000000000002e746578740000000000000000000000100000003c0000004c000000"
    "000000000500000020005060909090909090909090909090909090900000000009000000060004000000070000001400"
    "080000000a00000006000c0000000200000007000e0000000300000014002e7465787400000000000000010000000301"
    "100000000500000000000000000000000000000000001d000000000000000100200002005f6578740000000000000000"
    "0000200002005f666e0000000000000000000000200002005f67000000000000000000000100200002005f6c6f63616c"
    "0000040000000100000003005f666e000000000000000000000020000200000000003400000000000000000020000200"
    "000000004d000000000000000000200002005f6162735f666e00000000000000200002005d0000003f3f5f4776657279"
    "5f6c6f6e675f64657374727563746f72005f616c6961735f666e5f746861745f69735f6c6f6e67003f3f5f4776657279"
    "5f6c6f6e675f64657374727563746f72005f5f696d705f6578745f616c69617300";
static const char *const RED2 =
    "4c010100000000007e00000008000000000000002e746578740000000000000000000000100000003c0000004c000000"
    "000000000500000020005060909090909090909090909090909090900000000003000000060004000000070000001400"
    "080000000700000006000c0000000200000007000e0000000300000014002e7465787400000000000000010000000301"
    "1000000005000000000000000000000000005f7a000000000000000000000100200002005f6578740000000000000000"
    "0000200002005f666e0000000000000000000000200002000000000004000000000000000100200002005f6c6f63616c"
    "0000040000000100000003005f666e0000000000000000000000200002001d0000003f3f5f47766572795f6c6f6e675f"
    "64657374727563746f7200";
static const char *const REN =
    "4c010100000000007e00000007000000000000002e746578740000000000000000000000100000003c0000004c000000"
    "000000000500000020005060909090909090909090909090909090900000000003000000060004000000020000001400"
    "080000000200000006000c0000000400000007000e0000000300000014002e7465787400000000000000010000000301"
    "100000000500000000000000000000000000000000001d000000000000000100200002005f6532000000000000000000"
    "0000200002000000000034000000000000000000200002000000000004000000000000000100200002005f6c00000000"
    "0000040000000100000003004b0000003f3f5f47766572795f6c6f6e675f64657374727563746f72005f72656e616d65"
    "645f66756e6374696f6e5f6c6f6e67005f72656e616d65645f66756e6374696f6e5f6c6f6e6700";
static const char *const REN2 =
    "4c010100000000007e00000007000000000000002e746578740000000000000000000000100000003c0000004c000000"
    "000000000500000020005060909090909090909090909090909090900000000003000000060004000000020000001400"
    "080000000200000006000c0000000400000007000e0000000300000014002e7465787400000000000000010000000301"
    "1000000005000000000000000000000000005f666e0000000000000000000100200002005f6578740000000000000000"
    "0000200002005f666e0000000000000000000000200002000000000004000000000000000100200002005f6c6f63616c"
    "0000040000000100000003001d0000003f3f5f47766572795f6c6f6e675f64657374727563746f7200";
static DkStr unhex(const char *h) {
    size_t n = strlen(h) / 2;
    u8 *b = dk_alloc(dk_arena(), n + 1);
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        b[i] = (u8)v;
    }
    return (DkStr){(const char *)b, n};
}
#define CHECK_OBJ(got, hex)                        \
    do {                                            \
        DkStr want_ = unhex(hex);                  \
        CHECK_EQ_U64((got).n, want_.n);             \
        if ((got).n == want_.n) CHECK_MEM((got).p, want_.p, want_.n); \
    } while (0)

DK_TEST(coff_writers) {
    CoffAbsoluteEntry e[] = {{"_a", 0x401000}, {"?long_name@@YAXXZ", 0x12345678}, {"exactly8", 7}, {"nine_char", 0xFFFFFFFFu}};
    CHECK_OBJ(coff_absolute_object(e, 4), ABS);
    CoffWord w[] = {{NULL, 1}, {"_f", 4}, {"@", 0x10}, {"_g?long_extern", -1}, {"_f", 0}, {NULL, -5}};
    CHECK_OBJ(coff_table_object(".longsection", "_hooks", w, 6, DK_S("abc\0de")), TAB);
    CHECK_OBJ(coff_table_object(".d", "_p", NULL, 0, (DkStr){"", 0}), TAB2);
    CHECK_OBJ(coff_code_object((DkStr){"\x55\x8b\xec\xc3\x90", 5}), CODE);
}

static const char *alias_fn(void *ctx, const char *s) {
    DK_UNUSED(ctx);
    if (!strcmp(s, "_ext")) return "__imp_ext_alias";
    if (!strcmp(s, "_fn")) return "_abs_fn";
    return NULL;
}
static const char *no_alias(void *ctx, const char *s) {
    DK_UNUSED(ctx);
    DK_UNUSED(s);
    return NULL;
}

DK_TEST(coff_rewriters) {
    DkStr obj = unhex(OBJ);
    DkMap *own = dk_map_new();
    dk_map_put(own, DK_S("_fn"), NULL)->p = "_alias_fn_that_is_long";
    dk_map_put(own, DK_S("??_Gvery_long_destructor"), NULL)->p = "_g";
    CHECK_OBJ(coff_redirect(obj, own, alias_fn, NULL), RED);
    DkMap *own2 = dk_map_new();
    dk_map_put(own2, DK_S("_fn"), NULL)->p = "_z";
    CHECK_OBJ(coff_redirect(obj, own2, no_alias, NULL), RED2);
    DkMap *m = dk_map_new();
    dk_map_put(m, DK_S("_fn"), NULL)->p = "_renamed_function_long";
    dk_map_put(m, DK_S("_ext"), NULL)->p = "_e2";
    dk_map_put(m, DK_S("_local"), NULL)->p = "_l";
    CHECK_OBJ(coff_rename_symbols(obj, m), REN);
    CHECK_OBJ(coff_rename_symbols(obj, dk_map_new()), REN2);
}

DK_TEST(coff_symbols_of_a_file) {
    DkStr obj = unhex(OBJ);
    char *dir = dk_gettempdir(dk_arena());
    char *path = dk_join(dk_arena(), dir, "coff_test_fixture.obj");
    REQUIRE(dk_write_file(path, obj.p, obj.n));
    size_t n;
    const CoffSymbol *s = coff_symbols(path, &n);
    REQUIRE(n == 6);
    /* [('.text', 0, 1, 0, 3), ('_fn', 0, 1, 32, 2), ('_ext', 0, 0, 32, 2), ('_fn', 0, 0, 32, 2),
     *  ('??_Gvery_long_destructor', 0, 1, 32, 2), ('_local', 4, 1, 0, 3)] */
    CHECK_STR(s[0].name, ".text");
    CHECK(s[0].value == 0 && s[0].section == 1 && s[0].type == 0 && s[0].storage == 3);
    CHECK_STR(s[1].name, "_fn");
    CHECK(s[1].section == 1 && s[1].type == 32 && s[1].storage == 2);
    CHECK_STR(s[4].name, "??_Gvery_long_destructor");
    CHECK_STR(s[5].name, "_local");
    CHECK(s[5].value == 4);
    DkStrVec u = coff_undefined_symbols(path);   /* ['_ext', '_fn'] */
    REQUIRE(u.n == 2);
    CHECK_STR(u.v[0], "_ext");
    CHECK_STR(u.v[1], "_fn");
    DkStrVec d = coff_defined_symbols(path);     /* ['_fn', '??_Gvery_long_destructor'] */
    REQUIRE(d.n == 2);
    CHECK_STR(d.v[0], "_fn");
    CHECK_STR(d.v[1], "??_Gvery_long_destructor");
    dk_remove(path);
}

/* OBJ built by the fixture writer. */
static DkStr build_obj(void) {
    SynthCoff sc;
    synth_coff_init(&sc);
    u8 nops[16];
    memset(nops, 0x90, sizeof nops);
    u32 text = synth_coff_section(&sc, ".text", COFF_CODE_SECTION_CHARACTERISTICS, nops, sizeof nops);
    synth_coff_reloc(&sc, text, 0, 3, COFF_IMAGE_REL_I386_DIR32);
    synth_coff_reloc(&sc, text, 4, 2, COFF_IMAGE_REL_I386_REL32);
    synth_coff_reloc(&sc, text, 8, 2, COFF_IMAGE_REL_I386_DIR32);
    synth_coff_reloc(&sc, text, 12, 4, COFF_IMAGE_REL_I386_DIR32NB);
    synth_coff_reloc(&sc, text, 14, 3, COFF_IMAGE_REL_I386_REL32);
    u8 aux[18] = {0x10, 0, 0, 0, 5};
    synth_coff_symbol(&sc, ".text", 0, 1, 0, COFF_IMAGE_SYM_CLASS_STATIC, 1);
    synth_coff_aux(&sc, aux);
    synth_coff_symbol(&sc, "_fn", 0, 1, 0x20, COFF_IMAGE_SYM_CLASS_EXTERNAL, 0);
    synth_coff_symbol(&sc, "_ext", 0, 0, 0x20, COFF_IMAGE_SYM_CLASS_EXTERNAL, 0);
    synth_coff_symbol(&sc, "_fn", 0, 0, 0x20, COFF_IMAGE_SYM_CLASS_EXTERNAL, 0);
    synth_coff_symbol(&sc, "??_Gvery_long_destructor", 0, 1, 0x20, COFF_IMAGE_SYM_CLASS_EXTERNAL, 0);
    synth_coff_symbol(&sc, "_local", 4, 1, 0, COFF_IMAGE_SYM_CLASS_STATIC, 0);
    return synth_coff_build(&sc);
}

DK_TEST(coff_fixture_writer) {
    DkStr got = build_obj();
    CHECK_OBJ(got, OBJ);
}

DK_TEST(coff_round_trip) {
    /* write with the library's writers, read the symbols back through a file */
    CoffAbsoluteEntry e[] = {{"_a", 0x401000}, {"?long_name@@YAXXZ", 0x12345678}};
    DkStr abs_obj = coff_absolute_object(e, 2);
    char *path = dk_join(dk_arena(), dk_gettempdir(dk_arena()), "coff_test_abs.obj");
    REQUIRE(dk_write_file(path, abs_obj.p, abs_obj.n));
    size_t n;
    const CoffSymbol *s = coff_symbols(path, &n);
    REQUIRE(n == 2);
    CHECK_STR(s[0].name, "_a");
    CHECK(s[0].value == 0x401000 && s[0].section == -1 && s[0].storage == COFF_IMAGE_SYM_CLASS_EXTERNAL);
    CHECK_STR(s[1].name, "?long_name@@YAXXZ");
    CHECK(s[1].value == 0x12345678);
    dk_remove(path);
    CoffWord w[] = {{NULL, 1}, {"_f", 4}};
    DkStr tab = coff_table_object(".d", "_t", w, 2, (DkStr){"xy", 2});
    REQUIRE(dk_write_file(path, tab.p, tab.n));
    s = coff_symbols(path, &n);
    REQUIRE(n == 3);
    CHECK_STR(s[1].name, "_t");
    CHECK_STR(s[2].name, "_f");
    CHECK(s[2].section == 0);
    dk_remove(path);
}

DK_TEST_MAIN("coff")
