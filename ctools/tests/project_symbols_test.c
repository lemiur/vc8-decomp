// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* project_symbols.c: the symbol sources of the project adapter. Each source kind is written at test time (a TSV in
 * the layout of the usual function listing, one with only RVAs, a synthetic PDB 7.00 with publics and module
 * procedures, a hand-written MSVC linker map) and loaded through dk_symbols_load; then the precedence across sources,
 * the lookups (at, containing, next, find, all), the layering of names with dk_symbols_add and the errors. */
#include "dk/dk.h"
#include "dk/test.h"
#include "project.h"
#include "fixtures/synth_pdb.h"

#include <string.h>

#define BASE 0x400000u
#define REQUIRE_PTR(p) REQUIRE((p) != NULL)

/* A scratch folder per test, removed by the test at its end. */
static char *scratch(void) {
    char *dir = dk_mkdtemp(dk_arena(), "dk_symbols_test_", "", NULL);
    return dir;
}

static const char *write_text(const char *dir, const char *name, const char *text) {
    char *path = dk_path_join(dk_arena(), dir, name);
    dk_write_file(path, text, strlen(text));
    return path;
}

static DkSymSource tsv_src(const char *path) {
    DkSymSource s = {0};
    s.kind = DK_SYM_TSV;
    s.path = path;
    return s;
}

/* ---- a synthetic PDB: publics Foo (1:0x10), table (2:0x40), Bar (1:0x110); procedures Foo (len 0x20), baz (1:0x80,
 * len 0x10, no public), bar (1:0x110, len 0x10); sections at RVA 0x1000 and 0x3000 ---- */
static void build_pdb(SynthBuf *file) {
    SynthPdb p = {0};
    p.count = 9;
    synth_info(&p.stream[1], "/names", 6);

    SynthBuf recs = {{0}};
    synth_public(&recs, "?Foo@@YAHXZ", 1, 0x10, 2);
    synth_public(&recs, "_table", 2, 0x40, 0);
    synth_public(&recs, "?Bar@@YAXXZ", 1, 0x110, 2);
    sb_bytes(&p.stream[4], recs.data.v, recs.data.n);

    u32 rva[2] = {0x1000, 0x3000};
    synth_sections(&p.stream[5], rva, 2);

    const char *names[1] = {"src\\a.c"};
    u32 offsets[1];
    synth_names(&p.stream[6], names, 1, offsets);

    SynthBuf syms0 = {{0}};
    synth_proc(&syms0, 0x1110, "Foo", 1, 0x10, 0x20, 0x1000);
    synth_proc(&syms0, 0x1110, "baz", 1, 0x80, 0x10, 0x1000);
    u32 sym0, c13_0;
    synth_module_stream(&p.stream[7], &syms0, 1, 0, 0, NULL, 0, &sym0, &c13_0);

    SynthBuf syms1 = {{0}};
    synth_proc(&syms1, 0x110F, "bar", 1, 0x110, 0x10, 0x1000);
    u32 sym1, c13_1;
    synth_module_stream(&p.stream[8], &syms1, 1, 0, 0, NULL, 0, &sym1, &c13_1);

    SynthBuf mods = {{0}}, contribs = {{0}};
    synth_modinfo(&mods, 1, 0, 0x100, 7, sym0, c13_0, "C:\\build\\a.obj", "C:\\build\\a.obj");
    synth_modinfo(&mods, 1, 0x100, 0x80, 8, sym1, c13_1, "C:\\build\\b.obj", "C:\\build\\b.obj");
    sb_u32(&contribs, 0xF12EBA2Du);
    synth_contrib(&contribs, 1, 0, 0x100, 0x60000020u, 0);
    synth_contrib(&contribs, 1, 0x100, 0x80, 0x60000020u, 1);
    synth_dbi(&p.stream[3], 4, 5, &mods, &contribs);

    bool nil[SYNTH_MAX_STREAMS] = {0};
    nil[2] = true; /* no type stream */
    synth_msf_write(&p, nil, file);

    dk_vec_free(&recs.data);
    dk_vec_free(&syms0.data);
    dk_vec_free(&syms1.data);
    dk_vec_free(&mods.data);
    dk_vec_free(&contribs.data);
    synth_pdb_free(&p);
}

static const char *write_pdb(const char *dir, const char *name) {
    SynthBuf file = {{0}};
    build_pdb(&file);
    char *path = dk_path_join(dk_arena(), dir, name);
    dk_write_file(path, file.data.v, file.data.n);
    dk_vec_free(&file.data);
    return path;
}

static const char *const MAP_TEXT =
    " synthetic\r\n"
    "\r\n"
    " Timestamp is 4b8c0d3a (Fri Feb 26 12:00:00 2010)\r\n"
    "\r\n"
    " Preferred load address is 00400000\r\n"
    "\r\n"
    " Start         Length     Name                   Class\r\n"
    " 0001:00000000 00000100H .text                   CODE\r\n"
    " 0002:00000000 00000040H .data                   DATA\r\n"
    "\r\n"
    "  Address         Publics by Value              Rva+Base       Lib:Object\r\n"
    "\r\n"
    " 0001:00000010       _main                      00401010 f   main.obj\r\n"
    " 0001:00000040       ?alpha@@YAHH@Z             00401040 f   util.obj\r\n"
    " 0002:00000008       _g_table                   00402008     util.obj\r\n"
    " 0001:00000090       __imp__Sleep@4             00401090 f i kernel32:KERNEL32.dll\r\n"
    "\r\n"
    " entry point at        0001:00000010\r\n"
    "\r\n"
    " Static symbols\r\n"
    "\r\n"
    " 0001:00000080       ?helper@@YAXXZ             00401080 f   util.obj\r\n"
    " 0001:000000a0       `string'                   004010a0     util.obj\r\n"
    " 0001:000000b0       `dynamic initializer for 'g_x''  004010b0 f   util.obj\r\n";

/* ---- tsv ---------------------------------------------------------------------------------------------------------- */

DK_TEST(tsv_function_listing) {
    char *dir = scratch();
    const char *path = write_text(
        dir, "functions.tsv",
        "\xEF\xBB\xBFname\trva\tva\tsection\tsection_index\tsection_offset\tsize\tboundary_status\r\n"
        "?alpha@@YAHH@Z\t4096\t4198400\t.text\t1\t0\t48\tok\r\n"
        "?beta@@YAXXZ\t4160\t4198464\t.text\t1\t64\t\tok\r\n"
        "\t4200\t4198500\t.text\t1\t100\t8\tok\r\n"           /* no name: skipped */
        "?gamma@@YAXXZ\t0\tbogus\t.text\t1\t0\t8\tok\r\n"      /* unusable address: skipped */
        "?delta@@YAHXZ\t8192\t4198656\t.text\t1\t0\t16\tok\r\n");
    DkSymSource src = tsv_src(path);
    DkErr err = {0};
    DkSymbols *s = dk_symbols_load(NULL, &src, 1, 0, &err);
    REQUIRE_PTR(s);
    size_t n = 0;
    const DkSymbol *all = dk_symbols_all(s, &n);
    REQUIRE(n == 3);
    CHECK_EQ_U64(all[0].va, 0x401000);
    CHECK_CZ(all[0].name, "?alpha@@YAHH@Z");
    CHECK_EQ_U64(all[0].size, 48);
    CHECK_EQ_U64(all[1].va, 0x401040);
    CHECK_CZ(all[1].name, "?beta@@YAXXZ");
    CHECK_EQ_U64(all[1].size, 0);
    CHECK_EQ_U64(all[2].va, 0x401100);
    CHECK_CZ(all[2].name, "?delta@@YAHXZ");
    CHECK_EQ_U64(all[2].size, 16);
    dk_tempdir_cleanup(dir);
}

DK_TEST(tsv_rva_only) {
    char *dir = scratch();
    const char *path = write_text(dir, "rva.tsv",
                                  "name\trva\tsize\n"
                                  "?one@@YAXXZ\t4096\t32\n"
                                  "?two@@YAXXZ\t0x2000\t0x10\n"
                                  "?three@@YAXXZ\t0x3000\t\n"
                                  "?four@@YAXXZ\tnope\t4\n");
    DkSymSource src = tsv_src(path);
    DkErr err = {0};
    DkSymbols *s = dk_symbols_load(NULL, &src, 1, BASE, &err);
    REQUIRE_PTR(s);
    size_t n = 0;
    dk_symbols_all(s, &n);
    CHECK_EQ_U64(n, 3);
    const DkSymbol *one = dk_symbols_at(s, BASE + 0x1000);
    REQUIRE_PTR(one);
    CHECK_CZ(one->name, "?one@@YAXXZ");
    CHECK_EQ_U64(one->size, 32);
    const DkSymbol *two = dk_symbols_find(s, "?two@@YAXXZ");
    REQUIRE_PTR(two);
    CHECK_EQ_U64(two->va, BASE + 0x2000);
    CHECK_EQ_U64(two->size, 16);
    const DkSymbol *three = dk_symbols_at(s, BASE + 0x3000);
    REQUIRE_PTR(three);
    CHECK_EQ_U64(three->size, 0);
    dk_tempdir_cleanup(dir);
}

DK_TEST(tsv_rva_without_base_is_an_error) {
    char *dir = scratch();
    const char *path = write_text(dir, "rva.tsv", "name\trva\tsize\n?one@@YAXXZ\t4096\t32\n");
    DkSymSource src = tsv_src(path);
    DkErr err = {0};
    CHECK(dk_symbols_load(NULL, &src, 1, 0, &err) == NULL);
    CHECK_EQ_I64(err.code, DK_ERR_FORMAT);
    CHECK(strstr(err.msg, "image base") != NULL);
    CHECK(strstr(err.msg, "rva.tsv") != NULL);
    dk_tempdir_cleanup(dir);
}

DK_TEST(tsv_custom_columns) {
    char *dir = scratch();
    const char *path = write_text(dir, "index.tsv",
                                  "address\tsymbol\tlen\n"
                                  "0x00401000\t?alpha@@YAHH@Z\t12\n"
                                  "4198464\t?beta@@YAXXZ\t\n");
    DkSymSource src = tsv_src(path);
    src.col_name = "symbol";
    src.col_va = "address";
    src.col_size = "len";
    DkErr err = {0};
    DkSymbols *s = dk_symbols_load(NULL, &src, 1, 0, &err);
    REQUIRE_PTR(s);
    const DkSymbol *a = dk_symbols_find(s, "?alpha@@YAHH@Z");
    REQUIRE_PTR(a);
    CHECK_EQ_U64(a->va, 0x401000);
    CHECK_EQ_U64(a->size, 12);
    const DkSymbol *b = dk_symbols_find(s, "?beta@@YAXXZ");
    REQUIRE_PTR(b);
    CHECK_EQ_U64(b->va, 0x401040);
    /* the default names do not exist in this file */
    DkSymSource plain = tsv_src(path);
    CHECK(dk_symbols_load(NULL, &plain, 1, BASE, &err) == NULL);
    CHECK_EQ_I64(err.code, DK_ERR_FORMAT);
    dk_tempdir_cleanup(dir);
}

DK_TEST(missing_files_are_errors) {
    char *dir = scratch();
    char *gone = dk_path_join(dk_arena(), dir, "gone");
    DkErr err = {0};
    DkSymSource tsv = tsv_src(gone);
    CHECK(dk_symbols_load(NULL, &tsv, 1, BASE, &err) == NULL);
    CHECK_EQ_I64(err.code, DK_ERR_IO);
    CHECK(strstr(err.msg, "gone") != NULL);
    DkSymSource map = {DK_SYM_MAP, gone, NULL, NULL, NULL, NULL};
    CHECK(dk_symbols_load(NULL, &map, 1, BASE, &err) == NULL);
    CHECK_EQ_I64(err.code, DK_ERR_IO);
    DkSymSource pdb = {DK_SYM_PDB, gone, NULL, NULL, NULL, NULL};
    CHECK(dk_symbols_load(NULL, &pdb, 1, BASE, &err) == NULL);
    CHECK(err.code != 0);
    /* no sources: an empty table */
    DkSymbols *s = dk_symbols_load(NULL, NULL, 0, 0, &err);
    REQUIRE_PTR(s);
    size_t n = 7;
    dk_symbols_all(s, &n);
    CHECK_EQ_U64(n, 0);
    dk_tempdir_cleanup(dir);
}

/* ---- pdb ---------------------------------------------------------------------------------------------------------- */

DK_TEST(pdb_publics_and_procedures) {
    char *dir = scratch();
    const char *path = write_pdb(dir, "synth.pdb");
    DkSymSource src = {DK_SYM_PDB, path, NULL, NULL, NULL, NULL};
    DkErr err = {0};
    DkSymbols *s = dk_symbols_load(NULL, &src, 1, BASE, &err);
    REQUIRE_PTR(s);
    size_t n = 0;
    const DkSymbol *all = dk_symbols_all(s, &n);
    REQUIRE(n == 4);
    /* the publics keep their decorated names; a procedure's length fills the size of the public at its address */
    CHECK_EQ_U64(all[0].va, BASE + 0x1010);
    CHECK_CZ(all[0].name, "?Foo@@YAHXZ");
    CHECK_EQ_U64(all[0].size, 0x20);
    /* a procedure with no public is named by the procedure */
    CHECK_EQ_U64(all[1].va, BASE + 0x1080);
    CHECK_CZ(all[1].name, "baz");
    CHECK_EQ_U64(all[1].size, 0x10);
    CHECK_EQ_U64(all[2].va, BASE + 0x1110);
    CHECK_CZ(all[2].name, "?Bar@@YAXXZ");
    CHECK_EQ_U64(all[2].size, 0x10);
    /* a data public in the second section, size unknown */
    CHECK_EQ_U64(all[3].va, BASE + 0x3040);
    CHECK_CZ(all[3].name, "_table");
    CHECK_EQ_U64(all[3].size, 0);
    dk_tempdir_cleanup(dir);
}

DK_TEST(pdb_needs_an_image_base) {
    char *dir = scratch();
    const char *path = write_pdb(dir, "synth.pdb");
    DkSymSource src = {DK_SYM_PDB, path, NULL, NULL, NULL, NULL};
    DkErr err = {0};
    CHECK(dk_symbols_load(NULL, &src, 1, 0, &err) == NULL);
    CHECK_EQ_I64(err.code, DK_ERR_FORMAT);
    CHECK(strstr(err.msg, "image base") != NULL);
    /* a file that is not a PDB is an error, not a crash */
    const char *junk = write_text(dir, "junk.pdb", "this is not a program database");
    DkSymSource bad = {DK_SYM_PDB, junk, NULL, NULL, NULL, NULL};
    CHECK(dk_symbols_load(NULL, &bad, 1, BASE, &err) == NULL);
    CHECK(err.code != 0);
    dk_tempdir_cleanup(dir);
}

/* ---- map ---------------------------------------------------------------------------------------------------------- */

DK_TEST(map_publics_and_static_symbols) {
    char *dir = scratch();
    const char *path = write_text(dir, "link.map", MAP_TEXT);
    DkSymSource src = {DK_SYM_MAP, path, NULL, NULL, NULL, NULL};
    DkErr err = {0};
    DkSymbols *s = dk_symbols_load(NULL, &src, 1, 0, &err); /* a map needs no image base */
    REQUIRE_PTR(s);
    size_t n = 0;
    const DkSymbol *all = dk_symbols_all(s, &n);
    REQUIRE(n == 7);
    for (size_t i = 0; i < n; i++) CHECK_EQ_U64(all[i].size, 0);
    CHECK_CZ(all[0].name, "_main");
    CHECK_EQ_U64(all[0].va, 0x401010);
    CHECK_CZ(dk_symbols_at(s, 0x401040)->name, "?alpha@@YAHH@Z");
    CHECK_CZ(dk_symbols_at(s, 0x401080)->name, "?helper@@YAXXZ");
    CHECK_CZ(dk_symbols_at(s, 0x401090)->name, "__imp__Sleep@4");
    CHECK_CZ(dk_symbols_at(s, 0x4010a0)->name, "`string'");
    CHECK_CZ(dk_symbols_at(s, 0x4010b0)->name, "`dynamic initializer for 'g_x''");
    CHECK_CZ(dk_symbols_at(s, 0x402008)->name, "_g_table");
    /* the segment table above the publics is not read */
    CHECK(dk_symbols_find(s, ".text") == NULL);
    dk_tempdir_cleanup(dir);
}

/* ---- sources in order --------------------------------------------------------------------------------------------- */

DK_TEST(first_source_names_an_address) {
    char *dir = scratch();
    const char *tsv = write_text(dir, "a.tsv", "name\tva\tsize\n?tsvalpha@@YAHH@Z\t4198416\t\n?far@@YAXXZ\t4200000\t5\n");
    const char *map = write_text(dir, "link.map", MAP_TEXT);
    const char *pdb = write_pdb(dir, "synth.pdb");
    DkSymSource srcs[3] = {tsv_src(tsv), {DK_SYM_MAP, map, NULL, NULL, NULL, NULL}, {DK_SYM_PDB, pdb, NULL, NULL, NULL, NULL}};
    DkErr err = {0};
    DkSymbols *s = dk_symbols_load(NULL, srcs, 3, BASE, &err);
    REQUIRE_PTR(s);
    /* 0x401010 is named by the tsv, by the map (_main) and by the pdb (Foo): the tsv's name stays, the pdb's
     * procedure length fills the size the tsv left unknown */
    const DkSymbol *at = dk_symbols_at(s, 0x401010);
    REQUIRE_PTR(at);
    CHECK_CZ(at->name, "?tsvalpha@@YAHH@Z");
    CHECK_EQ_U64(at->size, 0x20);
    CHECK(dk_symbols_find(s, "_main") == NULL);
    CHECK(dk_symbols_find(s, "?Foo@@YAHXZ") == NULL);
    /* an address only a later source names is added; a size the first source gave is kept */
    CHECK_CZ(dk_symbols_at(s, 0x401040)->name, "?alpha@@YAHH@Z"); /* the map's name for 0x401040 */
    CHECK_CZ(dk_symbols_at(s, 0x401110)->name, "?Bar@@YAXXZ");
    CHECK_EQ_U64(dk_symbols_find(s, "?far@@YAXXZ")->size, 5);

    /* the same files, the pdb first: its names win */
    DkSymSource rev[3] = {srcs[2], srcs[1], srcs[0]};
    DkSymbols *r = dk_symbols_load(NULL, rev, 3, BASE, &err);
    REQUIRE_PTR(r);
    CHECK_CZ(dk_symbols_at(r, 0x401010)->name, "?Foo@@YAHXZ");
    CHECK_EQ_U64(dk_symbols_at(r, 0x401010)->size, 0x20);
    CHECK_CZ(dk_symbols_at(r, 0x401040)->name, "?alpha@@YAHH@Z");
    CHECK_CZ(dk_symbols_at(r, 0x403040)->name, "_table");
    dk_tempdir_cleanup(dir);
}

/* ---- the table ---------------------------------------------------------------------------------------------------- */

static DkSymbols *sample(void) {
    DkSymbols *s = dk_symbols_new(NULL);
    dk_symbols_add(s, 0x2000, 0, "c", false);
    dk_symbols_add(s, 0x1000, 0x20, "a", false);
    dk_symbols_add(s, 0x1100, 0x10, "b", false);
    dk_symbols_add(s, 0x1010, 0, "inner", false);
    return s;
}

DK_TEST(lookups) {
    DkSymbols *s = sample();
    size_t n = 0;
    const DkSymbol *all = dk_symbols_all(s, &n);
    REQUIRE(n == 4);
    CHECK_CZ(all[0].name, "a");
    CHECK_CZ(all[1].name, "inner");
    CHECK_CZ(all[2].name, "b");
    CHECK_CZ(all[3].name, "c");

    CHECK_CZ(dk_symbols_at(s, 0x1010)->name, "inner");
    CHECK(dk_symbols_at(s, 0x1011) == NULL);
    CHECK(dk_symbols_at(s, 0) == NULL);

    u32 start = 0;
    /* a sized symbol holding the address wins over a nearer unsized start */
    CHECK_CZ(dk_symbols_containing(s, 0x1015, &start)->name, "a");
    CHECK_EQ_U64(start, 0x1000);
    CHECK_CZ(dk_symbols_containing(s, 0x1105, &start)->name, "b");
    CHECK_EQ_U64(start, 0x1100);
    CHECK_CZ(dk_symbols_containing(s, 0x1100, NULL)->name, "b");
    /* in a gap: the nearest start at or below */
    CHECK_CZ(dk_symbols_containing(s, 0x1050, &start)->name, "inner");
    CHECK_EQ_U64(start, 0x1010);
    CHECK_CZ(dk_symbols_containing(s, 0x1110, &start)->name, "b"); /* b ends at 0x1110: nearest start */
    CHECK_CZ(dk_symbols_containing(s, 0x9000, &start)->name, "c");
    CHECK_EQ_U64(start, 0x2000);
    CHECK(dk_symbols_containing(s, 0xFFF, &start) == NULL);
    CHECK_EQ_U64(start, 0);

    CHECK_EQ_U64(dk_symbols_next(s, 0), 0x1000);
    CHECK_EQ_U64(dk_symbols_next(s, 0x1000), 0x1010);
    CHECK_EQ_U64(dk_symbols_next(s, 0x1011), 0x1100);
    CHECK_EQ_U64(dk_symbols_next(s, 0x2000), 0);

    CHECK_EQ_U64(dk_symbols_find(s, "b")->va, 0x1100);
    CHECK(dk_symbols_find(s, "nope") == NULL);
    CHECK(dk_symbols_find(NULL, "b") == NULL);
}

DK_TEST(layering_names) {
    DkSymbols *s = sample();
    /* replace = false keeps the name and fills only an unknown size */
    dk_symbols_add(s, 0x1100, 0x99, "b2", false);
    CHECK_CZ(dk_symbols_at(s, 0x1100)->name, "b");
    CHECK_EQ_U64(dk_symbols_at(s, 0x1100)->size, 0x10);
    dk_symbols_add(s, 0x2000, 4, "c2", false);
    CHECK_CZ(dk_symbols_at(s, 0x2000)->name, "c");
    CHECK_EQ_U64(dk_symbols_at(s, 0x2000)->size, 4);
    CHECK(dk_symbols_find(s, "b2") == NULL);
    /* replace = true layers a name on top; the old name no longer finds it */
    dk_symbols_add(s, 0x1010, 8, "inner2", true);
    CHECK_CZ(dk_symbols_at(s, 0x1010)->name, "inner2");
    CHECK_EQ_U64(dk_symbols_at(s, 0x1010)->size, 8);
    CHECK(dk_symbols_find(s, "inner") == NULL);
    CHECK_EQ_U64(dk_symbols_find(s, "inner2")->va, 0x1010);
    u32 start = 0;
    CHECK_CZ(dk_symbols_containing(s, 0x1015, &start)->name, "inner2"); /* the nearest sized symbol holding it */
    CHECK_EQ_U64(start, 0x1010);
    /* a new address added after a lookup is merged in */
    dk_symbols_add(s, 0x500, 0, "first", false);
    dk_symbols_add(s, 0x1800, 0, "late", true);
    size_t n = 0;
    const DkSymbol *all = dk_symbols_all(s, &n);
    REQUIRE(n == 6);
    CHECK_CZ(all[0].name, "first");
    CHECK_CZ(all[4].name, "late");
    CHECK_CZ(all[5].name, "c");
    /* nothing is added for no address or no name */
    dk_symbols_add(s, 0, 4, "zero", true);
    dk_symbols_add(s, 0x7000, 4, "", true);
    dk_symbols_add(s, 0x7000, 4, NULL, false);
    dk_symbols_all(s, &n);
    CHECK_EQ_U64(n, 6);
    CHECK(dk_symbols_at(s, 0x7000) == NULL);
}

DK_TEST(many_symbols_stay_sorted) {
    DkSymbols *s = dk_symbols_new(NULL);
    for (u32 i = 0; i < 2000; i++) {
        u32 va = 0x401000u + ((i * 37u) % 2000u) * 16u; /* a permutation of 2000 slots */
        dk_symbols_add(s, va, 16, dk_sprintf(dk_arena(), "f%u", va), false);
        if (i % 500 == 0) dk_symbols_next(s, va); /* a lookup in between */
    }
    size_t n = 0;
    const DkSymbol *all = dk_symbols_all(s, &n);
    REQUIRE(n == 2000);
    for (size_t i = 0; i < n; i++) CHECK_EQ_U64(all[i].va, 0x401000u + i * 16u);
    CHECK_EQ_U64(dk_symbols_containing(s, 0x401000u + 1234 * 16 + 7, NULL)->va, 0x401000u + 1234 * 16);
    CHECK_EQ_U64(dk_symbols_find(s, "f4202048")->size, 16);
}

DK_TEST_MAIN("project_symbols")
