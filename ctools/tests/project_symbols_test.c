// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* project_symbols.c: the symbol sources of the project adapter. Each source kind is written at test time (a TSV in
 * the layout of the usual function listing, one with only RVAs, a synthetic PDB 7.00 with publics and module
 * procedures, a hand-written MSVC linker map) and loaded through dk_symbols_load; then the precedence across sources,
 * the lookups (at, containing, next, find, all), the layering of names with dk_symbols_add and the errors. */
#include "dk/dk.h"
#include "dk/test.h"
#include "project.h"
#include "fakecl/fake_pe.h"
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

/* ---- a symbol store, a candidates file, names past an unsized symbol ----------------------------------------------- */

static const char *fwd_path(const char *p) {
    char *s = dk_strdup(dk_arena(), p);
    for (char *c = s; *c; c++)
        if (*c == '\\') *c = '/';
    return s;
}

static const char *join2(const char *a, const char *b) { return dk_join(dk_arena(), a, b); }

static void put32le(u8 *p, u32 v) { memcpy(p, &v, 4); }

/* Writes dir/rel (the folders made first). */
static void write_in(const char *dir, const char *rel, const char *text) {
    const char *path = join2(dir, rel);
    dk_makedirs(dk_cz(dk_arena(), dk_path_dirname(path)), true);
    DK_ASSERT(dk_write_file(path, text, strlen(text)));
}

/* The folder name of the CodeView record below: GUID 11223344-5566-7788-99AA-BBCCDDEEFF00, age 1. */
#define GUID_A "112233445566778899AABBCCDDEEFF001"
#define GUID_B "00000000000000000000000000000000B"
#define GUID_C "00000000000000000000000000000000C"

/* An image with a debug directory holding an RSDS record: the GUID above, its first byte replaced by first, age 1. */
static void write_rsds_image(const char *path, u8 first) {
    FakePe pe;
    fake_pe_init(&pe, BASE);
    u8 rdata[0x100];
    memset(rdata, 0, sizeof rdata);
    u32 rva = 0x1000;
    u32 raw = 0x200; /* the first section's file offset: the headers rounded up to 0x200 */
    put32le(rdata + 12, 2);        /* IMAGE_DEBUG_TYPE_CODEVIEW */
    put32le(rdata + 16, 24 + 6);   /* size of data */
    put32le(rdata + 20, rva + 28); /* address of raw data */
    put32le(rdata + 24, raw + 28); /* pointer to raw data */
    memcpy(rdata + 28, "RSDS", 4);
    static const u8 guid[16] = {0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77,
                                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
    memcpy(rdata + 32, guid, 16);
    rdata[32] = first;
    put32le(rdata + 48, 1); /* age */
    memcpy(rdata + 52, "x.pdb", 6);
    fake_pe_section(&pe, ".rdata", 0x40000040u, rdata, sizeof rdata);
    DK_ASSERT(fake_pe_write(&pe, path));
    /* the debug entry of the data directory (index 6, at the optional header + 96 + 48) */
    DkBytes b = {0};
    DK_ASSERT(dk_read_all(dk_arena(), path, &b));
    put32le(b.v + 0x98 + 96 + 48, rva);
    put32le(b.v + 0x98 + 96 + 52, 28);
    DK_ASSERT(dk_write_file(path, b.v, b.n));
}

static const char COMMON_CONFIG_TAIL[] =
    " \"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]},\n"
    " \"compiler\": {\"cl\": \"${root}/cl.exe\"},\n"
    " \"backend\": {\"kind\": \"object\"},\n"
    " \"annotations\": {\"marker\":\n"
    "  \"^//\\\\s*(?P<kind>FUNCTION):\\\\s+(?P<target>\\\\w+)\\\\s+(?P<addr>0x[0-9a-fA-F]+)\\\\s*$\",\n"
    "                 \"kinds\": {\"FUNCTION\": \"function\"}}}\n";

/* A store with the given entries (a folder name per entry, the first holding the real PDB, the others junk) and an
 * image whose GUID starts with image_first: the symbol table the project loads, or NULL with err set. */
static DkSymbols *load_store(const char *const *entries, size_t n, u8 image_first, DkErr *err) {
    char *root = dk_mkdtemp(dk_arena(), "dk_store_test_", "", NULL);
    const char *r = fwd_path(root);
    for (size_t i = 0; i < n; i++) {
        const char *sub = join2(r, dk_sprintf(dk_arena(), "symbols/synth.pdb/%s", entries[i]));
        dk_makedirs(sub, true);
        if (i == 0) {
            write_pdb(sub, "synth.pdb");
        } else {
            write_in(sub, "synth.pdb", "this is not a program database");
        }
    }
    write_rsds_image(join2(r, "t.dll"), image_first);
    write_in(r, "config/ctools.json",
             dk_sprintf(dk_arena(),
                        "{\"schema\": \"decompkit-project/1\",\n"
                        " \"targets\": {\"t\": {\"image\": \"${root}/t.dll\", \"image_base\": 4194304,\n"
                        "   \"symbols\": [{\"kind\": \"pdb\", \"path\": \"${root}/symbols/synth.pdb\"}]}},\n%s",
                        COMMON_CONFIG_TAIL));
    DkProject *p = dk_project_load(dk_arena(), r, NULL, err);
    if (!p) return NULL;
    return dk_project_symbols(p, 0, err);
}

DK_TEST(pdb_symbol_store_picks_the_image_entry) {
    /* the real pdb sits under the image's id; a second entry (junk) is not picked */
    const char *both[2] = {GUID_A, GUID_B};
    DkErr err = {0};
    DkSymbols *s = load_store(both, 2, 0x44, &err);
    CHECK_MSG(s != NULL, "%s", err.msg);
    REQUIRE_PTR(s);
    CHECK(dk_symbols_find(s, "?Foo@@YAHXZ") != NULL);
    /* the junk sits under the image's id and the real pdb elsewhere: the image's entry is the one read, and fails */
    const char *swapped[2] = {GUID_B, GUID_A};
    DkErr e2 = {0};
    CHECK(load_store(swapped, 2, 0x44, &e2) == NULL);
}

DK_TEST(pdb_symbol_store_falls_back_to_the_only_entry) {
    const char *one[1] = {GUID_B};
    DkErr err = {0};
    DkSymbols *s = load_store(one, 1, 0x44, &err); /* the image asks for GUID_A: not there, but the only entry */
    REQUIRE_PTR(s);
    CHECK(dk_symbols_find(s, "?Foo@@YAHXZ") != NULL);
}

DK_TEST(pdb_symbol_store_rejects_an_ambiguous_store) {
    const char *two[2] = {GUID_C, GUID_B};
    DkErr err = {0};
    CHECK(load_store(two, 2, 0x44, &err) == NULL);
    CHECK(err.msg[0] && strstr(err.msg, "symbol store") != NULL);
}

DK_TEST(candidates_source_names_objects_and_functions) {
    char *dir = scratch();
    const char *path = write_text(dir, "cands.json",
        "{\"schema_version\": 1, \"candidates\": [],\n"
        " \"referents\": {\"cl\": {\n"
        "  \"?g_obj@@3HA\": {\"va\": \"0x41a014\", \"kind\": \"symbol\", \"size\": 12},\n"
        "  \"?g_plain@@3HA\": {\"va\": \"0x41a020\", \"evidence\": \"no kind\"},\n"
        "  \"member:?g_obj@@3HA.f\": {\"kind\": \"member\", \"va\": \"0x41a018\", \"offset\": 4},\n"
        "  \"kernel32.dll!Sleep\": {\"kind\": \"import\", \"va\": \"0x40d00c\"},\n"
        "  \"literal:sha256:ab\": {\"kind\": \"literal\", \"va\": \"0x414990\", \"size\": 4},\n"
        "  \"entry-alias:a|b\": {\"kind\": \"entry-alias\", \"va\": \"0x40bd30\", \"size\": 43, \"aliases\": [\"a\", \"b\"]},\n"
        "  \"thunk\": {\"kind\": \"import-thunk\", \"va\": 4242240}}}}\n");
    DkSymSource src = {DK_SYM_CANDIDATES, path, "cl", NULL, NULL, NULL};
    DkErr err = {0};
    DkSymbols *s = dk_symbols_load(NULL, &src, 1, BASE, &err);
    REQUIRE_PTR(s);
    CHECK_EQ_U64(dk_symbols_find(s, "?g_obj@@3HA")->va, 0x41a014);
    CHECK_EQ_U64(dk_symbols_find(s, "?g_obj@@3HA")->size, 12);
    CHECK_EQ_U64(dk_symbols_find(s, "?g_plain@@3HA")->va, 0x41a020);
    CHECK_EQ_U64(dk_symbols_find(s, "thunk")->va, 4242240);
    CHECK(dk_symbols_find(s, "member:?g_obj@@3HA.f") == NULL);
    CHECK(dk_symbols_find(s, "kernel32.dll!Sleep") == NULL);
    CHECK(dk_symbols_find(s, "literal:sha256:ab") == NULL);
    CHECK(dk_symbols_find(s, "entry-alias:a|b") == NULL);
    CHECK_EQ_U64(dk_symbols_at(s, 0x40bd30)->size, 43); /* both aliases are at one address: the first name holds it */
    CHECK_CZ(dk_symbols_at(s, 0x40bd30)->name, "a");
    /* the file's only binary is taken when the name does not match; a two-binary file then needs the name */
    DkSymSource other = {DK_SYM_CANDIDATES, path, "name", NULL, NULL, NULL};
    CHECK(dk_symbols_load(NULL, &other, 1, BASE, &err) != NULL);
    const char *two = write_text(dir, "two.json", "{\"referents\": {\"cl\": {}, \"c1\": {}}}\n");
    DkSymSource bad = {DK_SYM_CANDIDATES, two, "name", NULL, NULL, NULL};
    CHECK(dk_symbols_load(NULL, &bad, 1, BASE, &err) == NULL);
    dk_tempdir_cleanup(dir);
}

/* An image with .text (at 0x401000: mov eax, [word], relocated) and .data (0x402000, 0x300 bytes), its symbols given
 * as tsv rows. */
static DkImage *reloc_image(u32 word, const char *tsv_rows) {
    char *root = dk_mkdtemp(dk_arena(), "dk_reloc_test_", "", NULL);
    const char *r = fwd_path(root);
    FakePe pe;
    fake_pe_init(&pe, BASE);
    u8 text[0x20];
    memset(text, 0xCC, sizeof text);
    text[0] = 0xA1;
    put32le(text + 1, word);
    u32 text_rva = fake_pe_section(&pe, ".text", 0x60000020u, text, sizeof text);
    u8 data[0x300];
    memset(data, 0, sizeof data);
    fake_pe_section(&pe, ".data", 0xC0000040u, data, sizeof data);
    fake_pe_reloc(&pe, text_rva + 1);
    DK_ASSERT(fake_pe_write(&pe, join2(r, "t.dll")));
    write_in(r, "t.tsv", dk_sprintf(dk_arena(), "name\tva\tsize\n%s", tsv_rows));
    write_in(r, "config/ctools.json",
             dk_sprintf(dk_arena(),
                        "{\"schema\": \"decompkit-project/1\",\n"
                        " \"targets\": {\"t\": {\"image\": \"${root}/t.dll\",\n"
                        "   \"symbols\": [{\"kind\": \"tsv\", \"path\": \"${root}/t.tsv\"}]}},\n%s",
                        COMMON_CONFIG_TAIL));
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), r, NULL, &err);
    DK_ASSERT(p != NULL);
    DkImage *im = dk_target_image(p, 0, &err);
    DK_ASSERT(im != NULL);
    return im;
}

static const DkReloc *first_reloc(DkImage *im) {
    size_t n = 0;
    const DkReloc *r = dk_image_relocs(im, 0x401000, 5, &n);
    DK_ASSERT(n == 1);
    return r;
}

DK_TEST(reloc_names_the_nearest_unsized_symbol_below) {
    /* _g_obj at 0x402100 has no size: 0x402104 is "_g_obj + 4" */
    DkImage *im = reloc_image(0x402104, "_g_obj\t0x402100\t\n_g_next\t0x402200\t\n");
    const DkReloc *r = first_reloc(im);
    REQUIRE_PTR(r->symbol);
    CHECK_CZ(r->symbol, "_g_obj");
    CHECK_EQ_U64(r->addend, 4);
}

DK_TEST(reloc_stays_unnamed_far_past_an_unsized_symbol) {
    /* 0x402204 lies 0x204 bytes past _g_obj: beyond the reach given to an unsized symbol */
    DkImage *im = reloc_image(0x402204, "_g_obj\t0x402000\t\n");
    const DkReloc *r = first_reloc(im);
    CHECK(r->symbol == NULL);
    CHECK_EQ_U64((u32)r->addend, 0x402204);
}

DK_TEST_MAIN("project_symbols")
