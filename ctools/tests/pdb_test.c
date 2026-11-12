// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* pdb.h: a synthetic PDB 7.00 (synth_pdb.h) is written to a temporary file and read back: the container, the DBI
 * (modules, section contributions, section headers), the publics, each module's compile record, environment block,
 * procedures and C13 lines, and the TPI (a struct, a pointer, a procedure, an enum). Malformed files throw. */
#include "dk/dk.h"
#include "dk/test.h"
#include "pdb.h"
#include "fixtures/synth_pdb.h"

#include <stdio.h>
#include <windows.h>

static void temp_path(char *out, size_t cap, const char *tag) {
    char dir[MAX_PATH];
    GetTempPathA(sizeof dir, dir);
    snprintf(out, cap, "%sdk_pdb_test_%lu_%s.pdb", dir, GetCurrentProcessId(), tag);
}

static void write_file(const char *path, const void *p, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(p, 1, n, f);
    fclose(f);
}

/* One LF_MEMBER (attribute, type, offset, name) of a field list, padded to 4. */
static void member(SynthBuf *b, u32 type, u32 off, const char *name) {
    sb_u16(b, 0x150D);
    sb_u16(b, 3);
    sb_u32(b, type);
    sb_u16(b, off);
    sb_cstr(b, name);
    size_t pad = (4 - b->data.n % 4) % 4;
    for (size_t i = pad; i > 0; i--) sb_u8(b, 0xF0u + (u32)i);
}

enum { TI_FIELDS = 0x1000, TI_POINT, TI_PTR, TI_ARGS, TI_PROC, TI_ENUMFL, TI_ENUM, TI_COUNT };

static void build_types(SynthBuf *tpi) {
    SynthBuf recs = {{0}}, body = {{0}};
    /* 0x1000: the field list of struct Point { int x; float y; } */
    member(&body, 0x74, 0, "x");
    member(&body, 0x40, 4, "y");
    sb_record(&recs, 0x1203, &body);
    body.data.n = 0;
    /* 0x1001: struct Point, 2 members, size 8 */
    sb_u16(&body, 2);
    sb_u16(&body, 0);
    sb_u32(&body, TI_FIELDS);
    sb_u32(&body, 0);
    sb_u32(&body, 0);
    sb_u16(&body, 8);
    sb_cstr(&body, "Point");
    sb_pad4(&body);
    sb_record(&recs, 0x1505, &body);
    body.data.n = 0;
    /* 0x1002: Point* (32-bit pointer) */
    sb_u32(&body, TI_POINT);
    sb_u32(&body, 0x0A);
    sb_record(&recs, 0x1002, &body);
    body.data.n = 0;
    /* 0x1003: argument list (Point*, int) */
    sb_u32(&body, 2);
    sb_u32(&body, TI_PTR);
    sb_u32(&body, 0x74);
    sb_record(&recs, 0x1201, &body);
    body.data.n = 0;
    /* 0x1004: int __cdecl (Point*, int) */
    sb_u32(&body, 0x74);
    sb_u8(&body, 0);
    sb_u8(&body, 0);
    sb_u16(&body, 2);
    sb_u32(&body, TI_ARGS);
    sb_record(&recs, 0x1008, &body);
    body.data.n = 0;
    /* 0x1005: enumerators ONE = 1, TWO = 2 */
    for (u32 i = 1; i <= 2; i++) {
        sb_u16(&body, 0x1502);
        sb_u16(&body, 3);
        sb_u16(&body, i);
        sb_cstr(&body, i == 1 ? "ONE" : "TWO");
        size_t pad = (4 - body.data.n % 4) % 4;
        for (size_t k = pad; k > 0; k--) sb_u8(&body, 0xF0u + (u32)k);
    }
    sb_record(&recs, 0x1203, &body);
    body.data.n = 0;
    /* 0x1006: enum Mode : unsigned int */
    sb_u16(&body, 2);
    sb_u16(&body, 0);
    sb_u32(&body, 0x75);
    sb_u32(&body, TI_ENUMFL);
    sb_cstr(&body, "Mode");
    sb_pad4(&body);
    sb_record(&recs, 0x1507, &body);
    synth_tpi(tpi, &recs, TI_COUNT - TI_FIELDS);
    dk_vec_free(&body.data);
    dk_vec_free(&recs.data);
}

static const char *const SRC_NAME = "src\\a.c";

/* The whole file: info, TPI, DBI (two modules, two contributions, two sections), publics, /names and two module
 * streams. */
static void build_pdb(SynthBuf *file, bool nil_tpi) {
    SynthPdb p = {0};
    p.count = 9;
    synth_info(&p.stream[1], "/names", 6);
    build_types(&p.stream[2]);

    SynthBuf recs = {{0}};
    synth_public(&recs, "?Foo@@YAHXZ", 1, 0x10, 2);
    synth_public(&recs, "_table", 2, 0x40, 0);
    synth_public(&recs, "?Bar@@YAXXZ", 1, 0x110, 2);
    sb_bytes(&p.stream[4], recs.data.v, recs.data.n);

    u32 rva[2] = {0x1000, 0x3000};
    synth_sections(&p.stream[5], rva, 2);

    const char *names[1] = {SRC_NAME};
    u32 offsets[1];
    synth_names(&p.stream[6], names, 1, offsets);

    /* module 0: a compile record, an environment block, a global procedure and two lines */
    SynthBuf syms0 = {{0}};
    const u32 fe[4] = {14, 0, 50727, 762}, be[4] = {14, 0, 50727, 762};
    synth_compile3(&syms0, 3, fe, be, "Synthetic Compiler 14.0");
    const char *kv[] = {"cwd", "C:\\work", "cl", "cl.exe"};
    synth_envblock(&syms0, kv, 4);
    synth_proc(&syms0, 0x1110, "Foo", 1, 0x10, 0x20, TI_PROC);
    const u32 lines[2][2] = {{0, 5}, {8, 6}}; /* relative to the block base 0x10 */
    u32 sym0, c13_0;
    synth_module_stream(&p.stream[7], &syms0, 1, 0x10, offsets[0], lines, 2, &sym0, &c13_0);

    /* module 1: from an archive, a local procedure and no lines */
    SynthBuf syms1 = {{0}};
    synth_proc(&syms1, 0x110F, "bar", 1, 0x110, 0x10, TI_PROC);
    u32 sym1, c13_1;
    synth_module_stream(&p.stream[8], &syms1, 1, 0, 0, NULL, 0, &sym1, &c13_1);

    SynthBuf mods = {{0}}, contribs = {{0}};
    synth_modinfo(&mods, 1, 0, 0x100, 7, sym0, c13_0, "C:\\build\\a.obj", "C:\\build\\a.obj");
    synth_modinfo(&mods, 1, 0x100, 0x80, 8, sym1, c13_1, "C:\\build\\b.obj", "D:\\lib\\synth.lib");
    sb_u32(&contribs, 0xF12EBA2Du);
    synth_contrib(&contribs, 1, 0, 0x100, 0x60000020u, 0);
    synth_contrib(&contribs, 1, 0x100, 0x80, 0x60000020u, 1);
    synth_dbi(&p.stream[3], 4, 5, &mods, &contribs);

    bool nil[SYNTH_MAX_STREAMS] = {0};
    nil[2] = nil_tpi;
    synth_msf_write(&p, nil, file);

    dk_vec_free(&recs.data);
    dk_vec_free(&syms0.data);
    dk_vec_free(&syms1.data);
    dk_vec_free(&mods.data);
    dk_vec_free(&contribs.data);
    synth_pdb_free(&p);
}

static DkPdb read_synth(const char *tag, bool nil_tpi) {
    SynthBuf file = {{0}};
    build_pdb(&file, nil_tpi);
    char path[MAX_PATH];
    temp_path(path, sizeof path, tag);
    write_file(path, file.data.v, file.data.n);
    dk_vec_free(&file.data);
    DkPdb p = dk_pdb_read(path, false);
    DeleteFileA(path);
    return p;
}

DK_TEST(msf_streams) {
    SynthBuf file = {{0}};
    build_pdb(&file, false);
    char path[MAX_PATH];
    temp_path(path, sizeof path, "msf");
    write_file(path, file.data.v, file.data.n);
    DkMsf *m = dk_msf_open(path);
    CHECK_EQ_U64(dk_msf_stream_count(m), 9);
    CHECK_EQ_U64(dk_msf_stream(m, 0).n, 0);
    CHECK(dk_msf_stream(m, 3).n > 64);
    CHECK_EQ_U64(dk_msf_stream(m, 99).n, 0); /* out of range is empty */
    DeleteFileA(path);
    dk_vec_free(&file.data);
}

DK_TEST(read_back) {
    DkPdb p = read_synth("full", false);

    /* publics and their lookup by (segment, offset) */
    REQUIRE(p.pubs.n == 3);
    CHECK_CZ(p.pubs.v[0].name, "?Foo@@YAHXZ");
    CHECK_EQ_U64(p.pubs.v[1].seg, 2);
    CHECK_EQ_U64(p.pubs.v[1].off, 0x40);
    const DkCzVec *at = dk_pdb_publics_at(&p, 1, 0x10);
    REQUIRE(at != NULL && at->n == 1);
    CHECK_CZ(at->v[0], "?Foo@@YAHXZ");
    CHECK(dk_pdb_publics_at(&p, 2, 0x40) == NULL); /* data, not code */
    CHECK(dk_pdb_publics_at(&p, 1, 0x11) == NULL);

    /* sections and RVAs */
    REQUIRE(p.sections.n == 2);
    i64 rva = 0;
    CHECK(dk_pdb_rva(&p, 1, 0x10, &rva));
    CHECK_EQ_I64(rva, 0x1010);
    CHECK(dk_pdb_rva(&p, 2, 0x20, &rva));
    CHECK_EQ_I64(rva, 0x3020);
    CHECK(!dk_pdb_rva(&p, 3, 0, &rva));

    /* section contributions */
    REQUIRE(p.contribs.n == 2);
    CHECK_EQ_U64(p.contribs.v[1].off, 0x100);
    CHECK_EQ_U64(p.contribs.v[1].size, 0x80);
    CHECK_EQ_U64(p.contribs.v[1].mod, 1);

    /* modules */
    REQUIRE(p.mods.n == 2);
    const DkPdbModule *m0 = &p.mods.v[0], *m1 = &p.mods.v[1];
    CHECK_CZ(m0->name, "C:\\build\\a.obj");
    CHECK_CZ(m0->object, "a.obj");
    CHECK_CZ(m0->library, "");
    CHECK_CZ(m1->object, "b.obj");
    CHECK_CZ(m1->library, "synth.lib");
    CHECK_EQ_U64(m1->sec_off, 0x100);
    CHECK(m0->compile.present);
    CHECK_CZ(m0->compile.compiler, "Synthetic Compiler 14.0");
    CHECK_CZ(m0->compile.frontend_ver, "14.0.50727.762");
    CHECK(!m1->compile.present);
    DkVal *cwd = dk_map_get(m0->env, DK_S("cwd"));
    REQUIRE(cwd != NULL);
    CHECK_CZ((const char *)cwd->p, "C:\\work");
    DkVal *cl = dk_map_get(m0->env, DK_S("cl"));
    REQUIRE(cl != NULL);
    CHECK_CZ((const char *)cl->p, "cl.exe");

    /* procedures: kind, type and the source file of the line table that covers them */
    REQUIRE(p.procs.n == 2);
    CHECK_CZ(p.procs.v[0].kind, "gproc");
    CHECK_CZ(p.procs.v[0].name, "Foo");
    CHECK_EQ_U64(p.procs.v[0].length, 0x20);
    CHECK_EQ_U64(p.procs.v[0].typind, TI_PROC);
    CHECK_CZ(p.procs.v[0].source, "src\\a.c");
    CHECK_CZ(p.procs.v[1].kind, "lproc");
    CHECK_EQ_U64(p.procs.v[1].mod, 1);
    CHECK_CZ(p.procs.v[1].source, "");

    /* lines */
    REQUIRE(p.lines.n == 2);
    CHECK_EQ_U64(p.lines.v[0].off, 0x10);
    CHECK_EQ_U64(p.lines.v[0].line, 5);
    CHECK_EQ_U64(p.lines.v[1].off, 0x18);
    CHECK_EQ_U64(p.lines.v[1].line, 6);
    CHECK_CZ(p.lines.v[1].file, "src\\a.c");
}

DK_TEST(types) {
    DkPdb p = read_synth("types", false);
    DkPdbTypes *t = p.types;

    CHECK_EQ_U64(dk_pdb_types_first(t), 0x1000);
    CHECK_EQ_U64(dk_pdb_types_end(t), TI_COUNT);
    CHECK_EQ_U64(dk_pdb_types_leaf(t, TI_POINT), 0x1505);
    CHECK_EQ_U64(dk_pdb_types_leaf(t, 0x74), 0);
    CHECK_CZ(dk_pdb_types_name(t, 0x74), "int");
    CHECK_CZ(dk_pdb_types_name(t, 0x75), "unsigned int");
    CHECK_CZ(dk_pdb_types_name(t, TI_POINT), "Point");
    CHECK_CZ(dk_pdb_types_name(t, TI_PTR), "Point*");
    CHECK_CZ(dk_pdb_types_name(t, TI_PROC), "int (__cdecl)(Point*, int)");
    CHECK_CZ(dk_pdb_types_name(t, 0x7000), "<missing 0x7000>");
    CHECK_EQ_I64(dk_pdb_types_size(t, TI_POINT), 8);
    CHECK_EQ_I64(dk_pdb_types_size(t, TI_PTR), 4);
    CHECK_EQ_I64(dk_pdb_types_size(t, TI_ENUM), 4);
    CHECK_CZ(dk_pdb_types_method_class(t, TI_PROC), "");

    DkPdbTypeInfo ti;
    REQUIRE(dk_pdb_types_info(t, TI_POINT, &ti));
    CHECK_CZ(ti.kind, "struct");
    CHECK_CZ(ti.name, "Point");
    CHECK_EQ_I64(ti.size, 8);
    CHECK(!ti.forward);
    REQUIRE(ti.fields.n == 2);
    CHECK_CZ(ti.fields.v[0].name, "x");
    CHECK_CZ(ti.fields.v[0].type, "int");
    CHECK_EQ_I64(ti.fields.v[0].offset, 0);
    CHECK_EQ_I64(ti.fields.v[0].size, 4);
    CHECK_CZ(ti.fields.v[1].name, "y");
    CHECK_CZ(ti.fields.v[1].type, "float");
    CHECK_EQ_I64(ti.fields.v[1].offset, 4);

    REQUIRE(dk_pdb_types_info(t, TI_ENUM, &ti));
    CHECK_CZ(ti.kind, "enum");
    CHECK_CZ(ti.name, "Mode");
    CHECK_CZ(ti.underlying, "unsigned int");
    REQUIRE(ti.enumerators.n == 2);
    CHECK_CZ(ti.enumerators.v[1].name, "TWO");
    CHECK_EQ_I64(ti.enumerators.v[1].value, 2);

    CHECK(!dk_pdb_types_info(t, TI_PTR, &ti)); /* a pointer is not a class */
}

DK_TEST(nil_type_stream) {
    DkPdb p = read_synth("nil", true);
    CHECK_EQ_U64(dk_pdb_types_end(p.types), 0x1000);
    CHECK_EQ_U64(p.mods.n, 2);
}

DK_TEST(rejects_malformed) {
    char path[MAX_PATH];
    temp_path(path, sizeof path, "bad");
    DkTry t;
    static const char junk[] = "this is not a program database";
    write_file(path, junk, sizeof junk);
    if (DK_TRY(&t)) {
        dk_msf_open(path);
        dk_try_end(&t);
        CHECK_MSG(false, "junk opened");
    } else {
        CHECK_EQ_I64(t.code, DK_ERR_FORMAT);
    }
    /* a valid prefix with the rest cut off */
    SynthBuf file = {{0}};
    build_pdb(&file, false);
    write_file(path, file.data.v, 1024);
    if (DK_TRY(&t)) {
        dk_pdb_read(path, false);
        dk_try_end(&t);
        CHECK_MSG(false, "truncated file read");
    } else {
        CHECK(t.code == DK_ERR_FORMAT || t.code == DK_ERR_IO);
    }
    DeleteFileA(path);
    if (DK_TRY(&t)) {
        dk_msf_open(path); /* gone */
        dk_try_end(&t);
        CHECK_MSG(false, "missing file opened");
    } else {
        CHECK(t.code == DK_ERR_IO);
    }
    dk_vec_free(&file.data);
}

DK_TEST(undecorate) {
    CHECK_CZ(dk_pdb_undecorate("plain_name", 0x1000), "plain_name");
    CHECK_CZ(dk_pdb_undecorate("?Foo@@YAHXZ", 0x1000), "Foo");
}

DK_TEST_MAIN("pdb")
