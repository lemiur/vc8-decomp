// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The project adapter end to end: load a fixture tree (copied to a temporary folder), parse the annotations of every
 * unit, look them up, bind them to the names of the target's symbol sources and open the object cache of a target.
 * Two fixtures, one per grammar: project_vc8 (marker lines "// FUNCTION: <target> 0x<addr>" with a "// SYMBOL:" line,
 * the name read from the declaration) and project_pertarget (one marker line "// match: <alpha> <beta>" naming both
 * targets' addresses, the name read from the next line, stop and pending lines, a flags line). The symbol files
 * (a TSV in the usual function listing layout, a TSV with other column names, a synthetic PDB and an MSVC linker
 * map) are written at test time with made-up names and addresses; the compiler's identity files are synthetic
 * bytes. */
#include "dk/dk.h"
#include "dk/test.h"
#include "objcache.h"
#include "project.h"
#include "fixtures/synth_pdb.h"

#include <string.h>

static const char *J(const char *a, const char *b) { return dk_join(dk_arena(), a, b); }

static void write_text(const char *path, const char *text) {
    DkStr dir = dk_path_dirname(path);
    dk_makedirs(dk_cz(dk_arena(), dir), true);
    DK_ASSERT(dk_write_file(path, text, strlen(text)));
}

/* A temporary copy of ctools/tests/fixtures/<name> (the tests run from the parent of ctools/). */
static const char *fixture_copy(const char *name) {
    char *dir = dk_mkdtemp(dk_arena(), "project_load-", "", NULL);
    DK_ASSERT(dir != NULL);
    DkCopytreeOpts o = {0};
    o.dirs_exist_ok = true;
    DK_ASSERT(dk_copytree(dk_sprintf(dk_arena(), "ctools/tests/fixtures/%s", name), dir, &o));
    return dir;
}

static DkProject *load(const char *dir) {
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), dir, NULL, &err);
    CHECK_MSG(p != NULL, "%s", err.msg);
    return p;
}

static const DkUnit *unit_named(DkProject *p, const char *path) {
    const DkUnit *u = dk_project_unit(p, path);
    CHECK_MSG(u != NULL, "no unit %s", path);
    return u;
}

static DkAnnot *annots_of(DkProject *p, const char *path, size_t *n) {
    const DkUnit *u = unit_named(p, path);
    if (!u) return NULL;
    DkErr err = {0};
    DkAnnot *v = dk_annotations(p, u, n, &err);
    CHECK_MSG(v != NULL, "%s: %s", path, err.msg);
    return v;
}

static bool msg_has(const DkErr *err, const char *text) { return strstr(err->msg, text) != NULL; }

/* ---- project_vc8: target+addr grammar, groups binary and va --------------------------------------------------------- */

static void vc8_symbols_file(const char *dir) {
    write_text(J(dir, "symbols/cl.functions.tsv"),
               "name\trva\tva\tsection\tsection_index\tsection_offset\tsize\tboundary_status\n"
               "?util_leaf@@YAHXZ\t4096\t4198400\t.text\t1\t0\t6\tok\n"
               "?util_twice@@YAHH@Z\t4160\t4198464\t.text\t1\t64\t0x10\tok\n"
               "?util_sum@@YAHPBHH@Z\t4224\t4198528\t.text\t1\t128\t32\tok\n"
               "_merr_zero\t4288\t4198592\t.text\t1\t192\t3\tok\n"
               "?util_table@@3PAHA\t\t4390928\t.data\t2\t16\t16\tok\n"
               "\t4400\t4198700\t.text\t1\t300\t8\tok\n");
}

DK_TEST(vc8_annotations) {
    const char *dir = fixture_copy("project_vc8");
    DkProject *p = load(dir);
    REQUIRE(p);
    CHECK_EQ_U64(dk_project_ntargets(p), 5);

    size_t n = 0;
    DkAnnot *v = annots_of(p, "matching/cl/util.cpp", &n);
    REQUIRE(v && n == 4);
    for (size_t i = 0; i < n; i++) {
        CHECK(v[i].unit == dk_project_unit(p, "matching/cl/util.cpp"));
        CHECK(v[i].flags == NULL && v[i].pending == NULL && v[i].pending_mask == 0);
        CHECK_EQ_U64(v[i].target_mask, 1);
        CHECK(v[i].body_start >= v[i].line + 1 && v[i].body_end >= v[i].body_start);
        for (int t = 1; t < DK_MAX_TARGETS; t++) CHECK_EQ_U64(v[i].addr[t], DK_NO_ADDR);
    }
    CHECK_EQ_I64(v[0].kind, DK_ANN_FUNCTION);
    CHECK_CZ(v[0].name, "util_leaf");
    CHECK_EQ_U64(v[0].addr[0], 0x401000);
    CHECK_EQ_I64(v[0].line, 4);
    CHECK_EQ_I64(v[0].body_start, 5);
    CHECK_EQ_I64(v[0].body_end, 5);
    CHECK_CZ(v[0].decl, "int util_leaf(void)");
    CHECK(v[0].symbol == NULL && v[0].stop_mask == 0 && v[0].stop_reason == NULL);

    CHECK_CZ(v[1].name, "util_twice");
    CHECK_EQ_U64(v[1].addr[0], 0x401040);
    CHECK_CZ(v[1].symbol, "?util_twice@@YAHH@Z");
    CHECK_EQ_U64(v[1].stop_mask, 1);
    CHECK_CZ(v[1].stop_reason, "synthetic register residue");
    CHECK(dk_stopped(&v[1], 0));
    CHECK(!dk_stopped(&v[1], 3));
    CHECK_EQ_I64(v[1].line, 7);
    CHECK_EQ_I64(v[1].body_start, 10);
    CHECK_EQ_I64(v[1].body_end, 13);
    CHECK_CZ(v[1].decl, "int util_twice(int x)");

    CHECK_CZ(v[2].name, "util_sum");
    CHECK_EQ_U64(v[2].addr[0], 0x401080);
    CHECK_EQ_U64(v[2].stop_mask, 0);
    CHECK(!dk_stopped(&v[2], 0));
    CHECK_EQ_I64(v[2].body_end - v[2].body_start, 6);

    CHECK_EQ_I64(v[3].kind, DK_ANN_DATA);
    CHECK_CZ(v[3].name, "util_table");
    CHECK_EQ_U64(v[3].addr[0], 0x430010);

    /* lookups: by plain name, with and without the address; a wrong address or name finds nothing */
    const DkUnit *u = dk_project_unit(p, "util.cpp");
    REQUIRE(u);
    const DkAnnot *f = dk_find_annotation(p, u, "util_twice", DK_NO_ADDR);
    REQUIRE(f);
    CHECK_EQ_I64(f->line, 7);
    CHECK(dk_find_annotation(p, u, "util_twice", 0x401040) != NULL && dk_find_annotation(p, u, "util_twice", 0x401040)->line == f->line);
    CHECK(dk_find_annotation(p, u, "util_twice", 0x401041) == NULL);
    CHECK(dk_find_annotation(p, u, "util_sum", 0x401040) == NULL);
    CHECK(dk_find_annotation(p, u, "no_such_function", DK_NO_ADDR) == NULL);
    CHECK_EQ_U64(dk_find_annotation(p, u, "util_table", 0x430010)->kind, DK_ANN_DATA);

    /* merr.c: a C unit with remove_compile_flags */
    v = annots_of(p, "matching/cl/merr.c", &n);
    REQUIRE(v && n == 1);
    CHECK_CZ(v[0].name, "merr_zero");
    CHECK_EQ_U64(v[0].addr[0], 0x4010C0);

    /* opt.c: not in any unit map, so any target may name it; targets c2 and c1 (indexes 3 and 1) */
    v = annots_of(p, "matching/c2/opt.c", &n);
    REQUIRE(v && n == 3);
    CHECK_CZ(v[0].name, "opt_pass");
    CHECK_EQ_U64(v[0].target_mask, 1u << 3);
    CHECK_EQ_U64(v[0].addr[3], 0x10001000);
    CHECK_EQ_U64(v[0].addr[0], DK_NO_ADDR);
    CHECK_CZ(v[1].name, "opt_fold");
    CHECK_EQ_U64(v[1].target_mask, 1u << 1);
    CHECK_EQ_U64(v[1].addr[1], 0x10002000);
    CHECK_EQ_I64(v[2].kind, DK_ANN_DATA);
    CHECK_CZ(v[2].name, "opt_level");
    CHECK_EQ_U64(v[2].addr[3], 0x10030000);

    /* a unit that is only listed in a map, not on disk, has no text to parse */
    const DkUnit *listed = dk_project_unit(p, "matching/cl/listed_only.cpp");
    if (listed) {
        DkErr err = {0};
        CHECK(dk_annotations(p, listed, &n, &err) == NULL);
        CHECK(err.code != 0);
    }
}

DK_TEST(vc8_symbols) {
    const char *dir = fixture_copy("project_vc8");
    vc8_symbols_file(dir);
    DkProject *p = load(dir);
    REQUIRE(p);
    DkErr err = {0};
    DkSymbols *s = dk_project_symbols(p, 0, &err);
    CHECK_MSG(s != NULL, "%s", err.msg);
    REQUIRE(s);
    CHECK(dk_project_symbols(p, 0, &err) == s); /* loaded once, then cached */
    CHECK(dk_project_target(p, 0)->syms == s);

    size_t n = 0;
    const DkSymbol *all = dk_symbols_all(s, &n);
    REQUIRE(n == 5); /* the row without a name is skipped; the data row has a VA but no RVA */
    for (size_t i = 1; i < n; i++) CHECK(all[i - 1].va < all[i].va);
    CHECK_CZ(all[0].name, "?util_leaf@@YAHXZ");
    CHECK_EQ_U64(all[0].va, 0x401000);
    CHECK_EQ_U64(all[0].size, 6);
    CHECK_EQ_U64(dk_symbols_at(s, 0x401040)->size, 0x10); /* a hex size */
    CHECK_CZ(dk_symbols_at(s, 0x430010)->name, "?util_table@@3PAHA");
    CHECK_CZ(dk_symbols_containing(s, 0x401085, NULL)->name, "?util_sum@@YAHPBHH@Z");
    CHECK_EQ_U64(dk_symbols_next(s, 0x401000), 0x401040);
    CHECK_EQ_U64(dk_symbols_next(s, 0x430010), 0);
    CHECK(dk_symbols_find(s, "_merr_zero") != NULL);
    CHECK(dk_symbols_find(s, "util_leaf") == NULL);
    CHECK(dk_symbols_at(s, 0x4010E0) == NULL);

    /* every annotation of the cl target is named by the source at its address, and binds to it */
    const char *names[8];
    size_t nn = 0;
    for (size_t i = 0; i < n; i++)
        if (all[i].va < 0x500000) names[nn++] = all[i].name;
    static const char *const units[] = {"matching/cl/util.cpp", "matching/cl/merr.c"};
    size_t checked = 0;
    for (int k = 0; k < 2; k++) {
        size_t na = 0;
        DkAnnot *v = annots_of(p, units[k], &na);
        REQUIRE(v);
        for (size_t i = 0; i < na; i++) {
            const DkSymbol *sym = dk_symbols_at(s, v[i].addr[0]);
            CHECK_MSG(sym != NULL, "%s: no symbol at its address", v[i].name);
            if (!sym) continue;
            if (v[i].kind == DK_ANN_FUNCTION) CHECK_MSG(dk_symbol_matches(&v[i], sym->name), "%s vs %s", v[i].name, sym->name);
            DkErr berr = {0};
            const char *bound = dk_annot_bind(&v[i], DK_NAME_DECLARATION, names, nn, &berr);
            CHECK_MSG(bound != NULL, "%s: %s", v[i].name, berr.msg);
            if (bound) CHECK_CZ(bound, sym->name);
            checked++;
        }
    }
    CHECK_EQ_U64(checked, 5);

    /* a target whose symbol file is absent reports it, with a message naming the file */
    err.code = 0;
    CHECK(dk_project_symbols(p, 3, &err) == NULL);
    CHECK(err.code != 0 && msg_has(&err, "c2.functions.tsv"));
}

DK_TEST(vc8_annotation_errors) {
    const char *dir = fixture_copy("project_vc8");
    write_text(J(dir, "matching/cl/bad_target.cpp"), "// FUNCTION: nosuch 0x00401000\nint f(void) { return 0; }\n");
    write_text(J(dir, "matching/cl/bad_dup.cpp"),
               "// FUNCTION: cl 0x00402000\nint g(void) { return 0; }\n"
               "// FUNCTION: cl 0x00402000\nint h(void) { return 1; }\n");
    write_text(J(dir, "matching/cl/bad_body.cpp"), "// FUNCTION: cl 0x00403000\n");
    DkProject *p = load(dir);
    REQUIRE(p);
    static const char *const bad[] = {"matching/cl/bad_target.cpp", "matching/cl/bad_dup.cpp", "matching/cl/bad_body.cpp"};
    for (int i = 0; i < 3; i++) {
        const DkUnit *u = dk_project_unit(p, bad[i]);
        REQUIRE(u);
        size_t n = 0;
        DkErr err = {0};
        CHECK_MSG(dk_annotations(p, u, &n, &err) == NULL, "%s parsed", bad[i]);
        CHECK_MSG(err.code != 0 && err.msg[0], "%s: no error", bad[i]);
    }
    DkErr err = {0};
    size_t n = 0;
    dk_annotations(p, dk_project_unit(p, bad[0]), &n, &err);
    CHECK(msg_has(&err, "nosuch"));
}

/* ---- project_pertarget: per-target grammar, next_line rule --------------------------------------------------------- */

#define PT_BASE 0x400000u

/* A synthetic PDB 7.00 for target alpha: publics ?both_pdb@@YAHXZ at 1:0 (the TSV also names that address: it wins)
 * and _extra_only at 1:0x2000, a module procedure extra_proc at 1:0x2100 (length 0x20); sections at RVA 0x1000. */
static void pt_pdb(SynthBuf *file) {
    SynthPdb p = {0};
    p.count = 8;
    synth_info(&p.stream[1], "/names", 6);

    SynthBuf recs = {{0}};
    synth_public(&recs, "?both_pdb@@YAHXZ", 1, 0, 2);
    synth_public(&recs, "_extra_only", 1, 0x2000, 2);
    sb_bytes(&p.stream[4], recs.data.v, recs.data.n);

    u32 rva[1] = {0x1000};
    synth_sections(&p.stream[5], rva, 1);

    const char *names[1] = {"src\\extra.c"};
    u32 offsets[1];
    synth_names(&p.stream[6], names, 1, offsets);

    SynthBuf syms0 = {{0}};
    synth_proc(&syms0, 0x1110, "extra_proc", 1, 0x2100, 0x20, 0x1000);
    u32 sym0, c13_0;
    synth_module_stream(&p.stream[7], &syms0, 1, 0, 0, NULL, 0, &sym0, &c13_0);

    SynthBuf mods = {{0}}, contribs = {{0}};
    synth_modinfo(&mods, 1, 0x2000, 0x200, 7, sym0, c13_0, "C:\\build\\extra.obj", "C:\\build\\extra.obj");
    sb_u32(&contribs, 0xF12EBA2Du);
    synth_contrib(&contribs, 1, 0x2000, 0x200, 0x60000020u, 0);
    synth_dbi(&p.stream[3], 4, 5, &mods, &contribs);

    bool nil[SYNTH_MAX_STREAMS] = {0};
    nil[2] = true; /* no type stream */
    synth_msf_write(&p, nil, file);

    dk_vec_free(&recs.data);
    dk_vec_free(&syms0.data);
    dk_vec_free(&mods.data);
    dk_vec_free(&contribs.data);
    synth_pdb_free(&p);
}

static void pt_symbol_files(const char *dir) {
    /* alpha: a TSV with its own column names (Name, Address, size), then the PDB */
    write_text(J(dir, "syms/alpha.tsv"),
               "Name\tAddress\tsize\n"
               "_both_value\t0x401000\t6\n"
               "_plain_value\t0x401100\t10\n"
               "_plain_twice\t0x401120\t8\n"
               "?Sides@Shape@@QBEHXZ\t0x401200\t6\n"
               "_ALPHABET_SIZE\t0x430000\t4\n");
    SynthBuf pdb = {{0}};
    pt_pdb(&pdb);
    DK_ASSERT(dk_write_file(J(dir, "syms/alpha.pdb"), pdb.data.v, pdb.data.n));
    dk_vec_free(&pdb.data);
    /* beta: an MSVC linker map */
    write_text(J(dir, "syms/beta.map"),
               " synthetic\r\n"
               "\r\n"
               " Timestamp is 4b8c0d3a (Fri Feb 26 12:00:00 2010)\r\n"
               "\r\n"
               " Preferred load address is 00400000\r\n"
               "\r\n"
               " Start         Length     Name                   Class\r\n"
               " 0001:00000000 00200000H .text                   CODE\r\n"
               " 0002:00000000 00040000H .data                   DATA\r\n"
               "\r\n"
               "  Address         Publics by Value              Rva+Base       Lib:Object\r\n"
               "\r\n"
               " 0001:00101000       _both_value                00501000 f   both.obj\r\n"
               " 0001:00101100       _plain_value               00501100 f   plain.obj\r\n"
               " 0001:00101130       _plain_twice               00501130 f   plain.obj\r\n"
               " 0002:00130000       _ALPHABET_SIZE             00530000     plain.obj\r\n"
               "\r\n"
               " entry point at        0001:00101000\r\n");
}

DK_TEST(pertarget_annotations) {
    const char *dir = fixture_copy("project_pertarget");
    DkProject *p = load(dir);
    REQUIRE(p);
    CHECK_EQ_U64(dk_project_ntargets(p), 2);
    size_t nu = 0;
    const DkUnit *units = dk_project_units(p, &nu);
    REQUIRE(nu == 3);

    size_t n = 0;
    DkAnnot *v = annots_of(p, "src/Shape.CPP", &n);
    REQUIRE(v && n == 1);
    CHECK_EQ_I64(v[0].kind, DK_ANN_FUNCTION);
    CHECK_CZ(v[0].name, "Shape::Sides");
    CHECK_CZ(v[0].decl, "int Shape::Sides() const");
    CHECK_EQ_U64(v[0].addr[0], 0x401200);
    CHECK_EQ_U64(v[0].addr[1], DK_NO_ADDR);
    CHECK_EQ_U64(v[0].target_mask, 1);
    CHECK(v[0].flags == NULL);

    /* both.c names target alpha's define: compiled once per target, one copy of the function in each */
    const DkUnit *both = unit_named(p, "src/both.c");
    REQUIRE(both);
    CHECK(both->per_target && !both->flags_line);
    v = annots_of(p, "src/both.c", &n);
    REQUIRE(v && n == 2);
    CHECK_CZ(v[0].name, "both_value");
    CHECK_CZ(v[1].name, "both_value");
    CHECK_EQ_U64(v[0].addr[0], 0x401000);
    CHECK_EQ_U64(v[0].addr[1], DK_NO_ADDR);
    CHECK_EQ_U64(v[0].target_mask, 1);
    CHECK_EQ_U64(v[1].addr[0], DK_NO_ADDR);
    CHECK_EQ_U64(v[1].addr[1], 0x501000);
    CHECK_EQ_U64(v[1].target_mask, 2);
    CHECK(v[0].flags == NULL && v[1].flags == NULL); /* the unit does not apply its flags line */

    const DkUnit *plain = unit_named(p, "src/plain.c");
    REQUIRE(plain);
    CHECK(!plain->per_target && plain->flags_line);
    v = annots_of(p, "src/plain.c", &n);
    REQUIRE(n == 3);
    for (size_t i = 0; i < n; i++) {
        CHECK_CZ(v[i].flags, "/GS- /Oy");
        CHECK_EQ_U64(v[i].target_mask, 3);
        CHECK(v[i].symbol == NULL);
    }
    CHECK_EQ_I64(v[0].kind, DK_ANN_DATA);
    CHECK_CZ(v[0].name, "ALPHABET_SIZE");
    CHECK_EQ_U64(v[0].addr[0], 0x430000);
    CHECK_EQ_U64(v[0].addr[1], 0x530000);
    CHECK_CZ(v[1].name, "plain_value");
    CHECK_EQ_I64(v[1].kind, DK_ANN_FUNCTION);
    CHECK_EQ_U64(v[1].addr[0], 0x401100);
    CHECK_EQ_U64(v[1].addr[1], 0x501100);
    CHECK_EQ_U64(v[1].stop_mask, 3);
    CHECK_CZ(v[1].stop_reason, "synthetic schedule residue");
    CHECK(dk_stopped(&v[1], 0) && dk_stopped(&v[1], 1));
    CHECK(v[1].pending == NULL && v[1].pending_mask == 0);
    CHECK_CZ(v[2].name, "plain_twice");
    CHECK_EQ_U64(v[2].addr[1], 0x501130);
    CHECK_EQ_U64(v[2].pending_mask, 3);
    CHECK_CZ(v[2].pending, "R4 a synthetic fixed-offset access");
    CHECK_EQ_U64(v[2].stop_mask, 0);
    CHECK(!dk_stopped(&v[2], 0));
    CHECK_EQ_I64(v[2].body_end - v[2].body_start, 3);

    /* the totals by kind over the whole project */
    int fn = 0, data = 0;
    size_t total = 0;
    for (size_t k = 0; k < nu; k++) {
        size_t na = 0;
        DkErr err = {0};
        DkAnnot *a = dk_annotations(p, &units[k], &na, &err);
        CHECK_MSG(a != NULL, "%s: %s", units[k].path, err.msg);
        for (size_t i = 0; a && i < na; i++) {
            if (a[i].kind == DK_ANN_FUNCTION) fn++;
            else if (a[i].kind == DK_ANN_DATA) data++;
        }
        total += na;
    }
    CHECK_EQ_I64(fn, 5);
    CHECK_EQ_I64(data, 1);
    CHECK_EQ_U64(total, 6);

    const DkUnit *shape = dk_project_unit(p, "Shape");
    REQUIRE(shape);
    CHECK(dk_find_annotation(p, shape, "Shape::Sides", 0x401200) != NULL);
    CHECK(dk_find_annotation(p, shape, "Sides", DK_NO_ADDR) != NULL); /* the plain method name finds the qualified one */
    CHECK(dk_find_annotation(p, shape, "Shape::Sides", 0x401201) == NULL);
    const DkAnnot *fb = dk_find_annotation(p, both, "both_value", 0x501000);
    CHECK(fb != NULL && fb->addr[1] == 0x501000 && fb->target_mask == 2);
}

DK_TEST(pertarget_symbols) {
    const char *dir = fixture_copy("project_pertarget");
    pt_symbol_files(dir);
    DkProject *p = load(dir);
    REQUIRE(p);
    DkErr err = {0};

    DkSymbols *alpha = dk_project_symbols(p, 0, &err);
    CHECK_MSG(alpha != NULL, "%s", err.msg);
    REQUIRE(alpha);
    size_t n = 0;
    dk_symbols_all(alpha, &n);
    CHECK_EQ_U64(n, 7); /* five TSV rows, the PDB's _extra_only and extra_proc; ?both_pdb@@YAHXZ lost to the TSV */
    CHECK_CZ(dk_symbols_at(alpha, 0x401000)->name, "_both_value");
    CHECK_EQ_U64(dk_symbols_at(alpha, 0x401000)->size, 6);
    CHECK(dk_symbols_find(alpha, "?both_pdb@@YAHXZ") == NULL);
    CHECK_CZ(dk_symbols_at(alpha, PT_BASE + 0x1000 + 0x2000)->name, "_extra_only");
    CHECK(dk_symbols_find(alpha, "extra_proc") != NULL);
    CHECK_EQ_U64(dk_symbols_find(alpha, "extra_proc")->size, 0x20);
    CHECK_EQ_U64(dk_symbols_find(alpha, "extra_proc")->va, PT_BASE + 0x1000 + 0x2100);

    DkSymbols *beta = dk_project_symbols(p, 1, &err);
    CHECK_MSG(beta != NULL, "%s", err.msg);
    REQUIRE(beta);
    dk_symbols_all(beta, &n);
    CHECK_EQ_U64(n, 4);
    CHECK_CZ(dk_symbols_at(beta, 0x501130)->name, "_plain_twice");
    CHECK_EQ_U64(dk_symbols_at(beta, 0x501130)->size, 0); /* a map gives no sizes */
    CHECK(alpha != beta && dk_project_symbols(p, 1, &err) == beta);

    /* each annotation binds, by the next_line rule, to the symbol its target holds at its address */
    static const char *const units[] = {"src/Shape.CPP", "src/both.c", "src/plain.c"};
    size_t bound = 0;
    for (int k = 0; k < 3; k++) {
        size_t na = 0;
        DkAnnot *v = annots_of(p, units[k], &na);
        REQUIRE(v);
        for (size_t i = 0; i < na; i++) {
            for (int t = 0; t < 2; t++) {
                if (v[i].addr[t] == DK_NO_ADDR) continue;
                DkSymbols *s = t == 0 ? alpha : beta;
                const DkSymbol *sym = dk_symbols_at(s, v[i].addr[t]);
                CHECK_MSG(sym != NULL, "%s: no symbol at target %d's address", v[i].name, t);
                if (!sym) continue;
                const char *one[1] = {sym->name};
                DkErr berr = {0};
                const char *b = dk_annot_bind(&v[i], DK_NAME_NEXT_LINE, one, 1, &berr);
                CHECK_MSG(b != NULL, "%s -> %s: %s", v[i].name, sym->name, berr.msg);
                bound++;
            }
        }
    }
    CHECK_EQ_U64(bound, 9); /* Shape 1; both 2; plain 3 x 2 */
}

DK_TEST(pertarget_symbols_missing_file) {
    const char *dir = fixture_copy("project_pertarget");
    write_text(J(dir, "syms/alpha.tsv"), "Name\tAddress\n_both_value\t0x401000\n");
    DkProject *p = load(dir);
    REQUIRE(p);
    DkErr err = {0};
    CHECK(dk_project_symbols(p, 0, &err) == NULL); /* alpha's second source, the PDB, is absent */
    CHECK(err.code != 0 && msg_has(&err, "alpha.pdb"));
    CHECK(dk_project_symbols(p, 1, &err) == NULL);  /* beta's map is absent */
    CHECK(msg_has(&err, "beta.map"));
}

/* ---- the object cache of a target ---------------------------------------------------------------------------------- */

DK_TEST(objcache_open_project_vc8) {
    const char *dir = fixture_copy("project_vc8");
    static const char *const ident[] = {"cl.exe", "c1.dll", "c1xx.dll", "c2.dll"};
    for (int i = 0; i < 4; i++) {
        const char *body = dk_sprintf(dk_arena(), "synthetic image %d\n", i);
        write_text(J(dir, dk_sprintf(dk_arena(), "toolchain/VC/bin/%s", ident[i])), body);
    }
    char *cache = dk_mkdtemp(dk_arena(), "project_load_cache-", "", NULL);
    REQUIRE(cache != NULL);
    DK_ASSERT(dk_setenv(OBJCACHE_ENV_CACHE, cache));
    DkProject *p = load(dir);
    REQUIRE(p);

    ObjcacheObjCache *c = objcache_open_project(p, 0, true);
    CHECK(c != NULL);
    if (c) CHECK_CZ(objcache_obj_cache_summary(c), "object cache: 0 reused, 0 compiled");
    CHECK(objcache_open_project(p, 0, false) == NULL);

    /* another target of the same project: the identity files are shared, so the cache opens as well */
    ObjcacheObjCache *c2 = objcache_open_project(p, 3, true);
    CHECK(c2 != NULL);

    DK_ASSERT(dk_unsetenv(OBJCACHE_ENV_CACHE));
}

DK_TEST(objcache_open_project_pertarget) {
    const char *dir = fixture_copy("project_pertarget");
    write_text(J(dir, "bin/cl.exe"), "synthetic compiler\n");
    char *cache = dk_mkdtemp(dk_arena(), "project_load_cache-", "", NULL);
    REQUIRE(cache != NULL);
    DK_ASSERT(dk_setenv(OBJCACHE_ENV_CACHE, cache));
    DkProject *p = load(dir);
    REQUIRE(p);
    /* beta overrides the compiler block (flags and environment): its identity is its own */
    for (int t = 0; t < 2; t++) {
        ObjcacheObjCache *c = objcache_open_project(p, t, true);
        CHECK_MSG(c != NULL, "target %d", t);
        if (c) CHECK_CZ(objcache_obj_cache_summary(c), "object cache: 0 reused, 0 compiled");
    }
    DK_ASSERT(dk_unsetenv(OBJCACHE_ENV_CACHE));
}

DK_TEST_MAIN("project_load")
