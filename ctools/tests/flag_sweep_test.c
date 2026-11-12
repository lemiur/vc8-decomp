// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* flag_sweep: the variant list and option arithmetic on synthetic option lists, then the whole sweep on the fake
 * toolchain (tests/fakecl/fake_tools.h): a temporary repository with two targets (each with its own base options),
 * canned objects that answer chosen option lists with other code, and the resulting table, verdict, JSON and
 * command line checked cell by cell. Names and addresses are made up. */
#include "dk/dk.h"
#include "dk/test.h"
#include "fakecl/fake_tools.h"
#include "fixtures/synth_coff.h"
#include "flag_sweep.h"

#include <string.h>
#include <windows.h>

static const char *J(const char *a, const char *b) { return dk_join(dk_arena(), a, b); }

static void write_text(const char *path, const char *text) {
    dk_makedirs(dk_cz(dk_arena(), dk_path_dirname(path)), true);
    DK_ASSERT(dk_write_file(path, text, strlen(text)));
}

static const char *fwd(const char *p) {
    char *s = dk_strdup(dk_arena(), p);
    for (char *c = s; *c; c++)
        if (*c == '\\') *c = '/';
    return s;
}

/* ---- option lists ------------------------------------------------------------------------------------------------- */

static DkCzVec list(const char *const *toks, size_t n) {
    DkCzVec v = {0};
    for (size_t i = 0; i < n; i++) dk_vec_push(&v, (char *)toks[i]);
    return v;
}

static bool has_variant(const DkFlagVariantVec *v, const char *name) {
    for (size_t i = 0; i < v->n; i++)
        if (strcmp(v->v[i].name, name) == 0) return true;
    return false;
}

static const char *joined(const DkCzVec *v) {
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    for (size_t i = 0; i < v->n; i++) {
        if (i) dk_buf_putc(&b, ' ');
        dk_buf_putz(&b, v->v[i]);
    }
    return dk_buf_cz(&b);
}

DK_TEST(apply_replaces_a_family) {
    const char *base[] = {"/O2", "/Oy", "/EHsc", "/W3"};
    DkCzVec b = list(base, 4);
    const char *extra[] = {"/Os", "/EHa", "/Zi"};
    DkCzVec r = dk_flag_apply(dk_arena(), &b, extra, 3);
    CHECK_CZ(joined(&r), "/Oy /W3 /Os /EHa /Zi");
    /* a family twice in the base keeps the last */
    const char *twice[] = {"/O1", "/O2", "/c"};
    DkCzVec t = list(twice, 3);
    DkCzVec rt = dk_flag_apply(dk_arena(), &t, NULL, 0);
    CHECK_CZ(joined(&rt), "/O2 /c");
}

DK_TEST(default_variants) {
    const char *base[] = {"/nologo", "/O2", "/Oy", "/GS", "/Gy", "/fp:fast", "/arch:SSE2", "/EHsc"};
    DkCzVec b = list(base, 8);
    DkFlagVariantVec v = dk_flag_variants(dk_arena(), &b, false, NULL, 0);
    const char *want[] = {"baseline", "-/Oy", "-/GS", "-/Gy", "-/fp:fast", "-/arch:SSE2",
                          "/EHsc->/EHa", "+/Ob1", "/O2->/Os", "+/Oi-"};
    REQUIRE(v.n == DK_ARRAY_LEN(want));
    for (size_t i = 0; i < v.n; i++) CHECK_CZ(v.v[i].name, want[i]);
    CHECK_CZ(joined(&v.v[0].tokens), "/nologo /O2 /Oy /GS /Gy /fp:fast /arch:SSE2 /EHsc");
    CHECK_CZ(joined(&v.v[1].tokens), "/nologo /O2 /GS /Gy /fp:fast /arch:SSE2 /EHsc /Oy-");
    CHECK_CZ(joined(&v.v[3].tokens), "/nologo /O2 /Oy /GS /fp:fast /arch:SSE2 /EHsc");
    CHECK_CZ(joined(&v.v[6].tokens), "/nologo /O2 /Oy /GS /Gy /fp:fast /arch:SSE2 /EHa");
    CHECK_CZ(joined(&v.v[8].tokens), "/nologo /Oy /GS /Gy /fp:fast /arch:SSE2 /EHsc /Os");

    /* an option the baseline lacks is not dropped; /EHa swaps to /EHsc; extended adds the further list */
    const char *lean[] = {"/O2", "/EHa"};
    DkCzVec l = list(lean, 2);
    DkFlagVariantVec lv = dk_flag_variants(dk_arena(), &l, false, NULL, 0);
    CHECK(!has_variant(&lv, "-/Gy") && !has_variant(&lv, "-/fp:fast") && has_variant(&lv, "/EHa->/EHsc"));
    DkFlagVariantVec ext = dk_flag_variants(dk_arena(), &l, true, NULL, 0);
    CHECK(ext.n > lv.n && has_variant(&ext, "+/Ob0") && has_variant(&ext, "+/Zp16"));
    CHECK(!has_variant(&ext, "+/O2")); /* nothing equal to the baseline is listed */
}

DK_TEST(configured_variants) {
    const char *base[] = {"/O2", "/Oy", "/EHsc"};
    DkCzVec b = list(base, 3);
    DkStrVec cfg[2] = {{0}, {0}};
    dk_vec_push(&cfg[0], dk_str("/O1"));
    dk_vec_push(&cfg[1], dk_str("/O2"));
    dk_vec_push(&cfg[1], dk_str("/Oy-"));
    DkFlagVariantVec v = dk_flag_variants(dk_arena(), &b, false, cfg, 2);
    REQUIRE(v.n == 3); /* the second entry's /O2 is already there, but the order of the options changes */
    CHECK_CZ(v.v[1].name, "+/O1");
    CHECK_CZ(v.v[2].name, "+/O2+/Oy-");
    CHECK_CZ(joined(&v.v[2].tokens), "/EHsc /O2 /Oy-");
    DkFlagVariantVec one = dk_flag_variants(dk_arena(), &b, false, cfg, 1);
    REQUIRE(one.n == 2);
    CHECK_CZ(one.v[1].name, "+/O1");
    CHECK(!has_variant(&one, "+/Ob1")); /* the configured list replaces the built-in one */
    CHECK_CZ(joined(&one.v[1].tokens), "/Oy /EHsc /O1");
}

DK_TEST(build_opts_are_the_difference) {
    const char *base[] = {"/O2", "/Oy", "/Gy", "/EHsc"};
    DkCzVec b = list(base, 4);
    DkFlagVariantVec v = dk_flag_variants(dk_arena(), &b, false, NULL, 0);
    for (size_t i = 0; i < v.n; i++) {
        if (strcmp(v.v[i].name, "/O2->/Os") != 0) continue;
        DkBuildOpts o;
        dk_flag_build_opts(dk_arena(), &b, &v.v[i].tokens, &o);
        REQUIRE(o.remove_flags.n == 1 && o.extra_flags.n == 1);
        CHECK(dk_str_eqz(o.remove_flags.v[0], "/O2") && dk_str_eqz(o.extra_flags.v[0], "/Os"));
    }
    DkBuildOpts same;
    dk_flag_build_opts(dk_arena(), &b, &v.v[0].tokens, &same);
    CHECK(same.remove_flags.n == 0 && same.extra_flags.n == 0);
}

/* ---- the sweep on the fake toolchain ------------------------------------------------------------------------------ */

static const char UNIT[] =
    "// FUNCTION: 401000 401000\n"
    "int f_all(void) { return 5; }\n"
    "// FUNCTION: 401010 401010\n"
    "int f_sens(int x) { return x + 1; }\n"
    "// FUNCTION: 401020 401020\n"
    "// stop: parked, differs in every build\n"
    "int f_cf(int x) { if (x) return 0; return 1; }\n";
static const char UNIT_V[] = "// FUNCTION: 401030 401030\nint f_u(void) { return 7; }\n";
static const char UNIT_BAD[] = "#error synthetic\n// FUNCTION: 401040 401040\nint f_b(void) { return 0; }\n";

static const u8 OK[6] = {0xB8, 5, 0, 0, 0, 0xC3};
static const u8 REG_REF[10] = {0x8B, 0x54, 0x24, 0x04, 0x83, 0xC2, 0x01, 0x8B, 0xC2, 0xC3};
static const u8 REG_OURS[10] = {0x8B, 0x4C, 0x24, 0x04, 0x83, 0xC1, 0x01, 0x8B, 0xC1, 0xC3};
static const u8 CF_OURS[6] = {0x85, 0xC0, 0x74, 0x01, 0xC3, 0xC3};
static const u8 CF_REF[6] = {0x85, 0xC0, 0x75, 0x01, 0xC3, 0xC3};
static const u8 U_REF[6] = {0xB8, 7, 0, 0, 0, 0xC3};
static const u8 U_OURS[6] = {0xB8, 8, 0, 0, 0, 0xC3};

/* The unit's object: f_all, f_sens (the given bytes), f_cf. */
static DkStr unit_object(const u8 sens[10]) {
    u8 code[22];
    memcpy(code, OK, 6);
    memcpy(code + 6, sens, 10);
    memcpy(code + 16, CF_OURS, 6);
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 t = synth_coff_section(&sc, ".text", 0x60500020u, code, sizeof code);
    synth_coff_symbol(&sc, "_f_all", 0, (i16)t, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_sens", 6, (i16)t, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_cf", 16, (i16)t, 0x20, 2, 0);
    return synth_coff_build(&sc);
}

static DkStr single_object(const char *sym, const u8 code[6]) {
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 t = synth_coff_section(&sc, ".text", 0x60500020u, code, 6);
    synth_coff_symbol(&sc, sym, 0, (i16)t, 0x20, 2, 0);
    return synth_coff_build(&sc);
}

static void reference(const char *path) {
    FakePe pe;
    fake_pe_init(&pe, 0x00400000u);
    u8 text[0x60];
    memset(text, 0xCC, sizeof text);
    memcpy(text + 0x00, OK, 6);
    memcpy(text + 0x10, REG_REF, 10);
    memcpy(text + 0x20, CF_REF, 6);
    memcpy(text + 0x30, U_REF, 6);
    fake_pe_section(&pe, ".text", 0x60000020u, text, sizeof text);
    DK_ASSERT(fake_pe_write(&pe, path));
}

/* Two targets, beta with base options of its own. */
static const char CONFIG[] =
    "{\"schema\": \"decompkit-project/1\",\n"
    " \"targets\": {\n"
    "  \"alpha\": {\"image\": \"${root}/ref/alpha.exe\", \"sha256\": \"%s\",\n"
    "            \"symbols\": [{\"kind\": \"tsv\", \"path\": \"${root}/ref/alpha.tsv\"}]},\n"
    "  \"beta\": {\"image\": \"${root}/ref/beta.exe\", \"sha256\": \"%s\",\n"
    "           \"symbols\": [{\"kind\": \"tsv\", \"path\": \"${root}/ref/alpha.tsv\"}],\n"
    "           \"compiler\": {\"base_flags\": [\"/nologo\", \"/c\", \"/O1\", \"/GS\"]}}},\n"
    " \"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]},\n"
    " \"compiler\": {\"cl\": \"${root}/bin/fakecl.exe\", \"env\": {\"FAKECL_REGISTRY\": \"${root}/fakereg\"},\n"
    "              \"base_flags\": [\"/nologo\", \"/c\", \"/O2\", \"/Oy\", \"/GS\", \"/Gy\", \"/fp:fast\", \"/arch:SSE2\","
    " \"/EHsc\"]},\n"
    " \"backend\": {\"kind\": \"object\"},\n"
    " \"annotations\": {\"addr_groups\": \"per-target\", \"name\": \"declaration\",\n"
    "  \"marker\": \"^//\\\\s*FUNCTION:\\\\s+(?P<addr_alpha>[0-9a-fA-F]+)\\\\s+(?P<addr_beta>[0-9a-fA-F]+)\\\\s*$\",\n"
    "  \"stop\": \"^\\\\s*//\\\\s*stop:\\\\s*(?P<reason>.+)$\"}}\n";

static void register_obj(const char *dir, DkStr unit_text, const char *flags, DkStr obj) {
    const char *key = fake_cl_key(unit_text, NULL, 0, "");
    DK_ASSERT(fake_cl_register(J(dir, "fakereg"), flags ? fake_cl_flags_key(key, flags) : key, obj));
}

static const char *make_repo(void) {
    const char *dir = fwd(dk_mkdtemp(dk_arena(), "flagsweep-", "", NULL));
    wchar_t self[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, self, MAX_PATH);
    DK_ASSERT(n > 0 && n < MAX_PATH);
    char me[MAX_PATH * 3];
    WideCharToMultiByte(CP_UTF8, 0, self, -1, me, (int)sizeof me, NULL, NULL);
    dk_makedirs(J(dir, "bin"), true);
    DK_ASSERT(dk_copyfile(me, J(dir, "bin/fakecl.exe")));
    write_text(J(dir, "src/u.c"), UNIT);
    write_text(J(dir, "src/v.c"), UNIT_V);
    write_text(J(dir, "src/bad.c"), UNIT_BAD);
    /* the baseline object answers every option list but the two registered below */
    register_obj(dir, dk_str(UNIT), NULL, unit_object(REG_REF));
    register_obj(dir, dk_str(UNIT_V), NULL, single_object("_f_u", U_REF));
    /* alpha without /Gy and beta swapped to /EHsc: f_sens changes code */
    register_obj(dir, dk_str(UNIT), "/O2 /Oy /GS /fp:fast /arch:SSE2 /EHsc", unit_object(REG_OURS));
    register_obj(dir, dk_str(UNIT), "/O1 /GS /EHsc", unit_object(REG_OURS));
    dk_makedirs(J(dir, "ref"), true);
    reference(J(dir, "ref/alpha.exe"));
    DK_ASSERT(dk_copyfile(J(dir, "ref/alpha.exe"), J(dir, "ref/beta.exe")));
    write_text(J(dir, "ref/alpha.tsv"),
               "name\tva\tsize\n_f_all\t0x401000\t6\n_f_sens\t0x401010\t10\n_f_cf\t0x401020\t6\n_f_u\t0x401030\t6\n");
    const char *sha = dk_file_digest_hex(dk_arena(), DK_HASH_SHA256, J(dir, "ref/alpha.exe"));
    write_text(J(dir, "config/ctools.json"), dk_sprintf(dk_arena(), CONFIG, sha, sha));
    return dir;
}

static const DkFlagRow *row_of(const DkFlagSweep *sw, const char *name, int target) {
    for (size_t i = 0; i < sw->rows.n; i++)
        if (strcmp(sw->rows.v[i].name, name) == 0 && sw->rows.v[i].target == target) return &sw->rows.v[i];
    return NULL;
}

static int col(const DkFlagSweep *sw, const char *name) {
    for (size_t i = 0; i < sw->columns.n; i++)
        if (strcmp(sw->columns.v[i], name) == 0) return (int)i;
    return -1;
}

static const char *cell(const DkFlagSweep *sw, const char *fn, int target, const char *column) {
    const DkFlagRow *r = row_of(sw, fn, target);
    int c = col(sw, column);
    if (!r || c < 0) return "<missing>";
    return r->cells[c] ? r->cells[c] : "-";
}

DK_TEST(table_on_two_targets) {
    const char *root = make_repo();
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    const DkUnit *u = dk_project_unit(p, "u");
    REQUIRE(u);
    DkFlagSweepOpts o;
    memset(&o, 0, sizeof o);
    DkFlagSweep sw;
    REQUIRE(dk_flag_sweep(p, u, &o, &sw, &err));
    CHECK(sw.build_errors.n == 0);
    CHECK_EQ_U64(sw.plan[0].n, 10); /* alpha: baseline and nine changes */
    CHECK_EQ_U64(sw.plan[1].n, 7);  /* beta: no /Oy, /Gy, /fp:fast, /arch:SSE2 or /EHsc to drop or swap */
    CHECK_CZ(sw.columns.v[0], "baseline");
    CHECK(col(&sw, "/EHsc->/EHa") >= 0 && col(&sw, "/EHa->/EHsc") >= 0 && col(&sw, "-/Gy") >= 0);
    CHECK_EQ_U64(sw.rows.n, 6); /* three functions, two targets, by line then target */
    CHECK(sw.rows.v[0].line < sw.rows.v[2].line && sw.rows.v[0].target == 0 && sw.rows.v[1].target == 1);

    CHECK_CZ(cell(&sw, "f_all", 0, "baseline"), "MATCH");
    CHECK_CZ(cell(&sw, "f_all", 0, "-/Gy"), "MATCH");
    CHECK_CZ(cell(&sw, "f_sens", 0, "baseline"), "MATCH");
    CHECK_CZ(cell(&sw, "f_sens", 0, "-/Gy"), "70%");
    CHECK_CZ(cell(&sw, "f_sens", 0, "-/Oy"), "MATCH");
    CHECK_CZ(cell(&sw, "f_sens", 0, "/EHa->/EHsc"), "-"); /* a variant of beta only */
    CHECK_CZ(cell(&sw, "f_sens", 1, "-/Gy"), "-");        /* a variant of alpha only */
    CHECK_CZ(cell(&sw, "f_sens", 1, "/EHa->/EHsc"), "70%");
    CHECK_CZ(cell(&sw, "f_sens", 1, "-/GS"), "MATCH");
    const DkFlagRow *cf = row_of(&sw, "f_cf", 0);
    REQUIRE(cf && cf->note && strcmp(cf->note, "stop") == 0);
    CHECK(strcmp(cf->cells[0], "MATCH") != 0 && strchr(cf->cells[0], '%'));

    DkFlagVerdict v = dk_flag_verdict(dk_arena(), &sw);
    CHECK_EQ_U64(v.n_matched, 4); /* f_all and f_sens, two targets; the parked f_cf stays out */
    CHECK(strstr(v.verdict, "NOT unique") && strstr(v.verdict, "-/Oy"));
    CHECK(!strstr(v.verdict, "-/Gy") && !strstr(v.verdict, "/EHa->/EHsc"));
    REQUIRE(v.insensitive.n == 1);
    CHECK_CZ(v.insensitive.v[0], "f_all");
    CHECK(v.n_functions == 2 && v.n_sensitive == 1);

    DkBuf text;
    dk_buf_init(&text, dk_arena());
    dk_flag_report(&text, p, &sw, &v);
    const char *t = dk_buf_cz(&text);
    CHECK(strstr(t, "f_sens [alpha]") && strstr(t, "f_cf [beta]*") && strstr(t, "excluded from the verdict"));
    CHECK(strstr(t, "VERDICT: baseline is NOT unique") && strstr(t, "flag-insensitive (match in every variant): 1 of 2"));

    DkJson *doc = dk_flag_json(dk_arena(), p, &sw, &v);
    CHECK_STR(dk_json_get_str(doc, "schema", DK_S("")), "decompkit-flag-sweep/1");
    CHECK_STR(dk_json_get_str(doc, "unit", DK_S("")), "src/u.c");
    DkJson *fns = dk_json_getz(doc, "functions");
    REQUIRE(dk_json_len(fns) == 6);
    DkJson *f2 = dk_json_at(fns, 2);
    CHECK_STR(dk_json_get_str(f2, "name", DK_S("")), "f_sens");
    CHECK_STR(dk_json_get_str(dk_json_getz(f2, "cells"), "-/Gy", DK_S("")), "70%");
    dk_tempdir_cleanup(root);
}

DK_TEST(target_selection) {
    const char *root = make_repo();
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    DkFlagSweepOpts o;
    memset(&o, 0, sizeof o);
    o.targets = 2; /* beta only */
    DkFlagSweep sw;
    REQUIRE(dk_flag_sweep(p, dk_project_unit(p, "u"), &o, &sw, &err));
    CHECK(sw.plan[0].n == 0 && sw.plan[1].n == 7 && sw.rows.n == 3);
    CHECK(col(&sw, "-/Gy") < 0);
    dk_tempdir_cleanup(root);
}

DK_TEST(unique_baseline) {
    const char *root = make_repo();
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    const DkUnit *u = dk_project_unit(p, "v");
    REQUIRE(u);
    /* every variant of alpha gets code that no longer matches */
    DkCzVec base = dk_flag_baseline(p, u, 0);
    DkFlagVariantVec plan = dk_flag_variants(dk_arena(), &base, false, NULL, 0);
    for (size_t i = 1; i < plan.n; i++) {
        DkCzVec cl = {0};
        for (size_t k = 0; k < plan.v[i].tokens.n; k++)
            if (strcmp(plan.v[i].tokens.v[k], "/nologo") != 0 && strcmp(plan.v[i].tokens.v[k], "/c") != 0)
                dk_vec_push(&cl, plan.v[i].tokens.v[k]);
        register_obj(root, dk_str(UNIT_V), joined(&cl), single_object("_f_u", U_OURS));
    }
    DkFlagSweepOpts o;
    memset(&o, 0, sizeof o);
    o.targets = 1;
    DkFlagSweep sw;
    REQUIRE(dk_flag_sweep(p, u, &o, &sw, &err));
    DkFlagVerdict v = dk_flag_verdict(dk_arena(), &sw);
    CHECK_MSG(strstr(v.verdict, "UNIQUE tested variant where all 1 matched"), "%s", v.verdict);
    CHECK(v.insensitive.n == 0 && v.n_functions == 1 && v.n_sensitive == 1);
    CHECK_CZ(cell(&sw, "f_u", 0, "+/Ob1"), "83%");
    dk_tempdir_cleanup(root);
}

DK_TEST(build_failure) {
    const char *root = make_repo();
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    DkFlagSweepOpts o;
    memset(&o, 0, sizeof o);
    o.targets = 1;
    DkFlagSweep sw;
    REQUIRE(dk_flag_sweep(p, dk_project_unit(p, "bad"), &o, &sw, &err));
    CHECK(sw.build_errors.n == sw.plan[0].n && strstr(sw.build_errors.v[0], "baseline [alpha]"));
    CHECK_CZ(cell(&sw, "f_b", 0, "baseline"), "ERR");
    DkFlagVerdict v = dk_flag_verdict(dk_arena(), &sw);
    CHECK(strstr(v.verdict, "no function matches") && v.n_matched == 0);
    dk_tempdir_cleanup(root);
}

static int run_main(const char *const *args, size_t n) {
    char **argv = DK_NEWN(dk_arena(), char *, n + 2);
    argv[0] = "flag_sweep";
    for (size_t i = 0; i < n; i++) argv[i + 1] = (char *)args[i];
    return dk_flag_sweep_main((int)n + 1, argv);
}

DK_TEST(command_line) {
    const char *root = make_repo();
    const char *json = J(root, "out/sweep.json");
    const char *a1[] = {"--root", root, "src/u.c", "--targets", "alpha", "--json", json};
    CHECK_EQ_I64(run_main(a1, DK_ARRAY_LEN(a1)), 0);
    DkBytes raw = {0};
    REQUIRE(dk_read_all(NULL, json, &raw));
    DkJson *doc = dk_json_parse(dk_arena(), dk_strn((const char *)raw.v, raw.n), NULL);
    dk_vec_free(&raw);
    REQUIRE(doc);
    CHECK_STR(dk_json_get_str(doc, "schema", DK_S("")), "decompkit-flag-sweep/1");
    CHECK(dk_json_len(dk_json_getz(doc, "functions")) == 3);
    DkJson *variants = dk_json_getz(dk_json_getz(doc, "variants"), "alpha");
    REQUIRE(variants);
    CHECK_STR(dk_json_get_str(variants, "baseline", DK_S("")),
              "/nologo /c /O2 /Oy /GS /Gy /fp:fast /arch:SSE2 /EHsc");
    const char *a2[] = {"--root", root, "u", "--variants", "extended"};
    CHECK_EQ_I64(run_main(a2, DK_ARRAY_LEN(a2)), 0);
    const char *a3[] = {"--root", root, "src/none.c"};
    CHECK_EQ_I64(run_main(a3, DK_ARRAY_LEN(a3)), 2);
    const char *a4[] = {"--root", root, "u", "--targets", "gamma"};
    CHECK_EQ_I64(run_main(a4, DK_ARRAY_LEN(a4)), 2);
    dk_tempdir_cleanup(root);
}

/* The entry point: the fake tools when started under their names, else the tests. */
static int run(int argc, char **argv) {
    int rc = fake_tool_dispatch(argc, argv);
    if (rc >= 0) return rc;
    return dk_test__run(argc, argv);
}
DK_MAIN(run, "test_flag_sweep")
