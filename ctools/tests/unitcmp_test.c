// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* unitcmp end to end on the fake toolchain (tests/fakecl/fake_tools.h): a temporary repository with one unit of three
 * functions (one MATCH, one register wall, one control-flow wall) against a synthetic reference image, through the
 * library (dk_unitcmp_collect) and the command line (dk_unitcmp_main: exit codes, --function, --diff, --summary,
 * --json). Names and addresses are made up. */
#include "dk/dk.h"
#include "dk/test.h"
#include "fakecl/fake_tools.h"
#include "fixtures/synth_coff.h"
#include "unitcmp.h"

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

static const char UNIT[] =
    "// FUNCTION: alpha 0x00401000\n"
    "int f_ok(void) { return 5; }\n"
    "// FUNCTION: alpha 0x00401010\n"
    "int f_reg(int x) { return x + 1; }\n"
    "// FUNCTION: alpha 0x00401020\n"
    "int f_cf(int x) { if (x) return 0; return 1; }\n";

static const u8 OK[6] = {0xB8, 5, 0, 0, 0, 0xC3};
static const u8 REG_OURS[10] = {0x8B, 0x4C, 0x24, 0x04, 0x83, 0xC1, 0x01, 0x8B, 0xC1, 0xC3};
static const u8 REG_REF[10] = {0x8B, 0x54, 0x24, 0x04, 0x83, 0xC2, 0x01, 0x8B, 0xC2, 0xC3};
static const u8 CF_OURS[6] = {0x85, 0xC0, 0x74, 0x01, 0xC3, 0xC3};
static const u8 CF_REF[6] = {0x85, 0xC0, 0x75, 0x01, 0xC3, 0xC3};

static DkStr unit_object(void) {
    u8 code[22];
    memcpy(code, OK, 6);
    memcpy(code + 6, REG_OURS, 10);
    memcpy(code + 16, CF_OURS, 6);
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 t = synth_coff_section(&sc, ".text", 0x60500020u, code, sizeof code);
    synth_coff_symbol(&sc, "_f_ok", 0, (i16)t, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_reg", 6, (i16)t, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_cf", 16, (i16)t, 0x20, 2, 0);
    return synth_coff_build(&sc);
}

static void reference(const char *path) {
    FakePe pe;
    fake_pe_init(&pe, 0x00400000u);
    u8 text[0x40];
    memset(text, 0xCC, sizeof text);
    memcpy(text + 0x00, OK, 6);
    memcpy(text + 0x10, REG_REF, 10);
    memcpy(text + 0x20, CF_REF, 6);
    fake_pe_section(&pe, ".text", 0x60000020u, text, sizeof text);
    DK_ASSERT(fake_pe_write(&pe, path));
}

static const char CONFIG[] =
    "{\"schema\": \"decompkit-project/1\",\n"
    " \"targets\": {\"alpha\": {\"image\": \"${root}/ref/alpha.exe\", \"sha256\": \"%s\",\n"
    "                         \"symbols\": [{\"kind\": \"tsv\", \"path\": \"${root}/ref/alpha.tsv\"}]}},\n"
    " \"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"], \"map\": {\"src/absent.c\": {}}},\n"
    " \"compiler\": {\"cl\": \"${root}/bin/fakecl.exe\", \"env\": {\"FAKECL_REGISTRY\": \"${root}/fakereg\"},\n"
    "              \"base_flags\": [\"/nologo\", \"/c\"]},\n"
    " \"backend\": {\"kind\": \"object\"},\n"
    " \"annotations\": {\"marker\":\n"
    "  \"^//\\\\s*(?P<kind>FUNCTION):\\\\s+(?P<target>\\\\w+)\\\\s+(?P<addr>0x[0-9a-fA-F]+)\\\\s*$\",\n"
    "                 \"kinds\": {\"FUNCTION\": \"function\"}}}\n";

static const char *make_repo(void) {
    const char *dir = fwd(dk_mkdtemp(dk_arena(), "unitcmp-", "", NULL));
    wchar_t self[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, self, MAX_PATH);
    DK_ASSERT(n > 0 && n < MAX_PATH);
    char me[MAX_PATH * 3];
    WideCharToMultiByte(CP_UTF8, 0, self, -1, me, (int)sizeof me, NULL, NULL);
    dk_makedirs(J(dir, "bin"), true);
    DK_ASSERT(dk_copyfile(me, J(dir, "bin/fakecl.exe")));
    write_text(J(dir, "src/u.c"), UNIT);
    DK_ASSERT(fake_cl_register(J(dir, "fakereg"), fake_cl_key(dk_str(UNIT), NULL, 0, ""), unit_object()));
    dk_makedirs(J(dir, "ref"), true);
    reference(J(dir, "ref/alpha.exe"));
    write_text(J(dir, "ref/alpha.tsv"), "name\tva\tsize\n_f_ok\t0x401000\t6\n_f_reg\t0x401010\t10\n_f_cf\t0x401020\t6\n");
    const char *sha = dk_file_digest_hex(dk_arena(), DK_HASH_SHA256, J(dir, "ref/alpha.exe"));
    write_text(J(dir, "config/ctools.json"), dk_sprintf(dk_arena(), CONFIG, sha));
    return dir;
}

static const DkUnitcmpRow *row_named(const DkUnitcmpRowVec *rows, const char *name) {
    for (size_t i = 0; i < rows->n; i++)
        if (rows->v[i].r->ann && rows->v[i].r->ann->name && strcmp(rows->v[i].r->ann->name, name) == 0)
            return &rows->v[i];
    return NULL;
}

DK_TEST(collect) {
    const char *root = make_repo();
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    DkUnitcmpOpts o;
    memset(&o, 0, sizeof o);
    o.all = true;
    o.target = -1;
    DkUnitcmpRowVec rows = {0};
    REQUIRE(dk_unitcmp_collect(p, &o, &rows, &err)); /* the unit map's absent file is left out */
    CHECK_EQ_U64(rows.n, 3);
    const DkUnitcmpRow *ok = row_named(&rows, "f_ok"), *reg = row_named(&rows, "f_reg"), *cf = row_named(&rows, "f_cf");
    REQUIRE(ok && reg && cf);
    CHECK(ok->r->status == DK_MATCH && strcmp(ok->wall.wall, "match") == 0);
    CHECK(reg->r->status == DK_DIFF && strcmp(reg->wall.wall, "register") == 0);
    CHECK(cf->r->status == DK_DIFF && strcmp(cf->wall.wall, "control-flow") == 0);
    DkStr line = dk_unitcmp_line(dk_arena(), p, reg);
    CHECK_MSG(dk_str_eqz(line, "DIFF       alpha  00401010 10/10        70.0% register     f_reg"), "%.*s",
              DK_SF(line));
    dk_vec_free(&rows);

    /* --function by name and by address; an unknown unit */
    const char *units[1] = {"u"};
    o.all = false;
    o.units = units;
    o.n_units = 1;
    o.function = "f_cf";
    REQUIRE(dk_unitcmp_collect(p, &o, &rows, &err));
    CHECK(rows.n == 1 && row_named(&rows, "f_cf"));
    dk_vec_free(&rows);
    o.function = "401010";
    REQUIRE(dk_unitcmp_collect(p, &o, &rows, &err));
    CHECK(rows.n == 1 && row_named(&rows, "f_reg"));
    dk_vec_free(&rows);
    const char *bad[1] = {"src/none.c"};
    o.units = bad;
    CHECK(!dk_unitcmp_collect(p, &o, &rows, &err) && strstr(err.msg, "src/none.c"));
    dk_tempdir_cleanup(root);
}

static int run_main(const char *const *args, size_t n) {
    char **argv = DK_NEWN(dk_arena(), char *, n + 2);
    argv[0] = "unitcmp";
    for (size_t i = 0; i < n; i++) argv[i + 1] = (char *)args[i];
    return dk_unitcmp_main((int)n + 1, argv);
}

DK_TEST(command_line) {
    const char *root = make_repo();
    const char *json = J(root, "out.json");
    const char *a1[] = {"--root", root, "src/u.c", "--diff", "--json", json};
    CHECK_EQ_I64(run_main(a1, DK_ARRAY_LEN(a1)), 1);
    DkBytes raw = {0};
    REQUIRE(dk_read_all(NULL, json, &raw));
    DkJson *doc = dk_json_parse(dk_arena(), dk_strn((const char *)raw.v, raw.n), NULL);
    dk_vec_free(&raw);
    REQUIRE(doc);
    CHECK_STR(dk_json_get_str(doc, "schema", DK_S("")), "decompkit-unitcmp/1");
    DkJson *totals = dk_json_getz(doc, "totals");
    CHECK(dk_json_get_i64(totals, "MATCH", -1) == 1 && dk_json_get_i64(totals, "DIFF", -1) == 2);
    DkJson *results = dk_json_getz(doc, "results");
    REQUIRE(dk_json_len(results) == 3);
    DkJson *second = dk_json_at(results, 1);
    CHECK_STR(dk_json_get_str(second, "name", DK_S("")), "f_reg");
    CHECK_STR(dk_json_get_str(second, "wall", DK_S("")), "register");
    CHECK_STR(dk_json_get_str(second, "address", DK_S("")), "0x00401010");
    CHECK(dk_json_get_i64(second, "differ", -1) == 3);
    CHECK(dk_json_getz(second, "classify") != NULL);
    CHECK_STR(dk_json_get_str(second, "unit", DK_S("")), "src/u.c");

    const char *a2[] = {"--root", root, "u", "--function", "f_ok"};
    CHECK_EQ_I64(run_main(a2, DK_ARRAY_LEN(a2)), 0);
    const char *a3[] = {"--root", root, "--all", "--summary", "--target", "alpha"};
    CHECK_EQ_I64(run_main(a3, DK_ARRAY_LEN(a3)), 1);
    const char *a4[] = {"--root", root, "src/none.c"};
    CHECK_EQ_I64(run_main(a4, DK_ARRAY_LEN(a4)), 2);
    const char *a5[] = {"--root", root, "u", "--target", "beta"};
    CHECK_EQ_I64(run_main(a5, DK_ARRAY_LEN(a5)), 2);
    const char *a6[] = {"--root", root};
    CHECK_EQ_I64(run_main(a6, DK_ARRAY_LEN(a6)), 2);
    dk_tempdir_cleanup(root);
}

DK_TEST(hooks_table) {
    const DkUnitcmpHook *h = dk_unitcmp_hooks();
    REQUIRE(h);
    size_t n = 0;
    while (h[n].option) n++;
    CHECK(n < 16);
}

/* The entry point: the fake tools when started under their names, else the tests. */
static int run(int argc, char **argv) {
    int rc = fake_tool_dispatch(argc, argv);
    if (rc >= 0) return rc;
    return dk_test__run(argc, argv);
}
DK_MAIN(run, "test_unitcmp")
