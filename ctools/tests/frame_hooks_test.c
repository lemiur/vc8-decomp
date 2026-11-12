// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The --frame and --residue hooks of unitcmp on the fake toolchain (tests/fakecl/fake_tools.h): a temporary
 * repository with a unit of two functions, one that differs in registers only and one in a branch, against a
 * synthetic reference image. The reports and the JSON members are read through the hooks table, and the command line
 * writes the JSON file; the compiler block carries `cdecl_import_dlls`, read back through the project. Names and
 * addresses are made up. */
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
    "// FUNCTION: alpha 0x00401010\n"
    "int f_reg(int x) { return x + 1; }\n"
    "// FUNCTION: alpha 0x00401030\n"
    "int f_cf(int x) { if (x) return 0; return 1; }\n";

/* f_reg: a frame with a local; ours keeps the argument in ecx, the reference in edx */
static const u8 REG_OURS[] = {0x83, 0xEC, 0x04, 0x8B, 0x4C, 0x24, 0x08, 0x89, 0x4C, 0x24, 0x00, 0x83, 0xC1, 0x01, 0x8B, 0xC1,
                              0x83, 0xC4, 0x04, 0xC3};
static const u8 REG_REF[] = {0x83, 0xEC, 0x04, 0x8B, 0x54, 0x24, 0x08, 0x89, 0x54, 0x24, 0x00, 0x83, 0xC2, 0x01, 0x8B, 0xC2,
                             0x83, 0xC4, 0x04, 0xC3};
static const u8 CF_OURS[6] = {0x85, 0xC0, 0x74, 0x01, 0xC3, 0xC3};
static const u8 CF_REF[6] = {0x85, 0xC0, 0x75, 0x01, 0xC3, 0xC3};

static DkStr unit_object(void) {
    u8 code[sizeof REG_OURS + 6];
    memcpy(code, REG_OURS, sizeof REG_OURS);
    memcpy(code + sizeof REG_OURS, CF_OURS, 6);
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 t = synth_coff_section(&sc, ".text", 0x60500020u, code, sizeof code);
    synth_coff_symbol(&sc, "_f_reg", 0, (i16)t, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_cf", (u32)sizeof REG_OURS, (i16)t, 0x20, 2, 0);
    return synth_coff_build(&sc);
}

static void reference(const char *path) {
    FakePe pe;
    fake_pe_init(&pe, 0x00400000u);
    u8 text[0x40];
    memset(text, 0xCC, sizeof text);
    memcpy(text + 0x10, REG_REF, sizeof REG_REF);
    memcpy(text + 0x30, CF_REF, 6);
    fake_pe_section(&pe, ".text", 0x60000020u, text, sizeof text);
    DK_ASSERT(fake_pe_write(&pe, path));
}

static const char CONFIG[] =
    "{\"schema\": \"decompkit-project/1\",\n"
    " \"targets\": {\"alpha\": {\"image\": \"${root}/ref/alpha.exe\", \"sha256\": \"%s\",\n"
    "                         \"symbols\": [{\"kind\": \"tsv\", \"path\": \"${root}/ref/alpha.tsv\"}]}},\n"
    " \"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]},\n"
    " \"compiler\": {\"cl\": \"${root}/bin/fakecl.exe\", \"env\": {\"FAKECL_REGISTRY\": \"${root}/fakereg\"},\n"
    "              \"base_flags\": [\"/nologo\", \"/c\"], \"cdecl_import_dlls\": [\"msvcr*\", \"my_runtime.dll\"]},\n"
    " \"backend\": {\"kind\": \"object\"},\n"
    " \"annotations\": {\"marker\":\n"
    "  \"^//\\\\s*(?P<kind>FUNCTION):\\\\s+(?P<target>\\\\w+)\\\\s+(?P<addr>0x[0-9a-fA-F]+)\\\\s*$\",\n"
    "                 \"kinds\": {\"FUNCTION\": \"function\"}}}\n";

static const char *make_repo(void) {
    const char *dir = fwd(dk_mkdtemp(dk_arena(), "frame-hooks-", "", NULL));
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
    write_text(J(dir, "ref/alpha.tsv"), "name\tva\tsize\n_f_reg\t0x401010\t20\n_f_cf\t0x401020\t6\n");
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

static const DkUnitcmpHook *hook(const char *option) {
    for (const DkUnitcmpHook *h = dk_unitcmp_hooks(); h->option; h++)
        if (strcmp(h->option, option) == 0) return h;
    return NULL;
}

static bool contains(DkStr s, const char *needle) { return dk_str_contains(s, dk_str(needle)); }

DK_TEST(hooks_registered) {
    const DkUnitcmpHook *f = hook("--frame"), *r = hook("--residue");
    REQUIRE(f && r);
    CHECK_CZ(f->dest, "frame");
    CHECK_CZ(r->dest, "residue");
    CHECK(f->report && f->json && r->report && r->json);
}

DK_TEST(compiler_key) {
    const char *root = make_repo();
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    const DkCompiler *c = dk_project_compiler(p, 0);
    CHECK(c->cdecl_import_dlls_set);
    REQUIRE(c->cdecl_import_dlls.n == 2);
    CHECK_STR(c->cdecl_import_dlls.v[0], "msvcr*");
    CHECK_STR(c->cdecl_import_dlls.v[1], "my_runtime.dll");
    dk_tempdir_cleanup(root);
}

DK_TEST(reports) {
    const char *root = make_repo();
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    DkUnitcmpOpts o;
    memset(&o, 0, sizeof o);
    o.all = true;
    o.target = -1;
    DkUnitcmpRowVec rows = {0};
    REQUIRE(dk_unitcmp_collect(p, &o, &rows, &err));
    const DkUnitcmpRow *reg = row_named(&rows, "f_reg"), *cf = row_named(&rows, "f_cf");
    REQUIRE(reg && cf);
    CHECK(reg->r->status == DK_DIFF);
    DkImage *im = dk_target_image(p, 0, &err);
    REQUIRE(im);

    /* --frame: both prologues, the slot table and the slot map */
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    hook("--frame")->report(p, reg, im, &b);
    DkStr text = dk_buf_str(&b);
    CHECK_MSG(contains(text, "alpha frame of f_reg at 00401010"), "%.*s", DK_SF(text));
    CHECK(contains(text, "alpha slot map of"));
    CHECK(contains(text, "slot(s) ours"));
    CHECK(contains(text, "paired"));
    DkJson *fj = hook("--frame")->json(p, reg, im, dk_arena());
    REQUIRE(fj);
    DkJson *ours = dk_json_getz(fj, "ours");
    REQUIRE(ours);
    CHECK_EQ_I64(dk_json_get_i64(ours, "locals", -1), 4);
    CHECK_EQ_I64(dk_json_get_i64(dk_json_getz(fj, "reference"), "locals", -1), 4);
    CHECK_EQ_I64(dk_json_get_i64(fj, "slot_rows_differ", -1), 0); /* same slots on both sides */

    /* --residue: the register wall is register-only, the renames ecx -> edx */
    dk_buf_init(&b, dk_arena());
    hook("--residue")->report(p, reg, im, &b);
    text = dk_buf_str(&b);
    CHECK_MSG(contains(text, "residue: register-only"), "%.*s", DK_SF(text));
    CHECK(contains(text, "ecx->edx"));
    DkJson *rj = hook("--residue")->json(p, reg, im, dk_arena());
    REQUIRE(rj);
    CHECK_STR(dk_json_get_str(rj, "verdict", DK_S("")), "register-only (the renames are all in block-local values)");
    CHECK(dk_json_get_bool(rj, "register_only", false));
    CHECK(dk_json_getz(dk_json_getz(dk_json_getz(rj, "mapping"), "all"), "ecx") != NULL);

    /* the branch wall is not register-only */
    dk_buf_init(&b, dk_arena());
    hook("--residue")->report(p, cf, im, &b);
    text = dk_buf_str(&b);
    CHECK_MSG(!contains(text, "register-only"), "%.*s", DK_SF(text));
    CHECK(contains(text, "residue:"));
    dk_vec_free(&rows);
    dk_tempdir_cleanup(root);
}

static int run_main(const char *const *args, size_t n) {
    char **argv = DK_NEWN(dk_arena(), char *, n + 2);
    argv[0] = "unitcmp";
    for (size_t i = 0; i < n; i++) argv[i + 1] = (char *)args[i];
    return dk_unitcmp_main((int)n + 1, argv);
}

DK_TEST(command_line_json) {
    const char *root = make_repo();
    const char *json = J(root, "out.json");
    const char *a1[] = {"--root", root, "src/u.c", "--frame", "--residue", "--json", json};
    CHECK_EQ_I64(run_main(a1, DK_ARRAY_LEN(a1)), 1);
    DkBytes raw = {0};
    REQUIRE(dk_read_all(NULL, json, &raw));
    DkJson *doc = dk_json_parse(dk_arena(), dk_strn((const char *)raw.v, raw.n), NULL);
    dk_vec_free(&raw);
    REQUIRE(doc);
    DkJson *results = dk_json_getz(doc, "results");
    REQUIRE(dk_json_len(results) == 2);
    for (size_t i = 0; i < 2; i++) {
        DkJson *r = dk_json_at(results, i);
        CHECK(dk_json_getz(r, "frame") != NULL);
        CHECK(dk_json_getz(r, "residue") != NULL);
    }
    /* without the flags the members are absent */
    const char *a2[] = {"--root", root, "src/u.c", "--json", json};
    CHECK_EQ_I64(run_main(a2, DK_ARRAY_LEN(a2)), 1);
    REQUIRE(dk_read_all(NULL, json, &raw));
    doc = dk_json_parse(dk_arena(), dk_strn((const char *)raw.v, raw.n), NULL);
    dk_vec_free(&raw);
    CHECK(dk_json_getz(dk_json_at(dk_json_getz(doc, "results"), 0), "frame") == NULL);
    dk_tempdir_cleanup(root);
}

/* The entry point: the fake tools when started under their names, else the tests. */
static int run(int argc, char **argv) {
    int rc = fake_tool_dispatch(argc, argv);
    if (rc >= 0) return rc;
    return dk_test__run(argc, argv);
}
DK_MAIN(run, "test_frame_hooks")
