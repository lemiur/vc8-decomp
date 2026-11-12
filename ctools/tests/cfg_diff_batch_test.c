// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* cfg_diff over the adapter's results, on the fake toolchain (tests/fakecl/fake_tools.h): a temporary repository with
 * one unit of four functions against a synthetic reference image. f_ok matches, f_reg has a register wall, f_cf a
 * control-flow wall (an inverted branch), f_cf2 a control-flow wall with the reference's second arm missing. The batch
 * analyses the control-flow walls only (all walls with --all-walls, parked functions only with --stopped) and writes
 * batch.tsv, batch.json and batch.md; the single-function form prints the report. Names and addresses are made up. */
#include "dk/dk.h"
#include "dk/test.h"
#include "fakecl/fake_tools.h"
#include "fixtures/synth_coff.h"
#include "cfg_diff.h"

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
    "// STOP: alpha branch\n"
    "int f_cf(int x) { if (x) return 0; return 1; }\n"
    "// FUNCTION: alpha 0x00401030\n"
    "int f_cf2(int x) { return x; }\n";

static const u8 OK[6] = {0xB8, 5, 0, 0, 0, 0xC3};
static const u8 REG_OURS[10] = {0x8B, 0x4C, 0x24, 0x04, 0x83, 0xC1, 0x01, 0x8B, 0xC1, 0xC3};
static const u8 REG_REF[10] = {0x8B, 0x54, 0x24, 0x04, 0x83, 0xC2, 0x01, 0x8B, 0xC2, 0xC3};
/* test eax,eax; jz L; mov eax,1; ret; L: xor eax,eax; ret   against   jnz with the arms in the other order */
static const u8 CF_OURS[13] = {0x85, 0xC0, 0x74, 0x06, 0xB8, 1, 0, 0, 0, 0xC3, 0x33, 0xC0, 0xC3};
static const u8 CF_REF[13] = {0x85, 0xC0, 0x75, 0x06, 0x33, 0xC0, 0xC3, 0xB8, 1, 0, 0, 0, 0xC3};
static const u8 CF2_OURS[3] = {0x8B, 0xC1, 0xC3};
static const u8 CF2_REF[8] = {0x85, 0xC9, 0x74, 0x03, 0x8B, 0xC1, 0xC3, 0xC3};

static DkStr unit_object(void) {
    u8 code[6 + 10 + 13 + 3];
    memcpy(code, OK, 6);
    memcpy(code + 6, REG_OURS, 10);
    memcpy(code + 16, CF_OURS, 13);
    memcpy(code + 29, CF2_OURS, 3);
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 t = synth_coff_section(&sc, ".text", 0x60500020u, code, sizeof code);
    synth_coff_symbol(&sc, "_f_ok", 0, (i16)t, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_reg", 6, (i16)t, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_cf", 16, (i16)t, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_cf2", 29, (i16)t, 0x20, 2, 0);
    return synth_coff_build(&sc);
}

static void reference(const char *path) {
    FakePe pe;
    fake_pe_init(&pe, 0x00400000u);
    u8 text[0x40];
    memset(text, 0xCC, sizeof text);
    memcpy(text + 0x00, OK, 6);
    memcpy(text + 0x10, REG_REF, 10);
    memcpy(text + 0x20, CF_REF, 13);
    memcpy(text + 0x30, CF2_REF, 8);
    fake_pe_section(&pe, ".text", 0x60000020u, text, sizeof text);
    DK_ASSERT(fake_pe_write(&pe, path));
}

static const char CONFIG[] =
    "{\"schema\": \"decompkit-project/1\",\n"
    " \"targets\": {\"alpha\": {\"image\": \"${root}/ref/alpha.exe\", \"sha256\": \"%s\",\n"
    "                         \"symbols\": [{\"kind\": \"tsv\", \"path\": \"${root}/ref/alpha.tsv\"}]}},\n"
    " \"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]},\n"
    " \"compiler\": {\"cl\": \"${root}/bin/fakecl.exe\", \"env\": {\"FAKECL_REGISTRY\": \"${root}/fakereg\"},\n"
    "              \"base_flags\": [\"/nologo\", \"/c\"]},\n"
    " \"backend\": {\"kind\": \"object\"},\n"
    " \"annotations\": {\"marker\":\n"
    "  \"^//\\\\s*(?P<kind>FUNCTION):\\\\s+(?P<target>\\\\w+)\\\\s+(?P<addr>0x[0-9a-fA-F]+)\\\\s*$\",\n"
    "                 \"kinds\": {\"FUNCTION\": \"function\"},\n"
    "                 \"stop\": \"^//\\\\s*STOP:\\\\s*(?P<target>\\\\w+)\\\\s+(?P<reason>.*)$\"}}\n";

static const char *make_repo(void) {
    const char *dir = fwd(dk_mkdtemp(dk_arena(), "cfgdiff-", "", NULL));
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
    write_text(J(dir, "ref/alpha.tsv"),
               "name\tva\tsize\n_f_ok\t0x401000\t6\n_f_reg\t0x401010\t10\n_f_cf\t0x401020\t13\n_f_cf2\t0x401030\t8\n");
    const char *sha = dk_file_digest_hex(dk_arena(), DK_HASH_SHA256, J(dir, "ref/alpha.exe"));
    write_text(J(dir, "config/ctools.json"), dk_sprintf(dk_arena(), CONFIG, sha));
    return dir;
}

static int run_main(const char *const *args, size_t n) {
    char **argv = DK_NEWN(dk_arena(), char *, n + 2);
    argv[0] = "cfg_diff";
    for (size_t i = 0; i < n; i++) argv[i + 1] = (char *)args[i];
    return cfg_diff_main((int)n + 1, argv);
}

static DkJson *read_json(const char *path) {
    DkBytes raw = {0};
    if (!dk_read_all(NULL, path, &raw)) return NULL;
    DkJson *doc = dk_json_parse(dk_arena(), dk_strn((const char *)raw.v, raw.n), NULL);
    dk_vec_free(&raw);
    return doc;
}

static DkJson *function_row(DkJson *doc, const char *name) {
    DkJson *fl = dk_json_getz(doc, "functions");
    for (i64 i = 0; fl && i < (i64)dk_json_len(fl); i++) {
        DkJson *row = dk_json_at(fl, (size_t)i);
        if (strcmp(dk_cz(dk_arena(), dk_json_get_str(row, "function", DK_S(""))), name) == 0) return row;
    }
    return NULL;
}

DK_TEST(batch_over_results) {
    const char *root = make_repo();
    const char *out = J(root, "out");
    const char *a1[] = {"--root", root, "--batch", "src/u.c", "--out", out};
    CHECK_EQ_I64(run_main(a1, DK_ARRAY_LEN(a1)), 0);
    DkJson *doc = read_json(J(out, "batch.json"));
    REQUIRE(doc);
    CHECK_STR(dk_json_get_str(doc, "schema", DK_S("")), "decompkit-cfg-diff/1");
    DkJson *cf = function_row(doc, "f_cf");
    REQUIRE(cf);
    CHECK(function_row(doc, "f_ok") == NULL); /* a MATCH is not a row */
    CHECK(function_row(doc, "f_reg") == NULL); /* the register wall is skipped: no analysed target, no row */
    DkJson *rec = dk_json_getz(dk_json_getz(cf, "targets"), "alpha");
    REQUIRE(rec);
    CHECK_STR(dk_json_get_str(rec, "wall", DK_S("")), "control-flow");
    CHECK(dk_json_get_i64(rec, "blocks_ours", -1) >= 3);
    DkJson *findings = dk_json_getz(rec, "findings");
    REQUIRE(findings && dk_json_len(findings) >= 1);
    CHECK_STR(dk_json_get_str(dk_json_at(findings, 0), "kind", DK_S("")), "inverted-branch");
    CHECK(function_row(doc, "f_cf2") != NULL);

    DkBytes tsv = {0};
    REQUIRE(dk_read_all(NULL, J(out, "batch.tsv"), &tsv));
    CHECK(strstr((const char *)tsv.v, "src/u.c\tf_cf\talpha\t00401020\t") != NULL);
    dk_vec_free(&tsv);

    /* --all-walls adds the register wall; --stopped keeps only the parked f_cf; --select a regex */
    const char *a2[] = {"--root", root, "--batch", "--all", "--all-walls", "--out", out};
    CHECK_EQ_I64(run_main(a2, DK_ARRAY_LEN(a2)), 0);
    doc = read_json(J(out, "batch.json"));
    REQUIRE(doc);
    CHECK(function_row(doc, "f_reg") != NULL && function_row(doc, "f_cf") != NULL);
    const char *a3[] = {"--root", root, "--batch", "--all", "--stopped", "--out", out};
    CHECK_EQ_I64(run_main(a3, DK_ARRAY_LEN(a3)), 0);
    doc = read_json(J(out, "batch.json"));
    REQUIRE(doc);
    CHECK(function_row(doc, "f_cf") != NULL && function_row(doc, "f_cf2") == NULL);
    const char *a4[] = {"--root", root, "--batch", "src/u.c", "--select", "cf2$", "--out", out};
    CHECK_EQ_I64(run_main(a4, DK_ARRAY_LEN(a4)), 0);
    doc = read_json(J(out, "batch.json"));
    REQUIRE(doc);
    CHECK(function_row(doc, "f_cf2") != NULL && function_row(doc, "f_cf") == NULL);

    dk_tempdir_cleanup(root);
}

DK_TEST(single_function) {
    const char *root = make_repo();
    const char *out = J(root, "out");
    const char *a1[] = {"--root", root, "src/u.c", "f_cf", "--dot", "--out", out};
    CHECK_EQ_I64(run_main(a1, DK_ARRAY_LEN(a1)), 1); /* not a match */
    CHECK(dk_isfile(J(out, "f_cf_alpha.dot")));
    const char *a2[] = {"--root", root, "src/u.c", "f_ok"};
    CHECK_EQ_I64(run_main(a2, DK_ARRAY_LEN(a2)), 0);
    const char *a3[] = {"--root", root, "src/u.c", "f_cf", "--address", "401020", "--target", "alpha"};
    CHECK_EQ_I64(run_main(a3, DK_ARRAY_LEN(a3)), 1);
    const char *a4[] = {"--root", root, "src/u.c", "nothing"};
    CHECK_EQ_I64(run_main(a4, DK_ARRAY_LEN(a4)), 1);
    const char *a5[] = {"--root", root, "src/u.c", "f_cf", "--target", "beta"};
    CHECK_EQ_I64(run_main(a5, DK_ARRAY_LEN(a5)), 2);
    dk_tempdir_cleanup(root);
}

/* The entry point: the fake tools when started under their names, else the tests. */
static int run(int argc, char **argv) {
    int rc = fake_tool_dispatch(argc, argv);
    if (rc >= 0) return rc;
    return dk_test__run(argc, argv);
}
DK_MAIN(run, "test_cfg_diff_batch")
