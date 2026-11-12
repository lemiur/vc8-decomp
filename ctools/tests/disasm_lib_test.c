// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* lib/disasm.c on a synthetic image (tests/fakecl/fake_pe.h) with a TSV symbol source and one annotated unit: the
 * rel32 scan, function bounds, listings with notes, cross references, dword dumps, jmp thunks, name search and the
 * command line. Names, addresses and bytes are made up.
 *
 * .text at 0x401000: f_a (0x00, calls and jumps to f_b), a jmp thunk to f_b (0x20), f_b (0x30), a `jmp [slot]` import
 * thunk (0x40), a `mov ecx; jmp` thunk (0x50), f_c (0x60: calls into the thunks and into the middle of f_b).
 * .data at 0x402000: a table of dwords. .idata: one import (Sleep). */
#include "dk/dk.h"
#include "dk/test.h"
#include "disasm.h"
#include "fakecl/fake_pe.h"

#include <string.h>

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

#define SLOT 0x403030u

static const char UNIT[] =
    "// FUNCTION: alpha 0x00401000\n"
    "int f_a(void) { return 1; }\n"
    "// FUNCTION: alpha 0x00401030\n"
    "int f_b(void) { return 5; }\n"
    "// FUNCTION: alpha 0x00401050\n"
    "int f_mthunk(void) { return 2; }\n"
    "// FUNCTION: alpha 0x00401060\n"
    "int f_c(void) { return 3; }\n"
    "// DATA: alpha 0x00402000\n"
    "int g_table[16];\n";

static void put32(u8 *p, u32 v) { memcpy(p, &v, 4); }

static void reference(const char *path) {
    FakePe pe;
    fake_pe_init(&pe, 0x00400000u);
    u8 text[0x80];
    memset(text, 0xCC, sizeof text);
    static const u8 fa[] = {0x55, 0x8B, 0xEC, 0xE8, 0x28, 0, 0, 0, 0x0F, 0x84, 0x22, 0, 0, 0, 0xA1, 0x00, 0x20, 0x40,
                            0x00, 0x5D, 0xC3};
    static const u8 thunk[] = {0xE9, 0x0B, 0, 0, 0};
    static const u8 fb[] = {0xB8, 5, 0, 0, 0, 0xC3};
    static const u8 iat[] = {0xFF, 0x25, 0x30, 0x30, 0x40, 0x00};
    static const u8 mthunk[] = {0xB9, 0x78, 0x56, 0x34, 0x12, 0xE9, 0xD6, 0xFF, 0xFF, 0xFF};
    static const u8 fc[] = {0xE8, 0xBB, 0xFF, 0xFF, 0xFF, 0xE8, 0xD6, 0xFF, 0xFF, 0xFF, 0xFF, 0x15, 0x30, 0x30,
                            0x40, 0x00, 0xE8, 0xBF, 0xFF, 0xFF, 0xFF, 0xC3};
    memcpy(text + 0x00, fa, sizeof fa);
    memcpy(text + 0x20, thunk, sizeof thunk);
    memcpy(text + 0x30, fb, sizeof fb);
    memcpy(text + 0x40, iat, sizeof iat);
    memcpy(text + 0x50, mthunk, sizeof mthunk);
    memcpy(text + 0x60, fc, sizeof fc);
    u8 data[0x40];
    memset(data, 0, sizeof data);
    put32(data + 0, 0x401020);
    put32(data + 4, 0x401030);
    put32(data + 8, 0x401034);
    put32(data + 12, 0x12345678);
    put32(data + 16, 0x402000);
    put32(data + 20, 0x401050);
    put32(data + 24, SLOT);
    u32 t = fake_pe_section(&pe, ".text", 0x60000020u, text, sizeof text);
    u32 dt = fake_pe_section(&pe, ".data", 0xC0000040u, data, sizeof data);
    fake_pe_import(&pe, "KERNEL32.dll", "Sleep");
    DK_ASSERT(0x400000u + fake_pe_import_slot(&pe, 0) == SLOT);
    fake_pe_reloc(&pe, t + 0x0F);
    fake_pe_reloc(&pe, t + 0x42);
    fake_pe_reloc(&pe, t + 0x6C);
    static const u32 words[] = {0, 4, 8, 16, 20};
    for (size_t i = 0; i < DK_ARRAY_LEN(words); i++) fake_pe_reloc(&pe, dt + words[i]);
    DK_ASSERT(fake_pe_write(&pe, path));
}

static const char CONFIG[] =
    "{\"schema\": \"decompkit-project/1\",\n"
    " \"targets\": {\"alpha\": {\"image\": \"${root}/ref/alpha.exe\", \"sha256\": \"%s\",\n"
    "                         \"symbols\": [{\"kind\": \"tsv\", \"path\": \"${root}/ref/alpha.tsv\"}]}},\n"
    " \"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]},\n"
    " \"annotations\": {\"marker\":\n"
    "  \"^//\\\\s*(?P<kind>FUNCTION|DATA):\\\\s+(?P<target>\\\\w+)\\\\s+(?P<addr>0x[0-9a-fA-F]+)\\\\s*$\",\n"
    "                 \"kinds\": {\"FUNCTION\": \"function\", \"DATA\": \"data\"}}}\n";

static const char *make_repo(void) {
    const char *dir = fwd(dk_mkdtemp(dk_arena(), "disasm-", "", NULL));
    write_text(J(dir, "src/u.c"), UNIT);
    dk_makedirs(J(dir, "ref"), true);
    reference(J(dir, "ref/alpha.exe"));
    write_text(J(dir, "ref/alpha.tsv"),
               "name\tva\tsize\nf_a\t0x401000\t21\nf_b\t0x401030\t6\nf_c\t0x401060\t22\ng_table\t0x402000\t20\n");
    const char *sha = dk_file_digest_hex(dk_arena(), DK_HASH_SHA256, J(dir, "ref/alpha.exe"));
    write_text(J(dir, "config/ctools.json"), dk_sprintf(dk_arena(), CONFIG, sha));
    return dir;
}

static DkDisasm *open_view(const char *root) {
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    CHECK_MSG(p != NULL, "%s", err.msg);
    DK_ASSERT(p);
    DkDisasm *d = dk_disasm_open(p, 0, &err);
    CHECK_MSG(d != NULL, "%s", err.msg);
    DK_ASSERT(d);
    return d;
}

static bool has(const DkBuf *b, const char *needle) {
    return strstr(dk_buf_cz((DkBuf *)b), needle) != NULL;
}

DK_TEST(sites_and_bounds) {
    const char *root = make_repo();
    DkDisasm *d = open_view(root);
    CHECK_EQ_U64(dk_disasm_image_base(d), 0x400000);

    DkU32Vec targets = {0};
    dk_vec_push(&targets, 0x401030);
    DkIMap *m = dk_disasm_rel32_sites(d, &targets, DK_DISASM_ALL);
    const DkVal *v = dk_imap_get(m, 0x401030);
    REQUIRE(v);
    const DkDisasmSiteVec *sv = v->p;
    REQUIRE(sv->n == 4);
    static const DkDisasmSite want[4] = {{0x401003, DK_DISASM_CALL}, {0x401008, DK_DISASM_JCC},
                                         {0x401020, DK_DISASM_JMP}, {0x401055, DK_DISASM_JMP}};
    for (size_t i = 0; i < 4; i++) {
        CHECK_EQ_U64(sv->v[i].site, want[i].site);
        CHECK_EQ_U64(sv->v[i].kind, want[i].kind);
    }
    DkIMap *calls = dk_disasm_rel32_sites(d, &targets, DK_DISASM_CALL);
    CHECK_EQ_U64(((const DkDisasmSiteVec *)dk_imap_get(calls, 0x401030)->p)->n, 1);
    dk_vec_free(&targets);

    const DkU32Vec *starts = dk_disasm_known_starts(d);
    REQUIRE(starts->n == 4);
    CHECK_EQ_U64(starts->v[0], 0x401000);
    CHECK_EQ_U64(starts->v[1], 0x401030);
    CHECK_EQ_U64(starts->v[2], 0x401050);
    CHECK_EQ_U64(starts->v[3], 0x401060);

    DkErr err = {0};
    u32 size;
    REQUIRE(dk_disasm_guess_size(d, 0x401000, DK_DISASM_GUESS_LIMIT, &size, &err));
    CHECK_EQ_U64(size, 0x15);
    REQUIRE(dk_disasm_guess_size(d, 0x401020, DK_DISASM_GUESS_LIMIT, &size, &err));
    CHECK_EQ_U64(size, 5);
    CHECK(!dk_disasm_guess_size(d, 0x900000, 16, &size, &err));
    DkDisasmBounds b;
    REQUIRE(dk_disasm_function_bounds(d, 0x401000, DK_DISASM_BOUNDS_LIMIT, &b, &err));
    CHECK_EQ_U64(b.size, 0x15);
    CHECK_CZ(b.why, "to the int3 padding");
    REQUIRE(dk_disasm_function_bounds(d, 0x401000, 0x10, &b, &err));
    CHECK_EQ_U64(b.size, 0x0E);

    u32 start;
    const char *name;
    REQUIRE(dk_disasm_containing_function(d, 0x401034, &start, &name));
    CHECK_EQ_U64(start, 0x401030);
    CHECK_CZ(name, "f_b");
    CHECK(!dk_disasm_containing_function(d, 0x401020, &start, &name));
    dk_tempdir_cleanup(root);
}

DK_TEST(listing_notes) {
    const char *root = make_repo();
    DkDisasm *d = open_view(root);
    DkErr err = {0};
    DkBuf out;
    dk_buf_init(&out, dk_arena());
    REQUIRE(dk_disasm_function(d, 0x401000, 0x15, true, &out, &err));
    CHECK(has(&out, "; alpha 00401000  21 bytes  f_a\n"));
    CHECK(has(&out, "00401003  E8 28 00 00 00"));
    CHECK(has(&out, "call 0x401030  ; f_b"));
    CHECK(has(&out, "dword ptr [0x402000]  ; g_table"));
    dk_buf_clear(&out);
    REQUIRE(dk_disasm_function(d, 0x401060, 0x16, false, &out, &err));
    CHECK(has(&out, "call 0x401020\n"));
    CHECK(has(&out, "call 0x401040  ; Sleep (import thunk)"));
    CHECK(has(&out, "dword ptr [0x403030]  ; __imp_Sleep"));
    CHECK(has(&out, "call 0x401034  ; f_b+0x4"));
    CHECK(!has(&out, "E8 BB"));
    CHECK(!dk_disasm_function(d, 0x900000, 4, true, &out, &err));
    dk_tempdir_cleanup(root);
}

DK_TEST(xrefs_words_thunks_names) {
    const char *root = make_repo();
    DkDisasm *d = open_view(root);
    DkErr err = {0};
    DkBuf out;
    dk_buf_init(&out, dk_arena());
    REQUIRE(dk_disasm_xrefs(d, 0x401030, &out, &err));
    CHECK(has(&out, "; callers of 00401030 (call rel32): 1\n  00401003  in f_a (00401000)\n"));
    CHECK(has(&out, "; jumps to 00401030 (jmp rel32): 2\n"));
    CHECK(has(&out, "; conditional jumps to 00401030 (jcc rel32): 1\n"));
    CHECK(has(&out, "; absolute references (relocated words) to 00401030: 1\n  00402004  in .data\n"));

    dk_buf_clear(&out);
    REQUIRE(dk_disasm_words(d, 0x402000, 8, &out));
    CHECK(has(&out, "; alpha 00402000  8 dword(s)  .data\n; data g_table\n"));
    CHECK(has(&out, "00402000  +0x0    [0]    00401020  reloc  \n") || has(&out, "[0]    00401020  reloc"));
    CHECK(has(&out, "[1]    00401030  reloc  function f_b"));
    CHECK(has(&out, "[2]    00401034  reloc  f_b+0x4"));
    CHECK(has(&out, "[3]    12345678       "));
    CHECK(has(&out, "[4]    00402000  reloc  data g_table"));
    CHECK(has(&out, "[5]    00401050  reloc  function f_mthunk"));
    CHECK(has(&out, "[6]    00403030         __imp_Sleep"));

    DkDisasmThunkVec rows = dk_disasm_hidden_thunks(d, 0, 0, false);
    REQUIRE(rows.n == 1);
    CHECK_EQ_U64(rows.v[0].va, 0x401020);
    CHECK_EQ_U64(rows.v[0].target, 0x401030);
    CHECK_CZ(rows.v[0].form, "jmp");
    CHECK_EQ_U64(rows.v[0].refs.n, 1);
    CHECK_EQ_U64(rows.v[0].calls.n, 1);
    DkDisasmThunkVec all = dk_disasm_hidden_thunks(d, 0, 0, true);
    REQUIRE(all.n == 2);
    CHECK_EQ_U64(all.v[1].va, 0x401050);
    CHECK(all.v[1].has_this && all.v[1].this_ == 0x12345678 && all.v[1].known);
    CHECK_CZ(all.v[1].form, "mov ecx; jmp");
    dk_buf_clear(&out);
    dk_disasm_print_thunks(d, 0, 0, false, &out);
    CHECK(has(&out, "; 1 jmp thunk(s) no symbol names\n00401020  jmp"));
    CHECK(has(&out, "-> 00401030 f_b"));

    const char *form;
    u32 target, this_;
    bool has_this;
    CHECK(!dk_disasm_jmp_thunk(d, 0x401000, &form, &target, &this_, &has_this));
    CHECK(dk_disasm_jmp_thunk(d, 0x401020, &form, &target, &this_, &has_this) && target == 0x401030);

    dk_buf_clear(&out);
    REQUIRE(dk_disasm_find_names(d, "^F_[ab]$", &out, &err));
    CHECK(has(&out, "00401000      21  f_a\n00401030       6  f_b\n"));
    CHECK(!has(&out, "f_c"));
    CHECK(!dk_disasm_find_names(d, "(", &out, &err));
    dk_tempdir_cleanup(root);
}

static int run_main(const char *const *args, size_t n) {
    char **argv = DK_NEWN(dk_arena(), char *, n + 2);
    argv[0] = "disasm";
    for (size_t i = 0; i < n; i++) argv[i + 1] = (char *)args[i];
    return dk_disasm_main((int)n + 1, argv);
}

DK_TEST(command_line) {
    const char *root = make_repo();
    const char *a1[] = {"--root", root, "alpha", "0x401000"};
    CHECK_EQ_I64(run_main(a1, DK_ARRAY_LEN(a1)), 0);
    const char *a2[] = {"--root", root, "alpha", "401030", "--xref"};
    CHECK_EQ_I64(run_main(a2, DK_ARRAY_LEN(a2)), 0);
    const char *a3[] = {"--root", root, "alpha", "402000", "--data"};
    CHECK_EQ_I64(run_main(a3, DK_ARRAY_LEN(a3)), 0);
    const char *a4[] = {"--root", root, "alpha", "--thunks", "--all"};
    CHECK_EQ_I64(run_main(a4, DK_ARRAY_LEN(a4)), 0);
    const char *a5[] = {"--root", root, "alpha", "--name", "f_"};
    CHECK_EQ_I64(run_main(a5, DK_ARRAY_LEN(a5)), 0);
    const char *a6[] = {"--root", root, "beta", "0x401000"};
    CHECK_EQ_I64(run_main(a6, DK_ARRAY_LEN(a6)), 2);
    const char *a7[] = {"--root", root, "alpha"};
    CHECK_EQ_I64(run_main(a7, DK_ARRAY_LEN(a7)), 2);
    const char *a8[] = {"--root", root, "alpha", "0x900000"};
    CHECK_EQ_I64(run_main(a8, DK_ARRAY_LEN(a8)), 1);
    dk_tempdir_cleanup(root);
}

DK_TEST_MAIN("disasm_lib")
