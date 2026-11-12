// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* A temporary repository for the scorer and float_order tests, on the fake toolchain (tests/fakecl/fake_tools.h): one
 * unit holding one float function whose source is `return <expr>;`, a synthetic reference image whose function sums
 * two products as a*b + c*d, and canned objects for the source texts a test registers. Names and addresses are made
 * up; the bytes are hand-assembled SSE. */
#pragma once
#include "dk/dk.h"
#include "dk/test.h"
#include "fakecl/fake_tools.h"
#include "fixtures/synth_coff.h"
#include "project.h"

#include <string.h>
#include <windows.h>

static const char *fo_J(const char *a, const char *b) { return dk_join(dk_arena(), a, b); }

static void fo_write_text(const char *path, const char *text) {
    dk_makedirs(dk_cz(dk_arena(), dk_path_dirname(path)), true);
    DK_ASSERT(dk_write_file(path, text, strlen(text)));
}

static const char *fo_fwd(const char *p) {
    char *s = dk_strdup(dk_arena(), p);
    for (char *c = s; *c; c++)
        if (*c == '\\') *c = '/';
    return s;
}

/* movss xmm0,[esp+4]; mulss xmm0,[esp+8]; movss xmm1,[esp+0Ch]; mulss xmm1,[esp+10h]; addss xmm0,xmm1; ret */
static const u8 FO_REF[29] = {0xF3, 0x0F, 0x10, 0x44, 0x24, 0x04, 0xF3, 0x0F, 0x59, 0x44, 0x24, 0x08, 0xF3, 0x0F, 0x10,
                              0x4C, 0x24, 0x0C, 0xF3, 0x0F, 0x59, 0x4C, 0x24, 0x10, 0xF3, 0x0F, 0x58, 0xC1, 0xC3};
/* the same with the sum's operands swapped: addss xmm1,xmm0; movaps xmm0,xmm1; ret */
static const u8 FO_COMMUTED[32] = {0xF3, 0x0F, 0x10, 0x44, 0x24, 0x04, 0xF3, 0x0F, 0x59, 0x44, 0x24, 0x08,
                                   0xF3, 0x0F, 0x10, 0x4C, 0x24, 0x0C, 0xF3, 0x0F, 0x59, 0x4C, 0x24, 0x10,
                                   0xF3, 0x0F, 0x58, 0xC8, 0x0F, 0x28, 0xC1, 0xC3};
/* a different instruction in the middle: not a MATCH, not a commuted sum */
static const u8 FO_SUBBED[29] = {0xF3, 0x0F, 0x10, 0x44, 0x24, 0x04, 0xF3, 0x0F, 0x59, 0x44, 0x24, 0x08, 0xF3, 0x0F, 0x10,
                                 0x4C, 0x24, 0x0C, 0xF3, 0x0F, 0x59, 0x4C, 0x24, 0x10, 0xF3, 0x0F, 0x5C, 0xC1, 0xC3};

#define REQUIRE_MSG(cond, ...)                \
    do {                                      \
        bool ok_ = (cond);                    \
        CHECK_MSG(ok_, __VA_ARGS__);          \
        if (!ok_) return;                     \
    } while (0)

#define FO_ADDR 0x00401000u

static const char FO_HEAD[] = "// FUNCTION: alpha 0x00401000\nfloat f_flt(float a, float b, float c, float d)\n{\n";

/* The unit as it is on disk, and as the search writes a candidate (the lines joined and one more newline). */
static const char *fo_unit_text(const char *expr) {
    return dk_sprintf(dk_arena(), "%s    return %s;\n}\n", FO_HEAD, expr);
}
static const char *fo_candidate_text(const char *expr) {
    return dk_sprintf(dk_arena(), "%s    return %s;\n}\n\n", FO_HEAD, expr);
}

static DkStr fo_object(const u8 *code, size_t n) {
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 t = synth_coff_section(&sc, ".text", 0x60500020u, code, n);
    synth_coff_symbol(&sc, "_f_flt", 0, (i16)t, 0x20, 2, 0);
    return synth_coff_build(&sc);
}

static void fo_register(const char *root, const char *text, const u8 *code, size_t n) {
    DK_ASSERT(fake_cl_register(fo_J(root, "fakereg"), fake_cl_key(dk_str(text), NULL, 0, ""), fo_object(code, n)));
}

static const char FO_CONFIG[] =
    "{\"schema\": \"decompkit-project/1\",\n"
    " \"targets\": {\"alpha\": {\"image\": \"${root}/ref/alpha.exe\", \"sha256\": \"%s\",\n"
    "                         \"symbols\": [{\"kind\": \"tsv\", \"path\": \"${root}/ref/alpha.tsv\"}]}},\n"
    " \"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]},\n"
    " \"compiler\": {\"cl\": \"${root}/bin/fakecl.exe\", \"env\": {\"FAKECL_REGISTRY\": \"${root}/fakereg\"},\n"
    "              \"base_flags\": [\"/nologo\", \"/c\"]},\n"
    " \"backend\": {\"kind\": \"object\"},\n"
    " \"annotations\": {\"marker\":\n"
    "  \"^//\\\\s*(?P<kind>FUNCTION):\\\\s+(?P<target>\\\\w+)\\\\s+(?P<addr>0x[0-9a-fA-F]+)\\\\s*$\",\n"
    "                 \"kinds\": {\"FUNCTION\": \"function\"}}}\n";

/* The repository: the unit with the expression a*b + c*d (compiled to the commuted sum), the reference, the
 * configuration. The test registers the objects of the candidates it expects. */
static const char *fo_make_repo(const char *prefix) {
    const char *dir = fo_fwd(dk_mkdtemp(dk_arena(), prefix, "", NULL));
    wchar_t self[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, self, MAX_PATH);
    DK_ASSERT(n > 0 && n < MAX_PATH);
    char me[MAX_PATH * 3];
    WideCharToMultiByte(CP_UTF8, 0, self, -1, me, (int)sizeof me, NULL, NULL);
    dk_makedirs(fo_J(dir, "bin"), true);
    DK_ASSERT(dk_copyfile(me, fo_J(dir, "bin/fakecl.exe")));
    fo_write_text(fo_J(dir, "src/u.c"), fo_unit_text("a * b + c * d"));
    fo_register(dir, fo_unit_text("a * b + c * d"), FO_COMMUTED, sizeof FO_COMMUTED);
    dk_makedirs(fo_J(dir, "ref"), true);
    FakePe pe;
    fake_pe_init(&pe, 0x00400000u);
    u8 text[0x40];
    memset(text, 0xCC, sizeof text);
    memcpy(text, FO_REF, sizeof FO_REF);
    fake_pe_section(&pe, ".text", 0x60000020u, text, sizeof text);
    DK_ASSERT(fake_pe_write(&pe, fo_J(dir, "ref/alpha.exe")));
    fo_write_text(fo_J(dir, "ref/alpha.tsv"), "name\tva\tsize\n_f_flt\t0x401000\t29\n");
    const char *sha = dk_file_digest_hex(dk_arena(), DK_HASH_SHA256, fo_J(dir, "ref/alpha.exe"));
    fo_write_text(fo_J(dir, "config/ctools.json"), dk_sprintf(dk_arena(), FO_CONFIG, sha));
    return dir;
}
