// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The adapter's build and compare half end to end, on a temporary repository whose compiler and linker are this test
 * executable copied as fakecl.exe and fakelink.exe (tests/fakecl/fake_tools.h). The reference images, symbol files,
 * referents, canned objects and manifests are synthetic and written at test time; names and addresses are made up.
 *
 *   object    one unit whose canned object holds a function for each status (MATCH, DIFF, SIZE, REFERENT,
 *             UNRESOLVED) and every relocation verdict: a call through an annotation, an import by name, a string
 *             compared by content (same and other), a referents entry, a well-known symbol, a symbol-source name, an
 *             unknown name and a switch-table word inside the function; one annotation with no compiled symbol
 *             (MISSING) and one unit that fails to compile (ERROR).
 *   link      discovery and /GL compiles, the fake link, the map, base relocations and rel32 branches, padding
 *             trimmed against sized symbols: every candidate MATCH against a reference linked at another base.
 *   manifest  the same candidates read from a synthetic manifest (one candidate of another unit left out). */
#include "dk/dk.h"
#include "dk/test.h"
#include "project.h"
#include "fakecl/fake_tools.h"
#include "fixtures/synth_coff.h"

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

/* A temporary repository with bin/fakecl.exe and bin/fakelink.exe. */
static const char *repo(const char *prefix) {
    const char *dir = fwd(dk_mkdtemp(dk_arena(), prefix, "", NULL));
    wchar_t self[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, self, MAX_PATH);
    DK_ASSERT(n > 0 && n < MAX_PATH);
    char me[MAX_PATH * 3];
    WideCharToMultiByte(CP_UTF8, 0, self, -1, me, (int)sizeof me, NULL, NULL);
    dk_makedirs(J(dir, "bin"), true);
    DK_ASSERT(dk_copyfile(me, J(dir, "bin/fakecl.exe")));
    DK_ASSERT(dk_copyfile(me, J(dir, "bin/fakelink.exe")));
    return dir;
}

static const char *sha_of(const char *path) { return dk_file_digest_hex(dk_arena(), DK_HASH_SHA256, path); }

static DkProject *load(const char *root, const char *config) {
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, config ? J(root, config) : NULL, &err);
    CHECK_MSG(p != NULL, "%s", err.msg);
    return p;
}

static void put32(u8 *p, u32 v) { memcpy(p, &v, 4); }

static const DkResult *result_named(const DkResult *rs, size_t n, const char *name) {
    for (size_t i = 0; i < n; i++)
        if (rs[i].ann && rs[i].ann->name && strcmp(rs[i].ann->name, name) == 0) return &rs[i];
    return NULL;
}

static const DkRefCheck *ref_named(const DkResult *r, const char *name) {
    for (size_t i = 0; r && i < r->n_refs; i++)
        if (r->refs[i].name && strcmp(r->refs[i].name, name) == 0) return &r->refs[i];
    return NULL;
}

#define CHECK_STATUS(rs, n, name, st)                                                                          \
    do {                                                                                                     \
        const DkResult *r_ = result_named((rs), (n), (name));                                                \
        CHECK_MSG(r_ && r_->status == (st), "%s: %s, expected %s (%s)", (name),                              \
                  r_ ? dk_status_name(r_->status) : "absent", dk_status_name(st),                            \
                  r_ && r_->error ? r_->error : "");                                                         \
    } while (0)

#define CHECK_VERDICT(r, name, v)                                                                              \
    do {                                                                                                     \
        const DkRefCheck *c_ = ref_named((r), (name));                                                       \
        CHECK_MSG(c_ && c_->verdict == (v), "%s: verdict %d, expected %d", (name), c_ ? (int)c_->verdict : -1, \
                  (int)(v));                                                                                 \
    } while (0)

/* ---- the object backend ---------------------------------------------------------------------------------------- */

static const char OBJ_UNIT[] =
    "// FUNCTION: alpha 0x00401000\n"
    "int f_match(void) { return f_callee(); }\n"
    "// FUNCTION: alpha 0x00401020\n"
    "int f_diff(void) { return 1; }\n"
    "// FUNCTION: alpha 0x00401040\n"
    "int f_size(void) { return 3; }\n"
    "// FUNCTION: alpha 0x00401060\n"
    "int f_ref(void) { return 0; }\n"
    "// FUNCTION: alpha 0x00401080\n"
    "int f_unres(void) { return g_nowhere; }\n"
    "// FUNCTION: alpha 0x004010A0\n"
    "int f_missing(void) { return 0; }\n"
    "// FUNCTION: alpha 0x004010C0\n"
    "int f_callee(void) { return 0; }\n";

static const char BAD_UNIT[] = "// FUNCTION: alpha 0x004010E0\nint f_bad(void) { return 0; }\n#error synthetic\n";

/* The canned object of OBJ_UNIT: one .text holding the functions back to back, one .data with two strings. */
static DkStr obj_unit_object(void) {
    u8 code[64];
    memset(code, 0, sizeof code);
    static const u8 match[17] = {0xE8, 0, 0, 0, 0, 0xFF, 0x15, 0, 0, 0, 0, 0x68, 0, 0, 0, 0, 0xC3};
    static const u8 diff[6] = {0xB8, 1, 0, 0, 0, 0xC3};
    static const u8 size[7] = {0xB8, 3, 0, 0, 0, 0x90, 0xC3};
    static const u8 ref[21] = {0x68, 0, 0, 0, 0, 0xA1, 0, 0, 0, 0, 0xA1, 0, 0, 0, 0, 0xA1, 0, 0, 0, 0, 0xC3};
    static const u8 unres[6] = {0xA1, 0, 0, 0, 0, 0xC3};
    static const u8 callee[7] = {0xB8, 0, 0, 0, 0, 0xC3, 0x90};
    memcpy(code + 0, match, 17);
    memcpy(code + 17, diff, 6);
    memcpy(code + 23, size, 7);
    memcpy(code + 30, ref, 21);
    memcpy(code + 51, unres, 6);
    memcpy(code + 57, callee, 7);
    put32(code + 58, 57 + 6); /* the section symbol's addend: a word inside f_callee */
    static const u8 data[8] = {'h', 'i', 0, 0, 'y', 'o', 0, 0};
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 text = synth_coff_section(&sc, ".text", 0x60500020u, code, sizeof code);
    u32 dat = synth_coff_section(&sc, ".data", 0xC0300040u, data, sizeof data);
    u32 s_text = synth_coff_symbol(&sc, ".text", 0, (i16)text, 0, 3, 0);
    synth_coff_symbol(&sc, ".data", 0, (i16)dat, 0, 3, 0);
    synth_coff_symbol(&sc, "_f_match", 0, (i16)text, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_diff", 17, (i16)text, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_size", 23, (i16)text, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_ref", 30, (i16)text, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_unres", 51, (i16)text, 0x20, 2, 0);
    u32 s_callee = synth_coff_symbol(&sc, "_f_callee", 57, (i16)text, 0x20, 2, 0);
    u32 s_sg1 = synth_coff_symbol(&sc, "$SG1", 0, (i16)dat, 0, 3, 0);
    u32 s_sg2 = synth_coff_symbol(&sc, "$SG2", 4, (i16)dat, 0, 3, 0);
    u32 s_imp = synth_coff_symbol(&sc, "__imp__Sleep@4", 0, 0, 0, 2, 0);
    u32 s_known = synth_coff_symbol(&sc, "_g_known", 0, 0, 0, 2, 0);
    u32 s_guard = synth_coff_symbol(&sc, "___guard", 0, 0, 0, 2, 0);
    u32 s_tsv = synth_coff_symbol(&sc, "_g_tsv", 0, 0, 0, 2, 0);
    u32 s_nowhere = synth_coff_symbol(&sc, "_g_nowhere", 0, 0, 0, 2, 0);
    synth_coff_reloc(&sc, text, 1, s_callee, 0x14);
    synth_coff_reloc(&sc, text, 7, s_imp, 0x06);
    synth_coff_reloc(&sc, text, 12, s_sg1, 0x06);
    synth_coff_reloc(&sc, text, 31, s_sg2, 0x06);
    synth_coff_reloc(&sc, text, 36, s_known, 0x06);
    synth_coff_reloc(&sc, text, 41, s_guard, 0x06);
    synth_coff_reloc(&sc, text, 46, s_tsv, 0x06);
    synth_coff_reloc(&sc, text, 52, s_nowhere, 0x06);
    synth_coff_reloc(&sc, text, 58, s_text, 0x06);
    return synth_coff_build(&sc);
}

/* The reference image of the object test (base 0x00400000): .text, .data, then KERNEL32.dll!Sleep. */
static void obj_reference(const char *path) {
    FakePe pe;
    fake_pe_init(&pe, 0x00400000u);
    u8 text[0x100];
    memset(text, 0xCC, sizeof text);
    u8 data[0x300];
    memset(data, 0, sizeof data);
    memcpy(data + 0x000, "hi\0\0", 4);
    memcpy(data + 0x010, "no\0\0", 4);
    /* the IAT slot is known once the sections are in: lay out .text and .data first, patch .text after */
    u32 text_rva = fake_pe_section(&pe, ".text", 0x60000020u, text, sizeof text);
    fake_pe_section(&pe, ".data", 0xC0000040u, data, sizeof data);
    fake_pe_import(&pe, "KERNEL32.dll", "Sleep");
    u32 iat = 0x00400000u + fake_pe_import_slot(&pe, 0);
    u8 *t = pe.secs[0].data.v;
    static const u8 match[17] = {0xE8, 0xBB, 0, 0, 0, 0xFF, 0x15, 0, 0, 0, 0, 0x68, 0x00, 0x20, 0x40, 0x00, 0xC3};
    memcpy(t + 0x00, match, 17);
    put32(t + 0x07, iat);
    static const u8 diff[6] = {0xB8, 2, 0, 0, 0, 0xC3};
    memcpy(t + 0x20, diff, 6);
    static const u8 size[6] = {0xB8, 3, 0, 0, 0, 0xC3};
    memcpy(t + 0x40, size, 6);
    static const u8 ref[21] = {0x68, 0x10, 0x20, 0x40, 0x00, 0xA1, 0x08, 0x21, 0x40, 0x00, 0xA1, 0x00, 0x21,
                               0x40, 0x00, 0xA1, 0x00, 0x22, 0x40, 0x00, 0xC3};
    memcpy(t + 0x60, ref, 21);
    static const u8 unres[6] = {0xA1, 0x34, 0x12, 0x40, 0x00, 0xC3};
    memcpy(t + 0x80, unres, 6);
    static const u8 callee[7] = {0xB8, 0xC6, 0x10, 0x40, 0x00, 0xC3, 0x90};
    memcpy(t + 0xC0, callee, 7);
    (void)text_rva;
    DK_ASSERT(fake_pe_write(&pe, path));
}

static const char OBJ_CONFIG[] =
    "{\"schema\": \"decompkit-project/1\",\n"
    " \"targets\": {\"alpha\": {\"image\": \"${root}/ref/alpha.exe\", \"sha256\": \"%s\",\n"
    "                         \"symbols\": [{\"kind\": \"tsv\", \"path\": \"${root}/ref/alpha.tsv\"}]}},\n"
    " \"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]},\n"
    " \"compiler\": {\"cl\": \"${root}/bin/fakecl.exe\", \"env\": {\"FAKECL_REGISTRY\": \"${root}/fakereg\"},\n"
    "              \"base_flags\": [\"/nologo\", \"/c\", \"/O2\"]},\n"
    " \"backend\": {\"kind\": \"object\"},\n"
    " \"annotations\": {\"marker\":\n"
    "  \"^//\\\\s*(?P<kind>FUNCTION|DATA):\\\\s+(?P<target>\\\\w+)\\\\s+(?P<addr>0x[0-9a-fA-F]+)\\\\s*$\",\n"
    "                 \"kinds\": {\"FUNCTION\": \"function\", \"DATA\": \"data\"}},\n"
    " \"referents\": [{\"file\": \"${root}/ref/known_addresses.json\", \"format\": \"json-symbols\"}],\n"
    " \"well_known\": {\"imports\": true, \"symbols\": [\"___guard\"]}}\n";

DK_TEST(object_backend_statuses_and_verdicts) {
    const char *root = repo("project_compare-obj-");
    write_text(J(root, "src/u.c"), OBJ_UNIT);
    write_text(J(root, "src/bad.c"), BAD_UNIT);
    REQUIRE(fake_cl_register(J(root, "fakereg"), fake_cl_key(dk_str(OBJ_UNIT), NULL, 0, ""), obj_unit_object()));
    dk_makedirs(J(root, "ref"), true);
    obj_reference(J(root, "ref/alpha.exe"));
    write_text(J(root, "ref/alpha.tsv"),
               "name\tva\tsize\n_f_match\t0x401000\t17\n_f_diff\t0x401020\t6\n_f_size\t0x401040\t6\n"
               "_f_ref\t0x401060\t21\n__guard\t0x402100\t4\n_g_tsv\t0x402104\t4\n");
    write_text(J(root, "ref/known_addresses.json"),
               "{\"_note\": \"synthetic\", \"_g_known\": {\"alpha\": \"0x00402108\"}}\n");
    write_text(J(root, "config/ctools.json"), dk_sprintf(dk_arena(), OBJ_CONFIG, sha_of(J(root, "ref/alpha.exe"))));
    DkProject *p = load(root, NULL);
    REQUIRE(p);

    size_t nref = 0;
    const DkReferentFile *rfs = dk_project_referents(p, &nref);
    CHECK_MSG(nref == 1, "referents %zu %s %s", nref, nref ? rfs[0].file : "", nref ? rfs[0].format : "");
    const DkUnit *u = dk_project_unit(p, "src/u.c");
    REQUIRE(u);
    DkBuildOpts o = {0};
    size_t n = 0;
    DkErr err = {0};
    DkResult *rs = dk_compare_unit(p, u, 0, &o, &n, &err);
    REQUIRE(rs);
    CHECK_EQ_U64(n, 7);
    CHECK_STATUS(rs, n, "f_match", DK_MATCH);
    CHECK_STATUS(rs, n, "f_diff", DK_DIFF);
    CHECK_STATUS(rs, n, "f_size", DK_SIZE);
    CHECK_STATUS(rs, n, "f_ref", DK_REFERENT);
    CHECK_STATUS(rs, n, "f_unres", DK_UNRESOLVED);
    CHECK_STATUS(rs, n, "f_missing", DK_MISSING);
    CHECK_STATUS(rs, n, "f_callee", DK_MATCH);

    const DkResult *m = result_named(rs, n, "f_match");
    CHECK_VERDICT(m, "_f_callee", DK_REF_SAME);       /* an annotation */
    CHECK_VERDICT(m, "__imp__Sleep@4", DK_REF_SAME);  /* an import by name */
    CHECK_VERDICT(m, "$SG1", DK_REF_SAME);            /* compiler-made data, same content */
    const DkRefCheck *call = ref_named(m, "_f_callee");
    CHECK(call && call->ours == 0x004010C0u && call->theirs == 0x004010C0u);
    const DkResult *rf = result_named(rs, n, "f_ref");
    CHECK_VERDICT(rf, "$SG2", DK_REF_OTHER);          /* other content */
    CHECK_VERDICT(rf, "_g_known", DK_REF_SAME);       /* a referents entry */
    CHECK_VERDICT(rf, "___guard", DK_REF_SAME);       /* a well-known symbol, one underscore less in the source */
    CHECK_VERDICT(rf, "_g_tsv", DK_REF_OTHER);        /* a symbol-source name, the word points elsewhere */
    const DkRefCheck *tsv = ref_named(rf, "_g_tsv");
    CHECK(tsv && tsv->ours == 0x00402104u && tsv->theirs == 0x00402200u);
    CHECK_VERDICT(result_named(rs, n, "f_unres"), "_g_nowhere", DK_REF_UNRESOLVED);
    const DkResult *c = result_named(rs, n, "f_callee");
    CHECK_VERDICT(c, "_f_callee", DK_REF_SAME);       /* the function itself: a word inside it */
    CHECK(c && c->n_refs == 1 && c->refs[0].ours == 0x004010C0u);

    /* a unit that does not compile: every annotation ERROR, the compiler's line in the message */
    const DkUnit *bad = dk_project_unit(p, "src/bad.c");
    REQUIRE(bad);
    size_t nb = 0;
    DkResult *rb = dk_compare_unit(p, bad, 0, &o, &nb, &err);
    REQUIRE(rb && nb == 1);
    CHECK_STATUS(rb, nb, "f_bad", DK_ERROR);
    CHECK_MSG(rb[0].error && strstr(rb[0].error, "C1189"), "error: %s", rb[0].error ? rb[0].error : "-");
    CHECK(err.code != 0);

    /* dk_build_unit and dk_compare on their own; MISSING without an address in the target */
    size_t nf = 0;
    DkStr log = {0};
    DkFunc *fns = dk_build_unit(p, u, 0, &o, &nf, &log, &err);
    REQUIRE(fns);
    CHECK_EQ_U64(nf, 6);
    CHECK_MSG(dk_str_find(log, DK_S("u.c"), 0, DK_END) >= 0, "log: %.*s", DK_SF(log));
    size_t na = 0;
    DkAnnot *anns = dk_annotations(p, u, &na, &err);
    REQUIRE(anns && na == 7);
    DkAnnot none = anns[0];
    none.target_mask = 0;
    none.addr[0] = DK_NO_ADDR;
    DkResult *r = dk_compare(p, &none, 0, &fns[0], &err);
    CHECK(r && r->status == DK_MISSING);
    r = dk_compare(p, &anns[0], 0, NULL, &err);
    CHECK(r && r->status == DK_MISSING);
    r = dk_compare(p, &anns[0], 0, &fns[0], &err);
    CHECK(r && r->status == DK_MATCH && r->theirs_va == 0x00401000u && r->theirs.n == 17);

    /* the image: names, sizes, an unreadable range */
    DkImage *im = dk_target_image(p, 0, &err);
    REQUIRE(im);
    u32 start = 0;
    CHECK_CZ(dk_image_name_at(im, 0x00401063u, &start), "_f_ref");
    CHECK_EQ_U64(start, 0x00401060u);
    u32 fsize = 0;
    CHECK(dk_image_function_size(im, 0x00401040u, &fsize) && fsize == 6);
    DkStr bytes;
    CHECK(!dk_image_read(im, 0x00500000u, 4, &bytes));
    CHECK(dk_image_read(im, 0x00401020u, 6, &bytes) && (u8)bytes.p[1] == 2);

    CHECK_CZ(dk_status_name(DK_UNRESOLVED), "UNRESOLVED");
    CHECK_CZ(dk_status_name(DK_SIZE), "SIZE");
    dk_tempdir_cleanup(root);
}

DK_TEST(object_backend_pinned_hash) {
    const char *root = repo("project_compare-sha-");
    write_text(J(root, "src/u.c"), OBJ_UNIT);
    REQUIRE(fake_cl_register(J(root, "fakereg"), fake_cl_key(dk_str(OBJ_UNIT), NULL, 0, ""), obj_unit_object()));
    dk_makedirs(J(root, "ref"), true);
    obj_reference(J(root, "ref/alpha.exe"));
    write_text(J(root, "ref/alpha.tsv"), "name\tva\tsize\n");
    write_text(J(root, "ref/known_addresses.json"), "{}\n");
    write_text(J(root, "config/ctools.json"),
               dk_sprintf(dk_arena(), OBJ_CONFIG, "00000000000000000000000000000000000000000000000000000000000000ff"));
    DkProject *p = load(root, NULL);
    REQUIRE(p);
    DkErr err = {0};
    CHECK(dk_target_image(p, 0, &err) == NULL && strstr(err.msg, "sha256"));
    size_t n = 0;
    DkBuildOpts o = {0};
    DkResult *rs = dk_compare_unit(p, dk_project_unit(p, "src/u.c"), 0, &o, &n, &err);
    REQUIRE(rs && n == 7);
    CHECK_STATUS(rs, n, "f_match", DK_ERROR);
    dk_tempdir_cleanup(root);
}

/* ---- the link and manifest backends ----------------------------------------------------------------------------- */

static const char LINK_UNIT[] =
    "// FUNCTION: beta 0x20001000\n"
    "int l_main(void) { return l_leaf(); }\n"
    "// FUNCTION: beta 0x20001020\n"
    "int l_leaf(void) { return 0; }\n";

/* Two code sections (one per function), a string, an import. */
static DkStr link_unit_object(void) {
    static const u8 main_code[17] = {0xE8, 0, 0, 0, 0, 0x68, 0, 0, 0, 0, 0xFF, 0x15, 0, 0, 0, 0, 0xC3};
    static const u8 leaf_code[3] = {0x31, 0xC0, 0xC3};
    static const u8 data[4] = {'o', 'k', 0, 0};
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 t1 = synth_coff_section(&sc, ".text$a", 0x60501020u, main_code, sizeof main_code);
    u32 t2 = synth_coff_section(&sc, ".text$b", 0x60501020u, leaf_code, sizeof leaf_code);
    u32 d = synth_coff_section(&sc, ".data", 0xC0300040u, data, sizeof data);
    synth_coff_symbol(&sc, "_l_main", 0, (i16)t1, 0x20, 2, 0);
    u32 s_leaf = synth_coff_symbol(&sc, "_l_leaf", 0, (i16)t2, 0x20, 2, 0);
    u32 s_sg = synth_coff_symbol(&sc, "$SG3", 0, (i16)d, 0, 3, 0);
    u32 s_imp = synth_coff_symbol(&sc, "__imp__Sleep@4", 0, 0, 0, 2, 0);
    synth_coff_reloc(&sc, t1, 1, s_leaf, 0x14);
    synth_coff_reloc(&sc, t1, 6, s_sg, 0x06);
    synth_coff_reloc(&sc, t1, 12, s_imp, 0x06);
    return synth_coff_build(&sc);
}

/* The reference: the same object linked at 0x20000000, its symbols in a TSV with the functions' true sizes. */
static void link_reference(const char *root) {
    const char *obj = J(root, "ref/beta-src.obj");
    DkStr o = link_unit_object();
    dk_makedirs(J(root, "ref"), true);
    DK_ASSERT(dk_write_file(obj, o.p, o.n));
    const char *objs[1] = {obj};
    DK_ASSERT(fake_link(objs, 1, 0x20000000u, J(root, "ref/beta.dll"), J(root, "ref/beta.map")) == 0);
    write_text(J(root, "ref/beta.tsv"),
               "name\tva\tsize\n_l_main\t0x20001000\t17\n_l_leaf\t0x20001020\t3\n__imp__Sleep@4\t0x20002010\t4\n");
}

static const char LINK_CONFIG[] =
    "{\"schema\": \"decompkit-project/1\",\n"
    " \"targets\": {\"beta\": {\"image\": \"${root}/ref/beta.dll\", \"sha256\": \"%s\",\n"
    "                        \"symbols\": [{\"kind\": \"tsv\", \"path\": \"${root}/ref/beta.tsv\"}]}},\n"
    " \"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]},\n"
    " \"compiler\": {\"cl\": \"${root}/bin/fakecl.exe\", \"env\": {\"FAKECL_REGISTRY\": \"${root}/fakereg\"},\n"
    "              \"base_flags\": [\"/nologo\", \"/c\"]},\n"
    " \"backend\": {\"kind\": \"%s\",\n"
    "             \"link\": {\"linker\": \"${root}/bin/fakelink.exe\",\n"
    "                      \"argv\": [\"/nologo\", \"/DLL\", \"/OUT:${out}/candidate.dll\",\n"
    "                               \"/MAP:${out}/candidate.map\",\n"
    "                               \"${roots}\", \"${objects}\", \"kernel32.lib\"],\n"
    "                      \"roots\": \"annotations\", \"map\": \"msvc\", \"discovery_compile\": true},\n"
    "             \"manifest\": {\"path\": \"${root}/man/manifest.json\"}},\n"
    " \"annotations\": {\"marker\":\n"
    "                 \"^//\\\\s*(?P<kind>FUNCTION):\\\\s+(?P<target>\\\\w+)\\\\s+(?P<addr>0x[0-9a-fA-F]+)\\\\s*$\",\n"
    "                 \"kinds\": {\"FUNCTION\": \"function\"}}}\n";

static void check_linked(DkProject *p, size_t expect_fns) {
    const DkUnit *u = dk_project_unit(p, "src/l.c");
    REQUIRE(u);
    DkBuildOpts o = {0};
    size_t nf = 0;
    DkStr log = {0};
    DkErr err = {0};
    DkFunc *fns = dk_build_unit(p, u, 0, &o, &nf, &log, &err);
    CHECK_MSG(fns != NULL, "%s", err.msg);
    CHECK_EQ_U64(nf, expect_fns);
    size_t n = 0;
    DkResult *rs = dk_compare_unit(p, u, 0, &o, &n, &err);
    REQUIRE(rs);
    CHECK_EQ_U64(n, 2);
    CHECK_STATUS(rs, n, "l_main", DK_MATCH);
    CHECK_STATUS(rs, n, "l_leaf", DK_MATCH);
    const DkResult *m = result_named(rs, n, "l_main");
    CHECK(m && m->ours.code.n == 17);          /* the int3 padding up to the next map symbol trimmed */
    CHECK_VERDICT(m, "_l_leaf", DK_REF_SAME);  /* a rel32 call, named through the map */
    CHECK_VERDICT(m, "$SG3", DK_REF_SAME);     /* a base relocation to linked data, compared by content */
    CHECK_VERDICT(m, "__imp__Sleep@4", DK_REF_SAME);
    CHECK(m && m->n_refs == 3);
}

DK_TEST(link_backend) {
    const char *root = repo("project_compare-link-");
    write_text(J(root, "src/l.c"), LINK_UNIT);
    DkStr obj = link_unit_object();
    REQUIRE(fake_cl_register(J(root, "fakereg"), fake_cl_key(dk_str(LINK_UNIT), NULL, 0, "/GL-"), obj));
    REQUIRE(fake_cl_register(J(root, "fakereg"), fake_cl_key(dk_str(LINK_UNIT), NULL, 0, "/GL"), obj));
    link_reference(root);
    write_text(J(root, "config/ctools.json"),
               dk_sprintf(dk_arena(), LINK_CONFIG, sha_of(J(root, "ref/beta.dll")), "link"));
    DkProject *p = load(root, NULL);
    REQUIRE(p);
    check_linked(p, 2);
    const DkUnit *u = dk_project_unit(p, "src/l.c");
    const char *dir = J(dk_project_build_dir(p, "build"), "link/beta/src_l_c");
    CHECK(dk_isfile(J(dir, "candidate.dll")) && dk_isfile(J(dir, "candidate.map")));
    CHECK(dk_isfile(J(dir, "discovery.obj")));
    (void)u;
    dk_tempdir_cleanup(root);
}

DK_TEST(manifest_backend) {
    const char *root = repo("project_compare-man-");
    write_text(J(root, "src/l.c"), LINK_UNIT);
    link_reference(root);
    /* a candidate image linked at 0x30000000 with its map beside it */
    const char *objs[1] = {J(root, "ref/beta-src.obj")};
    dk_makedirs(J(root, "man"), true);
    REQUIRE(fake_link(objs, 1, 0x30000000u, J(root, "man/cand.dll"), J(root, "man/cand.map")) == 0);
    const char *image = fwd(J(root, "man/cand.dll"));
    write_text(J(root, "man/manifest.json"),
               dk_sprintf(dk_arena(),
                          "{\"status\": \"built\", \"candidates\": [\n"
                          " {\"symbol\": \"_l_main\", \"retail_va\": \"0x20001000\",\n"
                          "  \"candidate_va\": \"0x30001000\",\n"
                          "  \"size\": 17, \"image_path\": \"%s\", \"source_path\": \"src/l.c\"},\n"
                          " {\"symbol\": \"_l_leaf\", \"retail_va\": 536875040, \"candidate_va\": 805310496,\n"
                          "  \"size\": 3, \"image_path\": \"%s\", \"source_path\": \"src/l.c\"},\n"
                          " {\"symbol\": \"_other\", \"retail_va\": 1, \"candidate_va\": 805310464, \"size\": 1,\n"
                          "  \"image_path\": \"%s\", \"source_path\": \"src/other.c\"}],\n"
                          " \"artifacts\": [{\"path\": \"%s\", \"kind\": \"linked-image\"}]}\n",
                          image, image, image, image));
    write_text(J(root, "config/ctools.json"),
               dk_sprintf(dk_arena(), LINK_CONFIG, sha_of(J(root, "ref/beta.dll")), "manifest"));
    DkProject *p = load(root, NULL);
    REQUIRE(p);
    check_linked(p, 2);
    dk_tempdir_cleanup(root);
}

/* ---- link dependencies (units.link_with, targets.<t>.link_with, a unit map's link_with / link_roots) ---------- */

static const char LW_UNIT[] = "// FUNCTION: beta 0x20001000\nint w_main(void) { return w_dep(); }\n";
static const char LW_DEP[] = "int w_dep(void) { return 0; }\n";

/* w_main calls w_dep, which only the dependency defines: the fake linker fails without it. */
static DkStr lw_unit_object(void) {
    static const u8 code[6] = {0xE8, 0, 0, 0, 0, 0xC3};
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 t = synth_coff_section(&sc, ".text", 0x60501020u, code, sizeof code);
    synth_coff_symbol(&sc, "_w_main", 0, (i16)t, 0x20, 2, 0);
    u32 s_dep = synth_coff_symbol(&sc, "_w_dep", 0, 0, 0x20, 2, 0);
    synth_coff_reloc(&sc, t, 1, s_dep, 0x14);
    return synth_coff_build(&sc);
}

static DkStr lw_dep_object(void) {
    static const u8 code[3] = {0x31, 0xC0, 0xC3};
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 t = synth_coff_section(&sc, ".text", 0x60501020u, code, sizeof code);
    synth_coff_symbol(&sc, "_w_dep", 0, (i16)t, 0x20, 2, 0);
    return synth_coff_build(&sc);
}

static const char *lw_repo(void) {
    const char *root = repo("project_compare-lw-");
    write_text(J(root, "src/w.c"), LW_UNIT);
    write_text(J(root, "src/dep.c"), LW_DEP);
    DkStr uo = lw_unit_object(), dobj = lw_dep_object();
    const char *reg = J(root, "fakereg");
    DK_ASSERT(fake_cl_register(reg, fake_cl_key(dk_str(LW_UNIT), NULL, 0, "/GL-"), uo));
    DK_ASSERT(fake_cl_register(reg, fake_cl_key(dk_str(LW_UNIT), NULL, 0, "/GL"), uo));
    DK_ASSERT(fake_cl_register(reg, fake_cl_key(dk_str(LW_DEP), NULL, 0, "/GL"), dobj));
    dk_makedirs(J(root, "ref"), true);
    const char *o1 = J(root, "ref/w.obj"), *o2 = J(root, "ref/dep.obj");
    DK_ASSERT(dk_write_file(o1, uo.p, uo.n) && dk_write_file(o2, dobj.p, dobj.n));
    const char *objs[2] = {o1, o2};
    DK_ASSERT(fake_link(objs, 2, 0x20000000u, J(root, "ref/beta.dll"), J(root, "ref/beta.map")) == 0);
    write_text(J(root, "ref/beta.tsv"), "name\tva\tsize\n_w_main\t0x20001000\t6\n");
    write_text(J(root, "config/deps.json"), "{\"dependencies\": {\"src/w.c\": [\"src/dep.c\", \"src/w.c\"]}}\n");
    return root;
}

/* LINK_CONFIG with its units block replaced, and an optional target-level member after the symbols. */
static const char *lw_config(const char *root, const char *units, const char *target_links) {
    DkStr base = dk_str(dk_sprintf(dk_arena(), LINK_CONFIG, sha_of(J(root, "ref/beta.dll")), "link"));
    DkStr old_units = DK_S("\"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]}");
    i64 at = dk_str_find(base, old_units, 0, DK_END);
    DK_ASSERT(at >= 0);
    DkStr old_sym = DK_S("\"${root}/ref/beta.tsv\"}]");
    i64 st = dk_str_find(base, old_sym, 0, DK_END);
    DK_ASSERT(st >= 0 && st < at);
    size_t se = (size_t)st + old_sym.n, ue = (size_t)at + old_units.n;
    return dk_sprintf(dk_arena(), "%.*s%s%.*s%s%s", (int)se, base.p, target_links ? target_links : "",
                      (int)((size_t)at - se), base.p + se, units, base.p + ue);
}

static void check_lw(DkProject *p) {
    const DkUnit *u = dk_project_unit(p, "src/w.c");
    REQUIRE(u);
    CHECK(u->link_with.n == 1 && dk_str_eqz(u->link_with.v[0], "src/dep.c"));
    size_t n = 0;
    DkBuildOpts o = {0};
    DkErr err = {0};
    DkResult *rs = dk_compare_unit(p, u, 0, &o, &n, &err);
    REQUIRE(rs);
    CHECK_EQ_U64(n, 1);
    CHECK_STATUS(rs, n, "w_main", DK_MATCH);
    CHECK_VERDICT(&rs[0], "_w_dep", DK_REF_SAME); /* the dependency's function, compared by content */
}

DK_TEST(link_backend_link_with) {
    /* the candidate-list form at units level, with an extra root */
    const char *root = lw_repo();
    write_text(J(root, "config/ctools.json"),
               lw_config(root,
                         "\"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"], \"link_with\": [{\"unit\": "
                         "\"src/w.c\", \"dependencies\": [\"./src/dep.c\"], \"roots\": [\"_w_dep\"], \"size\": 6}]}",
                         NULL));
    DkProject *p = load(root, NULL);
    REQUIRE(p);
    check_lw(p);
    const DkUnit *u = dk_project_unit(p, "src/w.c");
    CHECK(u && u->link_roots.n == 1 && dk_str_eqz(u->link_roots.v[0], "_w_dep"));
    const DkUnit *d = dk_project_unit(p, "src/dep.c");
    CHECK(d && d->link_with.n == 0);

    /* the map form at target level, by reference to another file: the unit itself is left out */
    write_text(J(root, "config/ctools.json"),
               lw_config(root, "\"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]}",
                         ", \"link_with\": {\"$from\": \"config/deps.json#/dependencies\"}"));
    p = load(root, NULL);
    REQUIRE(p);
    check_lw(p);

    /* a unit map entry; without any, the link fails on the undefined symbol */
    write_text(J(root, "config/ctools.json"),
               lw_config(root,
                         "\"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"], \"map\": {\"src/w.c\": "
                         "{\"link_with\": [\"src/dep.c\"]}}}",
                         NULL));
    p = load(root, NULL);
    REQUIRE(p);
    check_lw(p);
    write_text(J(root, "config/ctools.json"),
               lw_config(root, "\"units\": {\"roots\": [\"src\"], \"extensions\": [\".c\"]}", NULL));
    p = load(root, NULL);
    REQUIRE(p);
    size_t n = 0;
    DkBuildOpts o = {0};
    DkErr err = {0};
    DkResult *rs = dk_compare_unit(p, dk_project_unit(p, "src/w.c"), 0, &o, &n, &err);
    REQUIRE(rs && n == 1);
    CHECK_STATUS(rs, n, "w_main", DK_ERROR);

    /* a malformed list */
    write_text(J(root, "config/ctools.json"),
               lw_config(root, "\"units\": {\"roots\": [\"src\"], \"link_with\": [{\"dependencies\": []}]}", NULL));
    err = (DkErr){0};
    CHECK(dk_project_load(dk_arena(), root, NULL, &err) == NULL && strstr(err.msg, "units.link_with[0].unit"));
    dk_tempdir_cleanup(root);
}

/* The entry point: the fake tools when started under their names, else the tests. */
static int run(int argc, char **argv) {
    int rc = fake_tool_dispatch(argc, argv);
    if (rc >= 0) return rc;
    return dk_test__run(argc, argv);
}
DK_MAIN(run, "test_project_compare")
