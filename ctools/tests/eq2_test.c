// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Tests of the eq2 engine (lib/eq2_*.c): the expression algebra on random expressions and the whole checker on random
 * small x86 programs, both against the expected results of eq2_corpus.h (synthetic inputs). */
#include "dk/test.h"
#include "eq2_internal.h"
#include "eq2_front.h"
#include "fakecl/fake_tools.h"
#include "fixtures/synth_coff.h"
#include "fixtures/synth_pe.h"
#include <windows.h>
#include <errno.h>
#include "eq2_corpus.h"

/* ------------------------------------------------------------------------------------ a parser of the corpus reprs */
typedef struct Parser {
    const char *p;
} Parser;

static void skip_ws(Parser *ps) {
    while (*ps->p == ' ') ps->p++;
}

static Ex *parse_val(Parser *ps) {
    skip_ws(ps);
    const char *p = ps->p;
    if (*p == '(') {
        ps->p++;
        Ex *items[64];
        size_t n = 0;
        for (;;) {
            skip_ws(ps);
            if (*ps->p == ')') {
                ps->p++;
                break;
            }
            DK_ASSERT(n < 64);
            items[n++] = parse_val(ps);
            skip_ws(ps);
            if (*ps->p == ',') ps->p++;
        }
        return ex_tup(items, n);
    }
    if (*p == '\'') {
        const char *q = strchr(p + 1, '\'');
        DK_ASSERT(q);
        ps->p = q + 1;
        return ex_strn(p + 1, (size_t)(q - p - 1));
    }
    if (!strncmp(p, "None", 4)) {
        ps->p += 4;
        return ex_none();
    }
    if (!strncmp(p, "frozenset(", 10)) {
        ps->p += 10;
        unsigned mask = 0;
        while (*ps->p != ')') {
            if (*ps->p == '\'') {
                const char *q = strchr(ps->p + 1, '\'');
                size_t l = (size_t)(q - ps->p - 1);
                if (l == 2 && !strncmp(ps->p + 1, "lt", 2)) mask |= OUT_LT;
                else if (l == 2 && !strncmp(ps->p + 1, "eq", 2)) mask |= OUT_EQ;
                else if (l == 2 && !strncmp(ps->p + 1, "gt", 2)) mask |= OUT_GT;
                else if (l == 2 && !strncmp(ps->p + 1, "un", 2)) mask |= OUT_UN;
                ps->p = q + 1;
            } else {
                ps->p++;
            }
        }
        ps->p++;
        return ex_fset(mask);
    }
    char *end;
    errno = 0;
    if (*p == '-') {
        long long v = strtoll(p, &end, 10);
        if (errno == ERANGE) {   /* beyond 64 bits: a huge int keeps its decimal text */
            end = (char *)p + 1;
            while (*end >= '0' && *end <= '9') end++;
            char txt[600];
            snprintf(txt, sizeof txt, "%.*s", (int)(end - p), p);
            ps->p = end;
            return ex_int_text(txt);
        }
        ps->p = end;
        return ex_int(v);
    }
    unsigned long long v = strtoull(p, &end, 10);
    if (errno == ERANGE) {
        end = (char *)p;
        while (*end >= '0' && *end <= '9') end++;
        char txt[600];
        snprintf(txt, sizeof txt, "%.*s", (int)(end - p), p);
        ps->p = end;
        return ex_int_text(txt);
    }
    ps->p = end;
    return ex_uint(v);
}

static Ex *parse(const char *text) {
    Parser ps = {text};
    return parse_val(&ps);
}

/* ---------------------------------------------------------------------------------------------- algebra cases */
static const char *repr_cz(Ex *e) { return ex_repr(e); }

static void run_alg(const Eq2AlgCase *c, char *out, size_t cap) {
    eq2_init();
    Eq2Catch ct;
    if (!EQ2_TRY(&ct)) {
        snprintf(out, cap, ct.kind == EQ2_EXC_UNSUPPORTED ? "!Unsupported: %s" : "!%s", ct.msg);
        return;
    }
    const char *op = c->op;
    Ex *a = c->a[0] ? parse(c->a) : NULL, *b = c->b[0] ? parse(c->b) : NULL, *cc = c->c[0] ? parse(c->c) : NULL;
    const char *res = NULL;
    DkArena *ar = dk_scratch();
    if (!strcmp(op, "add")) res = repr_cz(eq2_add(a, b, (int)cc->i));
    else if (!strcmp(op, "scale")) res = repr_cz(eq2_scale(a, b->i));
    else if (!strcmp(op, "comm")) res = repr_cz(eq2_comm(a, b, cc));
    else if (!strcmp(op, "lo8")) res = repr_cz(eq2_lo8(a));
    else if (!strcmp(op, "b8")) res = repr_cz(eq2_b8(a));
    else if (!strcmp(op, "canon_e")) res = repr_cz(eq2_canon_e(a));
    else if (!strcmp(op, "short")) res = eq2_short_cz(ar, a);
    else if (!strcmp(op, "eqv")) res = eq2_eqv(a, b) ? "True" : "False";
    else if (!strcmp(op, "cond_eq")) res = eq2_cond_eq(a, b) ? "True" : "False";
    else if (!strcmp(op, "negcond")) res = repr_cz(eq2_negate_cond(a));
    else if (!strcmp(op, "canon_c")) res = repr_cz(eq2_canon_c(a));
    else if (!strcmp(op, "evalc")) {
        int v = eq2_eval_const_cond(a);
        res = v < 0 ? "None" : (v ? "True" : "False");
    } else if (!strcmp(op, "subst")) {
        ExMap facts = {0};
        for (u32 i = 0; i < b->n; i++) exmap_put(&facts, exkey(b->el[i]->el[0]), NULL)->e = b->el[i]->el[1];
        res = repr_cz(eq2_subst(a, &facts));
        exmap_free(&facts);
    } else if (!strcmp(op, "mkcond")) res = repr_cz(eq2_make_cond(a, b->s));
    else if (!strcmp(op, "dbl")) res = repr_cz(eq2_dbl_to_f32((u64)a->i));
    else if (!strcmp(op, "sym")) res = repr_cz(eq2_const_from_symbol(a->s, (int)b->i));
    else DK_ASSERT(!"unknown op");
    snprintf(out, cap, "%s", res);
    eq2_catch_end(&ct);
}

DK_TEST(algebra) {
    size_t n = DK_ARRAY_LEN(eq2_alg_cases), bad = 0;
    for (size_t i = 0; i < n; i++) {
        const Eq2AlgCase *c = &eq2_alg_cases[i];
        char got[4096];
        run_alg(c, got, sizeof got);
        if (strcmp(got, c->want)) {
            if (bad++ < 12) dk_test__fail(__FILE__, __LINE__, "%s(%s | %s | %s)\n  want %s\n  got  %s", c->op, c->a, c->b, c->c, c->want, got);
        }
    }
    CHECK_EQ_U64(bad, 0);
    printf("algebra: %zu cases\n", n);
}

/* ---------------------------------------------------------------------------------------------- engine cases */
static DkStr unhex(const char *hex) {
    size_t n = strlen(hex) / 2;
    u8 *p = dk_alloc(dk_arena(), n + 1);
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        p[i] = (u8)v;
    }
    return dk_strn((const char *)p, n);
}

static void run_progs(DkStr oc, DkStr gc, u32 base, const Eq2RelocVec *rv, const char *o_ret, const Eq2Image *image, DkBuf *out) {
    Eq2RelocVec none = {0};
    Eq2Prog *po = eq2_prog_new("ours", oc, base, rv ? rv : &none, image, true);
    Eq2Prog *pg = eq2_prog_new("reference", gc, base, &none, image, false);
    Eq2Checker *ck = eq2_checker_new(po, pg);
    ck->o_ret = o_ret;
    Eq2Sim *so = eq2_sim_new(po, eq2_state_new(po));
    Eq2Sim *sg = eq2_sim_new(pg, eq2_state_new(pg));
    DkTry t;
    if (DK_TRY(&t)) {
        eq2_checker_run(ck, so, sg);
        dk_try_end(&t);
    } else {
        char *m = dk_sprintf(dk_arena(), "CRASH %s", t.msg);
        eq2_checker_report(ck, m);
    }
    dk_buf_pyfmt(out, "paths %d", ck->paths);
    for (size_t i = 0; i < ck->diffs.n; i++) dk_buf_pyfmt(out, "\ndiff %s", ck->diffs.v[i]);
    for (size_t i = 0; i < ck->notes.n; i++) dk_buf_pyfmt(out, "\nnote %s", ck->notes.v[i]);
    for (size_t i = 0; i < ck->switches.n; i++)
        dk_buf_pyfmt(out, "\ncase %d ours %X reference %X", ck->switches.v[i].value, ck->switches.v[i].ours, ck->switches.v[i].game);
}

static void run_eng(const Eq2EngCase *c, DkBuf *out) {
    Eq2RelocVec rv = {(Eq2Reloc *)c->relocs, c->n_relocs, c->n_relocs};
    run_progs(unhex(c->ours_hex), unhex(c->game_hex), c->base, &rv, c->o_ret, NULL, out);
}

DK_TEST(engine) {
    size_t n = DK_ARRAY_LEN(eq2_eng_cases), bad = 0;
    for (size_t i = 0; i < n; i++) {
        const Eq2EngCase *c = &eq2_eng_cases[i];
        DkBuf got = {0};
        run_eng(c, &got);
        if (strcmp(dk_buf_cz(&got), c->want)) {
            if (bad++ < 8) dk_test__fail(__FILE__, __LINE__, "%s\n  want %s\n  got  %s", c->name, c->want, dk_buf_cz(&got));
        }
        dk_buf_free(&got);
    }
    CHECK_EQ_U64(bad, 0);
    printf("engine: %zu programs\n", n);
}


/* ---------------------------------------------------------------------------------------- image and front end */
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
    "int f_same(void) { return 5; }\n"
    "// FUNCTION: alpha 0x00401010\n"
    "int f_diff(void) { return 5; }\n";

static const u8 OURS_SAME[6] = {0xB8, 5, 0, 0, 0, 0xC3};
static const u8 REF_DIFF[6] = {0xB8, 6, 0, 0, 0, 0xC3};

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
    "                 \"kinds\": {\"FUNCTION\": \"function\"}}}\n";

static const char *make_repo(void) {
    const char *dir = fwd(dk_mkdtemp(dk_arena(), "eq2-", "", NULL));
    wchar_t self[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, self, MAX_PATH);
    DK_ASSERT(n > 0 && n < MAX_PATH);
    char me[MAX_PATH * 3];
    WideCharToMultiByte(CP_UTF8, 0, self, -1, me, (int)sizeof me, NULL, NULL);
    dk_makedirs(J(dir, "bin"), true);
    DK_ASSERT(dk_copyfile(me, J(dir, "bin/fakecl.exe")));
    write_text(J(dir, "src/u.c"), UNIT);
    u8 code[16];
    memset(code, 0xCC, sizeof code);
    memcpy(code, OURS_SAME, 6);
    memcpy(code + 6, OURS_SAME, 6);
    SynthCoff sc;
    synth_coff_init(&sc);
    u32 t = synth_coff_section(&sc, ".text", 0x60500020u, code, 12);
    synth_coff_symbol(&sc, "_f_same", 0, (i16)t, 0x20, 2, 0);
    synth_coff_symbol(&sc, "_f_diff", 6, (i16)t, 0x20, 2, 0);
    DK_ASSERT(fake_cl_register(J(dir, "fakereg"), fake_cl_key(dk_str(UNIT), NULL, 0, ""), synth_coff_build(&sc)));
    dk_makedirs(J(dir, "ref"), true);
    FakePe pe;
    fake_pe_init(&pe, 0x00400000u);
    u8 text[0x40];
    memset(text, 0xCC, sizeof text);
    memcpy(text, OURS_SAME, 6);
    memcpy(text + 0x10, REF_DIFF, 6);
    fake_pe_section(&pe, ".text", 0x60000020u, text, sizeof text);
    DK_ASSERT(fake_pe_write(&pe, J(dir, "ref/alpha.exe")));
    write_text(J(dir, "ref/alpha.tsv"), "name\tva\tsize\n_f_same\t0x401000\t6\n_f_diff\t0x401010\t6\n");
    const char *sha = dk_file_digest_hex(dk_arena(), DK_HASH_SHA256, J(dir, "ref/alpha.exe"));
    write_text(J(dir, "config/ctools.json"), dk_sprintf(dk_arena(), CONFIG, sha));
    return dir;
}

DK_TEST(image) {
    const char *root = make_repo();
    DkErr err = {0};
    Eq2Image *im = eq2_image_open(dk_arena(), J(root, "ref/alpha.exe"), &err);
    REQUIRE(im);
    const Eq2ImageSection *s = eq2_image_section_of(im, 0x401004);
    REQUIRE(s);
    CHECK(dk_str_eqz(s->name, ".text") && s->chars == 0x60000020u);
    CHECK(eq2_image_section_of(im, 0x300000) == NULL);
    DkStr b;
    const char *e = NULL;
    REQUIRE(eq2_image_read(im, 0x401010, 6, &b, &e));
    CHECK(b.n == 6 && memcmp(b.p, REF_DIFF, 6) == 0);
    CHECK(eq2_image_read_u32(im, 0x401010) == 0x000006B8u);
    CHECK(!eq2_image_read(im, 0x300000, 4, &b, &e) && strstr(e, "00300000"));
    CHECK(eq2_image_open(dk_arena(), J(root, "ref/alpha.tsv"), &err) == NULL);
    dk_tempdir_cleanup(root);
}

DK_TEST(front_end) {
    CHECK(strcmp(eq2_ret_kind(DK_S("void __cdecl f(int)")), "void") == 0);
    CHECK(strcmp(eq2_ret_kind(DK_S("float __thiscall C::m(void)")), "float") == 0);
    CHECK(strcmp(eq2_ret_kind(DK_S("public: bool __thiscall C::m(void)")), "bool") == 0);
    CHECK(strcmp(eq2_ret_kind(DK_S("struct S * __cdecl f(void)")), "int") == 0);
    CHECK(strcmp(eq2_conv_of(DK_S("int __stdcall f(int)")), "stdcall") == 0);
    CHECK(eq2_conv_of(DK_S("f")) == NULL);

    const char *root = make_repo();
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    int rc = -1;
    REQUIRE(eq2_run(p, "u", "f_same", -1, false, &rc, &err));
    CHECK_EQ_I64(rc, 0);
    REQUIRE(eq2_run(p, "u", "f_diff", 0, true, &rc, &err));
    CHECK_EQ_I64(rc, 1);
    REQUIRE(eq2_run(p, "u", "f_same,f_diff", -1, false, &rc, &err));
    CHECK_EQ_I64(rc, 1);
    REQUIRE(eq2_run(p, "u", "nothing", -1, false, &rc, &err));
    CHECK_EQ_I64(rc, 1);
    CHECK(!eq2_run(p, "src/none.c", "f_same", -1, false, &rc, &err) && strstr(err.msg, "src/none.c"));
    dk_tempdir_cleanup(root);
}

/* The entry point: the fake tools when started under their names, else the tests. */
static int run(int argc, char **argv) {
    int rc = fake_tool_dispatch(argc, argv);
    if (rc >= 0) return rc;
    return dk_test__run(argc, argv);
}
DK_MAIN(run, "test_eq2")
