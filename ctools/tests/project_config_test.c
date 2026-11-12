// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* project_config.c: loading config/ctools.json into the project model. Two fixture trees (copied to a temporary
 * folder before loading): project_vc8, a synthetic copy of a target+addr project whose configuration references its
 * own JSON files, and project_pertarget, two targets with per-target defines and the per-target annotation grammar.
 * Then the error cases, each from a configuration written by the test. */
#include "dk/fs.h"
#include "dk/json.h"
#include "dk/test.h"
#include "project.h"

static const char *J(const char *a, const char *b) { return dk_join(dk_arena(), a, b); }

static void write_text(const char *path, const char *text) {
    DkStr dir = dk_path_dirname(path);
    dk_makedirs(dk_cz(dk_arena(), dir), true);
    DK_ASSERT(dk_write_file(path, text, strlen(text)));
}

/* A temporary copy of ctools/tests/fixtures/<name> (the tests run from the parent of ctools/), under sub. */
static const char *fixture_copy(const char *name, const char *sub) {
    char *dir = dk_mkdtemp(dk_arena(), "project_config-", "", NULL);
    DK_ASSERT(dir != NULL);
    const char *dst = sub ? J(dir, sub) : dir;
    DkCopytreeOpts o = {0};
    o.dirs_exist_ok = true;
    DK_ASSERT(dk_copytree(dk_sprintf(dk_arena(), "ctools/tests/fixtures/%s", name), dst, &o));
    return dst;
}

static const char *fresh_dir(void) {
    char *dir = dk_mkdtemp(dk_arena(), "project_config-", "", NULL);
    DK_ASSERT(dir != NULL);
    return dir;
}

static const char *cat(const char *a, const char *b) { return dk_sprintf(dk_arena(), "%s%s", a, b); }

static bool vec_is(const DkStrVec *v, const char *const *want, size_t n) {
    if (v->n != n) return false;
    for (size_t i = 0; i < n; i++)
        if (!dk_str_eqz(v->v[i], want[i]) || v->v[i].p[v->v[i].n] != 0) return false;
    return true;
}
#define VEC_IS(v, ...) \
    vec_is((v), (const char *const[]){__VA_ARGS__}, sizeof((const char *const[]){__VA_ARGS__}) / sizeof(char *))

static const DkUnit *unit_at(const DkProject *p, const char *path) {
    size_t n;
    const DkUnit *u = dk_project_units(p, &n);
    for (size_t i = 0; i < n; i++)
        if (strcmp(u[i].path, path) == 0) return &u[i];
    return NULL;
}

/* ---- project_vc8 --------------------------------------------------------------------------------------------- */
static void check_vc8(DkProject *p, const char *root, const char *primary) {
    CHECK_CZ(dk_project_root(p), root);
    CHECK_CZ(dk_project_primary(p), primary);
    CHECK_CZ(dk_project_config_path(p), cat(root, "/config/ctools.json"));
    REQUIRE(dk_project_ntargets(p) == 5);
    const char *names[] = {"cl", "c1", "c1xx", "c2", "link"};
    for (int i = 0; i < 5; i++) {
        CHECK_CZ(dk_project_target(p, i)->name, names[i]);
        CHECK_EQ_I64(dk_project_target_index(p, names[i]), i);
        CHECK(dk_project_compiler(p, i) == dk_project_compiler(p, -1));
    }
    CHECK(dk_project_target(p, 5) == NULL);
    CHECK_EQ_I64(dk_project_target_index(p, "c3"), -1);

    const DkTarget *cl = dk_project_target(p, 0);
    CHECK_CZ(cl->image_path, cat(root, "/toolchain/VC/bin/cl.exe"));
    CHECK(cl->has_sha256);
    CHECK_EQ_U64(cl->sha256[0], 0xA1);
    CHECK_EQ_U64(cl->sha256[1], 0xB2);
    CHECK_EQ_U64(cl->sha256[31], 0xD4);
    CHECK_EQ_U64(cl->image_base, 0x400000);
    REQUIRE(cl->n_symbols == 1);
    CHECK(cl->symbols[0].kind == DK_SYM_TSV);
    CHECK_CZ(cl->symbols[0].path, cat(primary, "/symbols/cl.functions.tsv"));
    CHECK_CZ(cl->symbols[0].col_name, "name");
    CHECK_CZ(cl->symbols[0].col_va, "va");
    CHECK_CZ(cl->symbols[0].col_rva, "rva");
    CHECK_CZ(cl->symbols[0].col_size, "size");
    CHECK_EQ_U64(cl->defines.n, 0);
    const DkTarget *c1xx = dk_project_target(p, 2);
    CHECK_EQ_U64(c1xx->sha256[0], 0xFF);
    CHECK_EQ_U64(c1xx->sha256[31], 0x00);
    CHECK_EQ_U64(c1xx->image_base, 0);
    CHECK_CZ(dk_project_target(p, 4)->symbols[0].path, cat(primary, "/symbols/link.functions.tsv"));

    const DkCompiler *c = dk_project_compiler(p, -1);
    CHECK_CZ(c->cl, cat(root, "/toolchain/VC/bin/cl.exe"));
    CHECK(VEC_IS(&c->base_flags, "/nologo", "/c"));
    CHECK(VEC_IS(&c->cpp_flags, "/EHsc"));
    CHECK_EQ_U64(c->c_flags.n, 0);
    CHECK(VEC_IS(&c->identity_files, cat(root, "/toolchain/VC/bin/cl.exe"), cat(root, "/toolchain/VC/bin/c1.dll"),
                 cat(root, "/toolchain/VC/bin/c1xx.dll"), cat(root, "/toolchain/VC/bin/c2.dll")));
    CHECK(c->show_includes);
    CHECK(c->flag_variants == NULL);

    size_t n;
    const DkUnit *u = dk_project_units(p, &n);
    REQUIRE(n == 4);
    CHECK_CZ(u[0].path, "matching/c2/opt.c");
    CHECK_CZ(u[1].path, "matching/cl/listed_only.cpp");
    CHECK_CZ(u[2].path, "matching/cl/merr.c");
    CHECK_CZ(u[3].path, "matching/cl/util.cpp");
    CHECK_EQ_U64(u[0].target_mask, 0x1F);
    CHECK_EQ_U64(u[0].compile_flags.n, 0);
    CHECK(u[0].flags_line && !u[0].gl_set && !u[0].per_target);
    CHECK_EQ_U64(u[1].target_mask, 1);
    CHECK(VEC_IS(&u[1].link_flags, "advapi32.lib"));
    CHECK(VEC_IS(&u[2].remove_flags, "/EHsc"));
    CHECK(VEC_IS(&u[2].compile_flags, "/O1", "/D_TESTBLD"));
    CHECK(u[2].gl_set && !u[2].gl);
    CHECK(VEC_IS(&u[3].compile_flags, "/O1", "/Zc:wchar_t-", "/GF"));
    CHECK_EQ_U64(u[3].target_mask, 1);
    CHECK(dk_project_unit(p, "util") == &u[3]);
    CHECK(dk_project_unit(p, "merr.c") == &u[2]);
    CHECK(dk_project_unit(p, "matching/cl/merr.c") == &u[2]);
    CHECK(dk_project_unit(p, "matching\\c2\\opt.c") == &u[0]);
    CHECK(dk_project_unit(p, "nothing") == NULL);
    CHECK(VEC_IS(dk_project_unit_roots(p), "matching"));

    const DkBackend *b = dk_project_backend(p);
    CHECK(b->kind == DK_BACKEND_LINK);
    CHECK_CZ(b->linker, cat(root, "/toolchain/VC/bin/link.exe"));
    CHECK(VEC_IS(&b->link_argv, "/nologo", "/DLL", "/NOENTRY", "/LTCG", "/MACHINE:X86", "/INCREMENTAL:NO",
                 "/OPT:NOREF,NOICF", "/MANIFEST:NO", "/OUT:${out}/candidate.dll", "/MAP:${out}/candidate.map",
                 "${roots}", "${objects}", "kernel32.lib"));
    CHECK_CZ(b->roots, "annotations");
    CHECK_CZ(b->map_format, "msvc");
    CHECK(b->discovery_compile);
    CHECK(VEC_IS(&b->manifest_command, "python", "tools/match.py", "build", "--binary", "${target}"));
    CHECK(b->manifest_path == NULL);

    DkErr err = {0};
    DkExpandVars v = {0};
    v.out = "o/dir";
    v.objects = "a.obj b.obj";
    CHECK_CZ(dk_project_expand(dk_arena(), p, b->link_argv.v[8].p, &v, &err), "/OUT:o/dir/candidate.dll");
    CHECK_CZ(dk_project_expand(dk_arena(), p, b->link_argv.v[11].p, &v, &err), "a.obj b.obj");
    CHECK_CZ(dk_project_expand(dk_arena(), p, b->link_argv.v[10].p, &v, &err), "${roots}");
    CHECK_CZ(dk_project_expand(dk_arena(), p, b->link_argv.v[10].p, NULL, &err), "${roots}");
    v.target = "c2";
    CHECK_CZ(dk_project_expand(dk_arena(), p, b->manifest_command.v[4].p, &v, &err), "c2");
    CHECK_CZ(dk_project_expand(dk_arena(), p, "${toolchain_root}|${root}", NULL, &err), cat("toolchain/VC|", root));
    CHECK(dk_project_expand(dk_arena(), p, "/X:${nope}", &v, &err) == NULL);
    CHECK(err.code != 0 && strstr(err.msg, "nope") != NULL);
    CHECK(dk_project_expand(dk_arena(), p, "/X:${out", &v, &err) == NULL);

    const DkAnnotConfig *ac = dk_project_annot_config(p);
    REQUIRE(ac->marker && ac->re_marker);
    CHECK(strstr(ac->marker, "(?P<binary>") != NULL);
    REQUIRE(ac->n_kinds == 2);
    CHECK_CZ(ac->kinds[0].text, "FUNCTION");
    CHECK(ac->kinds[0].kind == DK_ANN_FUNCTION);
    CHECK_CZ(ac->kinds[1].text, "DATA");
    CHECK(ac->kinds[1].kind == DK_ANN_DATA);
    CHECK(ac->addr_groups == DK_ADDR_TARGET_ADDR);
    CHECK(ac->name == DK_NAME_DECLARATION);
    CHECK_CZ(ac->symbol, "^\\s*//\\s*SYMBOL:\\s*(\\S+)\\s*$");
    CHECK(ac->re_symbol && ac->re_stop && !ac->re_pending && !ac->re_flags);
    CHECK_EQ_I64(ac->flags_lines, 8);
    CHECK(ac->g_kind >= 0 && ac->g_kind == dk_re_group_index(ac->re_marker, "kind"));
    CHECK(ac->g_target >= 0 && ac->g_target == dk_re_group_index(ac->re_marker, "binary"));
    CHECK(ac->g_addr >= 0 && ac->g_addr == dk_re_group_index(ac->re_marker, "va"));
    CHECK_EQ_I64(ac->ntargets, 5);
    CHECK_CZ(ac->target_names[3], "c2");

    CHECK(dk_project_well_known_imports(p));
    CHECK(VEC_IS(dk_project_well_known_symbols(p), "___security_cookie"));
    CHECK(VEC_IS(dk_project_text_check_paths(p), "matching"));
    CHECK(VEC_IS(dk_project_text_check_no_bom(p), "matching/**"));
    size_t nref;
    dk_project_referents(p, &nref);
    CHECK_EQ_U64(nref, 0);
    CHECK_CZ(dk_project_build_dir(p, NULL), cat(root, "/build/ctools"));
    CHECK_CZ(dk_project_build_dir(p, "gate"), cat(root, "/build/ctools/gate"));
    CHECK_CZ(dk_project_var(p, "toolchain_root"), "toolchain/VC");
    CHECK_CZ(dk_project_var(p, "symbols"), cat(primary, "/symbols"));
    CHECK_CZ(dk_project_var(p, "root"), root);
    CHECK(dk_project_var(p, "unknown") == NULL);
    CHECK_CZ(dk_project_path(dk_arena(), p, "a/b.c"), cat(root, "/a/b.c"));

    struct DkJson *jb = dk_project_json_ref(p, "config/retail.json#/builds/c2/image_base", &err);
    CHECK(jb && dk_json_i64(jb, -1) == 268566528);
    CHECK(dk_project_json_ref(p, "config/retail.json#/builds/c9", &err) == NULL);
    CHECK(strstr(err.msg, "/builds/c9") != NULL);
    CHECK(dk_project_target_mut(p, 1) == dk_project_target(p, 1));
}

static const char *norm(const char *path) {
    char *s = dk_path_abspath(dk_arena(), path);
    for (char *q = s; *q; q++)
        if (*q == '\\') *q = '/';
    return s;
}

DK_TEST(vc8_configuration) {
    const char *dir = fixture_copy("project_vc8", NULL);
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), dir, NULL, &err);
    CHECK_MSG(p != NULL, "%s", err.msg);
    REQUIRE(p);
    CHECK_EQ_I64(err.code, 0);
    check_vc8(p, norm(dir), norm(dir));
}

DK_TEST(vc8_worktree_primary) {
    const char *base = fresh_dir();
    const char *main = J(base, "main");
    write_text(J(main, ".git/worktrees/wt/commondir"), "../..\n");
    const char *wt = J(base, "wt");
    DkCopytreeOpts o = {0};
    o.dirs_exist_ok = true;
    REQUIRE(dk_copytree("ctools/tests/fixtures/project_vc8", wt, &o));
    write_text(J(wt, ".git"), "gitdir: ../main/.git/worktrees/wt\n");
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), wt, NULL, &err);
    CHECK_MSG(p != NULL, "%s", err.msg);
    REQUIRE(p);
    check_vc8(p, norm(wt), norm(main));
}

DK_TEST(vc8_local_merge) {
    const char *dir = fixture_copy("project_vc8", NULL);
    write_text(J(dir, "config/ctools.local.json"),
               "{\"vars\": {\"toolchain_root\": \"Z:/tc\"},\n"
               " \"targets\": {\"c2\": {\"compiler\": {\"base_flags\": {\"$from\": \"config/c2.json#/flags/compile\"}}}},\n"
               " \"well_known\": {\"imports\": false}}\n");
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), dir, NULL, &err);
    CHECK_MSG(p != NULL, "%s", err.msg);
    REQUIRE(p);
    CHECK_CZ(dk_project_target(p, 0)->image_path, "Z:/tc/bin/cl.exe");
    CHECK(dk_project_target(p, 3)->has_sha256);
    const DkCompiler *c2 = dk_project_compiler(p, 3);
    CHECK(c2 != dk_project_compiler(p, -1));
    CHECK(VEC_IS(&c2->base_flags, "/nologo", "/GL", "/MD"));
    CHECK(VEC_IS(&c2->cpp_flags, "/EHsc"));
    CHECK_CZ(c2->cl, "Z:/tc/bin/cl.exe");
    CHECK(dk_project_compiler(p, 0) == dk_project_compiler(p, -1));
    CHECK(!dk_project_well_known_imports(p));
    CHECK(VEC_IS(dk_project_well_known_symbols(p), "___security_cookie"));

    /* An explicit configuration file is not merged with the local one. */
    p = dk_project_load(dk_arena(), dir, "config/ctools.json", &err);
    REQUIRE(p);
    CHECK(dk_project_well_known_imports(p));
}

/* ---- project_pertarget ------------------------------------------------------------------------------------------ */
DK_TEST(per_target_configuration) {
    const char *dir = fixture_copy("project_pertarget", NULL);
    const char *root = norm(dir);
    DkErr err = {0};
    DkProject *p = dk_project_load(NULL, dir, NULL, &err);
    CHECK_MSG(p != NULL, "%s", err.msg);
    REQUIRE(p);
    REQUIRE(dk_project_ntargets(p) == 2);
    const DkTarget *alpha = dk_project_target(p, 0), *beta = dk_project_target(p, 1);
    CHECK_CZ(alpha->name, "alpha");
    CHECK_CZ(beta->name, "beta");
    CHECK_CZ(alpha->image_path, cat(root, "/images/alpha.bin"));
    CHECK(alpha->has_sha256 && !beta->has_sha256);
    CHECK_EQ_U64(alpha->sha256[15], 0xFF);
    CHECK_EQ_U64(alpha->image_base, 0x400000);
    CHECK_EQ_U64(beta->image_base, 0);
    CHECK(VEC_IS(&alpha->defines, "ALPHA=1"));
    REQUIRE(alpha->n_symbols == 2 && beta->n_symbols == 1);
    CHECK(alpha->symbols[0].kind == DK_SYM_TSV);
    CHECK_CZ(alpha->symbols[0].col_name, "Name");
    CHECK_CZ(alpha->symbols[0].col_va, "Address");
    CHECK_CZ(alpha->symbols[0].col_size, "size");
    CHECK(alpha->symbols[1].kind == DK_SYM_PDB);
    CHECK_CZ(alpha->symbols[1].path, cat(root, "/syms/alpha.pdb"));
    CHECK(beta->symbols[0].kind == DK_SYM_MAP);

    const DkCompiler *c = dk_project_compiler(p, -1);
    CHECK_CZ(c->cl, cat(root, "/bin/cl.exe"));
    CHECK(VEC_IS(&c->env_names, "X", "Y"));
    CHECK(VEC_IS(&c->env_values, "1", "y"));
    CHECK(VEC_IS(&c->path_prepend, cat(root, "/bin")));
    CHECK(VEC_IS(&c->include, cat(root, "/src/inc")));
    CHECK(VEC_IS(&c->c_flags, "/TC"));
    REQUIRE(c->n_flag_variants == 2);
    CHECK(VEC_IS(&c->flag_variants[0], "/O1"));
    CHECK(VEC_IS(&c->flag_variants[1], "/O2", "/Oy-"));
    CHECK(dk_project_compiler(p, 0) == c);
    const DkCompiler *cb = dk_project_compiler(p, 1);
    CHECK(cb != c && beta->compiler == cb);
    CHECK(VEC_IS(&cb->base_flags, "/nologo", "/c", "/O1"));
    CHECK(VEC_IS(&cb->env_names, "X"));
    CHECK(VEC_IS(&cb->env_values, "2"));
    CHECK(VEC_IS(&cb->c_flags, "/TC"));
    CHECK_CZ(cb->cl, c->cl);

    size_t n;
    const DkUnit *u = dk_project_units(p, &n);
    REQUIRE(n == 3);
    CHECK_CZ(u[0].path, "src/Shape.CPP");
    CHECK_CZ(u[1].path, "src/both.c");
    CHECK_CZ(u[2].path, "src/plain.c");
    CHECK(u[1].per_target);
    CHECK(!u[1].flags_line);
    CHECK(VEC_IS(&u[1].compile_flags, "/Oy"));
    CHECK_EQ_U64(u[1].target_mask, 3);
    CHECK(!u[2].per_target && u[2].flags_line);
    CHECK(!u[0].per_target);
    CHECK(dk_project_unit(p, "plain") == &u[2]);
    CHECK(dk_project_unit(p, "Shape") == &u[0]);
    CHECK(unit_at(p, "src/vendor/skip.c") == NULL);

    const DkAnnotConfig *ac = dk_project_annot_config(p);
    CHECK(ac->addr_groups == DK_ADDR_PER_TARGET);
    CHECK(ac->name == DK_NAME_NEXT_LINE);
    CHECK_EQ_I64(ac->flags_lines, 4);
    CHECK(ac->re_pending && ac->re_flags && !ac->re_symbol);
    CHECK(ac->g_addr_target[0] >= 0 && ac->g_addr_target[0] == dk_re_group_index(ac->re_marker, "addr_alpha"));
    CHECK(ac->g_addr_target[1] >= 0 && ac->g_addr_target[1] == dk_re_group_index(ac->re_marker, "addr_beta"));
    CHECK_CZ(ac->target_names[1], "beta");

    CHECK(dk_project_backend(p)->kind == DK_BACKEND_OBJECT);
    CHECK_EQ_U64(dk_project_backend(p)->link_argv.n, 0);
    size_t nref;
    const DkReferentFile *rf = dk_project_referents(p, &nref);
    REQUIRE(nref == 1);
    CHECK_CZ(rf[0].file, cat(root, "/config/refs.tsv"));
    CHECK_CZ(rf[0].format, "tsv");
    CHECK(!dk_project_well_known_imports(p));
    CHECK(VEC_IS(dk_project_well_known_symbols(p), "_memcpy"));
    CHECK_CZ(dk_project_build_dir(p, NULL), cat(root, "/out/dk"));
    CHECK_CZ(dk_project_var(p, "cl_exe"), "bin/cl.exe");
    CHECK(dk_project_arena(p) == dk_arena());
}

/* ---- errors and reference rules ---------------------------------------------------------------------------------- */
#define SCHEMA "\"schema\": \"decompkit-project/1\""

/* Loads a configuration written into a fresh folder (other files: pairs of path, text, NULL-terminated). */
static DkProject *load_text(const char *json, DkErr *err, ...) {
    const char *dir = fresh_dir();
    write_text(J(dir, "config/ctools.json"), json);
    va_list ap;
    va_start(ap, err);
    for (const char *path; (path = va_arg(ap, const char *)) != NULL;) write_text(J(dir, path), va_arg(ap, const char *));
    va_end(ap);
    return dk_project_load(dk_arena(), dir, NULL, err);
}

static bool fails_with(const char *json, const char *needle, const char *other_file, const char *other_text) {
    DkErr err = {0};
    DkProject *p = load_text(json, &err, other_file, other_text, NULL);
    if (p || !err.code || !strstr(err.msg, needle)) {
        fprintf(stderr, "  expected an error naming \"%s\", got: %s\n", needle, p ? "(loaded)" : err.msg);
        return false;
    }
    return true;
}

DK_TEST(error_unknown_keys) {
    CHECK(fails_with("{" SCHEMA ", \"targets\": {\"cl\": {\"image\": \"a.exe\", \"imag\": \"b\"}}}", "targets.cl.imag",
                     NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"unitz\": {}}", "unitz", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"backend\": {\"kind\": \"link\", \"link\": {\"linkr\": \"l.exe\"}}}",
                     "backend.link.linkr", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"targets\": {\"a\": {\"image\": \"a\", \"symbols\": [{\"kind\": \"tsv\", "
                     "\"path\": \"x\", \"colour\": 1}]}}}",
                     "targets.a.symbols[0].colour", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"build_dir\": {\"$from\": \"config/o.json#/a\", \"defualt\": 1}}", "defualt", NULL,
                     NULL));
    CHECK(fails_with("{\"targets\": {}}", "schema", NULL, NULL));
    CHECK(fails_with("{\"schema\": \"decompkit-project/2\"}", "schema", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"targets\": {\"cl\": {\"sha256\": \"00\"}}}", "targets.cl.image", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"annotations\": {\"kinds\": {}}}", "annotations.marker", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"backend\": {\"kind\": \"manifest\"}}", "backend.manifest", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"vars\": {\"root\": \"x\"}}", "vars.root", NULL, NULL));
}

DK_TEST(error_sha256) {
    CHECK(fails_with("{" SCHEMA ", \"targets\": {\"cl\": {\"image\": \"a.exe\", \"sha256\": \"abc\"}}}",
                     "targets.cl.sha256", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"targets\": {\"cl\": {\"image\": \"a.exe\", \"sha256\": "
                     "\"g000000000000000000000000000000000000000000000000000000000000000\"}}}",
                     "targets.cl.sha256", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"targets\": {\"cl\": {\"image\": \"a.exe\", \"image_base\": \"zz\"}}}",
                     "targets.cl.image_base", NULL, NULL));
}

DK_TEST(error_from_missing) {
    DkErr err = {0};
    DkProject *p = load_text("{" SCHEMA ", \"targets\": {\"cl\": {\"image\": {\"$from\": \"config/none.json#/x\"}}}}",
                             &err, NULL);
    CHECK(!p && err.code == DK_ERR_IO);
    CHECK_MSG(strstr(err.msg, "config/none.json") && strstr(err.msg, "#/x") && strstr(err.msg, "targets.cl.image"),
              "%s", err.msg);
    p = load_text("{" SCHEMA ", \"targets\": {\"cl\": {\"image\": {\"$from\": \"config/o.json#/a/c\"}}}}", &err,
                  "config/o.json", "{\"a\": {\"b\": \"x.exe\"}}", NULL);
    CHECK(!p && err.code == DK_ERR_FORMAT);
    CHECK_MSG(strstr(err.msg, "config/o.json") && strstr(err.msg, "/a/c"), "%s", err.msg);
    CHECK(fails_with("{" SCHEMA ", \"build_dir\": {\"$from\": \"config/o.json#a\"}}", "malformed", "config/o.json",
                     "{}"));
    CHECK(fails_with("{" SCHEMA ", \"build_dir\": {\"$from\": \"config/o.json#/x\"}}", "config/o.json",
                     "config/o.json", "{not json"));
    CHECK(fails_with("{" SCHEMA ", \"build_dir\": {\"$from\": \"config/loop.json#/x\"}}", "deeper",
                     "config/loop.json", "{\"x\": {\"$from\": \"config/loop.json#/x\"}}"));
}

DK_TEST(from_rules) {
    DkErr err = {0};
    const char *other = "{\"a/b\": {\"m~n\": \"esc.exe\"}, \"list\": [\"x.exe\", \"y.exe\"], \"defs\": [\"B=1\", "
                        "\"C=1\"], \"name\": \"o\", \"nested\": {\"$from\": \"config/o.json#/name\"}, "
                        "\"tmpl\": \"${dir}/t.exe\"}";
    DkProject *p = load_text(
        "{" SCHEMA ",\n"
        " \"vars\": {\"file\": \"o\", \"which\": {\"$from\": \"config/${file}.json#/gone\", \"default\": \"q\"},"
        "            \"dir\": \"d\", \"name\": {\"$from\": \"config/${file}.json#/nested\"},"
        "            \"both\": \"${dir}/${name}\"},\n"
        " \"targets\": {\n"
        "  \"a\": {\"image\": {\"$from\": \"config/none.json#/x\", \"default\": \"dflt.exe\"}},\n"
        "  \"b\": {\"image\": {\"$from\": \"config/o.json#/missing\", \"default\": \"${dir}/p.exe\"}},\n"
        "  \"c\": {\"image\": {\"$from\": \"config/o.json#/a~1b/m~0n\"}},\n"
        "  \"d\": {\"image\": {\"$from\": \"config/o.json#/list/1\"},\n"
        "         \"defines\": [\"A=1\", {\"$from\": \"config/o.json#/defs\"}, \"Z=1\"]},\n"
        "  \"e\": {\"image\": {\"$from\": \"config/o.json#/tmpl\"}, \"image_base\": 4096}}}\n",
        &err, "config/o.json", other, NULL);
    CHECK_MSG(p != NULL, "%s", err.msg);
    REQUIRE(p);
    const char *root = dk_project_root(p);
    CHECK_CZ(dk_project_var(p, "which"), "q");
    CHECK_CZ(dk_project_var(p, "name"), "o");
    CHECK_CZ(dk_project_var(p, "both"), "d/o");
    CHECK_CZ(dk_project_target(p, 0)->image_path, cat(root, "/dflt.exe"));
    CHECK_CZ(dk_project_target(p, 1)->image_path, cat(root, "/d/p.exe"));
    CHECK_CZ(dk_project_target(p, 2)->image_path, cat(root, "/esc.exe"));
    CHECK_CZ(dk_project_target(p, 3)->image_path, cat(root, "/y.exe"));
    CHECK(VEC_IS(&dk_project_target(p, 3)->defines, "A=1", "B=1", "C=1", "Z=1"));
    CHECK_CZ(dk_project_target(p, 4)->image_path, cat(root, "/d/t.exe"));
    CHECK_EQ_U64(dk_project_target(p, 4)->image_base, 4096);
    struct DkJson *raw = dk_project_json_ref(p, "config/${file}.json#/tmpl", &err);
    CHECK(raw && dk_json_is_str(raw) && dk_str_eqz(raw->u.str, "${dir}/t.exe"));

    /* A BOM is tolerated. */
    p = load_text("\xEF\xBB\xBF{" SCHEMA "}", &err, NULL);
    CHECK_MSG(p != NULL, "%s", err.msg);
}

DK_TEST(error_variables) {
    CHECK(fails_with("{" SCHEMA ", \"targets\": {\"cl\": {\"image\": \"${nope}/a.exe\"}}}", "${nope}", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"targets\": {\"cl\": {\"image\": \"${nope}/a.exe\"}}}", "targets.cl.image", NULL,
                     NULL));
    CHECK(fails_with("{" SCHEMA ", \"vars\": {\"a\": \"${b}\", \"b\": \"x\"}}", "vars.a", NULL, NULL));
    CHECK(fails_with("{" SCHEMA ", \"build_dir\": \"${dir\"}", "unterminated", NULL, NULL));
    DkErr err = {0};
    DkProject *p = load_text("{" SCHEMA ", \"vars\": {\"a\": \"x\", \"b\": \"${a}/y\"}, \"backend\": {\"kind\": "
                             "\"manifest\", \"manifest\": {\"command\": [\"${b}\", \"${unit}\", \"${out}\"]}}}",
                             &err, NULL);
    CHECK_MSG(p != NULL, "%s", err.msg);
    REQUIRE(p);
    CHECK(VEC_IS(&dk_project_backend(p)->manifest_command, "x/y", "${unit}", "${out}"));
}

DK_TEST(error_too_many_targets) {
    DkBuf b = {0};
    dk_buf_putz(&b, "{" SCHEMA ", \"targets\": {");
    for (int i = 0; i < DK_MAX_TARGETS + 1; i++) dk_buf_printf(&b, "%s\"t%d\": {\"image\": \"t%d.exe\"}", i ? ", " : "", i, i);
    dk_buf_putz(&b, "}}");
    CHECK(fails_with(dk_buf_cz(&b), "targets", NULL, NULL));
    dk_buf_free(&b);
    DkErr err = {0};
    CHECK(dk_project_load(dk_arena(), fresh_dir(), NULL, &err) == NULL);
    CHECK(err.code == DK_ERR_IO && strstr(err.msg, "ctools.json") != NULL);
}

DK_TEST_MAIN("project_config")
