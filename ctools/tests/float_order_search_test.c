// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* float_order end to end on the fake toolchain: the search over the spellings of `a * b + c * d` finds the commuted
 * spelling the registered object of the reference's bytes stands for (status exact, a state diff written), a search
 * with no such candidate ends "none", --tree-only and the error paths exit cleanly, and the batch picks the body-wall
 * result of the adapter. Every spelling nobody registered fails to build and is counted as failed. */
#include "float_order.h"
#include "float_order_repo.h"
#include "unitcmp.h"

static int run_main(const char *const *args, size_t n) {
    char **argv = DK_NEWN(dk_arena(), char *, n + 2);
    argv[0] = "float_order";
    for (size_t i = 0; i < n; i++) argv[i + 1] = (char *)args[i];
    return float_order_main((int)n + 1, argv);
}

static DkJson *result_of(const char *root, const char *name) {
    const char *path = fo_J(root, dk_sprintf(dk_arena(), "build/ctools/float_order/%s_00401000/result.json", name));
    DkBytes raw = {0};
    if (!dk_read_all(NULL, path, &raw)) return NULL;
    DkJson *doc = dk_json_parse(dk_arena(), dk_strn((const char *)raw.v, raw.n), NULL);
    dk_vec_free(&raw);
    return doc;
}

DK_TEST(search_finds_the_commuted_spelling) {
    const char *root = fo_make_repo("fo-search-");
    fo_register(root, fo_candidate_text("c * d + a * b"), FO_REF, sizeof FO_REF);
    const char *args[] = {"--root", root, "u", "f_flt", "--minutes", "1", "--workers", "2", "--quiet", "--max-site", "60"};
    CHECK_EQ_I64(run_main(args, DK_ARRAY_LEN(args)), 0);
    DkJson *res = result_of(root, "f_flt");
    REQUIRE(res);
    CHECK_STR(dk_json_get_str(res, "status", DK_S("")), "exact");
    CHECK_STR(dk_json_get_str(res, "target", DK_S("")), "alpha");
    CHECK_STR(dk_json_get_str(res, "address", DK_S("")), "00401000");
    CHECK(dk_json_get_i64(res, "tried", 0) > 1);
    CHECK(dk_json_get_i64(res, "failed", 0) >= 1); /* the spellings nobody registered */
    DkJson *best = dk_json_getz(res, "best");
    REQUIRE(best && dk_json_len(best) == 2);
    DkJson *f = dk_json_at(best, 0), *sc = dk_json_at(best, 1);
    CHECK(dk_json_i64(dk_json_at(f, 0), -1) == 0 && dk_json_len(f) == 3);
    CHECK(dk_json_at(sc, 0) && dk_json_len(sc) == 3);
    DkJson *states = dk_json_getz(res, "states");
    CHECK(states && dk_json_len(states) >= 1);
    DkJson *gn = dk_json_getz(res, "game_nodes");
    CHECK(gn && dk_json_getz(gn, "before") && dk_json_getz(gn, "after"));
    dk_tempdir_cleanup(root);
}

DK_TEST(search_without_a_better_candidate) {
    const char *root = fo_make_repo("fo-none-");
    const char *args[] = {"--root", root, "u", "f_flt", "--minutes", "1", "--workers", "2", "--quiet", "--max-site", "40"};
    CHECK_EQ_I64(run_main(args, DK_ARRAY_LEN(args)), 0);
    DkJson *res = result_of(root, "f_flt");
    REQUIRE(res);
    DkStr st = dk_json_get_str(res, "status", DK_S(""));
    CHECK(dk_str_eqz(st, "none") || dk_str_eqz(st, "insensitive"));
    DkJson *un = dk_json_getz(res, "unreached");
    CHECK(un != NULL);
    dk_tempdir_cleanup(root);
}

DK_TEST(tree_only_and_errors) {
    const char *root = fo_make_repo("fo-tree-");
    const char *a1[] = {"--root", root, "u", "f_flt", "--tree-only"};
    CHECK_EQ_I64(run_main(a1, DK_ARRAY_LEN(a1)), 0);
    const char *a2[] = {"--root", root, "u", "nothing", "--quiet"};
    CHECK_EQ_I64(run_main(a2, DK_ARRAY_LEN(a2)), 2);
    const char *a3[] = {"--root", root, "src/none.c", "f_flt"};
    CHECK_EQ_I64(run_main(a3, DK_ARRAY_LEN(a3)), 2);
    const char *a4[] = {"--root", root, "u", "f_flt", "--target", "beta"};
    CHECK_EQ_I64(run_main(a4, DK_ARRAY_LEN(a4)), 2);
    const char *a5[] = {"--selftest"};
    CHECK_EQ_I64(run_main(a5, DK_ARRAY_LEN(a5)), 0);
    dk_tempdir_cleanup(root);
}

DK_TEST(batch_selects_by_wall) {
    const char *root = fo_make_repo("fo-batch-");
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    DkUnitcmpOpts o;
    memset(&o, 0, sizeof o);
    o.all = true;
    o.target = -1;
    DkUnitcmpRowVec rows = {0};
    REQUIRE(dk_unitcmp_collect(p, &o, &rows, &err));
    REQUIRE(rows.n == 1);
    const char *wall = dk_cz(dk_arena(), dk_str(rows.v[0].wall.wall));
    CHECK(strcmp(wall, "match") != 0);
    /* no result has this wall: no job */
    const char *a1[] = {"--root", root, "--batch", "--wall", "no-such-wall", "--minutes", "1"};
    CHECK_EQ_I64(run_main(a1, DK_ARRAY_LEN(a1)), 0);
    /* the wall of the function: one job (its child, the executable beside the tests, may be absent: an error row) */
    const char *a2[] = {"--root", root, "--batch", "--wall", wall, "--units", "u", "--minutes", "1", "--workers", "1"};
    CHECK_EQ_I64(run_main(a2, DK_ARRAY_LEN(a2)), 0);
    DkBytes raw = {0};
    REQUIRE(dk_read_all(NULL, fo_J(root, "build/ctools/float_order/summary.json"), &raw));
    DkJson *doc = dk_json_parse(dk_arena(), dk_strn((const char *)raw.v, raw.n), NULL);
    dk_vec_free(&raw);
    REQUIRE(doc && dk_json_len(doc) == 1);
    CHECK_STR(dk_json_get_str(dk_json_at(doc, 0), "name", DK_S("")), "f_flt");
    dk_tempdir_cleanup(root);
}

/* The entry point: the fake tools when started under their names, else the tests. */
static int run(int argc, char **argv) {
    int rc = fake_tool_dispatch(argc, argv);
    if (rc >= 0) return rc;
    return dk_test__run(argc, argv);
}
DK_MAIN(run, "test_float_order_search")
