// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* scorer on the fake toolchain: the score order, a baseline that is not a match, an exact candidate, a candidate that
 * does not build, state keys, repeated evaluations in two slots (the slots' memory is recycled), and the selection of
 * the annotation. */
#include "float_order_repo.h"
#include "scorer.h"

DK_TEST(score_order) {
    DkScore a = {3, 10, 400}, b = {3, 10, 401}, c = {1, 99, 999}, d = {3, 9, 999};
    CHECK(dk_score_cmp(a, b) < 0 && dk_score_cmp(b, a) > 0 && dk_score_cmp(a, a) == 0);
    CHECK(dk_score_cmp(c, a) < 0);
    CHECK(dk_score_cmp(d, a) < 0);
    CHECK(dk_score_exact(DK_SCORE_EXACT) && !dk_score_exact(c));
    CHECK_CZ(dk_score_str(a), "S3 D10 R400");
    CHECK_CZ(dk_score_tag(a), "S3_D10_R400");
}

DK_TEST(evaluate_candidates) {
    const char *root = fo_make_repo("scorer-");
    fo_register(root, fo_candidate_text("c * d + a * b"), FO_REF, sizeof FO_REF);
    fo_register(root, fo_candidate_text("a * b - c * d"), FO_SUBBED, sizeof FO_SUBBED);
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    const DkUnit *u = dk_project_unit(p, "u");
    REQUIRE(u);

    /* selection: by name, by address, wrong name, wrong address */
    const DkAnnot *an = dk_scorer_select(p, u, "f_flt", DK_NO_ADDR, 0, &err);
    REQUIRE(an);
    CHECK_EQ_U64(an->addr[0], FO_ADDR);
    const DkAnnot *by_addr = dk_scorer_select(p, u, "f_flt", FO_ADDR, 0, &err);
    CHECK(by_addr && by_addr->line == an->line);
    CHECK(dk_scorer_select(p, u, "nothing", DK_NO_ADDR, 0, &err) == NULL && strstr(err.msg, "nothing"));
    CHECK(dk_scorer_select(p, u, "f_flt", 0x401234, 0, &err) == NULL);

    DkScorer *s = dk_scorer_new(p, u, an, 0, 2, fo_J(root, "work"), &err);
    REQUIRE_MSG(s, "%s", err.msg);
    CHECK_EQ_U64(s->address, FO_ADDR);
    CHECK(s->symbol == NULL && s->game.p == NULL);

    /* the unit as it is: the commuted sum, 32 bytes against 29 */
    DkScored base;
    REQUIRE_MSG(dk_scorer_evaluate(s, 0, fo_J(root, "src/u.c"), &base, NULL, &err), "%s", err.msg);
    CHECK_CZ(s->symbol, "_f_flt");
    CHECK_EQ_U64(s->game.n, sizeof FO_REF);
    CHECK(memcmp(s->game.p, FO_REF, sizeof FO_REF) == 0);
    CHECK(base.status == DK_SIZE);
    CHECK_EQ_I64(base.score.status, 4);
    CHECK(base.score.differ > 0 && base.score.dissim > 0);
    CHECK_EQ_U64(base.code.n, sizeof FO_COMMUTED);
    CHECK_EQ_U64(base.n_relocs, 0);

    /* an exact candidate, in the other slot, from a file of its own */
    const char *c1 = fo_J(root, "work/cand1.c");
    fo_write_text(c1, fo_candidate_text("c * d + a * b"));
    DkScored good;
    REQUIRE_MSG(dk_scorer_evaluate(s, 1, c1, &good, NULL, &err), "%s", err.msg);
    CHECK(good.status == DK_MATCH && dk_score_exact(good.score));
    CHECK(strcmp(good.key, base.key) != 0);
    CHECK(dk_score_cmp(good.score, base.score) < 0);

    /* a candidate with another instruction: a worse status than an exact one, not a build failure */
    const char *c2 = fo_J(root, "work/cand2.c");
    fo_write_text(c2, fo_candidate_text("a * b - c * d"));
    DkScored bad;
    REQUIRE_MSG(dk_scorer_evaluate(s, 0, c2, &bad, NULL, &err), "%s", err.msg);
    CHECK(bad.status == DK_DIFF);
    CHECK_EQ_I64(bad.score.status, 3);
    CHECK_EQ_I64(bad.score.differ, 1);
    CHECK(dk_score_cmp(bad.score, good.score) > 0);

    /* a candidate nobody registered does not build */
    const char *c3 = fo_J(root, "work/cand3.c");
    fo_write_text(c3, fo_candidate_text("d * c + b * a"));
    DkScored none;
    CHECK(!dk_scorer_evaluate(s, 1, c3, &none, NULL, &err) && err.msg[0]);

    /* many evaluations in both slots: the same answers every time */
    for (int i = 0; i < 12; i++) {
        DkScored again;
        REQUIRE_MSG(dk_scorer_evaluate(s, i & 1, (i % 3) == 0 ? c1 : (i % 3) == 1 ? c2 : fo_J(root, "src/u.c"), &again,
                                       NULL, &err),
                    "%s", err.msg);
        const DkScored *want = (i % 3) == 0 ? &good : (i % 3) == 1 ? &bad : &base;
        CHECK(dk_score_cmp(again.score, want->score) == 0);
        CHECK_CZ(again.key, want->key);
        CHECK(again.code.n == want->code.n && memcmp(again.code.p, want->code.p, want->code.n) == 0);
        dk_scored_free(&again);
    }
    dk_scored_free(&base);
    dk_scored_free(&good);
    dk_scored_free(&bad);
    dk_tempdir_cleanup(root);
}

DK_TEST(clone_is_independent) {
    const char *root = fo_make_repo("scorer-clone-");
    DkErr err = {0};
    DkProject *p = dk_project_load(dk_arena(), root, NULL, &err);
    REQUIRE(p);
    DkProject *c = dk_project_clone(p, fo_J(root, "elsewhere"), &err);
    REQUIRE_MSG(c, "%s", err.msg);
    CHECK(c != p && dk_project_arena(c) != dk_project_arena(p));
    CHECK_CZ(dk_project_build_dir(c, NULL), fo_J(root, "elsewhere"));
    CHECK_EQ_U64(dk_project_ntargets(c), dk_project_ntargets(p));
    CHECK(dk_project_unit(c, "u") != NULL);
    dk_tempdir_cleanup(root);
}

/* The entry point: the fake tools when started under their names, else the tests. */
static int run(int argc, char **argv) {
    int rc = fake_tool_dispatch(argc, argv);
    if (rc >= 0) return rc;
    return dk_test__run(argc, argv);
}
DK_MAIN(run, "test_scorer")
