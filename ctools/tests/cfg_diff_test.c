// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* cfg_diff.h on hand-assembled function pairs (no compiler, no image): the whole analysis (decoding, blocks, alignment,
 * findings) and the verbose report, compared with the expected text in tests/cfg_diff_corpus.h, the block-aligned
 * score, and the condition and mnemonic helpers. Results are built by hand (DkResult, no image). */
#include "dk/dk.h"
#include "dk/test.h"
#include "cfg_diff.h"
#include "cfg_diff_corpus.h"

static DkResult *make_result(const CfgDiffCase *c) {
    DkArena *a = dk_arena();
    DkResult *r = DK_NEW(a, DkResult);
    r->status = DK_DIFF;
    r->ours.symbol = c->name;
    r->ours.code = dk_strn((const char *)c->ours, c->ours_n);
    r->theirs = dk_strn((const char *)c->game, c->game_n);
    r->theirs_va = c->address;
    return r;
}

DK_TEST(analysis_reports) {
    for (size_t i = 0; i < DK_ARRAY_LEN(CFGDIFF_CASES); i++) {
        const CfgDiffCase *c = &CFGDIFF_CASES[i];
        const char *err = NULL;
        CfgDiffAnalysis *an = cfg_diff_analyse(make_result(c), NULL, "t0", CFG_DIFF_NONE, &err);
        CHECK_MSG(an != NULL, "%s: analyse failed: %s", c->name, err ? err : "?");
        if (!an) continue;
        char name[64];
        snprintf(name, sizeof name, "f_%s", c->name);
        DkStr text = cfg_diff_format_analysis(name, an, true);
        CHECK_MSG(dk_str_eqz(text, c->report), "%s: report differs\n--- got\n%.*s--- want\n%s", c->name, DK_SF(text), c->report);
        CHECK_MSG(strcmp(cfg_diff_one_liner(an), c->one_liner) == 0, "%s: one_liner '%s', want '%s'", c->name, cfg_diff_one_liner(an),
                  c->one_liner);
    }
}

/* The block-aligned score of two hand-assembled bodies: the game is `test ecx,ecx; jz +7; inc eax; inc ecx; inc edx; ret`. */
static const unsigned char GAME_BODY[] = {0x85, 0xC9, 0x74, 0x03, 0x40, 0x41, 0x42, 0xC3};

static double block_score_of(const unsigned char *ours, size_t ours_n, const unsigned char *game, size_t game_n) {
    CfgDiffCase c = {"blk", ours, game, (unsigned)ours_n, (unsigned)game_n, 0x401000, "", ""};
    double pct = -1;
    CHECK(cfg_diff_result_block_score(make_result(&c), NULL, &pct));
    return pct;
}

static int positional_pct(const unsigned char *ours, size_t n, const unsigned char *game) {
    size_t same = 0;
    for (size_t i = 0; i < n; i++) same += ours[i] == game[i];
    return (int)(100 * same / n);
}

DK_TEST(block_score_identical) {
    CHECK(block_score_of(GAME_BODY, sizeof GAME_BODY, GAME_BODY, sizeof GAME_BODY) == 100.0);
}

DK_TEST(block_score_disjoint) {
    static const unsigned char ours[] = {0x40, 0xC2, 0x04, 0x00};
    static const unsigned char game[] = {0x49, 0xC3};
    CHECK(block_score_of(ours, sizeof ours, game, sizeof game) == 0.0);
}

/* Writing the missing middle block lowers the positional score and raises the block score. */
DK_TEST(block_score_added_block) {
    static const unsigned char before[] = {0x85, 0xC9, 0x74, 0x03, 0x40};
    static const unsigned char after[] = {0x85, 0xC9, 0x74, 0x03, 0x40, 0x41, 0x43, 0xC3};
    double b = block_score_of(before, sizeof before, GAME_BODY, sizeof GAME_BODY);
    double a = block_score_of(after, sizeof after, GAME_BODY, sizeof GAME_BODY);
    CHECK_MSG(positional_pct(after, sizeof after, GAME_BODY) < positional_pct(before, sizeof before, GAME_BODY),
              "positional did not fall");
    CHECK_MSG(b == 62.5 && a == 87.5, "block score %.1f -> %.1f, want 62.5 -> 87.5", b, a);
}

DK_TEST(conditions) {
    CHECK(cfg_diff_is_jcc("je"));
    CHECK(cfg_diff_is_jcc("jecxz"));
    CHECK(cfg_diff_is_jcc("loopne"));
    CHECK(!cfg_diff_is_jcc("jmp"));
    CHECK(!cfg_diff_is_jcc("call"));
    CHECK_CZ(cfg_diff_cond_of("jz"), "e");
    CHECK_CZ(cfg_diff_cond_of("jnbe"), "a");
    CHECK_CZ(cfg_diff_cond_of("jpo"), "np");
    CHECK_CZ(cfg_diff_cond_of("jl"), "l");
    CHECK_CZ(cfg_diff_cond_of("loop"), "loop");
}

DK_TEST(levers) {
    CHECK(cfg_diff_lever("inverted-branch") != NULL);
    CHECK(cfg_diff_lever("other") != NULL);
    CHECK(cfg_diff_lever("error") == NULL);
    CHECK_EQ_U64(CFG_DIFF_NKINDS, 14);
    CHECK_CZ(CFG_DIFF_KINDS[CFG_DIFF_NKINDS - 1], "error");
}

DK_TEST_MAIN("cfg_diff")
