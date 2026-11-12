// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* float_order's library layers on a synthetic corpus: hand-assembled SSE and x87 sequences for the operation trees
 * and their classification, and hand-written statements for the parser, the sites, the spellings and the statement
 * moves. */
#include "dk/dk.h"
#include "dk/test.h"
#include "float_order.h"

#include <string.h>

static DkStr S(const char *z) { return dk_str(z); }

/* ---- operation trees ---- */
/* a*b + c*d, SSE: movss/mulss twice, addss xmm0,xmm1 */
static const u8 SSE_AB_CD[28] = {0xF3, 0x0F, 0x10, 0x44, 0x24, 0x04, 0xF3, 0x0F, 0x59, 0x44, 0x24, 0x08, 0xF3, 0x0F,
                                 0x10, 0x4C, 0x24, 0x0C, 0xF3, 0x0F, 0x59, 0x4C, 0x24, 0x10, 0xF3, 0x0F, 0x58, 0xC1};
/* the same sum with its operands swapped: addss xmm1,xmm0 */
static const u8 SSE_CD_AB[28] = {0xF3, 0x0F, 0x10, 0x44, 0x24, 0x04, 0xF3, 0x0F, 0x59, 0x44, 0x24, 0x08, 0xF3, 0x0F,
                                 0x10, 0x4C, 0x24, 0x0C, 0xF3, 0x0F, 0x59, 0x4C, 0x24, 0x10, 0xF3, 0x0F, 0x58, 0xC8};
/* a*b - c*d: subss xmm0,xmm1 */
static const u8 SSE_AB_MINUS_CD[28] = {0xF3, 0x0F, 0x10, 0x44, 0x24, 0x04, 0xF3, 0x0F, 0x59, 0x44, 0x24, 0x08, 0xF3, 0x0F,
                                       0x10, 0x4C, 0x24, 0x0C, 0xF3, 0x0F, 0x59, 0x4C, 0x24, 0x10, 0xF3, 0x0F, 0x5C, 0xC1};
/* a*b + c*d, x87: fld a; fmul b; fld c; fmul d; faddp st(1),st */
static const u8 X87_AB_CD[18] = {0xD9, 0x44, 0x24, 0x04, 0xD8, 0x4C, 0x24, 0x08, 0xD9, 0x44, 0x24, 0x0C, 0xD8, 0x4C, 0x24, 0x10, 0xDE, 0xC1};
/* sqr(y) + sqr(x): the selftest's stream */
static const u8 SSE_YY_XX[22] = {0xf3, 0x0f, 0x10, 0x46, 0x04, 0xf3, 0x0f, 0x59, 0x46, 0x04, 0xf3, 0x0f,
                                 0x10, 0x06, 0xf3, 0x0f, 0x59, 0x06, 0xf3, 0x0f, 0x58, 0xc1};

static FoTree *tree_of(const u8 *code, size_t n) {
    return fo_float_tree(dk_arena(), dk_strn((const char *)code, n), 0x401000, NULL, 0);
}

static void classify(const FoTree *game, const FoTree *ours, u8 *classes) {
    u8 *used = dk_xcalloc(ours->interesting.n ? ours->interesting.n : 1, 1);
    fo_match_nodes(game, ours, classes, used);
    dk_xfree(used);
}

DK_TEST(sse_tree_shape) {
    FoTree *t = tree_of(SSE_AB_CD, sizeof SSE_AB_CD);
    REQUIRE(t->interesting.n == 3);
    CHECK(t->interesting.v[0]->op == FO_MUL && t->interesting.v[1]->op == FO_MUL && t->interesting.v[2]->op == FO_ADD);
    CHECK_STR(S(fo_op_name(FO_ADD)), "add");
    CHECK(t->interesting.v[2]->l == t->interesting.v[0] && t->interesting.v[2]->r == t->interesting.v[1]);
    fo_tree_prepare(t);
    CHECK(fo_ordered(t->interesting.v[0]) != fo_ordered(t->interesting.v[1]));
    CHECK(fo_commuted(t->interesting.v[2]) != 0);
    FoTree *u = tree_of(SSE_YY_XX, sizeof SSE_YY_XX);
    CHECK(u->interesting.n == 3);
}

DK_TEST(identical_trees_match) {
    FoTree *g = tree_of(SSE_AB_CD, sizeof SSE_AB_CD), *o = tree_of(SSE_AB_CD, sizeof SSE_AB_CD);
    fo_tree_prepare(g);
    fo_tree_prepare(o);
    u8 cls[3];
    classify(g, o, cls);
    for (int i = 0; i < 3; i++) CHECK_EQ_I64(cls[i], FO_MATCH);
    i64 f[3];
    fo_fscore(cls, 3, f);
    CHECK(f[0] == 0 && f[1] == 0 && f[2] == 0);
    CHECK_EQ_I64(fo_extra_ops(g, o), 0);
    CHECK_CZ(fo_class_counts_repr(cls, 3), "{'match': 3, 'commute': 0, 'assoc': 0, 'absent': 0}");
}

DK_TEST(commuted_sum_is_commute) {
    FoTree *g = tree_of(SSE_AB_CD, sizeof SSE_AB_CD), *o = tree_of(SSE_CD_AB, sizeof SSE_CD_AB);
    fo_tree_prepare(g);
    fo_tree_prepare(o);
    u8 cls[3];
    classify(g, o, cls);
    CHECK_EQ_I64(cls[0], FO_MATCH);
    CHECK_EQ_I64(cls[1], FO_MATCH);
    CHECK_EQ_I64(cls[2], FO_COMMUTE);
    i64 f[3];
    fo_fscore(cls, 3, f);
    CHECK(f[0] == 0 && f[1] == 0 && f[2] == 1);
    CHECK_EQ_I64(fo_extra_ops(g, o), 0);
}

DK_TEST(other_operation_is_not_a_match) {
    FoTree *g = tree_of(SSE_AB_CD, sizeof SSE_AB_CD), *o = tree_of(SSE_AB_MINUS_CD, sizeof SSE_AB_MINUS_CD);
    fo_tree_prepare(g);
    fo_tree_prepare(o);
    u8 cls[3];
    classify(g, o, cls);
    CHECK_EQ_I64(cls[0], FO_MATCH);
    CHECK_EQ_I64(cls[1], FO_MATCH);
    CHECK(cls[2] != FO_MATCH && cls[2] != FO_COMMUTE);
    CHECK(fo_extra_ops(g, o) >= 1); /* our subtraction matches no node of the reference */
}

DK_TEST(x87_and_sse_agree) {
    FoTree *x = tree_of(X87_AB_CD, sizeof X87_AB_CD), *s = tree_of(SSE_AB_CD, sizeof SSE_AB_CD);
    REQUIRE(x->interesting.n == 3);
    CHECK(x->interesting.v[0]->op == FO_MUL && x->interesting.v[1]->op == FO_MUL && x->interesting.v[2]->op == FO_ADD);
    fo_tree_prepare(x);
    fo_tree_prepare(s);
    u8 cls[3];
    classify(s, x, cls);
    for (int i = 0; i < 3; i++) CHECK_EQ_I64(cls[i], FO_MATCH);
}

DK_TEST(no_float_code) {
    static const u8 plain[] = {0x8B, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xC3}; /* mov eax,[esp+4]; add eax,[esp+8] */
    FoTree *t = tree_of(plain, sizeof plain);
    CHECK(t->interesting.n == 0);
}

/* ---- statements and spellings ---- */
static FoSiteVec sites_of(const char *text) {
    FoStmtInfo info = fo_parse_stmt(S(text));
    return fo_find_sites(S(text), &info, NULL);
}

static bool spelled(const FoSpellingVec *sp, const char *text) {
    for (size_t i = 0; i < sp->n; i++)
        if (strcmp(sp->v[i].text, text) == 0) return true;
    return false;
}

DK_TEST(statement_kinds) {
    FoStmtInfo i = fo_parse_stmt(S("return a * b + c;"));
    CHECK(i.kind == FS_RET && !i.bad);
    i = fo_parse_stmt(S("float t = x + y;"));
    CHECK(i.kind == FS_DECL && !i.bad);
    CHECK_STR(i.name, "t");
    i = fo_parse_stmt(S("if (x > 0.0f)"));
    CHECK(i.kind == FS_CTL);
    i = fo_parse_stmt(S("x = (a + ;"));
    CHECK(i.bad);
}

DK_TEST(sites_and_spellings) {
    FoSiteVec sites = sites_of("return a * b + c * d;");
    REQUIRE(sites.n == 1);
    CHECK_CZ(fo_render_tree(sites.v[0].tree), "a * b + c * d");
    FoSpellingVec sp = fo_spellings(sites.v[0].tree, 500, FO_ALL_MOVES, true, false);
    CHECK(spelled(&sp, "c * d + a * b"));
    CHECK(spelled(&sp, "b * a + c * d"));
    for (size_t i = 0; i < sp.n; i++)
        for (size_t j = 0; j < i; j++) CHECK(strcmp(sp.v[i].text, sp.v[j].text) != 0);
    dk_vec_free(&sp);
    sp = fo_spellings(sites.v[0].tree, 500, FOM_COMMUTE, true, false);
    CHECK(spelled(&sp, "c * d + a * b") && !spelled(&sp, "a * (b + c) * d"));
    dk_vec_free(&sp);
    dk_vec_free(&sites);
    CHECK_CZ(fo_moves_repr(FOM_COMMUTE | FOM_ASSOC), "['assoc', 'commute']");

    sites = sites_of("x = y * 0.5f;");
    REQUIRE(sites.n == 1);
    sp = fo_spellings(sites.v[0].tree, 50, FO_ALL_MOVES, true, false);
    CHECK(spelled(&sp, "y / 2.0f"));
    dk_vec_free(&sp);
    dk_vec_free(&sites);

    sites = sites_of("x = f(a) + g(b);");
    CHECK(sites.n == 0); /* two calls are never reordered */
    sites = sites_of("x = f(a) + b * c;");
    CHECK(sites.n != 0);
}

DK_TEST(statement_moves) {
    DkCzVec body = {0};
    dk_vec_push(&body, "    x += a * b;");
    dk_vec_push(&body, "    float s = p + q + r;");
    FoVariantVec vars = fo_stmt_variants(&body, NULL);
    bool compound = false, split = false;
    for (size_t i = 0; i < vars.n; i++) {
        if (strncmp(vars.v[i].note, "compound", 8) == 0) compound = true;
        if (strncmp(vars.v[i].note, "split", 5) == 0) split = true;
    }
    CHECK(compound && split);

    DkCzVec lines = {0};
    dk_vec_push(&lines, "    if (a.x * 2.0f +");
    dk_vec_push(&lines, "        b.y > c)");
    dk_vec_push(&lines, "        return false;");
    FoStmtVec stmts = fo_group_statements(&lines);
    REQUIRE(stmts.n == 2);
    CHECK(stmts.v[0].lo == 0 && stmts.v[0].hi == 1);
}

DK_TEST_MAIN("float_order")
