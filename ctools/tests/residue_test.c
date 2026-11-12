// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Tests of the text helpers of lib/residue_text.c (most common key, span, value text, mapping text) on hand-built values;
 * the expected strings are the helpers' documented forms. The register values and residue_compare are checked by
 * residue_values_test and residue_compare_test. */
#include "dk/dk.h"
#include "dk/test.h"
#include "residue.h"

typedef struct {
    const char *key;
    i64 n;
} Item;

static ResidueValue make_value(const u32 *refs, size_t nrefs, const char *reg, const Item *items, size_t nitems) {
    ResidueValue v;
    memset(&v, 0, sizeof v);
    v.reg = reg;
    v.kind = "cross";
    for (size_t i = 0; i < nrefs; i++) dk_vec_push(&v.refs, refs[i]);
    v.game = dk_map_new();
    for (size_t i = 0; i < nitems; i++) dk_map_put(v.game, dk_str(items[i].key), NULL)->i += items[i].n;
    return v;
}

typedef struct {
    const u32 *refs;
    size_t nrefs;
    const char *reg;
    const Item *items;
    size_t nitems;
    const char *span, *text, *text1, *text5;
} ValueCase;

static const u32 R1[] = {0x25, 0x32}, R2[] = {0x25, 0x2a, 0x32}, R3[] = {0x10}, R5[] = {0x1000, 0x1abc}, R6[] = {0x0};
static const Item I1[] = {{"ecx", 3}}, I2[] = {{"ecx", 3}, {"edx", 1}, {"esi", 1}, {"edi", 1}},
                  I3[] = {{"edx", 2}, {"ecx", 2}, {"eax", 1}},
                  I6[] = {{"xmm1", 5}, {"xmm2", 5}, {"xmm3", 4}, {"xmm4", 1}}, I7[] = {{"edi", 1}};

DK_TEST(value_text) {
    static const ValueCase C[] = {
        {R1, 2, "eax", I1, 1, "+025..+032", "+025..+032 eax -> ecx 3/3", "+025..+032 eax -> ecx 3/3", "+025..+032 eax -> ecx 3/3"},
        {R2, 3, "eax", I2, 4, "+025..+032", "+025..+032 eax -> ecx 3/6 (also edx 1, esi 1)", "+025..+032 eax -> ecx 3/6",
         "+025..+032 eax -> ecx 3/6 (also edx 1, esi 1, edi 1)"},
        {R3, 1, "ebx", I3, 3, "+010..+010", "+010..+010 ebx -> edx 2/5 (also ecx 2, eax 1)", "+010..+010 ebx -> edx 2/5",
         "+010..+010 ebx -> edx 2/5 (also ecx 2, eax 1)"},
        {R3, 1, "ebx", NULL, 0, "+010..+010", "+010..+010 ebx (no aligned use)", "+010..+010 ebx (no aligned use)",
         "+010..+010 ebx (no aligned use)"},
        {NULL, 0, "esi", NULL, 0, "entry", "entry esi (no aligned use)", "entry esi (no aligned use)", "entry esi (no aligned use)"},
        {R5, 2, "xmm0", I6, 4, "+1000..+1ABC", "+1000..+1ABC xmm0 -> xmm1 5/15 (also xmm2 5, xmm3 4)",
         "+1000..+1ABC xmm0 -> xmm1 5/15", "+1000..+1ABC xmm0 -> xmm1 5/15 (also xmm2 5, xmm3 4, xmm4 1)"},
        {R6, 1, "edi", I7, 1, "+000..+000", "+000..+000 edi -> edi 1/1", "+000..+000 edi -> edi 1/1", "+000..+000 edi -> edi 1/1"},
    };
    for (size_t i = 0; i < DK_ARRAY_LEN(C); i++) {
        ResidueValue v = make_value(C[i].refs, C[i].nrefs, C[i].reg, C[i].items, C[i].nitems);
        CHECK_CZ(residue_span(&v), C[i].span);
        CHECK_CZ(residue_value_text(&v, 3), C[i].text);
        CHECK_CZ(residue_value_text(&v, 1), C[i].text1);
        CHECK_CZ(residue_value_text(&v, 5), C[i].text5);
    }
}

static ResidueMapping *mapping(const char *game, i64 count, i64 total) {
    ResidueMapping *m = DK_NEW(dk_arena(), ResidueMapping);
    m->game = game;
    m->count = count;
    m->total = total;
    m->others = dk_map_new();
    return m;
}

typedef struct {
    const char *ours, *game;
    i64 count, total;
} MapRow;

static DkMap *build(const MapRow *rows, size_t n) {
    DkMap *m = dk_map_new();
    for (size_t i = 0; i < n; i++) dk_map_put(m, dk_str(rows[i].ours), NULL)->p = mapping(rows[i].game, rows[i].count, rows[i].total);
    return m;
}

DK_TEST(mapping_text) {
    static const MapRow A1[] = {{"esi", "edi", 12, 12}, {"eax", "eax", 5, 5}, {"ecx", "edx", 3, 4}, {"edx", "ecx", 4, 4}};
    DkMap *m = build(A1, DK_ARRAY_LEN(A1));
    CHECK_CZ(residue_mapping_text(m, 10), "esi->edi 12/12, ecx->edx 3/4, edx->ecx 4/4, eax->eax 5/5");
    CHECK_CZ(residue_mapping_text(m, 2), "esi->edi 12/12, ecx->edx 3/4, +2 more");
    CHECK_CZ(residue_mapping_text(m, 0), ", +4 more");

    static const char *const same[] = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4"};
    MapRow A2[DK_ARRAY_LEN(same)];
    for (size_t i = 0; i < DK_ARRAY_LEN(same); i++) A2[i] = (MapRow){same[i], same[i], 1, 1};
    m = build(A2, DK_ARRAY_LEN(A2));
    CHECK_CZ(residue_mapping_text(m, 10),
             "eax->eax 1/1, ebp->ebp 1/1, ebx->ebx 1/1, ecx->ecx 1/1, edi->edi 1/1, edx->edx 1/1, esi->esi 1/1, "
             "xmm0->xmm0 1/1, xmm1->xmm1 1/1, xmm2->xmm2 1/1, +2 more");
    CHECK_CZ(residue_mapping_text(m, 2), "eax->eax 1/1, ebp->ebp 1/1, +10 more");
    CHECK_CZ(residue_mapping_text(m, 0), ", +12 more");

    static const MapRow A3[] = {{"esi", "edi", 12, 12}, {"edi", "esi", 2, 12}, {"ebx", "ebx", 9, 9},  {"ebp", "eax", 9, 9},
                                {"eax", "ebp", 9, 9},   {"ecx", "ecx", 1, 1},  {"edx", "edx", 1, 1},  {"xmm0", "xmm1", 2, 2},
                                {"xmm1", "xmm0", 2, 2}, {"xmm2", "xmm2", 7, 7}, {"xmm3", "xmm4", 1, 1}, {"xmm4", "xmm3", 1, 1},
                                {"xmm5", "xmm6", 1, 1}, {"xmm6", "xmm5", 1, 1}};
    m = build(A3, DK_ARRAY_LEN(A3));
    CHECK_CZ(residue_mapping_text(m, 10),
             "edi->esi 2/12, esi->edi 12/12, eax->ebp 9/9, ebp->eax 9/9, xmm0->xmm1 2/2, xmm1->xmm0 2/2, xmm3->xmm4 1/1, "
             "xmm4->xmm3 1/1, xmm5->xmm6 1/1, xmm6->xmm5 1/1, +4 more");
    CHECK_CZ(residue_mapping_text(m, 2), "edi->esi 2/12, esi->edi 12/12, +12 more");
    CHECK_CZ(residue_mapping_text(m, 0), ", +14 more");
    CHECK_CZ(residue_mapping_text(dk_map_new(), 10), "");
}

DK_TEST(most_common) {
    DkMap *c = dk_map_new();
    DkStr key;
    i64 n;
    CHECK(!residue_most_common(c, &key, &n));
    dk_map_put(c, DK_S("b"), NULL)->i = 2;
    dk_map_put(c, DK_S("a"), NULL)->i = 3;
    dk_map_put(c, DK_S("c"), NULL)->i = 3;
    CHECK(residue_most_common(c, &key, &n)); /* the first maximum, as Counter.most_common(1) */
    CHECK_STR(key, "a");
    CHECK_EQ_I64(n, 3);
}

DK_TEST_MAIN("residue")
