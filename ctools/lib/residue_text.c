// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The text helpers of the residue report (most common key, span, value text, mapping text). They depend on nothing
 * but the core library, so the test links without cfg_diff; the register values and the comparison are in
 * residue.c. */
#include "residue.h"

#include "dk/sort.h"

#include <string.h>

static DkArena *A(void) { return dk_arena(); }
static const char *cstr(DkStr s) { return dk_cz(A(), s); }

static i64 counter_total(const DkMap *c) {
    i64 t = 0;
    DkMapIter it = {0};
    while (dk_map_next(c, &it)) t += it.val->i;
    return t;
}

bool residue_most_common(const DkMap *counter, DkStr *key, i64 *n) {
    DkMapIter it = {0};
    bool have = false;
    while (dk_map_next(counter, &it)) {
        if (!have || it.val->i > *n) {
            *key = it.key;
            *n = it.val->i;
            have = true;
        }
    }
    return have;
}

typedef struct {
    DkStr key;
    i64 n;
} CountItem;
typedef DK_VEC(CountItem) CountItemVec;

static int cmp_count(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    return dk_cmp_i64(((const CountItem *)x)->n, ((const CountItem *)y)->n);
}

/* most_common() with no argument: sorted by count, descending, ties in first-seen order. */
static CountItemVec most_common_all(const DkMap *c) {
    CountItemVec v = {0};
    DkMapIter it = {0};
    while (dk_map_next(c, &it)) dk_vec_push(&v, ((CountItem){it.key, it.val->i}));
    dk_sort(v.v, v.n, sizeof(CountItem), cmp_count, NULL, true);
    return v;
}


const char *residue_span(const ResidueValue *v) {
    if (!v->refs.n) return "entry";
    return dk_sprintf(A(), "+%03X..+%03X", v->refs.v[0], v->refs.v[v->refs.n - 1]);
}

const char *residue_value_text(const ResidueValue *v, int limit) {
    DkArena *a = A();
    i64 total = counter_total(v->game);
    if (!total) return dk_sprintf(a, "%s %s (no aligned use)", residue_span(v), v->reg);
    DkStr best = {0};
    i64 n = 0;
    residue_most_common(v->game, &best, &n);
    CountItemVec all = most_common_all(v->game);
    DkBuf rest;
    dk_buf_init(&rest, a);
    for (size_t i = 1; i < all.n && (int)i < limit; i++) {
        if (i > 1) dk_buf_putz(&rest, ", ");
        dk_buf_printf(&rest, "%.*s %lld", DK_SF(all.v[i].key), (long long)all.v[i].n);
    }
    dk_vec_free(&all);
    return dk_sprintf(a, "%s %s -> %.*s %lld/%lld%s%s%s", residue_span(v), v->reg, DK_SF(best), (long long)n,
                       (long long)total, rest.n ? " (also " : "", rest.n ? dk_buf_cz(&rest) : "", rest.n ? ")" : "");
}


typedef struct {
    const char *ours;
    const ResidueMapping *m;
} MapRow;

static int cmp_maprow(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    const MapRow *p = x, *q = y;
    int c = dk_cmp_i64(strcmp(p->m->game, p->ours) == 0, strcmp(q->m->game, q->ours) == 0);
    if (c) return c;
    c = dk_cmp_i64(-p->m->total, -q->m->total);
    return c ? c : strcmp(p->ours, q->ours);
}

const char *residue_mapping_text(const DkMap *mapping, int limit) {
    DkArena *a = A();
    DK_VEC(MapRow) rows = {0};
    DkMapIter it = {0};
    while (dk_map_next(mapping, &it)) dk_vec_push(&rows, ((MapRow){cstr(it.key), it.val->p}));
    dk_sort(rows.v, rows.n, sizeof(MapRow), cmp_maprow, NULL, false);
    DkBuf b;
    dk_buf_init(&b, a);
    for (size_t i = 0; i < rows.n && (int)i < limit; i++) {
        if (i) dk_buf_putz(&b, ", ");
        dk_buf_printf(&b, "%s->%s %lld/%lld", rows.v[i].ours, rows.v[i].m->game, (long long)rows.v[i].m->count,
                       (long long)rows.v[i].m->total);
    }
    if ((int)rows.n > limit) dk_buf_printf(&b, ", +%d more", (int)rows.n - limit);
    dk_vec_free(&rows);
    return dk_buf_cz(&b);
}
