// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The front end of eq2: which function in which target, the relocation table of our side, the output of one run and
 * the loop over a unit's functions (see eq2_front.h).
 *
 * A function that cannot be built prints `<name> BUILD ERROR <text>` and the run goes on: a unit that fails to
 * build, a result with no bytes, and what the engine throws (dk_throw) while the programs are decoded. */
#include "eq2_front.h"
#include "unitcmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------------------------- ret_kind, conv_of */

const char *eq2_ret_kind(DkStr plain) {
    static const char pat[] =
        "^(?:public: |private: |protected: )?(?:static |virtual )?(.*?)\\s*(?:__cdecl|__thiscall|__stdcall|__fastcall)";
    DkStr t = {"", 0};
    DkReMatch m;
    if (plain.p && dk_re_match(dk_re(pat, 0), plain, 0, DK_END, &m)) t = dk_str_strip(dk_re_group(&m, 1));
    if (dk_str_eqz(t, "void")) return "void";
    if (t.n == 0) return "int";
    if (dk_str_eqz(t, "float") || dk_str_eqz(t, "double")) return "float";
    if (dk_str_eqz(t, "bool") || dk_str_eqz(t, "char") || dk_str_eqz(t, "unsigned char") ||
        dk_str_eqz(t, "signed char"))
        return "bool";
    return "int";
}

const char *eq2_conv_of(DkStr plain) {
    static const char *const names[] = {"cdecl", "thiscall", "stdcall", "fastcall"};
    if (!plain.p) return NULL;
    /* the leftmost occurrence of any of the four */
    for (size_t i = 0; i + 2 <= plain.n; i++) {
        if (plain.p[i] != '_' || plain.p[i + 1] != '_') continue;
        for (size_t k = 0; k < 4; k++) {
            size_t len = strlen(names[k]);
            if (i + 2 + len <= plain.n && memcmp(plain.p + i + 2, names[k], len) == 0) return names[k];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------------------------------------------- build */

typedef struct {
    bool ok;
    const char *error; /* the text of the failure when !ok */
    Eq2Prog *ours, *game;
    DkStr plain;
} Eq2Built;

static void fail(Eq2Built *b, const char *text) {
    b->ok = false;
    b->error = text;
}

static bool starts_with(const char *s, const char *prefix) { return strncmp(s, prefix, strlen(prefix)) == 0; }

/* The reference images the engine reads constants and jump tables from, one per target. */
static const Eq2Image *engine_image(DkProject *p, int target, DkErr *err) {
    static const Eq2Image *images[DK_MAX_TARGETS];
    if (!images[target]) {
        const DkImage *image = dk_target_image(p, target, err);
        if (image) images[target] = eq2_image_of(dk_project_arena(p), image);
    }
    return images[target];
}

/* The relocations of our function: the comparison's verdict decides the address each resolved to. */
static void build_relocs(DkArena *a, const DkResult *r, Eq2RelocVec *out) {
    const DkFunc *fn = &r->ours;
    for (size_t i = 0; i < fn->n_relocs; i++) {
        const DkReloc *x = &fn->relocs[i];
        if ((size_t)x->offset >= fn->code.n) continue;
        const DkRefCheck *c = NULL;
        for (size_t k = 0; k < r->n_refs; k++)
            if (r->refs[k].offset == x->offset) c = &r->refs[k];
        Eq2Reloc d;
        memset(&d, 0, sizeof d);
        d.offset = x->offset;
        d.symbol = x->symbol ? x->symbol : "?";
        d.status = c ? (c->verdict == DK_REF_SAME ? "same" : c->verdict == DK_REF_OTHER ? "other" : "unresolved") : "?";
        bool rel = x->type == 0x14; /* IMAGE_REL_I386_REL32 */
        if (c && c->verdict != DK_REF_UNRESOLVED && c->ours) {
            d.has_target = true;
            d.target = c->ours;
        } else if (!x->symbol && c && c->theirs) {
            d.has_target = true;
            d.target = c->theirs;
        }
        if (!rel && fn->symbol && x->symbol && strcmp(x->symbol, fn->symbol) == 0 && x->addend != 0) {
            /* a label inside the function (a jump table entry): the offset of the label from the function's start */
            d.has_label = true;
            d.label = (u32)x->addend;
            d.has_target = false;
            d.kind = "abs";
        } else if (rel) {
            d.kind = "rel";
            char *name = dk_strdup(a, d.symbol);
            char *hash = strchr(name, '#'); /* the adapter's "name#<slot>" for a name defined twice */
            if (hash) *hash = 0;
            d.conv = eq2_conv_of(dk_undecorate_symbol(a, name, 0));
        } else {
            d.kind = "abs";
        }
        if (starts_with(d.symbol, "__real@") || starts_with(d.symbol, "__xmm@") || starts_with(d.symbol, "__mask@"))
            d.has_target = false;
        if (starts_with(d.symbol, "??_C@")) {
            d.has_target = false;
            d.strlit = true;
        }
        dk_vec_push(out, d);
    }
}

/* The two Progs of one result, or b->error. */
static void eq2_build(DkProject *p, const DkResult *r, Eq2Built *b) {
    DkArena *a = dk_project_arena(p);
    if (r->status == DK_ERROR || r->status == DK_MISSING || !r->ours.code.p || !r->ours.code.n) {
        fail(b, r->error ? r->error : "no compiled function");
        return;
    }
    DkErr err = {0};
    DkImage *im = dk_target_image(p, r->target, &err);
    const Eq2Image *eim = im ? engine_image(p, r->target, &err) : NULL;
    if (!eim) {
        fail(b, dk_strdup(a, err.msg));
        return;
    }
    u32 base = r->theirs_va;
    DkStr code = r->ours.code, game = r->theirs;
    u32 gs = 0;
    if (dk_image_function_size(im, base, &gs) && gs) {
        u32 total = gs > code.n ? gs : (u32)code.n;
        const char *e = NULL;
        if (!eq2_image_read(eim, base, total, &game, &e)) {
            fail(b, e);
            return;
        }
    }
    if (gs && gs > code.n + 64) dk_pyprintf("NOTE reference function size %d ours %d\n", gs, code.n);
    Eq2RelocVec relocs = {0};
    build_relocs(a, r, &relocs);
    b->ours = eq2_prog_new("ours", code, base, &relocs, eim, true);
    Eq2RelocVec none = {0};
    b->game = eq2_prog_new("game", game, base, &none, eim, false);
    b->plain = r->ours.symbol ? dk_undecorate_symbol(a, r->ours.symbol, 0) : (DkStr){"", 0};
    b->ok = true;
}

/* ------------------------------------------------------------------------------------------------------- one */

/* The differences without repeats: one met on several paths prints once. */
static DkCzVec dedup(const DkCzVec *diffs) {
    DkCzVec out = {0};
    DkSet *seen = dk_set_new();
    for (size_t i = 0; i < diffs->n; i++)
        if (dk_set_add(seen, dk_str(diffs->v[i]))) dk_vec_push(&out, diffs->v[i]);
    dk_set_free(seen);
    return out;
}

/* One function: true when EQUIVALENT. */
static bool eq2_one(DkProject *p, const char *name, const DkResult *r, bool verbose) {
    DkArena *a = dk_project_arena(p);
    const char *tname = dk_project_target(p, r->target)->name;
    Eq2Built *b = DK_NEW(a, Eq2Built);
    DkTry t;
    if (DK_TRY(&t)) {
        eq2_build(p, r, b);
        dk_try_end(&t);
    } else {
        fail(b, dk_strdup(a, t.msg));
    }
    if (!b->ok) {
        printf("%s BUILD ERROR %s\n", name, b->error);
        return false;
    }
    Eq2Checker *ck = eq2_checker_new(b->ours, b->game);
    ck->o_ret = eq2_ret_kind(b->plain);
    Eq2Sim *so = eq2_sim_new(b->ours, eq2_state_new(b->ours));
    Eq2Sim *sg = eq2_sim_new(b->game, eq2_state_new(b->game));
    DkTry t2;
    if (DK_TRY(&t2)) {
        eq2_checker_run(ck, so, sg);
        dk_try_end(&t2);
    } else {
        eq2_checker_report(ck, dk_strdup(a, t2.msg));
    }
    DkCzVec diffs = dedup(&ck->diffs);
    dk_pyprintf("%s %s: %s (paths %d, ret=%s)\n", name, tname, diffs.n ? "DIFFERENT" : "EQUIVALENT", ck->paths,
                ck->o_ret);
    for (size_t i = 0; i < diffs.n; i++) dk_pyprintf("  %s\n", diffs.v[i]);
    if (verbose) {
        for (size_t i = 0; i < ck->notes.n && i < 10; i++) dk_pyprintf("  note: %s\n", ck->notes.v[i]);
        for (size_t i = 0; i < ck->switches.n && i < 40; i++)
            dk_pyprintf("  case %d: ours +%X reference +%X\n", ck->switches.v[i].value, ck->switches.v[i].ours,
                        ck->switches.v[i].game);
    }
    bool same = diffs.n == 0;
    dk_vec_free(&diffs);
    return same;
}

/* ------------------------------------------------------------------------------------------------------ main */

typedef struct {
    const char *name;
    const DkResult *r;
} Job;
typedef DK_VEC(Job) JobVec;

static int cmp_job(const void *x, const void *y) {
    const Job *a = x, *b = y;
    if (a->r->ann->line != b->r->ann->line) return a->r->ann->line < b->r->ann->line ? -1 : 1;
    return a->r->target - b->r->target;
}

static int cmp_names(const void *x, const void *y) { return strcmp(*(const char *const *)x, *(const char *const *)y); }

static u32 first_target_bit(u32 mask) {
    u32 t = 0;
    while (t < DK_MAX_TARGETS && !(mask & (1u << t))) t++;
    return t;
}

bool eq2_run(DkProject *p, const char *unit, const char *functions, int target, bool verbose, int *exit_code,
             DkErr *err) {
    DkArena *a = dk_project_arena(p);
    *exit_code = 0;
    DkUnitcmpOpts o;
    memset(&o, 0, sizeof o);
    o.units = &unit;
    o.n_units = 1;
    o.target = target;
    o.use_cache = true;
    DkUnitcmpRowVec rows = {0};
    if (!dk_unitcmp_collect(p, &o, &rows, err)) return false;

    JobVec jobs = {0};
    DkStrVec names = dk_str_split(dk_str(functions), DK_S(","), -1);
    if (names.n == 1 && dk_str_eqz(names.v[0], "ALL")) {
        for (size_t i = 0; i < rows.n; i++) {
            const DkResult *r = rows.v[i].r;
            if (!r->ann || !r->ann->name || !dk_stopped(r->ann, r->target)) continue;
            if (target < 0 && (u32)r->target != first_target_bit(r->ann->target_mask)) continue;
            Job j = {r->ann->name, r};
            dk_vec_push(&jobs, j);
        }
        if (jobs.n > 1) qsort(jobs.v, jobs.n, sizeof *jobs.v, cmp_job);
    } else {
        for (size_t k = 0; k < names.n; k++) {
            const char *want = dk_cz(a, names.v[k]);
            const DkResult *best = NULL;
            for (size_t i = 0; i < rows.n; i++) {
                const DkResult *r = rows.v[i].r;
                if (!r->ann || !dk_unitcmp_selects(p, r->ann, want)) continue;
                if (!best || r->ann->line < best->ann->line ||
                    (r->ann->line == best->ann->line && r->target < best->target))
                    best = r;
            }
            if (best) {
                Job j = {want, best};
                dk_vec_push(&jobs, j);
                continue;
            }
            /* no such function: say which names the unit has */
            size_t nn = 0;
            const char **have = DK_NEWN(a, const char *, rows.n + 1);
            for (size_t i = 0; i < rows.n; i++) {
                const DkAnnot *an = rows.v[i].r->ann;
                if (!an || !an->name) continue;
                bool dup = false;
                for (size_t m = 0; m < nn && !dup; m++) dup = strcmp(have[m], an->name) == 0;
                if (!dup) have[nn++] = an->name;
            }
            qsort(have, nn, sizeof *have, cmp_names);
            printf("%s BUILD ERROR no such function: %s in", want, want);
            for (size_t m = 0; m < nn && m < 10; m++) printf("%s %s", m ? "," : "", have[m]);
            printf("\n");
            *exit_code = 1;
        }
    }
    for (size_t i = 0; i < jobs.n; i++)
        if (!eq2_one(p, jobs.v[i].name, jobs.v[i].r, verbose)) *exit_code = 1;
    dk_vec_free(&jobs);
    dk_vec_free(&names);
    dk_vec_free(&rows);
    return true;
}
