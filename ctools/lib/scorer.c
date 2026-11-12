// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
#include "scorer.h"

#include "dk/dk.h"
#include "insn_text.h"
#include "unitcmp.h"
#include "walls.h"

#include <string.h>

typedef struct {
    DkProject *p;   /* the slot's clone */
    const DkUnit *unit;
    DkArenaMark mark;
    bool marked;
} Slot;

typedef struct {
    Slot *slots;
    DkMutex lock;   /* the comparison with the image and the first-time state of the scorer */
} Priv;

/* ---- scores ------------------------------------------------------------------------------------------------------ */
int dk_score_cmp(DkScore a, DkScore b) {
    const i64 x[3] = {a.status, a.differ, a.dissim}, y[3] = {b.status, b.differ, b.dissim};
    for (int i = 0; i < 3; i++)
        if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
}

bool dk_score_exact(DkScore s) { return dk_score_cmp(s, DK_SCORE_EXACT) == 0; }

const char *dk_score_str(DkScore s) {
    return dk_sprintf(dk_arena(), "S%lld D%lld R%lld", (long long)s.status, (long long)s.differ, (long long)s.dissim);
}

const char *dk_score_tag(DkScore s) {
    return dk_sprintf(dk_arena(), "S%lld_D%lld_R%lld", (long long)s.status, (long long)s.differ, (long long)s.dissim);
}

void dk_scored_free(DkScored *s) {
    dk_xfree((void *)s->code.p);
    dk_xfree(s->reloc_offsets);
    memset(s, 0, sizeof *s);
}

static i64 status_rank(DkStatus st) {
    switch (st) {
    case DK_MATCH: return 0;
    case DK_REFERENT: return 1;
    case DK_UNRESOLVED: return 2;
    case DK_DIFF: return 3;
    default: return 4;
    }
}

/* 1000 - round(1000 * difflib ratio) of the normalised instruction texts. */
static i64 dissimilarity(DkArena *a, const DkResult *r) {
    DkInsnTextVec ours = dk_insn_disassemble(a, r->ours.code, r->theirs_va, r->ours.relocs, r->ours.n_relocs);
    DkInsnTextVec theirs = dk_insn_disassemble(a, r->theirs, r->theirs_va, NULL, 0);
    DkStr *av = DK_NEWN(a, DkStr, ours.n + 1), *bv = DK_NEWN(a, DkStr, theirs.n + 1);
    for (size_t i = 0; i < ours.n; i++) av[i] = dk_insn_normalise(a, ours.v[i].text, ours.v[i].note.n != 0);
    for (size_t j = 0; j < theirs.n; j++) bv[j] = dk_insn_normalise(a, theirs.v[j].text, false);
    DkSeqMatcher *sm = dk_seqm_new_str(a, av, ours.n, bv, theirs.n, &dk_seqm_no_autojunk);
    double ratio = dk_seqm_ratio(sm);
    dk_vec_free(&ours);
    dk_vec_free(&theirs);
    return 1000 - (i64)(ratio * 1000.0 + 0.5);
}

/* ---- the state key ----------------------------------------------------------------------------------------------- */
/* The names that differ between two compiles of the same code are blanked: string literals ("??_C@...") and
 * compiler labels ("$..."). */
static bool blank_name(const char *n) { return strncmp(n, "??_C@", 5) == 0 || n[0] == '$'; }

static const char *state_key(const DkFunc *f, size_t n) {
    DkHasher h;
    dk_hasher_init(&h, DK_HASH_SHA256);
    dk_hasher_update(&h, f->code.p, n);
    for (size_t i = 0; i < f->n_relocs; i++) {
        const DkReloc *r = &f->relocs[i];
        const char *name = r->symbol && !blank_name(r->symbol) ? r->symbol : "";
        char head[32];
        int k = snprintf(head, sizeof head, "|%u:%d:", r->offset, (int)r->addend);
        dk_hasher_update(&h, head, (size_t)k);
        dk_hasher_update(&h, name, strlen(name));
    }
    u8 d[32];
    dk_hasher_final(&h, d);
    dk_hasher_free(&h);
    return dk_hex(dk_arena(), d, 32);
}

/* ---- selecting and creating -------------------------------------------------------------------------------------- */
const DkAnnot *dk_scorer_select(DkProject *p, const DkUnit *u, const char *name, u32 address, int target, DkErr *err) {
    size_t n = 0;
    DkAnnot *v = dk_annotations(p, u, &n, err);
    if (!v) {
        if (err && !err->code) dk_err_set(err, DK_ERR_OTHER, "%s: no annotations", u->path);
        return NULL;
    }
    const DkAnnot *hit = NULL;
    size_t hits = 0;
    for (size_t i = 0; i < n; i++) {
        const DkAnnot *an = &v[i];
        if (an->kind != DK_ANN_FUNCTION || !(an->target_mask >> target & 1) || !dk_unitcmp_selects(p, an, name)) continue;
        if (address != DK_NO_ADDR && an->addr[target] != address) continue;
        hit = an;
        hits++;
    }
    if (hits == 0) {
        dk_err_set(err, DK_ERR_OTHER, "%s: no annotated function %s%s in target %s", u->path, name,
                   address ? " at that address" : "", dk_project_target(p, target)->name);
        return NULL;
    }
    if (hits > 1) {
        dk_err_set(err, DK_ERR_OTHER, "%s: %zu annotations fit %s: give --address", u->path, hits, name);
        return NULL;
    }
    return hit;
}

DkScorer *dk_scorer_new(DkProject *p, const DkUnit *u, const DkAnnot *an, int target, int slots, const char *work_root,
                        DkErr *err) {
    DkArena *a = dk_arena();
    if (slots < 1) slots = 1;
    DkScorer *s = DK_NEW(a, DkScorer);
    Priv *pv = DK_NEW(a, Priv);
    pv->slots = DK_NEWN(a, Slot, slots);
    for (int k = 0; k < slots; k++) {
        const char *dir = dk_sprintf(a, "%s/s%d", work_root, k);
        dk_makedirs(dir, true);
        pv->slots[k].p = dk_project_clone(p, dir, err);
        if (!pv->slots[k].p) return NULL;
        pv->slots[k].unit = dk_project_unit(pv->slots[k].p, u->path);
        if (!pv->slots[k].unit) {
            dk_err_set(err, DK_ERR_OTHER, "%s: not a unit of the cloned project", u->path);
            return NULL;
        }
    }
    s->project = p;
    s->unit = u;
    s->annot = an;
    s->target = target;
    s->address = an->addr[target];
    s->name = an->name;
    s->nslots = slots;
    s->priv = pv;
    return s;
}

/* ---- evaluating -------------------------------------------------------------------------------------------------- */
bool dk_scorer_evaluate(DkScorer *s, int slot, const char *source, DkScored *out, DkStr *log, DkErr *err) {
    Priv *pv = s->priv;
    Slot *sl = &pv->slots[slot];
    DkArena *sa = dk_project_arena(sl->p);
    memset(out, 0, sizeof *out);
    if (log) *log = (DkStr){"", 0};
    bool ok = false;

    DkBuildOpts bo;
    memset(&bo, 0, sizeof bo);
    bo.source_override = source;
    const char *unit_dir = dk_cz(sa, dk_path_dirname(dk_path_abspath(sa, dk_project_path(sa, s->project, s->unit->path))));
    DkStr inc = dk_str(dk_sprintf(sa, "/I%s", unit_dir));
    dk_vec_push(&bo.extra_flags, inc);
    size_t nfn = 0;
    DkStr blog = {"", 0};
    DkErr be = {0};
    DkFunc *fns = dk_build_unit(sl->p, sl->unit, s->target, &bo, &nfn, &blog, &be);
    if (log) *log = (DkStr){dk_cz(dk_arena(), blog), blog.n};
    if (!fns) {
        dk_err_set(err, DK_ERR_OTHER, "%s", be.msg[0] ? be.msg : "build failed");
        goto done;
    }
    DkCzVec names = {0};
    for (size_t i = 0; i < nfn; i++) dk_vec_push(&names, (char *)fns[i].symbol);
    DkErr ae = {0};
    const char *sym = dk_annot_bind(s->annot, dk_project_annot_config(s->project)->name, (const char *const *)names.v,
                                    names.n, &ae);
    dk_vec_free(&names);
    const DkFunc *fn = NULL;
    for (size_t i = 0; sym && i < nfn && !fn; i++)
        if (fns[i].symbol == sym) fn = &fns[i];
    if (!fn) {
        dk_err_set(err, DK_ERR_OTHER, "%s", ae.msg[0] ? ae.msg : "the candidate has no function for the annotation");
        goto done;
    }

    dk_mutex_lock(&pv->lock);
    DkErr ce = {0};
    DkResult *r = dk_compare(s->project, s->annot, s->target, fn, &ce);
    if (r->status == DK_ERROR || r->status == DK_MISSING) {
        dk_err_set(err, DK_ERR_OTHER, "%s", r->error ? r->error : ce.msg);
        dk_mutex_unlock(&pv->lock);
        goto done;
    }
    if (!s->symbol) {
        s->symbol = dk_strdup(dk_arena(), fn->symbol);
        DkErr ie = {0};
        DkImage *im = dk_target_image(s->project, s->target, &ie);
        DkStr win = dk_wall_reference_window(r, im);
        u8 *copy = dk_xmalloc(win.n ? win.n : 1);
        memcpy(copy, win.p, win.n);
        s->game = (DkStr){(const char *)copy, win.n};
    }
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    size_t nd = 0;
    dk_result_differ(sc, r, &nd);
    out->status = r->status;
    out->score.status = status_rank(r->status);
    out->score.differ = (i64)nd;
    out->score.dissim = r->status == DK_MATCH ? 0 : dissimilarity(sc, r);
    dk_arena_reset(sc, mk);
    dk_mutex_unlock(&pv->lock);

    out->key = state_key(&r->ours, r->ours.code.n);
    u8 *code = dk_xmalloc(r->ours.code.n ? r->ours.code.n : 1);
    memcpy(code, r->ours.code.p, r->ours.code.n);
    out->code = (DkStr){(const char *)code, r->ours.code.n};
    out->n_relocs = r->ours.n_relocs;
    out->reloc_offsets = dk_xmalloc((r->ours.n_relocs ? r->ours.n_relocs : 1) * sizeof(u32));
    for (size_t i = 0; i < r->ours.n_relocs; i++) out->reloc_offsets[i] = r->ours.relocs[i].offset;
    ok = true;

done:
    dk_vec_free(&bo.extra_flags);
    if (!sl->marked) {
        sl->mark = dk_arena_mark(sa);
        sl->marked = true;
    } else {
        dk_arena_reset(sa, sl->mark);
    }
    return ok;
}
