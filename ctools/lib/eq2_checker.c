// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The comparison driver: both sides run in lockstep path by path; conditions, calls, stores, switches and returns are
 * compared, and every difference found is one report line (the exact text of the tool's output). */
#include "eq2_internal.h"

typedef struct Eq2Pair {
    Eq2Sim *o, *g;
} Eq2Pair;
typedef DK_VEC(Eq2Pair) Eq2PairVec;

typedef struct Impl {
    Eq2Prog *o, *g;
    ExMap visits;        /* (pc ours, pc game) -> count */
    Eq2PairVec stack;
    Eq2Pair cur;         /* the pair being walked (owned unless external) */
} Impl;

/* ------------------------------------------------------------------------------------------------ plumbing */
Eq2Checker *eq2_checker_new(Eq2Prog *ours, Eq2Prog *game) {
    eq2_init();
    Eq2Checker *ck = dk_xcalloc(1, sizeof *ck);
    Impl *im = dk_xcalloc(1, sizeof *im);
    im->o = ours;
    im->g = game;
    ck->impl = im;
    return ck;
}

static char *keep(const char *s) { return dk_strdup(dk_arena(), s); }

void eq2_checker_report(Eq2Checker *ck, const char *msg) { dk_vec_push(&ck->diffs, keep(msg)); }

static void note(Eq2Checker *ck, DkBuf *b) {
    dk_vec_push(&ck->notes, keep(dk_buf_cz(b)));
    dk_buf_free(b);
}
static void report_buf(Eq2Checker *ck, DkBuf *b) {
    eq2_checker_report(ck, dk_buf_cz(b));
    dk_buf_free(b);
}

static void put_short(DkBuf *b, const Ex *e) { eq2_short(b, e, 0); }
static const char *tri(int v) { return v < 0 ? "None" : (v ? "True" : "False"); }
static void put_outs(DkBuf *b, const Ex *fs) {   /* sorted(outs) as a list repr */
    static const struct { unsigned bit; const char *n; } names[4] = {{OUT_EQ, "eq"}, {OUT_GT, "gt"}, {OUT_LT, "lt"}, {OUT_UN, "un"}};
    const char *items[4];
    size_t n = 0;
    for (int i = 0; i < 4; i++)
        if (fs->i & names[i].bit) items[n++] = names[i].n;
    eq2_repr_list(b, items, n);
}

static void pair_free(Eq2Pair p) {
    if (p.o && !p.o->external) eq2_sim_free(p.o);
    if (p.g && !p.g->external) eq2_sim_free(p.g);
}

/* ------------------------------------------------------------------------------------------- compare_writes */
typedef struct Bad {
    Ex *k;
    const char *who;
    i64 sz;
    Ex *v;
} Bad;

static bool compare_writes(Eq2Checker *ck, Eq2Sim *so, Eq2Sim *sg, const char *where) {
    Impl *im = ck->impl;
    ExMap *fo_ = &so->st->facts, *fg_ = &sg->st->facts;
    ExMap wo = {0}, wg = {0};
    const ExEnt *e;
    EXMAP_FOR(&so->st->writes, e) {
        ExVal *v = exmap_put(&wo, exkey(eq2_subst(exkey_ex(e->key), fo_)), NULL);
        v->n = e->val.n;
        v->e = eq2_subst(e->val.e, fo_);
    }
    EXMAP_FOR(&sg->st->writes, e) {
        ExVal *v = exmap_put(&wg, exkey(eq2_subst(exkey_ex(e->key), fg_)), NULL);
        v->n = e->val.n;
        v->e = eq2_subst(e->val.e, fg_);
    }
    DK_VEC(Bad) bad = {0};
    ExMap left;
    exmap_copy(&left, &wg);
    ExEnt *a;
    EXMAP_FOR(&wo, a) {
        Ex *k = exkey_ex(a->key);
        ExEnt *hit = NULL, *b;
        EXMAP_FOR(&left, b) {
            if (b->val.n == a->val.n && eq2_eqv(k, exkey_ex(b->key)) && eq2_eqv(a->val.e, b->val.e)) {
                hit = b;
                break;
            }
        }
        if (!hit) {
            Bad x = {k, "ours", a->val.n, a->val.e};
            dk_vec_push(&bad, x);
        } else {
            hit->live = false;
            left.n_live--;
        }
    }
    EXMAP_FOR(&left, a) {
        Bad x = {exkey_ex(a->key), "game", a->val.n, a->val.e};
        dk_vec_push(&bad, x);
    }
    /* _ident: a store of the value just loaded from the same address */
    size_t j = 0;
    for (size_t i = 0; i < bad.n; i++) {
        Ex *v = bad.v[i].v;
        bool ident = v->kind == EX_TUP && v->n >= 3 && ex_is(v, EA(ld)) && eq2_eqv(v->el[2], bad.v[i].k);
        if (!ident) bad.v[j++] = bad.v[i];
    }
    bad.n = j;
    bool ok = true;
    if (bad.n) {
        DkBuf b = {0};
        dk_buf_pyfmt(&b, "stores differ %s (ours +%X, game +%X): ", where, so->st->pc - (i64)im->o->base, sg->st->pc - (i64)im->g->base);
        for (size_t i = 0; i < bad.n && i < 4; i++) {
            if (i) dk_buf_putz(&b, " / ");
            dk_buf_pyfmt(&b, "    %s-only addr ", bad.v[i].who);
            put_short(&b, bad.v[i].k);
            dk_buf_putz(&b, " = ");
            put_short(&b, ex_t2(ex_int(bad.v[i].sz), bad.v[i].v));
        }
        report_buf(ck, &b);
        ok = false;
    } else {
        exmap_clear(&so->st->writes);
        exmap_clear(&sg->st->writes);
    }
    dk_vec_free(&bad);
    exmap_free(&wo);
    exmap_free(&wg);
    exmap_free(&left);
    return ok;
}

/* ------------------------------------------------------------------------------------------- compare_ret */
static void compare_ret(Eq2Checker *ck, Eq2Sim *so, Eq2Sim *sg, const cs_insn *io, const cs_insn *ig) {
    compare_writes(ck, so, sg, "at return");
    const char *rt = ck->o_ret;
    if (rt && !strcmp(rt, "float")) {
        Ex *a = so->st->fp.n ? eq2_subst((Ex *)so->st->fp.v[so->st->fp.n - 1], &so->st->facts) : ex_none();
        Ex *b = sg->st->fp.n ? eq2_subst((Ex *)sg->st->fp.v[sg->st->fp.n - 1], &sg->st->facts) : ex_none();
        if (!eq2_eqv(a, b)) {
            DkBuf m = {0};
            dk_buf_putz(&m, "float return value differs: ours ");
            put_short(&m, a);
            dk_buf_putz(&m, " game ");
            put_short(&m, b);
            report_buf(ck, &m);
        }
    } else if (rt && !strcmp(rt, "int")) {
        Ex *a = eq2_subst(so->st->regs[R_EAX], &so->st->facts), *b = eq2_subst(sg->st->regs[R_EAX], &sg->st->facts);
        if (!eq2_eqv(a, b)) {
            DkBuf m = {0};
            dk_buf_putz(&m, "return value differs: ours ");
            put_short(&m, a);
            dk_buf_putz(&m, " game ");
            put_short(&m, b);
            report_buf(ck, &m);
        }
    } else if (rt && !strcmp(rt, "bool")) {
        Ex *a = eq2_lo8(eq2_subst(so->st->regs[R_EAX], &so->st->facts));
        Ex *b = eq2_lo8(eq2_subst(sg->st->regs[R_EAX], &sg->st->facts));
        if (!eq2_eqv(a, b)) {
            DkBuf m = {0};
            dk_buf_putz(&m, "bool return differs: ours ");
            put_short(&m, a);
            dk_buf_putz(&m, " game ");
            put_short(&m, b);
            report_buf(ck, &m);
        }
    }
    int ng = eq2_nops(ig), no = eq2_nops(io);
    if (ng && no) {
        if (eq2_op(ig, 0)->imm != eq2_op(io, 0)->imm) eq2_checker_report(ck, "ret N differs");
    } else if ((ng != 0) != (no != 0)) {
        eq2_checker_report(ck, "ret N differs");
    }
}

/* ----------------------------------------------------------------------------------------------- calls */
static Ex *callee_key(Eq2Sim *side, const cs_insn *ins) {
    const cs_x86_op *o = eq2_op(ins, 0);
    const Eq2RelocList *rel = eq2_prog_rel(side->prog, ins);
    if (o->type == X86_OP_IMM) {
        if (side->prog->ours) {
            for (u32 i = 0; i < rel->n; i++) {
                const Eq2Reloc *r = &rel->v[i].r;
                if (!strcmp(r->kind, "rel")) {
                    if (r->local) return ex_t2(EA(local), ex_str(r->symbol));
                    return r->has_target && r->target ? ex_t2(EA(abs), ex_int(r->target)) : ex_t2(EA(sym), ex_str(r->symbol));
                }
            }
            return ex_t2(EA(abs), ex_int(o->imm));
        }
        return ex_t2(EA(abs), ex_int(o->imm));
    }
    if (o->type == X86_OP_MEM) return ex_t2(EA(ind), eq2_sim_load(side, ins, o, 4));
    return ex_t2(EA(ind), eq2_get_reg(side->st, eq2_regname(o->reg)));
}

/* callee_conv(so, io): the first relocation of the call decides (the `return` sits inside the loop). */
static const char *callee_conv(Eq2Sim *so, const cs_insn *io) {
    const Eq2RelocList *rel = eq2_prog_rel(so->prog, io);
    if (!rel->n) return NULL;
    const Eq2Reloc *r = &rel->v[0].r;
    const char *sym = r->symbol;
    bool is_rel = !strcmp(r->kind, "rel");
    if (is_rel && r->conv && *r->conv) return r->conv;
    if (sym[0] != '?') {
        bool imp = !strncmp(sym, "__imp_", 6);
        const char *name = imp ? sym + 6 : sym;
        if (imp || sym[0] == '_') return strchr(name, '@') ? "stdcall" : "cdecl";
    }
    return is_rel && r->conv && *r->conv ? r->conv : NULL;   /* r.get('conv'): absent or None for 'abs' */
}

static i64 cleanup(Eq2Sim *side, const cs_insn *ins, const char *conv) {
    Eq2State *st = side->st;
    i64 n = (i64)st->pushq.n;
    if (conv && !strcmp(conv, "cdecl")) return 0;
    if (conv && (!strcmp(conv, "thiscall") || !strcmp(conv, "stdcall"))) return 4 * n;
    const cs_insn *k = eq2_prog_ins(side->prog, (i64)ins->address + ins->size);
    int steps = 0;
    while (k && steps < 16) {
        if (!strcmp(k->mnemonic, "add") && !strncmp(k->op_str, "esp,", 4)) return eq2_op(k, 1)->imm >= 4 * n ? 0 : 4 * n;
        if (!strcmp(k->mnemonic, "pop")) return 0;
        if (!strcmp(k->mnemonic, "call") || !strcmp(k->mnemonic, "ret") || !strcmp(k->mnemonic, "retn") || k->mnemonic[0] == 'j') break;
        k = eq2_prog_ins(side->prog, (i64)k->address + k->size);
        steps++;
    }
    return 4 * n;
}

static int cmp_i64(const void *a, const void *b) {
    i64 x = *(const i64 *)a, y = *(const i64 *)b;
    return x < y ? -1 : (x > y);
}

static void call_args(Eq2Sim *side, Ex ***out, size_t *n) {
    Eq2State *st = side->st;
    *n = st->pushq.n;
    DkArena *a = dk_scratch();
    i64 *sorted = dk_alloc_noz(a, (*n + 1) * sizeof(i64));
    if (*n) memcpy(sorted, st->pushq.v, *n * sizeof(i64));
    qsort(sorted, *n, sizeof(i64), cmp_i64);
    Ex **r = dk_alloc_noz(a, (*n + 1) * sizeof(Ex *));
    for (size_t i = 0; i < *n; i++) {
        ExVal *v = exmap_get(&st->stack, (u64)sorted[i]);
        Ex *x = v ? v->e : ex_t1(EA(uninit));
        r[i] = eq2_subst(eq2_b8(x), &st->facts);
    }
    *out = r;
}

static void put_short_list(DkBuf *b, Ex **v, size_t n) {
    DkArena *a = dk_scratch();
    const char **items = dk_alloc_noz(a, (n + 1) * sizeof(char *));
    for (size_t i = 0; i < n; i++) items[i] = eq2_short_cz(a, v[i]);
    eq2_repr_list(b, items, n);
}

static bool compare_call(Eq2Checker *ck, Eq2Sim *so, Eq2Sim *sg, const cs_insn *io, const cs_insn *ig) {
    Impl *im = ck->impl;
    DkArena *sa = dk_scratch();
    DkArenaMark smk = dk_arena_mark(sa);
    Ex *ko = callee_key(so, io), *kg = callee_key(sg, ig);
    DkBuf wb = {0};
    dk_buf_pyfmt(&wb, "call at ours +%X / game +%X", (i64)io->address - (i64)im->o->base, (i64)ig->address - (i64)im->g->base);
    const char *where = dk_buf_cz(&wb);
    bool result = false;
    DkBuf m = {0};
    if (ex_is(ko, EA(local))) {
        dk_buf_putz(&m, "ours calls its local function ");
        /* ko[1][:40]: forty code points */
        const char *s = ko->el[1]->s;
        size_t cp = 0, i = 0, len = ko->el[1]->n;
        while (i < len && cp < 40) {
            i++;
            while (i < len && ((u8)s[i] & 0xC0) == 0x80) i++;
            cp++;
        }
        dk_buf_putn(&m, s, i);
        dk_buf_putz(&m, " where the game has ");
        put_short(&m, kg);
        dk_buf_putz(&m, " (inline/call set differs)");
        report_buf(ck, &m);
        goto done;
    }
    if (ko != kg) {
        bool oi = ex_is(ko, EA(ind)), gi = ex_is(kg, EA(ind));
        if (oi || gi) {
            bool oas = ex_is(ko, EA(abs)) || ex_is(ko, EA(sym)), gas = ex_is(kg, EA(abs)) || ex_is(kg, EA(sym));
            if (oi && gi && eq2_eqv(ko->el[1], kg->el[1])) {
                /* pass */
            } else if ((oas && gi) || (oi && gas)) {
                dk_buf_pyfmt(&m, "callee form differs (import/thunk) %s: ", where);
                put_short(&m, ko);
                dk_buf_putz(&m, " | ");
                put_short(&m, kg);
                note(ck, &m);
            } else {
                dk_buf_pyfmt(&m, "callee differs %s: ", where);
                put_short(&m, ko);
                dk_buf_putz(&m, " | ");
                put_short(&m, kg);
                report_buf(ck, &m);
                goto done;
            }
        } else {
            dk_buf_pyfmt(&m, "callee differs %s: ours ", where);
            ex_str_of(&m, ko->el[1]);
            dk_buf_putz(&m, " game ");
            ex_str_of(&m, kg->el[1]);
            report_buf(ck, &m);
            goto done;
        }
    }
    {
        Ex **ao, **ag;
        size_t nao, nag;
        call_args(so, &ao, &nao);
        call_args(sg, &ag, &nag);
        bool same = nao == nag;
        for (size_t i = 0; same && i < nao; i++)
            if (!eq2_eqv(ao[i], ag[i])) same = false;
        if (!same) {
            dk_buf_pyfmt(&m, "call args differ %s:\n    ours ", where);
            put_short_list(&m, ao, nao);
            dk_buf_putz(&m, "\n    game ");
            put_short_list(&m, ag, nag);
            report_buf(ck, &m);
            goto done;
        }
    }
    {
        const char *conv = callee_conv(so, io);
        const char *regs[2] = {NULL, NULL};
        int nregs = 0;
        if (conv && !strcmp(conv, "thiscall")) {
            regs[nregs++] = "ecx";
        } else if (conv && !strcmp(conv, "fastcall")) {
            regs[nregs++] = "ecx";
            regs[nregs++] = "edx";
        } else if (!conv) {
            if (so->st->fresh[1] && sg->st->fresh[1] && !eq2_eqv(so->st->regs[R_ECX], sg->st->regs[R_ECX])) {
                dk_buf_pyfmt(&m, "unknown-convention call %s: ecx ", where);
                put_short(&m, so->st->regs[R_ECX]);
                dk_buf_putz(&m, " | ");
                put_short(&m, sg->st->regs[R_ECX]);
                note(ck, &m);
            }
        }
        for (int i = 0; i < nregs; i++) {
            int ri = regs[i][1] == 'c' ? R_ECX : R_EDX;
            if (!eq2_eqv(eq2_subst(so->st->regs[ri], &so->st->facts), eq2_subst(sg->st->regs[ri], &sg->st->facts))) {
                dk_buf_pyfmt(&m, "%s differs at %s: ours ", regs[i], where);
                put_short(&m, so->st->regs[ri]);
                dk_buf_putz(&m, " game ");
                put_short(&m, sg->st->regs[ri]);
                report_buf(ck, &m);
                goto done;
            }
        }
        DkBuf bw = {0};
        dk_buf_pyfmt(&bw, "before %s", where);
        bool ok = compare_writes(ck, so, sg, dk_buf_cz(&bw));
        dk_buf_free(&bw);
        if (!ok) goto done;
        /* effects of the call */
        conv = callee_conv(so, io);
        Eq2Sim *sides[2] = {so, sg};
        const cs_insn *inss[2] = {io, ig};
        for (int s = 0; s < 2; s++) {
            Eq2State *st = sides[s]->st;
            const cs_insn *ins = inss[s];
            i64 cid = st->epoch;
            i64 cl = cleanup(sides[s], ins, conv);
            st->esp += cl;
            st->pushq.n = 0;
            st->epoch += 1;
            st->regs[R_EAX] = ex_t2(EA(ret), ex_int(cid));
            st->regs[R_ECX] = ex_t3(EA(clob), ex_int(cid), ex_str("ecx"));
            st->regs[R_EDX] = ex_t3(EA(clob), ex_int(cid), ex_str("edx"));
            st->fresh[0] = true;
            st->fresh[1] = false;
            st->fresh[2] = false;
            for (int k = 0; k < 8; k++) {
                char nm[8];
                snprintf(nm, sizeof nm, "xmm%d", k);
                st->xmm[k] = ex_t3(EA(clobx), ex_int(cid), ex_str(nm));
            }
            st->fp.n = 0;
            dk_vec_push(&st->fp, ex_t2(EA(retf), ex_int(cid)));
            exmap_clear(&st->mem);
            st->flags = NULL;
            st->pc = (i64)ins->address + ins->size;
        }
        result = true;
    }
done:
    dk_buf_free(&m);
    dk_buf_free(&wb);
    dk_arena_reset(sa, smk);
    return result;
}

/* ---------------------------------------------------------------------------------------------- switch */
static void push_pair(Impl *im, Eq2Sim *o, Eq2Sim *g) {
    Eq2Pair p = {o, g};
    dk_vec_push(&im->stack, p);
}

static void idx_info(Eq2Sim *side, const cs_insn *ins, Ex **v, i64 *tab) {
    const cs_x86_op *o = eq2_op(ins, 0);
    const char *r = eq2_regname(o->mem.index);
    *v = eq2_get_reg(side->st, r);
    i64 t = o->mem.disp;
    const Eq2RelocList *rel = eq2_prog_rel(side->prog, ins);
    if (side->prog->ours) {
        for (u32 i = 0; i < rel->n; i++) {
            const Eq2Reloc *x = &rel->v[i].r;
            if (!strcmp(x->kind, "abs")) {
                if (x->has_label) t = (i64)x->label + (i64)side->prog->base;
            }
        }
    }
    *tab = t;
}

static void do_switch(Eq2Checker *ck, Eq2Sim *so, Eq2Sim *sg, const cs_insn *io, const cs_insn *ig) {
    Impl *im = ck->impl;
    Ex *vo, *vg;
    i64 to, tg;
    idx_info(so, io, &vo, &to);
    idx_info(sg, ig, &vg, &tg);
    if (vo != vg) {
        /* sparse tables: both load an index byte from their own table; accept equal underlying indexes */
        if (!(ex_is(vo, EA(zx8)) && ex_is(vg, EA(zx8)))) {
            DkBuf m = {0};
            dk_buf_putz(&m, "switch index differs: ours ");
            put_short(&m, vo);
            dk_buf_putz(&m, " game ");
            put_short(&m, vg);
            report_buf(ck, &m);
            return;
        }
    }
    /* the case count: the consecutive relocations of ours at the table that carry a label */
    int cnt = 0;
    for (;;) {
        ExVal *v = exmap_get(&so->prog->reloc_at, (u64)(to - (i64)so->prog->base + 4 * (i64)cnt));
        if (!v || !so->prog->relocs[v->n].has_label) break;
        cnt++;
    }
    if (cnt == 0) {
        eq2_checker_report(ck, "switch table of ours not found");
        return;
    }
    DkArena *sa = dk_scratch();
    DkArenaMark smk = dk_arena_mark(sa);
    i64 *tos = dk_alloc_noz(sa, (size_t)cnt * sizeof(i64));
    i64 *tgs = dk_alloc_noz(sa, (size_t)cnt * sizeof(i64));
    eq2_prog_table_targets(so->prog, to, cnt, tos);
    eq2_prog_table_targets(sg->prog, tg, cnt, tgs);
    DkBuf m = {0};
    dk_buf_pyfmt(&m, "switch with %d table entries", cnt);
    note(ck, &m);
    for (int k = 0; k < cnt; k++) {
        Eq2Switch sw = {k, (u32)(tos[k] - (i64)im->o->base), (u32)(tgs[k] - (i64)im->g->base)};
        dk_vec_push(&ck->switches, sw);
        Eq2Sim *no = eq2_sim_copy(so), *ng = eq2_sim_copy(sg);
        no->st->pc = tos[k];
        ng->st->pc = tgs[k];
        push_pair(im, no, ng);
    }
    dk_arena_reset(sa, smk);
}

/* ------------------------------------------------------------------------------------------------- walk */
typedef struct PathSel {
    i64 po, pg;
    bool tko, tkg;
} PathSel;

static void walk(Eq2Checker *ck, Eq2Sim *so, Eq2Sim *sg) {
    Impl *im = ck->impl;
    for (;;) {
        Ex *vkey = ex_t2(ex_int(so->st->pc), ex_int(sg->st->pc));
        ExVal *vv = exmap_get(&im->visits, exkey(vkey));
        i64 n = vv ? vv->n : 0;
        if (n >= 4) return;
        exmap_put(&im->visits, exkey(vkey), NULL)->n = n + 1;
        Eq2Event ev_o = eq2_step_until_event(so);
        Eq2Event ev_g = eq2_step_until_event(sg);
        if (ev_o.kind != ev_g.kind) {
            DkBuf m = {0};
            dk_buf_pyfmt(&m, "event kind differs: ours %s at +%X, game %s at +%X", eq2_ev_names[ev_o.kind],
                          (i64)ev_o.ins->address - (i64)im->o->base, eq2_ev_names[ev_g.kind], (i64)ev_g.ins->address - (i64)im->g->base);
            report_buf(ck, &m);
            return;
        }
        switch (ev_o.kind) {
        case EV_RET:
            compare_ret(ck, so, sg, ev_o.ins, ev_g.ins);
            return;
        case EV_TAIL:
            compare_call(ck, so, sg, ev_o.ins, ev_g.ins);
            return;
        case EV_CALL:
            if (!compare_call(ck, so, sg, ev_o.ins, ev_g.ins)) return;
            continue;
        case EV_COND: {
            const cs_insn *io = ev_o.ins, *ig = ev_g.ins;
            Ex *co = ev_o.cond, *cg = ev_g.cond;
            Ex *co2 = eq2_cond_subst(co, &so->st->facts), *cg2 = eq2_cond_subst(cg, &sg->st->facts);
            int do_ = eq2_eval_const_cond(co2), dg = eq2_eval_const_cond(cg2);
            if (do_ >= 0 || dg >= 0) {
                int rel_ = eq2_cond_eq(co, cg) ? 0 : (eq2_cond_eq(co, eq2_negate_cond(cg)) ? 1 : 2);   /* same, neg, other */
                if (do_ < 0 || dg < 0 || (rel_ == 0 && do_ != dg) || (rel_ == 1 && do_ == dg)) {
                    DkBuf m = {0};
                    dk_buf_pyfmt(&m, "condition folds differently: ours +%X %s -> %s; game +%X %s -> %s", (i64)io->address - (i64)im->o->base,
                                  io->mnemonic, tri(do_), (i64)ig->address - (i64)im->g->base, ig->mnemonic, tri(dg));
                    report_buf(ck, &m);
                    return;
                }
                so->st->pc = do_ ? ev_o.t : ev_o.f;
                sg->st->pc = dg ? ev_g.t : ev_g.f;
                if (ev_o.set) eq2_sim_assign(so, io, 0, ex_c(do_ ? 1 : 0));
                if (ev_g.set) eq2_sim_assign(sg, ig, 0, ex_c(dg ? 1 : 0));
                continue;
            }
            co = co2;
            cg = cg2;
            PathSel pairs[2];
            if (eq2_cond_eq(co, cg)) {
                pairs[0] = (PathSel){ev_o.t, ev_g.t, true, true};
                pairs[1] = (PathSel){ev_o.f, ev_g.f, false, false};
            } else if (eq2_cond_eq(co, eq2_negate_cond(cg))) {
                pairs[0] = (PathSel){ev_o.t, ev_g.f, true, false};
                pairs[1] = (PathSel){ev_o.f, ev_g.t, false, true};
            } else {
                DkBuf m = {0};
                dk_buf_pyfmt(&m, "condition differs: ours +%X %s [%s ", (i64)io->address - (i64)im->o->base, io->mnemonic, co->el[0]->s);
                put_outs(&m, co->el[1]);
                dk_buf_putc(&m, ' ');
                put_short(&m, co->el[2]);
                dk_buf_putc(&m, ' ');
                put_short(&m, co->el[3]);
                dk_buf_pyfmt(&m, "]\n    game +%X %s [%s ", (i64)ig->address - (i64)im->g->base, ig->mnemonic, cg->el[0]->s);
                put_outs(&m, cg->el[1]);
                dk_buf_putc(&m, ' ');
                put_short(&m, cg->el[2]);
                dk_buf_putc(&m, ' ');
                put_short(&m, cg->el[3]);
                dk_buf_putc(&m, ']');
                report_buf(ck, &m);
                return;
            }
            for (int i = 0; i < 2; i++) {
                Eq2Sim *no = eq2_sim_copy(so), *ng = eq2_sim_copy(sg);
                no->st->pc = pairs[i].po;
                ng->st->pc = pairs[i].pg;
                if (ev_o.set) eq2_sim_assign(no, io, 0, ex_c(pairs[i].tko ? 1 : 0));
                if (ev_g.set) eq2_sim_assign(ng, ig, 0, ex_c(pairs[i].tkg ? 1 : 0));
                eq2_add_fact(&no->st->facts, co, pairs[i].tko);
                eq2_add_fact(&ng->st->facts, cg, pairs[i].tkg);
                push_pair(im, no, ng);
            }
            return;
        }
        case EV_SWITCH:
            do_switch(ck, so, sg, ev_o.ins, ev_g.ins);
            return;
        }
        eq2_unsupported("event %s", eq2_ev_names[ev_o.kind]);
    }
}

/* -------------------------------------------------------------------------------------------------- run */
void eq2_checker_run(Eq2Checker *ck, Eq2Sim *so, Eq2Sim *sg) {
    Impl *im = ck->impl;
    push_pair(im, so, sg);
    while (im->stack.n && ck->diffs.n < 4 && ck->paths < 4000) {
        im->cur = dk_vec_pop(&im->stack);
        ck->paths++;
        DkArena *sa = dk_scratch();
        DkArenaMark mk = dk_arena_mark(sa);
        Eq2Catch c;
        if (EQ2_TRY(&c)) {
            walk(ck, im->cur.o, im->cur.g);
            eq2_catch_end(&c);
            dk_arena_reset(sa, mk);
            pair_free(im->cur);
            memset(&im->cur, 0, sizeof im->cur);
        } else {
            dk_arena_reset(sa, mk);
            pair_free(im->cur);
            memset(&im->cur, 0, sizeof im->cur);
            for (size_t i = 0; i < im->stack.n; i++) pair_free(im->stack.v[i]);
            im->stack.n = 0;
            if (c.kind == EQ2_EXC_UNSUPPORTED) {
                DkBuf m = {0};
                dk_buf_pyfmt(&m, "UNSUPPORTED: %s", c.msg);
                report_buf(ck, &m);
                return;
            }
            dk_throw(DK_ERR_OTHER, "%s", c.msg);
        }
    }
    for (size_t i = 0; i < im->stack.n; i++) pair_free(im->stack.v[i]);
    im->stack.n = 0;
}
