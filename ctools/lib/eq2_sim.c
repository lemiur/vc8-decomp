// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The machine model of one side: Prog (decoded instructions and relocations), State (registers, stack, memory,
 * flags, x87 stack) and Sim (operand evaluation: memory addresses, loads and stores, immediates, constant pools). */
#include "eq2_internal.h"
#include <windows.h>
#include <stdlib.h>

static const char *R32_NAMES[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};

static int reg32_idx(const char *n) {
    for (int i = 0; i < 8; i++)
        if (!strcmp(n, R32_NAMES[i])) return i;
    return -1;
}

/* ------------------------------------------------------------------------------------------- register names */
static const char *g_regnames[X86_REG_ENDING];

static void regnames_init(void) {
    csh h = dk_dis_handle(dk_dis(DK_DIS_X86_32, DK_DIS_DETAIL));
    for (unsigned i = 1; i < X86_REG_ENDING; i++) g_regnames[i] = cs_reg_name(h, i);
}

const char *eq2_regname(unsigned reg) { return reg < X86_REG_ENDING ? g_regnames[reg] : NULL; }

/* The registers' names are filled once, by the first Prog. */
static INIT_ONCE g_names_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK names_cb(PINIT_ONCE o, PVOID p, PVOID *c) {
    DK_UNUSED(o);
    DK_UNUSED(p);
    DK_UNUSED(c);
    regnames_init();
    return TRUE;
}

const char *const eq2_ev_names[5] = {"tail", "switch", "cond", "call", "ret"};

/* -------------------------------------------------------------------------------------------------- Prog */
static const char *dupz(const char *s) { return s ? dk_strdup(dk_arena(), s) : NULL; }

Eq2Prog *eq2_prog_new(const char *name, DkStr code, u32 base, const Eq2RelocVec *relocs, const Eq2Image *image, bool ours) {
    eq2_init();
    InitOnceExecuteOnce(&g_names_once, names_cb, NULL, NULL);
    Eq2Prog *p = dk_xcalloc(1, sizeof *p);
    p->name = (char *)dupz(name);
    p->code = code;
    p->base = base;
    p->image = image;
    p->ours = ours;
    size_t n = 0;
    p->ins = dk_dis_all(dk_dis(DK_DIS_X86_32, DK_DIS_DETAIL), code.p, code.n, base, 0, &n);
    p->n_ins = n;
    p->at = dk_xmalloc((code.n + 1) * sizeof(i32));
    for (size_t i = 0; i < code.n + 1; i++) p->at[i] = -1;
    for (size_t i = 0; i < n; i++) p->at[p->ins[i].address - base] = (i32)i;
    p->rel = dk_xcalloc(n + 1, sizeof(Eq2RelocList));
    size_t nr = relocs ? relocs->n : 0;
    p->n_relocs = nr;
    p->relocs = dk_xcalloc(nr + 1, sizeof(Eq2Reloc));
    for (size_t k = 0; k < nr; k++) {
        Eq2Reloc r = relocs->v[k];
        r.symbol = dupz(r.symbol);
        r.status = dupz(r.status);
        r.kind = dupz(r.kind);
        r.conv = dupz(r.conv);
        p->relocs[k] = r;
        /* the first instruction with off <= offset < off + size (they are in address order and disjoint) */
        size_t lo = 0, hi = n;
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (p->ins[mid].address - base <= r.offset) lo = mid + 1;
            else hi = mid;
        }
        if (lo > 0) {
            size_t ii = lo - 1;
            const cs_insn *i = &p->ins[ii];
            u32 off = (u32)(i->address - base);
            if (r.offset >= off && r.offset < off + i->size) {
                u32 ro = r.offset - off;
                const cs_x86 *x = &i->detail->x86;
                Eq2RelocR rr;
                rr.r = r;
                rr.role = ro == x->encoding.disp_offset ? EQ2_ROLE_DISP : (ro == x->encoding.imm_offset ? EQ2_ROLE_IMM : EQ2_ROLE_OTHER);
                Eq2RelocList *l = &p->rel[ii];
                l->v = dk_xrealloc(l->v, (l->n + 1) * sizeof(Eq2RelocR));
                l->v[l->n++] = rr;
            }
        }
        exmap_put(&p->reloc_at, r.offset, NULL)->n = (i64)k;
    }
    return p;
}

const cs_insn *eq2_prog_ins(const Eq2Prog *p, i64 addr) {
    i64 off = addr - (i64)p->base;
    if (off < 0 || (u64)off >= p->code.n) return NULL;
    i32 i = p->at[off];
    return i < 0 ? NULL : &p->ins[i];
}

static const Eq2RelocList g_no_relocs = {NULL, 0};
const Eq2RelocList *eq2_prog_rel(const Eq2Prog *p, const cs_insn *ins) {
    size_t i = (size_t)(ins - p->ins);
    return i < p->n_ins && p->rel[i].n ? &p->rel[i] : &g_no_relocs;
}

/* Prog.table_targets(table_addr, count) */
void eq2_prog_table_targets(const Eq2Prog *p, i64 table_addr, int count, i64 *out) {
    for (int k = 0; k < count; k++) {
        if (p->ours) {
            i64 off = table_addr - (i64)p->base + 4 * (i64)k;
            ExVal *v = exmap_get(&p->reloc_at, (u64)off);
            if (!v) eq2_unsupported("table entry %d has no relocation", k);
            const Eq2Reloc *r = &p->relocs[v->n];
            if (!r->has_label) eq2_crash("KeyError('label')");
            out[k] = (i64)p->base + r->label;
        } else {
            if (!p->image) eq2_crash("AttributeError(\"'NoneType' object has no attribute 'read_u32'\")");
            u32 va = (u32)(table_addr + 4 * (i64)k), off;
            const char *err = NULL;
            if (!eq2_image_offset_of(p->image, va, &off, &err)) {
                DkArena *a = dk_scratch();
                DkArenaMark mk = dk_arena_mark(a);
                DkStr r = dk_repr_str(a, dk_str(err));
                char buf[1024];
                snprintf(buf, sizeof buf, "ValueError(%.*s)", (int)r.n, r.p);
                dk_arena_reset(a, mk);
                eq2_crash("%s", buf);
            }
            out[k] = eq2_image_read_u32(p->image, va);
        }
    }
}

/* ------------------------------------------------------------------------------------------------- State */
Eq2State *eq2_state_new(Eq2Prog *prog) {
    eq2_init();
    Eq2State *s = dk_xcalloc(1, sizeof *s);
    s->prog = prog;
    s->pc = prog->base;
    for (int i = 0; i < 8; i++)
        if (i != R_ESP) s->regs[i] = ex_t2(EA(in), ex_str(R32_NAMES[i]));
    s->fresh[0] = false;
    s->fresh[1] = true;
    s->fresh[2] = true;
    for (int i = 0; i < 8; i++) {
        char nm[8];
        snprintf(nm, sizeof nm, "xmm%d", i);
        s->xmm[i] = ex_t2(EA(in), ex_str(nm));
    }
    return s;
}

Eq2State *eq2_state_copy(const Eq2State *o) {
    Eq2State *s = dk_xmalloc(sizeof *s);
    *s = *o;
    exmap_copy(&s->stack, &o->stack);
    exmap_copy(&s->mem, &o->mem);
    exmap_copy(&s->writes, &o->writes);
    exmap_copy(&s->escaped, &o->escaped);
    exmap_copy(&s->facts, &o->facts);
    memset(&s->fp, 0, sizeof s->fp);
    if (o->fp.n) dk_vec_extend(&s->fp, o->fp.v, o->fp.n);
    memset(&s->pushq, 0, sizeof s->pushq);
    if (o->pushq.n) dk_vec_extend(&s->pushq, o->pushq.v, o->pushq.n);
    return s;
}

void eq2_state_free(Eq2State *s) {
    exmap_free(&s->stack);
    exmap_free(&s->mem);
    exmap_free(&s->writes);
    exmap_free(&s->escaped);
    exmap_free(&s->facts);
    dk_vec_free(&s->fp);
    dk_vec_free(&s->pushq);
    dk_xfree(s);
}

typedef struct { const char *n; int base; } SubReg;
static const SubReg SUB8[] = {{"al", R_EAX}, {"cl", R_ECX}, {"dl", R_EDX}, {"bl", R_EBX}};
static const SubReg SUB8H[] = {{"ah", R_EAX}, {"ch", R_ECX}, {"dh", R_EDX}, {"bh", R_EBX}};
static const SubReg SUB16[] = {{"ax", R_EAX}, {"cx", R_ECX}, {"dx", R_EDX}, {"bx", R_EBX},
                               {"si", R_ESI}, {"di", R_EDI}, {"bp", R_EBP}, {"sp", R_ESP}};

static int sub_find(const SubReg *t, size_t n, const char *name) {
    for (size_t i = 0; i < n; i++)
        if (!strcmp(t[i].n, name)) return t[i].base;
    return -1;
}

static Ex *esp0_term(void) {
    static DK_THREAD_LOCAL Ex *e;
    if (!e) e = ex_t1(EA(esp0));
    return e;
}

static Ex *reg_or_keyerror(Eq2State *st, int base) {
    if (base == R_ESP) eq2_crash("KeyError('esp')");
    return st->regs[base];
}

Ex *eq2_get_reg(Eq2State *st, const char *name) {
    if (!name) eq2_crash("TypeError('can only concatenate str (not \"NoneType\") to str')");
    int i = reg32_idx(name);
    if (i >= 0 && i != R_ESP) return st->regs[i];
    int b = sub_find(SUB8, 4, name);
    if (b >= 0) return eq2_lo8(st->regs[b]);
    b = sub_find(SUB16, 8, name);
    if (b >= 0) return ex_t2(EA(lo16), reg_or_keyerror(st, b));
    b = sub_find(SUB8H, 4, name);
    if (b >= 0) return ex_t2(EA(hi8), st->regs[b]);
    if (i == R_ESP) {
        DkArena *ar = dk_scratch();
        DkArenaMark mk = dk_arena_mark(ar);
        Terms t;
        terms_init(&t, ar);
        *terms_slot(&t, esp0_term()) = ex_int(1);
        Ex *r = eq2_mklin(&t, (u64)st->esp);
        dk_arena_reset(ar, mk);
        return r;
    }
    eq2_unsupported("register %s", name);
}

void eq2_set_reg(Eq2State *st, const char *name, Ex *v) {
    if (!name) eq2_crash("TypeError('can only concatenate str (not \"NoneType\") to str')");
    int i = reg32_idx(name);
    if (i >= 0 && i != R_ESP) {
        st->regs[i] = v;
        if (i <= R_EDX) st->fresh[i] = true;
        return;
    }
    int b = sub_find(SUB8, 4, name);
    if (b >= 0) {
        Ex *old = st->regs[b];
        st->regs[b] = old == ex_c(0) ? ex_t2(EA(zx8), v) : ex_t3(EA(ins8), old, v);
        if (b <= R_EDX) st->fresh[b] = true;
        return;
    }
    b = sub_find(SUB16, 8, name);
    if (b >= 0) {
        st->regs[b] = ex_t3(EA(ins16), reg_or_keyerror(st, b), v);
        if (b <= R_EDX) st->fresh[b] = true;
        return;
    }
    b = sub_find(SUB8H, 4, name);
    if (b >= 0) {
        st->regs[b] = ex_t3(EA(insh8), st->regs[b], v);
        return;
    }
    eq2_unsupported("write register %s", name);
}

bool eq2_is_xmm(const char *name) { return name && !strncmp(name, "xmm", 3); }

Ex **eq2_xmm_slot(Eq2State *st, const char *name) {
    if (name && !strncmp(name, "xmm", 3) && name[3] >= '0' && name[3] <= '7' && !name[4]) return &st->xmm[name[3] - '0'];
    DkArena *a = dk_scratch();
    DkArenaMark mk = dk_arena_mark(a);
    DkStr r = dk_repr_str(a, dk_str(name ? name : ""));
    char buf[256];
    snprintf(buf, sizeof buf, "KeyError(%.*s)", (int)r.n, r.p);
    dk_arena_reset(a, mk);
    if (!name) snprintf(buf, sizeof buf, "KeyError(None)");
    eq2_crash("%s", buf);
}

/* -------------------------------------------------------------------------------------------------- Sim */
Eq2Sim *eq2_sim_new(Eq2Prog *prog, Eq2State *state) {
    eq2_init();
    Eq2Sim *s = dk_xcalloc(1, sizeof *s);
    s->prog = prog;
    s->st = state;
    s->ours = prog->ours;
    s->image = prog->image;
    s->external = true;
    return s;
}

Eq2Sim *eq2_sim_copy(const Eq2Sim *o) {
    Eq2Sim *s = dk_xmalloc(sizeof *s);
    *s = *o;
    s->st = eq2_state_copy(o->st);
    s->external = false;
    return s;
}

void eq2_sim_free(Eq2Sim *s) {
    if (!s) return;
    eq2_state_free(s->st);
    dk_xfree(s);
}

const cs_x86_op *eq2_op(const cs_insn *ins, int i) {
    if (i < 0 || i >= ins->detail->x86.op_count) EQ2_IDX_ERR();
    return &ins->detail->x86.operands[i];
}

const Eq2RelocList *eq2_sim_reloc_of(const Eq2Sim *sim, const cs_insn *ins) { return eq2_prog_rel(sim->prog, ins); }

Ex *eq2_sim_mem_addr(Eq2Sim *sim, const cs_insn *ins, const cs_x86_op *op, const Eq2RelocList *rel) {
    Eq2State *st = sim->st;
    const x86_op_mem *m = &op->mem;
    if (m->segment) {
        const char *seg = eq2_regname(m->segment);
        if (seg && !strcmp(seg, "fs")) return ex_t2(EA(FS), ex_int(m->disp));
    }
    DK_UNUSED(ins);
    u64 constant = (u64)m->disp;
    DkArena *ar = dk_scratch();
    DkArenaMark mk = dk_arena_mark(ar);
    Terms terms;
    terms_init(&terms, ar);
    const char *base = m->base ? eq2_regname(m->base) : NULL;
    const char *index = m->index ? eq2_regname(m->index) : NULL;
    if (sim->ours && rel->n) {
        for (u32 k = 0; k < rel->n; k++) {
            const Eq2RelocR *r = &rel->v[k];
            if (!strcmp(r->r.kind, "abs") && r->role != EQ2_ROLE_IMM) {
                if (r->r.has_target && r->r.target) constant += r->r.target;
                else *terms_slot(&terms, ex_t2(EA(sym), ex_str(r->r.symbol))) = ex_int(1);
            }
        }
    }
    if (base && !strcmp(base, "esp")) {
        Ex **s = terms_slot(&terms, esp0_term());
        *s = eq2_coef_add(*s, ex_int(1));
        constant += (u64)st->esp;
    } else if (base) {
        Terms t;
        terms_init(&t, ar);
        u64 c = 0;
        eq2_lin(eq2_get_reg(st, base), &t, &c);
        for (size_t i = 0; i < t.n; i++) {
            Ex **s = terms_slot(&terms, t.v[i].k);
            *s = eq2_coef_add(*s, t.v[i].v);
        }
        constant += c;
    }
    if (index) {
        if (!strcmp(index, "esp")) eq2_unsupported("esp index");
        Terms t;
        terms_init(&t, ar);
        u64 c = 0;
        eq2_lin(eq2_get_reg(st, index), &t, &c);
        for (size_t i = 0; i < t.n; i++) {
            Ex **s = terms_slot(&terms, t.v[i].k);
            *s = eq2_coef_add(*s, eq2_coef_mul(t.v[i].v, ex_int(m->scale)));
        }
        constant += c * (u64)(i64)m->scale;
    }
    Ex *r = eq2_mklin(&terms, constant);
    dk_arena_reset(ar, mk);
    return r;
}

/* is_stack(addr): the offset from the entry esp when addr is ESP0 + const. */
bool eq2_sim_is_stack(Ex *addr, i64 *off) {
    Ex *e0 = esp0_term();
    if (addr == e0) {
        *off = 0;
        return true;
    }
    if (ex_is(addr, EA(L)) && addr->el[1]->n == 1 && addr->el[1]->el[0]->el[0] == e0 && addr->el[1]->el[0]->el[1]->i == 1) {
        *off = eq2_signed((u64)addr->el[2]->i);
        return true;
    }
    return false;
}

static bool nearest_escaped(const Eq2State *st, i64 so, i64 *idn, i64 *o_out) {
    bool have = false;
    i64 best_o = 0, best_id = 0;
    const ExEnt *e;
    EXMAP_FOR(&st->escaped, e) {
        i64 o = (i64)e->key;
        if (o <= so && (!have || o > best_o)) {
            have = true;
            best_o = o;
            best_id = e->val.n;
        }
    }
    *idn = best_id;
    *o_out = best_o;
    return have;
}

/* The terms part of an address, as an Ex that is equal exactly when lin()'s dicts are equal, and its constant. */
static Ex *terms_ex(Ex *e, u64 *c) {
    if (ex_is(e, EA(c))) {
        *c = ex_cval(e);
        return ex_tup(NULL, 0);
    }
    if (ex_is(e, EA(L))) {
        *c = (u64)e->el[2]->i;
        return e->el[1];
    }
    *c = 0;
    return ex_t1(ex_t2(e, ex_int(1)));
}

/* A load from read-only data of the game: its value, else NULL (Sim.const_read). */
static Ex *const_read(Eq2Sim *sim, Ex *addr, int size) {
    if (!ex_is(addr, EA(c))) return NULL;
    u64 a = ex_cval(addr);
    if (!sim->image) eq2_crash("AttributeError(\"'NoneType' object has no attribute 'section_of'\")");
    if (a > 0xffffffffull) return NULL;
    const Eq2ImageSection *s = eq2_image_section_of(sim->image, (u32)a);
    if (!s) return NULL;
    if ((dk_str_eq(s->name, DK_S(".rdata")) || dk_str_eq(s->name, DK_S(".text"))) && !(s->chars & 0x80000000u)) {
        DkStr b;
        const char *err = NULL;
        if (!eq2_image_read(sim->image, (u32)a, (u32)size, &b, &err)) {
            DkArena *ar = dk_scratch();
            DkArenaMark mk = dk_arena_mark(ar);
            DkStr r = dk_repr_str(ar, dk_str(err));
            char buf[1024];
            snprintf(buf, sizeof buf, "ValueError(%.*s)", (int)r.n, r.p);
            dk_arena_reset(ar, mk);
            eq2_crash("%s", buf);
        }
        u64 n = 0;
        bool wide = false;   /* int.from_bytes of more than 8 bytes with a non-zero tail */
        for (size_t i = 0; i < b.n; i++) {
            if (i < 8) n |= (u64)(u8)b.p[i] << (8 * i);
            else if (b.p[i]) wide = true;
        }
        if (size <= 4) return ex_c(n);
        if (wide) eq2_crash("error(\"'Q' format requires 0 <= number <= 18446744073709551615\")");
        return eq2_dbl_to_f32(n);
    }
    return NULL;
}

Ex *eq2_sim_load(Eq2Sim *sim, const cs_insn *ins, const cs_x86_op *op, int size) {
    Eq2State *st = sim->st;
    const Eq2RelocList *rel = eq2_sim_reloc_of(sim, ins);
    Ex *addr = eq2_sim_mem_addr(sim, ins, op, rel);
    if (ex_is(addr, EA(FS))) return ex_t2(EA(fs), addr->el[1]);
    if (sim->ours) {
        /* unresolved constant pool symbols: the first 'sym' term of lin(addr) in dict order */
        if (ex_is(addr, EA(L))) {
            Ex *tl = addr->el[1];
            for (u32 i = 0; i < tl->n; i++)
                if (ex_is(tl->el[i]->el[0], EA(sym))) return eq2_const_from_symbol(tl->el[i]->el[0]->el[1]->s, size);
        } else if (!ex_is(addr, EA(c)) && ex_is(addr, EA(sym))) {
            return eq2_const_from_symbol(addr->el[1]->s, size);
        }
    }
    i64 so;
    if (eq2_sim_is_stack(addr, &so)) {
        ExVal *ent = exmap_get(&st->stack, (u64)so);
        if (ent) {
            i64 s = ent->n;
            Ex *v = ent->e;
            if (s == size) return v;
            if (size == 4 && s == 1) return ex_t3(EA(ins8), ex_t1(EA(uninit)), v);
            if (size == 1 && s == 4) return eq2_lo8(v);
            return ex_t3(EA(part), ex_int(size), v);
        }
        if (so > 0) return ex_t3(EA(arg), ex_int(so), ex_int(size));
        i64 idn, eo;
        if (nearest_escaped(st, so, &idn, &eo)) {
            Ex *v[5] = {EA(eld), ex_int(idn), ex_int(so - eo), ex_int(size), ex_int(st->epoch)};
            return ex_tup(v, 5);
        }
        return ex_t1(EA(uninit));
    }
    Ex *k = const_read(sim, addr, size);
    if (k) return k;
    Ex *key = ex_t2(addr, ex_int(size));
    ExVal *mv = exmap_get(&st->mem, exkey(key));
    if (mv) return mv->e;
    Ex *v[4] = {EA(ld), ex_int(size), addr, ex_int(st->epoch)};
    return ex_tup(v, 4);
}

void eq2_sim_store(Eq2Sim *sim, const cs_insn *ins, const cs_x86_op *op, int size, Ex *val) {
    Eq2State *st = sim->st;
    const Eq2RelocList *rel = eq2_sim_reloc_of(sim, ins);
    Ex *addr = eq2_sim_mem_addr(sim, ins, op, rel);
    if (ex_is(addr, EA(FS))) return;
    i64 so;
    if (eq2_sim_is_stack(addr, &so)) {
        ExEnt *e;
        EXMAP_FOR(&st->stack, e) {
            i64 o = (i64)e->key;
            if (o != so && o < so + size && so < o + e->val.n) {
                e->live = false;
                st->stack.n_live--;
            }
        }
        ExVal *v = exmap_put(&st->stack, (u64)so, NULL);
        v->n = size;
        v->e = val;
        return;   /* no warning for a store below esp is kept */
    }
    u64 ca;
    Ex *ta = terms_ex(addr, &ca);
    ExEnt *e;
    EXMAP_FOR(&st->mem, e) {
        Ex *key = exkey_ex(e->key);
        i64 ks = key->el[1]->i;
        u64 cb;
        Ex *tb = terms_ex(key->el[0], &cb);
        if (tb == ta && (i64)ca < (i64)cb + ks && (i64)cb < (i64)ca + size) {
            e->live = false;
            st->mem.n_live--;
        }
    }
    exmap_put(&st->mem, exkey(ex_t2(addr, ex_int(size))), NULL)->e = val;
    ExVal *w = exmap_put(&st->writes, exkey(addr), NULL);
    w->n = size;
    w->e = val;
}

Ex *eq2_sim_value(Eq2Sim *sim, const cs_insn *ins, int i) {
    const cs_x86_op *op = eq2_op(ins, i);
    Eq2State *st = sim->st;
    const Eq2RelocList *rel = eq2_sim_reloc_of(sim, ins);
    if (op->type == X86_OP_REG) return eq2_get_reg(st, eq2_regname(op->reg));
    if (op->type == X86_OP_IMM) {
        if (sim->ours && rel->n) {
            for (u32 k = 0; k < rel->n; k++) {
                const Eq2RelocR *r = &rel->v[k];
                if (!strcmp(r->r.kind, "abs") && r->role != EQ2_ROLE_DISP) {
                    if (r->r.strlit) return ex_t1(EA(strptr));
                    if (r->r.has_target && r->r.target) return ex_c((u64)r->r.target + (u64)op->imm);
                    return ex_t2(EA(sym), ex_str(r->r.symbol));
                }
            }
        }
        u64 v = (u64)op->imm & EQ2_M32;
        if (!sim->ours && sim->image) {
            const Eq2ImageSection *s = eq2_image_section_of(sim->image, (u32)v);
            if (s && dk_str_eq(s->name, DK_S(".rdata")) && !strcmp(ins->mnemonic, "push")) return ex_t1(EA(strptr));
        }
        return ex_c(v);
    }
    if (op->type == X86_OP_MEM) return eq2_sim_load(sim, ins, op, op->size);
    eq2_unsupported("operand");
}

void eq2_sim_assign(Eq2Sim *sim, const cs_insn *ins, int i, Ex *val) {
    const cs_x86_op *op = eq2_op(ins, i);
    if (op->type == X86_OP_REG) eq2_set_reg(sim->st, eq2_regname(op->reg), val);
    else if (op->type == X86_OP_MEM) eq2_sim_store(sim, ins, op, op->size, val);
    else eq2_unsupported("assign");
}
