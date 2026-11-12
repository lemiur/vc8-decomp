// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The simulator step: run one side until a branch, call, switch, tail jump or return, executing the stack, move,
 * control-flow and integer instructions here (SSE and x87 are in eq2_fpu.c). */
#include "eq2_internal.h"

static bool mn_in_(const char *mn, const char *const *list) {
    for (; *list; list++)
        if (!strcmp(mn, *list)) return true;
    return false;
}
#define MN_IN(mn, ...) mn_in_((mn), (const char *const[]){__VA_ARGS__, NULL})

static bool reg_is(const cs_x86_op *op, const char *name) {
    const char *n = op->type == X86_OP_REG ? eq2_regname(op->reg) : NULL;
    return n && !strcmp(n, name);
}

static void pushq_filter(Eq2State *st) {   /* st.pushq = [x for x in st.pushq if x >= st.esp] */
    size_t j = 0;
    for (size_t i = 0; i < st->pushq.n; i++)
        if (st->pushq.v[i] >= st->esp) st->pushq.v[j++] = st->pushq.v[i];
    st->pushq.n = j;
}

Ex *eq2_make_cond_any(Ex *flags, const char *j) { return eq2_make_cond(flags, j); }

static DK_NORETURN void unsupported_pc(i64 pc) {
    DkArena *a = dk_scratch();
    DkArenaMark mk = dk_arena_mark(a);
    DkStr s = dk_pyfmt(a, "pc outside code %x", pc);
    char buf[128];
    snprintf(buf, sizeof buf, "%.*s", (int)s.n, s.p);
    dk_arena_reset(a, mk);
    eq2_unsupported("%s", buf);
}

/* step_until_event(sim) */
Eq2Event eq2_step_until_event(Eq2Sim *sim) {
    Eq2State *st = sim->st;
    Eq2Prog *prog = sim->prog;
    int guard = 0;
    for (;;) {
        guard++;
        if (guard > 5000) eq2_unsupported("runaway");
        const cs_insn *ins = eq2_prog_ins(prog, st->pc);
        if (!ins) unsupported_pc(st->pc);
        DkArena *sa = dk_scratch();
        DkArenaMark mk = dk_arena_mark(sa);
        Eq2Catch c;
        Eq2Event ev;
        memset(&ev, 0, sizeof ev);
        if (EQ2_TRY(&c)) {
            bool got = eq2_exec_ins(sim, ins, &ev);
            eq2_catch_end(&c);
            dk_arena_reset(sa, mk);
            if (got) return ev;
        } else {
            dk_arena_reset(sa, mk);
            if (c.kind == EQ2_EXC_UNSUPPORTED)
                eq2_unsupported("%s [%s +%X: %s %s]", c.msg, prog->name, (unsigned)(ins->address - prog->base), ins->mnemonic, ins->op_str);
            eq2_rethrow(&c);
        }
    }
}

static bool ev_none(void) { return false; }

bool eq2_exec_ins(Eq2Sim *sim, const cs_insn *ins, Eq2Event *ev) {
    Eq2State *st = sim->st;
    Eq2Prog *prog = sim->prog;
    const char *mn = ins->mnemonic;
    i64 nxt = (i64)ins->address + ins->size;
#define ADV() (st->pc = nxt)

    /* --- no-ops */
    if (MN_IN(mn, "nop", "int3", "fnop", "prefetcht0", "cld")) { ADV(); return ev_none(); }
    if (!strcmp(mn, "lea") && eq2_op(ins, 1)->mem.base && eq2_op(ins, 0)->reg == eq2_op(ins, 1)->mem.base &&
        !eq2_op(ins, 1)->mem.index && eq2_op(ins, 1)->mem.disp == 0 && !eq2_sim_reloc_of(sim, ins)->n) {
        ADV();
        return ev_none();
    }
    if (!strcmp(mn, "mov") && eq2_op(ins, 0)->type == X86_OP_REG && eq2_op(ins, 1)->type == X86_OP_REG &&
        eq2_op(ins, 0)->reg == eq2_op(ins, 1)->reg) {
        ADV();
        return ev_none();
    }
    /* --- control flow */
    if (!strcmp(mn, "jmp")) {
        const cs_x86_op *o = eq2_op(ins, 0);
        ev->ins = ins;
        if (o->type == X86_OP_IMM) {
            if (!((i64)prog->base <= o->imm && o->imm < (i64)prog->base + (i64)prog->code.n) || eq2_sim_reloc_of(sim, ins)->n) {
                ev->kind = EV_TAIL;
                return true;
            }
            st->pc = o->imm;
            return false;
        }
        if (o->type == X86_OP_MEM && o->mem.index && !o->mem.base) {
            ev->kind = EV_SWITCH;
            return true;
        }
        ev->kind = EV_TAIL;
        return true;
    }
    if (eq2_cond_mnemonic(mn)) {
        i64 tgt = eq2_op(ins, 0)->imm;
        Ex *cond = eq2_make_cond(st->flags, mn);
        ev->kind = EV_COND;
        ev->ins = ins;
        ev->cond = cond;
        ev->t = tgt;
        ev->f = nxt;
        ev->set = false;
        return true;
    }
    if (!strcmp(mn, "call")) {
        ev->kind = EV_CALL;
        ev->ins = ins;
        return true;
    }
    if (!strcmp(mn, "ret") || !strcmp(mn, "retn")) {
        ev->kind = EV_RET;
        ev->ins = ins;
        return true;
    }
    /* --- stack */
    if (!strcmp(mn, "push")) {
        Ex *v = eq2_sim_value(sim, ins, 0);
        st->esp -= 4;
        ExVal *s = exmap_put(&st->stack, (u64)st->esp, NULL);
        s->n = 4;
        s->e = v;
        bool excluded = ex_is(v, EA(in));
        if (!excluded) dk_vec_push(&st->pushq, st->esp);
        ADV();
        return ev_none();
    }
    if (!strcmp(mn, "pop")) {
        const cs_x86_op *o = eq2_op(ins, 0);
        ExVal *sv = exmap_get(&st->stack, (u64)st->esp);
        Ex *v = sv ? sv->e : ex_t1(EA(uninit));
        st->esp += 4;
        pushq_filter(st);
        if (o->type == X86_OP_REG) {
            const char *r = eq2_regname(o->reg);
            if (!r) eq2_crash("TypeError(\"argument of type 'NoneType' is not iterable\")");
            static const char *const R32[] = {"eax", "ecx", "edx", "ebx", "ebp", "esi", "edi"};
            static const int IDX[] = {R_EAX, R_ECX, R_EDX, R_EBX, R_EBP, R_ESI, R_EDI};
            for (int i = 0; i < 7; i++)
                if (!strcmp(r, R32[i])) st->regs[IDX[i]] = v;
        }
        ADV();
        return ev_none();
    }
    if ((!strcmp(mn, "sub") || !strcmp(mn, "add")) && eq2_op(ins, 0)->type == X86_OP_REG && reg_is(eq2_op(ins, 0), "esp")) {
        i64 n = eq2_op(ins, 1)->imm;
        if (!strcmp(mn, "sub")) {
            st->esp -= n;
        } else {
            st->esp += n;
            pushq_filter(st);
        }
        ADV();
        return ev_none();
    }
    if (!strcmp(mn, "and") && eq2_op(ins, 0)->type == X86_OP_REG && reg_is(eq2_op(ins, 0), "esp")) {
        st->esp = st->esp & eq2_signed((u64)eq2_op(ins, 1)->imm);
        ADV();
        return ev_none();
    }
    if (!strcmp(mn, "mov") && eq2_op(ins, 0)->type == X86_OP_REG && reg_is(eq2_op(ins, 0), "esp")) {
        Ex *v = eq2_sim_value(sim, ins, 1);
        i64 so;
        if (!eq2_sim_is_stack(v, &so)) eq2_unsupported("mov esp, non-stack");
        st->esp = so;
        pushq_filter(st);
        ADV();
        return ev_none();
    }
    if (!strcmp(mn, "leave")) eq2_unsupported("esp manipulation: %s", mn);
    if (!strcmp(mn, "mov") && eq2_op(ins, 0)->type == X86_OP_MEM && eq2_op(ins, 0)->mem.segment &&
        eq2_regname(eq2_op(ins, 0)->mem.segment) && !strcmp(eq2_regname(eq2_op(ins, 0)->mem.segment), "fs")) {
        st->pushq.n = 0;   /* SEH frame installed: everything pushed so far is the frame */
        ADV();
        return ev_none();
    }
    /* --- moves */
    if (!strcmp(mn, "mov")) {
        Ex *v = eq2_sim_value(sim, ins, 1);
        eq2_sim_assign(sim, ins, 0, v);
        ADV();
        return ev_none();
    }
    if (!strcmp(mn, "movzx") || !strcmp(mn, "movsx")) {
        Ex *v = eq2_sim_value(sim, ins, 1);
        int sz = eq2_op(ins, 1)->size;
        Ex *r;
        if (!strcmp(mn, "movzx")) r = sz == 1 ? eq2_zx8(v) : ex_t2(EA(zx16), v);
        else r = sz == 1 ? ex_t2(EA(sx8), v) : ex_t2(EA(sx16), v);
        eq2_sim_assign(sim, ins, 0, r);
        ADV();
        return ev_none();
    }
    if (!strcmp(mn, "lea")) {
        const cs_x86_op *op = eq2_op(ins, 1);
        Ex *addr = eq2_sim_mem_addr(sim, ins, op, eq2_sim_reloc_of(sim, ins));
        i64 so;
        if (eq2_sim_is_stack(addr, &so)) {
            bool created;
            ExVal *e = exmap_put(&st->escaped, (u64)so, &created);
            if (created) e->n = (i64)st->escaped.n_live - 1;
            addr = ex_t2(EA(PTR), ex_int(e->n));
        }
        eq2_sim_assign(sim, ins, 0, addr);
        ADV();
        return ev_none();
    }
    if (!strcmp(mn, "xchg")) {
        Ex *a = eq2_sim_value(sim, ins, 0), *b = eq2_sim_value(sim, ins, 1);
        eq2_sim_assign(sim, ins, 0, b);
        eq2_sim_assign(sim, ins, 1, a);
        ADV();
        return ev_none();
    }
    /* --- integer ALU */
    if (MN_IN(mn, "add", "sub", "and", "or", "xor", "cmp", "test", "imul", "shl", "sal", "shr", "sar", "adc", "sbb", "neg", "not",
              "inc", "dec", "bt", "rol", "ror", "idiv", "div", "mul", "cdq", "cwde", "movsx", "bswap"))
        return eq2_int_alu(sim, ins, mn, ev);
    const char *sj = eq2_setcc_jname(mn);
    if (sj) {
        Ex *cond = eq2_make_cond_any(st->flags, sj);
        int cv = eq2_eval_const_cond(eq2_cond_subst(cond, &st->facts));
        if (cv >= 0) {
            eq2_sim_assign(sim, ins, 0, ex_c(cv ? 1 : 0));
            ADV();
            return ev_none();
        }
        ev->kind = EV_COND;
        ev->ins = ins;
        ev->cond = cond;
        ev->t = nxt;
        ev->f = nxt;
        ev->set = true;
        return true;
    }
    const char *cj = eq2_cmov_jname(mn);
    if (cj) {
        Ex *cond = eq2_make_cond_any(st->flags, cj);
        Ex *a = eq2_sim_value(sim, ins, 0);
        Ex *b = eq2_sim_value(sim, ins, 1);
        eq2_sim_assign(sim, ins, 0, ex_t4(EA(cmov), cond, a, b));
        ADV();
        return ev_none();
    }
    /* --- SSE / x87 */
    if (eq2_fp_ins(sim, ins, mn)) {
        ADV();
        return ev_none();
    }
    /* --- string ops / unknown: opaque */
    if (!strncmp(mn, "rep", 3) || MN_IN(mn, "movsd", "movsb", "movsw", "stosd", "stosb", "lodsd")) eq2_unsupported("string op %s", mn);
    eq2_unsupported("instruction %s", mn);
#undef ADV
}

/* int_alu(sim, ins, mn) */
bool eq2_int_alu(Eq2Sim *sim, const cs_insn *ins, const char *mn, Eq2Event *ev) {
    DK_UNUSED(ev);
    Eq2State *st = sim->st;
    int nops = eq2_nops(ins);
    i64 nxt = (i64)ins->address + ins->size;
    if (!strcmp(mn, "cdq")) {
        st->regs[R_EDX] = ex_t2(EA(sx31), st->regs[R_EAX]);
        st->fresh[2] = true;
        st->pc = nxt;
        return false;
    }
    if (MN_IN(mn, "idiv", "div", "mul")) {
        Ex *a = eq2_sim_value(sim, ins, 0);
        Ex *e = st->regs[R_EAX], *d = st->regs[R_EDX];
        Ex *q = !strcmp(mn, "idiv") ? EA(idivq) : (!strcmp(mn, "div") ? EA(divq) : EA(mulq));
        Ex *r = !strcmp(mn, "idiv") ? EA(idivr) : (!strcmp(mn, "div") ? EA(divr) : EA(mulr));
        st->regs[R_EAX] = ex_t4(q, e, d, a);
        st->regs[R_EDX] = ex_t4(r, e, d, a);
        st->fresh[0] = st->fresh[2] = true;
        st->pc = nxt;
        return false;
    }
    if (MN_IN(mn, "neg", "not", "inc", "dec", "bswap") && nops == 1) {
        Ex *a = eq2_sim_value(sim, ins, 0);
        Ex *r;
        if (!strcmp(mn, "neg")) {
            r = eq2_scale(a, -1);
            st->flags = ex_t2(EA(negflags), a);
        } else if (!strcmp(mn, "not")) {
            r = ex_t2(EA(not), a);
        } else if (!strcmp(mn, "inc")) {
            r = eq2_add(a, ex_c(1), 1);
            st->flags = ex_t2(EA(res), r);
        } else if (!strcmp(mn, "dec")) {
            r = eq2_add(a, ex_c(EQ2_M32), 1);
            st->flags = ex_t2(EA(res), r);
        } else {
            r = ex_t2(EA(bswap), a);
        }
        eq2_sim_assign(sim, ins, 0, r);
        st->pc = nxt;
        return false;
    }
    /* two-operand forms */
    if (!strcmp(mn, "imul") && nops == 3) {
        Ex *a = eq2_sim_value(sim, ins, 1), *b = eq2_sim_value(sim, ins, 2);
        Ex *r = ex_isc(b) ? eq2_scale_u(a, ex_cval(b)) : ex_t3(EA(mul), a, b);
        eq2_sim_assign(sim, ins, 0, r);
        st->pc = nxt;
        return false;
    }
    if (nops == 1 && !strcmp(mn, "imul")) {
        Ex *a = eq2_sim_value(sim, ins, 0);
        Ex *e = st->regs[R_EAX];
        st->regs[R_EAX] = ex_t3(EA(imulq), e, a);
        st->regs[R_EDX] = ex_t3(EA(imulh), e, a);
        st->pc = nxt;
        return false;
    }
    Ex *a = eq2_sim_value(sim, ins, 0);
    Ex *b = eq2_sim_value(sim, ins, 1);
    const cs_x86_op *o0 = eq2_op(ins, 0), *o1 = eq2_op(ins, 1);
    /* xor r,r */
    if (!strcmp(mn, "xor") && o0->type == X86_OP_REG && o1->type == X86_OP_REG && o0->reg == o1->reg) {
        eq2_sim_assign(sim, ins, 0, ex_c(0));
        st->flags = ex_t2(EA(res), ex_c(0));
        st->pc = nxt;
        return false;
    }
    Ex *r;
    if (!strcmp(mn, "add")) {
        r = eq2_add(a, b, 1);
        st->flags = ex_t2(EA(res), r);
    } else if (!strcmp(mn, "sub")) {
        r = eq2_add(a, b, -1);
        st->flags = ex_t3(EA(cmp), a, b);
    } else if (!strcmp(mn, "cmp")) {
        st->flags = ex_t3(EA(cmp), a, b);
        st->pc = nxt;
        return false;
    } else if (!strcmp(mn, "test")) {
        Ex *eax = st->regs[R_EAX];
        if (reg_is(o0, "ah") && o1->type == X86_OP_IMM && ex_is(eax, EA(insh8)) && ex_is(eax->el[2], EA(LAHF)) &&
            eax->el[2]->el[1]->kind == EX_TUP && eax->el[2]->el[1]->n && ex_is(eax->el[2]->el[1], EA(fcmp))) {
            Ex *fl = eax->el[2]->el[1];
            st->flags = ex_t4(EA(fahmask), fl->el[1], fl->el[2], ex_int(o1->imm & 0xff));
            st->pc = nxt;
            return false;
        }
        if (o0->type == X86_OP_REG && o1->type == X86_OP_REG && o0->reg == o1->reg) st->flags = ex_t2(EA(res), a);
        else st->flags = ex_t2(EA(res), eq2_comm(EA(and), a, b));
        st->pc = nxt;
        return false;
    } else if (MN_IN(mn, "and", "or", "xor")) {
        r = eq2_comm(!strcmp(mn, "and") ? EA(and) : (!strcmp(mn, "or") ? EA(or) : EA(xor)), a, b);
        st->flags = ex_t2(EA(res), r);
    } else if (MN_IN(mn, "shl", "sal")) {
        r = ex_isc(b) && ex_cval(b) < 31 ? eq2_scale(a, (i64)1 << ex_cval(b)) : ex_t3(EA(shl), a, b);
        st->flags = ex_t2(EA(res), r);
    } else if (MN_IN(mn, "shr", "sar", "rol", "ror")) {
        r = ex_t3(ex_str(mn), a, b);
        st->flags = ex_t2(EA(res), r);
    } else if (!strcmp(mn, "imul")) {
        if (ex_isc(b)) {
            r = eq2_scale_u(a, ex_cval(b));
        } else {
            Ex *x = a, *y = b;
            eq2_sort2(&x, &y);
            r = ex_t3(EA(mul), x, y);
        }
    } else if (MN_IN(mn, "adc", "sbb")) {
        r = ex_t4(ex_str(mn), a, b, st->flags ? st->flags : ex_none());
        st->flags = ex_t2(EA(res), r);
    } else if (!strcmp(mn, "bt")) {
        st->flags = ex_t3(EA(btflags), a, b);
        st->pc = nxt;
        return false;
    } else {
        eq2_unsupported("%s", mn);
    }
    eq2_sim_assign(sim, ins, 0, r);
    st->pc = nxt;
    return false;
}
