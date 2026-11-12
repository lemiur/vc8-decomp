// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The SSE scalar/packed instructions and the x87 stack instructions of the simulator step. */
#include "eq2_internal.h"

static bool mn_in_(const char *mn, const char *const *list) {
    for (; *list; list++)
        if (!strcmp(mn, *list)) return true;
    return false;
}
#define MN_IN(mn, ...) mn_in_((mn), (const char *const[]){__VA_ARGS__, NULL})

/* st.fp[-k] (k >= 1) and the other list operations on the x87 stack, with an IndexError crash. */
static Ex *fp_get(Eq2State *st, size_t k) {
    if (k > st->fp.n) EQ2_IDX_ERR();
    return st->fp.v[st->fp.n - k];
}
static void fp_set(Eq2State *st, size_t k, Ex *v) {
    if (k > st->fp.n) EQ2_IDX_ERR();
    st->fp.v[st->fp.n - k] = v;
}
static Ex *fp_pop(Eq2State *st) {
    if (!st->fp.n) eq2_crash("IndexError('pop from empty list')");
    return (Ex *)dk_vec_pop(&st->fp);
}
static void fp_push(Eq2State *st, Ex *v) { dk_vec_push(&st->fp, v); }

/* re.search(r'st\((\d)\)', text): the digit of the first match, or -1. */
static int st_first(const char *t) {
    for (const char *p = t; *p; p++)
        if (p[0] == 's' && p[1] == 't' && p[2] == '(' && p[3] >= '0' && p[3] <= '9' && p[4] == ')') return p[3] - '0';
    return -1;
}
static int st_first_or_err(const char *t) {
    int d = st_first(t);
    if (d < 0) eq2_crash("AttributeError(\"'NoneType' object has no attribute 'group'\")");
    return d;
}
/* re.findall(r'st\((\d)\)', text) */
static int st_all(const char *t, int *out, int max) {
    int n = 0;
    for (const char *p = t; *p; p++)
        if (p[0] == 's' && p[1] == 't' && p[2] == '(' && p[3] >= '0' && p[3] <= '9' && p[4] == ')' && n < max) {
            out[n++] = p[3] - '0';
            p += 4;
        }
    return n;
}
static bool py_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; }

static Ex *fp_bin(const char *base, bool rev, Ex *a, Ex *b) {
    if (rev) {
        Ex *t = a;
        a = b;
        b = t;
    }
    Ex *name = !strcmp(base, "add") ? EA(faddss) : (!strcmp(base, "sub") ? EA(fsubss) : (!strcmp(base, "mul") ? EA(fmulss) : EA(fdivss)));
    if (!strcmp(base, "add") || !strcmp(base, "mul")) {
        eq2_sort2(&a, &b);
        return ex_t3(name, a, b);
    }
    return ex_t3(name, a, b);
}

/* mn =~ ^f(i?)(add|sub|subr|mul|div|divr)(p?)$ */
static bool parse_farith(const char *mn, bool *isint, char op[8], bool *pop) {
    if (mn[0] != 'f') return false;
    const char *rest = mn + 1;
    static const char *const OPS[] = {"add", "sub", "subr", "mul", "div", "divr"};
    for (int with_i = 1; with_i >= 0; with_i--) {
        const char *r = rest;
        if (with_i) {
            if (r[0] != 'i') continue;
            r++;
        }
        for (size_t k = 0; k < DK_ARRAY_LEN(OPS); k++) {
            size_t l = strlen(OPS[k]);
            if (strncmp(r, OPS[k], l)) continue;
            const char *tail = r + l;
            if (tail[0] == 0 || (tail[0] == 'p' && tail[1] == 0)) {
                *isint = with_i != 0;
                strcpy(op, OPS[k]);
                *pop = tail[0] == 'p';
                return true;
            }
        }
    }
    return false;
}

/* fp_ins(sim, ins, mn): false: the instruction is not an FPU one. */
bool eq2_fp_ins(Eq2Sim *sim, const cs_insn *ins, const char *mn) {
    Eq2State *st = sim->st;
    int nops = eq2_nops(ins);
#define XR(i) eq2_regname(eq2_op(ins, (i))->reg)
#define XMM(i) (*eq2_xmm_slot(st, XR(i)))
#define SRC(i) (eq2_op(ins, (i))->type == X86_OP_REG ? XMM(i) : eq2_sim_value(sim, ins, (i)))

    if (MN_IN(mn, "movss", "movaps", "movups", "movd", "movq", "movdqa", "movdqu", "movapd", "movlps", "movhps", "movsd")) {
        if (eq2_op(ins, 0)->type == X86_OP_REG && eq2_is_xmm(XR(0))) {
            Ex *v;
            if (eq2_op(ins, 1)->type != X86_OP_REG || eq2_is_xmm(XR(1))) v = SRC(1);
            else v = eq2_get_reg(st, XR(1));
            XMM(0) = v;
        } else {
            Ex *v = SRC(1);
            if (eq2_op(ins, 1)->type == X86_OP_REG && !eq2_is_xmm(XR(1))) v = eq2_get_reg(st, XR(1));
            if (eq2_op(ins, 0)->type != X86_OP_REG) eq2_sim_assign(sim, ins, 0, v);
            else eq2_set_reg(st, XR(0), v);
        }
        return true;
    }
    if (MN_IN(mn, "addss", "subss", "mulss", "divss", "minss", "maxss", "addsd", "subsd", "mulsd", "divsd", "addps", "subps", "mulps",
              "divps")) {
        Ex *a = XMM(0);
        Ex *b = SRC(1);
        char name[16];
        size_t l = strlen(mn);
        snprintf(name, sizeof name, "f%.3s%s", mn, mn + l - 2);
        Ex *tag = ex_str(name);
        if (!strncmp(mn, "add", 3) || !strncmp(mn, "mul", 3)) {
            eq2_sort2(&a, &b);
            XMM(0) = ex_t3(tag, a, b);
        } else {
            XMM(0) = ex_t3(tag, a, b);
        }
        return true;
    }
    if (MN_IN(mn, "sqrtss", "sqrtsd", "rcpss", "rsqrtss")) {
        char name[16];
        snprintf(name, sizeof name, "f%s", mn);
        Ex *v = ex_t2(ex_str(name), SRC(1));
        XMM(0) = v;
        return true;
    }
    if (MN_IN(mn, "andps", "xorps", "orps", "andnps", "pxor", "andpd", "xorpd")) {
        if (MN_IN(mn, "xorps", "pxor", "xorpd") && eq2_op(ins, 1)->type == X86_OP_REG && eq2_op(ins, 0)->reg == eq2_op(ins, 1)->reg) {
            XMM(0) = ex_c(0);
            return true;
        }
        Ex *a = XMM(0);
        Ex *b = SRC(1);
        char base[16];
        {   /* mn.replace('ps', '').replace('pd', '') */
            char tmp[16];
            size_t j = 0;
            for (const char *p = mn; *p;) {
                if (p[0] == 'p' && p[1] == 's') p += 2;
                else tmp[j++] = *p++;
            }
            tmp[j] = 0;
            j = 0;
            for (const char *p = tmp; *p;) {
                if (p[0] == 'p' && p[1] == 'd') p += 2;
                else base[j++] = *p++;
            }
            base[j] = 0;
        }
        if (!strcmp(base, "and") && b == ex_c(0x7fffffff)) XMM(0) = ex_t2(EA(fabs), a);
        else if (!strcmp(base, "xor") && b == ex_c(0x80000000u)) XMM(0) = ex_t2(EA(fneg), a);
        else if (!strcmp(base, "andn")) XMM(0) = ex_t3(EA(andn), a, b);
        else {
            Ex *op = !strcmp(base, "and") ? EA(and) : (!strcmp(base, "or") ? EA(or) : EA(xor));
            XMM(0) = eq2_comm(op, a, b);
        }
        return true;
    }
    if (MN_IN(mn, "comiss", "ucomiss", "comisd", "ucomisd")) {
        Ex *a = XMM(0);
        st->flags = ex_t3(EA(fcmp), a, SRC(1));
        return true;
    }
    if (MN_IN(mn, "cvtsi2ss", "cvtsi2sd")) {
        XMM(0) = ex_t2(EA(i2f), eq2_sim_value(sim, ins, 1));
        return true;
    }
    if (MN_IN(mn, "cvttss2si", "cvttsd2si")) {
        Ex *v = ex_t2(EA(f2i_t), SRC(1));
        eq2_set_reg(st, XR(0), v);
        return true;
    }
    if (MN_IN(mn, "cvtss2si", "cvtsd2si")) {
        Ex *v = ex_t2(EA(f2i_r), SRC(1));
        eq2_set_reg(st, XR(0), v);
        return true;
    }
    if (MN_IN(mn, "cvtss2sd", "cvtsd2ss", "cvtps2pd", "cvtpd2ps", "cvtdq2ps", "cvttps2dq")) {
        Ex *v = ex_t2(ex_str(mn), SRC(1));
        XMM(0) = v;
        return true;
    }
    if (MN_IN(mn, "unpcklps", "shufps", "movlhps", "movhlps", "pshufd", "unpckhps", "punpckldq", "movmskps")) {
        Ex *a = XMM(0);
        Ex *b = SRC(1);
        i64 extra = nops > 2 ? eq2_op(ins, 2)->imm : 0;
        XMM(0) = ex_t4(ex_str(mn), a, b, ex_int(extra));
        return true;
    }
    if (!strcmp(mn, "lahf")) {
        st->regs[R_EAX] = ex_t3(EA(insh8), st->regs[R_EAX], ex_t2(EA(LAHF), st->flags ? st->flags : ex_none()));
        return true;
    }
    if (!strcmp(mn, "seto") || !strcmp(mn, "setno")) {
        eq2_sim_assign(sim, ins, 0, ex_t2(EA(seto), st->flags ? st->flags : ex_none()));
        return true;
    }
    /* ---- x87 */
    if (MN_IN(mn, "fcom", "fcomp", "fcompp", "fucom", "fucomp", "fucompp", "ftst")) {
        size_t l = strlen(mn);
        bool pp = l >= 2 && mn[l - 1] == 'p' && mn[l - 2] == 'p';
        bool p1 = mn[l - 1] == 'p';
        if (!strcmp(mn, "ftst")) {
            st->fsw = ex_t3(EA(fcmp), fp_get(st, 1), ex_c(0));
        } else {
            Ex *b;
            if (nops && eq2_op(ins, 0)->type == X86_OP_MEM) b = eq2_sim_load(sim, ins, eq2_op(ins, 0), eq2_op(ins, 0)->size);
            else if (strstr(ins->op_str, "st(")) b = fp_get(st, 1 + (size_t)st_first_or_err(ins->op_str));
            else b = fp_get(st, 2);
            st->fsw = ex_t3(EA(fcmp), fp_get(st, 1), b);
            if (pp) {
                fp_pop(st);
                fp_pop(st);
            } else if (p1) {
                fp_pop(st);
            }
        }
        return true;
    }
    if (!strcmp(mn, "fnstsw")) {
        st->regs[R_EAX] = ex_t3(EA(insh8), st->regs[R_EAX], ex_t2(EA(LAHF), st->fsw ? st->fsw : ex_none()));
        return true;
    }
    if (!strcmp(mn, "fld")) {
        const cs_x86_op *o = eq2_op(ins, 0);
        if (o->type == X86_OP_MEM) {
            fp_push(st, eq2_sim_load(sim, ins, o, o->size));
        } else {
            int idx = st_first_or_err(ins->op_str);
            fp_push(st, fp_get(st, 1 + (size_t)idx));
        }
        return true;
    }
    if (!strcmp(mn, "fldz")) { fp_push(st, ex_c(0)); return true; }
    if (!strcmp(mn, "fld1")) { fp_push(st, ex_c(0x3f800000)); return true; }
    if (!strcmp(mn, "fild")) {
        const cs_x86_op *o = eq2_op(ins, 0);
        fp_push(st, ex_t2(EA(i2f), eq2_sim_load(sim, ins, o, o->size)));
        return true;
    }
    if (!strcmp(mn, "fstp") || !strcmp(mn, "fst")) {
        const cs_x86_op *o = eq2_op(ins, 0);
        Ex *v = fp_get(st, 1);
        if (o->type == X86_OP_MEM) {
            eq2_sim_store(sim, ins, o, o->size, v);
        } else {
            int idx = st_first_or_err(ins->op_str);
            if (!strcmp(mn, "fst") || idx != 0) fp_set(st, 1 + (size_t)idx, v);
        }
        if (!strcmp(mn, "fstp")) fp_pop(st);
        return true;
    }
    if (!strcmp(mn, "fistp") || !strcmp(mn, "fist")) {
        const cs_x86_op *o = eq2_op(ins, 0);
        eq2_sim_store(sim, ins, o, o->size, ex_t2(EA(f2i_t), fp_get(st, 1)));
        if (!strcmp(mn, "fistp")) fp_pop(st);
        return true;
    }
    if (MN_IN(mn, "fnstcw", "fldcw", "fwait", "fninit")) {
        if (!strcmp(mn, "fnstcw")) eq2_sim_store(sim, ins, eq2_op(ins, 0), 2, ex_t1(EA(cw)));
        return true;
    }
    if (!strcmp(mn, "fxch")) {
        int idx = strstr(ins->op_str, "st(") ? st_first_or_err(ins->op_str) : 1;
        Ex *x = fp_get(st, 1 + (size_t)idx);
        Ex *y = fp_get(st, 1);
        fp_set(st, 1, x);
        fp_set(st, 1 + (size_t)idx, y);
        return true;
    }
    if (MN_IN(mn, "fchs", "fabs", "fsqrt", "fsin", "fcos", "frndint")) {
        Ex *nm = !strcmp(mn, "fchs") ? EA(fneg) : (!strcmp(mn, "fabs") ? EA(fabs) : (!strcmp(mn, "fsqrt") ? EA(fsqrtss) : ex_str(mn)));
        fp_set(st, 1, ex_t2(nm, fp_get(st, 1)));
        return true;
    }
    if (!strcmp(mn, "fsincos")) {
        Ex *a = fp_pop(st);
        fp_push(st, ex_t2(EA(fcos), a));
        fp_push(st, ex_t2(EA(fsin), a));
        return true;
    }
    if (MN_IN(mn, "fcompi", "fucomip", "fcomip", "fucompi", "fcomi", "fucomi")) {
        int idx = strstr(ins->op_str, "st(") ? st_first_or_err(ins->op_str) : 1;
        Ex *a = fp_get(st, 1);
        Ex *b = fp_get(st, 1 + (size_t)idx);
        st->flags = ex_t3(EA(fcmp), a, b);
        size_t l = strlen(mn);
        if (mn[l - 1] == 'p' || (mn[l - 1] == 'i' && mn[l - 2] == 'p')) fp_pop(st);
        return true;
    }
    bool isint, pop;
    char opn[8];
    if (parse_farith(mn, &isint, opn, &pop)) {
        bool rev = !strcmp(opn, "subr") || !strcmp(opn, "divr");
        char base[8];
        strcpy(base, opn);
        if (rev) base[strlen(base) - 1] = 0;
        if (nops == 1 && eq2_op(ins, 0)->type == X86_OP_MEM) {
            const cs_x86_op *o = eq2_op(ins, 0);
            Ex *b = eq2_sim_load(sim, ins, o, o->size);
            if (isint) b = ex_t2(EA(i2f), b);
            Ex *a = fp_get(st, 1);
            fp_set(st, 1, fp_bin(base, rev, a, b));
        } else {
            const char *text = ins->op_str;
            size_t dst_i = 0, src_i = 1;
            const char *q = text;
            while (py_space(*q)) q++;
            bool mm = q[0] == 's' && q[1] == 't' && q[2] == '(' && q[3] >= '0' && q[3] <= '9' && q[4] == ')';
            bool blank = true;
            for (const char *p = text; *p; p++)
                if (!py_space(*p)) blank = false;
            if (blank || !mm) {
                dst_i = 0;
                src_i = 1;
            } else {
                int idxs[8];
                int cnt = st_all(text, idxs, 8);
                if (cnt == 2) {
                    dst_i = (size_t)idxs[0];
                    src_i = (size_t)idxs[1];
                } else if (cnt == 1) {
                    dst_i = 0;
                    src_i = (size_t)idxs[0];
                    if (pop) {
                        dst_i = (size_t)idxs[0];
                        src_i = 0;
                    }
                }
            }
            Ex *a = fp_get(st, 1 + dst_i);
            Ex *b = fp_get(st, 1 + src_i);
            fp_set(st, 1 + dst_i, fp_bin(base, rev, a, b));
        }
        if (pop) fp_pop(st);
        return true;
    }
    return false;
#undef XR
#undef XMM
#undef SRC
}
