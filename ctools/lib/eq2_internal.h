// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* eq2 engine internals: the representation of expressions and the engine's private API between eq2_expr.c,
 * eq2_sim.c, eq2_alu.c, eq2_fpu.c and eq2_checker.c. Nothing outside the engine includes this header (the front end
 * uses lib/eq2.h only).
 *
 * Expressions are nested tuples (('c', 5), ('in', 'eax'), ('L', (...), const), conditions (dom, set of outcomes, a,
 * b), ...) compared by value (equality and hashing: dict keys, membership) and ordered by their printed form. An `Ex`
 * is an immutable, hash-consed value (none, int, str, tuple, set of outcome names), so equality is pointer equality
 * and a dict keyed by tuples is a map keyed by pointers. The printed form is computed lazily (and cached) because
 * operands are ordered by it.
 *
 *  - ints: a signed 64-bit value, an unsigned 64-bit value above INT64_MAX (`big`: ('c', n) of an unmasked 64-bit
 *    constant), or a huge int carrying its decimal text (`s`): the L-form coefficients are never reduced, so a long
 *    chain of shifts or multiplications exceeds 64 bits (eq2_big.c does that arithmetic).
 *  - outcome sets only ever hold the names lt/eq/gt/un: an Ex of kind EX_FSET carries them as a bit mask, printed
 *    sorted.
 *  - strs are process-wide atoms (one Ex per text, immortal). Tuples and ints live in a per-thread universe.
 *
 * Errors. `Unsupported` is eq2_unsupported(fmt, ...), caught by the step loop (which adds the instruction) and by
 * the checker's run. Any other internal failure is eq2_crash(text) with the text of the failing operation (for
 * example "KeyError('eax')"): it travels the same way up to eq2_checker_run, which frees the engine's state and
 * rethrows it with dk_throw(DK_ERR_OTHER, text). Memory between a throw and its catcher is bounded: everything is
 * owned by the checker (freed there), temporaries come from the thread's scratch arena (reset by the catcher). */
#pragma once
#include "eq2.h"
#include "dk/arena.h"
#include "dk/disasm.h"
#include "dk/fmt.h"

#define EQ2_M32 0xffffffffu

/* ---------------------------------------------------------------------------------------------------- values */
typedef enum { EX_NONE = 0, EX_INT, EX_STR, EX_TUP, EX_FSET } Eq2ExKind;

typedef struct Ex Ex;
struct Ex {
    u8 kind;
    bool big;          /* EX_INT: `i` holds an unsigned value above INT64_MAX */
    u32 n;             /* EX_TUP: element count; EX_STR: length in bytes */
    u32 hash;
    i64 i;             /* EX_INT: the value; EX_FSET: the outcome mask */
    const char *s;     /* EX_STR: the text, NUL-terminated, immortal; EX_INT: the decimal text of a huge int (beyond 64 bits) */
    Ex **el;           /* EX_TUP: the elements */
    const char *repr;  /* cached repr(), NULL until asked */
    u32 repr_len;
};

/* Outcome names of the conditions (frozenset members) as bits. */
enum { OUT_LT = 1, OUT_EQ = 2, OUT_GT = 4, OUT_UN = 8 };

/* The atoms (strs) the code tests or builds by name: EA(c) is the Ex for 'c'. */
#define EQ2_ATOMS(X)                                                                                              \
    X(c, "c") X(L, "L") X(in, "in") X(esp0, "ESP0") X(sym, "sym") X(FS, "FS") X(fs, "fs") X(PTR, "PTR")           \
    X(strptr, "strptr") X(uninit, "uninit") X(part, "part") X(arg, "arg") X(eld, "eld") X(ld, "ld")               \
    X(lo8, "lo8") X(lo16, "lo16") X(hi8, "hi8") X(zx8, "zx8") X(zx16, "zx16") X(sx8, "sx8") X(sx16, "sx16")       \
    X(sx31, "sx31") X(ins8, "ins8") X(ins16, "ins16") X(insh8, "insh8") X(b8, "b8") X(bit, "bit")                 \
    X(shr, "shr") X(sar, "sar") X(shl, "shl") X(rol, "rol") X(ror, "ror") X(and, "and") X(or, "or")               \
    X(xor, "xor") X(mul, "mul") X(not, "not") X(bswap, "bswap") X(cmov, "cmov") X(negflags, "negflags")           \
    X(res, "res") X(cmp, "cmp") X(fcmp, "fcmp") X(fahmask, "fahmask") X(btflags, "btflags") X(LAHF, "LAHF")       \
    X(seto, "seto") X(adc, "adc") X(sbb, "sbb") X(idivq, "idivq") X(idivr, "idivr") X(divq, "divq")               \
    X(divr, "divr") X(mulq, "mulq") X(mulr, "mulr") X(imulq, "imulq") X(imulh, "imulh") X(fabs, "fabs")          \
    X(fneg, "fneg") X(fsqrtss, "fsqrtss") X(andn, "andn") X(i2f, "i2f") X(f2i_t, "f2i_t") X(f2i_r, "f2i_r")      \
    X(cw, "cw") X(fsin, "fsin") X(fcos, "fcos") X(frndint, "frndint") X(retf, "retf") X(ret, "ret")              \
    X(clob, "clob") X(clobx, "clobx") X(ind, "ind") X(abs, "abs") X(local, "local") X(d_s, "s") X(d_u, "u")      \
    X(d_i, "i") X(d_f, "f") X(d_sg, "sg") X(faddss, "faddss") X(fsubss, "fsubss") X(fmulss, "fmulss")            \
    X(fdivss, "fdivss")
typedef struct Eq2Atoms {
#define X(f, s) Ex *a_##f;
    EQ2_ATOMS(X)
#undef X
    Ex *none;
} Eq2Atoms;
extern Eq2Atoms eq2_A;
#define EA(f) (eq2_A.a_##f)

/* Idempotent, thread-safe; every public entry point of the engine calls it first. */
void eq2_init(void);

Ex *ex_none(void);
Ex *ex_int(i64 v);
Ex *ex_uint(u64 v);        /* an int that may exceed INT64_MAX */
Ex *ex_int_text(const char *decimal);   /* an int beyond both 64-bit forms (eq2_big.c makes them) */
Ex *ex_str(const char *s);
Ex *ex_strn(const char *s, size_t n);
Ex *ex_tup(Ex *const *el, size_t n);
Ex *ex_fset(unsigned mask);
Ex *ex_t1(Ex *a);
Ex *ex_t2(Ex *a, Ex *b);
Ex *ex_t3(Ex *a, Ex *b, Ex *c);
Ex *ex_t4(Ex *a, Ex *b, Ex *c, Ex *d);
Ex *ex_t5(Ex *a, Ex *b, Ex *c, Ex *d, Ex *e);
/* ('tag', x...) with the tag spelled as a C string (mnemonic-derived names). */
Ex *ex_tagn(const char *tag, size_t n, Ex *const *rest);

static inline bool ex_is_tup(const Ex *e) { return e->kind == EX_TUP; }
/* e[0] when e is a non-empty tuple whose first element is a str, else NULL (so `e[0] == 'x'` is ex_tag(e) == EA(x)). */
static inline const Ex *ex_tag(const Ex *e) { return e->kind == EX_TUP && e->n && e->el[0]->kind == EX_STR ? e->el[0] : NULL; }
static inline bool ex_is(const Ex *e, const Ex *tag) { return e->kind == EX_TUP && e->n && e->el[0] == tag; }
/* ('c', n): C(n) masks to 32 bits, ex_craw keeps the unmasked value. */
Ex *ex_c(u64 n);
Ex *ex_craw(u64 n);
static inline bool ex_isc(const Ex *e) { return ex_is(e, EA(c)); }
static inline u64 ex_cval(const Ex *e) { return (u64)e->el[1]->i; }  /* the n of ('c', n) */
/* The elements of a tuple as ints (x[1] etc.). */
static inline i64 ex_ival(const Ex *e) { return e->i; }

/* repr(e) (cached) and the order sorted(key=repr) uses (byte order of the UTF-8 text equals code point order). */
const char *ex_repr(Ex *e);
int ex_repr_cmp(Ex *a, Ex *b);
/* str(e): the text of a str, the decimal of an int, "None", else repr. */
void ex_str_of(DkBuf *b, const Ex *e);

/* ----------------------------------------------------------------------------------------------- exceptions */
typedef struct Eq2Catch {
    jmp_buf jb;
    struct Eq2Catch *prev;
    int kind;            /* EQ2_EXC_UNSUPPORTED or EQ2_EXC_CRASH */
    char msg[4096];
} Eq2Catch;
enum { EQ2_EXC_UNSUPPORTED = 1, EQ2_EXC_CRASH = 2 };
void eq2_catch_push(Eq2Catch *c);
void eq2_catch_end(Eq2Catch *c);
#define EQ2_TRY(c) (eq2_catch_push(c), setjmp((c)->jb) == 0)
DK_NORETURN void eq2_unsupported(DK_PRINTF_FMT const char *fmt, ...);
DK_NORETURN void eq2_crash(DK_PRINTF_FMT const char *fmt, ...);
/* Throws the caught exception again to the next catcher (or, with none, as dk_throw). */
DK_NORETURN void eq2_rethrow(const Eq2Catch *c);
#define EQ2_IDX_ERR() eq2_crash("IndexError('list index out of range')")

/* ------------------------------------------------------------------------------------ ordered map (dict) */
/* A dict keyed by Ex pointers or ints (the key is a u64): insertion order, assignment to an existing key keeps
 * its position, delete + insert goes to the end. Entries are visited by index (deleting while visiting is fine: dead
 * entries are skipped and only compacted by a later insert). */
typedef struct ExVal {
    i64 n;
    Ex *e;
} ExVal;
typedef struct ExEnt {
    u64 key;
    ExVal val;
    bool live;
} ExEnt;
typedef struct ExMap {
    ExEnt *ent;
    u32 n_ent, cap_ent, n_live;
    u32 *idx;
    u32 idx_cap;
} ExMap;
void exmap_free(ExMap *m);
void exmap_copy(ExMap *dst, const ExMap *src);   /* dst = dict(src); dst must be empty/zeroed */
void exmap_clear(ExMap *m);
ExVal *exmap_get(const ExMap *m, u64 key);
ExVal *exmap_put(ExMap *m, u64 key, bool *created);  /* a new entry's value is zeroed */
bool exmap_del(ExMap *m, u64 key);
#define EXMAP_CAT2_(a, b) a##b
#define EXMAP_CAT_(a, b) EXMAP_CAT2_(a, b)
#define EXMAP_FOR_(m, ep, I) for (u32 I = 0; I < (m)->n_ent; I++) if (((ep) = &(m)->ent[I])->live)
#define EXMAP_FOR(m, ep) EXMAP_FOR_(m, ep, EXMAP_CAT_(ei_, __LINE__))
static inline u64 exkey(const Ex *e) { return (u64)(uintptr_t)e; }
static inline Ex *exkey_ex(u64 k) { return (Ex *)(uintptr_t)k; }

/* ------------------------------------------------------------------------------------------ the algebra */
i64 eq2_signed(u64 n);                 /* signed(): 32-bit two's complement of n & M32 */
/* lin / mklin with the term list in insertion order. */
typedef struct Term {
    Ex *k;
    Ex *v;   /* the coefficient, an Ex int */
} Term;
typedef struct Terms {
    Term *v;
    size_t n, cap;
    DkArena *a;
} Terms;
void terms_init(Terms *t, DkArena *a);
Ex **terms_slot(Terms *t, Ex *k);      /* the coefficient of k, inserting 0 when absent */
Ex *eq2_coef_add(Ex *a, Ex *b);
Ex *eq2_coef_mul(Ex *a, Ex *b);
u64 eq2_coef_lo64(const Ex *a);        /* modulo 2**64 */
Ex *eq2_scale_ex(Ex *a, Ex *k);        /* scale() by an Ex int */
void eq2_lin(Ex *e, Terms *t, u64 *c); /* lin(e): terms in order, constant (the unmasked e[1] of a 'c') */
Ex *eq2_mklin(Terms *t, u64 constant); /* the constant is taken mod 2**32 (masked at the end) */
Ex *eq2_add(Ex *a, Ex *b, int sign);
Ex *eq2_scale(Ex *a, i64 k);
Ex *eq2_scale_u(Ex *a, u64 k);   /* scale by a 'c' value, which may exceed INT64_MAX (only constants can take it) */
Ex *eq2_comm(Ex *op, Ex *a, Ex *b);    /* op is EA(and) / EA(or) / EA(xor) */
Ex *eq2_lo8(Ex *v);
Ex *eq2_zx8(Ex *v);
Ex *eq2_b8(Ex *x);
bool eq2_eqv(Ex *a, Ex *b);
Ex *eq2_canon_e(Ex *e);
Ex *eq2_canon_c(Ex *c);
bool eq2_cond_eq(Ex *c1, Ex *c2);
Ex *eq2_subst(Ex *e, const ExMap *facts);
Ex *eq2_cond_subst(Ex *c, const ExMap *facts);
int eq2_eval_const_cond(Ex *c);        /* -1: None, 0: False, 1: True */
void eq2_add_fact(ExMap *facts, Ex *c, bool taken);
Ex *eq2_make_cond(Ex *flags, const char *jname);  /* flags NULL: None */
Ex *eq2_negate_cond(Ex *c);
Ex *eq2_dbl_to_f32(u64 n);
Ex *eq2_const_from_symbol(const char *sym, int size);
/* sorted([a, b], key=repr) */
void eq2_sort2(Ex **a, Ex **b);
/* short(e, depth) appended to b. */
void eq2_short(DkBuf *b, const Ex *e, int depth);
char *eq2_short_cz(DkArena *a, const Ex *e);
/* The text of a list of strs, e.g. ['a', 'b']. */
void eq2_repr_list(DkBuf *b, const char *const *items, size_t n);

/* --------------------------------------------------------------------------------------- Prog / State / Sim */
enum { EQ2_ROLE_DISP, EQ2_ROLE_IMM, EQ2_ROLE_OTHER };
typedef struct Eq2RelocR {   /* a relocation dict `rr` of Prog.relocs[address]: the build() dict plus 'role' */
    Eq2Reloc r;
    int role;
} Eq2RelocR;
typedef struct Eq2RelocList {
    Eq2RelocR *v;
    u32 n;
} Eq2RelocList;

struct Eq2Prog {
    char *name;
    DkStr code;
    u32 base;
    const Eq2Image *image;
    bool ours;
    cs_insn *ins;            /* decoded, with detail */
    size_t n_ins;
    i32 *at;                 /* code offset -> index into ins, -1 where no instruction starts; code.n entries */
    Eq2RelocList *rel;       /* per instruction index */
    Eq2Reloc *relocs;        /* a copy of the build() dicts, in order */
    size_t n_relocs;
    ExMap reloc_at;          /* offset -> index into relocs (the last one wins, as the dict comprehension) */
};
const cs_insn *eq2_prog_ins(const Eq2Prog *p, i64 addr);   /* Prog.ins.get(addr) */
const Eq2RelocList *eq2_prog_rel(const Eq2Prog *p, const cs_insn *ins);  /* Prog.relocs.get(address, []) */
/* table_targets(table_addr, count): the absolute targets; Unsupported / the error raised there. */
void eq2_prog_table_targets(const Eq2Prog *p, i64 table_addr, int count, i64 *out);

enum { R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI };
struct Eq2State {
    Eq2Prog *prog;
    i64 pc;
    Ex *regs[8];             /* regs[R_ESP] unused */
    bool fresh[3];           /* eax, ecx, edx */
    Ex *xmm[8];
    i64 esp;
    ExMap stack;             /* offset -> (size, value) */
    ExMap mem;               /* Ex (addr, size) -> value */
    ExMap writes;            /* addr -> (size, value) */
    DkPtrVec fp;            /* the x87 stack (Ex *) */
    Ex *flags;               /* NULL: None */
    Ex *fsw;
    DkI64Vec pushq;
    i64 epoch;
    ExMap escaped;           /* offset -> id */
    ExMap facts;             /* Ex -> Ex */
};
struct Eq2Sim {
    Eq2Prog *prog;
    Eq2State *st;
    bool ours;
    const Eq2Image *image;
    bool external;           /* made by eq2_sim_new: owned by the front end, never freed by the checker */
};

Eq2State *eq2_state_copy(const Eq2State *s);
void eq2_state_free(Eq2State *s);
Eq2Sim *eq2_sim_copy(const Eq2Sim *s);          /* Sim.copy_state() */
void eq2_sim_free(Eq2Sim *s);

const char *eq2_regname(unsigned reg);            /* ins.reg_name(reg); NULL where there is none */
Ex *eq2_get_reg(Eq2State *st, const char *name);
void eq2_set_reg(Eq2State *st, const char *name, Ex *v);
Ex **eq2_xmm_slot(Eq2State *st, const char *name);  /* st.xmm[name]; KeyError(name) when absent */
bool eq2_is_xmm(const char *name);

const cs_x86_op *eq2_op(const cs_insn *ins, int i);  /* ins.operands[i]; IndexError when absent */
static inline int eq2_nops(const cs_insn *ins) { return ins->detail->x86.op_count; }

Ex *eq2_sim_value(Eq2Sim *sim, const cs_insn *ins, int i);
void eq2_sim_assign(Eq2Sim *sim, const cs_insn *ins, int i, Ex *val);
Ex *eq2_sim_mem_addr(Eq2Sim *sim, const cs_insn *ins, const cs_x86_op *op, const Eq2RelocList *rel);
Ex *eq2_sim_load(Eq2Sim *sim, const cs_insn *ins, const cs_x86_op *op, int size);
void eq2_sim_store(Eq2Sim *sim, const cs_insn *ins, const cs_x86_op *op, int size, Ex *val);
bool eq2_sim_is_stack(Ex *addr, i64 *off);       /* is_stack(): true with the signed offset, false for None */
const Eq2RelocList *eq2_sim_reloc_of(const Eq2Sim *sim, const cs_insn *ins);

/* ------------------------------------------------------------------------------------- the step / the events */
typedef enum { EV_TAIL, EV_SWITCH, EV_COND, EV_CALL, EV_RET } Eq2EvKind;
extern const char *const eq2_ev_names[5];   /* "tail", "switch", "cond", "call", "ret" */
typedef struct Eq2Event {
    Eq2EvKind kind;
    const cs_insn *ins;
    Ex *cond;
    i64 t, f;
    bool set;          /* the 6th item of a setcc event; False/None for a branch */
} Eq2Event;
Eq2Event eq2_step_until_event(Eq2Sim *sim);
/* exec_ins: true with *ev filled when the instruction raised an event, false after advancing. */
bool eq2_exec_ins(Eq2Sim *sim, const cs_insn *ins, Eq2Event *ev);
bool eq2_int_alu(Eq2Sim *sim, const cs_insn *ins, const char *mn, Eq2Event *ev);
/* fp_ins: false when the instruction is not an FPU one. */
bool eq2_fp_ins(Eq2Sim *sim, const cs_insn *ins, const char *mn);
Ex *eq2_make_cond_any(Ex *flags, const char *j);
bool eq2_cond_mnemonic(const char *mn);    /* mn in JCC or mn in JCC_F */
const char *eq2_setcc_jname(const char *mn);   /* SETCC[mn] or NULL */
const char *eq2_cmov_jname(const char *mn);    /* CMOV[mn] or NULL */

/* ------------------------------------------------------------------------------------------------ the checker */
/* eq2_checker.c keeps its own private state in Eq2Checker.impl. */
