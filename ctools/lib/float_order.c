// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* float_order: the float operation trees read out of machine code, the expression parser, the sites of a statement, the spellings of a site and the statement-level moves (float_order.h). The search, the batch and the command line are float_order_search.c and float_order_cli.c. */
#include "float_order.h"
#include "ctext.h"

#include "dk/fmt.h"
#include "dk/pool.h"
#include "dk/re.h"
#include "dk/sort.h"

#include <math.h>

#define RE(p) dk_re((p), 0)

static DkStr S(const char *z) { return dk_str(z); }
static char *dupv(DkArena *a, DkStr s) { return dk_cz(a, s); }

/* ========================================================================================== 1. float trees */

static const char *const OP_NAMES[] = {"leaf", "add", "sub", "mul", "div", "min", "max", "sqrt",
                                       "rsqrt", "rcp", "neg", "abs", "cmp"};
const char *const FO_CLASS_NAMES[4] = {"match", "commute", "assoc", "absent"};

const char *fo_op_name(FoOp op) { return OP_NAMES[op]; }

static u64 mix(u64 h, u64 x) {
    h ^= x + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

static u64 hash_cz(const char *s) {
    u64 h = 1469598103934665603ULL;
    for (; *s; s++) h = (h ^ (u8)*s) * 1099511628211ULL;
    return h;
}

enum { H_O = 1, H_C = 2, H_F = 4 };

/* ordered(n): the signature with the exact operand order. */
u64 fo_ordered(FoNode *n) {
    if (!(n->have & H_O)) {
        if (n->op == FO_LEAF) n->o = mix(0x1111, hash_cz(n->label));
        else n->o = mix(mix(mix(0x2222, (u64)n->op), fo_ordered(n->l)), n->r ? fo_ordered(n->r) : 0);
        n->have |= H_O;
    }
    return n->o;
}

/* commuted(n): the operands of add / mul / min / max sorted. */
u64 fo_commuted(FoNode *n) {
    if (!(n->have & H_C)) {
        if (n->op == FO_LEAF) {
            n->c = mix(0x3333, hash_cz(n->label));
        } else {
            u64 a = fo_commuted(n->l), b = n->r ? fo_commuted(n->r) : 0;
            if ((n->op == FO_ADD || n->op == FO_MUL || n->op == FO_MIN || n->op == FO_MAX) && a > b) {
                u64 t = a;
                a = b;
                b = t;
            }
            n->c = mix(mix(mix(0x4444, (u64)n->op), a), b);
        }
        n->have |= H_C;
    }
    return n->c;
}

typedef struct Term {
    int sign;
    u64 h;
} Term;
typedef DK_VEC(Term) TermVec;

static u64 fo_flat_(FoNode *n);

static void flat_terms(FoNode *n, int sign, TermVec *out) {
    if (n->op == FO_ADD || n->op == FO_SUB) {
        flat_terms(n->l, sign, out);
        flat_terms(n->r, n->op == FO_ADD ? sign : -sign, out);
    } else if (n->op == FO_NEG) {
        flat_terms(n->l, -sign, out);
    } else {
        Term t = {sign, fo_flat_(n)};
        dk_vec_push(out, t);
    }
}

static void flat_factors(FoNode *n, DkU64Vec *out) {
    if (n->op == FO_MUL) {
        flat_factors(n->l, out);
        flat_factors(n->r, out);
    } else {
        dk_vec_push(out, fo_flat_(n));
    }
}

static int cmp_term(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    const Term *a = x, *b = y;
    if (a->sign != b->sign) return a->sign < b->sign ? -1 : 1;
    return a->h < b->h ? -1 : a->h > b->h ? 1 : 0;
}

/* flat(n): add / sub chains as sets of signed terms, mul chains as sets of factors. */
static u64 fo_flat_(FoNode *n) {
    if (!(n->have & H_F)) {
        if (n->op == FO_LEAF) {
            n->f = mix(0x5555, hash_cz(n->label));
        } else if (n->op == FO_ADD || n->op == FO_SUB) {
            TermVec t = {0};
            flat_terms(n, 1, &t);
            dk_sort(t.v, t.n, sizeof(Term), cmp_term, NULL, false);
            u64 h = 0x7777;
            for (size_t i = 0; i < t.n; i++) h = mix(mix(h, (u64)(t.v[i].sign + 2)), t.v[i].h);
            n->f = mix(h, t.n);
            dk_vec_free(&t);
        } else if (n->op == FO_MUL) {
            DkU64Vec t = {0};
            flat_factors(n, &t);
            dk_sort_u64(t.v, t.n);
            u64 h = 0x8888;
            for (size_t i = 0; i < t.n; i++) h = mix(h, t.v[i]);
            n->f = mix(h, t.n);
            dk_vec_free(&t);
        } else {
            n->f = mix(mix(mix(0x6666, (u64)n->op), fo_flat_(n->l)), n->r ? fo_flat_(n->r) : 0);
        }
        n->have |= H_F;
    }
    return n->f;
}

u64 fo_flat(FoNode *n) { return fo_flat_(n); }

void fo_tree_prepare(FoTree *t) {
    for (size_t i = 0; i < t->nodes.n; i++) {
        FoNode *n = t->nodes.v[i];
        fo_ordered(n);
        fo_commuted(n);
        fo_flat_(n);
    }
}

static const char *sym_of(FoOp op) {
    switch (op) {
    case FO_ADD: return "+";
    case FO_SUB: return "-";
    case FO_MUL: return "*";
    case FO_DIV: return "/";
    default: return OP_NAMES[op];
    }
}

/* render(n, depth, top): readable infix text of a node. */
static void render_into(DkBuf *b, const FoNode *n, int depth, bool top) {
    if (!n) {
        dk_buf_putz(b, "?");
        return;
    }
    if (n->op == FO_LEAF) {
        dk_buf_putz(b, n->label);
        return;
    }
    if (depth <= 0) {
        dk_buf_putz(b, "...");
        return;
    }
    if (!n->r) {
        dk_buf_putz(b, OP_NAMES[n->op]);
        dk_buf_putc(b, '(');
        render_into(b, n->l, depth - 1, true);
        dk_buf_putc(b, ')');
        return;
    }
    if (!top) dk_buf_putc(b, '(');
    render_into(b, n->l, depth - 1, false);
    dk_buf_putc(b, ' ');
    dk_buf_putz(b, sym_of(n->op));
    dk_buf_putc(b, ' ');
    render_into(b, n->r, depth - 1, false);
    if (!top) dk_buf_putc(b, ')');
}

const char *fo_render(const FoNode *n, int depth, bool top) {
    DkBuf b = {0};
    render_into(&b, n, depth, top);
    char *r = dk_strdup(dk_arena(), b.p ? b.p : "");
    dk_buf_free(&b);
    return r;
}

/* cut(text, n=120): by code points. */
const char *fo_cut(const char *text, int n) {
    DkStr t = S(text);
    if ((i64)dk_u8_len(t) <= n) return text;
    DkBuf b = {0};
    dk_buf_put(&b, dk_u8_slice(t, 0, n - 3));
    dk_buf_putz(&b, "...");
    char *r = dk_strdup(dk_arena(), b.p);
    dk_buf_free(&b);
    return r;
}

static bool is_interesting(FoOp op) { return op == FO_ADD || op == FO_SUB || op == FO_MUL || op == FO_DIV; }

/* ------------------------------------------------------------------------------- float_tree: machine code */

#define ARITH_PAT "^(add|sub|mul|div|min|max|sqrt|rsqrt|rcp)(ss|sd|ps|pd)$"
#define GPR_PAT "^(e?[abcd]x|[abcd][lh]|e?[sd]i)$"
#define REGS32_PAT "\\be(?:[abcd]x|si|di|bp|sp)\\b"
#define DISP_PAT "([+-]) (0x[0-9a-f]+|\\d+)$"

static bool in_list(const char *s, const char *const *list) {
    for (; *list; list++)
        if (strcmp(s, *list) == 0) return true;
    return false;
}

static const char *const MOVES[] = {"movss", "movsd", "movaps", "movups", "movapd", "movupd", "movd", "movq", "movlps",
                                    "movhps", "movlpd", "movhpd", "movdqa", "movdqu", "movlhps", "movhlps", "movddup", NULL};
static const char *const COPIES[] = {"shufps", "shufpd", "unpcklps", "unpckhps", "unpcklpd", "pshufd", "punpckldq",
                                     "cvtss2sd", "cvtsd2ss", "pshuflw", "pshufhw", "movshdup", "movsldup", NULL};
static const char *const READERS[] = {"comiss", "ucomiss", "comisd", "ucomisd", "ptest", NULL};
static const char *const X87_QUIET[] = {"fnstsw", "fnstcw", "fldcw", "fwait", "fnop", "wait", NULL};

/* X87_OPS = {"fadd": "add", "fsub": "sub", "fmul": "mul", "fdiv": "div", "fsubr": "sub", "fdivr": "div"} */
static bool x87_op(const char *mn, FoOp *op, bool *rev) {
    if (strcmp(mn, "fadd") == 0) { *op = FO_ADD; *rev = false; return true; }
    if (strcmp(mn, "fsub") == 0) { *op = FO_SUB; *rev = false; return true; }
    if (strcmp(mn, "fmul") == 0) { *op = FO_MUL; *rev = false; return true; }
    if (strcmp(mn, "fdiv") == 0) { *op = FO_DIV; *rev = false; return true; }
    if (strcmp(mn, "fsubr") == 0) { *op = FO_SUB; *rev = true; return true; }
    if (strcmp(mn, "fdivr") == 0) { *op = FO_DIV; *rev = true; return true; }
    return false;
}

/* int(text, 0) of a match the patterns guarantee: 0x.. hex or decimal. */
static i64 int0(DkStr s) {
    i64 v = 0;
    if (!dk_parse_int(s, 0, &v, NULL)) dk_panic(__FILE__, __LINE__, "ValueError: invalid literal for int() with base 0: '%.*s'", DK_SF(s));
    return v;
}

/* stack_disp(inner): the signed displacement at the end of the operand, 0 when there is none. */
static i64 stack_disp(DkStr inner) {
    DkReMatch m;
    if (!dk_re_search(RE(DISP_PAT), inner, 0, DK_END, &m)) return 0;
    return int0(dk_re_group(&m, 2)) * (dk_re_group(&m, 1).p[0] == '+' ? 1 : -1);
}

/* stack_slot(inner, esp_off): ("b", disp) for an ebp-based operand, ("s", esp_off + disp) otherwise, encoded so that
 * the integer order is the tuple order. */
static u64 slot_key(DkStr inner, i64 esp_off) {
    if (dk_re_search(RE("\\bebp\\b"), inner, 0, DK_END, NULL)) return (u64)(stack_disp(inner) + (1LL << 40));
    return (1ULL << 62) + (u64)(esp_off + stack_disp(inner) + (1LL << 40));
}

typedef struct Ins {
    u64 address;
    u32 size;
    char mn[32];
    char ops[160];
} Ins;
typedef DK_VEC(Ins) InsVec;

/* esp_step(ins, esp_off): the esp offset after push / pop / sub esp / add esp. */
static i64 esp_step(const Ins *ins, i64 esp_off) {
    if (strcmp(ins->mn, "push") == 0) return esp_off - 4;
    if (strcmp(ins->mn, "pop") == 0) return esp_off + 4;
    DkReMatch m;
    if (dk_re_match(RE("^esp, (0x[0-9a-f]+|\\d+)$"), S(ins->ops), 0, DK_END, &m) &&
        (strcmp(ins->mn, "sub") == 0 || strcmp(ins->mn, "add") == 0)) {
        i64 v = int0(dk_re_group(&m, 1));
        return esp_off + (strcmp(ins->mn, "add") == 0 ? v : -v);
    }
    return esp_off;
}

static char *fmt_off(DkArena *a, i64 n) {
    return n >= 0 ? dk_sprintf(a, "+0x%llx", (unsigned long long)n) : dk_sprintf(a, "-0x%llx", (unsigned long long)-n);
}

/* What each integer register holds: (name, offset). */
typedef struct Prov {
    bool have;
    const char *text;
    i64 off;
} Prov;
static const char *const GPR_NAMES[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
static int gpr_index(DkStr name) {
    for (int i = 0; i < 8; i++)
        if (dk_str_eqz(name, GPR_NAMES[i])) return i;
    return -1;
}
static const Prov *gpr_get(const Prov gpr[8], DkStr name) {
    int i = gpr_index(name);
    return i >= 0 && gpr[i].have ? &gpr[i] : NULL;
}

/* permute.reg_full(r) as an index into GPR_NAMES (-1 for an unknown name) and whether r is its own full name. */
static int reg_full_index(DkStr r, bool *same) {
    char buf[16];
    if (r.n >= sizeof buf) {
        *same = false;
        return -1;
    }
    memcpy(buf, r.p, r.n);
    buf[r.n] = 0;
    const char *full = dk_ctext_reg_full(buf);
    *same = strcmp(full, buf) == 0;
    return gpr_index(S(full));
}

/* mem_label(op, relocated, ranks, esp_off, gpr): the leaf label of a memory operand. */
typedef struct Ranks {
    u64 *keys;
    size_t n;
} Ranks;
static i64 rank_of(const Ranks *r, u64 key) {
    size_t lo = 0, hi = r->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (r->keys[mid] < key) lo = mid + 1;
        else hi = mid;
    }
    return lo < r->n && r->keys[lo] == key ? (i64)lo : -1;
}

static const char *mem_label(DkArena *a, DkStr op, bool relocated, const Ranks *ranks, i64 esp_off, const Prov gpr[8]) {
    i64 lb = dk_str_findc(op, '['), rb = dk_str_rfind(op, S("]"), 0, DK_END);
    if (lb < 0 || rb < 0) dk_panic(__FILE__, __LINE__, "ValueError: substring not found");
    DkStr inner = dk_str_slice(op, lb + 1, rb);
    if (relocated || !dk_re_search(RE(REGS32_PAT), inner, 0, DK_END, NULL)) return "[g]";
    if (dk_re_search(RE("\\be[sb]p\\b"), inner, 0, DK_END, NULL)) {
        i64 r = ranks && ranks->n ? rank_of(ranks, slot_key(inner, esp_off)) : -1;
        return r >= 0 ? dk_sprintf(a, "[sp#%lld]", (long long)r) : "[sp]";
    }
    i64 disp = stack_disp(inner);
    DkReMatch idx;
    bool has_idx = dk_re_search(RE("\\b(e[a-ds][xi])\\*(\\d)"), inner, 0, DK_END, &idx);
    DkStr idx_reg = has_idx ? dk_re_group(&idx, 1) : S("");
    bool star = dk_str_findc(inner, '*') >= 0;
    /* regs = [r for r in re.findall(r"\b(e[a-ds][xi])\b", inner) if not (idx and r == idx.group(1) and "*" in inner)] */
    DkStr base = {NULL, 0};
    DkReIter it;
    DkReMatch m;
    dk_re_iter_init(&it, RE("\\b(e[a-ds][xi])\\b"), inner, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) {
        DkStr r = dk_re_group(&m, 1);
        if (has_idx && dk_str_eq(r, idx_reg) && star) continue;
        base = r;
        break;
    }
    const Prov *prov = base.p ? gpr_get(gpr, base) : NULL;
    const char *text = prov ? prov->text : "r";
    disp += prov ? prov->off : 0;
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_putc(&b, '[');
    dk_buf_putz(&b, text);
    dk_buf_putz(&b, fmt_off(a, disp));
    if (has_idx) {
        const Prov *ip = gpr_get(gpr, idx_reg);
        dk_buf_putc(&b, '+');
        if (ip) {
            dk_buf_putz(&b, ip->text);
            if (ip->off) dk_buf_putz(&b, fmt_off(a, ip->off));
        } else {
            dk_buf_putc(&b, 'r');
        }
        dk_buf_putc(&b, '*');
        dk_buf_put(&b, dk_re_group(&idx, 2));
    }
    dk_buf_putc(&b, ']');
    return dk_buf_cz(&b);
}

/* mem_key(op, label) */
static DkStr mem_key(DkStr op, const char *label) { return strncmp(label, "[sp#", 4) == 0 ? S(label) : op; }

typedef struct Ft {
    DkArena *a;
    FoTree *tree;
    Ranks ranks;
    Prov gpr[8];
    FoNode *xmm[8];
    DkMap *mem;            /* {mem_key: FoNode*} */
    FoNode **st;            /* the x87 stack, top last */
    size_t n_st, cap_st;
    i64 esp_off;
    bool rel;
} Ft;

static FoNode *ft_leaf(Ft *c, const char *label) {
    FoNode *n = DK_NEW(c->a, FoNode);
    n->op = FO_LEAF;
    n->label = label;
    return n;
}

static FoNode *ft_make(Ft *c, FoOp op, FoNode *l, FoNode *r) {
    FoNode *n = DK_NEW(c->a, FoNode);
    n->op = op;
    n->l = l;
    n->r = r;
    dk_vec_push(&c->tree->nodes, n);
    if (is_interesting(op)) dk_vec_push(&c->tree->interesting, n);
    return n;
}

static void st_push(Ft *c, FoNode *n) {
    if (c->n_st == c->cap_st) {
        c->cap_st = c->cap_st ? c->cap_st * 2 : 16;
        c->st = dk_xrealloc(c->st, c->cap_st * sizeof *c->st);
    }
    c->st[c->n_st++] = n;
}

/* The xmm register number of an operand ("^xmm([0-7])$"), -1 for None. */
static int xi(DkStr op) {
    if (op.n == 4 && memcmp(op.p, "xmm", 3) == 0 && op.p[3] >= '0' && op.p[3] <= '7') return op.p[3] - '0';
    return -1;
}

static bool has_br(DkStr s) { return dk_str_findc(s, '[') >= 0; }

/* val(op) */
static FoNode *ft_val(Ft *c, DkStr op) {
    int x = xi(op);
    if (x >= 0) return c->xmm[x] ? c->xmm[x] : ft_leaf(c, "?");
    if (has_br(op)) {
        const char *lab = mem_label(c->a, op, c->rel, &c->ranks, c->esp_off, c->gpr);
        if (!c->rel) {
            DkVal *v = dk_map_get(c->mem, mem_key(op, lab));
            if (v) return v->p;
        }
        return ft_leaf(c, lab);
    }
    return ft_leaf(c, "?int");
}

static void ft_store(Ft *c, DkStr op, FoNode *node) {
    const char *lab = mem_label(c->a, op, c->rel, &c->ranks, c->esp_off, c->gpr);
    FoRoot r = {true, lab, node};
    dk_vec_push(&c->tree->roots, r);
    if (!c->rel) dk_map_put(c->mem, dk_str_dup(c->a, mem_key(op, lab)), NULL)->p = node;
}

/* int(re.search(r"\d", s).group()) or -1 when s has no digit (the AttributeError). */
static int first_digit(DkStr s) {
    for (size_t i = 0; i < s.n; i++)
        if (s.p[i] >= '0' && s.p[i] <= '9') return s.p[i] - '0';
    return -1;
}

/* st[-1 - k], or NULL when the stack is too short (IndexError). */
static FoNode **st_at(Ft *c, int k) { return (size_t)(k + 1) <= c->n_st ? &c->st[c->n_st - 1 - (size_t)k] : NULL; }

/* The x87 block of float_tree (L315-364): any IndexError / ValueError / AttributeError clears the stack. */
static void ft_x87(Ft *c, const char *mn, const DkStr *ops, int nops) {
    FoOp op;
    bool rev;
    char base_buf[32];
    size_t ml = strlen(mn);
    const char *base_mn = mn;
    if (ml > 0 && mn[ml - 1] == 'p' && ml < sizeof base_buf) {
        memcpy(base_buf, mn, ml - 1);
        base_buf[ml - 1] = 0;
        FoOp o2;
        bool r2;
        if (x87_op(base_buf, &o2, &r2)) base_mn = base_buf;
    }
    if (strcmp(mn, "fld") == 0 || strcmp(mn, "fild") == 0) {
        if (strcmp(mn, "fild") != 0 && nops < 1) goto bad;
        if (strcmp(mn, "fild") == 0 || has_br(ops[0])) {
            st_push(c, strcmp(mn, "fld") == 0 ? ft_val(c, ops[0]) : ft_leaf(c, "int"));
        } else {
            int d = first_digit(ops[0]);
            FoNode **p = d >= 0 ? st_at(c, d) : NULL;
            if (!p) goto bad;
            st_push(c, *p);
        }
    } else if (strcmp(mn, "fld1") == 0) {
        st_push(c, ft_leaf(c, "1"));
    } else if (strcmp(mn, "fldz") == 0) {
        st_push(c, ft_leaf(c, "0"));
    } else if (strcmp(mn, "fst") == 0 || strcmp(mn, "fstp") == 0) {
        FoNode *node = c->n_st ? c->st[c->n_st - 1] : ft_leaf(c, "?");
        if (nops < 1) goto bad;
        if (has_br(ops[0])) ft_store(c, ops[0], node);
        if (strcmp(mn, "fstp") == 0 && c->n_st) c->n_st--;
    } else if (strcmp(mn, "fchs") == 0 || strcmp(mn, "fabs") == 0 || strcmp(mn, "fsqrt") == 0) {
        FoNode **p = st_at(c, 0);
        if (!p) goto bad;
        *p = ft_make(c, strcmp(mn, "fchs") == 0 ? FO_NEG : strcmp(mn, "fabs") == 0 ? FO_ABS : FO_SQRT, *p, NULL);
    } else if (strcmp(mn, "fxch") == 0) {
        int i = 1;
        if (nops) {
            i = first_digit(ops[0]);
            if (i < 0) goto bad;
        }
        FoNode **p0 = st_at(c, 0), **p1 = st_at(c, i);
        if (!p0 || !p1) goto bad;
        FoNode *t = *p0;
        *p0 = *p1;
        *p1 = t;
    } else if (x87_op(base_mn, &op, &rev)) {
        bool pop = strcmp(base_mn, mn) != 0;
        if (nops == 1 && has_br(ops[0])) {
            FoNode *src = ft_val(c, ops[0]);
            FoNode **p = st_at(c, 0);
            if (!p) goto bad;
            *p = rev ? ft_make(c, op, src, *p) : ft_make(c, op, *p, src);
        } else {
            DkStr two[2];
            if (nops == 1) {
                if (pop) {
                    two[0] = S("st(1)");
                    two[1] = S("st(0)");
                } else {
                    two[0] = S("st(0)");
                    two[1] = ops[0];
                }
            } else if (nops >= 2) {
                two[0] = ops[0];
                two[1] = ops[1];
            } else {
                goto bad;
            }
            int a = first_digit(two[0]), b = first_digit(two[1]);
            if (a < 0 || b < 0) goto bad;
            FoNode **pl = st_at(c, a), **pr = st_at(c, b);
            if (!pl || !pr) goto bad;
            FoNode *l = *pl, *r = *pr;
            *pl = rev ? ft_make(c, op, r, l) : ft_make(c, op, l, r);
            if (pop) c->n_st--;
        }
    } else {
        c->n_st = 0;
    }
    return;
bad:
    c->n_st = 0;
}

/* The operands of an instruction: op_str.split(", "). */
static int split_ops(const char *op_str, DkStr out[8]) {
    if (!*op_str) return 0;
    DkStr rest = S(op_str);
    int n = 0;
    while (n < 7) {
        i64 k = dk_str_find(rest, S(", "), 0, DK_END);
        if (k < 0) break;
        out[n++] = dk_strn(rest.p, (size_t)k);
        rest = dk_strn(rest.p + k + 2, rest.n - (size_t)k - 2);
    }
    out[n++] = rest;
    return n;
}

static bool is_gpr(DkStr s) { return dk_re_match(RE(GPR_PAT), s, 0, DK_END, NULL); }

static int cmp_u64v(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    u64 a = *(const u64 *)x, b = *(const u64 *)y;
    return a < b ? -1 : a > b ? 1 : 0;
}

FoTree *fo_float_tree(DkArena *a, DkStr code, u32 base, const u8 *reloc_bytes, size_t n_reloc) {
    FoTree *tree = DK_NEW(a, FoTree);
    Ft c = {0};
    c.a = a;
    c.tree = tree;
    c.mem = dk_map_new();
    InsVec insns = {0};
    {
        DkDisIter it;
        dk_dis_iter(&it, dk_dis(DK_DIS_X86_32, DK_DIS_SKIPDATA), code.p, code.n, base, 0);
        while (dk_dis_next(&it)) {
            Ins i = {0};
            i.address = it.insn->address;
            i.size = it.insn->size;
            snprintf(i.mn, sizeof i.mn, "%s", it.insn->mnemonic);
            snprintf(i.ops, sizeof i.ops, "%s", it.insn->op_str);
            dk_vec_push(&insns, i);
        }
        dk_dis_iter_end(&it);
    }
    /* the stack slots of the function, ranked by their entry-relative offset */
    DkU64Vec slots = {0};
    i64 off_ = 0;
    for (size_t k = 0; k < insns.n; k++) {
        const Ins *ins = &insns.v[k];
        DkReIter it;
        DkReMatch m;
        dk_re_iter_init(&it, RE("\\[([^\\]]*\\be[sb]p\\b[^\\]]*)\\]"), S(ins->ops), 0, DK_END);
        while (dk_re_iter_next(&it, &m)) dk_vec_push(&slots, slot_key(dk_re_group(&m, 1), off_));
        off_ = esp_step(ins, off_);
    }
    dk_sort(slots.v, slots.n, sizeof(u64), cmp_u64v, NULL, false);
    {
        size_t w = 0;
        for (size_t k = 0; k < slots.n; k++)
            if (k == 0 || slots.v[k] != slots.v[k - 1]) slots.v[w++] = slots.v[k];
        slots.n = w;
    }
    c.ranks.keys = slots.v;
    c.ranks.n = slots.n;
    i64 nxt_off = 0;
    c.esp_off = 0;
    c.gpr[1] = (Prov){true, "this", 0}; /* ecx */
    for (size_t k = 0; k < insns.n; k++) {
        const Ins *ins = &insns.v[k];
        c.esp_off = nxt_off;
        nxt_off = esp_step(ins, nxt_off);
        const char *mn = ins->mn;
        DkStr ops[8];
        int nops = split_ops(ins->ops, ops);
        i64 off = (i64)(ins->address - base);
        c.rel = false;
        for (u32 q = 0; q < ins->size; q++)
            if ((size_t)(off + q) < n_reloc && reloc_bytes && reloc_bytes[off + q]) {
                c.rel = true;
                break;
            }
        if (strcmp(mn, "call") == 0) {
            c.gpr[0].have = c.gpr[1].have = c.gpr[2].have = false; /* eax, ecx, edx */
            memset(c.xmm, 0, sizeof c.xmm);
            c.n_st = 0;
            continue;
        }
        if (mn[0] == 'f' && !in_list(mn, X87_QUIET) && strncmp(mn, "fs:", 3) != 0) {
            ft_x87(&c, mn, ops, nops);
            continue;
        }
        if (nops == 0) continue;
        bool same0 = false;
        int g0 = is_gpr(ops[0]) ? reg_full_index(ops[0], &same0) : -1;
        bool g0_ok = is_gpr(ops[0]) && g0 != 4 && g0 != 5 && strcmp(mn, "cmp") != 0 && strcmp(mn, "test") != 0 &&
                     strcmp(mn, "push") != 0;
        if (is_gpr(ops[0]) && g0 < 0) {
            /* an 8/16-bit name the table cannot hold cannot happen (GPR only matches the eight families) */
            dk_panic(__FILE__, __LINE__, "unexpected register %.*s", DK_SF(ops[0]));
        }
        if (g0_ok) {
            Prov nw = {0};
            if (strcmp(mn, "mov") == 0 && nops > 1) {
                DkStr src = ops[1];
                if (has_br(src)) {
                    nw = (Prov){true, dk_sprintf(a, "*%s", mem_label(a, src, c.rel, &c.ranks, c.esp_off, c.gpr)), 0};
                } else if (is_gpr(src)) {
                    bool same;
                    int si = reg_full_index(src, &same);
                    if (same && si >= 0 && c.gpr[si].have) nw = c.gpr[si];
                }
            } else if (strcmp(mn, "lea") == 0 && nops > 1) {
                i64 lb = dk_str_findc(ops[1], '['), rb = dk_str_rfind(ops[1], S("]"), 0, DK_END);
                if (lb < 0 || rb < 0) dk_panic(__FILE__, __LINE__, "ValueError: substring not found");
                DkStr inner = dk_str_slice(ops[1], lb + 1, rb);
                DkReMatch m;
                if (dk_re_fullmatch(RE("(e[a-ds][xi])(?: ([+-]) (0x[0-9a-f]+|\\d+))?"), inner, 0, DK_END, &m)) {
                    const Prov *p = gpr_get(c.gpr, dk_re_group(&m, 1));
                    if (p) {
                        i64 dd = 0;
                        if (dk_re_matched(&m, 3)) dd = int0(dk_re_group(&m, 3)) * (dk_re_group(&m, 2).p[0] == '-' ? -1 : 1);
                        nw = (Prov){true, p->text, p->off + dd};
                    }
                }
            } else if ((strcmp(mn, "add") == 0 || strcmp(mn, "sub") == 0) && nops > 1 && same0 && c.gpr[g0].have &&
                       dk_re_fullmatch(RE("0x[0-9a-f]+|\\d+"), ops[1], 0, DK_END, NULL) && dk_str_eq(ops[0], S(GPR_NAMES[g0]))) {
                i64 v = int0(ops[1]);
                nw = (Prov){true, c.gpr[g0].text, c.gpr[g0].off + (strcmp(mn, "add") == 0 ? v : -v)};
            }
            c.gpr[g0] = nw; /* new, or popped when None */
            continue;
        }
        int d = xi(ops[0]);
        if (d < 0) {
            /* a store of an xmm register */
            if (has_br(ops[0]) && nops > 1 && xi(ops[1]) >= 0 && in_list(mn, MOVES)) ft_store(&c, ops[0], ft_val(&c, ops[1]));
            continue;
        }
        if (in_list(mn, READERS)) {
            if (nops < 2) dk_panic(__FILE__, __LINE__, "IndexError: list index out of range");
            FoNode *l = ft_val(&c, ops[0]), *r = ft_val(&c, ops[1]);
            FoRoot rt = {false, NULL, ft_make(&c, FO_CMP, l, r)};
            dk_vec_push(&tree->roots, rt);
            continue;
        }
        DkReMatch am;
        if (dk_re_match(RE(ARITH_PAT), S(mn), 0, DK_END, &am) && nops >= 2) {
            DkStr opn = dk_re_group(&am, 1);
            if (dk_str_eqz(opn, "sqrt") || dk_str_eqz(opn, "rsqrt") || dk_str_eqz(opn, "rcp")) {
                FoOp o = dk_str_eqz(opn, "sqrt") ? FO_SQRT : dk_str_eqz(opn, "rsqrt") ? FO_RSQRT : FO_RCP;
                c.xmm[d] = ft_make(&c, o, ft_val(&c, ops[1]), NULL);
            } else if (dk_str_eqz(opn, "sub") && dk_str_eq(ops[0], ops[1])) {
                c.xmm[d] = ft_leaf(&c, "0");
            } else {
                FoOp o = dk_str_eqz(opn, "add") ? FO_ADD : dk_str_eqz(opn, "sub") ? FO_SUB : dk_str_eqz(opn, "mul") ? FO_MUL
                       : dk_str_eqz(opn, "div") ? FO_DIV : dk_str_eqz(opn, "min") ? FO_MIN : FO_MAX;
                FoNode *l = ft_val(&c, ops[0]), *r = ft_val(&c, ops[1]);
                c.xmm[d] = ft_make(&c, o, l, r);
            }
        } else if (in_list(mn, MOVES) || in_list(mn, COPIES)) {
            c.xmm[d] = nops > 1 ? ft_val(&c, ops[1]) : NULL;
        } else if ((strcmp(mn, "xorps") == 0 || strcmp(mn, "xorpd") == 0 || strcmp(mn, "pxor") == 0 ||
                    strcmp(mn, "andps") == 0 || strcmp(mn, "andpd") == 0 || strcmp(mn, "pand") == 0) && nops >= 2) {
            bool is_xor = strncmp(mn, "xor", 3) == 0 || strncmp(mn, "pxor", 4) == 0;
            if (dk_str_eq(ops[0], ops[1])) {
                if (is_xor) c.xmm[d] = ft_leaf(&c, "0");
            } else if (strncmp(mn, "and", 3) == 0) {
                c.xmm[d] = ft_make(&c, FO_ABS, ft_val(&c, ops[0]), NULL);
            } else if (is_xor) {
                c.xmm[d] = ft_make(&c, FO_NEG, ft_val(&c, ops[0]), NULL);
            } else {
                c.xmm[d] = NULL;
            }
        } else if (strcmp(mn, "cvtsi2ss") == 0 || strcmp(mn, "cvtsi2sd") == 0) {
            c.xmm[d] = ft_leaf(&c, "int");
        } else {
            c.xmm[d] = NULL;
        }
    }
    dk_vec_free(&insns);
    dk_vec_free(&slots);
    dk_map_free(c.mem);
    dk_xfree(c.st);
    return tree;
}

void fo_tree_free(FoTree *t) {
    dk_vec_free(&t->nodes);
    dk_vec_free(&t->interesting);
    dk_vec_free(&t->roots);
}

/* ---------------------------------------------------------------------------------------- classification */

typedef DK_VEC(i32) I32Vec;

/* match_nodes(game, ours): per game node the first level (match, commute, assoc) at which an unused node of ours has
 * its signature; `used` marks the nodes of ours consumed. */
void fo_match_nodes(const FoTree *game, const FoTree *ours, u8 *classes, u8 *used) {
    size_t np = ours->interesting.n, ng = game->interesting.n;
    for (size_t i = 0; i < np; i++) used[i] = 0;
    for (size_t g = 0; g < ng; g++) classes[g] = FO_ABSENT;
    u8 *res = (u8 *)dk_xcalloc(ng ? ng : 1, 1); /* 0: None, else level + 1 */
    I32Vec next = {0};
    dk_vec_reserve(&next, np ? np : 1);
    next.n = np;
    for (int level = 0; level < 3; level++) {
        u64 (*sig)(FoNode *) = level == 0 ? fo_ordered : level == 1 ? fo_commuted : fo_flat_;
        DkIMap *head = dk_imap_new_cap(np);
        /* index.setdefault(sig(n), []).append(i) over the unused nodes of ours, in order: lists built backwards */
        for (size_t i = np; i-- > 0;) {
            if (used[i]) continue;
            bool created;
            DkVal *v = dk_imap_put(head, sig(ours->interesting.v[i]), &created);
            next.v[i] = created ? -1 : (i32)v->i;
            v->i = (i64)i;
        }
        for (size_t g = 0; g < ng; g++) {
            if (res[g]) continue;
            DkVal *v = dk_imap_get(head, sig(game->interesting.v[g]));
            if (v && v->i >= 0) { /* index.get(sig(g)) is a non-empty list: pop(0) */
                i32 i = (i32)v->i;
                used[i] = 1;
                v->i = next.v[i];
                res[g] = (u8)(level + 1);
            }
        }
        dk_imap_free(head);
    }
    for (size_t g = 0; g < ng; g++) classes[g] = res[g] ? (u8)(res[g] - 1) : FO_ABSENT;
    dk_xfree(res);
    dk_vec_free(&next);
}

/* extra_ops(game, ours): the nodes of ours no game node uses, plus the negations / abs beyond the game's. */
i64 fo_extra_ops(const FoTree *game, const FoTree *ours) {
    size_t ng = game->interesting.n, np = ours->interesting.n;
    u8 *classes = (u8 *)dk_xcalloc(ng ? ng : 1, 1), *used = (u8 *)dk_xcalloc(np ? np : 1, 1);
    fo_match_nodes(game, ours, classes, used);
    i64 extra = 0;
    for (size_t i = 0; i < np; i++)
        if (!used[i]) extra++;
    dk_xfree(classes);
    dk_xfree(used);
    /* have = Counter(ordered(n) for n in game.nodes if n.op in SIGN_OPS); each of ours consumes one or counts extra */
    DkIMap *have = dk_imap_new();
    for (size_t i = 0; i < game->nodes.n; i++) {
        FoNode *n = game->nodes.v[i];
        if (n->op == FO_NEG || n->op == FO_ABS) dk_imap_put(have, fo_ordered(n), NULL)->i += 1;
    }
    for (size_t i = 0; i < ours->nodes.n; i++) {
        FoNode *n = ours->nodes.v[i];
        if (n->op == FO_NEG || n->op == FO_ABS) {
            DkVal *v = dk_imap_get(have, fo_ordered(n));
            if (v && v->i > 0) v->i -= 1;
            else extra++;
        }
    }
    dk_imap_free(have);
    return extra;
}

void fo_fscore(const u8 *classes, size_t n, i64 f[3]) {
    f[0] = f[1] = f[2] = 0;
    for (size_t i = 0; i < n; i++) {
        if (classes[i] == FO_ABSENT) f[0]++;
        else if (classes[i] == FO_ASSOC) f[1]++;
        else if (classes[i] == FO_COMMUTE) f[2]++;
    }
}

const char *fo_class_counts_repr(const u8 *classes, size_t n) {
    i64 c[4] = {0, 0, 0, 0};
    for (size_t i = 0; i < n; i++) c[classes[i]]++;
    return dk_sprintf(dk_arena(), "{'match': %lld, 'commute': %lld, 'assoc': %lld, 'absent': %lld}", (long long)c[0],
                       (long long)c[1], (long long)c[2], (long long)c[3]);
}

/* ================================================================================== 2. parsing expressions */

typedef enum { TK_NUM, TK_ID, TK_STR, TK_OP } TokKind;
typedef struct Tok {
    TokKind kind;
    DkStr text;
    i64 s, e;
} Tok;
typedef DK_VEC(Tok) TokVec;

static const char TOK_PAT[] =
    "\\s*(?:(?P<num>0[xX][0-9a-fA-F]+[uUlL]*|(?:\\d+\\.\\d*|\\.\\d+)(?:[eE][-+]?\\d+)?[fF]?|\\d+[eE][-+]?\\d+[fF]?|\\d+[uUlLfF]*)\n"
    " |(?P<id>[A-Za-z_]\\w*)\n"
    " |(?P<str>\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])+')\n"
    " |(?P<op><<=|>>=|->|::|<=|>=|==|!=|&&|\\|\\||\\+\\+|--|\\+=|-=|\\*=|/=|%=|&=|\\|=|\\^=|<<|>>|[-+*/%&|^~!<>=?:.,;()\\[\\]{}]))";

DK_NORETURN static void parse_fail(const char *msg) { dk_throw(DK_ERR_OTHER, "ParseError: %s", msg); }

/* tokenize(text) */
static void tokenize(DkStr text, TokVec *out) {
    const DkRe *re = dk_re(TOK_PAT, DK_RE_X);
    i64 pos = 0;
    while (pos < (i64)text.n) {
        DkReMatch m;
        if (!dk_re_match(re, text, pos, DK_END, &m)) {
            if (dk_str_strip(dk_strn(text.p + pos, text.n - (size_t)pos)).n) parse_fail("token");
            break;
        }
        int g = m.lastindex;
        Tok t;
        t.kind = g == 1 ? TK_NUM : g == 2 ? TK_ID : g == 3 ? TK_STR : TK_OP;
        t.text = dk_re_group(&m, g);
        t.s = dk_re_start(&m, g);
        t.e = dk_re_end(&m, g);
        dk_vec_push(out, t);
        pos = dk_re_end(&m, 0);
    }
}

typedef struct Parser {
    DkArena *a;
    TokVec t;
    size_t i;
    DkStr text;
} Parser;

static const Tok *pk(const Parser *p, size_t k) { return p->i + k < p->t.n ? &p->t.v[p->i + k] : NULL; }
static bool is_op_at(const Parser *p, const char *txt, size_t k) {
    const Tok *t = pk(p, k);
    return t && t->kind == TK_OP && dk_str_eqz(t->text, txt);
}
static bool is_op(const Parser *p, const char *txt) { return is_op_at(p, txt, 0); }
static void expect(Parser *p, const char *txt) {
    if (!is_op(p, txt)) parse_fail("expected");
    p->i++;
}

static size_t match_close(const Parser *p, size_t i, const char *open_, const char *close) {
    int depth = 0;
    for (size_t j = i; j < p->t.n; j++) {
        if (p->t.v[j].kind == TK_OP) {
            if (dk_str_eqz(p->t.v[j].text, open_)) depth++;
            else if (dk_str_eqz(p->t.v[j].text, close)) {
                depth--;
                if (depth == 0) return j;
            }
        }
    }
    parse_fail("unbalanced");
}

static FoP *newp(Parser *p, FoPKind kind, DkStr op, int na, i64 s, i64 e) {
    FoP *x = DK_NEW(p->a, FoP);
    x->kind = kind;
    x->op = op;
    x->na = na;
    x->a = na ? DK_NEWN(p->a, FoP *, na) : NULL;
    x->s = s;
    x->e = e;
    return x;
}

static const DkStr NO_OP = {NULL, 0};

static FoP *parse_assign(Parser *p);
static FoP *parse_unary(Parser *p);

static int prec_of(DkStr op) {
    static const struct {
        const char *op;
        int p;
    } tab[] = {{"||", 1}, {"&&", 2}, {"|", 3}, {"^", 4}, {"&", 5}, {"==", 6}, {"!=", 6}, {"<", 7}, {">", 7},
               {"<=", 7}, {">=", 7}, {"<<", 8}, {">>", 8}, {"+", 9}, {"-", 9}, {"*", 10}, {"/", 10}, {"%", 10}};
    for (size_t i = 0; i < DK_ARRAY_LEN(tab); i++)
        if (dk_str_eqz(op, tab[i].op)) return tab[i].p;
    return 0;
}

static bool is_assign_op(DkStr op) {
    static const char *const ops[] = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", NULL};
    for (const char *const *o = ops; *o; o++)
        if (dk_str_eqz(op, *o)) return true;
    return false;
}

static FoP *parse_bin(Parser *p, int minp) {
    FoP *left = parse_unary(p);
    for (;;) {
        const Tok *t = pk(p, 0);
        int pr;
        if (!t || t->kind != TK_OP || (pr = prec_of(t->text)) == 0 || pr < minp) return left;
        p->i++;
        FoP *right = parse_bin(p, pr + 1);
        FoP *b = newp(p, FP_BIN, t->text, 2, left->s, right->e);
        b->a[0] = left;
        b->a[1] = right;
        left = b;
    }
}

static FoP *parse_cond(Parser *p) {
    FoP *c = parse_bin(p, 1);
    if (is_op(p, "?")) {
        p->i++;
        FoP *a = parse_assign(p);
        expect(p, ":");
        FoP *b = parse_cond(p);
        FoP *x = newp(p, FP_COND, S("?"), 3, c->s, b->e);
        x->a[0] = c;
        x->a[1] = a;
        x->a[2] = b;
        return x;
    }
    return c;
}

static FoP *parse_assign(Parser *p) {
    FoP *l = parse_cond(p);
    const Tok *t = pk(p, 0);
    if (t && t->kind == TK_OP && is_assign_op(t->text)) {
        p->i++;
        FoP *r = parse_assign(p);
        FoP *x = newp(p, FP_ASSIGN, t->text, 2, l->s, r->e);
        x->a[0] = l;
        x->a[1] = r;
        return x;
    }
    return l;
}

static bool is_typeword(DkStr w) {
    static const char *const tw[] = {"float", "int", "uint32", "double", "bool", "char", "unsigned", "signed", "long",
                                     "short", "const", "int8", "int16", "int32", "int64", "uint8", "uint16", "uint64",
                                     "size_t", "BYTE", "WORD", "DWORD", NULL};
    for (const char *const *o = tw; *o; o++)
        if (dk_str_eqz(w, *o)) return true;
    return false;
}

/* is_type(toks): a cast's type tokens */
static bool is_type(const Tok *toks, size_t n) {
    if (!n) return false;
    for (size_t i = 0; i < n; i++)
        if (toks[i].kind != TK_ID && toks[i].kind != TK_OP) return false;
    for (size_t i = 0; i < n; i++)
        if (toks[i].kind == TK_OP && !dk_str_eqz(toks[i].text, "*") && !dk_str_eqz(toks[i].text, "&") &&
            !dk_str_eqz(toks[i].text, "::"))
            return false;
    if (dk_str_eqz(toks[n - 1].text, "*")) return true;
    if (!is_typeword(toks[0].text)) return false;
    for (size_t i = 0; i < n; i++)
        if (!(toks[i].kind == TK_ID || dk_str_eqz(toks[i].text, "::"))) return false;
    return true;
}

static FoP *parse_primary(Parser *p) {
    const Tok *tp = pk(p, 0);
    if (!tp) parse_fail("end");
    Tok t = *tp;
    if (t.kind == TK_NUM || t.kind == TK_STR) {
        p->i++;
        return newp(p, FP_ATOM, NO_OP, 0, t.s, t.e);
    }
    if (t.kind == TK_ID) {
        p->i++;
        i64 end = t.e;
        while (is_op(p, "::") && pk(p, 1) && pk(p, 1)->kind == TK_ID) {
            end = pk(p, 1)->e;
            p->i += 2;
        }
        if ((dk_str_eqz(t.text, "static_cast") || dk_str_eqz(t.text, "const_cast") || dk_str_eqz(t.text, "reinterpret_cast")) &&
            is_op(p, "<")) {
            int depth = 0;
            while (pk(p, 0)) {
                if (is_op(p, "<")) {
                    depth++;
                } else if (is_op(p, ">")) {
                    depth--;
                    if (depth == 0) {
                        end = pk(p, 0)->e;
                        p->i++;
                        break;
                    }
                }
                p->i++;
            }
        }
        return newp(p, FP_ATOM, NO_OP, 0, t.s, end);
    }
    if (t.kind == TK_OP && dk_str_eqz(t.text, "(")) {
        size_t j = match_close(p, p->i, "(", ")");
        const Tok *nxt = j + 1 < p->t.n ? &p->t.v[j + 1] : NULL;
        if (is_type(&p->t.v[p->i + 1], j - p->i - 1) && nxt &&
            (nxt->kind == TK_ID || nxt->kind == TK_NUM ||
             (nxt->kind == TK_OP && (dk_str_eqz(nxt->text, "(") || dk_str_eqz(nxt->text, "-") || dk_str_eqz(nxt->text, "*") ||
                                     dk_str_eqz(nxt->text, "&") || dk_str_eqz(nxt->text, "!") || dk_str_eqz(nxt->text, "~"))))) {
            p->i = j + 1;
            FoP *x = parse_unary(p);
            FoP *r = newp(p, FP_ATOM, NO_OP, 1, t.s, x->e);
            r->a[0] = x;
            return r;
        }
        p->i++;
        FoP *x = parse_assign(p);
        expect(p, ")");
        FoP *r = newp(p, FP_PAREN, NO_OP, 1, t.s, p->t.v[p->i - 1].e);
        r->a[0] = x;
        return r;
    }
    parse_fail("primary");
}

typedef DK_VEC(FoP *) PVec;

static FoP *parse_postfix(Parser *p) {
    FoP *base = parse_primary(p);
    PVec subs = {0};
    i64 end = base->e;
    bool moved = false;
    for (;;) {
        const Tok *t = pk(p, 0);
        if (!t || t->kind != TK_OP) break;
        if (dk_str_eqz(t->text, "(")) {
            p->i++;
            if (!is_op(p, ")")) {
                for (;;) {
                    dk_vec_push(&subs, parse_assign(p));
                    if (is_op(p, ",")) {
                        p->i++;
                        continue;
                    }
                    break;
                }
            }
            expect(p, ")");
        } else if (dk_str_eqz(t->text, "[")) {
            p->i++;
            dk_vec_push(&subs, parse_assign(p));
            expect(p, "]");
        } else if (dk_str_eqz(t->text, ".") || dk_str_eqz(t->text, "->")) {
            p->i++;
            if (!pk(p, 0) || pk(p, 0)->kind != TK_ID) parse_fail("member");
            p->i++;
        } else if (dk_str_eqz(t->text, "++") || dk_str_eqz(t->text, "--")) {
            p->i++;
        } else {
            break;
        }
        moved = true;
        end = p->t.v[p->i - 1].e;
    }
    if (!moved) {
        dk_vec_free(&subs);
        return base;
    }
    FoP *r;
    if (base->kind == FP_PAREN) {
        r = newp(p, FP_ATOM, NO_OP, (int)subs.n + 1, base->s, end);
        r->a[0] = base;
        for (size_t k = 0; k < subs.n; k++) r->a[k + 1] = subs.v[k];
    } else {
        r = newp(p, FP_ATOM, NO_OP, base->na + (int)subs.n, base->s, end);
        for (int k = 0; k < base->na; k++) r->a[k] = base->a[k];
        for (size_t k = 0; k < subs.n; k++) r->a[base->na + (int)k] = subs.v[k];
    }
    dk_vec_free(&subs);
    return r;
}

static FoP *parse_unary(Parser *p) {
    const Tok *tp = pk(p, 0);
    if (!tp) parse_fail("end");
    Tok t = *tp;
    if (t.kind == TK_OP) {
        static const char *const un[] = {"-", "+", "!", "~", "*", "&", "++", "--", NULL};
        bool hit = false;
        for (const char *const *o = un; *o; o++)
            if (dk_str_eqz(t.text, *o)) hit = true;
        if (hit) {
            p->i++;
            FoP *x = parse_unary(p);
            FoP *r = newp(p, dk_str_eqz(t.text, "-") ? FP_NEG : FP_UN, t.text, 1, t.s, x->e);
            r->a[0] = x;
            return r;
        }
    }
    if (t.kind == TK_ID && dk_str_eqz(t.text, "sizeof")) {
        p->i++;
        if (is_op(p, "(")) {
            size_t j = match_close(p, p->i, "(", ")");
            i64 e = p->t.v[j].e;
            p->i = j + 1;
            return newp(p, FP_ATOM, NO_OP, 0, t.s, e);
        }
        FoP *x = parse_unary(p);
        return newp(p, FP_ATOM, NO_OP, 0, t.s, x->e);
    }
    return parse_postfix(p);
}

static bool in_words(DkStr w, const char *const *list) {
    for (; *list; list++)
        if (dk_str_eqz(w, *list)) return true;
    return false;
}

static bool try_decl(Parser *p, FoStmtInfo *info) {
    size_t j = p->i, n = p->t.n;
    size_t run_start = j;
    while (j < n && (p->t.v[j].kind == TK_ID || (p->t.v[j].kind == TK_OP && (dk_str_eqz(p->t.v[j].text, "*") ||
                                                                              dk_str_eqz(p->t.v[j].text, "&") ||
                                                                              dk_str_eqz(p->t.v[j].text, "::")))))
        j++;
    const Tok *run = &p->t.v[run_start];
    size_t rn = j - run_start;
    static const char *const not_decl[] = {"return", "delete", "new", "throw", "goto", "else", "case", "if", "while", "for",
                                           "switch", "do", NULL};
    if (rn < 2 || in_words(run[0].text, not_decl) || run[rn - 1].kind != TK_ID || dk_str_eqz(run[rn - 2].text, "::")) return false;
    int ids = 0;
    for (size_t k = 0; k < rn; k++)
        if (run[k].kind == TK_ID) ids++;
    if (ids < 2 && !dk_str_eqz(run[rn - 2].text, "*") && !dk_str_eqz(run[rn - 2].text, "&")) return false;
    if (!(j < n && p->t.v[j].kind == TK_OP &&
          (dk_str_eqz(p->t.v[j].text, "=") || dk_str_eqz(p->t.v[j].text, ";") || dk_str_eqz(p->t.v[j].text, "[") ||
           dk_str_eqz(p->t.v[j].text, ","))))
        return false;
    info->kind = FS_DECL;
    info->name = run[rn - 1].text;
    info->type = dk_str_strip(dk_strn(p->text.p + run[0].s, (size_t)(run[rn - 1].s - run[0].s)));
    p->i = j;
    if (is_op(p, "=")) {
        p->i++;
        FoP *init = parse_assign(p);
        dk_vec_push(&info->roots, init);
        info->init = init;
    }
    return true;
}

static void statement(Parser *p, FoStmtInfo *info) {
    DkStr text = p->text;
    while (pk(p, 0)) {
        Tok t = *pk(p, 0);
        if (t.kind == TK_OP && (dk_str_eqz(t.text, "{") || dk_str_eqz(t.text, "}") || dk_str_eqz(t.text, ";"))) {
            p->i++;
            continue;
        }
        if (t.kind == TK_ID && (dk_str_eqz(t.text, "if") || dk_str_eqz(t.text, "while") || dk_str_eqz(t.text, "switch"))) {
            p->i++;
            expect(p, "(");
            dk_vec_push(&info->roots, parse_assign(p));
            expect(p, ")");
            info->kind = FS_CTL;
            continue;
        }
        if (t.kind == TK_ID && dk_str_eqz(t.text, "for")) {
            p->i++;
            expect(p, "(");
            static const char *const closers[3] = {";", ";", ")"};
            for (int q = 0; q < 3; q++) {
                if (!is_op(p, closers[q])) {
                    if (!try_decl(p, info)) dk_vec_push(&info->roots, parse_assign(p));
                }
                expect(p, closers[q]);
            }
            info->kind = FS_CTL;
            continue;
        }
        if (t.kind == TK_ID && (dk_str_eqz(t.text, "else") || dk_str_eqz(t.text, "do"))) {
            p->i++;
            continue;
        }
        if (t.kind == TK_ID && (dk_str_eqz(t.text, "break") || dk_str_eqz(t.text, "continue") || dk_str_eqz(t.text, "goto"))) {
            while (pk(p, 0) && !is_op(p, ";")) p->i++;
            continue;
        }
        if (t.kind == TK_ID && (dk_str_eqz(t.text, "case") || dk_str_eqz(t.text, "default"))) {
            while (pk(p, 0) && !is_op(p, ":")) p->i++;
            p->i++;
            continue;
        }
        if (t.kind == TK_ID && dk_str_eqz(t.text, "return")) {
            p->i++;
            if (!is_op(p, ";") && pk(p, 0)) {
                FoP *e = parse_assign(p);
                dk_vec_push(&info->roots, e);
            }
            info->kind = FS_RET;
            continue;
        }
        if (try_decl(p, info)) {
            if (is_op(p, ",")) {
                info->multi = true;
                return;
            }
            continue;
        }
        FoP *e = parse_assign(p);
        dk_vec_push(&info->roots, e);
        info->kind = FS_EXPR;
        info->expr = e;
        info->expr_at0 = e->s == 0; /* and not info.get("ctl_before"), which nothing sets */
        if (pk(p, 0) && !is_op(p, ";")) parse_fail("trailing");
    }
    DK_UNUSED(text);
}

FoStmtInfo fo_parse_stmt(DkStr text) {
    FoStmtInfo info = {0};
    info.kind = FS_OTHER;
    Parser p = {0};
    p.a = dk_arena();
    p.text = text;
    DkTry t;
    if (DK_TRY(&t)) {
        tokenize(text, &p.t);
        statement(&p, &info);
        dk_try_end(&t);
    } else {
        FoStmtInfo bad = {0};
        bad.kind = FS_OTHER;
        bad.bad = true;
        info = bad;
    }
    dk_vec_free(&p.t);
    return info;
}

/* ===================================================================================== 3. sites and spellings */

static bool is_arith(const FoP *p) {
    if (p->kind == FP_BIN) return p->op.n == 1 && strchr("+-*/", p->op.p[0]);
    return p->kind == FP_NEG || (p->kind == FP_PAREN && is_arith(p->a[0]));
}

/* norm(t): runs of whitespace become one space, stripped. */
static DkStr norm(DkStr t) {
    DkStr r = dk_re_sub(dk_arena(), RE("\\s+"), S(" "), t, 0);
    return dk_str_strip(r);
}

/* ---- the hash-consed trees */
static DkMutex tr_lock;
static DkMap *tr_table;

static FoTr *tr_intern(char kind, char op, DkStr text, FoTr *l, FoTr *r) {
    DkBuf key = {0};
    dk_buf_putc(&key, kind);
    dk_buf_putc(&key, op);
    dk_buf_putn(&key, &l, sizeof l);
    dk_buf_putn(&key, &r, sizeof r);
    dk_buf_put(&key, text);
    dk_mutex_lock(&tr_lock);
    if (!tr_table) tr_table = dk_map_new();
    bool created;
    DkVal *v = dk_map_put(tr_table, dk_buf_str(&key), &created);
    if (created) {
        FoTr *t = DK_NEW(dk_arena(), FoTr);
        t->kind = kind;
        t->op = op;
        t->text = dk_str_dup(dk_arena(), text);
        t->l = l;
        t->r = r;
        v->p = t;
    }
    FoTr *res = v->p;
    dk_mutex_unlock(&tr_lock);
    dk_buf_free(&key);
    return res;
}

FoTr *fo_tr_a(DkStr text) { return tr_intern('a', 0, text, NULL, NULL); }
FoTr *fo_tr_n(FoTr *x) { return tr_intern('n', 0, S(""), x, NULL); }
FoTr *fo_tr_b(char op, FoTr *l, FoTr *r) { return tr_intern('b', op, S(""), l, r); }

typedef DK_VEC(DkStr) StrVec;

static FoTr *to_tree(const FoP *p, DkStr text, PVec *atoms) {
    if (p->kind == FP_BIN && p->op.n == 1 && strchr("+-*/", p->op.p[0])) {
        /* left operand first: the atoms are collected in source order (C leaves the argument order open) */
        FoTr *l = to_tree(p->a[0], text, atoms);
        FoTr *r = to_tree(p->a[1], text, atoms);
        return fo_tr_b(p->op.p[0], l, r);
    }
    if (p->kind == FP_NEG) return fo_tr_n(to_tree(p->a[0], text, atoms));
    if (p->kind == FP_PAREN && is_arith(p->a[0])) return to_tree(p->a[0], text, atoms);
    dk_vec_push(atoms, (FoP *)p);
    return fo_tr_a(norm(dk_str_slice(text, p->s, p->e)));
}

static void tree_atoms(const FoTr *t, StrVec *out) {
    if (t->kind == 'a') {
        dk_vec_push(out, t->text);
    } else if (t->kind == 'n') {
        tree_atoms(t->l, out);
    } else {
        tree_atoms(t->l, out);
        tree_atoms(t->r, out);
    }
}

/* pow2_literal(text): the value of a float literal that is a power of two within 2**-8..2**8 and not 1, else 0. */
static double pow2_literal(DkStr text) {
    DkReMatch m;
    if (!dk_re_fullmatch(RE("(\\d+\\.?\\d*|\\.\\d+)[fF]?"), text, 0, DK_END, &m)) return 0;
    double v;
    if (!dk_parse_float(dk_re_group(&m, 1), &v)) return 0;
    if (v <= 0) return 0;
    int e;
    double mant = frexp(v, &e);
    return mant == 0.5 && abs(e - 1) <= 8 && v != 1.0 ? v : 0;
}

static bool eligible(const FoTr *t) {
    if (t->kind == 'a') return false;
    if (t->kind == 'n') return eligible(t->l);
    if (t->op == '+' || t->op == '-' || t->op == '*') return true;
    if (t->r->kind == 'a' && pow2_literal(t->r->text) != 0) return true;
    return eligible(t->l) || eligible(t->r);
}

typedef struct SiteCtx {
    DkStr text;
    const DkSet *float_names;
    FoSiteVec *sites;
} SiteCtx;

static void visit(SiteCtx *c, const FoP *p) {
    if (is_arith(p)) {
        PVec atoms = {0};
        FoTr *tree = to_tree(p, c->text, &atoms);
        if (eligible(tree)) {
            StrVec texts = {0};
            tree_atoms(tree, &texts);
            int ncalls = 0;
            bool bad = false;
            for (size_t i = 0; i < texts.n; i++) {
                if (dk_ctext_calls(texts.v[i])) ncalls++;
                if (dk_re_search(RE("\\+\\+|--|[^=!<>]=[^=]"), texts.v[i], 0, DK_END, NULL)) bad = true;
            }
            if (ncalls <= 1 && !bad) {
                DkStr body = dk_str_slice(c->text, p->s, p->e);
                bool hint = dk_re_search(RE("\\b\\d+\\.\\d*f?\\b|\\b\\d+e[-+]?\\d+f\\b|\\.\\d+f?\\b"), body, 0, DK_END, NULL) ||
                            dk_str_contains(body, S("values["));
                if (!hint && c->float_names) {
                    size_t pos = 0;
                    DkStr nm;
                    while (dk_set_next(c->float_names, &pos, &nm)) {
                        DkBuf pat = {0};
                        dk_buf_putz(&pat, "\\b");
                        dk_buf_put(&pat, dk_re_escape(dk_arena(), nm));
                        dk_buf_putz(&pat, "\\b");
                        bool hit = dk_re_search(dk_re_try_n(dk_buf_str(&pat), 0), body, 0, DK_END, NULL);
                        dk_buf_free(&pat);
                        if (hit) {
                            hint = true;
                            break;
                        }
                    }
                }
                FoSite s = {p->s, p->e, tree, dk_str_slice(c->text, p->s, p->e), p->kind == FP_PAREN, (int)texts.n, hint, 0};
                dk_vec_push(c->sites, s);
            }
            dk_vec_free(&texts);
        }
        for (size_t i = 0; i < atoms.n; i++)
            for (int k = 0; k < atoms.v[i]->na; k++) visit(c, atoms.v[i]->a[k]);
        dk_vec_free(&atoms);
    } else {
        for (int k = 0; k < p->na; k++) visit(c, p->a[k]);
    }
}

FoSiteVec fo_find_sites(DkStr text, const FoStmtInfo *info, const DkSet *float_names) {
    FoSiteVec sites = {0};
    SiteCtx c = {text, float_names, &sites};
    for (size_t i = 0; i < info->roots.n; i++) visit(&c, info->roots.v[i]);
    /* seen[text] numbering */
    for (size_t i = 0; i < sites.n; i++) {
        int n = 0;
        for (size_t j = 0; j < i; j++)
            if (dk_str_eq(sites.v[j].text, sites.v[i].text)) n++;
        sites.v[i].nth = n;
    }
    return sites;
}

/* ---- statements of a body */

static DkStr strip_comment(DkStr line) {
    i64 k = dk_str_find(line, S("//"), 0, DK_END);
    return k < 0 ? line : dk_strn(line.p, (size_t)k);
}

static bool stmt_complete(DkStr text) {
    int depth = 0;
    DkStr nostr = dk_re_sub(dk_arena(), RE("\"(?:\\\\.|[^\"\\\\])*\""), S(""), text, 0);
    for (size_t i = 0; i < nostr.n; i++) depth += (nostr.p[i] == '(') - (nostr.p[i] == ')');
    if (depth > 0) return false;
    char last = text.p[text.n - 1];
    if (last == ';' || last == '{' || last == '}') return true;
    if (dk_str_eqz(text, "else") || dk_str_endswith(text, S(" else")) || dk_str_eqz(text, "do")) return true;
    if (dk_re_match(RE("^(?:else\\s+)?(?:if|while|for|switch)\\b"), text, 0, DK_END, NULL) && last == ')') return true;
    if (last == ':' && dk_re_match(RE("^(?:case\\b|default\\b|\\w+:$)"), text, 0, DK_END, NULL)) return true;
    return false;
}

FoStmtVec fo_group_statements(const DkCzVec *lines) {
    FoStmtVec out = {0};
    size_t i = 0;
    while (i < lines->n) {
        DkStr code = dk_str_strip(strip_comment(S(lines->v[i])));
        if (!code.n || code.p[0] == '#') {
            i++;
            continue;
        }
        size_t lo = i;
        DkBuf text = {0};
        dk_buf_put(&text, code);
        while (!stmt_complete(dk_buf_str(&text)) && i + 1 < lines->n) {
            i++;
            DkStr c = dk_str_strip(strip_comment(S(lines->v[i])));
            if (c.n) {
                dk_buf_putc(&text, ' ');
                dk_buf_put(&text, c);
            }
        }
        FoStmt st = {(i64)lo, (i64)i, dk_str_dup(dk_arena(), dk_buf_str(&text))};
        dk_buf_free(&text);
        dk_vec_push(&out, st);
        i++;
    }
    return out;
}

/* with_statement(body, st, new_texts): body with the lines of st replaced by one line per text. */
static DkCzVec with_statement(const DkCzVec *body, const FoStmt *st, const DkStr *new_texts, size_t n_new) {
    DkArena *a = dk_arena();
    DkStr first = S(body->v[st->lo]);
    DkStr ind = dk_strn(first.p, first.n - dk_str_lstrip(first).n);
    DkStr tail = {"", 0};
    if (st->lo == st->hi) {
        DkReMatch m;
        if (dk_re_search(RE("\\s*//.*$"), first, 0, DK_END, &m)) tail = dk_re_group(&m, 0);
    }
    DkCzVec out = {0};
    for (i64 k = 0; k < st->lo; k++) dk_vec_push(&out, body->v[k]);
    for (size_t k = 0; k < n_new; k++) {
        DkBuf b;
        dk_buf_init(&b, a);
        dk_buf_put(&b, ind);
        dk_buf_put(&b, new_texts[k]);
        if (k == n_new - 1 && tail.n) dk_buf_put(&b, tail);
        dk_vec_push(&out, dk_buf_cz(&b));
    }
    for (size_t k = (size_t)st->hi + 1; k < body->n; k++) dk_vec_push(&out, body->v[k]);
    return out;
}

/* ---- spellings of one site */

static char *fmt_literal(double v, bool f) {
    DkArena *a = dk_arena();
    DkStr s = dk_pyfmt(a, "%.17g", v);
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_put(&b, s);
    if (dk_str_findc(s, '.') < 0 && dk_str_findc(s, 'e') < 0) dk_buf_putz(&b, ".0");
    if (f) dk_buf_putc(&b, 'f');
    return dk_buf_cz(&b);
}

/* render_tree(t): (text, precedence): atoms 100, unary minus 90, * / 20, + - 10. */
static void render_tree_(FoTr *t) {
    if (t->rtext) return;
    DkArena *a = dk_arena();
    if (t->kind == 'a') {
        t->rtext = dupv(a, t->text);
        t->rprec = 100;
        return;
    }
    if (t->kind == 'n') {
        render_tree_(t->l);
        const char *x = t->l->rtext;
        if (t->l->rprec < 90 || x[0] == '-') x = dk_sprintf(a, "(%s)", x);
        t->rtext = dk_sprintf(a, "-%s", x);
        t->rprec = 90;
        return;
    }
    int p = (t->op == '*' || t->op == '/') ? 20 : 10;
    render_tree_(t->l);
    render_tree_(t->r);
    const char *l = t->l->rtext, *r = t->r->rtext;
    if (t->l->rprec < p) l = dk_sprintf(a, "(%s)", l);
    if (t->r->rprec <= p) r = dk_sprintf(a, "(%s)", r);
    t->rtext = dk_sprintf(a, "%s %c %s", l, t->op, r);
    t->rprec = p;
}

const char *fo_render_tree(FoTr *t) {
    render_tree_(t);
    return t->rtext;
}

/* kind_of(t): 'a' (add), 'm' (mul) or 0 */
static char kind_of(const FoTr *t) {
    if (t->kind == 'b' && (t->op == '+' || t->op == '-')) return 'a';
    if (t->kind == 'b' && t->op == '*') return 'm';
    return 0;
}

typedef struct STerm {
    int sign;
    FoTr *t;
} STerm;
typedef DK_VEC(STerm) STermVec;
typedef DK_VEC(FoTr *) TrVec;

static void flatten(FoTr *t, int sign, STermVec *out) {
    if (t->kind == 'b' && (t->op == '+' || t->op == '-')) {
        flatten(t->l, sign, out);
        flatten(t->r, t->op == '+' ? sign : -sign, out);
    } else if (t->kind == 'n') {
        flatten(t->l, -sign, out);
    } else {
        STerm s = {sign, t};
        dk_vec_push(out, s);
    }
}

static void flatten_mul(FoTr *t, TrVec *out) {
    if (t->kind == 'b' && t->op == '*') {
        flatten_mul(t->l, out);
        flatten_mul(t->r, out);
    } else {
        dk_vec_push(out, t);
    }
}

static FoTr *chain(const STerm *terms, size_t n) {
    FoTr *acc = terms[0].t;
    for (size_t i = 1; i < n; i++) acc = fo_tr_b(terms[i].sign > 0 ? '+' : '-', acc, terms[i].t);
    return acc;
}

typedef struct Move {
    FoTr *t;
    const char *mv;
} Move;
typedef DK_VEC(Move) MoveVec;

static void add_move(MoveVec *out, FoTr *t, const char *mv) {
    Move m = {t, mv};
    dk_vec_push(out, m);
}

/* Heap's order is not itertools.permutations': lexicographic by index, generated here. */
static bool next_permutation_idx(int *idx, int n) {
    int i = n - 2;
    while (i >= 0 && idx[i] >= idx[i + 1]) i--;
    if (i < 0) return false;
    int j = n - 1;
    while (idx[j] <= idx[i]) j--;
    int t = idx[i];
    idx[i] = idx[j];
    idx[j] = t;
    for (int a = i + 1, b = n - 1; a < b; a++, b--) {
        t = idx[a];
        idx[a] = idx[b];
        idx[b] = t;
    }
    return true;
}

static bool is_b(const FoTr *t, char op) { return t->kind == 'b' && t->op == op; }

static void root_moves(MoveVec *out, FoTr *t, unsigned allowed, bool hint, bool chain_root) {
    DkArena *a = dk_arena();
    if (t->kind == 'b') {
        char op = t->op;
        FoTr *l = t->l, *r = t->r;
        if ((allowed & FOM_COMMUTE) && (op == '+' || op == '*')) add_move(out, fo_tr_b(op, r, l), "commute");
        if (allowed & FOM_ASSOC) {
            if (op == '+' || op == '*') {
                if (is_b(l, op)) add_move(out, fo_tr_b(op, l->l, fo_tr_b(op, l->r, r)), "assoc");
                if (is_b(r, op)) add_move(out, fo_tr_b(op, fo_tr_b(op, l, r->l), r->r), "assoc");
            }
            if (op == '+' && is_b(l, '-')) add_move(out, fo_tr_b('-', l->l, fo_tr_b('-', l->r, r)), "assoc");
            if (op == '-' && is_b(r, '-')) add_move(out, fo_tr_b('+', fo_tr_b('-', l, r->l), r->r), "assoc");
            if (op == '-' && is_b(l, '+')) add_move(out, fo_tr_b('+', l->l, fo_tr_b('-', l->r, r)), "assoc");
            if (op == '+' && is_b(r, '-')) add_move(out, fo_tr_b('-', fo_tr_b('+', l, r->l), r->r), "assoc");
            if (op == '-' && is_b(l, '-')) add_move(out, fo_tr_b('-', l->l, fo_tr_b('+', l->r, r)), "assoc");
            if (op == '-' && is_b(r, '+')) add_move(out, fo_tr_b('-', fo_tr_b('-', l, r->l), r->r), "assoc");
            if (hint && op == '/' && is_b(l, '*')) add_move(out, fo_tr_b('*', l->l, fo_tr_b('/', l->r, r)), "assoc");
            if (hint && op == '*' && is_b(r, '/')) add_move(out, fo_tr_b('/', fo_tr_b('*', l, r->l), r->r), "assoc");
        }
        if ((allowed & FOM_SUMORDER) && chain_root && kind_of(t)) {
            STermVec terms = {0};
            if (kind_of(t) == 'a') {
                flatten(t, 1, &terms);
            } else {
                TrVec fs = {0};
                flatten_mul(t, &fs);
                for (size_t i = 0; i < fs.n; i++) {
                    STerm s = {1, fs.v[i]};
                    dk_vec_push(&terms, s);
                }
                dk_vec_free(&fs);
            }
            int n = (int)terms.n;
            if (n >= 3 && n <= 4) {
                int idx[4] = {0, 1, 2, 3};
                do {
                    STerm perm[4];
                    for (int i = 0; i < n; i++) perm[i] = terms.v[idx[i]];
                    if (perm[0].sign < 0) continue;
                    if (kind_of(t) == 'a') {
                        add_move(out, chain(perm, (size_t)n), "sumorder");
                        if (n == 4) {
                            FoTr *left = fo_tr_b(perm[1].sign > 0 ? '+' : '-', perm[0].t, perm[1].t);
                            FoTr *right = fo_tr_b((perm[3].sign > 0) == (perm[2].sign > 0) ? '+' : '-', perm[2].t, perm[3].t);
                            add_move(out, fo_tr_b(perm[2].sign > 0 ? '+' : '-', left, right), "sumorder");
                        }
                    } else {
                        FoTr *acc = perm[0].t;
                        for (int i = 1; i < n; i++) acc = fo_tr_b('*', acc, perm[i].t);
                        add_move(out, acc, "sumorder");
                        if (n == 4)
                            add_move(out, fo_tr_b('*', fo_tr_b('*', perm[0].t, perm[1].t), fo_tr_b('*', perm[2].t, perm[3].t)),
                                     "sumorder");
                    }
                } while (next_permutation_idx(idx, n));
            }
            dk_vec_free(&terms);
        }
        if (allowed & FOM_FACTOR) {
            if ((op == '+' || op == '-') && is_b(l, '*') && is_b(r, '*')) {
                for (int i = 2; i <= 3; i++)
                    for (int j = 2; j <= 3; j++) {
                        FoTr *li = i == 2 ? l->l : l->r, *rj = j == 2 ? r->l : r->r;
                        if (strcmp(fo_render_tree(li), fo_render_tree(rj)) == 0) {
                            FoTr *aa = (5 - i) == 2 ? l->l : l->r, *bb = (5 - j) == 2 ? r->l : r->r;
                            FoTr *s = fo_tr_b(op, aa, bb);
                            add_move(out, i == 3 ? fo_tr_b('*', s, li) : fo_tr_b('*', li, s), "factor");
                        }
                    }
            }
            if (op == '*') {
                for (int q = 0; q < 2; q++) {
                    FoTr *x = q == 0 ? l : r, *y = q == 0 ? r : l;
                    if (x->kind == 'b' && (x->op == '+' || x->op == '-')) {
                        FoTr *p0, *p1;
                        if (q == 0) { /* `y is r` */
                            p0 = fo_tr_b('*', x->l, y);
                            p1 = fo_tr_b('*', x->r, y);
                        } else {
                            p0 = fo_tr_b('*', y, x->l);
                            p1 = fo_tr_b('*', y, x->r);
                        }
                        add_move(out, fo_tr_b(x->op, p0, p1), "factor");
                    }
                }
            }
        }
        if (allowed & FOM_SIGN) {
            if (op == '-') {
                add_move(out, fo_tr_n(fo_tr_b('-', r, l)), "sign");
                add_move(out, fo_tr_b('+', l, fo_tr_n(r)), "sign");
            }
            if (op == '+' && l->kind == 'n') add_move(out, fo_tr_b('-', r, l->l), "sign");
            if (op == '+' && r->kind == 'n') add_move(out, fo_tr_b('-', l, r->l), "sign");
        }
        if (allowed & FOM_HALF) {
            if (op == '*') {
                for (int q = 0; q < 2; q++) {
                    FoTr *x = q == 0 ? l : r, *k = q == 0 ? r : l;
                    double v = k->kind == 'a' ? pow2_literal(k->text) : 0;
                    if (v != 0 && v < 1) {
                        char lastc = k->text.p[k->text.n - 1];
                        const char *lit = fmt_literal(1 / v, lastc == 'f' || lastc == 'F');
                        add_move(out, fo_tr_b('/', x, fo_tr_a(S(lit))), "half");
                    }
                }
            }
            if (op == '/' && r->kind == 'a') {
                double v = pow2_literal(r->text);
                if (v != 0 && v > 1) {
                    char lastc = r->text.p[r->text.n - 1];
                    const char *lit = fmt_literal(1 / v, lastc == 'f' || lastc == 'F');
                    add_move(out, fo_tr_b('*', l, fo_tr_a(S(lit))), "half");
                }
            }
        }
    } else if (t->kind == 'n' && (allowed & FOM_SIGN)) {
        FoTr *x = t->l;
        if (is_b(x, '-')) add_move(out, fo_tr_b('-', x->r, x->l), "sign");
    }
    DK_UNUSED(a);
}

static void neighbors(MoveVec *out, FoTr *t, unsigned allowed, bool hint, bool chain_root) {
    root_moves(out, t, allowed, hint, chain_root);
    if (t->kind == 'n') {
        MoveVec sub = {0};
        neighbors(&sub, t->l, allowed, hint, true);
        for (size_t i = 0; i < sub.n; i++) add_move(out, fo_tr_n(sub.v[i].t), sub.v[i].mv);
        dk_vec_free(&sub);
    } else if (t->kind == 'b') {
        char same = kind_of(t);
        MoveVec sub = {0};
        neighbors(&sub, t->l, allowed, hint, !(same && kind_of(t->l) == same));
        for (size_t i = 0; i < sub.n; i++) add_move(out, fo_tr_b(t->op, sub.v[i].t, t->r), sub.v[i].mv);
        sub.n = 0;
        neighbors(&sub, t->r, allowed, hint, !(same && kind_of(t->r) == same));
        for (size_t i = 0; i < sub.n; i++) add_move(out, fo_tr_b(t->op, t->l, sub.v[i].t), sub.v[i].mv);
        dk_vec_free(&sub);
    }
}

const char *fo_moves_repr(unsigned allowed) {
    static const struct {
        unsigned bit;
        const char *name;
    } names[] = {{FOM_ASSOC, "assoc"}, {FOM_COMMUTE, "commute"}, {FOM_FACTOR, "factor"},
                 {FOM_HALF, "half"},   {FOM_SIGN, "sign"},       {FOM_SUMORDER, "sumorder"}};
    DkBuf b = {0};
    dk_buf_putc(&b, '[');
    bool first = true;
    for (size_t i = 0; i < DK_ARRAY_LEN(names); i++) {
        if (!(allowed & names[i].bit)) continue;
        if (!first) dk_buf_putz(&b, ", ");
        first = false;
        dk_buf_putc(&b, '\'');
        dk_buf_putz(&b, names[i].name);
        dk_buf_putc(&b, '\'');
    }
    dk_buf_putc(&b, ']');
    char *r = dk_strdup(dk_arena(), b.p);
    dk_buf_free(&b);
    return r;
}

const char *fo_path_text(const FoPath *p) {
    DkCzVec rev = {0};
    for (; p; p = p->prev) dk_vec_push(&rev, (char *)p->mv);
    DkBuf b = {0};
    for (size_t i = rev.n; i-- > 0;) {
        dk_buf_putz(&b, rev.v[i]);
        if (i) dk_buf_putc(&b, ',');
    }
    char *r = dk_strdup(dk_arena(), b.p ? b.p : "");
    dk_buf_free(&b);
    dk_vec_free(&rev);
    return r;
}

typedef struct Front {
    FoTr *t;
    FoPath *path;
} Front;
typedef DK_VEC(Front) FrontVec;

FoSpellingVec fo_spellings(FoTr *tree, size_t max_n, unsigned allowed, bool hint, bool paren) {
    DkArena *a = dk_arena();
    DkISet *seen = dk_iset_new();
    dk_iset_add(seen, (u64)(uintptr_t)tree);
    FrontVec frontier = {0};
    Front f0 = {tree, NULL};
    dk_vec_push(&frontier, f0);
    FoSpellingVec out = {0};
    while (frontier.n && out.n < max_n) {
        FrontVec nxt = {0};
        for (size_t fi = 0; fi < frontier.n; fi++) {
            MoveVec nb = {0};
            neighbors(&nb, frontier.v[fi].t, allowed, hint, true);
            for (size_t k = 0; k < nb.n; k++) {
                if (!dk_iset_add(seen, (u64)(uintptr_t)nb.v[k].t)) continue;
                FoPath *path = DK_NEW(a, FoPath);
                path->prev = frontier.v[fi].path;
                path->mv = nb.v[k].mv;
                Front nf = {nb.v[k].t, path};
                dk_vec_push(&nxt, nf);
                const char *s = fo_render_tree(nb.v[k].t);
                FoSpelling sp = {paren ? dk_sprintf(a, "(%s)", s) : s, nb.v[k].t, path};
                dk_vec_push(&out, sp);
                if (out.n >= max_n) {
                    dk_vec_free(&nb);
                    dk_vec_free(&nxt);
                    dk_vec_free(&frontier);
                    dk_iset_free(seen);
                    return out;
                }
            }
            dk_vec_free(&nb);
        }
        dk_vec_free(&frontier);
        frontier = nxt;
    }
    dk_vec_free(&frontier);
    dk_iset_free(seen);
    return out;
}

/* ---- statement moves: compound forms, split / join of a sum, single-use local inlined */

static bool simple_lvalue(DkStr s) { return dk_re_match(RE("^[A-Za-z_][\\w.\\->\\[\\]]*$"), s, 0, DK_END, NULL); }

static bool calls_v(DkStr s) { return dk_ctext_calls(s) != 0; }

/* r"\b" + re.escape(name) + r"\b" */
static const DkRe *word_re(DkStr name) {
    DkBuf b = {0};
    dk_buf_putz(&b, "\\b");
    dk_buf_put(&b, dk_re_escape(dk_arena(), name));
    dk_buf_putz(&b, "\\b");
    const DkRe *re = dk_re_try_n(dk_buf_str(&b), 0);
    dk_buf_free(&b);
    return re;
}

static void flat_plus(const FoP *p, DkStr text, StrVec *terms) {
    if (p->kind == FP_BIN && dk_str_eqz(p->op, "+")) {
        flat_plus(p->a[0], text, terms);
        flat_plus(p->a[1], text, terms);
    } else {
        dk_vec_push(terms, dk_str_slice(text, p->s, p->e));
    }
}

static void push_variant(FoVariantVec *out, DkCzVec body, const char *note) {
    FoVariant v = {body, note};
    dk_vec_push(out, v);
}

typedef struct InlCtx {
    DkStr init;
} InlCtx;
static void inline_repl(void *ctx, const DkReMatch *m, DkBuf *out) {
    DK_UNUSED(m);
    dk_buf_put(out, ((InlCtx *)ctx)->init);
}

FoVariantVec fo_stmt_variants(const DkCzVec *body, const DkISet *only) {
    DkArena *a = dk_arena();
    FoVariantVec out = {0};
    FoStmtVec stmts = fo_group_statements(body);
    FoStmtInfo *infos = DK_NEWN(a, FoStmtInfo, stmts.n ? stmts.n : 1);
    for (size_t k = 0; k < stmts.n; k++) infos[k] = fo_parse_stmt(stmts.v[k].text);
    for (size_t k = 0; k < stmts.n; k++) {
        FoStmt *st = &stmts.v[k];
        FoStmtInfo *info = &infos[k];
        if (only && !dk_iset_has(only, k)) continue;
        DkStr text = st->text;
        FoP *e = info->expr;
        DkStr text_nosemi = dk_str_strip(dk_str_rstrip_chars(text, S(";")));
        if (info->kind == FS_EXPR && e && e->kind == FP_ASSIGN && info->expr_at0 &&
            dk_str_eq(text_nosemi, dk_str_slice(text, e->s, e->e))) {
            DkStr L = dk_str_slice(text, e->a[0]->s, e->a[0]->e), R = dk_str_slice(text, e->a[1]->s, e->a[1]->e);
            if (simple_lvalue(L) && !calls_v(R) && !calls_v(L)) {
                if (dk_str_eqz(e->op, "+=") || dk_str_eqz(e->op, "*=") || dk_str_eqz(e->op, "-=")) {
                    char bop = e->op.p[0];
                    FoP *r1 = e->a[1];
                    /* e.a[1].op in "+-" is a substring test: only the one-character + and - hit */
                    bool wrap = (r1->kind == FP_BIN || r1->kind == FP_COND || r1->kind == FP_ASSIGN) &&
                                (bop == '*' || (r1->op.n == 1 && (r1->op.p[0] == '+' || r1->op.p[0] == '-')));
                    DkStr Rw = wrap ? dk_str_dup(a, dk_str(dk_sprintf(a, "(%.*s)", DK_SF(R)))) : R;
                    DkStr t1 = dk_str(dk_sprintf(a, "%.*s = %.*s %c %.*s;", DK_SF(L), DK_SF(L), bop, DK_SF(Rw)));
                    char note[40];
                    snprintf(note, sizeof note, "compound %d", (int)k);
                    push_variant(&out, with_statement(body, st, &t1, 1), dk_strdup(a, note));
                    if (bop != '-') {
                        DkStr t2 = dk_str(dk_sprintf(a, "%.*s = %.*s %c %.*s;", DK_SF(L), DK_SF(Rw), bop, DK_SF(L)));
                        push_variant(&out, with_statement(body, st, &t2, 1), dk_strdup(a, note));
                    }
                } else if (dk_str_eqz(e->op, "=") && e->a[1]->kind == FP_BIN && e->a[1]->op.n == 1 &&
                           strchr("+*-", e->a[1]->op.p[0])) {
                    FoP *rl = e->a[1]->a[0], *rr = e->a[1]->a[1];
                    DkStr tl = dk_str_slice(text, rl->s, rl->e), tr = dk_str_slice(text, rr->s, rr->e);
                    char opc = e->a[1]->op.p[0];
                    char note[40];
                    snprintf(note, sizeof note, "compound %d", (int)k);
                    if (dk_str_eq(norm(tl), L)) {
                        DkStr t1 = dk_str(dk_sprintf(a, "%.*s %c= %.*s;", DK_SF(L), opc, DK_SF(tr)));
                        push_variant(&out, with_statement(body, st, &t1, 1), dk_strdup(a, note));
                    } else if (dk_str_eq(norm(tr), L) && opc != '-') {
                        DkStr t1 = dk_str(dk_sprintf(a, "%.*s %c= %.*s;", DK_SF(L), opc, DK_SF(tl)));
                        push_variant(&out, with_statement(body, st, &t1, 1), dk_strdup(a, note));
                    }
                }
            }
        }
        /* s = a + b + c  ->  s = a; s += b; s += c */
        FoP *rhs = NULL;
        DkStr name = {NULL, 0}, head = {NULL, 0};
        if (info->kind == FS_EXPR && e && e->kind == FP_ASSIGN && dk_str_eqz(e->op, "=") && info->expr_at0 &&
            dk_str_eq(text_nosemi, dk_str_slice(text, e->s, e->e))) {
            rhs = e->a[1];
            name = dk_str_slice(text, e->a[0]->s, e->a[0]->e);
            head = dk_str_slice(text, 0, e->a[1]->s);
        } else if (info->kind == FS_DECL && info->init && !info->multi) {
            DkStrVec tw = dk_str_split(info->type, S(""), -1);
            bool fl = tw.n && (dk_str_eqz(tw.v[0], "float") || dk_str_eqz(tw.v[0], "double"));
            dk_vec_free(&tw);
            if (fl && dk_str_eq(text_nosemi, dk_str_slice(text, 0, info->init->e))) {
                rhs = info->init;
                name = info->name;
                head = dk_str_slice(text, 0, info->init->s);
            }
        }
        if (rhs && simple_lvalue(name)) {
            StrVec terms = {0};
            flat_plus(rhs, text, &terms);
            const DkRe *wre = word_re(name);
            bool ok = terms.n >= 2 && terms.n <= 4;
            for (size_t i = 0; ok && i < terms.n; i++)
                if (calls_v(terms.v[i])) ok = false;
            for (size_t i = 0; ok && i < terms.n; i++)
                if (dk_re_search(wre, terms.v[i], 0, DK_END, NULL)) ok = false;
            if (ok) {
                DkStr *nt = DK_NEWN(a, DkStr, terms.n);
                nt[0] = dk_str(dk_sprintf(a, "%.*s%.*s;", DK_SF(head), DK_SF(terms.v[0])));
                for (size_t i = 1; i < terms.n; i++)
                    nt[i] = dk_str(dk_sprintf(a, "%.*s += %.*s;", DK_SF(name), DK_SF(terms.v[i])));
                char note[40];
                snprintf(note, sizeof note, "split %d", (int)k);
                push_variant(&out, with_statement(body, st, nt, terms.n), dk_strdup(a, note));
            }
            dk_vec_free(&terms);
            /* join the following `name += x;` statements */
            size_t j = k + 1;
            StrVec adds = {0};
            DkBuf pat = {0};
            dk_buf_putz(&pat, "^");
            dk_buf_put(&pat, dk_re_escape(a, name));
            dk_buf_putz(&pat, " \\+= (.+);$");
            const DkRe *are = dk_re_try_n(dk_buf_str(&pat), 0);
            dk_buf_free(&pat);
            while (j < stmts.n) {
                DkReMatch m;
                if (!dk_re_match(are, stmts.v[j].text, 0, DK_END, &m)) break;
                dk_vec_push(&adds, dk_re_group(&m, 1));
                j++;
            }
            bool addcalls = false;
            for (size_t i = 0; i < adds.n; i++)
                if (calls_v(adds.v[i])) addcalls = true;
            if (adds.n && !addcalls) {
                DkBuf joined;
                dk_buf_init(&joined, a);
                dk_buf_put(&joined, head);
                dk_buf_put(&joined, dk_str_slice(text, rhs->s, rhs->e));
                for (size_t i = 0; i < adds.n; i++) {
                    dk_buf_putz(&joined, " + ");
                    if (dk_re_search(RE(" [-+] "), adds.v[i], 0, DK_END, NULL)) {
                        dk_buf_putc(&joined, '(');
                        dk_buf_put(&joined, adds.v[i]);
                        dk_buf_putc(&joined, ')');
                    } else {
                        dk_buf_put(&joined, adds.v[i]);
                    }
                }
                dk_buf_putc(&joined, ';');
                DkStr jt = dk_buf_str(&joined);
                DkCzVec merged = with_statement(body, st, &jt, 1);
                i64 last = stmts.v[j - 1].hi;
                i64 lo_add = stmts.v[k + 1].lo, hi_add = last;
                i64 delta = (i64)merged.n - (i64)body->n;
                DkCzVec m2 = {0};
                for (i64 q = 0; q < lo_add + delta && q < (i64)merged.n; q++) dk_vec_push(&m2, merged.v[q]);
                for (i64 q = hi_add + 1 + delta; q < (i64)merged.n; q++)
                    if (q >= 0) dk_vec_push(&m2, merged.v[q]);
                dk_vec_free(&merged);
                char note[40];
                snprintf(note, sizeof note, "join %d", (int)k);
                push_variant(&out, m2, dk_strdup(a, note));
            }
            dk_vec_free(&adds);
        }
        /* a single-use float local inlined into the next statement */
        if (info->kind == FS_DECL && info->init && !info->multi &&
            (dk_str_eqz(info->type, "float") || dk_str_eqz(info->type, "double")) && k + 1 < stmts.n &&
            dk_str_eq(text_nosemi, dk_str_slice(text, 0, info->init->e)) &&
            !calls_v(dk_str_slice(text, info->init->s, info->init->e))) {
            DkStr nm = info->name;
            DkBuf rest;
            dk_buf_init(&rest, a);
            for (size_t q = k + 1; q < stmts.n; q++) {
                if (q > k + 1) dk_buf_putc(&rest, ' ');
                dk_buf_put(&rest, stmts.v[q].text);
            }
            DkStr nxt = stmts.v[k + 1].text;
            const DkRe *wre = word_re(nm);
            size_t count = 0;
            {
                DkReIter it;
                DkReMatch m;
                dk_re_iter_init(&it, wre, dk_buf_str(&rest), 0, DK_END);
                while (dk_re_iter_next(&it, &m)) count++;
            }
            DkStr init_t = dk_str_slice(text, info->init->s, info->init->e);
            bool disjoint = true;
            {
                DkSet *w = dk_ctext_written(nxt), *rd = dk_ctext_read(init_t);
                size_t pos = 0;
                DkStr member;
                while (dk_set_next(w, &pos, &member))
                    if (dk_set_has(rd, member)) disjoint = false;
                dk_set_free(w);
                dk_set_free(rd);
            }
            if (count == 1 && dk_re_search(wre, nxt, 0, DK_END, NULL) && disjoint) {
                DkStr init = dk_ctext_atomic(init_t) ? init_t : dk_str(dk_sprintf(a, "(%.*s)", DK_SF(init_t)));
                InlCtx ic = {init};
                DkStr new_next = dk_re_sub_fn(a, wre, inline_repl, &ic, nxt, 0, NULL);
                DkCzVec b2 = with_statement(body, &stmts.v[k + 1], &new_next, 1);
                DkCzVec b3 = {0};
                for (i64 q = 0; q < st->lo; q++) dk_vec_push(&b3, b2.v[q]);
                for (size_t q = (size_t)st->hi + 1; q < b2.n; q++) dk_vec_push(&b3, b2.v[q]);
                dk_vec_free(&b2);
                char note[40];
                snprintf(note, sizeof note, "inline %d", (int)k);
                push_variant(&out, b3, dk_strdup(a, note));
            }
            dk_buf_free(&rest);
        }
    }
    dk_vec_free(&stmts);
    return out;
}
