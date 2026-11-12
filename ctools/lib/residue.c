// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* residue: what is left of a compared function's difference. Both sides are disassembled (insn_text.h), the
 * reference's whole function read as walls.h reads it, each cut at its first switch table; the instructions are
 * aligned (difflib over the normalised text, every register masked to its class and width) and the aligned
 * instructions whose registers differ give the renames (ours -> the reference's, majority per register). The rest of
 * the difference is classified (operand, frame, schedule, moves, body, call-set, control-flow) and our register values
 * (webs of reaching definitions over cfg_diff's basic blocks) carry the reference's register at their aligned uses.
 *
 * Counters are DkMap {key: n (.i)} in first-seen order; ties of a most-common pick keep that order. A set whose
 * iteration order could reach an output (the reaching-definition sets, the webs' offsets) is held sorted. */
#include "residue.h"

#include "dk/difflib.h"
#include "dk/sort.h"
#include "insn_text.h"
#include "walls.h"

#include <stdio.h>
#include <string.h>

/* ================================================================================================ registers */

/* The registers the module knows, in sorted (alphabetical) order, so a register set iterates in name order
 * The 32-bit register a sub-register belongs to is its token's reg. */
enum { NREGS = 15 };
static const char *const REGS[NREGS] = {"eax",  "ebp",  "ebx",  "ecx",  "edi",  "edx",  "esi",  "xmm0",
                                        "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"};

/* A register token: the 32-bit register it belongs to and WIDTH[token] ("R", "R16", "R8", "X"). */
typedef struct {
    const char *token;
    int reg;
    const char *width;
} RegToken;

static const RegToken TOKENS[] = {
    {"eax", 0, "R"},   {"ax", 0, "R16"},  {"al", 0, "R8"},   {"ah", 0, "R8"},    {"ebx", 2, "R"},   {"bx", 2, "R16"},
    {"bl", 2, "R8"},   {"bh", 2, "R8"},   {"ecx", 3, "R"},   {"cx", 3, "R16"},   {"cl", 3, "R8"},   {"ch", 3, "R8"},
    {"edx", 5, "R"},   {"dx", 5, "R16"},  {"dl", 5, "R8"},   {"dh", 5, "R8"},    {"esi", 6, "R"},   {"si", 6, "R16"},
    {"sil", 6, "R8"},  {"edi", 4, "R"},   {"di", 4, "R16"},  {"dil", 4, "R8"},   {"ebp", 1, "R"},   {"bp", 1, "R16"},
    {"bpl", 1, "R8"},  {"xmm0", 7, "X"},  {"xmm1", 8, "X"},  {"xmm2", 9, "X"},   {"xmm3", 10, "X"}, {"xmm4", 11, "X"},
    {"xmm5", 12, "X"}, {"xmm6", 13, "X"}, {"xmm7", 14, "X"},
};

static const RegToken *token_of(DkStr t) {
    for (size_t i = 0; i < DK_ARRAY_LEN(TOKENS); i++)
        if (dk_str_eqz(t, TOKENS[i].token)) return &TOKENS[i];
    return NULL;
}

/* WIDTH[token]: a token REG_RE matches that the table lacks is a KeyError (never produced by a decoded instruction). */
static const RegToken *token_need(DkStr t) {
    const RegToken *k = token_of(t);
    if (!k) dk_panic(__FILE__, __LINE__, "KeyError: '%.*s'", DK_SF(t));
    return k;
}

#define REG_PAT "\\b(e?[abcd]x|[abcd][lh]|e?[sd]il?|e?bpl?|xmm[0-7])\\b"
#define NUMBER_PAT "(?<![*\\w])(0x[0-9a-f]+|\\d+)\\b"
#define ESP_SLOT_PAT "\\[esp \\+ [^\\]]*\\]"
#define MEM_PAT "(byte|word|dword|qword|xmmword) ptr \\[([^\\]]*)\\]"

static const char *const CLASSES[] = {"register", "call-set", "control-flow", "body", "moves", "schedule", "operand", "frame"};
static const char *const MOVES[] = {"mov",    "movd",   "movq",   "movss",  "movsd",  "movaps", "movups",
                                    "movapd", "movdqa", "movdqu", "lea",    "push",   "pop",    "xchg"};

static bool in_list(const char *s, const char *const *list, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(s, list[i]) == 0) return true;
    return false;
}

static DkArena *A(void) { return dk_arena(); }

/* reg_tokens(text): the 32-bit register index and the width class of each register an instruction names, in order. */
typedef struct {
    int reg;
    const char *width;
} RegUse;
typedef DK_VEC(RegUse) RegUseVec;

static RegUseVec reg_tokens(DkStr text) {
    RegUseVec out = {0};
    DkReIter it;
    DkReMatch m;
    dk_re_iter_init(&it, dk_re(REG_PAT, 0), text, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) {
        const RegToken *k = token_need(dk_re_group(&m, 1));
        dk_vec_push(&out, ((RegUse){k->reg, k->width}));
    }
    return out;
}

/* ================================================================================================== counters */

static void counter_add(DkMap *c, DkStr key, i64 n) { dk_map_put(c, key, NULL)->i += n; }

static i64 counter_get(const DkMap *c, DkStr key) {
    const DkVal *v = dk_map_get(c, key);
    return v ? v->i : 0;
}

static i64 counter_total(const DkMap *c) {
    i64 t = 0;
    DkMapIter it = {0};
    while (dk_map_next(c, &it)) t += it.val->i;
    return t;
}

/* ================================================================================================ small text */

static const char *mnemonic_of(DkStr text) {
    i64 sp = dk_str_findc(text, ' ');
    return dk_cz(A(), sp < 0 ? text : dk_strn(text.p, (size_t)sp));
}

/* ========================================================================================== text of a shape */

static void sub_width(void *ctx, const DkReMatch *m, DkBuf *out) {
    DK_UNUSED(ctx);
    dk_buf_putz(out, token_need(dk_re_group(m, 1))->width);
}

static void sub_r(void *ctx, const DkReMatch *m, DkBuf *out) {
    DK_UNUSED(ctx);
    DK_UNUSED(m);
    dk_buf_putc(out, 'R');
}

/* shape(text, relocated=None): normalised text with each register masked to its class and width. REL is 0 (None),
 * 1 ("end": the relocated word ends the instruction) or 2 ("mid": it is inside): the instruction holds one of our
 * relocations, whose word is still the addend where the reference's holds an address, so that number is masked as
 * dk_insn_normalise masks the reference's addresses. */
static DkStr shape(DkStr text, int rel) {
    DkArena *a = A();
    text = dk_insn_normalise(a, text, false);
    if (rel) {
        DkReMatch m;
        bool tail = dk_re_search(dk_re("\\], (0x[0-9a-f]+|\\d+)$", 0), text, 0, DK_END, &m);
        if (rel == 1 && tail) {
            text = dk_str_concat(a, dk_str_slice(text, 0, dk_re_start(&m, 1)), DK_S("IMM"));
        } else if (dk_str_findc(text, '[') >= 0) {
            i64 i = dk_str_findc(text, '['), j = dk_str_find(text, DK_S("]"), 0, DK_END);
            if (j < 0) dk_panic(__FILE__, __LINE__, "ValueError: substring not found");
            DkStr inside = dk_re_sub(a, dk_re(NUMBER_PAT, 0), DK_S("IMM"), dk_str_slice(text, i, j), 0);
            if (!dk_str_contains(inside, DK_S("IMM"))) inside = dk_str_concat(a, inside, DK_S(" + IMM"));
            DkStr parts[3] = {dk_str_slice(text, 0, i), inside, dk_str_slice(text, j, DK_END)};
            text = dk_str_join(a, DK_S(""), parts, 3);
        } else {
            text = dk_re_sub(a, dk_re("(0x[0-9a-f]+|\\d+)$", 0), DK_S("IMM"), text, 0);
        }
    }
    return dk_re_sub_fn(a, dk_re(REG_PAT, 0), sub_width, NULL, text, 0, NULL);
}

/* ==================================================================================================== rows */

/* One instruction row: (offset, size, text, relocated) of match.disassemble, with its shape. */
typedef struct {
    u32 off, size;
    DkStr text;
    int rel; /* 0 None, 1 "end", 2 "mid" */
    DkStr shape;
    DkStr numberless; /* lazily: NUMBER_RE.sub("N", shape.replace("IMM", "N")) */
    const char *mn;
} Row;
typedef DK_VEC(Row *) RowVec;
typedef struct {
    const Row *o, *g;
} RowPair;
typedef DK_VEC(RowPair) RowPairVec;

/* The rows of code up to its first switch table (dk_wall_table_start; ours: the compared result, whose tables are
 * relocations, NULL for the reference's bytes), the data tail dropped. */
static RowVec instructions(DkStr code, u32 base, const DkReloc *relocs, size_t n_relocs, const DkResult *ours) {
    DkArena *a = A();
    DkInsns ins = dk_wall_disasm(code, base);
    i64 cut;
    bool has_cut = dk_wall_table_start(&ins, base, code.n, ours, &cut);
    dk_wall_insns_free(&ins);
    if (has_cut) {
        if (cut < 0) cut = 0;
        if ((size_t)cut < code.n) code.n = (size_t)cut;
        DkReloc *kept = DK_NEWN(a, DkReloc, n_relocs + 1);
        size_t k = 0;
        for (size_t i = 0; i < n_relocs; i++)
            if ((i64)relocs[i].offset < cut) kept[k++] = relocs[i];
        relocs = kept;
        n_relocs = k;
    }
    DkInsnTextVec rows = dk_insn_disassemble(a, code, base, relocs, n_relocs);
    RowVec out = {0};
    for (size_t i = 0; i < rows.n; i++) {
        const DkInsnText *t = &rows.v[i];
        if (t->text.n && t->text.p[0] == '(') continue;
        bool any = false, end = false;
        for (size_t k = 0; k < n_relocs; k++) {
            u32 ro = relocs[k].offset;
            if (t->offset <= ro && ro < t->offset + t->size) {
                any = true;
                if (ro + 4 == t->offset + t->size) end = true;
            }
        }
        Row *r = DK_NEW(a, Row);
        r->off = t->offset;
        r->size = t->size;
        r->text = t->text;
        r->rel = any ? (end ? 1 : 2) : 0;
        r->mn = mnemonic_of(t->text);
        dk_vec_push(&out, r);
    }
    dk_vec_free(&rows);
    return out;
}

/* strip_padding(rows): trailing int3 and nop rows dropped. */
static void strip_padding(RowVec *rows) {
    while (rows->n && (strcmp(rows->v[rows->n - 1]->mn, "int3") == 0 || strcmp(rows->v[rows->n - 1]->mn, "nop") == 0))
        rows->n--;
}

static const char *cstr(DkStr s) { return dk_cz(A(), s); }

/* ====================================================================================== register values */

/* access_of(ins): (registers read, registers written) as masks of REGS: a write of a sub-register is also a read; a call
 * writes the scratch registers; ret reads eax; `xor r, r` reads nothing. Two empty sets when
 * the register access is not available (no detail, a skipdata byte). */
static void access_of(const cs_insn *ins, u32 *reads, u32 *writes) {
    *reads = *writes = 0;
    DkDis *d = dk_dis(DK_DIS_X86_32, DK_DIS_DETAIL);
    DkDisRegs acc;
    if (!ins->detail || !dk_dis_regs_access(d, ins, &acc)) return;
    for (unsigned i = 0; i < acc.n_read; i++) {
        const char *name = dk_dis_reg_name(d, acc.read[i]);
        const RegToken *k = name ? token_of(dk_str(name)) : NULL;
        if (k) *reads |= 1u << k->reg;
    }
    for (unsigned i = 0; i < acc.n_write; i++) {
        const char *name = dk_dis_reg_name(d, acc.write[i]);
        const RegToken *k = name ? token_of(dk_str(name)) : NULL;
        if (!k) continue;
        *writes |= 1u << k->reg;
        if (strcmp(k->width, "R16") == 0 || strcmp(k->width, "R8") == 0) *reads |= 1u << k->reg;
    }
    static const char *const ZERO_IDIOMS[] = {"xor", "sub", "pxor", "xorps", "xorpd"};
    if (in_list(ins->mnemonic, ZERO_IDIOMS, DK_ARRAY_LEN(ZERO_IDIOMS))) {
        DkStrVec ops = dk_str_split(dk_str(ins->op_str), DK_S(", "), -1);
        if (ops.n == 2 && dk_str_eq(ops.v[0], ops.v[1])) {
            const RegToken *k = token_of(ops.v[0]);
            if (k) *reads &= ~(1u << k->reg);
        }
        dk_vec_free(&ops);
    }
    if (strcmp(ins->mnemonic, "call") == 0) *writes |= (1u << 0) | (1u << 3) | (1u << 5); /* eax, ecx, edx */
    if (strcmp(ins->mnemonic, "ret") == 0 || strcmp(ins->mnemonic, "retn") == 0) *reads |= 1u << 0;
}

/* frame_setup(side, ins): the frame code VC8 adds itself: the exception registration (fs:[0]) and the /GS cookie.
 * *raised: a relocation without a symbol. */
static bool frame_setup(const CfgDiffSide *side, const cs_insn *ins, bool *raised) {
    if (strstr(ins->op_str, "fs:")) return true;
    if (!side->ours) return false;
    DkPtrVec rel = cfg_diff_side_reloc_in(side, (u32)(ins->address - side->base), ins->size);
    bool found = false;
    for (size_t i = 0; i < rel.n && !found; i++) {
        const DkReloc *r = rel.v[i];
        if (!r->symbol) {
            *raised = true;
            break;
        }
        found = strstr(r->symbol, "security_cookie") != NULL;
    }
    dk_vec_free(&rel);
    return found;
}

/* One instruction of the decoded side. */
typedef struct {
    u32 off, reads, writes;
    const cs_insn *ins;
    i32 block;
} Acc;

/* A node of the union-find: a definition (offset, register) or the entry value of a register (off = UINT32_MAX). */
typedef struct {
    u32 off;
    int reg;
} Node;
typedef DK_VEC(Node) NodeVec;

typedef struct {
    DkI32Vec parent;
    NodeVec nodes;
} Dsu;

static u32 dsu_find(Dsu *d, u32 x) {
    while ((u32)d->parent.v[x] != x) {
        d->parent.v[x] = d->parent.v[(u32)d->parent.v[x]];
        x = (u32)d->parent.v[x];
    }
    return x;
}

static void dsu_union(Dsu *d, u32 a, u32 b) {
    u32 ra = dsu_find(d, a), rb = dsu_find(d, b);
    if (ra != rb) d->parent.v[rb] = (i32)ra;
}

/* A set of definitions (node ids), sorted. */
static void set_add_all(DkU32Vec *dst, const DkU32Vec *src) {
    DkU32Vec out = {0};
    size_t i = 0, j = 0;
    while (i < dst->n || j < src->n) {
        u32 x;
        if (j >= src->n || (i < dst->n && dst->v[i] < src->v[j])) x = dst->v[i++];
        else if (i >= dst->n || src->v[j] < dst->v[i]) x = src->v[j++];
        else { x = dst->v[i]; i++; j++; }
        dk_vec_push(&out, x);
    }
    dk_vec_free(dst);
    *dst = out;
}

static bool set_equal(const DkU32Vec *x, const DkU32Vec *y) {
    return x->n == y->n && (x->n == 0 || memcmp(x->v, y->v, x->n * sizeof(u32)) == 0);
}

static void set_copy(DkU32Vec *dst, const DkU32Vec *src) {
    dk_vec_clear(dst);
    if (src->n) dk_vec_extend(dst, src->v, src->n);
}

typedef i32 GenRow[NREGS];
typedef DkU32Vec RegSets[NREGS];

/* A web in construction. */
typedef struct {
    bool used, entry;
    int reg;
    DkU32Vec defs, uses;
} Web;

static int cmp_u32(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    return dk_cmp_u64(*(const u32 *)x, *(const u32 *)y);
}

static void sort_unique(DkU32Vec *v) {
    dk_sort(v->v, v->n, sizeof(u32), cmp_u32, NULL, false);
    size_t k = 0;
    for (size_t i = 0; i < v->n; i++)
        if (i == 0 || v->v[i] != v->v[i - 1]) v->v[k++] = v->v[i];
    v->n = k;
}

static int cmp_value(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    const ResidueValue *a = *(ResidueValue *const *)x, *b = *(ResidueValue *const *)y;
    int c = dk_cmp_u64(a->refs.v[0], b->refs.v[0]);
    return c ? c : strcmp(a->reg, b->reg);
}

static DkStr index_key(u32 off, const char *reg) {
    char buf[48];
    int n = snprintf(buf, sizeof buf, "%u\t%s", off, reg);
    return dk_str_dup(A(), dk_strn(buf, (size_t)n));
}

/* The value index of (offset, register), -1 when there is none. */
static i64 index_get(const DkMap *index, u32 off, const char *reg) {
    char buf[48];
    int n = snprintf(buf, sizeof buf, "%u\t%s", off, reg);
    const DkVal *v = dk_map_get(index, dk_strn(buf, (size_t)n));
    return v ? v->i : -1;
}

bool residue_values(const CfgDiffSide *side, ResidueValueVec *values, DkMap **index_out) {
    DkArena *a = A();
    *index_out = dk_map_new();
    memset(values, 0, sizeof *values);
    size_t nb = side->blocks.n;
    if (!nb) return true;

    /* acc / insn / block_of: per offset (a later block's instruction at one offset replaces the earlier, in place) */
    DkIMap *accmap = dk_imap_new();
    DK_VEC(Acc *) accs = {0};
    for (size_t bi = 0; bi < nb; bi++) {
        const CfgDiffBlock *b = side->blocks.v[bi];
        for (size_t k = 0; k < b->insns.n; k++) {
            const cs_insn *ins = b->insns.v[k];
            u32 o = (u32)(ins->address - side->base);
            bool created;
            DkVal *slot = dk_imap_put(accmap, o, &created);
            Acc *ac;
            if (created) {
                ac = DK_NEW(a, Acc);
                slot->p = ac;
                dk_vec_push(&accs, ac);
            } else {
                ac = slot->p;
            }
            ac->off = o;
            ac->ins = ins;
            ac->block = b->idx;
            access_of(ins, &ac->reads, &ac->writes);
        }
    }
    u32 regmask = 0;
    for (size_t i = 0; i < accs.n; i++) regmask |= accs.v[i]->reads | accs.v[i]->writes;

    /* nodes: entry values first (sorted registers), then every definition in acc order */
    Dsu dsu = {0};
    DkIMap *def_id = dk_imap_new(); /* (off << 4 | reg) -> node */
    i32 entry_id[NREGS];
    for (int r = 0; r < NREGS; r++) {
        entry_id[r] = -1;
        if (regmask & (1u << r)) {
            entry_id[r] = (i32)dsu.nodes.n;
            dk_vec_push(&dsu.nodes, ((Node){UINT32_MAX, r}));
            dk_vec_push(&dsu.parent, (i32)dsu.parent.n);
        }
    }
    for (size_t i = 0; i < accs.n; i++)
        for (int r = 0; r < NREGS; r++)
            if (accs.v[i]->writes & (1u << r)) {
                dk_imap_put(def_id, ((u64)accs.v[i]->off << 4) | (u64)r, NULL)->i = (i64)dsu.nodes.n;
                dk_vec_push(&dsu.nodes, ((Node){accs.v[i]->off, r}));
                dk_vec_push(&dsu.parent, (i32)dsu.parent.n);
            }
#define DEF(o, r) ((u32)dk_imap_get(def_id, ((u64)(o) << 4) | (u64)(r))->i)

    /* block index by idx, the first block's idx */
    i32 maxidx = 0;
    for (size_t bi = 0; bi < nb; bi++)
        if (side->blocks.v[bi]->idx > maxidx) maxidx = side->blocks.v[bi]->idx;
    size_t nslots = (size_t)maxidx + 1;
    i32 *pos_of = DK_NEWN(a, i32, nslots);
    for (size_t i = 0; i < nslots; i++) pos_of[i] = -1;
    for (size_t bi = 0; bi < nb; bi++)
        if (side->blocks.v[bi]->idx >= 0) pos_of[side->blocks.v[bi]->idx] = (i32)bi;
    i32 first = side->blocks.v[0]->idx;

    /* gen: each block's last definition per register */
    GenRow *gen = DK_NEWN(a, GenRow, nb);
    for (size_t bi = 0; bi < nb; bi++) {
        for (int r = 0; r < NREGS; r++) gen[bi][r] = -1;
        const CfgDiffBlock *b = side->blocks.v[bi];
        for (size_t k = 0; k < b->insns.n; k++) {
            u32 o = (u32)(b->insns.v[k]->address - side->base);
            const Acc *ac = dk_imap_get(accmap, o)->p;
            for (int r = 0; r < NREGS; r++)
                if (ac->writes & (1u << r)) gen[bi][r] = (i32)DEF(o, r);
        }
    }

    /* reaching definitions to a fixed point */
    RegSets *in_defs = DK_NEWN(a, RegSets, nb);
    RegSets *out_defs = DK_NEWN(a, RegSets, nb);
    bool *has_out = DK_NEWN(a, bool, nb);
    bool changed = true;
    int rounds = 0;
    while (changed && rounds < 200) {
        changed = false;
        rounds++;
        for (size_t bi = 0; bi < nb; bi++) {
            const CfgDiffBlock *b = side->blocks.v[bi];
            DkU32Vec incoming[NREGS];
            memset(incoming, 0, sizeof incoming);
            if (b->idx == first)
                for (int r = 0; r < NREGS; r++)
                    if (entry_id[r] >= 0) dk_vec_push(&incoming[r], (u32)entry_id[r]);
            for (size_t pi = 0; pi < b->preds.n; pi++) {
                i32 p = b->preds.v[pi];
                if (p < 0 || (size_t)p >= nslots || pos_of[p] < 0 || !has_out[pos_of[p]]) continue;
                for (int r = 0; r < NREGS; r++)
                    if (out_defs[pos_of[p]][r].n) set_add_all(&incoming[r], &out_defs[pos_of[p]][r]);
            }
            for (int r = 0; r < NREGS; r++) {
                dk_vec_free(&in_defs[bi][r]);
                in_defs[bi][r] = incoming[r];
            }
            DkU32Vec new_out[NREGS];
            memset(new_out, 0, sizeof new_out);
            for (int r = 0; r < NREGS; r++) {
                if (gen[bi][r] >= 0) dk_vec_push(&new_out[r], (u32)gen[bi][r]);
                else set_copy(&new_out[r], &incoming[r]);
            }
            bool same = has_out[bi];
            for (int r = 0; r < NREGS && same; r++) same = set_equal(&new_out[r], &out_defs[bi][r]);
            if (!same) {
                for (int r = 0; r < NREGS; r++) {
                    dk_vec_free(&out_defs[bi][r]);
                    out_defs[bi][r] = new_out[r];
                }
                has_out[bi] = true;
                changed = true;
            } else {
                for (int r = 0; r < NREGS; r++) dk_vec_free(&new_out[r]);
            }
        }
    }

    /* the uses: the definitions that reach one use join one web */
    DkIMap *uses = dk_imap_new(); /* (off << 4 | reg) -> head node */
    for (size_t bi = 0; bi < nb; bi++) {
        const CfgDiffBlock *b = side->blocks.v[bi];
        DkU32Vec cur[NREGS];
        memset(cur, 0, sizeof cur);
        for (int r = 0; r < NREGS; r++) set_copy(&cur[r], &in_defs[bi][r]);
        for (size_t k = 0; k < b->insns.n; k++) {
            u32 o = (u32)(b->insns.v[k]->address - side->base);
            const Acc *ac = dk_imap_get(accmap, o)->p;
            for (int r = 0; r < NREGS; r++) {
                if (!(ac->reads & (1u << r)) || !cur[r].n) continue;
                u32 head = cur[r].v[0]; /* py: set order (any member: the union is the same) */
                for (size_t d = 0; d < cur[r].n; d++) dsu_union(&dsu, head, cur[r].v[d]);
                dk_imap_put(uses, ((u64)o << 4) | (u64)r, NULL)->i = head;
                if (ac->writes & (1u << r)) dsu_union(&dsu, DEF(o, r), head);
            }
            for (int r = 0; r < NREGS; r++)
                if (ac->writes & (1u << r)) {
                    dk_vec_clear(&cur[r]);
                    dk_vec_push(&cur[r], DEF(o, r));
                }
        }
        for (int r = 0; r < NREGS; r++) dk_vec_free(&cur[r]);
    }

    /* the webs, in node order */
    Web *webs = DK_NEWN(a, Web, dsu.nodes.n);
    for (size_t d = 0; d < dsu.nodes.n; d++) {
        Web *w = &webs[dsu_find(&dsu, (u32)d)];
        if (!w->used) {
            w->used = true;
            w->reg = dsu.nodes.v[d].reg;
        }
        if (dsu.nodes.v[d].off == UINT32_MAX) w->entry = true;
        else dk_vec_push(&w->defs, dsu.nodes.v[d].off);
    }
    DkIMapIter ui = {0};
    while (dk_imap_next(uses, &ui)) dk_vec_push(&webs[dsu_find(&dsu, (u32)ui.val->i)].uses, (u32)(ui.key >> 4));

    bool raised = false;
    for (size_t d = 0; d < dsu.nodes.n && !raised; d++) {
        Web *w = &webs[d];
        if (!w->used) continue;
        sort_unique(&w->defs);
        sort_unique(&w->uses);
        DkU32Vec refs = {0};
        dk_vec_extend(&refs, w->defs.v, w->defs.n);
        dk_vec_extend(&refs, w->uses.v, w->uses.n);
        sort_unique(&refs);
        if (!refs.n) continue;
        DkU32Vec blocks = {0};
        bool only_save_ops = true;
        for (size_t i = 0; i < refs.n; i++) {
            const Acc *ac = dk_imap_get(accmap, refs.v[i])->p;
            dk_vec_push(&blocks, (u32)ac->block);
            if (strcmp(ac->ins->mnemonic, "push") != 0 && strcmp(ac->ins->mnemonic, "pop") != 0) only_save_ops = false;
        }
        sort_unique(&blocks);
        const char *kind;
        bool callee_saved = w->reg == 1 || w->reg == 2 || w->reg == 4 || w->reg == 6; /* ebp ebx edi esi */
        if (callee_saved && only_save_ops) {
            kind = "save";
        } else {
            bool frame = false;
            for (size_t i = 0; i < refs.n && !frame && !raised; i++) {
                const Acc *ac = dk_imap_get(accmap, refs.v[i])->p;
                frame = frame_setup(side, ac->ins, &raised);
            }
            if (raised) break;
            kind = frame ? "frame" : (blocks.n <= 1 && !w->entry) ? "local" : "cross";
        }
        ResidueValue *v = DK_NEW(a, ResidueValue);
        v->reg = REGS[w->reg];
        v->kind = kind;
        v->defs = w->defs;
        v->uses = w->uses;
        v->refs = refs;
        v->blocks = blocks;
        v->entry = w->entry;
        v->game = dk_map_new();
        dk_vec_push(values, v);
    }
    if (raised) {
        memset(values, 0, sizeof *values);
        return false;
    }
    dk_sort(values->v, values->n, sizeof(ResidueValue *), cmp_value, NULL, false);
    for (size_t k = 0; k < values->n; k++)
        for (size_t i = 0; i < values->v[k]->refs.n; i++)
            dk_map_put(*index_out, index_key(values->v[k]->refs.v[i], values->v[k]->reg), NULL)->i = (i64)k;
    return true;
#undef DEF
}

/* ============================================================================================== structure */

/* _frame(insns): the `sub esp, N` of the first 12 rows, 0 when none. */
static i64 frame_of(const RowVec *rows) {
    const DkRe *re = dk_re("sub esp, (0x[0-9a-f]+|\\d+)$", 0);
    for (size_t i = 0; i < rows->n && i < 12; i++) {
        DkReMatch m;
        if (dk_re_match(re, rows->v[i]->text, 0, DK_END, &m)) {
            i64 v = 0;
            if (!dk_parse_int(dk_re_group(&m, 1), 0, &v, NULL))
                dk_panic(__FILE__, __LINE__, "ValueError: invalid literal for int() with base 0: '%.*s'",
                          DK_SF(dk_re_group(&m, 1)));
            return v;
        }
    }
    return 0;
}

/* The counter of the memory operands read (registers masked; esp slots, lea and stores left out). */
static DkMap *loads_of(const RowVec *rows) {
    DkArena *a = A();
    DkMap *c = dk_map_new();
    const DkRe *mem = dk_re(MEM_PAT, 0);
    for (size_t i = 0; i < rows->n; i++) {
        const Row *t = rows->v[i];
        DkReMatch m;
        if (!dk_re_search(mem, t->text, 0, DK_END, &m)) continue;
        DkStr inner = dk_re_group(&m, 2);
        if (dk_str_contains(inner, DK_S("esp"))) continue;
        const char *mn = t->mn;
        if (strcmp(mn, "lea") == 0 || strcmp(mn, "push") == 0 || strcmp(mn, "call") == 0 || strcmp(mn, "jmp") == 0)
            continue;
        if (strncmp(mn, "mov", 3) == 0) {
            i64 comma = dk_str_findc(t->text, ',');
            if (comma >= 0 && dk_re_start(&m, 0) < comma) continue; /* a store */
        }
        DkStr operand = dk_insn_normalise(a, inner, false);
        if (t->rel) operand = dk_re_sub(a, dk_re(NUMBER_PAT, 0), DK_S("IMM"), operand, 0);
        operand = dk_re_sub_fn(a, dk_re(REG_PAT, 0), sub_r, NULL, operand, 0, NULL);
        counter_add(c, operand, 1);
    }
    return c;
}

static bool x87(const Row *t) { return t->text.n && t->text.p[0] == 'f'; }

/* The first findings kinds, unique in first-seen order (sorted(set(kinds), key=kinds.index)). */
static DkCzVec unique_kinds(const CfgDiffAnalysis *an) {
    DkCzVec out = {0};
    for (size_t i = 0; i < an->findings.n; i++) {
        const char *k = an->findings.v[i].kind;
        bool seen = false;
        for (size_t j = 0; j < out.n && !seen; j++) seen = strcmp(out.v[j], k) == 0;
        if (!seen) dk_vec_push(&out, (char *)k);
    }
    return out;
}

static const char *join_cz(const DkCzVec *v, const char *sep) {
    DkBuf b;
    dk_buf_init(&b, A());
    for (size_t i = 0; i < v->n; i++) {
        if (i) dk_buf_putz(&b, sep);
        dk_buf_putz(&b, v->v[i]);
    }
    return dk_buf_cz(&b);
}

static const char *row_text(const Row *r, const char *who) {
    return dk_sprintf(A(), "%s +%03X %s", who, r->off, cstr(r->text));
}

/* structure(out, ours, game, analysis, info): the differences that are not register choices, as lines. ANALYSIS NULL:
 * None (cfg_diff failed). */
static DkCzVec structure(const DkMap *classes, const RowVec *ours, const RowVec *game, const CfgDiffAnalysis *an,
                          const DkWallInfo *info) {
    DkArena *a = A();
    DkCzVec lines = {0};
    i64 size_o = 0, size_g = 0;
    for (size_t i = 0; i < ours->n; i++) size_o += ours->v[i]->size;
    for (size_t i = 0; i < game->n; i++) size_g += game->v[i]->size;
    if (an) {
        if (an->size_ours) size_o = an->size_ours;
        if (an->size_game) size_g = an->size_game;
    }
    if (size_o != size_g || ours->n != game->n)
        dk_vec_push(&lines, (char *)dk_sprintf(a, "size: ours %lld bytes / %zu instructions, the reference's %lld bytes / %zu "
                                                    "instructions", (long long)size_o, ours->n, (long long)size_g, game->n));
    if (an) {
        i64 bo = an->blocks_ours, bg = an->blocks_game, m = an->matched;
        i64 lowest = (bo ? bo : 0) < (bg ? bg : 0) ? (bo ? bo : 0) : (bg ? bg : 0);
        if (bo != bg || m < lowest || an->findings.n) {
            DkCzVec kinds = unique_kinds(an);
            dk_vec_push(&lines, (char *)dk_sprintf(a, "blocks: ours %lld, the reference's %lld, %lld mapped%s%s (cfg_diff)",
                                                     (long long)bo, (long long)bg, (long long)m,
                                                     kinds.n ? "; " : "", kinds.n ? join_cz(&kinds, ", ") : ""));
        }
    }
    if (info && (info->calls_only_ours.n || info->calls_only_reference.n))
        dk_vec_push(&lines, (char *)dk_sprintf(a, "call set: calls only ours: %s; only the reference's: %s",
                                                 info->calls_only_ours.n ? join_cz(&info->calls_only_ours, ", ") : "-",
                                                 info->calls_only_reference.n ? join_cz(&info->calls_only_reference, ", ") : "-"));
    i64 fo = frame_of(ours), fg = frame_of(game);
    if (fo != fg)
        dk_vec_push(&lines, (char *)dk_sprintf(a, "frame: ours sub esp, 0x%llX; the reference's sub esp, 0x%llX",
                                                 (unsigned long long)fo, (unsigned long long)fg));
    size_t xo = 0, xg = 0;
    for (size_t i = 0; i < ours->n; i++) xo += x87(ours->v[i]);
    for (size_t i = 0; i < game->n; i++) xg += x87(game->v[i]);
    if (xo != xg)
        dk_vec_push(&lines, (char *)dk_sprintf(a, "x87: ours %zu x87 instruction(s), the reference's %zu (a copy through the "
                                                    "FPU stack on one side)", xo, xg));
    DkMap *lo = loads_of(ours), *lg = loads_of(game);
    DkCzVec parts_g = {0}, parts_o = {0};
    DkMapIter it = {0};
    while (dk_map_next(lg, &it)) {
        i64 d = it.val->i - counter_get(lo, it.key);
        if (d > 0 && parts_g.n < 2)
            dk_vec_push(&parts_g, (char *)dk_sprintf(a, "[%.*s] %lld in the reference, %lld in ours", DK_SF(it.key),
                                                       (long long)it.val->i, (long long)counter_get(lo, it.key)));
    }
    memset(&it, 0, sizeof it);
    while (dk_map_next(lo, &it)) {
        i64 d = it.val->i - counter_get(lg, it.key);
        if (d > 0 && parts_o.n < 2)
            dk_vec_push(&parts_o, (char *)dk_sprintf(a, "[%.*s] %lld in the reference, %lld in ours", DK_SF(it.key),
                                                       (long long)counter_get(lg, it.key), (long long)it.val->i));
    }
    if (parts_g.n || parts_o.n) {
        for (size_t i = 0; i < parts_o.n; i++) dk_vec_push(&parts_g, parts_o.v[i]);
        dk_vec_push(&lines, (char *)dk_sprintf(a, "loads: %s (a value loaded again on one side and kept in a register on "
                                                    "the other: CSE or a reload, decided before colouring)",
                                                 join_cz(&parts_g, "; ")));
    }
    static const char *const KS[] = {"schedule", "body", "moves", "operand"};
    for (size_t i = 0; i < DK_ARRAY_LEN(KS); i++) {
        const DkVal *v = dk_map_get(classes, dk_str(KS[i]));
        if (v) dk_vec_push(&lines, (char *)dk_sprintf(a, "%s: %s", KS[i], (const char *)v->p));
    }
    return lines;
}

/* ================================================================================================= compare */

static DkStr numberless_of(Row *r) {
    if (!r->numberless.p) {
        DkArena *a = A();
        r->numberless = dk_re_sub(a, dk_re(NUMBER_PAT, 0), DK_S("N"), dk_str_replace(a, r->shape, DK_S("IMM"), DK_S("N"), -1), 0);
    }
    return r->numberless;
}

static DkStr strip_esp(DkStr s) { return dk_re_sub(A(), dk_re(ESP_SLOT_PAT, 0), DK_S("[esp]"), s, 0); }

typedef struct {
    RowVec *ours, *game;
    const DkMap *vindex;
    ResidueValueVec *vals;
    DkMap *pairs; /* "ours\tgame" -> n */
} Pairing;

/* pair_regs(i, j): pairs our registers with the reference's at aligned instructions of one shape (numbers aside), of the
 * same class and width at each position; true when a register differs. */
static bool pair_regs(Pairing *p, size_t i, size_t j) {
    Row *o = p->ours->v[i], *g = p->game->v[j];
    if (!dk_str_eq(numberless_of(o), numberless_of(g))) return false;
    RegUseVec ro = reg_tokens(o->text), rg = reg_tokens(g->text);
    bool ok = ro.n == rg.n;
    for (size_t k = 0; ok && k < ro.n; k++) ok = strcmp(ro.v[k].width, rg.v[k].width) == 0;
    if (!ok) {
        dk_vec_free(&ro);
        dk_vec_free(&rg);
        return false;
    }
    bool differ = false;
    for (size_t k = 0; k < ro.n; k++) {
        const char *x = REGS[ro.v[k].reg], *y = REGS[rg.v[k].reg];
        char key[32];
        int n = snprintf(key, sizeof key, "%s\t%s", x, y);
        counter_add(p->pairs, dk_strn(key, (size_t)n), 1);
        i64 kv = index_get(p->vindex, o->off, x);
        if (kv >= 0) {
            ResidueValue *v = p->vals->v[kv];
            counter_add(v->game, dk_str(y), 1);
            v->renamed += ro.v[k].reg != rg.v[k].reg;
        }
        differ = differ || ro.v[k].reg != rg.v[k].reg;
    }
    dk_vec_free(&ro);
    dk_vec_free(&rg);
    return differ;
}

/* Counter(a) & Counter(b) keyed by text: the multiset intersection. */
static DkMap *counter_of_shapes(const RowVec *rows, bool esp) {
    DkMap *c = dk_map_new();
    for (size_t i = 0; i < rows->n; i++) counter_add(c, esp ? strip_esp(rows->v[i]->shape) : rows->v[i]->shape, 1);
    return c;
}

static DkMap *counter_and(const DkMap *x, const DkMap *y) {
    DkMap *out = dk_map_new();
    DkMapIter it = {0};
    while (dk_map_next(x, &it)) {
        i64 n = counter_get(y, it.key);
        if (n > it.val->i) n = it.val->i;
        if (n > 0) counter_add(out, it.key, n);
    }
    return out;
}

static DkMap *counter_copy(const DkMap *c) {
    DkMap *out = dk_map_new();
    DkMapIter it = {0};
    while (dk_map_next(c, &it)) counter_add(out, it.key, it.val->i);
    return out;
}

static void put_class(DkMap *classes, const char *name, const char *text) {
    dk_map_put(classes, dk_str(name), NULL)->p = (void *)text;
}

static const char *cz_or(const DkCzVec *v, const char *dflt) { return v->n ? join_cz(v, ", ") : dflt; }

/* The mapping entries of a Counter-per-register table. */
static ResidueMapping *mapping_of(const DkMap *c) {
    ResidueMapping *m = DK_NEW(A(), ResidueMapping);
    DkStr best;
    i64 n;
    residue_most_common(c, &best, &n);
    m->game = cstr(best);
    m->count = n;
    m->total = counter_total(c);
    m->others = counter_copy(c);
    return m;
}

ResidueReport *residue_compare(const DkResult *result, const DkImage *image, const char *target) {
    DkArena *a = A();
    ResidueReport *out = DK_NEW(a, ResidueReport);
    out->status = dk_status_name(result->status);
    out->classes = dk_map_new();
    out->mapping = dk_map_new();
    out->cross_mapping = dk_map_new();
    if (result->status != DK_DIFF && result->status != DK_SIZE) {
        out->verdict = dk_sprintf(a, "none (%s)", out->status);
        return out;
    }
    if (!result->theirs_va) {
        out->verdict = "none (no reference address)";
        return out;
    }
    u32 address = result->theirs_va;
    const DkFunc *fn = &result->ours;
    DkStr game_bytes = dk_wall_reference_window(result, image);
    RowVec ours = instructions(fn->code, address, fn->relocs, fn->n_relocs, result);
    strip_padding(&ours);
    RowVec game = instructions(game_bytes, address, NULL, 0, NULL);
    strip_padding(&game);
    out->insns_ours = (i64)ours.n;
    out->insns_game = (i64)game.n;

    const char *aerr = NULL; /* the residue verdict never fails the trace */
    CfgDiffAnalysis *an = cfg_diff_analyse(result, image, target, CFG_DIFF_NONE, &aerr);
    ResidueValueVec vals = {0};
    DkMap *vindex = dk_map_new();
    if (an && an->ours) {
        if (!residue_values(an->ours, &vals, &vindex)) {
            memset(&vals, 0, sizeof vals);
            vindex = dk_map_new();
        }
    }

    DkStr *so = DK_NEWN(a, DkStr, ours.n + 1), *sg = DK_NEWN(a, DkStr, game.n + 1);
    for (size_t i = 0; i < ours.n; i++) so[i] = ours.v[i]->shape = shape(ours.v[i]->text, ours.v[i]->rel);
    for (size_t j = 0; j < game.n; j++) sg[j] = game.v[j]->shape = shape(game.v[j]->text, game.v[j]->rel);
    DkSeqMatcher *sm = dk_seqm_new_str(a, so, ours.n, sg, game.n, &dk_seqm_no_autojunk);
    size_t nops;
    const DkOpcode *ops = dk_seqm_opcodes(sm, &nops);

    Pairing pr = {&ours, &game, vindex, &vals, dk_map_new()};
    RowPairVec renames = {0}, operand = {0}, frame = {0};
    RowVec only_ours = {0}, only_game = {0};
    for (size_t oi = 0; oi < nops; oi++) {
        const DkOpcode *op = &ops[oi];
        if (op->tag == DK_OP_EQUAL) {
            for (size_t i = op->i1, j = op->j1; i < op->i2; i++, j++) {
                out->aligned++;
                if (pair_regs(&pr, i, j)) dk_vec_push(&renames, ((RowPair){ours.v[i], game.v[j]}));
            }
            continue;
        }
        size_t la = op->i2 - op->i1, lb = op->j2 - op->j1;
        bool same_mn = op->tag == DK_OP_REPLACE && la == lb;
        for (size_t k = 0; same_mn && k < la; k++) same_mn = strcmp(ours.v[op->i1 + k]->mn, game.v[op->j1 + k]->mn) == 0;
        if (same_mn) {
            for (size_t i = op->i1, j = op->j1; i < op->i2; i++, j++) {
                out->aligned++;
                if (pair_regs(&pr, i, j)) dk_vec_push(&renames, ((RowPair){ours.v[i], game.v[j]}));
                RowPair pair = {ours.v[i], game.v[j]};
                if (dk_str_eq(strip_esp(so[i]), strip_esp(sg[j]))) dk_vec_push(&frame, pair);
                else dk_vec_push(&operand, pair);
            }
            continue;
        }
        for (size_t i = op->i1; i < op->i2; i++) dk_vec_push(&only_ours, ours.v[i]);
        for (size_t j = op->j1; j < op->j2; j++) dk_vec_push(&only_game, game.v[j]);
    }

    /* an instruction on both sides at another place: a schedule difference, not an extra instruction */
    DkMap *left = counter_of_shapes(&only_ours, false), *right = counter_of_shapes(&only_game, false);
    DkMap *common = counter_and(left, right);
    RowVec moved = {0}, extra_o = {0}, extra_g = {0};
    for (int side = 0; side < 2; side++) {
        const RowVec *rows = side == 0 ? &only_ours : &only_game;
        RowVec *extra = side == 0 ? &extra_o : &extra_g;
        DkMap *budget = counter_copy(common);
        for (size_t i = 0; i < rows->n; i++) {
            DkStr s = rows->v[i]->shape;
            if (counter_get(budget, s) > 0) {
                counter_add(budget, s, -1);
                if (side == 0) dk_vec_push(&moved, rows->v[i]);
            } else {
                dk_vec_push(extra, rows->v[i]);
            }
        }
    }
    /* then the same instruction with another esp displacement (a frame slot moved by a push or a spill) */
    DkMap *ecommon = counter_and(counter_of_shapes(&extra_o, true), counter_of_shapes(&extra_g, true));
    if (dk_map_len(ecommon)) {
        RowVec kept[2] = {{0}, {0}}, hits[2] = {{0}, {0}};
        for (int side = 0; side < 2; side++) {
            const RowVec *rows = side == 0 ? &extra_o : &extra_g;
            DkMap *budget = counter_copy(ecommon);
            for (size_t i = 0; i < rows->n; i++) {
                DkStr s = strip_esp(rows->v[i]->shape);
                if (counter_get(budget, s) > 0) {
                    counter_add(budget, s, -1);
                    dk_vec_push(&hits[side], rows->v[i]);
                } else {
                    dk_vec_push(&kept[side], rows->v[i]);
                }
            }
        }
        extra_o = kept[0];
        extra_g = kept[1];
        size_t zn = hits[0].n < hits[1].n ? hits[0].n : hits[1].n;
        for (size_t i = 0; i < zn; i++) dk_vec_push(&frame, ((RowPair){hits[0].v[i], hits[1].v[i]}));
    }
    RowVec moves = {0}, body_o = {0}, body_g = {0};
    for (int side = 0; side < 2; side++) {
        const RowVec *rows = side == 0 ? &extra_o : &extra_g;
        for (size_t i = 0; i < rows->n; i++) {
            if (in_list(rows->v[i]->mn, MOVES, DK_ARRAY_LEN(MOVES))) dk_vec_push(&moves, rows->v[i]);
            else dk_vec_push(side == 0 ? &body_o : &body_g, rows->v[i]);
        }
    }

    DkMap *classes = out->classes;
    for (size_t i = 0; i < renames.n; i++) { /* a value live across blocks (a globreg) or a block-local one */
        const Row *o = renames.v[i].o, *g = renames.v[i].g;
        RegUseVec ro = reg_tokens(o->text), rg = reg_tokens(g->text);
        bool any = false, all_local = true;
        size_t zn = ro.n < rg.n ? ro.n : rg.n;
        for (size_t k = 0; k < zn; k++) {
            if (ro.v[k].reg == rg.v[k].reg) continue;
            i64 kv = index_get(vindex, o->off, REGS[ro.v[k].reg]);
            if (kv < 0) continue;
            any = true;
            if (strcmp(vals.v[kv]->kind, "local") != 0) all_local = false;
        }
        if (any && all_local) out->local_renames++;
        else out->cross_renames++;
        dk_vec_free(&ro);
        dk_vec_free(&rg);
    }
    if (renames.n)
        put_class(classes, "register",
                  dk_sprintf(a, "%zu aligned instruction(s) differ only in registers (first: +%03X %s | reference %s)%s",
                              renames.n, renames.v[0].o->off, cstr(renames.v[0].o->text), cstr(renames.v[0].g->text),
                              vals.n ? dk_sprintf(a, "; %lld in block-local values, %lld in values live across blocks",
                                                   (long long)out->local_renames, (long long)out->cross_renames)
                                     : ""));
    DkWallInfo info;
    memset(&info, 0, sizeof info);
    const char *wall = dk_wall_classify(result, image, &info);
    if (strcmp(wall, "call-set") == 0)
        put_class(classes, "call-set", dk_sprintf(a, "calls only ours: %s; only the reference's: %s",
                                                   cz_or(&info.calls_only_ours, "-"), cz_or(&info.calls_only_reference, "-")));
    const char *kinds = "";
    if (!an) kinds = dk_sprintf(a, "cfg_diff failed: %s", aerr ? aerr : "");
    else kinds = cfg_diff_one_liner(an);
    if (an && an->findings.n) {
        DkStr ev = dk_u8_slice(dk_str(an->findings.v[0].evidence ? an->findings.v[0].evidence : ""), 0, 90);
        put_class(classes, "control-flow", dk_sprintf(a, "%s (cfg_diff; first: %.*s)", kinds, DK_SF(ev)));
    } else if (strcmp(wall, "control-flow") == 0) {
        put_class(classes, "control-flow", "the ordered branch sequence differs (walls)");
    }
    if (body_o.n || body_g.n) {
        DkCzVec sample = {0};
        for (size_t i = 0; i < body_o.n && i < 2; i++) dk_vec_push(&sample, (char *)row_text(body_o.v[i], "ours"));
        for (size_t i = 0; i < body_g.n && i < 2; i++) dk_vec_push(&sample, (char *)row_text(body_g.v[i], "reference"));
        put_class(classes, "body", dk_sprintf(a, "%zu instruction(s) only ours, %zu only the reference's (%s)", body_o.n,
                                               body_g.n, join_cz(&sample, "; ")));
    }
    if (moves.n) {
        DkCzVec sample = {0};
        for (size_t i = 0; i < moves.n && i < 3; i++) dk_vec_push(&sample, (char *)cstr(moves.v[i]->text));
        put_class(classes, "moves", dk_sprintf(a, "%zu extra copy/push/pop/lea (%s)", moves.n, join_cz(&sample, "; ")));
    }
    if (moved.n)
        put_class(classes, "schedule", dk_sprintf(a, "%zu instruction(s) at another place (first: %s)", moved.n,
                                                   cstr(moved.v[0]->text)));
    if (operand.n)
        put_class(classes, "operand", dk_sprintf(a, "%zu instruction(s) with another constant or displacement (first: %s | "
                                                     "reference %s)", operand.n, cstr(operand.v[0].o->text),
                                                  cstr(operand.v[0].g->text)));
    if (frame.n)
        put_class(classes, "frame", dk_sprintf(a, "%zu instruction(s) with other esp displacements (first: %s | reference %s)",
                                                frame.n, cstr(frame.v[0].o->text), cstr(frame.v[0].g->text)));

    /* our register -> the reference's, by majority over the aligned positions */
    DkMap *by_ours = dk_map_new();
    DkMapIter it = {0};
    while (dk_map_next(pr.pairs, &it)) {
        DkStr tab_a, tab_b;
        dk_str_partition(it.key, DK_S("\t"), &tab_a, &tab_b);
        DkVal *slot = dk_map_put(by_ours, tab_a, NULL);
        if (!slot->p) slot->p = dk_map_new();
        counter_add(slot->p, tab_b, it.val->i);
    }
    memset(&it, 0, sizeof it);
    while (dk_map_next(by_ours, &it)) dk_map_put(out->mapping, it.key, NULL)->p = mapping_of(it.val->p);
    /* the same over the values live across blocks only (the registers Color gave the globregs) */
    DkMap *cross = dk_map_new();
    for (size_t k = 0; k < vals.n; k++) {
        if (strcmp(vals.v[k]->kind, "cross") != 0) continue;
        DkVal *slot = dk_map_put(cross, dk_str(vals.v[k]->reg), NULL);
        if (!slot->p) slot->p = dk_map_new();
        DkMapIter gi = {0};
        while (dk_map_next(vals.v[k]->game, &gi)) counter_add(slot->p, gi.key, gi.val->i);
    }
    memset(&it, 0, sizeof it);
    while (dk_map_next(cross, &it))
        if (dk_map_len(it.val->p)) dk_map_put(out->cross_mapping, it.key, NULL)->p = mapping_of(it.val->p);
    out->values = vals;
    for (size_t i = 0; i < renames.n; i++) {
        const Row *o = renames.v[i].o, *g = renames.v[i].g;
        dk_vec_push(&out->renames, (char *)dk_sprintf(a, "+%03X %s | reference %s", o->off, cstr(o->text), cstr(g->text)));
        RegUseVec ro = reg_tokens(o->text), rg = reg_tokens(g->text);
        size_t zn = ro.n < rg.n ? ro.n : rg.n;
        for (size_t k = 0; k < zn; k++) {
            if (ro.v[k].reg == rg.v[k].reg) continue;
            if (ro.v[k].reg >= 7 || rg.v[k].reg >= 7) out->xmm = true; /* xmm0..xmm7 */
            else out->gp = true;
        }
        dk_vec_free(&ro);
        dk_vec_free(&rg);
    }
    DkCzVec rest = {0};
    for (size_t i = 1; i < DK_ARRAY_LEN(CLASSES); i++)
        if (dk_map_has(classes, dk_str(CLASSES[i]))) dk_vec_push(&rest, (char *)CLASSES[i]);
    bool has_register = dk_map_has(classes, DK_S("register"));
    if (!dk_map_len(classes)) {
        out->verdict = "no register difference (bytes differ only in masked words?)";
    } else if (has_register) {
        out->verdict = rest.n ? dk_sprintf(a, "register + %s", join_cz(&rest, ", ")) : "register-only";
        if (vals.n && !out->cross_renames)
            out->verdict = dk_sprintf(a, "%s (the renames are all in block-local values)", out->verdict);
    } else {
        out->verdict = dk_sprintf(a, "no register difference: %s", join_cz(&rest, ", "));
    }
    out->has_register_only = true;
    out->register_only = has_register && !rest.n;
    out->structure = structure(classes, &ours, &game, an, &info);
    out->has_cfg = true;
    if (an) {
        out->cfg_blocks_ours = an->blocks_ours;
        out->cfg_blocks_game = an->blocks_game;
        out->cfg_matched = an->matched;
        out->cfg_size_ours = an->size_ours;
        out->cfg_size_game = an->size_game;
    } else {
        out->cfg_blocks_ours = out->cfg_blocks_game = out->cfg_matched = out->cfg_size_ours = out->cfg_size_game =
            RESIDUE_NONE;
    }
    return out;
}

/* ============================================================================================ the report */

void residue_format(DkBuf *out, const ResidueReport *r) {
    DkArena *a = A();
    dk_buf_putz(out, dk_sprintf(a, "  residue: %s\n", r->verdict));
    if (!r->has_register_only) return;
    dk_buf_putz(out, dk_sprintf(a, "    %lld aligned instruction(s) (ours %lld, the reference's %lld)\n", (long long)r->aligned,
                                (long long)r->insns_ours, (long long)r->insns_game));
    DkMapIter it = {0};
    while (dk_map_next(r->classes, &it))
        dk_buf_putz(out, dk_sprintf(a, "    %.*s: %s\n", DK_SF(it.key), (const char *)it.val->p));
    for (size_t i = 0; i < r->structure.n; i++) dk_buf_putz(out, dk_sprintf(a, "    structure: %s\n", r->structure.v[i]));
    if (dk_map_len(r->mapping))
        dk_buf_putz(out, dk_sprintf(a, "    registers (ours->reference): %s\n", residue_mapping_text(r->mapping, 10)));
    if (dk_map_len(r->cross_mapping))
        dk_buf_putz(out, dk_sprintf(a, "    live across blocks: %s\n", residue_mapping_text(r->cross_mapping, 10)));
    size_t shown = 0;
    for (size_t i = 0; i < r->values.n && shown < 12; i++) {
        if (strcmp(r->values.v[i]->kind, "cross") != 0) continue;
        dk_buf_putz(out, dk_sprintf(a, "    value %s\n", residue_value_text(r->values.v[i], 3)));
        shown++;
    }
}

DkJson *residue_json(DkArena *a, const ResidueReport *r) {
    DkJson *o = dk_json_obj(a);
    dk_json_set(a, o, DK_S("verdict"), dk_json_strz(a, r->verdict));
    dk_json_set(a, o, DK_S("status"), dk_json_strz(a, r->status));
    if (!r->has_register_only) return o;
    dk_json_set(a, o, DK_S("register_only"), dk_json_bool(r->register_only));
    DkJson *cl = dk_json_obj(a);
    DkMapIter it = {0};
    while (dk_map_next(r->classes, &it)) dk_json_set(a, cl, it.key, dk_json_strz(a, (const char *)it.val->p));
    dk_json_set(a, o, DK_S("classes"), cl);
    dk_json_set(a, o, DK_S("aligned"), dk_json_int(a, r->aligned));
    dk_json_set(a, o, DK_S("insns_ours"), dk_json_int(a, r->insns_ours));
    dk_json_set(a, o, DK_S("insns_reference"), dk_json_int(a, r->insns_game));
    dk_json_set(a, o, DK_S("local_renames"), dk_json_int(a, r->local_renames));
    dk_json_set(a, o, DK_S("cross_renames"), dk_json_int(a, r->cross_renames));
    DkJson *rn = dk_json_arr(a);
    for (size_t i = 0; i < r->renames.n; i++) dk_json_arr_push(a, rn, dk_json_strz(a, r->renames.v[i]));
    dk_json_set(a, o, DK_S("renames"), rn);
    DkJson *st = dk_json_arr(a);
    for (size_t i = 0; i < r->structure.n; i++) dk_json_arr_push(a, st, dk_json_strz(a, r->structure.v[i]));
    dk_json_set(a, o, DK_S("structure"), st);
    DkJson *maps = dk_json_obj(a);
    for (int k = 0; k < 2; k++) {
        const DkMap *m = k ? r->cross_mapping : r->mapping;
        DkJson *mo = dk_json_obj(a);
        DkMapIter mi = {0};
        while (dk_map_next(m, &mi)) {
            const ResidueMapping *e = mi.val->p;
            DkJson *eo = dk_json_obj(a);
            dk_json_set(a, eo, DK_S("reference"), dk_json_strz(a, e->game));
            dk_json_set(a, eo, DK_S("count"), dk_json_int(a, e->count));
            dk_json_set(a, eo, DK_S("total"), dk_json_int(a, e->total));
            dk_json_set(a, mo, mi.key, eo);
        }
        dk_json_set(a, maps, dk_str(k ? "across_blocks" : "all"), mo);
    }
    dk_json_set(a, o, DK_S("mapping"), maps);
    return o;
}
