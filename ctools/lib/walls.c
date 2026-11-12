// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The structural classification of a compared function (walls.h). */
#include "walls.h"

#include "dk/fmt.h"
#include "dk/re.h"
#include "insn_text.h"

#include <stdio.h>
#include <string.h>

const char *const DK_WALL_ORDER[7] = {"match", "referent", "register", "body", "control-flow", "call-set", "error"};

int dk_wall_rank(const char *wall) {
    for (int i = 0; i < 7; i++)
        if (strcmp(DK_WALL_ORDER[i], wall) == 0) return i;
    return -1;
}

double dk_wall_weight(const char *wall, double dflt) {
    static const struct {
        const char *wall;
        double w;
    } WEIGHT[] = {{"referent", 1.0}, {"register", 0.8}, {"body", 0.6},
                  {"control-flow", 0.6}, {"call-set", 0.5}, {"error", 0.2}};
    for (size_t i = 0; i < DK_ARRAY_LEN(WEIGHT); i++)
        if (strcmp(WEIGHT[i].wall, wall) == 0) return WEIGHT[i].w;
    return dflt;
}

/* ---- disassembly ---- */

DkInsns dk_wall_disasm(DkStr code, u64 base) {
    DkInsns out = {0};
    size_t n = 0;
    if (code.n) out.v = dk_dis_all(dk_dis(DK_DIS_X86_32, 0), code.p, code.n, base, 0, &n);
    out.n = out.total = out.v ? n : 0;
    return out;
}

void dk_wall_insns_free(DkInsns *insns) {
    if (insns->v) dk_dis_free(insns->v, insns->total);
    insns->v = NULL;
    insns->n = insns->total = 0;
}

/* ---- tokens ---- */

DkIMap *dk_wall_verdicts(const DkResult *r) {
    DkIMap *m = dk_imap_new_cap(r ? r->n_refs : 0);
    for (size_t i = 0; r && i < r->n_refs; i++) dk_imap_put(m, r->refs[i].offset, NULL)->p = (void *)&r->refs[i];
    return m;
}

/* The operand as one hex number (capstone prints direct targets as 0x...). */
static bool hex_operand(const cs_insn *ins, u64 *out) {
    i64 v;
    if (!dk_parse_int(dk_str(ins->op_str), 16, &v, NULL) || v < 0) return false;
    *out = (u64)v;
    return true;
}

bool dk_wall_target_of(const cs_insn *ins, u64 *target) {
    u8 b = ins->bytes[0];
    if (!(b == 0xE9 || b == 0xEB || b == 0x0F || (b >= 0x70 && b <= 0x7F))) return false;
    return hex_operand(ins, target);
}

/* Our relocation check of the rel32 field of a call or jmp (the field follows the one-byte opcode). */
static const DkRefCheck *check_at(const DkIMap *verdicts, u64 field) {
    if (!verdicts) return NULL;
    const DkVal *v = dk_imap_get(verdicts, field);
    return v ? (const DkRefCheck *)v->p : NULL;
}

static DkCallToken tok_int(u64 n) {
    DkCallToken t = {true, n, {NULL, 0}};
    return t;
}

static DkCallToken tok_str(DkStr s) {
    DkCallToken t = {false, 0, s};
    return t;
}

static DkStr check_name(const DkRefCheck *c) { return dk_str(c->name ? c->name : "?"); }

bool dk_wall_call_token(const cs_insn *ins, u64 base, const DkIMap *verdicts, size_t size, DkCallToken *out) {
    DkArena *a = dk_arena();
    const DkRefCheck *c = check_at(verdicts, ins->address - base + 1);
    if (strcmp(ins->mnemonic, "jmp") == 0) {
        if (ins->bytes[0] != 0xE9 && ins->bytes[0] != 0xEB) return false;
        u64 target;
        if (c) {
            if (c->verdict == DK_REF_UNRESOLVED) {
                *out = tok_str(dk_str(dk_sprintf(a, "tail:sym:%.*s", DK_SF(check_name(c)))));
                return true;
            }
            target = c->ours;
        } else if (!dk_wall_target_of(ins, &target)) {
            return false;
        }
        if (base <= target && target < base + size) return false;
        *out = tok_str(dk_str(dk_sprintf(a, "tail:0x%llX", (unsigned long long)target)));
        return true;
    }
    if (strcmp(ins->mnemonic, "call") != 0) return false;
    if (ins->bytes[0] != 0xE8) {
        *out = tok_str(DK_S("indirect"));
        return true;
    }
    if (c) {
        if (c->verdict != DK_REF_UNRESOLVED) *out = tok_int(c->ours);
        else *out = tok_str(dk_str(dk_sprintf(a, "sym:%.*s", DK_SF(check_name(c)))));
        return true;
    }
    u64 t;
    *out = hex_operand(ins, &t) ? tok_int(t) : tok_str(DK_S("indirect"));
    return true;
}

DkStr dk_wall_tok_text(DkArena *a, const DkCallToken *t) {
    if (t->is_int) return dk_str(dk_sprintf(a, "0x%llX", (unsigned long long)t->n));
    return t->s;
}

/* ---- moves and branches ---- */

bool dk_wall_is_move(const char *m) {
    static const char *const MOVELIKE[] = {"push", "pop", "lea", "nop", "xchg", "int3", "fld", "fst", "fstp", "fild",
                                           "fist", "fistp", "fxch"};
    if (strncmp(m, "mov", 3) == 0 && strcmp(m, "movzx") != 0 && strcmp(m, "movsx") != 0) return true;
    for (size_t i = 0; i < DK_ARRAY_LEN(MOVELIKE); i++)
        if (strcmp(m, MOVELIKE[i]) == 0) return true;
    return false;
}

DkBranchVec dk_wall_branch_tokens(const DkInsns *insns, bool targets) {
    DkBranchVec out = {0};
    /* where[i]: the number of non-move instructions before instruction i; addresses ascend (binary search) */
    i64 *where = insns->n ? (i64 *)dk_xmalloc(insns->n * sizeof *where) : NULL;
    i64 k = 0;
    for (size_t i = 0; i < insns->n; i++) {
        where[i] = k;
        if (!dk_wall_is_move(insns->v[i].mnemonic)) k++;
    }
    for (size_t i = 0; i < insns->n; i++) {
        const cs_insn *ins = &insns->v[i];
        DkBranch b;
        memset(&b, 0, sizeof b);
        b.target = DK_WALL_TARGET_NONE;
        if (strcmp(ins->mnemonic, "ret") == 0) {
            strcpy(b.mnemonic, "ret");
        } else if (ins->mnemonic[0] == 'j') {
            strncpy(b.mnemonic, ins->mnemonic, sizeof b.mnemonic - 1);
            if (targets) {
                u64 t;
                if (!dk_wall_target_of(ins, &t)) {
                    b.target = DK_WALL_TARGET_INDIRECT;
                } else {
                    b.target = DK_WALL_TARGET_OUT;
                    size_t lo = 0, hi = insns->n;
                    while (lo < hi) {
                        size_t mid = lo + (hi - lo) / 2;
                        if (insns->v[mid].address < t) lo = mid + 1;
                        else hi = mid;
                    }
                    if (lo < insns->n && insns->v[lo].address == t) b.target = where[lo];
                }
            }
        } else {
            continue;
        }
        dk_vec_push(&out, b);
    }
    dk_xfree(where);
    return out;
}

static bool branches_equal(const DkBranchVec *x, const DkBranchVec *y) {
    if (x->n != y->n) return false;
    for (size_t i = 0; i < x->n; i++)
        if (x->v[i].target != y->v[i].target || strcmp(x->v[i].mnemonic, y->v[i].mnemonic) != 0) return false;
    return true;
}

/* ---- switch tables ---- */

#define TABLE_PAT                                                                                                  \
    "^(?:jmp dword ptr \\[\\w+\\*4(?: \\+ (0x[0-9a-f]+|\\d+))?\\]|movzx \\w+, byte ptr \\[\\w+(?: \\+ "           \
    "(0x[0-9a-f]+|\\d+))?\\])$"

bool dk_wall_table_start(const DkInsns *insns, u64 base, size_t size, const DkResult *ours, i64 *cut_out) {
    const DkRe *re = dk_re(TABLE_PAT, 0);
    bool have = false;
    i64 cut = 0;
    char text[CS_MNEMONIC_SIZE + 1 + 160 + 1];
    for (size_t i = 0; i < insns->n; i++) {
        const cs_insn *ins = &insns->v[i];
        if (strcmp(ins->mnemonic, "jmp") != 0 && strcmp(ins->mnemonic, "movzx") != 0) continue;
        int len = snprintf(text, sizeof text, "%s %s", ins->mnemonic, ins->op_str);
        if (len < 0) continue;
        DkReMatch m;
        if (!dk_re_match(re, dk_strn(text, (size_t)len), 0, DK_END, &m)) continue;
        i64 at = (i64)(ins->address - base);
        bool has_off = false;
        i64 off = 0;
        if (ours) {
            /* our table's word: a relocation inside the instruction whose resolved address lies in the function */
            for (size_t k = 0; k < ours->n_refs && !has_off; k++) {
                const DkRefCheck *c = &ours->refs[k];
                if (at <= (i64)c->offset && (i64)c->offset < at + ins->size && c->verdict != DK_REF_UNRESOLVED &&
                    c->ours >= ours->theirs_va && (u64)c->ours < (u64)ours->theirs_va + size) {
                    off = (i64)c->ours - (i64)ours->theirs_va;
                    has_off = true;
                }
            }
        } else if (dk_re_matched(&m, 1) || dk_re_matched(&m, 2)) {
            DkStr g = dk_re_matched(&m, 1) ? dk_re_group(&m, 1) : dk_re_group(&m, 2);
            i64 v;
            if (dk_parse_int(g, 0, &v, NULL)) {
                off = v - (i64)base;
                has_off = true;
            }
        }
        if (has_off && at < off && off < (i64)size) {
            cut = have ? DK_MIN(cut, off) : off;
            have = true;
        }
    }
    if (have) *cut_out = cut;
    return have;
}

DkInsns dk_wall_code_only(const DkInsns *insns, u64 base, size_t size, const DkResult *ours) {
    i64 cut;
    DkInsns out = *insns;
    if (!dk_wall_table_start(insns, base, size, ours, &cut)) return out;
    size_t n = 0;
    while (n < insns->n && (i64)(insns->v[n].address - base) < cut) n++;
    out.n = n;
    return out;
}

/* ---- the reference's window ---- */

static bool ends_in_exit(const DkInsns *x) {
    if (!x->n) return false;
    const char *m = x->v[x->n - 1].mnemonic;
    return strcmp(m, "ret") == 0 || strcmp(m, "jmp") == 0;
}

static bool symbol_starts(const DkImage *im, u32 va) {
    u32 start = 0;
    return dk_image_name_at(im, va, &start) && start == va;
}

DkStr dk_wall_reference_window(const DkResult *r, const DkImage *im) {
    u32 base = r->theirs_va;
    size_t n = r->ours.code.n;
    DkStr window = r->theirs;
    u32 sized = 0;
    if (im && dk_image_function_size(im, base, &sized) && sized && sized != window.n) {
        DkStr got;
        if (dk_image_read(im, base, sized, &got) && got.n) window = got;
    }
    while (window.n && (u8)window.p[window.n - 1] == 0xCC) window.n--;
    DkInsns tail = dk_wall_disasm(window, base);
    i64 cut;
    if (dk_wall_table_start(&tail, base, window.n, NULL, &cut)) {
        dk_wall_insns_free(&tail);
        return dk_strn(window.p, (size_t)cut);
    }
    bool ends = ends_in_exit(&tail);
    dk_wall_insns_free(&tail);
    if (!im || (ends && window.n >= n)) return window;
    size_t limit = n >= 32 ? DK_MIN(n + 64, n * 2) : n * 2;
    limit = DK_MAX(limit, window.n);
    DkStr big;
    if (!limit || !dk_image_read(im, base, limit, &big)) return window;
    DkInsns insns = dk_wall_disasm(big, base);
    if (dk_wall_table_start(&insns, base, big.n, NULL, &cut)) {
        dk_wall_insns_free(&insns);
        return dk_strn(big.p, (size_t)cut);
    }
    size_t last = 0;
    for (size_t i = 0; i < insns.n; i++) {
        const cs_insn *ins = &insns.v[i];
        if (strcmp(ins->mnemonic, "ret") != 0 && strcmp(ins->mnemonic, "jmp") != 0) continue;
        size_t end = (size_t)(ins->address - base) + ins->size;
        last = end;
        u8 nxt = end < big.n ? (u8)big.p[end] : 0;
        if ((end < big.n && (nxt == 0xCC || nxt == 0x90)) || symbol_starts(im, base + (u32)end)) {
            dk_wall_insns_free(&insns);
            return dk_strn(big.p, end);
        }
    }
    dk_wall_insns_free(&insns);
    return last ? dk_strn(big.p, last) : window;
}

/* ---- classification ---- */

/* The tokens of insns counted by their text (first-seen order kept). */
static DkMap *count_tokens(const DkInsns *insns, u64 base, const DkIMap *verdicts, size_t size) {
    DkMap *m = dk_map_new();
    DkArena *a = dk_arena();
    for (size_t i = 0; i < insns->n; i++) {
        DkCallToken t;
        if (!dk_wall_call_token(&insns->v[i], base, verdicts, size, &t)) continue;
        dk_map_put(m, dk_wall_tok_text(a, &t), NULL)->i += 1;
    }
    return m;
}

/* The keys of x whose count exceeds y's, each repeated by the excess, at most five. */
static DkCzVec only_in(const DkMap *x, const DkMap *y) {
    DkCzVec out = {0};
    DkArena *a = dk_arena();
    DkMapIter it = {0};
    while (dk_map_next(x, &it) && out.n < 5) {
        const DkVal *o = dk_map_get(y, it.key);
        i64 d = it.val->i - (o ? o->i : 0);
        for (i64 k = 0; k < d && out.n < 5; k++) dk_vec_push(&out, dk_cz(a, it.key));
    }
    return out;
}

static bool counters_equal(const DkMap *x, const DkMap *y) {
    if (dk_map_len(x) != dk_map_len(y)) return false;
    DkMapIter it = {0};
    while (dk_map_next(x, &it)) {
        const DkVal *o = dk_map_get(y, it.key);
        if (!o || o->i != it.val->i) return false;
    }
    return true;
}

static DkMap *count_mnemonics(const DkInsns *insns) {
    DkMap *m = dk_map_new();
    for (size_t i = 0; i < insns->n; i++) {
        if (dk_wall_is_move(insns->v[i].mnemonic)) continue;
        dk_map_put(m, dk_str(insns->v[i].mnemonic), NULL)->i += 1;
    }
    return m;
}

static size_t count_real(const DkInsns *insns) {
    size_t c = 0;
    for (size_t i = 0; i < insns->n; i++)
        if (strcmp(insns->v[i].mnemonic, "int3") != 0 && strcmp(insns->v[i].mnemonic, "nop") != 0) c++;
    return c;
}

static bool same_mnemonic_lists(const DkInsns *x, const DkInsns *y) {
    if (x->n != y->n) return false;
    for (size_t i = 0; i < x->n; i++)
        if (strcmp(x->v[i].mnemonic, y->v[i].mnemonic) != 0) return false;
    return true;
}

/* The number of keys whose counts differ, and one of them. */
static size_t differing_keys(const DkMap *x, const DkMap *y, DkStr *one) {
    size_t n = 0;
    DkMapIter it = {0};
    while (dk_map_next(x, &it)) {
        const DkVal *o = dk_map_get(y, it.key);
        if (it.val->i - (o ? o->i : 0) > 0) {
            n++;
            *one = it.key;
        }
    }
    return n;
}

const char *dk_wall_classify(const DkResult *r, const DkImage *im, DkWallInfo *info) {
    DkArena *a = dk_arena();
    u64 base = r->theirs_va;
    DkIMap *verdicts = dk_wall_verdicts(r);
    DkStr ref_bytes = dk_wall_reference_window(r, im);
    DkInsns ours_all = dk_wall_disasm(r->ours.code, base);
    DkInsns ref_all = dk_wall_disasm(ref_bytes, base);
    DkInsns ours = dk_wall_code_only(&ours_all, base, r->ours.code.n, r);
    DkInsns ref = dk_wall_code_only(&ref_all, base, ref_bytes.n, NULL);
    size_t nd = 0;
    u32 *differ = dk_result_differ(a, r, &nd);
    info->classified = true;
    info->insns_ours = (i64)ours.n;
    info->insns_reference = (i64)ref.n;
    info->has_first_difference = nd > 0;
    info->first_difference = nd ? (i64)differ[0] : 0;
    info->reference_window = (i64)ref_bytes.n;
    DkMap *co = count_tokens(&ours, base, verdicts, r->ours.code.n);
    DkMap *cg = count_tokens(&ref, base, NULL, ref_bytes.n);
    info->calls_only_ours = only_in(co, cg);
    info->calls_only_reference = only_in(cg, co);
    info->same_mnemonics = same_mnemonic_lists(&ours, &ref);

    const char *wall = NULL;
    if (!counters_equal(co, cg)) {
        /* one key in both, counted differently: a target called more or fewer times (a duplicated or merged tail) */
        DkStr one = {0};
        size_t nkeys = differing_keys(co, cg, &one) + differing_keys(cg, co, &one);
        wall = nkeys == 1 && dk_map_has(co, one) && dk_map_has(cg, one) ? "control-flow" : "call-set";
    }
    if (!wall) {
        DkBranchVec bo = dk_wall_branch_tokens(&ours, false), bg = dk_wall_branch_tokens(&ref, false);
        if (!branches_equal(&bo, &bg)) wall = "control-flow";
        dk_vec_free(&bo);
        dk_vec_free(&bg);
    }
    if (!wall) {
        DkMap *ko = count_mnemonics(&ours), *kg = count_mnemonics(&ref);
        i64 delta = (i64)count_real(&ours) - (i64)count_real(&ref);
        if (!counters_equal(ko, kg) || delta > 2 || delta < -2) {
            wall = "body";
        } else {
            DkBranchVec bo = dk_wall_branch_tokens(&ours, true), bg = dk_wall_branch_tokens(&ref, true);
            wall = branches_equal(&bo, &bg) ? "register" : "control-flow";
            dk_vec_free(&bo);
            dk_vec_free(&bg);
        }
        dk_map_free(ko);
        dk_map_free(kg);
    }
    dk_map_free(co);
    dk_map_free(cg);
    dk_imap_free(verdicts);
    dk_wall_insns_free(&ours_all);
    dk_wall_insns_free(&ref_all);
    return wall;
}

DkBuildWall dk_build_wall(const DkResult *r, const DkImage *im) {
    DkBuildWall out;
    memset(&out, 0, sizeof out);
    out.status = DK_ERROR;
    out.wall = "error";
    if (!r) return out;
    out.status = r->status;
    if (r->status == DK_ERROR || r->status == DK_MISSING) return out;
    size_t nd = 0;
    dk_result_differ(dk_arena(), r, &nd);
    i64 size = r->ours.code.n ? (i64)r->ours.code.n : 1;
    i64 differ = (i64)nd;
    out.close = dk_py_round((double)(size - differ) / (double)size * 100, 1);
    if (out.close < 0) out.close = 0;
    out.info.size = (i64)r->ours.code.n;
    out.info.differ = differ;
    u32 rs = 0;
    if (im && dk_image_function_size(im, r->theirs_va, &rs) && rs) {
        out.info.has_reference_size = true;
        out.info.reference_size = rs;
    }
    switch (r->status) {
    case DK_MATCH: out.wall = "match"; return out;
    case DK_REFERENT:
    case DK_UNRESOLVED: out.wall = "referent"; return out;
    default: break;
    }
    out.wall = dk_wall_classify(r, im, &out.info);
    return out;
}
