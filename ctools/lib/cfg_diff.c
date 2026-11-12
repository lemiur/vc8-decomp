// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* cfg_diff: compare the control flow graphs of our compiled function and the reference's, and name the structural
 * differences.
 *
 * Both sides are disassembled by recursive descent from the entry (switch tables followed through their words), cut
 * into basic blocks, and the blocks of ours are aligned with the reference's: entry with entry, blocks with a unique
 * call / global signature, then along the edges by role (a negated or mirrored condition crosses or keeps the arms),
 * then by similarity (calls, globals, constants, opcode sequence, neighbours already mapped). What does not line up
 * is named (inverted-branch, mirrored-compare, block-order, duplicated-tail, merged-tail, early-return,
 * loop-rotation, jump-threading, switch-lowering, tail-call, missing-block, extra-block, other), each finding with
 * its evidence and the source lever. --batch analyses every result of the adapter (lib/unitcmp.h) that is not a MATCH
 * and whose wall (lib/walls.h) is control-flow (every DIFF or SIZE result with --all-walls).
 *
 * The file's order: the tables, one side (decoding, blocks, features), similarity and alignment, loops, the findings,
 * the analysis, the output (report, dot, html) and the command line. The best-first heap of the alignment orders its
 * entries by a total key that ends in the two block indices, and the sets of block indices that role_pairs and
 * neighbours walk reach no output beyond that heap order ("set order" marks the sites). */
#include "cfg_diff.h"

#include "dk/args.h"
#include "dk/difflib.h"
#include "dk/fmt.h"
#include "dk/fs.h"
#include "dk/json.h"
#include "dk/map.h"
#include "dk/pool.h"
#include "dk/proc.h"
#include "dk/re.h"
#include "dk/sort.h"
#include "project_backend.h"
#include "unitcmp.h"
#include "walls.h"

#define A_ (dk_arena())
/* "%..." formatting with the printf-style rules of the report into the thread arena; the result is a NUL-terminated const char *. */
#define PF(...) (dk_pyfmt(A_, __VA_ARGS__).p)

static const char DOC[] =
#include "cfg_diff_doc.inc"
    ;

/* ---------------------------------------------------------------- tables */

typedef struct {
    const char *from, *to;
} Pair;

static const Pair ALIAS[] = {{"z", "e"},   {"nz", "ne"},  {"c", "b"},   {"nae", "b"}, {"nc", "ae"},
                             {"nb", "ae"}, {"na", "be"},  {"nbe", "a"}, {"nge", "l"}, {"nl", "ge"},
                             {"ng", "le"}, {"nle", "g"},  {"pe", "p"},  {"po", "np"}};
/* NEG with its inverse pairs added (NEG.update({v: k ...})). */
static const Pair NEG[] = {{"e", "ne"}, {"l", "ge"}, {"le", "g"}, {"b", "ae"}, {"be", "a"}, {"s", "ns"},
                           {"p", "np"}, {"o", "no"}, {"ne", "e"}, {"ge", "l"}, {"g", "le"}, {"ae", "b"},
                           {"a", "be"}, {"ns", "s"},  {"np", "p"}, {"no", "o"}};
/* MIRROR with its inverse pairs added. */
static const Pair MIRROR[] = {{"l", "g"}, {"le", "ge"}, {"b", "a"},  {"be", "ae"}, {"e", "e"},
                              {"ne", "ne"}, {"g", "l"}, {"ge", "le"}, {"a", "b"},   {"ae", "be"}};

static const char *tbl_get(const Pair *t, size_t n, const char *k) {
    if (!k) return NULL;
    for (size_t i = 0; i < n; i++)
        if (strcmp(t[i].from, k) == 0) return t[i].to;
    return NULL;
}
#define NEG_GET(k) tbl_get(NEG, DK_ARRAY_LEN(NEG), (k))
#define MIRROR_GET(k) tbl_get(MIRROR, DK_ARRAY_LEN(MIRROR), (k))

/* a == b where either may be None (NULL). */
static bool opt_eq(const char *a, const char *b) {
    if (!a || !b) return a == b;
    return strcmp(a, b) == 0;
}

typedef struct {
    const char *kind, *lever;
} LeverRow;
static const LeverRow LEVER[] = {
    {"inverted-branch",
     "swap the if/else arms or negate the test (`if (!x) B; else A;` <-> `if (x) A; else B;`); "
     "the operand order of a short-circuit (`if (a && b)` vs `if (b && a)`)"},
    {"mirrored-compare",
     "swap the compared operands (`if (end > frame)` vs `if (frame < end)`)"},
    {"block-order",
     "VC8 lays blocks out in source order: move the statement or arm, swap if/else arms, nested if vs "
     "early `return`/`continue`"},
    {"duplicated-tail",
     "tail merging: separate returns vs `goto` one exit vs `&&`/`||` collapse"},
    {"merged-tail",
     "the game merged what ours duplicates: one shared exit/tail (`goto`, a single return, `&&`/`||`) "
     "instead of repeated statements"},
    {"early-return",
     "a `return` from the middle duplicates the destructor/epilogue at "
     "that exit; a single exit at the end does not"},
    {"loop-rotation",
     "`while (c) {}` vs `if (c) do {} while (c);`, `for` vs `do-while` (e.g. "
     "`if (n <= 0) ...; do { } while (++i < n);`)"},
    {"jump-threading",
     "select wall: game keeps the retest -> `T* p = obj ? obj->Accessor() : 0;` with the "
     "inline accessor call in the arm; ours keeps it -> `if`/`else` or a "
     "direct member read"},
    {"switch-lowering",
     "cases in the order of their values, shared tail after the switch; "
     "`switch` vs an if/else chain; case count/density decides table vs chain"},
    {"tail-call",
     "frame/epilogue differences (EH state, a local still alive after the call): check the code after "
     "the call"},
    {"missing-block", "likely a source difference: a statement, condition or case ours lacks"},
    {"extra-block", "likely a source difference: a statement, condition or case the game lacks"},
    {"other", "compare the two disassemblies (the unit's side-by-side diff)"},

};

const char *const CFG_DIFF_KINDS[] = {"inverted-branch", "mirrored-compare", "block-order", "duplicated-tail",
                                      "merged-tail",     "early-return",     "loop-rotation", "jump-threading",
                                      "switch-lowering", "tail-call",        "missing-block", "extra-block",
                                      "other",           "error"};
const size_t CFG_DIFF_NKINDS = DK_ARRAY_LEN(CFG_DIFF_KINDS);

const char *cfg_diff_lever(const char *kind) {
    for (size_t i = 0; i < DK_ARRAY_LEN(LEVER); i++)
        if (strcmp(LEVER[i].kind, kind) == 0) return LEVER[i].lever;
    return NULL;
}

/* KINDS.index(kind). */
static int kind_index(const char *kind) {
    for (size_t i = 0; i < CFG_DIFF_NKINDS; i++)
        if (strcmp(CFG_DIFF_KINDS[i], kind) == 0) return (int)i;
    dk_throw(DK_ERR_OTHER, "%s is not in list", kind);
}

/* The mnemonics whose result a following jcc tests. */
static const char *const FLAGS[] = {"cmp",  "test",  "comiss", "ucomiss", "comisd", "ucomisd", "sahf", "fcomi",
                                    "fucomi", "fcomip", "fucomip", "and",   "or",    "xor",     "sub",  "add",
                                    "inc",  "dec",   "neg",    "sar",     "shr",    "shl",     "bt",   "sbb",
                                    "adc"};
static bool in_list(const char *const *list, size_t n, const char *s) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(list[i], s) == 0) return true;
    return false;
}
#define IN_LIST(list, s) in_list((list), DK_ARRAY_LEN(list), (s))

/* rel(path): the path relative to the project root with "/" separators. */
const char *cfg_diff_rel(const DkProject *project, const char *path) {
    char *out = NULL;
    if (!dk_path_relpath(A_, path, dk_project_root(project), &out)) dk_panic(__FILE__, __LINE__, "relpath failed for %s", path);
    for (char *c = out; *c; c++)
        if (*c == '\\') *c = '/';
    return out;
}

bool cfg_diff_is_jcc(const char *m) {
    return (m[0] == 'j' && strcmp(m, "jmp") != 0) || strncmp(m, "loop", 4) == 0;
}

const char *cfg_diff_cond_of(const char *m) {
    if (strncmp(m, "loop", 4) == 0) return m;
    const char *c = m + 1;
    const char *a = tbl_get(ALIAS, DK_ARRAY_LEN(ALIAS), c);
    return a ? a : c;
}
#define is_jcc cfg_diff_is_jcc
#define cond_of cfg_diff_cond_of

/* int(text, 0): a failure (dk_throw, caught by cfg_diff_analyse) for a malformed number. */
static i64 py_int0(const char *text) {
    i64 v;
    if (!dk_parse_int(dk_str(text), 0, &v, NULL))
        dk_throw(DK_ERR_OTHER, "invalid literal for int() with base 0: %s", dk_repr_str(A_, dk_str(text)).p);
    return v;
}

/* ---------------------------------------------------------------- one side: decoding, blocks */

/* Slice s[start:end] of a buffer of length n, for a non-negative start. */
static DkStr slice_from(DkStr s, i64 start, i64 end) {
    i64 n = (i64)s.n;
    if (start > n) start = n;
    if (end < 0) end += n;
    if (end < 0) end = 0;
    if (end > n) end = n;
    if (end < start) return dk_strn(s.p ? s.p : "", 0);
    return dk_strn(s.p + start, (size_t)(end - start));
}

CfgDiffSide *cfg_diff_side_new(const char *name, DkStr code, u32 base, u32 extent, const DkFunc *fn,
                               DkIMap *verdicts, const DkImage *image) {
    CfgDiffSide *s = DK_NEW(A_, CfgDiffSide);
    s->name = name;
    s->code = code;
    s->base = base;
    s->extent = extent;
    s->fn = fn;
    s->image = image;
    s->verdicts = verdicts ? verdicts : dk_imap_new();
    s->relocs = dk_imap_new();
    if (fn)
        for (size_t i = 0; i < fn->n_relocs; i++) dk_imap_put(s->relocs, fn->relocs[i].offset, NULL)->p = &fn->relocs[i];
    s->ours = fn != NULL;
    s->at = dk_imap_new();
    s->tables = dk_imap_new();
    return s;
}

bool cfg_diff_side_inside(const CfgDiffSide *s, u32 va) { return s->base <= va && va < (u64)s->base + s->extent; }
static bool inside_i(const CfgDiffSide *s, i64 va) { return (i64)s->base <= va && va < (i64)s->base + (i64)s->extent; }

/* reloc_in(off, size): [self.relocs[o] for o in range(off, off + size) if o in self.relocs]. */
DkPtrVec cfg_diff_side_reloc_in(const CfgDiffSide *s, u32 off, u32 size) {
    DkPtrVec out = {0};
    if (!dk_imap_len(s->relocs)) return out;
    for (u32 o = off; o < off + size; o++) {
        const DkVal *v = dk_imap_get(s->relocs, o);
        if (v) dk_vec_push(&out, v->p);
    }
    return out;
}

/* own(reloc): the symbol is defined in the function's own section. */
static bool side_own(const CfgDiffSide *s, const DkReloc *r) {
    if (!r->symbol) return false;
    /* the adapter records a target inside the function (a label, a switch table) as the function itself */
    return s->fn && s->fn->symbol && strcmp(r->symbol, s->fn->symbol) == 0;
}

/* own_target(reloc): the absolute address an own-section relocation (a label, a switch table) points at. */
static i64 side_own_target(const CfgDiffSide *s, const DkReloc *r) { return (i64)s->base + (i64)r->addend; }

/* ref_address(ins): the absolute address of an instruction's memory reference (a switch table). */
static bool side_ref_address(const CfgDiffSide *s, const cs_insn *ins, i64 *out) {
    if (s->ours) {
        DkPtrVec rs = cfg_diff_side_reloc_in(s, (u32)(ins->address - s->base), ins->size);
        bool found = false;
        for (size_t i = 0; i < rs.n && !found; i++)
            if (side_own(s, rs.v[i])) {
                *out = side_own_target(s, rs.v[i]);
                found = true;
            }
        dk_vec_free(&rs);
        return found;
    }
    const cs_x86 *x = &ins->detail->x86;
    for (int i = 0; i < x->op_count; i++)
        if (x->operands[i].type == X86_OP_MEM) {
            *out = (i64)((u64)x->operands[i].mem.disp & 0xFFFFFFFFu);
            return true;
        }
    return false;
}

/* word(va): the dword at va (a relocation's own target on our side), or none. */
static bool side_word(const CfgDiffSide *s, i64 va, i64 *out) {
    if (s->ours) {
        const DkVal *v = dk_imap_get(s->relocs, (u64)(va - (i64)s->base));
        if (v && side_own(s, v->p)) {
            *out = side_own_target(s, v->p);
            return true;
        }
        return false;
    }
    if (!s->image || va < 0 || va > 0xFFFFFFFFll) return false;
    DkStr w;
    if (!dk_image_read(s->image, (u32)va, 4, &w)) return false;
    u32 word;
    memcpy(&word, w.p, 4);
    *out = word;
    return true;
}

/* read_bytes(va, n): our code slice, or the game's bytes (b"" on any failure). */
static DkStr side_read_bytes(const CfgDiffSide *s, i64 va, i64 n) {
    if (s->ours) {
        i64 off = va - (i64)s->base;
        return off >= 0 ? slice_from(s->code, off, off + n) : dk_strn("", 0);
    }
    if (!s->image || n <= 0 || va < 0 || va > 0xFFFFFFFFll) return dk_strn("", 0);
    DkStr got;
    if (!dk_image_read(s->image, (u32)va, (size_t)n, &got)) return dk_strn("", 0);
    return got;
}

typedef enum { DT_INDIRECT, DT_IN, DT_OUT } DirectKind;

/* direct_target(ins): ('in', offset) for a jump inside the function, ('out', va) for one leaving it, None (DT_INDIRECT)
 * if indirect. */
static DirectKind side_direct_target(const CfgDiffSide *s, const cs_insn *ins, i64 *val) {
    i64 off = (i64)ins->address - (i64)s->base;
    u8 b0 = ins->bytes[0];
    if (!(b0 == 0xE9 || b0 == 0xEB || (b0 >= 0x70 && b0 <= 0x7F) || (b0 == 0x0F && ins->bytes[1] >= 0x80 && ins->bytes[1] <= 0x8F)))
        return DT_INDIRECT;
    if (s->ours) {
        DkPtrVec rs = cfg_diff_side_reloc_in(s, (u32)(off + 1), ins->size - 1);
        bool any = rs.n != 0;
        dk_vec_free(&rs);
        if (any) return DT_OUT;
    }
    u64 t;
    if (!dk_wall_target_of(ins, &t)) return DT_INDIRECT;
    if (inside_i(s, (i64)t)) {
        *val = (i64)t - (i64)s->base;
        return DT_IN;
    }
    *val = (i64)t;
    return DT_OUT;
}

typedef DK_VEC(const cs_insn *) InsnPtrVec;

/* switch_targets(side, ins, run): the targets (offsets) of `jmp dword ptr [reg*4 + X]`; false for None. run: the
 * instructions decoded before it, this one last. */
static bool switch_targets(CfgDiffSide *s, const cs_insn *ins, const InsnPtrVec *run, DkI64Vec *targets) {
    const cs_x86 *x = &ins->detail->x86;
    if (x->op_count != 1 || x->operands[0].type != X86_OP_MEM) return false;
    const x86_op_mem *mem = &x->operands[0].mem;
    if (mem->base != 0 || mem->scale != 4 || mem->index == 0) return false;
    i64 table;
    if (!side_ref_address(s, ins, &table)) return false;
    const char *index_reg = dk_dis_reg_name(dk_dis(DK_DIS_X86_32, DK_DIS_DETAIL), mem->index);
    if (!index_reg) dk_throw(DK_ERR_OTHER, "startswith first arg must be str or a tuple of str, not NoneType");
    bool has_bound = false, has_index_table = false;
    i64 bound = 0, index_table = 0;
    size_t lo = run->n > 6 ? run->n - 6 : 0, nlast = run->n - lo;
    const cs_insn *const *last = run->v + lo;
    for (size_t k = nlast; k-- > 0;) {
        const cs_insn *p = last[k];
        if (strcmp(p->mnemonic, "movzx") == 0 && !has_index_table && strncmp(p->op_str, index_reg, strlen(index_reg)) == 0 &&
            strstr(p->op_str, "byte ptr")) {
            has_index_table = side_ref_address(s, p, &index_table);
        }
        const cs_x86 *px = &p->detail->x86;
        if (strcmp(p->mnemonic, "cmp") == 0 && px->op_count == 2 && px->operands[1].type == X86_OP_IMM) {
            const cs_insn *nxt = k + 1 < nlast ? last[k + 1] : NULL;
            if (nxt && (strcmp(nxt->mnemonic, "ja") == 0 || strcmp(nxt->mnemonic, "jae") == 0 || strcmp(nxt->mnemonic, "jnbe") == 0)) {
                bound = px->operands[1].imm + (strcmp(nxt->mnemonic, "jae") != 0 ? 0 : -1);
                has_bound = true;
                break;
            }
        }
    }
    i64 count = 1024;
    if (has_index_table) {
        DkStr idx = side_read_bytes(s, index_table, has_bound ? bound + 1 : 256);
        if (idx.n) {
            u8 mx = 0;
            for (size_t i = 0; i < idx.n; i++) mx = DK_MAX(mx, (u8)idx.p[i]);
            count = (i64)mx + 1;
        }
    } else if (has_bound) {
        count = bound + 1;
    }
    for (i64 k = 0; k < DK_MIN(count, 1024); k++) {
        i64 t;
        if (!side_word(s, table + 4 * k, &t) || !inside_i(s, t)) break;
        dk_vec_push(targets, t - (i64)s->base);
    }
    dk_imap_put(s->tables, (u64)((i64)ins->address - (i64)s->base), NULL)->i = (i64)targets->n;
    return targets->n != 0;
}

static const cs_insn *ins_copy(const cs_insn *src) {
    cs_insn *d = dk_alloc_noz(A_, sizeof *d);
    *d = *src;
    if (src->detail) {
        cs_detail *dt = dk_alloc_noz(A_, sizeof *dt);
        *dt = *src->detail;
        d->detail = dt;
    }
    return d;
}

static bool is_stop_mnemonic(const char *m) {
    return strcmp(m, "ret") == 0 || strcmp(m, "retf") == 0 || strcmp(m, "int3") == 0 || strcmp(m, "hlt") == 0 ||
           strcmp(m, "ud2") == 0 || strcmp(m, "iretd") == 0;
}

/* The decoded instructions of one side: {offset: instruction}, the jump / table target offsets, the switch tables
 * {jmp offset: DkI64Vec* of case target offsets}. */
typedef struct Decoded {
    DkIMap *insns;
    DkISet *targets;
    DkIMap *cases;
} Decoded;

/* decode(side): {offset: instruction} by recursive descent, plus jump/table target offsets. */
static Decoded decode(CfgDiffSide *s) {
    DkDis *md = dk_dis(DK_DIS_X86_32, DK_DIS_DETAIL);
    Decoded d = {dk_imap_new(), dk_iset_new(), dk_imap_new()};
    DkI64Vec work = {0};
    dk_vec_push(&work, 0);
    while (work.n) {
        i64 start = dk_vec_pop(&work);
        if (dk_imap_has(d.insns, (u64)start) || !(0 <= start && start < (i64)s->extent)) continue;
        InsnPtrVec run = {0};
        DkStr code = slice_from(s->code, start, (i64)s->extent);
        DkDisIter it;
        dk_dis_iter(&it, md, code.p, code.n, (u64)s->base + (u64)start, 0);
        while (dk_dis_next(&it)) {
            i64 off = (i64)it.insn->address - (i64)s->base;
            if (dk_imap_has(d.insns, (u64)off)) {
                dk_dis_iter_end(&it);
                break;
            }
            const cs_insn *ins = ins_copy(it.insn);
            dk_imap_put(d.insns, (u64)off, NULL)->p = (void *)ins;
            dk_vec_push(&run, ins);
            const char *m = ins->mnemonic;
            if (is_stop_mnemonic(m)) {
                dk_dis_iter_end(&it);
                break;
            }
            if (strcmp(m, "jmp") == 0) {
                i64 t = 0;
                DirectKind k = side_direct_target(s, ins, &t);
                if (k == DT_IN) {
                    dk_iset_add(d.targets, (u64)t);
                    dk_vec_push(&work, t);
                } else if (k == DT_INDIRECT) {
                    DkI64Vec *tl = DK_NEW(A_, DkI64Vec);
                    if (switch_targets(s, ins, &run, tl)) {
                        dk_imap_put(d.cases, (u64)off, NULL)->p = tl;
                        for (size_t i = 0; i < tl->n; i++) {
                            dk_iset_add(d.targets, (u64)tl->v[i]);
                            dk_vec_push(&work, tl->v[i]);
                        }
                    }
                }
                dk_dis_iter_end(&it);
                break;
            }
            if (is_jcc(m)) {
                i64 t = 0;
                if (side_direct_target(s, ins, &t) == DT_IN) {
                    dk_iset_add(d.targets, (u64)t);
                    dk_vec_push(&work, t);
                }
            }
        }
        dk_vec_free(&run);
    }
    if (!dk_imap_len(d.insns)) { /* linear fallback */
        DkStr code = slice_from(s->code, 0, (i64)s->extent);
        DkDisIter it;
        dk_dis_iter(&it, md, code.p, code.n, s->base, 0);
        while (dk_dis_next(&it)) {
            const cs_insn *ins = ins_copy(it.insn);
            dk_imap_put(d.insns, (u64)((i64)ins->address - (i64)s->base), NULL)->p = (void *)ins;
        }
    }
    dk_vec_free(&work);
    return d;
}

/* terminates(ins, cases) */
static bool terminates(const cs_insn *ins) {
    const char *m = ins->mnemonic;
    return is_stop_mnemonic(m) || strcmp(m, "jmp") == 0 || is_jcc(m);
}

/* Per-block forms the similarity compares (CfgDiffBlock.priv_). */
typedef struct BlockPriv {
    DkMap *calls_cnt;  /* Counter(calls_sim) */
    u32 calls_total;
    DkStr *ops_s;      /* ops as views, for difflib */
    DkStr *sim_s;      /* calls_sim as views */
    u32 globals_total;  /* sum(globals.values()) */
    u32 consts_total;
} BlockPriv;
static BlockPriv *bpriv(const CfgDiffBlock *b) { return b->priv_; }

i32 cfg_diff_block_succ_role(const CfgDiffBlock *b, const char *role) {
    for (size_t i = 0; i < b->succ.n; i++)
        if (strcmp(b->succ.v[i].role, role) == 0) return b->succ.v[i].to;
    return -1;
}

DkI32Vec cfg_diff_block_successors(const CfgDiffBlock *b) {
    DkI32Vec out = {0};
    for (size_t i = 0; i < b->succ.n; i++)
        if (b->succ.v[i].to >= 0) dk_vec_push(&out, b->succ.v[i].to);
    return out;
}

static bool vec_has(const DkI32Vec *v, i32 x) {
    for (size_t i = 0; i < v->n; i++)
        if (v->v[i] == x) return true;
    return false;
}

static bool succ_has(const CfgDiffBlock *b, i32 x) {
    for (size_t i = 0; i < b->succ.n; i++)
        if (b->succ.v[i].to == x && x >= 0) return true;
    return false;
}

static size_t n_successors(const CfgDiffBlock *b) {
    size_t n = 0;
    for (size_t i = 0; i < b->succ.n; i++) n += b->succ.v[i].to >= 0;
    return n;
}

/* operand_tokens(side, ins): the globals and constants of one instruction. */
static void operand_tokens(const CfgDiffSide *s, const cs_insn *ins, DkCzVec *glob, DkCzVec *cnst) {
    i64 off = (i64)ins->address - (i64)s->base;
    u8 b0 = ins->bytes[0];
    if (b0 == 0xE8 || b0 == 0xE9 || b0 == 0xEB || (b0 >= 0x70 && b0 <= 0x7F) ||
        (b0 == 0x0F && ins->bytes[1] >= 0x80 && ins->bytes[1] <= 0x8F))
        return;
    DkI64Vec consumed = {0};
    if (s->ours) {
        DkPtrVec rs = cfg_diff_side_reloc_in(s, (u32)off, ins->size);
        for (size_t i = 0; i < rs.n; i++) {
            const DkReloc *r = rs.v[i];
            dk_vec_push(&consumed, (i64)r->offset - off);
            if (side_own(s, r)) continue;
            const DkVal *vv = dk_imap_get(s->verdicts, r->offset);
            const DkRefCheck *v = vv ? vv->p : NULL;
            if (v && v->verdict != DK_REF_UNRESOLVED) {
                dk_vec_push(glob, (char *)PF("0x%X", v->ours));
            } else if (v) {
                dk_vec_push(glob, (char *)PF("sym:%s", v->name ? v->name : "?"));
            } else {
                dk_vec_push(glob, (char *)PF("sym:%s", r->symbol ? r->symbol : "?"));
            }
        }
        dk_vec_free(&rs);
    }
    const cs_x86 *x = &ins->detail->x86;
    for (int i = 0; i < x->op_count; i++) {
        const cs_x86_op *op = &x->operands[i];
        i64 field, value;
        if (op->type == X86_OP_IMM) {
            field = x->encoding.imm_offset;
            value = (i64)((u64)op->imm & 0xFFFFFFFFu);
        } else if (op->type == X86_OP_MEM) {
            if (op->mem.base == X86_REG_ESP || op->mem.base == X86_REG_EBP || op->mem.disp == 0) continue;
            field = x->encoding.disp_offset;
            value = (i64)((u64)op->mem.disp & 0xFFFFFFFFu);
        } else {
            continue;
        }
        if (s->ours) {
            bool hit = false;
            for (size_t k = 0; k < consumed.n; k++) hit |= consumed.v[k] == field;
            if (hit) continue;
        }
        if (!s->ours && value >= 0x400000 && s->image && dk__image_section_end(s->image, (u32)value)) {
            if (!inside_i(s, value)) dk_vec_push(glob, (char *)PF("0x%X", value));
            continue;
        }
        dk_vec_push(cnst, (char *)PF("%d", value & 0x80000000ll ? value - (1ll << 32) : value));
    }
    dk_vec_free(&consumed);
}

static void counter_add(DkMap *m, const char *text) {
    dk_map_put(m, dk_str(text), NULL)->i += 1;
}

/* features(side, b) */
static void features(const CfgDiffSide *s, CfgDiffBlock *b) {
    for (size_t k = 0; k < b->insns.n; k++) {
        const cs_insn *ins = b->insns.v[k];
        const char *m = ins->mnemonic;
        DkCallToken tok;
        if (dk_wall_call_token(ins, s->base, s->ours ? s->verdicts : NULL, s->extent, &tok)) {
            const char *t = dk_cz(A_, dk_wall_tok_text(A_, &tok));
            if (strncmp(t, "tail:", 5) == 0) b->tail = t + 5;
            dk_vec_push(&b->calls, (char *)t);
            dk_vec_push(&b->calls_sim, (char *)(strncmp(t, "tail:", 5) == 0 ? t + 5 : t));
        }
        DkCzVec g = {0}, c = {0};
        operand_tokens(s, ins, &g, &c);
        for (size_t i = 0; i < g.n; i++) counter_add(b->globals, g.v[i]);
        for (size_t i = 0; i < c.n; i++) counter_add(b->consts, c.v[i]);
        dk_vec_free(&g);
        dk_vec_free(&c);
        if (strcmp(m, "ret") == 0 || strcmp(m, "retf") == 0) b->has_ret = true;
        if (!dk_wall_is_move(m) && strcmp(m, "jmp") != 0 && !is_jcc(m) && strcmp(m, "int3") != 0 && strcmp(m, "nop") != 0)
            dk_vec_push(&b->ops, (char *)m);
    }
    if (strcmp(b->term, "jcc") == 0 && b->insns.n >= 2) {
        for (size_t k = b->insns.n - 1; k-- > 0;) {
            const cs_insn *ins = b->insns.v[k];
            if (IN_LIST(FLAGS, ins->mnemonic)) {
                b->has_cmp = true;
                b->cmp_m = ins->mnemonic;
                b->cmp_ops = ins->op_str;
                break;
            }
        }
    }
}

static u32 counter_total(const DkMap *m) {
    u32 t = 0;
    DkMapIter it = {0};
    while (dk_map_next(m, &it)) t += (u32)it.val->i;
    return t;
}

/* The multiset forms of a block, computed once its features are final (resolve_literals replaces globals later:
 * refresh_priv recomputes the totals). */
static void refresh_priv(CfgDiffBlock *b) {
    BlockPriv *p = b->priv_;
    if (!p) {
        p = b->priv_ = DK_NEW(A_, BlockPriv);
        p->calls_cnt = dk_map_new();
        for (size_t i = 0; i < b->calls_sim.n; i++) counter_add(p->calls_cnt, b->calls_sim.v[i]);
        p->calls_total = (u32)b->calls_sim.n;
        p->ops_s = DK_NEWN(A_, DkStr, b->ops.n + 1);
        for (size_t i = 0; i < b->ops.n; i++) p->ops_s[i] = dk_str(b->ops.v[i]);
        p->sim_s = DK_NEWN(A_, DkStr, b->calls_sim.n + 1);
        for (size_t i = 0; i < b->calls_sim.n; i++) p->sim_s[i] = dk_str(b->calls_sim.v[i]);
    }
    p->globals_total = counter_total(b->globals);
    p->consts_total = counter_total(b->consts);
}

static CfgDiffBlock *block_new(i32 idx, u32 start) {
    CfgDiffBlock *b = DK_NEW(A_, CfgDiffBlock);
    b->idx = b->layout = idx;
    b->start = b->end = start;
    b->globals = dk_map_new();
    b->consts = dk_map_new();
    b->table = -1;
    return b;
}

static int cmp_i64_v(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    return dk_cmp_i64(*(const i64 *)x, *(const i64 *)y);
}

/* build_blocks(side): the blocks of a decoded side, edges, predecessors and features. */
void cfg_diff_build_blocks(CfgDiffSide *s) {
    Decoded d = decode(s);
    DkISet *leaders = dk_iset_new();
    dk_iset_add(leaders, 0);
    {
        size_t pos = 0;
        u64 t;
        while (dk_iset_next(d.targets, &pos, &t)) dk_iset_add(leaders, t);
    }
    DkI64Vec offs = {0};
    {
        DkIMapIter it = {0};
        while (dk_imap_next(d.insns, &it)) dk_vec_push(&offs, (i64)it.key);
    }
    dk_sort(offs.v, offs.n, sizeof(i64), cmp_i64_v, NULL, false);
    for (size_t i = 0; i < offs.n; i++) {
        const cs_insn *ins = dk_imap_get(d.insns, (u64)offs.v[i])->p;
        if (terminates(ins)) dk_iset_add(leaders, (u64)(offs.v[i] + ins->size));
    }
    CfgDiffBlock *cur = NULL;
    i64 cur_end = 0;
    for (size_t i = 0; i < offs.n; i++) {
        i64 o = offs.v[i];
        const cs_insn *ins = dk_imap_get(d.insns, (u64)o)->p;
        if (!cur || dk_iset_has(leaders, (u64)o) || o != cur_end) {
            cur = block_new((i32)s->blocks.n, (u32)o);
            dk_vec_push(&s->blocks, cur);
        }
        dk_vec_push(&cur->insns, ins);
        cur_end = o + ins->size;
        cur->end = (u32)cur_end;
        if (terminates(ins)) cur = NULL;
    }
    dk_imap_clear(s->at);
    for (size_t i = 0; i < s->blocks.n; i++) dk_imap_put(s->at, s->blocks.v[i]->start, NULL)->i = s->blocks.v[i]->idx;
#define AT_GET(x, out)                                         \
    do {                                                       \
        const DkVal *av_ = dk_imap_get(s->at, (u64)(x));     \
        (out) = av_ ? (i32)av_->i : -1;                        \
    } while (0)
    for (size_t bi = 0; bi < s->blocks.n; bi++) {
        CfgDiffBlock *b = s->blocks.v[bi];
        const cs_insn *last = b->insns.v[b->insns.n - 1];
        const char *m = last->mnemonic;
        i64 off = (i64)last->address - (i64)s->base;
        if (strcmp(m, "ret") == 0 || strcmp(m, "retf") == 0 || strcmp(m, "iretd") == 0) {
            b->term = "ret";
        } else if (strcmp(m, "int3") == 0 || strcmp(m, "hlt") == 0 || strcmp(m, "ud2") == 0) {
            b->term = "trap";
        } else if (strcmp(m, "jmp") == 0) {
            i64 t = 0;
            DirectKind k = side_direct_target(s, last, &t);
            const DkVal *cv = dk_imap_get(d.cases, (u64)off);
            if (cv) {
                const DkI64Vec *tl = cv->p;
                b->term = "switch";
                DkI64Vec seen = {0};
                for (size_t i = 0; i < tl->n; i++) {
                    bool dup = false;
                    for (size_t j = 0; j < seen.n; j++) dup |= seen.v[j] == tl->v[i];
                    if (dup) continue;
                    dk_vec_push(&seen, tl->v[i]);
                    i32 to;
                    AT_GET(tl->v[i], to);
                    dk_vec_push(&b->succ, ((CfgDiffEdge){"case", to}));
                }
                dk_vec_free(&seen);
                b->table = (i32)tl->n;
            } else if (k == DT_IN) {
                b->term = "jmp";
                i32 to;
                AT_GET(t, to);
                dk_vec_push(&b->succ, ((CfgDiffEdge){"taken", to}));
            } else {
                b->term = "tail";
            }
        } else if (is_jcc(m)) {
            b->term = "jcc";
            b->cond = cond_of(m);
            i64 t = 0;
            DirectKind k = side_direct_target(s, last, &t);
            i32 taken = -1, fall;
            if (k == DT_IN) AT_GET(t, taken);
            AT_GET(b->end, fall);
            dk_vec_push(&b->succ, ((CfgDiffEdge){"taken", taken}));
            dk_vec_push(&b->succ, ((CfgDiffEdge){"fall", fall}));
        } else {
            i32 nxt;
            AT_GET(b->end, nxt);
            if (nxt >= 0) {
                b->term = "fall";
                dk_vec_push(&b->succ, ((CfgDiffEdge){"fall", nxt}));
            } else {
                b->term = "stop";
            }
        }
    }
#undef AT_GET
    for (size_t bi = 0; bi < s->blocks.n; bi++) {
        const CfgDiffBlock *b = s->blocks.v[bi];
        for (size_t i = 0; i < b->succ.n; i++) {
            i32 t = b->succ.v[i].to;
            if (t < 0) continue;
            DkI32Vec *pr = &s->blocks.v[t]->preds;
            if (!vec_has(pr, b->idx)) dk_vec_push(pr, b->idx);
        }
    }
    for (size_t bi = 0; bi < s->blocks.n; bi++) {
        features(s, s->blocks.v[bi]);
        refresh_priv(s->blocks.v[bi]);
    }
    dk_vec_free(&offs);
}

/* ---------------------------------------------------------------- similarity and alignment */

/* jaccard(a, b) of two Counters (totals: sum of the counts). */
static double jaccard_maps(const DkMap *a, const DkMap *b, u32 ta, u32 tb) {
    if (!dk_map_len(a) && !dk_map_len(b)) return 0.5;
    u32 inter = 0;
    DkMapIter it = {0};
    while (dk_map_next(a, &it)) {
        const DkVal *o = dk_map_get(b, it.key);
        if (o) inter += (u32)DK_MIN(it.val->i, o->i);
    }
    u32 uni = ta + tb - inter;
    return uni ? (double)inter / (double)uni : 0.5;
}

/* Counter equality (the counts are positive, so missing equals zero). */
static bool counter_eq(const DkMap *a, const DkMap *b) {
    if (dk_map_len(a) != dk_map_len(b)) return false;
    DkMapIter it = {0};
    while (dk_map_next(a, &it)) {
        const DkVal *o = dk_map_get(b, it.key);
        if (!o || o->i != it.val->i) return false;
    }
    return true;
}

/* ratio(a, b) of two opcode lists. */
static double ops_ratio(const CfgDiffBlock *a, const CfgDiffBlock *b) {
    if (!a->ops.n && !b->ops.n) return 1.0;
    return dk_ratio_str(bpriv(a)->ops_s, a->ops.n, bpriv(b)->ops_s, b->ops.n, false);
}

/* content(o, g) */
static double content(const CfgDiffBlock *o, const CfgDiffBlock *g) {
    const BlockPriv *po = bpriv(o), *pg = bpriv(g);
    double j1 = jaccard_maps(po->calls_cnt, pg->calls_cnt, po->calls_total, pg->calls_total);
    double j2 = jaccard_maps(o->globals, g->globals, po->globals_total, pg->globals_total);
    double j3 = jaccard_maps(o->consts, g->consts, po->consts_total, pg->consts_total);
    double r = ops_ratio(o, g);
    return 3 * j1 + 2 * j2 + j3 + 2 * r;
}

/* _cmp_operands(b): the two operands of a `cmp`, false for None. */
static bool cmp_operands(const CfgDiffBlock *b, DkStr parts[2]) {
    if (!b->has_cmp || strcmp(b->cmp_m, "cmp") != 0) return false;
    DkStrVec v = dk_str_split(dk_str(b->cmp_ops), DK_S(","), -1);
    bool ok = v.n == 2;
    if (ok) {
        parts[0] = dk_str_strip(v.v[0]);
        parts[1] = dk_str_strip(v.v[1]);
    }
    dk_vec_free(&v);
    return ok;
}

/* _kind(text): "imm" for re.match(r"^-?(0x[0-9a-f]+|\d+)$"), else "mem" with a "[", else "reg". */
static const char *kind_of(DkStr t) {
    size_t i = 0;
    if (i < t.n && t.p[i] == '-') i++;
    bool imm = false;
    if (i + 2 < t.n + 0 && t.p[i] == '0' && t.p[i + 1] == 'x') {
        size_t j = i + 2;
        while (j < t.n && ((t.p[j] >= '0' && t.p[j] <= '9') || (t.p[j] >= 'a' && t.p[j] <= 'f'))) j++;
        imm = j == t.n && j > i + 2;
    }
    if (!imm && i < t.n) {
        size_t j = i;
        while (j < t.n && t.p[j] >= '0' && t.p[j] <= '9') j++;
        imm = j == t.n;
    }
    if (imm) return "imm";
    return memchr(t.p, '[', t.n) ? "mem" : "reg";
}

/* relation(ob, gb): same / inverted / mirrored / inv+mir / other, for two jcc blocks. */
static const char *relation(const CfgDiffBlock *ob, const CfgDiffBlock *gb) {
    const char *co = ob->cond, *cg = gb->cond;
    if (opt_eq(co, cg)) return "same";
    if (NEG_GET(co) && opt_eq(NEG_GET(co), cg)) return "inverted";
    DkStr po[2], pg[2];
    bool hpo = cmp_operands(ob, po), hpg = cmp_operands(gb, pg);
    static const char *const COMI[] = {"comiss", "ucomiss", "comisd", "ucomisd"};
    bool swapped = (hpo && hpg) || (ob->has_cmp && gb->has_cmp && IN_LIST(COMI, ob->cmp_m) && strcmp(gb->cmp_m, ob->cmp_m) == 0);
    if (hpo && hpg) {
        const char *ko0 = kind_of(po[0]), *ko1 = kind_of(po[1]), *kg0 = kind_of(pg[0]), *kg1 = kind_of(pg[1]);
        if (strcmp(ko0, kg0) == 0 && strcmp(ko1, kg1) == 0 && strcmp(ko0, ko1) != 0) swapped = false;
        if (dk_str_eq(po[0], pg[0]) && dk_str_eq(po[1], pg[1])) swapped = false;
    }
    if (swapped && MIRROR_GET(co) && opt_eq(MIRROR_GET(co), cg)) return "mirrored";
    if (swapped && MIRROR_GET(co) && NEG_GET(MIRROR_GET(co)) && opt_eq(NEG_GET(MIRROR_GET(co)), cg)) return "inv+mir";
    return "other";
}

/* The alignment's working state (CfgDiffAlign.priv_). Block numbers are the ours / game indices; -1 is None. */
typedef struct AlignS {
    const CfgDiffSide *O, *G;
    i32 no, ng;
    i32 *mo, *mg;               /* ours idx -> game idx, game idx -> ours idx */
    double *score;
    const char **how, **rel;
    i32 *copy_o, *copy_g;
    DkI32Vec order;            /* ours idx in the order add() mapped them (the insertion order of mo) */
    double *cmemo;              /* the content memo (_content), valid where chas */
    u8 *chas;
    i32 *mark_o, *mark_g;       /* neighbour marks with their tokens (the sets of nbr) */
    i32 tok_o, tok_g;
} AlignS;

static const CfgDiffBlock *OB(const AlignS *al, i32 i) { return al->O->blocks.v[i]; }
static const CfgDiffBlock *GB(const AlignS *al, i32 i) { return al->G->blocks.v[i]; }

static double al_c(AlignS *al, i32 o, i32 g) {
    size_t k = (size_t)o * (size_t)al->ng + (size_t)g;
    if (!al->chas[k]) {
        al->cmemo[k] = content(OB(al, o), GB(al, g));
        al->chas[k] = 1;
    }
    return al->cmemo[k];
}

/* nbr(o, g): the share of ours' mapped neighbours (successors and predecessors) whose image is a neighbour of g. */
static double al_nbr(AlignS *al, i32 o, i32 g) {
    const CfgDiffBlock *gb = GB(al, g), *ob = OB(al, o);
    i32 tg = ++al->tok_g, to = ++al->tok_o;
    for (size_t i = 0; i < gb->succ.n; i++)
        if (gb->succ.v[i].to >= 0) al->mark_g[gb->succ.v[i].to] = tg;
    for (size_t i = 0; i < gb->preds.n; i++) al->mark_g[gb->preds.v[i]] = tg;
    int mapped = 0, hit = 0;
    for (size_t i = 0; i < ob->succ.n + ob->preds.n; i++) {
        i32 n = i < ob->succ.n ? ob->succ.v[i].to : ob->preds.v[i - ob->succ.n];
        if (n < 0 || al->mark_o[n] == to) continue;
        al->mark_o[n] = to;
        if (al->mo[n] >= 0) {
            mapped++;
            if (al->mark_g[al->mo[n]] == tg) hit++;
        }
    }
    if (!mapped) return 0.0;
    return (double)hit / (double)mapped;
}

static double al_sim(AlignS *al, i32 o, i32 g) { return al_c(al, o, g) + al_nbr(al, o, g); }

static void al_add(AlignS *al, i32 o, i32 g, const char *how) {
    al->mo[o] = g;
    al->mg[g] = o;
    dk_vec_push(&al->order, o);
    al->score[o] = dk_py_round(al_sim(al, o, g), 2);
    al->how[o] = how;
    const CfgDiffBlock *ob = OB(al, o), *gb = GB(al, g);
    if (strcmp(ob->term, "jcc") == 0 && strcmp(gb->term, "jcc") == 0) al->rel[o] = relation(ob, gb);
}

static bool al_free(const AlignS *al, i32 o, i32 g) { return o >= 0 && g >= 0 && al->mo[o] < 0 && al->mg[g] < 0; }

typedef struct RolePair {
    i32 x, y;
    bool sure;
} RolePair;
typedef DK_VEC(RolePair) RolePairVec;

/* role_pairs(o, g): [(ours, game, sure)] proposed by the edges of a mapped pair: successors by role, then predecessors. */
static void al_role_pairs(AlignS *al, i32 o, i32 g, RolePairVec *out) {
    const CfgDiffBlock *ob = OB(al, o), *gb = GB(al, g);
    RolePairVec raw = {0};
#define PUSHP(X, Y, S) dk_vec_push(&raw, ((RolePair){(X), (Y), (S)}))
    if (strcmp(ob->term, "jcc") == 0 && strcmp(gb->term, "jcc") == 0) {
        const char *r = relation(ob, gb);
        i32 ot = cfg_diff_block_succ_role(ob, "taken"), of = cfg_diff_block_succ_role(ob, "fall");
        i32 gt = cfg_diff_block_succ_role(gb, "taken"), gf = cfg_diff_block_succ_role(gb, "fall");
        if (strcmp(r, "same") == 0 || strcmp(r, "mirrored") == 0) {
            PUSHP(ot, gt, true);
            PUSHP(of, gf, true);
        } else if (strcmp(r, "inverted") == 0 || strcmp(r, "inv+mir") == 0) {
            PUSHP(ot, gf, true);
            PUSHP(of, gt, true);
        } else {
            PUSHP(ot, gt, false);
            PUSHP(of, gf, false);
            PUSHP(ot, gf, false);
            PUSHP(of, gt, false);
        }
    } else if (n_successors(ob) == 1 && n_successors(gb) == 1) {
        DkI32Vec so = cfg_diff_block_successors(ob), sg = cfg_diff_block_successors(gb);
        PUSHP(so.v[0], sg.v[0], true);
        dk_vec_free(&so);
        dk_vec_free(&sg);
    } else {
        /* set order -- set(successors) x set(successors); the heap orders its entries totally, so the order of
         * the proposals does not reach the result. */
        DkI32Vec so = cfg_diff_block_successors(ob), sg = cfg_diff_block_successors(gb), uo = {0}, ug = {0};
        for (size_t i = 0; i < so.n; i++)
            if (!vec_has(&uo, so.v[i])) dk_vec_push(&uo, so.v[i]);
        for (size_t i = 0; i < sg.n; i++)
            if (!vec_has(&ug, sg.v[i])) dk_vec_push(&ug, sg.v[i]);
        for (size_t i = 0; i < uo.n; i++)
            for (size_t j = 0; j < ug.n; j++) PUSHP(uo.v[i], ug.v[j], false);
        dk_vec_free(&so);
        dk_vec_free(&sg);
        dk_vec_free(&uo);
        dk_vec_free(&ug);
    }
    if (ob->preds.n == 1 && gb->preds.n == 1) {
        PUSHP(ob->preds.v[0], gb->preds.v[0], true);
    } else {
        for (size_t i = 0; i < ob->preds.n; i++)
            for (size_t j = 0; j < gb->preds.n; j++) PUSHP(ob->preds.v[i], gb->preds.v[j], false);
    }
#undef PUSHP
    for (size_t i = 0; i < raw.n; i++)
        if (raw.v[i].x >= 0 && raw.v[i].y >= 0) dk_vec_push(out, raw.v[i]);
    dk_vec_free(&raw);
}

/* cs(o, g): content plus agreement of the terminators (a tie-break among look-alike blocks). */
static double al_cs(AlignS *al, i32 o, i32 g) {
    const CfgDiffBlock *ob = OB(al, o), *gb = GB(al, g);
    double bonus = strcmp(ob->term, gb->term) == 0 ? 0.5 : 0.0;
    if (strcmp(ob->term, gb->term) == 0 && strcmp(ob->term, "jcc") == 0 && strcmp(relation(ob, gb), "other") == 0) bonus = 0.0;
    return al_c(al, o, g) + bonus;
}

typedef struct HeapItem {
    double ns;      /* -score */
    u32 so, sg;     /* the blocks' start offsets */
    i32 x, y;
} HeapItem;
typedef DK_VEC(HeapItem) HeapVec;

static int heap_cmp(const void *a, const void *b, void *ctx) {
    DK_UNUSED(ctx);
    const HeapItem *p = a, *q = b;
    if (p->ns != q->ns) return p->ns < q->ns ? -1 : 1;
    if (p->so != q->so) return p->so < q->so ? -1 : 1;
    if (p->sg != q->sg) return p->sg < q->sg ? -1 : 1;
    if (p->x != q->x) return p->x < q->x ? -1 : 1;
    return (p->y > q->y) - (p->y < q->y);
}

#define PROP_FLOOR CFG_DIFF_PROP_FLOOR
#define SIM_FLOOR CFG_DIFF_SIM_FLOOR

typedef struct Seed {
    i32 o, g;
} Seed;
typedef DK_VEC(Seed) SeedVec;

static void al_push(AlignS *al, HeapVec *heap, i32 o, i32 g) {
    RolePairVec rp = {0};
    al_role_pairs(al, o, g, &rp);
    for (size_t i = 0; i < rp.n; i++) {
        i32 x = rp.v[i].x, y = rp.v[i].y;
        bool sure = rp.v[i].sure;
        if (!al_free(al, x, y)) continue;
        double s = al_cs(al, x, y) + al_nbr(al, x, y) + (sure ? 0.5 : 0.0);
        if (s >= PROP_FLOOR + (sure ? 0.5 : 1.5)) {
            HeapItem it = {-s, OB(al, x)->start, GB(al, y)->start, x, y};
            dk_vec_reserve(heap, heap->n + 1);
            dk_heap_push(heap->v, &heap->n, sizeof(HeapItem), &it, heap_cmp, NULL);
        }
    }
    dk_vec_free(&rp);
}

/* propagate(seeds): best-first along the edges: the most similar pair proposed by any mapped pair is accepted first. A
 * pair proposed by its role (one successor each, the same or a negated condition) needs PROP_FLOOR, a guess among
 * several candidates PROP_FLOOR + 1.5. */
static void al_propagate(AlignS *al, const SeedVec *seeds) {
    HeapVec heap = {0};
    for (size_t i = 0; i < seeds->n; i++) al_push(al, &heap, seeds->v[i].o, seeds->v[i].g);
    while (heap.n) {
        HeapItem it;
        dk_heap_pop(heap.v, &heap.n, sizeof(HeapItem), &it, heap_cmp, NULL);
        if (!al_free(al, it.x, it.y)) continue;
        al_add(al, it.x, it.y, "edge");
        al_push(al, &heap, it.x, it.y);
    }
    dk_vec_free(&heap);
}

typedef struct Cand {
    double s;
    i32 d, o, g;
} Cand;

static int cand_cmp(const void *a, const void *b, void *ctx) {
    DK_UNUSED(ctx);
    const Cand *p = a, *q = b;
    if (p->s != q->s) return p->s > q->s ? -1 : 1; /* -s ascending */
    if (p->d != q->d) return p->d < q->d ? -1 : 1;
    if (p->o != q->o) return p->o < q->o ? -1 : 1;
    return (p->g > q->g) - (p->g < q->g);
}

/* similarity(): the unmatched pairs scoring SIM_FLOOR or more, best first (ties: nearer start offsets, then indices). */
static void al_similarity(AlignS *al, SeedVec *out) {
    DK_VEC(Cand) cand = {0};
    for (i32 o = 0; o < al->no; o++) {
        if (al->mo[o] >= 0) continue;
        for (i32 g = 0; g < al->ng; g++) {
            if (al->mg[g] >= 0) continue;
            double s = al_sim(al, o, g);
            if (s >= SIM_FLOOR) {
                i32 d = (i32)OB(al, o)->start - (i32)GB(al, g)->start;
                Cand c = {s, d < 0 ? -d : d, o, g};
                dk_vec_push(&cand, c);
            }
        }
    }
    dk_sort(cand.v, cand.n, sizeof(Cand), cand_cmp, NULL, false);
    for (size_t i = 0; i < cand.n; i++)
        if (al_free(al, cand.v[i].o, cand.v[i].g)) {
            al_add(al, cand.v[i].o, cand.v[i].g, "sim");
            dk_vec_push(out, ((Seed){cand.v[i].o, cand.v[i].g}));
        }
    dk_vec_free(&cand);
}

/* sig(b) as a key: (tuple(calls_sim), tuple(sorted(globals.elements()))). */
static DkStr sig_key(const CfgDiffBlock *b) {
    DkBuf buf;
    dk_buf_init(&buf, A_);
    dk_buf_printf(&buf, "%zu", b->calls_sim.n);
    for (size_t i = 0; i < b->calls_sim.n; i++) {
        dk_buf_putc(&buf, '\x1f');
        dk_buf_putz(&buf, b->calls_sim.v[i]);
    }
    dk_buf_putc(&buf, '\x1e');
    DkStrVec keys = dk_map_keys(b->globals);
    dk_sort_strs(keys.v, keys.n);
    for (size_t i = 0; i < keys.n; i++) {
        i64 n = dk_map_get(b->globals, keys.v[i])->i;
        for (i64 k = 0; k < n; k++) {
            dk_buf_putc(&buf, '\x1f');
            dk_buf_put(&buf, keys.v[i]);
        }
    }
    dk_vec_free(&keys);
    return dk_buf_str(&buf);
}

static bool substantial(const CfgDiffBlock *b) {
    return b->ops.n >= 3 || b->calls.n || dk_map_len(b->globals) || b->has_ret;
}

/* twin(b, other, mapped): the mapped block of the other side with the same calls, globals, constants and terminator and
 * near-identical opcodes (ratio >= 0.8), or -1. */
static i32 al_twin(const CfgDiffBlock *b, const CfgDiffSide *other, const i32 *mapped) {
    double best_r = 0;
    i32 best = -1;
    for (size_t k = 0; k < other->blocks.n; k++) {
        const CfgDiffBlock *x = other->blocks.v[k];
        if (mapped[x->idx] < 0) continue;
        if (!counter_eq(bpriv(x)->calls_cnt, bpriv(b)->calls_cnt) || !counter_eq(x->globals, b->globals) ||
            !counter_eq(x->consts, b->consts) || strcmp(x->term, b->term) != 0)
            continue;
        size_t d = x->ops.n > b->ops.n ? x->ops.n - b->ops.n : b->ops.n - x->ops.n;
        if (d > DK_MAX((size_t)1, b->ops.n / 4)) continue;
        double r = ops_ratio(b, x);
        if (best < 0 || r >= best_r) { /* max() of (ratio, idx): the later index wins a tie */
            best_r = r;
            best = x->idx;
        }
    }
    return best >= 0 && best_r >= 0.8 ? best : -1;
}

/* copies(): an unmatched block whose content equals a matched block of the other side and whose opcodes are
 * near-identical is a copy: duplicated on its own side. */
static void al_copies(AlignS *al) {
    for (i32 o = 0; o < al->no; o++)
        if (al->mo[o] < 0 && substantial(OB(al, o))) al->copy_o[o] = al_twin(OB(al, o), al->G, al->mg);
    for (i32 g = 0; g < al->ng; g++)
        if (al->mg[g] < 0 && substantial(GB(al, g))) al->copy_g[g] = al_twin(GB(al, g), al->O, al->mo);
}

static void al_run(AlignS *al) {
    bool both = al->no && al->ng;
    if (both) al_add(al, 0, 0, "entry");
    DkMap *so = dk_map_new(), *sg = dk_map_new(), *by_g = dk_map_new();
    DkStr *sigs_o = DK_NEWN(A_, DkStr, al->no + 1), *sigs_g = DK_NEWN(A_, DkStr, al->ng + 1);
    for (i32 i = 0; i < al->no; i++) {
        sigs_o[i] = sig_key(OB(al, i));
        dk_map_put(so, sigs_o[i], NULL)->i += 1;
    }
    for (i32 i = 0; i < al->ng; i++) {
        sigs_g[i] = sig_key(GB(al, i));
        dk_map_put(sg, sigs_g[i], NULL)->i += 1;
    }
    for (i32 i = 0; i < al->ng; i++)
        if (dk_map_get(sg, sigs_g[i])->i == 1) dk_map_put(by_g, sigs_g[i], NULL)->i = i;
    SeedVec seeds = {0};
    if (both) dk_vec_push(&seeds, ((Seed){0, 0}));
    for (i32 i = 0; i < al->no; i++) {
        const CfgDiffBlock *b = OB(al, i);
        const DkVal *g = dk_map_get(by_g, sigs_o[i]);
        if ((b->calls_sim.n || dk_map_len(b->globals)) && dk_map_get(so, sigs_o[i])->i == 1 && g && al_free(al, i, (i32)g->i)) {
            al_add(al, i, (i32)g->i, "anchor");
            dk_vec_push(&seeds, ((Seed){i, (i32)g->i}));
        }
    }
    al_propagate(al, &seeds);
    for (int round = 0; round < 3; round++) {
        SeedVec fresh = {0};
        al_similarity(al, &fresh);
        if (!fresh.n) {
            dk_vec_free(&fresh);
            break;
        }
        al_propagate(al, &fresh);
        dk_vec_free(&fresh);
    }
    dk_vec_free(&seeds);
    al_copies(al);
}

static AlignS *align_new(const CfgDiffSide *ours, const CfgDiffSide *game) {
    AlignS *al = DK_NEW(A_, AlignS);
    al->O = ours;
    al->G = game;
    al->no = (i32)ours->blocks.n;
    al->ng = (i32)game->blocks.n;
    al->mo = DK_NEWN(A_, i32, al->no + 1);
    al->mg = DK_NEWN(A_, i32, al->ng + 1);
    al->copy_o = DK_NEWN(A_, i32, al->no + 1);
    al->copy_g = DK_NEWN(A_, i32, al->ng + 1);
    for (i32 i = 0; i < al->no; i++) al->mo[i] = al->copy_o[i] = -1;
    for (i32 i = 0; i < al->ng; i++) al->mg[i] = al->copy_g[i] = -1;
    al->score = DK_NEWN(A_, double, al->no + 1);
    al->how = DK_NEWN(A_, const char *, al->no + 1);
    al->rel = DK_NEWN(A_, const char *, al->no + 1);
    al->cmemo = DK_NEWN(A_, double, (size_t)al->no * (size_t)al->ng + 1);
    al->chas = DK_NEWN(A_, u8, (size_t)al->no * (size_t)al->ng + 1);
    al->mark_o = DK_NEWN(A_, i32, al->no + 1);
    al->mark_g = DK_NEWN(A_, i32, al->ng + 1);
    return al;
}

/* Align(ours_blocks, game_blocks).run(), with the result in the public maps. */
CfgDiffAlign *cfg_diff_align(const CfgDiffSide *ours, const CfgDiffSide *game) {
    AlignS *al = align_new(ours, game);
    al_run(al);
    CfgDiffAlign *a = DK_NEW(A_, CfgDiffAlign);
    a->priv_ = al;
    a->mo = dk_imap_new();
    a->mg = dk_imap_new();
    a->score = dk_imap_new();
    a->how = dk_imap_new();
    a->rel = dk_imap_new();
    a->copy_o = dk_imap_new();
    a->copy_g = dk_imap_new();
    for (size_t i = 0; i < al->order.n; i++) {
        i32 o = al->order.v[i];
        dk_imap_put(a->mo, (u64)o, NULL)->i = al->mo[o];
        dk_imap_put(a->score, (u64)o, NULL)->f = al->score[o];
        dk_imap_put(a->how, (u64)o, NULL)->p = (void *)al->how[o];
        if (al->rel[o]) dk_imap_put(a->rel, (u64)o, NULL)->p = (void *)al->rel[o];
    }
    for (size_t i = 0; i < al->order.n; i++) dk_imap_put(a->mg, (u64)al->mo[al->order.v[i]], NULL)->i = al->order.v[i];
    for (i32 o = 0; o < al->no; o++)
        if (al->copy_o[o] >= 0) dk_imap_put(a->copy_o, (u64)o, NULL)->i = al->copy_o[o];
    for (i32 g = 0; g < al->ng; g++)
        if (al->copy_g[g] >= 0) dk_imap_put(a->copy_g, (u64)g, NULL)->i = al->copy_g[g];
    return a;
}

/* ---------------------------------------------------------------- loops */

typedef struct Loop {
    i32 header, latch;
    u8 *body;       /* the member blocks */
    i32 nbody;
} Loop;
typedef DK_VEC(Loop) LoopVec;

typedef struct Frame {
    i32 n;
    DkI32Vec it;
    size_t pos;
} Frame;

/* loops(blocks): [(header, latch, body set)] from DFS back edges. */
static LoopVec find_loops(const CfgDiffSide *side) {
    LoopVec out = {0};
    size_t nb = side->blocks.n;
    if (!nb) return out;
    i8 *state = DK_NEWN(A_, i8, nb);
    DK_VEC(Frame) stack = {0};
    Frame f0 = {0, cfg_diff_block_successors(side->blocks.v[0]), 0};
    dk_vec_push(&stack, f0);
    state[0] = 1;
    while (stack.n) {
        Frame *f = &stack.v[stack.n - 1];
        i32 n = f->n;
        if (f->pos >= f->it.n) {
            state[n] = 2;
            dk_vec_free(&f->it);
            stack.n--;
            continue;
        }
        i32 nxt = f->it.v[f->pos++];
        if (state[nxt] == 1) {
            u8 *body = DK_NEWN(A_, u8, nb);
            i32 nbody = 0;
            body[nxt] = 1;
            nbody++;
            if (!body[n]) {
                body[n] = 1;
                nbody++;
            }
            DkI32Vec work = {0};
            dk_vec_push(&work, n);
            while (work.n) {
                i32 x = dk_vec_pop(&work);
                if (x == nxt) continue;
                const DkI32Vec *pr = &side->blocks.v[x]->preds;
                for (size_t i = 0; i < pr->n; i++)
                    if (!body[pr->v[i]]) {
                        body[pr->v[i]] = 1;
                        nbody++;
                        dk_vec_push(&work, pr->v[i]);
                    }
            }
            dk_vec_free(&work);
            dk_vec_push(&out, ((Loop){nxt, n, body, nbody}));
        } else if (state[nxt] == 0) {
            state[nxt] = 1;
            Frame fn = {nxt, cfg_diff_block_successors(side->blocks.v[nxt]), 0};
            dk_vec_push(&stack, fn);
        }
    }
    dk_vec_free(&stack);
    return out;
}

/* loop_shape: 'bottom' (the latch's jcc goes back), 'top' (the header's jcc leaves, the latch jumps back) or '?'. */
static const char *loop_shape(const CfgDiffSide *side, i32 header, i32 latch, const u8 *body) {
    const CfgDiffBlock *lb = side->blocks.v[latch], *hb = side->blocks.v[header];
    bool lb_goes_back = false, lb_leaves = false, hb_leaves = false;
    for (size_t i = 0; i < lb->succ.n; i++) {
        i32 s = lb->succ.v[i].to;
        if (s < 0) continue;
        lb_goes_back |= s == header;
        lb_leaves |= !body[s];
    }
    for (size_t i = 0; i < hb->succ.n; i++) {
        i32 s = hb->succ.v[i].to;
        if (s >= 0) hb_leaves |= !body[s];
    }
    if (strcmp(lb->term, "jcc") == 0 && lb_goes_back && lb_leaves) return "bottom";
    if (strcmp(hb->term, "jcc") == 0 && hb_leaves && (strcmp(lb->term, "jmp") == 0 || strcmp(lb->term, "fall") == 0)) return "top";
    return "?";
}

/* ---------------------------------------------------------------- findings */

typedef struct Find {
    CfgDiffFinding f;
    i64 key_g, key_o;   /* "_g" / "_o": the smallest start of the finding's game / ours blocks, 1 << 30 for none */
} Find;
typedef DK_VEC(Find) FindVec;

typedef struct Ctx {
    const CfgDiffSide *ours, *game;
    const AlignS *al;
    FindVec F;
    u8 *exp_o, *exp_g;  /* explained_o / explained_g */
} Ctx;

#define NONE_KEY (1ll << 30)

/* add(kind, o_list, g_list, evidence). The lists are index arrays (duplicates kept). */
static void f_add(Ctx *c, const char *kind, const i32 *ol, size_t no, const i32 *gl, size_t ng, const char *evidence) {
    Find f;
    memset(&f, 0, sizeof f);
    f.f.kind = kind;
    f.key_g = NONE_KEY;
    f.key_o = NONE_KEY;
    for (size_t i = 0; i < no; i++) {
        dk_vec_push(&f.f.ours, (char *)PF("+%03X", c->ours->blocks.v[ol[i]]->start));
        f.key_o = DK_MIN(f.key_o, (i64)c->ours->blocks.v[ol[i]]->start);
    }
    for (size_t i = 0; i < ng; i++) {
        dk_vec_push(&f.f.game, (char *)PF("+%03X", c->game->blocks.v[gl[i]]->start));
        f.key_g = DK_MIN(f.key_g, (i64)c->game->blocks.v[gl[i]]->start);
    }
    f.f.evidence = evidence;
    f.f.lever = cfg_diff_lever(kind);
    dk_vec_push(&c->F, f);
}
#define ADDV(c, kind, ov, gv, ev) f_add((c), (kind), (ov).v, (ov).n, (gv).v, (gv).n, (ev))
#define ADD1(c, kind, o, g, ev)                        \
    do {                                               \
        i32 o_ = (o), g_ = (g);                        \
        f_add((c), (kind), &o_, 1, &g_, 1, (ev));      \
    } while (0)

/* _blk_desc(b) */
static const char *blk_desc(const CfgDiffBlock *b) {
    DkBuf out;
    dk_buf_init(&out, A_);
    bool any = false;
    if (b->calls.n) {
        dk_buf_putz(&out, "calls ");
        for (size_t i = 0; i < b->calls.n && i < 4; i++) {
            if (i) dk_buf_putc(&out, ' ');
            dk_buf_putz(&out, b->calls.v[i]);
        }
        any = true;
    }
    if (dk_map_len(b->globals)) {
        DkStrVec keys = dk_map_keys(b->globals);
        dk_sort_strs(keys.v, keys.n);
        if (any) dk_buf_putz(&out, "; ");
        dk_buf_putz(&out, "globals ");
        for (size_t i = 0; i < keys.n && i < 4; i++) {
            if (i) dk_buf_putc(&out, ' ');
            dk_buf_put(&out, keys.v[i]);
        }
        dk_vec_free(&keys);
        any = true;
    }
    if (dk_map_len(b->consts)) {
        DkStrVec keys = dk_map_keys(b->consts);
        dk_sort_strs(keys.v, keys.n); /* sorted(b.consts, key=str) */
        if (any) dk_buf_putz(&out, "; ");
        dk_buf_putz(&out, "consts ");
        for (size_t i = 0; i < keys.n && i < 5; i++) {
            if (i) dk_buf_putc(&out, ' ');
            dk_buf_put(&out, keys.v[i]);
        }
        dk_vec_free(&keys);
        any = true;
    }
    if (!any) {
        if (b->ops.n) {
            for (size_t i = 0; i < b->ops.n && i < 6; i++) {
                if (i) dk_buf_putc(&out, ' ');
                dk_buf_putz(&out, b->ops.v[i]);
            }
        } else {
            dk_buf_putz(&out, "(moves only)");
        }
    }
    return dk_buf_cz(&out);
}

/* The register a null retest block tests (`test r,r` / `cmp r,0` + je/jne, >= 2 preds, one pred zeroing r) and the
 * block that zeroes it; false for None. */
static bool retest(const CfgDiffSide *side, const CfgDiffBlock *b, const char **reg_out, i32 *zero_out) {
    if (strcmp(b->term, "jcc") != 0 || !(strcmp(b->cond, "e") == 0 || strcmp(b->cond, "ne") == 0) || b->preds.n < 2) return false;
    const cs_insn *t = NULL;
    size_t nbody = 0;
    for (size_t i = 0; i + 1 < b->insns.n; i++)
        if (!dk_wall_is_move(b->insns.v[i]->mnemonic)) {
            t = b->insns.v[i];
            nbody++;
        }
    if (nbody != 1) return false;
    DkStrVec ops = dk_str_split(dk_str(t->op_str), DK_S(","), -1);
    const char *reg;
    if (strcmp(t->mnemonic, "test") == 0 && ops.n == 2 && dk_str_eq(dk_str_strip(ops.v[0]), dk_str_strip(ops.v[1]))) {
        reg = dk_cz(A_, dk_str_strip(ops.v[0]));
    } else if (strcmp(t->mnemonic, "cmp") == 0 && ops.n == 2 && dk_str_eqz(dk_str_strip(ops.v[1]), "0")) {
        reg = dk_cz(A_, dk_str_strip(ops.v[0]));
    } else {
        dk_vec_free(&ops);
        return false;
    }
    dk_vec_free(&ops);
    const char *xor_ops = PF("%s, %s", reg, reg), *mov_ops = PF("%s, 0", reg);
    i32 zero = -1;
    for (size_t k = 0; k < b->preds.n; k++) {
        i32 p = b->preds.v[k];
        const CfgDiffBlock *pb = side->blocks.v[p];
        /* tail = [i for i in pb.insns if i.mnemonic != "jmp"][-2:] */
        const cs_insn *last2[2] = {NULL, NULL};
        for (size_t i = 0; i < pb->insns.n; i++)
            if (strcmp(pb->insns.v[i]->mnemonic, "jmp") != 0) {
                last2[0] = last2[1];
                last2[1] = pb->insns.v[i];
            }
        for (int j = 0; j < 2; j++) {
            const cs_insn *i = last2[j];
            if (!i) continue;
            if ((strcmp(i->mnemonic, "xor") == 0 && strcmp(i->op_str, xor_ops) == 0) ||
                (strcmp(i->mnemonic, "mov") == 0 && strcmp(i->op_str, mov_ops) == 0))
                zero = p;
        }
    }
    if (zero < 0) return false;
    *reg_out = reg;
    *zero_out = zero;
    return true;
}

typedef struct ChainItem {
    i32 idx;
    i64 value;
} ChainItem;
typedef DK_VEC(ChainItem) ChainVec;

/* _kind(text) on a NUL-terminated operand. */
static const char *kindz(DkStr t) { return kind_of(t); }

/* _chain(side): [(block idx, case value)] of compare-chain blocks (cmp/sub/dec r + je/jne on one register), layout
 * order. */
static ChainVec chain_of(const CfgDiffSide *side) {
    ChainVec out = {0};
    DkMap *acc = dk_map_new();   /* reg -> index into accv */
    struct Acc {
        bool has;
        i64 v;
    } accv[64];
    size_t nacc = 0;
    bool prev = false;
    for (size_t bi = 0; bi < side->blocks.n; bi++) {
        const CfgDiffBlock *b = side->blocks.v[bi];
        if (strcmp(b->term, "jcc") != 0 || !(strcmp(b->cond, "e") == 0 || strcmp(b->cond, "ne") == 0)) {
            prev = false;
            continue;
        }
        const cs_insn *i = NULL;
        size_t nbody = 0;
        for (size_t k = 0; k + 1 < b->insns.n; k++)
            if (!dk_wall_is_move(b->insns.v[k]->mnemonic)) {
                i = b->insns.v[k];
                nbody++;
            }
        if (nbody != 1) {
            prev = false;
            continue;
        }
        DkStrVec ops = dk_str_split(dk_str(i->op_str), DK_S(","), -1);
        for (size_t k = 0; k < ops.n; k++) ops.v[k] = dk_str_strip(ops.v[k]);
        DkStr reg = ops.n ? ops.v[0] : DK_S("");
        const char *m = i->mnemonic;
        DkVal *slot = dk_map_put(acc, reg, NULL);
        size_t ai;
        bool fresh = slot->u == 0;
        if (fresh) {
            DK_ASSERT(nacc < DK_ARRAY_LEN(accv));
            ai = nacc++;
            slot->u = ai + 1;
            accv[ai].has = false;
            accv[ai].v = 0;
            /* acc.get(reg) of an unseen register is None: 'has' false */
        } else {
            ai = slot->u - 1;
        }
        if (strcmp(m, "cmp") == 0 && ops.n == 2 && strcmp(kindz(ops.v[1]), "imm") == 0 && strcmp(kindz(reg), "reg") == 0) {
            dk_vec_push(&out, ((ChainItem){b->idx, py_int0(dk_cz(A_, ops.v[1]))}));
            accv[ai].has = false;
        } else if ((strcmp(m, "sub") == 0 || strcmp(m, "dec") == 0 || strcmp(m, "add") == 0 || strcmp(m, "inc") == 0) &&
                   strcmp(kindz(reg), "reg") == 0) {
            i64 k = ops.n == 2 && strcmp(kindz(ops.v[1]), "imm") == 0 ? py_int0(dk_cz(A_, ops.v[1])) : 1;
            if (strcmp(m, "add") == 0 || strcmp(m, "inc") == 0) k = -k;
            i64 base = (prev && accv[ai].has) ? accv[ai].v : 0; /* (acc.get(reg) if prev is not None else None) or 0 */
            accv[ai].has = true;
            accv[ai].v = base + k;
            dk_vec_push(&out, ((ChainItem){b->idx, accv[ai].v}));
        } else {
            dk_vec_free(&ops);
            prev = false;
            continue;
        }
        dk_vec_free(&ops);
        prev = true;
    }
    dk_map_free(acc);
    return out;
}

/* _lis(seq): the indices of a longest increasing subsequence, as a mask. */
static u8 *lis_mask(const i64 *seq, size_t n) {
    u8 *mask = DK_NEWN(A_, u8, n + 1);
    DkI64Vec tails = {0};
    DkI32Vec tails_i = {0};
    i32 *parent = DK_NEWN(A_, i32, n + 1);
    for (size_t i = 0; i < n; i++) {
        size_t k = dk_bisect_left_i64(tails.v, tails.n, seq[i]);
        if (k == tails.n) {
            dk_vec_push(&tails, seq[i]);
            dk_vec_push(&tails_i, (i32)i);
        } else {
            tails.v[k] = seq[i];
            tails_i.v[k] = (i32)i;
        }
        parent[i] = k ? tails_i.v[k - 1] : -1;
    }
    i32 i = tails_i.n ? tails_i.v[tails_i.n - 1] : -1;
    while (i >= 0) {
        mask[i] = 1;
        i = parent[i];
    }
    dk_vec_free(&tails);
    dk_vec_free(&tails_i);
    return mask;
}

/* to_ret(side, i): a return block, or a straight line of one-successor fall/jmp blocks (at most 4) ending in one. */
static bool to_ret(const CfgDiffSide *side, i32 i) {
    for (int k = 0; k < 4; k++) {
        if (i < 0) return false;
        const CfgDiffBlock *b = side->blocks.v[i];
        if (b->has_ret) return true;
        if (!(strcmp(b->term, "fall") == 0 || strcmp(b->term, "jmp") == 0) || n_successors(b) != 1) return false;
        DkI32Vec s = cfg_diff_block_successors(b);
        i = s.v[0];
        dk_vec_free(&s);
    }
    return false;
}

/* near(side, i, depth=2): the jcc blocks within two steps of block i. */
static DkI32Vec near_jcc(const CfgDiffSide *side, i32 i) {
    DkI32Vec out = {0}, frontier = {0};
    dk_vec_push(&frontier, i);
    for (int d = 0; d < 2; d++) {
        DkI32Vec nxt = {0};
        for (size_t k = 0; k < frontier.n; k++) {
            const CfgDiffBlock *b = side->blocks.v[frontier.v[k]];
            for (size_t e = 0; e < b->succ.n; e++) {
                i32 s = b->succ.v[e].to;
                if (s >= 0 && !vec_has(&out, s) && s != i) {
                    dk_vec_push(&out, s);
                    dk_vec_push(&nxt, s);
                }
            }
        }
        dk_vec_free(&frontier);
        frontier = nxt;
    }
    dk_vec_free(&frontier);
    DkI32Vec res = {0};
    for (size_t k = 0; k < out.n; k++)
        if (strcmp(side->blocks.v[out.v[k]]->term, "jcc") == 0) dk_vec_push(&res, out.v[k]);
    dk_vec_free(&out);
    return res;
}

/* cmp_text(b) */
static const char *cmp_text(const CfgDiffBlock *b) {
    return b->has_cmp ? PF("%s %s; j%s", b->cmp_m, b->cmp_ops, b->cond) : PF("j%s", b->cond);
}

static i64 last_off(const CfgDiffSide *side, const CfgDiffBlock *b) {
    return (i64)b->insns.v[b->insns.n - 1]->address - (i64)side->base;
}

/* "[1, 2, 3]" */
static const char *int_list(const i64 *v, size_t n) {
    DkBuf b;
    dk_buf_init(&b, A_);
    dk_buf_putc(&b, '[');
    for (size_t i = 0; i < n; i++) dk_buf_printf(&b, "%s%lld", i ? ", " : "", (long long)v[i]);
    dk_buf_putc(&b, ']');
    return dk_buf_cz(&b);
}

typedef DK_VEC(DkI32Vec) RunVec;

typedef struct SelRec {
    i32 b;
    const cs_insn *i;
} SelRec;
typedef DK_VEC(SelRec) SelVec;

static int cmp_i32_v(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    return (*(const i32 *)x > *(const i32 *)y) - (*(const i32 *)x < *(const i32 *)y);
}

/* runs(idxs, blocks): the blocks in start order, split where one does not follow or lead into the next. */
static RunVec runs_of(const DkI32Vec *idxs, const CfgDiffSide *side) {
    RunVec out = {0};
    DkI32Vec sorted = {0};
    dk_vec_extend(&sorted, idxs->v, idxs->n);
    /* a stable insertion by start: the lists are short */
    for (size_t i = 1; i < sorted.n; i++) {
        i32 x = sorted.v[i];
        size_t j = i;
        while (j > 0 && side->blocks.v[sorted.v[j - 1]]->start > side->blocks.v[x]->start) {
            sorted.v[j] = sorted.v[j - 1];
            j--;
        }
        sorted.v[j] = x;
    }
    DkI32Vec cur = {0};
    for (size_t k = 0; k < sorted.n; k++) {
        i32 i = sorted.v[k];
        if (cur.n) {
            const CfgDiffBlock *last = side->blocks.v[cur.v[cur.n - 1]];
            if (last->end != side->blocks.v[i]->start && !succ_has(last, side->blocks.v[i]->idx)) {
                dk_vec_push(&out, cur);
                memset(&cur, 0, sizeof cur);
            }
        }
        dk_vec_push(&cur, i);
    }
    if (cur.n) dk_vec_push(&out, cur);
    dk_vec_free(&sorted);
    return out;
}

static bool trivial_block(const CfgDiffBlock *b) {
    if (b->calls.n) return false;
    for (size_t k = 0; k < b->insns.n; k++) {
        const char *m = b->insns.v[k]->mnemonic;
        if (!(strcmp(m, "jmp") == 0 || strcmp(m, "nop") == 0 || strcmp(m, "int3") == 0 || dk_wall_is_move(m))) return false;
    }
    return true;
}

static const char *plural(size_t n, const char *one, const char *many) { return n == 1 ? one : many; }

static int find_cmp(const void *a, const void *b, void *ctx) {
    DK_UNUSED(ctx);
    const Find *p = a, *q = b;
    int c = dk_cmp_i64(p->key_g, q->key_g);
    if (c) return c;
    c = dk_cmp_i64(p->key_o, q->key_o);
    if (c) return c;
    return dk_cmp_i64(kind_index(p->f.kind), kind_index(q->f.kind));
}

/* find(ours, game, al) */
static FindVec find_findings(const CfgDiffSide *ours, const CfgDiffSide *game, const CfgDiffAlign *alp) {
    const AlignS *al = alp->priv_;
    Ctx c = {ours, game, al, {0}, NULL, NULL};
    i32 no = al->no, ng = al->ng;
    c.exp_o = DK_NEWN(A_, u8, no + 1);
    c.exp_g = DK_NEWN(A_, u8, ng + 1);
    const CfgDiffBlock *const *O = (const CfgDiffBlock *const *)ours->blocks.v;
    const CfgDiffBlock *const *G = (const CfgDiffBlock *const *)game->blocks.v;

    /* inverted / mirrored compares. An inverted test whose arm is a return block (or leads only to one) is the
     * early-return shape when the exit counts differ: folded into that finding; otherwise the arm is a return block
     * one side places at the end and the other inline, said so in the evidence. */
    DkI32Vec ro = {0}, rg = {0};
    for (i32 i = 0; i < no; i++)
        if (O[i]->has_ret) dk_vec_push(&ro, i);
    for (i32 i = 0; i < ng; i++)
        if (G[i]->has_ret) dk_vec_push(&rg, i);
    bool exits_differ = ro.n != rg.n;
    DkI32Vec folded_o = {0}, folded_g = {0};

    for (i32 o = 0; o < no; o++) {
        if (al->mo[o] < 0) continue;
        i32 g = al->mo[o];
        const char *r = al->rel[o];
        const CfgDiffBlock *ob = O[o], *gb = G[g];
        if (r && (strcmp(r, "inverted") == 0 || strcmp(r, "inv+mir") == 0)) {
            i32 ot = cfg_diff_block_succ_role(ob, "taken"), of = cfg_diff_block_succ_role(ob, "fall");
            i32 gt = cfg_diff_block_succ_role(gb, "taken"), gf = cfg_diff_block_succ_role(gb, "fall");
            bool straight = (ot >= 0 && al->mo[ot] == gt) || (of >= 0 && al->mo[of] == gf);
            if (straight) continue;
            const char *ev = PF("ours +%03X j%s / game +%03X j%s   arms swapped: ours fall %s = game taken %s",
                                last_off(ours, ob), ob->cond, last_off(game, gb), gb->cond,
                                of >= 0 ? PF("+%03X", O[of]->start) : "?", gt >= 0 ? PF("+%03X", G[gt]->start) : "?");
            if (strcmp(r, "inv+mir") == 0) {
                bool both = ob->has_cmp && gb->has_cmp;
                ev = PF("%s (and the cmp operands swapped: %s %s / %s %s)", ev, both ? ob->cmp_m : "",
                        both ? ob->cmp_ops : "", both ? gb->cmp_m : "", both ? gb->cmp_ops : "");
            }
            i32 ret_o[2], ret_g[2];
            size_t nro = 0, nrg = 0;
            i32 cand_o[2] = {ot, of}, cand_g[2] = {gt, gf};
            for (int k = 0; k < 2; k++)
                if (to_ret(ours, cand_o[k])) ret_o[nro++] = cand_o[k];
            for (int k = 0; k < 2; k++)
                if (to_ret(game, cand_g[k])) ret_g[nrg++] = cand_g[k];
            if ((nro || nrg) && exits_differ) {
                dk_vec_push(&folded_o, o);
                dk_vec_push(&folded_g, g);
            } else if (nro || nrg) {
                /* which side keeps the return arm inline (its fall-through), which jumps to it */
                if (nro == 2 || nrg == 2) {
                    ev = PF("%s; both arms end in a return: the arms are in the other order", ev);
                } else {
                    bool inline_o = false, inline_g = false;
                    for (size_t k = 0; k < nro; k++) inline_o |= of >= 0 && ret_o[k] == of;
                    for (size_t k = 0; k < nrg; k++) inline_g |= gf >= 0 && ret_g[k] == gf;
                    ev = PF("%s; the arm is a return block: ours places it %s, the game %s", ev,
                            inline_o ? "inline" : "at the end (jumped to)", inline_g ? "inline" : "at the end (jumped to)");
                }
                ADD1(&c, "inverted-branch", o, g, ev);
                c.F.v[c.F.n - 1].f.lever =
                    PF("%s; an early `return` in the source vs a single exit/else arm",
                       cfg_diff_lever("inverted-branch"));
            } else {
                ADD1(&c, "inverted-branch", o, g, ev);
            }
            if (ot >= 0) c.exp_o[ot] = 1;
            if (of >= 0) c.exp_o[of] = 1;
            if (gt >= 0) c.exp_g[gt] = 1;
            if (gf >= 0) c.exp_g[gf] = 1;
        } else if (r && strcmp(r, "mirrored") == 0) {
            ADD1(&c, "mirrored-compare", o, g,
                 PF("ours %s %s; j%s / game %s %s; j%s", ob->has_cmp ? ob->cmp_m : "?", ob->has_cmp ? ob->cmp_ops : "", ob->cond,
                    gb->has_cmp ? gb->cmp_m : "?", gb->has_cmp ? gb->cmp_ops : "", gb->cond));
        }
    }

    /* the same tests in another order: a pair of jcc blocks with unrelated conditions where each side's condition
     * appears a step or two further on the other side */
    for (i32 o = 0; o < no; o++) {
        if (al->mo[o] < 0) continue;
        i32 g = al->mo[o];
        if (!al->rel[o] || strcmp(al->rel[o], "other") != 0 || c.exp_o[o]) continue;
        const CfgDiffBlock *ob = O[o], *gb = G[g];
        DkI32Vec no_ = near_jcc(ours, o), ng_ = near_jcc(game, g);
        i32 o2 = -1, g2 = -1;
        for (size_t k = 0; k < no_.n && o2 < 0; k++)
            if (opt_eq(O[no_.v[k]]->cond, gb->cond) || opt_eq(O[no_.v[k]]->cond, NEG_GET(gb->cond))) o2 = no_.v[k];
        for (size_t k = 0; k < ng_.n && g2 < 0; k++)
            if (opt_eq(G[ng_.v[k]]->cond, ob->cond) || opt_eq(G[ng_.v[k]]->cond, NEG_GET(ob->cond))) g2 = ng_.v[k];
        dk_vec_free(&no_);
        dk_vec_free(&ng_);
        if (o2 < 0 || g2 < 0) continue;
        const char *ev = PF("the same tests in another order: game `%s` (+%03X) then `%s` (+%03X); ours `%s` (+%03X) then `%s` (+%03X)",
                            cmp_text(gb), last_off(game, gb), cmp_text(G[g2]), last_off(game, G[g2]), cmp_text(ob),
                            last_off(ours, ob), cmp_text(O[o2]), last_off(ours, O[o2]));
        i32 ol[2] = {o, o2}, gl[2] = {g, g2};
        f_add(&c, "block-order", ol, 2, gl, 2, ev);
        c.exp_o[o] = c.exp_o[o2] = 1;
        c.exp_g[g] = c.exp_g[g2] = 1;
        for (size_t k = 0; k < ob->succ.n; k++)
            if (ob->succ.v[k].to >= 0) c.exp_o[ob->succ.v[k].to] = 1;
        for (size_t k = 0; k < O[o2]->succ.n; k++)
            if (O[o2]->succ.v[k].to >= 0) c.exp_o[O[o2]->succ.v[k].to] = 1;
        for (size_t k = 0; k < gb->succ.n; k++)
            if (gb->succ.v[k].to >= 0) c.exp_g[gb->succ.v[k].to] = 1;
        for (size_t k = 0; k < G[g2]->succ.n; k++)
            if (G[g2]->succ.v[k].to >= 0) c.exp_g[G[g2]->succ.v[k].to] = 1;
    }

    /* loops */
    LoopVec lo = find_loops(ours), lg = find_loops(game);
    for (size_t li = 0; li < lo.n; li++) {
        const Loop *lp = &lo.v[li];
        const Loop *pick = NULL;
        for (size_t gi = 0; gi < lg.n && !pick; gi++) {
            const Loop *q = &lg.v[gi];
            bool ok = al->mo[lp->header] == q->header || al->mo[lp->latch] == q->latch;
            if (!ok) {
                i32 common = 0;
                for (i32 x = 0; x < no; x++)
                    if (lp->body[x] && al->mo[x] >= 0 && q->body[al->mo[x]]) common++;
                ok = common * 2 > lp->nbody;
            }
            if (ok) pick = q;
        }
        if (!pick) continue;
        const char *so = loop_shape(ours, lp->header, lp->latch, lp->body), *sg = loop_shape(game, pick->header, pick->latch, pick->body);
        if (strcmp(so, sg) != 0 && strcmp(so, "?") != 0 && strcmp(sg, "?") != 0) {
            i32 ol[2] = {lp->header, lp->latch}, gl[2] = {pick->header, pick->latch};
            f_add(&c, "loop-rotation", ol, 2, gl, 2,
                  PF("ours tests the loop at the %s (header +%03X, latch +%03X), game at the %s (header +%03X, latch +%03X)", so,
                     O[lp->header]->start, O[lp->latch]->start, sg, G[pick->header]->start, G[pick->latch]->start));
            for (i32 x = 0; x < no; x++) c.exp_o[x] |= lp->body[x];
            for (i32 x = 0; x < ng; x++) c.exp_g[x] |= pick->body[x];
        }
    }

    /* jump threading (select wall) */
    for (int pass = 0; pass < 2; pass++) {
        bool game_side = pass == 0;
        const CfgDiffSide *side = game_side ? game : ours, *other = game_side ? ours : game;
        const i32 *m = game_side ? al->mg : al->mo;
        const char *own_label = game_side ? "game" : "ours", *other_label = game_side ? "ours" : "game";
        for (size_t bi = 0; bi < side->blocks.n; bi++) {
            const CfgDiffBlock *b = side->blocks.v[bi];
            const char *reg;
            i32 zero;
            if (!retest(side, b, &reg, &zero)) continue;
            i32 cp = m[b->idx];
            const char *oreg;
            i32 ozero;
            if (cp >= 0 && retest(other, other->blocks.v[cp], &oreg, &ozero)) continue;
            DkI32Vec succ_other = {0};
            for (size_t k = 0; k < b->succ.n; k++) {
                i32 s = b->succ.v[k].to;
                if (s >= 0 && m[s] >= 0 && !vec_has(&succ_other, m[s])) dk_vec_push(&succ_other, m[s]);
            }
            dk_sort(succ_other.v, succ_other.n, sizeof(i32), cmp_i32_v, NULL, false);
            DkBuf wb;
            dk_buf_init(&wb, A_);
            for (size_t k = 0; k < succ_other.n; k++) dk_buf_printf(&wb, "%s+%03X", k ? ", " : "", other->blocks.v[succ_other.v[k]]->start);
            const char *where = wb.n ? dk_buf_cz(&wb) : "elsewhere";
            dk_vec_free(&succ_other);
            const char *ev = PF("%s +%03X..+%03X keeps the null retest (xor %s,%s / test %s,%s), %s jumps to %s", own_label,
                                side->blocks.v[zero]->start, b->end, reg, reg, reg, reg, other_label, where);
            i32 pair[2] = {zero, b->idx};
            if (game_side) {
                f_add(&c, "jump-threading", NULL, 0, pair, 2, ev);
                c.exp_g[zero] = c.exp_g[b->idx] = 1;
            } else {
                f_add(&c, "jump-threading", pair, 2, NULL, 0, ev);
                c.exp_o[zero] = c.exp_o[b->idx] = 1;
            }
        }
    }

    /* switch lowering */
    DkI32Vec so_ = {0}, sg_ = {0};
    for (i32 i = 0; i < no; i++)
        if (strcmp(O[i]->term, "switch") == 0) dk_vec_push(&so_, i);
    for (i32 i = 0; i < ng; i++)
        if (strcmp(G[i]->term, "switch") == 0) dk_vec_push(&sg_, i);
    ChainVec co = chain_of(ours), cg = chain_of(game);
    if (so_.n != sg_.n) {
        DkBuf tb;
        dk_buf_init(&tb, A_);
        if (sg_.n > so_.n) {
            for (size_t k = 0; k < sg_.n; k++) dk_buf_printf(&tb, "%s%zu cases", k ? ", " : "", G[sg_.v[k]]->succ.n);
            i64 vals[8];
            size_t nv = DK_MIN(co.n, (size_t)8);
            for (size_t k = 0; k < nv; k++) vals[k] = co.v[k].value;
            DkI32Vec ol = {0};
            for (size_t k = 0; k < co.n && k < 4; k++) dk_vec_push(&ol, co.v[k].idx);
            const char *ev = PF("game has %d jump table(s) (%s), ours %d; ours compare chain cases %s", sg_.n, dk_buf_cz(&tb), so_.n,
                                int_list(vals, nv));
            f_add(&c, "switch-lowering", ol.v, ol.n, sg_.v, sg_.n, ev);
            dk_vec_free(&ol);
        } else {
            for (size_t k = 0; k < so_.n; k++) dk_buf_printf(&tb, "%s%zu cases", k ? ", " : "", O[so_.v[k]]->succ.n);
            i64 vals[8];
            size_t nv = DK_MIN(cg.n, (size_t)8);
            for (size_t k = 0; k < nv; k++) vals[k] = cg.v[k].value;
            DkI32Vec gl = {0};
            for (size_t k = 0; k < cg.n && k < 4; k++) dk_vec_push(&gl, cg.v[k].idx);
            const char *ev = PF("ours has %d jump table(s) (%s), game %d; game compare chain cases %s", so_.n, dk_buf_cz(&tb), sg_.n,
                                int_list(vals, nv));
            f_add(&c, "switch-lowering", so_.v, so_.n, gl.v, gl.n, ev);
            dk_vec_free(&gl);
        }
        for (size_t k = 0; k < co.n; k++) c.exp_o[co.v[k].idx] = 1;
        for (size_t k = 0; k < cg.n; k++) c.exp_g[cg.v[k].idx] = 1;
        for (size_t k = 0; k < so_.n; k++)
            for (size_t e = 0; e < O[so_.v[k]]->succ.n; e++)
                if (O[so_.v[k]]->succ.v[e].to >= 0) c.exp_o[O[so_.v[k]]->succ.v[e].to] = 1;
        for (size_t k = 0; k < sg_.n; k++)
            for (size_t e = 0; e < G[sg_.v[k]]->succ.n; e++)
                if (G[sg_.v[k]]->succ.v[e].to >= 0) c.exp_g[G[sg_.v[k]]->succ.v[e].to] = 1;
    } else {
        for (size_t k = 0; k < so_.n; k++) {
            const CfgDiffBlock *a = O[so_.v[k]], *b = G[sg_.v[k]];
            if (a->succ.n != b->succ.n)
                ADD1(&c, "switch-lowering", so_.v[k], sg_.v[k],
                     PF("jump tables: ours %d entries / %d distinct targets, game %d / %d (a case missing or extra, or the case range differs)",
                        a->table > 0 ? a->table : 0, a->succ.n, b->table > 0 ? b->table : 0, b->succ.n));
        }
    }
    {
        i64 *vo = DK_NEWN(A_, i64, co.n + 1), *vg = DK_NEWN(A_, i64, cg.n + 1), *so2 = DK_NEWN(A_, i64, co.n + 1),
            *sg2 = DK_NEWN(A_, i64, cg.n + 1);
        for (size_t k = 0; k < co.n; k++) vo[k] = so2[k] = co.v[k].value;
        for (size_t k = 0; k < cg.n; k++) vg[k] = sg2[k] = cg.v[k].value;
        dk_sort_i64(so2, co.n);
        dk_sort_i64(sg2, cg.n);
        bool same_sorted = co.n == cg.n && (co.n == 0 || memcmp(so2, sg2, co.n * sizeof(i64)) == 0);
        bool same_order = co.n == cg.n && (co.n == 0 || memcmp(vo, vg, co.n * sizeof(i64)) == 0);
        if (co.n >= 2 && same_sorted && !same_order) {
            DkI32Vec ol = {0}, gl = {0};
            for (size_t k = 0; k < co.n; k++) dk_vec_push(&ol, co.v[k].idx);
            for (size_t k = 0; k < cg.n; k++) dk_vec_push(&gl, cg.v[k].idx);
            f_add(&c, "switch-lowering", ol.v, ol.n, gl.v, gl.n,
                  PF("compare chains test the same cases in another order: ours %s, game %s", int_list(vo, DK_MIN(co.n, (size_t)10)),
                     int_list(vg, DK_MIN(cg.n, (size_t)10))));
            dk_vec_free(&ol);
            dk_vec_free(&gl);
        }
    }

    /* tail calls */
    for (int pass = 0; pass < 2; pass++) {
        const CfgDiffSide *side = pass == 0 ? ours : game, *other = pass == 0 ? game : ours;
        const char *label = pass == 0 ? "ours" : "game";
        for (size_t bi = 0; bi < side->blocks.n; bi++) {
            const CfgDiffBlock *b = side->blocks.v[bi];
            if (!b->tail || !*b->tail || strcmp(b->tail, "indirect") == 0) continue;
            bool in_tails = false, in_calls = false;
            for (size_t k = 0; k < other->blocks.n; k++) {
                const CfgDiffBlock *x = other->blocks.v[k];
                if (x->tail && *x->tail && strcmp(x->tail, b->tail) == 0) in_tails = true;
                for (size_t q = 0; q < x->calls.n; q++)
                    if (strncmp(x->calls.v[q], "tail:", 5) != 0 && strcmp(x->calls.v[q], b->tail) == 0) in_calls = true;
            }
            if (in_tails || !in_calls) continue;
            DkI32Vec obv = {0};
            for (size_t k = 0; k < other->blocks.n; k++)
                for (size_t q = 0; q < other->blocks.v[k]->calls.n; q++)
                    if (strcmp(other->blocks.v[k]->calls.v[q], b->tail) == 0) {
                        dk_vec_push(&obv, (i32)k);
                        break;
                    }
            DkBuf sb;
            dk_buf_init(&sb, A_);
            for (size_t k = 0; k < obv.n && k < 3; k++) dk_buf_printf(&sb, "%s%03X", k ? ", +" : "", other->blocks.v[obv.v[k]]->start);
            const char *ev = PF("%s +%03X ends with `jmp %s`; %s calls it (+%s) and returns", label, last_off(side, b), b->tail,
                                pass == 0 ? "game" : "ours", dk_buf_cz(&sb));
            if (pass == 0)
                f_add(&c, "tail-call", &(i32){b->idx}, 1, obv.v, DK_MIN(obv.n, (size_t)1), ev);
            else
                f_add(&c, "tail-call", obv.v, DK_MIN(obv.n, (size_t)1), &(i32){b->idx}, 1, ev);
            dk_vec_free(&obv);
        }
    }

    /* early returns and duplicated / merged tails */
    if (exits_differ) {
        const char *more = ro.n > rg.n ? "ours" : "game";
        size_t ndup = 0;
        for (i32 o = 0; o < no; o++) ndup += al->copy_o[o] >= 0 && O[o]->has_ret;
        for (i32 g = 0; g < ng; g++) ndup += al->copy_g[g] >= 0 && G[g]->has_ret;
        DkBuf ob_, gb_;
        dk_buf_init(&ob_, A_);
        dk_buf_init(&gb_, A_);
        i64 *po = DK_NEWN(A_, i64, ro.n + 1), *pg = DK_NEWN(A_, i64, rg.n + 1);
        for (size_t k = 0; k < ro.n; k++) {
            dk_buf_printf(&ob_, "%s+%03X", k ? " " : "", O[ro.v[k]]->start);
            for (size_t q = 0; q < O[ro.v[k]]->insns.n; q++) po[k] += strcmp(O[ro.v[k]]->insns.v[q]->mnemonic, "pop") == 0;
        }
        for (size_t k = 0; k < rg.n; k++) {
            dk_buf_printf(&gb_, "%s+%03X", k ? " " : "", G[rg.v[k]]->start);
            for (size_t q = 0; q < G[rg.v[k]]->insns.n; q++) pg[k] += strcmp(G[rg.v[k]]->insns.v[q]->mnemonic, "pop") == 0;
        }
        const char *dup_txt = ndup ? PF(" (%d epilogue cop%s)", ndup, ndup == 1 ? "y" : "ies") : "";
        const char *ev = PF("ret/epilogue blocks: ours %d (%s), game %d (%s); %s returns from the middle%s; pops per exit: ours %s, game %s",
                            ro.n, dk_buf_cz(&ob_), rg.n, dk_buf_cz(&gb_), more, dup_txt, int_list(po, ro.n), int_list(pg, rg.n));
        ADDV(&c, "early-return", ro, rg, ev);
        if (folded_o.n) {
            DkBuf fo, fg;
            dk_buf_init(&fo, A_);
            dk_buf_init(&fg, A_);
            for (size_t k = 0; k < folded_o.n; k++) {
                dk_buf_printf(&fo, "%s+%03X", k ? " " : "", (u32)last_off(ours, O[folded_o.v[k]]));
                dk_buf_printf(&fg, "%s+%03X", k ? " " : "", (u32)last_off(game, G[folded_g.v[k]]));
            }
            Find *last = &c.F.v[c.F.n - 1];
            last->f.evidence = PF("%s; with %d inverted test%s (ours %s / game %s)", last->f.evidence, folded_o.n,
                                  folded_o.n == 1 ? "" : "s", dk_buf_cz(&fo), dk_buf_cz(&fg));
            for (size_t k = 0; k < folded_o.n; k++) dk_vec_push(&last->f.ours, (char *)PF("+%03X", O[folded_o.v[k]]->start));
            for (size_t k = 0; k < folded_g.n; k++) dk_vec_push(&last->f.game, (char *)PF("+%03X", G[folded_g.v[k]]->start));
        }
        for (i32 o = 0; o < no; o++)
            if (al->copy_o[o] >= 0 && O[o]->has_ret) c.exp_o[o] = 1;
        for (i32 g = 0; g < ng; g++)
            if (al->copy_g[g] >= 0 && G[g]->has_ret) c.exp_g[g] = 1;
        for (size_t k = 0; k < ro.n; k++) c.exp_o[ro.v[k]] = 1;
        for (size_t k = 0; k < rg.n; k++) c.exp_g[rg.v[k]] = 1;
    }

    {
        DkI32Vec pick = {0};
        for (i32 o = 0; o < no; o++)
            if (al->copy_o[o] >= 0 && !c.exp_o[o]) dk_vec_push(&pick, o);
        RunVec rs = runs_of(&pick, ours);
        for (size_t ri = 0; ri < rs.n; ri++) {
            const DkI32Vec *r = &rs.v[ri];
            DkI32Vec twins = {0}, olist = {0};
            bool any_ret = false;
            for (size_t k = 0; k < r->n; k++) {
                dk_vec_push(&twins, al->copy_o[r->v[k]]);
                dk_vec_push(&olist, r->v[k]);
                any_ret |= O[r->v[k]]->has_ret;
            }
            for (size_t k = 0; k < twins.n; k++)
                if (al->mg[twins.v[k]] >= 0) dk_vec_push(&olist, al->mg[twins.v[k]]);
            const char *kind = any_ret ? "early-return" : "merged-tail";
            const char *what = r->n == 1 ? "a block" : PF("a %d-block tail", r->n);
            const char *second = al->mg[twins.v[0]] >= 0 ? PF("%03X", O[al->mg[twins.v[0]]]->start) : "?";
            const char *ev = PF("ours has %s twice (+%s and +%s); the game once (+%s): %s", what, PF("%03X", O[r->v[0]]->start), second,
                                PF("%03X", G[twins.v[0]]->start), blk_desc(O[r->v[0]]));
            f_add(&c, kind, olist.v, olist.n, twins.v, twins.n, ev);
            for (size_t k = 0; k < r->n; k++) c.exp_o[r->v[k]] = 1;
            dk_vec_free(&twins);
            dk_vec_free(&olist);
        }
        dk_vec_free(&pick);
    }
    {
        DkI32Vec pick = {0};
        for (i32 g = 0; g < ng; g++)
            if (al->copy_g[g] >= 0 && !c.exp_g[g]) dk_vec_push(&pick, g);
        RunVec rs = runs_of(&pick, game);
        for (size_t ri = 0; ri < rs.n; ri++) {
            const DkI32Vec *r = &rs.v[ri];
            DkI32Vec twins = {0}, glist = {0};
            bool any_ret = false;
            for (size_t k = 0; k < r->n; k++) {
                dk_vec_push(&twins, al->copy_g[r->v[k]]);
                dk_vec_push(&glist, r->v[k]);
                any_ret |= G[r->v[k]]->has_ret;
            }
            for (size_t k = 0; k < twins.n; k++)
                if (al->mo[twins.v[k]] >= 0) dk_vec_push(&glist, al->mo[twins.v[k]]);
            const char *kind = any_ret ? "early-return" : "duplicated-tail";
            const char *what = r->n == 1 ? "a block" : PF("a %d-block tail", r->n);
            const char *second = al->mo[twins.v[0]] >= 0 ? PF("%03X", G[al->mo[twins.v[0]]]->start) : "?";
            const char *ev = PF("the game has %s twice (+%s and +%s); ours once (+%s): %s", what, PF("%03X", G[r->v[0]]->start), second,
                                PF("%03X", O[twins.v[0]]->start), blk_desc(G[r->v[0]]));
            f_add(&c, kind, twins.v, twins.n, glist.v, glist.n, ev);
            for (size_t k = 0; k < r->n; k++) c.exp_g[r->v[k]] = 1;
            dk_vec_free(&twins);
            dk_vec_free(&glist);
        }
        dk_vec_free(&pick);
    }

    /* block order */
    {
        DkI32Vec mapped = {0};
        for (i32 o = 0; o < no; o++)
            if (al->mo[o] >= 0) dk_vec_push(&mapped, o); /* sorted(al.mo, key=start): the blocks are numbered in start order */
        i64 *seq = DK_NEWN(A_, i64, mapped.n + 1);
        for (size_t k = 0; k < mapped.n; k++) seq[k] = G[al->mo[mapped.v[k]]]->start;
        u8 *keep = lis_mask(seq, mapped.n);
        DkI32Vec moved = {0};
        for (size_t k = 0; k < mapped.n; k++)
            if (!keep[k] && !c.exp_o[mapped.v[k]] && !c.exp_g[al->mo[mapped.v[k]]]) dk_vec_push(&moved, mapped.v[k]);
        DkI32Vec moved2 = {0};
        for (size_t k = 0; k < moved.n; k++)
            if (O[moved.v[k]]->insns.n > 1 || strcmp(O[moved.v[k]]->term, "jmp") != 0) dk_vec_push(&moved2, moved.v[k]);
        if (moved2.n) {
            DkBuf mb;
            dk_buf_init(&mb, A_);
            DkI32Vec gl = {0};
            for (size_t k = 0; k < moved2.n; k++) {
                dk_vec_push(&gl, al->mo[moved2.v[k]]);
                if (k < 6) dk_buf_printf(&mb, "%sours +%03X = game +%03X", k ? ", " : "", O[moved2.v[k]]->start, G[al->mo[moved2.v[k]]]->start);
            }
            f_add(&c, "block-order", moved2.v, moved2.n, gl.v, gl.n,
                  PF("%d mapped block(s) laid out elsewhere: %s", moved2.n, dk_buf_cz(&mb)));
            dk_vec_free(&gl);
        }
        dk_vec_free(&mapped);
        dk_vec_free(&moved);
        dk_vec_free(&moved2);
    }

    /* a select (cmov/setcc) on one side where the other branches */
    {
        SelVec sel_o = {0}, sel_g = {0};
        for (i32 b = 0; b < no; b++)
            for (size_t k = 0; k < O[b]->insns.n; k++) {
                const char *m = O[b]->insns.v[k]->mnemonic;
                if (strncmp(m, "cmov", 4) == 0 || strncmp(m, "set", 3) == 0) dk_vec_push(&sel_o, ((SelRec){b, O[b]->insns.v[k]}));
            }
        for (i32 b = 0; b < ng; b++)
            for (size_t k = 0; k < G[b]->insns.n; k++) {
                const char *m = G[b]->insns.v[k]->mnemonic;
                if (strncmp(m, "cmov", 4) == 0 || strncmp(m, "set", 3) == 0) dk_vec_push(&sel_g, ((SelRec){b, G[b]->insns.v[k]}));
            }
        if (sel_o.n != sel_g.n) {
            bool more_ours = sel_o.n > sel_g.n;
            const CfgDiffSide *more = more_ours ? ours : game, *less = more_ours ? game : ours;
            const i32 *m_more = more_ours ? al->mo : al->mg, *m_less = more_ours ? al->mg : al->mo;
            size_t sn = more_ours ? sel_o.n : sel_g.n;
            const SelRec *sel = more_ours ? sel_o.v : sel_g.v;
            i32 nless = (i32)less->blocks.n;
            u8 *near_sel = DK_NEWN(A_, u8, nless + 1);
            for (size_t k = 0; k < sn; k++)
                if (m_more[sel[k].b] >= 0) near_sel[m_more[sel[k].b]] = 1;
            for (int round = 0; round < 2; round++) { /* the unmatched blocks next to the counterparts of the select blocks: the branch */
                u8 *add_ = DK_NEWN(A_, u8, nless + 1);
                for (i32 x = 0; x < nless; x++) {
                    if (!near_sel[x]) continue;
                    const CfgDiffBlock *xb = less->blocks.v[x];
                    for (size_t e = 0; e < xb->succ.n; e++)
                        if (xb->succ.v[e].to >= 0) add_[xb->succ.v[e].to] = 1;
                    for (size_t e = 0; e < xb->preds.n; e++) add_[xb->preds.v[e]] = 1;
                }
                for (i32 x = 0; x < nless; x++) near_sel[x] |= add_[x];
            }
            DkI32Vec small = {0};
            for (i32 x = 0; x < nless; x++)
                if (near_sel[x] && m_less[x] < 0 && !less->blocks.v[x]->calls.n) dk_vec_push(&small, x);
            DkBuf tb;
            dk_buf_init(&tb, A_);
            for (size_t k = 0; k < sn && k < 4; k++)
                dk_buf_printf(&tb, "%s%s +%03X", k ? ", " : "", sel[k].i->mnemonic, (u32)((i64)sel[k].i->address - (i64)more->base));
            const char *ev = PF("%s selects without a branch (%s); %s has %d such instruction(s) and branches instead", more->name,
                                dk_buf_cz(&tb), less->name, more_ours ? sel_g.n : sel_o.n);
            DkI32Vec bl = {0};
            for (size_t k = 0; k < sn; k++) dk_vec_push(&bl, sel[k].b);
            if (more_ours) {
                f_add(&c, "other", bl.v, bl.n, small.v, small.n, ev);
                for (size_t k = 0; k < small.n; k++) c.exp_g[small.v[k]] = 1;
            } else {
                f_add(&c, "other", small.v, small.n, bl.v, bl.n, ev);
                for (size_t k = 0; k < small.n; k++) c.exp_o[small.v[k]] = 1;
            }
            c.F.v[c.F.n - 1].f.lever =
                "a branch vs a cmov/setcc select: `if (b < a) a = b;` vs `a = b < a ? b : a` / min(); a "
                "bool result written as `return x != 0` vs an if/else";
            dk_vec_free(&bl);
            dk_vec_free(&small);
        }
        dk_vec_free(&sel_o);
        dk_vec_free(&sel_g);
    }

    /* what is left unmatched */
    DkI32Vec trivial_g = {0}, trivial_o = {0}, nontriv_g = {0}, nontriv_o = {0};
    for (i32 g = 0; g < ng; g++)
        if (al->mg[g] < 0 && al->copy_g[g] < 0 && !c.exp_g[g]) dk_vec_push(trivial_block(G[g]) ? &trivial_g : &nontriv_g, g);
    for (i32 o = 0; o < no; o++)
        if (al->mo[o] < 0 && al->copy_o[o] < 0 && !c.exp_o[o]) dk_vec_push(trivial_block(O[o]) ? &trivial_o : &nontriv_o, o);
    {
        RunVec rs = runs_of(&nontriv_g, game);
        for (size_t ri = 0; ri < rs.n; ri++) {
            const DkI32Vec *r = &rs.v[ri];
            DkBuf db;
            dk_buf_init(&db, A_);
            for (size_t k = 0; k < r->n && k < 3; k++) dk_buf_printf(&db, "%s%s", k ? " | " : "", blk_desc(G[r->v[k]]));
            f_add(&c, "missing-block", NULL, 0, r->v, r->n,
                  PF("game +%03X..+%03X (%d block%s) has no counterpart in ours: %s", G[r->v[0]]->start, G[r->v[r->n - 1]]->end, r->n,
                     plural(r->n, "", "s"), dk_buf_cz(&db)));
        }
    }
    {
        RunVec rs = runs_of(&nontriv_o, ours);
        for (size_t ri = 0; ri < rs.n; ri++) {
            const DkI32Vec *r = &rs.v[ri];
            DkBuf db;
            dk_buf_init(&db, A_);
            for (size_t k = 0; k < r->n && k < 3; k++) dk_buf_printf(&db, "%s%s", k ? " | " : "", blk_desc(O[r->v[k]]));
            f_add(&c, "extra-block", r->v, r->n, NULL, 0,
                  PF("ours +%03X..+%03X (%d block%s) has no counterpart in the game: %s", O[r->v[0]]->start, O[r->v[r->n - 1]]->end, r->n,
                     plural(r->n, "", "s"), dk_buf_cz(&db)));
        }
    }

    /* edges of mapped pairs that disagree (short-circuit structure), not explained above */
    typedef struct Bad {
        i32 o, g;
        const char *text;
    } Bad;
    DK_VEC(Bad) bad = {0};
    for (i32 o = 0; o < no; o++) {
        if (al->mo[o] < 0) continue;
        i32 g = al->mo[o];
        if (al->rel[o] && (strcmp(al->rel[o], "inverted") == 0 || strcmp(al->rel[o], "inv+mir") == 0)) continue;
        const CfgDiffBlock *ob = O[o], *gb = G[g];
        static const char *const TERMS[] = {"jcc", "jmp", "fall", "ret", "tail", "switch"};
        if (strcmp(ob->term, gb->term) != 0 && IN_LIST(TERMS, ob->term) && IN_LIST(TERMS, gb->term)) {
            bool jf = (strcmp(ob->term, "jmp") == 0 && strcmp(gb->term, "fall") == 0) || (strcmp(ob->term, "fall") == 0 && strcmp(gb->term, "jmp") == 0);
            if (!(jf || c.exp_o[o] || c.exp_g[g])) dk_vec_push(&bad, ((Bad){o, g, PF("ours ends in %s, game in %s", ob->term, gb->term)}));
            continue;
        }
        if (strcmp(ob->term, "jcc") == 0 && al->rel[o] && (strcmp(al->rel[o], "same") == 0 || strcmp(al->rel[o], "mirrored") == 0)) {
            static const char *const ROLES[] = {"taken", "fall"};
            for (int k = 0; k < 2; k++) {
                i32 s_o = cfg_diff_block_succ_role(ob, ROLES[k]), s_g = cfg_diff_block_succ_role(gb, ROLES[k]);
                if (s_o >= 0 && s_g >= 0 && al->mo[s_o] >= 0 && al->mg[s_g] >= 0 && al->mo[s_o] != s_g && !c.exp_o[s_o])
                    dk_vec_push(&bad, ((Bad){o, g, PF("%s edge: ours -> +%03X (= game +%03X), game -> +%03X", ROLES[k], O[s_o]->start,
                                                       G[al->mo[s_o]]->start, G[s_g]->start)}));
            }
        }
    }
    u8 *lat_o = DK_NEWN(A_, u8, no + 1), *lat_g = DK_NEWN(A_, u8, ng + 1);
    for (size_t k = 0; k < lo.n; k++) lat_o[lo.v[k].latch] = 1;
    for (size_t k = 0; k < lg.n; k++) lat_g[lg.v[k].latch] = 1;
    for (i32 o = 0; o < no; o++) {
        if (al->mo[o] < 0) continue;
        i32 g = al->mo[o];
        if (!al->rel[o] || strcmp(al->rel[o], "other") != 0 || c.exp_o[o] || c.exp_g[g]) continue;
        const CfgDiffBlock *ob = O[o], *gb = G[g];
        if (lat_o[o] && lat_g[g])
            ADD1(&c, "other", o, g,
                 PF("the loop latches test differently: ours `%s`, game `%s` (the induction variable: counting up vs down, index vs pointer)",
                    cmp_text(ob), cmp_text(gb)));
        else
            ADD1(&c, "other", o, g, PF("a different test: ours `%s`, game `%s`", cmp_text(ob), cmp_text(gb)));
    }
    if (bad.n) {
        DkBuf bb;
        dk_buf_init(&bb, A_);
        DkI32Vec bo = {0}, bg = {0};
        for (size_t k = 0; k < bad.n; k++) {
            dk_vec_push(&bo, bad.v[k].o);
            dk_vec_push(&bg, bad.v[k].g);
            if (k < 4)
                dk_buf_printf(&bb, "%sours +%03X / game +%03X %s", k ? "; " : "", O[bad.v[k].o]->start, G[bad.v[k].g]->start, bad.v[k].text);
        }
        f_add(&c, "other", bo.v, bo.n, bg.v, bg.n,
              PF("edges differ (short-circuit / condition structure): %s", dk_buf_cz(&bb)));
        dk_vec_free(&bo);
        dk_vec_free(&bg);
    }
    if ((trivial_o.n || trivial_g.n) && !c.F.n)
        f_add(&c, "other", trivial_o.v, trivial_o.n, trivial_g.v, trivial_g.n,
              PF("only jmp-only blocks differ: ours %d, game %d (a jump threaded or added)", trivial_o.n, trivial_g.n));

    /* one structural cause once */
    dk_sort(c.F.v, c.F.n, sizeof(Find), find_cmp, NULL, false);
    FindVec out = {0};
    for (size_t k = 0; k < c.F.n; k++) {
        const Find *f = &c.F.v[k];
        bool dup = false;
        for (size_t j = 0; j < out.n && !dup; j++) {
            const Find *p = &out.v[j];
            if (strcmp(p->f.kind, f->f.kind) != 0 || p->f.ours.n != f->f.ours.n || p->f.game.n != f->f.game.n) continue;
            bool same = true;
            for (size_t q = 0; q < f->f.ours.n && same; q++) same = strcmp(p->f.ours.v[q], f->f.ours.v[q]) == 0;
            for (size_t q = 0; q < f->f.game.n && same; q++) same = strcmp(p->f.game.v[q], f->f.game.v[q]) == 0;
            dup = same;
        }
        if (!dup) dk_vec_push(&out, *f);
    }
    return out;
}

/* ---------------------------------------------------------------- the analysis */

/* resolve_literals(ours, game): our unresolved literal constants (`__real@3f800000`) taken as the game's global with
 * the same content. */
static int hex_digit(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static void resolve_literals(CfgDiffSide *ours, CfgDiffSide *game) {
    if (!game->image) return;
    DkMap *by_content = dk_map_new(); /* {(n, bytes): first token with that content} */
    for (size_t bi = 0; bi < game->blocks.n; bi++) {
        DkMapIter it = {0};
        while (dk_map_next(game->blocks.v[bi]->globals, &it)) {
            i64 va;
            if (!dk_parse_int(it.key, 16, &va, NULL))
                dk_throw(DK_ERR_OTHER, "invalid literal for int() with base 16: %s", dk_repr_str(A_, it.key).p);
            for (int n = 4; n <= 16; n *= 2) {
                DkStr data = side_read_bytes(game, va, n);
                if ((int)data.n != n) continue;
                char key[17];
                key[0] = (char)n;
                memcpy(key + 1, data.p, (size_t)n);
                bool created;
                DkVal *slot = dk_map_put(by_content, dk_strn(key, (size_t)n + 1), &created);
                if (created) slot->p = dk_cz(A_, it.key);
            }
        }
    }
    for (size_t bi = 0; bi < ours->blocks.n; bi++) {
        CfgDiffBlock *b = ours->blocks.v[bi];
        DkMap *fresh = dk_map_new();
        DkMapIter it = {0};
        while (dk_map_next(b->globals, &it)) {
            DkStr t = it.key;
            i64 k = it.val->i;
            static const char *const PREFIX[] = {"sym:__real@", "sym:__xmm@"};
            for (int pi = 0; pi < 2; pi++) {
                size_t pl = strlen(PREFIX[pi]);
                if (t.n <= pl || memcmp(t.p, PREFIX[pi], pl) != 0) continue;
                size_t hn = t.n - pl;
                bool all_hex = true;
                for (size_t q = 0; q < hn; q++) all_hex &= hex_digit(t.p[pl + q]) >= 0;
                if (!all_hex || !(hn == 8 || hn == 16 || hn == 32)) continue;
                size_t n = hn / 2;
                char key[17];
                key[0] = (char)n;
                for (size_t q = 0; q < n; q++) { /* int(h, 16).to_bytes(n, "little") */
                    size_t hi = pl + hn - 2 - 2 * q;
                    key[1 + q] = (char)(hex_digit(t.p[hi]) * 16 + hex_digit(t.p[hi + 1]));
                }
                const DkVal *hit = dk_map_get(by_content, dk_strn(key, n + 1));
                if (hit) t = dk_str((const char *)hit->p);
                break;
            }
            dk_map_put(fresh, t, NULL)->i += k;
        }
        b->globals = fresh;
        refresh_priv(b);
    }
}

/* sides_of(result, image, game_size): the reference's window is cut at the function's end and before a switch table
 * (dk_wall_reference_window); an explicit or sized game_size reads on past it. */
static void sides_of(const DkResult *result, const DkImage *image, i64 game_size, CfgDiffSide **ours_out,
                     CfgDiffSide **game_out) {
    if (result->theirs_va == DK_NO_ADDR) dk_throw(DK_ERR_OTHER, "the result has no reference address");
    u32 base = result->theirs_va;
    const DkFunc *fn = &result->ours;
    DkIMap *verdicts = dk_wall_verdicts(result);
    if (game_size == CFG_DIFF_NONE && image) {
        u32 gs = 0;
        if (dk_image_function_size(image, base, &gs) && gs) game_size = (i64)gs;
    }
    DkStr window = dk_wall_reference_window(result, image);
    size_t extent = DK_MAX(window.n, (size_t)(game_size == CFG_DIFF_NONE ? 0 : game_size));
    DkStr code = window;
    if (image && extent > window.n) {
        DkStr got;
        if (dk_image_read(image, base, extent, &got))
            code = got;
        else
            extent = window.n;
    }
    CfgDiffSide *ours = cfg_diff_side_new("ours", fn->code, base, (u32)fn->code.n, fn, verdicts, image);
    CfgDiffSide *game = cfg_diff_side_new("game", code, base, (u32)extent, NULL, NULL, image);
    cfg_diff_build_blocks(ours);
    cfg_diff_build_blocks(game);
    resolve_literals(ours, game);
    /* the game's extent: up to its last decoded instruction */
    u32 gmax = 0, omax = 0;
    for (size_t i = 0; i < game->blocks.n; i++) gmax = DK_MAX(gmax, game->blocks.v[i]->end);
    for (size_t i = 0; i < ours->blocks.n; i++) omax = DK_MAX(omax, ours->blocks.v[i]->end);
    game->extent = game->blocks.n ? gmax : (u32)extent;
    ours->size = ours->blocks.n ? omax : (u32)fn->code.n;
    game->size = game->extent;
    *ours_out = ours;
    *game_out = game;
}

static CfgDiffAnalysis *analyse_impl(const DkResult *result, const DkImage *image, const char *target, i64 game_size) {
    CfgDiffSide *ours, *game;
    sides_of(result, image, game_size, &ours, &game);
    CfgDiffAlign *alp = cfg_diff_align(ours, game);
    const AlignS *al = alp->priv_;
    FindVec found = find_findings(ours, game, alp);
    CfgDiffAnalysis *an = DK_NEW(A_, CfgDiffAnalysis);
    for (i32 o = 0; o < al->no; o++) {
        if (al->mo[o] < 0) continue;
        const char *r = al->rel[o];
        const char *note = "";
        if (r) note = strcmp(r, "inverted") == 0 ? "inv" : strcmp(r, "inv+mir") == 0 ? "inv,mir" : strcmp(r, "mirrored") == 0 ? "mir" : "";
        CfgDiffMapping m = {PF("+%03X", ours->blocks.v[o]->start), PF("+%03X", game->blocks.v[al->mo[o]]->start), al->how[o], note,
                            al->score[o], true};
        dk_vec_push(&an->mapping, m);
    }
    for (i32 o = 0; o < al->no; o++)
        if (al->copy_o[o] >= 0) {
            CfgDiffMapping m = {PF("+%03X", ours->blocks.v[o]->start), PF("+%03X", game->blocks.v[al->copy_o[o]]->start), "copy",
                                "ours copy", 0.0, false};
            dk_vec_push(&an->mapping, m);
        }
    for (i32 g = 0; g < al->ng; g++)
        if (al->copy_g[g] >= 0) {
            CfgDiffMapping m = {PF("+%03X", ours->blocks.v[al->copy_g[g]]->start), PF("+%03X", game->blocks.v[g]->start), "copy",
                                "game copy", 0.0, false};
            dk_vec_push(&an->mapping, m);
        }
    for (size_t i = 0; i < found.n; i++) dk_vec_push(&an->findings, found.v[i].f);
    an->address = result->theirs_va;
    an->target = target;
    an->size_ours = ours->size;
    an->size_game = game->size;
    an->blocks_ours = (i64)ours->blocks.n;
    an->blocks_game = (i64)game->blocks.n;
    an->matched = (i64)al->order.n;
    an->ours = ours;
    an->game = game;
    an->align = alp;
    return an;
}

CfgDiffAnalysis *cfg_diff_analyse(const DkResult *result, const DkImage *image, const char *target, i64 game_size,
                                  const char **err) {
    DkTry t;
    if (DK_TRY(&t)) {
        CfgDiffAnalysis *an = analyse_impl(result, image, target, game_size);
        dk_try_end(&t);
        return an;
    }
    if (!err) dk_panic(__FILE__, __LINE__, "cfg_diff.analyse: %s", t.msg);
    *err = dk_strdup(A_, t.msg);
    return NULL;
}

const char *cfg_diff_one_liner(const CfgDiffAnalysis *a) {
    size_t counts[DK_ARRAY_LEN(LEVER) + 8] = {0};
    DK_ASSERT(CFG_DIFF_NKINDS <= DK_ARRAY_LEN(counts));
    for (size_t i = 0; i < a->findings.n; i++) counts[kind_index(a->findings.v[i].kind)]++;
    DkBuf out;
    dk_buf_init(&out, A_);
    bool any = false;
    for (size_t k = 0; k < CFG_DIFF_NKINDS; k++) {
        if (!counts[k]) continue;
        if (any) dk_buf_putz(&out, ", ");
        any = true;
        if (counts[k] == 1)
            dk_buf_putz(&out, CFG_DIFF_KINDS[k]);
        else
            dk_buf_printf(&out, "%s x%zu", CFG_DIFF_KINDS[k], counts[k]);
    }
    return any ? dk_buf_cz(&out) : "no structural difference";
}

/* ---------------------------------------------------------------- output */

static const char *hexaddr_s(i64 address) {
    return PF("%08X", (u32)address);
}

static const char *term_text(const CfgDiffBlock *b) { return b->cond ? PF("%s %s", b->term, b->cond) : b->term; }

DkStr cfg_diff_format_analysis(const char *name, const CfgDiffAnalysis *a, bool verbose) {
    DkBuf out;
    dk_buf_init(&out, A_);
    const CfgDiffSide *ours = a->ours, *game = a->game;
    const AlignS *al = a->align->priv_;
    dk_buf_pyfmt(&out, "%-4s %s  %s  ours %d bytes / %d blocks, game %d bytes / %d blocks, %d matched\n", a->target, hexaddr_s(a->address), name,
                 a->size_ours, a->blocks_ours, a->size_game, a->blocks_game, a->matched);
    DkBuf line;
    dk_buf_init(&line, A_);
    dk_buf_putz(&line, "  blocks (ours -> game):");
    for (size_t i = 0; i < a->mapping.n; i++) {
        const CfgDiffMapping *m = &a->mapping.v[i];
        if (strcmp(m->how, "copy") == 0) continue;
        const char *cell = *m->note ? PF("%s->%s (%s)", m->ours, m->game, m->note) : PF("%s->%s", m->ours, m->game);
        if (line.n + strlen(cell) + 2 > 118) {
            dk_buf_pyfmt(&out, "%s\n", dk_buf_cz(&line));
            dk_buf_clear(&line);
            dk_buf_putz(&line, "   ");
        }
        dk_buf_putz(&line, "  ");
        dk_buf_putz(&line, cell);
    }
    dk_buf_pyfmt(&out, "%s\n", dk_buf_cz(&line));
    if (verbose) {
        dk_buf_pyfmt(&out, "  %-5s %-6s %5s %-7s %-22s %-8s %s\n", "side", "block", "size", "term", "successors", "mapped", "score/how");
        for (int pass = 0; pass < 2; pass++) {
            const CfgDiffSide *side = pass == 0 ? ours : game, *other = pass == 0 ? game : ours;
            const i32 *m = pass == 0 ? al->mo : al->mg;
            const i32 *copy = pass == 0 ? al->copy_o : al->copy_g;
            for (size_t bi = 0; bi < side->blocks.n; bi++) {
                const CfgDiffBlock *b = side->blocks.v[bi];
                DkBuf sb;
                dk_buf_init(&sb, A_);
                for (size_t k = 0; k < b->succ.n; k++) {
                    if (k) dk_buf_putc(&sb, ' ');
                    if (b->succ.v[k].to >= 0)
                        dk_buf_printf(&sb, "%s:+%03X", b->succ.v[k].role, side->blocks.v[b->succ.v[k].to]->start);
                    else
                        dk_buf_printf(&sb, "%s:?", b->succ.v[k].role);
                }
                i32 cp = m[b->idx];
                const char *mapped, *how;
                if (cp >= 0) {
                    mapped = PF("+%03X", other->blocks.v[cp]->start);
                    i32 key = pass == 0 ? b->idx : cp;
                    how = PF("%v %s", al->score[key], al->how[key]);
                } else {
                    i32 cpy = copy[b->idx];
                    mapped = cpy >= 0 ? PF("copy of +%03X", other->blocks.v[cpy]->start) : "-";
                    how = "";
                }
                dk_buf_pyfmt(&out, "  %-5s +%03X %6d %-7s %-22s %-8s %s\n", side->name, b->start, b->end - b->start, term_text(b),
                             dk_buf_cz(&sb), mapped, how);
            }
        }
    }
    dk_buf_pyfmt(&out, "  findings:\n");
    if (!a->findings.n) dk_buf_pyfmt(&out, "    (none: the blocks map 1-1 with the same edges; register or schedule)\n");
    for (size_t i = 0; i < a->findings.n; i++) {
        dk_buf_pyfmt(&out, "    %-16s %s\n", a->findings.v[i].kind, a->findings.v[i].evidence);
        dk_buf_pyfmt(&out, "        lever: %s\n", a->findings.v[i].lever);
    }
    dk_buf_pyfmt(&out, "  summary: %s\n", cfg_diff_one_liner(a));
    return dk_buf_str(&out);
}

void cfg_diff_print_analysis(const char *name, const CfgDiffAnalysis *a, bool verbose) {
    DkStr text = cfg_diff_format_analysis(name, a, verbose);
    dk_pyprintf("%S", &text);
}

/* colour_maps(a): "red" (unmatched), "orange" (flagged by a finding of the compare / order kinds) or "green" per block. */
static const char *const *colour_of(const CfgDiffAnalysis *a, bool ours_side) {
    const CfgDiffSide *side = ours_side ? a->ours : a->game;
    const AlignS *al = a->align->priv_;
    const i32 *m = ours_side ? al->mo : al->mg;
    const char **col = DK_NEWN(A_, const char *, side->blocks.n + 1);
    for (size_t bi = 0; bi < side->blocks.n; bi++) {
        const CfgDiffBlock *b = side->blocks.v[bi];
        const char *off = PF("+%03X", b->start);
        bool flagged = false;
        for (size_t fi = 0; fi < a->findings.n && !flagged; fi++) {
            const char *k = a->findings.v[fi].kind;
            if (!(strcmp(k, "inverted-branch") == 0 || strcmp(k, "block-order") == 0 || strcmp(k, "mirrored-compare") == 0 ||
                  strcmp(k, "loop-rotation") == 0))
                continue;
            const DkCzVec *l = ours_side ? &a->findings.v[fi].ours : &a->findings.v[fi].game;
            for (size_t q = 0; q < l->n; q++) flagged |= strcmp(l->v[q], off) == 0;
        }
        col[bi] = m[b->idx] < 0 ? "red" : (flagged ? "orange" : "green");
    }
    return col;
}

static bool write_utf8_lf(const char *path, DkStr text) {
    return dk_write_text(path, text, DK_TM_UTF8_NL_LF);
}

static void make_parent_dir(const char *path) {
    char *dir = dk_strdup(A_, path);
    DkStr d = dk_path_dirname(dir);
    char *dz = dk_cz(A_, d);
    if (!dk_makedirs(dz, true)) dk_panic(__FILE__, __LINE__, "cannot create %s: %s", dz, dk_io_err_str(A_).p);
}

static const char *fill_of(const char *colour) {
    return strcmp(colour, "green") == 0 ? "#c8f0c8" : strcmp(colour, "orange") == 0 ? "#ffd8a0" : "#ffb0b0";
}

const char *cfg_diff_write_dot(const char *path, const char *name, const CfgDiffAnalysis *a) {
    const AlignS *al = a->align->priv_;
    DkBuf out;
    dk_buf_init(&out, A_);
    DkStr nm = dk_str_replace(A_, dk_str(name), DK_S("\""), DK_S("'"), -1);
    dk_buf_printf(&out, "digraph cfg {\n  label=\"%.*s\"; node [shape=box, style=filled, fontname=\"Consolas\", fontsize=9];", DK_SF(nm));
    for (int pass = 0; pass < 2; pass++) {
        const CfgDiffSide *side = pass == 0 ? a->ours : a->game;
        const char *p = pass == 0 ? "o" : "g";
        const char *const *cols = colour_of(a, pass == 0);
        dk_buf_printf(&out, "\n  subgraph cluster_%s { label=\"%s\";", p, side->name);
        for (size_t bi = 0; bi < side->blocks.n; bi++) {
            const CfgDiffBlock *b = side->blocks.v[bi];
            DkBuf text;
            dk_buf_init(&text, A_);
            dk_buf_printf(&text, "+%03X %s\\l", b->start, term_text(b));
            for (size_t k = 0; k < b->insns.n && k < 8; k++) {
                DkStr s = dk_str_replace(A_, dk_str(PF("%s %s\\l", b->insns.v[k]->mnemonic, b->insns.v[k]->op_str)), DK_S("\""),
                                           DK_S("'"), -1);
                dk_buf_put(&text, s);
            }
            if (b->insns.n > 8) dk_buf_putz(&text, "...\\l");
            dk_buf_printf(&out, "\n    %s%d [label=\"%s\", fillcolor=\"%s\"];", p, b->idx, dk_buf_cz(&text), fill_of(cols[b->idx]));
        }
        for (size_t bi = 0; bi < side->blocks.n; bi++) {
            const CfgDiffBlock *b = side->blocks.v[bi];
            for (size_t k = 0; k < b->succ.n; k++) {
                if (b->succ.v[k].to < 0) continue;
                const char *role = b->succ.v[k].role;
                dk_buf_printf(&out, "\n    %s%d -> %s%d [label=\"%s\"];", p, b->idx, p, b->succ.v[k].to,
                               strcmp(role, "taken") == 0 ? "T" : strcmp(role, "fall") == 0 ? "F" : "");
            }
        }
        dk_buf_putz(&out, "\n  }");
    }
    for (size_t i = 0; i < al->order.n; i++)
        dk_buf_printf(&out, "\n  o%d -> g%d [style=dashed, color=gray, constraint=false, arrowhead=none];", al->order.v[i],
                       al->mo[al->order.v[i]]);
    dk_buf_putz(&out, "\n}\n");
    make_parent_dir(path);
    if (!write_utf8_lf(path, dk_buf_str(&out))) dk_panic(__FILE__, __LINE__, "cannot write %s: %s", path, dk_io_err_str(A_).p);
    return path;
}

/* html.escape(s) with quote=True */
static void html_escape(DkBuf *out, const char *s) {
    for (; *s; s++) {
        switch (*s) {
        case '&': dk_buf_putz(out, "&amp;"); break;
        case '<': dk_buf_putz(out, "&lt;"); break;
        case '>': dk_buf_putz(out, "&gt;"); break;
        case '"': dk_buf_putz(out, "&quot;"); break;
        case '\'': dk_buf_putz(out, "&#x27;"); break;
        default: dk_buf_putc(out, *s);
        }
    }
}
static const char *html_esc(const char *s) {
    DkBuf b;
    dk_buf_init(&b, A_);
    html_escape(&b, s);
    return dk_buf_cz(&b);
}

const char *cfg_diff_write_html(const char *path, const char *name, const CfgDiffAnalysis *a) {
    const AlignS *al = a->align->priv_;
    static const char *const PALETTE[] = {"#e6f2ff", "#fff0e6", "#eaffea", "#f6e6ff", "#ffffe0", "#e0ffff", "#ffe6f0", "#f0f0f0"};
    DkStr svg = {"", 0};
    if (dk_which(A_, "dot", NULL, NULL)) {
        DkStr stem, ext;
        dk_path_splitext(path, &stem, &ext);
        const char *dot = cfg_diff_write_dot(PF("%S.dot", &stem), name, a);
        const char *argv[] = {"dot", "-Tsvg", dot, NULL};
        DkProcSpec spec = {0};
        spec.argv = argv;
        spec.out = DK_IO_CAPTURE;
        spec.err = DK_IO_CAPTURE;
        spec.text = true;
        spec.timeout = 60;
        DkProcResult r = dk_run(&spec);
        if (r.status == DK_PROC_OK || r.status == DK_PROC_BAD_EXIT) {
            i64 at = dk_str_find(r.out, DK_S("<svg"), 0, DK_END);
            if (at >= 0) svg = dk_str_slice(r.out, at, DK_END);
        }
    }
    const char *const *col_o = colour_of(a, true), *const *col_g = colour_of(a, false);
    DkBuf out;
    dk_buf_init(&out, A_);
    dk_buf_printf(&out, "<!doctype html><html><head><meta charset='utf-8'><title>%s</title><style>\n", html_esc(name));
    dk_buf_putz(&out,
                 "body{font-family:Consolas,monospace;font-size:12px;margin:12px}table{border-collapse:collapse}"
                 "td{vertical-align:top;padding:4px}.blk{border-left:4px solid;margin:4px 0;padding:2px 6px}"
                 "pre{margin:0}.f{margin:2px 0}.lever{color:#666;margin-left:2em}</style></head><body>");
    dk_buf_printf(&out, "\n<h3>%s %s %s</h3>\n", html_esc(a->target), hexaddr_s(a->address), html_esc(name));
    dk_buf_printf(&out, "<p>ours %lld bytes / %lld blocks, game %lld bytes / %lld blocks, %lld matched</p><h4>findings</h4>",
                   (long long)a->size_ours, (long long)a->blocks_ours, (long long)a->size_game, (long long)a->blocks_game,
                   (long long)a->matched);
    if (!a->findings.n) {
        dk_buf_printf(&out, "\n<div class='f'><b>%s</b> %s<div class='lever'>%s</div></div>", "none", "the blocks map 1-1", "");
    }
    for (size_t i = 0; i < a->findings.n; i++) {
        const CfgDiffFinding *f = &a->findings.v[i];
        dk_buf_printf(&out, "\n<div class='f'><b>%s</b> %s<div class='lever'>%s</div></div>", html_esc(f->kind), html_esc(f->evidence),
                       html_esc(f->lever));
    }
    dk_buf_putz(&out, "\n<table><tr><th>ours</th><th>game</th></tr><tr>");
    for (int pass = 0; pass < 2; pass++) {
        const CfgDiffSide *side = pass == 0 ? a->ours : a->game, *other = pass == 0 ? a->game : a->ours;
        const char *const *cols = pass == 0 ? col_o : col_g;
        const i32 *m = pass == 0 ? al->mo : al->mg;
        const char *p = pass == 0 ? "o" : "g", *q = pass == 0 ? "g" : "o";
        dk_buf_putz(&out, "\n<td>");
        for (size_t bi = 0; bi < side->blocks.n; bi++) {
            const CfgDiffBlock *b = side->blocks.v[bi];
            i32 cp = m[b->idx];
            i32 pair = pass == 0 ? b->idx : cp;
            const char *bg = cp >= 0 ? PALETTE[pair % DK_ARRAY_LEN(PALETTE)] : "#fff";
            const char *link = cp >= 0 ? PF(" &rarr; <a href='#%s%d'>+%03X</a>", q, cp, other->blocks.v[cp]->start) : " (unmatched)";
            const char *colour = cols[b->idx];
            const char *border = strcmp(colour, "green") == 0 ? "#3a3" : strcmp(colour, "orange") == 0 ? "#e80" : "#d22";
            dk_buf_printf(&out, "\n<div class='blk' id='%s%d' style='border-color:%s;background:%s'><b>+%03X</b> %s%s<pre>", p, b->idx,
                           border, bg, b->start, html_esc(term_text(b)), link);
            for (size_t k = 0; k < b->insns.n; k++) {
                const cs_insn *ins = b->insns.v[k];
                dk_buf_putc(&out, '\n');
                html_escape(&out, PF("+%03X  %s %s", (u32)((i64)ins->address - (i64)side->base), ins->mnemonic, ins->op_str));
            }
            dk_buf_putz(&out, "\n</pre></div>");
        }
        dk_buf_putz(&out, "\n</td>");
    }
    dk_buf_putz(&out, "\n</tr></table>");
    if (svg.n) {
        dk_buf_putz(&out, "\n<h4>graph</h4>");
        dk_buf_put(&out, svg);
    }
    dk_buf_putz(&out, "\n</body></html>");
    make_parent_dir(path);
    if (!write_utf8_lf(path, dk_buf_str(&out))) dk_panic(__FILE__, __LINE__, "cannot write %s: %s", path, dk_io_err_str(A_).p);
    return path;
}

/* ---------------------------------------------------------------- CLI */

/* name_text(name): a printable function name. */
static const char *name_text(const char *name) { return name ? name : "(unnamed)"; }

/* safe(name): every run of characters outside [A-Za-z0-9_.-] becomes one "_", the result stripped of "_" and cut to
 * 120 characters. */
static const char *safe_name(const char *name_z) {
    DkStr name = dk_str(name_z);
    DkBuf b;
    dk_buf_init(&b, A_);
    bool run_ = false;
    for (size_t i = 0; i < name.n; i++) {
        unsigned char ch = (unsigned char)name.p[i];
        bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-';
        if (ok) {
            dk_buf_putc(&b, (char)ch);
            run_ = false;
        } else if (!run_) {
            dk_buf_putc(&b, '_');
            run_ = true;
        }
    }
    DkStr s = dk_str_strip_chars(dk_buf_str(&b), DK_S("_"));
    if (s.n > 120) s.n = 120;
    return dk_cz(A_, s);
}

/* The output folder: --out, relative to the root, else <build_dir>/cfg_diff. */
static const char *abs_out(DkProject *p, const DkArgs *args) {
    if (dk_args_is_none(args, "out") || !dk_args_str(args, "out").n) return dk_project_build_dir(p, "cfg_diff");
    return dk_project_path(A_, p, dk_cz(A_, dk_args_str(args, "out")));
}

/* Whether the result carries both sides' bytes for an analysis. */
static bool analysable(const DkResult *r) { return r->status == DK_DIFF || r->status == DK_SIZE; }

static const DkImage *image_of(DkProject *p, const DkResult *r) {
    DkErr e = {0};
    return dk_target_image(p, r->target, &e);
}

static const char *target_name(DkProject *p, const DkResult *r) { return dk_project_target(p, r->target)->name; }

/* The target option: -1 for all, else the target's index; false with the message printed. */
static bool target_opt(DkProject *p, const DkArgs *args, int *target) {
    DkStr tname = dk_args_str(args, "target");
    *target = -1;
    if (dk_str_eqz(tname, "all")) return true;
    const char *tn = dk_cz(A_, tname);
    *target = dk_project_target_index(p, tn);
    if (*target < 0) {
        fprintf(stderr, "cfg_diff: %s: not a target of %s\n", tn, dk_project_config_path(p));
        return false;
    }
    return true;
}

static int single(DkProject *p, const DkArgs *args) {
    DkStrVec pos = dk_args_strs(args, "args");
    const char *unit_arg = dk_cz(A_, pos.v[0]);
    const char *name = dk_cz(A_, pos.v[1]);
    DkUnitcmpOpts o;
    memset(&o, 0, sizeof o);
    const char *one[1] = {unit_arg};
    o.units = one;
    o.n_units = 1;
    if (!target_opt(p, args, &o.target)) return 2;
    o.function = name;
    o.use_cache = !dk_args_bool(args, "no_cache");
    DkUnitcmpRowVec rows = {0};
    DkErr err = {0};
    if (!dk_unitcmp_collect(p, &o, &rows, &err)) {
        fprintf(stderr, "cfg_diff: %s\n", err.msg);
        return 2;
    }
    bool has_want = false;
    i64 want = 0;
    if (!dk_args_is_none(args, "address") && dk_args_str(args, "address").n) {
        if (!dk_parse_int(dk_args_str(args, "address"), 16, &want, NULL)) {
            fprintf(stderr, "cfg_diff: --address: %.*s is not a hex number\n", DK_SF(dk_args_str(args, "address")));
            return 2;
        }
        has_want = true;
    }
    const char *out = abs_out(p, args);
    bool verbose = dk_args_bool(args, "verbose"), want_dot = dk_args_bool(args, "dot"), want_html = dk_args_bool(args, "html");
    int found = 0, rc = 0;
    const DkAnnot *last = NULL;
    for (size_t i = 0; i < rows.n; i++) {
        const DkResult *r = rows.v[i].r;
        if (has_want) {
            bool hit = false;
            for (size_t t = 0; t < DK_MAX_TARGETS; t++) hit |= r->ann->addr[t] != DK_NO_ADDR && (i64)r->ann->addr[t] == want;
            if (!hit) continue;
        }
        if (r->ann != last) found++;
        last = r->ann;
        const char *tn = target_name(p, r);
        const char *label = name_text(r->ann->name);
        if (!analysable(r)) {
            dk_pyprintf("%-4s %s  %s  %s\n", tn, hexaddr_s(r->theirs_va), label,
                        r->status == DK_MATCH ? "exact" : dk_status_name(r->status));
            if (r->status != DK_MATCH) rc = 1;
            continue;
        }
        const char *aerr = NULL;
        CfgDiffAnalysis *an = cfg_diff_analyse(r, image_of(p, r), tn, CFG_DIFF_NONE, &aerr);
        rc = 1;
        if (!an) {
            dk_pyprintf("cfg_diff failed: %s\n", aerr);
            continue;
        }
        cfg_diff_print_analysis(label, an, verbose);
        const char *stem = dk_path_join(A_, out, PF("%s_%s", safe_name(label), tn));
        if (want_dot) dk_pyprintf("  wrote %s\n", cfg_diff_rel(p, cfg_diff_write_dot(PF("%s.dot", stem), label, an)));
        if (want_html) dk_pyprintf("  wrote %s\n", cfg_diff_rel(p, cfg_diff_write_html(PF("%s.html", stem), label, an)));
    }
    dk_vec_free(&rows);
    if (!found) {
        dk_pyprintf("no claim named %s in %s\n", name, unit_arg);
        return 1;
    }
    return rc;
}

/* One target of one row of the batch. */
typedef struct BRec {
    const char *target;
    u32 address;
    bool skipped;
    const char *wall, *status;
    double close;
    bool analysed;              /* an analysis ran (blocks / matched exist) */
    i64 blocks_ours, blocks_game, matched;
    DkCzVec kinds;             /* sorted set of the findings' kinds ("kinds") */
    DkCzVec finding_kinds;     /* the findings' kinds in order */
    const char *one_liner;
    DkJson *json;
} BRec;

typedef struct Row {
    const char *unit;
    const char *function;
    BRec b[DK_MAX_TARGETS];
    int nb;
} Row;
typedef DK_VEC(Row) RowVec;

static DkJson *jstr(const char *s) { return dk_json_strz(A_, s); }
static void jset(DkJson *o, const char *key, DkJson *v) { dk_json_set(A_, o, dk_str(key), v); }

static DkJson *list_json(const DkCzVec *l) {
    DkJson *a = dk_json_arr(A_);
    for (size_t i = 0; i < l->n; i++) dk_json_arr_push(A_, a, jstr(l->v[i]));
    return a;
}

static int cmp_cz(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    return strcmp(*(char *const *)x, *(char *const *)y);
}

/* Every run of whitespace becomes one space. */
static const char *collapse_ws(const char *text) {
    DkBuf b;
    dk_buf_init(&b, A_);
    bool ws = false;
    for (const char *p = text; *p; p++) {
        if (*p == ' ' || (*p >= '\t' && *p <= '\r')) {
            if (!ws) dk_buf_putc(&b, ' ');
            ws = true;
        } else {
            dk_buf_putc(&b, *p);
            ws = false;
        }
    }
    return dk_buf_cz(&b);
}

/* The record of a result that is not analysed: its wall and status only. */
static void skip_record(BRec *rec, const DkUnitcmpRow *ur) {
    rec->skipped = true;
    rec->wall = ur->wall.wall ? ur->wall.wall : "";
    rec->status = dk_status_name(ur->r->status);
    rec->close = ur->wall.close;
    DkJson *o = dk_json_obj(A_);
    jset(o, "address", dk_json_int(A_, ur->r->theirs_va));
    jset(o, "wall", jstr(rec->wall));
    jset(o, "status", jstr(rec->status));
    jset(o, "close", dk_json_float(A_, rec->close));
    jset(o, "skipped", dk_json_bool(true));
    rec->json = o;
}

static void analyse_record(DkProject *p, BRec *rec, const DkUnitcmpRow *ur) {
    const DkResult *r = ur->r;
    const char *err = NULL;
    CfgDiffAnalysis *an = cfg_diff_analyse(r, image_of(p, r), rec->target, CFG_DIFF_NONE, &err);
    rec->wall = ur->wall.wall ? ur->wall.wall : "";
    rec->status = dk_status_name(r->status);
    rec->close = ur->wall.close;
    DkJson *o = dk_json_obj(A_);
    if (!an) {
        rec->one_liner = PF("error: %s", err);
        dk_vec_push(&rec->kinds, (char *)"error");
        dk_vec_push(&rec->finding_kinds, (char *)"error");
        jset(o, "address", dk_json_int(A_, r->theirs_va));
        jset(o, "wall", jstr(rec->wall));
        jset(o, "status", jstr(rec->status));
        jset(o, "close", dk_json_float(A_, rec->close));
        jset(o, "kinds", list_json(&rec->kinds));
        jset(o, "one_liner", jstr(rec->one_liner));
        DkJson *fl = dk_json_arr(A_), *f = dk_json_obj(A_);
        jset(f, "kind", jstr("error"));
        jset(f, "evidence", jstr(err));
        dk_json_arr_push(A_, fl, f);
        jset(o, "findings", fl);
        rec->json = o;
        return;
    }
    rec->analysed = true;
    rec->blocks_ours = an->blocks_ours;
    rec->blocks_game = an->blocks_game;
    rec->matched = an->matched;
    rec->one_liner = cfg_diff_one_liner(an);
    for (size_t k = 0; k < an->findings.n; k++) {
        dk_vec_push(&rec->finding_kinds, (char *)an->findings.v[k].kind);
        bool have = false;
        for (size_t q = 0; q < rec->kinds.n; q++) have |= strcmp(rec->kinds.v[q], an->findings.v[k].kind) == 0;
        if (!have) dk_vec_push(&rec->kinds, (char *)an->findings.v[k].kind);
    }
    dk_sort(rec->kinds.v, rec->kinds.n, sizeof(char *), cmp_cz, NULL, false);
    jset(o, "address", dk_json_int(A_, an->address));
    jset(o, "target", jstr(an->target));
    jset(o, "size_ours", dk_json_int(A_, an->size_ours));
    jset(o, "size_game", dk_json_int(A_, an->size_game));
    jset(o, "blocks_ours", dk_json_int(A_, an->blocks_ours));
    jset(o, "blocks_game", dk_json_int(A_, an->blocks_game));
    jset(o, "matched", dk_json_int(A_, an->matched));
    DkJson *ml = dk_json_arr(A_);
    for (size_t k = 0; k < an->mapping.n; k++) {
        const CfgDiffMapping *m = &an->mapping.v[k];
        DkJson *mo = dk_json_obj(A_);
        jset(mo, "ours", jstr(m->ours));
        jset(mo, "game", jstr(m->game));
        jset(mo, "score", m->has_score ? dk_json_float(A_, m->score) : dk_json_null());
        jset(mo, "how", jstr(m->how));
        jset(mo, "note", jstr(m->note));
        dk_json_arr_push(A_, ml, mo);
    }
    jset(o, "mapping", ml);
    DkJson *fl = dk_json_arr(A_);
    for (size_t k = 0; k < an->findings.n; k++) {
        const CfgDiffFinding *f = &an->findings.v[k];
        DkJson *fo = dk_json_obj(A_);
        jset(fo, "kind", jstr(f->kind));
        jset(fo, "ours", list_json(&f->ours));
        jset(fo, "game", list_json(&f->game));
        jset(fo, "evidence", jstr(f->evidence));
        jset(fo, "lever", jstr(f->lever));
        dk_json_arr_push(A_, fl, fo);
    }
    jset(o, "findings", fl);
    jset(o, "wall", jstr(rec->wall));
    jset(o, "status", jstr(rec->status));
    jset(o, "close", dk_json_float(A_, rec->close));
    jset(o, "kinds", list_json(&rec->kinds));
    jset(o, "one_liner", jstr(rec->one_liner));
    rec->json = o;
}

static bool write_text(const char *path, DkStr text) {
    if (!write_utf8_lf(path, text)) {
        fprintf(stderr, "cfg_diff: cannot write %s: %s\n", path, dk_io_err_str(A_).p);
        return false;
    }
    return true;
}

int cfg_diff_batch(DkProject *p, const DkUnitcmpRowVec *urows, const CfgDiffBatchOpts *bo) {
    RowVec rows = {0};
    DkJson *compile_errors = dk_json_obj(A_);
    DkRe *select = NULL;
    if (bo->select && *bo->select) select = dk_re_try_n(dk_str(bo->select), 0);
    const DkAnnot *prev = NULL;
    const DkUnit *prev_unit = NULL;
    for (size_t i = 0; i < urows->n; i++) {
        const DkUnitcmpRow *ur = &urows->v[i];
        const DkResult *r = ur->r;
        if (r->status == DK_ERROR) {
            if (r->error && !dk_json_get(compile_errors, dk_str(ur->unit->path))) jset(compile_errors, ur->unit->path, jstr(r->error));
            continue;
        }
        if (r->status == DK_MATCH || r->status == DK_MISSING) continue;
        if (bo->stopped && !dk_stopped(r->ann, r->target)) continue;
        if (select && !dk_re_search(select, dk_str(r->ann->name ? r->ann->name : ""), 0, DK_END, NULL)) continue;
        if (!(rows.n && prev == r->ann && prev_unit == ur->unit)) {
            Row row;
            memset(&row, 0, sizeof row);
            row.unit = ur->unit->path;
            row.function = r->ann->name;
            dk_vec_push(&rows, row);
        }
        prev = r->ann;
        prev_unit = ur->unit;
        Row *row = &rows.v[rows.n - 1];
        if (row->nb >= DK_MAX_TARGETS) continue;
        BRec *rec = &row->b[row->nb++];
        rec->target = target_name(p, r);
        rec->address = r->theirs_va;
        if (!analysable(r) || (strcmp(ur->wall.wall ? ur->wall.wall : "", "control-flow") != 0 && !bo->all_walls)) {
            skip_record(rec, ur);
            continue;
        }
        analyse_record(p, rec, ur);
    }
    /* a row whose every target was skipped is not a batch row */
    size_t keep = 0;
    for (size_t i = 0; i < rows.n; i++) {
        bool any = false;
        for (int k = 0; k < rows.v[i].nb; k++) any |= !rows.v[i].b[k].skipped;
        if (any) rows.v[keep++] = rows.v[i];
    }
    rows.n = keep;

    const char *out = bo->out;
    if (!dk_makedirs(out, true)) {
        fprintf(stderr, "cfg_diff: cannot create %s: %s\n", out, dk_io_err_str(A_).p);
        return 2;
    }
    size_t nk = CFG_DIFF_NKINDS;
    size_t *funcs = DK_NEWN(A_, size_t, nk), *totals = DK_NEWN(A_, size_t, nk);
    for (size_t ri = 0; ri < rows.n; ri++) {
        const Row *row = &rows.v[ri];
        size_t *per_kind = DK_NEWN(A_, size_t, nk);
        bool *seen = DK_NEWN(A_, bool, nk);
        for (int bi = 0; bi < row->nb; bi++) {
            const BRec *v = &row->b[bi];
            if (v->skipped) continue;
            size_t *cnt = DK_NEWN(A_, size_t, nk);
            for (size_t k = 0; k < v->finding_kinds.n; k++) {
                int ki = kind_index(v->finding_kinds.v[k]);
                seen[ki] = true;
                cnt[ki]++;
            }
            for (size_t k = 0; k < nk; k++) per_kind[k] = DK_MAX(per_kind[k], cnt[k]);
        }
        for (size_t k = 0; k < nk; k++) {
            funcs[k] += seen[k];
            totals[k] += per_kind[k];
        }
    }

    DkCzVec hist = {0};
    for (size_t k = 0; k < nk; k++)
        if (funcs[k]) dk_vec_push(&hist, (char *)PF("%-17s %4d functions  %4d findings", CFG_DIFF_KINDS[k], funcs[k], totals[k]));
    const char *head = PF("analysed %d non-matching function(s) (%s)", rows.n, bo->all_walls ? "every DIFF or SIZE result" : "control-flow walls");

    DkCzVec liners = {0};
    for (size_t ri = 0; ri < rows.n; ri++) {
        const Row *row = &rows.v[ri];
        DkBuf lb;
        dk_buf_init(&lb, A_);
        const char *prev_text = NULL;
        for (int bi = 0; bi < row->nb; bi++) {
            const BRec *v = &row->b[bi];
            const char *text = v->skipped ? PF("(%s wall, not analysed)", v->wall) : v->one_liner;
            if (bi) dk_buf_putz(&lb, " | ");
            dk_buf_printf(&lb, "%s: %s", v->target, prev_text && strcmp(text, prev_text) == 0 ? "same" : text);
            prev_text = text;
        }
        dk_vec_push(&liners, dk_buf_cz(&lb));
    }

    {
        DkBuf tsv;
        dk_buf_init(&tsv, A_);
        dk_buf_putz(&tsv, "unit\tfunction\ttarget\taddress\tblocks_ours\tblocks_game\tmatched\tkinds\tone_liner\n");
        for (size_t ri = 0; ri < rows.n; ri++) {
            const Row *row = &rows.v[ri];
            for (int bi = 0; bi < row->nb; bi++) {
                const BRec *v = &row->b[bi];
                if (v->skipped) continue;
                DkBuf kb;
                dk_buf_init(&kb, A_);
                for (size_t k = 0; k < v->kinds.n; k++) dk_buf_printf(&kb, "%s%s", k ? " " : "", v->kinds.v[k]);
                dk_buf_printf(&tsv, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", row->unit, name_text(row->function), v->target,
                               v->address ? PF("%08X", v->address) : "",
                               v->analysed ? PF("%d", v->blocks_ours) : "", v->analysed ? PF("%d", v->blocks_game) : "",
                               v->analysed ? PF("%d", v->matched) : "", dk_buf_cz(&kb), collapse_ws(v->one_liner));
            }
        }
        if (!write_text(dk_path_join(A_, out, "batch.tsv"), dk_buf_str(&tsv))) return 2;
    }
    {
        DkJson *root = dk_json_obj(A_), *fl = dk_json_arr(A_), *hj = dk_json_obj(A_);
        for (size_t ri = 0; ri < rows.n; ri++) {
            const Row *row = &rows.v[ri];
            DkJson *ro = dk_json_obj(A_), *bj = dk_json_obj(A_);
            jset(ro, "unit", jstr(row->unit));
            jset(ro, "function", row->function ? jstr(row->function) : dk_json_null());
            for (int bi = 0; bi < row->nb; bi++) jset(bj, row->b[bi].target, row->b[bi].json);
            jset(ro, "targets", bj);
            dk_json_arr_push(A_, fl, ro);
        }
        for (size_t k = 0; k < nk; k++)
            if (funcs[k]) {
                DkJson *e = dk_json_obj(A_);
                jset(e, "functions", dk_json_int(A_, (i64)funcs[k]));
                jset(e, "findings", dk_json_int(A_, (i64)totals[k]));
                jset(hj, CFG_DIFF_KINDS[k], e);
            }
        jset(root, "schema", jstr("decompkit-cfg-diff/1"));
        jset(root, "functions", fl);
        jset(root, "histogram", hj);
        jset(root, "compile_errors", compile_errors);
        DkJsonDumpOpts jo = DK_JSON_INDENT(1);
        if (!write_text(dk_path_join(A_, out, "batch.json"), dk_json_dumps(A_, root, &jo))) return 2;
    }
    {
        DkBuf md;
        dk_buf_init(&md, A_);
        dk_buf_printf(&md, "# cfg_diff batch\n\n%s\n\n```\n", head);
        for (size_t k = 0; k < hist.n; k++) dk_buf_printf(&md, "%s%s", k ? "\n" : "", hist.v[k]);
        dk_buf_putz(&md, "\n```\n\n");
        for (size_t ri = 0; ri < rows.n; ri++)
            dk_buf_printf(&md, "- %s `%s`  %s\n", rows.v[ri].unit, name_text(rows.v[ri].function), liners.v[ri]);
        if (!write_text(dk_path_join(A_, out, "batch.md"), dk_buf_str(&md))) return 2;
    }
    dk_pyprintf("%s\n", head);
    for (size_t k = 0; k < hist.n; k++) dk_pyprintf("%s\n", hist.v[k]);
    dk_pyprintf("\n");
    for (size_t ri = 0; ri < rows.n; ri++)
        dk_pyprintf("%s  %s  %s\n", rows.v[ri].unit, name_text(rows.v[ri].function), liners.v[ri]);
    dk_pyprintf("\nwrote %s\n", cfg_diff_rel(p, out));
    return 0;
}

int cfg_diff_main(int argc, char **argv) {
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){
        .prog = "cfg_diff", .description = DOC, .formatter = DK_FORMAT_RAW_DESCRIPTION});
    dk_arg(ap, &(DkArgDesc){.names = "args", .nargs = DK_NARGS_STAR, .help = "<unit> <Name>, or with --batch the units"});
    dk_arg(ap, &(DkArgDesc){.names = "--batch", .action = DK_ARG_STORE_TRUE});
    dk_arg(ap, &(DkArgDesc){.names = "--all", .action = DK_ARG_STORE_TRUE, .help = "with --batch: every unit of the project"});
    dk_arg(ap, &(DkArgDesc){.names = "--target", .dflt = DK_DEF_STR("all"), .metavar = "T",
                            .help = "one configured target, or all (default)"});
    dk_arg(ap, &(DkArgDesc){.names = "--address", .dflt = DK_DEF_NONE});
    dk_arg(ap, &(DkArgDesc){.names = "--html", .action = DK_ARG_STORE_TRUE});
    dk_arg(ap, &(DkArgDesc){.names = "--dot", .action = DK_ARG_STORE_TRUE});
    dk_arg(ap, &(DkArgDesc){.names = "-v --verbose", .action = DK_ARG_STORE_TRUE});
    dk_arg(ap, &(DkArgDesc){.names = "--select", .dflt = DK_DEF_NONE});
    dk_arg(ap, &(DkArgDesc){.names = "--all-walls", .action = DK_ARG_STORE_TRUE});
    dk_arg(ap, &(DkArgDesc){.names = "--stopped", .action = DK_ARG_STORE_TRUE});
    dk_arg(ap, &(DkArgDesc){.names = "--out", .dflt = DK_DEF_NONE});
    dk_arg(ap, &(DkArgDesc){.names = "--no-cache", .action = DK_ARG_STORE_TRUE});
    dk_arg(ap, &(DkArgDesc){.names = "--root", .metavar = "DIR", .dflt = DK_DEF_NONE});
    dk_arg(ap, &(DkArgDesc){.names = "--config", .metavar = "FILE", .dflt = DK_DEF_NONE});
    DkArgs *args = dk_args_parse(ap, argc, argv);
    bool batch_mode = dk_args_bool(args, "batch");
    if (!batch_mode && dk_args_len(args, "args") != 2) dk_args_error(ap, "give a unit and a function name (or --batch)");
    bool all = dk_args_bool(args, "all");
    if (batch_mode && !dk_args_len(args, "args") && !all) dk_args_error(ap, "--batch: name units, or --all");

    const char *root = dk_args_is_none(args, "root") ? NULL : dk_cz(A_, dk_args_str(args, "root"));
    const char *config = dk_args_is_none(args, "config") ? NULL : dk_cz(A_, dk_args_str(args, "config"));
    DkErr err = {0};
    DkProject *p = dk_project_load(A_, root, config, &err);
    if (!p) {
        fprintf(stderr, "cfg_diff: %s\n", err.msg);
        return 2;
    }
    if (!batch_mode) return single(p, args);

    DkStrVec units = dk_args_strs(args, "args");
    DkUnitcmpOpts o;
    memset(&o, 0, sizeof o);
    const char **names = DK_NEWN(A_, const char *, units.n + 1);
    for (size_t i = 0; i < units.n; i++) names[i] = dk_cz(A_, units.v[i]);
    o.units = names;
    o.n_units = units.n;
    o.all = all;
    if (!target_opt(p, args, &o.target)) return 2;
    o.use_cache = !dk_args_bool(args, "no_cache");
    DkUnitcmpRowVec urows = {0};
    if (!dk_unitcmp_collect(p, &o, &urows, &err)) {
        fprintf(stderr, "cfg_diff: %s\n", err.msg);
        return 2;
    }
    CfgDiffBatchOpts bo;
    memset(&bo, 0, sizeof bo);
    bo.select = dk_args_is_none(args, "select") ? NULL : dk_cz(A_, dk_args_str(args, "select"));
    bo.all_walls = dk_args_bool(args, "all_walls");
    bo.stopped = dk_args_bool(args, "stopped");
    bo.out = abs_out(p, args);
    int rc = cfg_diff_batch(p, &urows, &bo);
    dk_vec_free(&urows);
    return rc;
}

/* The key of an instruction for the instruction alignment: the mnemonic and the operand classes (register, immediate,
 * stack memory, other memory), not the registers or displacements: the two builds differ in those. */
static const char *insn_key(const cs_insn *ins) {
    DkBuf b;
    dk_buf_init(&b, A_);
    dk_buf_putz(&b, ins->mnemonic);
    unsigned n = ins->detail ? ins->detail->x86.op_count : 0;
    for (unsigned i = 0; i < n; i++) {
        const cs_x86_op *op = &ins->detail->x86.operands[i];
        if (op->type == X86_OP_REG) dk_buf_putz(&b, " r");
        else if (op->type == X86_OP_IMM) dk_buf_putz(&b, " i");
        else if (op->type == X86_OP_MEM)
            dk_buf_putz(&b, (op->mem.base == X86_REG_ESP || op->mem.base == X86_REG_EBP) ? " s" : " m");
    }
    return dk_strdup(A_, dk_cz(A_, dk_buf_str(&b)));
}

/* The aligned instruction pairs of the mapped blocks: fn(ours, game, ctx) for each. */
typedef void (*InsnPairFn)(const CfgDiffAnalysis *an, const cs_insn *x, const cs_insn *y, void *ctx);

static void insn_pairs_each(const CfgDiffAnalysis *an, InsnPairFn fn, void *ctx) {
    const CfgDiffSide *os = an->ours, *gs = an->game;
    for (size_t i = 0; i < os->blocks.n; i++) {
        DkVal *mv = dk_imap_get(an->align->mo, (u64)i);
        if (!mv || mv->i < 0 || (size_t)mv->i >= gs->blocks.n) continue;
        const CfgDiffBlock *ob = os->blocks.v[i], *gb = gs->blocks.v[mv->i];
        size_t na = ob->insns.n, nb = gb->insns.n;
        if (!na || !nb) continue;
        DkStr *ka = DK_NEWN(A_, DkStr, na), *kb = DK_NEWN(A_, DkStr, nb);
        for (size_t k = 0; k < na; k++) ka[k] = dk_str(insn_key(ob->insns.v[k]));
        for (size_t k = 0; k < nb; k++) kb[k] = dk_str(insn_key(gb->insns.v[k]));
        DkSeqMatcher *sm = dk_seqm_new_str(A_, ka, na, kb, nb, &dk_seqm_no_autojunk);
        size_t nops;
        const DkOpcode *ops = dk_seqm_opcodes(sm, &nops);
        for (size_t p = 0; p < nops; p++) {
            const DkOpcode *op = &ops[p];
            if (op->tag == DK_OP_INSERT || op->tag == DK_OP_DELETE) continue;
            if (op->tag == DK_OP_REPLACE && op->i2 - op->i1 != op->j2 - op->j1) continue;
            for (size_t k = 0; k < op->i2 - op->i1; k++) {
                const cs_insn *x = ob->insns.v[op->i1 + k], *y = gb->insns.v[op->j1 + k];
                if (op->tag == DK_OP_REPLACE && strcmp(x->mnemonic, y->mnemonic) != 0) continue;
                fn(an, x, y, ctx);
            }
        }
    }
}

static void insn_map_put(const CfgDiffAnalysis *an, const cs_insn *x, const cs_insn *y, void *ctx) {
    dk_imap_put(ctx, (u64)((i64)x->address - (i64)an->ours->base), NULL)->i = (i64)y->address - (i64)an->game->base;
}

DkIMap *cfg_diff_insn_map(const CfgDiffAnalysis *an) {
    DkIMap *out = dk_imap_new();
    insn_pairs_each(an, insn_map_put, out);
    return out;
}

/* The bytes of an instruction that the comparison masks: our relocated words, and the displacement of a relative
 * jump or call (the block mapping, not the offset, says where it goes). */
static void insn_mask(const CfgDiffSide *os, const cs_insn *x, u8 *mask) {
    memset(mask, 0, 16);
    u8 b0 = x->bytes[0];
    unsigned disp = 0;
    if (b0 == 0xE8 || b0 == 0xE9 || b0 == 0xEB || (b0 >= 0x70 && b0 <= 0x7F)) disp = 1;
    else if (b0 == 0x0F && x->bytes[1] >= 0x80 && x->bytes[1] <= 0x8F) disp = 2;
    for (unsigned k = disp; disp && k < x->size && k < 16; k++) mask[k] = 1;
    DkPtrVec rs = cfg_diff_side_reloc_in(os, (u32)(x->address - os->base), x->size);
    for (size_t i = 0; i < rs.n; i++) {
        const DkReloc *r = rs.v[i];
        u32 off = (u32)(r->offset - (u32)(x->address - os->base));
        for (u32 k = off; k < off + 4 && k < x->size && k < 16; k++) mask[k] = 1;
    }
    dk_vec_free(&rs);
}

typedef struct BlockScoreAcc {
    i64 equal;
} BlockScoreAcc;

static void block_score_pair(const CfgDiffAnalysis *an, const cs_insn *x, const cs_insn *y, void *ctx) {
    BlockScoreAcc *acc = ctx;
    if (x->size != y->size || x->size > 16) return;
    u8 mask[16];
    insn_mask(an->ours, x, mask);
    for (unsigned k = 0; k < x->size; k++)
        if (!mask[k] && x->bytes[k] != y->bytes[k]) return;
    acc->equal += y->size;
}

double cfg_diff_block_score(const CfgDiffAnalysis *an) {
    BlockScoreAcc acc = {0};
    insn_pairs_each(an, block_score_pair, &acc);
    if (an->size_game <= 0) return 0.0;
    double pct = 100.0 * (double)acc.equal / (double)an->size_game;
    return pct > 100.0 ? 100.0 : pct;
}

bool cfg_diff_result_block_score(const DkResult *result, const DkImage *image, double *pct) {
    if (!result || result->error || result->theirs_va == DK_NO_ADDR) return false;
    const char *err = NULL;
    CfgDiffAnalysis *an = cfg_diff_analyse(result, image, "", CFG_DIFF_NONE, &err);
    if (!an) return false;
    *pct = cfg_diff_block_score(an);
    return true;
}
