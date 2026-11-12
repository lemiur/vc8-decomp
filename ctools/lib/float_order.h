// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* float_order: float expression orders against the reference's. It reads the float operation trees (add/sub/mul/div,
 * neg/abs, ...) out of the reference's machine code at the annotated address and out of ours, classifies every
 * reference node against ours (match / commute / assoc / absent), rewrites the body's float expressions in place into
 * algebraically equal spellings (commute, reassociate, every order of 3-4 terms, factor, sign forms, x * 0.5f <->
 * x / 2.0f, compound-assignment and split/join/inline statement moves), builds them in parallel through the scorer
 * (scorer.h) and ranks them by (FScore, extra operations, scorer score). Output goes under <build_dir>/float_order/
 * <Name>_<address>/ (result.json, state<k>_<tag>.diff); --batch runs one child per body-wall result of the adapter.
 *
 * The library layers below are exposed for tests/float_order_test.c.
 *
 * Differences from a textual port worth knowing:
 *   - the node signatures (ordered / commuted / flat) are 64-bit structural hashes; they only ever decide equality
 *     (index keys, counter keys, set membership), never an order that reaches an output;
 *   - the spelling trees ("a", text) | ("n", x) | ("b", op, l, r) are hash-consed (FoTr): tree equality is pointer
 *     equality;
 *   - a parse error is dk_throw(DK_ERR_OTHER) caught inside fo_parse_stmt;
 *   - the search runs on a thread with a 128 MiB stack (deep trees recurse). */
#pragma once
#include "dk/dk.h"
#include "project.h"
#include "scorer.h"
#include "dk/disasm.h"

/* ============================================================================================ 1. float trees */

typedef enum {
    FO_LEAF, FO_ADD, FO_SUB, FO_MUL, FO_DIV, FO_MIN, FO_MAX, FO_SQRT, FO_RSQRT, FO_RCP, FO_NEG, FO_ABS, FO_CMP
} FoOp;
/* The op's name ("leaf", "add", ...). */
const char *fo_op_name(FoOp op);

typedef struct FoNode {
    FoOp op;
    struct FoNode *l, *r;   /* r NULL for unary operations and leaves */
    const char *label;      /* leaves */
    u64 o, c, f;            /* ordered / commuted / flat signatures, computed on demand (have bits 1, 2, 4) */
    unsigned have;
} FoNode;

typedef struct FoRoot {
    bool store;             /* ("store", label, node) or ("cmp", node) */
    const char *label;
    FoNode *node;
} FoRoot;

typedef struct FoTree {
    DK_VEC(FoNode *) nodes;        /* every operation node, in creation order */
    DK_VEC(FoNode *) interesting;  /* the add/sub/mul/div nodes among them */
    DK_VEC(FoRoot) roots;
} FoTree;

u64 fo_ordered(FoNode *n);
u64 fo_commuted(FoNode *n);
u64 fo_flat(FoNode *n);
/* Computes the three signatures of every node (a tree shared by threads is prepared first, then read only). */
void fo_tree_prepare(FoTree *t);
/* render(n, depth, top) and cut(text, n). */
const char *fo_render(const FoNode *n, int depth, bool top);
const char *fo_cut(const char *text, int n);

/* float_tree(code, base, reloc_bytes): the symbolic dataflow over the straight-line stream. reloc_bytes: a bitmap
 * indexed by code offset (NULL for the empty set), n_reloc its length. Nodes, labels and the tree itself come from
 * arena a (a scratch arena works: nothing outlives the caller's mark); fo_tree_free releases the vectors. */
FoTree *fo_float_tree(DkArena *a, DkStr code, u32 base, const u8 *reloc_bytes, size_t n_reloc);
void fo_tree_free(FoTree *t);

enum { FO_MATCH, FO_COMMUTE, FO_ASSOC, FO_ABSENT };
extern const char *const FO_CLASS_NAMES[4];
/* match_nodes(game, ours): the class of every interesting game node (an DkU32Vec of FO_*) and, when used != NULL,
 * a flag per interesting node of ours (filled by the caller-sized array of ours->interesting.n bytes). */
void fo_match_nodes(const FoTree *game, const FoTree *ours, u8 *classes, u8 *used);
/* extra_ops(game, ours) and fscore(classes): (absent, assoc, commute). */
i64 fo_extra_ops(const FoTree *game, const FoTree *ours);
void fo_fscore(const u8 *classes, size_t n, i64 f[3]);
/* class_counts(classes) printed as the dict repr "{'match': 1, 'commute': 0, 'assoc': 0, 'absent': 0}". */
const char *fo_class_counts_repr(const u8 *classes, size_t n);

/* ====================================================================================== 2. parsing expressions */

typedef enum { FP_ASSIGN, FP_COND, FP_BIN, FP_NEG, FP_UN, FP_ATOM, FP_PAREN } FoPKind;
typedef struct FoP {
    FoPKind kind;
    DkStr op;              /* p == NULL: None */
    struct FoP **a;
    int na;
    i64 s, e;               /* byte offsets into the statement text */
} FoP;

typedef enum { FS_OTHER, FS_CTL, FS_RET, FS_EXPR, FS_DECL } FoStmtKind;
typedef struct FoStmtInfo {
    DK_VEC(FoP *) roots;
    FoStmtKind kind;
    bool bad;
    bool multi;
    bool expr_at0;
    FoP *expr;              /* kind expr (and the last expression parsed) */
    FoP *init;              /* a declaration's initialiser */
    DkStr name, type;      /* a declaration's name and type text */
} FoStmtInfo;
/* parse_stmt(text): ParseError gives kind other with bad set. */
FoStmtInfo fo_parse_stmt(DkStr text);

/* ================================================================================================= 3. spellings */

/* Trees: ("a", text) | ("n", x) | ("b", op, l, r), hash-consed. */
typedef struct FoTr {
    char kind;              /* 'a', 'n', 'b' */
    char op;                /* 'b': one of + - * / */
    DkStr text;            /* 'a' */
    struct FoTr *l, *r;     /* 'n': l; 'b': l and r */
    const char *rtext;      /* render_tree cache */
    int rprec;
} FoTr;
FoTr *fo_tr_a(DkStr text);
FoTr *fo_tr_n(FoTr *x);
FoTr *fo_tr_b(char op, FoTr *l, FoTr *r);
/* render_tree(t)[0]. */
const char *fo_render_tree(FoTr *t);

typedef struct FoSite {
    i64 s, e;
    FoTr *tree;
    DkStr text;
    bool paren;
    int leaves;
    bool hint;
    int nth;
} FoSite;
typedef DK_VEC(FoSite) FoSiteVec;
/* find_sites(text, info, float_names): float_names an DkSet (NULL: empty). */
FoSiteVec fo_find_sites(DkStr text, const FoStmtInfo *info, const DkSet *float_names);

/* The moves (bit set), ALL_MOVES and the sorted repr "['assoc', 'commute']". */
enum { FOM_COMMUTE = 1, FOM_ASSOC = 2, FOM_SUMORDER = 4, FOM_FACTOR = 8, FOM_SIGN = 16, FOM_HALF = 32 };
#define FO_ALL_MOVES 63u
const char *fo_moves_repr(unsigned allowed);
typedef struct FoPath {
    struct FoPath *prev;
    const char *mv;
} FoPath;
typedef struct FoSpelling {
    const char *text;
    FoTr *tree;
    FoPath *path;           /* the moves, last first */
} FoSpelling;
typedef DK_VEC(FoSpelling) FoSpellingVec;
/* spellings(tree, max_n, allowed, hint, paren): distinct rendered spellings, nearest first. */
FoSpellingVec fo_spellings(FoTr *tree, size_t max_n, unsigned allowed, bool hint, bool paren);
/* ",".join(path) in move order. */
const char *fo_path_text(const FoPath *p);

typedef struct FoStmt {
    i64 lo, hi;
    DkStr text;
} FoStmt;
typedef DK_VEC(FoStmt) FoStmtVec;
FoStmtVec fo_group_statements(const DkCzVec *lines);

typedef struct FoVariant {
    DkCzVec body;
    const char *note;
} FoVariant;
typedef DK_VEC(FoVariant) FoVariantVec;
/* stmt_variants(body, only): only is a sorted array of statement ordinals (NULL: all). */
FoVariantVec fo_stmt_variants(const DkCzVec *body, const DkISet *only);

/* ============================================================================================= 4. the commands */

typedef struct FloatOrderArgs {
    DkProject *project;
    const DkUnit *unit_def;     /* set by the search from unit */
    const char *unit, *name;
    const char *target;         /* NULL: the function's first annotated target */
    const char *address;        /* hex text or NULL */
    double minutes;
    bool minutes_int;           /* the default applied: printed without ".0" */
    bool minutes_set;
    i64 workers;
    bool workers_set;
    i64 line, max_site;
    bool quiet, full_unit, tree_only;
    bool normal_priority;
    /* batch */
    const char *select, *wall, *units;
    i64 jobs, limit;
    const char *root, *config;  /* passed on to the batch's children */
} FloatOrderArgs;

/* search(args): one function. Returns the exit code. */
int float_order_search(FloatOrderArgs *args);
/* batch(args): one child process per result of the adapter whose wall is args->wall. */
int float_order_batch(FloatOrderArgs *args);
/* selftest(): the asserted cases; prints "selftest ok". */
int float_order_selftest(void);
/* main(argv): the command line. */
int float_order_main(int argc, char **argv);
