// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* cfg_diff: our function's control-flow graph against the reference's. Both sides are decoded by recursive descent
 * into basic blocks (switch tables followed), the blocks are aligned (entry, role pairs, best-first propagation, then
 * similarity) and the structural differences are named (inverted-branch, block-order, loop-rotation,
 * switch-lowering, tail-call, early-return, ...), each with its source lever. cfg_diff_batch analyses the rows of
 * the adapter's compare (unitcmp.h) that are not a MATCH.
 *
 * The block graph (CfgDiffSide, CfgDiffBlock, CfgDiffAlign) is the interface of the later diagnostics (frame and
 * residue): cfg_diff_analyse builds it from a compared result and the target's image. capstone through dk/disasm.h
 * with detail on; instructions are cs_insn kept for the analysis's life. Sets of block indices that are walked in
 * role_pairs reach no output beyond the heap order, which breaks ties on ints: keep DkPyIntSet where a set is
 * iterated. */
#pragma once
#include "dk/disasm.h"
#include "project.h"
#include "unitcmp.h"

/* The condition tables (ALIAS, NEG, MIRROR), the lever texts (LEVER) and the report order of the finding kinds
 * (KINDS, "error" last). */
extern const char *const CFG_DIFF_KINDS[];
extern const size_t CFG_DIFF_NKINDS;
/* LEVER[kind]: the source lever text of a finding kind (NULL for an unknown kind). */
const char *cfg_diff_lever(const char *kind);
#define CFG_DIFF_PROP_FLOOR 2.5
#define CFG_DIFF_SIM_FLOOR 4.0

/* rel(p, path): the path relative to the project root, with "/" separators. */
const char *cfg_diff_rel(const DkProject *project, const char *path);
/* is_jcc(m), cond_of(m): a conditional jump mnemonic and its alias-normalised condition ("e", "ne", "ae", ...). */
bool cfg_diff_is_jcc(const char *mnemonic);
const char *cfg_diff_cond_of(const char *mnemonic);

/* One successor edge: (role, block index); role is "taken", "fall", "case", ... index -1 for
 * none (an edge out of the function). */
typedef struct CfgDiffEdge {
    const char *role;
    i32 to;
} CfgDiffEdge;
typedef DK_VEC(CfgDiffEdge) CfgDiffEdgeVec;
typedef DK_VEC(const cs_insn *) CfgDiffInsnVec;

/* Block: one basic block of one side. Offsets are from the function's start. */
typedef struct CfgDiffBlock {
    i32 idx, layout;
    u32 start, end;
    CfgDiffInsnVec insns;
    const char *term;           /* "ret", "trap", "switch", "jmp", "tail", "jcc", "fall" or "stop" */
    const char *cond;           /* cond_of(last mnemonic) of a "jcc" block, else NULL */
    CfgDiffEdgeVec succ;
    DkI32Vec preds;
    DkCzVec calls, calls_sim;  /* call tokens (dk_wall_tok_text) in order */
    DkMap *globals, *consts;   /* Counter{text: n (.i)} in first-seen order */
    DkCzVec ops;               /* the non-move mnemonics */
    bool has_ret;
    bool has_cmp;               /* cmp is not None: the last flag-setting instruction before the jcc */
    const char *cmp_m, *cmp_ops;/* cmp = (mnemonic, op_str) */
    const char *tail;           /* the tail-call target text or NULL */
    i32 table;                  /* the switch table's entry count, -1 for None */
    void *priv_;                /* cfg_diff.c: the multiset forms the similarity uses */
} CfgDiffBlock;
/* succ_role(role): the first successor with that role, -1 for None; successors(): the non-None successors. */
i32 cfg_diff_block_succ_role(const CfgDiffBlock *b, const char *role);
DkI32Vec cfg_diff_block_successors(const CfgDiffBlock *b);

/* Side: one side's bytes. ours: the object's code with its relocations and verdicts; else the reference bytes. */
typedef struct CfgDiffSide {
    const char *name;               /* "ours" / "reference" */
    DkStr code;
    u32 base, extent, size;         /* size: the decoded code's length */
    const DkFunc *fn;               /* NULL for the reference */
    const DkImage *image;           /* the target's image: the reference bytes and globals; may be NULL */
    DkIMap *verdicts;              /* {offset: const DkRefCheck* (.p)}: our relocation checks (dk_wall_verdicts) */
    DkIMap *relocs;                /* {offset: const DkReloc* (.p)} */
    bool ours;
    DK_VEC(CfgDiffBlock *) blocks; /* in idx order */
    DkIMap *at;                    /* {offset: block idx (.i)} */
    DkIMap *tables;                /* {table offset: case count (.i)} */
} CfgDiffSide;
CfgDiffSide *cfg_diff_side_new(const char *name, DkStr code, u32 base, u32 extent, const DkFunc *fn,
                               DkIMap *verdicts, const DkImage *image);
bool cfg_diff_side_inside(const CfgDiffSide *s, u32 va);
/* reloc_in(off, size): the relocations starting in [off, off + size), in offset order. */
DkPtrVec cfg_diff_side_reloc_in(const CfgDiffSide *s, u32 off, u32 size);

/* build_blocks(side): decodes and splits the side (fills blocks, at, tables, and every block's features). */
void cfg_diff_build_blocks(CfgDiffSide *s);

/* Align(ours_blocks, game_blocks).run(): mo {ours idx: game idx}, mg the inverse, score {ours idx: double},
 * how {ours idx: "entry"|"anchor"|"edge"|"sim"}, rel {ours idx: relation text}, copy_o / copy_g (duplicated blocks:
 * {ours idx: game idx} and {game idx: ours idx}). Maps are DkIMap with .i values (score: .f), insertion order kept. */
typedef struct CfgDiffAlign {
    DkIMap *mo, *mg, *score, *how, *rel, *copy_o, *copy_g;
    void *priv_;                    /* the content-similarity memo */
} CfgDiffAlign;
CfgDiffAlign *cfg_diff_align(const CfgDiffSide *ours, const CfgDiffSide *game);

/* One finding: kind, the ours/game block descriptions, the evidence and the lever text. */
typedef struct CfgDiffFinding {
    const char *kind;
    DkCzVec ours, game;
    const char *evidence, *lever;
} CfgDiffFinding;
typedef DK_VEC(CfgDiffFinding) CfgDiffFindingVec;
/* One mapping row: "+%03X" starts, the score (round(.., 2); has_score false for the copies' None), how, note. */
typedef struct CfgDiffMapping {
    const char *ours, *game, *how, *note;
    double score;
    bool has_score;
} CfgDiffMapping;
typedef DK_VEC(CfgDiffMapping) CfgDiffMappingVec;

/* analyse(result, image, target, game_size): the analysis of one compared function; target labels the report (the
 * target's name). game_size CFG_DIFF_NONE: the sized symbol's size in the image, else the reference window's. On a
 * failure (no reference address, an undecodable operand) returns NULL with *err set to the text; err may be NULL
 * when the caller does not catch (then dk_panic). */
#define CFG_DIFF_NONE INT64_MIN
typedef struct CfgDiffAnalysis {
    i64 address;
    const char *target;
    i64 size_ours, size_game, blocks_ours, blocks_game, matched;
    CfgDiffMappingVec mapping;
    CfgDiffFindingVec findings;
    CfgDiffSide *ours, *game;       
    CfgDiffAlign *align;
} CfgDiffAnalysis;
CfgDiffAnalysis *cfg_diff_analyse(const DkResult *result, const DkImage *image, const char *target, i64 game_size,
                                  const char **err);
/* one_liner(analysis): "no structural difference", else the finding kinds in KINDS order, "kind xN" when repeated,
 * joined by ", ". */
const char *cfg_diff_one_liner(const CfgDiffAnalysis *a);

/* format_analysis(name, a, verbose): the text print_analysis prints (the tests compare it); print_analysis writes it. */
DkStr cfg_diff_format_analysis(const char *name, const CfgDiffAnalysis *a, bool verbose);
/* print_analysis(name, a, verbose): the report of one function (stdout). */
void cfg_diff_print_analysis(const char *name, const CfgDiffAnalysis *a, bool verbose);
/* write_dot / write_html(path, name, a): the Graphviz file and the HTML page (utf-8, "\n"); write_html runs
 * `dot -Tsvg` (shutil.which, timeout 60, any failure swallowed) for the inline graph. Return path. */
const char *cfg_diff_write_dot(const char *path, const char *name, const CfgDiffAnalysis *a);
const char *cfg_diff_write_html(const char *path, const char *name, const CfgDiffAnalysis *a);

/* The batch: every row of urows (dk_unitcmp_collect) that is not a MATCH, MISSING or ERROR is analysed when it is a
 * DIFF or SIZE whose wall is control-flow (every one with all_walls); the others are listed as skipped. Writes
 * batch.tsv, batch.json and batch.md to out and prints the histogram. stopped: only the functions parked (stop line)
 * for the row's target. select: a regex searched in the function name (NULL: all). Returns the exit code. */
typedef struct {
    const char *select, *out;
    bool all_walls, stopped;
} CfgDiffBatchOpts;
int cfg_diff_batch(DkProject *p, const DkUnitcmpRowVec *rows, const CfgDiffBatchOpts *opts);

/* main(argv): the command line: single (unit, Name) or --batch. Returns the exit code. */
int cfg_diff_main(int argc, char **argv);

/* cfg_diff_insn_map(analysis): {our instruction offset: the game's} over the aligned blocks (offsets from the
 * function's start; .i). Inside a block pair the instructions are aligned by mnemonic and operand classes (SequenceMatcher),
 * a replaced run of equal length pairwise where the mnemonics agree. Instructions of unmatched blocks have no entry. */
DkIMap *cfg_diff_insn_map(const CfgDiffAnalysis *an);

/* cfg_diff_block_score(analysis): the block-aligned score, a percentage of the game's function size: the bytes of the
 * game's instructions that are paired (cfg_diff_insn_map's alignment inside the mapped blocks) with an instruction of ours
 * whose bytes are equal, relocated words and the displacement of a relative jump or call masked, over the game's
 * decoded size. An unwritten game block counts 0 and a written block that equals the game's counts fully, so adding a
 * correct block never lowers it. */
double cfg_diff_block_score(const CfgDiffAnalysis *an);
/* cfg_diff_result_block_score(result, image, &pct): analyse one compared function and score it; false when cfg_diff
 * cannot analyse it (an ERROR result, no address, a decode failure). */
bool cfg_diff_result_block_score(const DkResult *result, const DkImage *image, double *pct);
