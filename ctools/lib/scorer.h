// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* scorer: the measure the source-rewriting search tools (float_order) rank candidates by. A candidate is the whole
 * unit's source text in a file; the scorer builds it with the project adapter (dk_build_unit with source_override),
 * binds the annotated function's compiled symbol, compares it with the target's reference bytes (dk_compare) and
 * scores the result:
 *
 *   status    0 MATCH, 1 REFERENT, 2 UNRESOLVED, 3 DIFF, 4 SIZE;
 *   differ    the differing byte offsets (dk_result_differ);
 *   dissim    1000 times the dissimilarity of the two disassemblies: the difflib ratio of the normalised
 *             instruction texts (insn_text.h), 1000 - round(1000 * ratio).
 *
 * Scores compare lexicographically, lower is better; {0, 0, 0} is an exact match. A candidate that does not build, or
 * has no function for the annotation, has no score.
 *
 * Concurrency: the scorer owns `slots` independent builders (a clone of the project each, dk_project_clone, with the
 * build folder <work_root>/s<k>). A slot is used by one thread at a time; slots are independent, so a pool of
 * threads each holding a slot builds in parallel. The comparison with the reference image is serialised. A slot's
 * memory is released after each evaluation: everything an evaluation returns is heap-owned (dk_scored_free) or
 * lives in the calling thread's dk_arena(). */
#pragma once
#include "project.h"

typedef struct {
    i64 status, differ, dissim;
} DkScore;
#define DK_SCORE_EXACT ((DkScore){0, 0, 0})
int dk_score_cmp(DkScore a, DkScore b);   /* <0, 0, >0 as a tuple comparison */
bool dk_score_exact(DkScore s);
const char *dk_score_str(DkScore s);      /* "S3 D12 R45" (status, differing bytes, dissimilarity); the thread's arena */
const char *dk_score_tag(DkScore s);      /* "S3_D12_R45", for file names */

/* One evaluated candidate. code and reloc_offsets are heap-owned. */
typedef struct {
    DkScore score;
    DkStatus status;
    const char *key;        /* the state key: sha256 hex over the function's bytes and its relocations' names */
    DkStr code;             /* our function's bytes as compared (padding past the reference's end dropped) */
    u32 *reloc_offsets;     /* offsets of our relocations */
    size_t n_relocs;
} DkScored;
void dk_scored_free(DkScored *s);

typedef struct DkScorer DkScorer;
struct DkScorer {
    DkProject *project;
    const DkUnit *unit;
    const DkAnnot *annot;   /* the annotation scored (in project) */
    int target;
    u32 address;            /* the annotation's address in the target */
    const char *name;       /* annot->name */
    const char *symbol;     /* the compiled symbol, NULL until the first evaluation binds it */
    DkStr game;             /* the reference function's bytes (dk_wall_reference_window), p NULL until the first
                             * evaluation; heap-owned */
    int nslots;
    void *priv;
};

/* The annotation of unit u that name (plain or qualified) and address (DK_NO_ADDR: any) pick, in target; NULL with
 * *err when none, or several, fit. */
const DkAnnot *dk_scorer_select(DkProject *p, const DkUnit *u, const char *name, u32 address, int target, DkErr *err);

/* A scorer for annotation an of unit u in target, with `slots` builders under work_root. NULL with *err when a
 * clone of the project cannot be made. */
DkScorer *dk_scorer_new(DkProject *p, const DkUnit *u, const DkAnnot *an, int target, int slots, const char *work_root,
                        DkErr *err);

/* Builds the candidate at source (a file; its directory is added to the include path, so relative includes of the
 * unit still resolve) in slot, binds and compares the function and fills *out. false with *err when the candidate
 * does not build or has no function for the annotation. log, when not NULL, receives the compiler output. The first
 * success sets symbol and game. */
bool dk_scorer_evaluate(DkScorer *s, int slot, const char *source, DkScored *out, DkStr *log, DkErr *err);
