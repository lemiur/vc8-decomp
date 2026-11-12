// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* eq2: symbolic equivalence check of a compiled function against the reference image's bytes. Both sides run in
 * lockstep on symbolic inputs and their events (branches and conditions, calls, stores, switches, returns) are
 * compared path by path.
 *
 * The declarations below are the boundary between the engine (eq2_expr.c, eq2_sim.c, eq2_alu.c, eq2_fpu.c,
 * eq2_big.c, eq2_checker.c; eq2_internal.h is private to them) and the front end (eq2_front.c), which gets the two
 * functions from the project adapter. */
#pragma once
#include "dk/dk.h"
#include "project.h"

/* ---- the reference image ---------------------------------------------------------------------------------------- */
typedef struct Eq2Image Eq2Image;
typedef struct {
    DkStr name;      /* ".rdata" */
    u32 va;          /* absolute (image base added) */
    u32 vsize, raw_size, raw;
    u32 chars;       /* the section's characteristics */
} Eq2ImageSection;

/* A PE32 file read whole; NULL with *err when it cannot be read or is not a PE32 image. */
Eq2Image *eq2_image_open(DkArena *a, const char *path, DkErr *err);
/* The first section (table order) holding va, i.e. va <= x < va + max(virtual size, raw size), or NULL. */
const Eq2ImageSection *eq2_image_section_of(const Eq2Image *im, u32 va);
/* The file offset of va; false with the text "address %08X is not in <file name>" in *err (may be NULL). */
bool eq2_image_offset_of(const Eq2Image *im, u32 va, u32 *offset, const char **err);
/* size file bytes from the offset of va (shorter at the end of the file); no section bound. The result is a view. */
bool eq2_image_read(const Eq2Image *im, u32 va, u32 size, DkStr *out, const char **err);
/* The dword at va; an address outside the image is an internal error (dk_panic). */
u32 eq2_image_read_u32(const Eq2Image *im, u32 va);

/* ---- relocations of our side ------------------------------------------------------------------------------------ */
/* One relocation of our function, as the symbolic engine uses it (the reference side has none). */
typedef struct Eq2Reloc {
    u32 offset;
    const char *symbol;  /* the relocation's symbol name */
    bool has_target;     /* the relocation resolved to an address of the reference image */
    u32 target;
    const char *status;  /* the verdict's name, "?" when none */
    bool has_label;      /* a label inside the function (jump table entry): label = its offset from the start */
    u32 label;
    const char *kind;    /* "abs" or "rel" */
    const char *conv;    /* rel only: the calling convention the callee's decorated name shows, or NULL */
    bool local;          /* a callee compared by content, with no address of its own */
    bool strlit;         /* a string literal */
} Eq2Reloc;
typedef DK_VEC(Eq2Reloc) Eq2RelocVec;

typedef struct Eq2Prog Eq2Prog;
typedef struct Eq2State Eq2State;
typedef struct Eq2Sim Eq2Sim;

/* A program: `code` decoded (32-bit x86, instruction detail) at `base`; image is the reference image the engine
 * reads constants and jump tables from (NULL: none, a read that needs it is an error of the run). */
Eq2Prog *eq2_prog_new(const char *name, DkStr code, u32 base, const Eq2RelocVec *relocs, const Eq2Image *image,
                      bool ours);
/* The initial symbolic state of one side and its simulator. */
Eq2State *eq2_state_new(Eq2Prog *prog);
Eq2Sim *eq2_sim_new(Eq2Prog *prog, Eq2State *state);

typedef struct Eq2Switch { /* one (case, ours offset, reference offset) */
    i64 value;
    u32 ours, game;
} Eq2Switch;
typedef DK_VEC(Eq2Switch) Eq2SwitchVec;

typedef struct Eq2Checker {
    DkCzVec diffs;           /* in report order (duplicates kept: the front end prints each once) */
    DkCzVec notes;
    Eq2SwitchVec switches;   /* empty when no switch was met */
    i64 paths;
    const char *o_ret;       /* the return kind of our function ("void", "int", "float" or "bool"), set by the caller */
    void *impl;              /* the engine's private state */
} Eq2Checker;

Eq2Checker *eq2_checker_new(Eq2Prog *ours, Eq2Prog *game);
/* Appends msg to the differences. */
void eq2_checker_report(Eq2Checker *ck, const char *msg);
/* Runs both sides. An internal error of the engine is raised with dk_throw (DK_ERR_OTHER) and a short text such as
 * "KeyError('eax')"; the caller catches it with DK_TRY and reports "CRASH " followed by it. */
void eq2_checker_run(Eq2Checker *ck, Eq2Sim *so, Eq2Sim *sg);
