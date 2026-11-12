// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* residue: what is left of a compared function's difference: the register renames over the aligned instructions
 * (ours -> the reference's, majority per register, over every aligned instruction and over the values live across
 * blocks), the operand / frame / schedule / moves / body / call-set / control-flow classes, and the verdict
 * ("register-only", "register + ...", "no register difference: ...", "none (STATUS)"). No command line: unitcmp
 * --residue reaches it.
 *
 * residue.c holds the values and the comparison; residue_text.c the text helpers (most_common, span, value_text,
 * mapping_text), which do not need cfg_diff, so their test links alone. Counters are DkMap {register: n (.i)} in
 * first-seen order (most_common breaks ties on that order). */
#pragma once
#include "cfg_diff.h"
#include "dk/json.h"
#include "project.h"

/* "None" of the cfg numbers of a report whose cfg_diff analysis failed. */
#define RESIDUE_NONE CFG_DIFF_NONE

/* One register value (a web of reaching definitions over cfg_diff's decoded blocks of our side). */
typedef struct ResidueValue {
    const char *reg;        /* the 32-bit register name ("eax", "xmm0", ...) */
    const char *kind;       /* "cross", "local", "save", "frame" */
    DkU32Vec defs, uses, refs, blocks; /* sorted offsets (blocks: sorted block indexes) */
    bool entry;             /* live at the entry */
    DkMap *game;           /* Counter{reference register: n (.i)}, filled by compare */
    i64 renamed;
} ResidueValue;
typedef DK_VEC(ResidueValue *) ResidueValueVec;
/* The values of a side, sorted by (refs[0], reg); index maps "<offset>\t<register>" to the value's position (.i). An
 * empty side gives no values. false when the side cannot be analysed (the caller then goes on without values). */
bool residue_values(const CfgDiffSide *side, ResidueValueVec *values, DkMap **index);
/* "+%03X..+%03X" of the first and last ref, "entry" when none. */
const char *residue_span(const ResidueValue *v);
/* The value's text (limit others at most): "+025..+032 eax -> ecx 3/3 (also edx 1)" or "<span> <reg> (no aligned use)". */
const char *residue_value_text(const ResidueValue *v, int limit);

/* One mapping entry: ours register -> {reference, count, total, others}. */
typedef struct ResidueMapping {
    const char *game;       /* the majority reference register */
    i64 count, total;
    DkMap *others;         /* Counter of the other reference registers (.i), first-seen order */
} ResidueMapping;
/* The mapping's text (at most limit entries): "esi->edi 12/12, ..." sorted by (game == ours, -total, ours), then ", +N more".
 * mapping: {ours register: ResidueMapping* (.p)} in insertion order. */
const char *residue_mapping_text(const DkMap *mapping, int limit);

/* The residue of one compared result; image is the target's image (may be NULL), target its name (labels cfg_diff's
 * report). For a status other than DIFF and SIZE only status and verdict ("none (<STATUS>)") are set and
 * has_register_only is false. */
typedef struct ResidueReport {
    const char *status;
    DkMap *classes;        /* {class: text (char* .p)} in insertion order */
    DkCzVec renames;       /* one text per renamed instruction pair: "+%03X <ours> | reference <reference's>" */
    DkMap *mapping;        /* {ours register: ResidueMapping* (.p)} */
    DkMap *cross_mapping;  /* the same over the values live across blocks */
    i64 aligned, insns_ours, insns_game, local_renames, cross_renames;
    bool xmm, gp;
    ResidueValueVec values;
    DkCzVec structure;     /* the structure lines */
    /* the cfg_diff numbers (RESIDUE_NONE when cfg_diff failed) */
    i64 cfg_blocks_ours, cfg_blocks_game, cfg_matched, cfg_size_ours, cfg_size_game;
    bool has_cfg;           /* the cfg numbers were filled */
    const char *verdict;
    bool register_only, has_register_only;
} ResidueReport;
ResidueReport *residue_compare(const DkResult *result, const DkImage *image, const char *target);
/* The most common key of a counter (the first inserted maximum); false when empty. */
bool residue_most_common(const DkMap *counter, DkStr *key, i64 *n);

/* The report as indented text lines (each starting with two spaces) appended to out: the verdict, the classes, the
 * structure lines, the register mappings and the first values live across blocks. */
void residue_format(DkBuf *out, const ResidueReport *r);
/* The report as a JSON object (verdict, status and, for a DIFF, the classes, counts, renames, structure and the two
 * register mappings). */
DkJson *residue_json(DkArena *a, const ResidueReport *r);
