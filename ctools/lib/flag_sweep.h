// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* flag_sweep: the compiler-option oracle (tools/flag_sweep_main.c). It builds a unit with its effective options and
 * with one change at a time (an option dropped, a family swapped, an option added) through the project adapter's
 * build and compare (project.h), and tells whether the unit's option set matters and is the only one that matches.
 *
 *   flag_sweep <unit> [--targets a,b|all] [--variants default|extended] [--no-cache] [--json FILE] [--root DIR]
 *              [--config FILE]
 *
 * A variant is an option list. It reaches the build as the difference from the baseline: the baseline options the
 * variant lacks go to DkBuildOpts.remove_flags, the options it adds to extra_flags (appended, so the last option of
 * a family wins). compiler.flag_variants (project.h) replaces the built-in list of variants. */
#pragma once
#include "dk/json.h"
#include "project.h"

#include <stdio.h>

/* A named option list: the whole list, baseline included. */
typedef struct {
    const char *name;
    DkCzVec tokens;
} DkFlagVariant;
typedef DK_VEC(DkFlagVariant) DkFlagVariantVec;

/* The unit's effective options for a target, without the include folders, defines and /showIncludes the build adds
 * at the end. */
DkCzVec dk_flag_baseline(DkProject *p, const DkUnit *u, int target);
/* The list after `extra` is applied over `base`: as the compiler does, the last option of a family wins. */
DkCzVec dk_flag_apply(DkArena *a, const DkCzVec *base, const char *const *extra, size_t n_extra);
/* The baseline, then the variants: the configured ones (each entry applied over the baseline) when n_configured is
 * not 0, else the built-in one-change list; `extended` appends the further built-in options. A variant equal to the
 * baseline is left out. */
DkFlagVariantVec dk_flag_variants(DkArena *a, const DkCzVec *baseline, bool extended, const DkStrVec *configured,
                                  size_t n_configured);
/* The build options that turn the baseline into the variant. */
void dk_flag_build_opts(DkArena *a, const DkCzVec *baseline, const DkCzVec *variant, DkBuildOpts *out);

/* One function of one target across the variants. */
typedef struct {
    const char *name;
    int line;
    int target;
    const char *note;              /* "stop", "pending" or NULL: parked, outside the verdict */
    const char **cells;            /* per column; NULL where the variant does not apply to the target */
} DkFlagRow;
typedef DK_VEC(DkFlagRow) DkFlagRowVec;

typedef struct {
    bool extended;
    u32 targets;                   /* bit t: sweep target t; 0: every target */
    bool use_cache;
    FILE *progress;                /* one line per variant and target; NULL: none */
} DkFlagSweepOpts;

typedef struct {
    const DkUnit *unit;
    DkFlagVariantVec plan[DK_MAX_TARGETS];   /* per target; empty for a target not swept */
    DkCzVec columns;                         /* the variant names, first seen first; "baseline" is column 0 */
    DkFlagRowVec rows;                       /* by line, then target */
    DkCzVec build_errors;                    /* "<variant> [<target>]: first line" */
} DkFlagSweep;

/* Sweeps one unit. false with *err for a backend that does not compile or a configuration error. */
bool dk_flag_sweep(DkProject *p, const DkUnit *u, const DkFlagSweepOpts *o, DkFlagSweep *out, DkErr *err);

typedef struct {
    const char *verdict;
    size_t n_matched;              /* live rows that match in the baseline */
    DkCzVec ok_variants;           /* the columns where every such row matches */
    DkCzVec insensitive;           /* functions matching in every variant that applies to them, sorted */
    size_t n_functions;            /* distinct names among the matched rows */
    size_t n_sensitive;
} DkFlagVerdict;
DkFlagVerdict dk_flag_verdict(DkArena *a, const DkFlagSweep *sw);

/* The text report (table, verdict, counts) and the JSON document {"schema": "decompkit-flag-sweep/1", ...}. */
void dk_flag_report(DkBuf *out, const DkProject *p, const DkFlagSweep *sw, const DkFlagVerdict *v);
DkJson *dk_flag_json(DkArena *a, const DkProject *p, const DkFlagSweep *sw, const DkFlagVerdict *v);

int dk_flag_sweep_main(int argc, char **argv);
