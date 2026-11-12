// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* unitcmp: the project adapter's own compare front end (tools/unitcmp_main.c). It builds each unit with the
 * configured backend, compares every annotated function with each target's reference image, and prints one line per
 * function and target: the status, the closeness, the wall (walls.h) and the name; --diff adds the side-by-side
 * disassembly (insn_text.h), --json writes every result with its relocation checks. It is a diagnostic and an
 * acceptance harness for the adapter, not a replacement for a project's own match and gate tools.
 *
 *   unitcmp <unit>... | --all [--target T|all] [--function NAME] [--summary] [--diff] [--max-rows N] [--json FILE]
 *           [--no-cache] [--root DIR] [--config FILE]
 *
 * A unit is a repository-relative path or a unique stem. --function selects by the annotation's name (plain or
 * qualified, or the last "::" part of a qualified one) or by an address in any target (hex, 0x optional). The exit
 * code is 0 when every selected result is MATCH, 1 when one is not, 2 for a usage, configuration or unit error.
 *
 * Per-result reports are hooks (DkUnitcmpHook): each adds a command-line flag, a report printed under the result's
 * line and a member of the result's JSON object. The table lives in unitcmp.c. */
#pragma once
#include "dk/json.h"
#include "project.h"
#include "walls.h"

/* One compared function in one target. */
typedef struct {
    const DkUnit *unit;
    const DkResult *r;
    DkBuildWall wall;
} DkUnitcmpRow;
typedef DK_VEC(DkUnitcmpRow) DkUnitcmpRowVec;

/* A per-result report. option: the flag ("--frame"); dest: its argument name and the result's JSON member
 * ("frame"). report appends text under the result's line; json returns the member's value (NULL: none). Either may
 * be NULL. */
typedef struct {
    const char *option, *dest, *help;
    void (*report)(DkProject *p, const DkUnitcmpRow *row, const DkImage *im, DkBuf *out);
    DkJson *(*json)(DkProject *p, const DkUnitcmpRow *row, const DkImage *im, DkArena *a);
} DkUnitcmpHook;
/* The hooks, NULL-terminated (an entry with option NULL ends it). */
const DkUnitcmpHook *dk_unitcmp_hooks(void);

typedef struct {
    const char *const *units;      /* paths or stems; NULL with all: every unit of the project */
    size_t n_units;
    bool all;                      /* every unit whose file exists */
    int target;                   /* -1: every target */
    const char *function;          /* NULL: every annotated function */
    bool use_cache;
} DkUnitcmpOpts;

/* Builds and compares; the rows in unit, then annotation, then target order. false with *err for an unknown unit or
 * target; a unit that fails to build gives ERROR rows, not a failure. */
bool dk_unitcmp_collect(DkProject *p, const DkUnitcmpOpts *o, DkUnitcmpRowVec *rows, DkErr *err);
/* Whether an annotation is the one a --function spec names. */
bool dk_unitcmp_selects(const DkProject *p, const DkAnnot *an, const char *spec);
/* The result line: "<STATUS> <target> <addr> <ours>/<reference> <close>% <wall> <name>[  (<error>)]". */
DkStr dk_unitcmp_line(DkArena *a, const DkProject *p, const DkUnitcmpRow *row);
/* The rows as one JSON document {"schema": "decompkit-unitcmp/1", "results": [...], "totals": {...}}. hook_on[i]
 * says whether hook i was asked for (NULL: none). */
DkJson *dk_unitcmp_json(DkArena *a, DkProject *p, const DkUnitcmpRowVec *rows, const bool *hook_on);

/* The command line; returns the exit code. */
int dk_unitcmp_main(int argc, char **argv);
