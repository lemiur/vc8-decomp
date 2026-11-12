// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* eq2 front end: the functions to check come from the project adapter (project.h). A unit is built for each target
 * (the configured backend), every annotated function is compared with the target's image, and the checker of eq2.h
 * runs our bytes and the reference's in lockstep. The relocations of our side come from the comparison's relocation
 * checks: the address a relocation resolved to, a label inside the function (a jump table entry), a string literal,
 * the callee's calling convention from its decorated name. */
#pragma once
#include "eq2.h"

/* The return kind of a function from its undecorated name (dbghelp, full): "void", "int", "float" or "bool". */
const char *eq2_ret_kind(DkStr plain);
/* The calling convention an undecorated name shows: "cdecl", "thiscall", "stdcall", "fastcall", or NULL. */
const char *eq2_conv_of(DkStr plain);

/* Checks the functions of a unit and prints one block per function:
 *   <name> <target>: EQUIVALENT|DIFFERENT (paths N, ret=<kind>)
 *     <one line per difference>
 * functions: names separated by commas (an annotation's name, plain or qualified, the last part of a qualified one,
 * or an address), or "ALL": every function of the unit parked with a stop mark. target -1: each function in the first
 * target that has a copy of it (ALL: each stop once, in the first target with a copy). A function that cannot be built
 * prints `<name> BUILD ERROR <text>` and the run goes on. verbose adds the checker's notes and the switch cases.
 * Returns 0 when every function checked is EQUIVALENT, 1 when one is DIFFERENT or cannot be built. false with *err
 * for an unknown unit. */
bool eq2_run(DkProject *p, const char *unit, const char *functions, int target, bool verbose, int *exit_code,
             DkErr *err);
