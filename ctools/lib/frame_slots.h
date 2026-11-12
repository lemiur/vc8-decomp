// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* frame_slots: the frame report of one compared function (frame.h) from the adapter's result: the prologues and the
 * slots by offset of ours and the reference's, then the slot map, the slots of both sides paired by the instruction
 * alignment of cfg_diff's block mapping. unitcmp --frame prints it. */
#pragma once
#include "frame.h"
#include "dk/json.h"
#include "project.h"

/* The slot map of one function (heading line, table, summary) appended to out. When the cfg_diff analysis fails or
 * the reference's bytes are missing, one line says so. im is the target's image; names may be empty. */
void dk_frame_slots_format(DkBuf *out, const DkProject *p, const DkResult *r, const DkImage *im,
                           const DkFrameName *names, size_t n_names);
/* The whole report: dk_frame_format's two prologues and slot table, then the slot map. A result with no reference
 * (MISSING, ERROR) gives one line. */
void dk_frame_report(DkBuf *out, const DkProject *p, const DkResult *r, const DkImage *im);
/* The frame facts of both sides as a JSON object: per side the saved registers, locals, frame pointer, alignment,
 * cookie, EH registration, unknown calls and slot count, and the number of differing slot rows. NULL when the
 * result has no reference bytes. */
DkJson *dk_frame_json(DkArena *a, const DkProject *p, const DkResult *r, const DkImage *im);
