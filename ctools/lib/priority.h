// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* priority: the CPU priority of the search tools (float_order, the scorer, flag_sweep's batches): BELOW_NORMAL by
 * default, so a match or gate run on the same machine keeps the CPU first; the compilers and linkers a search starts
 * inherit the class. --normal-priority or DECOMPKIT_SEARCH_PRIORITY=normal keeps the normal class. A lower priority
 * never changes a result. */
#pragma once
#include "dk/args.h"

#define DK_PRIORITY_ENV "DECOMPKIT_SEARCH_PRIORITY"

/* What dk_priority_lower would do: "normal" (normal is true, or the environment variable is normal, off, 0, no or
 * none, case and surrounding blanks ignored) or "below-normal". */
const char *dk_priority_wanted(bool normal);
/* Puts this process in the below-normal class unless dk_priority_wanted says "normal"; returns the class in effect
 * ("normal" or "below-normal"). A failure leaves the priority as it is and returns "normal". */
const char *dk_priority_lower(bool normal);
/* The --normal-priority flag of a search tool (stored as "normal_priority"). */
void dk_priority_add_argument(DkArgParser *parser);
