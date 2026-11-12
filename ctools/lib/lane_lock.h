// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* lane_lock: checkout locks and the lane registry. The public API is `dk_lane_check` (what a merge or batch tool
 * calls before it writes) plus the four sub-commands of the command line.
 *
 * A claim is one JSON file in <git common dir>/lane-locks/ kept as a DkJson object, so extra keys a hand-edited file
 * carries survive a refresh. */
#pragma once
#include "dk/dk.h"
#include "dk/json.h"

#define DK_LANE_TTL_HOURS 12.0

/* check(checkout, units, session, ttl, out): true when no live claim of another session holds the
 * checkout or the units. Writes the conflict lines through out(ctx, line) (out == NULL: print() to stdout, one line
 * each), refreshes this session's own claim of the checkout. checkout NULL or "": the current directory's checkout.
 * units may be NULL. session NULL: LANE_SESSION, CLAUDE_CODE_SESSION_ID, else user@host. */
typedef void (*DkLaneOut)(void *ctx, DkStr line);
bool dk_lane_check(const char *checkout, const DkStrVec *units, const char *session, double ttl, DkLaneOut out,
                    void *ctx);

/* The pure helpers, public for the unit tests. */
char *dk_lane_claim_id(DkArena *a, DkStr session, DkStr checkout);   /* sha1("session|checkout")[:12] */
DkStr dk_lane_age(DkArena *a, double seconds_since);                  /* age(): "12m" or "1.5h" */

/* The sub-commands (parsed arguments in; the return value is the exit code). Optional strings are NULL when the
 * option was not given; pid_given tells --pid. */
typedef struct {
    const char *checkout, *session;
    double ttl;
    const char *branch, *units, *note;
    bool pid_given;
    i64 pid;
    bool force;
} DkLaneClaimArgs;
typedef struct {
    const char *checkout, *session;
    double ttl;
    bool all, stale;
    const char *id;
} DkLaneReleaseArgs;
typedef struct {
    const char *checkout, *session;
    double ttl;
} DkLaneStatusArgs;
typedef struct {
    const char *checkout, *session;
    double ttl;
    const char *units;
    bool hook;
} DkLaneCheckArgs;
int dk_lane_cmd_claim(const DkLaneClaimArgs *a);
int dk_lane_cmd_release(const DkLaneReleaseArgs *a);
int dk_lane_cmd_status(const DkLaneStatusArgs *a);
int dk_lane_cmd_check(const DkLaneCheckArgs *a);

/* The module docstring (argparse's description). */
extern const char dk_lane_lock_doc[];
