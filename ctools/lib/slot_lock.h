// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* slot_lock: the library part of the slot lock (the tool is tools/slot_lock_main.c).
 *
 * The slot lock is the file `.slot_lock` at the top of a worktree: a JSON object (agent, branch, host, pid,
 * started, started_at, heartbeat, last_tool, note). The functions take the worktree folder `root` (forward slashes,
 * no trailing separator: dk_slot_root); a lock is a DkJson object. A value that cannot be handled (a heartbeat that
 * is a list, a branch name that does not decode) ends the process with a message and exit code 1 (dk_throw outside a
 * try), except in dk_slot_warn, which never fails. */
#pragma once
#include "dk/json.h"

#define DK_SLOT_LOCK_NAME ".slot_lock"

/* The worktree the tool works on: dk_root() (--root, $DECOMPKIT_ROOT, the executable's checkout), normalised. */
const char *dk_slot_root(DkArena *a);
/* ttl_hours(): $SLOT_LOCK_TTL as a float, else 6.0 (also when it does not parse). */
double dk_slot_ttl_hours(void);
/* branch(root): the checked out branch, "(detached <short sha>)", or "-" when git says nothing. */
char *dk_slot_branch(DkArena *a, const char *root);
/* read(root): the lock, or NULL when there is none (missing file, bad JSON, not an object, no agent). */
DkJson *dk_slot_read(DkArena *a, const char *root);
/* write(lock, root): atomically (temporary file, then replace), indent=1, a CRLF file (text-mode stream). */
void dk_slot_write(DkArena *a, const DkJson *lock, const char *root);
/* stale(lock, now): the heartbeat (else the start) is older than the TTL. */
bool dk_slot_stale(const DkJson *lock, double now);
/* age(seconds): "42s", "7min", "3.5h". */
char *dk_slot_age(DkArena *a, double seconds);
char *dk_slot_describe(DkArena *a, const DkJson *lock, double now);
/* my_agent(arg): arg (NULL or empty for none), else $SLOT_AGENT, stripped. */
char *dk_slot_my_agent(DkArena *a, const char *arg);

/* take / release / status print their result on stdout and return the exit code. note NULL: none given. */
int dk_slot_take(DkArena *a, const char *agent, const char *note, bool force, const char *root);
int dk_slot_release(DkArena *a, const char *agent, bool force, const char *root);
int dk_slot_status(DkArena *a, const char *root);

/* warn(tool): for the tools of a worktree, on start: a `WARNING: slot lock:` line on stdout when the slot looks shared,
 * else a refreshed heartbeat; nothing without a lock. Never fails, never blocks. */
void dk_slot_warn(const char *tool);
