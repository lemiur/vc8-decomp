// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The slot lock: which agent works in this worktree (a worker slot), so that two agents never share one. The lock
 * is the file `.slot_lock` at the top of the worktree (never versioned): a JSON object with the agent, the branch
 * checked out when it was taken, the start time, the last time a tool ran under it (the heartbeat), the host and a
 * note. A lock whose heartbeat is older than the TTL is stale. Advisory and crash-safe: nothing is ever blocked but
 * `take`.
 *
 * The lock is kept as the DkJson tree, so keys this tool does not know survive a refresh and the key order is
 * kept. */
#include "slot_lock.h"

#include "dk/clock.h"
#include "dk/fmt.h"
#include "dk/fs.h"
#include "dk/proc.h"
#include "dk/win.h"

#include <stdio.h>

#define TTL_HOURS 6.0

const char *dk_slot_root(DkArena *a) {
    return dk_path_normpath(a, dk_root());
}

double dk_slot_ttl_hours(void) {
    const char *v = dk_getenv(dk_scratch(), "SLOT_LOCK_TTL");
    double f;
    /* an empty value is the default, a bad one too */
    if (v && *v && dk_parse_float(dk_str(v), &f)) return f;
    return TTL_HOURS;
}

static char *lock_path(DkArena *a, const char *root) {
    return dk_path_join(a, root, DK_SLOT_LOCK_NAME);
}

/* ---- git ---- */

char *dk_slot_branch(DkArena *a, const char *root) {
    const char *const argv[] = {"git", "-C", root, "rev-parse", "--abbrev-ref", "HEAD", NULL};
        DkProcResult r = dk_run(&(DkProcSpec){.argv = argv, .out = DK_IO_CAPTURE, .err = DK_IO_CAPTURE,
                                             .text = true, .errors = DK_ERRORS_REPLACE, .arena = a});
    if (r.status == DK_PROC_START_FAILED) dk_throw(DK_ERR_PROC, "%s", r.message ? r.message : "git did not start");
    DkStr name = r.returncode == 0 ? dk_str_strip(r.out) : DK_S("");
    if (dk_str_eqz(name, "HEAD")) { /* detached: the commit */
        const char *const argv2[] = {"git", "-C", root, "rev-parse", "--short", "HEAD", NULL};
        DkProcResult r2 = dk_run(&(DkProcSpec){.argv = argv2, .out = DK_IO_CAPTURE, .err = DK_IO_CAPTURE,
                                                  .text = true, .arena = a});
        if (r2.status == DK_PROC_START_FAILED || r2.status == DK_PROC_DECODE_ERROR)
            dk_throw(DK_ERR_PROC, "git rev-parse --short HEAD failed");
        return (char *)dk_pyfmt(a, "(detached %s)", dk_cz(a, dk_str_strip(r2.out))).p;
    }
    return name.n ? dk_cz(a, name) : dk_strdup(a, "-");
}

/* ---- values of the lock ---- */

/* The text of a JSON value; a container prints as its JSON text (no lock the tool wrote holds one). */
static const char *py_str(DkArena *a, const DkJson *v) {
    if (!v || v->kind == DK_JSON_NULL) return "None";
    switch (v->kind) {
    case DK_JSON_BOOL: return v->b ? "True" : "False";
    case DK_JSON_INT: return v->big ? dk_cz(a, v->u.str) : dk_sprintf(a, "%lld", (long long)v->u.i);
    case DK_JSON_FLOAT: return dk_cz(a, dk_repr_f64(a, v->u.f));
    case DK_JSON_STRING: return dk_cz(a, v->u.str);
    default: return dk_cz(a, dk_json_dumps(a, v, &(DkJsonDumpOpts){0}));
    }
}

/* The number a truthy JSON value stands for; a container or a string that is no number ends the process. */
static double py_float(const DkJson *v) {
    double f = 0;
    switch (v ? v->kind : DK_JSON_NULL) {
    case DK_JSON_BOOL: return v->b ? 1.0 : 0.0;
    case DK_JSON_INT:
        if (!v->big) return (double)v->u.i;
        dk_parse_float(v->u.str, &f);
        return f;
    case DK_JSON_FLOAT: return v->u.f;
    case DK_JSON_STRING:
        if (dk_parse_float(v->u.str, &f)) return f;
        dk_throw(DK_ERR_OTHER, "could not convert string to float: '%.*s'", DK_SF(v->u.str));
    default: dk_throw(DK_ERR_OTHER, "float() argument must be a string or a real number");
    }
}

/* float(lock.get(k1) or lock.get(k2) or fallback); k2 may be NULL. */
static double float_of(const DkJson *lock, const char *k1, const char *k2, double fallback) {
    const DkJson *v = dk_json_getz(lock, k1);
    if (!dk_json_truthy(v) && k2) v = dk_json_getz(lock, k2);
    return dk_json_truthy(v) ? py_float(v) : fallback;
}

/* lock["agent"] == agent (a lock holding a non-string agent equals no name). */
static bool agent_is(const DkJson *lock, const char *agent) {
    const DkJson *v = dk_json_getz(lock, "agent");
    return v && v->kind == DK_JSON_STRING && dk_str_eqz(v->u.str, agent);
}

/* current != lock.get("branch") */
static bool branch_differs(const DkJson *lock, const char *current) {
    const DkJson *v = dk_json_getz(lock, "branch");
    return !(v && v->kind == DK_JSON_STRING && dk_str_eqz(v->u.str, current));
}

/* ---- read / write ---- */

DkJson *dk_slot_read(DkArena *a, const char *root) {
    DkStr text;
    if (!dk_read_text(a, lock_path(a, root), DK_TM_UTF8, &text)) return NULL; /* OSError, UnicodeDecodeError */
    DkJsonError err;
    DkJson *lock = dk_json_parse(a, text, &err);
    if (!lock) return NULL; /* ValueError (JSONDecodeError) */
    return lock->kind == DK_JSON_OBJECT && dk_json_truthy(dk_json_getz(lock, "agent")) ? lock : NULL;
}

void dk_slot_write(DkArena *a, const DkJson *lock, const char *root) {
    char *tmp;
    DkFile *f = dk_mkstemp(a, ".slot_lock_", "", root, &tmp);
    if (!f) dk_throw(DK_ERR_IO, "%.*s", DK_SF(dk_io_err_str(a)));
    /* json.dump(lock, fh, indent=1) into a text-mode file: "\n" becomes "\r\n" */
    DkJsonDumpOpts indent1 = DK_JSON_INDENT(1);
    DkStr text = dk_json_dumps(a, lock, &indent1), bytes;
    if (!dk_encode_text(a, text, DK_TM_UTF8, &bytes) || !dk_fwrite(f, bytes.p, bytes.n) || !dk_fclose(f))
        dk_throw(DK_ERR_IO, "%.*s", DK_SF(dk_io_err_str(a)));
    if (!dk_replace(tmp, lock_path(a, root))) dk_throw(DK_ERR_IO, "%.*s", DK_SF(dk_io_err_str(a)));
}

bool dk_slot_stale(const DkJson *lock, double now) {
    return now - float_of(lock, "heartbeat", "started_at", 0.0) > dk_slot_ttl_hours() * 3600;
}

char *dk_slot_age(DkArena *a, double seconds) {
    if (!(seconds > -9e18 && seconds < 9e18)) /* int(nan), int(inf) */
        dk_throw(DK_ERR_OTHER, "cannot convert float to integer");
    i64 s = (i64)seconds; /* int() truncates toward zero */
    if (s < 0) s = 0;
    if (s < 120) return (char *)dk_pyfmt(a, "%ds", s).p;
    if (s < 7200) return (char *)dk_pyfmt(a, "%dmin", s / 60).p;
    return (char *)dk_pyfmt(a, "%.1fh", (double)s / 3600.0).p;
}

char *dk_slot_describe(DkArena *a, const DkJson *lock, double now) {
    const DkJson *last_tool = dk_json_getz(lock, "last_tool");
    const char *started_ago = dk_slot_age(a, now - float_of(lock, "started_at", NULL, now));
    const char *heartbeat_ago = dk_slot_age(a, now - float_of(lock, "heartbeat", NULL, now));
    DkStr text = dk_pyfmt(a, "%s on %s since %s (%s ago), heartbeat %s ago%s",
                            py_str(a, dk_json_getz(lock, "agent")), py_str(a, dk_json_getz(lock, "branch")),
                            py_str(a, dk_json_getz(lock, "started")), started_ago, heartbeat_ago,
                            dk_json_truthy(last_tool) ? dk_pyfmt(a, " by %s", py_str(a, last_tool)).p : "");
    const DkJson *note = dk_json_getz(lock, "note");
    if (dk_json_truthy(note)) text = dk_pyfmt(a, "%S, note: %s", &text, py_str(a, note));
    return (char *)text.p;
}

char *dk_slot_my_agent(DkArena *a, const char *arg) {
    const char *v = arg && *arg ? arg : dk_getenv(a, "SLOT_AGENT");
    return dk_cz(a, dk_str_strip(dk_str(v && *v ? v : "")));
}

/* ---- the commands ---- */

static DkJson *jstr(DkArena *a, const char *cz) {
    return dk_json_strz(a, cz);
}

int dk_slot_take(DkArena *a, const char *agent, const char *note, bool force, const char *root) {
    double now = dk_time();
    DkJson *lock = dk_slot_read(a, root);
    if (lock && !agent_is(lock, agent)) {
        bool is_stale = dk_slot_stale(lock, now);
        if (!is_stale && !force) {
            dk_pyprintf("slot_lock: %s is held by %s\n", root, dk_slot_describe(a, lock, now));
            dk_pyprintf("slot_lock: pick another slot (or --force when the holder is gone for sure)\n");
            return 1;
        }
        dk_pyprintf("slot_lock: %s lock of %s replaced\n", is_stale ? "stale" : "live (--force)",
                     py_str(a, dk_json_getz(lock, "agent")));
        lock = NULL;
    }
    DkJson *started = lock ? dk_json_getz(lock, "started") : NULL;
    if (!dk_json_truthy(started)) {
        DkDateTime dt = dk_datetime_now();
        DkStr text;
        if (!dk_datetime_strftime(a, &dt, "%Y-%m-%d %H:%M:%S", &text)) dk_throw(DK_ERR_OTHER, "strftime failed");
        started = dk_json_str(a, text);
    }
    DkJson *started_at = lock && dk_json_has(lock, DK_S("started_at")) ? dk_json_getz(lock, "started_at")
                                                                          : dk_json_float(a, now);
    DkJson *note_v;
    if (note) note_v = jstr(a, note);
    else if (lock && dk_json_has(lock, DK_S("note"))) note_v = dk_json_getz(lock, "note");
    else note_v = jstr(a, "");
    const char *br = dk_slot_branch(a, root);
    DkJson *n = dk_json_obj(a);
    dk_json_set(a, n, DK_S("agent"), jstr(a, agent));
    dk_json_set(a, n, DK_S("branch"), jstr(a, br));
    dk_json_set(a, n, DK_S("host"), jstr(a, dk_hostname(a)));
    dk_json_set(a, n, DK_S("pid"), dk_json_int(a, (i64)dk_getpid()));
    dk_json_set(a, n, DK_S("started"), started);
    dk_json_set(a, n, DK_S("started_at"), started_at);
    dk_json_set(a, n, DK_S("heartbeat"), dk_json_float(a, now));
    dk_json_set(a, n, DK_S("last_tool"), jstr(a, "take"));
    dk_json_set(a, n, DK_S("note"), note_v);
    dk_slot_write(a, n, root);
    dk_pyprintf("slot_lock: %s %s by %s on %s\n", root, lock ? "refreshed" : "taken", agent, br);
    return 0;
}

int dk_slot_release(DkArena *a, const char *agent, bool force, const char *root) {
    DkJson *lock = dk_slot_read(a, root);
    if (!lock) {
        dk_pyprintf("slot_lock: %s has no lock\n", root);
        return 0;
    }
    if (!agent_is(lock, agent) && !force) {
        dk_pyprintf("slot_lock: %s is held by %s, not %s (--force releases it anyway)\n", root,
                     py_str(a, dk_json_getz(lock, "agent")), *agent ? agent : "-");
        return 1;
    }
    if (!dk_remove(lock_path(a, root))) dk_throw(DK_ERR_IO, "%.*s", DK_SF(dk_io_err_str(a)));
    dk_pyprintf("slot_lock: %s released (was %s)\n", root, py_str(a, dk_json_getz(lock, "agent")));
    return 0;
}

int dk_slot_status(DkArena *a, const char *root) {
    DkJson *lock = dk_slot_read(a, root);
    if (!lock) {
        dk_pyprintf("slot_lock: %s is free\n", root);
        return 0;
    }
    double now = dk_time();
    bool live = !dk_slot_stale(lock, now);
    dk_pyprintf("slot_lock: %s %s: %s\n", root, live ? "LIVE" : "STALE", dk_slot_describe(a, lock, now));
    const char *current = dk_slot_branch(a, root);
    if (branch_differs(lock, current))
        dk_pyprintf("slot_lock: the branch checked out is %s, not the lock's %s\n", current,
                     py_str(a, dk_json_getz(lock, "branch")));
    return live ? 1 : 0;
}

/* ---- warn ---- */

static void warn_body(const char *tool, const char *root) {
    DkArena *a = dk_scratch();
    DkJson *lock = dk_slot_read(a, root);
    if (!lock) return;
    double now = dk_time();
    DkStrVec problems = {0};
    const char *current = dk_slot_branch(a, root);
    if (branch_differs(lock, current))
        dk_vec_push(&problems,
                     dk_pyfmt(a, "the lock's branch is %s but %s is checked out: another agent may have switched it",
                               py_str(a, dk_json_getz(lock, "branch")), current));
    const char *me = dk_slot_my_agent(a, NULL);
    if (*me && !agent_is(lock, me)) dk_vec_push(&problems, dk_pyfmt(a, "SLOT_AGENT is %s", me));
    if (problems.n) {
        if (dk_slot_stale(lock, now)) return; /* a stale lock: the holder is gone; the next take replaces it */
        DkStr joined = dk_str_join(a, DK_S("; "), problems.v, problems.n);
        dk_pyprintf("WARNING: slot lock: %s holds %s (%s ago, heartbeat %s ago); %S (slot_lock status)\n",
                     py_str(a, dk_json_getz(lock, "agent")), root,
                     dk_slot_age(a, now - float_of(lock, "started_at", NULL, now)),
                     dk_slot_age(a, now - float_of(lock, "heartbeat", NULL, now)), &joined);
        fflush(stdout);
        return;
    }
    if (now - float_of(lock, "heartbeat", NULL, 0.0) > 60) { /* at most one write a minute */
        dk_json_set(a, lock, DK_S("heartbeat"), dk_json_float(a, now));
        dk_json_set(a, lock, DK_S("last_tool"), jstr(a, tool));
        dk_slot_write(a, lock, root);
    }
}

void dk_slot_warn(const char *tool) {
    DkArenaMark mark = dk_arena_mark(dk_scratch());
    DkTry t;
    /* any failure is swallowed: a warning never fails its tool */
    if (DK_TRY(&t)) {
        warn_body(tool, dk_slot_root(dk_scratch()));
        dk_try_end(&t);
    }
    dk_arena_reset(dk_scratch(), mark);
}
