// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Tests of lib/slot_lock.c: age and describe texts, the TTL, the branch name, the CRLF write, and the warn line, on a
 * lock {"agent": "a1", "branch": "br", "started": "2001-09-09 01:46:40", "started_at": 1e9, "heartbeat": 1000003600.0,
 * "last_tool": "mytool", "note": "nn"} and on temporary repositories. */
#include "dk/test.h"

#pragma warning(push)
#pragma warning(disable : 4030 4031) /* fs.h and proc.h declare dk_which differently */
#include "dk/fs.h"
#include "dk/proc.h"
#pragma warning(pop)
#include "dk/clock.h"
#include "dk/json.h"
#include "dk/win.h"
#include "slot_lock.h"

#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Whether out says "heartbeat Ns ago" with N under a minute: a heartbeat written moments before, without assuming
 * how many seconds a loaded build machine took in between. */
static bool recent_heartbeat(const char *out) {
    const char *h = strstr(out, "heartbeat ");
    if (!h) return false;
    char *end = NULL;
    long n = strtol(h + 10, &end, 10);
    return end != h + 10 && n >= 0 && n < 60 && strncmp(end, "s ago", 5) == 0;
}

static DkJson *sample_lock(DkArena *a) {
    const char *text =
        "{\"agent\": \"a1\", \"branch\": \"br\", \"started\": \"2001-09-09 01:46:40\", \"started_at\": 1000000000.0,"
        " \"heartbeat\": 1000003600.0, \"last_tool\": \"gate.exe\", \"note\": \"nn\"}";
    DkJsonError err;
    DkJson *j = dk_json_parse(a, dk_str(text), &err);
    CHECK(j != NULL);
    return j;
}

DK_TEST(age_text) {
    DkArena *a = dk_scratch();
    CHECK_CZ(dk_slot_age(a, 0), "0s");
    CHECK_CZ(dk_slot_age(a, 1), "1s");
    CHECK_CZ(dk_slot_age(a, 119.9), "119s");
    CHECK_CZ(dk_slot_age(a, 120), "2min");
    CHECK_CZ(dk_slot_age(a, 7199), "119min");
    CHECK_CZ(dk_slot_age(a, 7200), "2.0h");
    CHECK_CZ(dk_slot_age(a, 3600 * 3.55), "3.5h");
    CHECK_CZ(dk_slot_age(a, -5), "0s");
    CHECK_CZ(dk_slot_age(a, 1e6), "277.8h");
    CHECK_CZ(dk_slot_age(a, 359999.9), "100.0h");
    CHECK_CZ(dk_slot_age(a, 12.5), "12s");
    CHECK_CZ(dk_slot_age(a, 7200.4), "2.0h");
}

DK_TEST(describe_and_stale) {
    DkArena *a = dk_scratch();
    DkJson *lock = sample_lock(a);
    CHECK_CZ(dk_slot_describe(a, lock, 1000010000.0),
             "a1 on br since 2001-09-09 01:46:40 (2.8h ago), heartbeat 106min ago by gate.exe, note: nn");
    DkJsonError err;
    DkJson *minimal = dk_json_parse(a, dk_str("{\"agent\": \"a1\"}"), &err);
    CHECK_CZ(dk_slot_describe(a, minimal, 1000010000.0), "a1 on None since None (0s ago), heartbeat 0s ago");
    dk_setenv("SLOT_LOCK_TTL", "");
    CHECK(!dk_slot_stale(lock, 1000003600.0 + 6 * 3600));
    CHECK(dk_slot_stale(lock, 1000003600.0 + 6 * 3600 + 1));
    dk_setenv("SLOT_LOCK_TTL", "abc");
    CHECK(dk_slot_stale(lock, 1000003600.0 + 6 * 3600 + 1));
    dk_setenv("SLOT_LOCK_TTL", "1e9");
    CHECK(!dk_slot_stale(lock, 1000003600.0 + 6 * 3600 + 1));
    dk_setenv("SLOT_LOCK_TTL", "0");
    CHECK(dk_slot_stale(lock, 1000003600.1));
    dk_unsetenv("SLOT_LOCK_TTL");
}

static void git(const char *dir, const char *a1, const char *a2, const char *a3, const char *a4, const char *a5,
                const char *a6) {
    const char *argv[] = {"git", "-C", dir, a1, a2, a3, a4, a5, a6, NULL};
    for (int i = 8; i >= 4 && !argv[i]; i--) argv[i] = NULL;
    DkProcResult r = dk_run(&(DkProcSpec){.argv = argv, .out = DK_IO_CAPTURE, .err = DK_IO_CAPTURE, .text = true});
    CHECK_EQ_I64(r.status, DK_PROC_OK);
}

/* Redirects the process's stdout into a file for the duration of a call and returns what was written. */
static char *capture_stdout(DkArena *a, const char *tmp_file, void (*fn)(void *), void *ctx) {
    fflush(stdout);
    int saved = _dup(1);
    FILE *f = fopen(tmp_file, "wb");
    if (!f) return "";
    _dup2(_fileno(f), 1);
    fclose(f);
    fn(ctx);
    fflush(stdout);
    _dup2(saved, 1);
    _close(saved);
    DkBytes data = {0};
    dk_read_all(a, tmp_file, &data);
    return dk_cz(a, dk_strn((const char *)data.v, data.n));
}

static void call_warn(void *ctx) {
    dk_slot_warn((const char *)ctx);
}

DK_TEST(branch_warn_and_write) {
    DkArena *a = dk_scratch();
    char *dir = dk_mkdtemp(a, "slot_lock_test", "", NULL);
    REQUIRE(dir != NULL);
    git(dir, "init", "-q", "-b", "main", NULL, NULL);
    CHECK_CZ(dk_slot_branch(a, dir), "-"); /* no commit yet: rev-parse fails */
    git(dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q");
    {
        const char *argv[] = {"git", "-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                              "--allow-empty", "-m", "x", NULL};
        DkProcResult r = dk_run(&(DkProcSpec){.argv = argv, .out = DK_IO_CAPTURE, .err = DK_IO_CAPTURE});
        CHECK_EQ_I64(r.returncode, 0);
    }
    CHECK_CZ(dk_slot_branch(a, dir), "main");
    git(dir, "checkout", "-q", "--detach", NULL, NULL, NULL);
    {
        const char *argv[] = {"git", "-C", dir, "rev-parse", "--short", "HEAD", NULL};
        DkProcResult r = dk_run(&(DkProcSpec){.argv = argv, .out = DK_IO_CAPTURE, .text = true});
        char *want = dk_sprintf(a, "(detached %.*s)", DK_SF(dk_str_strip(r.out)));
        CHECK_CZ(dk_slot_branch(a, dir), want);
    }
    git(dir, "checkout", "-q", "-b", "other", NULL, NULL);
    CHECK_CZ(dk_slot_branch(a, dir), "other");

    /* write: indent=1, CRLF, atomic */
    double now = 1.7e9;
    DkJsonError err;
    char *text = dk_sprintf(a,
        "{\"agent\": \"zz\", \"branch\": \"other\", \"started_at\": %.1f, \"heartbeat\": %.1f, \"started\": \"s\"}",
        now, now);
    DkJson *lock = dk_json_parse(a, dk_str(text), &err);
    REQUIRE(lock != NULL);
    dk_slot_write(a, lock, dir);
    DkBytes raw = {0};
    REQUIRE(dk_read_all(a, dk_path_join(a, dir, ".slot_lock"), &raw));
    DkStr head = dk_strn((const char *)raw.v, DK_MIN(raw.n, 30));
    CHECK(dk_str_startswith(head, DK_S("{\r\n \"agent\": \"zz\",\r\n \"branch\"")));
    DkJson *back = dk_slot_read(a, dir);
    REQUIRE(back != NULL);
    CHECK_STR(dk_json_get_str(back, "agent", DK_S("")), "zz");

    /* warn: a branch that differs prints the warning , SLOT_AGENT too */
    dk_unsetenv("SLOT_AGENT");
    dk_setenv("DECOMPKIT_ROOT", dir);
    dk_set_root(dir);
    double t = dk_time();
    text = dk_sprintf(a, "{\"agent\": \"zz\", \"branch\": \"main\", \"started_at\": %.3f, \"heartbeat\": %.3f, \"started\": \"s\"}",
                       t - 990, t - 990);
    dk_slot_write(a, dk_json_parse(a, dk_str(text), &err), dir);
    char *out = capture_stdout(a, dk_path_join(a, dir, "out.txt"), call_warn, "mytool");
    CHECK(strstr(out, "WARNING: slot lock: zz holds ") == out);
    CHECK(strstr(out, " (16min ago, heartbeat 16min ago); the lock's branch is main but other is checked out: another agent may have switched it (slot_lock status)") != NULL);

    text = dk_sprintf(a, "{\"agent\": \"zz\", \"branch\": \"other\", \"started_at\": %.3f, \"heartbeat\": %.3f, \"started\": \"s\"}",
                       t - 100, t - 100);
    dk_slot_write(a, dk_json_parse(a, dk_str(text), &err), dir);
    out = capture_stdout(a, dk_path_join(a, dir, "out.txt"), call_warn, "mytool");
    CHECK_CZ(out, "");
    back = dk_slot_read(a, dir);
    REQUIRE(back != NULL);
    CHECK_STR(dk_json_get_str(back, "last_tool", DK_S("")), "mytool"); /* the heartbeat was refreshed */
    CHECK(dk_json_get_f64(back, "heartbeat", 0) > t - 5);

    dk_setenv("SLOT_AGENT", "intruder");
    out = capture_stdout(a, dk_path_join(a, dir, "out.txt"), call_warn, "mytool");
    CHECK(strstr(out, "; SLOT_AGENT is intruder (slot_lock status)\n") != NULL);
    CHECK(recent_heartbeat(out)); /* refreshed above: seconds ago, however loaded the machine */
    dk_unsetenv("SLOT_AGENT");

    /* no lock: nothing, and no file is created */
    CHECK(dk_remove(dk_path_join(a, dir, ".slot_lock")));
    out = capture_stdout(a, dk_path_join(a, dir, "out.txt"), call_warn, "mytool");
    CHECK_CZ(out, "");
    CHECK(!dk_exists(dk_path_join(a, dir, ".slot_lock")));
    dk_tempdir_cleanup(dir);
}

DK_TEST_MAIN("slot_lock")
