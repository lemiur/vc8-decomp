// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* lane_lock.h: the claim id and the age text, and the claim registry on a temporary repository. */
#include "dk/dk.h"
#include "dk/test.h"
#include "lane_lock.h"

#pragma warning(push)
#pragma warning(disable : 4030 4031) /* fs.h and proc.h declare dk_which differently */
#include "dk/fs.h"
#include "dk/proc.h"
#pragma warning(pop)
#include "dk/win.h"

DK_TEST(claim_id) {
    DkArena *a = dk_arena_new(0);
    CHECK_CZ(dk_lane_claim_id(a, DK_S("s1"), DK_S("e:\\repo\\x")), "88d6fbd5da7e");
    CHECK_CZ(dk_lane_claim_id(a, DK_S("user@host"), DK_S("c:\\r")), "fdd8f0143032");
    CHECK_CZ(dk_lane_claim_id(a, DK_S("\xc3\xa9"), DK_S("\xc3\xbc")), "4124aa073598");
    CHECK_CZ(dk_lane_claim_id(a, DK_S(""), DK_S("")), "3eb416223e9e");
    dk_arena_free(a);
}

DK_TEST(age_text) {
    DkArena *a = dk_arena_new(0);
    CHECK_STR(dk_lane_age(a, 0), "0m");
    CHECK_STR(dk_lane_age(a, 59.9), "0m");
    CHECK_STR(dk_lane_age(a, 60), "1m");
    CHECK_STR(dk_lane_age(a, 61), "1m");
    CHECK_STR(dk_lane_age(a, 3599.9), "59m");
    CHECK_STR(dk_lane_age(a, 3600), "1.0h");
    CHECK_STR(dk_lane_age(a, 5400), "1.5h");
    CHECK_STR(dk_lane_age(a, 36000), "10.0h");
    CHECK_STR(dk_lane_age(a, 43200.5), "12.0h");
    dk_arena_free(a);
}

typedef struct {
    DkStrVec lines;
} Lines;

static void collect(void *ctx, DkStr line) {
    Lines *l = (Lines *)ctx;
    dk_vec_push(&l->lines, dk_str(dk_strdup(dk_arena(), (const char *)dk_cz(dk_arena(), line))));
}

static void git(const char *dir, const char *a1, const char *a2, const char *a3, const char *a4) {
    const char *argv[] = {"git", "-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", a1, a2, a3, a4, NULL};
    for (int i = 10; i >= 8 && !argv[i]; i--) argv[i] = NULL;
    DkProcResult r = dk_run(&(DkProcSpec){.argv = argv, .out = DK_IO_CAPTURE, .err = DK_IO_CAPTURE, .text = true});
    CHECK_EQ_I64(r.status, DK_PROC_OK);
    CHECK_EQ_I64(r.returncode, 0);
}

/* The registry on a temporary repository: a claim holds the checkout against another session, not against its own;
 * units overlap case-insensitively; a claim of a dead process on this host is stale and never blocks. */
DK_TEST(registry) {
    DkArena *a = dk_arena();
    char *dir = dk_mkdtemp(a, "lane_lock_test", "", NULL);
    REQUIRE(dir != NULL);
    git(dir, "init", "-q", "-b", "main");
    git(dir, "commit", "--allow-empty", "-m", "x");
    git(dir, "commit", "--allow-empty", "-m", "x");
    DkLaneClaimArgs claim = {.checkout = dir, .session = "sess-a", .ttl = DK_LANE_TTL_HOURS, .units = "Alpha,beta"};
    claim.note = "n";
    CHECK_EQ_I64(dk_lane_cmd_claim(&claim), 0);

    Lines l = {{0}};
    DkStrVec units = {0};
    dk_vec_push(&units, DK_S("ALPHA"));
    /* another session: refused for the checkout (and the unit) */
    CHECK(!dk_lane_check(dir, &units, "sess-b", DK_LANE_TTL_HOURS, collect, &l));
    REQUIRE(l.lines.n == 1);
    CHECK(strstr(dk_cz(a, l.lines.v[0]), "lane_lock: refused: held by another session (checkout)") != NULL);
    /* the same session: fine */
    l.lines.n = 0;
    CHECK(dk_lane_check(dir, &units, "sess-a", DK_LANE_TTL_HOURS, collect, &l));
    CHECK_EQ_I64((i64)l.lines.n, 0);
    /* the branch switched under the claim */
    git(dir, "checkout", "-q", "-b", "other");
    CHECK(!dk_lane_check(dir, NULL, "sess-a", DK_LANE_TTL_HOURS, collect, &l));
    CHECK(strstr(dk_cz(a, l.lines.v[0]), "switched under the claim") != NULL);
    git(dir, "checkout", "-q", "main", NULL);
    /* an old heartbeat is stale: reported, never blocking */
    l.lines.n = 0;
    CHECK(dk_lane_check(dir, NULL, "sess-b", 0.0, collect, &l));
    CHECK(l.lines.n >= 1 && strstr(dk_cz(a, l.lines.v[0]), "lane_lock: stale claim (heartbeat") != NULL);
    DkLaneReleaseArgs rel = {.checkout = dir, .session = "sess-a", .ttl = DK_LANE_TTL_HOURS};
    CHECK_EQ_I64(dk_lane_cmd_release(&rel), 0);
    l.lines.n = 0;
    CHECK(dk_lane_check(dir, &units, "sess-b", DK_LANE_TTL_HOURS, collect, &l));
    CHECK_EQ_I64((i64)l.lines.n, 0);
    dk_vec_free(&units);
    dk_tempdir_cleanup(dir);
}

DK_TEST_MAIN("lane_lock")
