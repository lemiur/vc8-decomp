// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* text_checks: the conflict-marker and BOM scans on synthetic text, the prefix rule, and a run over a temporary repository. */
#include "dk/test.h"

#pragma warning(push)
#pragma warning(disable : 4030 4031) /* fs.h and proc.h declare dk_which differently */
#include "dk/fs.h"
#include "dk/proc.h"
#pragma warning(pop)
#include "dk/win.h"
#include "text_checks.h"

#include <stdio.h>

static DkStrVec scan(DkStr name, const char *data, size_t n, const DkStrVec *bom) {
    DkStrVec found = {0};
    dk_text_checks_scan(dk_arena(), name, dk_strn(data, n), bom, &found);
    return found;
}

DK_TEST(prefixes) {
    CHECK(dk_text_checks_under(DK_S("src/a.c"), DK_S("src")));
    CHECK(dk_text_checks_under(DK_S("src/a.c"), DK_S("src/")));
    CHECK(dk_text_checks_under(DK_S("src/a.c"), DK_S("src/a.c")));
    CHECK(!dk_text_checks_under(DK_S("srcx/a.c"), DK_S("src")));
    CHECK(!dk_text_checks_under(DK_S("docs/a.c"), DK_S("src")));
    CHECK(dk_text_checks_under(DK_S("docs/a.c"), DK_S("")));
}

DK_TEST(markers) {
    DkArena *a = dk_arena();
    static const char text[] = "a\n<<<<<<< HEAD\nx\n=======\ny\n>>>>>>> branch\nz\n";
    DkStrVec f = scan(DK_S("f.txt"), text, sizeof text - 1, NULL);
    REQUIRE(f.n == 3);
    CHECK_CZ(dk_cz(a, f.v[0]), "f.txt:2: conflict marker");
    CHECK_CZ(dk_cz(a, f.v[1]), "f.txt:4: conflict marker");
    CHECK_CZ(dk_cz(a, f.v[2]), "f.txt:6: conflict marker");
    /* a setext heading outside a conflict is not a marker */
    static const char md[] = "Title\n=======\ntext\n";
    f = scan(DK_S("a.md"), md, sizeof md - 1, NULL);
    CHECK_EQ_I64((i64)f.n, 0);
    /* a diff3 base line counts, a longer run does not start a conflict */
    static const char d3[] = "||||||| base\n<<<<<<<<\n";
    f = scan(DK_S("a.txt"), d3, sizeof d3 - 1, NULL);
    CHECK_EQ_I64((i64)f.n, 1);
    /* a binary file (a NUL early) is skipped */
    static const char bin[] = "\0<<<<<<< x\n";
    f = scan(DK_S("a.bin"), bin, sizeof bin - 1, NULL);
    CHECK_EQ_I64((i64)f.n, 0);
}

DK_TEST(bom) {
    DkArena *a = dk_arena();
    DkStrVec bom = {0};
    dk_vec_push(&bom, DK_S("src/"));
    static const char text[] = "\xef\xbb\xbfhello\n";
    DkStrVec f = scan(DK_S("src/a.c"), text, sizeof text - 1, &bom);
    REQUIRE(f.n == 1);
    CHECK_CZ(dk_cz(a, f.v[0]), "src/a.c: UTF-8 BOM");
    f = scan(DK_S("docs/a.md"), text, sizeof text - 1, &bom);
    CHECK_EQ_I64((i64)f.n, 0);
    f = scan(DK_S("src/a.c"), text, sizeof text - 1, NULL);
    CHECK_EQ_I64((i64)f.n, 0);
    dk_vec_free(&bom);
}

static void git(const char *dir, const char *a1, const char *a2, const char *a3) {
    const char *argv[] = {"git", "-C", dir, a1, a2, a3, NULL};
    for (int i = 5; i >= 4 && !argv[i]; i--) argv[i] = NULL;
    DkProcResult r = dk_run(&(DkProcSpec){.argv = argv, .out = DK_IO_CAPTURE, .err = DK_IO_CAPTURE, .text = true});
    CHECK_EQ_I64(r.status, DK_PROC_OK);
    CHECK_EQ_I64(r.returncode, 0);
}

DK_TEST(run_over_repository) {
    DkArena *a = dk_arena();
    char *dir = dk_mkdtemp(a, "text_checks_test", "", NULL);
    REQUIRE(dir != NULL);
    git(dir, "init", "-q", NULL);
    CHECK(dk_makedirs(dk_path_join(a, dir, "src"), true));
    static const char bad[] = "\xef\xbb\xbfx\n<<<<<<< a\n";
    static const char good[] = "fine\n";
    CHECK(dk_write_file(dk_path_join(a, dir, "src/bad.c"), bad, sizeof bad - 1));
    CHECK(dk_write_file(dk_path_join(a, dir, "good.txt"), good, sizeof good - 1));
    git(dir, "add", "-A", NULL);
    dk_set_root(dir);
    DkStrVec bom = {0}, only = {0};
    dk_vec_push(&bom, DK_S("src"));
    fflush(stdout);
    CHECK_EQ_I64(dk_text_checks_run(&(DkTextChecksOpts){.bom_under = &bom}), 1);
    dk_vec_push(&only, DK_S("good.txt"));
    CHECK_EQ_I64(dk_text_checks_run(&(DkTextChecksOpts){.paths = &only, .bom_under = &bom}), 0);
    dk_vec_free(&bom);
    dk_vec_free(&only);
    dk_tempdir_cleanup(dir);
}

DK_TEST_MAIN("text_checks")
