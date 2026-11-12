// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* priority: the class a search tool asks for, from its flag and the environment. */
#include "dk/dk.h"
#include "dk/fs.h"
#include "dk/test.h"
#include "priority.h"

#include <string.h>

DK_TEST(wanted) {
    CHECK(dk_setenv(DK_PRIORITY_ENV, ""));
    CHECK_CZ(dk_priority_wanted(true), "normal");
    CHECK_CZ(dk_priority_wanted(false), "below-normal");
    static const char *const off[] = {"normal", " OFF ", "0", "No", "none"};
    for (size_t i = 0; i < DK_ARRAY_LEN(off); i++) {
        CHECK(dk_setenv(DK_PRIORITY_ENV, off[i]));
        CHECK_MSG(strcmp(dk_priority_wanted(false), "normal") == 0, "%s", off[i]);
    }
    CHECK(dk_setenv(DK_PRIORITY_ENV, "low"));
    CHECK_CZ(dk_priority_wanted(false), "below-normal");
    CHECK(dk_setenv(DK_PRIORITY_ENV, "normal"));
    CHECK_CZ(dk_priority_lower(false), "normal"); /* nothing changed */
}

DK_TEST(flag) {
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "t"});
    dk_priority_add_argument(ap);
    char *argv[] = {"t", "--normal-priority", NULL};
    DkArgs *r = dk_args_parse(ap, 2, argv);
    CHECK(dk_args_bool(r, "normal_priority"));
}

DK_TEST_MAIN("priority")
