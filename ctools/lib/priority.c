// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The CPU priority of the search tools: below normal unless the caller (or DECOMPKIT_SEARCH_PRIORITY) asks for
 * normal (priority.h). */
#include "priority.h"

#include "dk/fs.h"
#include "dk/win.h"

#include <string.h>

const char *dk_priority_wanted(bool normal) {
    if (normal) return "normal";
    DkArena *a = dk_scratch();
    DkArenaMark mark = dk_arena_mark(a);
    const char *env = dk_getenv(a, DK_PRIORITY_ENV);
    bool off = false;
    if (env) {
        DkStr v = dk_str_lower(a, dk_str_strip(dk_str(env)));
        static const char *const words[] = {"normal", "off", "0", "no", "none"};
        for (size_t i = 0; i < DK_ARRAY_LEN(words); i++)
            if (dk_str_eqz(v, words[i])) off = true;
    }
    dk_arena_reset(a, mark);
    return off ? "normal" : "below-normal";
}

const char *dk_priority_lower(bool normal) {
    if (strcmp(dk_priority_wanted(normal), "normal") == 0) return "normal";
    return dk_set_priority_below_normal() ? "below-normal" : "normal";
}

void dk_priority_add_argument(DkArgParser *parser) {
    dk_arg(parser, &(DkArgDesc){
        .names = "--normal-priority", .action = DK_ARG_STORE_TRUE,
        .help = "keep the normal CPU priority (default: below normal; also " DK_PRIORITY_ENV "=normal)"});
}
