// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* eq2.exe <unit> <Function>[,<Function>...|ALL] [--target T] [-v]: symbolic equivalence check of a compiled
 * function against the reference image (lib/eq2_front.c, the engine lib/eq2_*.c). */
#include "dk/args.h"
#include "dk/dk.h"
#include "dk/pool.h"
#include "eq2_front.h"

#include <stdio.h>

/* The description of `--help`. */
static const char DOC[] =
#include "eq2_doc.inc"
    ;

static int run(int argc, char **argv) {
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){
        .prog = "eq2.exe", .description = DOC, .formatter = DK_FORMAT_RAW_DESCRIPTION});
    dk_arg(ap, &(DkArgDesc){.names = "unit"});
    dk_arg(ap, &(DkArgDesc){.names = "functions", .help = "names separated by commas, or ALL (the unit's stopped functions)"});
    dk_arg(ap, &(DkArgDesc){.names = "--target", .metavar = "T",
                            .help = "one configured target (default: the first target with a copy of the function)"});
    dk_arg(ap, &(DkArgDesc){.names = "-v", .action = DK_ARG_STORE_TRUE,
                            .help = "also the checker's notes and the switch cases"});
    dk_arg(ap, &(DkArgDesc){.names = "--root", .metavar = "DIR",
                            .help = "the repository (default: $DECOMPKIT_ROOT, else found from here)"});
    dk_arg(ap, &(DkArgDesc){.names = "--config", .metavar = "FILE",
                            .help = "the configuration (default: <root>/config/ctools.json)"});
    DkArgs *args = dk_args_parse(ap, argc, argv);
    DkArena *a = dk_arena();
    const char *root = dk_args_is_none(args, "root") ? NULL : dk_cz(a, dk_args_str(args, "root"));
    const char *config = dk_args_is_none(args, "config") ? NULL : dk_cz(a, dk_args_str(args, "config"));
    DkErr err = {0};
    DkProject *p = dk_project_load(a, root, config, &err);
    if (!p) {
        fprintf(stderr, "eq2: %s\n", err.msg);
        return 2;
    }
    int target = -1;
    if (!dk_args_is_none(args, "target")) {
        const char *tn = dk_cz(a, dk_args_str(args, "target"));
        target = dk_project_target_index(p, tn);
        if (target < 0) {
            fprintf(stderr, "eq2: %s: not a target of %s\n", tn, dk_project_config_path(p));
            return 2;
        }
    }
    int rc = 0;
    if (!eq2_run(p, dk_cz(a, dk_args_str(args, "unit")), dk_cz(a, dk_args_str(args, "functions")), target,
                 dk_args_bool(args, "v"), &rc, &err)) {
        fprintf(stderr, "eq2: %s\n", err.msg);
        return 2;
    }
    return rc;
}

DK_MAIN(run, "eq2")
