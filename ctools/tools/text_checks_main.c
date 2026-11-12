// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* text_checks.exe [--paths PREFIX ...] [--bom-under PREFIX ...]: text checks over the tracked files: a UTF-8 BOM under the
 * --bom-under folders, and merge conflict markers. Prints one line per finding and a summary line; exit 0 when clean,
 * 1 otherwise. The library part is lib/text_checks.c. */
#include "dk/args.h"
#include "text_checks.h"

static int run(int argc, char **argv) {
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){
        .prog = "text_checks.exe",
        .description = "Text checks over the tracked files: a UTF-8 BOM under the --bom-under folders, and merge conflict "
                       "markers. Prefixes are repository-relative with forward slashes (a folder or one file)."});
    dk_arg(ap, &(DkArgDesc){.names = "--root", .help = "the repository (default: $DECOMPKIT_ROOT, else found from here)"});
    dk_arg(ap, &(DkArgDesc){.names = "--paths", .nargs = DK_NARGS_STAR,
                            .help = "restrict the check to the tracked files under these prefixes (default: all)"});
    dk_arg(ap, &(DkArgDesc){.names = "--bom-under", .nargs = DK_NARGS_STAR,
                            .help = "report a UTF-8 BOM in files under these prefixes (default: never)"});
    DkArgs *args = dk_args_parse(ap, argc, argv);
    if (!dk_args_is_none(args, "root")) dk_set_root(dk_cz(dk_arena(), dk_args_str(args, "root")));
    DkStrVec paths = dk_args_strs(args, "paths"), bom = dk_args_strs(args, "bom_under");
    return dk_text_checks_run(&(DkTextChecksOpts){.paths = &paths, .bom_under = &bom});
}

DK_MAIN(run, "text_checks")
