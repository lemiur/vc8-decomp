// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* slot_lock.exe take|status|release: claims, shows or gives back the slot lock of the worktree (--root, $DECOMPKIT_ROOT,
 * or the checkout the executable is in). The logic is in lib/slot_lock.c. */
#include "dk/args.h"
#include "slot_lock.h"

static const char DOC[] =
#include "slot_lock_doc.inc"
    "";

static int run(int argc, char **argv) {
    DkArena *a = dk_arena();
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){
        .prog = "slot_lock.exe", .description = DOC, .formatter = DK_FORMAT_RAW_DESCRIPTION});
    dk_arg(ap, &(DkArgDesc){.names = "--root", .help = "the worktree (default: $DECOMPKIT_ROOT, else the executable's checkout)"});
    DkArgSubparsers *sub = dk_args_subparsers(ap, &(DkArgSubparsersDesc){.dest = "command", .required = true});
    DkArgParser *p = dk_args_subparser(sub, "take", NULL);
    dk_arg(p, &(DkArgDesc){.names = "--agent"});
    dk_arg(p, &(DkArgDesc){.names = "--note", .dflt = DK_DEF_NONE});
    dk_arg(p, &(DkArgDesc){.names = "--force", .action = DK_ARG_STORE_TRUE});
    dk_args_subparser(sub, "status", NULL);
    p = dk_args_subparser(sub, "release", NULL);
    dk_arg(p, &(DkArgDesc){.names = "--agent"});
    dk_arg(p, &(DkArgDesc){.names = "--force", .action = DK_ARG_STORE_TRUE});
    DkArgs *args = dk_args_parse(ap, argc, argv);

    if (!dk_args_is_none(args, "root")) dk_set_root(dk_cz(a, dk_args_str(args, "root")));
    const char *root = dk_slot_root(a);
    DkStr command = dk_args_str(args, "command");
    if (dk_str_eqz(command, "status")) return dk_slot_status(a, root);
    const char *given = dk_args_is_none(args, "agent") ? NULL : dk_cz(a, dk_args_str(args, "agent"));
    const char *agent = dk_slot_my_agent(a, given);
    bool force = dk_args_bool(args, "force");
    if (dk_str_eqz(command, "take")) {
        if (!*agent) dk_args_error(ap, "take needs --agent ID (or $SLOT_AGENT)");
        const char *note = dk_args_is_none(args, "note") ? NULL : dk_cz(a, dk_args_str(args, "note"));
        return dk_slot_take(a, agent, note, force, root);
    }
    if (!*agent && !force) dk_args_error(ap, "release needs --agent ID (or $SLOT_AGENT), or --force");
    return dk_slot_release(a, agent, force, root);
}

DK_MAIN(run, "slot_lock")
