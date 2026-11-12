// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* lane_lock.exe: the command line of the lane registry (claim, release, status, check). */
#include "dk/args.h"
#include "lane_lock.h"

static const char *opt_str(const DkArgs *r, const char *dest) {
    if (dk_args_is_none(r, dest)) return NULL;
    DkStr s = dk_args_str(r, dest);
    return dk_cz(dk_arena(), s);
}

static int run(int argc, char **argv) {
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "lane_lock.exe",
                                                                .description = dk_lane_lock_doc,
                                                                .formatter = DK_FORMAT_RAW_DESCRIPTION});
    DkArgSubparsers *sub = dk_args_subparsers(ap, &(DkArgSubparsersDesc){.dest = "cmd", .required = true});
    const char *names[] = {"claim", "release", "status", "check"};
    DkArgParser *sp[4];
    for (int i = 0; i < 4; i++) {
        sp[i] = dk_args_subparser(sub, names[i], NULL);
        dk_arg(sp[i], &(DkArgDesc){.names = "--checkout"});
        dk_arg(sp[i], &(DkArgDesc){.names = "--session"});
        dk_arg(sp[i], &(DkArgDesc){.names = "--ttl", .type = DK_T_FLOAT, .dflt = DK_DEF_FLOAT(DK_LANE_TTL_HOURS)});
    }
    dk_arg(sp[0], &(DkArgDesc){.names = "--branch"});
    dk_arg(sp[0], &(DkArgDesc){.names = "--units"});
    dk_arg(sp[0], &(DkArgDesc){.names = "--pid", .type = DK_T_INT});
    dk_arg(sp[0], &(DkArgDesc){.names = "--note"});
    dk_arg(sp[0], &(DkArgDesc){.names = "--force", .action = DK_ARG_STORE_TRUE});
    DkArgMutex *g = dk_args_mutex(sp[1], false);
    dk_arg_mutex(g, &(DkArgDesc){.names = "--all", .action = DK_ARG_STORE_TRUE});
    dk_arg_mutex(g, &(DkArgDesc){.names = "--stale", .action = DK_ARG_STORE_TRUE});
    dk_arg_mutex(g, &(DkArgDesc){.names = "--id"});
    dk_arg(sp[3], &(DkArgDesc){.names = "--units"});
    dk_arg(sp[3], &(DkArgDesc){.names = "--hook", .action = DK_ARG_STORE_TRUE});

    const DkArgs *r = dk_args_parse(ap, argc, argv);
    DkStr cmd = dk_args_str(r, "cmd");
    const char *checkout = opt_str(r, "checkout"), *session = opt_str(r, "session");
    double ttl = dk_args_float(r, "ttl");
    if (dk_str_eqz(cmd, "claim")) {
        DkLaneClaimArgs a = {.checkout = checkout, .session = session, .ttl = ttl,
                              .branch = opt_str(r, "branch"), .units = opt_str(r, "units"),
                              .note = opt_str(r, "note"), .force = dk_args_bool(r, "force")};
        a.pid_given = !dk_args_is_none(r, "pid");
        a.pid = a.pid_given ? dk_args_int(r, "pid") : 0;
        return dk_lane_cmd_claim(&a);
    }
    if (dk_str_eqz(cmd, "release")) {
        DkLaneReleaseArgs a = {.checkout = checkout, .session = session, .ttl = ttl, .all = dk_args_bool(r, "all"),
                                .stale = dk_args_bool(r, "stale"), .id = opt_str(r, "id")};
        return dk_lane_cmd_release(&a);
    }
    if (dk_str_eqz(cmd, "status")) {
        DkLaneStatusArgs a = {.checkout = checkout, .session = session, .ttl = ttl};
        return dk_lane_cmd_status(&a);
    }
    DkLaneCheckArgs a = {.checkout = checkout, .session = session, .ttl = ttl, .units = opt_str(r, "units"),
                          .hook = dk_args_bool(r, "hook")};
    return dk_lane_cmd_check(&a);
}

DK_MAIN(run, "lane_lock")
