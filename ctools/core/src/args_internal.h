// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* args.h internals shared by args.c (building and parsing) and args_format.c (usage, help, textwrap, repr). */
#pragma once
#include "dk/args.h"

/* nargs inside the library: DK_NARGS_* values for the special forms, ARGN_NONE for nargs=None, and 0, 1, 2, ... for
 * a number (flag actions have 0). */
#define ARGN_NONE (-100)

/* kinds beyond the public DkArgActionKind */
#define ARGK_SUBPARSERS 100 /* the action add_subparsers creates (nargs PARSER, choices = the sub-parsers) */
#define ARGK_PSEUDO 101     /* the help-only entry of one sub-command in the command list */

typedef DK_VEC(const char *) CzVec;
typedef DK_VEC(DkArgAction *) ActionVec;

struct DkArgAction {
    DkArgParser *parser;
    size_t index;            /* position in parser->actions */
    int kind;
    size_t nopts;
    const char **opts;       /* option_strings, in order given; nopts == 0 for a positional */
    const char *dest;        /* NULL: argparse.SUPPRESS */
    int nargs;
    DkArgType type;
    DkArgConv conv;
    void *conv_ctx;
    const char *type_name;   /* shown in "invalid <type> value" and by MetavarTypeHelpFormatter */
    const char *metavar;
    size_t nmetavars;        /* a metavar tuple */
    const char **metavars;
    const char **choices;    /* NULL when there are none; the sub-commands for ARGK_SUBPARSERS are in sub */
    size_t nchoices;
    DkArgDefault dflt;      /* resolved: never DK_DK_UNSET */
    bool has_dflt_list;
    size_t ndflt_list;
    const char **dflt_list;
    DkArgDefault cnst;
    bool required;
    const char *help;        /* NULL = None */
    bool help_suppress;
    const char *version;
    DkArgSection *section;
    DkArgSubparsers *sub;
};

struct DkArgSection {
    DkArgParser *parser;
    const char *title;
    const char *description;
    ActionVec actions;       /* _group_actions */
};

struct DkArgMutex {
    DkArgParser *parser;
    DkArgSection *container;
    bool required;
    ActionVec actions;
};

struct DkArgSubparsers {
    DkArgParser *owner;
    DkArgAction *action;
    const char *prog_prefix;
    CzVec names;                       /* the name_parser_map keys, aliases included */
    DK_VEC(DkArgParser *) parsers;   /* parallel to names */
    ActionVec pseudo;                  /* _choices_actions: the help lines of the sub-commands */
};

typedef struct {
    const char *str;
    DkArgAction *action;
} OptionEntry;

struct DkArgParser {
    DkArena *a;
    const char *prog;
    const char *usage;
    const char *description;
    const char *epilog;
    DkArgFormatter formatter;
    bool allow_abbrev;
    ActionVec actions;                          /* _actions */
    DK_VEC(OptionEntry) option_actions;        /* _option_string_actions in insertion order */
    DK_VEC(DkArgSection *) sections;          /* _action_groups */
    DK_VEC(DkArgMutex *) mutexes;             /* _mutually_exclusive_groups */
    DkArgSection *positionals;
    DkArgSection *optionals;
    DkArgSubparsers *subparsers;
    bool has_negative_number_optionals;
};

/* ---- args_format.c ---- */
size_t argp_cplen(DkStr s);                      /* len() of the str: code points */
size_t argp_cplen_z(const char *cz);
void argp_repr(DkBuf *b, DkStr s);              /* repr(str) */
void argp_float_repr(DkBuf *b, double x);        /* repr(float) */
const char *argp_action_name(DkArena *a, const DkArgAction *act); /* _get_action_name, NULL for None */
DkStr argp_format_usage(DkArgParser *p);        /* parser.format_usage() */
DkStr argp_format_help(DkArgParser *p);         /* parser.format_help() */
/* The prog of a sub-parsers action: the usage of the positionals so far, without prefix, stripped. */
const char *argp_subparsers_prog(DkArgParser *p);
/* The text a version action prints: formatter.add_text(version); formatter.format_help(). */
DkStr argp_format_version(DkArgParser *p, const char *version);
/* `s % {...}` for the one name help texts and usage use: replaces %(prog)s and %% (everything else is an error). */
DkStr argp_percent_prog(DkArena *a, const char *s, const char *prog);
