// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Python's argparse (CPython 3.14.8) for command-line tools: a declarative parser that parses, converts, checks and
 * reports exactly as argparse does, and prints argparse's usage and help text byte for byte (without colour: Python
 * only colours a terminal). It covers what the project's tools use and the rest of the common surface:
 *   - options and positionals; actions store, store_const, store_true, store_false, append, append_const, extend,
 *     count, help, version, BooleanOptionalAction; nargs None, N, '?', '*', '+', REMAINDER ('...'), PARSER;
 *   - types str, int, int(v, 0), float, identity (Path), or a converter function; choices (strings); defaults
 *     (a string default goes through the type, as argparse does); const; dest; metavar (a name or a tuple);
 *     required options; help with %(default)s / %(default)r / %(prog)s / %(dest)s / %(choices)s / %%;
 *   - subparsers (add_subparsers(dest=, required=) / add_parser(name, help=, aliases=)), mutually exclusive groups
 *     (required or not), argument groups (title, description);
 *   - parse_args / parse_known_args semantics: the positional/optional interleaving and the greedy matching of
 *     nargs (the regular-expression matching of argparse, done by a small backtracking matcher), long-option
 *     prefix abbreviation (allow_abbrev), --opt=value, attached short values (-j8), short flag clusters (-abc),
 *     the negative-number rule, `--`, "ambiguous option", "unrecognized arguments", "expected one argument",
 *     "invalid int value: 'x'", "invalid choice: 'x' (choose from 'a', 'b')", "the following arguments are
 *     required: ...", "argument --x: not allowed with argument --y", "one of the arguments --a --b is required";
 *   - formatters HelpFormatter, RawDescriptionHelpFormatter, RawTextHelpFormatter, ArgumentDefaultsHelpFormatter,
 *     MetavarTypeHelpFormatter; usage wrapping and help wrapping (textwrap.wrap with hyphen breaking) at the width
 *     argparse uses: the COLUMNS environment variable if it is a positive integer, else the console width of
 *     stdout, else 80, minus 2.
 * An error prints argparse's usage and "<prog>: error: <message>" on stderr and exits with code 2; -h prints the
 * help on stdout and exits 0. prog is settable.
 *
 *     static const char *const builds[] = {"debug", "release", "both", NULL};
 *     DkArgParser *p = dk_args_parser(NULL, &(DkArgParserDesc){
 *         .prog = "demo", .description = "Run the demo.", .formatter = DK_FORMAT_RAW_DESCRIPTION});
 *     dk_arg(p, &(DkArgDesc){.names = "-j --jobs", .type = DK_T_INT, .dflt = DK_DEF_INT(4), .metavar = "N"});
 *     dk_arg(p, &(DkArgDesc){.names = "--build", .choices = builds, .dflt = DK_DEF_STR("both")});
 *     dk_arg(p, &(DkArgDesc){.names = "units", .nargs = DK_NARGS_STAR});
 *     DkArgs *r = dk_args_parse(p, argc, argv);                 // argv[0] is the program: parse_args(argv[1:])
 *     i64 jobs = dk_args_int(r, "jobs");
 *     DkStrVec units = dk_args_strs(r, "units");
 *
 * Differences from Python: an int is 64-bit (a bigger one is "invalid int value"); choices are strings, so a
 * choices list on a typed argument (int, float) is rejected when the parser is built; the repr of a str in messages
 * escapes the common non-printable code points only (C0/C1 controls, NBSP, soft hyphen and the Unicode space and
 * format ranges), not the whole Unicode printable table; fromfile_prefix_chars, parents, conflict_handler='resolve',
 * argument_default, set_defaults, FileType, parse_intermixed_args, suggest_on_error, deprecated and prefix_chars other
 * than "-" are not supported. A mistake in the declaration (a duplicate option string, a bad nargs) is an internal
 * error (dk_panic), where Python raised ValueError at add_argument. */
#pragma once
#include "str.h"

typedef struct DkArgParser DkArgParser;
typedef struct DkArgAction DkArgAction;
typedef struct DkArgSection DkArgSection;     /* add_argument_group */
typedef struct DkArgMutex DkArgMutex;         /* add_mutually_exclusive_group */
typedef struct DkArgSubparsers DkArgSubparsers;
typedef struct DkArgs DkArgs;                 /* the parse result: Python's Namespace */

/* ---- values ---------------------------------------------------------------------------------------------------- */
typedef enum {
    DK_V_NONE,  /* Python None */
    DK_V_STR,
    DK_V_INT,
    DK_V_FLOAT,
    DK_V_BOOL,
    DK_V_LIST   /* a list of values (nargs lists, append, extend) */
} DkArgKind;
typedef struct DkArgValue DkArgValue;
struct DkArgValue {
    DkArgKind kind;
    DkStr s;                  /* DK_V_STR */
    i64 i;                     /* DK_V_INT, DK_V_BOOL (0 or 1) */
    double f;                  /* DK_V_FLOAT */
    const DkArgValue *items;  /* DK_V_LIST */
    size_t n;
};

/* A default or a const. Build with DK_DEF_*; the zero value is "not given". DK_DEF_SUPPRESS is
 * default=argparse.SUPPRESS: the attribute does not exist unless the argument is given. */
typedef enum {
    DK_DK_UNSET = 0,
    DK_DK_NONE,
    DK_DK_STR,
    DK_DK_INT,
    DK_DK_FLOAT,
    DK_DK_BOOL,
    DK_DK_SUPPRESS
} DkDefaultKind;
typedef struct {
    DkDefaultKind kind;
    const char *s;
    i64 i;
    double f;
} DkArgDefault;
#define DK_DEF_NONE ((DkArgDefault){DK_DK_NONE, NULL, 0, 0.0})
#define DK_DEF_STR(str) ((DkArgDefault){DK_DK_STR, (str), 0, 0.0})
#define DK_DEF_INT(v) ((DkArgDefault){DK_DK_INT, NULL, (v), 0.0})
#define DK_DEF_FLOAT(v) ((DkArgDefault){DK_DK_FLOAT, NULL, 0, (v)})
#define DK_DEF_BOOL(v) ((DkArgDefault){DK_DK_BOOL, NULL, (v) ? 1 : 0, 0.0})
#define DK_DEF_SUPPRESS ((DkArgDefault){DK_DK_SUPPRESS, NULL, 0, 0.0})

/* ---- declarations ---------------------------------------------------------------------------------------------- */
typedef enum {
    DK_FORMAT_DEFAULT = 0,        /* HelpFormatter */
    DK_FORMAT_RAW_DESCRIPTION,    /* RawDescriptionHelpFormatter */
    DK_FORMAT_RAW_TEXT,           /* RawTextHelpFormatter */
    DK_FORMAT_ARGUMENT_DEFAULTS,  /* ArgumentDefaultsHelpFormatter */
    DK_FORMAT_METAVAR_TYPE        /* MetavarTypeHelpFormatter */
} DkArgFormatter;

typedef struct {
    const char *prog;           /* NULL: the tool name (dk_tool_name()); subparsers: "<parent prog> <name>" */
    const char *usage;          /* NULL: generated; "%(prog)s" is replaced */
    const char *description;
    const char *epilog;
    DkArgFormatter formatter;
    bool no_help;               /* add_help=False */
    bool no_abbrev;             /* allow_abbrev=False */
    const char *help;           /* subparsers only: the help of this command in the command list (NULL: none) */
    const char *const *aliases; /* subparsers only: NULL-terminated */
} DkArgParserDesc;

enum {
    DK_NARGS_NONE = 0,       /* one value (nargs=None) */
    DK_NARGS_OPT = -1,       /* '?' */
    DK_NARGS_STAR = -2,      /* '*' */
    DK_NARGS_PLUS = -3,      /* '+' */
    DK_NARGS_REMAINDER = -4, /* argparse.REMAINDER ('...') */
    DK_NARGS_PARSER = -5,    /* 'A...' (the subparsers action) */
    DK_NARGS_SUPPRESS = -6
    /* a positive N is nargs=N: a list of N values */
};

typedef enum {
    DK_ARG_STORE = 0,
    DK_ARG_STORE_CONST,
    DK_ARG_STORE_TRUE,
    DK_ARG_STORE_FALSE,
    DK_ARG_APPEND,
    DK_ARG_APPEND_CONST,
    DK_ARG_EXTEND,
    DK_ARG_COUNT,
    DK_ARG_HELP,
    DK_ARG_VERSION,
    DK_ARG_BOOLEAN_OPTIONAL  /* BooleanOptionalAction: --x and --no-x */
} DkArgActionKind;

typedef enum {
    DK_T_STR = 0,  /* type=None / str */
    DK_T_INT,      /* int */
    DK_T_INT0,     /* lambda v: int(v, 0) (the type name in messages is "<lambda>") */
    DK_T_FLOAT,    /* float */
    DK_T_IDENT,    /* Path and other types that accept every string (the value stays a string); type_name is shown */
    DK_T_CUSTOM    /* conv */
} DkArgType;

/* A converter for DK_T_CUSTOM. Return true with *out set, or false: with msg set (msg->p != NULL) it is an
 * ArgumentTypeError (the message is shown as is), without it a ValueError ("invalid <type_name> value: '<arg>'"). */
typedef bool (*DkArgConv)(void *ctx, DkArena *a, DkStr in, DkArgValue *out, DkStr *msg);

typedef struct {
    const char *names;           /* options "-j --jobs" (separated by spaces) or one positional name "units" */
    DkArgActionKind action;
    DkArgType type;
    DkArgConv conv;
    void *conv_ctx;
    const char *type_name;       /* DK_T_CUSTOM / DK_T_IDENT: Python's type.__name__ for messages */
    int nargs;                   /* DK_NARGS_* or N */
    const char *dest;            /* NULL: from the first long option (--foo-bar -> foo_bar) or the positional name */
    const char *metavar;
    const char *const *metavars; /* a metavar tuple, NULL-terminated (nargs=2, metavar=("OLD", "NEW")) */
    const char *const *choices;  /* NULL-terminated */
    DkArgDefault dflt;
    const char *const *dflt_list; /* default=[...] of strings for append/extend, NULL-terminated; non-NULL even if empty */
    DkArgDefault cnst;          /* const= */
    bool required;               /* options only */
    const char *help;            /* NULL: no help; DK_ARG_SUPPRESS hides the argument */
    const char *version;         /* DK_ARG_VERSION */
} DkArgDesc;
extern const char dk_args_suppress[];
#define DK_ARG_SUPPRESS dk_args_suppress

typedef struct {
    const char *dest;            /* NULL: SUPPRESS */
    bool required;
    const char *metavar;
    const char *help;
    const char *title;           /* with a title or description the commands get their own section */
    const char *description;
} DkArgSubparsersDesc;

/* ---- building -------------------------------------------------------------------------------------------------- */
/* arena NULL: the calling thread's long-lived arena. A parser is used by one thread at a time. */
DkArgParser *dk_args_parser(DkArena *arena, const DkArgParserDesc *d);
DkArgAction *dk_arg(DkArgParser *p, const DkArgDesc *d);                                   /* add_argument */
DkArgSection *dk_args_group(DkArgParser *p, const char *title, const char *description);   /* add_argument_group */
DkArgAction *dk_arg_in(DkArgSection *g, const DkArgDesc *d);
DkArgMutex *dk_args_mutex(DkArgParser *p, bool required);                  /* add_mutually_exclusive_group */
DkArgMutex *dk_args_mutex_in(DkArgSection *g, bool required);
DkArgAction *dk_arg_mutex(DkArgMutex *g, const DkArgDesc *d);
DkArgSubparsers *dk_args_subparsers(DkArgParser *p, const DkArgSubparsersDesc *d);
/* add_parser(name, help=..., aliases=...): d may be NULL; the prog is "<parent usage prefix> <name>". */
DkArgParser *dk_args_subparser(DkArgSubparsers *s, const char *name, const DkArgParserDesc *d);
DkArgParser *dk_args_subparser_get(DkArgSubparsers *s, const char *name); /* subparsers.choices[name], or NULL */

/* ---- parsing --------------------------------------------------------------------------------------------------- */
/* parse_args(argv[1:]): on an error prints the usage and message on stderr and exits 2; on -h/--help prints the help
 * on stdout and exits 0. The result is allocated from the parser's arena. */
DkArgs *dk_args_parse(DkArgParser *p, int argc, char **argv);
/* parse_known_args(argv[1:]): the unrecognized arguments are dk_args_extras(). */
DkArgs *dk_args_parse_known(DkArgParser *p, int argc, char **argv);
/* The same on an explicit list (Python's parse_args(list)). */
DkArgs *dk_args_parse_list(DkArgParser *p, const DkStr *args, size_t n, bool known);
/* Without exiting: returns NULL when Python would have exited, with the exit code and the texts it would have
 * written (usage and error line on err, help or version on out). */
typedef struct {
    int code;
    DkStr out;
    DkStr err;
} DkArgsExit;
DkArgs *dk_args_try_parse(DkArgParser *p, const DkStr *args, size_t n, bool known, DkArgsExit *ex);

/* ---- results --------------------------------------------------------------------------------------------------- */
/* Accessors by dest. An unknown dest, or the wrong kind of value, is an internal error (Python's AttributeError or
 * TypeError). None reads as "" / 0 / false / empty list; use dk_args_is_none to tell. */
bool dk_args_has(const DkArgs *r, const char *dest);     /* the attribute exists (a SUPPRESS default may leave it out) */
const DkArgValue *dk_args_value(const DkArgs *r, const char *dest); /* NULL if absent */
bool dk_args_is_none(const DkArgs *r, const char *dest);
bool dk_args_given(const DkArgs *r, const char *dest);   /* the argument appeared on the command line */
DkStr dk_args_str(const DkArgs *r, const char *dest);   /* str value; for a None the result has p == NULL, n == 0 */
i64 dk_args_int(const DkArgs *r, const char *dest);      /* int, also count */
double dk_args_float(const DkArgs *r, const char *dest);
bool dk_args_bool(const DkArgs *r, const char *dest);
size_t dk_args_len(const DkArgs *r, const char *dest);   /* len() of a list value */
const DkArgValue *dk_args_item(const DkArgs *r, const char *dest, size_t i);
DkStrVec dk_args_strs(const DkArgs *r, const char *dest); /* a list of str, as a vector (heap-backed) */
DkI64Vec dk_args_ints(const DkArgs *r, const char *dest);
DkStrVec dk_args_extras(const DkArgs *r);                /* parse_known_args' second result */

/* ---- usage, help and errors ------------------------------------------------------------------------------------ */
DkStr dk_args_format_usage(DkArgParser *p);              /* format_usage(): "usage: ...\n" */
DkStr dk_args_format_help(DkArgParser *p);               /* format_help() */
void dk_args_print_usage(DkArgParser *p);                 /* stdout */
void dk_args_print_help(DkArgParser *p);                  /* stdout */
/* parser.error(message): the usage and "<prog>: error: <message>" on stderr, exit code 2. */
DK_NORETURN void dk_args_error(DkArgParser *p, DK_PRINTF_FMT const char *fmt, ...);
DkStr dk_args_error_text(DkArgParser *p, DkStr message); /* what error() writes, without exiting */
const char *dk_args_prog(const DkArgParser *p);
/* The width argparse formats to: COLUMNS if a positive integer, else the console width of stdout, else 80, minus 2. */
int dk_args_width(void);
