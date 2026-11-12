// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* args.h: building a parser and parsing, following CPython 3.14.8's argparse.py (_ActionsContainer.add_argument,
 * ArgumentParser._parse_known_args and its helpers, _get_values, _get_value, _check_value). The regular expressions
 * argparse matches the argument-kind pattern ("AOA-A") with are done by a small backtracking matcher with the same
 * greedy semantics. Python's names are in the comments. */
#include "args_internal.h"

#include <stdio.h>
#include <stdlib.h>

/* ---- the result (Namespace) ------------------------------------------------------------------------------------- */
typedef struct {
    const char *name;
    DkArgValue val;
    bool given;                 /* an action of this dest was taken with arguments or as an option */
    bool touched;               /* an action wrote the value after the default was set */
    const DkArgAction *owner;  /* the action whose default set the value */
} NsEntry;

struct DkArgs {
    DkArena *a;
    DK_VEC(NsEntry) v;
    DkStrVec extras;
    DkStrVec unrec;            /* _UNRECOGNIZED_ARGS_ATTR */
};

static NsEntry *ns_find(const DkArgs *ns, const char *name) {
    for (size_t i = 0; i < ns->v.n; i++)
        if (strcmp(ns->v.v[i].name, name) == 0) return &ns->v.v[i];
    return NULL;
}

static DkArgs *ns_new(DkArena *a) {
    DkArgs *ns = DK_NEW(a, DkArgs);
    ns->a = a;
    return ns;
}

static NsEntry *ns_set(DkArgs *ns, const char *name, DkArgValue val, bool touched) {
    NsEntry *e = ns_find(ns, name);
    if (!e) {
        e = dk_vec_push_zero(&ns->v);
        e->name = name;
    }
    e->val = val;
    if (touched) e->touched = true;
    return e;
}

/* ---- value constructors ----------------------------------------------------------------------------------------- */
static DkArgValue v_none(void) {
    DkArgValue v = {0};
    return v;
}
static DkArgValue v_str(DkStr s) {
    DkArgValue v = {0};
    v.kind = DK_V_STR;
    v.s = s;
    return v;
}
static DkArgValue v_int(i64 i) {
    DkArgValue v = {0};
    v.kind = DK_V_INT;
    v.i = i;
    return v;
}
static DkArgValue v_float(double f) {
    DkArgValue v = {0};
    v.kind = DK_V_FLOAT;
    v.f = f;
    return v;
}
static DkArgValue v_bool(bool b) {
    DkArgValue v = {0};
    v.kind = DK_V_BOOL;
    v.i = b ? 1 : 0;
    return v;
}
static DkArgValue v_list(DkArena *a, const DkArgValue *items, size_t n) {
    DkArgValue v = {0};
    v.kind = DK_V_LIST;
    DkArgValue *copy = (DkArgValue *)dk_alloc(a, (n + 1) * sizeof(DkArgValue));
    if (n) memcpy(copy, items, n * sizeof(DkArgValue));
    v.items = copy;
    v.n = n;
    return v;
}
static DkArgValue v_default(DkArena *a, DkArgDefault d) {
    switch (d.kind) {
    case DK_DK_STR: return v_str(dk_str(d.s));
    case DK_DK_INT: return v_int(d.i);
    case DK_DK_FLOAT: return v_float(d.f);
    case DK_DK_BOOL: return v_bool(d.i != 0);
    default: DK_UNUSED(a); return v_none();
    }
}

/* ---- building ---------------------------------------------------------------------------------------------------- */
static const char *dup_cz(DkArena *a, const char *s) { return s ? dk_strdup(a, s) : NULL; }

static const char **dup_czlist(DkArena *a, const char *const *list, size_t *count) {
    size_t n = 0;
    if (list)
        while (list[n]) n++;
    const char **out = (const char **)dk_alloc(a, (n + 1) * sizeof(char *));
    for (size_t i = 0; i < n; i++) out[i] = dk_strdup(a, list[i]);
    if (count) *count = n;
    return out;
}

static DkArgDefault dup_default(DkArena *a, DkArgDefault d) {
    if (d.kind == DK_DK_STR) d.s = dk_strdup(a, d.s ? d.s : "");
    return d;
}

DkArgParser *dk_args_parser(DkArena *arena, const DkArgParserDesc *d) {
    if (!arena) arena = dk_arena();
    static const DkArgParserDesc none = {0};
    if (!d) d = &none;
    DkArgParser *p = DK_NEW(arena, DkArgParser);
    p->a = arena;
    p->prog = dk_strdup(arena, d->prog ? d->prog : dk_tool_name());
    p->usage = dup_cz(arena, d->usage);
    p->description = dup_cz(arena, d->description);
    p->epilog = dup_cz(arena, d->epilog);
    p->formatter = d->formatter;
    p->allow_abbrev = !d->no_abbrev;
    p->positionals = DK_NEW(arena, DkArgSection);
    p->positionals->parser = p;
    p->positionals->title = "positional arguments";
    p->optionals = DK_NEW(arena, DkArgSection);
    p->optionals->parser = p;
    p->optionals->title = "options";
    dk_vec_push(&p->sections, p->positionals);
    dk_vec_push(&p->sections, p->optionals);
    if (!d->no_help) {
        DkArgDesc h = {0};
        h.names = "-h --help";
        h.action = DK_ARG_HELP;
        h.help = "show this help message and exit";
        dk_arg(p, &h);
    }
    return p;
}

static bool is_negative_number_like(DkStr s) {
    /* re.compile(r'-\.?\d').match(s) */
    if (s.n < 2 || s.p[0] != '-') return false;
    size_t i = 1;
    if (s.p[i] == '.') i++;
    if (i >= s.n) return false;
    if (s.p[i] >= '0' && s.p[i] <= '9') return true;
    if ((u8)s.p[i] >= 0x80) {
        const char *q = s.p + i;
        u32 c = dk_u8_next(&q, s.p + s.n);
        char buf[4];
        size_t n = dk_u8_put(buf, c);
        return dk_str_isdecimal(dk_strn(buf, n));
    }
    return false;
}

static void register_option(DkArgParser *p, const char *opt, DkArgAction *act) {
    for (size_t i = 0; i < p->option_actions.n; i++)
        if (strcmp(p->option_actions.v[i].str, opt) == 0)
            dk_panic(__FILE__, __LINE__, "argparse: conflicting option string: %s", opt);
    OptionEntry e = {opt, act};
    dk_vec_push(&p->option_actions, e);
    if (is_negative_number_like(dk_str(opt))) p->has_negative_number_optionals = true;
}

static const char *type_name_of(const DkArgDesc *d) {
    switch (d->type) {
    case DK_T_INT: return "int";
    case DK_T_INT0: return "<lambda>";
    case DK_T_FLOAT: return "float";
    case DK_T_STR: return "str";
    default: return d->type_name ? d->type_name : "type";
    }
}

/* add_argument: the container is the section the action is listed in (and the mutex group, if any). */
static DkArgAction *add_action(DkArgParser *p, DkArgSection *section, DkArgMutex *mutex, const DkArgDesc *d) {
    DkArena *a = p->a;
    DkArgAction *act = DK_NEW(a, DkArgAction);
    act->parser = p;
    act->kind = (int)d->action;
    DK_ASSERT(d->names && d->names[0]);

    /* names: one positional, or option strings */
    DkStrVec names = dk_str_split(dk_str(d->names), DK_S(""), -1);
    DK_ASSERT(names.n > 0);
    bool positional = names.v[0].p[0] != '-';
    if (positional && names.n > 1) dk_panic(__FILE__, __LINE__, "argparse: several names for a positional: %s", d->names);
    if (!positional) {
        bool boolopt = d->action == DK_ARG_BOOLEAN_OPTIONAL;
        act->opts = (const char **)dk_alloc(a, (names.n * 2 + 1) * sizeof(char *));
        for (size_t i = 0; i < names.n; i++) {
            DkStr n = names.v[i];
            if (n.p[0] != '-') dk_panic(__FILE__, __LINE__, "argparse: invalid option string '%.*s'", DK_SF(n));
            act->opts[act->nopts++] = dk_cz(a, n);
            if (boolopt && n.n > 1 && n.p[1] == '-') {
                if (n.n > 5 && memcmp(n.p, "--no-", 5) == 0)
                    dk_panic(__FILE__, __LINE__, "argparse: invalid option name '%.*s' for BooleanOptionalAction", DK_SF(n));
                act->opts[act->nopts++] = dk_sprintf(a, "--no-%.*s", (int)(n.n - 2), n.p + 2);
            }
        }
    }

    /* dest */
    bool flag_action = false;
    switch (d->action) {
    case DK_ARG_STORE_CONST:
    case DK_ARG_STORE_TRUE:
    case DK_ARG_STORE_FALSE:
    case DK_ARG_APPEND_CONST:
    case DK_ARG_COUNT:
    case DK_ARG_HELP:
    case DK_ARG_VERSION:
    case DK_ARG_BOOLEAN_OPTIONAL: flag_action = true; break;
    default: break;
    }
    if (d->dest) act->dest = dk_strdup(a, d->dest);
    else if (d->action == DK_ARG_HELP || d->action == DK_ARG_VERSION) act->dest = NULL;
    else if (positional) act->dest = dk_cz(a, names.v[0]);
    else {
        DkStr pick = names.v[0];
        for (size_t i = 0; i < names.n; i++)
            if (names.v[i].n > 1 && names.v[i].p[1] == '-') {
                pick = names.v[i];
                break;
            }
        size_t k = 0;
        while (k < pick.n && pick.p[k] == '-') k++;
        if (k == pick.n) dk_panic(__FILE__, __LINE__, "argparse: dest= is required for options like '%.*s'", DK_SF(pick));
        char *dest = dk_cz(a, dk_strn(pick.p + k, pick.n - k));
        for (char *c = dest; *c; c++)
            if (*c == '-') *c = '_';
        act->dest = dest;
    }
    dk_vec_free(&names);

    /* nargs */
    if (flag_action) {
        if (d->nargs != DK_NARGS_NONE) dk_panic(__FILE__, __LINE__, "argparse: nargs given for a flag action (%s)", d->names);
        act->nargs = 0;
    } else {
        act->nargs = d->nargs == DK_NARGS_NONE ? ARGN_NONE : d->nargs;
    }
    if (positional && flag_action) dk_panic(__FILE__, __LINE__, "argparse: action not valid for positionals (%s)", d->names);

    act->type = d->type;
    act->conv = d->conv;
    act->conv_ctx = d->conv_ctx;
    act->type_name = d->type == DK_T_STR ? dup_cz(a, d->type_name) : dup_cz(a, type_name_of(d));
    if (d->type == DK_T_CUSTOM && !d->conv) dk_panic(__FILE__, __LINE__, "argparse: DK_T_CUSTOM without conv");
    act->metavar = dup_cz(a, d->metavar);
    if (d->metavars) act->metavars = dup_czlist(a, d->metavars, &act->nmetavars);
    if (d->choices) {
        if (d->type != DK_T_STR && d->type != DK_T_IDENT)
            dk_panic(__FILE__, __LINE__, "argparse: choices on a typed argument (%s)", d->names);
        act->choices = dup_czlist(a, d->choices, &act->nchoices);
    }
    if (act->metavars) {
        size_t want;
        int na = act->nargs;
        if (na == ARGN_NONE || na == DK_NARGS_OPT || na == DK_NARGS_PARSER) want = 1;
        else if (na == DK_NARGS_PLUS) want = 2;
        else if (na == DK_NARGS_STAR) want = act->nmetavars == 2 ? 2 : 1;
        else if (na >= 0) want = (size_t)na;
        else want = act->nmetavars;
        if (act->nmetavars != want) dk_panic(__FILE__, __LINE__, "argparse: length of metavar tuple does not match nargs (%s)", d->names);
    }

    /* default and const */
    act->dflt = dup_default(a, d->dflt);
    if (act->dflt.kind == DK_DK_UNSET) {
        switch (d->action) {
        case DK_ARG_STORE_TRUE: act->dflt = (DkArgDefault){DK_DK_BOOL, NULL, 0, 0.0}; break;
        case DK_ARG_STORE_FALSE: act->dflt = (DkArgDefault){DK_DK_BOOL, NULL, 1, 0.0}; break;
        case DK_ARG_HELP:
        case DK_ARG_VERSION: act->dflt = DK_DEF_SUPPRESS; break;
        default: act->dflt = DK_DEF_NONE; break;
        }
    }
    if (d->dflt_list) {
        act->has_dflt_list = true;
        act->dflt_list = dup_czlist(a, d->dflt_list, &act->ndflt_list);
    }
    act->cnst = dup_default(a, d->cnst);
    if (d->action == DK_ARG_STORE_TRUE) act->cnst = (DkArgDefault){DK_DK_BOOL, NULL, 1, 0.0};
    if (d->action == DK_ARG_STORE_FALSE) act->cnst = (DkArgDefault){DK_DK_BOOL, NULL, 0, 0.0};
    if (act->cnst.kind != DK_DK_UNSET && act->cnst.kind != DK_DK_NONE && d->action != DK_ARG_STORE_CONST &&
        d->action != DK_ARG_APPEND_CONST && d->action != DK_ARG_STORE_TRUE && d->action != DK_ARG_STORE_FALSE &&
        act->nargs != DK_NARGS_OPT)
        dk_panic(__FILE__, __LINE__, "argparse: nargs must be '?' to supply const (%s)", d->names);

    /* required */
    if (positional) {
        if (d->required) dk_panic(__FILE__, __LINE__, "argparse: 'required' is an invalid argument for positionals (%s)", d->names);
        int na = act->nargs;
        act->required = !(na == DK_NARGS_OPT || na == DK_NARGS_STAR || na == DK_NARGS_REMAINDER || na == DK_NARGS_SUPPRESS);
    } else act->required = d->required;

    if (d->help == DK_ARG_SUPPRESS) act->help_suppress = true;
    else act->help = dup_cz(a, d->help);
    if (d->action == DK_ARG_VERSION) {
        act->version = dup_cz(a, d->version);
        if (!act->help) act->help = "show program's version number and exit";
    }

    if (mutex && act->required) dk_panic(__FILE__, __LINE__, "argparse: mutually exclusive arguments must be optional (%s)", d->names);

    /* _add_action */
    act->index = p->actions.n;
    dk_vec_push(&p->actions, act);
    for (size_t i = 0; i < act->nopts; i++) register_option(p, act->opts[i], act);
    DkArgSection *sec = section ? section : (act->nopts ? p->optionals : p->positionals);
    act->section = sec;
    dk_vec_push(&sec->actions, act);
    if (mutex) dk_vec_push(&mutex->actions, act);
    return act;
}

DkArgAction *dk_arg(DkArgParser *p, const DkArgDesc *d) { return add_action(p, NULL, NULL, d); }

DkArgSection *dk_args_group(DkArgParser *p, const char *title, const char *description) {
    DkArgSection *s = DK_NEW(p->a, DkArgSection);
    s->parser = p;
    s->title = dup_cz(p->a, title);
    s->description = dup_cz(p->a, description);
    dk_vec_push(&p->sections, s);
    return s;
}

DkArgAction *dk_arg_in(DkArgSection *g, const DkArgDesc *d) { return add_action(g->parser, g, NULL, d); }

DkArgMutex *dk_args_mutex(DkArgParser *p, bool required) {
    DkArgMutex *m = DK_NEW(p->a, DkArgMutex);
    m->parser = p;
    m->required = required;
    dk_vec_push(&p->mutexes, m);
    return m;
}

DkArgMutex *dk_args_mutex_in(DkArgSection *g, bool required) {
    DkArgMutex *m = dk_args_mutex(g->parser, required);
    m->container = g;
    return m;
}

DkArgAction *dk_arg_mutex(DkArgMutex *g, const DkArgDesc *d) { return add_action(g->parser, g->container, g, d); }

DkArgSubparsers *dk_args_subparsers(DkArgParser *p, const DkArgSubparsersDesc *d) {
    DK_ASSERT(!p->subparsers);
    DkArena *a = p->a;
    DkArgSubparsers *sp = DK_NEW(a, DkArgSubparsers);
    sp->owner = p;
    DkArgSection *sec = p->positionals;
    if (d && (d->title || d->description)) sec = dk_args_group(p, d->title ? d->title : "subcommands", d->description);
    sp->prog_prefix = argp_subparsers_prog(p);
    DkArgAction *act = DK_NEW(a, DkArgAction);
    act->parser = p;
    act->kind = ARGK_SUBPARSERS;
    act->dest = d ? dup_cz(a, d->dest) : NULL;
    act->nargs = DK_NARGS_PARSER;
    act->dflt = d && d->dest ? DK_DEF_NONE : DK_DEF_SUPPRESS;
    act->required = d && d->required;
    act->metavar = d ? dup_cz(a, d->metavar) : NULL;
    if (d && d->help == DK_ARG_SUPPRESS) act->help_suppress = true;
    else act->help = d ? dup_cz(a, d->help) : NULL;
    act->sub = sp;
    act->index = p->actions.n;
    dk_vec_push(&p->actions, act);
    act->section = sec;
    dk_vec_push(&sec->actions, act);
    sp->action = act;
    p->subparsers = sp;
    return sp;
}

DkArgParser *dk_args_subparser(DkArgSubparsers *s, const char *name, const DkArgParserDesc *d) {
    DkArena *a = s->owner->a;
    DkArgParserDesc copy = {0};
    if (d) copy = *d;
    if (!copy.prog) copy.prog = dk_sprintf(a, "%s %s", s->prog_prefix, name);
    for (size_t i = 0; i < s->names.n; i++)
        if (strcmp(s->names.v[i], name) == 0) dk_panic(__FILE__, __LINE__, "argparse: conflicting subparser: %s", name);
    if (copy.help) {
        DkArgAction *pa = DK_NEW(a, DkArgAction);
        pa->parser = s->owner;
        pa->kind = ARGK_PSEUDO;
        pa->dest = dk_strdup(a, name);
        pa->nargs = ARGN_NONE;
        pa->help = dk_strdup(a, copy.help);
        if (copy.aliases && copy.aliases[0]) {
            DkBuf b;
            dk_buf_init(&b, a);
            dk_buf_printf(&b, "%s (", name);
            for (size_t i = 0; copy.aliases[i]; i++) {
                if (i) dk_buf_putz(&b, ", ");
                dk_buf_putz(&b, copy.aliases[i]);
            }
            dk_buf_putc(&b, ')');
            pa->metavar = dk_buf_cz(&b);
        } else pa->metavar = pa->dest;
        dk_vec_push(&s->pseudo, pa);
    }
    copy.help = NULL;
    DkArgParser *sub = dk_args_parser(a, &copy);
    dk_vec_push(&s->names, dk_strdup(a, name));
    dk_vec_push(&s->parsers, sub);
    if (d && d->aliases)
        for (size_t i = 0; d->aliases[i]; i++) {
            dk_vec_push(&s->names, dk_strdup(a, d->aliases[i]));
            dk_vec_push(&s->parsers, sub);
        }
    return sub;
}

DkArgParser *dk_args_subparser_get(DkArgSubparsers *s, const char *name) {
    for (size_t i = 0; i < s->names.n; i++)
        if (strcmp(s->names.v[i], name) == 0) return s->parsers.v[i];
    return NULL;
}

const char *dk_args_prog(const DkArgParser *p) { return p->prog; }

/* ---- running a parse (errors unwind with longjmp to the entry point) -------------------------------------------- */
typedef struct {
    jmp_buf jb;
    DkArgsExit ex;
} Run;

static DK_NORETURN void run_exit(Run *r, int code, DkStr out, DkStr err) {
    r->ex.code = code;
    r->ex.out = out;
    r->ex.err = err;
    longjmp(r->jb, 1);
}

DkStr dk_args_error_text(DkArgParser *p, DkStr message) {
    DkBuf b;
    dk_buf_init(&b, p->a);
    dk_buf_put(&b, argp_format_usage(p));
    dk_buf_printf(&b, "%s: error: %.*s\n", p->prog, DK_SF(message));
    return dk_buf_str(&b);
}

/* ArgumentParser.error(message) */
static DK_NORETURN void parser_error(Run *r, DkArgParser *p, DkStr message) {
    run_exit(r, 2, dk_str(""), dk_args_error_text(p, message));
}

/* raise ArgumentError(action, message), as handled by the parser that parses */
static DK_NORETURN void arg_error(Run *r, DkArgParser *p, const DkArgAction *act, DkStr message) {
    const char *name = argp_action_name(p->a, act);
    if (!name) parser_error(r, p, message);
    parser_error(r, p, dk_str(dk_sprintf(p->a, "argument %s: %.*s", name, DK_SF(message))));
}

static DK_NORETURN void arg_errorf(Run *r, DkArgParser *p, const DkArgAction *act, DK_PRINTF_FMT const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *msg = dk_vsprintf(p->a, fmt, ap);
    va_end(ap);
    arg_error(r, p, act, dk_str(msg));
}

DK_NORETURN void dk_args_error(DkArgParser *p, DK_PRINTF_FMT const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *msg = dk_vsprintf(p->a, fmt, ap);
    va_end(ap);
    DkStr text = dk_args_error_text(p, dk_str(msg));
    fwrite(text.p, 1, text.n, stderr);
    dk_exit(2);
}

/* ---- the matcher for the nargs patterns --------------------------------------------------------------------------- */
enum { M_A = 1, M_O = 2, M_D = 4 };
typedef struct {
    u8 mask;
    int min;
    int max; /* -1: unbounded */
} Item;
typedef DK_VEC(Item) ItemVec;

static void push_item(ItemVec *v, u8 mask, int min, int max) {
    Item it = {mask, min, max};
    dk_vec_push(v, it);
}

/* _get_nargs_pattern(action) as items: each group of an action is a contiguous run of items. */
static void action_items(ItemVec *v, const DkArgAction *act) {
    int nargs = act->nargs;
    bool option = act->nopts != 0;
    if (nargs == ARGN_NONE) {
        if (option) push_item(v, M_A, 1, 1);
        else {
            push_item(v, M_D, 0, -1);
            push_item(v, M_A, 1, 1);
            push_item(v, M_D, 0, -1);
        }
    } else if (nargs == DK_NARGS_OPT) {
        if (option) push_item(v, M_A, 0, 1);
        else {
            push_item(v, M_D, 0, -1);
            push_item(v, M_A, 0, 1);
            push_item(v, M_D, 0, -1);
        }
    } else if (nargs == DK_NARGS_STAR) {
        if (option) push_item(v, M_A, 0, -1);
        else {
            push_item(v, M_D, 0, -1);
            push_item(v, M_A | M_D, 0, -1);
        }
    } else if (nargs == DK_NARGS_PLUS) {
        if (option) push_item(v, M_A, 1, -1);
        else {
            push_item(v, M_D, 0, -1);
            push_item(v, M_A, 1, 1);
            push_item(v, M_A | M_D, 0, -1);
        }
    } else if (nargs == DK_NARGS_REMAINDER) {
        if (option) push_item(v, M_A | M_O, 0, -1);
        else push_item(v, M_A | M_O | M_D, 0, -1);
    } else if (nargs == DK_NARGS_PARSER) {
        if (option) {
            push_item(v, M_A, 1, 1);
            push_item(v, M_A | M_O, 0, -1);
        } else {
            push_item(v, M_D, 0, -1);
            push_item(v, M_A, 1, 1);
            push_item(v, M_D | M_A | M_O, 0, -1);
        }
    } else if (nargs == DK_NARGS_SUPPRESS) {
        if (!option) push_item(v, M_D, 0, -1);
    } else { /* a number: ([AO]{N}) or ((?:-*A){N}-*) */
        if (option) push_item(v, M_A | M_O, nargs, nargs);
        else {
            for (int i = 0; i < nargs; i++) {
                push_item(v, M_D, 0, -1);
                push_item(v, M_A, 1, 1);
            }
            push_item(v, M_D, 0, -1);
        }
    }
}

static u8 char_mask(char c) { return c == 'A' ? M_A : c == 'O' ? M_O : M_D; }

/* re.match semantics: greedy quantifiers, backtracking, anchored at the start, not at the end. */
static bool match_items(const Item *it, size_t nit, size_t k, const char *s, size_t n, size_t pos, size_t *counts,
                        size_t *end) {
    if (k == nit) {
        *end = pos;
        return true;
    }
    size_t run = 0;
    size_t limit = it[k].max < 0 ? n - pos : (size_t)it[k].max;
    while (run < limit && pos + run < n && (char_mask(s[pos + run]) & it[k].mask)) run++;
    if ((int)run < it[k].min) return false;
    for (size_t c = run;; c--) {
        counts[k] = c;
        if (match_items(it, nit, k + 1, s, n, pos + c, counts, end)) return true;
        if (c == (size_t)it[k].min) break;
    }
    return false;
}

/* _match_argument: the number of strings the option's arguments take, or an error. */
static size_t match_argument(Run *r, DkArgParser *p, const DkArgAction *act, const char *pattern, size_t plen) {
    ItemVec items = {0};
    action_items(&items, act);
    size_t *counts = (size_t *)dk_xcalloc(items.n + 1, sizeof(size_t));
    size_t end = 0;
    bool ok = match_items(items.v, items.n, 0, pattern, plen, 0, counts, &end);
    size_t total = 0;
    if (ok)
        for (size_t i = 0; i < items.n; i++) total += counts[i];
    dk_vec_free(&items);
    dk_xfree(counts);
    if (ok) return total;
    if (act->nargs == ARGN_NONE) arg_errorf(r, p, act, "expected one argument");
    if (act->nargs == DK_NARGS_OPT) arg_errorf(r, p, act, "expected at most one argument");
    if (act->nargs == DK_NARGS_PLUS) arg_errorf(r, p, act, "expected at least one argument");
    arg_errorf(r, p, act, act->nargs == 1 ? "expected %d argument" : "expected %d arguments", act->nargs);
}

/* ---- types, choices and values ----------------------------------------------------------------------------------- */
static bool parse_type(Run *r, DkArgParser *p, const DkArgAction *act, DkStr s, DkArgValue *out) {
    DkArena *a = p->a;
    DkStr msg = {NULL, 0};
    switch (act->type) {
    case DK_T_STR:
    case DK_T_IDENT: *out = v_str(dk_str_dup(a, s)); return true;
    case DK_T_INT:
    case DK_T_INT0: {
        i64 v;
        bool overflow = false;
        if (!dk_parse_int(s, act->type == DK_T_INT0 ? 0 : 10, &v, &overflow)) return false;
        *out = v_int(v);
        return true;
    }
    case DK_T_FLOAT: {
        double d;
        if (!dk_parse_float(s, &d)) return false;
        *out = v_float(d);
        return true;
    }
    default: {
        if (act->conv(act->conv_ctx, a, s, out, &msg)) return true;
        if (msg.p) arg_error(r, p, act, dk_str_dup(a, msg)); /* ArgumentTypeError */
        return false;
    }
    }
}

/* _get_value: type_func(arg_string), turning a ValueError into "invalid <type> value: <repr>". */
static DkArgValue get_value(Run *r, DkArgParser *p, const DkArgAction *act, DkStr s) {
    DkArgValue v;
    if (parse_type(r, p, act, s, &v)) return v;
    DkBuf b;
    dk_buf_init(&b, p->a);
    const char *tn = act->type_name ? act->type_name : (act->type == DK_T_INT ? "int" : act->type == DK_T_FLOAT ? "float" : "type");
    dk_buf_printf(&b, "invalid %s value: ", tn);
    argp_repr(&b, s);
    arg_error(r, p, act, dk_buf_str(&b));
}

/* _check_value: value not in choices */
static void check_value(Run *r, DkArgParser *p, const DkArgAction *act, const DkArgValue *v) {
    const char *const *names;
    size_t n;
    if (act->kind == ARGK_SUBPARSERS) {
        names = act->sub->names.v;
        n = act->sub->names.n;
    } else if (act->choices) {
        names = act->choices;
        n = act->nchoices;
    } else return;
    DK_ASSERT(v->kind == DK_V_STR);
    for (size_t i = 0; i < n; i++)
        if (dk_str_eqz(v->s, names[i])) return;
    DkBuf b;
    dk_buf_init(&b, p->a);
    dk_buf_putz(&b, "invalid choice: ");
    argp_repr(&b, v->s);
    dk_buf_putz(&b, " (choose from ");
    for (size_t i = 0; i < n; i++) {
        if (i) dk_buf_putz(&b, ", ");
        argp_repr(&b, dk_str(names[i]));
    }
    dk_buf_putc(&b, ')');
    arg_error(r, p, act, dk_buf_str(&b));
}

/* ---- the parse state --------------------------------------------------------------------------------------------- */
typedef struct {
    DkArgAction *action;
    DkStr opt;
    int sep;        /* 0: None, 1: '', 2: '=' */
    bool has_explicit;
    DkStr explicit_arg;
} OptTuple;
typedef struct {
    OptTuple *v;
    size_t n;
} OptList;

typedef struct {
    Run *run;
    DkArgParser *p;
    DkArgs *ns;
    DkStr *args;
    size_t nargs;
    char *pattern;
    OptList *opts;           /* option_string_indices: n == 0 where the argument is not an option */
    ActionVec positionals;
    DkStrVec extras;
    bool *seen;
    bool *seen_nd;
    DK_VEC(size_t) *conflicts; /* action_conflicts: indices into p->actions, per action */
} State;

static DkArgAction *find_option(const DkArgParser *p, DkStr s) {
    for (size_t i = 0; i < p->option_actions.n; i++)
        if (dk_str_eqz(s, p->option_actions.v[i].str)) return p->option_actions.v[i].action;
    return NULL;
}

/* the byte length of the first count code points of s */
static size_t cp_bytes(DkStr s, size_t count) {
    const char *q = s.p, *end = s.p + s.n;
    while (count-- && q < end) (void)dk_u8_next(&q, end);
    return (size_t)(q - s.p);
}

/* _get_option_tuples */
static void get_option_tuples(State *st, DkStr opt, OptTuple **out, size_t *count) {
    DkArgParser *p = st->p;
    OptTuple *res = (OptTuple *)dk_alloc(p->a, (p->option_actions.n + 1) * sizeof(OptTuple));
    size_t n = 0;
    if (opt.p[0] == '-' && opt.n > 1 && opt.p[1] == '-') {
        if (p->allow_abbrev) {
            i64 eq = dk_str_findc(opt, '=');
            DkStr prefix = eq >= 0 ? dk_strn(opt.p, (size_t)eq) : opt;
            for (size_t i = 0; i < p->option_actions.n; i++) {
                if (!dk_str_startswith(dk_str(p->option_actions.v[i].str), prefix)) continue;
                OptTuple t = {0};
                t.action = p->option_actions.v[i].action;
                t.opt = dk_str(p->option_actions.v[i].str);
                if (eq >= 0) {
                    t.sep = 2;
                    t.has_explicit = true;
                    t.explicit_arg = dk_strn(opt.p + eq + 1, opt.n - (size_t)eq - 1);
                }
                res[n++] = t;
            }
        }
    } else if (opt.p[0] == '-' && opt.n > 1 && opt.p[1] != '-') {
        i64 eq = dk_str_findc(opt, '=');
        DkStr prefix = eq >= 0 ? dk_strn(opt.p, (size_t)eq) : opt;
        size_t two = cp_bytes(opt, 2);
        DkStr short_prefix = dk_strn(opt.p, two);
        DkStr short_arg = dk_strn(opt.p + two, opt.n - two);
        for (size_t i = 0; i < p->option_actions.n; i++) {
            DkStr os = dk_str(p->option_actions.v[i].str);
            OptTuple t = {0};
            t.action = p->option_actions.v[i].action;
            t.opt = os;
            if (dk_str_eq(os, short_prefix)) {
                t.sep = 1;
                t.has_explicit = true;
                t.explicit_arg = short_arg;
                res[n++] = t;
            } else if (p->allow_abbrev && dk_str_startswith(os, prefix)) {
                if (eq >= 0) {
                    t.sep = 2;
                    t.has_explicit = true;
                    t.explicit_arg = dk_strn(opt.p + eq + 1, opt.n - (size_t)eq - 1);
                }
                res[n++] = t;
            }
        }
    }
    *out = res;
    *count = n;
}

/* _parse_optional: false when the string is a positional-like argument ('A'). */
static bool parse_optional(State *st, DkStr arg, OptList *out) {
    DkArgParser *p = st->p;
    out->v = NULL;
    out->n = 0;
    if (!arg.n) return false;
    if (arg.p[0] != '-') return false;
    DkArgAction *act = find_option(p, arg);
    if (act) {
        OptTuple *t = DK_NEW(p->a, OptTuple);
        t->action = act;
        t->opt = arg;
        out->v = t;
        out->n = 1;
        return true;
    }
    if (arg.n == 1) return false;
    i64 eq = dk_str_findc(arg, '=');
    if (eq >= 0) {
        DkStr optstr = dk_strn(arg.p, (size_t)eq);
        DkArgAction *a2 = find_option(p, optstr);
        if (a2) {
            OptTuple *t = DK_NEW(p->a, OptTuple);
            t->action = a2;
            t->opt = optstr;
            t->sep = 2;
            t->has_explicit = true;
            t->explicit_arg = dk_strn(arg.p + eq + 1, arg.n - (size_t)eq - 1);
            out->v = t;
            out->n = 1;
            return true;
        }
    }
    OptTuple *tuples;
    size_t count;
    get_option_tuples(st, arg, &tuples, &count);
    if (count) {
        out->v = tuples;
        out->n = count;
        return true;
    }
    if (is_negative_number_like(arg) && !p->has_negative_number_optionals) return false;
    if (dk_str_findc(arg, ' ') >= 0) return false;
    OptTuple *t = DK_NEW(p->a, OptTuple);
    t->action = NULL;
    t->opt = arg;
    out->v = t;
    out->n = 1;
    return true;
}

/* _get_values */
static DkArgValue get_values(State *st, DkArgAction *act, const DkStr *strs, size_t n, bool *suppress) {
    Run *r = st->run;
    DkArgParser *p = st->p;
    DkArena *a = p->a;
    *suppress = false;
    int nargs = act->nargs;
    if (n == 0 && nargs == DK_NARGS_OPT) {
        DkArgDefault src = act->nopts ? act->cnst : act->dflt;
        DkArgValue v = v_default(a, src);
        if (v.kind == DK_V_STR) v = get_value(r, p, act, v.s);
        return v;
    }
    if (n == 0 && nargs == DK_NARGS_STAR && !act->nopts) {
        if (act->dflt.kind != DK_DK_NONE && act->dflt.kind != DK_DK_UNSET) return v_default(a, act->dflt);
        if (act->has_dflt_list) {
            DkArgValue *items = (DkArgValue *)dk_alloc(a, (act->ndflt_list + 1) * sizeof(DkArgValue));
            for (size_t i = 0; i < act->ndflt_list; i++) items[i] = v_str(dk_str(act->dflt_list[i]));
            return v_list(a, items, act->ndflt_list);
        }
        return v_list(a, NULL, 0);
    }
    if (n == 1 && (nargs == ARGN_NONE || nargs == DK_NARGS_OPT)) {
        DkArgValue v = get_value(r, p, act, strs[0]);
        check_value(r, p, act, &v);
        return v;
    }
    if (nargs == DK_NARGS_SUPPRESS) {
        *suppress = true;
        return v_none();
    }
    DkArgValue *items = (DkArgValue *)dk_alloc(a, (n + 1) * sizeof(DkArgValue));
    for (size_t i = 0; i < n; i++) items[i] = get_value(r, p, act, strs[i]);
    if (nargs == DK_NARGS_REMAINDER) return v_list(a, items, n);
    if (nargs == DK_NARGS_PARSER) {
        check_value(r, p, act, &items[0]);
        return v_list(a, items, n);
    }
    for (size_t i = 0; i < n; i++) check_value(r, p, act, &items[i]);
    return v_list(a, items, n);
}

static DkArgValue list_with(DkArena *a, const DkArgValue *old, const DkArgValue *add, size_t nadd) {
    size_t n0 = old && old->kind == DK_V_LIST ? old->n : 0;
    DkArgValue *items = (DkArgValue *)dk_alloc(a, (n0 + nadd + 1) * sizeof(DkArgValue));
    if (n0) memcpy(items, old->items, n0 * sizeof(DkArgValue));
    for (size_t i = 0; i < nadd; i++) items[n0 + i] = add[i];
    return v_list(a, items, n0 + nadd);
}

static void parse_known(State *st, DkArgParser *p, const DkStr *args, size_t n, DkArgs *ns, DkStrVec *extras_out);

/* ArgumentParser.parse_known_args on a fresh namespace for a sub-parser, merged into ns (_SubParsersAction.__call__) */
static void call_subparsers(State *st, DkArgAction *act, const DkArgValue *values) {
    DkArgParser *p = st->p;
    DkArena *a = p->a;
    DK_ASSERT(values->kind == DK_V_LIST && values->n >= 1);
    DkStr name = values->items[0].s;
    if (act->dest) ns_set(st->ns, act->dest, v_str(name), true);
    DkArgParser *sub = NULL;
    for (size_t i = 0; i < act->sub->names.n; i++)
        if (dk_str_eqz(name, act->sub->names.v[i])) sub = act->sub->parsers.v[i];
    DK_ASSERT(sub);
    DkStr *rest = (DkStr *)dk_alloc(a, values->n * sizeof(DkStr));
    for (size_t i = 1; i < values->n; i++) rest[i - 1] = values->items[i].s;
    DkArgs *subns = ns_new(a);
    DkStrVec sub_extras = {0};
    parse_known(st, sub, rest, values->n - 1, subns, &sub_extras);
    for (size_t i = 0; i < subns->v.n; i++) {
        NsEntry *e = &subns->v.v[i];
        NsEntry *d = ns_set(st->ns, e->name, e->val, e->touched);
        d->given = e->given;
        d->owner = e->owner;
    }
    for (size_t i = 0; i < sub_extras.n; i++) dk_vec_push(&st->ns->unrec, sub_extras.v[i]);
    dk_vec_free(&sub_extras);
}

/* Action.__call__ */
static void run_action(State *st, DkArgAction *act, const DkArgValue *values, DkStr option_string, bool has_option) {
    DkArgParser *p = st->p;
    DkArena *a = p->a;
    DkArgs *ns = st->ns;
    switch (act->kind) {
    case DK_ARG_STORE:
        if (act->dest) ns_set(ns, act->dest, *values, true);
        break;
    case DK_ARG_STORE_CONST:
    case DK_ARG_STORE_TRUE:
    case DK_ARG_STORE_FALSE:
        ns_set(ns, act->dest, v_default(a, act->cnst), true);
        break;
    case DK_ARG_APPEND: {
        NsEntry *e = ns_find(ns, act->dest);
        ns_set(ns, act->dest, list_with(a, e ? &e->val : NULL, values, 1), true);
        break;
    }
    case DK_ARG_APPEND_CONST: {
        NsEntry *e = ns_find(ns, act->dest);
        DkArgValue c = v_default(a, act->cnst);
        ns_set(ns, act->dest, list_with(a, e ? &e->val : NULL, &c, 1), true);
        break;
    }
    case DK_ARG_EXTEND: {
        NsEntry *e = ns_find(ns, act->dest);
        DK_ASSERT(values->kind == DK_V_LIST);
        ns_set(ns, act->dest, list_with(a, e ? &e->val : NULL, values->items, values->n), true);
        break;
    }
    case DK_ARG_COUNT: {
        NsEntry *e = ns_find(ns, act->dest);
        i64 c = e && e->val.kind == DK_V_INT ? e->val.i : 0;
        ns_set(ns, act->dest, v_int(c + 1), true);
        break;
    }
    case DK_ARG_HELP: run_exit(st->run, 0, argp_format_help(p), dk_str("")); break;
    case DK_ARG_VERSION: {
        const char *v = act->version ? act->version : "";
        run_exit(st->run, 0, argp_format_version(p, v), dk_str(""));
        break;
    }
    case DK_ARG_BOOLEAN_OPTIONAL:
        if (has_option) {
            for (size_t i = 0; i < act->nopts; i++)
                if (dk_str_eqz(option_string, act->opts[i])) {
                    bool no = dk_str_startswith(option_string, DK_S("--no-"));
                    ns_set(ns, act->dest, v_bool(!no), true);
                }
        }
        break;
    case ARGK_SUBPARSERS: call_subparsers(st, act, values); break;
    default: DK_ASSERT(false);
    }
}

/* take_action(action, argument_strings, option_string) */
static void take_action(State *st, DkArgAction *act, const DkStr *strs, size_t n, DkStr option_string, bool has_option) {
    DkArgParser *p = st->p;
    st->seen[act->index] = true;
    bool suppress;
    DkArgValue values = get_values(st, act, strs, n, &suppress);
    if (act->nopts || n) {
        st->seen_nd[act->index] = true;
        for (size_t i = 0; i < st->conflicts[act->index].n; i++) {
            DkArgAction *c = p->actions.v[st->conflicts[act->index].v[i]];
            if (st->seen_nd[c->index])
                arg_errorf(st->run, p, act, "not allowed with argument %s", argp_action_name(p->a, c));
        }
    }
    if (!suppress) run_action(st, act, &values, option_string, has_option);
    if (act->dest) {
        NsEntry *e = ns_find(st->ns, act->dest);
        if (e && (act->nopts || n)) e->given = true;
    }
}

/* consume_optional(start_index) */
static size_t consume_optional(State *st, size_t start_index) {
    DkArgParser *p = st->p;
    Run *r = st->run;
    OptList list = st->opts[start_index];
    if (list.n > 1) {
        DkBuf b;
        dk_buf_init(&b, p->a);
        for (size_t i = 0; i < list.n; i++) {
            if (i) dk_buf_putz(&b, ", ");
            dk_buf_put(&b, list.v[i].opt);
        }
        DkStr msg = dk_str(dk_sprintf(p->a, "ambiguous option: %.*s could match %.*s", DK_SF(st->args[start_index]),
                                         DK_SF(dk_buf_str(&b))));
        parser_error(r, p, msg);
    }
    OptTuple t = list.v[0];
    DkArgAction *action = t.action;
    DkStr option_string = t.opt;
    int sep = t.sep;
    bool has_explicit = t.has_explicit;
    DkStr explicit_arg = t.explicit_arg;
    typedef struct {
        DkArgAction *action;
        DkStr *args;
        size_t nargs;
        DkStr option_string;
    } Pending;
    DK_VEC(Pending) tuples = {0};
    size_t stop = start_index + 1;
    for (;;) {
        if (!action) {
            dk_vec_push(&st->extras, st->args[start_index]);
            dk_vec_free(&tuples);
            return start_index + 1;
        }
        if (has_explicit) {
            size_t arg_count = match_argument(r, p, action, "A", 1);
            if (arg_count == 0 && option_string.p[1] != '-' && explicit_arg.n != 0) {
                if (sep == 2 || explicit_arg.p[0] == '-') { /* Python: `if sep or ...` ('' is false) */
                    DkBuf b;
                    dk_buf_init(&b, p->a);
                    dk_buf_putz(&b, "ignored explicit argument ");
                    argp_repr(&b, explicit_arg);
                    arg_error(r, p, action, dk_buf_str(&b));
                }
                Pending pd = {action, NULL, 0, option_string};
                dk_vec_push(&tuples, pd);
                size_t first = cp_bytes(explicit_arg, 1);
                DkBuf nb;
                dk_buf_init(&nb, p->a);
                dk_buf_putc(&nb, option_string.p[0]);
                dk_buf_putn(&nb, explicit_arg.p, first);
                DkStr new_opt = dk_buf_str(&nb);
                DkArgAction *next = find_option(p, new_opt);
                if (next) {
                    action = next;
                    option_string = new_opt;
                    explicit_arg = dk_strn(explicit_arg.p + first, explicit_arg.n - first);
                    if (!explicit_arg.n) {
                        sep = 0;
                        has_explicit = false;
                    } else if (explicit_arg.p[0] == '=') {
                        sep = 2;
                        explicit_arg = dk_strn(explicit_arg.p + 1, explicit_arg.n - 1);
                    } else sep = 1;
                } else {
                    DkBuf eb;
                    dk_buf_init(&eb, p->a);
                    dk_buf_putc(&eb, option_string.p[0]);
                    dk_buf_put(&eb, explicit_arg);
                    dk_vec_push(&st->extras, dk_buf_str(&eb));
                    stop = start_index + 1;
                    break;
                }
            } else if (arg_count == 1) {
                stop = start_index + 1;
                DkStr *one = (DkStr *)dk_alloc(p->a, sizeof(DkStr));
                one[0] = explicit_arg;
                Pending pd = {action, one, 1, option_string};
                dk_vec_push(&tuples, pd);
                break;
            } else {
                DkBuf b;
                dk_buf_init(&b, p->a);
                dk_buf_putz(&b, "ignored explicit argument ");
                argp_repr(&b, explicit_arg);
                arg_error(r, p, action, dk_buf_str(&b));
            }
        } else {
            size_t start = start_index + 1;
            size_t arg_count = match_argument(r, p, action, st->pattern + start, st->nargs - start);
            stop = start + arg_count;
            Pending pd = {action, st->args + start, arg_count, option_string};
            dk_vec_push(&tuples, pd);
            break;
        }
    }
    for (size_t i = 0; i < tuples.n; i++)
        take_action(st, tuples.v[i].action, tuples.v[i].args, tuples.v[i].nargs, tuples.v[i].option_string, true);
    dk_vec_free(&tuples);
    return stop;
}

/* _match_arguments_partial: the argument count of each leading positional that matches, or none. */
static size_t match_partial(const ActionVec *acts, const char *pattern, size_t plen, size_t *counts_out) {
    ItemVec items = {0};
    size_t *group_end = (size_t *)dk_xcalloc(acts->n + 1, sizeof(size_t));
    for (size_t i = 0; i < acts->n; i++) {
        action_items(&items, acts->v[i]);
        group_end[i] = items.n;
    }
    size_t *counts = (size_t *)dk_xcalloc(items.n + 1, sizeof(size_t));
    size_t result = 0;
    for (size_t i = acts->n; i > 0; i--) {
        size_t nit = group_end[i - 1];
        size_t end = 0;
        if (match_items(items.v, nit, 0, pattern, plen, 0, counts, &end)) {
            size_t prev = 0;
            for (size_t g = 0; g < i; g++) {
                size_t sum = 0;
                for (size_t k = prev; k < group_end[g]; k++) sum += counts[k];
                counts_out[g] = sum;
                prev = group_end[g];
            }
            result = i;
            if (end < plen && pattern[end] == 'O')
                while (result && !counts_out[result - 1]) result--;
            break;
        }
    }
    dk_vec_free(&items);
    dk_xfree(group_end);
    dk_xfree(counts);
    return result;
}

/* consume_positionals(start_index) */
static size_t consume_positionals(State *st, size_t start_index) {
    ActionVec *pos = &st->positionals;
    if (!pos->n) return start_index;
    size_t *counts = (size_t *)dk_xcalloc(pos->n + 1, sizeof(size_t));
    size_t nc = match_partial(pos, st->pattern + start_index, st->nargs - start_index, counts);
    for (size_t i = 0; i < nc; i++) {
        DkArgAction *act = pos->v[i];
        size_t arg_count = counts[i];
        DkStr *args = st->args + start_index;
        size_t nargs = arg_count;
        DkStr *tmp = NULL;
        bool drop_dashes = false;
        if (act->nargs == DK_NARGS_PARSER) {
            if (start_index < st->nargs && st->pattern[start_index] == '-') drop_dashes = true;
        } else if (act->nargs != DK_NARGS_REMAINDER) {
            for (size_t k = start_index; k < start_index + arg_count; k++)
                if (st->pattern[k] == '-') drop_dashes = true;
        }
        if (drop_dashes) {
            /* args.remove('--'): the first element equal to '--' */
            tmp = (DkStr *)dk_alloc(st->p->a, (arg_count + 1) * sizeof(DkStr));
            size_t o = 0;
            bool removed = false;
            for (size_t k = 0; k < arg_count; k++) {
                if (!removed && dk_str_eqz(args[k], "--")) {
                    removed = true;
                    continue;
                }
                tmp[o++] = args[k];
            }
            args = tmp;
            nargs = o;
        }
        start_index += arg_count;
        take_action(st, act, args, nargs, dk_str(""), false);
    }
    /* positionals[:] = positionals[len(arg_counts):] */
    memmove(pos->v, pos->v + nc, (pos->n - nc) * sizeof(DkArgAction *));
    pos->n -= nc;
    dk_xfree(counts);
    return start_index;
}

/* ArgumentParser._parse_known_args2 + _parse_known_args: fills ns, returns the extras. */
static void parse_known(State *parent, DkArgParser *p, const DkStr *args_in, size_t n, DkArgs *ns, DkStrVec *extras_out) {
    DkArena *a = p->a;
    Run *run = parent->run;
    State st_;
    State *st = &st_;
    memset(st, 0, sizeof *st);
    st->run = run;
    st->p = p;
    st->ns = ns;
    st->nargs = n;
    st->args = (DkStr *)dk_alloc(a, (n + 1) * sizeof(DkStr));
    for (size_t i = 0; i < n; i++) st->args[i] = args_in[i];

    /* add any action defaults that aren't present */
    for (size_t i = 0; i < p->actions.n; i++) {
        DkArgAction *act = p->actions.v[i];
        if (!act->dest) continue;
        if (ns_find(ns, act->dest)) continue;
        if (act->dflt.kind == DK_DK_SUPPRESS) continue;
        DkArgValue v;
        if (act->has_dflt_list) {
            DkArgValue *items = (DkArgValue *)dk_alloc(a, (act->ndflt_list + 1) * sizeof(DkArgValue));
            for (size_t k = 0; k < act->ndflt_list; k++) items[k] = v_str(dk_str(act->dflt_list[k]));
            v = v_list(a, items, act->ndflt_list);
        } else v = v_default(a, act->dflt);
        NsEntry *e = ns_set(ns, act->dest, v, false);
        e->owner = act;
    }

    /* action_conflicts */
    st->conflicts = (void *)dk_alloc(a, (p->actions.n + 1) * sizeof(*st->conflicts));
    for (size_t g = 0; g < p->mutexes.n; g++) {
        const ActionVec *ga = &p->mutexes.v[g]->actions;
        for (size_t i = 0; i < ga->n; i++)
            for (size_t j = 0; j < ga->n; j++)
                if (i != j) dk_vec_push(&st->conflicts[ga->v[i]->index], ga->v[j]->index);
    }

    /* the argument-kind pattern */
    st->pattern = (char *)dk_alloc(a, n + 1);
    st->opts = (OptList *)dk_alloc(a, (n + 1) * sizeof(OptList));
    size_t max_option_string_index = 0;
    bool any_option = false;
    for (size_t i = 0; i < n; i++) {
        if (dk_str_eqz(st->args[i], "--")) {
            st->pattern[i] = '-';
            for (size_t k = i + 1; k < n; k++) st->pattern[k] = 'A';
            break;
        }
        OptList ol;
        if (!parse_optional(st, st->args[i], &ol)) st->pattern[i] = 'A';
        else {
            st->opts[i] = ol;
            st->pattern[i] = 'O';
            max_option_string_index = i;
            any_option = true;
        }
    }

    st->seen = (bool *)dk_alloc(a, p->actions.n + 1);
    st->seen_nd = (bool *)dk_alloc(a, p->actions.n + 1);
    for (size_t i = 0; i < p->actions.n; i++)
        if (!p->actions.v[i]->nopts) dk_vec_push(&st->positionals, p->actions.v[i]);

    size_t start_index = 0;
    if (any_option) {
        while (start_index <= max_option_string_index) {
            size_t next_option_string_index = start_index;
            while (next_option_string_index <= max_option_string_index) {
                if (st->opts[next_option_string_index].n) break;
                next_option_string_index++;
            }
            if (start_index != next_option_string_index) {
                size_t positionals_end_index = consume_positionals(st, start_index);
                if (positionals_end_index > start_index) {
                    start_index = positionals_end_index;
                    continue;
                }
                start_index = positionals_end_index;
            }
            if (!st->opts[start_index].n) {
                for (size_t k = start_index; k < next_option_string_index; k++) dk_vec_push(&st->extras, st->args[k]);
                start_index = next_option_string_index;
            }
            start_index = consume_optional(st, start_index);
        }
    }
    size_t stop_index = consume_positionals(st, start_index);
    for (size_t k = stop_index; k < n; k++) dk_vec_push(&st->extras, st->args[k]);

    /* make sure all required actions were present, and convert the string defaults of the others */
    DkBuf req;
    dk_buf_init(&req, a);
    bool any_req = false;
    for (size_t i = 0; i < p->actions.n; i++) {
        DkArgAction *act = p->actions.v[i];
        if (st->seen[i]) continue;
        if (act->required) {
            const char *nm = argp_action_name(a, act);
            if (any_req) dk_buf_putz(&req, ", ");
            dk_buf_putz(&req, nm ? nm : "None");
            any_req = true;
        } else if (act->dflt.kind == DK_DK_STR && act->dest) {
            NsEntry *e = ns_find(ns, act->dest);
            if (e && !e->touched && e->owner == act && e->val.kind == DK_V_STR) {
                e->val = get_value(run, p, act, e->val.s);
            }
        }
    }
    if (any_req)
        parser_error(run, p, dk_str(dk_sprintf(a, "the following arguments are required: %s", dk_buf_cz(&req))));

    for (size_t g = 0; g < p->mutexes.n; g++) {
        DkArgMutex *m = p->mutexes.v[g];
        if (!m->required) continue;
        bool found = false;
        for (size_t i = 0; i < m->actions.n; i++)
            if (st->seen_nd[m->actions.v[i]->index]) found = true;
        if (!found) {
            DkBuf names;
            dk_buf_init(&names, a);
            bool first = true;
            for (size_t i = 0; i < m->actions.n; i++) {
                if (m->actions.v[i]->help_suppress) continue;
                if (!first) dk_buf_putc(&names, ' ');
                const char *nm = argp_action_name(a, m->actions.v[i]);
                dk_buf_putz(&names, nm ? nm : "None");
                first = false;
            }
            parser_error(run, p, dk_str(dk_sprintf(a, "one of the arguments %s is required", dk_buf_cz(&names))));
        }
    }

    /* args.extend(getattr(namespace, _UNRECOGNIZED_ARGS_ATTR)) */
    for (size_t i = 0; i < ns->unrec.n; i++) dk_vec_push(&st->extras, ns->unrec.v[i]);
    dk_vec_free(&ns->unrec);
    *extras_out = st->extras;
    for (size_t i = 0; i < p->actions.n; i++) dk_vec_free(&st->conflicts[i]);
    dk_vec_free(&st->positionals);
}

/* ---- entry points ----------------------------------------------------------------------------------------------- */
DkArgs *dk_args_try_parse(DkArgParser *p, const DkStr *args, size_t n, bool known, DkArgsExit *ex) {
    DkArena *a = p->a;
    Run *run = DK_NEW(a, Run);
    DkArgs *ns = ns_new(a);
    if (setjmp(run->jb) != 0) {
        if (ex) *ex = run->ex;
        return NULL;
    }
    State top;
    memset(&top, 0, sizeof top);
    top.run = run;
    top.p = p;
    DkStrVec extras = {0};
    parse_known(&top, p, args, n, ns, &extras);
    if (!known && extras.n) {
        DkBuf b;
        dk_buf_init(&b, a);
        dk_buf_putz(&b, "unrecognized arguments: ");
        for (size_t i = 0; i < extras.n; i++) {
            if (i) dk_buf_putc(&b, ' ');
            dk_buf_put(&b, extras.v[i]);
        }
        parser_error(run, p, dk_buf_str(&b));
    }
    ns->extras = extras;
    return ns;
}

static DkArgs *parse_main(DkArgParser *p, int argc, char **argv, bool known) {
    size_t n = argc > 1 ? (size_t)(argc - 1) : 0;
    DkStr *args = (DkStr *)dk_alloc(p->a, (n + 1) * sizeof(DkStr));
    for (size_t i = 0; i < n; i++) args[i] = dk_str(argv[i + 1]);
    return dk_args_parse_list(p, args, n, known);
}

DkArgs *dk_args_parse_list(DkArgParser *p, const DkStr *args, size_t n, bool known) {
    DkArgsExit ex = {0};
    DkArgs *r = dk_args_try_parse(p, args, n, known, &ex);
    if (r) return r;
    if (ex.out.n) fwrite(ex.out.p, 1, ex.out.n, stdout);
    if (ex.err.n) fwrite(ex.err.p, 1, ex.err.n, stderr);
    dk_exit(ex.code);
}

DkArgs *dk_args_parse(DkArgParser *p, int argc, char **argv) { return parse_main(p, argc, argv, false); }
DkArgs *dk_args_parse_known(DkArgParser *p, int argc, char **argv) { return parse_main(p, argc, argv, true); }

/* ---- results ----------------------------------------------------------------------------------------------------- */
static const NsEntry *need(const DkArgs *r, const char *dest) {
    const NsEntry *e = ns_find(r, dest);
    if (!e) dk_panic(__FILE__, __LINE__, "argparse: no attribute '%s' in the result (AttributeError)", dest);
    return e;
}

bool dk_args_has(const DkArgs *r, const char *dest) { return ns_find(r, dest) != NULL; }
const DkArgValue *dk_args_value(const DkArgs *r, const char *dest) {
    const NsEntry *e = ns_find(r, dest);
    return e ? &e->val : NULL;
}
bool dk_args_is_none(const DkArgs *r, const char *dest) { return need(r, dest)->val.kind == DK_V_NONE; }
bool dk_args_given(const DkArgs *r, const char *dest) {
    const NsEntry *e = ns_find(r, dest);
    return e && e->given;
}

DkStr dk_args_str(const DkArgs *r, const char *dest) {
    const DkArgValue *v = &need(r, dest)->val;
    if (v->kind == DK_V_NONE) return (DkStr){NULL, 0};
    if (v->kind != DK_V_STR) dk_panic(__FILE__, __LINE__, "argparse: '%s' is not a str", dest);
    return v->s;
}
i64 dk_args_int(const DkArgs *r, const char *dest) {
    const DkArgValue *v = &need(r, dest)->val;
    if (v->kind == DK_V_NONE) return 0;
    if (v->kind != DK_V_INT && v->kind != DK_V_BOOL) dk_panic(__FILE__, __LINE__, "argparse: '%s' is not an int", dest);
    return v->i;
}
double dk_args_float(const DkArgs *r, const char *dest) {
    const DkArgValue *v = &need(r, dest)->val;
    if (v->kind == DK_V_NONE) return 0.0;
    if (v->kind == DK_V_INT) return (double)v->i;
    if (v->kind != DK_V_FLOAT) dk_panic(__FILE__, __LINE__, "argparse: '%s' is not a float", dest);
    return v->f;
}
bool dk_args_bool(const DkArgs *r, const char *dest) {
    const DkArgValue *v = &need(r, dest)->val;
    if (v->kind == DK_V_NONE) return false;
    if (v->kind != DK_V_BOOL && v->kind != DK_V_INT) dk_panic(__FILE__, __LINE__, "argparse: '%s' is not a bool", dest);
    return v->i != 0;
}
size_t dk_args_len(const DkArgs *r, const char *dest) {
    const DkArgValue *v = &need(r, dest)->val;
    if (v->kind == DK_V_NONE) return 0;
    if (v->kind != DK_V_LIST) dk_panic(__FILE__, __LINE__, "argparse: '%s' is not a list", dest);
    return v->n;
}
const DkArgValue *dk_args_item(const DkArgs *r, const char *dest, size_t i) {
    const DkArgValue *v = &need(r, dest)->val;
    DK_ASSERT(v->kind == DK_V_LIST && i < v->n);
    return &v->items[i];
}
DkStrVec dk_args_strs(const DkArgs *r, const char *dest) {
    DkStrVec out = {0};
    const DkArgValue *v = &need(r, dest)->val;
    if (v->kind == DK_V_NONE) return out;
    if (v->kind != DK_V_LIST) dk_panic(__FILE__, __LINE__, "argparse: '%s' is not a list", dest);
    for (size_t i = 0; i < v->n; i++) {
        if (v->items[i].kind != DK_V_STR) dk_panic(__FILE__, __LINE__, "argparse: '%s' holds a non-str", dest);
        dk_vec_push(&out, v->items[i].s);
    }
    return out;
}
DkI64Vec dk_args_ints(const DkArgs *r, const char *dest) {
    DkI64Vec out = {0};
    const DkArgValue *v = &need(r, dest)->val;
    if (v->kind == DK_V_NONE) return out;
    if (v->kind != DK_V_LIST) dk_panic(__FILE__, __LINE__, "argparse: '%s' is not a list", dest);
    for (size_t i = 0; i < v->n; i++) dk_vec_push(&out, v->items[i].i);
    return out;
}
DkStrVec dk_args_extras(const DkArgs *r) { return r->extras; }

/* ---- usage and help ---------------------------------------------------------------------------------------------- */
DkStr dk_args_format_usage(DkArgParser *p) { return argp_format_usage(p); }
DkStr dk_args_format_help(DkArgParser *p) { return argp_format_help(p); }
void dk_args_print_usage(DkArgParser *p) {
    DkStr s = argp_format_usage(p);
    fwrite(s.p, 1, s.n, stdout);
}
void dk_args_print_help(DkArgParser *p) {
    DkStr s = argp_format_help(p);
    fwrite(s.p, 1, s.n, stdout);
}
