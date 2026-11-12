// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* float_order command line and self test. The work runs on a thread with a 128 MiB stack. */
#include "float_order.h"

#include "dk/args.h"
#include "dk/fmt.h"
#include "dk/pool.h"
#include "dk/re.h"
#include "priority.h"

#define RE(p) dk_re((p), 0)

static DkStr S(const char *z) { return dk_str(z); }
static char *dupv(DkStr s) { return dk_cz(dk_arena(), s); }

static char *fmt_(DK_PRINTF_FMT const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *r = dk_vsprintf(dk_arena(), fmt, ap);
    va_end(ap);
    return r;
}

/* ---------------------------------------------------------------------------------------------- self test */

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) dk_panic(__FILE__, __LINE__, "AssertionError: %s", #cond); \
    } while (0)

static FoSiteVec sites_of(const char *text) {
    FoStmtInfo info = fo_parse_stmt(S(text));
    return fo_find_sites(S(text), &info, NULL);
}

static bool spelled(const FoSpellingVec *sp, const char *text) {
    for (size_t i = 0; i < sp->n; i++)
        if (strcmp(sp->v[i].text, text) == 0) return true;
    return false;
}

static bool any_contains(const FoSpellingVec *sp, const char *needle) {
    for (size_t i = 0; i < sp->n; i++)
        if (strstr(sp->v[i].text, needle)) return true;
    return false;
}

int float_order_selftest(void) {
    /* 1. a dot product of three products: 3 terms -> 6 sum orders, commuted factors */
    const char *text = "a.values[0] * b.values[0] + a.values[1] * b.values[1] + a.values[2] * b.values[2];";
    FoSiteVec sites = sites_of(fmt_("x = %s", text));
    CHECK(sites.n == 1);
    FoSite s = sites.v[0];
    DkStr normed = dk_str_rstrip_chars(S(text), S(";"));
    CHECK(strcmp(fo_render_tree(s.tree), dupv(dk_re_sub(dk_arena(), RE("\\s+"), S(" "), normed, 0))) == 0);
    FoSpellingVec sp = fo_spellings(s.tree, 2000, FO_ALL_MOVES, true, false);
    for (size_t i = 0; i < sp.n; i++)
        for (size_t j = 0; j < i; j++) CHECK(strcmp(sp.v[i].text, sp.v[j].text) != 0); /* a spelling repeats */
    char prods[3][64];
    for (int i = 0; i < 3; i++) snprintf(prods[i], sizeof prods[i], "a.values[%d] * b.values[%d]", i, i);
    static const int perms[6][3] = {{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}};
    for (int p = 0; p < 6; p++) {
        const char *joined = fmt_("%s + %s + %s", prods[perms[p][0]], prods[perms[p][1]], prods[perms[p][2]]);
        CHECK(spelled(&sp, joined) || strcmp(joined, fo_render_tree(s.tree)) == 0);
    }
    CHECK(any_contains(&sp, "b.values[1] * a.values[1]"));
    dk_vec_free(&sp);
    dk_vec_free(&sites);
    /* 2. halves */
    sites = sites_of("x = y * 0.5f;");
    sp = fo_spellings(sites.v[0].tree, 50, FO_ALL_MOVES, true, false);
    CHECK(spelled(&sp, "y / 2.0f"));
    dk_vec_free(&sp);
    sites = sites_of("x = y / 4.0f;");
    sp = fo_spellings(sites.v[0].tree, 50, FO_ALL_MOVES, true, false);
    CHECK(spelled(&sp, "y * 0.25f"));
    dk_vec_free(&sp);
    /* 3. sign forms */
    sites = sites_of("x = -(b - a);");
    CHECK(sites.n);
    sp = fo_spellings(sites.v[0].tree, 50, FO_ALL_MOVES, true, false);
    CHECK(spelled(&sp, "a - b"));
    dk_vec_free(&sp);
    sites = sites_of("x = a - b;");
    sp = fo_spellings(sites.v[0].tree, 50, FO_ALL_MOVES, true, false);
    CHECK(spelled(&sp, "-(b - a)"));
    dk_vec_free(&sp);
    /* 4. a parenthesised sum times a literal keeps its parentheses and distributes */
    sites = sites_of("m = (p.x + q.x) * 0.5f;");
    CHECK(strcmp(fo_render_tree(sites.v[0].tree), "(p.x + q.x) * 0.5f") == 0);
    sp = fo_spellings(sites.v[0].tree, 200, FO_ALL_MOVES, true, false);
    CHECK(spelled(&sp, "0.5f * (p.x + q.x)") && spelled(&sp, "p.x * 0.5f + q.x * 0.5f") && spelled(&sp, "(p.x + q.x) / 2.0f"));
    dk_vec_free(&sp);
    /* 5. a multi-line `if (` condition is one statement */
    DkCzVec ls = {0};
    dk_vec_push(&ls, "    if (a.x * 2.0f +");
    dk_vec_push(&ls, "        b.y > c)");
    dk_vec_push(&ls, "        return false;");
    FoStmtVec stmts = fo_group_statements(&ls);
    CHECK(stmts.n == 2 && stmts.v[0].hi == 1);
    sites = sites_of(dupv(stmts.v[0].text));
    CHECK(sites.n == 1 && dk_str_eqz(sites.v[0].text, "a.x * 2.0f + b.y"));
    /* 6. two calls are never reordered; one call is an atom */
    sites = sites_of("x = f(a) + g(b);");
    CHECK(sites.n == 0);
    sites = sites_of("x = f(a) + b * c;");
    CHECK(sites.n != 0);
    /* 7. sites inside call arguments and a cast operand */
    sites = sites_of("x = sqrtf(a * a + b * b);");
    CHECK(sites.n == 1);
    /* 8. statement moves */
    DkCzVec body = {0};
    dk_vec_push(&body, "    x += a * b;");
    dk_vec_push(&body, "    float s = p + q + r;");
    FoVariantVec vars = fo_stmt_variants(&body, NULL);
    bool compound = false, split = false;
    for (size_t i = 0; i < vars.n; i++) {
        if (strncmp(vars.v[i].note, "compound", 8) == 0) compound = true;
        if (strncmp(vars.v[i].note, "split", 5) == 0) split = true;
    }
    CHECK(compound && split);
    /* 9. a tree of a hand-made instruction stream: sqr(y) + sqr(x) */
    static const u8 code[] = {0xf3, 0x0f, 0x10, 0x46, 0x04, 0xf3, 0x0f, 0x59, 0x46, 0x04, 0xf3, 0x0f,
                              0x10, 0x06, 0xf3, 0x0f, 0x59, 0x06, 0xf3, 0x0f, 0x58, 0xc1};
    FoTree *tr = fo_float_tree(dk_arena(), dk_strn((const char *)code, sizeof code), 0x1000, NULL, 0);
    CHECK(tr->interesting.n == 3 && tr->interesting.v[0]->op == FO_MUL && tr->interesting.v[1]->op == FO_MUL &&
          tr->interesting.v[2]->op == FO_ADD);
    dk_pyprintf("selftest ok\n");
    return 0;
}

/* -------------------------------------------------------------------------------------------- main */

static const char DOC[] =
#include "float_order_doc.inc"
    ;

/* batch_jobs(workers): max(1, int(cpus / workers + 0.5)) */
static i64 batch_jobs(i64 workers) {
    i64 cpus = dk_cpu_count();
    if (cpus <= 0) cpus = 2;
    double v = (double)cpus / (double)DK_MAX(1, workers) + 0.5;
    return DK_MAX(1, (i64)v);
}

static const char *opt_str(const DkArgs *r, const char *dest) {
    if (dk_args_is_none(r, dest)) return NULL;
    return dk_cz(dk_arena(), dk_args_str(r, dest));
}

typedef struct Run {
    FloatOrderArgs *args;
    int mode; /* 0 search, 1 batch, 2 selftest */
    int rc;
} Run;

static void run_thread(void *p) {
    Run *r = p;
    r->rc = r->mode == 2 ? float_order_selftest() : r->mode == 1 ? float_order_batch(r->args) : float_order_search(r->args);
}

int float_order_main(int argc, char **argv) {
    DkArena *a = dk_arena();
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "float_order.exe", .description = DOC,
                                                                  .formatter = DK_FORMAT_RAW_DESCRIPTION});
    dk_arg(ap, &(DkArgDesc){.names = "unit", .nargs = DK_NARGS_OPT});
    dk_arg(ap, &(DkArgDesc){.names = "name", .nargs = DK_NARGS_OPT});
    dk_arg(ap, &(DkArgDesc){.names = "--target", .dflt = DK_DEF_NONE, .metavar = "T",
                              .help = "the configured target (default: the function's first annotated target)"});
    dk_arg(ap, &(DkArgDesc){.names = "--address", .help = "the function's address (hex), for an overloaded name"});
    dk_arg(ap, &(DkArgDesc){.names = "--minutes", .type = DK_T_FLOAT, .dflt = DK_DEF_NONE,
                              .help = "time budget (default 5; 3 per function in --batch)"});
    dk_arg(ap, &(DkArgDesc){.names = "--workers", .type = DK_T_INT0, .dflt = DK_DEF_NONE,
                              .help = "parallel compiles (default: half the CPUs; 3 in --batch)"});
    dk_arg(ap, &(DkArgDesc){.names = "--line", .type = DK_T_INT0, .dflt = DK_DEF_INT(0), .help = "only the statement at this source line"});
    dk_arg(ap, &(DkArgDesc){.names = "--max-site", .type = DK_T_INT0, .dflt = DK_DEF_INT(400), .help = "spellings tried per site"});
    dk_arg(ap, &(DkArgDesc){.names = "--quiet", .action = DK_ARG_STORE_TRUE});
    dk_arg(ap, &(DkArgDesc){.names = "--full-unit", .action = DK_ARG_STORE_TRUE, .help = "always compile the whole unit"});
    dk_arg(ap, &(DkArgDesc){.names = "--tree-only", .action = DK_ARG_STORE_TRUE,
                              .help = "print the float trees and the classification, nothing else"});
    dk_arg(ap, &(DkArgDesc){.names = "--selftest", .action = DK_ARG_STORE_TRUE});
    dk_arg(ap, &(DkArgDesc){.names = "--batch", .action = DK_ARG_STORE_TRUE, .help = "every result of the adapter whose wall is --wall"});
    dk_arg(ap, &(DkArgDesc){.names = "--select", .dflt = DK_DEF_NONE, .help = "regex on the stop reason (--batch)"});
    dk_arg(ap, &(DkArgDesc){.names = "--wall", .dflt = DK_DEF_STR("body"), .help = "wall class to select (--batch)"});
    dk_arg(ap, &(DkArgDesc){.names = "--units", .help = "comma-separated unit stems (--batch)"});
    dk_arg(ap, &(DkArgDesc){.names = "--jobs", .type = DK_T_INT0, .dflt = DK_DEF_NONE,
                              .help = "functions at a time (--batch; default: the CPUs divided by --workers, rounded)"});
    dk_arg(ap, &(DkArgDesc){.names = "--limit", .type = DK_T_INT0, .dflt = DK_DEF_INT(0), .help = "at most this many functions (--batch)"});
    dk_arg(ap, &(DkArgDesc){.names = "--root", .metavar = "DIR", .help = "the repository (default: $DECOMPKIT_ROOT, else found from here)"});
    dk_arg(ap, &(DkArgDesc){.names = "--config", .metavar = "FILE", .help = "the configuration (default: <root>/config/ctools.json)"});
    dk_priority_add_argument(ap);
    DkArgs *r = dk_args_parse(ap, argc, argv);

    FloatOrderArgs args = {0};
    args.unit = opt_str(r, "unit");
    args.name = opt_str(r, "name");
    args.target = opt_str(r, "target");
    args.address = opt_str(r, "address");
    args.minutes_set = !dk_args_is_none(r, "minutes");
    args.minutes = args.minutes_set ? dk_args_float(r, "minutes") : 0;
    args.workers_set = !dk_args_is_none(r, "workers");
    args.workers = args.workers_set ? dk_args_int(r, "workers") : 0;
    args.line = dk_args_int(r, "line");
    args.max_site = dk_args_int(r, "max_site");
    args.quiet = dk_args_bool(r, "quiet");
    args.full_unit = dk_args_bool(r, "full_unit");
    args.tree_only = dk_args_bool(r, "tree_only");
    args.normal_priority = dk_args_bool(r, "normal_priority");
    args.root = opt_str(r, "root");
    args.config = opt_str(r, "config");
    args.select = opt_str(r, "select");
    args.wall = opt_str(r, "wall");
    args.units = opt_str(r, "units");
    bool jobs_set = !dk_args_is_none(r, "jobs");
    args.jobs = jobs_set ? dk_args_int(r, "jobs") : 0;
    args.limit = dk_args_int(r, "limit");

    dk_priority_lower(args.normal_priority); /* before any compiler starts: they inherit it */
    Run run = {&args, 0, 0};
    if (dk_args_bool(r, "selftest")) {
        run.mode = 2;
    } else if (dk_args_bool(r, "batch")) {
        if (!args.minutes_set) {
            args.minutes = 3;
            args.minutes_int = true;
        }
        if (!args.workers_set) args.workers = 3;
        if (!jobs_set) args.jobs = batch_jobs(args.workers);
        run.mode = 1;
    } else {
        if (!(args.unit && *args.unit && args.name && *args.name)) dk_args_error(ap, "give a unit and a function name, or --batch");
        if (!args.minutes_set) {
            args.minutes = 5;
            args.minutes_int = true;
        }
        if (!args.workers_set) {
            i64 cpus = dk_cpu_count();
            if (cpus <= 0) cpus = 2;
            args.workers = DK_MAX(1, cpus / 2);
        }
    }
    if (run.mode != 2) {
        DkErr err = {0};
        args.project = dk_project_load(a, args.root, args.config, &err);
        if (!args.project) {
            fprintf(stderr, "float_order: %s\n", err.msg);
            return 2;
        }
    }
    DkThread *t = dk_thread_start(run_thread, &run, (size_t)128 * 1024 * 1024);
    dk_thread_join(t);
    return run.rc;
}
