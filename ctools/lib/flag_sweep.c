// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The compiler-option oracle (flag_sweep.h). */
#include "flag_sweep.h"

#include "dk/args.h"
#include "dk/clock.h"
#include "dk/fmt.h"
#include "dk/fs.h"
#include "dk/re.h"
#include "dk/sort.h"
#include "insn_text.h"

#include <stdlib.h>
#include <string.h>

static const char DOC[] =
#include "flag_sweep_doc.inc"
    ;

/* ---- option lists ------------------------------------------------------------------------------------------------- */

static const char *const FAMILIES[] = {"/EH[a-z\\-]*", "/O[12sxtd]", "/Ob\\d", "/Oi-?", "/Oy-?", "/GS-?",
                                       "/Gy-?",         "/GF-?",      "/fp:\\w+", "/arch:\\w+", "/Zp\\d*", "/Gs\\d*"};
#define N_FAMILIES (sizeof FAMILIES / sizeof FAMILIES[0])

/* The option family a token belongs to (a later token of a family replaces an earlier one); -1 for none. */
static int family(const char *token) {
    DkStr t = dk_str(token);
    for (size_t i = 0; i < N_FAMILIES; i++)
        if (dk_re_fullmatch(dk_re(FAMILIES[i], 0), t, 0, DK_END, NULL)) return (int)i;
    return -1;
}

static bool tokens_eq(const DkCzVec *a, const DkCzVec *b) {
    if (a->n != b->n) return false;
    for (size_t i = 0; i < a->n; i++)
        if (strcmp(a->v[i], b->v[i]) != 0) return false;
    return true;
}

static bool tokens_has(const DkCzVec *v, const char *t) {
    for (size_t i = 0; i < v->n; i++)
        if (strcmp(v->v[i], t) == 0) return true;
    return false;
}

static const char *join_tokens(DkArena *a, const DkCzVec *v) {
    DkBuf b;
    dk_buf_init(&b, a);
    for (size_t i = 0; i < v->n; i++) {
        if (i) dk_buf_putc(&b, ' ');
        dk_buf_putz(&b, v->v[i]);
    }
    return dk_buf_cz(&b);
}

DkCzVec dk_flag_apply(DkArena *a, const DkCzVec *base, const char *const *extra, size_t n_extra) {
    DkCzVec out = {0};
    for (size_t pass = 0; pass < 2; pass++) {
        size_t n = pass ? n_extra : base->n;
        for (size_t i = 0; i < n; i++) {
            const char *tok = pass ? extra[i] : base->v[i];
            int fam = family(tok);
            if (fam >= 0) {
                size_t keep = 0;
                for (size_t k = 0; k < out.n; k++)
                    if (family(out.v[k]) != fam) out.v[keep++] = out.v[k];
                out.n = keep;
            }
            dk_vec_push(&out, dk_strdup(a, tok));
        }
    }
    return out;
}

DkCzVec dk_flag_baseline(DkProject *p, const DkUnit *u, int target) {
    DkArena *a = dk_project_arena(p);
    const DkCompiler *c = dk_project_compiler(p, target);
    DkCzVec flags = {0};
    size_t n = strlen(u->path);
    bool is_c = n >= 2 && _stricmp(u->path + n - 2, ".c") == 0;
    const DkStrVec *groups[2] = {&c->base_flags, is_c ? &c->c_flags : &c->cpp_flags};
    for (int g = 0; g < 2; g++)
        for (size_t i = 0; i < groups[g]->n; i++) {
            bool removed = false;
            for (size_t r = 0; r < u->remove_flags.n && !removed; r++)
                removed = _stricmp(groups[g]->v[i].p, u->remove_flags.v[r].p) == 0;
            if (!removed) dk_vec_push(&flags, dk_strdup(a, groups[g]->v[i].p));
        }
    for (size_t i = 0; i < u->compile_flags.n; i++) dk_vec_push(&flags, dk_strdup(a, u->compile_flags.v[i].p));
    if (u->flags_line) {
        DkBytes text = {0};
        if (dk_read_all(a, dk_project_path(a, p, u->path), &text)) {
            DkStr t = {(const char *)text.v, text.n};
            if (dk_str_startswith(t, DK_S("\xEF\xBB\xBF"))) t = (DkStr){t.p + 3, t.n - 3};
            const char *line = dk_annot_flags_line(a, dk_project_annot_config(p), t);
            if (line) {
                DkStrVec parts = dk_str_split(dk_str(line), DK_S(""), -1);
                for (size_t i = 0; i < parts.n; i++) dk_vec_push(&flags, dk_cz(a, parts.v[i]));
                dk_vec_free(&parts);
            }
        }
    }
    return flags;
}

/* ---- the variants ------------------------------------------------------------------------------------------------- */

static void variant_add(DkFlagVariantVec *out, const DkCzVec *baseline, const char *name, DkCzVec changed) {
    if (tokens_eq(&changed, baseline)) return;
    DkFlagVariant v = {name, changed};
    dk_vec_push(out, v);
}

/* The baseline with one option removed. */
static DkCzVec without(DkArena *a, const DkCzVec *tokens, const char *drop) {
    DkCzVec changed = {0};
    for (size_t k = 0; k < tokens->n; k++)
        if (strcmp(tokens->v[k], drop) != 0) dk_vec_push(&changed, dk_strdup(a, tokens->v[k]));
    return changed;
}

static DkCzVec with(DkArena *a, const DkCzVec *tokens, const char *extra) {
    return dk_flag_apply(a, tokens, &extra, 1);
}

DkFlagVariantVec dk_flag_variants(DkArena *a, const DkCzVec *baseline, bool extended, const DkStrVec *configured,
                                  size_t n_configured) {
    DkFlagVariantVec out = {0};
    DkCzVec tokens = dk_flag_apply(a, baseline, NULL, 0);
    DkFlagVariant first = {"baseline", tokens};
    dk_vec_push(&out, first);
    if (n_configured) {
        for (size_t i = 0; i < n_configured; i++) {
            DkCzVec extra = {0};
            DkBuf name;
            dk_buf_init(&name, a);
            for (size_t k = 0; k < configured[i].n; k++) {
                dk_vec_push(&extra, dk_cz(a, configured[i].v[k]));
                dk_buf_putc(&name, '+');
                dk_buf_putz(&name, extra.v[k]);
            }
            variant_add(&out, &tokens, dk_buf_cz(&name),
                        dk_flag_apply(a, &tokens, (const char *const *)extra.v, extra.n));
            dk_vec_free(&extra);
        }
    } else {
        /* /Oy and /GS are on by default in VC8 (/O2 implies /Oy), so "dropping" them means the negated option */
        static const char *const negated[2][2] = {{"/Oy-", "-/Oy"}, {"/GS-", "-/GS"}};
        for (int i = 0; i < 2; i++) variant_add(&out, &tokens, negated[i][1], with(a, &tokens, negated[i][0]));
        static const char *const dropped[3][2] = {
            {"/Gy", "-/Gy"}, {"/fp:fast", "-/fp:fast"}, {"/arch:SSE2", "-/arch:SSE2"}};
        for (int i = 0; i < 3; i++) variant_add(&out, &tokens, dropped[i][1], without(a, &tokens, dropped[i][0]));
        bool ehsc = tokens_has(&tokens, "/EHsc");
        const char *other = ehsc ? "/EHa" : "/EHsc";
        variant_add(&out, &tokens, dk_sprintf(a, "%s->%s", ehsc ? "/EHsc" : "/EHa", other), with(a, &tokens, other));
        variant_add(&out, &tokens, "+/Ob1", with(a, &tokens, "/Ob1"));
        variant_add(&out, &tokens, "/O2->/Os", with(a, &tokens, "/Os"));
        variant_add(&out, &tokens, "+/Oi-", with(a, &tokens, "/Oi-"));
    }
    if (extended) {
        static const char *const more[] = {"/Ob0", "/Ob2", "/O1", "/Ox", "/Oi", "/Ot", "/EHs", "/GF",
                                           "/Gs",  "/GS-", "/fp:precise", "/fp:strict", "/arch:SSE", "/Zp4", "/Zp16"};
        for (size_t i = 0; i < sizeof more / sizeof more[0]; i++)
            variant_add(&out, &tokens, dk_sprintf(a, "+%s", more[i]), with(a, &tokens, more[i]));
    }
    return out;
}

void dk_flag_build_opts(DkArena *a, const DkCzVec *baseline, const DkCzVec *variant, DkBuildOpts *out) {
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < baseline->n; i++)
        if (!tokens_has(variant, baseline->v[i]))
            dk_vec_push(&out->remove_flags, dk_str(dk_strdup(a, baseline->v[i])));
    for (size_t i = 0; i < variant->n; i++)
        if (!tokens_has(baseline, variant->v[i]))
            dk_vec_push(&out->extra_flags, dk_str(dk_strdup(a, variant->v[i])));
}

/* ---- the sweep ---------------------------------------------------------------------------------------------------- */

/* MATCH, ERR, NOFN, the status of equal bytes (REFERENT, UNRESOLVED), or the byte percentage. */
static const char *score(DkArena *a, const DkResult *r) {
    switch (r->status) {
    case DK_MATCH: return "MATCH";
    case DK_ERROR: return "ERR";
    case DK_MISSING: return "NOFN";
    case DK_REFERENT:
    case DK_UNRESOLVED: return dk_status_name(r->status);
    default: break;
    }
    size_t nd = 0;
    (void)dk_result_differ(a, r, &nd);
    double size = r->theirs.n > 1 ? (double)r->theirs.n : 1.0;
    i64 pct = dk_py_round_int(100.0 * (1.0 - (double)nd / size));
    return dk_sprintf(a, "%lld%%", (long long)(pct > 0 ? pct : 0));
}

static int column_of(const DkCzVec *cols, const char *name) {
    for (size_t i = 0; i < cols->n; i++)
        if (strcmp(cols->v[i], name) == 0) return (int)i;
    return -1;
}

static int cmp_rows(const void *x, const void *y, void *ctx) {
    (void)ctx;
    const DkFlagRow *a = (const DkFlagRow *)x, *b = (const DkFlagRow *)y;
    if (a->line != b->line) return a->line < b->line ? -1 : 1;
    if (a->target != b->target) return a->target < b->target ? -1 : 1;
    return 0;
}

bool dk_flag_sweep(DkProject *p, const DkUnit *u, const DkFlagSweepOpts *o, DkFlagSweep *sw, DkErr *err) {
    dk_err_clear(err);
    memset(sw, 0, sizeof *sw);
    sw->unit = u;
    DkArena *a = dk_project_arena(p);
    if (dk_project_backend(p)->kind == DK_BACKEND_MANIFEST) {
        dk_err_set(err, DK_ERR_OTHER, "flag_sweep: the manifest backend does not compile, so options change nothing");
        return false;
    }
    size_t ntargets = dk_project_ntargets(p);
    DkCzVec baselines[DK_MAX_TARGETS];
    memset(baselines, 0, sizeof baselines);
    /* the plans first: the columns are the union of the variant names */
    for (size_t t = 0; t < ntargets; t++) {
        if ((o->targets && !(o->targets & (1u << t))) || !(u->target_mask & (1u << t))) continue;
        const DkCompiler *c = dk_project_compiler(p, (int)t);
        baselines[t] = dk_flag_baseline(p, u, (int)t);
        sw->plan[t] = dk_flag_variants(a, &baselines[t], o->extended, c ? c->flag_variants : NULL,
                                       c ? c->n_flag_variants : 0);
        for (size_t v = 0; v < sw->plan[t].n; v++)
            if (column_of(&sw->columns, sw->plan[t].v[v].name) < 0)
                dk_vec_push(&sw->columns, (char *)sw->plan[t].v[v].name);
    }
    for (size_t t = 0; t < ntargets; t++) {
        if (!sw->plan[t].n) continue;
        size_t row0 = sw->rows.n;
        const char *tname = dk_project_target((const DkProject *)p, (int)t)->name;
        for (size_t v = 0; v < sw->plan[t].n; v++) {
            const DkFlagVariant *var = &sw->plan[t].v[v];
            int col = column_of(&sw->columns, var->name);
            DkBuildOpts bo;
            dk_flag_build_opts(a, &baselines[t], &var->tokens, &bo);
            bo.use_cache = o->use_cache;
            double t0 = dk_time();
            size_t n = 0;
            DkErr ce = {0};
            DkResult *rs = dk_compare_unit(p, u, (int)t, &bo, &n, &ce);
            if (!rs) {
                *err = ce;
                return false;
            }
            if (ce.code) {
                char first[101];
                const char *nl = strpbrk(ce.msg, "\r\n");
                size_t len = nl ? (size_t)(nl - ce.msg) : strlen(ce.msg);
                if (len > 100) len = 100;
                memcpy(first, ce.msg, len);
                first[len] = 0;
                dk_vec_push(&sw->build_errors, dk_sprintf(a, "%s [%s]: %s", var->name, tname, first));
                if (o->progress) fprintf(o->progress, "  %-14s %-8s build failed: %s\n", var->name, tname, first);
            } else if (o->progress) {
                fprintf(o->progress, "  %-14s %-8s %5.1fs\n", var->name, tname, dk_time() - t0);
            }
            if (v == 0) {
                for (size_t i = 0; i < n; i++) {
                    DkFlagRow row;
                    memset(&row, 0, sizeof row);
                    row.name = rs[i].ann && rs[i].ann->name ? rs[i].ann->name : "?";
                    row.line = rs[i].ann ? rs[i].ann->line : 0;
                    row.target = (int)t;
                    if (rs[i].ann && dk_stopped(rs[i].ann, (int)t)) row.note = "stop";
                    else if (rs[i].ann && (rs[i].ann->pending_mask & (1u << t))) row.note = "pending";
                    row.cells = DK_NEWN(a, const char *, sw->columns.n);
                    dk_vec_push(&sw->rows, row);
                }
            }
            for (size_t i = 0; i < n && row0 + i < sw->rows.n; i++)
                sw->rows.v[row0 + i].cells[col] = score(a, &rs[i]);
        }
    }
    dk_sort(sw->rows.v, sw->rows.n, sizeof sw->rows.v[0], cmp_rows, NULL, false);
    return true;
}

/* ---- the verdict -------------------------------------------------------------------------------------------------- */

static bool is_match(const char *cell) { return cell && strcmp(cell, "MATCH") == 0; }

static int cmp_cz(const void *x, const void *y) { return strcmp(*(const char *const *)x, *(const char *const *)y); }

static bool cz_in(const DkCzVec *v, const char *s) { return tokens_has(v, s); }

DkFlagVerdict dk_flag_verdict(DkArena *a, const DkFlagSweep *sw) {
    DkFlagVerdict v;
    memset(&v, 0, sizeof v);
    DK_VEC(const DkFlagRow *) matched = {0}, live = {0};
    for (size_t i = 0; i < sw->rows.n; i++) {
        const DkFlagRow *r = &sw->rows.v[i];
        if (r->note) continue;
        dk_vec_push(&live, r);
        if (is_match(r->cells[0])) dk_vec_push(&matched, r);
    }
    v.n_matched = matched.n;
    if (matched.n)
        for (size_t c = 0; c < sw->columns.n; c++) {
            bool all = true, any = false;
            for (size_t i = 0; i < matched.n && all; i++) {
                const char *cell = matched.v[i]->cells[c];
                if (!cell) continue;
                any = true;
                all = is_match(cell);
            }
            if (all && any) dk_vec_push(&v.ok_variants, sw->columns.v[c]);
        }
    /* a function is flag-insensitive when every row of it matches in every variant that applies to it */
    DkCzVec names = {0}, bad = {0};
    for (size_t i = 0; i < matched.n; i++) {
        const DkFlagRow *r = matched.v[i];
        if (!cz_in(&names, r->name)) dk_vec_push(&names, (char *)r->name);
        bool all = true;
        for (size_t c = 0; c < sw->columns.n && all; c++) all = !r->cells[c] || is_match(r->cells[c]);
        if (!all && !cz_in(&bad, r->name)) dk_vec_push(&bad, (char *)r->name);
    }
    for (size_t i = 0; i < names.n; i++)
        if (!cz_in(&bad, names.v[i])) dk_vec_push(&v.insensitive, names.v[i]);
    if (v.insensitive.n) qsort(v.insensitive.v, v.insensitive.n, sizeof v.insensitive.v[0], cmp_cz);
    v.n_functions = names.n;
    v.n_sensitive = names.n - v.insensitive.n;
    if (!matched.n) {
        v.verdict = "no function matches in the baseline: nothing to prove";
    } else if (v.ok_variants.n == 1 && strcmp(v.ok_variants.v[0], "baseline") == 0) {
        v.verdict = dk_sprintf(a, "baseline is the UNIQUE tested variant where all %zu matched function-targets match",
                               matched.n);
    } else if (cz_in(&v.ok_variants, "baseline")) {
        DkBuf b;
        dk_buf_init(&b, a);
        bool first = true;
        for (size_t i = 0; i < v.ok_variants.n; i++) {
            if (strcmp(v.ok_variants.v[i], "baseline") == 0) continue;
            if (!first) dk_buf_putz(&b, ", ");
            first = false;
            dk_buf_putz(&b, v.ok_variants.v[i]);
        }
        v.verdict = dk_sprintf(a, "baseline is NOT unique: also fully matching: %s", dk_buf_cz(&b));
    } else {
        DkBuf b;
        dk_buf_init(&b, a);
        bool first = true;
        for (size_t i = 0; i < live.n; i++) {
            if (is_match(live.v[i]->cells[0])) continue;
            if (!first) dk_buf_putz(&b, ", ");
            first = false;
            dk_buf_putz(&b, live.v[i]->name);
        }
        const char *list = dk_buf_cz(&b);
        v.verdict = dk_sprintf(a, "baseline does not match every function (%.200s)", list);
    }
    dk_vec_free(&matched);
    dk_vec_free(&live);
    dk_vec_free(&names);
    dk_vec_free(&bad);
    return v;
}

/* ---- reports ------------------------------------------------------------------------------------------------------ */

void dk_flag_report(DkBuf *out, const DkProject *p, const DkFlagSweep *sw, const DkFlagVerdict *v) {
    size_t width = 10;
    for (size_t i = 0; i < sw->rows.n; i++) {
        size_t w = strlen(sw->rows.v[i].name) + strlen(dk_project_target(p, sw->rows.v[i].target)->name) + 5;
        if (w > width) width = w;
    }
    if (width > 64) width = 64;
    dk_buf_printf(out, "\n%-*s", (int)width, "function");
    for (size_t c = 0; c < sw->columns.n; c++) dk_buf_printf(out, "%-13.12s", sw->columns.v[c]);
    dk_buf_putc(out, '\n');
    bool any_apart = false;
    for (size_t pass = 0; pass < 2; pass++)
        for (size_t i = 0; i < sw->rows.n; i++) {
            const DkFlagRow *r = &sw->rows.v[i];
            if ((r->note != NULL) != (pass == 1)) continue;
            any_apart |= pass == 1;
            const char *label = dk_sprintf(dk_arena(), "%s [%s]%s", r->name, dk_project_target(p, r->target)->name,
                                           pass ? "*" : "");
            size_t ln = strlen(label);
            if (ln > width - 1) label += ln - (width - 1);
            dk_buf_printf(out, "%-*s", (int)width, label);
            for (size_t c = 0; c < sw->columns.n; c++)
                dk_buf_printf(out, "%-13s", r->cells[c] && *r->cells[c] ? r->cells[c] : "-");
            dk_buf_putc(out, '\n');
        }
    if (any_apart) dk_buf_putz(out, "(* = stop: or pending:, excluded from the verdict)\n");
    dk_buf_printf(out, "\nVERDICT: %s\n", v->verdict);
    dk_buf_printf(out, "flag-insensitive (match in every variant): %zu of %zu functions", v->insensitive.n,
                  v->n_functions);
    for (size_t i = 0; i < v->insensitive.n && i < 8; i++) dk_buf_printf(out, "%s%s", i ? ", " : ": ", v->insensitive.v[i]);
    if (v->insensitive.n > 8) dk_buf_putz(out, ", ...");
    dk_buf_printf(out, "\nflag-sensitive: %zu\n", v->n_sensitive);
    for (size_t i = 0; i < sw->build_errors.n; i++) dk_buf_printf(out, "build failed: %s\n", sw->build_errors.v[i]);
}

static void set(DkArena *a, DkJson *o, const char *key, DkJson *v) { dk_json_set(a, o, dk_str(key), v); }

DkJson *dk_flag_json(DkArena *a, const DkProject *p, const DkFlagSweep *sw, const DkFlagVerdict *v) {
    DkJson *root = dk_json_obj(a);
    set(a, root, "schema", dk_json_strz(a, "decompkit-flag-sweep/1"));
    set(a, root, "unit", dk_json_strz(a, sw->unit->path));
    DkJson *targets = dk_json_obj(a);
    for (size_t t = 0; t < DK_MAX_TARGETS; t++) {
        if (!sw->plan[t].n) continue;
        DkJson *vars = dk_json_obj(a);
        for (size_t i = 0; i < sw->plan[t].n; i++)
            set(a, vars, sw->plan[t].v[i].name, dk_json_strz(a, join_tokens(a, &sw->plan[t].v[i].tokens)));
        set(a, targets, dk_project_target(p, (int)t)->name, vars);
    }
    set(a, root, "variants", targets);
    set(a, root, "verdict", dk_json_strz(a, v->verdict));
    DkJson *ins = dk_json_arr(a);
    for (size_t i = 0; i < v->insensitive.n; i++) dk_json_arr_push(a, ins, dk_json_strz(a, v->insensitive.v[i]));
    set(a, root, "insensitive", ins);
    DkJson *errs = dk_json_arr(a);
    for (size_t i = 0; i < sw->build_errors.n; i++) dk_json_arr_push(a, errs, dk_json_strz(a, sw->build_errors.v[i]));
    set(a, root, "build_errors", errs);
    DkJson *fns = dk_json_arr(a);
    for (size_t i = 0; i < sw->rows.n; i++) {
        const DkFlagRow *r = &sw->rows.v[i];
        DkJson *f = dk_json_obj(a);
        set(a, f, "name", dk_json_strz(a, r->name));
        set(a, f, "line", dk_json_int(a, r->line));
        set(a, f, "target", dk_json_strz(a, dk_project_target(p, r->target)->name));
        set(a, f, "note", r->note ? dk_json_strz(a, r->note) : dk_json_null());
        DkJson *cells = dk_json_obj(a);
        for (size_t c = 0; c < sw->columns.n; c++)
            set(a, cells, sw->columns.v[c], r->cells[c] ? dk_json_strz(a, r->cells[c]) : dk_json_null());
        set(a, f, "cells", cells);
        dk_json_arr_push(a, fns, f);
    }
    set(a, root, "functions", fns);
    return root;
}

/* ---- the command line --------------------------------------------------------------------------------------------- */

static const char *const VARIANT_CHOICES[] = {"default", "extended", NULL};

int dk_flag_sweep_main(int argc, char **argv) {
    DkArena *a = dk_arena();
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "flag_sweep", .description = DOC,
                                                              .formatter = DK_FORMAT_RAW_DESCRIPTION});
    dk_arg(ap, &(DkArgDesc){.names = "unit", .help = "the unit (a path or a unique stem)"});
    dk_arg(ap, &(DkArgDesc){.names = "--variants", .choices = VARIANT_CHOICES, .dflt = DK_DEF_STR("default")});
    dk_arg(ap, &(DkArgDesc){.names = "--targets", .dflt = DK_DEF_STR("all"), .metavar = "A,B",
                            .help = "targets to sweep, comma separated (default: all)"});
    dk_arg(ap, &(DkArgDesc){.names = "--json", .metavar = "FILE", .help = "write the table and verdict as JSON"});
    dk_arg(ap, &(DkArgDesc){.names = "--no-cache", .action = DK_ARG_STORE_TRUE, .help = "do not use the object cache"});
    dk_arg(ap, &(DkArgDesc){.names = "--root", .metavar = "DIR",
                            .help = "the repository (default: $DECOMPKIT_ROOT, else found from here)"});
    dk_arg(ap, &(DkArgDesc){.names = "--config", .metavar = "FILE",
                            .help = "the configuration (default: <root>/config/ctools.json)"});
    DkArgs *args = dk_args_parse(ap, argc, argv);

    const char *root = dk_args_is_none(args, "root") ? NULL : dk_cz(a, dk_args_str(args, "root"));
    const char *config = dk_args_is_none(args, "config") ? NULL : dk_cz(a, dk_args_str(args, "config"));
    DkErr err = {0};
    DkProject *p = dk_project_load(a, root, config, &err);
    if (!p) {
        fprintf(stderr, "flag_sweep: %s\n", err.msg);
        return 2;
    }
    const char *uname = dk_cz(a, dk_args_str(args, "unit"));
    const DkUnit *u = dk_project_unit(p, uname);
    if (!u) {
        fprintf(stderr, "flag_sweep: %s: not a unit of %s\n", uname, dk_project_config_path(p));
        return 2;
    }
    bool want[DK_MAX_TARGETS];
    memset(want, 0, sizeof want);
    DkStr tl = dk_args_str(args, "targets");
    bool all = dk_str_eqz(tl, "all");
    if (!all) {
        DkStrVec parts = dk_str_split(tl, DK_S(","), -1);
        for (size_t i = 0; i < parts.n; i++) {
            if (!parts.v[i].n) continue;
            const char *tn = dk_cz(a, parts.v[i]);
            int t = dk_project_target_index(p, tn);
            if (t < 0) {
                fprintf(stderr, "flag_sweep: %s: not a target of %s\n", tn, dk_project_config_path(p));
                return 2;
            }
            want[t] = true;
        }
        dk_vec_free(&parts);
    }
    DkFlagSweepOpts o;
    memset(&o, 0, sizeof o);
    o.extended = dk_str_eqz(dk_args_str(args, "variants"), "extended");

    for (size_t t = 0; t < dk_project_ntargets(p); t++)
        if (want[t]) o.targets |= 1u << t;
    o.use_cache = !dk_args_bool(args, "no_cache");
    o.progress = stdout;
    double started = dk_time();
    DkFlagSweep sweep;
    for (size_t t = 0; t < dk_project_ntargets(p); t++) {
        if ((o.targets && !(o.targets & (1u << t))) || !(u->target_mask & (1u << t))) continue;
        DkCzVec base = dk_flag_baseline(p, u, (int)t);
        printf("unit %s; target %s; baseline options: %s\n", u->path, dk_project_target(p, (int)t)->name,
               join_tokens(a, &base));
    }
    if (!dk_flag_sweep(p, u, &o, &sweep, &err)) {
        fprintf(stderr, "flag_sweep: %s\n", err.msg);
        return 2;
    }
    if (!sweep.columns.n) {
        fprintf(stderr, "flag_sweep: %s: no target to sweep\n", u->path);
        return 2;
    }
    DkFlagVerdict verdict = dk_flag_verdict(a, &sweep);
    DkBuf text;
    dk_buf_init(&text, a);
    dk_flag_report(&text, p, &sweep, &verdict);
    printf("%.*s", (int)text.n, text.p);
    printf("runtime %.1fs\n", dk_time() - started);
    if (!dk_args_is_none(args, "json")) {
        const char *path = dk_cz(a, dk_args_str(args, "json"));
        DkJson *doc = dk_flag_json(a, p, &sweep, &verdict);
        DkBuf b;
        dk_buf_init(&b, a);
        dk_json_dump_buf(&b, doc, &DK_JSON_INDENT(1));
        dk_buf_putc(&b, '\n');
        const char *dir = dk_cz(a, dk_path_dirname(path));
        if (*dir) dk_makedirs(dir, true);
        if (!dk_write_file(path, b.p, b.n)) {
            fprintf(stderr, "flag_sweep: cannot write %s\n", path);
            return 2;
        }
    }
    return 0;
}
