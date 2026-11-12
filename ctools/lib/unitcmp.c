// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The adapter's compare front end (unitcmp.h). */
#include "unitcmp.h"

#include "dk/args.h"
#include "dk/fmt.h"
#include "dk/fs.h"
#include "frame_slots.h"
#include "insn_text.h"
#include "residue.h"

#include <stdio.h>
#include <string.h>

/* ---- hooks -------------------------------------------------------------------------------------------------------
 * Each entry adds one flag and one per-result report: --frame (frame.h: the prologues, the slots, the slot map) and
 * --residue (residue.h: the register renames and difference classes). */
static bool has_reference(const DkResult *r) {
    return r->status != DK_ERROR && r->status != DK_MISSING && r->theirs_va != 0;
}

static void frame_report(DkProject *p, const DkUnitcmpRow *row, const DkImage *im, DkBuf *out) {
    if (!has_reference(row->r)) return;
    dk_frame_report(out, p, row->r, im);
    dk_buf_putc(out, '\n');
}

static DkJson *frame_json(DkProject *p, const DkUnitcmpRow *row, const DkImage *im, DkArena *a) {
    if (!has_reference(row->r)) return NULL;
    return dk_frame_json(a, p, row->r, im);
}

static ResidueReport *residue_of(const DkProject *p, const DkUnitcmpRow *row, const DkImage *im) {
    return residue_compare(row->r, im, dk_project_target(p, row->r->target)->name);
}

static void residue_report(DkProject *p, const DkUnitcmpRow *row, const DkImage *im, DkBuf *out) {
    if (row->r->status == DK_ERROR || row->r->status == DK_MISSING) return;
    residue_format(out, residue_of(p, row, im));
}

static DkJson *residue_member(DkProject *p, const DkUnitcmpRow *row, const DkImage *im, DkArena *a) {
    if (row->r->status == DK_ERROR || row->r->status == DK_MISSING) return NULL;
    return residue_json(a, residue_of(p, row, im));
}

static const DkUnitcmpHook HOOKS[] = {
    {"--frame", "frame", "the stack frames of ours and the reference's, and their slot map", frame_report, frame_json},
    {"--residue", "residue", "the register renames and difference classes of a non-matching function", residue_report,
     residue_member},
    {NULL, NULL, NULL, NULL, NULL},
};

const DkUnitcmpHook *dk_unitcmp_hooks(void) { return HOOKS; }

static size_t n_hooks(void) {
    size_t n = 0;
    while (HOOKS[n].option) n++;
    return n;
}

/* ---- selection --------------------------------------------------------------------------------------------------- */

static bool parse_hex(const char *s, u32 *out) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (!*s || strlen(s) > 8) return false;
    u32 v = 0;
    for (; *s; s++) {
        char c = *s;
        int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (d < 0) return false;
        v = v << 4 | (u32)d;
    }
    *out = v;
    return true;
}

bool dk_unitcmp_selects(const DkProject *p, const DkAnnot *an, const char *spec) {
    if (!spec) return true;
    if (an->name) {
        if (strcmp(an->name, spec) == 0) return true;
        size_t n = strlen(an->name), k = strlen(spec);
        if (n > k + 2 && strcmp(an->name + n - k, spec) == 0 && an->name[n - k - 1] == ':' && an->name[n - k - 2] == ':')
            return true;
    }
    if (an->symbol && strcmp(an->symbol, spec) == 0) return true;
    u32 addr;
    if (parse_hex(spec, &addr) && addr != DK_NO_ADDR)
        for (size_t t = 0; t < dk_project_ntargets(p); t++)
            if ((an->target_mask & (1u << t)) && an->addr[t] == addr) return true;
    return false;
}

/* ---- collecting --------------------------------------------------------------------------------------------------- */

bool dk_unitcmp_collect(DkProject *p, const DkUnitcmpOpts *o, DkUnitcmpRowVec *rows, DkErr *err) {
    dk_err_clear(err);
    size_t ntargets = dk_project_ntargets(p);
    if (o->target >= (int)ntargets) {
        dk_err_set(err, DK_ERR_OTHER, "no target %d", o->target);
        return false;
    }
    DK_VEC(const DkUnit *) units = {0};
    if (o->all) {
        size_t n = 0;
        const DkUnit *us = dk_project_units(p, &n);
        /* a unit map may name a file that does not exist (yet): --all leaves it out */
        for (size_t i = 0; i < n; i++)
            if (dk_isfile(dk_project_path(dk_project_arena(p), p, us[i].path))) dk_vec_push(&units, &us[i]);
    }
    for (size_t i = 0; i < o->n_units; i++) {
        const DkUnit *u = dk_project_unit(p, o->units[i]);
        if (!u) {
            dk_err_set(err, DK_ERR_OTHER, "%s: not a unit of %s", o->units[i], dk_project_config_path(p));
            dk_vec_free(&units);
            return false;
        }
        dk_vec_push(&units, u);
    }
    DkBuildOpts bo;
    memset(&bo, 0, sizeof bo);
    bo.use_cache = o->use_cache;
    for (size_t i = 0; i < units.n; i++) {
        const DkUnit *u = units.v[i];
        /* the unit's annotations first: a unit with none in the selection is not built */
        size_t nann = 0;
        DkErr aerr = {0};
        DkAnnot *anns = dk_annotations(p, u, &nann, &aerr);
        if (!anns && aerr.code) {
            *err = aerr;
            dk_vec_free(&units);
            return false;
        }
        for (size_t t = 0; t < ntargets; t++) {
            if (o->target >= 0 && (int)t != o->target) continue;
            if (!(u->target_mask & (1u << t))) continue;
            bool any = false;
            for (size_t k = 0; k < nann && !any; k++)
                any = anns[k].kind == DK_ANN_FUNCTION && (anns[k].target_mask & (1u << t)) &&
                      dk_unitcmp_selects(p, &anns[k], o->function);
            if (!any) continue;
            DkErr ce = {0};
            size_t nr = 0;
            DkResult *rs = dk_compare_unit(p, u, (int)t, &bo, &nr, &ce);
            if (!rs) {
                *err = ce;
                dk_vec_free(&units);
                return false;
            }
            DkErr ie = {0};
            DkImage *im = dk_target_image(p, (int)t, &ie);
            for (size_t k = 0; k < nr; k++) {
                if (!dk_unitcmp_selects(p, rs[k].ann, o->function)) continue;
                DkUnitcmpRow row = {u, &rs[k], dk_build_wall(&rs[k], im)};
                dk_vec_push(rows, row);
            }
        }
    }
    dk_vec_free(&units);
    return true;
}

/* ---- printing ------------------------------------------------------------------------------------------------------ */

static const char *row_name(const DkUnitcmpRow *row) {
    const DkResult *r = row->r;
    if (r->ann && r->ann->name) return r->ann->name;
    if (r->ours.symbol) return r->ours.symbol;
    return "?";
}

DkStr dk_unitcmp_line(DkArena *a, const DkProject *p, const DkUnitcmpRow *row) {
    const DkResult *r = row->r;
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_printf(&b, "%-10s %-6s %08X ", dk_status_name(r->status), dk_project_target(p, r->target)->name,
                  r->theirs_va);
    if (r->status == DK_ERROR || r->status == DK_MISSING) {
        dk_buf_printf(&b, "%-11s %6s %-12s %s", "-", "-", row->wall.wall, row_name(row));
    } else {
        char sizes[32];
        snprintf(sizes, sizeof sizes, "%zu/%zu", r->ours.code.n, r->theirs.n);
        dk_buf_printf(&b, "%-11s %5.1f%% %-12s %s", sizes, row->wall.close, row->wall.wall, row_name(row));
    }
    if (r->error && r->status != DK_MATCH) dk_buf_printf(&b, "  (%s)", r->error);
    return dk_buf_str(&b);
}

static const char *verdict_name(DkRefVerdict v) {
    switch (v) {
    case DK_REF_SAME: return "same";
    case DK_REF_OTHER: return "other";
    case DK_REF_UNRESOLVED: return "unresolved";
    }
    return "?";
}

static DkJson *hex_json(DkArena *a, u32 v) { return dk_json_strz(a, dk_sprintf(a, "0x%08X", v)); }

static void set(DkArena *a, DkJson *o, const char *key, DkJson *v) { dk_json_set(a, o, dk_str(key), v); }

static DkJson *strs_json(DkArena *a, const DkCzVec *v) {
    DkJson *arr = dk_json_arr(a);
    for (size_t i = 0; i < v->n; i++) dk_json_arr_push(a, arr, dk_json_strz(a, v->v[i]));
    return arr;
}

DkJson *dk_unitcmp_json(DkArena *a, DkProject *p, const DkUnitcmpRowVec *rows, const bool *hook_on) {
    DkJson *doc = dk_json_obj(a);
    set(a, doc, "schema", dk_json_strz(a, "decompkit-unitcmp/1"));
    DkJson *results = dk_json_arr(a);
    size_t counts[DK_ERROR + 1];
    memset(counts, 0, sizeof counts);
    for (size_t i = 0; i < rows->n; i++) {
        const DkUnitcmpRow *row = &rows->v[i];
        const DkResult *r = row->r;
        counts[r->status]++;
        DkJson *o = dk_json_obj(a);
        set(a, o, "unit", dk_json_strz(a, row->unit->path));
        set(a, o, "target", dk_json_strz(a, dk_project_target(p, r->target)->name));
        set(a, o, "name", r->ann && r->ann->name ? dk_json_strz(a, r->ann->name) : dk_json_null());
        set(a, o, "line", dk_json_int(a, r->ann ? r->ann->line : 0));
        set(a, o, "symbol", r->ours.symbol ? dk_json_strz(a, r->ours.symbol) : dk_json_null());
        set(a, o, "address", hex_json(a, r->theirs_va));
        set(a, o, "status", dk_json_strz(a, dk_status_name(r->status)));
        set(a, o, "size", dk_json_uint(a, r->ours.code.n));
        set(a, o, "reference_size", dk_json_uint(a, r->theirs.n));
        set(a, o, "close", dk_json_float(a, row->wall.close));
        set(a, o, "wall", dk_json_strz(a, row->wall.wall));
        set(a, o, "differ", dk_json_int(a, row->wall.info.differ));
        set(a, o, "stopped", dk_json_bool(r->ann && dk_stopped(r->ann, r->target)));
        set(a, o, "error", r->error ? dk_json_strz(a, r->error) : dk_json_null());
        if (row->wall.info.classified) {
            DkJson *c = dk_json_obj(a);
            set(a, c, "insns_ours", dk_json_int(a, row->wall.info.insns_ours));
            set(a, c, "insns_reference", dk_json_int(a, row->wall.info.insns_reference));
            set(a, c, "first_difference",
                row->wall.info.has_first_difference ? dk_json_int(a, row->wall.info.first_difference) : dk_json_null());
            set(a, c, "same_mnemonics", dk_json_bool(row->wall.info.same_mnemonics));
            set(a, c, "calls_only_ours", strs_json(a, &row->wall.info.calls_only_ours));
            set(a, c, "calls_only_reference", strs_json(a, &row->wall.info.calls_only_reference));
            set(a, o, "classify", c);
        }
        DkJson *refs = dk_json_arr(a);
        for (size_t k = 0; k < r->n_refs; k++) {
            const DkRefCheck *c = &r->refs[k];
            DkJson *ro = dk_json_obj(a);
            set(a, ro, "offset", dk_json_uint(a, c->offset));
            set(a, ro, "name", c->name ? dk_json_strz(a, c->name) : dk_json_null());
            set(a, ro, "verdict", dk_json_strz(a, verdict_name(c->verdict)));
            set(a, ro, "ours", hex_json(a, c->ours));
            set(a, ro, "theirs", hex_json(a, c->theirs));
            dk_json_arr_push(a, refs, ro);
        }
        set(a, o, "refs", refs);
        const DkUnitcmpHook *hooks = dk_unitcmp_hooks();
        for (size_t h = 0; hook_on && hooks[h].option; h++) {
            if (!hook_on[h] || !hooks[h].json) continue;
            DkErr ie = {0};
            DkJson *v = hooks[h].json(p, row, dk_target_image(p, r->target, &ie), a);
            if (v) set(a, o, hooks[h].dest, v);
        }
        dk_json_arr_push(a, results, o);
    }
    set(a, doc, "results", results);
    DkJson *totals = dk_json_obj(a);
    for (int s = DK_MATCH; s <= DK_ERROR; s++)
        set(a, totals, dk_status_name((DkStatus)s), dk_json_uint(a, counts[s]));
    set(a, doc, "totals", totals);
    return doc;
}

/* ---- the command line ------------------------------------------------------------------------------------------- */

int dk_unitcmp_main(int argc, char **argv) {
    DkArena *a = dk_arena();
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "unitcmp",
        .description = "Build units with the configured backend and compare every annotated function with the "
                       "reference images (config/ctools.json)."});
    dk_arg(ap, &(DkArgDesc){.names = "units", .nargs = DK_NARGS_STAR, .help = "units (paths or unique stems)"});
    dk_arg(ap, &(DkArgDesc){.names = "--all", .action = DK_ARG_STORE_TRUE, .help = "every unit of the project"});
    dk_arg(ap, &(DkArgDesc){.names = "--target", .dflt = DK_DEF_STR("all"), .metavar = "T",
                            .help = "one configured target, or all (default)"});
    dk_arg(ap, &(DkArgDesc){.names = "--function", .metavar = "NAME",
                            .help = "one function: its name, the last part of a qualified name, or an address"});
    dk_arg(ap, &(DkArgDesc){.names = "--summary", .action = DK_ARG_STORE_TRUE,
                            .help = "print only the results that are not MATCH, and the totals"});
    dk_arg(ap, &(DkArgDesc){.names = "--diff", .action = DK_ARG_STORE_TRUE,
                            .help = "print the side-by-side disassembly of each result that is not MATCH"});
    dk_arg(ap, &(DkArgDesc){.names = "--max-rows", .type = DK_T_INT0, .dflt = DK_DEF_INT(0), .metavar = "N",
                            .help = "with --diff: only the first N differing rows (default: every row)"});
    dk_arg(ap, &(DkArgDesc){.names = "--json", .metavar = "FILE", .help = "write every result as JSON"});
    dk_arg(ap, &(DkArgDesc){.names = "--no-cache", .action = DK_ARG_STORE_TRUE, .help = "do not use the object cache"});
    dk_arg(ap, &(DkArgDesc){.names = "--root", .metavar = "DIR",
                            .help = "the repository (default: $DECOMPKIT_ROOT, else found from here)"});
    dk_arg(ap, &(DkArgDesc){.names = "--config", .metavar = "FILE",
                            .help = "the configuration (default: <root>/config/ctools.json)"});
    const DkUnitcmpHook *hooks = dk_unitcmp_hooks();
    size_t nh = n_hooks();
    for (size_t h = 0; h < nh; h++)
        dk_arg(ap, &(DkArgDesc){.names = hooks[h].option, .action = DK_ARG_STORE_TRUE, .help = hooks[h].help});
    DkArgs *args = dk_args_parse(ap, argc, argv);

    const char *root = dk_args_is_none(args, "root") ? NULL : dk_cz(a, dk_args_str(args, "root"));
    const char *config = dk_args_is_none(args, "config") ? NULL : dk_cz(a, dk_args_str(args, "config"));
    DkErr err = {0};
    DkProject *p = dk_project_load(a, root, config, &err);
    if (!p) {
        fprintf(stderr, "unitcmp: %s\n", err.msg);
        return 2;
    }
    DkStrVec units = dk_args_strs(args, "units");
    bool all = dk_args_bool(args, "all");
    if (!units.n && !all) {
        fprintf(stderr, "unitcmp: name a unit, or --all\n");
        return 2;
    }
    DkUnitcmpOpts o;
    memset(&o, 0, sizeof o);
    const char **names = DK_NEWN(a, const char *, units.n + 1);
    for (size_t i = 0; i < units.n; i++) names[i] = dk_cz(a, units.v[i]);
    o.units = names;
    o.n_units = units.n;
    o.all = all;
    o.target = -1;
    DkStr tname = dk_args_str(args, "target");
    if (!dk_str_eqz(tname, "all")) {
        const char *tn = dk_cz(a, tname);
        o.target = dk_project_target_index(p, tn);
        if (o.target < 0) {
            fprintf(stderr, "unitcmp: %s: not a target of %s\n", tn, dk_project_config_path(p));
            return 2;
        }
    }
    o.function = dk_args_is_none(args, "function") ? NULL : dk_cz(a, dk_args_str(args, "function"));
    o.use_cache = !dk_args_bool(args, "no_cache");
    bool summary = dk_args_bool(args, "summary"), diff = dk_args_bool(args, "diff");
    size_t max_rows = (size_t)dk_args_int(args, "max_rows");
    bool *hook_on = DK_NEWN(a, bool, nh + 1);
    for (size_t h = 0; h < nh; h++) hook_on[h] = dk_args_bool(args, hooks[h].dest);

    DkUnitcmpRowVec rows = {0};
    if (!dk_unitcmp_collect(p, &o, &rows, &err)) {
        fprintf(stderr, "unitcmp: %s\n", err.msg);
        return 2;
    }
    size_t counts[DK_ERROR + 1];
    memset(counts, 0, sizeof counts);
    for (size_t i = 0; i < rows.n; i++) {
        const DkUnitcmpRow *row = &rows.v[i];
        const DkResult *r = row->r;
        counts[r->status]++;
        if (summary && r->status == DK_MATCH) continue;
        DkStr line = dk_unitcmp_line(a, p, row);
        printf("%.*s\n", DK_SF(line));
        DkErr ie = {0};
        DkImage *im = dk_target_image(p, r->target, &ie);
        if (diff && r->status != DK_MATCH && r->status != DK_ERROR && r->status != DK_MISSING) {
            DkInsnDiffOpts d = {0, max_rows, dk_project_target(p, r->target)->name};
            DkStr text = dk_insn_diff(a, r, im, &d);
            printf("%.*s\n", DK_SF(text));
        }
        for (size_t h = 0; h < nh; h++) {
            if (!hook_on[h] || !hooks[h].report) continue;
            DkBuf b;
            dk_buf_init(&b, a);
            hooks[h].report(p, row, im, &b);
            if (b.n) printf("%.*s", (int)b.n, b.p);
        }
    }
    printf("%zu result(s):", rows.n);
    for (int s = DK_MATCH; s <= DK_ERROR; s++)
        if (counts[s]) printf(" %s %zu", dk_status_name((DkStatus)s), counts[s]);
    printf("\n");
    if (!dk_args_is_none(args, "json")) {
        const char *path = dk_cz(a, dk_args_str(args, "json"));
        DkJson *doc = dk_unitcmp_json(a, p, &rows, hook_on);
        DkBuf b;
        dk_buf_init(&b, a);
        dk_json_dump_buf(&b, doc, &DK_JSON_INDENT(1));
        dk_buf_putc(&b, '\n');
        if (!dk_write_file(path, b.p, b.n)) {
            fprintf(stderr, "unitcmp: cannot write %s\n", path);
            dk_vec_free(&rows);
            return 2;
        }
    }
    int rc = counts[DK_MATCH] == rows.n ? 0 : 1;
    dk_vec_free(&rows);
    return rc;
}
