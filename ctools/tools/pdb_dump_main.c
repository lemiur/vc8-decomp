// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* pdb_dump: lists what a PDB 7.00 file holds.
 *
 *     pdb_dump <pdb> publics|modules|procs|lines|types [--tsv] [--legacy]
 *
 * publics: every S_PUB32 (segment:offset, flags, decorated name). modules: each module's object, archive, section
 * contribution, compiler and sizes. procs: each module procedure with its type and source file. lines: every line
 * entry. types: every TPI record with its spelled name and size, and the members of each class. --tsv prints tab
 * separated columns under a header line, else the text is aligned for reading. --legacy also reads the 16-bit-type
 * and Pascal-string record kinds. */
#include "dk/args.h"
#include "dk/dk.h"
#include "dk/fmt.h"
#include "pdb.h"

#include <stdio.h>

static bool g_tsv;

/* A row: tab separated, or the cells joined by two spaces. */
static void row(int n, const char *const *cells) {
    for (int i = 0; i < n; i++) {
        if (i) fputs(g_tsv ? "\t" : "  ", stdout);
        fputs(cells[i], stdout);
    }
    fputc('\n', stdout);
}

static const char *hex(const char *fmt, u32 v) { return dk_sprintf(dk_arena(), fmt, (unsigned)v); }
static const char *num(u32 v) { return dk_sprintf(dk_arena(), "%u", (unsigned)v); }

static void dump_publics(const DkPdb *p) {
    row(4, (const char *[]){"seg", "off", "flags", "name"});
    for (size_t i = 0; i < p->pubs.n; i++) {
        const DkPdbPublic *s = &p->pubs.v[i];
        row(4, (const char *[]){num(s->seg), hex("0x%08X", s->off), hex("0x%X", s->flags), s->name});
    }
}

static void dump_modules(const DkPdb *p) {
    row(9, (const char *[]){"index", "object", "library", "section", "offset", "size", "compiler", "symbols", "c13"});
    for (size_t i = 0; i < p->mods.n; i++) {
        const DkPdbModule *m = &p->mods.v[i];
        row(9, (const char *[]){num(m->index), m->object, m->library, num(m->sec), hex("0x%08X", m->sec_off),
                                hex("0x%X", m->sec_size), m->compile.present ? m->compile.compiler : "",
                                num(m->sym_bytes), num(m->c13_bytes)});
    }
}

static void dump_procs(const DkPdb *p) {
    row(8, (const char *[]){"kind", "seg", "off", "length", "module", "type", "source", "name"});
    for (size_t i = 0; i < p->procs.n; i++) {
        const DkPdbProc *r = &p->procs.v[i];
        row(8, (const char *[]){r->kind, num(r->seg), hex("0x%08X", r->off), hex("0x%X", r->length),
                                p->mods.v[r->mod].object, dk_pdb_types_name(p->types, r->typind), r->source, r->name});
    }
}

static void dump_lines(const DkPdb *p) {
    row(6, (const char *[]){"module", "seg", "off", "end", "line", "file"});
    for (size_t i = 0; i < p->lines.n; i++) {
        const DkPdbLine *l = &p->lines.v[i];
        row(6, (const char *[]){p->mods.v[l->mod].object, num(l->seg), hex("0x%08X", l->off),
                                l->end ? hex("0x%08X", l->end) : "", num(l->line), l->file});
    }
}

static void dump_types(const DkPdb *p) {
    DkPdbTypes *t = p->types;
    row(5, (const char *[]){"type", "leaf", "size", "kind", "name"});
    for (u32 ti = dk_pdb_types_first(t); ti < dk_pdb_types_end(t); ti++) {
        DkPdbTypeInfo info;
        bool cls = dk_pdb_types_info(t, ti, &info);
        row(5, (const char *[]){hex("0x%X", ti), hex("0x%X", dk_pdb_types_leaf(t, ti)),
                                dk_sprintf(dk_arena(), "%lld", (long long)dk_pdb_types_size(t, ti)),
                                cls ? info.kind : "", dk_pdb_types_name(t, ti)});
        if (!cls) continue;
        for (size_t i = 0; i < info.bases.n; i++)
            row(5, (const char *[]){"", "base", dk_sprintf(dk_arena(), "%lld", (long long)info.bases.v[i].offset),
                                    info.bases.v[i].is_virtual ? "virtual" : "", info.bases.v[i].name});
        for (size_t i = 0; i < info.fields.n; i++) {
            const DkPdbField *f = &info.fields.v[i];
            row(5, (const char *[]){"", "member", dk_sprintf(dk_arena(), "%lld", (long long)f->offset), f->type, f->name});
        }
        for (size_t i = 0; i < info.enumerators.n; i++)
            row(5, (const char *[]){"", "enumerator", dk_sprintf(dk_arena(), "%lld", (long long)info.enumerators.v[i].value),
                                    "", info.enumerators.v[i].name});
        for (size_t i = 0; i < info.methods.n; i++)
            row(5, (const char *[]){"", "method", "", info.methods.v[i].prop, info.methods.v[i].name});
    }
}

static int run(int argc, char **argv) {
    static const char *const what[] = {"publics", "modules", "procs", "lines", "types", NULL};
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){
        .prog = "pdb_dump", .description = "List the publics, modules, procedures, lines or types of a PDB 7.00 file."});
    dk_arg(ap, &(DkArgDesc){.names = "pdb", .help = "the PDB file"});
    dk_arg(ap, &(DkArgDesc){.names = "what", .choices = what, .help = "which table to list"});
    dk_arg(ap, &(DkArgDesc){.names = "--tsv", .action = DK_ARG_STORE_TRUE, .help = "tab separated columns"});
    dk_arg(ap, &(DkArgDesc){.names = "--legacy", .action = DK_ARG_STORE_TRUE,
                            .help = "also read the 16-bit-type and Pascal-string record kinds"});
    DkArgs *r = dk_args_parse(ap, argc, argv);
    g_tsv = dk_args_bool(r, "tsv");
    DkPdb p = dk_pdb_read(dk_cz(dk_arena(), dk_args_str(r, "pdb")), dk_args_bool(r, "legacy"));
    DkStr w = dk_args_str(r, "what");
    if (dk_str_eqz(w, "publics")) dump_publics(&p);
    else if (dk_str_eqz(w, "modules")) dump_modules(&p);
    else if (dk_str_eqz(w, "procs")) dump_procs(&p);
    else if (dk_str_eqz(w, "lines")) dump_lines(&p);
    else dump_types(&p);
    return 0;
}

DK_MAIN(run, "pdb_dump")
