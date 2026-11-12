// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The symbol sources of the project adapter (project.h): the names of a target's addresses, layered from an ordered
 * list of TSV, PDB and MSVC linker map sources. An address keeps the name of the first source that names it; a later
 * source adds new addresses and fills a size that is still 0. Annotation names are layered on top with
 * dk_symbols_add(replace = true).
 *
 * Storage: the symbols in insertion order (recs), an address -> record map and a name -> record map, both kept current
 * on every add; and a derived array sorted by address (ord) with the running maximum of the symbol ends (maxend),
 * brought up to date lazily: the symbols added since the last lookup are sorted on their own and merged in, so a
 * lookup after a few adds costs O(n) and a lookup with nothing new O(log n). Pointers handed out by the lookups point
 * into ord and stay valid until the next dk_symbols_add that names a new address.
 *
 * Sources. tsv: a header row naming the columns, then one row per symbol; the address is the VA column, else the RVA
 * column plus the image base; numbers are decimal or 0x hex, an empty size is unknown (0), a row with no name or no
 * usable address is skipped, a UTF-8 BOM is dropped. pdb (a file, or a symbol store folder symbols/<name>.pdb/<GUID><age>/<name>.pdb: the entry for the image's CodeView GUID and age, else its only entry): the publics (decorated names), then the module procedures
 * for the addresses no public names (a procedure's length fills the size of the public at its address); VA = image
 * base + RVA. map: the "Publics by Value" and "Static symbols" tables of an MSVC linker map, whose third column is the
 * VA; sizes are unknown. A name made of several words (a quoted compiler-generated name) is rejoined with single
 * spaces. */
#include "project.h"

#include "dk/dk.h"
#include "pdb.h"

#include <string.h>

/* ---- the symbol table ---------------------------------------------------------------------------------------------- */

struct DkSymbols {
    DkArena *a;
    DK_VEC(DkSymbol) recs; /* insertion order; an index into it is stable */
    DkIMap *at;            /* va -> index into recs */
    DkMap *by_name;        /* name -> index into recs (the first symbol of that name, or the last one renamed to it) */
    DkSymbol *ord;         /* the first nsorted records, sorted by va */
    u64 *maxend;           /* maxend[i] = max over j <= i of ord[j].va + ord[j].size */
    size_t nsorted;
    bool ends_stale;
};

DkSymbols *dk_symbols_new(DkArena *a) {
    if (!a) a = dk_arena();
    DkSymbols *s = DK_NEW(a, DkSymbols);
    s->a = a;
    s->at = dk_imap_new();
    s->by_name = dk_map_new();
    return s;
}

static int cmp_va(const void *x, const void *y, void *ctx) {
    (void)ctx;
    const DkSymbol *a = (const DkSymbol *)x, *b = (const DkSymbol *)y;
    if (a->va != b->va) return a->va < b->va ? -1 : 1;
    return 0;
}

/* Brings ord and maxend up to date: sorts the records added since the last call and merges them in. */
static void refresh(const DkSymbols *cs) {
    DkSymbols *s = (DkSymbols *)cs;
    size_t n = s->recs.n;
    if (s->nsorted == n && !s->ends_stale) return;
    if (s->nsorted != n) {
        size_t t = n - s->nsorted;
        DkSymbol *tail = (DkSymbol *)dk_xrealloc(NULL, t * sizeof(DkSymbol));
        memcpy(tail, s->recs.v + s->nsorted, t * sizeof(DkSymbol));
        dk_sort(tail, t, sizeof(DkSymbol), cmp_va, NULL, false);
        DkSymbol *merged = (DkSymbol *)dk_xrealloc(NULL, n * sizeof(DkSymbol));
        size_t i = 0, j = 0, k = 0;
        while (i < s->nsorted && j < t) merged[k++] = s->ord[i].va < tail[j].va ? s->ord[i++] : tail[j++];
        while (i < s->nsorted) merged[k++] = s->ord[i++];
        while (j < t) merged[k++] = tail[j++];
        dk_xfree(tail);
        dk_xfree(s->ord);
        s->ord = merged;
        s->nsorted = n;
        dk_xfree(s->maxend);
        s->maxend = (u64 *)dk_xrealloc(NULL, n * sizeof(u64));
    }
    u64 hi = 0;
    for (size_t i = 0; i < n; i++) {
        u64 end = (u64)s->ord[i].va + s->ord[i].size;
        if (end > hi) hi = end;
        s->maxend[i] = hi;
    }
    s->ends_stale = false;
}

/* The number of sorted symbols starting at or below va. */
static size_t upper(const DkSymbols *s, u32 va) {
    size_t lo = 0, hi = s->nsorted;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (s->ord[mid].va <= va) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

const DkSymbol *dk_symbols_all(const DkSymbols *s, size_t *n) {
    if (!s) {
        if (n) *n = 0;
        return NULL;
    }
    refresh(s);
    if (n) *n = s->nsorted;
    return s->ord;
}

const DkSymbol *dk_symbols_at(const DkSymbols *s, u32 va) {
    if (!s || va == DK_NO_ADDR) return NULL;
    refresh(s);
    size_t i = upper(s, va);
    return i && s->ord[i - 1].va == va ? &s->ord[i - 1] : NULL;
}

const DkSymbol *dk_symbols_containing(const DkSymbols *s, u32 va, u32 *start) {
    if (start) *start = 0;
    if (!s) return NULL;
    refresh(s);
    size_t i = upper(s, va);
    if (!i) return NULL;
    size_t nearest = i - 1;
    /* The nearest sized symbol that holds va: walk down only while some symbol below can still reach va. */
    for (size_t j = i; j-- > 0 && s->maxend[j] > va;) {
        const DkSymbol *c = &s->ord[j];
        if (c->size && (u64)va < (u64)c->va + c->size) {
            if (start) *start = c->va;
            return c;
        }
    }
    if (start) *start = s->ord[nearest].va;
    return &s->ord[nearest];
}

const DkSymbol *dk_symbols_find(const DkSymbols *s, const char *name) {
    if (!s || !name) return NULL;
    const DkVal *v = dk_map_get(s->by_name, dk_str(name));
    return v ? dk_symbols_at(s, s->recs.v[v->u].va) : NULL;
}

u32 dk_symbols_next(const DkSymbols *s, u32 va) {
    if (!s) return 0;
    refresh(s);
    size_t i = upper(s, va);
    return i < s->nsorted ? s->ord[i].va : 0;
}

/* Mirrors a change of recs[idx] into ord when the record is already sorted in. */
static void mirror(DkSymbols *s, size_t idx) {
    if (idx >= s->nsorted) return;
    size_t i = upper(s, s->recs.v[idx].va);
    s->ord[i - 1] = s->recs.v[idx];
    s->ends_stale = true;
}

void dk_symbols_add(DkSymbols *s, u32 va, u32 size, const char *name, bool replace) {
    if (!s || va == DK_NO_ADDR) return;
    bool has_name = name && *name;
    bool created;
    DkVal *slot = dk_imap_put(s->at, va, &created);
    if (created) {
        if (!has_name) {
            dk_imap_del(s->at, va);
            return;
        }
        DkSymbol rec;
        rec.va = va;
        rec.size = size;
        rec.name = dk_cz(s->a, dk_str(name));
        slot->u = s->recs.n;
        dk_vec_push(&s->recs, rec);
        bool fresh;
        DkVal *nv = dk_map_put(s->by_name, dk_str(rec.name), &fresh);
        if (fresh) nv->u = slot->u;
        return;
    }
    size_t idx = (size_t)slot->u;
    DkSymbol *rec = &s->recs.v[idx];
    bool changed = false;
    if (replace && has_name && strcmp(rec->name, name) != 0) {
        DkVal *old = dk_map_get(s->by_name, dk_str(rec->name));
        if (old && old->u == idx) dk_map_del(s->by_name, dk_str(rec->name));
        rec->name = dk_cz(s->a, dk_str(name));
        dk_map_put(s->by_name, dk_str(rec->name), NULL)->u = idx;
        changed = true;
    }
    if (size && (replace || rec->size == 0) && rec->size != size) {
        rec->size = size;
        changed = true;
    }
    if (changed) mirror(s, idx);
}

/* ---- numbers ------------------------------------------------------------------------------------------------------ */

/* A decimal or 0x-prefixed hex number that fits 32 bits. */
static bool parse_u32(DkStr s, u32 *out) {
    s = dk_str_strip(s);
    if (!s.n || s.p[0] == '-' || s.p[0] == '+') return false;
    i64 v;
    bool hex = s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X');
    if (!dk_parse_int(s, hex ? 16 : 10, &v, NULL) || v < 0 || v > 0xFFFFFFFFll) return false;
    *out = (u32)v;
    return true;
}

static bool all_hex(DkStr s) {
    for (size_t i = 0; i < s.n; i++) {
        char c = s.p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
    return s.n > 0;
}

/* ---- tsv ---------------------------------------------------------------------------------------------------------- */

static i64 column(const DkStrVec *header, const char *name) {
    for (size_t i = 0; i < header->n; i++)
        if (dk_str_eqz(dk_str_strip(header->v[i]), name)) return (i64)i;
    return -1;
}

static DkStr cell(const DkStrVec *row, i64 col) {
    return col >= 0 && (size_t)col < row->n ? row->v[col] : dk_strn("", 0);
}

static bool load_tsv(DkSymbols *s, const DkSymSource *src, u32 image_base, DkErr *err, bool *need_base) {
    DkStr text;
    if (!dk_read_text(s->a, src->path, DK_TM_UTF8_SIG_REPLACE, &text)) {
        dk_err_set(err, DK_ERR_IO, "%s: cannot read the tsv symbol source", src->path);
        return false;
    }
    DkLines it;
    dk_lines_init(&it, text, DK_LINES_UNIVERSAL);
    DkStr line = {0};
    DkStrVec row = {0};
    bool have_header = false;
    while (!have_header && dk_lines_next(&it, &line))
        if (dk_str_strip(line).n) have_header = true;
    if (!have_header) {
        dk_err_set(err, DK_ERR_FORMAT, "%s: the tsv symbol source has no header row", src->path);
        return false;
    }
    dk_tsv_split(line, &row);
    const char *want_name = src->col_name ? src->col_name : "name";
    const char *want_va = src->col_va ? src->col_va : "va";
    const char *want_rva = src->col_rva ? src->col_rva : "rva";
    const char *want_size = src->col_size ? src->col_size : "size";
    i64 c_name = column(&row, want_name), c_va = column(&row, want_va), c_rva = column(&row, want_rva);
    i64 c_size = column(&row, want_size);
    bool ok = true;
    if (c_name < 0) {
        dk_err_set(err, DK_ERR_FORMAT, "%s: the tsv symbol source has no '%s' column", src->path, want_name);
        ok = false;
    } else if (c_va < 0 && c_rva < 0) {
        dk_err_set(err, DK_ERR_FORMAT, "%s: the tsv symbol source has neither a '%s' nor a '%s' column", src->path,
                   want_va, want_rva);
        ok = false;
    } else if (c_va < 0 && !image_base) {
        dk_err_set(err, DK_ERR_FORMAT, "%s: the tsv symbol source gives RVAs ('%s') and no image base is known",
                   src->path, want_rva);
        *need_base = true;
        ok = false;
    }
    while (ok && dk_lines_next(&it, &line)) {
        dk_tsv_split(line, &row);
        DkStr name = cell(&row, c_name);
        if (!name.n) continue;
        u32 va = 0, rva = 0;
        bool have = c_va >= 0 && parse_u32(cell(&row, c_va), &va);
        if (!have && c_rva >= 0 && image_base && parse_u32(cell(&row, c_rva), &rva) &&
            rva <= 0xFFFFFFFFu - image_base) {
            va = image_base + rva;
            have = true;
        }
        if (!have || va == DK_NO_ADDR) continue;
        u32 size = 0;
        if (c_size >= 0 && !parse_u32(cell(&row, c_size), &size)) size = 0;
        dk_symbols_add(s, va, size, dk_cz(s->a, name), false);
    }
    dk_vec_free(&row);
    return ok;
}

/* ---- pdb ---------------------------------------------------------------------------------------------------------- */

/* A symbol store entry (symbols/<name>.pdb/<GUID><age>/<name>.pdb): the folder name the image's debug directory asks
 * for (the CodeView RSDS record: the GUID as 32 upper-case hex digits, then the age in hex), or NULL when the image
 * has none. */
static const char *image_store_id(DkArena *a, const char *image_path) {
    DkBytes bytes = {0};
    if (!image_path || !dk_read_all(NULL, image_path, &bytes)) return NULL;
    const char *id = NULL;
    DkTry tr;
    if (DK_TRY(&tr)) {
        const DkPe *pe = dk_pe_parse(a, bytes.v, bytes.n);
        DkPeDataDir dd = pe->n_data_directory > DK_PE_DIR_DEBUG ? pe->data_directory[DK_PE_DIR_DEBUG] : (DkPeDataDir){0};
        for (u32 off = 0; off + 28 <= dd.size && !id; off += 28) {
            DkPeSpan span;
            if (!dk_pe_try_get_data(pe, (u64)dd.virtual_address + off, 28, &span) || span.n < 28) break;
            u32 type, raw;
            memcpy(&type, span.p + 12, 4);
            memcpy(&raw, span.p + 24, 4);
            if (type != 2 || (u64)raw + 24 > bytes.n || memcmp(bytes.v + raw, "RSDS", 4) != 0) continue;
            const u8 *g = bytes.v + raw + 4;
            u32 d1, age;
            u16 d2, d3;
            memcpy(&d1, g, 4);
            memcpy(&d2, g + 4, 2);
            memcpy(&d3, g + 6, 2);
            memcpy(&age, g + 16, 4);
            id = dk_sprintf(a, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X", d1, d2, d3, g[8], g[9], g[10], g[11],
                            g[12], g[13], g[14], g[15], age);
        }
        dk_try_end(&tr);
    }
    dk_vec_free(&bytes);
    return id;
}

/* The PDB inside a symbol store folder: the entry for the image's GUID and age, else the only entry. */
static bool store_pdb(DkArena *a, const char *dir, const char *image_path, const char **out, DkErr *err) {
    DkStrVec names = {0};
    if (!dk_listdir(a, dir, &names)) {
        dk_err_set(err, DK_ERR_IO, "%s: cannot list the symbol store", dir);
        return false;
    }
    const char *leaf = dk_cz(a, dk_path_basename(dir));
    const char *id = image_store_id(a, image_path);
    const char *pick = NULL;
    size_t entries = 0;
    for (size_t i = 0; i < names.n; i++) {
        const char *sub = dk_path_join(a, dir, dk_cz(a, names.v[i]));
        const char *file = dk_path_join(a, sub, leaf);
        if (!dk_isdir(sub) || !dk_isfile(file)) continue;
        entries++;
        if (id && dk_str_eqz(names.v[i], id)) {
            pick = file;
            break;
        }
        if (!pick) pick = file;
    }
    dk_vec_free(&names);
    bool exact = id && pick && strstr(pick, id) != NULL;
    if (!pick || (!exact && entries != 1)) {
        dk_err_set(err, DK_ERR_IO, "%s: the symbol store has %s%s%s", dir,
                   entries ? "no entry for " : "no entries", entries && id ? id : "", entries && !id ? "an unknown image" : "");
        return false;
    }
    *out = pick;
    return true;
}


static bool load_pdb(DkSymbols *s, const DkSymSource *src, u32 image_base, const char *image_path, DkErr *err,
                     bool *need_base) {
    if (!image_base) {
        dk_err_set(err, DK_ERR_FORMAT, "%s: a pdb symbol source needs the image base, and none is known", src->path);
        *need_base = true;
        return false;
    }
    const char *path = src->path;
    if (dk_isdir(path) && !store_pdb(s->a, path, image_path, &path, err)) return false;
    DkPdb pdb;
    DkTry t;
    if (DK_TRY(&t)) {
        pdb = dk_pdb_read(path, false);
        dk_try_end(&t);
    } else {
        dk_err_set(err, t.code ? t.code : DK_ERR_FORMAT, "%s: %s", src->path, t.msg);
        return false;
    }
    for (size_t i = 0; i < pdb.pubs.n; i++) {
        const DkPdbPublic *p = &pdb.pubs.v[i];
        i64 rva;
        if (!dk_pdb_rva(&pdb, p->seg, p->off, &rva) || rva < 0 || (u64)rva + image_base > 0xFFFFFFFFull) continue;
        dk_symbols_add(s, image_base + (u32)rva, 0, p->name, false);
    }
    for (size_t i = 0; i < pdb.procs.n; i++) {
        const DkPdbProc *p = &pdb.procs.v[i];
        i64 rva;
        if (!dk_pdb_rva(&pdb, p->seg, p->off, &rva) || rva < 0 || (u64)rva + image_base > 0xFFFFFFFFull) continue;
        dk_symbols_add(s, image_base + (u32)rva, p->length, p->name, false);
    }
    return true;
}

/* ---- map ---------------------------------------------------------------------------------------------------------- */

/* A table row, " 0001:00000010       _name   00401010 f   obj.obj": the name is the words between the segment:offset
 * and the first 8-digit hex word that is followed by at most a flag letter or two and the object; that word is the VA. */
static bool map_row(DkArena *a, DkStr line, u32 *va, DkStr *name) {
    DkStrVec w = dk_str_split(line, dk_strn("", 0), -1);
    bool ok = false;
    if (w.n >= 3 && w.v[0].n == 13 && w.v[0].p[4] == ':' && all_hex(dk_str_slice(w.v[0], 0, 4)) &&
        all_hex(dk_str_slice(w.v[0], 5, 13))) {
        for (size_t i = 2; i < w.n && !ok; i++) {
            u64 v;
            bool word = w.n - i <= 4 && w.v[i].n == 8 && all_hex(w.v[i]);
            if (word && dk_parse_uint(w.v[i], 16, &v) && v <= 0xFFFFFFFFull) {
                *va = (u32)v;
                *name = i == 2 ? w.v[1] : dk_str_join(a, DK_S(" "), w.v + 1, i - 1);
                ok = true;
            }
        }
    }
    dk_vec_free(&w);
    return ok;
}

static bool load_map(DkSymbols *s, const DkSymSource *src, DkErr *err) {
    DkStr text;
    if (!dk_read_text(s->a, src->path, DK_TM_UTF8_SIG_REPLACE, &text)) {
        dk_err_set(err, DK_ERR_IO, "%s: cannot read the map symbol source", src->path);
        return false;
    }
    DkLines it;
    dk_lines_init(&it, text, DK_LINES_UNIVERSAL);
    DkStr line;
    bool in_table = false;
    while (dk_lines_next(&it, &line)) {
        if (dk_str_contains(line, DK_S("Publics by Value")) || dk_str_contains(line, DK_S("Static symbols"))) {
            in_table = true;
            continue;
        }
        if (!in_table) continue;
        DkStr first = dk_str_lstrip(line);
        if (!first.n) continue;
        u32 va;
        DkStr name;
        if (map_row(s->a, line, &va, &name))
            dk_symbols_add(s, va, 0, dk_cz(s->a, name), false);
        else if (!(first.n >= 13 && first.p[4] == ':'))
            in_table = false; /* "entry point at", "Line numbers for", "Exports" ... end the table */
    }
    return true;
}

/* ---- loading ------------------------------------------------------------------------------------------------------ */

static DkSymbols *load_sources(DkArena *a, const DkSymSource *srcs, size_t n, u32 image_base,
                               const char *image_path, DkErr *err, bool *need_base) {
    if (err) dk_err_clear(err);
    DkSymbols *s = dk_symbols_new(a);
    for (size_t i = 0; i < n; i++) {
        bool ok;
        switch (srcs[i].kind) {
        case DK_SYM_TSV: ok = load_tsv(s, &srcs[i], image_base, err, need_base); break;
        case DK_SYM_PDB: ok = load_pdb(s, &srcs[i], image_base, image_path, err, need_base); break;
        case DK_SYM_MAP: ok = load_map(s, &srcs[i], err); break;
        default:
            dk_err_set(err, DK_ERR_OTHER, "symbol source %zu: unknown kind %d", i, (int)srcs[i].kind);
            ok = false;
            break;
        }
        if (!ok) return NULL;
    }
    return s;
}

DkSymbols *dk_symbols_load(DkArena *a, const DkSymSource *srcs, size_t n, u32 image_base, DkErr *err) {
    bool need_base = false;
    return load_sources(a, srcs, n, image_base, NULL, err, &need_base);
}

/* The image base of the target's executable, from the PE header of its image file; 0 with *err set on failure. */
static u32 base_from_image(DkArena *a, const DkTarget *t, DkErr *err) {
    const char *name = t->name ? t->name : "?";
    DkBytes bytes = {0};
    if (!t->image_path || !dk_read_all(NULL, t->image_path, &bytes)) {
        dk_err_set(err, DK_ERR_IO, "target %s: the image base is not configured and the image %s cannot be read",
                   name, t->image_path ? t->image_path : "(none)");
        return 0;
    }
    u32 base = 0;
    DkTry tr;
    if (DK_TRY(&tr)) {
        const DkPe *pe = dk_pe_parse(a, bytes.v, bytes.n);
        if (pe->image_base > 0 && pe->image_base <= 0xFFFFFFFFull) base = (u32)pe->image_base;
        dk_try_end(&tr);
        if (!base)
            dk_err_set(err, DK_ERR_FORMAT, "target %s: the image %s has no 32-bit image base", name, t->image_path);
    } else {
        dk_err_set(err, DK_ERR_FORMAT, "target %s: %s: %s", name, t->image_path, tr.msg);
    }
    dk_vec_free(&bytes);
    return base;
}

DkSymbols *dk_project_symbols(DkProject *p, int target, DkErr *err) {
    if (target < 0 || (size_t)target >= dk_project_ntargets(p)) {
        dk_err_set(err, DK_ERR_OTHER, "symbols: no target %d", target);
        return NULL;
    }
    DkTarget *t = dk_project_target_mut(p, target);
    if (t->syms) return t->syms;
    DkArena *a = dk_project_arena(p);
    bool need_base = false;
    DkSymbols *s = load_sources(a, t->symbols, t->n_symbols, t->image_base, t->image_path, err, &need_base);
    if (!s && need_base && !t->image_base) {
        DkErr e2 = {0};
        u32 base = base_from_image(a, t, &e2);
        if (!base) {
            if (err) *err = e2;
            return NULL;
        }
        s = load_sources(a, t->symbols, t->n_symbols, base, t->image_path, err, &need_base);
    }
    t->syms = s;
    return s;
}
