// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Comparing a candidate function with the reference image (docs/c-toolkit-design.md section 5.3).
 *
 * The relocated fields of ours are masked on both sides and the remaining bytes compared; then every relocation is
 * resolved on both sides. The reference's target comes from its own word (DIR32: the word less the addend; DIR32NB:
 * plus the image base; REL32: the next instruction plus the displacement, less the addend). Ours is the address the
 * reference image should hold for our relocation's symbol, found by this ladder, the first answer winning:
 *
 *   1. the function itself (labels, switch tables): the reference function's address plus the offset;
 *   2. an annotation of any unit that binds to the symbol (its address in the target);
 *   3. the target's symbol sources, by exact name;
 *   4. a symbol our build defines with readable bytes (compiler-made data: strings, constants, tables; or a static
 *      function): compared by content with the reference's bytes at its target, the relocations inside it
 *      resolved by this same ladder (depth 16, a cycle unresolved);
 *   5. the configured referents files;
 *   6. the well-known names: the linker's image base symbol (__ImageBase); "__imp_" imports by name in the
 *      reference's import table (when well_known.imports); then the listed symbols in the target's symbol sources
 *      (as given, then without one leading underscore).
 *
 * A relocation whose expected word equals the reference's is SAME, a different one OTHER, one with no answer (or an
 * unknown type) UNRESOLVED. Status: ERROR (no image, unreadable bytes, a failed build), MISSING (no address in the
 * target, or no candidate), SIZE (the reference's size is known from a sized symbol and differs from ours, trailing
 * int3/nop padding of ours past it ignored), DIFF (an unmasked byte differs), REFERENT (a relocation is OTHER),
 * UNRESOLVED (one is UNRESOLVED), else MATCH. */
#include "dk/dk.h"
#include "project_backend.h"

#include <string.h>

#define CONTENT_DEPTH_LIMIT 16

typedef struct {
    DkAnnot *anns; /* every unit's annotations */
    size_t nanns;
    DkMap *by_name; /* symbol -> address (u64; (u64)-1: none or ambiguous) */
    DkMap *referents;
} CompareCache;

typedef struct Active {
    const char *symbol;
    u32 at;
    const struct Active *up;
} Active;

typedef struct {
    DkProject *p;
    int target;
    DkImage *im;
    CompareCache *cc;
    const DkFunc *root; /* the candidate: its build defines the content symbols */
    DkArena *a;
} Cmp;

const char *dk_status_name(DkStatus s) {
    switch (s) {
    case DK_MATCH: return "MATCH";
    case DK_DIFF: return "DIFF";
    case DK_SIZE: return "SIZE";
    case DK_REFERENT: return "REFERENT";
    case DK_UNRESOLVED: return "UNRESOLVED";
    case DK_MISSING: return "MISSING";
    case DK_ERROR: return "ERROR";
    }
    return "?";
}

/* ---- the per-target caches --------------------------------------------------------------------------------------- */
static bool parse_addr(DkStr s, u32 *out) {
    s = dk_str_strip(s);
    u64 v = 0;
    size_t i = 0;
    int base = 10;
    if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X')) {
        base = 16;
        i = 2;
    }
    if (i >= s.n) return false;
    for (; i < s.n; i++) {
        char c = s.p[i];
        int d = c >= '0' && c <= '9' ? c - '0' : base == 16 && c >= 'a' && c <= 'f' ? c - 'a' + 10
                : base == 16 && c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (d < 0) return false;
        v = v * (u64)base + (u64)d;
        if (v > 0xFFFFFFFFull) return false;
    }
    *out = (u32)v;
    return true;
}

static bool json_addr(const DkJson *v, u32 *out) {
    if (!v) return false;
    if (dk_json_is_int(v)) {
        i64 x = dk_json_i64(v, -1);
        if (x < 0 || x > 0xFFFFFFFFll) return false;
        *out = (u32)x;
        return true;
    }
    return dk_json_is_str(v) && parse_addr(dk_json_str_or(v, DK_S("")), out);
}

static void put_referent(DkMap *m, DkStr name, u32 addr) {
    bool created = false;
    DkVal *v = dk_map_put(m, name, &created);
    if (created) v->u = addr;
}

/* json-symbols: {"symbol": address | {"<target>": address, ...}, ...} (a member whose value is no address, such as
 * a comment, is ignored); tsv: a header naming symbol (or name), va (or address) and optionally target. */
static bool load_referents(Cmp *c, DkErr *err) {
    DkMap *m = dk_map_new();
    c->cc->referents = m;
    size_t n = 0;
    const DkReferentFile *files = dk_project_referents(c->p, &n);
    const char *tname = dk_project_target(c->p, c->target)->name;
    for (size_t f = 0; f < n; f++) {
        DkBytes data = {0};
        if (!dk_read_all(c->a, files[f].file, &data)) {
            dk_err_set(err, DK_ERR_IO, "referents: %s: %.*s", files[f].file, DK_SF(dk_io_err_str(c->a)));
            return false;
        }
        DkStr text = {(const char *)data.v, data.n};
        if (dk_str_startswith(text, DK_S("\xEF\xBB\xBF"))) text = (DkStr){text.p + 3, text.n - 3};
        if (files[f].format && strcmp(files[f].format, "tsv") == 0) {
            DkStrVec lines = dk_str_splitlines(text, false);
            int c_name = -1, c_va = -1, c_target = -1;
            for (size_t i = 0; i < lines.n; i++) {
                DkStrVec cells = dk_str_split(lines.v[i], DK_S("\t"), -1);
                if (i == 0) {
                    for (size_t k = 0; k < cells.n; k++) {
                        DkStr h = dk_str_strip(cells.v[k]);
                        if (dk_str_eqz(h, "symbol") || (c_name < 0 && dk_str_eqz(h, "name"))) c_name = (int)k;
                        else if (dk_str_eqz(h, "va") || (c_va < 0 && dk_str_eqz(h, "address"))) c_va = (int)k;
                        else if (dk_str_eqz(h, "target")) c_target = (int)k;
                    }
                    if (c_name < 0 || c_va < 0) {
                        dk_vec_free(&cells);
                        dk_vec_free(&lines);
                        dk_err_set(err, DK_ERR_FORMAT, "referents: %s: the header needs symbol and va columns",
                                   files[f].file);
                        return false;
                    }
                } else if ((size_t)c_name < cells.n && (size_t)c_va < cells.n) {
                    u32 addr;
                    bool ours = c_target < 0 || (size_t)c_target >= cells.n || !dk_str_strip(cells.v[c_target]).n ||
                                dk_str_eqz(dk_str_strip(cells.v[c_target]), tname);
                    DkStr name = dk_str_strip(cells.v[c_name]);
                    if (ours && name.n && parse_addr(cells.v[c_va], &addr)) put_referent(m, name, addr);
                }
                dk_vec_free(&cells);
            }
            dk_vec_free(&lines);
            continue;
        }
        DkJsonError je = {0};
        DkJson *doc = dk_json_parse(c->a, text, &je);
        if (!doc || !dk_json_is_obj(doc)) {
            dk_err_set(err, DK_ERR_FORMAT, "referents: %s: not a JSON object", files[f].file);
            return false;
        }
        for (size_t i = 0; i < dk_json_len(doc); i++) {
            const DkJsonMember *mem = dk_json_member(doc, i);
            if (!mem->key.n) continue;
            u32 addr;
            const DkJson *v = mem->val;
            if (dk_json_is_obj(v)) v = dk_json_getz(v, tname);
            if (json_addr(v, &addr)) put_referent(m, mem->key, addr);
        }
    }
    return true;
}

static CompareCache *cache_of(Cmp *c, DkErr *err) {
    dk__image_lock(c->im);
    CompareCache **slot = (CompareCache **)dk__image_compare_slot(c->im);
    if (!*slot) {
        CompareCache *cc = DK_NEW(c->a, CompareCache);
        cc->by_name = dk_map_new();
        size_t nunits = 0;
        const DkUnit *units = dk_project_units(c->p, &nunits);
        DK_VEC(DkAnnot) all = {0};
        for (size_t u = 0; u < nunits; u++) {
            size_t n = 0;
            DkErr e = {0};
            DkAnnot *v = dk_annotations(c->p, &units[u], &n, &e);
            for (size_t i = 0; v && i < n; i++)
                if (v[i].target_mask & (1u << c->target)) dk_vec_push(&all, v[i]);
        }
        cc->anns = all.n ? (DkAnnot *)dk_memdup(c->a, all.v, all.n * sizeof *all.v) : NULL;
        cc->nanns = all.n;
        dk_vec_free(&all);
        c->cc = cc;
        if (!load_referents(c, err)) {
            dk__image_unlock(c->im);
            return NULL;
        }
        *slot = cc;
    }
    dk__image_unlock(c->im);
    c->cc = *slot;
    return *slot;
}

/* The address of an annotation that binds to symbol (step 2). */
static bool annotation_addr(Cmp *c, const char *symbol, u32 *addr) {
    dk__image_lock(c->im);
    const DkVal *hit = dk_map_get(c->cc->by_name, dk_str(symbol));
    u64 found;
    if (hit) {
        found = hit->u;
    } else {
        found = (u64)-1;
        bool ambiguous = false;
        DkNameRule rule = dk_project_annot_config(c->p)->name;
        const char *one[1] = {symbol};
        for (size_t i = 0; i < c->cc->nanns && !ambiguous; i++) {
            const DkAnnot *an = &c->cc->anns[i];
            u32 at = an->addr[c->target];
            if (at == DK_NO_ADDR || !dk_annot_bind(an, rule, one, 1, NULL)) continue;
            if (found == (u64)-1) found = at;
            else if (found != at) ambiguous = true;
        }
        if (ambiguous) found = (u64)-1;
        bool created = false;
        dk_map_put(c->cc->by_name, dk_str(dk_strdup(c->a, symbol)), &created)->u = found;
    }
    dk__image_unlock(c->im);
    if (found == (u64)-1) return false;
    *addr = (u32)found;
    return true;
}

static bool well_known_addr(Cmp *c, const char *symbol, u32 *addr) {
    /* the linker's image base symbol */
    if (strcmp(symbol, "___ImageBase") == 0 || strcmp(symbol, "__ImageBase") == 0) {
        *addr = dk_image_base(c->im);
        return true;
    }
    if (dk_project_well_known_imports(c->p) && strncmp(symbol, "__imp_", 6) == 0 &&
        dk__image_import_va(c->im, symbol, addr))
        return true;
    const DkStrVec *list = dk_project_well_known_symbols(c->p);
    for (size_t i = 0; list && i < list->n; i++) {
        if (strcmp(list->v[i].p, symbol) != 0) continue;
        DkSymbols *syms = dk__image_symbols(c->im);
        const DkSymbol *s = dk_symbols_find(syms, symbol);
        if (!s && symbol[0] == '_') s = dk_symbols_find(syms, symbol + 1);
        if (s) {
            *addr = s->va;
            return true;
        }
    }
    return false;
}

/* ---- relocation arithmetic --------------------------------------------------------------------------------------- */
static bool known_type(u16 t) { return t == DK_RELOC_DIR32 || t == DK_RELOC_DIR32NB || t == DK_RELOC_REL32; }

static u32 target_of_actual(const Cmp *c, const DkReloc *r, u32 word, u32 site) {
    switch (r->type) {
    case DK_RELOC_DIR32NB: return word - (u32)r->addend + dk_image_base(c->im);
    case DK_RELOC_REL32: return word + site + 4 - (u32)r->addend;
    default: return word - (u32)r->addend;
    }
}

static u32 expected_of(const Cmp *c, const DkReloc *r, u32 target, u32 site) {
    switch (r->type) {
    case DK_RELOC_DIR32NB: return target + (u32)r->addend - dk_image_base(c->im);
    case DK_RELOC_REL32: return target + (u32)r->addend - (site + 4);
    default: return target + (u32)r->addend;
    }
}

static DkRefVerdict check_reloc(Cmp *c, const DkFunc *self, u32 self_at, const DkReloc *r, DkStr theirs, int depth,
                                const Active *active, DkRefCheck *out);

/* Step 4: the content of symbol in our build against the reference's bytes at at. */
static DkRefVerdict check_content(Cmp *c, const char *symbol, u32 at, int depth, const Active *active) {
    if (depth >= CONTENT_DEPTH_LIMIT) return DK_REF_UNRESOLVED;
    for (const Active *x = active; x; x = x->up)
        if (x->at == at && strcmp(x->symbol, symbol) == 0) return DK_REF_UNRESOLVED;
    DkFunc content;
    bool is_function = false;
    if (!dk__build_content(c->root, symbol, &content, &is_function)) return DK_REF_UNRESOLVED;
    DkStr theirs;
    if (!dk_image_read(c->im, at, content.code.n, &theirs)) return DK_REF_OTHER;
    u8 *mask = (u8 *)dk_alloc(c->a, content.code.n + 4);
    for (size_t i = 0; i < content.n_relocs; i++) {
        u32 o = content.relocs[i].offset;
        for (u32 k = 0; k < 4 && (size_t)o + k < content.code.n; k++) mask[o + k] = 1;
    }
    for (size_t i = 0; i < content.code.n; i++)
        if (!mask[i] && content.code.p[i] != theirs.p[i]) return DK_REF_OTHER;
    Active me = {symbol, at, active};
    DkRefVerdict worst = DK_REF_SAME;
    for (size_t i = 0; i < content.n_relocs; i++) {
        DkRefCheck rc;
        DkRefVerdict v = check_reloc(c, &content, at, &content.relocs[i], theirs, depth + 1, &me, &rc);
        if (v == DK_REF_OTHER) return DK_REF_OTHER;
        if (v == DK_REF_UNRESOLVED) worst = DK_REF_UNRESOLVED;
    }
    return worst;
}

/* One relocation of self (whose reference copy starts at self_at, theirs its bytes). */
static DkRefVerdict check_reloc(Cmp *c, const DkFunc *self, u32 self_at, const DkReloc *r, DkStr theirs, int depth,
                                const Active *active, DkRefCheck *out) {
    memset(out, 0, sizeof *out);
    out->offset = r->offset;
    out->name = r->symbol;
    out->verdict = DK_REF_UNRESOLVED;
    if ((size_t)r->offset + 4 > theirs.n) return DK_REF_UNRESOLVED;
    u32 word;
    memcpy(&word, theirs.p + r->offset, 4);
    u32 site = self_at + r->offset;
    if (!r->symbol) { /* unnamed: the addend is our absolute target, not an offset */
        DkReloc plain = *r;
        plain.addend = 0;
        out->theirs = target_of_actual(c, &plain, word, site);
        return DK_REF_UNRESOLVED;
    }
    out->theirs = target_of_actual(c, r, word, site);
    if (!known_type(r->type)) return DK_REF_UNRESOLVED;
    const char *s = r->symbol;
    u32 expect = 0;
    bool have = false;
    bool inside = false, defined = false;
    u32 off = 0;
    if (self->symbol && strcmp(s, self->symbol) == 0) { /* 1 */
        expect = self_at;
        have = true;
    } else {
        defined = dk__build_defines(c->root, s, &inside, &off);
        if (defined && inside && self == c->root) {
            expect = self_at + off;
            have = true;
        }
    }
    if (!have) have = annotation_addr(c, s, &expect); /* 2 */
    if (!have) { /* 3 */
        const DkSymbol *sym = dk_symbols_find(dk__image_symbols(c->im), s);
        if (sym) {
            expect = sym->va;
            have = true;
        }
    }
    DkFunc probe;
    bool probe_fn = false;
    if (!have && defined && dk__build_content(c->root, s, &probe, &probe_fn)) { /* 4 */
        DkRefVerdict v = check_content(c, s, out->theirs, depth, active);
        out->verdict = v;
        if (v == DK_REF_SAME) out->ours = out->theirs;
        return v;
    }
    if (!have) { /* 5 */
        const DkVal *v = dk_map_get(c->cc->referents, dk_str(s));
        if (v) {
            expect = (u32)v->u;
            have = true;
        }
    }
    if (!have) have = well_known_addr(c, s, &expect); /* 6 */
    if (!have) return DK_REF_UNRESOLVED;
    out->ours = expect;
    out->verdict = expected_of(c, r, expect, site) == word ? DK_REF_SAME : DK_REF_OTHER;
    return out->verdict;
}

/* ---- comparing --------------------------------------------------------------------------------------------------- */
static DkResult *result_new(DkArena *a, const DkAnnot *an, int target) {
    DkResult *r = DK_NEW(a, DkResult);
    r->ann = an;
    r->target = target;
    return r;
}

static DkResult *fail(DkResult *r, DkStatus st, DkErr *err, DkArena *a, const char *fmt, const char *arg) {
    r->status = st;
    r->error = dk_sprintf(a, fmt, arg ? arg : "");
    if (st == DK_ERROR) dk_err_set(err, DK_ERR_OTHER, "%s", r->error);
    return r;
}

DkResult *dk_compare(DkProject *p, const DkAnnot *an, int target, const DkFunc *ours, DkErr *err) {
    dk_err_clear(err);
    DkArena *a = dk_project_arena(p);
    DkResult *r = result_new(a, an, target);
    if (target < 0 || (size_t)target >= dk_project_ntargets(p)) return fail(r, DK_ERROR, err, a, "no target%s", NULL);
    const char *name = an && an->name ? an->name : ours && ours->symbol ? ours->symbol : "?";
    if (!an || !(an->target_mask & (1u << target)) || an->addr[target] == DK_NO_ADDR)
        return fail(r, DK_MISSING, err, a, "%s: no address in this target", name);
    if (!ours) return fail(r, DK_MISSING, err, a, "%s: no candidate was built", name);
    r->ours = *ours;
    u32 va = an->addr[target];
    r->theirs_va = va;
    DkErr ie = {0};
    DkImage *im = dk_target_image(p, target, &ie);
    if (!im) return fail(r, DK_ERROR, err, a, "%s", ie.msg);
    Cmp c = {p, target, im, NULL, ours, a};
    if (!cache_of(&c, &ie)) return fail(r, DK_ERROR, err, a, "%s", ie.msg);
    /* the reference's size, when a sized symbol gives it */
    size_t n = ours->code.n;
    const DkSymbol *sym = dk_symbols_at(dk__image_symbols(im), va);
    bool sized = sym && sym->size;
    if (sized && n > sym->size) {
        bool padding = true;
        for (size_t i = sym->size; i < n && padding; i++)
            padding = (u8)ours->code.p[i] == 0xCC || (u8)ours->code.p[i] == 0x90;
        bool reloc_past = false;
        for (size_t i = 0; i < ours->n_relocs; i++) reloc_past |= ours->relocs[i].offset + 4 > sym->size;
        if (padding && !reloc_past) n = sym->size;
    }
    if (!sized && ours->va) {
        /* a linked candidate's end is the next map symbol: its trailing int3/nop padding is not part of it */
        size_t floor = 0;
        for (size_t i = 0; i < ours->n_relocs; i++)
            if ((size_t)ours->relocs[i].offset + 4 > floor) floor = (size_t)ours->relocs[i].offset + 4;
        while (n > floor && ((u8)ours->code.p[n - 1] == 0xCC || (u8)ours->code.p[n - 1] == 0x90)) n--;
    }
    size_t want = sized ? sym->size : n;
    DkStr theirs;
    if (!dk_image_read(im, va, want, &theirs)) {
        const char *msg = dk_sprintf(a, "%s: the image ends inside the function at %08X", name, va);
        return fail(r, DK_ERROR, err, a, "%s", msg);
    }
    r->theirs = theirs;
    r->ours.code.n = n;
    size_t common = n < want ? n : want;
    u8 *mask = (u8 *)dk_alloc(a, n + 4);
    DK_VEC(DkRefCheck) refs = {0};
    bool other = false, unresolved = false;
    for (size_t i = 0; i < ours->n_relocs; i++) {
        const DkReloc *rel = &ours->relocs[i];
        if ((size_t)rel->offset >= n) continue;
        for (u32 k = 0; k < 4 && (size_t)rel->offset + k < n; k++) mask[rel->offset + k] = 1;
        DkRefCheck rc;
        DkStr view = {theirs.p, common};
        DkRefVerdict v = check_reloc(&c, ours, va, rel, view, 0, NULL, &rc);
        other |= v == DK_REF_OTHER;
        unresolved |= v == DK_REF_UNRESOLVED;
        dk_vec_push(&refs, rc);
    }
    r->refs = refs.n ? (DkRefCheck *)dk_memdup(a, refs.v, refs.n * sizeof *refs.v) : NULL;
    r->n_refs = refs.n;
    dk_vec_free(&refs);
    bool differ = false;
    for (size_t i = 0; i < common && !differ; i++) differ = !mask[i] && ours->code.p[i] != theirs.p[i];
    if (n != want) {
        r->status = DK_SIZE;
        r->error = dk_sprintf(a, "%zu bytes, the reference has %zu", n, want);
    } else if (differ) r->status = DK_DIFF;
    else if (other) r->status = DK_REFERENT;
    else if (unresolved) r->status = DK_UNRESOLVED;
    else r->status = DK_MATCH;
    return r;
}

DkResult *dk_compare_unit(DkProject *p, const DkUnit *u, int target, const DkBuildOpts *o, size_t *n, DkErr *err) {
    *n = 0;
    dk_err_clear(err);
    DkArena *a = dk_project_arena(p);
    size_t nann = 0;
    DkAnnot *anns = dk_annotations(p, u, &nann, err);
    if (!anns && err && err->code) return NULL;
    DkErr berr = {0};
    size_t nfn = 0;
    DkStr log = {0};
    DkFunc *fns = NULL;
    bool any = false;
    for (size_t i = 0; i < nann && !any; i++)
        any = anns[i].kind == DK_ANN_FUNCTION && (anns[i].target_mask & (1u << target));
    if (any) fns = dk_build_unit(p, u, target, o, &nfn, &log, &berr);
    DkCzVec names = {0};
    for (size_t i = 0; fns && i < nfn; i++) dk_vec_push(&names, (char *)fns[i].symbol);
    DK_VEC(DkResult) out = {0};
    DkNameRule rule = dk_project_annot_config(p)->name;
    for (size_t i = 0; i < nann; i++) {
        const DkAnnot *an = &anns[i];
        if (an->kind != DK_ANN_FUNCTION || !(an->target_mask & (1u << target))) continue;
        DkResult *r;
        if (!fns) {
            r = result_new(a, an, target);
            r->status = DK_ERROR;
            r->theirs_va = an->addr[target];
            r->error = dk_strdup(a, berr.msg[0] ? berr.msg : "build failed");
        } else {
            DkErr be = {0};
            const char *sym = dk_annot_bind(an, rule, (const char *const *)names.v, names.n, &be);
            const DkFunc *fn = NULL;
            for (size_t k = 0; sym && k < nfn && !fn; k++)
                if (fns[k].symbol == sym) fn = &fns[k];
            if (fn) {
                DkErr ce = {0};
                r = dk_compare(p, an, target, fn, &ce);
            } else {
                r = result_new(a, an, target);
                r->status = DK_MISSING;
                r->theirs_va = an->addr[target];
                r->error = dk_strdup(a, be.msg[0] ? be.msg : "no candidate");
            }
        }
        dk_vec_push(&out, *r);
    }
    dk_vec_free(&names);
    DkResult *v = DK_NEWN(a, DkResult, out.n ? out.n : 1);
    if (out.n) memcpy(v, out.v, out.n * sizeof *v);
    *n = out.n;
    dk_vec_free(&out);
    if (!fns && berr.code && err) *err = berr;
    return v;
}
