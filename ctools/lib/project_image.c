// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Reference images and linked candidates: a PE32 file read once, with its base relocations (HIGHLOW words, sorted),
 * its import address table and a symbol table (the target's symbol sources, or a linker map's names). Bytes are read
 * by VA within a section's raw data; a word's target, a relocation or a branch is named through the symbols, the
 * IAT slots named "__imp_<import>". */
#include "dk/dk.h"
#include "project_backend.h"

#include <string.h>
#include <windows.h>

struct DkImage {
    DkArena *a;
    const char *path;
    DkBytes data;
    DkPe *pe;
    u32 base;
    u32 *relocs; /* VAs of the HIGHLOW words, sorted */
    size_t n_relocs;
    DkMap *import_by_name; /* import name (as the PE names it) -> IAT slot VA */
    DkIMap *import_by_va;  /* IAT slot VA -> "__imp_" + name */
    DkSymbols *syms;
    SRWLOCK lock;
    void *compare_cache;
};

static int cmp_u32(const void *x, const void *y) {
    u32 a = *(const u32 *)x, b = *(const u32 *)y;
    return a < b ? -1 : a > b;
}

static void index_imports(DkImage *im) {
    im->import_by_name = dk_map_new();
    im->import_by_va = dk_imap_new();
    DkPeImports imps = dk_pe_imports(im->pe, im->a);
    for (size_t d = 0; d < imps.n; d++) {
        const DkPeImportDll *dll = &imps.dlls[d];
        for (size_t i = 0; i < dll->n; i++) {
            const DkPeImport *imp = &dll->imports[i];
            if (!imp->name.p || imp->address > 0xFFFFFFFFull) continue;
            u32 va = (u32)imp->address;
            bool created = false;
            DkVal *v = dk_map_put(im->import_by_name, dk_str_concat(im->a, imp->name, DK_S("")), &created);
            if (created) v->u = va;
            v = dk_imap_put(im->import_by_va, va, &created);
            if (created) v->p = dk_cz(im->a, dk_str_concat(im->a, DK_S("__imp_"), imp->name));
        }
    }
}

DkImage *dk__image_open(DkArena *a, const char *path, const u8 *sha256, DkErr *err) {
    DkImage *im = DK_NEW(a, DkImage);
    im->a = a;
    im->path = dk_strdup(a, path);
    InitializeSRWLock(&im->lock);
    if (!dk_read_all(a, path, &im->data)) {
        dk_err_set(err, DK_ERR_IO, "%s: %.*s", path, DK_SF(dk_io_err_str(a)));
        return NULL;
    }
    if (sha256) {
        u8 got[32];
        dk_sha256(im->data.v, im->data.n, got);
        if (memcmp(got, sha256, 32) != 0) {
            dk_err_set(err, DK_ERR_FORMAT, "%s: sha256 %s differs from the pinned %s", path, dk_hex(a, got, 32),
                       dk_hex(a, sha256, 32));
            return NULL;
        }
    }
    DkTry tr;
    if (DK_TRY(&tr)) {
        im->pe = dk_pe_parse(a, im->data.v, im->data.n);
        if (im->pe->pe_type != DK_PE_MAGIC_PE32 || im->pe->image_base > 0xFFFFFFFFull)
            dk_throw(DK_ERR_FORMAT, "not a PE32 image");
        im->base = (u32)im->pe->image_base;
        size_t n = 0;
        bool present = false;
        u32 *rvas = dk_pe_reloc_rvas(im->pe, a, DK_PE_REL_BASED_HIGHLOW, &n, &present);
        im->relocs = DK_NEWN(a, u32, n ? n : 1);
        for (size_t i = 0; i < n; i++) im->relocs[i] = im->base + rvas[i];
        qsort(im->relocs, n, sizeof *im->relocs, cmp_u32);
        im->n_relocs = n;
        index_imports(im);
        dk_try_end(&tr);
    } else {
        dk_err_set(err, DK_ERR_FORMAT, "%s: %s", path, tr.msg);
        return NULL;
    }
    im->syms = dk_symbols_new(a);
    return im;
}

void dk__image_set_symbols(DkImage *im, DkSymbols *syms) { im->syms = syms ? syms : dk_symbols_new(im->a); }
DkSymbols *dk__image_symbols(const DkImage *im) { return im->syms; }
u32 dk__image_base(const DkImage *im) { return im->base; }
const char *dk__image_path(const DkImage *im) { return im->path; }
void dk__image_lock(DkImage *im) { AcquireSRWLockExclusive(&im->lock); }
void dk__image_unlock(DkImage *im) { ReleaseSRWLockExclusive(&im->lock); }
void **dk__image_compare_slot(DkImage *im) { return &im->compare_cache; }

DkImage *dk_target_image(DkProject *p, int target, DkErr *err) {
    if (target < 0 || (size_t)target >= dk_project_ntargets(p)) {
        dk_err_set(err, DK_ERR_OTHER, "image: no target %d", target);
        return NULL;
    }
    DkTarget *t = dk_project_target_mut(p, target);
    if (t->image) return t->image;
    if (!t->image_path) {
        dk_err_set(err, DK_ERR_OTHER, "target %s: no image configured", t->name);
        return NULL;
    }
    DkErr e = {0};
    DkImage *im = dk__image_open(dk_project_arena(p), t->image_path, t->has_sha256 ? t->sha256 : NULL, &e);
    if (!im) {
        dk_err_set(err, e.code, "target %s: %s", t->name, e.msg);
        return NULL;
    }
    if (t->image_base && t->image_base != im->base) {
        dk_err_set(err, DK_ERR_FORMAT, "target %s: image base %08X, configured %08X", t->name, im->base,
                   t->image_base);
        return NULL;
    }
    DkSymbols *syms = dk_project_symbols(p, target, err);
    if (!syms) return NULL;
    im->syms = syms;
    t->image = im;
    return im;
}

/* The section holding rva, with the raw bytes it has there. */
static const DkPeSection *section_of(const DkImage *im, u32 va) {
    if (va < im->base) return NULL;
    return dk_pe_section_by_rva(im->pe, (u64)(va - im->base));
}

bool dk_image_read(const DkImage *im, u32 va, size_t n, DkStr *out) {
    if (!im || va < im->base) return false;
    u64 rva = (u64)(va - im->base);
    const DkPeSection *s = section_of(im, va);
    if (!s || rva + n > (u64)s->virtual_address + s->size_of_raw_data) return false;
    DkPeSpan span;
    if (!dk_pe_try_get_data(im->pe, rva, (i64)n, &span) || span.n != n) return false;
    out->p = (const char *)span.p;
    out->n = n;
    return true;
}

const char *dk__image_import_at(const DkImage *im, u32 va) {
    const DkVal *v = dk_imap_get(im->import_by_va, va);
    return v ? (const char *)v->p : NULL;
}

bool dk__image_import_va(const DkImage *im, const char *name, u32 *va) {
    DkStr s = dk_str(name);
    if (dk_str_startswith(s, DK_S("__imp_"))) s = (DkStr){s.p + 6, s.n - 6};
    for (int pass = 0; pass < 3; pass++) {
        const DkVal *v = dk_map_get(im->import_by_name, s);
        if (v) {
            *va = (u32)v->u;
            return true;
        }
        if (pass == 0) { /* the C name: one leading underscore */
            if (!s.n || s.p[0] != '_') continue;
            s = (DkStr){s.p + 1, s.n - 1};
        } else if (pass == 1) { /* the stdcall suffix @N */
            i64 at = -1;
            for (size_t i = s.n; i-- > 0;)
                if (s.p[i] == '@') {
                    at = (i64)i;
                    break;
                }
            if (at <= 0) return false;
            s.n = (size_t)at;
        }
    }
    return false;
}

const char *dk_image_name_at(const DkImage *im, u32 va, u32 *start) {
    if (start) *start = 0;
    if (!im) return NULL;
    const char *imp = dk__image_import_at(im, va);
    if (imp) {
        if (start) *start = va;
        return imp;
    }
    u32 at = 0;
    const DkSymbol *s = dk_symbols_containing(im->syms, va, &at);
    if (!s) return NULL;
    if (!(s->size && va < (u64)at + s->size)) {
        /* nearest below: only within the same section, and when no sized symbol says it ends before va */
        if (s->size || section_of(im, at) != section_of(im, va)) return NULL;
    }
    if (start) *start = at;
    return s->name;
}

bool dk_image_function_size(const DkImage *im, u32 va, u32 *size) {
    if (!im) return false;
    const DkSymbol *s = dk_symbols_at(im->syms, va);
    if (s && s->size) {
        *size = s->size;
        return true;
    }
    if (!s) return false;
    u32 next = dk_symbols_next(im->syms, va);
    const DkPeSection *sec = section_of(im, va);
    if (!sec) return false;
    u32 end = im->base + sec->virtual_address + sec->size_of_raw_data;
    if (next && next > va && next <= end) end = next;
    if (end <= va) return false;
    *size = end - va;
    return true;
}

/* The name of a relocation's target: an import slot, a symbol starting there, or a sized symbol holding it (never
 * the nearest symbol below: an unnamed target, such as compiler-made data a map does not list, stays unnamed). */
static const char *reloc_target_name(const DkImage *im, u32 va, u32 *start) {
    const char *imp = dk__image_import_at(im, va);
    if (imp) {
        *start = va;
        return imp;
    }
    const DkSymbol *exact = dk_symbols_at(im->syms, va);
    if (exact) {
        *start = va;
        return exact->name;
    }
    u32 at = 0;
    const DkSymbol *s = dk_symbols_containing(im->syms, va, &at);
    if (!s || !(s->size && va < (u64)at + s->size)) return NULL;
    *start = at;
    return s->name;
}

bool dk__image_word_reloc(const DkImage *im, u32 site, DkArena *a, DkReloc *out) {
    size_t lo = 0, hi = im->n_relocs;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (im->relocs[mid] < site) lo = mid + 1;
        else hi = mid;
    }
    if (lo >= im->n_relocs || im->relocs[lo] != site) return false;
    DkStr w;
    memset(out, 0, sizeof *out);
    out->type = DK_RELOC_DIR32;
    if (!dk_image_read(im, site, 4, &w)) return true;
    u32 target;
    memcpy(&target, w.p, 4);
    u32 start = 0;
    const char *name = reloc_target_name(im, target, &start);
    if (name) {
        out->symbol = dk_strdup(a, name);
        out->addend = (i32)(target - start);
    } else {
        out->addend = (i32)target;
    }
    return true;
}

const DkReloc *dk_image_relocs(const DkImage *im, u32 va, size_t n, size_t *count) {
    *count = 0;
    if (!im) return NULL;
    size_t lo = 0, hi = im->n_relocs;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (im->relocs[mid] < va) lo = mid + 1;
        else hi = mid;
    }
    size_t first = lo, last = lo;
    while (last < im->n_relocs && (u64)im->relocs[last] + 4 <= (u64)va + n) last++;
    if (last == first) return NULL;
    DkReloc *v = DK_NEWN(im->a, DkReloc, last - first);
    for (size_t i = first; i < last; i++) {
        dk__image_word_reloc(im, im->relocs[i], im->a, &v[i - first]);
        v[i - first].offset = im->relocs[i] - va;
    }
    *count = last - first;
    return v;
}

void dk__image_branch_relocs(const DkImage *im, u32 va, DkStr code, DkArena *a, DkRelocVec *out) {
    DkDisIter it;
    dk_dis_iter(&it, dk_dis(DK_DIS_X86_32, DK_DIS_SKIPDATA), code.p, code.n, va, 0);
    while (dk_dis_next(&it)) {
        const cs_insn *in = it.insn;
        u32 field;
        if (in->size == 5 && (in->bytes[0] == 0xE8 || in->bytes[0] == 0xE9)) field = 1;
        else if (in->size == 6 && in->bytes[0] == 0x0F && (in->bytes[1] & 0xF0) == 0x80) field = 2;
        else continue;
        i32 disp;
        memcpy(&disp, in->bytes + field, 4);
        u32 next = (u32)in->address + in->size;
        u32 target = next + (u32)disp;
        if (target >= va && (u64)target < (u64)va + code.n) continue;
        DkReloc r = {0};
        r.offset = (u32)in->address - va + field;
        r.type = DK_RELOC_REL32;
        u32 start = 0;
        const char *name = reloc_target_name(im, target, &start);
        if (name) {
            r.symbol = dk_strdup(a, name);
            r.addend = (i32)(target - start);
        } else {
            r.addend = (i32)target;
        }
        dk_vec_push(out, r);
    }
    dk_dis_iter_end(&it);
}

u32 dk__image_section_end(const DkImage *im, u32 va) {
    const DkPeSection *s = section_of(im, va);
    if (!s) return 0;
    u32 size = s->virtual_size && s->virtual_size < s->size_of_raw_data ? s->virtual_size : s->size_of_raw_data;
    return im->base + s->virtual_address + size;
}
