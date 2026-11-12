// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Reference-image disassembly and cross references for the configured targets (lib/disasm.h). */
#include "disasm.h"

#include "dk/args.h"
#include "dk/disasm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char disasm_doc[] =
#include "disasm_doc.inc"
    "";

struct DkDisasm {
    DkArena *a;
    DkProject *p;
    int target;
    const char *name;
    const DkImage *im; /* the target's reference image (lib/project.h) */
    u32 base;
    const DkImageSection *code; /* the code section */
    u32 code_va, code_vsize;
    const u8 *code_p;
    size_t code_n;
    const u32 *relocs; /* VAs of the HIGHLOW words, sorted */
    size_t n_relocs;
    DkIMap *thunks;  /* VA of a `jmp dword ptr [slot]` -> the import's name */
    DkSymbols *syms;
    u32 cookie;
    DkU32Vec starts;
    bool starts_done;
    DkIMap *annotated;  /* annotated VA -> "kind name" */
    DkISet *ann_starts; /* function and declaration annotations */
    bool ann_done;
};

static int cmp_u32(const void *x, const void *y) {
    u32 a = *(const u32 *)x, b = *(const u32 *)y;
    return a < b ? -1 : a > b;
}

static i32 rel_at(const u8 *p) {
    i32 v;
    memcpy(&v, p, 4);
    return v;
}

static const DkImageSection *sec_of(const DkDisasm *d, u32 va) { return dk_image_section_of(d->im, va); }

/* n bytes at va, inside one section's raw data. */
static bool rd(const DkDisasm *d, u32 va, size_t n, DkStr *out) {
    const DkImageSection *s = sec_of(d, va);
    if (!s || (u64)va + n > (u64)s->va + s->raw_size) return false;
    if (!n) {
        *out = (DkStr){"", 0};
        return true;
    }
    return dk_image_read(d->im, va, n, out);
}

static bool read_u32(const DkDisasm *d, u32 va, u32 *out) {
    DkStr s;
    if (!rd(d, va, 4, &s)) return false;
    memcpy(out, s.p, 4);
    return true;
}

static void not_in_image(const DkDisasm *d, u32 va, DkErr *err) {
    dk_err_set(err, DK_ERR_OTHER, "address %08X is not in the image of %s", va, d->name);
}

static size_t lower_bound_u32(const u32 *v, size_t n, u32 x) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (v[mid] < x) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static size_t upper_bound_u32(const u32 *v, size_t n, u32 x) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (x < v[mid]) hi = mid;
        else lo = mid + 1;
    }
    return lo;
}

const char *dk_disasm_target_name(const DkDisasm *d) { return d->name; }
u32 dk_disasm_image_base(const DkDisasm *d) { return d->base; }

/* ---- opening ----------------------------------------------------------------------------------------------------- */

DkDisasm *dk_disasm_open(DkProject *p, int target, DkErr *err) {
    const DkImage *im = dk_target_image(p, target, err); /* the pinned sha256, the symbol sources */
    if (!im) return NULL;
    const DkTarget *t = dk_project_target(p, target);
    DkArena *a = dk_project_arena(p);
    DkDisasm *d = DK_NEW(a, DkDisasm);
    d->a = a;
    d->p = p;
    d->target = target;
    d->name = t->name;
    d->im = im;
    d->base = dk_image_base(im);
    d->relocs = dk_image_base_relocs(im, &d->n_relocs);
    d->cookie = dk_image_security_cookie(im);
    size_t n_sections = 0, file_n = 0;
    const DkImageSection *sections = dk_image_sections(im, &n_sections);
    for (size_t i = 0; i < n_sections && !d->code; i++)
        if (dk_str_eqz(sections[i].name, ".text")) d->code = &sections[i];
    for (size_t i = 0; i < n_sections && !d->code; i++)
        if (sections[i].chars & 0x20000000u) d->code = &sections[i];
    if (!d->code) {
        dk_err_set(err, DK_ERR_FORMAT, "%s: no code section", t->image_path);
        return NULL;
    }
    const u8 *file = dk_image_file(im, &file_n);
    d->code_va = d->code->va;
    d->code_vsize = d->code->vsize ? d->code->vsize : d->code->raw_size;
    if (d->code->raw < file_n) {
        d->code_p = file + d->code->raw;
        d->code_n = d->code->raw_size;
        if (d->code_n > file_n - d->code->raw) d->code_n = file_n - d->code->raw;
    }
    d->syms = dk_project_symbols(p, target, err);
    if (!d->syms) return NULL;
    return d;
}

/* Whether a base relocation covers the word at va. */
static bool has_reloc(const DkDisasm *d, u32 va) {
    size_t k = lower_bound_u32(d->relocs, d->n_relocs, va);
    return k < d->n_relocs && d->relocs[k] == va;
}

/* {VA of `jmp dword ptr [slot]`: the import's name} for the relocated slots of the code section. */
static DkIMap *thunk_map(DkDisasm *d) {
    if (d->thunks) return d->thunks;
    d->thunks = dk_imap_new();
    for (size_t i = 0; i < d->n_relocs; i++) {
        u32 site = d->relocs[i], slot;
        if (site < d->code_va + 2 || site >= d->code_va + d->code_n) continue;
        size_t off = site - d->code_va;
        if (d->code_p[off - 2] != 0xFF || d->code_p[off - 1] != 0x25) continue;
        if (!read_u32(d, site, &slot)) continue;
        const char *imp = dk_image_import_at(d->im, slot);
        if (imp) dk_imap_put(d->thunks, site - 2, NULL)->p = (char *)imp + 6; /* past "__imp_" */
    }
    return d->thunks;
}

/* ---- annotations ------------------------------------------------------------------------------------------------- */

static void annotations_load(DkDisasm *d) {
    if (d->ann_done) return;
    d->ann_done = true;
    d->annotated = dk_imap_new();
    d->ann_starts = dk_iset_new();
    static const char *const kinds[] = {"function", "data", "decl", "vtable"};
    size_t nu = 0;
    const DkUnit *units = dk_project_units(d->p, &nu);
    for (size_t i = 0; i < nu; i++) {
        if (!((units[i].target_mask >> d->target) & 1u)) continue;
        size_t na = 0;
        DkErr e = {0};
        const DkAnnot *an = dk_annotations(d->p, &units[i], &na, &e);
        if (!an) continue; /* a unit that cannot be read or parsed adds nothing */
        for (size_t k = 0; k < na; k++) {
            u32 va = an[k].addr[d->target];
            if (va == DK_NO_ADDR) continue;
            if (an[k].kind == DK_ANN_FUNCTION || an[k].kind == DK_ANN_DECL) dk_iset_add(d->ann_starts, va);
            if (an[k].name && *an[k].name && !dk_imap_has(d->annotated, va))
                dk_imap_put(d->annotated, va, NULL)->p = dk_sprintf(d->a, "%s %s", kinds[an[k].kind], an[k].name);
        }
    }
}

/* ---- containing function, bounds ---------------------------------------------------------------------------------- */

bool dk_disasm_containing_function(const DkDisasm *d, u32 va, u32 *start, const char **name) {
    u32 s = 0;
    const DkSymbol *sym = dk_symbols_containing(d->syms, va, &s);
    if (!sym) return false;
    u64 size = sym->size ? sym->size : 1;
    if ((u64)va >= (u64)s + size) return false;
    if (start) *start = s;
    if (name) *name = sym->name;
    return true;
}

const DkU32Vec *dk_disasm_known_starts(DkDisasm *d) {
    if (d->starts_done) return &d->starts;
    d->starts_done = true;
    annotations_load(d);
    DkISet *starts = dk_iset_new();
    size_t pos = 0;
    u64 v;
    while (dk_iset_next(d->ann_starts, &pos, &v)) dk_iset_add(starts, v);
    size_t nsym = 0;
    dk_symbols_all(d->syms, &nsym);
    if (nsym) {
        DkISet *referenced = dk_iset_new();
        const u8 *code = d->code_p;
        size_t at = 0;
        while (at + 5 <= d->code_n) {
            const u8 *hit = memchr(code + at, 0xE8, d->code_n - 5 + 1 - at);
            if (!hit) break;
            at = (size_t)(hit - code);
            u32 target = d->code_va + (u32)at + 5 + (u32)rel_at(code + at + 1);
            if (target >= d->code_va && target < d->code_va + d->code_vsize && dk_symbols_at(d->syms, target))
                dk_iset_add(referenced, target);
            at++;
        }
        for (size_t i = 0; i < d->n_relocs; i++) {
            u32 target;
            if (!read_u32(d, d->relocs[i], &target)) continue;
            if (target >= d->code_va && target < d->code_va + d->code_vsize && dk_symbols_at(d->syms, target))
                dk_iset_add(referenced, target);
        }
        pos = 0;
        while (dk_iset_next(referenced, &pos, &v)) dk_iset_add(starts, v);
        dk_iset_free(referenced);
    }
    DkU64Vec sorted = dk_iset_sorted(starts);
    for (size_t i = 0; i < sorted.n; i++) dk_vec_push(&d->starts, (u32)sorted.v[i]);
    dk_vec_free(&sorted);
    dk_iset_free(starts);
    return &d->starts;
}

bool dk_disasm_guess_size(const DkDisasm *d, u32 address, u32 limit, u32 *size, DkErr *err) {
    const DkImageSection *s = sec_of(d, address);
    if (!s) {
        not_in_image(d, address, err);
        return false;
    }
    u64 avail = (u64)s->va + s->raw_size;
    avail = avail > address ? avail - address : 0;
    if (limit > avail) limit = (u32)avail;
    DkStr code;
    if (!rd(d, address, limit, &code)) {
        not_in_image(d, address, err);
        return false;
    }
    DkDisIter it;
    dk_dis_iter(&it, dk_dis(DK_DIS_X86_32, 0), code.p, code.n, address, 0);
    u32 end = 0;
    while (dk_dis_next(&it)) {
        const cs_insn *ins = it.insn;
        u32 off = (u32)(ins->address - address) + ins->size;
        end = off;
        const char *m = ins->mnemonic;
        if ((strcmp(m, "ret") == 0 || strcmp(m, "jmp") == 0 || strcmp(m, "int3") == 0) && off < code.n &&
            (u8)code.p[off] == 0xCC)
            break;
        if (strcmp(m, "int3") == 0) {
            end = off - ins->size;
            break;
        }
    }
    dk_dis_iter_end(&it);
    *size = end;
    return true;
}

bool dk_disasm_function_bounds(DkDisasm *d, u32 address, u32 limit, DkDisasmBounds *out, DkErr *err) {
    const DkU32Vec *starts = dk_disasm_known_starts(d);
    size_t k = upper_bound_u32(starts->v, starts->n, address);
    bool has_next = k < starts->n;
    u32 next_start = has_next ? starts->v[k] : 0;
    if (has_next && next_start - address < limit) limit = next_start - address;
    u32 size;
    if (!dk_disasm_guess_size(d, address, limit, &size, err)) return false;
    if (has_next && (u64)address + size >= next_start) {
        out->size = next_start - address;
        out->why = dk_sprintf(d->a, "to the next known start %08X", next_start);
        return true;
    }
    out->size = size;
    out->why = "to the int3 padding";
    return true;
}

/* ---- listing ------------------------------------------------------------------------------------------------------ */

/* The first "0x" + at least five lower-case hex digits of an operand text. */
static bool find_hex_target(const char *s, u64 *out) {
    size_t n = strlen(s);
    for (size_t i = 0; i + 2 < n; i++) {
        if (s[i] != '0' || s[i + 1] != 'x') continue;
        size_t j = i + 2;
        u64 v = 0;
        while (j < n && ((s[j] >= '0' && s[j] <= '9') || (s[j] >= 'a' && s[j] <= 'f'))) {
            v = v * 16 + (u64)(s[j] <= '9' ? s[j] - '0' : s[j] - 'a' + 10);
            j++;
        }
        if (j - (i + 2) >= 5) {
            *out = v;
            return true;
        }
    }
    return false;
}

static const char *symbol_name_at(const DkDisasm *d, u32 va) {
    const DkSymbol *s = dk_symbols_at(d->syms, va);
    return s && s->name && *s->name ? s->name : NULL;
}

bool dk_disasm_function(DkDisasm *d, u32 address, i64 size, bool show_bytes, DkBuf *out, DkErr *err) {
    DkStr code;
    if (!rd(d, address, size > 0 ? (size_t)size : 0, &code)) {
        not_in_image(d, address, err);
        return false;
    }
    DkIMap *thunks = thunk_map(d);
    const char *name = symbol_name_at(d, address);
    if (name) dk_buf_printf(out, "; %s %08X  %lld bytes  %s\n", d->name, address, (long long)size, name);
    else dk_buf_printf(out, "; %s %08X  %lld bytes\n", d->name, address, (long long)size);
    DkDisIter it;
    dk_dis_iter(&it, dk_dis(DK_DIS_X86_32, 0), code.p, code.n, address, 0);
    while (dk_dis_next(&it)) {
        const cs_insn *ins = it.insn;
        const char *note = NULL;
        u64 target;
        if (find_hex_target(ins->op_str, &target)) {
            bool is32 = target <= 0xFFFFFFFFu;
            const char *sym = is32 ? symbol_name_at(d, (u32)target) : NULL;
            const DkVal *tv = is32 ? dk_imap_get(thunks, target) : NULL;
            const char *imp = is32 ? dk_image_import_at(d->im, (u32)target) : NULL;
            if (sym) {
                note = sym;
            } else if (tv) {
                note = dk_sprintf(d->a, "%s (import thunk)", (const char *)tv->p);
            } else if (imp) {
                note = imp;
            } else if (d->cookie && target == d->cookie) {
                note = "__security_cookie";
            } else if (ins->mnemonic[0] == 'j' || strcmp(ins->mnemonic, "call") == 0) {
                u32 f;
                const char *fname;
                if (is32 && dk_disasm_containing_function(d, (u32)target, &f, &fname) && *fname && f != address)
                    note = dk_sprintf(d->a, "%s+0x%X", fname, (u32)target - f);
            }
        }
        dk_buf_printf(out, "%08X  ", (u32)ins->address);
        if (show_bytes) {
            char hex[16 * 3 + 1];
            size_t h = 0;
            for (u16 i = 0; i < ins->size && i < 16; i++)
                h += (size_t)snprintf(hex + h, sizeof hex - h, i ? " %02X" : "%02X", ins->bytes[i]);
            dk_buf_printf(out, "%-24s", hex);
        }
        dk_buf_printf(out, "%s %s", ins->mnemonic, ins->op_str);
        if (note && *note) dk_buf_printf(out, "  ; %s", note);
        dk_buf_putc(out, '\n');
    }
    dk_dis_iter_end(&it);
    return true;
}

/* ---- rel32 sites -------------------------------------------------------------------------------------------------- */

const char *dk_disasm_kind_name(DkDisasmKind kind) {
    return kind == DK_DISASM_CALL ? "call" : kind == DK_DISASM_JMP ? "jmp" : "jcc";
}

typedef struct {
    u32 site, target;
} RawHit;
typedef DK_VEC(RawHit) RawHitVec;
enum { N_KINDS = 18 }; /* call, jmp, then jcc 0F 80..0F 8F */

static int cmp_site(const void *x, const void *y) {
    const DkDisasmSite *p = x, *q = y;
    if (p->site != q->site) return p->site < q->site ? -1 : 1;
    return strcmp(dk_disasm_kind_name(p->kind), dk_disasm_kind_name(q->kind));
}

DkIMap *dk_disasm_rel32_sites(const DkDisasm *d, const DkU32Vec *targets, unsigned kinds) {
    DkISet *wanted = dk_iset_new();
    for (size_t i = 0; i < targets->n; i++) dk_iset_add(wanted, targets->v[i]);
    const u8 *code = d->code_p;
    size_t n = d->code_n;
    bool want_call = kinds & DK_DISASM_CALL, want_jmp = kinds & DK_DISASM_JMP, want_jcc = kinds & DK_DISASM_JCC;
    RawHitVec hits[N_KINDS];
    memset(hits, 0, sizeof hits);
    for (size_t at = 0; at < n; at++) {
        u8 b = code[at];
        if (b == 0xE8) {
            if (want_call && at + 5 <= n) {
                u32 t = d->code_va + (u32)at + 5 + (u32)rel_at(code + at + 1);
                if (dk_iset_has(wanted, t)) dk_vec_push(&hits[0], ((RawHit){d->code_va + (u32)at, t}));
            }
        } else if (b == 0xE9) {
            if (want_jmp && at + 5 <= n) {
                u32 t = d->code_va + (u32)at + 5 + (u32)rel_at(code + at + 1);
                if (dk_iset_has(wanted, t)) dk_vec_push(&hits[1], ((RawHit){d->code_va + (u32)at, t}));
            }
        } else if (b == 0x0F && want_jcc && at + 1 < n && (code[at + 1] & 0xF0) == 0x80) {
            if (at + 6 <= n) {
                u32 t = d->code_va + (u32)at + 6 + (u32)rel_at(code + at + 2);
                if (dk_iset_has(wanted, t))
                    dk_vec_push(&hits[2 + (code[at + 1] - 0x80)], ((RawHit){d->code_va + (u32)at, t}));
            }
        }
    }
    DkIMap *found = dk_imap_new();
    for (int k = 0; k < N_KINDS; k++) {
        DkDisasmKind kind = k == 0 ? DK_DISASM_CALL : k == 1 ? DK_DISASM_JMP : DK_DISASM_JCC;
        for (size_t i = 0; i < hits[k].n; i++) {
            bool created;
            DkVal *slot = dk_imap_put(found, hits[k].v[i].target, &created);
            if (created) slot->p = DK_NEW(d->a, DkDisasmSiteVec);
            DkDisasmSiteVec *sv = (DkDisasmSiteVec *)slot->p;
            DkDisasmSite s = {hits[k].v[i].site, kind};
            dk_vec_push(sv, s);
        }
        dk_vec_free(&hits[k]);
    }
    DkIMapIter it = {0};
    while (dk_imap_next(found, &it)) {
        DkDisasmSiteVec *sv = (DkDisasmSiteVec *)it.val->p;
        qsort(sv->v, sv->n, sizeof(DkDisasmSite), cmp_site);
    }
    dk_iset_free(wanted);
    return found;
}

/* ---- cross references --------------------------------------------------------------------------------------------- */

/* "name (ADDR)" of the symbol containing va, or NULL. */
static const char *function_text(const DkDisasm *d, u32 va) {
    u32 f;
    const char *name;
    if (dk_disasm_containing_function(d, va, &f, &name) && *name) return dk_sprintf(d->a, "%s (%08X)", name, f);
    return NULL;
}

/* Where a site is: the containing function inside the code section, else the section's name. */
static const char *where_text(const DkDisasm *d, u32 va, const char *f) {
    const DkImageSection *s = sec_of(d, va);
    if (f && s && dk_str_eqz(s->name, ".text")) return f;
    return s ? dk_cz(d->a, s->name) : "?";
}

bool dk_disasm_xrefs(DkDisasm *d, u32 address, DkBuf *out, DkErr *err) {
    (void)err;
    DkU32Vec target = {0};
    dk_vec_push(&target, address);
    DkIMap *all = dk_disasm_rel32_sites(d, &target, DK_DISASM_ALL);
    dk_vec_free(&target);
    const DkVal *sv = dk_imap_get(all, address);
    const DkDisasmSiteVec *sites = sv ? (const DkDisasmSiteVec *)sv->p : NULL;
    static const struct {
        DkDisasmKind kind;
        const char *what;
    } order[3] = {{DK_DISASM_CALL, "callers of"}, {DK_DISASM_JMP, "jumps to"}, {DK_DISASM_JCC, "conditional jumps to"}};
    for (int o = 0; o < 3; o++) {
        DkU32Vec found = {0};
        for (size_t i = 0; sites && i < sites->n; i++)
            if (sites->v[i].kind == order[o].kind) dk_vec_push(&found, sites->v[i].site);
        if (order[o].kind != DK_DISASM_CALL && found.n == 0) continue;
        dk_buf_printf(out, "; %s %08X (%s rel32): %zu\n", order[o].what, address, dk_disasm_kind_name(order[o].kind),
                      found.n);
        for (size_t i = 0; i < found.n; i++) {
            const char *f = function_text(d, found.v[i]);
            dk_buf_printf(out, "  %08X  in %s\n", found.v[i], f ? f : "?");
        }
        dk_vec_free(&found);
    }
    DkU32Vec absolute = {0};
    for (size_t i = 0; i < d->n_relocs; i++) {
        u32 value;
        if (read_u32(d, d->relocs[i], &value) && value == address) dk_vec_push(&absolute, d->relocs[i]);
    }
    dk_buf_printf(out, "; absolute references (relocated words) to %08X: %zu\n", address, absolute.n);
    for (size_t i = 0; i < absolute.n; i++)
        dk_buf_printf(out, "  %08X  in %s\n", absolute.v[i],
                      where_text(d, absolute.v[i], function_text(d, absolute.v[i])));
    dk_vec_free(&absolute);
    return true;
}

/* ---- thunks ------------------------------------------------------------------------------------------------------- */

bool dk_disasm_jmp_thunk(const DkDisasm *d, u32 va, const char **form, u32 *target, u32 *this_, bool *has_this) {
    DkStr code;
    if (!rd(d, va, 10, &code)) return false;
    const u8 *c = (const u8 *)code.p;
    if (c[0] == 0xE9) {
        *form = "jmp";
        *target = va + 5 + (u32)rel_at(c + 1);
        *this_ = 0;
        *has_this = false;
        return true;
    }
    if (c[0] == 0xB9 && c[5] == 0xE9) {
        *form = "mov ecx; jmp";
        *target = va + 10 + (u32)rel_at(c + 6);
        memcpy(this_, c + 1, 4);
        *has_this = true;
        return true;
    }
    return false;
}

static DkU32Vec *vec_for(DkDisasm *d, DkIMap *m, u32 key) {
    bool created;
    DkVal *slot = dk_imap_put(m, key, &created);
    if (created) slot->p = DK_NEW(d->a, DkU32Vec);
    return (DkU32Vec *)slot->p;
}

DkDisasmThunkVec dk_disasm_hidden_thunks(DkDisasm *d, u32 start, u32 end, bool everything) {
    u32 lo = d->code_va, hi = d->code_va + d->code_vsize;
    if (start && start > lo) lo = start;
    if (end && end < hi) hi = end;
    DkIMap *refs = dk_imap_new();
    for (size_t i = 0; i < d->n_relocs; i++) {
        u32 target;
        if (!read_u32(d, d->relocs[i], &target)) continue;
        if (lo <= target && target < hi) dk_vec_push(vec_for(d, refs, target), d->relocs[i]);
    }
    const u8 *code = d->code_p;
    DkIMap *calls = dk_imap_new();
    size_t at = 0;
    while (at + 5 <= d->code_n) {
        const u8 *hit = memchr(code + at, 0xE8, d->code_n - 5 + 1 - at);
        if (!hit) break;
        at = (size_t)(hit - code);
        u32 target = d->code_va + (u32)at + 5 + (u32)rel_at(code + at + 1);
        if (lo <= target && target < hi) dk_vec_push(vec_for(d, calls, target), d->code_va + (u32)at);
        at++;
    }
    const DkU32Vec *known_starts = dk_disasm_known_starts(d);
    DkU32Vec keys = {0};
    DkIMapIter it = {0};
    while (dk_imap_next(refs, &it)) dk_vec_push(&keys, (u32)it.key);
    it = (DkIMapIter){0};
    while (dk_imap_next(calls, &it))
        if (!dk_imap_has(refs, it.key)) dk_vec_push(&keys, (u32)it.key);
    qsort(keys.v, keys.n, sizeof(u32), cmp_u32);
    DkDisasmThunkVec out = {0};
    for (size_t i = 0; i < keys.n; i++) {
        u32 va = keys.v[i];
        const char *form;
        u32 target, this_;
        bool has_this;
        if (!dk_disasm_jmp_thunk(d, va, &form, &target, &this_, &has_this) ||
            !(d->code_va <= target && target < d->code_va + d->code_vsize))
            continue;
        /* a function start: 16-byte aligned (/Gy) or after int3 padding; a `jmp` that opens a switch case (its jump
         * table is a relocated word too) is neither */
        if (va % 16) {
            i64 idx = (i64)va - (i64)d->code_va - 1;
            if (idx < 0) idx += (i64)d->code_n;
            if (idx < 0 || idx >= (i64)d->code_n || code[idx] != 0xCC) continue;
        }
        bool known = dk_symbols_at(d->syms, va) != NULL;
        if (!known) {
            size_t k = lower_bound_u32(known_starts->v, known_starts->n, va);
            known = k < known_starts->n && known_starts->v[k] == va;
        }
        if (known && !everything) continue;
        DkDisasmThunk *t = dk_vec_push_zero(&out);
        t->va = va;
        t->form = form;
        t->target = target;
        t->this_ = this_;
        t->has_this = has_this;
        const DkVal *rv = dk_imap_get(refs, va), *cv = dk_imap_get(calls, va);
        if (rv) t->refs = *(DkU32Vec *)rv->p;
        if (cv) t->calls = *(DkU32Vec *)cv->p;
        t->known = known;
    }
    dk_vec_free(&keys);
    return out;
}

void dk_disasm_print_thunks(DkDisasm *d, u32 start, u32 end, bool everything, DkBuf *out) {
    DkDisasmThunkVec rows = dk_disasm_hidden_thunks(d, start, end, everything);
    const char *what = everything ? "" : " no symbol names";
    if (start) {
        if (!end) end = d->code_va + d->code_vsize;
        dk_buf_printf(out, "; %zu jmp thunk(s)%s in %08X-%08X\n", rows.n, what, start, end);
    } else {
        dk_buf_printf(out, "; %zu jmp thunk(s)%s\n", rows.n, what);
    }
    for (size_t i = 0; i < rows.n; i++) {
        const DkDisasmThunk *t = &rows.v[i];
        const char *tname = symbol_name_at(d, t->target);
        DkStr ts = dk_u8_slice(dk_str(tname ? tname : "?"), 0, 40);
        u32 first = t->refs.n ? t->refs.v[0] : t->calls.v[0];
        const char *where = where_text(d, first, function_text(d, first));
        dk_buf_printf(out, "%08X  %-13s -> %08X %-*.*s ", t->va, t->form, t->target, 40, (int)ts.n, ts.p);
        if (t->has_this) dk_buf_printf(out, "this %08X; ", t->this_);
        dk_buf_printf(out, "%zu abs ref(s), %zu call(s); first %08X in %s%s\n", t->refs.n, t->calls.n, first, where,
                      t->known ? "  (known)" : "");
    }
}

/* ---- dword dumps -------------------------------------------------------------------------------------------------- */

bool dk_disasm_words(DkDisasm *d, u32 address, u32 count, DkBuf *out) {
    annotations_load(d);
    DkIMap *thunks = thunk_map(d);
    const DkImageSection *sec = sec_of(d, address);
    const char *here = symbol_name_at(d, address);
    const DkVal *own = dk_imap_get(d->annotated, address);
    dk_buf_printf(out, "; %s %08X  %u dword(s)  %s\n", d->name, address, count,
                  sec ? dk_cz(d->a, sec->name) : "outside the image");
    if (own) dk_buf_printf(out, "; %s\n", (const char *)own->p);
    else if (here) dk_buf_printf(out, "; %s\n", here);
    for (u32 i = 0; i < count; i++) {
        u32 va = address + 4 * i, value;
        if (!read_u32(d, va, &value)) {
            dk_buf_printf(out, "%08X  +0x%-4X  outside the image\n", va, 4 * i);
            break;
        }
        bool reloc = has_reloc(d, va);
        const char *note = NULL;
        const DkImageSection *vs = sec_of(d, value);
        if (reloc || vs) {
            const DkVal *av = dk_imap_get(d->annotated, value), *tv = dk_imap_get(thunks, value);
            const char *imp = dk_image_import_at(d->im, value);
            const char *sym = symbol_name_at(d, value);
            u32 f;
            const char *fname;
            if (av) note = (const char *)av->p;
            else if (sym) note = sym;
            else if (tv) note = dk_sprintf(d->a, "%s (import thunk)", (const char *)tv->p);
            else if (imp) note = imp;
            else if (dk_disasm_containing_function(d, value, &f, &fname) && *fname)
                note = dk_sprintf(d->a, "%s+0x%X", fname, value - f);
            else if (vs) note = dk_sprintf(d->a, "(%.*s)", DK_SF(vs->name));
        }
        dk_buf_printf(out, "%08X  +0x%-4X %-6s %08X  %-5s%s%s\n", va, 4 * i, dk_sprintf(d->a, "[%u]", i), value,
                      reloc ? "reloc" : "", note ? "  " : "", note ? note : "");
    }
    return true;
}

/* ---- names -------------------------------------------------------------------------------------------------------- */

bool dk_disasm_find_names(const DkDisasm *d, const char *pattern, DkBuf *out, DkErr *err) {
    DkRe *re = NULL;
    char msg[256];
    if (!dk_re_compile(dk_str(pattern), DK_RE_I, &re, msg, sizeof msg)) {
        dk_err_set(err, DK_ERR_REGEX, "bad pattern: %s", msg);
        return false;
    }
    size_t n = 0;
    const DkSymbol *all = dk_symbols_all(d->syms, &n);
    for (size_t i = 0; i < n; i++)
        if (dk_re_search(re, dk_str(all[i].name), 0, DK_END, NULL))
            dk_buf_printf(out, "%08X  %6u  %s\n", all[i].va, all[i].size, all[i].name);
    if (n == 0) dk_buf_printf(out, "no symbols for %s\n", d->name);
    return true;
}

/* ---- command line ------------------------------------------------------------------------------------------------- */

static bool hex_arg(const char *text, i64 *out) { return dk_parse_int(dk_str(text), 16, out, NULL); }

static const char *opt_str(const DkArgs *r, const char *dest) {
    return dk_args_is_none(r, dest) ? NULL : dk_cz(dk_arena(), dk_args_str(r, dest));
}

static void flush(DkBuf *b) {
    if (b->n) fwrite(b->p, 1, b->n, stdout);
    dk_buf_clear(b);
}

int dk_disasm_main(int argc, char **argv) {
    DkArgParser *ap = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "disasm",
                                                                .description = disasm_doc,
                                                                .formatter = DK_FORMAT_RAW_DESCRIPTION});
    dk_arg(ap, &(DkArgDesc){.names = "target", .help = "a target of config/ctools.json"});
    dk_arg(ap, &(DkArgDesc){.names = "address", .nargs = DK_NARGS_OPT, .help = "virtual address (hex)"});
    dk_arg(ap, &(DkArgDesc){.names = "--size", .metavar = "N", .help = "bytes to decode (hex)"});
    dk_arg(ap, &(DkArgDesc){.names = "--xref", .action = DK_ARG_STORE_TRUE,
                            .help = "callers, jumps and absolute references to ADDRESS"});
    dk_arg(ap, &(DkArgDesc){.names = "--name", .metavar = "REGEX", .help = "look symbol names up"});
    dk_arg(ap, &(DkArgDesc){.names = "--no-bytes", .action = DK_ARG_STORE_TRUE, .help = "leave the raw bytes out"});
    dk_arg(ap, &(DkArgDesc){.names = "--thunks", .action = DK_ARG_STORE_TRUE,
                            .help = "the jmp thunks something points at that no symbol names (from ADDRESS, --size)"});
    dk_arg(ap, &(DkArgDesc){.names = "--all", .action = DK_ARG_STORE_TRUE, .help = "with --thunks: the known ones too"});
    dk_arg(ap, &(DkArgDesc){.names = "--data", .action = DK_ARG_STORE_TRUE,
                            .help = "dump dwords from ADDRESS (16, or --words N) with the names they point at"});
    dk_arg(ap, &(DkArgDesc){.names = "--words", .metavar = "N", .help = "with or without --data: dump N dwords"});
    dk_arg(ap, &(DkArgDesc){.names = "--root", .metavar = "DIR",
                            .help = "the repository (default: $DECOMPKIT_ROOT, else found from here)"});
    dk_arg(ap, &(DkArgDesc){.names = "--config", .metavar = "FILE",
                            .help = "the configuration (default: <root>/config/ctools.json)"});
    DkArgs *args = dk_args_parse(ap, argc, argv);

    DkArena *a = dk_arena();
    DkErr err = {0};
    DkProject *p = dk_project_load(a, opt_str(args, "root"), opt_str(args, "config"), &err);
    if (!p) {
        fprintf(stderr, "disasm: %s\n", err.msg);
        return 2;
    }
    const char *tname = dk_cz(a, dk_args_str(args, "target"));
    int t = dk_project_target_index(p, tname);
    if (t < 0) {
        fprintf(stderr, "disasm: %s: not a target of %s\n", tname, dk_project_config_path(p));
        return 2;
    }
    DkDisasm *d = dk_disasm_open(p, t, &err);
    if (!d) {
        fprintf(stderr, "disasm: %s\n", err.msg);
        return 2;
    }
    const char *address_s = opt_str(args, "address"), *size_s = opt_str(args, "size"), *name = opt_str(args, "name"),
               *words_s = opt_str(args, "words");
    if (!words_s && dk_args_bool(args, "data")) words_s = "";
    DkBuf out;
    dk_buf_init(&out, a);

    if (name && *name) {
        if (!dk_disasm_find_names(d, name, &out, &err)) {
            fprintf(stderr, "disasm: %s\n", err.msg);
            return 2;
        }
        flush(&out);
        return 0;
    }
    i64 address = 0, size = 0;
    bool has_address = address_s && *address_s;
    if (has_address && (!hex_arg(address_s, &address) || address < 0 || address > 0xFFFFFFFFll)) {
        fprintf(stderr, "disasm: bad address '%s'\n", address_s);
        return 2;
    }
    bool has_size = size_s && *size_s;
    if (has_size && (!hex_arg(size_s, &size) || size < 0)) {
        fprintf(stderr, "disasm: bad size '%s'\n", size_s);
        return 2;
    }
    if (dk_args_bool(args, "thunks")) {
        u32 start = has_address ? (u32)address : 0;
        u32 end = has_address && has_size ? (u32)(address + size) : 0;
        dk_disasm_print_thunks(d, start, end, dk_args_bool(args, "all"), &out);
        flush(&out);
        return 0;
    }
    if (!has_address) {
        fprintf(stderr, "disasm: an address or --name is required\n");
        return 2;
    }
    bool ok;
    if (dk_args_bool(args, "xref")) {
        ok = dk_disasm_xrefs(d, (u32)address, &out, &err);
    } else if (words_s) {
        i64 count = 16;
        if (*words_s && !dk_parse_int(dk_str(words_s), 10, &count, NULL) && !hex_arg(words_s, &count)) count = 0;
        if (count <= 0 || count > 0x10000) {
            fprintf(stderr, "disasm: bad --words '%s'\n", words_s);
            return 2;
        }
        ok = dk_disasm_words(d, (u32)address, (u32)count, &out);
    } else {
        if (!has_size) {
            DkDisasmBounds b;
            if (!dk_disasm_function_bounds(d, (u32)address, DK_DISASM_BOUNDS_LIMIT, &b, &err)) {
                fprintf(stderr, "disasm: %s\n", err.msg);
                return 1;
            }
            size = b.size;
            const DkSymbol *s = dk_symbols_at(dk_project_symbols(p, t, NULL), (u32)address);
            u32 known = s ? s->size : 0;
            if (!known)
                dk_buf_printf(&out, "; size %s: %lld bytes (no sized symbol)\n", b.why, (long long)size);
            else if (known != b.size)
                dk_buf_printf(&out, "; size %s: %lld bytes; the symbol source says %u (--size 0x%X for its)\n", b.why,
                              (long long)size, known, known);
        }
        ok = dk_disasm_function(d, (u32)address, size, !dk_args_bool(args, "no_bytes"), &out, &err);
    }
    flush(&out);
    if (!ok) {
        fprintf(stderr, "disasm: %s\n", err.msg);
        return 1;
    }
    return 0;
}
