// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* COFF objects and "!<arch>" archives: the reader of pe.h (see
 * pe.h). Everything is bounds-checked; where the Python read past the data (struct.error, IndexError, ValueError)
 * this code throws DK_ERR_FORMAT. */
#include "dk/pe.h"
#include "pe_internal.h"
#include <stdio.h>

static DK_NORETURN void bad(const char *fmt, ...) {
    char msg[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    dk_throw(DK_ERR_FORMAT, "%s", msg);
}

/* Python's bytes.rstrip(b"\0") */
static size_t rstrip_nul(const u8 *p, size_t n) {
    while (n > 0 && p[n - 1] == 0) n--;
    return n;
}

/* ---- COFF ------------------------------------------------------------------------------------------------------- */

/* A stable merge sort of relocations by offset (matchlib: relocs.sort(key=offset)); the records are nearly always
 * sorted already, so that case is one pass. */
static void sort_relocs(DkCoffReloc *r, size_t n) {
    bool sorted = true;
    for (size_t i = 1; i < n && sorted; i++)
        if (r[i].offset < r[i - 1].offset) sorted = false;
    if (sorted) return;
    DkCoffReloc *tmp = dk_xmalloc(n * sizeof *tmp);
    for (size_t width = 1; width < n; width *= 2) {
        for (size_t lo = 0; lo < n; lo += 2 * width) {
            size_t mid = DK_MIN(lo + width, n), hi = DK_MIN(lo + 2 * width, n);
            size_t i = lo, j = mid, k = lo;
            while (i < mid && j < hi) tmp[k++] = (r[j].offset < r[i].offset) ? r[j++] : r[i++];
            while (i < mid) tmp[k++] = r[i++];
            while (j < hi) tmp[k++] = r[j++];
        }
        memcpy(r, tmp, n * sizeof *tmp);
    }
    dk_xfree(tmp);
}

static DkStr strtab_name(const DkCoff *c, u64 strtab_start, u32 offset) {
    u64 at = strtab_start + offset;
    if (at >= c->file.n) bad("COFF: string table name at %llu is outside the file", (unsigned long long)at);
    const u8 *z = memchr(c->file.p + at, 0, c->file.n - (size_t)at);
    if (!z) bad("COFF: string table name at %llu has no terminator", (unsigned long long)at);
    return (DkStr){(const char *)c->file.p + at, (size_t)(z - (c->file.p + at))};
}

DkCoff *dk_coff_parse(DkArena *a, const void *data, size_t n, unsigned expect_machine) {
    const u8 *d = data;
    if (n < 20) bad("COFF: the file is shorter than its header");
    DkCoff *c = DK_NEW(a, DkCoff);
    c->file = (DkPeSpan){d, n};
    c->machine = dk_pe__ld16(d);
    c->number_of_sections = dk_pe__ld16(d + 2);
    c->time_date_stamp = dk_pe__ld32(d + 4);
    c->pointer_to_symbol_table = dk_pe__ld32(d + 8);
    c->number_of_symbols = dk_pe__ld32(d + 12);
    c->size_of_optional_header = dk_pe__ld16(d + 16);
    c->characteristics = dk_pe__ld16(d + 18);
    if (expect_machine && c->machine != expect_machine) bad("not an object of machine 0x%X (0x%X)", expect_machine, c->machine);

    const u64 symtab = c->pointer_to_symbol_table;
    const u64 nsyms = c->number_of_symbols;
    const u64 strtab = symtab + nsyms * 18;
    if (nsyms && strtab > n) bad("COFF: the symbol table lies outside the file");
    if (strtab + 4 <= n) {
        u32 sz = dk_pe__ld32(d + strtab);
        c->string_table = dk_pe_slice(d, n, (i64)strtab, (i64)(strtab + sz));
    }

    /* symbols */
    c->symbols = DK_NEWN(a, DkCoffSymbol, nsyms ? nsyms : 1);
    for (u64 i = 0; i < nsyms;) {
        const u8 *rec = d + symtab + i * 18;
        DkCoffSymbol *s = &c->symbols[i];
        s->index = (u32)i;
        s->record_offset = (u32)(symtab + i * 18);
        if (dk_pe__ld32(rec) == 0) {
            s->name = strtab_name(c, strtab, dk_pe__ld32(rec + 4));
        } else {
            s->name = (DkStr){(const char *)rec, rstrip_nul(rec, 8)};
        }
        s->value = dk_pe__ld32(rec + 8);
        s->section = (i16)dk_pe__ld16(rec + 12);
        s->type = dk_pe__ld16(rec + 14);
        s->storage_class = rec[16];
        s->number_of_aux = rec[17];
        if (i + 1 + s->number_of_aux > nsyms) bad("COFF: auxiliary records of symbol %llu run past the table", (unsigned long long)i);
        for (u32 k = 0; k < s->number_of_aux; k++) {
            DkCoffSymbol *x = &c->symbols[i + 1 + k];
            x->index = (u32)(i + 1 + k);
            x->aux = true;
            x->record_offset = (u32)(symtab + (i + 1 + k) * 18);
        }
        i += 1 + s->number_of_aux;
    }

    /* sections */
    c->sections = DK_NEWN(a, DkCoffSection, c->number_of_sections ? c->number_of_sections : 1);
    for (u32 si = 0; si < c->number_of_sections; si++) {
        u64 at = 20 + (u64)c->size_of_optional_header + (u64)si * 40;
        if (at + 40 > n) bad("COFF: section header %u lies outside the file", si + 1);
        const u8 *h = d + at;
        DkCoffSection *s = &c->sections[si];
        s->index = si + 1;
        memcpy(s->name_raw, h, 8);
        s->name = (DkStr){(const char *)h, rstrip_nul(h, 8)};
        s->long_name = s->name;
        if (s->name.n >= 2 && s->name.p[0] == '/') {
            u64 off = 0;
            bool digits = true;
            for (size_t k = 1; k < s->name.n; k++) {
                if (s->name.p[k] < '0' || s->name.p[k] > '9') { digits = false; break; }
                off = off * 10 + (u64)(s->name.p[k] - '0');
            }
            if (digits && strtab + 4 <= n && strtab + off < n && memchr(d + strtab + off, 0, n - (size_t)(strtab + off)))
                s->long_name = strtab_name(c, strtab, (u32)off);
        }
        s->virtual_size = dk_pe__ld32(h + 8);
        s->size = dk_pe__ld32(h + 16);
        s->pointer_to_raw_data = dk_pe__ld32(h + 20);
        s->pointer_to_relocations = dk_pe__ld32(h + 24);
        s->pointer_to_linenumbers = dk_pe__ld32(h + 28);
        s->number_of_relocations = dk_pe__ld16(h + 32);
        s->number_of_linenumbers = dk_pe__ld16(h + 34);
        s->characteristics = dk_pe__ld32(h + 36);
        s->header_offset = (u32)at;
        if (s->pointer_to_raw_data)
            s->data = dk_pe_slice(d, n, (i64)s->pointer_to_raw_data, (i64)s->pointer_to_raw_data + (i64)s->size);
        size_t nrel = s->number_of_relocations;
        s->n_relocs = nrel;
        s->relocs = DK_NEWN(a, DkCoffReloc, nrel ? nrel : 1);
        for (size_t r = 0; r < nrel; r++) {
            u64 ro = (u64)s->pointer_to_relocations + (u64)r * 10;
            if (ro + 10 > n) bad("COFF: relocation %zu of section %u lies outside the file", r, si + 1);
            DkCoffReloc *rl = &s->relocs[r];
            rl->offset = dk_pe__ld32(d + ro);
            rl->symbol_index = dk_pe__ld32(d + ro + 4);
            rl->type = dk_pe__ld16(d + ro + 8);
            rl->record_offset = (u32)ro;
            if (rl->symbol_index >= nsyms) bad("COFF: relocation %zu of section %u names symbol %u of %llu", r, si + 1, rl->symbol_index, (unsigned long long)nsyms);
            rl->addend = (u64)rl->offset + 4 <= s->data.n ? dk_pe__ld32(s->data.p + rl->offset) : 0;
        }
        sort_relocs(s->relocs, nrel);
    }
    return c;
}

const DkCoffSymbol *dk_coff_symbol(const DkCoff *c, u32 index) {
    if (index >= c->number_of_symbols) return NULL;
    const DkCoffSymbol *s = &c->symbols[index];
    return s->aux ? NULL : s;
}

const u8 *dk_coff_aux_raw(const DkCoff *c, const DkCoffSymbol *sym, unsigned k) {
    if (sym->aux || k >= sym->number_of_aux) return NULL;
    return c->file.p + c->pointer_to_symbol_table + ((u64)sym->index + 1 + k) * 18;
}

bool dk_coff_aux_section(const DkCoff *c, const DkCoffSymbol *sym, DkCoffSectionAux *out) {
    const u8 *r = dk_coff_aux_raw(c, sym, 0);
    if (!r) return false;
    out->length = dk_pe__ld32(r);
    out->number_of_relocations = dk_pe__ld16(r + 4);
    out->number_of_linenumbers = dk_pe__ld16(r + 6);
    out->checksum = dk_pe__ld32(r + 8);
    out->number = dk_pe__ld16(r + 12);
    out->selection = r[14];
    return true;
}

bool dk_coff_aux_weak(const DkCoff *c, const DkCoffSymbol *sym, DkCoffWeakAux *out) {
    const u8 *r = dk_coff_aux_raw(c, sym, 0);
    if (!r) return false;
    out->tag_index = dk_pe__ld32(r);
    out->characteristics = dk_pe__ld32(r + 4);
    return true;
}

DkStr dk_coff_aux_file(const DkCoff *c, const DkCoffSymbol *sym) {
    const u8 *r = dk_coff_aux_raw(c, sym, 0);
    if (!r) return (DkStr){NULL, 0};
    size_t len = (size_t)sym->number_of_aux * 18;
    const u8 *z = memchr(r, 0, len);
    return (DkStr){(const char *)r, z ? (size_t)(z - r) : len};
}

const DkCoffSymbol **dk_coff_section_symbols(const DkCoff *c, DkArena *a) {
    const DkCoffSymbol **out = DK_NEWN(a, const DkCoffSymbol *, (size_t)c->number_of_sections + 1);
    for (u32 i = 0; i < c->number_of_symbols; i++) {
        const DkCoffSymbol *s = &c->symbols[i];
        if (s->aux || s->section <= 0 || s->storage_class != DK_SYM_CLASS_STATIC || s->value != 0 || s->type != 0) continue;
        if ((u32)s->section > c->number_of_sections) continue;
        if (!out[s->section]) out[s->section] = s;
    }
    return out;
}

DkStrVec dk_coff_undefined_symbols(const DkCoff *c, DkArena *a) {
    DkStrVec v = {0};
    for (u32 i = 0; i < c->number_of_symbols; i++) {
        const DkCoffSymbol *s = &c->symbols[i];
        if (!s->aux && s->section == 0 && s->storage_class == DK_SYM_CLASS_EXTERNAL && s->value == 0)
            dk_vec_push(&v, dk_pe__dup(a, s->name));
    }
    return v;
}

DkStrVec dk_coff_defined_symbols(const DkCoff *c, DkArena *a) {
    DkStrVec v = {0};
    for (u32 i = 0; i < c->number_of_symbols; i++) {
        const DkCoffSymbol *s = &c->symbols[i];
        if (!s->aux && s->section > 0 && s->storage_class == DK_SYM_CLASS_EXTERNAL) dk_vec_push(&v, dk_pe__dup(a, s->name));
    }
    return v;
}

bool dk_coff_is_short_import(const void *data, size_t n) {
    return n >= 4 && dk_pe__ld16(data) == 0 && dk_pe__ld16((const u8 *)data + 2) == 0xFFFF;
}

bool dk_coff_short_import(const void *data, size_t n, DkCoffShortImport *out) {
    const u8 *d = data;
    if (n < 20 || !dk_coff_is_short_import(d, n)) return false;
    const u8 *z = memchr(d + 20, 0, n - 20);
    if (!z) return false;
    out->version = dk_pe__ld16(d + 4);
    out->machine = dk_pe__ld16(d + 6);
    out->time_date_stamp = dk_pe__ld32(d + 8);
    out->size_of_data = dk_pe__ld32(d + 12);
    out->ordinal_hint = dk_pe__ld16(d + 16);
    out->kind = dk_pe__ld16(d + 18);
    out->name_type = (out->kind >> 2) & 7u;
    out->symbol = (DkStr){(const char *)d + 20, (size_t)(z - (d + 20))};
    const u8 *dll = z + 1;
    const u8 *z2 = dll < d + n ? memchr(dll, 0, (size_t)(d + n - dll)) : NULL;
    out->dll = (DkStr){(const char *)dll, dll >= d + n ? 0 : (z2 ? (size_t)(z2 - dll) : (size_t)(d + n - dll))};
    return true;
}

/* ---- archives --------------------------------------------------------------------------------------------------- */

/* Python's str.isspace for the characters a Latin-1 decoded header field can hold */
static bool py_space(u8 c) { return c == ' ' || (c >= 9 && c <= 13) || (c >= 0x1c && c <= 0x1f) || c == 0x85 || c == 0xA0; }

static size_t rstrip_space(const u8 *p, size_t n) {
    while (n > 0 && py_space(p[n - 1])) n--;
    return n;
}

static u64 hash_str(DkStr s) {
    u64 h = 1469598103934665603ull;
    for (size_t i = 0; i < s.n; i++) h = (h ^ (u8)s.p[i]) * 1099511628211ull;
    return h;
}

typedef DK_VEC(DkArMember) MemberVec;

DkArchive *dk_archive_parse(DkArena *a, const void *data, size_t n) {
    const u8 *d = data;
    if (n < 8 || memcmp(d, "!<arch>\n", 8) != 0) bad("not an archive");
    DkArchive *ar = DK_NEW(a, DkArchive);
    ar->file = (DkPeSpan){d, n};
    MemberVec members = {0};
    DkPeSpan longnames = {NULL, 0};
    DK_VEC(DkPeSpan) linker = {0};
    size_t at = 8;
    while (at + 60 <= n) {
        size_t rawn = rstrip_space(d + at, 16);
        const u8 *raw = d + at;
        /* the size field: Python's int(field.strip() or 0) */
        size_t s0 = 0, s1 = 10;
        const u8 *sf = d + at + 48;
        while (s0 < s1 && py_space(sf[s0])) s0++;
        while (s1 > s0 && py_space(sf[s1 - 1])) s1--;
        u64 size = 0;
        for (size_t k = s0; k < s1; k++) {
            if (sf[k] < '0' || sf[k] > '9') bad("archive: member header at %zu has a bad size field", at);
            size = size * 10 + (u64)(sf[k] - '0');
            if (size > (u64)1 << 40) bad("archive: member header at %zu has a bad size field", at);
        }
        DkPeSpan body = dk_pe_slice(d, n, (i64)(at + 60), (i64)(at + 60 + size));
        if (rawn == 1 && raw[0] == '/') {
            dk_vec_push(&linker, body);
        } else if (rawn == 2 && raw[0] == '/' && raw[1] == '/') {
            longnames = body;
        } else {
            DkStr name;
            bool digits = rawn >= 2 && raw[0] == '/';
            u64 off = 0;
            for (size_t k = 1; digits && k < rawn; k++) {
                if (raw[k] < '0' || raw[k] > '9') digits = false;
                else off = off * 10 + (u64)(raw[k] - '0');
            }
            if (digits) {
                if (off >= longnames.n) name = (DkStr){(const char *)longnames.p, 0};
                else {
                    const u8 *z = memchr(longnames.p + off, 0, longnames.n - (size_t)off);
                    size_t len = z ? (size_t)(z - (longnames.p + off)) : longnames.n - (size_t)off;
                    while (len > 0 && longnames.p[off + len - 1] == '\n') len--;
                    name = (DkStr){(const char *)longnames.p + off, len};
                }
            } else {
                name = (DkStr){(const char *)raw, (rawn > 0 && raw[rawn - 1] == '/') ? rawn - 1 : rawn};
            }
            DkArMember m = {name, (u32)at, body};
            dk_vec_push(&members, m);
            if (dk_coff_is_short_import(body.p, body.n)) ar->short_imports++;
        }
        at += 60 + (size_t)size + (size_t)(size & 1);
    }
    ar->n_members = members.n;
    ar->members = dk_memdup(a, members.v ? members.v : (DkArMember[1]){{{NULL, 0}, 0, {NULL, 0}}},
                             (members.n ? members.n : 1) * sizeof(DkArMember));
    dk_vec_free(&members);

    /* the symbol index: the second linker member (little endian), else the first (big endian) */
    if (linker.n >= 1) {
        bool second = linker.n >= 2;
        DkPeSpan s = linker.v[second ? 1 : 0];
        const u8 *p = s.p;
        size_t cnt, names_at;
        const u8 *offsets;
        const u8 *idx16 = NULL;
        if (second) {
            if (s.n < 4) bad("archive: second linker member is too short");
            size_t m = dk_pe__ld32(p);
            if (m > (s.n - 4) / 4 || s.n < 8 + 4 * m) bad("archive: second linker member is damaged");
            offsets = p + 4;
            cnt = dk_pe__ld32(p + 4 + 4 * m);
            if (cnt > (s.n - 8 - 4 * m) / 2) bad("archive: second linker member is damaged");
            idx16 = p + 8 + 4 * m;
            names_at = 8 + 4 * m + 2 * cnt;
            ar->symbol = DK_NEWN(a, DkStr, cnt ? cnt : 1);
            ar->symbol_member_offset = DK_NEWN(a, u32, cnt ? cnt : 1);
            size_t pos = names_at;
            for (size_t i = 0; i < cnt; i++) {
                if (pos > s.n) bad("archive: second linker member has fewer names than symbols");
                const u8 *z = memchr(p + pos, 0, s.n - pos);
                size_t len = z ? (size_t)(z - (p + pos)) : s.n - pos;
                if (!z && i + 1 < cnt) bad("archive: second linker member has fewer names than symbols");
                ar->symbol[i] = (DkStr){(const char *)p + pos, len};
                u32 ix = dk_pe__ld16(idx16 + 2 * i);
                /* offsets[idx - 1], with Python's negative index for idx == 0 */
                size_t which = ix == 0 ? m - 1 : (size_t)ix - 1;
                if (m == 0 || which >= m) bad("archive: symbol %zu names member %u of %zu", i, ix, m);
                ar->symbol_member_offset[i] = dk_pe__ld32(offsets + 4 * which);
                pos += len + 1;
            }
            ar->n_symbols = cnt;
        } else {
            if (s.n < 4) bad("archive: first linker member is too short");
            cnt = (size_t)p[0] << 24 | (size_t)p[1] << 16 | (size_t)p[2] << 8 | p[3];
            if (cnt > (s.n - 4) / 4) bad("archive: first linker member is damaged");
            offsets = p + 4;
            names_at = 4 + 4 * cnt;
            ar->symbol = DK_NEWN(a, DkStr, cnt ? cnt : 1);
            ar->symbol_member_offset = DK_NEWN(a, u32, cnt ? cnt : 1);
            size_t pos = names_at;
            for (size_t i = 0; i < cnt; i++) {
                if (pos > s.n) bad("archive: first linker member has fewer names than symbols");
                const u8 *z = memchr(p + pos, 0, s.n - pos);
                size_t len = z ? (size_t)(z - (p + pos)) : s.n - pos;
                if (!z && i + 1 < cnt) bad("archive: first linker member has fewer names than symbols");
                ar->symbol[i] = (DkStr){(const char *)p + pos, len};
                const u8 *o = offsets + 4 * i;
                ar->symbol_member_offset[i] = (u32)o[0] << 24 | (u32)o[1] << 16 | (u32)o[2] << 8 | o[3];
                pos += len + 1;
            }
            ar->n_symbols = cnt;
        }
    }
    dk_vec_free(&linker);

    /* hash index: name -> first slot, slots with the same name chained in order */
    size_t cap = 16;
    while (cap < ar->n_symbols * 2) cap *= 2;
    ar->hash_cap = cap;
    ar->hash = DK_NEWN(a, u32, cap);
    ar->next_same = DK_NEWN(a, u32, ar->n_symbols ? ar->n_symbols : 1);
    u32 *tail = DK_NEWN(a, u32, ar->n_symbols ? ar->n_symbols : 1);
    for (size_t i = 0; i < ar->n_symbols; i++) {
        ar->next_same[i] = UINT32_MAX;
        size_t h = (size_t)hash_str(ar->symbol[i]) & (cap - 1);
        for (;;) {
            u32 e = ar->hash[h];
            if (!e) {
                ar->hash[h] = (u32)i + 1;
                tail[i] = (u32)i;
                break;
            }
            if (dk_pe__eq(ar->symbol[e - 1], ar->symbol[i])) {
                ar->next_same[tail[e - 1]] = (u32)i;
                tail[e - 1] = (u32)i;
                break;
            }
            h = (h + 1) & (cap - 1);
        }
    }
    return ar;
}

static const DkArMember *member_at_offset(const DkArchive *ar, u32 off) {
    size_t lo = 0, hi = ar->n_members;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (ar->members[mid].header_offset < off) lo = mid + 1; else hi = mid;
    }
    return lo < ar->n_members && ar->members[lo].header_offset == off ? &ar->members[lo] : NULL;
}

static u32 first_slot(const DkArchive *ar, DkStr symbol) {
    if (!ar->hash_cap) return UINT32_MAX;
    size_t h = (size_t)hash_str(symbol) & (ar->hash_cap - 1);
    for (;;) {
        u32 e = ar->hash[h];
        if (!e) return UINT32_MAX;
        if (dk_pe__eq(ar->symbol[e - 1], symbol)) return e - 1;
        h = (h + 1) & (ar->hash_cap - 1);
    }
}

DkStrVec dk_archive_definers(const DkArchive *ar, DkArena *a, DkStr symbol) {
    (void)a;
    DkStrVec v = {0};
    for (u32 i = first_slot(ar, symbol); i != UINT32_MAX; i = ar->next_same[i]) {
        const DkArMember *m = member_at_offset(ar, ar->symbol_member_offset[i]);
        if (m) dk_vec_push(&v, m->name);
    }
    return v;
}

bool dk_archive_member(const DkArchive *ar, DkStr name, const DkStr *symbol, DkPeSpan *out) {
    const DkArMember *first = NULL;
    size_t found = 0;
    for (size_t i = 0; i < ar->n_members; i++) {
        if (!dk_pe__eq(ar->members[i].name, name)) continue;
        if (!first) first = &ar->members[i];
        found++;
    }
    if (!first) return false;
    if (found > 1 && symbol) {
        u32 slot = first_slot(ar, *symbol);
        if (slot != UINT32_MAX) {
            for (size_t i = 0; i < ar->n_members; i++) {
                if (!dk_pe__eq(ar->members[i].name, name)) continue;
                for (u32 k = slot; k != UINT32_MAX; k = ar->next_same[k]) {
                    if (ar->symbol_member_offset[k] == ar->members[i].header_offset) {
                        *out = ar->members[i].data;
                        return true;
                    }
                }
            }
        }
    }
    *out = first->data;
    return true;
}
