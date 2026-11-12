// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* PE images: the port of the parts of pefile 2024.8.26 the tools use (see pe.h). The comments name the pefile
 * function each piece follows. */
#include "dk/pe.h"
#include "pe_internal.h"

#define MAX_STRING_LENGTH 0x100000u
#define MAX_IMPORT_SYMBOLS 0x2000u
#define MAX_IMPORT_NAME_LENGTH 0x200u
#define MAX_DLL_LENGTH 0x200u
#define MAX_SYMBOL_NAME_LENGTH 0x200u
#define MAX_SECTIONS 0x800u
#define MAX_SYMBOL_EXPORT_COUNT 0x2000u
#define MAX_REPEATED_SYMBOL 10u        /* named exports */
#define MAX_REPEATED_ORDINAL 120u      /* PE(max_repeated_symbol=120): ordinal-only exports */
#define MAX_MAPPED_VIRTUAL_ADDRESS 0x10000000u

static DK_NORETURN void bad(const char *msg) { dk_throw(DK_ERR_FORMAT, "%s", msg); }

/* ---- slices ------------------------------------------------------------------------------------------------- */

DkPeSpan dk_pe_slice(const u8 *p, size_t n, i64 start, i64 end) {
    i64 len = (i64)n;
    i64 s = start == DK_PE_NONE ? 0 : start;
    i64 e = end == DK_PE_NONE ? len : end;
    if (s < 0) { s += len; if (s < 0) s = 0; } else if (s > len) s = len;
    if (e < 0) { e += len; if (e < 0) e = 0; } else if (e > len) e = len;
    if (e < s) e = s;
    return (DkPeSpan){p + s, (size_t)(e - s)};
}

static bool all_zero(const u8 *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i]) return false;
    return true;
}

/* ---- alignment (adjust_SectionAlignment / adjust_PointerToRawData) --------------------------------------------- */

static u64 adjust_section_alignment(u64 val, u64 section_alignment, u64 file_alignment) {
    if (section_alignment < 0x1000) section_alignment = file_alignment;
    if (section_alignment && val % section_alignment) return section_alignment * (val / section_alignment);
    return val;
}

static u32 adjust_pointer_to_raw_data(u32 val) { return val & ~0x1FFu; }

/* ---- parsing -------------------------------------------------------------------------------------------------- */

/* The optional header: pefile unpacks the PE32 layout (96 bytes) from the 0x200 bytes at the offset, retries with 128
 * zero bytes of padding when the data is shorter but holds at least 69 bytes, and switches to the PE32+ layout (112
 * bytes, padding allowed from 73 bytes) when the magic says so. `ob` is the zero-padded copy of those bytes. */
static void read_optional_header(DkPe *pe, const u8 *ob, size_t avail) {
    pe->magic = dk_pe__ld16(ob);
    bool plus = pe->magic == DK_PE_MAGIC_PE32_PLUS;
    if (avail < 69) bad("No Optional Header found, invalid PE32 or PE32+ file.");
    if (plus && avail < 73) bad("No Optional Header found, invalid PE32 or PE32+ file.");
    pe->pe_type = (pe->magic == DK_PE_MAGIC_PE32 || plus) ? pe->magic : 0;
    pe->major_linker_version = ob[2];
    pe->minor_linker_version = ob[3];
    pe->size_of_code = dk_pe__ld32(ob + 4);
    pe->size_of_initialized_data = dk_pe__ld32(ob + 8);
    pe->size_of_uninitialized_data = dk_pe__ld32(ob + 12);
    pe->address_of_entry_point = dk_pe__ld32(ob + 16);
    pe->base_of_code = dk_pe__ld32(ob + 20);
    size_t o;
    if (plus) {
        pe->base_of_data = 0;
        pe->image_base = dk_pe__ld64(ob + 24);
        o = 32;
    } else {
        pe->base_of_data = dk_pe__ld32(ob + 24);
        pe->image_base = dk_pe__ld32(ob + 28);
        o = 32;
    }
    pe->section_alignment = dk_pe__ld32(ob + o);
    pe->file_alignment = dk_pe__ld32(ob + o + 4);
    pe->major_operating_system_version = dk_pe__ld16(ob + o + 8);
    pe->minor_operating_system_version = dk_pe__ld16(ob + o + 10);
    pe->major_image_version = dk_pe__ld16(ob + o + 12);
    pe->minor_image_version = dk_pe__ld16(ob + o + 14);
    pe->major_subsystem_version = dk_pe__ld16(ob + o + 16);
    pe->minor_subsystem_version = dk_pe__ld16(ob + o + 18);
    pe->win32_version_value = dk_pe__ld32(ob + o + 20);
    pe->size_of_image = dk_pe__ld32(ob + o + 24);
    pe->size_of_headers = dk_pe__ld32(ob + o + 28);
    pe->checksum = dk_pe__ld32(ob + o + 32);
    pe->subsystem = dk_pe__ld16(ob + o + 36);
    pe->dll_characteristics = dk_pe__ld16(ob + o + 38);
    size_t q = o + 40;
    if (plus) {
        pe->size_of_stack_reserve = dk_pe__ld64(ob + q);
        pe->size_of_stack_commit = dk_pe__ld64(ob + q + 8);
        pe->size_of_heap_reserve = dk_pe__ld64(ob + q + 16);
        pe->size_of_heap_commit = dk_pe__ld64(ob + q + 24);
        q += 32;
    } else {
        pe->size_of_stack_reserve = dk_pe__ld32(ob + q);
        pe->size_of_stack_commit = dk_pe__ld32(ob + q + 4);
        pe->size_of_heap_reserve = dk_pe__ld32(ob + q + 8);
        pe->size_of_heap_commit = dk_pe__ld32(ob + q + 12);
        q += 16;
    }
    pe->loader_flags = dk_pe__ld32(ob + q);
    pe->number_of_rva_and_sizes = dk_pe__ld32(ob + q + 4);
    pe->optional_header_size = (u32)(q + 8);
}

/* Values pefile derives from a section header once the file and the optional header are known. */
static void section_derive(const DkPe *pe, DkPeSection *s) {
    u32 ptrd = adjust_pointer_to_raw_data(s->pointer_to_raw_data);
    if (pe->section_alignment < 0x1000 && s->pointer_to_raw_data == s->virtual_address) ptrd = s->virtual_address;
    s->pointer_to_raw_data_adj = ptrd;
    s->virtual_address_adj =
        (u32)adjust_section_alignment(s->virtual_address, pe->section_alignment, pe->file_alignment);
}

DkPe *dk_pe_parse(DkArena *a, const void *data, size_t n) {
    const u8 *d = data;
    if (n < 64) bad("Unable to read the DOS Header, possibly a truncated file.");
    u16 e_magic = dk_pe__ld16(d);
    if (e_magic == 0x4D5A) bad("Probably a ZM Executable (not a PE file).");
    if (e_magic != 0x5A4D) bad("DOS Header magic not found.");
    u32 e_lfanew = dk_pe__ld32(d + 0x3C);
    if (e_lfanew > n) bad("Invalid e_lfanew value, probably not a PE file");
    size_t nt = e_lfanew;
    if (n - nt < 4) bad("NT Headers not found.");
    u32 sig = dk_pe__ld32(d + nt);
    if (sig == 0) bad("NT Headers not found.");
    switch (sig & 0xFFFF) {
    case 0x454E: bad("Invalid NT Headers signature. Probably a NE file");
    case 0x454C: bad("Invalid NT Headers signature. Probably a LE file");
    case 0x584C: bad("Invalid NT Headers signature. Probably a LX file");
    case 0x4554: bad("Invalid NT Headers signature. Probably a TE file");
    default: break;
    }
    if (sig != 0x00004550) bad("Invalid NT Headers signature.");

    DkPe *pe = DK_NEW(a, DkPe);
    pe->file = (DkPeSpan){d, n};
    pe->e_lfanew = e_lfanew;
    if (n - nt < 4 + 20) bad("File Header missing");
    const u8 *fh = d + nt + 4;
    pe->machine = dk_pe__ld16(fh);
    pe->number_of_sections = dk_pe__ld16(fh + 2);
    pe->time_date_stamp = dk_pe__ld32(fh + 4);
    pe->pointer_to_symbol_table = dk_pe__ld32(fh + 8);
    pe->number_of_symbols = dk_pe__ld32(fh + 12);
    pe->size_of_optional_header = dk_pe__ld16(fh + 16);
    pe->characteristics = dk_pe__ld16(fh + 18);

    size_t opt = nt + 4 + 20;
    pe->optional_header_offset = (u32)opt;
    size_t sections_offset = opt + pe->size_of_optional_header;
    u8 ob[0x200 + 128];
    memset(ob, 0, sizeof ob);
    size_t avail = opt < n ? DK_MIN((size_t)0x200, n - opt) : 0;
    if (avail) memcpy(ob, d + opt, avail);
    if (avail < 2) bad("No Optional Header found, invalid PE32 or PE32+ file.");
    read_optional_header(pe, ob, avail);

    /* the data directories (the loop of __parse__): a table past the end of the file gives zero entries */
    size_t offset = opt + pe->optional_header_size;
    for (u32 i = 0; i < (pe->number_of_rva_and_sizes & 0x7FFFFFFFu); i++) {
        u8 ent[8] = {0};
        if (n == offset) break;
        if (offset < n) memcpy(ent, d + offset, DK_MIN((size_t)8, n - offset));
        if (i >= 16) break;
        pe->data_directory[pe->n_data_directory].virtual_address = dk_pe__ld32(ent);
        pe->data_directory[pe->n_data_directory].size = dk_pe__ld32(ent + 4);
        pe->n_data_directory++;
        offset += 8;
        if (offset >= opt + pe->optional_header_size + 8 * 16) break;
    }

    /* parse_sections */
    size_t cap = pe->number_of_sections < MAX_SECTIONS ? pe->number_of_sections : MAX_SECTIONS;
    DkPeSection *secs = DK_NEWN(a, DkPeSection, cap ? cap : 1);
    size_t ns = 0;
    for (u32 i = 0; i < pe->number_of_sections; i++) {
        if (i >= MAX_SECTIONS) break;
        size_t so = sections_offset + (size_t)40 * i;
        if (so >= n) break; /* section_data is empty */
        size_t have = DK_MIN((size_t)40, n - so);
        if (have == 40 && all_zero(d + so, 40)) break;
        if (have < 40) bad("Data length less than expected header length.");
        const u8 *h = d + so;
        DkPeSection *s = &secs[ns];
        memset(s, 0, sizeof *s);
        memcpy(s->name_raw, h, 8);
        s->virtual_size = dk_pe__ld32(h + 8);
        s->virtual_address = dk_pe__ld32(h + 12);
        s->size_of_raw_data = dk_pe__ld32(h + 16);
        s->pointer_to_raw_data = dk_pe__ld32(h + 20);
        s->pointer_to_relocations = dk_pe__ld32(h + 24);
        s->pointer_to_linenumbers = dk_pe__ld32(h + 28);
        s->number_of_relocations = dk_pe__ld16(h + 32);
        s->number_of_linenumbers = dk_pe__ld16(h + 34);
        s->characteristics = dk_pe__ld32(h + 36);
        s->header_offset = (u32)so;
        s->index = i;
        unsigned errors = 0;
        if ((u64)s->size_of_raw_data + s->pointer_to_raw_data > n) errors++;
        if (adjust_pointer_to_raw_data(s->pointer_to_raw_data) > n) errors++;
        if (s->virtual_size > 0x10000000u) errors++;
        if (adjust_section_alignment(s->virtual_address, pe->section_alignment, pe->file_alignment) > 0x10000000u)
            errors++;
        if (pe->file_alignment != 0 && (s->pointer_to_raw_data % pe->file_alignment) != 0) errors++;
        if (errors >= 3) break;
        size_t len = 8;
        while (len > 0 && s->name_raw[len - 1] == 0) len--;
        s->name = (DkStr){(const char *)s->name_raw, len};
        ns++;
    }
    /* sorted by VirtualAddress, stable (insertion sort: stable, and the table is nearly sorted) */
    for (size_t i = 1; i < ns; i++) {
        DkPeSection key = secs[i];
        size_t j = i;
        while (j > 0 && secs[j - 1].virtual_address > key.virtual_address) {
            secs[j] = secs[j - 1];
            j--;
        }
        secs[j] = key;
    }
    pe->sections = secs;
    pe->n_sections = ns;
    /* name views point into the structs, which moved with the sort */
    for (size_t i = 0; i < ns; i++) {
        secs[i].name.p = (const char *)secs[i].name_raw;
        section_derive(pe, &secs[i]);
    }
    for (size_t i = 0; i < ns; i++) {
        DkPeSection *s = &secs[i];
        u64 size;
        if ((i64)n - (i64)s->pointer_to_raw_data_adj < (i64)s->size_of_raw_data) size = s->virtual_size;
        else size = DK_MAX(s->size_of_raw_data, s->virtual_size);
        if (i + 1 < ns) {
            u32 next = secs[i + 1].virtual_address;
            if (next > s->virtual_address && (u64)s->virtual_address_adj + size > next) size = next - s->virtual_address_adj;
        }
        s->min_addr = s->virtual_address_adj;
        s->max_addr = (u64)s->virtual_address_adj + size;
    }

    /* the offset parse_sections returns, and pe.header */
    size_t end_of_headers = sections_offset;
    if (pe->number_of_sections > 0 && ns > 0) end_of_headers = sections_offset + (size_t)40 * pe->number_of_sections;
    u64 lowest = 0;
    bool have_lowest = false;
    for (size_t i = 0; i < ns; i++) {
        if (secs[i].pointer_to_raw_data > 0) {
            u64 v = adjust_pointer_to_raw_data(secs[i].pointer_to_raw_data);
            if (!have_lowest || v < lowest) lowest = v;
            have_lowest = true;
        }
    }
    if (!have_lowest || lowest == 0 || lowest < end_of_headers) pe->header = dk_pe_slice(d, n, 0, (i64)end_of_headers);
    else pe->header = dk_pe_slice(d, n, 0, (i64)lowest);
    return pe;
}

/* ---- sections, offsets, data ----------------------------------------------------------------------------------- */

bool dk_pe_section_contains_rva(const DkPeSection *s, u64 rva) { return s->min_addr <= rva && rva < s->max_addr; }

bool dk_pe_section_contains_offset(const DkPeSection *s, u64 offset) {
    return s->pointer_to_raw_data_adj <= offset && offset < (u64)s->pointer_to_raw_data_adj + s->size_of_raw_data;
}

const DkPeSection *dk_pe_section_by_rva(const DkPe *pe, u64 rva) {
    for (size_t i = 0; i < pe->n_sections; i++)
        if (dk_pe_section_contains_rva(&pe->sections[i], rva)) return &pe->sections[i];
    return NULL;
}

const DkPeSection *dk_pe_section_by_offset(const DkPe *pe, u64 offset) {
    for (size_t i = 0; i < pe->n_sections; i++)
        if (dk_pe_section_contains_offset(&pe->sections[i], offset)) return &pe->sections[i];
    return NULL;
}

const DkPeSection *dk_pe_section_with_prefix(const DkPe *pe, DkStr prefix) {
    for (size_t i = 0; i < pe->n_sections; i++) {
        /* Name is the raw 8 bytes: startswith compares them with their NUL padding */
        const DkPeSection *s = &pe->sections[i];
        if (prefix.n <= 8 && memcmp(s->name_raw, prefix.p, prefix.n) == 0) return s;
    }
    return NULL;
}

DkPeSpan dk_pe_section_get_data(const DkPe *pe, const DkPeSection *s, i64 start, i64 length, bool ignore_padding) {
    i64 offset = start == DK_PE_NONE ? (i64)s->pointer_to_raw_data_adj
                                      : (start - (i64)s->virtual_address_adj) + (i64)s->pointer_to_raw_data_adj;
    i64 end = length != DK_PE_NONE ? offset + length : offset + (i64)s->size_of_raw_data;
    if (ignore_padding && end > offset + (i64)s->virtual_size) end = offset + (i64)s->virtual_size;
    i64 limit = (i64)s->pointer_to_raw_data + (i64)s->size_of_raw_data;
    if (end > limit) end = limit;
    return dk_pe_slice(pe->file.p, pe->file.n, offset, end);
}

bool dk_pe_try_get_data(const DkPe *pe, u64 rva, i64 length, DkPeSpan *out) {
    const DkPeSection *s = dk_pe_section_by_rva(pe, rva);
    if (!s) {
        i64 end = length == DK_PE_NONE ? DK_PE_NONE : (i64)rva + length;
        if (rva < pe->header.n) {
            *out = dk_pe_slice(pe->header.p, pe->header.n, (i64)rva, end);
            return true;
        }
        if (rva < pe->file.n) {
            *out = dk_pe_slice(pe->file.p, pe->file.n, (i64)rva, end);
            return true;
        }
        return false;
    }
    *out = dk_pe_section_get_data(pe, s, (i64)rva, length, false);
    return true;
}

DkPeSpan dk_pe_get_data(const DkPe *pe, u64 rva, i64 length) {
    DkPeSpan sp;
    if (!dk_pe_try_get_data(pe, rva, length, &sp)) bad("data at RVA can't be fetched. Corrupt header?");
    return sp;
}

bool dk_pe_dword_at_rva(const DkPe *pe, u64 rva, u32 *out) {
    DkPeSpan sp;
    if (!dk_pe_try_get_data(pe, rva, 4, &sp) || sp.n < 4) return false;
    *out = dk_pe__ld32(sp.p);
    return true;
}

bool dk_pe_word_at_rva(const DkPe *pe, u64 rva, u16 *out) {
    DkPeSpan sp;
    if (!dk_pe_try_get_data(pe, rva, 2, &sp) || sp.n < 2) return false;
    *out = dk_pe__ld16(sp.p);
    return true;
}

bool dk_pe_offset_from_rva(const DkPe *pe, u64 rva, u64 *offset) {
    const DkPeSection *s = dk_pe_section_by_rva(pe, rva);
    if (!s) {
        if (rva < pe->file.n) {
            *offset = rva;
            return true;
        }
        return false;
    }
    *offset = rva - s->virtual_address_adj + s->pointer_to_raw_data_adj;
    return true;
}

bool dk_pe_rva_from_offset(const DkPe *pe, u64 offset, u64 *rva) {
    const DkPeSection *s = dk_pe_section_by_offset(pe, offset);
    if (!s) {
        if (pe->n_sections) {
            u64 lowest = UINT64_MAX;
            for (size_t i = 0; i < pe->n_sections; i++)
                if (pe->sections[i].virtual_address_adj < lowest) lowest = pe->sections[i].virtual_address_adj;
            if (offset < lowest) {
                *rva = offset;
                return true;
            }
            return false;
        }
        *rva = offset;
        return true;
    }
    *rva = offset - s->pointer_to_raw_data_adj + s->virtual_address_adj;
    return true;
}

static DkStr string_from_span(DkPeSpan sp) {
    const u8 *z = sp.n ? memchr(sp.p, 0, sp.n) : NULL;
    return (DkStr){(const char *)sp.p, z ? (size_t)(z - sp.p) : sp.n};
}

DkStr dk_pe_string_at_rva(const DkPe *pe, u64 rva, size_t max_length) {
    const DkPeSection *s = dk_pe_section_by_rva(pe, rva);
    DkPeSpan sp;
    if (!s) sp = dk_pe_slice(pe->file.p, pe->file.n, (i64)rva, (i64)rva + (i64)max_length);
    else sp = dk_pe_section_get_data(pe, s, (i64)rva, (i64)max_length, false);
    return string_from_span(sp);
}

u8 *dk_pe_memory_mapped_image(const DkPe *pe, DkArena *a, size_t *n_out) {
    const u64 n = pe->file.n;
    /* pass 1: the largest length the image reaches (a section can cut the data back, so it is not the final one) */
    size_t len = pe->header.n, peak = len;
    for (int pass = 0; pass < 2; pass++) {
        u8 *buf = NULL;
        if (pass == 1) {
            buf = dk_alloc_noz(a, peak ? peak : 1);
            memcpy(buf, pe->header.p, pe->header.n);
            len = pe->header.n;
        }
        for (size_t i = 0; i < pe->n_sections; i++) {
            const DkPeSection *s = &pe->sections[i];
            if (s->virtual_size == 0 && s->size_of_raw_data == 0) continue;
            u64 srd = s->size_of_raw_data;
            u64 prd = adjust_pointer_to_raw_data(s->pointer_to_raw_data);
            u64 va = s->virtual_address_adj;
            if (srd > n || prd > n || srd + prd > n || va >= MAX_MAPPED_VIRTUAL_ADDRESS) continue;
            i64 padding = (i64)va - (i64)len;
            if (padding > 0) {
                if (pass == 1) memset(buf + len, 0, (size_t)padding);
                len += (size_t)padding;
            } else if (padding < 0) {
                size_t cut = (size_t)(-padding);
                len = cut > len ? 0 : len - cut;
            }
            DkPeSpan sd = dk_pe_section_get_data(pe, s, DK_PE_NONE, DK_PE_NONE, false);
            if (pass == 1) memcpy(buf + len, sd.p, sd.n);
            len += sd.n;
            if (pass == 0 && len > peak) peak = len;
        }
        if (pass == 1) {
            *n_out = len;
            return buf;
        }
    }
    return NULL;
}

/* ---- small sets (pefile's AddressSet, the export counters) ---------------------------------------------------- */

typedef struct {
    u64 *keys; /* 0 is stored as key + 1 shifted: keys are kept as value + 1 so that 0 means empty */
    size_t cap, n;
    u64 min, max;
    bool any;
} U64Set;

static bool uset_add(U64Set *s, u64 v) { /* true when v was already a member */
    if ((s->n + 1) * 2 > s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 64;
        u64 *nk = dk_xcalloc(ncap, sizeof(u64));
        for (size_t i = 0; i < s->cap; i++) {
            if (!s->keys[i]) continue;
            size_t h = (size_t)((s->keys[i] - 1) * 0x9E3779B97F4A7C15ull >> 20) & (ncap - 1);
            while (nk[h]) h = (h + 1) & (ncap - 1);
            nk[h] = s->keys[i];
        }
        dk_xfree(s->keys);
        s->keys = nk;
        s->cap = ncap;
    }
    size_t h = (size_t)(v * 0x9E3779B97F4A7C15ull >> 20) & (s->cap - 1);
    while (s->keys[h]) {
        if (s->keys[h] == v + 1) return true;
        h = (h + 1) & (s->cap - 1);
    }
    s->keys[h] = v + 1;
    s->n++;
    s->min = s->any ? DK_MIN(s->min, v) : v;
    s->max = s->any ? DK_MAX(s->max, v) : v;
    s->any = true;
    return false;
}

static u64 uset_diff(const U64Set *s) { return s->any ? s->max - s->min : 0; }
static void uset_free(U64Set *s) { dk_xfree(s->keys); memset(s, 0, sizeof *s); }

/* ---- imports --------------------------------------------------------------------------------------------------- */

typedef struct {
    u64 address_of_data;
    u64 thunk_offset;
} Thunk;
typedef DK_VEC(Thunk) ThunkVec;
typedef DK_VEC(DkPeImport) ImportVec;
typedef DK_VEC(DkPeImportDll) ImportDllVec;

static bool name_chars_valid(DkStr s, const char *extra, bool dos) {
    (void)dos;
    for (size_t i = 0; i < s.n; i++) {
        unsigned char c = (unsigned char)s.p[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) continue;
        if (c && strchr(extra, c)) continue;
        return false;
    }
    return true;
}
static bool valid_function_name(DkStr s) { return name_chars_valid(s, "._?@$()<>", false); }
static bool valid_dos_filename(DkStr s) { return name_chars_valid(s, "!#$%&'()-@^_`{}~+,.;=[]:\\/", true); }

/* get_import_table: the thunks of one table, empty where pefile returned None or [] */
static void import_table(const DkPe *pe, u64 rva, bool bounded, u64 max_length, unsigned *total, ThunkVec *out) {
    const bool plus = pe->pe_type == DK_PE_MAGIC_PE32_PLUS;
    const size_t esize = plus ? 8 : 4;
    const u64 ordinal_flag = plus ? 0x8000000000000000ull : 0x80000000ull;
    const u64 spread = 128u * 1024 * 1024;
    unsigned repeated = 0;
    U64Set set32 = {0}, set64 = {0};
    const u64 start_rva = rva;
    bool empty_result = false;
    while (rva) {
        if (bounded && rva >= start_rva + max_length) break;
        if (*total > MAX_IMPORT_SYMBOLS) break;
        (*total)++;
        if (repeated >= 15) { empty_result = true; break; }
        if (uset_diff(&set32) > spread || uset_diff(&set64) > spread) { empty_result = true; break; }
        DkPeSpan sp;
        if (!dk_pe_try_get_data(pe, rva, (i64)esize, &sp) || sp.n != esize) { empty_result = true; break; }
        u64 aod = plus ? dk_pe__ld64(sp.p) : dk_pe__ld32(sp.p);
        if (aod >= start_rva && aod <= rva) break;
        if (aod) {
            if (aod & ordinal_flag) {
                if ((aod & 0x7FFFFFFFu) > 0xFFFF) { empty_result = true; break; }
            } else if (uset_add(aod >= 0x100000000ull ? &set64 : &set32, aod)) {
                repeated++;
            }
        }
        if (all_zero(sp.p, esize)) break;
        u64 off = 0;
        if (!dk_pe_offset_from_rva(pe, rva, &off)) { empty_result = true; break; }
        Thunk t = {aod, off};
        dk_vec_push(out, t);
        rva += esize;
    }
    if (empty_result) out->n = 0;
    uset_free(&set32);
    uset_free(&set64);
}

/* parse_imports: false where pefile raised PEFormatError (the descriptor then has no imports) */
static bool parse_imports(const DkPe *pe, u32 oft, u32 ft, u64 max_length, unsigned *total, ImportVec *out) {
    ThunkVec ilt = {0}, iat = {0};
    import_table(pe, oft, true, max_length, total, &ilt);
    import_table(pe, ft, true, max_length, total, &iat);
    bool ok = true;
    if (ilt.n == 0 && iat.n == 0) goto done;
    {
        const ThunkVec *table = ilt.n ? &ilt : &iat;
        const bool plus = pe->pe_type == DK_PE_MAGIC_PE32_PLUS;
        const u64 ordinal_flag = plus ? 0x8000000000000000ull : 0x80000000ull;
        const u64 address_mask = plus ? 0x7FFFFFFFFFFFFFFFull : 0x7FFFFFFFull;
        const u64 imp_offset = plus ? 8 : 4;
        size_t num_invalid = 0;
        for (size_t idx = 0; idx < table->n; idx++) {
            const Thunk *t = &table->v[idx];
            DkPeImport imp;
            memset(&imp, 0, sizeof imp);
            bool ord_set = false, name_set = false;
            u16 imp_ord = 0;
            DkStr imp_name = {NULL, 0};
            if (t->address_of_data) {
                if (t->address_of_data & ordinal_flag) {
                    imp.by_ordinal = true;
                    imp_ord = (u16)(t->address_of_data & 0xFFFF);
                    ord_set = true;
                } else {
                    u64 hnt = t->address_of_data & address_mask;
                    DkPeSpan sp;
                    if (dk_pe_try_get_data(pe, hnt, 2, &sp)) {
                        imp.hint_name_table_rva = (u32)hnt;
                        if (sp.n >= 2) {
                            imp.has_hint = true;
                            imp.hint = dk_pe__ld16(sp.p);
                        }
                        imp_name = dk_pe_string_at_rva(pe, t->address_of_data + 2, MAX_IMPORT_NAME_LENGTH);
                        if (!valid_function_name(imp_name)) imp_name = dk_pe__cz("*invalid*");
                        name_set = true;
                        u64 no;
                        if (dk_pe_offset_from_rva(pe, t->address_of_data + 2, &no)) imp.name_offset = (u32)no;
                    }
                }
                imp.thunk_offset = (u32)t->thunk_offset;
                u64 trva = 0;
                if (dk_pe_rva_from_offset(pe, t->thunk_offset, &trva)) imp.thunk_rva = (u32)trva;
            }
            imp.address = (u64)ft + pe->image_base + (u64)idx * imp_offset;
            if (ilt.n && iat.n && idx < ilt.n && idx < iat.n && ilt.v[idx].address_of_data != iat.v[idx].address_of_data) {
                imp.has_bound = true;
                imp.bound = iat.v[idx].address_of_data;
            }
            if (!ord_set && !name_set) { ok = false; goto done; }
            if (name_set && imp_name.n == 9 && memcmp(imp_name.p, "*invalid*", 9) == 0) {
                if (num_invalid > 1000 && num_invalid == idx) { ok = false; goto done; }
                num_invalid++;
                continue;
            }
            if ((ord_set && imp_ord) || (name_set && imp_name.n)) {
                imp.ordinal = imp_ord;
                imp.name = name_set ? imp_name : (DkStr){NULL, 0};
                dk_vec_push(out, imp);
            }
        }
    }
done:
    dk_vec_free(&ilt);
    dk_vec_free(&iat);
    return ok;
}

DkPeImports dk_pe_imports(const DkPe *pe, DkArena *a) {
    DkPeImports res = {0};
    if (pe->n_data_directory <= DK_PE_DIR_IMPORT) return res;
    u64 rva = pe->data_directory[DK_PE_DIR_IMPORT].virtual_address;
    if (!rva) return res;
    ImportDllVec dlls = {0};
    unsigned error_count = 0;
    unsigned total = 0;
    for (;;) {
        DkPeSpan sp;
        if (!dk_pe_try_get_data(pe, rva, 20, &sp)) break;
        if (sp.n < 20) break;
        u64 file_offset = 0;
        if (!dk_pe_offset_from_rva(pe, rva, &file_offset)) break;
        if (all_zero(sp.p, 20)) break;
        u32 oft = dk_pe__ld32(sp.p), tds = dk_pe__ld32(sp.p + 4), fwd = dk_pe__ld32(sp.p + 8),
            nrva = dk_pe__ld32(sp.p + 12), ft = dk_pe__ld32(sp.p + 16);
        rva += 20;
        u64 max_len = pe->file.n - file_offset;
        if (rva > oft || rva > ft) max_len = (u64)DK_MAX((i64)rva - (i64)oft, (i64)rva - (i64)ft);
        ImportVec imps = {0};
        bool ok = parse_imports(pe, oft, ft, max_len, &total, &imps);
        if (!ok) imps.n = 0;
        if (error_count > 5) { dk_vec_free(&imps); break; }
        if (imps.n == 0) {
            error_count++;
            dk_vec_free(&imps);
            continue;
        }
        DkStr dll = dk_pe_string_at_rva(pe, nrva, MAX_DLL_LENGTH);
        if (!valid_dos_filename(dll)) dll = dk_pe__cz("*invalid*");
        if (dll.n) {
            DkPeImport *copy = dk_memdup(a, imps.v, imps.n * sizeof(DkPeImport));
            for (size_t i = 0; i < imps.n; i++) {
                if (!copy[i].name.p) {
                    bool known;
                    DkStr nm = dk_pe__ordinal_name(a, dll, copy[i].ordinal, &known);
                    if (nm.p) copy[i].name = nm;
                }
            }
            DkPeImportDll d = {dll, oft, tds, fwd, nrva, ft, copy, imps.n};
            dk_vec_push(&dlls, d);
        }
        dk_vec_free(&imps);
    }
    if (dlls.n) {
        res.present = true;
        res.dlls = dk_memdup(a, dlls.v, dlls.n * sizeof(DkPeImportDll));
        res.n = dlls.n;
    }
    dk_vec_free(&dlls);
    return res;
}

/* ---- base relocations ------------------------------------------------------------------------------------------ */

/* parse_image_base_relocation_list + parse_relocations. visit(ctx, block page, block size, entries data, nwords)
 * is called for every block; the entries of one block end at its first repeated (offset, type) pair. */
typedef void (*BlockFn)(void *ctx, u32 page, u32 block_size, const u8 *words, size_t nwords, bool *stop);

static size_t block_words(const u8 *w, size_t nwords) {
    /* the number of leading words before a repeated (offset, type) pair: 4096 offsets x 16 types = 64k bits */
    u8 seen[8192];
    memset(seen, 0, sizeof seen);
    size_t k = 0;
    for (; k < nwords; k++) {
        u16 word = dk_pe__ld16(w + 2 * k);
        if (seen[word >> 3] & (1u << (word & 7))) break;
        seen[word >> 3] |= (u8)(1u << (word & 7));
    }
    return k;
}

static void walk_relocations(const DkPe *pe, BlockFn fn, void *ctx) {
    u64 rva = pe->data_directory[DK_PE_DIR_BASERELOC].virtual_address;
    u64 end = rva + pe->data_directory[DK_PE_DIR_BASERELOC].size;
    while (rva < end) {
        DkPeSpan sp;
        if (!dk_pe_try_get_data(pe, rva, 8, &sp) || sp.n < 8) break;
        u32 page = dk_pe__ld32(sp.p), block = dk_pe__ld32(sp.p + 4);
        if (page > pe->size_of_image) break;
        if (block > pe->size_of_image) break;
        DkPeSpan ed = {NULL, 0};
        i64 size = (i64)block - 8;
        if (!dk_pe_try_get_data(pe, rva + 8, size, &ed)) ed = (DkPeSpan){NULL, 0};
        bool stop = false;
        fn(ctx, page, block, ed.p, ed.n / 2, &stop);
        if (stop || !block) break;
        rva += block;
    }
}

typedef struct {
    const DkPe *pe;
    DK_VEC(DkPeRelocBlock) blocks;
    DkArena *a;
} RelocCtx;

static void reloc_block(void *vc, u32 page, u32 block_size, const u8 *words, size_t nwords, bool *stop) {
    RelocCtx *c = vc;
    (void)stop;
    size_t k = nwords ? block_words(words, nwords) : 0;
    DkPeRelocBlock b = {page, block_size, NULL, k};
    b.entries = DK_NEWN(c->a, DkPeReloc, k ? k : 1);
    for (size_t i = 0; i < k; i++) {
        u16 w = dk_pe__ld16(words + 2 * i);
        b.entries[i].word = w;
        b.entries[i].type = (u8)(w >> 12);
        b.entries[i].rva = page + (w & 0x0FFF);
    }
    dk_vec_push(&c->blocks, b);
}

DkPeRelocs dk_pe_relocations(const DkPe *pe, DkArena *a) {
    DkPeRelocs res = {0};
    if (pe->n_data_directory <= DK_PE_DIR_BASERELOC || !pe->data_directory[DK_PE_DIR_BASERELOC].virtual_address)
        return res;
    RelocCtx c = {pe, {0}, a};
    walk_relocations(pe, reloc_block, &c);
    if (c.blocks.n) {
        res.present = true;
        res.blocks = dk_memdup(a, c.blocks.v, c.blocks.n * sizeof(DkPeRelocBlock));
        res.n = c.blocks.n;
    }
    dk_vec_free(&c.blocks);
    return res;
}

typedef struct {
    unsigned type;
    size_t blocks;
    DkU32Vec out;
} RvaCtx;

static void reloc_rvas_block(void *vc, u32 page, u32 block_size, const u8 *words, size_t nwords, bool *stop) {
    RvaCtx *c = vc;
    (void)block_size;
    (void)stop;
    c->blocks++;
    size_t k = nwords ? block_words(words, nwords) : 0;
    for (size_t i = 0; i < k; i++) {
        u16 w = dk_pe__ld16(words + 2 * i);
        if ((unsigned)(w >> 12) == c->type) dk_vec_push(&c->out, page + (w & 0x0FFFu));
    }
}

u32 *dk_pe_reloc_rvas(const DkPe *pe, DkArena *a, unsigned type, size_t *n, bool *present) {
    *n = 0;
    if (present) *present = false;
    if (pe->n_data_directory <= DK_PE_DIR_BASERELOC || !pe->data_directory[DK_PE_DIR_BASERELOC].virtual_address)
        return dk_alloc(a, 4);
    RvaCtx c = {type, 0, {0}};
    walk_relocations(pe, reloc_rvas_block, &c);
    u32 *res = dk_memdup(a, c.out.v ? c.out.v : (u32[1]){0}, (c.out.n ? c.out.n : 1) * sizeof(u32));
    *n = c.out.n;
    if (present) *present = c.blocks > 0; /* pefile keeps the attribute when the block list is not empty */
    dk_vec_free(&c.out);
    return res;
}

/* ---- load configuration ---------------------------------------------------------------------------------------- */

static const char kLc32[] = "4422444444444422444444444224444444444422444444444444";
static const char kLc64[] = "4422444888888422888888884224488888888422844888888888";

DkPeLoadConfig dk_pe_load_config(const DkPe *pe) {
    DkPeLoadConfig lc = {0};
    if (pe->n_data_directory <= DK_PE_DIR_LOAD_CONFIG) return lc;
    u32 rva = pe->data_directory[DK_PE_DIR_LOAD_CONFIG].virtual_address;
    if (!rva) return lc;
    const char *sizes;
    bool plus;
    if (pe->pe_type == DK_PE_MAGIC_PE32) { sizes = kLc32; plus = false; }
    else if (pe->pe_type == DK_PE_MAGIC_PE32_PLUS) { sizes = kLc64; plus = true; }
    else return lc;
    (void)plus;
    u32 dir_size = 0;
    bool have_size = dk_pe_dword_at_rva(pe, rva, &dir_size);
    size_t nfields = strlen(sizes), counter = 0, cum = 0;
    for (size_t i = 0; i < nfields; i++) {
        counter++;
        cum += (size_t)(sizes[i] - '0');
        if (have_size && cum == dir_size) break;
    }
    size_t total = 0;
    size_t offs[64];
    for (size_t i = 0; i < counter; i++) {
        offs[i] = total;
        total += (size_t)(sizes[i] - '0');
    }
    DkPeSpan sp;
    if (!dk_pe_try_get_data(pe, rva, (i64)total, &sp) || sp.n < total) return lc;
    lc.present = true;
    lc.field_count = (unsigned)counter;
#define FIELD(idx, dst, ty)                                                                       \
    do {                                                                                          \
        if ((idx) < counter) {                                                                    \
            size_t w_ = (size_t)(sizes[idx] - '0');                                               \
            dst = (ty)(w_ == 8 ? dk_pe__ld64(sp.p + offs[idx]) : w_ == 4 ? dk_pe__ld32(sp.p + offs[idx]) \
                                                                          : dk_pe__ld16(sp.p + offs[idx])); \
        }                                                                                         \
    } while (0)
    FIELD(0, lc.size, u32);
    FIELD(1, lc.time_date_stamp, u32);
    FIELD(17, lc.security_cookie, u64);
    FIELD(18, lc.se_handler_table, u64);
    FIELD(19, lc.se_handler_count, u64);
    FIELD(20, lc.guard_cf_check_function_pointer, u64);
    FIELD(22, lc.guard_cf_function_table, u64);
    FIELD(23, lc.guard_cf_function_count, u64);
    FIELD(24, lc.guard_flags, u32);
#undef FIELD
    return lc;
}

/* ---- exports ---------------------------------------------------------------------------------------------------- */

typedef struct {
    DkStr name;
    u32 address;
    unsigned count;
} ExportCount;

DkPeExports dk_pe_exports(const DkPe *pe, DkArena *a) {
    DkPeExports res = {0};
    if (pe->n_data_directory <= DK_PE_DIR_EXPORT) return res;
    u32 rva = pe->data_directory[DK_PE_DIR_EXPORT].virtual_address;
    u32 size = pe->data_directory[DK_PE_DIR_EXPORT].size;
    if (!rva) return res;
    DkPeSpan sp;
    if (!dk_pe_try_get_data(pe, rva, 40, &sp) || sp.n < 40) return res;
    u64 off;
    if (!dk_pe_offset_from_rva(pe, rva, &off)) return res;
    u32 characteristics = dk_pe__ld32(sp.p), tds = dk_pe__ld32(sp.p + 4);
    u16 major = dk_pe__ld16(sp.p + 8), minor = dk_pe__ld16(sp.p + 10);
    u32 name_rva = dk_pe__ld32(sp.p + 12), base = dk_pe__ld32(sp.p + 16), nfunc = dk_pe__ld32(sp.p + 20),
        nnames = dk_pe__ld32(sp.p + 24), aof = dk_pe__ld32(sp.p + 28), aon = dk_pe__ld32(sp.p + 32),
        aono = dk_pe__ld32(sp.p + 36);
    bool dir_zero = all_zero(sp.p, 40);

    DkPeSpan names_d, ords_d, funcs_d;
    u64 o1, o2, o3;
    if (!dk_pe_offset_from_rva(pe, aon, &o1) || !dk_pe_offset_from_rva(pe, aono, &o2) ||
        !dk_pe_offset_from_rva(pe, aof, &o3))
        return res;
    if (!dk_pe_try_get_data(pe, aon, (i64)DK_MIN((i64)pe->file.n - (i64)o1, (i64)nnames * 4), &names_d)) return res;
    if (!dk_pe_try_get_data(pe, aono, (i64)DK_MIN((i64)pe->file.n - (i64)o2, (i64)nnames * 4), &ords_d)) return res;
    if (!dk_pe_try_get_data(pe, aof, (i64)DK_MIN((i64)pe->file.n - (i64)o3, (i64)nfunc * 4), &funcs_d)) return res;

    DK_VEC(DkPeExport) exports = {0};
    DK_VEC(ExportCount) counts = {0};
    int failed_left = 10;
    const DkPeSection *sec = dk_pe_section_by_rva(pe, aon);
    i64 boundary = (i64)pe->file.n;
    if (sec) boundary = (i64)sec->virtual_address + (i64)dk_pe_section_data(pe, sec).n - (i64)aon;
    i64 limit = DK_MIN((i64)nnames, boundary / 4);
    bool normal = true;
    bool abandon = false;
    for (i64 i = 0; i < limit; i++) {
        if ((size_t)(i + 1) * 2 > ords_d.n) {
            abandon = true; /* symbol_ordinal None: "assume it's all useless" */
            break;
        }
        u32 so = dk_pe__ld16(ords_d.p + 2 * i);
        if ((size_t)so * 4 >= funcs_d.n) { abandon = true; break; }
        u32 addr = dk_pe__ld32(funcs_d.p + 4 * (size_t)so);
        if (addr == 0) continue;
        DkStr fwd = {NULL, 0};
        if (addr >= rva && addr < (u64)rva + size) {
            u64 fo;
            fwd = dk_pe_string_at_rva(pe, addr, MAX_STRING_LENGTH);
            if (!dk_pe_offset_from_rva(pe, addr, &fo)) continue;
        }
        if ((size_t)(i + 1) * 4 > names_d.n) {
            failed_left--;
            normal = false; /* the name address is None: the name check below fails and ends the loop */
            break;
        }
        u32 nrva = dk_pe__ld32(names_d.p + 4 * (size_t)i);
        DkStr nm = dk_pe_string_at_rva(pe, nrva, MAX_SYMBOL_NAME_LENGTH);
        bool valid = true;
        for (size_t k = 0; k < nm.n; k++) {
            unsigned char c = (unsigned char)nm.p[k];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c && strchr("!\"#$%&'()*+,-./:<>?[\\]^_`{|}~@", c)))) {
                valid = false;
                break;
            }
        }
        if (!valid) { normal = false; break; }
        u64 noff;
        if (!dk_pe_offset_from_rva(pe, nrva, &noff)) {
            if (--failed_left <= 0) { normal = false; break; }
            if (--failed_left <= 0) { normal = false; break; }
            continue;
        }
        /* repeated (name, address) pairs: more than 10 of one, or more than 0x2000 distinct, end the loop */
        size_t ci = 0;
        for (; ci < counts.n; ci++)
            if (counts.v[ci].address == addr && dk_pe__eq(counts.v[ci].name, nm)) break;
        if (ci == counts.n) {
            ExportCount ec = {nm, addr, 0};
            dk_vec_push(&counts, ec);
        }
        counts.v[ci].count++;
        if (counts.v[ci].count > MAX_REPEATED_SYMBOL) break;
        if (counts.n > MAX_SYMBOL_EXPORT_COUNT) break;
        DkPeExport e = {base + so, addr, nm, fwd, nrva};
        dk_vec_push(&exports, e);
    }
    if (abandon) goto none;

    {
        u8 *has_named = dk_xcalloc(1, funcs_d.n / 4 + 1);
        for (size_t k = 0; k < exports.n; k++) {
            u32 idx = exports.v[k].ordinal - base;
            if ((size_t)idx < funcs_d.n / 4 + 1) has_named[idx] = 1;
        }
        failed_left = 10;
        sec = dk_pe_section_by_rva(pe, aof);
        boundary = (i64)pe->file.n;
        if (sec) boundary = (i64)sec->virtual_address + (i64)dk_pe_section_data(pe, sec).n - (i64)aof;
        i64 limit2 = DK_MIN((i64)nfunc, boundary / 4);
        counts.n = 0;
        bool normal2 = true;
        for (i64 idx = 0; idx < limit2; idx++) {
            if ((size_t)idx < funcs_d.n / 4 + 1 && has_named[idx]) continue;
            if ((size_t)(idx + 1) * 4 > funcs_d.n) {
                if (--failed_left <= 0) { normal2 = false; }
                break;
            }
            u32 addr = dk_pe__ld32(funcs_d.p + 4 * (size_t)idx);
            if (addr == 0) continue;
            DkStr fwd = {NULL, 0};
            if (addr >= rva && addr < (u64)rva + size) fwd = dk_pe_string_at_rva(pe, addr, MAX_STRING_LENGTH);
            size_t ci = 0;
            for (; ci < counts.n; ci++)
                if (counts.v[ci].address == addr) break;
            if (ci == counts.n) {
                ExportCount ec = {{NULL, 0}, addr, 0};
                dk_vec_push(&counts, ec);
            }
            counts.v[ci].count++;
            if (counts.v[ci].count > MAX_REPEATED_ORDINAL) break;
            if (counts.n > MAX_SYMBOL_EXPORT_COUNT) break;
            DkPeExport e = {base + (u32)idx, addr, {NULL, 0}, fwd, 0};
            dk_vec_push(&exports, e);
        }
        dk_xfree(has_named);
        if (!normal2) goto none;
    }
    (void)normal;
    if (exports.n == 0 && dir_zero) goto none;
    res.present = true;
    res.characteristics = characteristics;
    res.time_date_stamp = tds;
    res.major_version = major;
    res.minor_version = minor;
    res.base = base;
    res.number_of_functions = nfunc;
    res.number_of_names = nnames;
    res.name = dk_pe_string_at_rva(pe, name_rva, MAX_STRING_LENGTH);
    res.n = exports.n;
    res.exports = dk_memdup(a, exports.v ? exports.v : (DkPeExport[1]){0}, (exports.n ? exports.n : 1) * sizeof(DkPeExport));
none:
    dk_vec_free(&exports);
    dk_vec_free(&counts);
    return res;
}

/* ---- the Rich header --------------------------------------------------------------------- */

bool dk_pe_rich(const void *file, size_t n, DkArena *a, DkPeRich *out) {
    const u8 *d = file;
    size_t end = SIZE_MAX;
    size_t last = DK_MIN((size_t)0x400, n);
    for (size_t at = 0x80; at + 4 <= last; at++)
        if (memcmp(d + at, "Rich", 4) == 0) { end = at; break; }
    if (end == SIZE_MAX || end + 8 > n) return false;
    u32 key = dk_pe__ld32(d + end + 4);
    size_t start = SIZE_MAX;
    for (size_t at = end - 4; at > 0x40; at -= 4) {
        if ((dk_pe__ld32(d + at) ^ key) == 0x536E6144) { start = at; break; }
        if (at < 4) break;
    }
    if (start == SIZE_MAX) return false;
    size_t count = 0;
    for (size_t at = start + 16; at < end; at += 8) count++;
    out->key = key;
    out->n = count;
    out->entries = DK_NEWN(a, DkPeRichEntry, count ? count : 1);
    size_t k = 0;
    for (size_t at = start + 16; at < end; at += 8, k++) {
        u32 compid = dk_pe__ld32(d + at) ^ key;
        u32 cnt = dk_pe__ld32(d + at + 4) ^ key;
        out->entries[k].product = (u16)(compid >> 16);
        out->entries[k].build = (u16)(compid & 0xFFFF);
        out->entries[k].count = cnt;
    }
    return true;
}
