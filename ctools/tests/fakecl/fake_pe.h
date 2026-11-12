// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* A PE32 image writer for the adapter's tests and the fake linker: sections at 0x1000-aligned RVAs (file alignment
 * 0x200), a base relocation directory of HIGHLOW entries and an optional import directory of one DLL. Written from
 * the PE format's documented layout; nothing is read from disk.
 *
 *     FakePe pe;
 *     fake_pe_init(&pe, 0x00400000u);
 *     u32 text = fake_pe_section(&pe, ".text", 0x60000020u, code, n);   // returns the section's RVA
 *     fake_pe_reloc(&pe, text + 6);                                     // a HIGHLOW word at that RVA
 *     u32 iat = fake_pe_import(&pe, "KERNEL32.dll", "Sleep");           // the IAT slot's RVA (after the sections)
 *     fake_pe_write(&pe, path);
 *
 * Section RVAs are given in the order sections are added; imports go to an ".idata" section placed after them, so
 * fake_pe_import's RVA is known as soon as the last section was added. */
#pragma once
#include "dk/dk.h"

#include <string.h>

enum { FAKE_PE_MAX_SECTIONS = 8, FAKE_PE_MAX_IMPORTS = 16 };

typedef struct {
    char name[9];
    u32 chars;
    u32 rva;
    DkBytes data;
} FakePeSection;

typedef struct {
    u32 base;
    FakePeSection secs[FAKE_PE_MAX_SECTIONS];
    int nsecs;
    DkU32Vec relocs;
    const char *dll;
    const char *imports[FAKE_PE_MAX_IMPORTS];
    int nimports;
} FakePe;

static inline u32 fake_pe__align(u32 v, u32 a) { return (v + a - 1) & ~(a - 1); }
static inline void fake_pe__put32(u8 *p, u32 v) { memcpy(p, &v, 4); }
static inline void fake_pe__put16(u8 *p, u16 v) { memcpy(p, &v, 2); }

static inline void fake_pe_init(FakePe *pe, u32 base) {
    memset(pe, 0, sizeof *pe);
    pe->base = base;
}

static inline u32 fake_pe__next_rva(const FakePe *pe) {
    if (!pe->nsecs) return 0x1000;
    const FakePeSection *l = &pe->secs[pe->nsecs - 1];
    return fake_pe__align(l->rva + (u32)(l->data.n ? l->data.n : 1), 0x1000);
}

static inline u32 fake_pe_section(FakePe *pe, const char *name, u32 chars, const void *data, size_t n) {
    DK_ASSERT(pe->nsecs < FAKE_PE_MAX_SECTIONS - 2);
    FakePeSection *s = &pe->secs[pe->nsecs];
    memset(s, 0, sizeof *s);
    strncpy(s->name, name, 8);
    s->chars = chars;
    s->rva = fake_pe__next_rva(pe);
    if (n) dk_vec_extend(&s->data, (const u8 *)data, n);
    pe->nsecs++;
    return s->rva;
}

static inline void fake_pe_reloc(FakePe *pe, u32 rva) { dk_vec_push(&pe->relocs, rva); }

/* The IAT layout of the .idata section (placed right after the added sections): descriptors (2 * 20 bytes), the
 * lookup table, the address table, then the hint/name entries and the DLL name. */
static inline u32 fake_pe__iat_rva(const FakePe *pe, int index) {
    u32 at = fake_pe__next_rva(pe);
    return at + 40 + 4 * (u32)(pe->nimports + 1) + 4 * (u32)index;
}

/* Declares an import; the RVA it returns is final only once all imports are declared (the tables grow). Call it for
 * every import first, then read the slots with fake_pe_import_slot. */
static inline void fake_pe_import(FakePe *pe, const char *dll, const char *name) {
    DK_ASSERT(pe->nimports < FAKE_PE_MAX_IMPORTS);
    pe->dll = dll;
    pe->imports[pe->nimports++] = name;
}
static inline u32 fake_pe_import_slot(const FakePe *pe, int index) { return fake_pe__iat_rva(pe, index); }

static inline void fake_pe__idata(FakePe *pe) {
    if (!pe->nimports) return;
    u32 rva = fake_pe__next_rva(pe);
    u32 n = (u32)pe->nimports;
    u32 ilt = 40, iat = ilt + 4 * (n + 1), names = iat + 4 * (n + 1);
    DkBytes d = {0};
    dk_vec_reserve(&d, names + 64 * (n + 1));
    memset(d.v, 0, names);
    d.n = names;
    u32 *hint_at = (u32 *)dk_xmalloc(4 * n);
    for (u32 i = 0; i < n; i++) {
        hint_at[i] = (u32)d.n;
        u8 hint[2] = {0, 0};
        dk_vec_extend(&d, hint, 2);
        dk_vec_extend(&d, (const u8 *)pe->imports[i], strlen(pe->imports[i]) + 1);
        if (d.n & 1) dk_vec_push(&d, 0);
    }
    u32 dll_at = (u32)d.n;
    dk_vec_extend(&d, (const u8 *)pe->dll, strlen(pe->dll) + 1);
    for (u32 i = 0; i < n; i++) {
        fake_pe__put32(d.v + ilt + 4 * i, rva + hint_at[i]);
        fake_pe__put32(d.v + iat + 4 * i, rva + hint_at[i]);
    }
    fake_pe__put32(d.v + 0, rva + ilt);   /* OriginalFirstThunk */
    fake_pe__put32(d.v + 12, rva + dll_at); /* Name */
    fake_pe__put32(d.v + 16, rva + iat);  /* FirstThunk */
    dk_xfree(hint_at);
    FakePeSection *s = &pe->secs[pe->nsecs++];
    memset(s, 0, sizeof *s);
    strncpy(s->name, ".idata", 8);
    s->chars = 0xC0000040u;
    s->rva = rva;
    s->data = d;
}

static inline int fake_pe__cmp(const void *x, const void *y) {
    u32 a = *(const u32 *)x, b = *(const u32 *)y;
    return a < b ? -1 : a > b;
}

static inline void fake_pe__reloc_section(FakePe *pe) {
    if (!pe->relocs.n) return;
    qsort(pe->relocs.v, pe->relocs.n, sizeof *pe->relocs.v, fake_pe__cmp);
    DkBytes d = {0};
    size_t i = 0;
    while (i < pe->relocs.n) {
        u32 page = pe->relocs.v[i] & ~0xFFFu;
        size_t j = i;
        while (j < pe->relocs.n && (pe->relocs.v[j] & ~0xFFFu) == page) j++;
        u32 count = (u32)(j - i), padded = (count + 1) & ~1u;
        u8 head[8];
        fake_pe__put32(head, page);
        fake_pe__put32(head + 4, 8 + 2 * padded);
        dk_vec_extend(&d, head, 8);
        for (size_t k = i; k < j; k++) {
            u8 e[2];
            fake_pe__put16(e, (u16)(0x3000 | (pe->relocs.v[k] & 0xFFF)));
            dk_vec_extend(&d, e, 2);
        }
        if (padded != count) {
            u8 z[2] = {0, 0};
            dk_vec_extend(&d, z, 2);
        }
        i = j;
    }
    FakePeSection *s = &pe->secs[pe->nsecs];
    memset(s, 0, sizeof *s);
    strncpy(s->name, ".reloc", 8);
    s->chars = 0x42000040u;
    s->rva = fake_pe__next_rva(pe);
    s->data = d;
    pe->nsecs++;
}

/* Writes the image (and frees the builder's buffers). */
static inline bool fake_pe_write(FakePe *pe, const char *path) {
    fake_pe__idata(pe);
    int idata = pe->nimports ? pe->nsecs - 1 : -1;
    fake_pe__reloc_section(pe);
    int reloc = pe->relocs.n ? pe->nsecs - 1 : -1;
    const u32 nt = 0x80, opt = nt + 24, sect = opt + 224;
    const u32 headers = fake_pe__align(sect + 40 * (u32)pe->nsecs, 0x200);
    u32 raw = headers;
    u32 size_of_image = fake_pe__next_rva(pe);
    DkBytes o = {0};
    dk_vec_reserve(&o, headers);
    memset(o.v, 0, headers);
    o.n = headers;
    u8 *p = o.v;
    p[0] = 'M';
    p[1] = 'Z';
    fake_pe__put32(p + 0x3C, nt);
    memcpy(p + nt, "PE\0\0", 4);
    fake_pe__put16(p + nt + 4, 0x14C);
    fake_pe__put16(p + nt + 6, (u16)pe->nsecs);
    fake_pe__put16(p + nt + 20, 224);
    fake_pe__put16(p + nt + 22, 0x2102); /* executable, 32-bit, DLL */
    fake_pe__put16(p + opt, 0x10B);
    fake_pe__put32(p + opt + 20, 0x1000); /* BaseOfCode */
    fake_pe__put32(p + opt + 28, pe->base);
    fake_pe__put32(p + opt + 32, 0x1000);
    fake_pe__put32(p + opt + 36, 0x200);
    fake_pe__put16(p + opt + 40, 5);
    fake_pe__put16(p + opt + 48, 5);
    fake_pe__put32(p + opt + 56, size_of_image);
    fake_pe__put32(p + opt + 60, headers);
    fake_pe__put16(p + opt + 68, 2);
    fake_pe__put32(p + opt + 72, 0x100000);
    fake_pe__put32(p + opt + 76, 0x1000);
    fake_pe__put32(p + opt + 80, 0x100000);
    fake_pe__put32(p + opt + 84, 0x1000);
    fake_pe__put32(p + opt + 92, 16);
    if (idata >= 0) {
        fake_pe__put32(p + opt + 96 + 8, pe->secs[idata].rva);
        fake_pe__put32(p + opt + 96 + 12, 40);
        fake_pe__put32(p + opt + 96 + 96, pe->secs[idata].rva + 40 + 4 * (u32)(pe->nimports + 1));
        fake_pe__put32(p + opt + 96 + 100, 4 * (u32)(pe->nimports + 1));
    }
    if (reloc >= 0) {
        fake_pe__put32(p + opt + 96 + 40, pe->secs[reloc].rva);
        fake_pe__put32(p + opt + 96 + 44, (u32)pe->secs[reloc].data.n);
    }
    for (int i = 0; i < pe->nsecs; i++) {
        FakePeSection *s = &pe->secs[i];
        u8 *h = p + sect + 40 * (u32)i;
        memcpy(h, s->name, strlen(s->name));
        u32 rawsize = fake_pe__align((u32)s->data.n, 0x200);
        fake_pe__put32(h + 8, (u32)(s->data.n ? s->data.n : 1));
        fake_pe__put32(h + 12, s->rva);
        fake_pe__put32(h + 16, rawsize);
        fake_pe__put32(h + 20, rawsize ? raw : 0);
        fake_pe__put32(h + 36, s->chars);
        raw += rawsize;
    }
    for (int i = 0; i < pe->nsecs; i++) {
        FakePeSection *s = &pe->secs[i];
        u32 rawsize = fake_pe__align((u32)s->data.n, 0x200);
        size_t at = o.n;
        dk_vec_reserve(&o, at + rawsize);
        memset(o.v + at, 0, rawsize);
        if (s->data.n) memcpy(o.v + at, s->data.v, s->data.n);
        o.n = at + rawsize;
        dk_vec_free(&s->data);
    }
    dk_vec_free(&pe->relocs);
    bool ok = dk_write_file(path, o.v, o.n);
    dk_vec_free(&o);
    return ok;
}
