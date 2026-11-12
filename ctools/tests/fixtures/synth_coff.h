// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Fixture writer of i386 COFF objects for tests: sections (with data and relocations) and symbols (with auxiliary
 * records), serialised in the layout the VC8 compiler writes: header, section headers, then each section's data and
 * relocations, the symbol table, the string table. Long names go through coff.h's CoffStringTable.
 *
 *     SynthCoff sc;
 *     synth_coff_init(&sc);
 *     u32 text = synth_coff_section(&sc, ".text", 0x60500020u, code, code_len);    // 1-based section number
 *     u32 fn = synth_coff_symbol(&sc, "_fn", 0, (i16)text, 0x20, 2, 0);            // symbol table slot
 *     synth_coff_reloc(&sc, text, 4, fn, 0x14);
 *     DkStr obj = synth_coff_build(&sc);                                            // in the thread's arena
 *
 * An auxiliary record occupies a slot of its own: synth_coff_aux() after the symbol that announces it. */
#pragma once
#include "dk/dk.h"
#include "../../lib/coff.h"

enum { SYNTH_COFF_MAX_SECTIONS = 8 };

typedef struct {
    char name[9]; /* cut to 8 bytes in the section header; the symbol of the section keeps its own name */
    u32 flags;
    DkBytes data;
    DkBytes relocs; /* 10-byte records */
} SynthSection;

typedef struct {
    SynthSection sections[SYNTH_COFF_MAX_SECTIONS];
    u32 nsections;
    DkBytes symbols; /* 18-byte records, names resolved through `strings` as they are added */
    u32 nsyms;
    CoffStringTable strings;
} SynthCoff;

static inline void synth_coff__put(DkBytes *o, const void *p, size_t n) {
    if (n) dk_vec_extend(o, (const u8 *)p, n);
}
static inline void synth_coff__put16(DkBytes *o, u16 v) { synth_coff__put(o, &v, 2); }
static inline void synth_coff__put32(DkBytes *o, u32 v) { synth_coff__put(o, &v, 4); }

static inline void synth_coff_init(SynthCoff *sc) {
    memset(sc, 0, sizeof *sc);
    coff_string_table_init(&sc->strings);
}

/* Adds a section holding data; returns its 1-based number. */
static inline u32 synth_coff_section(SynthCoff *sc, const char *name, u32 flags, const void *data, size_t n) {
    SynthSection *s = &sc->sections[sc->nsections];
    DK_ASSERT(sc->nsections < SYNTH_COFF_MAX_SECTIONS);
    strncpy(s->name, name, 8);
    s->flags = flags;
    synth_coff__put(&s->data, data, n);
    return ++sc->nsections;
}

/* Adds a relocation of section `section` (1-based): the 32-bit word at `offset` names symbol slot `symbol`. */
static inline void synth_coff_reloc(SynthCoff *sc, u32 section, u32 offset, u32 symbol, u16 type) {
    SynthSection *s = &sc->sections[section - 1];
    synth_coff__put32(&s->relocs, offset);
    synth_coff__put32(&s->relocs, symbol);
    synth_coff__put16(&s->relocs, type);
}

/* Adds a symbol record (the aux count is the number of synth_coff_aux calls that follow); returns its slot. */
static inline u32 synth_coff_symbol(SynthCoff *sc, const char *name, u32 value, i16 section, u16 type, u8 storage,
                                    u8 aux) {
    u8 f[8];
    coff_string_table_name_field(&sc->strings, dk_str(name), f);
    synth_coff__put(&sc->symbols, f, 8);
    synth_coff__put32(&sc->symbols, value);
    synth_coff__put16(&sc->symbols, (u16)section);
    synth_coff__put16(&sc->symbols, type);
    dk_vec_push(&sc->symbols, storage);
    dk_vec_push(&sc->symbols, aux);
    return sc->nsyms++;
}

/* Adds the 18 bytes of an auxiliary record; returns its slot. */
static inline u32 synth_coff_aux(SynthCoff *sc, const u8 rec[18]) {
    synth_coff__put(&sc->symbols, rec, 18);
    return sc->nsyms++;
}

/* Serialises the object into the thread's arena and frees the builder's buffers. */
static inline DkStr synth_coff_build(SynthCoff *sc) {
    DkBytes o = {0};
    u32 at = 20 + 40 * sc->nsections;
    for (u32 i = 0; i < sc->nsections; i++) at += (u32)(sc->sections[i].data.n + sc->sections[i].relocs.n);
    synth_coff__put16(&o, COFF_IMAGE_FILE_MACHINE_I386);
    synth_coff__put16(&o, (u16)sc->nsections);
    synth_coff__put32(&o, 0);
    synth_coff__put32(&o, at);
    synth_coff__put32(&o, sc->nsyms);
    synth_coff__put32(&o, 0);
    u32 raw = 20 + 40 * sc->nsections;
    for (u32 i = 0; i < sc->nsections; i++) {
        SynthSection *s = &sc->sections[i];
        u8 nm[8] = {0};
        memcpy(nm, s->name, strlen(s->name));
        synth_coff__put(&o, nm, 8);
        synth_coff__put32(&o, 0);
        synth_coff__put32(&o, 0);
        synth_coff__put32(&o, (u32)s->data.n);
        synth_coff__put32(&o, raw);
        synth_coff__put32(&o, s->relocs.n ? raw + (u32)s->data.n : 0);
        synth_coff__put32(&o, 0);
        synth_coff__put16(&o, (u16)(s->relocs.n / 10));
        synth_coff__put16(&o, 0);
        synth_coff__put32(&o, s->flags);
        raw += (u32)(s->data.n + s->relocs.n);
    }
    for (u32 i = 0; i < sc->nsections; i++) {
        synth_coff__put(&o, sc->sections[i].data.v, sc->sections[i].data.n);
        synth_coff__put(&o, sc->sections[i].relocs.v, sc->sections[i].relocs.n);
        dk_vec_free(&sc->sections[i].data);
        dk_vec_free(&sc->sections[i].relocs);
    }
    synth_coff__put(&o, sc->symbols.v, sc->symbols.n);
    DkStr blob = coff_string_table_blob(&sc->strings);
    synth_coff__put(&o, blob.p, blob.n);
    DkStr r = {(const char *)dk_memdup(dk_arena(), o.v, o.n), o.n};
    dk_vec_free(&o);
    dk_vec_free(&sc->symbols);
    dk_vec_free(&sc->strings.data);
    return r;
}
