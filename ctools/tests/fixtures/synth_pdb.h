// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Writers of synthetic PDB 7.00 files for tests: an MSF container from a list of streams, and the stream bodies
 * (PDB info, DBI, symbol records, module symbols with C13 lines, a TPI) written from the documented layouts. Nothing
 * here comes from a real PDB. Streams: 0 old directory (empty), 1 PDB info, 2 TPI, 3 DBI, 4 symbol records,
 * 5 section headers, 6 /names, 7.. module streams. */
#pragma once
#include "dk/dk.h"

typedef struct {
    DkBytes data;
} SynthBuf;

static inline void sb_u8(SynthBuf *b, u32 v) { dk_vec_push(&b->data, (u8)v); }
static inline void sb_u16(SynthBuf *b, u32 v) {
    sb_u8(b, v & 0xFF);
    sb_u8(b, (v >> 8) & 0xFF);
}
static inline void sb_u32(SynthBuf *b, u32 v) {
    sb_u16(b, v & 0xFFFF);
    sb_u16(b, v >> 16);
}
static inline void sb_bytes(SynthBuf *b, const void *p, size_t n) { dk_vec_extend(&b->data, (const u8 *)p, n); }
static inline void sb_cstr(SynthBuf *b, const char *s) { sb_bytes(b, s, strlen(s) + 1); }
static inline void sb_pstr(SynthBuf *b, const char *s) {
    sb_u8(b, (u32)strlen(s));
    sb_bytes(b, s, strlen(s));
}
static inline void sb_pad4(SynthBuf *b) {
    while (b->data.n % 4) sb_u8(b, 0);
}
static inline void sb_set32(SynthBuf *b, size_t at, u32 v) {
    for (int i = 0; i < 4; i++) b->data.v[at + (size_t)i] = (u8)(v >> (8 * i));
}

/* A symbol or type record: length (of what follows), kind, body. */
static inline void sb_record(SynthBuf *out, u32 kind, const SynthBuf *body) {
    sb_u16(out, (u32)body->data.n + 2);
    sb_u16(out, kind);
    sb_bytes(out, body->data.v, body->data.n);
}

enum { SYNTH_BLOCK = 512, SYNTH_MAX_STREAMS = 16 };

typedef struct {
    SynthBuf stream[SYNTH_MAX_STREAMS];
    int count;
} SynthPdb;

/* The MSF 7.00 container: block 0 the superblock, 1 and 2 the free block maps, the streams from block 3, then the
 * directory and the block holding the directory's block list. A stream with size 0xFFFFFFFF (nil) is written by
 * setting nil[i]. */
static inline void synth_msf_write(const SynthPdb *pdb, const bool *nil, SynthBuf *out) {
    SynthBuf dir = {{0}};
    u32 next_block = 3;
    u32 first[SYNTH_MAX_STREAMS] = {0};
    for (int i = 0; i < pdb->count; i++) {
        first[i] = next_block;
        next_block += (u32)((pdb->stream[i].data.n + SYNTH_BLOCK - 1) / SYNTH_BLOCK);
    }
    sb_u32(&dir, (u32)pdb->count);
    for (int i = 0; i < pdb->count; i++) sb_u32(&dir, (nil && nil[i]) ? 0xFFFFFFFFu : (u32)pdb->stream[i].data.n);
    for (int i = 0; i < pdb->count; i++) {
        if (nil && nil[i]) continue;
        u32 nb = (u32)((pdb->stream[i].data.n + SYNTH_BLOCK - 1) / SYNTH_BLOCK);
        for (u32 j = 0; j < nb; j++) sb_u32(&dir, first[i] + j);
    }
    u32 dir_blocks = (u32)((dir.data.n + SYNTH_BLOCK - 1) / SYNTH_BLOCK);
    u32 dir_first = next_block, map_block = dir_first + dir_blocks, total = map_block + 1;

    static const char magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0";
    sb_bytes(out, magic, 32);
    sb_u32(out, SYNTH_BLOCK);
    sb_u32(out, 1);     /* free block map */
    sb_u32(out, total); /* number of blocks */
    sb_u32(out, (u32)dir.data.n);
    sb_u32(out, 0);
    sb_u32(out, map_block);
    while (out->data.n < (size_t)total * SYNTH_BLOCK) sb_u8(out, 0);
    for (int i = 0; i < pdb->count; i++) {
        if (nil && nil[i]) continue;
        memcpy(out->data.v + (size_t)first[i] * SYNTH_BLOCK, pdb->stream[i].data.v, pdb->stream[i].data.n);
    }
    memcpy(out->data.v + (size_t)dir_first * SYNTH_BLOCK, dir.data.v, dir.data.n);
    for (u32 j = 0; j < dir_blocks; j++) {
        u32 v = dir_first + j;
        for (int k = 0; k < 4; k++) out->data.v[(size_t)map_block * SYNTH_BLOCK + 4 * j + (size_t)k] = (u8)(v >> (8 * k));
    }
    dk_vec_free(&dir.data);
}

/* The PDB info stream: version, signature, age, GUID, then the named stream map with one entry, name -> stream. */
static inline void synth_info(SynthBuf *b, const char *name, u32 stream) {
    sb_u32(b, 20000404);
    sb_u32(b, 0x12345678);
    sb_u32(b, 1);
    for (int i = 0; i < 16; i++) sb_u8(b, (u32)i);
    sb_u32(b, (u32)strlen(name) + 1); /* the string buffer */
    sb_cstr(b, name);
    sb_u32(b, 1); /* entries */
    sb_u32(b, 1); /* capacity */
    sb_u32(b, 1); /* present bit vector: one word */
    sb_u32(b, 1);
    sb_u32(b, 0); /* deleted bit vector: none */
    sb_u32(b, 0); /* name offset */
    sb_u32(b, stream);
}

/* The /names stream: signature, version, size, then the strings (offset 0 is the empty string's slot). */
static inline void synth_names(SynthBuf *b, const char *const *names, int n, u32 *offsets) {
    sb_u32(b, 0xEFFEEFFE);
    sb_u32(b, 1);
    sb_u32(b, 0);
    for (int i = 0; i < n; i++) {
        offsets[i] = (u32)b->data.n - 12;
        sb_cstr(b, names[i]);
    }
    sb_set32(b, 8, (u32)b->data.n - 12);
}

/* A public symbol record (S_PUB32, flags bit 1 = function). */
static inline void synth_public(SynthBuf *recs, const char *name, u32 seg, u32 off, u32 flags) {
    SynthBuf body = {{0}};
    sb_u32(&body, flags);
    sb_u32(&body, off);
    sb_u16(&body, seg);
    sb_cstr(&body, name);
    sb_record(recs, 0x110E, &body);
    dk_vec_free(&body.data);
}

/* A section header stream with n headers of 40 bytes whose virtual addresses are rva[i]. */
static inline void synth_sections(SynthBuf *b, const u32 *rva, int n) {
    for (int i = 0; i < n; i++) {
        size_t at = b->data.n;
        for (int k = 0; k < 40; k++) sb_u8(b, 0);
        sb_set32(b, at + 12, rva[i]);
    }
}

/* S_GPROC32 (kind 0x1110) or S_LPROC32 (0x110F). */
static inline void synth_proc(SynthBuf *syms, u32 kind, const char *name, u32 seg, u32 off, u32 len, u32 typind) {
    SynthBuf body = {{0}};
    sb_u32(&body, 0); /* parent */
    sb_u32(&body, 0); /* end */
    sb_u32(&body, 0); /* next */
    sb_u32(&body, len);
    sb_u32(&body, 0); /* debug start */
    sb_u32(&body, len);
    sb_u32(&body, typind);
    sb_u32(&body, off);
    sb_u16(&body, seg);
    sb_u8(&body, 0); /* flags */
    sb_cstr(&body, name);
    sb_record(syms, kind, &body);
    dk_vec_free(&body.data);
}

/* S_COMPILE3: flags, machine, frontend and backend versions (4 x u16), the compiler string. */
static inline void synth_compile3(SynthBuf *syms, u32 machine, const u32 fe[4], const u32 be[4], const char *text) {
    SynthBuf body = {{0}};
    sb_u32(&body, 0x00010101u);
    sb_u16(&body, machine);
    for (int i = 0; i < 4; i++) sb_u16(&body, fe[i]);
    for (int i = 0; i < 4; i++) sb_u16(&body, be[i]);
    sb_cstr(&body, text);
    sb_record(syms, 0x113C, &body);
    dk_vec_free(&body.data);
}

/* S_ENVBLOCK: a flag byte, then key and value strings, ended by an empty key. */
static inline void synth_envblock(SynthBuf *syms, const char *const *kv, int n) {
    SynthBuf body = {{0}};
    sb_u8(&body, 0);
    for (int i = 0; i < n; i++) sb_cstr(&body, kv[i]);
    sb_u8(&body, 0);
    sb_record(syms, 0x113D, &body);
    dk_vec_free(&body.data);
}

/* One module stream: signature, symbols, then C13 subsections (DEBUG_S_LINES of one block, DEBUG_S_FILECHKSMS of one
 * file whose name is at names offset name_off). The line entries are (offset, line) pairs. */
static inline void synth_module_stream(SynthBuf *out, const SynthBuf *syms, u32 seg, u32 base_off,
                                       u32 name_off, const u32 (*lines)[2], int nlines, u32 *sym_bytes,
                                       u32 *c13_bytes) {
    sb_u32(out, 4); /* signature */
    sb_bytes(out, syms->data.v, syms->data.n);
    *sym_bytes = (u32)out->data.n;
    size_t c13_start = out->data.n;
    if (nlines) {
        SynthBuf sub = {{0}};
        sb_u32(&sub, base_off);
        sb_u16(&sub, seg);
        sb_u16(&sub, 0); /* flags: no columns */
        sb_u32(&sub, 0x100); /* code size */
        sb_u32(&sub, 0); /* file id: the checksum entry at 0 */
        sb_u32(&sub, (u32)nlines);
        sb_u32(&sub, 12 + 8 * (u32)nlines);
        for (int i = 0; i < nlines; i++) {
            sb_u32(&sub, lines[i][0]);
            sb_u32(&sub, lines[i][1] | 0x80000000u); /* is-statement */
        }
        sb_u32(out, 0xF2);
        sb_u32(out, (u32)sub.data.n);
        sb_bytes(out, sub.data.v, sub.data.n);
        sb_pad4(out);
        SynthBuf chk = {{0}};
        sb_u32(&chk, name_off);
        sb_u8(&chk, 16); /* checksum bytes */
        sb_u8(&chk, 1);  /* MD5 */
        for (int i = 0; i < 16; i++) sb_u8(&chk, 0xA0u + (u32)i);
        sb_pad4(&chk);
        sb_u32(out, 0xF4);
        sb_u32(out, (u32)chk.data.n);
        sb_bytes(out, chk.data.v, chk.data.n);
        dk_vec_free(&sub.data);
        dk_vec_free(&chk.data);
    }
    *c13_bytes = (u32)(out->data.n - c13_start);
}

/* One DBI module information record. */
static inline void synth_modinfo(SynthBuf *b, u32 sec, u32 off, u32 size, u32 stream, u32 sym_bytes, u32 c13_bytes,
                                 const char *module, const char *object) {
    sb_u32(b, 0);
    sb_u16(b, sec);
    sb_u16(b, 0);
    sb_u32(b, off);
    sb_u32(b, size);
    sb_u32(b, 0x60000020u); /* characteristics */
    sb_u16(b, 0);           /* module index */
    sb_u16(b, 0);
    sb_u32(b, 0);           /* data crc */
    sb_u32(b, 0);           /* reloc crc */
    sb_u16(b, 0);           /* flags */
    sb_u16(b, stream);
    sb_u32(b, sym_bytes);
    sb_u32(b, 0);           /* C11 bytes */
    sb_u32(b, c13_bytes);
    sb_u16(b, 1);           /* source files */
    sb_u16(b, 0);
    sb_u32(b, 0); /* file name offsets */
    sb_u32(b, 0); /* source file */
    sb_u32(b, 0); /* pdb file */
    sb_cstr(b, module);
    sb_cstr(b, object);
    sb_pad4(b);
}

/* One DBI section contribution (the 28-byte V60 form). */
static inline void synth_contrib(SynthBuf *b, u32 sec, u32 off, u32 size, u32 flags, u32 mod) {
    sb_u16(b, sec);
    sb_u16(b, 0);
    sb_u32(b, off);
    sb_u32(b, size);
    sb_u32(b, flags);
    sb_u16(b, mod);
    sb_u16(b, 0);
    sb_u32(b, 0);
    sb_u32(b, 0);
}

/* The DBI stream: header, module infos, section contributions, an optional debug header naming the section header
 * stream as its sixth entry. */
static inline void synth_dbi(SynthBuf *b, u32 symrec_stream, u32 sechdr_stream, const SynthBuf *mods,
                             const SynthBuf *contribs) {
    SynthBuf opt = {{0}};
    for (int i = 0; i < 6; i++) sb_u16(&opt, i == 5 ? sechdr_stream : 0xFFFF);
    sb_u32(b, 0xFFFFFFFFu);
    sb_u32(b, 19990903); /* version V70 */
    sb_u32(b, 1);        /* age */
    sb_u16(b, 0xFFFF);   /* global symbol stream */
    sb_u16(b, 0x8000 | 8);
    sb_u16(b, 0xFFFF);   /* public symbol stream */
    sb_u16(b, 0);
    sb_u16(b, symrec_stream);
    sb_u16(b, 0);
    sb_u32(b, (u32)mods->data.n);
    sb_u32(b, (u32)contribs->data.n);
    sb_u32(b, 0); /* section map */
    sb_u32(b, 0); /* file info */
    sb_u32(b, 0); /* type server map */
    sb_u32(b, 0); /* mfc type server index */
    sb_u32(b, (u32)opt.data.n);
    sb_u32(b, 0); /* EC substream */
    sb_u32(b, 0); /* flags and machine */
    sb_u32(b, 0);
    sb_bytes(b, mods->data.v, mods->data.n);
    sb_bytes(b, contribs->data.v, contribs->data.n);
    sb_bytes(b, opt.data.v, opt.data.n);
    dk_vec_free(&opt.data);
}

/* TPI records: each type record is (length, leaf, body); the table is returned as the stream. */
static inline void synth_tpi(SynthBuf *b, const SynthBuf *records, u32 count) {
    sb_u32(b, 20040203);
    sb_u32(b, 56);
    sb_u32(b, 0x1000);
    sb_u32(b, 0x1000 + count);
    sb_u32(b, (u32)records->data.n);
    for (int i = 0; i < 9; i++) sb_u32(b, 0); /* hash stream indexes and offsets */
    sb_bytes(b, records->data.v, records->data.n);
}

static inline void synth_pdb_free(SynthPdb *p) {
    for (int i = 0; i < p->count; i++) dk_vec_free(&p->stream[i].data);
}
