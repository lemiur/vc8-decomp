// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* What pdb.c and pdb_types.c share: bounds-checked little-endian reads that throw DK_ERR_FORMAT where the data is
 * short, and the Latin-1 string readers. Slices clamp. */
#pragma once
#include "pdb.h"

DK_NORETURN void pdb_fail(const char *what);
/* The n bytes at off of b, or pdb_fail (off < 0 too). */
const u8 *pdb_at(DkStr b, i64 off, size_t n);
static inline u8 pdb_u8(DkStr b, i64 off) { return *pdb_at(b, off, 1); }
static inline u16 pdb_le16(DkStr b, i64 off) {
    const u8 *p = pdb_at(b, off, 2);
    return (u16)(p[0] | (p[1] << 8));
}
static inline u32 pdb_le32(DkStr b, i64 off) {
    const u8 *p = pdb_at(b, off, 4);
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
/* Latin-1 bytes to a UTF-8 string of the arena, NUL-terminated. */
char *pdb_latin1(DkArena *a, const void *p, size_t n);
/* The NUL-terminated string at p (the text and the index after the NUL) / the length-prefixed string at p. */
const char *pdb_cstr(DkStr b, i64 p, i64 *next);
const char *pdb_pstr(DkStr b, i64 p, i64 *next);
/* The LF_NUMERIC leaf at p (an integer leaf; a float or other leaf fails). */
i64 pdb_numeric(DkStr b, i64 p, i64 *next);
