// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Shared by pe*.c only. */
#pragma once
#include "dk/pe.h"

static inline u16 dk_pe__ld16(const u8 *p) { u16 v; memcpy(&v, p, 2); return v; }
static inline u32 dk_pe__ld32(const u8 *p) { u32 v; memcpy(&v, p, 4); return v; }
static inline u64 dk_pe__ld64(const u8 *p) { u64 v; memcpy(&v, p, 8); return v; }

/* ordlookup.ordLookup(dll, ordinal): the name of an ordinal of ws2_32/wsock32/oleaut32 ("ord<N>" for an ordinal the
 * table lacks); name.p == NULL (and *known_dll false) for any other DLL. dll is compared case-insensitively. */
DkStr dk_pe__ordinal_name(DkArena *a, DkStr dll, u32 ordinal, bool *known_dll);

/* Local string helpers, so that pe*.c do not depend on str.c. */
static inline bool dk_pe__eq(DkStr a, DkStr b) { return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, a.n) == 0); }
static inline DkStr dk_pe__cz(const char *cz) { return (DkStr){cz, cz ? strlen(cz) : 0}; }
static inline DkStr dk_pe__dup(DkArena *a, DkStr s) {
    char *p = dk_alloc(a, s.n + 1);
    if (s.n) memcpy(p, s.p, s.n);
    return (DkStr){p, s.n};
}
