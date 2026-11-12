// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Bump arenas. The tools are short-lived processes: most memory comes from the calling thread's long-lived arena
 * (dk_arena()) and is never freed; loops that allocate per item use a scratch arena with a mark and a reset.
 * Memory from any arena stays valid for the process's life unless that arena is reset or freed, so pointers may be
 * handed to other threads. An arena itself is used by one thread at a time. */
#pragma once
#include "base.h"

typedef struct DkArena DkArena;

DkArena *dk_arena_new(size_t block_size); /* 0: the default block size (1 MiB); larger requests get their own block */
void dk_arena_free(DkArena *a);

void *dk_alloc(DkArena *a, size_t n);     /* zeroed, 16-byte aligned; n == 0 gives a valid unique pointer */
void *dk_alloc_noz(DkArena *a, size_t n); /* not zeroed */
/* Grows (or shrinks) the allocation p of size old_n; in place when p is the arena's last allocation. */
void *dk_arena_realloc(DkArena *a, void *p, size_t old_n, size_t new_n);
char *dk_strdup(DkArena *a, const char *s);
void *dk_memdup(DkArena *a, const void *p, size_t n);
char *dk_sprintf(DkArena *a, DK_PRINTF_FMT const char *fmt, ...); /* C printf rules (not Python's: see fmt.h) */
char *dk_vsprintf(DkArena *a, const char *fmt, va_list ap);

typedef struct {
    void *block;
    size_t used;
} DkArenaMark;
DkArenaMark dk_arena_mark(DkArena *a);
void dk_arena_reset(DkArena *a, DkArenaMark mark); /* frees everything allocated after the mark */
/* Between a mark and its reset, do not grow what was allocated before the mark (dk_arena_realloc, an DkBuf or DkVec on
 * that arena): the grown part counts as allocated after the mark and the reset frees it. */

/* The calling thread's long-lived arena (created on first use, never freed). */
DkArena *dk_arena(void);
/* The calling thread's scratch arena: take a mark, use it, reset to the mark before returning. Never return
 * scratch memory to a caller. */
DkArena *dk_scratch(void);

#define DK_NEW(a, T) ((T *)dk_alloc((a), sizeof(T)))
#define DK_NEWN(a, T, count) ((T *)dk_alloc((a), sizeof(T) * (size_t)(count)))
