// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Private helpers shared by the fs*.c and win*.c files of dkcore (not part of the public API). */
#pragma once
#include "dk/dk.h"
#include "dk/fs.h"
#include "dk/win.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <winioctl.h>

/* UTF-8 <-> UTF-16. u8_to_w gives a NUL-terminated string (invalid bytes become U+FFFD). */
wchar_t *dk_fs_u8_to_w(DkArena *a, const char *s);
/* UTF-16 (n units, or n < 0 up to the NUL) to a NUL-terminated UTF-8 string of the arena. */
char *dk_fs_w_to_u8(DkArena *a, const wchar_t *w, i64 n);
/* The path for a Win32 call: UTF-16, with the \\?\ prefix added (after GetFullPathNameW) when it would not fit in
 * MAX_PATH. */
wchar_t *dk_fs_wpath(DkArena *a, const char *path);

/* Failure recording (see fs.h). The path arguments may be NULL. */
void dk_fs_fail_last(const char *path, const char *path2);              /* [WinError n] of GetLastError() */
void dk_fs_fail_open(unsigned winerror, const char *path);               /* open()'s [Errno n] from a Win32 error */
void dk_fs_fail_value(const char *fmt, ...);                             /* ValueError */
void dk_fs_fail_embedded_nul(void);

/* A minimal growing string builder over an arena (or the heap when a is NULL), so these files do not depend on
 * str.c. The content is NUL-terminated after fsb_cz(). */
typedef struct {
    char *p;
    size_t n, cap;
    DkArena *a;
} FsBuf;
void fsb_init(FsBuf *b, DkArena *a);
void fsb_reserve(FsBuf *b, size_t extra);
void fsb_put(FsBuf *b, const void *p, size_t n);
void fsb_putz(FsBuf *b, const char *z);
void fsb_putc(FsBuf *b, char c);
void fsb_putcp(FsBuf *b, u32 cp);
void fsb_printf(FsBuf *b, DK_PRINTF_FMT const char *fmt, ...);
char *fsb_cz(FsBuf *b);   /* NUL-terminated content (never NULL) */
DkStr fsb_str(FsBuf *b); /* NUL-terminated view of the content */

/* One UTF-8 code point (invalid bytes give U+FFFD, one byte each) and its encoding. */
u32 dk_fs_u8_next(const char **p, const char *end);
size_t dk_fs_u8_put(char out[4], u32 cp);

/* An DkStr over a NUL-terminated string / a copy of n bytes with a NUL after them. */
static inline DkStr fs_s(const char *z) { DkStr s = {z, z ? strlen(z) : 0}; return s; }
DkStr fs_dup(DkArena *a, const char *p, size_t n);
static inline char *fs_cz(DkArena *a, DkStr s) { return (char *)fs_dup(a, s.p, s.n).p; }

/* Python's repr() of a str, appended to a builder. */
void dk_fs_repr(FsBuf *b, const char *utf8);

/* The text-codec core (fs_text.c). encode appends the file bytes of `text` (newline translation, then the encoding;
 * bom: put the utf-8-sig BOM first) to out. */
bool dk_fs_encode_text(FsBuf *out, DkStr text, DkTextMode m, bool bom);
bool dk_fs_decode_bytes(DkArena *a, const u8 *p, size_t n, DkTextMode m, DkStr *out);

/* Opens a file the way the CRT's _wopen does for Python (share read+write, not inheritable). access is a
 * GENERIC_* mask, disposition a CREATE_* value. Returns INVALID_HANDLE_VALUE after recording an open()-style
 * failure. */
HANDLE dk_fs_open_handle(const char *path, DWORD access, DWORD disposition);

/* 64-bit helpers */
i64 dk_fs_filetime_to_ns(FILETIME ft);

/* GetFileInformationByHandle into an DkStat (fs_os.c). */
bool dk_fs_stat_handle(HANDLE h, const char *path, DkStat *st);

/* Temporary arenas. Every function of this module takes a private arena for its temporaries with fs_tmp() and gives
 * it back with fs_tmp_done(sc, mark) on every exit; the arena of a nested call is a different one, so a caller may
 * hand any arena (even dk_scratch()) to a function as the arena of its result. */
DkArena *fs_tmp(void);
void fs_tmp_done(DkArena *sc, DkArenaMark mk);
