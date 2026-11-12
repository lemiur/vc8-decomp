// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The thread's I/O error record: the exception Python would have raised, its class, errno, winerror and filenames,
 * and str() of it; Python's repr() of a path string; the UTF-8 <-> UTF-16 and long-path helpers every other fs file
 * uses. */
#include "fs_priv.h"

#include <stdarg.h>
#include <stdio.h>

static DK_THREAD_LOCAL DkIoErr t_err;

#define FS_TMP_MAX 64
static DK_THREAD_LOCAL DkArena *t_tmp[FS_TMP_MAX];
static DK_THREAD_LOCAL int t_depth;

DkArena *fs_tmp(void) {
    DK_ASSERT(t_depth < FS_TMP_MAX);
    if (!t_tmp[t_depth]) t_tmp[t_depth] = dk_arena_new(0);
    return t_tmp[t_depth++];
}

void fs_tmp_done(DkArena *sc, DkArenaMark mk) {
    dk_arena_reset(sc, mk);
    t_depth--;
    DK_ASSERT(t_depth >= 0 && t_tmp[t_depth] == sc);
}

/* ---- the builder and UTF-8 helpers ---------------------------------------------------------------------------- */

void fsb_init(FsBuf *b, DkArena *a) {
    b->p = NULL;
    b->n = b->cap = 0;
    b->a = a;
}

void fsb_reserve(FsBuf *b, size_t extra) {
    size_t need = b->n + extra + 1;
    if (need <= b->cap) return;
    size_t cap = b->cap ? b->cap : 64;
    while (cap < need) cap *= 2;
    if (b->a) b->p = (char *)dk_arena_realloc(b->a, b->p, b->cap, cap);
    else b->p = (char *)dk_xrealloc(b->p, cap);
    b->cap = cap;
}

void fsb_put(FsBuf *b, const void *p, size_t n) {
    fsb_reserve(b, n);
    if (n) memcpy(b->p + b->n, p, n);
    b->n += n;
}
void fsb_putz(FsBuf *b, const char *z) { fsb_put(b, z, strlen(z)); }
void fsb_putc(FsBuf *b, char c) { fsb_put(b, &c, 1); }
void fsb_putcp(FsBuf *b, u32 cp) {
    char t[4];
    size_t k = dk_fs_u8_put(t, cp);
    fsb_put(b, t, k);
}
void fsb_printf(FsBuf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    fsb_reserve(b, (size_t)n);
    va_start(ap, fmt);
    vsnprintf(b->p + b->n, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->n += (size_t)n;
}
char *fsb_cz(FsBuf *b) {
    fsb_reserve(b, 0);
    b->p[b->n] = 0;
    return b->p;
}
DkStr fsb_str(FsBuf *b) {
    DkStr s = {fsb_cz(b), b->n};
    return s;
}
DkStr fs_dup(DkArena *a, const char *p, size_t n) {
    char *d = (char *)dk_alloc_noz(a, n + 1);
    if (n) memcpy(d, p, n);
    d[n] = 0;
    DkStr s = {d, n};
    return s;
}

u32 dk_fs_u8_next(const char **pp, const char *end) {
    const unsigned char *p = (const unsigned char *)*pp;
    u32 c = p[0];
    size_t left = (size_t)(end - *pp);
    if (c < 0x80) {
        *pp += 1;
        return c;
    }
    int need;
    u32 min, v;
    if (c >= 0xC2 && c <= 0xDF) { need = 1; v = c & 0x1F; min = 0x80; }
    else if (c >= 0xE0 && c <= 0xEF) { need = 2; v = c & 0x0F; min = 0x800; }
    else if (c >= 0xF0 && c <= 0xF4) { need = 3; v = c & 0x07; min = 0x10000; }
    else { *pp += 1; return 0xFFFD; }
    if (left < (size_t)need + 1) { *pp += 1; return 0xFFFD; }
    for (int i = 1; i <= need; i++) {
        if ((p[i] & 0xC0) != 0x80) { *pp += 1; return 0xFFFD; }
        v = (v << 6) | (p[i] & 0x3F);
    }
    if (v < min || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) { *pp += 1; return 0xFFFD; }
    *pp += need + 1;
    return v;
}

size_t dk_fs_u8_put(char out[4], u32 c) {
    if (c < 0x80) { out[0] = (char)c; return 1; }
    if (c < 0x800) { out[0] = (char)(0xC0 | (c >> 6)); out[1] = (char)(0x80 | (c & 0x3F)); return 2; }
    if (c < 0x10000) {
        out[0] = (char)(0xE0 | (c >> 12)); out[1] = (char)(0x80 | ((c >> 6) & 0x3F)); out[2] = (char)(0x80 | (c & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (c >> 18)); out[1] = (char)(0x80 | ((c >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((c >> 6) & 0x3F)); out[3] = (char)(0x80 | (c & 0x3F));
    return 4;
}

const DkIoErr *dk_io_err(void) { return &t_err; }

void dk_io_clear(void) { memset(&t_err, 0, sizeof t_err); }

bool dk_io_is(int err) { return t_err.kind == DK_IOE_OS && t_err.err == err; }

static void set_path(char *dst, size_t cap, const char *src) {
    if (!src) {
        dst[0] = 0;
        return;
    }
    size_t n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
        while (n > 0 && ((unsigned char)src[n] & 0xC0) == 0x80) n--; /* do not cut a UTF-8 sequence */
    }
    memcpy(dst, src, n);
    dst[n] = 0;
}

void dk_io_fail_errno(int err, const char *path, const char *path2) {
    memset(&t_err, 0, sizeof t_err);
    t_err.kind = DK_IOE_OS;
    t_err.err = err;
    set_path(t_err.path, sizeof t_err.path, path);
    set_path(t_err.path2, sizeof t_err.path2, path2);
}

void dk_io_fail_win(unsigned winerror, const char *path, const char *path2) {
    memset(&t_err, 0, sizeof t_err);
    t_err.kind = DK_IOE_OS;
    t_err.winerror = (int)winerror;
    t_err.err = dk_winerror_to_errno(winerror);
    set_path(t_err.path, sizeof t_err.path, path);
    set_path(t_err.path2, sizeof t_err.path2, path2);
}

void dk_io_fail_msg(int kind, int err, const char *fmt, ...) {
    memset(&t_err, 0, sizeof t_err);
    t_err.kind = kind;
    t_err.err = err;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(t_err.msg, sizeof t_err.msg, fmt, ap);
    va_end(ap);
}

void dk_fs_fail_last(const char *path, const char *path2) {
    unsigned e = GetLastError();
    dk_io_fail_win(e, path, path2);
}

void dk_fs_fail_open(unsigned winerror, const char *path) {
    /* open() raises through the CRT: errno from the Win32 error, the strerror text, no winerror. */
    dk_io_fail_errno(dk_winerror_to_errno(winerror), path, NULL);
}

void dk_fs_fail_value(const char *fmt, ...) {
    memset(&t_err, 0, sizeof t_err);
    t_err.kind = DK_IOE_VALUE;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(t_err.msg, sizeof t_err.msg, fmt, ap);
    va_end(ap);
}

void dk_fs_fail_embedded_nul(void) { dk_fs_fail_value("embedded null character"); }

const char *dk_io_err_class(void) {
    switch (t_err.kind) {
    case DK_IOE_DECODE: return "UnicodeDecodeError";
    case DK_IOE_ENCODE: return "UnicodeEncodeError";
    case DK_IOE_VALUE: return "ValueError";
    case DK_IOE_SHUTIL: return t_err.err == 1 ? "SameFileError" : "Error";
    case DK_IOE_OS: break;
    default: return "";
    }
    switch (t_err.err) {
    case ENOENT: return "FileNotFoundError";
    case EEXIST: return "FileExistsError";
    case EACCES:
    case EPERM: return "PermissionError";
    case ENOTDIR: return "NotADirectoryError";
    case EISDIR: return "IsADirectoryError";
    case ECHILD: return "ChildProcessError";
    case EAGAIN: return "BlockingIOError";
    case EPIPE: return "BrokenPipeError";
    case EINTR: return "InterruptedError";
    case ESRCH: return "ProcessLookupError";
    case ETIMEDOUT: return "TimeoutError";
    case ECONNABORTED: return "ConnectionAbortedError";
    case ECONNREFUSED: return "ConnectionRefusedError";
    case ECONNRESET: return "ConnectionResetError";
    default: return "OSError";
    }
}

/* Whether Python's str.isprintable() is false for the code point (the ranges that matter in file names). */
static bool nonprintable(u32 c) {
    if (c < 0x20 || (c >= 0x7F && c <= 0xA0) || c == 0xAD) return true;
    if (c < 0x600) return false;
    return (c >= 0x600 && c <= 0x605) || c == 0x61C || c == 0x6DD || c == 0x70F || c == 0x180E ||
           (c >= 0x2000 && c <= 0x200F) || (c >= 0x2028 && c <= 0x202F) || (c >= 0x205F && c <= 0x206F) ||
           c == 0x3000 || (c >= 0xD800 && c <= 0xF8FF) || c == 0xFEFF || (c >= 0xFFF0 && c <= 0xFFFB) ||
           c >= 0xE0000;
}

void dk_fs_repr(FsBuf *b, const char *utf8) {
    bool has_sq = strchr(utf8, '\'') != NULL, has_dq = strchr(utf8, '"') != NULL;
    char q = (has_sq && !has_dq) ? '"' : '\'';
    fsb_putc(b, q);
    const char *p = utf8, *end = utf8 + strlen(utf8);
    while (p < end) {
        u32 c = dk_fs_u8_next(&p, end);
        if (c == (u32)q || c == '\\') {
            fsb_putc(b, '\\');
            fsb_putc(b, (char)c);
        } else if (c == '\n') fsb_putz(b, "\\n");
        else if (c == '\r') fsb_putz(b, "\\r");
        else if (c == '\t') fsb_putz(b, "\\t");
        else if (nonprintable(c)) {
            if (c <= 0xFF) fsb_printf(b, "\\x%02x", c);
            else if (c <= 0xFFFF) fsb_printf(b, "\\u%04x", c);
            else fsb_printf(b, "\\U%08x", c);
        } else fsb_putcp(b, c);
    }
    fsb_putc(b, q);
}

DkStr dk_io_err_repr_path(DkArena *a, const char *s) {
    FsBuf b;
    fsb_init(&b, a);
    dk_fs_repr(&b, s);
    return fsb_str(&b);
}

DkStr dk_io_err_str(DkArena *a) {
    FsBuf b;
    fsb_init(&b, a);
    if (t_err.kind != DK_IOE_OS || (t_err.err == 0 && t_err.winerror == 0 && t_err.msg[0])) {
        fsb_putz(&b, t_err.msg);
        return fsb_str(&b);
    }
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    if (t_err.winerror) {
        fsb_printf(&b, "[WinError %d] ", t_err.winerror);
        { DkStr m = dk_win_error_message(sc, (unsigned)t_err.winerror); fsb_put(&b, m.p, m.n); }
    } else {
        char text[160];
        if (strerror_s(text, sizeof text, t_err.err) != 0) snprintf(text, sizeof text, "Unknown error %d", t_err.err);
        fsb_printf(&b, "[Errno %d] %s", t_err.err, text);
    }
    if (t_err.path[0]) {
        fsb_putz(&b, ": ");
        dk_fs_repr(&b, t_err.path);
        if (t_err.path2[0]) {
            fsb_putz(&b, " -> ");
            dk_fs_repr(&b, t_err.path2);
        }
    }
    fs_tmp_done(sc, mk);
    return fsb_str(&b);
}

/* ---- UTF-8 <-> UTF-16 and Win32 paths -------------------------------------------------------------------------- */

wchar_t *dk_fs_u8_to_w(DkArena *a, const char *s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *out = (wchar_t *)dk_alloc_noz(a, ((size_t)(len > 0 ? len : 1) + 1) * sizeof(wchar_t));
    if (len > 0) MultiByteToWideChar(CP_UTF8, 0, s, -1, out, len);
    else out[0] = 0;
    return out;
}

char *dk_fs_w_to_u8(DkArena *a, const wchar_t *w, i64 n) {
    int cnt = (int)n;
    int len = WideCharToMultiByte(CP_UTF8, 0, w, cnt, NULL, 0, NULL, NULL);
    char *out = (char *)dk_alloc_noz(a, (size_t)len + 1);
    if (len > 0) WideCharToMultiByte(CP_UTF8, 0, w, cnt, out, len, NULL, NULL);
    out[len] = 0;
    if (n < 0 && len > 0) out[len - 1] = 0; /* n == -1 counted the terminator */
    return out;
}

wchar_t *dk_fs_wpath(DkArena *a, const char *path) {
    wchar_t *w = dk_fs_u8_to_w(a, path);
    size_t n = wcslen(w);
    if (n < MAX_PATH - 12 || (w[0] == L'\\' && w[1] == L'\\' && (w[2] == L'?' || w[2] == L'.')))
        return w;
    DWORD need = GetFullPathNameW(w, 0, NULL, NULL);
    if (need == 0) return w;
    wchar_t *full = (wchar_t *)dk_alloc_noz(a, ((size_t)need + 1) * sizeof(wchar_t));
    DWORD got = GetFullPathNameW(w, need, full, NULL);
    if (got == 0 || got >= need) return w;
    if (full[0] == L'\\' && full[1] == L'\\') {
        wchar_t *out = (wchar_t *)dk_alloc_noz(a, ((size_t)got + 16) * sizeof(wchar_t));
        wcscpy(out, L"\\\\?\\UNC\\");
        wcscpy(out + 8, full + 2);
        return out;
    }
    wchar_t *out = (wchar_t *)dk_alloc_noz(a, ((size_t)got + 8) * sizeof(wchar_t));
    wcscpy(out, L"\\\\?\\");
    wcscpy(out + 4, full);
    return out;
}

i64 dk_fs_filetime_to_ns(FILETIME ft) {
    i64 ticks = (i64)(((u64)ft.dwHighDateTime << 32) | ft.dwLowDateTime) - 116444736000000000LL;
    i64 sec = ticks / 10000000, rem = ticks % 10000000;
    if (rem < 0) {
        sec -= 1;
        rem += 10000000;
    }
    return sec * 1000000000LL + rem * 100;
}
