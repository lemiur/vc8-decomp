// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The binary cache format and its append-only log variant. The format is documented at the top of cache.h. */
#include "dk/cache.h"
#include "dk/hash.h"

#include <stdio.h>
#include <wchar.h>
#include <windows.h>

/* The format is little-endian by definition; x64 Windows is little-endian, so fields are read and written with
 * memcpy of the native value. */
static inline u32 ld32(const u8 *p) { u32 v; memcpy(&v, p, 4); return v; }
static inline u64 ld64(const u8 *p) { u64 v; memcpy(&v, p, 8); return v; }
static inline void st32(u8 *p, u32 v) { memcpy(p, &v, 4); }
static inline void st64(u8 *p, u64 v) { memcpy(p, &v, 8); }

#define FIXED_HEADER 48u
#define KIND_MAX 255u
#define STAMP_MAX (1u << 20)
#define LOG_MARKER 0x01525641u /* "AVR\1" */

/* ================================================================================================================
 * writer
 * ================================================================================================================ */

void dk_cw_init(DkCacheWriter *w) { memset(w, 0, sizeof *w); }
void dk_cw_clear(DkCacheWriter *w) { dk_vec_clear(&w->b); }
void dk_cw_free(DkCacheWriter *w) { dk_vec_free(&w->b); }

static void cw_put(DkCacheWriter *w, const void *p, size_t n) { dk_vec_extend(&w->b, (const u8 *)p, n); }

void dk_cw_u8(DkCacheWriter *w, u8 v) { cw_put(w, &v, 1); }
void dk_cw_u16(DkCacheWriter *w, u16 v) { cw_put(w, &v, 2); }
void dk_cw_u32(DkCacheWriter *w, u32 v) { cw_put(w, &v, 4); }
void dk_cw_u64(DkCacheWriter *w, u64 v) { cw_put(w, &v, 8); }
void dk_cw_i32(DkCacheWriter *w, i32 v) { cw_put(w, &v, 4); }
void dk_cw_i64(DkCacheWriter *w, i64 v) { cw_put(w, &v, 8); }
void dk_cw_f64(DkCacheWriter *w, double v) { cw_put(w, &v, 8); }
void dk_cw_bool(DkCacheWriter *w, bool v) { dk_cw_u8(w, v ? 1 : 0); }
void dk_cw_bytes(DkCacheWriter *w, const void *p, size_t n) {
    DK_ASSERT(n <= 0xFFFFFFFFu);
    dk_cw_u32(w, (u32)n);
    if (n) cw_put(w, p, n);
}
void dk_cw_str(DkCacheWriter *w, DkStr s) { dk_cw_bytes(w, s.p, s.n); }
void dk_cw_cz(DkCacheWriter *w, const char *cz) { dk_cw_bytes(w, cz, cz ? strlen(cz) : 0); }
void dk_cw_count(DkCacheWriter *w, size_t n) {
    DK_ASSERT(n <= 0xFFFFFFFFu);
    dk_cw_u32(w, (u32)n);
}
size_t dk_cw_begin(DkCacheWriter *w) {
    size_t token = w->b.n;
    dk_cw_u32(w, 0);
    return token;
}
void dk_cw_end(DkCacheWriter *w, size_t token) {
    size_t len = w->b.n - token - 4;
    DK_ASSERT(len <= 0xFFFFFFFFu);
    st32(w->b.v + token, (u32)len);
}

/* ================================================================================================================
 * reader
 * ================================================================================================================ */

void dk_cr_init(DkCacheReader *r, const void *p, size_t n) {
    r->p = (const u8 *)p;
    r->end = r->p + n;
    r->bad = false;
}
bool dk_cr_ok(const DkCacheReader *r) { return !r->bad; }
size_t dk_cr_remaining(const DkCacheReader *r) { return r->bad ? 0 : (size_t)(r->end - r->p); }

/* Takes n bytes; on a short read the reader goes bad, parks at its end and the caller sees zeros. */
static const u8 *cr_take(DkCacheReader *r, size_t n) {
    static const u8 zeros[8] = {0};
    if (r->bad || (size_t)(r->end - r->p) < n) {
        r->bad = true;
        r->p = r->end;
        return zeros; /* only used for fixed-size reads of at most 8 bytes */
    }
    const u8 *q = r->p;
    r->p += n;
    return q;
}

u8 dk_cr_u8(DkCacheReader *r) { return *cr_take(r, 1); }
u16 dk_cr_u16(DkCacheReader *r) { u16 v; memcpy(&v, cr_take(r, 2), 2); return v; }
u32 dk_cr_u32(DkCacheReader *r) { return ld32(cr_take(r, 4)); }
u64 dk_cr_u64(DkCacheReader *r) { return ld64(cr_take(r, 8)); }
i32 dk_cr_i32(DkCacheReader *r) { i32 v; memcpy(&v, cr_take(r, 4), 4); return v; }
i64 dk_cr_i64(DkCacheReader *r) { i64 v; memcpy(&v, cr_take(r, 8), 8); return v; }
double dk_cr_f64(DkCacheReader *r) { double v; memcpy(&v, cr_take(r, 8), 8); return v; }
bool dk_cr_bool(DkCacheReader *r) {
    u8 v = dk_cr_u8(r);
    if (v > 1) r->bad = true;
    return v == 1;
}

const u8 *dk_cr_bytes(DkCacheReader *r, size_t *n) {
    u32 len = dk_cr_u32(r);
    if (r->bad || (size_t)(r->end - r->p) < len) {
        r->bad = true;
        r->p = r->end;
        *n = 0;
        return NULL;
    }
    const u8 *q = r->p;
    r->p += len;
    *n = len;
    return q;
}
DkStr dk_cr_str(DkCacheReader *r) {
    size_t n;
    const u8 *q = dk_cr_bytes(r, &n);
    DkStr s = {q ? (const char *)q : "", n};
    return s;
}
void dk_cr_skip(DkCacheReader *r, size_t n) {
    if (r->bad || (size_t)(r->end - r->p) < n) {
        r->bad = true;
        r->p = r->end;
        return;
    }
    r->p += n;
}
u32 dk_cr_count(DkCacheReader *r, size_t min_elem_bytes) {
    u32 c = dk_cr_u32(r);
    if (r->bad) return 0;
    if (min_elem_bytes == 0) min_elem_bytes = 1;
    if ((u64)c * min_elem_bytes > (u64)(r->end - r->p)) {
        r->bad = true;
        return 0;
    }
    return c;
}
bool dk_cr_record(DkCacheReader *r, DkCacheReader *sub) {
    u32 len = dk_cr_u32(r);
    if (r->bad || (size_t)(r->end - r->p) < len) {
        r->bad = true;
        r->p = r->end;
        sub->p = sub->end = r->end;
        sub->bad = true;
        return false;
    }
    sub->p = r->p;
    sub->end = r->p + len;
    sub->bad = false;
    r->p += len;
    return true;
}
void dk_cr_end(DkCacheReader *r, const DkCacheReader *sub) {
    if (sub->bad) r->bad = true;
}

/* ================================================================================================================
 * header
 * ================================================================================================================ */

static size_t align8(size_t n) { return (n + 7) & ~(size_t)7; }

typedef struct {
    u32 schema;
    const u8 *stamp;
    u32 stamp_n;
    u64 payload_len;
    u64 payload_hash;
    size_t body_off; /* where the payload / the log records start */
} Header;

static u32 header_crc(const u8 *h, size_t kind_n, size_t stamp_n) {
    u32 c = dk_crc32(0, h, 40);
    return dk_crc32(c, h + FIXED_HEADER, kind_n + stamp_n);
}

/* Builds the header bytes (header size = align8(48 + kind + stamp)). */
static void header_build(DkBytes *out, const char magic[4], const char *kind, u32 schema, const void *stamp,
                         size_t stamp_n, u64 payload_len, u64 payload_hash) {
    size_t kind_n = strlen(kind);
    DK_ASSERT(kind_n <= KIND_MAX && stamp_n <= STAMP_MAX);
    size_t hs = align8(FIXED_HEADER + kind_n + stamp_n);
    size_t base = out->n;
    dk_vec_reserve(out, base + hs);
    u8 *h = out->v + base;
    memset(h, 0, hs);
    memcpy(h, magic, 4);
    st32(h + 4, DK_CACHE_FORMAT);
    st32(h + 8, schema);
    st32(h + 12, 0);
    st32(h + 16, (u32)kind_n);
    st32(h + 20, (u32)stamp_n);
    st64(h + 24, payload_len);
    st64(h + 32, payload_hash);
    memcpy(h + FIXED_HEADER, kind, kind_n);
    if (stamp_n) memcpy(h + FIXED_HEADER + kind_n, stamp, stamp_n);
    st32(h + 40, header_crc(h, kind_n, stamp_n));
    out->n = base + hs;
}

/* Validates the header of a file image. Never reads past n. */
static bool header_parse(const u8 *img, size_t n, const char magic[4], const char *kind, u32 schema, const void *stamp,
                         size_t stamp_n, Header *out) {
    if (n < FIXED_HEADER || memcmp(img, magic, 4) != 0) return false;
    if (ld32(img + 4) != DK_CACHE_FORMAT || ld32(img + 12) != 0 || ld32(img + 44) != 0) return false;
    if (ld32(img + 8) != schema) return false;
    u32 kind_n = ld32(img + 16), sn = ld32(img + 20);
    if (kind_n > KIND_MAX || sn > STAMP_MAX) return false;
    u64 hs = ((u64)FIXED_HEADER + kind_n + sn + 7) & ~(u64)7;
    if (hs > n) return false;
    if (header_crc(img, kind_n, sn) != ld32(img + 40)) return false;
    for (u64 i = (u64)FIXED_HEADER + kind_n + sn; i < hs; i++)
        if (img[i] != 0) return false; /* the padding is part of the format: every byte of the file is checked */
    if (kind_n != strlen(kind) || memcmp(img + FIXED_HEADER, kind, kind_n) != 0) return false;
    if (stamp && (sn != stamp_n || (sn && memcmp(img + FIXED_HEADER + kind_n, stamp, sn) != 0))) return false;
    out->schema = ld32(img + 8);
    out->stamp = img + FIXED_HEADER + kind_n;
    out->stamp_n = sn;
    out->payload_len = ld64(img + 24);
    out->payload_hash = ld64(img + 32);
    out->body_off = (size_t)hs;
    return true;
}

/* ================================================================================================================
 * files: mapping and atomic replace
 * ================================================================================================================ */

/* UTF-8 path to a heap wide string, backslashes, and the extended-length prefix for long absolute paths. */
static wchar_t *wide_path(const char *path, size_t extra) {
    int n = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = (wchar_t *)dk_xmalloc(((size_t)n + extra + 8) * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, path, -1, w, n);
    for (wchar_t *c = w; *c; c++)
        if (*c == L'/') *c = L'\\';
    size_t len = wcslen(w);
    if (len + extra >= 240 && len > 3 && w[1] == L':' && w[2] == L'\\') {
        memmove(w + 4, w, (len + 1) * sizeof(wchar_t));
        memcpy(w, L"\\\\?\\", 4 * sizeof(wchar_t));
    }
    return w;
}

static bool map_file(const char *path, const u8 **base, size_t *size, void **file, void **mapping) {
    wchar_t *w = wide_path(path, 0);
    if (!w) return false;
    /* share delete: another process can replace the name while we read (the replace itself waits for our unmap) */
    HANDLE f = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    dk_xfree(w);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart < (LONGLONG)FIXED_HEADER || (u64)sz.QuadPart > (u64)SIZE_MAX / 2) {
        CloseHandle(f);
        return false;
    }
    HANDLE m = CreateFileMappingW(f, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!m) {
        CloseHandle(f);
        return false;
    }
    const u8 *v = (const u8 *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    if (!v) {
        CloseHandle(m);
        CloseHandle(f);
        return false;
    }
    *base = v;
    *size = (size_t)sz.QuadPart;
    *file = f;
    *mapping = m;
    return true;
}

static void unmap_file(const u8 *base, void *file, void *mapping) {
    if (base && mapping) UnmapViewOfFile(base);
    if (mapping) CloseHandle((HANDLE)mapping);
    if (file) CloseHandle((HANDLE)file);
}

static volatile LONG g_tmp_counter;

/* Writes the parts to <path>.<pid>-<tid>-<n>.tmp and renames it over path. Retries the rename while a reader holds
 * the target mapped (ERROR_ACCESS_DENIED / sharing violations), about 2 seconds at most. */
static bool replace_file(const char *path, const void *const *parts, const size_t *lens, size_t count) {
    wchar_t *dst = wide_path(path, 0);
    if (!dst) return false;
    size_t dl = wcslen(dst);
    wchar_t *tmp = (wchar_t *)dk_xmalloc((dl + 48) * sizeof(wchar_t));
    swprintf(tmp, dl + 48, L"%ls.%lu-%lu-%ld.tmp", dst, GetCurrentProcessId(), GetCurrentThreadId(),
             (long)InterlockedIncrement(&g_tmp_counter));
    HANDLE f = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    bool ok = f != INVALID_HANDLE_VALUE;
    for (size_t i = 0; ok && i < count; i++) {
        const u8 *q = (const u8 *)parts[i];
        size_t left = lens[i];
        while (left && ok) {
            DWORD k = left > 0x40000000u ? 0x40000000u : (DWORD)left, w = 0;
            ok = WriteFile(f, q, k, &w, NULL) && w == k;
            q += k;
            left -= k;
        }
    }
    if (f != INVALID_HANDLE_VALUE && !CloseHandle(f)) ok = false;
    if (ok) {
        ok = false;
        for (int attempt = 0; attempt < 100; attempt++) {
            if (MoveFileExW(tmp, dst, MOVEFILE_REPLACE_EXISTING)) {
                ok = true;
                break;
            }
            DWORD e = GetLastError();
            if (e != ERROR_ACCESS_DENIED && e != ERROR_SHARING_VIOLATION && e != ERROR_LOCK_VIOLATION) break;
            Sleep(attempt < 10 ? 5 : 20);
        }
    }
    if (!ok) DeleteFileW(tmp);
    dk_xfree(tmp);
    dk_xfree(dst);
    return ok;
}

/* ================================================================================================================
 * cache files
 * ================================================================================================================ */

void dk_cache_encode(DkBytes *out, const char *kind, u32 schema, const void *stamp, size_t stamp_n,
                      const void *payload, size_t payload_n) {
    header_build(out, "AVPC", kind, schema, stamp, stamp_n, payload_n, dk_hash64(payload, payload_n, DK_CACHE_SEED));
    if (payload_n) dk_vec_extend(out, (const u8 *)payload, payload_n);
}

bool dk_cache_write(const char *path, const char *kind, u32 schema, const void *stamp, size_t stamp_n,
                     const void *payload, size_t payload_n) {
    DkBytes hdr = {0};
    header_build(&hdr, "AVPC", kind, schema, stamp, stamp_n, payload_n, dk_hash64(payload, payload_n, DK_CACHE_SEED));
    const void *parts[2] = {hdr.v, payload};
    size_t lens[2] = {hdr.n, payload_n};
    bool ok = replace_file(path, parts, lens, payload_n ? 2 : 1);
    dk_vec_free(&hdr);
    return ok;
}

bool dk_cache_write_w(const char *path, const char *kind, u32 schema, const void *stamp, size_t stamp_n,
                       const DkCacheWriter *w) {
    return dk_cache_write(path, kind, schema, stamp, stamp_n, w->b.v, w->b.n);
}

bool dk_cache_open_mem(DkCache *c, const void *image, size_t n, const char *kind, u32 schema, const void *stamp,
                        size_t stamp_n) {
    memset(c, 0, sizeof *c);
    Header h;
    if (!header_parse((const u8 *)image, n, "AVPC", kind, schema, stamp, stamp_n, &h)) return false;
    if (h.payload_len != (u64)(n - h.body_off)) return false; /* truncated, or a tail that is not ours */
    const u8 *payload = (const u8 *)image + h.body_off;
    if (dk_hash64(payload, (size_t)h.payload_len, DK_CACHE_SEED) != h.payload_hash) return false;
    c->base = (const u8 *)image;
    c->size = n;
    c->payload = payload;
    c->payload_n = (size_t)h.payload_len;
    c->stamp = h.stamp;
    c->stamp_n = h.stamp_n;
    c->schema = h.schema;
    dk_cr_init(&c->r, payload, c->payload_n);
    return true;
}

bool dk_cache_open(DkCache *c, const char *path, const char *kind, u32 schema, const void *stamp, size_t stamp_n) {
    memset(c, 0, sizeof *c);
    const u8 *base;
    size_t size;
    void *file, *mapping;
    if (!map_file(path, &base, &size, &file, &mapping)) return false;
    /* The view can fault if the file shrinks under us (a writer truncating in place; ours never do): guard it. */
    bool ok;
    __try {
        ok = dk_cache_open_mem(c, base, size, kind, schema, stamp, stamp_n);
    } __except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        ok = false;
    }
    if (!ok) {
        unmap_file(base, file, mapping);
        memset(c, 0, sizeof *c);
        return false;
    }
    c->file = file;
    c->mapping = mapping;
    return true;
}

void dk_cache_close(DkCache *c) {
    if (c->mapping) unmap_file(c->base, c->file, c->mapping);
    memset(c, 0, sizeof *c);
}

/* ================================================================================================================
 * log files
 * ================================================================================================================ */

static u32 frame_check(const void *body, size_t n) {
    u64 h = dk_hash64(body, n, DK_LOG_SEED);
    return (u32)h ^ (u32)(h >> 32);
}

void dk_log_frame(DkBytes *out, const void *body, size_t n) {
    DK_ASSERT(n <= 0xFFFFFFFFu);
    size_t base = out->n;
    dk_vec_reserve(out, base + 12 + n);
    st32(out->v + base, LOG_MARKER);
    st32(out->v + base + 4, (u32)n);
    st32(out->v + base + 8, frame_check(body, n));
    if (n) memcpy(out->v + base + 12, body, n);
    out->n = base + 12 + n;
}

bool dk_log_write_file(const char *path, const char *kind, u32 schema, const void *stamp, size_t stamp_n,
                        const void *frames, size_t frames_n) {
    DkBytes hdr = {0};
    header_build(&hdr, "AVPL", kind, schema, stamp, stamp_n, 0, 0);
    const void *parts[2] = {hdr.v, frames};
    size_t lens[2] = {hdr.n, frames_n};
    bool ok = replace_file(path, parts, lens, frames_n ? 2 : 1);
    dk_vec_free(&hdr);
    return ok;
}

bool dk_log_open(DkLog *l, const char *path, const char *kind, u32 schema, const void *stamp, size_t stamp_n) {
    memset(l, 0, sizeof *l);
    const u8 *base;
    size_t size;
    void *file, *mapping;
    if (!map_file(path, &base, &size, &file, &mapping)) return false;
    Header h;
    memset(&h, 0, sizeof h);
    bool ok;
    __try {
        ok = header_parse(base, size, "AVPL", kind, schema, stamp, stamp_n, &h);
    } __except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        ok = false;
    }
    if (!ok) {
        unmap_file(base, file, mapping);
        return false;
    }
    l->c.base = base;
    l->c.size = size;
    l->c.stamp = h.stamp;
    l->c.stamp_n = h.stamp_n;
    l->c.schema = h.schema;
    l->c.file = file;
    l->c.mapping = mapping;
    l->pos = h.body_off;
    return true;
}

bool dk_log_next(DkLog *l, DkCacheReader *body) {
    const u8 *b = l->c.base;
    size_t n = l->c.size;
    while (l->pos + 12 <= n) {
        size_t pos = l->pos;
        if (ld32(b + pos) == LOG_MARKER) {
            u32 len = ld32(b + pos + 4);
            if ((size_t)len <= n - pos - 12 && frame_check(b + pos + 12, len) == ld32(b + pos + 8)) {
                dk_cr_init(body, b + pos + 12, len);
                l->pos = pos + 12 + len;
                l->records++;
                return true;
            }
        }
        /* damaged or torn: resynchronise on the next marker */
        size_t q = pos + 1;
        while (q + 4 <= n && ld32(b + q) != LOG_MARKER) q++;
        if (q + 4 > n) q = n;
        l->skipped += q - pos;
        l->pos = q;
    }
    if (l->pos < n) {
        l->skipped += n - l->pos; /* a partial frame header at the very end */
        l->pos = n;
    }
    return false;
}

void dk_log_close(DkLog *l) {
    if (l->c.mapping) unmap_file(l->c.base, l->c.file, l->c.mapping);
    memset(l, 0, sizeof *l);
}

bool dk_log_append_open(DkLogAppender *a, const char *path, const char *kind, u32 schema, const void *stamp,
                         size_t stamp_n) {
    a->file = NULL;
    wchar_t *w = wide_path(path, 0);
    if (!w) return false;
    /* A missing log is created exclusively (CREATE_NEW, no sharing while the header is written), so threads or
       processes racing on a new log never replace one another's file and lose the records already appended. A log
       that exists but does not probe may be one being created right now: retry briefly before treating it as stale
       (another schema or stamp) and replacing it. */
    bool ready = false, complete_seen = false;
    for (int tries = 0; tries < 50 && !ready; tries++) {
        DkLog probe;
        if (dk_log_open(&probe, path, kind, schema, stamp, stamp_n)) {
            dk_log_close(&probe);
            ready = true;
            break;
        }
        if (GetFileAttributesW(w) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND) {
            HANDLE c = CreateFileW(w, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
            if (c != INVALID_HANDLE_VALUE) {
                DkBytes hdr = {0};
                header_build(&hdr, "AVPL", kind, schema, stamp, stamp_n, 0, 0);
                DWORD written = 0;
                bool ok = WriteFile(c, hdr.v, (DWORD)hdr.n, &written, NULL) && written == hdr.n;
                dk_vec_free(&hdr);
                CloseHandle(c);
                if (!ok) {
                    DeleteFileW(w);
                    dk_xfree(w);
                    return false;
                }
                ready = true;
                break;
            }
            if (GetLastError() != ERROR_FILE_EXISTS) {
                dk_xfree(w);
                return false;
            }
            continue; /* another creator won: probe its file */
        }
        /* A log being created is open without sharing until its header is written (above; dk_log_write_file renames a
           finished file into place): a file that opens is complete. It may have been created since the probe, so it
           is probed once more; a complete file that still does not probe is stale. */
        HANDLE h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            if (complete_seen) break;
            complete_seen = true;
            continue;
        }
        if (GetLastError() == ERROR_FILE_NOT_FOUND) continue; /* gone since: create it */
        Sleep(2);
    }
    if (!ready && !dk_log_write_file(path, kind, schema, stamp, stamp_n, NULL, 0)) {
        dk_xfree(w);
        return false;
    }
    HANDLE f = INVALID_HANDLE_VALUE;
    for (int tries = 0; tries < 500; tries++) {
        f = CreateFileW(w, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE || GetLastError() != ERROR_SHARING_VIOLATION) break;
        Sleep(2);
    }
    dk_xfree(w);
    if (f == INVALID_HANDLE_VALUE) return false;
    a->file = f;
    return true;
}

bool dk_log_append(DkLogAppender *a, const void *body, size_t n) {
    if (!a->file || n > 0xFFFFFFFFu) return false;
    u8 stack[4096];
    u8 *buf = n + 12 <= sizeof stack ? stack : (u8 *)dk_xmalloc(n + 12);
    st32(buf, LOG_MARKER);
    st32(buf + 4, (u32)n);
    st32(buf + 8, frame_check(body, n));
    if (n) memcpy(buf + 12, body, n);
    DWORD written = 0;
    /* one WriteFile on an append-only handle: the OS places the record at the end atomically */
    bool ok = WriteFile((HANDLE)a->file, buf, (DWORD)(n + 12), &written, NULL) && written == n + 12;
    if (buf != stack) dk_xfree(buf);
    return ok;
}

void dk_log_append_close(DkLogAppender *a) {
    if (a->file) CloseHandle((HANDLE)a->file);
    a->file = NULL;
}
