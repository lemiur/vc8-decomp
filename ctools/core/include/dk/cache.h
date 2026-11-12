// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The binary cache format that replaces pickle (design.md section 8): objcache's PickleMemo tables, the gate
 * snapshots and lane records, the annotation store. Pickle files were
 * read with `except Exception: start afresh`; this format keeps that contract and makes it checkable: a cache file
 * that is missing, torn by a crash, zero-filled, written by another version, or made from other inputs is "no
 * cache" (the open function returns false) and is rebuilt by the tool. Never a crash, never a partial read.
 *
 * ---- Format 1 (all integers little-endian, the same on every machine) ----------------------------------------------
 *
 *   offset  size  field
 *        0     4  magic "AVPC"                  (a log file has "AVPL", see below)
 *        4     4  u32 format = 1                this container; any other value is "no cache"
 *        8     4  u32 schema                    the caller's version of the payload layout (bump it when a record
 *                                               changes); must equal what the reader expects
 *       12     4  u32 flags = 0                 reserved
 *       16     4  u32 kind_len                  <= 255
 *       20     4  u32 stamp_len                 <= 1 MiB
 *       24     8  u64 payload_len
 *       32     8  u64 payload_hash              dk_hash64(payload, payload_len, DK_CACHE_SEED)
 *       40     4  u32 header_crc                crc32 of bytes 0..39 followed by the kind and stamp bytes
 *       44     4  u32 reserved = 0
 *       48  kind_len   kind                     "tool/kind" text, e.g. "gate/snapshot": a file of another kind is
 *                                               refused
 *        .. stamp_len  stamp                    the input stamp the caller supplies (a sha256, a list of hashes, a
 *                                               commit id...): the cache is valid only for exactly these bytes
 *        ..  0..7     zero padding up to a multiple of 8 from the file start (must be zero: every byte of a file is
 *                     covered by a check, so no single altered byte is accepted)
 *        P  payload_len  payload                typed records, below
 *   The file length must be exactly P + payload_len: a truncated file and a file with a tail are both refused.
 *
 * ---- Payload: typed, length-prefixed records -----------------------------------------------------------------------
 *   u8 u16 u32 u64 i32 i64    fixed width, little-endian (bool is a u8 0 or 1)
 *   f64                       the 8 bytes of the IEEE double (bit exact, NaN payloads and -0.0 survive)
 *   bytes / str               u32 length, then that many bytes (str is UTF-8 by convention, no NUL needed)
 *   record                    u32 byte length, then the fields of the record. A reader that finds fewer fields than
 *                             a newer writer put in skips to the record's end on its own (forward compatible), and
 *                             one that wants more fields than there are gets sticky "bad" (old file: no cache).
 *   vector of records         u32 count, then count records;  map: a vector of records (key, value, ...)
 * The reader never reads outside the mapped file: every read is bounds-checked against the record it is in, a read
 * past the end sets the reader's sticky `bad` flag and returns 0 / empty; counts are checked against the bytes that
 * remain (dk_cr_count) so a damaged count cannot make a caller allocate gigabytes. Check dk_cr_ok() once, after
 * the whole payload has been read, and treat bad as "no cache". (The payload checksum already rejects damaged
 * files; the bounds checks make a bug in a record layout an error instead of a crash.)
 *
 * ---- Writing: atomic, safe against concurrent writers ---------------------------------------------------------------
 * The file is written whole to a temp file in the destination folder (name <path>.<pid>-<thread>-<n>.tmp) and then
 * renamed over the destination (MoveFileExW, REPLACE_EXISTING): a reader sees the old complete file or the new
 * complete file. Two processes writing the same cache (two slots): both write complete files, the last rename wins.
 * Readers map the file with FILE_SHARE_DELETE, and a rename over a file that is mapped right now fails with
 * ACCESS_DENIED on Windows, so the writer retries for up to ~2 seconds, then gives up (returns false: a cache write
 * is best effort, like objcache's `except OSError: pass`). No fsync: a crash that tears the file is caught by the
 * checksum at the next read.
 *
 * ---- Append-only variant: the log ---------------------------------------------------------------------------------------
 * For tables that grow by a few entries per run and are shared by processes (objcache's PickleMemo: a key -> answer
 * table that Python re-read, merged and rewrote whole at exit), a log file avoids the read-merge-write race and the
 * rewrite of a large table: one header like the cache's but with magic "AVPL" (payload_len and payload_hash 0, the
 * header_crc covers it), then framed records appended one at a time:
 *        u32 marker 0x01525641 ("AVR\1"), u32 body_len, u32 check, body (one record of the typed fields above)
 *        check = low 32 bits xor high 32 bits of dk_hash64(body, body_len, DK_LOG_SEED)
 * Each record is appended with ONE WriteFile on a handle opened FILE_APPEND_DATA, which the OS positions atomically
 * at the end of the file, so records of concurrent appenders never interleave. A reader takes every record whose
 * frame and check are valid; a torn or damaged record is skipped by scanning forward for the next marker, so a crash
 * mid-append loses that record only. Later records override earlier ones when the caller's table is keyed (replay
 * in order). To shrink a log, the caller replays it, keeps what it wants, frames it with dk_log_frame and replaces
 * the file with dk_log_write_file (atomic, as above).
 */
#pragma once
#include "str.h"

#define DK_CACHE_FORMAT 1u
#define DK_CACHE_SEED 0x4156504341434845ull /* "AVPCACHE" */
#define DK_LOG_SEED 0x4156504C4F472121ull

/* ================================================================================================================
 * writing a payload
 * ================================================================================================================ */

typedef struct {
    DkBytes b; /* the payload so far (heap) */
} DkCacheWriter;
void dk_cw_init(DkCacheWriter *w);
void dk_cw_clear(DkCacheWriter *w); /* empties it, keeps the memory */
void dk_cw_free(DkCacheWriter *w);
void dk_cw_u8(DkCacheWriter *w, u8 v);
void dk_cw_u16(DkCacheWriter *w, u16 v);
void dk_cw_u32(DkCacheWriter *w, u32 v);
void dk_cw_u64(DkCacheWriter *w, u64 v);
void dk_cw_i32(DkCacheWriter *w, i32 v);
void dk_cw_i64(DkCacheWriter *w, i64 v);
void dk_cw_f64(DkCacheWriter *w, double v);
void dk_cw_bool(DkCacheWriter *w, bool v);
void dk_cw_bytes(DkCacheWriter *w, const void *p, size_t n); /* u32 length + bytes; n must fit in a u32 */
void dk_cw_str(DkCacheWriter *w, DkStr s);
void dk_cw_cz(DkCacheWriter *w, const char *cz);             /* NULL is the empty string */
void dk_cw_count(DkCacheWriter *w, size_t n);                 /* the u32 count that starts a vector / map */
/* A record: token = dk_cw_begin(w); ...fields...; dk_cw_end(w, token); (the length is patched in). */
size_t dk_cw_begin(DkCacheWriter *w);
void dk_cw_end(DkCacheWriter *w, size_t token);

/* ================================================================================================================
 * reading a payload
 * ================================================================================================================ */

typedef struct {
    const u8 *p;   /* next byte */
    const u8 *end; /* end of the record / payload */
    bool bad;      /* sticky: a read ran past the end, or a count did not fit */
} DkCacheReader;
void dk_cr_init(DkCacheReader *r, const void *p, size_t n);
bool dk_cr_ok(const DkCacheReader *r);
size_t dk_cr_remaining(const DkCacheReader *r);
u8 dk_cr_u8(DkCacheReader *r);
u16 dk_cr_u16(DkCacheReader *r);
u32 dk_cr_u32(DkCacheReader *r);
u64 dk_cr_u64(DkCacheReader *r);
i32 dk_cr_i32(DkCacheReader *r);
i64 dk_cr_i64(DkCacheReader *r);
double dk_cr_f64(DkCacheReader *r);
bool dk_cr_bool(DkCacheReader *r);
/* Views into the mapping/buffer (valid while it is): the empty string / NULL with n 0 after an error. */
DkStr dk_cr_str(DkCacheReader *r);
const u8 *dk_cr_bytes(DkCacheReader *r, size_t *n);
void dk_cr_skip(DkCacheReader *r, size_t n);
/* The u32 count of a vector / map whose elements take at least min_elem_bytes each: 0 and bad when the bytes left
 * cannot hold that many (so `dk_vec_reserve(&v, count)` is always safe). */
u32 dk_cr_count(DkCacheReader *r, size_t min_elem_bytes);
/* A record: sub covers its fields; r moves past the whole record. After reading the fields call dk_cr_end(r, &sub)
 * so a short or damaged record marks r bad. Returns false (r bad) when the record does not fit. */
bool dk_cr_record(DkCacheReader *r, DkCacheReader *sub);
void dk_cr_end(DkCacheReader *r, const DkCacheReader *sub);

/* ================================================================================================================
 * cache files
 * ================================================================================================================ */

/* Writes the file atomically (see above). stamp may be NULL (stamp_n 0). False when it could not be written (the
 * folder is missing, disk full, the target stayed mapped by a reader past the retries); the old file, if any, is
 * untouched. The folder is not created: the caller made it (fs.h). */
bool dk_cache_write(const char *path, const char *kind, u32 schema, const void *stamp, size_t stamp_n,
                     const void *payload, size_t payload_n);
bool dk_cache_write_w(const char *path, const char *kind, u32 schema, const void *stamp, size_t stamp_n,
                       const DkCacheWriter *w);

typedef struct {
    DkCacheReader r;   /* reads the payload; use it directly or dk_cr_record() sub-readers */
    const u8 *payload;  /* the payload and its length */
    size_t payload_n;
    const u8 *stamp;    /* the stamp stored in the file (a view into the mapping) */
    size_t stamp_n;
    u32 schema;
    const u8 *base;     /* the whole file image (mapping) */
    size_t size;
    void *file, *mapping; /* OS handles; NULL when the image is caller memory (dk_cache_open_mem) */
} DkCache;
/* Maps the file read-only and validates it: magic, format, header crc, kind, schema, stamp (when stamp != NULL;
 * with NULL any stamp is accepted and c->stamp tells it), exact length, payload checksum. False for every mismatch,
 * truncation, missing or unreadable file; *c is then empty and needs no close. The mapping stays valid until
 * dk_cache_close: copy out what you need, then close (an open view makes writers wait). */
bool dk_cache_open(DkCache *c, const char *path, const char *kind, u32 schema, const void *stamp, size_t stamp_n);
/* The same validation over a file image already in memory (c->file and c->mapping stay NULL). */
bool dk_cache_open_mem(DkCache *c, const void *image, size_t n, const char *kind, u32 schema, const void *stamp,
                        size_t stamp_n);
void dk_cache_close(DkCache *c);
/* The bytes of a whole cache file (header + payload) appended to out: what dk_cache_write puts on disk. */
void dk_cache_encode(DkBytes *out, const char *kind, u32 schema, const void *stamp, size_t stamp_n,
                      const void *payload, size_t payload_n);

/* ================================================================================================================
 * log files (append-only)
 * ================================================================================================================ */

/* Reading: maps the file, validates the header (magic "AVPL", format, kind, schema, stamp), then yields records. */
typedef struct {
    DkCache c;       /* c.base / c.size; the header fields */
    size_t pos;       /* next unread offset */
    size_t skipped;   /* bytes passed over because a record was torn or damaged (a status line may show it) */
    size_t records;   /* records yielded so far */
} DkLog;
bool dk_log_open(DkLog *l, const char *path, const char *kind, u32 schema, const void *stamp, size_t stamp_n);
/* The next valid record's body as a reader (a view into the mapping); false at the end. */
bool dk_log_next(DkLog *l, DkCacheReader *body);
void dk_log_close(DkLog *l);

/* Appending. Opens the log for appending, creating it (atomically, header only) when it is missing or its header
 * is not the expected one (another version / stamp: the old records are dropped, as a stale cache is). False when
 * it cannot be opened. One DkLogAppender per thread; any number of processes may append to one file. */
typedef struct {
    void *file;
} DkLogAppender;
bool dk_log_append_open(DkLogAppender *a, const char *path, const char *kind, u32 schema, const void *stamp,
                         size_t stamp_n);
/* One WriteFile of one framed record. False if the write failed (the record may be lost; the log stays valid). */
bool dk_log_append(DkLogAppender *a, const void *body, size_t n);
void dk_log_append_close(DkLogAppender *a);

/* Building a whole log in memory (for compaction): header via dk_log_write_file, records via dk_log_frame. */
void dk_log_frame(DkBytes *out, const void *body, size_t n);
bool dk_log_write_file(const char *path, const char *kind, u32 schema, const void *stamp, size_t stamp_n,
                        const void *frames, size_t frames_n);
