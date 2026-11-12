// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* cache.h: round trips of every record type, validation (kind, schema, stamp), corruption (cut at every offset, every
 * byte flipped, a wrong format version, a tail), bounds-checked reading, atomic replace under concurrent writers in
 * threads and in other processes, a writer that has to wait for a mapped reader, and the append-only log. */
#include "dk/dk.h"
#include "dk/cache.h"
#include "dk/hash.h"
#include "dk/test.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>

static void temp_path(char *out, size_t cap, const char *tag) {
    char dir[MAX_PATH];
    GetTempPathA(sizeof dir, dir);
    snprintf(out, cap, "%sdk_cache_test_%lu_%s", dir, GetCurrentProcessId(), tag);
}

static void del(const char *p) { DeleteFileA(p); }

/* ---- a payload with every type ---- */

typedef struct {
    u64 id;
    DkStr name;
    double weight;
} Item;

static void write_sample(DkCacheWriter *w) {
    dk_cw_u8(w, 200);
    dk_cw_u16(w, 60000);
    dk_cw_u32(w, 0xDEADBEEFu);
    dk_cw_u64(w, 0x0123456789ABCDEFull);
    dk_cw_i32(w, -123456);
    dk_cw_i64(w, INT64_MIN);
    dk_cw_f64(w, -0.0);
    dk_cw_f64(w, 3.141592653589793);
    u64 nan_bits = 0x7ff8000000001234ull;
    double nan;
    memcpy(&nan, &nan_bits, 8);
    dk_cw_f64(w, nan);
    dk_cw_bool(w, true);
    dk_cw_bool(w, false);
    dk_cw_cz(w, "hello");
    dk_cw_cz(w, "");
    dk_cw_cz(w, NULL);
    dk_cw_bytes(w, "a\0b", 3);
    /* a vector of records */
    dk_cw_count(w, 3);
    static const Item items[3] = {{1, {"one", 3}, 1.5}, {2, {"two\0x", 5}, -2.25}, {3, {"", 0}, 0.0}};
    for (int i = 0; i < 3; i++) {
        size_t t = dk_cw_begin(w);
        dk_cw_u64(w, items[i].id);
        dk_cw_str(w, items[i].name);
        dk_cw_f64(w, items[i].weight);
        dk_cw_end(w, t);
    }
    /* a map: key -> record (a later writer adds a field the reader below does not know) */
    dk_cw_count(w, 2);
    for (int i = 0; i < 2; i++) {
        dk_cw_cz(w, i ? "beta" : "alpha");
        size_t t = dk_cw_begin(w);
        dk_cw_u32(w, (u32)(10 + i));
        dk_cw_u32(w, 777); /* the extra field */
        dk_cw_end(w, t);
    }
    dk_cw_u32(w, 0xCAFEF00Du); /* a sentinel after everything */
}

static void check_sample(DkCacheReader *r) {
    CHECK_EQ_U64(dk_cr_u8(r), 200);
    CHECK_EQ_U64(dk_cr_u16(r), 60000);
    CHECK_EQ_U64(dk_cr_u32(r), 0xDEADBEEFu);
    CHECK_EQ_U64(dk_cr_u64(r), 0x0123456789ABCDEFull);
    CHECK_EQ_I64(dk_cr_i32(r), -123456);
    CHECK_EQ_I64(dk_cr_i64(r), INT64_MIN);
    CHECK_EQ_F64(dk_cr_f64(r), -0.0);
    CHECK_EQ_F64(dk_cr_f64(r), 3.141592653589793);
    double nan = dk_cr_f64(r);
    u64 bits;
    memcpy(&bits, &nan, 8);
    CHECK_EQ_U64(bits, 0x7ff8000000001234ull);
    CHECK(dk_cr_bool(r));
    CHECK(!dk_cr_bool(r));
    CHECK_STR(dk_cr_str(r), "hello");
    CHECK_STR(dk_cr_str(r), "");
    CHECK_STR(dk_cr_str(r), "");
    size_t bn;
    const u8 *b = dk_cr_bytes(r, &bn);
    CHECK(bn == 3 && b && memcmp(b, "a\0b", 3) == 0);
    u32 n = dk_cr_count(r, 4);
    CHECK_EQ_U64(n, 3);
    for (u32 i = 0; i < n; i++) {
        DkCacheReader rec;
        CHECK(dk_cr_record(r, &rec));
        CHECK_EQ_U64(dk_cr_u64(&rec), i + 1);
        DkStr s = dk_cr_str(&rec);
        CHECK(s.n == (i == 1 ? 5u : i == 0 ? 3u : 0u));
        double wgt = dk_cr_f64(&rec);
        CHECK_EQ_F64(wgt, i == 0 ? 1.5 : i == 1 ? -2.25 : 0.0);
        dk_cr_end(r, &rec);
    }
    n = dk_cr_count(r, 4);
    CHECK_EQ_U64(n, 2);
    for (u32 i = 0; i < n; i++) {
        CHECK_STR(dk_cr_str(r), i ? "beta" : "alpha");
        DkCacheReader rec;
        CHECK(dk_cr_record(r, &rec));
        CHECK_EQ_U64(dk_cr_u32(&rec), 10 + i);
        /* the extra field is not read: the reader skips to the record's end */
        dk_cr_end(r, &rec);
    }
    CHECK_EQ_U64(dk_cr_u32(r), 0xCAFEF00Du);
    CHECK_EQ_U64(dk_cr_remaining(r), 0);
    CHECK(dk_cr_ok(r));
}

DK_TEST(round_trip_every_type) {
    char path[MAX_PATH];
    temp_path(path, sizeof path, "rt.bin");
    DkCacheWriter w;
    dk_cw_init(&w);
    write_sample(&w);
    CHECK(dk_cache_write_w(path, "test/sample", 3, "stamp-abc", 9, &w));
    DkCache c;
    REQUIRE(dk_cache_open(&c, path, "test/sample", 3, "stamp-abc", 9));
    CHECK_EQ_U64(c.schema, 3);
    CHECK(c.stamp_n == 9 && memcmp(c.stamp, "stamp-abc", 9) == 0);
    CHECK_EQ_U64(c.payload_n, w.b.n);
    check_sample(&c.r);
    dk_cache_close(&c);
    /* the stamp may be left open to read it back */
    REQUIRE(dk_cache_open(&c, path, "test/sample", 3, NULL, 0));
    CHECK(c.stamp_n == 9 && memcmp(c.stamp, "stamp-abc", 9) == 0);
    dk_cache_close(&c);
    dk_cw_free(&w);
    del(path);
}

DK_TEST(mismatches_are_no_cache) {
    char path[MAX_PATH];
    temp_path(path, sizeof path, "mm.bin");
    CHECK(dk_cache_write(path, "tool/kind", 1, "s1", 2, "payload", 7));
    DkCache c;
    CHECK(dk_cache_open(&c, path, "tool/kind", 1, "s1", 2));
    dk_cache_close(&c);
    CHECK(!dk_cache_open(&c, path, "tool/other", 1, "s1", 2));
    CHECK(!dk_cache_open(&c, path, "tool/kin", 1, "s1", 2));
    CHECK(!dk_cache_open(&c, path, "tool/kind", 2, "s1", 2));
    CHECK(!dk_cache_open(&c, path, "tool/kind", 1, "s2", 2));
    CHECK(!dk_cache_open(&c, path, "tool/kind", 1, "s", 1));
    CHECK(!dk_cache_open(&c, path, "tool/kind", 1, "", 0));
    CHECK(!dk_cache_open(&c, "Z:/does/not/exist/cache.bin", "tool/kind", 1, NULL, 0));
    /* empty payload and empty stamp are fine */
    CHECK(dk_cache_write(path, "tool/kind", 1, NULL, 0, NULL, 0));
    CHECK(dk_cache_open(&c, path, "tool/kind", 1, NULL, 0));
    CHECK_EQ_U64(c.payload_n, 0);
    CHECK(dk_cr_ok(&c.r) && dk_cr_remaining(&c.r) == 0);
    dk_cache_close(&c);
    /* a file that is not a cache at all */
    FILE *f = fopen(path, "wb");
    fputs("this is definitely not a cache file, but it is longer than a header", f);
    fclose(f);
    CHECK(!dk_cache_open(&c, path, "tool/kind", 1, NULL, 0));
    f = fopen(path, "wb");
    fclose(f);
    CHECK(!dk_cache_open(&c, path, "tool/kind", 1, NULL, 0));
    del(path);
}

DK_TEST(corruption_cut_and_flip_every_byte) {
    DkBytes img = {0};
    DkCacheWriter w;
    dk_cw_init(&w);
    dk_cw_u32(&w, 42);
    dk_cw_cz(&w, "some payload text");
    dk_cache_encode(&img, "gate/snapshot", 7, "0123456789abcdef0123456789abcdef", 32, w.b.v, w.b.n);
    DkCache c;
    REQUIRE(dk_cache_open_mem(&c, img.v, img.n, "gate/snapshot", 7, "0123456789abcdef0123456789abcdef", 32));
    CHECK_EQ_U64(dk_cr_u32(&c.r), 42);
    /* every truncation: no cache (and no read outside the image: the copy is exactly cut long) */
    for (size_t cut = 0; cut < img.n; cut++) {
        u8 *copy = (u8 *)dk_xmalloc(cut ? cut : 1);
        memcpy(copy, img.v, cut);
        CHECK_MSG(!dk_cache_open_mem(&c, copy, cut, "gate/snapshot", 7, NULL, 0), "cut at %zu accepted", cut);
        dk_xfree(copy);
    }
    /* every byte altered, two different ways: the stamp is not passed, so a changed stamp byte is the stored stamp's
       business; the header crc and payload checksum must still refuse the file */
    for (size_t i = 0; i < img.n; i++) {
        for (int mode = 0; mode < 2; mode++) {
            u8 saved = img.v[i];
            img.v[i] = mode ? (u8)(saved ^ 0xFF) : (u8)(saved ^ 0x01);
            CHECK_MSG(!dk_cache_open_mem(&c, img.v, img.n, "gate/snapshot", 7, NULL, 0), "byte %zu changed (mode %d) accepted", i, mode);
            img.v[i] = saved;
        }
    }
    /* a tail after the payload */
    dk_vec_push(&img, 0);
    CHECK(!dk_cache_open_mem(&c, img.v, img.n, "gate/snapshot", 7, NULL, 0));
    img.n--;
    CHECK(dk_cache_open_mem(&c, img.v, img.n, "gate/snapshot", 7, NULL, 0));
    /* a future format version with an otherwise valid header (crc recomputed): refused */
    u32 v2 = 2;
    memcpy(img.v + 4, &v2, 4);
    u32 kn, sn;
    memcpy(&kn, img.v + 16, 4);
    memcpy(&sn, img.v + 20, 4);
    u32 crc = dk_crc32(dk_crc32(0, img.v, 40), img.v + 48, kn + sn);
    memcpy(img.v + 40, &crc, 4);
    CHECK(!dk_cache_open_mem(&c, img.v, img.n, "gate/snapshot", 7, NULL, 0));
    dk_cw_free(&w);
    dk_vec_free(&img);
}

DK_TEST(reader_is_bounds_checked) {
    /* a reader over a short buffer: sticky bad, zeros, no read past the end */
    u8 buf[6] = {1, 0, 0, 0, 9, 9};
    DkCacheReader r;
    dk_cr_init(&r, buf, sizeof buf);
    CHECK_EQ_U64(dk_cr_u32(&r), 1);
    CHECK(dk_cr_ok(&r));
    CHECK_EQ_U64(dk_cr_u32(&r), 0); /* two bytes left */
    CHECK(!dk_cr_ok(&r));
    CHECK_EQ_U64(dk_cr_u8(&r), 0);
    CHECK_EQ_U64(dk_cr_remaining(&r), 0);
    /* a string whose length runs past the end */
    u8 big[8] = {0xFF, 0xFF, 0xFF, 0x7F, 'a', 'b', 'c', 'd'};
    dk_cr_init(&r, big, sizeof big);
    DkStr s = dk_cr_str(&r);
    CHECK(s.n == 0 && !dk_cr_ok(&r));
    /* a count that cannot fit */
    u8 cnt[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0};
    dk_cr_init(&r, cnt, sizeof cnt);
    CHECK_EQ_U64(dk_cr_count(&r, 4), 0);
    CHECK(!dk_cr_ok(&r));
    /* a record longer than what is left; a record read past its own end marks the parent bad */
    u8 rec[9] = {4, 0, 0, 0, 1, 0, 0, 0, 7};
    dk_cr_init(&r, rec, sizeof rec);
    DkCacheReader sub;
    CHECK(dk_cr_record(&r, &sub));
    CHECK_EQ_U64(dk_cr_u32(&sub), 1);
    CHECK_EQ_U64(dk_cr_u32(&sub), 0); /* the record has only 4 bytes: the byte after it is not ours */
    dk_cr_end(&r, &sub);
    CHECK(!dk_cr_ok(&r));
    u8 rec2[6] = {200, 0, 0, 0, 1, 2};
    dk_cr_init(&r, rec2, sizeof rec2);
    CHECK(!dk_cr_record(&r, &sub));
    CHECK(!dk_cr_ok(&r));
    /* a bool that is neither 0 nor 1 */
    u8 bb[1] = {5};
    dk_cr_init(&r, bb, 1);
    dk_cr_bool(&r);
    CHECK(!dk_cr_ok(&r));
}

/* ---- concurrency ---- */

#define PAYLOAD_WORDS 4000

static void make_payload(DkCacheWriter *w, u32 writer, u32 iter) {
    dk_cw_clear(w);
    dk_cw_u32(w, writer);
    dk_cw_u32(w, iter);
    for (u32 j = 0; j < PAYLOAD_WORDS; j++) dk_cw_u32(w, writer * 1000003u + iter * 7919u + j);
}

static bool payload_consistent(DkCacheReader *r, u32 *writer_out) {
    u32 writer = dk_cr_u32(r), iter = dk_cr_u32(r);
    bool ok = true;
    for (u32 j = 0; j < PAYLOAD_WORDS; j++) ok = ok && dk_cr_u32(r) == writer * 1000003u + iter * 7919u + j;
    *writer_out = writer;
    return ok && dk_cr_ok(r) && dk_cr_remaining(r) == 0;
}

typedef struct {
    const char *path;
    u32 id;
    int iters;
    volatile LONG ok_writes, failed_writes;
} WriterArg;

static DWORD WINAPI writer_thread(LPVOID p) {
    WriterArg *a = (WriterArg *)p;
    DkCacheWriter w;
    dk_cw_init(&w);
    for (int i = 0; i < a->iters; i++) {
        make_payload(&w, a->id, (u32)i);
        if (dk_cache_write_w(a->path, "test/race", 1, "same-stamp", 10, &w)) InterlockedIncrement(&a->ok_writes);
        else InterlockedIncrement(&a->failed_writes);
    }
    dk_cw_free(&w);
    return 0;
}

DK_TEST(concurrent_writers_in_threads) {
    char path[MAX_PATH];
    temp_path(path, sizeof path, "race.bin");
    del(path);
    enum { NW = 4 };
    WriterArg args[NW];
    HANDLE th[NW];
    for (int i = 0; i < NW; i++) {
        args[i].path = path;
        args[i].id = (u32)i + 1;
        args[i].iters = 150;
        args[i].ok_writes = args[i].failed_writes = 0;
        th[i] = CreateThread(NULL, 0, writer_thread, &args[i], 0, NULL);
    }
    /* readers (this thread) keep opening while the writers replace the file: every file they get is complete */
    int reads = 0, bad = 0;
    DWORD t0 = GetTickCount();
    for (;;) {
        DWORD st = WaitForMultipleObjects(NW, th, TRUE, 0);
        DkCache c;
        if (dk_cache_open(&c, path, "test/race", 1, "same-stamp", 10)) {
            u32 who;
            if (payload_consistent(&c.r, &who)) reads++;
            else bad++;
            dk_cache_close(&c);
        }
        if (st != WAIT_TIMEOUT || GetTickCount() - t0 > 60000) break;
    }
    LONG ok = 0;
    for (int i = 0; i < NW; i++) {
        WaitForSingleObject(th[i], INFINITE);
        CloseHandle(th[i]);
        ok += args[i].ok_writes;
    }
    if (getenv("DK_CACHE_STATS")) printf("threads: %d reads, %ld of %d writes ok\n", reads, (long)ok, NW * 150);
    CHECK_EQ_U64(bad, 0);
    CHECK_MSG(reads > 0, "no read ever succeeded");
    CHECK_MSG(ok >= NW * 150 * 9 / 10, "only %ld of %d writes succeeded", (long)ok, NW * 150);
    DkCache c;
    u32 who = 0;
    REQUIRE(dk_cache_open(&c, path, "test/race", 1, "same-stamp", 10));
    CHECK(payload_consistent(&c.r, &who) && who >= 1 && who <= NW);
    dk_cache_close(&c);
    /* no temp files are left behind */
    char pattern[MAX_PATH + 8];
    snprintf(pattern, sizeof pattern, "%s.*.tmp", path);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    CHECK_MSG(h == INVALID_HANDLE_VALUE, "temp file left: %s", h == INVALID_HANDLE_VALUE ? "" : fd.cFileName);
    if (h != INVALID_HANDLE_VALUE) FindClose(h);
    del(path);
}

/* The same race across processes: this executable is started again with --filter child_writer and the work given in
 * the environment (two slots writing one cache). Without the variable the test does nothing. */
DK_TEST(child_writer) {
    const char *path = getenv("DK_CACHE_CHILD_PATH");
    if (!path) return;
    WriterArg a;
    a.path = path;
    a.id = (u32)atoi(getenv("DK_CACHE_CHILD_ID"));
    a.iters = 120;
    a.ok_writes = a.failed_writes = 0;
    writer_thread(&a);
    CHECK_MSG(a.ok_writes >= 100, "child %u: %ld writes ok", a.id, (long)a.ok_writes);
}

DK_TEST(concurrent_writers_in_processes) {
    if (getenv("DK_CACHE_CHILD_PATH")) return; /* a child runs only child_writer */
    char path[MAX_PATH];
    temp_path(path, sizeof path, "procrace.bin");
    del(path);
    SetEnvironmentVariableA("DK_CACHE_CHILD_PATH", path);
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    enum { NP = 3 };
    PROCESS_INFORMATION pi[NP];
    for (int i = 0; i < NP; i++) {
        char id[8];
        snprintf(id, sizeof id, "%d", i + 1);
        SetEnvironmentVariableA("DK_CACHE_CHILD_ID", id);
        wchar_t cmd[MAX_PATH + 64];
        swprintf(cmd, MAX_PATH + 64, L"\"%ls\" --filter child_writer", exe);
        STARTUPINFOW si;
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        memset(&pi[i], 0, sizeof pi[i]);
        REQUIRE(CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi[i]));
    }
    SetEnvironmentVariableA("DK_CACHE_CHILD_PATH", NULL);
    SetEnvironmentVariableA("DK_CACHE_CHILD_ID", NULL);
    int reads = 0, bad = 0;
    DWORD t0 = GetTickCount();
    for (;;) {
        HANDLE hs[NP];
        for (int i = 0; i < NP; i++) hs[i] = pi[i].hProcess;
        DWORD st = WaitForMultipleObjects(NP, hs, TRUE, 0);
        DkCache c;
        if (dk_cache_open(&c, path, "test/race", 1, "same-stamp", 10)) {
            u32 who;
            if (payload_consistent(&c.r, &who)) reads++;
            else bad++;
            dk_cache_close(&c);
        }
        if (st != WAIT_TIMEOUT || GetTickCount() - t0 > 120000) break;
    }
    for (int i = 0; i < NP; i++) {
        DWORD code = 1;
        if (WaitForSingleObject(pi[i].hProcess, 30000) == WAIT_TIMEOUT) {
            TerminateProcess(pi[i].hProcess, 1); /* never wait on a stuck child (crash and hang policy) */
            WaitForSingleObject(pi[i].hProcess, 10000);
        }
        GetExitCodeProcess(pi[i].hProcess, &code);
        CHECK_MSG(code == 0, "child %d exited with %lu", i + 1, (unsigned long)code);
        CloseHandle(pi[i].hProcess);
        CloseHandle(pi[i].hThread);
    }
    if (getenv("DK_CACHE_STATS")) printf("processes: %d reads\n", reads);
    CHECK_EQ_U64(bad, 0);
    CHECK_MSG(reads > 0, "no read succeeded");
    DkCache c;
    u32 who = 0;
    REQUIRE(dk_cache_open(&c, path, "test/race", 1, "same-stamp", 10));
    CHECK(payload_consistent(&c.r, &who) && who >= 1 && who <= NP);
    dk_cache_close(&c);
    del(path);
}

static DWORD WINAPI close_later(LPVOID p) {
    Sleep(300);
    dk_cache_close((DkCache *)p);
    return 0;
}

DK_TEST(writer_waits_for_a_mapped_reader) {
    char path[MAX_PATH];
    temp_path(path, sizeof path, "wait.bin");
    CHECK(dk_cache_write(path, "test/wait", 1, NULL, 0, "old contents", 12));
    DkCache c;
    REQUIRE(dk_cache_open(&c, path, "test/wait", 1, NULL, 0));
    HANDLE t = CreateThread(NULL, 0, close_later, &c, 0, NULL);
    DWORD t0 = GetTickCount();
    CHECK(dk_cache_write(path, "test/wait", 1, NULL, 0, "new contents!", 13)); /* waits for the close */
    DWORD took = GetTickCount() - t0;
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
    CHECK_MSG(took >= 250, "the replace did not wait for the mapped reader (%lu ms)", (unsigned long)took);
    REQUIRE(dk_cache_open(&c, path, "test/wait", 1, NULL, 0));
    CHECK(c.payload_n == 13 && memcmp(c.payload, "new contents!", 13) == 0);
    dk_cache_close(&c);
    del(path);
}

/* ---- the log ---- */

static void append_record(DkLogAppender *a, u32 key, u32 value) {
    DkCacheWriter w;
    dk_cw_init(&w);
    dk_cw_u32(&w, key);
    dk_cw_u32(&w, value);
    dk_cw_cz(&w, "tail");
    CHECK(dk_log_append(a, w.b.v, w.b.n));
    dk_cw_free(&w);
}

DK_TEST(log_append_and_replay) {
    char path[MAX_PATH];
    temp_path(path, sizeof path, "log.bin");
    del(path);
    DkLog l;
    CHECK(!dk_log_open(&l, path, "memo/x", 1, "v1", 2)); /* missing */
    DkLogAppender a;
    REQUIRE(dk_log_append_open(&a, path, "memo/x", 1, "v1", 2));
    for (u32 i = 0; i < 100; i++) append_record(&a, i % 10, i);
    dk_log_append_close(&a);
    /* a second appender (another run) adds to the same file */
    REQUIRE(dk_log_append_open(&a, path, "memo/x", 1, "v1", 2));
    append_record(&a, 3, 1000);
    dk_log_append_close(&a);
    REQUIRE(dk_log_open(&l, path, "memo/x", 1, "v1", 2));
    u32 last[10] = {0};
    DkCacheReader r;
    u32 n = 0;
    while (dk_log_next(&l, &r)) {
        u32 k = dk_cr_u32(&r), v = dk_cr_u32(&r);
        CHECK_STR(dk_cr_str(&r), "tail");
        CHECK(dk_cr_ok(&r) && k < 10);
        last[k] = v; /* later records override earlier ones */
        n++;
    }
    CHECK_EQ_U64(n, 101);
    CHECK_EQ_U64(l.skipped, 0);
    CHECK_EQ_U64(last[3], 1000);
    CHECK_EQ_U64(last[9], 99);
    dk_log_close(&l);
    /* mismatches */
    CHECK(!dk_log_open(&l, path, "memo/x", 1, "v2", 2));
    CHECK(!dk_log_open(&l, path, "memo/y", 1, "v1", 2));
    CHECK(!dk_log_open(&l, path, "memo/x", 2, "v1", 2));
    DkCache cc;
    CHECK(!dk_cache_open(&cc, path, "memo/x", 1, "v1", 2)); /* a log is not a cache file */
    /* appending with another stamp starts a fresh log: the old records are gone */
    REQUIRE(dk_log_append_open(&a, path, "memo/x", 1, "v2", 2));
    append_record(&a, 1, 5);
    dk_log_append_close(&a);
    REQUIRE(dk_log_open(&l, path, "memo/x", 1, "v2", 2));
    n = 0;
    while (dk_log_next(&l, &r)) n++;
    CHECK_EQ_U64(n, 1);
    dk_log_close(&l);
    del(path);
}

typedef struct {
    const char *path;
    HANDLE go;
    u32 id;
    LONG opened;
} LogRaceArg;

static DWORD WINAPI log_race_thread(void *p) {
    LogRaceArg *a = (LogRaceArg *)p;
    WaitForSingleObject(a->go, INFINITE);
    DkLogAppender ap;
    if (!dk_log_append_open(&ap, a->path, "memo/race", 1, "v1", 2)) return 0;
    a->opened = 1;
    for (u32 i = 0; i < 20; i++) append_record(&ap, a->id, i);
    dk_log_append_close(&ap);
    return 0;
}

/* Threads that all find the log missing create it once: no creator replaces a file another one has appended to. */
DK_TEST(log_creation_race_loses_nothing) {
    char path[MAX_PATH];
    temp_path(path, sizeof path, "lograce.bin");
    enum { NT = 8, ROUNDS = 25 };
    for (int round = 0; round < ROUNDS; round++) {
        del(path);
        HANDLE go = CreateEventA(NULL, TRUE, FALSE, NULL);
        LogRaceArg args[NT];
        HANDLE th[NT];
        for (int i = 0; i < NT; i++) {
            args[i].path = path;
            args[i].go = go;
            args[i].id = (u32)i;
            args[i].opened = 0;
            th[i] = CreateThread(NULL, 0, log_race_thread, &args[i], 0, NULL);
        }
        SetEvent(go);
        WaitForMultipleObjects(NT, th, TRUE, INFINITE);
        int opened = 0;
        for (int i = 0; i < NT; i++) {
            CloseHandle(th[i]);
            opened += (int)args[i].opened;
        }
        CloseHandle(go);
        CHECK_EQ_U64(opened, NT);
        DkLog l;
        REQUIRE(dk_log_open(&l, path, "memo/race", 1, "v1", 2));
        DkCacheReader r;
        int n = 0;
        while (dk_log_next(&l, &r)) n++;
        dk_log_close(&l);
        CHECK_EQ_U64(n, NT * 20);
        if (n != NT * 20) break;
    }
    del(path);
}

DK_TEST(log_survives_torn_and_damaged_records) {
    char path[MAX_PATH];
    temp_path(path, sizeof path, "logdmg.bin");
    del(path);
    DkLogAppender a;
    REQUIRE(dk_log_append_open(&a, path, "memo/x", 1, "v1", 2));
    for (u32 i = 0; i < 20; i++) append_record(&a, i, i * 3);
    dk_log_append_close(&a);
    /* read the file, damage record 7's body, append half a frame, write it back */
    FILE *f = fopen(path, "rb");
    DkBytes img = {0};
    u8 chunk[4096];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, f)) > 0) dk_vec_extend(&img, chunk, got);
    fclose(f);
    /* every record is 12 + (4 + 4 + 4 + 4) = 28 bytes; the header is at least 48 bytes: find record 7 by scanning */
    u32 marker = 0x01525641u;
    size_t first = 0;
    for (size_t i = 48 - 8; i + 4 <= img.n; i++)
        if (memcmp(img.v + i, &marker, 4) == 0) { first = i; break; }
    REQUIRE(first >= 40 && first <= 64);
    img.v[first + 7 * 28 + 14] ^= 0x55;
    static const u8 half[] = {0x41, 0x56, 0x52, 0x01, 0x20, 0x00};
    dk_vec_extend(&img, half, sizeof half);
    f = fopen(path, "wb");
    fwrite(img.v, 1, img.n, f);
    fclose(f);
    DkLog l;
    REQUIRE(dk_log_open(&l, path, "memo/x", 1, "v1", 2));
    DkCacheReader r;
    u32 seen = 0;
    bool had7 = false;
    while (dk_log_next(&l, &r)) {
        u32 k = dk_cr_u32(&r);
        if (k == 7) had7 = true;
        seen++;
    }
    CHECK_EQ_U64(seen, 19);
    CHECK(!had7);
    CHECK_MSG(l.skipped >= 28, "skipped %zu", l.skipped);
    dk_log_close(&l);
    /* appending after a torn tail still works: later records are found by the resync */
    REQUIRE(dk_log_append_open(&a, path, "memo/x", 1, "v1", 2));
    append_record(&a, 99, 99);
    dk_log_append_close(&a);
    REQUIRE(dk_log_open(&l, path, "memo/x", 1, "v1", 2));
    seen = 0;
    bool had99 = false;
    while (dk_log_next(&l, &r)) {
        if (dk_cr_u32(&r) == 99) had99 = true;
        seen++;
    }
    CHECK(had99);
    CHECK_EQ_U64(seen, 20);
    dk_log_close(&l);
    /* compaction: replay, keep two records, replace the file */
    DkBytes frames = {0};
    DkCacheWriter w;
    dk_cw_init(&w);
    dk_cw_u32(&w, 5);
    dk_cw_u32(&w, 50);
    dk_log_frame(&frames, w.b.v, w.b.n);
    dk_log_frame(&frames, w.b.v, 0);
    CHECK(dk_log_write_file(path, "memo/x", 1, "v1", 2, frames.v, frames.n));
    REQUIRE(dk_log_open(&l, path, "memo/x", 1, "v1", 2));
    seen = 0;
    while (dk_log_next(&l, &r)) seen++;
    CHECK_EQ_U64(seen, 2);
    CHECK_EQ_U64(l.skipped, 0);
    dk_log_close(&l);
    dk_cw_free(&w);
    dk_vec_free(&frames);
    dk_vec_free(&img);
    del(path);
}

typedef struct {
    const char *path;
    u32 id;
    int n;
} AppendArg;
static DWORD WINAPI append_thread(LPVOID p) {
    AppendArg *a = (AppendArg *)p;
    DkLogAppender ap;
    if (!dk_log_append_open(&ap, a->path, "memo/mt", 1, "s", 1)) return 1;
    for (int i = 0; i < a->n; i++) append_record(&ap, a->id, (u32)i);
    dk_log_append_close(&ap);
    return 0;
}

DK_TEST(log_concurrent_appenders) {
    char path[MAX_PATH];
    temp_path(path, sizeof path, "logmt.bin");
    del(path);
    {
        DkLogAppender ap;
        REQUIRE(dk_log_append_open(&ap, path, "memo/mt", 1, "s", 1)); /* the header exists before the race */
        dk_log_append_close(&ap);
    }
    enum { NT = 6, PER = 300 };
    AppendArg args[NT];
    HANDLE th[NT];
    for (int i = 0; i < NT; i++) {
        args[i].path = path;
        args[i].id = (u32)i;
        args[i].n = PER;
        th[i] = CreateThread(NULL, 0, append_thread, &args[i], 0, NULL);
    }
    WaitForMultipleObjects(NT, th, TRUE, INFINITE);
    for (int i = 0; i < NT; i++) CloseHandle(th[i]);
    DkLog l;
    REQUIRE(dk_log_open(&l, path, "memo/mt", 1, "s", 1));
    DkCacheReader r;
    u32 count[NT] = {0}, next[NT] = {0};
    bool in_order = true;
    while (dk_log_next(&l, &r)) {
        u32 k = dk_cr_u32(&r), v = dk_cr_u32(&r);
        if (k < NT) {
            count[k]++;
            in_order = in_order && v == next[k]++;
        }
    }
    for (int i = 0; i < NT; i++) CHECK_EQ_U64(count[i], PER);
    CHECK(in_order);
    CHECK_EQ_U64(l.skipped, 0); /* no record of one appender cut another in two */
    dk_log_close(&l);
    del(path);
}

DK_TEST(bench) {
    if (!getenv("DK_BENCH")) return;
    char path[MAX_PATH];
    temp_path(path, sizeof path, "bench.bin");
    size_t n = 100u << 20;
    DkCacheWriter w;
    dk_cw_init(&w);
    LARGE_INTEGER f, t0, t1, t2, t3;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    for (size_t i = 0; i < n / 8; i++) dk_cw_u64(&w, i * 0x9E3779B97F4A7C15ull);
    QueryPerformanceCounter(&t1);
    CHECK(dk_cache_write_w(path, "bench/x", 1, "s", 1, &w));
    QueryPerformanceCounter(&t2);
    DkCache c;
    CHECK(dk_cache_open(&c, path, "bench/x", 1, "s", 1));
    u64 sum = 0;
    for (size_t i = 0; i < n / 8; i++) sum += dk_cr_u64(&c.r);
    dk_cache_close(&c);
    QueryPerformanceCounter(&t3);
    double fq = (double)f.QuadPart;
    printf("cache 100 MB: build %.0f ms, write %.0f ms, open+checksum+read %.0f ms (%llx)\n", 1e3 * (double)(t1.QuadPart - t0.QuadPart) / fq,
           1e3 * (double)(t2.QuadPart - t1.QuadPart) / fq, 1e3 * (double)(t3.QuadPart - t2.QuadPart) / fq, (unsigned long long)sum);
    dk_cw_free(&w);
    del(path);
}

DK_TEST_MAIN("cache")
