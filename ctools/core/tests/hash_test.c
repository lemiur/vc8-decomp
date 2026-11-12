// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* hash.h against CPython 3.14: hashlib digests and zlib.crc32 of known vectors and of pseudo-random buffers (the
 * expected values are in hash_corpus.h with their generator), incremental hashing, file digests, and the frozen
 * dk_hash64. Set DK_BENCH=1 to print throughput against the numbers hashlib gives (see the report). */
#include "dk/dk.h"
#include "dk/hash.h"
#include "dk/test.h"

#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#include <windows.h>

#include "hash_corpus.h"

/* the same xorshift64* byte generator as the corpus snippet */
static u8 *fill(size_t n, u64 seed) {
    u8 *out = (u8 *)dk_xmalloc(n ? n : 1);
    u64 x = seed;
    for (size_t i = 0; i < n; i++) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        out[i] = (u8)((x * 0x2545F4914F6CDD1Dull) >> 56);
    }
    return out;
}

static const char *hex(DkArena *a, DkHashAlg alg, const void *p, size_t n) { return dk_hash_hex(a, alg, p, n); }

DK_TEST(known_vectors) {
    DkArena *a = dk_arena_new(0);
    /* python -c "import hashlib; [print(f(b'abc').hexdigest()) for f in (hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512)]" */
    CHECK_CZ(hex(a, DK_HASH_MD5, "abc", 3), "900150983cd24fb0d6963f7d28e17f72");
    CHECK_CZ(hex(a, DK_HASH_SHA1, "abc", 3), "a9993e364706816aba3e25717850c26c9cd0d89d");
    CHECK_CZ(hex(a, DK_HASH_SHA256, "abc", 3), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK_CZ(hex(a, DK_HASH_SHA512, "abc", 3),
             "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    CHECK_CZ(hex(a, DK_HASH_SHA256, "", 0), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK_CZ(dk_sha256_hex(a, "abc", 3), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK_CZ(dk_md5_hex(a, "abc", 3), "900150983cd24fb0d6963f7d28e17f72");
    CHECK_CZ(dk_sha1_hex(a, "abc", 3), "a9993e364706816aba3e25717850c26c9cd0d89d");
    u8 d[32];
    dk_sha256("abc", 3, d);
    CHECK_CZ(dk_hex(a, d, 6), "ba7816bf8f01");
    CHECK_EQ_U64(dk_hash_len(DK_HASH_MD5), 16);
    CHECK_EQ_U64(dk_hash_len(DK_HASH_SHA1), 20);
    CHECK_EQ_U64(dk_hash_len(DK_HASH_SHA256), 32);
    CHECK_EQ_U64(dk_hash_len(DK_HASH_SHA512), 64);
    char buf[16];
    CHECK_EQ_U64(dk_hex_to((const u8 *)"\x00\xff\x10", 3, buf), 6);
    CHECK_CZ(buf, "00ff10");
    dk_arena_free(a);
}

DK_TEST(corpus_digests_and_crc) {
    DkArena *a = dk_arena_new(0);
    for (size_t i = 0; i < DK_ARRAY_LEN(k_hash_cases); i++) {
        const HashCase *c = &k_hash_cases[i];
        u8 *buf = fill(c->n, c->seed);
        CHECK_CZ(hex(a, DK_HASH_MD5, buf, c->n), c->md5);
        CHECK_CZ(hex(a, DK_HASH_SHA1, buf, c->n), c->sha1);
        CHECK_CZ(hex(a, DK_HASH_SHA256, buf, c->n), c->sha256);
        CHECK_CZ(hex(a, DK_HASH_SHA512, buf, c->n), c->sha512);
        CHECK_EQ_U64(dk_crc32(0, buf, c->n), c->crc);
        dk_xfree(buf);
    }
    dk_arena_free(a);
}

DK_TEST(crc32_semantics) {
    /* python -c "import zlib; print(hex(zlib.crc32(b'123456789')), zlib.crc32(b''), zlib.crc32(b'6789', zlib.crc32(b'12345')))" */
    CHECK_EQ_U64(dk_crc32(0, "123456789", 9), 0xCBF43926u);
    CHECK_EQ_U64(dk_crc32(0, "", 0), 0);
    CHECK_EQ_U64(dk_crc32(dk_crc32(0, "12345", 5), "6789", 4), 0xCBF43926u);
    CHECK_EQ_U64(dk_crc32(0, NULL, 0), 0);
}

DK_TEST(incremental_matches_one_shot) {
    DkArena *a = dk_arena_new(0);
    u8 *buf = fill(100000, 77);
    for (int alg = DK_HASH_MD5; alg <= DK_HASH_SHA512; alg++) {
        u8 one[DK_HASH_MAX_LEN], inc[DK_HASH_MAX_LEN], peeked[DK_HASH_MAX_LEN];
        dk_hash((DkHashAlg)alg, buf, 100000, one);
        size_t len = dk_hash_len((DkHashAlg)alg);
        static const size_t steps[] = {1, 7, 63, 64, 65, 4096, 99999};
        for (size_t s = 0; s < DK_ARRAY_LEN(steps); s++) {
            DkHasher h;
            dk_hasher_init(&h, (DkHashAlg)alg);
            size_t i = 0;
            while (i < 100000) {
                size_t k = DK_MIN(steps[s], 100000 - i);
                dk_hasher_update(&h, buf + i, k);
                i += k;
                if (i == 50000 || (steps[s] == 1 && i == 40)) {
                    /* hashlib: h.copy().digest() in the middle does not disturb h */
                    dk_hasher_peek(&h, peeked);
                    u8 expect[DK_HASH_MAX_LEN];
                    dk_hash((DkHashAlg)alg, buf, i, expect);
                    CHECK_MEM(peeked, expect, len);
                }
            }
            dk_hasher_final(&h, inc);
            CHECK_MEM(one, inc, len);
        }
        /* copy: two continuations from one state */
        DkHasher h1, h2;
        dk_hasher_init(&h1, (DkHashAlg)alg);
        dk_hasher_update(&h1, buf, 1000);
        dk_hasher_copy(&h2, &h1);
        dk_hasher_update(&h1, buf + 1000, 5);
        dk_hasher_update(&h2, buf + 1000, 6);
        u8 x1[DK_HASH_MAX_LEN], x2[DK_HASH_MAX_LEN], e1[DK_HASH_MAX_LEN], e2[DK_HASH_MAX_LEN];
        dk_hasher_final(&h1, x1);
        dk_hasher_final(&h2, x2);
        dk_hash((DkHashAlg)alg, buf, 1005, e1);
        dk_hash((DkHashAlg)alg, buf, 1006, e2);
        CHECK_MEM(x1, e1, len);
        CHECK_MEM(x2, e2, len);
        /* an abandoned hash and re-use of the struct */
        DkHasher h3;
        dk_hasher_init(&h3, (DkHashAlg)alg);
        dk_hasher_update(&h3, "x", 1);
        dk_hasher_free(&h3);
        CHECK(h3.h == NULL);
        dk_hasher_free(&h3);
    }
    dk_xfree(buf);
    dk_arena_free(a);
}

static void write_bytes(const char *path, const void *p, size_t n) {
    FILE *f = fopen(path, "wb");
    if (f) {
        if (n) fwrite(p, 1, n, f);
        fclose(f);
    }
}

DK_TEST(file_digests) {
    DkArena *a = dk_arena_new(0);
    char dir[MAX_PATH], path[MAX_PATH];
    GetTempPathA(sizeof dir, dir);
    snprintf(path, sizeof path, "%sdk_hash_test_%lu.bin", dir, GetCurrentProcessId());
    for (size_t i = 0; i < DK_ARRAY_LEN(k_hash_cases); i++) {
        const HashCase *c = &k_hash_cases[i];
        u8 *buf = fill(c->n, c->seed);
        write_bytes(path, buf, c->n);
        CHECK_CZ(dk_file_digest_hex(a, DK_HASH_SHA256, path), c->sha256);
        CHECK_CZ(dk_file_digest_hex(a, DK_HASH_MD5, path), c->md5);
        u8 d[32], e[32];
        CHECK(dk_file_digest(DK_HASH_SHA256, path, d));
        dk_sha256(buf, c->n, e);
        CHECK_MEM(d, e, 32);
        dk_xfree(buf);
    }
    DeleteFileA(path);
    CHECK(dk_file_digest_hex(a, DK_HASH_SHA256, path) == NULL);
    u8 d[32];
    CHECK(!dk_file_digest(DK_HASH_SHA256, path, d));
    dk_arena_free(a);
}

/* Frozen vectors of dk_hash64 (cache.h stores its value, so it may never change). The table was produced by
 * this independent Python port of the algorithm and agrees with the C code (fill() is the corpus generator):
 *
 * M=(1<<64)-1
 * K0,K1,K2,K3=0xa0761d6478bd642f,0xe7037ed1a0b428db,0x8ebc6af09c88c6e3,0x589965cc75374cc3
 * def mix(a,b):
 *     p=a*b; return (p&M)^(p>>64)
 * def r64(b,i): return int.from_bytes(b[i:i+8],'little')
 * def r32(b,i): return int.from_bytes(b[i:i+4],'little')
 * def h64(d,seed):
 *     n=len(d); seed&=M
 *     seed^=mix(seed^K0,K1); p=0
 *     if n<=16:
 *         if n>=4:
 *             q=(n>>3)<<2
 *             a=(r32(d,0)<<32)|r32(d,q); b=(r32(d,n-4)<<32)|r32(d,n-4-q)
 *         elif n>0:
 *             a=(d[0]<<16)|(d[n>>1]<<8)|d[n-1]; b=0
 *         else: a=b=0
 *     else:
 *         i=n
 *         if i>48:
 *             s1=s2=seed
 *             while True:
 *                 seed=mix(r64(d,p)^K1,r64(d,p+8)^seed)
 *                 s1=mix(r64(d,p+16)^K2,r64(d,p+24)^s1)
 *                 s2=mix(r64(d,p+32)^K3,r64(d,p+40)^s2)
 *                 p+=48;i-=48
 *                 if i<=48: break
 *             seed^=s1^s2
 *         while i>16:
 *             seed=mix(r64(d,p)^K1,r64(d,p+8)^seed);p+=16;i-=16
 *         a=r64(d,p+i-16);b=r64(d,p+i-8)
 *     a^=K1;b^=seed
 *     pr=(a&M)*(b&M); lo=pr&M; hi=pr>>64
 *     return mix(lo^K0^n,hi^K1)
 *    buf = fill(5000, 99); for n in (...): h64(buf[:n], seed)  with seed 0 and 0x123456789abcdef
 */
typedef struct { size_t n; u64 seed; u64 expect; } H64Vec;
static const H64Vec k_h64[] = {
    {0, 0, 0x0409638ee2bde459ull},
    {0, 0x123456789abcdefull, 0x2b4e3df129b1f482ull},
    {1, 0, 0xd47b2c522ce63819ull},
    {1, 0x123456789abcdefull, 0x698bb7d7576ffd6dull},
    {2, 0, 0x7665aee61dd61113ull},
    {2, 0x123456789abcdefull, 0xa6763bde771a69e7ull},
    {3, 0, 0x5c6b3723ec0b7304ull},
    {3, 0x123456789abcdefull, 0xb9852f4f916dffc3ull},
    {4, 0, 0x757a5f64ac0f04ecull},
    {4, 0x123456789abcdefull, 0xe56b0dc92e8f27e5ull},
    {5, 0, 0xd03b59f5d598bbadull},
    {5, 0x123456789abcdefull, 0x12d72412a91c0980ull},
    {8, 0, 0xa4ef7d0be758245aull},
    {8, 0x123456789abcdefull, 0xd20b03df393d60f6ull},
    {9, 0, 0xfe6a42d1f749cf2dull},
    {9, 0x123456789abcdefull, 0x7787311576c5fa88ull},
    {15, 0, 0x2660eb19b4388893ull},
    {15, 0x123456789abcdefull, 0x97fd9f8237630999ull},
    {16, 0, 0x4ab2c59b4ca02735ull},
    {16, 0x123456789abcdefull, 0x53913165331fa788ull},
    {17, 0, 0x30ad43d996a152eeull},
    {17, 0x123456789abcdefull, 0x1f0abfc0bbc16a95ull},
    {31, 0, 0x8589015f1b7eca1eull},
    {31, 0x123456789abcdefull, 0x571c78d9ec08290full},
    {32, 0, 0xa5676933c0062cb9ull},
    {32, 0x123456789abcdefull, 0xe38f76108bbd073cull},
    {33, 0, 0x7712ac1a6fb9e71bull},
    {33, 0x123456789abcdefull, 0xcd16d8ed16967761ull},
    {47, 0, 0x4b9997b71fb2e9f9ull},
    {47, 0x123456789abcdefull, 0x5deb588bab3cd2bfull},
    {48, 0, 0x0b1165834854f51aull},
    {48, 0x123456789abcdefull, 0x1928159e4951f456ull},
    {49, 0, 0x6e9b38729857cd82ull},
    {49, 0x123456789abcdefull, 0x1255f34a4dd164b6ull},
    {63, 0, 0x67b9e5e671e9e0d3ull},
    {63, 0x123456789abcdefull, 0x82f1417c03a74413ull},
    {64, 0, 0xfe5e076fb9550f0eull},
    {64, 0x123456789abcdefull, 0x7e3f195f11f11b4cull},
    {65, 0, 0x66d0ac00c1046fbfull},
    {65, 0x123456789abcdefull, 0x70db97d09213ae8bull},
    {100, 0, 0x286a0471a11f9cf8ull},
    {100, 0x123456789abcdefull, 0xb11754b97d395d9eull},
    {1000, 0, 0xe0a05d0b2bf5ce3eull},
    {1000, 0x123456789abcdefull, 0x9175780639cb2dd7ull},
    {5000, 0, 0xfb6be2b2d138e471ull},
    {5000, 0x123456789abcdefull, 0xa59b676709f2cfb6ull},
};

DK_TEST(hash64_frozen) {
    u8 *buf = fill(5000, 99);
    if (getenv("DK_HASH64_PRINT")) {
        static const size_t lens[] = {0, 1, 2, 3, 4, 5, 8, 9, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 100, 1000, 5000};
        for (size_t i = 0; i < DK_ARRAY_LEN(lens); i++)
            printf("    {%zu, 0, 0x%016llxull},\n    {%zu, 0x123456789abcdefull, 0x%016llxull},\n", lens[i],
                   (unsigned long long)dk_hash64(buf, lens[i], 0), lens[i],
                   (unsigned long long)dk_hash64(buf, lens[i], 0x123456789abcdefull));
    }
    for (size_t i = 0; i < DK_ARRAY_LEN(k_h64); i++) CHECK_EQ_U64(dk_hash64(buf, k_h64[i].n, k_h64[i].seed), k_h64[i].expect);
    dk_xfree(buf);
}

DK_TEST(hash64_quality) {
    u8 *buf = fill(4096, 5);
    /* every prefix length gives a different value, and alignment does not matter */
    u64 prev[600];
    for (size_t n = 0; n < 600; n++) {
        prev[n] = dk_hash64(buf, n, 0);
        u8 *shifted = (u8 *)dk_xmalloc(n + 8);
        memcpy(shifted + 3, buf, n);
        CHECK_EQ_U64(dk_hash64(shifted + 3, n, 0), prev[n]);
        dk_xfree(shifted);
    }
    for (size_t i = 0; i < 600; i++)
        for (size_t j = i + 1; j < 600; j++)
            if (prev[i] == prev[j]) CHECK_MSG(0, "prefix hashes %zu and %zu collide", i, j);
    /* the seed matters; the input matters in every byte (a one-bit change flips about half the output bits) */
    CHECK(dk_hash64(buf, 100, 1) != dk_hash64(buf, 100, 2));
    int worst_lo = 64, worst_hi = 0;
    for (size_t n = 1; n <= 300; n += 7) {
        u64 base = dk_hash64(buf, n, 0);
        for (size_t byte = 0; byte < n; byte += (n > 16 ? 5 : 1)) {
            u8 tmp[300];
            memcpy(tmp, buf, n);
            tmp[byte] ^= 1;
            u64 diff = base ^ dk_hash64(tmp, n, 0);
            int bits = (int)__popcnt64(diff);
            if (bits < worst_lo) worst_lo = bits;
            if (bits > worst_hi) worst_hi = bits;
        }
    }
    CHECK_MSG(worst_lo >= 14 && worst_hi <= 50, "avalanche %d..%d bits", worst_lo, worst_hi);
    /* the integer finaliser is a bijection on a sample and not the identity */
    CHECK(dk_hash64_u64(0) == 0);
    CHECK(dk_hash64_u64(1) != 1);
    CHECK(dk_hash64_u64(1) != dk_hash64_u64(2));
    DkStr s = {"hello", 5};
    CHECK_EQ_U64(dk_hash64_str(s, 3), dk_hash64("hello", 5, 3));
    dk_xfree(buf);
}

typedef struct { int id; int failures; } ThreadArg;
static DWORD WINAPI hash_thread(LPVOID p) {
    ThreadArg *t = (ThreadArg *)p;
    DkArena *a = dk_arena_new(0);
    for (int iter = 0; iter < 300; iter++) {
        const HashCase *c = &k_hash_cases[(size_t)(iter + t->id) % DK_ARRAY_LEN(k_hash_cases)];
        if (c->n > 200000) continue;
        u8 *buf = fill(c->n, c->seed);
        DkArenaMark mark = dk_arena_mark(a);
        DkHasher h;
        dk_hasher_init(&h, DK_HASH_SHA256);
        dk_hasher_update(&h, buf, c->n / 2);
        dk_hasher_update(&h, buf + c->n / 2, c->n - c->n / 2);
        u8 d[32];
        dk_hasher_final(&h, d);
        if (strcmp(dk_hex(a, d, 32), c->sha256) != 0) t->failures++;
        if (strcmp(dk_md5_hex(a, buf, c->n), c->md5) != 0) t->failures++;
        if (strcmp(dk_hash_hex(a, DK_HASH_SHA512, buf, c->n), c->sha512) != 0) t->failures++;
        dk_arena_reset(a, mark);
        dk_xfree(buf);
    }
    dk_arena_free(a);
    return 0;
}

DK_TEST(threads_share_the_algorithm_handles) {
    enum { N = 8 };
    ThreadArg args[N];
    HANDLE th[N];
    for (int i = 0; i < N; i++) {
        args[i].id = i;
        args[i].failures = 0;
        th[i] = CreateThread(NULL, 0, hash_thread, &args[i], 0, NULL);
    }
    WaitForMultipleObjects(N, th, TRUE, INFINITE);
    for (int i = 0; i < N; i++) {
        CloseHandle(th[i]);
        CHECK_EQ_I64(args[i].failures, 0);
    }
}

DK_TEST(bench) {
    if (!getenv("DK_BENCH")) return;
    size_t n = 100u << 20;
    u8 *buf = fill(n, 123);
    LARGE_INTEGER f, t0, t1;
    QueryPerformanceFrequency(&f);
    u8 d[64];
    static const struct { DkHashAlg alg; const char *name; } algs[] = {
        {DK_HASH_MD5, "md5"}, {DK_HASH_SHA1, "sha1"}, {DK_HASH_SHA256, "sha256"}, {DK_HASH_SHA512, "sha512"}};
    for (size_t i = 0; i < 4; i++) {
        QueryPerformanceCounter(&t0);
        dk_hash(algs[i].alg, buf, n, d);
        QueryPerformanceCounter(&t1);
        printf("%-7s %8.1f MB/s\n", algs[i].name, 100.0 / ((double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart));
    }
    QueryPerformanceCounter(&t0);
    u32 crc = dk_crc32(0, buf, n);
    QueryPerformanceCounter(&t1);
    printf("%-7s %8.1f MB/s (%08x)\n", "crc32", 100.0 / ((double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart), crc);
    QueryPerformanceCounter(&t0);
    u64 h = dk_hash64(buf, n, 0);
    QueryPerformanceCounter(&t1);
    printf("%-7s %8.1f MB/s (%016llx)\n", "hash64", 100.0 / ((double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart), (unsigned long long)h);
    /* small inputs: cache-key sized sha256 calls per second */
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < 200000; i++) dk_sha256(buf + i, 64, d);
    QueryPerformanceCounter(&t1);
    printf("sha256 of 64 bytes: %.0f ns each\n", 1e9 * ((double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart) / 200000.0);
    dk_xfree(buf);
}

DK_TEST_MAIN("hash")
