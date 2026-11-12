// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Hashing: CNG digests, hex, file digests, CRC-32 and the fast 64-bit hash. See hash.h for the Python equivalents. */
#include "dk/hash.h"

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>

/* ---- CNG algorithm handles: one per algorithm, opened once, shared by all threads --------------------------------- */

typedef struct {
    INIT_ONCE once;
    BCRYPT_ALG_HANDLE h;
    ULONG object_len; /* BCRYPT_OBJECT_LENGTH: the bytes a hash object needs */
    ULONG digest_len;
} AlgSlot;

static AlgSlot g_alg[4] = {{INIT_ONCE_STATIC_INIT, NULL, 0, 0}, {INIT_ONCE_STATIC_INIT, NULL, 0, 0},
                           {INIT_ONCE_STATIC_INIT, NULL, 0, 0}, {INIT_ONCE_STATIC_INIT, NULL, 0, 0}};

static const wchar_t *const k_alg_names[4] = {BCRYPT_MD5_ALGORITHM, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
                                              BCRYPT_SHA512_ALGORITHM};
static const ULONG k_alg_len[4] = {DK_MD5_LEN, DK_SHA1_LEN, DK_SHA256_LEN, DK_SHA512_LEN};

static BOOL CALLBACK alg_open(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    DK_UNUSED(once);
    DK_UNUSED(ctx);
    AlgSlot *s = (AlgSlot *)param;
    int i = (int)(s - g_alg);
    NTSTATUS st = BCryptOpenAlgorithmProvider(&s->h, k_alg_names[i], NULL, BCRYPT_HASH_REUSABLE_FLAG);
    if (st < 0) dk_panic(__FILE__, __LINE__, "BCryptOpenAlgorithmProvider failed: 0x%08lx", (unsigned long)st);
    ULONG got = 0;
    st = BCryptGetProperty(s->h, BCRYPT_OBJECT_LENGTH, (PUCHAR)&s->object_len, sizeof s->object_len, &got, 0);
    if (st < 0) dk_panic(__FILE__, __LINE__, "BCryptGetProperty(object length) failed: 0x%08lx", (unsigned long)st);
    s->digest_len = k_alg_len[i];
    return TRUE;
}

static AlgSlot *alg_slot(DkHashAlg alg) {
    DK_ASSERT((unsigned)alg < 4);
    AlgSlot *s = &g_alg[alg];
    InitOnceExecuteOnce(&s->once, alg_open, s, NULL);
    return s;
}

size_t dk_hash_len(DkHashAlg alg) {
    DK_ASSERT((unsigned)alg < 4);
    return k_alg_len[alg];
}

/* CNG takes ULONG lengths: larger inputs go in pieces (never a partial block is split, any size is fine for update). */
#define CHUNK_MAX ((size_t)1 << 30)

void dk_hasher_init(DkHasher *h, DkHashAlg alg) {
    AlgSlot *s = alg_slot(alg);
    /* One block: the BCRYPT_HASH_HANDLE, then the hash object CNG works in. */
    struct Block {
        BCRYPT_HASH_HANDLE hh;
        u64 pad; /* keeps obj 16-byte aligned together with hh */
        u8 obj[1];
    };
    size_t total = offsetof(struct Block, obj) + s->object_len;
    struct Block *b = (struct Block *)dk_xmalloc(total);
    NTSTATUS st = BCryptCreateHash(s->h, &b->hh, b->obj, s->object_len, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
    if (st < 0) dk_panic(__FILE__, __LINE__, "BCryptCreateHash failed: 0x%08lx", (unsigned long)st);
    h->h = b;
    h->alg = alg;
}

static BCRYPT_HASH_HANDLE hasher_handle(const DkHasher *h) {
    DK_ASSERT(h->h != NULL);
    return *(BCRYPT_HASH_HANDLE *)h->h;
}

void dk_hasher_update(DkHasher *h, const void *p, size_t n) {
    BCRYPT_HASH_HANDLE hh = hasher_handle(h);
    const u8 *q = (const u8 *)p;
    while (n) {
        size_t k = n < CHUNK_MAX ? n : CHUNK_MAX;
        NTSTATUS st = BCryptHashData(hh, (PUCHAR)q, (ULONG)k, 0);
        if (st < 0) dk_panic(__FILE__, __LINE__, "BCryptHashData failed: 0x%08lx", (unsigned long)st);
        q += k;
        n -= k;
    }
}

void dk_hasher_free(DkHasher *h) {
    if (!h->h) return;
    BCryptDestroyHash(hasher_handle(h));
    dk_xfree(h->h);
    h->h = NULL;
}

void dk_hasher_final(DkHasher *h, u8 *out) {
    BCRYPT_HASH_HANDLE hh = hasher_handle(h);
    NTSTATUS st = BCryptFinishHash(hh, out, (ULONG)dk_hash_len(h->alg), 0);
    if (st < 0) dk_panic(__FILE__, __LINE__, "BCryptFinishHash failed: 0x%08lx", (unsigned long)st);
    dk_hasher_free(h);
}

void dk_hasher_copy(DkHasher *dst, const DkHasher *src) {
    AlgSlot *s = alg_slot(src->alg);
    struct Block {
        BCRYPT_HASH_HANDLE hh;
        u64 pad;
        u8 obj[1];
    };
    size_t total = offsetof(struct Block, obj) + s->object_len;
    struct Block *b = (struct Block *)dk_xmalloc(total);
    NTSTATUS st = BCryptDuplicateHash(hasher_handle(src), &b->hh, b->obj, s->object_len, 0);
    if (st < 0) dk_panic(__FILE__, __LINE__, "BCryptDuplicateHash failed: 0x%08lx", (unsigned long)st);
    dst->h = b;
    dst->alg = src->alg;
}

void dk_hasher_peek(const DkHasher *h, u8 *out) {
    DkHasher tmp;
    dk_hasher_copy(&tmp, h);
    dk_hasher_final(&tmp, out);
}

void dk_hash(DkHashAlg alg, const void *p, size_t n, u8 *out) {
    AlgSlot *s = alg_slot(alg);
    if (n <= CHUNK_MAX) {
        /* BCryptHash needs no hash object: one call, the fast path for the many small digests (cache keys). */
        static const u8 empty = 0;
        NTSTATUS st = BCryptHash(s->h, NULL, 0, (PUCHAR)(n ? p : &empty), (ULONG)n, out, s->digest_len);
        if (st < 0) dk_panic(__FILE__, __LINE__, "BCryptHash failed: 0x%08lx", (unsigned long)st);
        return;
    }
    DkHasher h;
    dk_hasher_init(&h, alg);
    dk_hasher_update(&h, p, n);
    dk_hasher_final(&h, out);
}

void dk_md5(const void *p, size_t n, u8 out[16]) { dk_hash(DK_HASH_MD5, p, n, out); }
void dk_sha1(const void *p, size_t n, u8 out[20]) { dk_hash(DK_HASH_SHA1, p, n, out); }
void dk_sha256(const void *p, size_t n, u8 out[32]) { dk_hash(DK_HASH_SHA256, p, n, out); }
void dk_sha512(const void *p, size_t n, u8 out[64]) { dk_hash(DK_HASH_SHA512, p, n, out); }

/* ---- hex ---------------------------------------------------------------------------------------------------------- */

size_t dk_hex_to(const u8 *p, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[p[i] >> 4];
        out[2 * i + 1] = digits[p[i] & 15];
    }
    out[2 * n] = 0;
    return 2 * n;
}

char *dk_hex(DkArena *a, const u8 *p, size_t n) {
    char *out = (char *)dk_alloc_noz(a, 2 * n + 1);
    dk_hex_to(p, n, out);
    return out;
}

char *dk_hash_hex(DkArena *a, DkHashAlg alg, const void *p, size_t n) {
    u8 d[DK_HASH_MAX_LEN];
    dk_hash(alg, p, n, d);
    return dk_hex(a, d, dk_hash_len(alg));
}
char *dk_md5_hex(DkArena *a, const void *p, size_t n) { return dk_hash_hex(a, DK_HASH_MD5, p, n); }
char *dk_sha1_hex(DkArena *a, const void *p, size_t n) { return dk_hash_hex(a, DK_HASH_SHA1, p, n); }
char *dk_sha256_hex(DkArena *a, const void *p, size_t n) { return dk_hash_hex(a, DK_HASH_SHA256, p, n); }

/* ---- files -------------------------------------------------------------------------------------------------------- */

/* UTF-8 path to a NUL-terminated UTF-16 string on the heap (CreateFileW takes / as well as \). */
static wchar_t *utf8_to_wide(const char *path) {
    int n = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = (wchar_t *)dk_xmalloc((size_t)n * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, path, -1, w, n);
    return w;
}

bool dk_file_digest(DkHashAlg alg, const char *path, u8 *out) {
    wchar_t *w = utf8_to_wide(path);
    if (!w) return false;
    HANDLE f = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    dk_xfree(w);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(f, &size) || size.QuadPart < 0) {
        CloseHandle(f);
        return false;
    }
    if (size.QuadPart == 0) {
        CloseHandle(f);
        dk_hash(alg, NULL, 0, out);
        return true;
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
    dk_hash(alg, v, (size_t)size.QuadPart, out);
    UnmapViewOfFile(v);
    CloseHandle(m);
    CloseHandle(f);
    return true;
}

char *dk_file_digest_hex(DkArena *a, DkHashAlg alg, const char *path) {
    u8 d[DK_HASH_MAX_LEN];
    if (!dk_file_digest(alg, path, d)) return NULL;
    return dk_hex(a, d, dk_hash_len(alg));
}

/* ---- CRC-32 -------------------------------------------------------------------------------------------------------- */

/* CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320), computed bit by bit: it only checksums small cache headers.
 * See: https://en.wikipedia.org/wiki/Cyclic_redundancy_check */
u32 dk_crc32(u32 value, const void *p, size_t n) {
    const u8 *q = (const u8 *)p;
    u32 c = ~value;
    while (n--) {
        c ^= *q++;
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

/* ---- dk_hash64 ----------------------------------------------------------------------------------------------------
 * Folded multiply: mix(a, b) = lo64(a * b) ^ hi64(a * b), the full 128-bit product of two 64-bit values. Each input
 * word is xored with a constant (and the running state) before it is multiplied, so a word of zeros does not erase
 * the state and the constants differ per lane. All loads are little-endian (x64 is, and the code says so). */

static const u64 K0 = 0xa0761d6478bd642full, K1 = 0xe7037ed1a0b428dbull, K2 = 0x8ebc6af09c88c6e3ull,
                 K3 = 0x589965cc75374cc3ull;

static inline u64 mix(u64 a, u64 b) {
    u64 hi;
    u64 lo = _umul128(a, b, &hi);
    return lo ^ hi;
}
static inline u64 rd64(const u8 *p) {
    u64 v;
    memcpy(&v, p, 8);
    return v;
}
static inline u64 rd32(const u8 *p) {
    u32 v;
    memcpy(&v, p, 4);
    return v;
}

u64 dk_hash64(const void *data, size_t n, u64 seed) {
    const u8 *p = (const u8 *)data;
    size_t len = n;
    u64 a, b;
    seed ^= mix(seed ^ K0, K1);
    if (len <= 16) {
        if (len >= 4) {
            /* two overlapping 4-byte reads from each end, shifted to cover 4..16 bytes */
            size_t q = (len >> 3) << 2;
            a = (rd32(p) << 32) | rd32(p + q);
            b = (rd32(p + len - 4) << 32) | rd32(p + len - 4 - q);
        } else if (len > 0) {
            a = ((u64)p[0] << 16) | ((u64)p[len >> 1] << 8) | p[len - 1];
            b = 0;
        } else {
            a = b = 0;
        }
    } else {
        size_t i = len;
        if (i > 48) {
            u64 s1 = seed, s2 = seed;
            do {
                seed = mix(rd64(p) ^ K1, rd64(p + 8) ^ seed);
                s1 = mix(rd64(p + 16) ^ K2, rd64(p + 24) ^ s1);
                s2 = mix(rd64(p + 32) ^ K3, rd64(p + 40) ^ s2);
                p += 48;
                i -= 48;
            } while (i > 48);
            seed ^= s1 ^ s2;
        }
        while (i > 16) {
            seed = mix(rd64(p) ^ K1, rd64(p + 8) ^ seed);
            p += 16;
            i -= 16;
        }
        /* the last 16 bytes of the input, overlapping what the loops took when i < 16 */
        a = rd64(p + i - 16);
        b = rd64(p + i - 8);
    }
    a ^= K1;
    b ^= seed;
    u64 hi;
    u64 lo = _umul128(a, b, &hi);
    return mix(lo ^ K0 ^ (u64)len, hi ^ K1);
}

u64 dk_hash64_str(DkStr s, u64 seed) { return dk_hash64(s.p, s.n, seed); }

u64 dk_hash64_u64(u64 x) {
    /* splitmix64's finaliser: each step is invertible, so the whole is a bijection of u64 */
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ull;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebull;
    x ^= x >> 31;
    return x;
}
