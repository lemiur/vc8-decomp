// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The coefficients of the linear forms.
 *
 * Coefficients are unbounded integers and are never reduced (scale and add keep v * k and sums as they come), so
 * a chain such as shl eax, 8 repeated nine times builds a coefficient beyond 64 bits that is printed and compared as
 * it is. A coefficient is an Ex int: a plain 64-bit value (fast path), a u64 above INT64_MAX, or (beyond both) a
 * "huge" int that carries its decimal text. The arithmetic here is exact for the sizes that can occur (up to 1536
 * bits; a result beyond that stops with an internal error). */
#include "eq2_internal.h"
#include <intrin.h>

#define BIG_LIMBS 48

typedef struct Big {
    bool neg;
    u32 n;               /* limbs used (no leading zero limbs; 0 has n == 0) */
    u32 d[BIG_LIMBS];    /* magnitude, least significant first */
} Big;

static void big_trim(Big *b) {
    while (b->n && !b->d[b->n - 1]) b->n--;
    if (!b->n) b->neg = false;
}

static void big_from_u64(Big *b, u64 v, bool neg) {
    memset(b, 0, sizeof *b);
    b->d[0] = (u32)v;
    b->d[1] = (u32)(v >> 32);
    b->n = 2;
    b->neg = neg;
    big_trim(b);
}

static void big_from_ex(Big *b, const Ex *e) {
    if (e->s) {   /* huge: decimal text */
        memset(b, 0, sizeof *b);
        const char *p = e->s;
        bool neg = *p == '-';
        if (neg) p++;
        for (; *p; p++) {
            u64 carry = (u64)(*p - '0');
            for (u32 i = 0; i < b->n; i++) {
                u64 t = (u64)b->d[i] * 10 + carry;
                b->d[i] = (u32)t;
                carry = t >> 32;
            }
            if (carry) {
                DK_ASSERT(b->n < BIG_LIMBS);
                b->d[b->n++] = (u32)carry;
            }
        }
        b->neg = neg;
        big_trim(b);
        return;
    }
    if (e->big) big_from_u64(b, (u64)e->i, false);
    else if (e->i < 0) big_from_u64(b, (u64)0 - (u64)e->i, true);
    else big_from_u64(b, (u64)e->i, false);
}

static int mag_cmp(const Big *a, const Big *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (u32 i = a->n; i-- > 0;)
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    return 0;
}

static void mag_add(Big *r, const Big *a, const Big *b) {
    u32 n = DK_MAX(a->n, b->n);
    u64 carry = 0;
    Big t;
    memset(&t, 0, sizeof t);
    for (u32 i = 0; i < n; i++) {
        u64 s = carry + (i < a->n ? a->d[i] : 0) + (i < b->n ? b->d[i] : 0);
        t.d[i] = (u32)s;
        carry = s >> 32;
    }
    t.n = n;
    if (carry) {
        DK_ASSERT(n < BIG_LIMBS);
        t.d[t.n++] = (u32)carry;
    }
    t.neg = false;
    *r = t;
}

static void mag_sub(Big *r, const Big *a, const Big *b) {   /* |a| >= |b| */
    Big t;
    memset(&t, 0, sizeof t);
    i64 borrow = 0;
    for (u32 i = 0; i < a->n; i++) {
        i64 s = (i64)a->d[i] - (i < b->n ? (i64)b->d[i] : 0) - borrow;
        borrow = s < 0;
        if (s < 0) s += (i64)1 << 32;
        t.d[i] = (u32)s;
    }
    t.n = a->n;
    big_trim(&t);
    *r = t;
}

static void big_add(Big *r, const Big *a, const Big *b) {
    Big t;
    if (a->neg == b->neg) {
        mag_add(&t, a, b);
        t.neg = a->neg;
    } else if (mag_cmp(a, b) >= 0) {
        mag_sub(&t, a, b);
        t.neg = a->neg;
    } else {
        mag_sub(&t, b, a);
        t.neg = b->neg;
    }
    big_trim(&t);
    *r = t;
}

static void big_mul(Big *r, const Big *a, const Big *b) {
    Big t;
    memset(&t, 0, sizeof t);
    if (a->n && b->n) {
        DK_ASSERT(a->n + b->n <= BIG_LIMBS);
        for (u32 i = 0; i < a->n; i++) {
            u64 carry = 0;
            for (u32 j = 0; j < b->n; j++) {
                u64 cur = (u64)t.d[i + j] + (u64)a->d[i] * b->d[j] + carry;
                t.d[i + j] = (u32)cur;
                carry = cur >> 32;
            }
            t.d[i + b->n] += (u32)carry;
        }
        t.n = a->n + b->n;
        t.neg = a->neg != b->neg;
        big_trim(&t);
    }
    *r = t;
}

/* The Ex int of a Big: plain i64, u64 above INT64_MAX, or a huge int with its decimal text. */
static Ex *big_to_ex(const Big *b) {
    if (b->n <= 2) {
        u64 mag = b->n ? ((u64)b->d[0] | ((b->n > 1 ? (u64)b->d[1] : 0) << 32)) : 0;
        if (!b->neg) return mag <= (u64)INT64_MAX ? ex_int((i64)mag) : ex_uint(mag);
        if (mag <= (u64)INT64_MAX + 1) return ex_int((i64)((u64)0 - mag));
    }
    Big t = *b;
    char rev[BIG_LIMBS * 10 + 4];
    size_t k = 0;
    while (t.n) {   /* divide by 10**9 */
        u64 rem = 0;
        for (u32 i = t.n; i-- > 0;) {
            u64 cur = (rem << 32) | t.d[i];
            t.d[i] = (u32)(cur / 1000000000u);
            rem = cur % 1000000000u;
        }
        big_trim(&t);
        for (int j = 0; j < 9; j++) {
            rev[k++] = (char)('0' + rem % 10);
            rem /= 10;
        }
    }
    while (k > 1 && rev[k - 1] == '0') k--;
    char txt[BIG_LIMBS * 10 + 4];
    size_t o = 0;
    if (b->neg) txt[o++] = '-';
    while (k) txt[o++] = rev[--k];
    txt[o] = 0;
    return ex_int_text(txt);
}

static bool plain(const Ex *e) { return !e->big && !e->s; }

Ex *eq2_coef_add(Ex *a, Ex *b) {
    if (plain(a) && plain(b)) {
        i64 x = a->i, y = b->i;
        if (!((y > 0 && x > INT64_MAX - y) || (y < 0 && x < INT64_MIN - y))) return ex_int(x + y);
    }
    Big x, y, r;
    big_from_ex(&x, a);
    big_from_ex(&y, b);
    big_add(&r, &x, &y);
    return big_to_ex(&r);
}

Ex *eq2_coef_mul(Ex *a, Ex *b) {
    if (plain(a) && plain(b)) {
        i64 hi;
        i64 lo = _mul128(a->i, b->i, &hi);
        if (hi == (lo >> 63)) return ex_int(lo);
    }
    Big x, y, r;
    big_from_ex(&x, a);
    big_from_ex(&y, b);
    big_mul(&r, &x, &y);
    return big_to_ex(&r);
}

/* The value modulo 2**64 (two's complement), which is all the 32-bit constants of mklin need. */
u64 eq2_coef_lo64(const Ex *a) {
    if (plain(a) || a->big) return (u64)a->i;
    Big x;
    big_from_ex(&x, a);
    u64 lo = (x.n ? x.d[0] : 0) | ((u64)(x.n > 1 ? x.d[1] : 0) << 32);
    return x.neg ? (u64)0 - lo : lo;
}
