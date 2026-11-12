// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Float to text as CPython 3.14 (Python/dtoa.c's _Py_dg_dtoa modes 0, 2 and 3, Python/pystrtod.c's format_float_short),
 * with exact big-integer arithmetic instead of David Gay's floating-point tricks: the results are the same digits
 * (shortest round-trip, closest on a tie of lengths; correctly rounded half-even for the fixed modes), so the
 * output does not depend on the C library's printf. */
#include "dk/fmt.h"
#include <float.h>
#include <intrin.h>
#include <math.h>
#include <stdlib.h>

/* ---- unsigned big integers: little-endian 32-bit limbs, no leading zero limb ---- */
#define BN_CAP 100 /* 3200 bits: the largest value is f * 5**1074 (2547 bits) */
typedef struct {
    int n;
    u32 d[BN_CAP];
} Big;

static void bn_from_u64(Big *x, u64 v) {
    x->n = 0;
    if (v) {
        x->d[x->n++] = (u32)v;
        if (v >> 32) x->d[x->n++] = (u32)(v >> 32);
    }
}

static void bn_mul_u32(Big *x, u32 m) {
    u64 carry = 0;
    for (int i = 0; i < x->n; i++) {
        u64 t = (u64)x->d[i] * m + carry;
        x->d[i] = (u32)t;
        carry = t >> 32;
    }
    if (carry) {
        DK_ASSERT(x->n < BN_CAP);
        x->d[x->n++] = (u32)carry;
    }
}

static void bn_shl(Big *x, int bits) {
    if (!x->n || !bits) return;
    int ws = bits >> 5, bs = bits & 31;
    DK_ASSERT(x->n + ws + 1 <= BN_CAP);
    if (bs) {
        u32 carry = 0;
        for (int i = 0; i < x->n; i++) {
            u32 v = x->d[i];
            x->d[i] = (v << bs) | carry;
            carry = v >> (32 - bs);
        }
        if (carry) x->d[x->n++] = carry;
    }
    if (ws) {
        memmove(x->d + ws, x->d, (size_t)x->n * 4);
        memset(x->d, 0, (size_t)ws * 4);
        x->n += ws;
    }
}

static int bn_cmp(const Big *a, const Big *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (int i = a->n - 1; i >= 0; i--)
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    return 0;
}

static void bn_add(Big *r, const Big *a) {
    int n = DK_MAX(r->n, a->n);
    DK_ASSERT(n + 1 <= BN_CAP);
    u64 carry = 0;
    for (int i = 0; i < n; i++) {
        u64 t = carry + (i < r->n ? r->d[i] : 0) + (i < a->n ? a->d[i] : 0);
        r->d[i] = (u32)t;
        carry = t >> 32;
    }
    r->n = n;
    if (carry) r->d[r->n++] = (u32)carry;
}

/* r -= a, r >= a. */
static void bn_sub(Big *r, const Big *a) {
    i64 borrow = 0;
    for (int i = 0; i < r->n; i++) {
        i64 t = (i64)r->d[i] - (i < a->n ? a->d[i] : 0) - borrow;
        borrow = t < 0;
        r->d[i] = (u32)t;
    }
    while (r->n && r->d[r->n - 1] == 0) r->n--;
}

static u32 bn_divmod_u32(Big *x, u32 dv) {
    u64 rem = 0;
    for (int i = x->n - 1; i >= 0; i--) {
        u64 cur = (rem << 32) | x->d[i];
        x->d[i] = (u32)(cur / dv);
        rem = cur % dv;
    }
    while (x->n && x->d[x->n - 1] == 0) x->n--;
    return (u32)rem;
}

static const u32 kPow10[10] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000};

static void bn_mul_pow10(Big *x, int k) {
    for (; k >= 9; k -= 9) bn_mul_u32(x, 1000000000u);
    if (k > 0) bn_mul_u32(x, kPow10[k]);
}

static void bn_mul_pow5(Big *x, int k) {
    for (; k >= 13; k -= 13) bn_mul_u32(x, 1220703125u); /* 5**13 */
    static const u32 p5[13] = {1, 5, 25, 125, 625, 3125, 15625, 78125, 390625, 1953125, 9765625, 48828125, 244140625};
    if (k > 0) bn_mul_u32(x, p5[k]);
}

/* ---- digit generation ---- */

/* Adds the final digit d (0..10; 10 carries into the digits before it) to buf[0..*nd) and fixes *decpt. */
static void put_last_digit(char *buf, size_t *nd, int d, int *decpt) {
    if (d < 10) {
        buf[(*nd)++] = (char)('0' + d);
        return;
    }
    while (*nd > 0 && buf[*nd - 1] == '9') (*nd)--;
    if (*nd == 0) {
        buf[(*nd)++] = '1';
        (*decpt)++;
    } else {
        buf[*nd - 1]++;
    }
}

/* Mode 0: the shortest digit string that reads back as f * 2**e (f a 53-bit integer, or a subnormal's), as Gay's
 * dtoa with ROUND_BIASED undefined: the interval's ends count when the mantissa is even (round-half-even reads
 * them back to x); when the shortest length admits two digits the closer one wins, a tie going to the even digit. */
static size_t dtoa_shortest(u64 f, int e, char *buf, int *decpt) {
    /* Integral values below 2**53 are their own shortest digits (the interval is narrower than 1). */
    if (e < 0 && e > -53 && (f & ((1ull << -e) - 1)) == 0) {
        f >>= -e;
        e = 0;
    }
    if (e >= 0 && e < 11 && (f << e) < (1ull << 53)) {
        u64 v = f << e;
        char tmp[24];
        size_t n = dk_u64_digits(tmp, v, 10, false);
        *decpt = (int)n;
        while (n > 1 && tmp[n - 1] == '0') n--;
        memcpy(buf, tmp, n);
        buf[n] = 0;
        return n;
    }

    Big r, s, mp, mm;
    bool even = !(f & 1);
    bool narrow_low = f == (1ull << 52) && e > -1074; /* the gap below is half the gap above */
    if (e >= 0) {
        if (!narrow_low) {
            bn_from_u64(&r, f);
            bn_shl(&r, e + 1);
            bn_from_u64(&s, 2);
            bn_from_u64(&mp, 1);
            bn_shl(&mp, e);
            mm = mp;
        } else {
            bn_from_u64(&r, f);
            bn_shl(&r, e + 2);
            bn_from_u64(&s, 4);
            bn_from_u64(&mp, 1);
            bn_shl(&mp, e + 1);
            bn_from_u64(&mm, 1);
            bn_shl(&mm, e);
        }
    } else if (!narrow_low) {
        bn_from_u64(&r, f * 2);
        bn_from_u64(&s, 1);
        bn_shl(&s, 1 - e);
        bn_from_u64(&mp, 1);
        mm = mp;
    } else {
        bn_from_u64(&r, f * 4);
        bn_from_u64(&s, 1);
        bn_shl(&s, 2 - e);
        bn_from_u64(&mp, 2);
        bn_from_u64(&mm, 1);
    }

    /* k0 = ceil(log10 x) or one less, never more. */
    unsigned long hi;
    _BitScanReverse64(&hi, f);
    int be = e + (int)hi;
    int k = (int)ceil(be * 0.30102999566398114 - 1e-10);
    if (k >= 0) {
        bn_mul_pow10(&s, k);
    } else {
        bn_mul_pow10(&r, -k);
        bn_mul_pow10(&mp, -k);
        bn_mul_pow10(&mm, -k);
    }
    /* Afterwards r/s = x / 10**k. When the upper end reaches 10**k the digits start at k + 1 with r/s in [1, 10);
     * otherwise scale up by ten so that r/s is in [1, 10). */
    Big t = r;
    bn_add(&t, &mp);
    int c = bn_cmp(&t, &s);
    if (even ? c >= 0 : c > 0) {
        k++;
    } else {
        bn_mul_u32(&r, 10);
        bn_mul_u32(&mp, 10);
        bn_mul_u32(&mm, 10);
    }

    size_t nd = 0;
    for (;;) {
        int d = 0;
        while (bn_cmp(&r, &s) >= 0) {
            bn_sub(&r, &s);
            d++;
        }
        int cl = bn_cmp(&r, &mm);
        bool tc1 = even ? cl <= 0 : cl < 0;
        t = r;
        bn_add(&t, &mp);
        int ch = bn_cmp(&t, &s);
        bool tc2 = even ? ch >= 0 : ch > 0;
        if (!tc1 && !tc2) {
            buf[nd++] = (char)('0' + d);
            bn_mul_u32(&r, 10);
            bn_mul_u32(&mp, 10);
            bn_mul_u32(&mm, 10);
            continue;
        }
        if (tc1 && tc2) {
            Big r2 = r;
            bn_shl(&r2, 1);
            int c2 = bn_cmp(&r2, &s);
            if (c2 > 0 || (c2 == 0 && (d & 1))) d++;
        } else if (tc2) {
            d++;
        }
        put_last_digit(buf, &nd, d, &k);
        break;
    }
    while (nd > 1 && buf[nd - 1] == '0') nd--;
    buf[nd] = 0;
    *decpt = k;
    return nd;
}

/* The exact decimal expansion of f * 2**e (f != 0) without trailing zeros: value = 0.DIGITS * 10**decpt. */
static size_t dtoa_exact(u64 f, int e, char *buf, int *decpt) {
    unsigned long tz;
    _BitScanForward64(&tz, f);
    f >>= tz;
    e += (int)tz;
    Big n;
    bn_from_u64(&n, f);
    int dexp = 0;
    if (e >= 0) {
        bn_shl(&n, e);
    } else {
        bn_mul_pow5(&n, -e); /* 2**e = 5**-e / 10**-e */
        dexp = e;
    }
    u32 chunks[BN_CAP * 10 / 9 + 4];
    int nc = 0;
    while (n.n) chunks[nc++] = bn_divmod_u32(&n, 1000000000u);
    size_t len = 0;
    char tmp[16];
    for (int i = nc - 1; i >= 0; i--) {
        size_t m = dk_u64_digits(tmp, chunks[i], 10, false);
        if (i != nc - 1)
            for (size_t z = m; z < 9; z++) buf[len++] = '0';
        memcpy(buf + len, tmp, m);
        len += m;
    }
    *decpt = (int)len + dexp;
    while (len > 1 && buf[len - 1] == '0') len--;
    buf[len] = 0;
    return len;
}

/* Rounds the digit string ds[0..*len) of 0.DS * 10**decpt to its first pos digits, half to even on the exact value
 * (the string is the exact expansion). pos <= 0 may leave no digits. */
static void round_digits(char *ds, size_t *len, int *decpt, int pos, int empty_decpt) {
    if (pos >= (int)*len) return;
    if (pos < 0) {
        *len = 0;
        *decpt = empty_decpt;
        ds[0] = 0;
        return;
    }
    bool up;
    if (pos == 0) {
        up = ds[0] > '5' || (ds[0] == '5' && *len > 1);
        if (up) {
            ds[0] = '1';
            *len = 1;
            (*decpt)++;
        } else {
            *len = 0;
            *decpt = empty_decpt;
        }
        ds[*len] = 0;
        return;
    }
    char c = ds[pos];
    up = c > '5' || (c == '5' && (*len > (size_t)pos + 1 || ((ds[pos - 1] - '0') & 1)));
    *len = (size_t)pos;
    if (up) {
        int i = pos - 1;
        while (i >= 0 && ds[i] == '9') i--;
        if (i < 0) {
            ds[0] = '1';
            *len = 1;
            (*decpt)++;
        } else {
            ds[i]++;
            *len = (size_t)i + 1;
        }
    }
    while (*len > 1 && ds[*len - 1] == '0') (*len)--;
    ds[*len] = 0;
}

size_t dk_dtoa(double x, int mode, int ndigits, char buf[DK_DTOA_BUF], int *decpt, bool *neg) {
    u64 bits;
    memcpy(&bits, &x, sizeof bits);
    *neg = (bits >> 63) != 0;
    int bexp = (int)((bits >> 52) & 0x7ff);
    u64 frac = bits & ((1ull << 52) - 1);
    DK_ASSERT(bexp != 0x7ff);
    if (bexp == 0 && frac == 0) {
        buf[0] = '0';
        buf[1] = 0;
        *decpt = 1;
        return 1;
    }
    u64 f;
    int e;
    if (bexp == 0) {
        f = frac;
        e = -1074;
    } else {
        f = frac | (1ull << 52);
        e = bexp - 1075;
    }
    if (mode == 0) return dtoa_shortest(f, e, buf, decpt);
    size_t len = dtoa_exact(f, e, buf, decpt);
    if (mode == 2) {
        if (ndigits < 1) ndigits = 1;
        round_digits(buf, &len, decpt, ndigits, 0);
    } else {
        DK_ASSERT(mode == 3);
        round_digits(buf, &len, decpt, *decpt + ndigits, -ndigits);
    }
    return len;
}

size_t dk_u64_digits(char *out, u64 v, int base, bool upper) {
    const char *alpha = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[64];
    size_t n = 0;
    do {
        tmp[n++] = alpha[v % (u64)base];
        v /= (u64)base;
    } while (v);
    for (size_t i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    return n;
}

/* ---- output sink: a fixed buffer or an DkBuf ---- */
typedef struct {
    char *p;
    size_t n, cap;
    DkBuf *b;
} Sink;

static void sk_putn(Sink *s, const char *src, size_t n) {
    if (s->b) {
        dk_buf_putn(s->b, src, n);
    } else {
        DK_ASSERT(s->n + n < s->cap);
        memcpy(s->p + s->n, src, n);
    }
    s->n += n;
}

static void sk_putc(Sink *s, char c) { sk_putn(s, &c, 1); }

static void sk_zeros(Sink *s, int n) {
    static const char z[33] = "00000000000000000000000000000000";
    while (n > 0) {
        int k = n < 32 ? n : 32;
        sk_putn(s, z, (size_t)k);
        n -= k;
    }
}

/* Python/pystrtod.c format_float_short. Writes the unsigned text of |x| (finite) and returns whether the sign bit
 * was set and the result is not rounded to zero under NO_NEG_0. */
static void format_short(Sink *sk, double x, char type, int precision, int flags, bool *neg_out) {
    char lc = (char)(type | 0x20);
    int mode, prec = precision;
    bool alt = (flags & DK_DTSF_ALT) != 0;
    bool add_dot_0 = (flags & DK_DTSF_ADD_DOT_0) != 0;
    if (prec < 0 && lc != 'r') prec = 6;
    switch (lc) {
    case 'e': mode = 2; prec++; break;
    case 'f': mode = 3; break;
    case 'g': mode = 2; if (prec == 0) prec = 1; break;
    case 'r': mode = 0; break;
    default: dk_panic(__FILE__, __LINE__, "dk_float_to_string: bad type '%c'", type);
    }
    char dig[DK_DTOA_BUF];
    int decpt;
    bool neg;
    size_t nd = dk_dtoa(x, mode, prec, dig, &decpt, &neg);
    if ((flags & DK_DTSF_NO_NEG_0) && neg) {
        bool zero = true;
        for (size_t i = 0; i < nd; i++)
            if (dig[i] != '0') zero = false;
        if (zero) neg = false;
    }
    *neg_out = neg;

    bool use_exp = false;
    int vend = (int)nd;
    switch (lc) {
    case 'e': use_exp = true; vend = prec; break;
    case 'f': vend = decpt + prec; break;
    case 'g':
        if (decpt <= -4 || decpt > (add_dot_0 ? prec - 1 : prec)) use_exp = true;
        if (alt) vend = prec;
        break;
    default: /* r */
        if (decpt <= -4 || decpt > 16) use_exp = true;
        break;
    }
    int exp10 = 0;
    if (use_exp) {
        exp10 = decpt - 1;
        decpt = 1;
    }
    int vstart = decpt <= 0 ? decpt - 1 : 0;
    if (!use_exp && add_dot_0) vend = vend > decpt ? vend : decpt + 1;
    else vend = vend > decpt ? vend : decpt;

    size_t start = sk->n;
    if (decpt <= 0) {
        sk_zeros(sk, decpt - vstart);
        sk_putc(sk, '.');
        sk_zeros(sk, -decpt);
    } else {
        sk_zeros(sk, -vstart);
    }
    if (0 < decpt && decpt <= (int)nd) {
        sk_putn(sk, dig, (size_t)decpt);
        sk_putc(sk, '.');
        sk_putn(sk, dig + decpt, nd - (size_t)decpt);
    } else {
        sk_putn(sk, dig, nd);
    }
    if ((int)nd < decpt) {
        sk_zeros(sk, decpt - (int)nd);
        sk_putc(sk, '.');
        sk_zeros(sk, vend - decpt);
    } else {
        sk_zeros(sk, vend - (int)nd);
    }
    /* Delete a trailing decimal point unless the alternative form asks for it. */
    if (sk->n > start) {
        char last = sk->b ? sk->b->p[sk->b->n - 1] : sk->p[sk->n - 1];
        if (last == '.' && !alt) {
            sk->n--;
            if (sk->b) {
                sk->b->n--;
                sk->b->p[sk->b->n] = 0;
            }
        }
    }
    if (use_exp) {
        char eb[16];
        int len = snprintf(eb, sizeof eb, "%c%+.02d", (type & 0x20) ? 'e' : 'E', exp10);
        sk_putn(sk, eb, (size_t)len);
    }
}

/* Writes sign and text of any double through the sink. */
static void double_to_sink(Sink *sk, double x, char type, int precision, int flags) {
    bool upper = type >= 'A' && type <= 'Z';
    u64 bits;
    memcpy(&bits, &x, sizeof bits);
    bool sign = (bits >> 63) != 0;
    if (!isfinite(x)) {
        bool nan = isnan(x);
        if (nan) sign = false; /* Python never prints the sign of a NaN */
        if (sign) sk_putc(sk, '-');
        else if (flags & DK_DTSF_SIGN) sk_putc(sk, '+');
        const char *t = nan ? (upper ? "NAN" : "nan") : (upper ? "INF" : "inf");
        sk_putn(sk, t, 3);
        return;
    }
    size_t at = sk->n;
    size_t bat = sk->b ? sk->b->n : 0;
    sk_putc(sk, '+'); /* placeholder for the sign, replaced below */
    bool neg;
    format_short(sk, x, type, precision, flags, &neg);
    char sc = neg ? '-' : ((flags & DK_DTSF_SIGN) ? '+' : 0);
    if (sk->b) {
        if (sc) {
            sk->b->p[bat] = sc;
        } else {
            memmove(sk->b->p + bat, sk->b->p + bat + 1, sk->b->n - bat - 1);
            sk->b->n--;
            sk->b->p[sk->b->n] = 0;
            sk->n--;
        }
    } else {
        if (sc) {
            sk->p[at] = sc;
        } else {
            memmove(sk->p + at, sk->p + at + 1, sk->n - at - 1);
            sk->n--;
        }
    }
}

void dk_float_to_string(DkBuf *b, double x, char type, int precision, int flags) {
    Sink sk = {NULL, 0, 0, b};
    double_to_sink(&sk, x, type, precision, flags);
}

size_t dk_float_repr(double x, char out[32]) {
    Sink sk = {out, 0, 31, NULL};
    double_to_sink(&sk, x, 'r', 0, DK_DTSF_ADD_DOT_0);
    out[sk.n] = 0;
    return sk.n;
}

DkStr dk_repr_f64(DkArena *a, double x) {
    char tmp[32];
    size_t n = dk_float_repr(x, tmp);
    return dk_str_dup(a, dk_strn(tmp, n));
}

/* ---- round() ---- */

double dk_py_round(double x, int ndigits) {
    /* Python/floatobject.c double_round: NDIGITS_MAX and NDIGITS_MIN come from (DBL_MANT_DIG - DBL_MIN_EXP) and
     * (DBL_MIN_EXP - DBL_MANT_DIG - 1) times 0.30103. */
    if (!isfinite(x)) return x;
    if (ndigits > 323) return x;
    if (ndigits < -323) return 0.0 * x;
    char dig[DK_DTOA_BUF];
    char str[DK_DTOA_BUF + 40];
    int decpt;
    bool neg;
    size_t nd = dk_dtoa(x, 3, ndigits, dig, &decpt, &neg);
    snprintf(str, sizeof str, "%s0%se%d", neg ? "-" : "", dig, decpt - (int)nd);
    return strtod(str, NULL);
}

i64 dk_py_round_int(double x) {
    double r = nearbyint(x); /* the default rounding mode is round-half-even */
    if (r >= 9223372036854775807.0) return INT64_MAX;
    if (r <= -9223372036854775808.0) return INT64_MIN;
    return (i64)r;
}
