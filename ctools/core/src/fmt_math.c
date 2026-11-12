// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Python's integer and float arithmetic whose results reach the output: // and % (floor semantics), the built-in
 * sum() over floats (Python/bltinmodule.c, Neumaier compensation since 3.12) and math.fsum (Modules/mathmodule.c,
 * Shewchuk's exact partials with the half-even fix-up). */
#include "dk/fmt.h"
#include <math.h>
#include <float.h>

i64 dk_floordiv_i64(i64 a, i64 b) {
    if (b == 0) dk_throw(DK_ERR_OTHER, "integer division or modulo by zero");
    if (a == INT64_MIN && b == -1) return INT64_MAX; /* 2**63 does not fit */
    i64 q = a / b;
    if ((a % b != 0) && ((a < 0) != (b < 0))) q--;
    return q;
}

i64 dk_mod_i64(i64 a, i64 b) {
    if (b == 0) dk_throw(DK_ERR_OTHER, "integer division or modulo by zero");
    if (b == -1) return 0;
    i64 r = a % b;
    if (r != 0 && ((r < 0) != (b < 0))) r += b;
    return r;
}

/* Objects/floatobject.c float_rem */
double dk_floormod_f64(double a, double b) {
    if (b == 0.0) dk_throw(DK_ERR_OTHER, "float modulo by zero");
    double mod = fmod(a, b);
    if (mod) {
        if ((b < 0) != (mod < 0)) mod += b;
    } else {
        mod = copysign(0.0, b);
    }
    return mod;
}

/* Objects/floatobject.c float_divmod, the quotient */
double dk_floordiv_f64(double a, double b) {
    if (b == 0.0) dk_throw(DK_ERR_OTHER, "float floor division by zero");
    double mod = fmod(a, b);
    double div = (a - mod) / b;
    if (mod) {
        if ((b < 0) != (mod < 0)) div -= 1.0;
    }
    double fd;
    if (div) {
        fd = floor(div);
        if (div - fd > 0.5) fd += 1.0;
    } else {
        fd = copysign(0.0, a / b);
    }
    return fd;
}

double dk_sum_f64(const double *v, size_t n, double start) {
    double f = start, c = 0.0;
    for (size_t i = 0; i < n; i++) {
        double x = v[i];
        double t = f + x;
        if (fabs(f) >= fabs(x)) c += (f - t) + x;
        else c += (x - t) + f;
        f = t;
    }
    if (c && isfinite(c)) f += c;
    return f;
}

double dk_fsum_neumaier(const double *v, size_t n) {
    if (n == 0) return 0.0;
    /* The int 0 start plus the first float is the float 0.0 + v[0] (so -0.0 becomes 0.0). */
    return dk_sum_f64(v + 1, n - 1, 0.0 + v[0]);
}

double dk_math_fsum(const double *v, size_t n) {
    double ps[32], *p = ps;
    size_t m = 32, cnt = 0;
    double special_sum = 0.0, inf_sum = 0.0;
    double x, y, t, hi, yr, lo = 0.0;
    for (size_t k = 0; k < n; k++) {
        x = v[k];
        double xsave = x;
        size_t i = 0;
        for (size_t j = 0; j < cnt; j++) {
            y = p[j];
            if (fabs(x) < fabs(y)) {
                t = x;
                x = y;
                y = t;
            }
            hi = x + y;
            yr = hi - x;
            lo = y - yr;
            if (lo != 0.0) p[i++] = lo;
            x = hi;
        }
        cnt = i;
        if (x != 0.0) {
            if (!isfinite(x)) {
                /* A nonfinite x is either an intermediate overflow or a nan/inf among the summands. */
                if (isfinite(xsave)) {
                    if (p != ps) dk_xfree(p);
                    dk_throw(DK_ERR_OTHER, "intermediate overflow in fsum");
                }
                if (isinf(xsave)) inf_sum += xsave;
                special_sum += xsave;
                cnt = 0;
            } else {
                if (cnt >= m) {
                    m *= 2;
                    if (p == ps) {
                        p = dk_xmalloc(m * sizeof(double));
                        memcpy(p, ps, cnt * sizeof(double));
                    } else {
                        p = dk_xrealloc(p, m * sizeof(double));
                    }
                }
                p[cnt++] = x;
            }
        }
    }
    if (special_sum != 0.0) {
        if (p != ps) dk_xfree(p);
        if (isnan(inf_sum)) dk_throw(DK_ERR_OTHER, "-inf + inf in fsum");
        return special_sum;
    }
    hi = 0.0;
    if (cnt > 0) {
        hi = p[--cnt];
        /* sum_exact from the top, stopping when the sum becomes inexact. */
        while (cnt > 0) {
            x = hi;
            y = p[--cnt];
            hi = x + y;
            yr = hi - x;
            lo = y - yr;
            if (lo != 0.0) break;
        }
        /* Half-even rounding across several partials: a lone 1-ulp error is fixed up (sum([1e-16, 1, 1e16])). */
        if (cnt > 0 && ((lo < 0.0 && p[cnt - 1] < 0.0) || (lo > 0.0 && p[cnt - 1] > 0.0))) {
            y = lo * 2.0;
            x = hi + y;
            yr = x - hi;
            if (y == yr) hi = x;
        }
    }
    if (p != ps) dk_xfree(p);
    return hi;
}

/* Modules/mathmodule.c math.hypot / vector_norm (CPython 3.12+): the scaled, error-free-transformation sum of squares
 * with a differential correction. It differs from the C library's hypot in the last bit for some inputs, so the tools
 * that print math.hypot / math.dist results use this one. */
typedef struct {
    double hi, lo;
} HypotDL;

static HypotDL hypot_fast_sum(double a, double b) {
    double x = a + b;
    double y = (a - x) + b;
    HypotDL r = {x, y};
    return r;
}
static HypotDL hypot_mul(double x, double y) {
    double z = x * y;
    double zz = fma(x, y, -z);
    HypotDL r = {z, zz};
    return r;
}

static double hypot_norm(size_t n, double *vec, double max, bool found_nan) {
    if (isinf(max)) return max;
    if (found_nan) return NAN;
    if (max == 0.0 || n <= 1) return max;
    int max_e;
    frexp(max, &max_e);
    if (max_e < -1023) {
        /* ldexp(1.0, -max_e) would overflow: scale subnormals up to normals first */
        for (size_t i = 0; i < n; i++) vec[i] /= DBL_MIN;
        return DBL_MIN * hypot_norm(n, vec, max / DBL_MIN, found_nan);
    }
    double scale = ldexp(1.0, -max_e);
    double csum = 1.0, frac1 = 0.0, frac2 = 0.0;
    for (size_t i = 0; i < n; i++) {
        double x = vec[i] * scale; /* lossless scaling */
        HypotDL pr = hypot_mul(x, x);
        HypotDL sm = hypot_fast_sum(csum, pr.hi);
        csum = sm.hi;
        frac1 += pr.lo;
        frac2 += sm.lo;
    }
    double h = sqrt(csum - 1.0 + (frac1 + frac2));
    HypotDL pr = hypot_mul(-h, h);
    HypotDL sm = hypot_fast_sum(csum, pr.hi);
    csum = sm.hi;
    frac1 += pr.lo;
    frac2 += sm.lo;
    double x = csum - 1.0 + (frac1 + frac2);
    h += x / (2.0 * h); /* differential correction */
    return h / scale;
}

double dk_math_hypot(const double *v, size_t n) {
    double stack[16];
    double *c = n <= 16 ? stack : (double *)dk_xmalloc(n * sizeof(double));
    double max = 0.0;
    bool found_nan = false;
    for (size_t i = 0; i < n; i++) {
        double x = fabs(v[i]);
        c[i] = x;
        found_nan |= isnan(x);
        if (x > max) max = x;
    }
    double r = hypot_norm(n, c, max, found_nan);
    if (c != stack) dk_xfree(c);
    return r;
}
