// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Tests of fmt.h against CPython 3.14: the generated corpus in fmt_corpus.h (the generator is in its header
 * comment; the expected values are what CPython printed) plus hand-written cases and randomized cross-checks of
 * the digit generation against the C runtime (round trip through strtod, printf for the fixed modes). */
#include "dk/dk.h"
#include "dk/fmt.h"
#include "dk/test.h"
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

typedef struct {
    u64 bits;
    const char *want;
} ReprCase;
typedef struct {
    const char *fmt;
    char kind; /* F double, I long long, U unsigned long long, S string, f star + double, s star + string */
    u64 bits;
    long long i;
    unsigned long long u;
    const char *s;
    int w, p;
    const char *want;
} PctCase;
typedef struct {
    char kind; /* I, U, F, S */
    long long i;
    unsigned long long u;
    u64 bits;
    const char *s;
    const char *spec;
    const char *want; /* "ValueError: message" when !ok */
    int ok;
} SpecCase;
typedef struct {
    u64 x;
    int n;
    u64 want;
} RoundCase;
typedef struct {
    u64 x;
    i64 want;
} RoundIntCase;
typedef struct {
    i64 a, b, q, r;
} IdivCase;
typedef struct {
    u64 a, b, q, r;
} FdivCase;
typedef struct {
    const char *s;
    size_t n;
    const char *want;
} ReprStrCase;
typedef struct {
    u32 cp;
    int ok;
} PrintableCase;
typedef struct {
    int len;
    u64 sum, start, sum_start;
    int fsum_ok;
    u64 fsum;
} SumCase;
typedef struct {
    const char *parts[8];
    int n;
    const char *list;
    const char *tuple;
} ContCase;
typedef struct {
    const char *parts[8];
    int n;
    const char *want;
} SetCase;
typedef struct {
    const char *keys[4], *vals[4];
    int n;
    const char *want;
} DictCase;

#define R(b, w) {b, w}
#define PF(fmt, b, w) {fmt, 'F', b, 0, 0, NULL, 0, 0, w}
#define PI(fmt, v, w) {fmt, 'I', 0, v, 0, NULL, 0, 0, w}
#define PU(fmt, v, w) {fmt, 'U', 0, 0, v, NULL, 0, 0, w}
#define PS(fmt, str, w) {fmt, 'S', 0, 0, 0, str, 0, 0, w}
#define PFSTAR(fmt, wd, pr, b, w) {fmt, 'f', b, 0, 0, NULL, wd, pr, w}
#define PSSTAR(fmt, wd, pr, str, w) {fmt, 's', 0, 0, 0, str, wd, pr, w}
#define SI(v, spec, w, ok) {'I', v, 0, 0, NULL, spec, w, ok}
#define SU(v, spec, w, ok) {'U', 0, v, 0, NULL, spec, w, ok}
#define SF(b, spec, w, ok) {'F', 0, 0, b, NULL, spec, w, ok}
#define SS(str, spec, w, ok) {'S', 0, 0, 0, str, spec, w, ok}
#define RND(x, n, w) {x, n, w}
#define RI(x, w) {x, w}
#define ID(a, b, q, r) {a, b, q, r}
#define FD(a, b, q, r) {a, b, q, r}
#define RS(lit, w) {lit, sizeof(lit) - 1, w}

#include "fmt_corpus.h"

static double d_of(u64 bits) {
    double d;
    memcpy(&d, &bits, sizeof d);
    return d;
}

static u64 bits_of(double d) {
    u64 b;
    memcpy(&b, &d, sizeof b);
    return b;
}

/* Prints only the first few failures of a corpus loop. */
#define REPORT(counter, ...)                    \
    do {                                        \
        if ((counter)++ < 12) CHECK_MSG(0, __VA_ARGS__); \
        else dk_test__failed_checks += 0;      \
    } while (0)

DK_TEST(float_repr_corpus) {
    int bad = 0;
    for (size_t k = 0; k < DK_ARRAY_LEN(kReprCases); k++) {
        char out[32];
        size_t n = dk_float_repr(d_of(kReprCases[k].bits), out);
        if (strcmp(out, kReprCases[k].want) != 0 || n != strlen(out))
            REPORT(bad, "repr(0x%016llx): got %s want %s", (unsigned long long)kReprCases[k].bits, out, kReprCases[k].want);
    }
    CHECK_EQ_I64(bad, 0);
    CHECK(DK_ARRAY_LEN(kReprCases) > 4000);
}

DK_TEST(float_repr_basics) {
    char out[32];
    dk_float_repr(1e16, out);
    CHECK_CZ(out, "1e+16");
    dk_float_repr(1e15, out);
    CHECK_CZ(out, "1000000000000000.0");
    dk_float_repr(-0.0, out);
    CHECK_CZ(out, "-0.0");
    dk_float_repr(1e-5, out);
    CHECK_CZ(out, "1e-05");
    dk_float_repr(0.0001, out);
    CHECK_CZ(out, "0.0001");
    dk_float_repr(d_of(0xFFF8000000000000ull), out); /* a NaN with the sign bit */
    CHECK_CZ(out, "nan");
    dk_float_repr(-INFINITY, out);
    CHECK_CZ(out, "-inf");
    dk_float_repr(-1.7976931348623157e308, out);
    CHECK_CZ(out, "-1.7976931348623157e+308");
    DkStr s = dk_repr_f64(dk_scratch(), 0.1 + 0.2);
    CHECK_STR(s, "0.30000000000000004");
}

/* The shortest digits must read back as the same double, and mode 2/3 must agree with the C runtime's printf
 * (which is correctly rounded for the digits asked) on random values. */
DK_TEST(float_digits_random_crosscheck) {
    u64 st = 0x9E3779B97F4A7C15ull;
    int bad_rt = 0, bad_p = 0, checked = 0;
    for (int it = 0; it < 150000; it++) {
        st = st * 6364136223846793005ull + 1442695040888963407ull;
        u64 b = st ^ (st >> 29);
        double x = d_of(b);
        if (!isfinite(x)) continue;
        if (it % 3 == 0) x = ldexp((double)(b & 0xFFFFFF) / 1048576.0 + 0.5, (int)((b >> 40) % 80) - 40);
        char out[32];
        dk_float_repr(x, out);
        double back = strtod(out, NULL);
        if (bits_of(back) != bits_of(x)) REPORT(bad_rt, "round trip of %s failed", out);
        int prec = (int)((b >> 20) % 18);
        char dig[DK_DTOA_BUF], want[64], got[64];
        int decpt;
        bool neg;
        dk_dtoa(x, 2, prec + 1, dig, &decpt, &neg);
        snprintf(want, sizeof want, "%.*e", prec, x);
        /* printf: d.ddde+XX */
        int wexp = atoi(strchr(want, 'e') + 1);
        char wd[32];
        size_t k = 0;
        for (const char *q = want; *q && *q != 'e'; q++)
            if (*q >= '0' && *q <= '9') wd[k++] = *q;
        while (k > 1 && wd[k - 1] == '0') k--;
        wd[k] = 0;
        snprintf(got, sizeof got, "%s", dig);
        if (strcmp(wd, got) != 0 || (wexp + 1 != decpt && x != 0.0))
            REPORT(bad_p, "digits of %s at %d: ours %s e%d printf %s e%d", out, prec + 1, got, decpt - 1, wd, wexp);
        checked++;
    }
    CHECK_EQ_I64(bad_rt, 0);
    CHECK_EQ_I64(bad_p, 0);
    CHECK(checked > 100000);
}

static void run_pct(const PctCase *c, DkStr *out) {
    DkArena *a = dk_scratch();
    switch (c->kind) {
    case 'F': *out = dk_pyfmt(a, c->fmt, d_of(c->bits)); break;
    case 'I': *out = dk_pyfmt(a, c->fmt, c->i); break;
    case 'U': *out = dk_pyfmt(a, c->fmt, c->u); break;
    case 'S':
        if (strchr(c->fmt, 'S') || strchr(c->fmt, 'R')) {
            DkStr s = dk_str(c->s);
            *out = dk_pyfmt(a, c->fmt, &s);
        } else {
            *out = dk_pyfmt(a, c->fmt, c->s);
        }
        break;
    case 'f': *out = dk_pyfmt(a, c->fmt, c->w, c->p, d_of(c->bits)); break;
    default: *out = dk_pyfmt(a, c->fmt, c->w, c->p, c->s); break;
    }
}

DK_TEST(pct_corpus) {
    int bad = 0;
    DkArena *a = dk_scratch();
    DkArenaMark m = dk_arena_mark(a);
    for (size_t k = 0; k < DK_ARRAY_LEN(kPctCases); k++) {
        const PctCase *c = &kPctCases[k];
        DkStr got;
        run_pct(c, &got);
        if (!dk_str_eqz(got, c->want)) REPORT(bad, "%s kind %c: got \"%.*s\" want \"%s\"", c->fmt, c->kind, DK_SF(got), c->want);
        dk_arena_reset(a, m);
    }
    CHECK_EQ_I64(bad, 0);
}

DK_TEST(pct_basics) {
    DkArena *a = dk_scratch();
    DkStr s = DK_S("q'");
    CHECK_STR(dk_pyfmt(a, "%d items, %s=%v, %5.1f%%|%-4d|%04x|%R", 3, "pi", 3.14159, 99.55, 7, 255, &s), kMultiWant);
    CHECK_STR(dk_pyfmt(a, "no conversions"), "no conversions");
    CHECK_STR(dk_pyfmt(a, "%S|%10S|%-10S|", &s, &s, &s), "q'|        q'|q'        |");
    CHECK_STR(dk_pyfmt(a, "%s", (const char *)NULL), "None");
    size_t big = 123456789012u;
    CHECK_STR(dk_pyfmt(a, "%d %u %x", big, (unsigned)4000000000u, (short)-3), "123456789012 4000000000 -3");
    CHECK_STR(dk_pyfmt(a, "%lld %ld %hd", 5ll, 6l, 7), "5 6 7");
    DkBuf b = {0};
    dk_buf_pyfmt(&b, "a=%d,", 1);
    dk_buf_pyfmt(&b, "b=%.2f", 2.0);
    CHECK_CZ(dk_buf_cz(&b), "a=1,b=2.00");
    dk_buf_free(&b);
    char many[200];
    DkStr r = dk_pyfmt(a, "%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d", 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6);
    snprintf(many, sizeof many, "%.*s", DK_SF(r));
    CHECK_CZ(many, "1234567890123456");
    /* a result of any size */
    DkStr wide = dk_pyfmt(a, "%100000d", 1);
    CHECK_EQ_U64(wide.n, 100000);
    DkStr huge = dk_pyfmt(a, "%.400f", 1e-5);
    CHECK_EQ_U64(huge.n, 402);
}

DK_TEST(pct_printing) {
    fflush(stdout);
    size_t n = dk_pyprintf("");
    CHECK_EQ_U64(n, 0);
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    char leaf[48];
    snprintf(leaf, sizeof leaf, "dk_fmt_test_%lu.txt", (unsigned long)GetCurrentProcessId());   /* one file per process: parallel runs */
    strcat(path, leaf);
    FILE *f = fopen(path, "wb");
    REQUIRE(f != NULL);
    n = dk_pyfprintf(f, "%5.2f|%s\n", 3.14159, "x");
    fclose(f);
    CHECK_EQ_U64(n, 8);
    f = fopen(path, "rb");
    REQUIRE(f != NULL);
    char buf[32] = {0};
    size_t got = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    remove(path);
    CHECK_EQ_U64(got, 8);
    CHECK_CZ(buf, " 3.14|x\n");
}

/* Splits "ValueError: message" -> message. */
static const char *err_message(const char *want) {
    const char *c = strstr(want, ": ");
    return c ? c + 2 : want;
}

typedef struct {
    bool threw;
    char msg[256];
    DkStr out;
} SpecResult;

static void run_spec(const SpecCase *c, SpecResult *r) {
    DkArena *a = dk_scratch();
    DkTry t;
    r->threw = false;
    r->out = DK_S("");
    if (DK_TRY(&t)) {
        switch (c->kind) {
        case 'I': r->out = dk_format_i64(a, c->i, c->spec); break;
        case 'U': r->out = dk_format_u64(a, c->u, c->spec); break;
        case 'F': r->out = dk_format_f64(a, d_of(c->bits), c->spec); break;
        default: r->out = dk_format_str(a, dk_str(c->s), c->spec); break;
        }
        dk_try_end(&t);
    } else {
        r->threw = true;
        snprintf(r->msg, sizeof r->msg, "%s", t.msg);
    }
}

DK_TEST(format_spec_corpus) {
    int bad = 0;
    DkArena *a = dk_scratch();
    DkArenaMark m = dk_arena_mark(a);
    size_t errors = 0;
    for (size_t k = 0; k < DK_ARRAY_LEN(kSpecCases); k++) {
        const SpecCase *c = &kSpecCases[k];
        SpecResult r;
        run_spec(c, &r);
        if (c->ok) {
            if (r.threw) REPORT(bad, "kind %c spec \"%s\": threw \"%s\", want \"%s\"", c->kind, c->spec, r.msg, c->want);
            else if (!dk_str_eqz(r.out, c->want))
                REPORT(bad, "kind %c spec \"%s\": got \"%.*s\" want \"%s\"", c->kind, c->spec, DK_SF(r.out), c->want);
        } else {
            errors++;
            if (!r.threw) REPORT(bad, "kind %c spec \"%s\": no error, want \"%s\" (got \"%.*s\")", c->kind, c->spec, c->want, DK_SF(r.out));
            else if (strcmp(r.msg, err_message(c->want)) != 0)
                REPORT(bad, "kind %c spec \"%s\": error \"%s\" want \"%s\"", c->kind, c->spec, r.msg, c->want);
        }
        dk_arena_reset(a, m);
    }
    CHECK_EQ_I64(bad, 0);
    CHECK(errors > 100);
}

DK_TEST(format_spec_basics) {
    DkArena *a = dk_scratch();
    CHECK_STR(dk_format_i64(a, 1234567, ","), "1,234,567");
    CHECK_STR(dk_format_i64(a, -255, "#010x"), "-0x00000ff");
    CHECK_STR(dk_format_i64(a, 1234, "08,"), "0,001,234");
    CHECK_STR(dk_format_i64(a, 5, ""), "5");
    CHECK_STR(dk_format_u64(a, 18446744073709551615ull, "x"), "ffffffffffffffff");
    CHECK_STR(dk_format_f64(a, 1e5, ".6"), "1e+05");
    CHECK_STR(dk_format_f64(a, 0.5, ".0%"), "50%");
    CHECK_STR(dk_format_f64(a, 1234.5678, "010,.1f"), "0,001,234.6");
    CHECK_STR(dk_format_str(a, DK_S("h\xc3\xa9llo"), "*^9"), "**h\xc3\xa9llo**");
    CHECK_STR(dk_format_str(a, DK_S("abc"), ".2"), "ab");
    CHECK_STR(dk_format_str(a, DK_S("ab"), "05"), "ab000");
}

DK_TEST(round_corpus) {
    int bad = 0;
    for (size_t k = 0; k < DK_ARRAY_LEN(kRoundCases); k++) {
        const RoundCase *c = &kRoundCases[k];
        double got = dk_py_round(d_of(c->x), c->n);
        if (bits_of(got) != c->want)
            REPORT(bad, "round(0x%016llx, %d): got %.17g want %.17g", (unsigned long long)c->x, c->n, got, d_of(c->want));
    }
    CHECK_EQ_I64(bad, 0);
    for (size_t k = 0; k < DK_ARRAY_LEN(kRoundIntCases); k++) {
        const RoundIntCase *c = &kRoundIntCases[k];
        i64 got = dk_py_round_int(d_of(c->x));
        if (got != c->want) REPORT(bad, "round(%.17g): got %lld want %lld", d_of(c->x), (long long)got, (long long)c->want);
    }
    CHECK_EQ_I64(bad, 0);
    CHECK_EQ_I64(dk_py_round_int(2.5), 2);
    CHECK_EQ_I64(dk_py_round_int(-0.5), 0);
    CHECK_EQ_F64(dk_py_round(2.675, 2), 2.67);
    CHECK(isinf(dk_py_round(INFINITY, 2)));
}

DK_TEST(floor_div_mod) {
    int bad = 0;
    for (size_t k = 0; k < DK_ARRAY_LEN(kIdivCases); k++) {
        const IdivCase *c = &kIdivCases[k];
        i64 q = dk_floordiv_i64(c->a, c->b), r = dk_mod_i64(c->a, c->b);
        if (q != c->q || r != c->r) REPORT(bad, "%lld // %lld: got %lld %lld want %lld %lld", (long long)c->a, (long long)c->b, (long long)q, (long long)r, (long long)c->q, (long long)c->r);
    }
    for (size_t k = 0; k < DK_ARRAY_LEN(kFdivCases); k++) {
        const FdivCase *c = &kFdivCases[k];
        double a = d_of(c->a), b = d_of(c->b);
        u64 q = bits_of(dk_floordiv_f64(a, b)), r = bits_of(dk_floormod_f64(a, b));
        if (q != c->q || r != c->r)
            REPORT(bad, "%.17g // %% %.17g: got %.17g %.17g want %.17g %.17g", a, b, d_of(q), d_of(r), d_of(c->q), d_of(c->r));
    }
    CHECK_EQ_I64(bad, 0);
    DkTry t;
    if (DK_TRY(&t)) {
        dk_floordiv_i64(1, 0);
        dk_try_end(&t);
        CHECK(0);
    } else {
        CHECK_CZ(t.msg, "integer division or modulo by zero");
    }
}

DK_TEST(sums) {
    int bad = 0;
    size_t off = 0;
    for (size_t k = 0; k < DK_ARRAY_LEN(kSumCases); k++) {
        const SumCase *c = &kSumCases[k];
        double v[128];
        REQUIRE((size_t)c->len <= DK_ARRAY_LEN(v));
        for (int i = 0; i < c->len; i++) v[i] = d_of(kSumVals[off + (size_t)i]);
        off += (size_t)c->len;
        u64 s = bits_of(dk_fsum_neumaier(v, (size_t)c->len));
        u64 s2 = bits_of(dk_sum_f64(v, (size_t)c->len, d_of(c->start)));
        if (s != c->sum && !(isnan(d_of(s)) && isnan(d_of(c->sum))))
            REPORT(bad, "sum case %zu: got %.17g want %.17g", k, d_of(s), d_of(c->sum));
        if (s2 != c->sum_start && !(isnan(d_of(s2)) && isnan(d_of(c->sum_start))))
            REPORT(bad, "sum(start) case %zu: got %.17g want %.17g", k, d_of(s2), d_of(c->sum_start));
        DkTry t;
        if (DK_TRY(&t)) {
            u64 f = bits_of(dk_math_fsum(v, (size_t)c->len));
            dk_try_end(&t);
            if (!c->fsum_ok) REPORT(bad, "fsum case %zu: no error", k);
            else if (f != c->fsum && !(isnan(d_of(f)) && isnan(d_of(c->fsum))))
                REPORT(bad, "fsum case %zu: got %.17g want %.17g", k, d_of(f), d_of(c->fsum));
        } else if (c->fsum_ok) {
            REPORT(bad, "fsum case %zu: threw %s", k, t.msg);
        }
    }
    CHECK_EQ_I64(bad, 0);
}

DK_TEST(repr_str_corpus) {
    int bad = 0;
    DkArena *a = dk_scratch();
    DkArenaMark m = dk_arena_mark(a);
    for (size_t k = 0; k < DK_ARRAY_LEN(kReprStrCases); k++) {
        const ReprStrCase *c = &kReprStrCases[k];
        DkStr got = dk_repr_str(a, dk_strn(c->s, c->n));
        if (!dk_str_eqz(got, c->want)) REPORT(bad, "repr case %zu: got %.*s want %s", k, DK_SF(got), c->want);
        dk_arena_reset(a, m);
    }
    CHECK_EQ_I64(bad, 0);
    for (size_t k = 0; k < DK_ARRAY_LEN(kPrintableCases); k++)
        if (dk_cp_isprintable(kPrintableCases[k].cp) != (kPrintableCases[k].ok != 0))
            REPORT(bad, "isprintable(U+%04X) want %d", kPrintableCases[k].cp, kPrintableCases[k].ok);
    CHECK_EQ_I64(bad, 0);
}

DK_TEST(repr_containers) {
    DkArena *a = dk_scratch();
    for (size_t k = 0; k < DK_ARRAY_LEN(kListCases); k++) {
        DkStr parts[8];
        for (int i = 0; i < kListCases[k].n; i++) parts[i] = dk_str(kListCases[k].parts[i]);
        CHECK_STR(dk_repr_list(a, parts, (size_t)kListCases[k].n), kListCases[k].list);
        CHECK_STR(dk_repr_tuple(a, parts, (size_t)kListCases[k].n), kListCases[k].tuple);
    }
    for (size_t k = 0; k < DK_ARRAY_LEN(kSetCases); k++) {
        DkStr parts[8];
        for (int i = 0; i < kSetCases[k].n; i++) parts[i] = dk_str(kSetCases[k].parts[i]);
        CHECK_STR(dk_repr_set(a, parts, (size_t)kSetCases[k].n), kSetCases[k].want);
    }
    for (size_t k = 0; k < DK_ARRAY_LEN(kDictCases); k++) {
        DkStr ks[4], vs[4];
        for (int i = 0; i < kDictCases[k].n; i++) {
            ks[i] = dk_str(kDictCases[k].keys[i]);
            vs[i] = dk_str(kDictCases[k].vals[i]);
        }
        CHECK_STR(dk_repr_dict(a, ks, vs, (size_t)kDictCases[k].n), kDictCases[k].want);
    }
    CHECK_STR(dk_repr_i64(a, -42), "-42");
    CHECK_STR(dk_repr_i64(a, INT64_MIN), "-9223372036854775808");
    CHECK_STR(dk_repr_bool(true), "True");
}

DK_TEST(float_to_string_and_dtoa) {
    DkBuf b = {0};
    dk_float_to_string(&b, 1.5, 'f', 2, DK_DTSF_SIGN);
    dk_buf_putc(&b, '|');
    dk_float_to_string(&b, 100000.0, 'g', 6, DK_DTSF_ALT);
    dk_buf_putc(&b, '|');
    dk_float_to_string(&b, 1e5, 'g', 6, DK_DTSF_ADD_DOT_0);
    dk_buf_putc(&b, '|');
    dk_float_to_string(&b, -0.0001, 'f', 2, DK_DTSF_NO_NEG_0);
    dk_buf_putc(&b, '|');
    dk_float_to_string(&b, -0.0001, 'f', 2, 0);
    dk_buf_putc(&b, '|');
    dk_float_to_string(&b, INFINITY, 'E', 3, DK_DTSF_SIGN);
    dk_buf_putc(&b, '|');
    dk_float_to_string(&b, 12345.678, 'E', 2, 0);
    CHECK_CZ(dk_buf_cz(&b), "+1.50|100000.|1e+05|0.00|-0.00|+INF|1.23E+04");
    dk_buf_free(&b);

    char dig[DK_DTOA_BUF];
    int decpt;
    bool neg;
    CHECK_EQ_U64(dk_dtoa(0.5, 3, 0, dig, &decpt, &neg), 0); /* rounds half to even: no digits */
    CHECK_EQ_I64(decpt, 0);
    CHECK_EQ_U64(dk_dtoa(1.5, 3, 0, dig, &decpt, &neg), 1);
    CHECK_CZ(dig, "2");
    CHECK_EQ_U64(dk_dtoa(-2.5, 3, 0, dig, &decpt, &neg), 1);
    CHECK_CZ(dig, "2");
    CHECK(neg);
    CHECK_EQ_U64(dk_dtoa(0.0, 0, 0, dig, &decpt, &neg), 1);
    CHECK_CZ(dig, "0");
    CHECK_EQ_I64(decpt, 1);
    CHECK_EQ_U64(dk_dtoa(9.5, 2, 1, dig, &decpt, &neg), 1); /* 9.5 to 1 digit carries to 10 */
    CHECK_CZ(dig, "1");
    CHECK_EQ_I64(decpt, 2);
    dk_dtoa(5e-324, 0, 0, dig, &decpt, &neg);
    CHECK_CZ(dig, "5");
    CHECK_EQ_I64(decpt, -323);
    CHECK_EQ_U64(dk_dtoa(5e-324, 2, 800, dig, &decpt, &neg), 751); /* the exact expansion */

    char d[64];
    CHECK_EQ_U64(dk_u64_digits(d, 0, 10, false), 1);
    CHECK_EQ_U64(dk_u64_digits(d, 18446744073709551615ull, 16, true), 16);
    CHECK_MEM(d, "FFFFFFFFFFFFFFFF", 16);
    CHECK_EQ_U64(dk_u64_digits(d, 5, 2, false), 3);
    CHECK_MEM(d, "101", 3);
}

DK_TEST(speed_report) {
    double t0 = dk_process_time();   /* CPU time, not wall: a loaded machine must not fail a speed check */
    u64 st = 12345;
    size_t total = 0;
    for (int i = 0; i < 200000; i++) {
        st = st * 6364136223846793005ull + 1442695040888963407ull;
        double x = d_of(st);
        if (!isfinite(x)) continue;
        char out[32];
        total += dk_float_repr(x, out);
    }
    double ms = (dk_process_time() - t0) * 1000.0;
    printf("float_repr: 200000 random doubles in %.0f ms (%zu chars)\n", ms, total);
    CHECK(ms < 5000);
    t0 = dk_process_time();
    total = 0;
    for (int i = 1; i <= 200000; i++) {
        char out[32];
        total += dk_float_repr(i * 0.37 + 1.0 / i, out);
    }
    ms = (dk_process_time() - t0) * 1000.0;
    printf("float_repr: 200000 typical doubles in %.0f ms (%zu chars)\n", ms, total);
    CHECK(ms < 5000);
}

DK_TEST_MAIN("fmt")
