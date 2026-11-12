// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* args.h: hand-written cases for the parser API, its error and help texts (the expected strings are what
 * CPython 3.14.8 argparse prints for the same definitions). */
#include "dk/args.h"
#include "dk/dk.h"
#include "dk/test.h"

#include "../src/args_internal.h"

#include <math.h>
#include <stdlib.h>

static void set_columns(int w) {
    char b[16];
    snprintf(b, sizeof b, "%d", w);
    _putenv_s("COLUMNS", b);
}

/* ---- API behaviour ---------------------------------------------------------------------------------------------- */
DK_TEST(accessors_and_given) {
    set_columns(80);
    DkArgParser *p = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "demo.py"});
    dk_arg(p, &(DkArgDesc){.names = "-j --jobs", .type = DK_T_INT, .dflt = DK_DEF_INT(4), .metavar = "N"});
    dk_arg(p, &(DkArgDesc){.names = "--name"});
    dk_arg(p, &(DkArgDesc){.names = "--ratio", .type = DK_T_FLOAT, .dflt = DK_DEF_FLOAT(0.5)});
    dk_arg(p, &(DkArgDesc){.names = "-q", .action = DK_ARG_STORE_TRUE});
    dk_arg(p, &(DkArgDesc){.names = "-v", .action = DK_ARG_COUNT});
    dk_arg(p, &(DkArgDesc){.names = "units", .nargs = DK_NARGS_STAR});
    DkStr argv[] = {DK_S("-j8"), DK_S("-qvv"), DK_S("a"), DK_S("b")};
    DkArgsExit ex;
    DkArgs *r = dk_args_try_parse(p, argv, 4, false, &ex);
    if (!r) fprintf(stderr, "exit %d: %.*s%.*s", ex.code, DK_SF(ex.out), DK_SF(ex.err));
    REQUIRE(r != NULL);
    CHECK_EQ_I64(dk_args_int(r, "jobs"), 8);
    CHECK(dk_args_given(r, "jobs"));
    CHECK(dk_args_is_none(r, "name"));
    CHECK(!dk_args_given(r, "name"));
    CHECK_EQ_F64(dk_args_float(r, "ratio"), 0.5);
    CHECK(!dk_args_given(r, "ratio"));
    CHECK(dk_args_bool(r, "q"));
    CHECK_EQ_I64(dk_args_int(r, "v"), 2);
    DkStrVec units = dk_args_strs(r, "units");
    REQUIRE(units.n == 2);
    CHECK_STR(units.v[0], "a");
    CHECK_STR(units.v[1], "b");
    dk_vec_free(&units);
    CHECK(dk_args_str(r, "name").p == NULL);
}

DK_TEST(error_text_and_exit) {
    set_columns(80);
    DkArgParser *p = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "demo.py"});
    dk_arg(p, &(DkArgDesc){.names = "--build", .choices = (const char *const[]){"x86", "i386", NULL}});
    DkStr argv[] = {DK_S("--build"), DK_S("ppc")};
    DkArgsExit ex;
    DkArgs *r = dk_args_try_parse(p, argv, 2, false, &ex);
    CHECK(r == NULL);
    CHECK_EQ_I64(ex.code, 2);
    CHECK_STR(ex.err, "usage: demo.py [-h] [--build {x86,i386}]\n"
                      "demo.py: error: argument --build: invalid choice: 'ppc' (choose from 'x86', 'i386')\n");
    DkStr h[] = {DK_S("-h")};
    r = dk_args_try_parse(p, h, 1, false, &ex);
    CHECK(r == NULL);
    CHECK_EQ_I64(ex.code, 0);
    CHECK_STR(ex.out, "usage: demo.py [-h] [--build {x86,i386}]\n\noptions:\n  -h, --help          show this help message and exit\n  --build {x86,i386}\n");
    CHECK_STR(dk_args_error_text(p, DK_S("custom")), "usage: demo.py [-h] [--build {x86,i386}]\ndemo.py: error: custom\n");
}

static bool even_conv(void *ctx, DkArena *a, DkStr in, DkArgValue *out, DkStr *msg) {
    DK_UNUSED(ctx);
    DK_UNUSED(a);
    i64 v;
    if (!dk_parse_int(in, 10, &v, NULL)) return false;
    if (v % 2) {
        *msg = DK_S("must be even");
        return false;
    }
    out->kind = DK_V_INT;
    out->i = v;
    return true;
}

DK_TEST(custom_type_converter) {
    set_columns(80);
    DkArgParser *p = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "demo.py"});
    dk_arg(p, &(DkArgDesc){.names = "--n", .type = DK_T_CUSTOM, .type_name = "even", .conv = even_conv});
    DkArgsExit ex;
    DkStr ok[] = {DK_S("--n"), DK_S("4")};
    DkArgs *r = dk_args_try_parse(p, ok, 2, false, &ex);
    REQUIRE(r != NULL);
    CHECK_EQ_I64(dk_args_int(r, "n"), 4);
    DkStr odd[] = {DK_S("--n=3")};
    CHECK(dk_args_try_parse(p, odd, 1, false, &ex) == NULL);
    CHECK_STR(ex.err, "usage: demo.py [-h] [--n N]\ndemo.py: error: argument --n: must be even\n");
    DkStr bad[] = {DK_S("--n"), DK_S("x")};
    CHECK(dk_args_try_parse(p, bad, 2, false, &ex) == NULL);
    CHECK_STR(ex.err, "usage: demo.py [-h] [--n N]\ndemo.py: error: argument --n: invalid even value: 'x'\n");
}

DK_TEST(width_from_columns) {
    set_columns(100);
    CHECK_EQ_I64(dk_args_width(), 98); /* shutil.get_terminal_size().columns - 2 */
    _putenv_s("COLUMNS", " 60 ");
    CHECK_EQ_I64(dk_args_width(), 58); /* int(" 60 ") is 60 */
    set_columns(80);
    CHECK_EQ_I64(dk_args_width(), 78);
}

DK_TEST(huge_int_is_rejected) {
    /* Python's int is unbounded; this port's is 64-bit, so a value that does not fit is "invalid int value" */
    set_columns(80);
    DkArgParser *p = dk_args_parser(NULL, &(DkArgParserDesc){.prog = "demo.py"});
    dk_arg(p, &(DkArgDesc){.names = "--n", .type = DK_T_INT});
    DkStr big[] = {DK_S("--n"), DK_S("99999999999999999999")};
    DkArgsExit ex;
    CHECK(dk_args_try_parse(p, big, 2, false, &ex) == NULL);
    CHECK_STR(ex.err, "usage: demo.py [-h] [--n N]\ndemo.py: error: argument --n: invalid int value: '99999999999999999999'\n");
}

/* python -c "print(repr(x))" for each value (the %(default)s of a float default in help texts) */
DK_TEST(float_repr) {
    static const struct {
        double x;
        const char *repr;
    } cases[] = {
    {0.0, "0.0"},
    {-0.0, "-0.0"},
    {1.0, "1.0"},
    {0.1, "0.1"},
    {0.25, "0.25"},
    {1e+16, "1e+16"},
    {1000000000000000.0, "1000000000000000.0"},
    {123456789012345.6, "123456789012345.6"},
    {1e-05, "1e-05"},
    {0.0001, "0.0001"},
    {1.234e-05, "1.234e-05"},
    {5e-324, "5e-324"},
    {1.7976931348623157e+308, "1.7976931348623157e+308"},
    {0.3333333333333333, "0.3333333333333333"},
    {100.0, "100.0"},
    {2.5e-07, "2.5e-07"},
    {1.2345678901234567e+19, "1.2345678901234567e+19"},
    {0.5, "0.5"},
    {-2.5, "-2.5"},
    {1e+22, "1e+22"},
    {1e+23, "1e+23"},
    {1e+23, "1e+23"},
    {INFINITY, "inf"},
    {-INFINITY, "-inf"},
    {3.141592653589793, "3.141592653589793"},
    {9007199254740992.0, "9007199254740992.0"},
    {1234567890123456.0, "1234567890123456.0"},
    {1.2345678901234568e+16, "1.2345678901234568e+16"},
    {0.001, "0.001"},
    {1.5e+300, "1.5e+300"},
    {4.35, "4.35"},
    {0.3, "0.3"}
    };
    for (size_t i = 0; i < DK_ARRAY_LEN(cases); i++) {
        DkBuf b;
        dk_buf_init(&b, NULL);
        argp_float_repr(&b, cases[i].x);
        CHECK_CZ(dk_buf_cz(&b), cases[i].repr);
        dk_buf_free(&b);
    }
}

DK_TEST_MAIN("args")
