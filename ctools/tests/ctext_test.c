// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* ctext: register names and the statement helpers, on hand-written statements. */
#include "ctext.h"
#include "dk/dk.h"
#include "dk/test.h"

#include <string.h>

static bool has(const DkSet *s, const char *name) { return dk_set_has(s, dk_str(name)); }

DK_TEST(registers) {
    CHECK_CZ(dk_ctext_reg_full("al"), "eax");
    CHECK_CZ(dk_ctext_reg_full("dh"), "edx");
    CHECK_CZ(dk_ctext_reg_full("si"), "esi");
    CHECK_CZ(dk_ctext_reg_full("ebx"), "ebx");
    CHECK_CZ(dk_ctext_reg_full("xmm3"), "xmm3");
    CHECK_CZ(dk_ctext_reg_class("xmm1"), "xmm");
    CHECK_CZ(dk_ctext_reg_class("st(2)"), "st");
    CHECK_CZ(dk_ctext_reg_class("mm0"), "mm");
    CHECK_CZ(dk_ctext_reg_class("esp"), "esp");
    CHECK_CZ(dk_ctext_reg_class("ecx"), "r32");
    CHECK_CZ(dk_ctext_reg_class("cl"), "r8");
    CHECK_CZ(dk_ctext_reg_class("cx"), "r16");
}

DK_TEST(code_of_and_calls) {
    CHECK_STR(dk_ctext_code_of(dk_str("  x = f(1); // note")), "x = f(1);");
    CHECK_STR(dk_ctext_code_of(dk_str("\ty++;\t")), "y++;");
    CHECK_EQ_I64(dk_ctext_calls(dk_str("x = f(g(1)) + h (2);")), 3);
    CHECK_EQ_I64(dk_ctext_calls(dk_str("if (a) return sizeof(b);")), 0);
    CHECK_EQ_I64(dk_ctext_calls(dk_str("return static_cast<int>(v(1));")), 1);
}

DK_TEST(written_and_read) {
    DkSet *w = dk_ctext_written(dk_str("float t = a * b;"));
    CHECK(dk_set_len(w) == 1 && has(w, "t"));
    dk_set_free(w);
    w = dk_ctext_written(dk_str("p->pos.x += d[i];"));
    CHECK(has(w, "x") && !has(w, "p"));
    dk_set_free(w);
    w = dk_ctext_written(dk_str("arr[k] = 0;"));
    CHECK(has(w, "arr[k]"));
    dk_set_free(w);
    w = dk_ctext_written(dk_str("++count; s.n--;"));
    CHECK(has(w, "count") && has(w, "n"));
    dk_set_free(w);
    w = dk_ctext_written(dk_str("return a == b;"));
    CHECK(dk_set_len(w) == 0);
    dk_set_free(w);
    w = dk_ctext_written(dk_str("int n;"));
    CHECK(has(w, "n"));
    dk_set_free(w);
    DkSet *r = dk_ctext_read(dk_str("x = y + z->w;"));
    CHECK(has(r, "x") && has(r, "y") && has(r, "z") && has(r, "w") && dk_set_len(r) == 4);
    dk_set_free(r);
    CHECK(dk_ctext_not_type(dk_str("return")) && !dk_ctext_not_type(dk_str("int")));
}

DK_TEST(split_and_atomic) {
    DkStr l, r;
    CHECK(dk_ctext_split_top(dk_str("f(a, b), c"), ",", &l, &r));
    CHECK_STR(l, "f(a, b)");
    CHECK_STR(r, " c");
    CHECK(!dk_ctext_split_top(dk_str("A::b"), ":", NULL, NULL));
    CHECK(dk_ctext_split_top(dk_str("c ? A::x : y"), ":", &l, &r));
    CHECK_STR(r, " y");
    CHECK(dk_ctext_atomic(dk_str(" p->m[2] ")));
    CHECK(dk_ctext_atomic(dk_str("0x1F")));
    CHECK(dk_ctext_atomic(dk_str("1.5f")));
    CHECK(!dk_ctext_atomic(dk_str("(a + b)"))); /* a closing bracket is never a separator (ctext.h) */
    CHECK(!dk_ctext_split_top(dk_str("a + b)"), ")", NULL, NULL));
    CHECK(!dk_ctext_atomic(dk_str("(a) + (b)")));
    CHECK(!dk_ctext_atomic(dk_str("a + b")));
}

DK_TEST_MAIN("ctext")
