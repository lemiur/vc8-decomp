// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dk_base64_encode against base64.b64encode of CPython 3.14 (the strings below were produced with
 *   python -c "import base64; print(base64.b64encode(bytes(range(n))))"-style calls on the inputs shown). */
#include "dk/test.h"

static DkStr enc(const char *s, size_t n) { return dk_base64_encode(dk_scratch(), s, n); }

DK_TEST(base64_rfc4648_vectors) {
    CHECK_STR(enc("", 0), "");
    CHECK_STR(enc("f", 1), "Zg==");
    CHECK_STR(enc("fo", 2), "Zm8=");
    CHECK_STR(enc("foo", 3), "Zm9v");
    CHECK_STR(enc("foob", 4), "Zm9vYg==");
    CHECK_STR(enc("fooba", 5), "Zm9vYmE=");
    CHECK_STR(enc("foobar", 6), "Zm9vYmFy");
}

DK_TEST(base64_all_byte_values) {
    /* base64.b64encode(bytes([0, 1, 2, 250, 251, 252, 253, 254, 255])) */
    static const u8 b[] = {0, 1, 2, 250, 251, 252, 253, 254, 255};
    CHECK_STR(dk_base64_encode(dk_scratch(), b, sizeof b), "AAEC+vv8/f7/");
    /* base64.b64encode(bytes([254, 255])) and bytes([255]) */
    CHECK_STR(dk_base64_encode(dk_scratch(), b + 7, 2), "/v8=");
    CHECK_STR(dk_base64_encode(dk_scratch(), b + 8, 1), "/w==");
}

DK_TEST_MAIN("str_base64")
