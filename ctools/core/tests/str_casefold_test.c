// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* str.casefold(): a CPython corpus (casefold_corpus.h) and the digest of the fold of every code point. */
#include "dk/dk.h"
#include "dk/test.h"

#include "casefold_corpus.h"

DK_TEST(casefold_corpus) {
    DkArena *a = dk_scratch();
    for (size_t i = 0; i < DK_ARRAY_LEN(casefold_cases); i++) {
        DkStr got = dk_str_casefold(a, dk_str(casefold_cases[i].in));
        CHECK_MSG(dk_str_eqz(got, casefold_cases[i].want), "case %zu: got \"%.*s\", want \"%s\"", i, DK_SF(got),
                  casefold_cases[i].want);
    }
}

DK_TEST(casefold_every_code_point) {
    u64 h = 0xcbf29ce484222325ULL;
    for (u32 cp = 0; cp < 0x110000; cp++) {
        if (cp >= 0xD800 && cp <= 0xDFFF) continue;
        char in[5];
        size_t n = dk_u8_put(in, cp);
        DkArena *a = dk_scratch();
        DkArenaMark mk = dk_arena_mark(a);
        DkStr got = dk_str_casefold(a, dk_strn(in, n));
        for (size_t i = 0; i < got.n; i++) h = (h ^ (u8)got.p[i]) * 0x100000001b3ULL;
        dk_arena_reset(a, mk);
    }
    CHECK(h == casefold_all_digest);
}

DK_TEST(casefold_matches_lower_on_ascii) {
    DkArena *a = dk_scratch();
    CHECK_STR(dk_str_casefold(a, DK_S("AbC-Z_9")), "abc-z_9");
    CHECK_STR(dk_str_casefold(a, DK_S("\xC3\x9F")), "ss");
    CHECK_STR(dk_str_casefold(a, DK_S("\xCF\x82")), "\xCF\x83");
}
DK_TEST_MAIN("str_casefold")
