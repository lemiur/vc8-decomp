// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* residue_values (lib/residue.c: the webs of reaching definitions over cfg_diff's basic blocks) on four hand-assembled
 * functions: a diamond (a value joined from two definitions, a push/pop save), a loop with sub-registers, an xmm zero
 * idiom and a call, the exception registration (fs:[0], a `frame` value) with a sub-register write, and an empty side.
 * Each line is one value: register, kind, definition, use and reference offsets, blocks, live at the entry. */
#include "dk/dk.h"
#include "dk/test.h"
#include "residue.h"

typedef struct {
    const char *hex;
    u32 base;
    const char *expected;
} Sample;

static const Sample SAMPLES[] = {
    {"55 8B EC 8B 45 08 85 C0 74 05 8B 48 04 EB 02 33 C9 8B C1 5D C3", 0x401000,
     "ebp save d=- u=0 r=0 b=0 e=1\n"
     "ebp local d=1 u=3 r=1,3 b=0 e=0\n"
     "eax cross d=3 u=6,A r=3,6,A b=0,1 e=0\n"
     "ecx cross d=A,F u=11 r=A,F,11 b=1,2,3 e=0\n"
     "eax local d=11 u=14 r=11,14 b=3 e=0\n"
     "ebp save d=13 u=- r=13 b=3 e=0\n"},
    {"53 56 8B 74 24 0C 33 DB 8B 06 03 D8 83 C6 04 83 FE 20 75 F4 8A C3 0F 57 C0 E8 00 00 00 00 5E 5B C3", 0x402000,
     "ebx save d=- u=0 r=0 b=0 e=1\n"
     "esi save d=- u=1 r=1 b=0 e=1\n"
     "esi cross d=2,C u=8,C,F r=2,8,C,F b=0,1 e=0\n"
     "ebx cross d=6,A u=A,14 r=6,A,14 b=0,1,2 e=0\n"
     "eax cross d=8,14 u=A,14 r=8,A,14 b=1,2 e=0\n"
     "xmm0 local d=16 u=- r=16 b=2 e=0\n"
     "eax local d=19 u=20 r=19,20 b=2 e=0\n"
     "ecx local d=19 u=- r=19 b=2 e=0\n"
     "edx local d=19 u=- r=19 b=2 e=0\n"
     "esi save d=1E u=- r=1E b=2 e=0\n"
     "ebx save d=1F u=- r=1F b=2 e=0\n"},
    {"64 A1 00 00 00 00 50 64 89 25 00 00 00 00 8A 01 0F B6 C0 33 C0 C3", 0x403000,
     "eax frame d=0,E,10 u=6,E,10 r=0,6,E,10 b=0 e=0\n"
     "ecx cross d=- u=E r=E b=0 e=1\n"
     "eax local d=13 u=15 r=13,15 b=0 e=0\n"},
    {"", 0x404000, ""},
};

static DkBytes from_hex(const char *s) {
    DkBytes out = {0};
    for (const char *p = s; *p;) {
        if (*p == ' ') {
            p++;
            continue;
        }
        char two[3] = {p[0], p[1], 0};
        dk_vec_push(&out, (u8)strtoul(two, NULL, 16));
        p += 2;
    }
    return out;
}

static void list(DkBuf *b, const DkU32Vec *v) {
    if (!v->n) dk_buf_putc(b, '-');
    for (size_t i = 0; i < v->n; i++) dk_buf_printf(b, i ? ",%X" : "%X", v->v[i]);
}

DK_TEST(values) {
    for (size_t k = 0; k < DK_ARRAY_LEN(SAMPLES); k++) {
        DkBytes code = from_hex(SAMPLES[k].hex);
        CfgDiffSide *side = cfg_diff_side_new("game", dk_strn((const char *)code.v, code.n), SAMPLES[k].base, (u32)code.n,
                                              NULL, NULL, NULL);
        cfg_diff_build_blocks(side);
        ResidueValueVec vals = {0};
        DkMap *index = NULL;
        REQUIRE(residue_values(side, &vals, &index));
        DkBuf b;
        dk_buf_init(&b, dk_arena());
        for (size_t i = 0; i < vals.n; i++) {
            const ResidueValue *v = vals.v[i];
            dk_buf_printf(&b, "%s %s d=", v->reg, v->kind);
            list(&b, &v->defs);
            dk_buf_putz(&b, " u=");
            list(&b, &v->uses);
            dk_buf_putz(&b, " r=");
            list(&b, &v->refs);
            dk_buf_putz(&b, " b=");
            list(&b, &v->blocks);
            dk_buf_printf(&b, " e=%d\n", v->entry ? 1 : 0);
        }
        CHECK_MSG(dk_str_eqz(dk_buf_str(&b), SAMPLES[k].expected), "sample %zu:\n%s--- want:\n%s", k, dk_buf_cz(&b),
                  SAMPLES[k].expected);
        /* every (offset, register) of a value's refs indexes that value */
        for (size_t i = 0; i < vals.n; i++)
            for (size_t r = 0; r < vals.v[i]->refs.n; r++) {
                const DkVal *got = dk_map_get(index, dk_str(dk_sprintf(dk_arena(), "%u\t%s", vals.v[i]->refs.v[r], vals.v[i]->reg)));
                CHECK(got != NULL && got->i == (i64)i);
            }
    }
}

DK_TEST_MAIN("residue_values")
