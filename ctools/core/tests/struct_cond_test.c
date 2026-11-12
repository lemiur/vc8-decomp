// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* A struct-valued conditional whose arm is an inlined function that returns the struct by value, built with the
 * Release flags (tools/c/CMakeLists.txt).
 *
 * MSVC 14.51's instruction scheduler moves the store of the arm's temporary past the 16-byte load that copies it out
 * (seen under /GL at link time):
 *
 *     lea    rax, [rbp-78h]
 *     movups xmm6, xmmword ptr [rax]        ; reads the p of an earlier pass through the frame
 *     mov    qword ptr [rbp-78h], rcx       ; the new p, too late
 *
 * so the result had the right length and the previous string's pointer, or an uninitialised one. Linking with
 * /d2:-scheduler- keeps the order. The shape of this file is what makes the compiler take that path, so a small edit
 * can stop it from reproducing: keep the three switch arms, the sizes of the tables and the mark/reset around the
 * check. Without the option, this test fails in Release with the toolset above. */
#include "dk/test.h"
#include "dk/fmt.h"

typedef struct {
    i64 key;
    const char *name;
} Entry;

static const Entry PRIMITIVE[] = {{1, "POINTLIST"}, {2, "LINELIST"}, {3, "LINESTRIP"}, {4, "TRIANGLELIST"}, {5, "TRIANGLESTRIP"}, {6, "TRIANGLEFAN"}};
static const Entry STAGE[] = {{1, "AAA"}, {2, "BBBB"}, {3, "CCCCC"}, {9, "DDDDDD"}, {11, "EEEEEEE"}, {12, "FFFFFFFF"}, {13, "GG"}, {14, "HH"},
                              {15, "II"}, {16, "JJ"}, {17, "KK"}, {18, "LL"}, {19, "MM"}, {20, "NN"}, {21, "OO"}};
static const Entry RENDER[] = {{7, "Z"}, {8, "Y"}, {9, "X"}, {10, "W"}, {11, "V"}, {12, "U"}, {13, "T"}, {14, "S"}, {15, "R"},
                               {16, "Q"}, {17, "P"}, {18, "O"}, {19, "N"}, {20, "M"}, {21, "L"}, {22, "K"}, {23, "J"}, {24, "I"}};
static const struct {
    const char *state;
    const Entry *table;
    size_t n;
} VALUES[] = {{"Z", PRIMITIVE, 6}, {"Y", STAGE, 15}, {"X", RENDER, 18}};

static const char *enum_get(const Entry *t, size_t n, i64 key) {
    for (size_t i = 0; i < n; i++)
        if (t[i].key == key)
            return t[i].name;
    return NULL;
}

/* the conditional under test: one arm inlined, the other a real call */
static DkStr state_name(DkArena *a, const Entry *t, size_t n, i64 key) {
    const char *s = enum_get(t, n, key);
    return s ? dk_str_dup(a, dk_str(s)) : dk_pyfmt(a, "%d", key);
}

static DkStr primitive(DkArena *a, i64 v) { return state_name(a, PRIMITIVE, DK_ARRAY_LEN(PRIMITIVE), v); }

static DkStr stage_state(DkArena *a, i64 stage, i64 type, const i64 *pv) {
    DkStr name = state_name(a, STAGE, DK_ARRAY_LEN(STAGE), type);
    if (pv == NULL)
        return dk_pyfmt(a, "t%d.%S", stage, &name);
    return dk_pyfmt(a, "t%d.%S = %d", stage, &name, *pv);
}

static DkStr render_state(DkArena *a, i64 state, const i64 *pvalue) {
    DkStr name = state_name(a, RENDER, DK_ARRAY_LEN(RENDER), state);
    if (pvalue == NULL)
        return name;
    i64 value = *pvalue;
    const char *nz = dk_cz(a, name);
    for (size_t i = 0; i < DK_ARRAY_LEN(VALUES); i++) {
        if (strcmp(VALUES[i].state, nz) == 0) {
            const char *sub = enum_get(VALUES[i].table, VALUES[i].n, value);
            if (sub)
                return dk_pyfmt(a, "%s = %s", nz, sub);
            break;
        }
    }
    return dk_pyfmt(a, "%s = %d", nz, value);
}

typedef struct {
    int kind;
    long long stage, type;
    int has;
    long long value;
    const char *want;
} Case;

static const Case CASES[] = {
    {3, 0, 4, 0, 0, "TRIANGLELIST"},
    {3, 0, 5, 0, 0, "TRIANGLESTRIP"},
    {3, 0, 6, 0, 0, "TRIANGLEFAN"},
    {3, 0, 7, 0, 0, "7"},
    {2, 1, 1, 0, 0, "t1.AAA"},
    {2, 2, 2, 1, 5, "t2.BBBB = 5"},
    {0, 0, 7, 0, 0, "Z"},
    {0, 0, 8, 1, 3, "Y = CCCCC"},
};

DK_TEST(struct_conditional_with_an_inlined_arm) {
    DkArena *a = dk_arena();
    for (size_t i = 0; i < DK_ARRAY_LEN(CASES); i++) {
        DkArenaMark mark = dk_arena_mark(a);
        const i64 *pv = CASES[i].has ? &CASES[i].value : NULL;
        DkStr got;
        switch (CASES[i].kind) {
        case 0: got = render_state(a, CASES[i].type, pv); break;
        case 2: got = stage_state(a, CASES[i].stage, CASES[i].type, pv); break;
        default: got = primitive(a, CASES[i].type); break;
        }
        CHECK_MSG(dk_str_eqz(got, CASES[i].want), "kind %d stage %lld type %lld value %lld: got \"%.*s\" want \"%s\"",
                  CASES[i].kind, CASES[i].stage, CASES[i].type, CASES[i].value, DK_SF(got), CASES[i].want);
        dk_arena_reset(a, mark);
    }
}

DK_TEST_MAIN("struct_cond")
