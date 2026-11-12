// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* insn_text: instruction rows, normal forms, differing bytes and the side-by-side diff, on hand-assembled bytes. */
#include "dk/dk.h"
#include "dk/test.h"
#include "insn_text.h"

#include <string.h>

static DkResult result(const u8 *ours, size_t no, const u8 *theirs, size_t nt, DkReloc *relocs, size_t nr) {
    DkResult r;
    memset(&r, 0, sizeof r);
    r.status = DK_DIFF;
    r.ours.symbol = "_f_sample";
    r.ours.code = dk_strn((const char *)ours, no);
    r.ours.relocs = relocs;
    r.ours.n_relocs = nr;
    r.theirs = dk_strn((const char *)theirs, nt);
    r.theirs_va = 0x00401000u;
    return r;
}

DK_TEST(disassemble_rows) {
    static const u8 code[13] = {0xB8, 1, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xC3, 0x00, 0x00};
    DkReloc rel = {6, 0x14, "_callee", 0};
    DkReloc rel2 = {1, 0x06, "$SG1", 8};
    DkInsnTextVec v = dk_insn_disassemble(dk_arena(), dk_strn((const char *)code, 11), 0x00401000u, &rel, 1);
    REQUIRE(v.n == 3);
    CHECK_STR(v.v[0].text, "mov eax, 1");
    CHECK_STR(v.v[0].note, "");
    CHECK_STR(v.v[1].text, "call 0x40100a");
    CHECK_STR(v.v[1].note, "_callee");
    CHECK(v.v[1].offset == 5 && v.v[1].size == 5);
    CHECK_STR(v.v[2].text, "ret ");
    dk_vec_free(&v);
    /* undecodable bytes at the end, an addend in the note */
    static const u8 tail[4] = {0xC3, 0xFF, 0xFF, 0xFF};
    v = dk_insn_disassemble(dk_arena(), dk_strn((const char *)tail, 4), 0x00401000u, NULL, 0);
    REQUIRE(v.n == 2);
    CHECK_STR(v.v[1].text, "(3 bytes of data)");
    CHECK(v.v[1].offset == 1 && v.v[1].size == 3);
    dk_vec_free(&v);
    v = dk_insn_disassemble(dk_arena(), dk_strn((const char *)code, 5), 0x00401000u, &rel2, 1);
    REQUIRE(v.n == 1);
    CHECK_STR(v.v[0].note, "$SG1+0x8");
    dk_vec_free(&v);
}

DK_TEST(normalise) {
    CHECK_STR(dk_insn_normalise(dk_arena(), dk_str("call 0x40100a"), false), "call IMM");
    CHECK_STR(dk_insn_normalise(dk_arena(), dk_str("add eax, 0x10"), false), "add eax, 0x10");
    CHECK_STR(dk_insn_normalise(dk_arena(), dk_str("mov eax, dword ptr [0]"), true), "mov eax, dword ptr [IMM]");
    CHECK_STR(dk_insn_normalise(dk_arena(), dk_str("mov eax, dword ptr [ecx*4 + 0]"), true),
              "mov eax, dword ptr [ecx*4 + IMM]");
    CHECK_STR(dk_insn_normalise(dk_arena(), dk_str("fld dword ptr [eax*4]"), true), "fld dword ptr [eax*4]");
    CHECK_STR(dk_insn_normalise(dk_arena(), dk_str("push 0"), false), "push 0");
}

DK_TEST(differ) {
    static const u8 ours[6] = {0xB8, 1, 0, 0, 0, 0xC3};
    static const u8 theirs[7] = {0xB8, 2, 0, 0, 0, 0xC3, 0xCC};
    DkResult r = result(ours, 6, theirs, 7, NULL, 0);
    size_t n = 0;
    u32 *d = dk_result_differ(dk_arena(), &r, &n);
    REQUIRE(n == 2);
    CHECK(d[0] == 1 && d[1] == 6);
    DkReloc rel = {1, 0x06, "_g", 0};
    r = result(ours, 6, theirs, 6, &rel, 1);
    d = dk_result_differ(dk_arena(), &r, &n);
    CHECK(n == 0 && d == NULL);
}

DK_TEST(side_by_side) {
    /* ours: mov eax, 0x1234; ret. the reference: mov eax, 0x5678; inc eax; ret. The two movs normalise alike (an
     * equal row with differing bytes: '!'); inc is the reference's only ('+'); the rets differ at offset 5. */
    static const u8 ours[6] = {0xB8, 0x34, 0x12, 0, 0, 0xC3};
    static const u8 theirs[7] = {0xB8, 0x78, 0x56, 0, 0, 0x40, 0xC3};
    DkResult r = result(ours, 6, theirs, 7, NULL, 0);
    DkInsnDiffOpts o = {40, 0, "alpha"};
    DkStr text = dk_insn_diff(dk_arena(), &r, NULL, &o);
    CHECK_MSG(dk_str_find(text, DK_S("alpha  _f_sample  00401000  DIFF  ours: 6 bytes, reference: 7 bytes"), 0,
                          DK_END) == 0,
              "%.*s", DK_SF(text));
    CHECK_MSG(dk_str_find(text, DK_S("\n! +000  mov eax, 0x1234"), 0, DK_END) > 0, "%.*s", DK_SF(text));
    CHECK_MSG(dk_str_find(text, DK_S("| +000  mov eax, 0x5678"), 0, DK_END) > 0, "%.*s", DK_SF(text));
    CHECK_MSG(dk_str_find(text, DK_S("\n+ "), 0, DK_END) > 0, "%.*s", DK_SF(text));
    CHECK_MSG(dk_str_find(text, DK_S("| +005  inc eax"), 0, DK_END) > 0, "%.*s", DK_SF(text));
    CHECK_MSG(dk_str_find(text, DK_S("\n! +005  ret "), 0, DK_END) > 0, "%.*s", DK_SF(text));
    /* only the first differing row */
    o.max_rows = 1;
    text = dk_insn_diff(dk_arena(), &r, NULL, &o);
    CHECK(dk_str_find(text, DK_S("inc eax"), 0, DK_END) < 0 &&
          dk_str_find(text, DK_S("mov eax, 0x5678"), 0, DK_END) > 0);
}

DK_TEST_MAIN("insn_text")
