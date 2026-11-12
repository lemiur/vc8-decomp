// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* walls: tokens, branches, switch tables and every wall of the classification, on hand-assembled byte pairs (results
 * built by hand, no image). */
#include "dk/dk.h"
#include "dk/test.h"
#include "walls.h"

#include <string.h>

#define BASE 0x00401000u

static DkResult result(DkStatus st, const u8 *ours, size_t no, const u8 *theirs, size_t nt) {
    DkResult r;
    memset(&r, 0, sizeof r);
    r.status = st;
    r.ours.symbol = "_f_sample";
    r.ours.code = dk_strn((const char *)ours, no);
    r.theirs = dk_strn((const char *)theirs, nt);
    r.theirs_va = BASE;
    return r;
}

static void put32(u8 *p, u32 v) { memcpy(p, &v, 4); }

DK_TEST(tables) {
    CHECK_EQ_I64(dk_wall_rank("match"), 0);
    CHECK_EQ_I64(dk_wall_rank("call-set"), 5);
    CHECK_EQ_I64(dk_wall_rank("nope"), -1);
    CHECK_EQ_F64(dk_wall_weight("register", 0.0), 0.8);
    CHECK_EQ_F64(dk_wall_weight("match", 1.5), 1.5);
    CHECK(dk_wall_is_move("mov") && dk_wall_is_move("movsd") && dk_wall_is_move("fstp") && dk_wall_is_move("push"));
    CHECK(!dk_wall_is_move("movzx") && !dk_wall_is_move("add") && !dk_wall_is_move("call"));
}

DK_TEST(branch_tokens) {
    /* test eax, eax; je +2; mov eax, ecx; ret; jmp eax */
    static const u8 code[9] = {0x85, 0xC0, 0x74, 0x02, 0x8B, 0xC1, 0xC3, 0xFF, 0xE0};
    DkInsns x = dk_wall_disasm(dk_strn((const char *)code, sizeof code), BASE);
    REQUIRE(x.n == 5);
    DkBranchVec b = dk_wall_branch_tokens(&x, true);
    REQUIRE(b.n == 3);
    CHECK(strcmp(b.v[0].mnemonic, "je") == 0 && b.v[0].target == 2); /* test, je before the ret */
    CHECK(strcmp(b.v[1].mnemonic, "ret") == 0 && b.v[1].target == DK_WALL_TARGET_NONE);
    CHECK(strcmp(b.v[2].mnemonic, "jmp") == 0 && b.v[2].target == DK_WALL_TARGET_INDIRECT);
    dk_vec_free(&b);
    b = dk_wall_branch_tokens(&x, false);
    CHECK(b.n == 3 && b.v[0].target == DK_WALL_TARGET_NONE);
    dk_vec_free(&b);
    u64 t = 0;
    CHECK(dk_wall_target_of(&x.v[1], &t) && t == BASE + 6);
    CHECK(!dk_wall_target_of(&x.v[4], &t));
    dk_wall_insns_free(&x);
}

DK_TEST(call_tokens) {
    /* call rel32 (ours: through a relocation check); call [mem]; jmp out of the function (a tail call) */
    u8 code[16] = {0xE8, 0, 0, 0, 0, 0xFF, 0x15, 0, 0, 0, 0, 0xE9, 0, 0, 0, 0};
    put32(code + 12, 0x100);
    DkResult r = result(DK_DIFF, code, sizeof code, code, sizeof code);
    DkRefCheck refs[2] = {{1, 0x00402000u, 0x00402000u, "_callee", DK_REF_SAME},
                          {12, 0, 0x00401110u, "_gone", DK_REF_UNRESOLVED}};
    r.refs = refs;
    r.n_refs = 2;
    DkIMap *v = dk_wall_verdicts(&r);
    DkInsns x = dk_wall_disasm(r.ours.code, BASE);
    REQUIRE(x.n == 3);
    DkCallToken t;
    CHECK(dk_wall_call_token(&x.v[0], BASE, v, sizeof code, &t) && t.is_int && t.n == 0x00402000u);
    CHECK_STR(dk_wall_tok_text(dk_arena(), &t), "0x402000");
    CHECK(dk_wall_call_token(&x.v[1], BASE, v, sizeof code, &t) && !t.is_int);
    CHECK_STR(t.s, "indirect");
    CHECK(dk_wall_call_token(&x.v[2], BASE, v, sizeof code, &t));
    CHECK_STR(t.s, "tail:sym:_gone");
    /* the reference's side reads the operands */
    CHECK(dk_wall_call_token(&x.v[0], BASE, NULL, sizeof code, &t) && t.is_int && t.n == BASE + 5);
    CHECK(dk_wall_call_token(&x.v[2], BASE, NULL, sizeof code, &t));
    CHECK_STR(t.s, "tail:0x401110");
    dk_imap_free(v);
    dk_wall_insns_free(&x);
}

DK_TEST(switch_table) {
    /* jmp dword ptr [eax*4 + 0x401010]; ret; padding; the table */
    u8 code[0x18];
    memset(code, 0xCC, sizeof code);
    static const u8 jmp[7] = {0xFF, 0x24, 0x85, 0x10, 0x10, 0x40, 0x00};
    memcpy(code, jmp, sizeof jmp);
    code[7] = 0xC3;
    put32(code + 0x10, BASE + 7);
    put32(code + 0x14, BASE + 7);
    DkInsns x = dk_wall_disasm(dk_strn((const char *)code, sizeof code), BASE);
    i64 cut = 0;
    CHECK(dk_wall_table_start(&x, BASE, sizeof code, NULL, &cut) && cut == 0x10);
    DkInsns only = dk_wall_code_only(&x, BASE, sizeof code, NULL);
    CHECK(only.n == 10); /* jmp, ret and the int3 padding */
    /* ours: the table's word is a relocation whose check places it inside the function */
    DkResult r = result(DK_DIFF, code, sizeof code, code, sizeof code);
    DkRefCheck ref = {3, BASE + 0x10, BASE + 0x10, "$LN4", DK_REF_SAME};
    r.refs = &ref;
    r.n_refs = 1;
    cut = 0;
    CHECK(dk_wall_table_start(&x, BASE, sizeof code, &r, &cut) && cut == 0x10);
    /* the reference window stops before the table */
    DkStr w = dk_wall_reference_window(&r, NULL);
    CHECK_EQ_U64(w.n, 0x10);
    dk_wall_insns_free(&x);
}

DK_TEST(walls) {
    /* register: mov ecx, [esp+4]; add ecx, 1; mov eax, ecx; ret -- the same with edx */
    static const u8 reg_o[10] = {0x8B, 0x4C, 0x24, 0x04, 0x83, 0xC1, 0x01, 0x8B, 0xC1, 0xC3};
    static const u8 reg_t[10] = {0x8B, 0x54, 0x24, 0x04, 0x83, 0xC2, 0x01, 0x8B, 0xC2, 0xC3};
    DkResult r = result(DK_DIFF, reg_o, 10, reg_t, 10);
    DkBuildWall bw = dk_build_wall(&r, NULL);
    CHECK_CZ(bw.wall, "register");
    CHECK(bw.info.classified && bw.info.same_mnemonics && bw.info.insns_ours == 4);
    CHECK(bw.info.has_first_difference && bw.info.first_difference == 1);
    CHECK_EQ_F64(bw.close, 70.0); /* 3 of 10 bytes differ */

    /* body: inc ecx for add ecx, 1 */
    static const u8 body_t[8] = {0x8B, 0x4C, 0x24, 0x04, 0x41, 0x8B, 0xC1, 0xC3};
    r = result(DK_SIZE, reg_o, 10, body_t, 8);
    CHECK_CZ(dk_build_wall(&r, NULL).wall, "body");

    /* control-flow: je for jne */
    static const u8 cf_o[6] = {0x85, 0xC0, 0x74, 0x01, 0xC3, 0xC3};
    static const u8 cf_t[6] = {0x85, 0xC0, 0x75, 0x01, 0xC3, 0xC3};
    r = result(DK_DIFF, cf_o, 6, cf_t, 6);
    CHECK_CZ(dk_build_wall(&r, NULL).wall, "control-flow");

    /* call-set: the reference calls one more target */
    u8 cs_o[6] = {0xE8, 0, 0, 0, 0, 0xC3};
    u8 cs_t[11] = {0xE8, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xC3};
    put32(cs_t + 1, 0x00401200u - (BASE + 5));
    put32(cs_t + 6, 0x00401300u - (BASE + 10));
    DkReloc rel = {1, 0x14, "_callee", 0};
    DkRefCheck ref = {1, 0x00401200u, 0x00401200u, "_callee", DK_REF_SAME};
    r = result(DK_SIZE, cs_o, 6, cs_t, 11);
    r.ours.relocs = &rel;
    r.ours.n_relocs = 1;
    r.refs = &ref;
    r.n_refs = 1;
    bw = dk_build_wall(&r, NULL);
    CHECK_CZ(bw.wall, "call-set");
    CHECK(bw.info.calls_only_reference.n == 1 && strcmp(bw.info.calls_only_reference.v[0], "0x401300") == 0);
    CHECK(bw.info.calls_only_ours.n == 0);

    /* one target called a different number of times: control-flow (a duplicated tail) */
    put32(cs_t + 6, 0x00401200u - (BASE + 10));
    r.theirs = dk_strn((const char *)cs_t, 11);
    CHECK_CZ(dk_build_wall(&r, NULL).wall, "control-flow");

    /* the statuses that need no classification */
    r = result(DK_MATCH, reg_o, 10, reg_o, 10);
    bw = dk_build_wall(&r, NULL);
    CHECK(strcmp(bw.wall, "match") == 0 && bw.close == 100.0 && !bw.info.classified);
    r.status = DK_REFERENT;
    CHECK_CZ(dk_build_wall(&r, NULL).wall, "referent");
    r.status = DK_UNRESOLVED;
    CHECK_CZ(dk_build_wall(&r, NULL).wall, "referent");
    r.status = DK_MISSING;
    CHECK_CZ(dk_build_wall(&r, NULL).wall, "error");
    CHECK_CZ(dk_build_wall(NULL, NULL).wall, "error");
}

DK_TEST_MAIN("walls")
