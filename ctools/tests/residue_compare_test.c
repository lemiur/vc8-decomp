// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* residue_compare on small hand-assembled functions (no compiler, no image; the results are built by hand): the
 * renames, the frame / operand / moves / body / schedule / call-set / control-flow classes, the register values with
 * the reference's registers, the mappings and the structure lines. Each case is a pair of byte strings (ours, the
 * reference's) and a flag for DIFF or MATCH; the expected dump is the report written out line by line. */
#include "dk/dk.h"
#include "dk/test.h"
#include "residue.h"

typedef struct {
    const char *id, *ours, *game;
    bool differ;
} Case;

static const Case CASES[] = {
    {"renames", "8B 44 24 04 03 C1 8B D0 C3", "8B 4C 24 04 03 CA 8B C1 C3", true},
    {"frame_operand", "83 EC 10 8B 44 24 14 C3", "83 EC 20 8B 44 24 24 C3", true},
    {"moves", "56 8B F1 8B 06 83 C0 05 5E C3", "8B 01 83 C0 05 C3", true},
    {"inverted_branch", "85 C0 74 03 40 40 C3", "85 C0 75 03 40 40 C3", true},
    {"call_set", "E8 00 00 00 00 E8 10 00 00 00 C3", "E8 00 00 00 00 C3", true},
    {"xmm", "F3 0F 10 44 24 04 F3 0F 59 C1 C3", "F3 0F 10 54 24 04 F3 0F 59 D1 C3", true},
    {"same_bytes", "8B 44 24 04 C3", "8B 44 24 04 C3", true},
    {"match", "8B 44 24 04 C3", "8B 44 24 04 C3", false},
    {"body_schedule", "8B 44 24 04 8B 4C 24 08 03 C1 0F AF C1 C3", "8B 4C 24 08 8B 44 24 04 0F AF C1 03 C1 C3", true},
    {"padding", "8B 44 24 04 C3 CC CC CC", "8B 4C 24 04 C3 CC CC CC", true},
    {"loop_regs", "33 C0 8B 4C 24 04 40 3B C1 7C FB C3", "33 D2 8B 4C 24 04 42 3B D1 7C FB 8B C2 C3", true},
};

static const char EXPECTED[] =
    "case renames\n"
    "status DIFF\n"
    "verdict register-only\n"
    "classes:\n"
    "  register: 3 aligned instruction(s) differ only in registers (first: +000 mov eax, dword ptr [esp + 4] | reference mov ecx, dword ptr [esp + 4]); 2 in block-local values, 1 in values live across blocks\n"
    "aligned 4 ours 4 game 4 local 2 cross 1 xmm 0 gp 1 reg_only 1\n"
    "mapping: eax->ecx 3/3, ecx->edx 1/1, edx->eax 1/1\n"
    "  eax -> ecx 3/3 others ecx:3\n"
    "  ecx -> edx 1/1 others edx:1\n"
    "  edx -> eax 1/1 others eax:1\n"
    "cross_mapping: ecx->edx 1/1\n"
    "  ecx -> edx 1/1 others edx:1\n"
    "structure:\n"
    "cfg 1 1 1 9 9\n"
    "values:\n"
    "  +000..+008 eax -> ecx 3/3 [local] renamed=3\n"
    "  +004..+004 ecx -> edx 1/1 [cross] renamed=1\n"
    "  +006..+006 edx -> eax 1/1 [local] renamed=1\n"
    "case frame_operand\n"
    "status DIFF\n"
    "verdict no register difference: operand, frame\n"
    "classes:\n"
    "  operand: 1 instruction(s) with another constant or displacement (first: sub esp, 0x10 | reference sub esp, 0x20)\n"
    "  frame: 1 instruction(s) with other esp displacements (first: mov eax, dword ptr [esp + 0x14] | reference mov eax, dword ptr [esp + 0x24])\n"
    "aligned 3 ours 3 game 3 local 0 cross 0 xmm 0 gp 0 reg_only 0\n"
    "mapping: eax->eax 1/1\n"
    "  eax -> eax 1/1 others eax:1\n"
    "cross_mapping: -\n"
    "structure:\n"
    "  frame: ours sub esp, 0x10; the reference's sub esp, 0x20\n"
    "  operand: 1 instruction(s) with another constant or displacement (first: sub esp, 0x10 | reference sub esp, 0x20)\n"
    "cfg 1 1 1 8 8\n"
    "values:\n"
    "  +003..+007 eax -> eax 1/1 [local] renamed=0\n"
    "case moves\n"
    "status DIFF\n"
    "verdict register + moves (the renames are all in block-local values)\n"
    "classes:\n"
    "  register: 1 aligned instruction(s) differ only in registers (first: +003 mov eax, dword ptr [esi] | reference mov eax, dword ptr [ecx]); 1 in block-local values, 0 in values live across blocks\n"
    "  moves: 3 extra copy/push/pop/lea (push esi; mov esi, ecx; pop esi)\n"
    "aligned 3 ours 6 game 3 local 1 cross 0 xmm 0 gp 1 reg_only 0\n"
    "mapping: esi->ecx 1/1, eax->eax 2/2\n"
    "  eax -> eax 2/2 others eax:2\n"
    "  esi -> ecx 1/1 others ecx:1\n"
    "cross_mapping: -\n"
    "structure:\n"
    "  size: ours 10 bytes / 6 instructions, the reference's 6 bytes / 3 instructions\n"
    "  moves: 3 extra copy/push/pop/lea (push esi; mov esi, ecx; pop esi)\n"
    "cfg 1 1 1 10 6\n"
    "values:\n"
    "  +000..+000 esi (no aligned use) [save] renamed=0\n"
    "  +001..+001 ecx (no aligned use) [cross] renamed=0\n"
    "  +001..+003 esi -> ecx 1/1 [local] renamed=1\n"
    "  +003..+009 eax -> eax 2/2 [local] renamed=0\n"
    "  +008..+008 esi (no aligned use) [save] renamed=0\n"
    "case inverted_branch\n"
    "status DIFF\n"
    "verdict no register difference: control-flow, body\n"
    "classes:\n"
    "  control-flow: the ordered branch sequence differs (walls)\n"
    "  body: 1 instruction(s) only ours, 1 only the reference's (ours +002 je 0x401007; reference +002 jne 0x401007)\n"
    "aligned 4 ours 5 game 5 local 0 cross 0 xmm 0 gp 0 reg_only 0\n"
    "mapping: eax->eax 4/4\n"
    "  eax -> eax 4/4 others eax:4\n"
    "cross_mapping: eax->eax 4/4\n"
    "  eax -> eax 4/4 others eax:4\n"
    "structure:\n"
    "  body: 1 instruction(s) only ours, 1 only the reference's (ours +002 je 0x401007; reference +002 jne 0x401007)\n"
    "cfg 2 2 2 7 7\n"
    "values:\n"
    "  +000..+006 eax -> eax 4/4 [cross] renamed=0\n"
    "case call_set\n"
    "status DIFF\n"
    "verdict no register difference: call-set, body\n"
    "classes:\n"
    "  call-set: calls only ours: 0x40101A; only the reference's: -\n"
    "  body: 1 instruction(s) only ours, 0 only the reference's (ours +000 call 0x401005)\n"
    "aligned 2 ours 3 game 2 local 0 cross 0 xmm 0 gp 0 reg_only 0\n"
    "mapping: -\n"
    "cross_mapping: -\n"
    "structure:\n"
    "  size: ours 11 bytes / 3 instructions, the reference's 6 bytes / 2 instructions\n"
    "  call set: calls only ours: 0x40101A; only the reference's: -\n"
    "  body: 1 instruction(s) only ours, 0 only the reference's (ours +000 call 0x401005)\n"
    "cfg 1 1 1 11 6\n"
    "values:\n"
    "  +000..+000 eax (no aligned use) [local] renamed=0\n"
    "  +000..+000 ecx (no aligned use) [local] renamed=0\n"
    "  +000..+000 edx (no aligned use) [local] renamed=0\n"
    "  +005..+00A eax (no aligned use) [local] renamed=0\n"
    "  +005..+005 ecx (no aligned use) [local] renamed=0\n"
    "  +005..+005 edx (no aligned use) [local] renamed=0\n"
    "case xmm\n"
    "status DIFF\n"
    "verdict register-only (the renames are all in block-local values)\n"
    "classes:\n"
    "  register: 2 aligned instruction(s) differ only in registers (first: +000 movss xmm0, dword ptr [esp + 4] | reference movss xmm2, dword ptr [esp + 4]); 2 in block-local values, 0 in values live across blocks\n"
    "aligned 3 ours 3 game 3 local 2 cross 0 xmm 1 gp 0 reg_only 1\n"
    "mapping: xmm0->xmm2 2/2, xmm1->xmm1 1/1\n"
    "  xmm0 -> xmm2 2/2 others xmm2:2\n"
    "  xmm1 -> xmm1 1/1 others xmm1:1\n"
    "cross_mapping: xmm1->xmm1 1/1\n"
    "  xmm1 -> xmm1 1/1 others xmm1:1\n"
    "structure:\n"
    "cfg 1 1 1 11 11\n"
    "values:\n"
    "  +000..+006 xmm0 -> xmm2 2/2 [local] renamed=2\n"
    "  +006..+006 xmm1 -> xmm1 1/1 [cross] renamed=0\n"
    "  +00A..+00A eax (no aligned use) [cross] renamed=0\n"
    "case same_bytes\n"
    "status DIFF\n"
    "verdict no register difference (bytes differ only in masked words?)\n"
    "classes:\n"
    "aligned 2 ours 2 game 2 local 0 cross 0 xmm 0 gp 0 reg_only 0\n"
    "mapping: eax->eax 1/1\n"
    "  eax -> eax 1/1 others eax:1\n"
    "cross_mapping: -\n"
    "structure:\n"
    "cfg 1 1 1 5 5\n"
    "values:\n"
    "  +000..+004 eax -> eax 1/1 [local] renamed=0\n"
    "case match\n"
    "status MATCH\n"
    "verdict none (MATCH)\n"
    "case body_schedule\n"
    "status DIFF\n"
    "verdict no register difference: schedule\n"
    "classes:\n"
    "  schedule: 2 instruction(s) at another place (first: mov ecx, dword ptr [esp + 8])\n"
    "aligned 3 ours 5 game 5 local 0 cross 0 xmm 0 gp 0 reg_only 0\n"
    "mapping: eax->eax 2/2, ecx->ecx 1/1\n"
    "  eax -> eax 2/2 others eax:2\n"
    "  ecx -> ecx 1/1 others ecx:1\n"
    "cross_mapping: -\n"
    "structure:\n"
    "  schedule: 2 instruction(s) at another place (first: mov ecx, dword ptr [esp + 8])\n"
    "cfg 1 1 1 14 14\n"
    "values:\n"
    "  +000..+00D eax -> eax 2/2 [local] renamed=0\n"
    "  +004..+00A ecx -> ecx 1/1 [local] renamed=0\n"
    "case padding\n"
    "status DIFF\n"
    "verdict register-only (the renames are all in block-local values)\n"
    "classes:\n"
    "  register: 1 aligned instruction(s) differ only in registers (first: +000 mov eax, dword ptr [esp + 4] | reference mov ecx, dword ptr [esp + 4]); 1 in block-local values, 0 in values live across blocks\n"
    "aligned 2 ours 2 game 2 local 1 cross 0 xmm 0 gp 1 reg_only 1\n"
    "mapping: eax->ecx 1/1\n"
    "  eax -> ecx 1/1 others ecx:1\n"
    "cross_mapping: -\n"
    "structure:\n"
    "cfg 1 1 1 5 5\n"
    "values:\n"
    "  +000..+004 eax -> ecx 1/1 [local] renamed=1\n"
    "case loop_regs\n"
    "status DIFF\n"
    "verdict register + moves\n"
    "classes:\n"
    "  register: 3 aligned instruction(s) differ only in registers (first: +000 xor eax, eax | reference xor edx, edx); 0 in block-local values, 3 in values live across blocks\n"
    "  moves: 1 extra copy/push/pop/lea (mov eax, edx)\n"
    "aligned 6 ours 6 game 7 local 0 cross 3 xmm 0 gp 1 reg_only 0\n"
    "mapping: eax->edx 4/4, ecx->ecx 2/2\n"
    "  eax -> edx 4/4 others edx:4\n"
    "  ecx -> ecx 2/2 others ecx:2\n"
    "cross_mapping: eax->edx 4/4, ecx->ecx 2/2\n"
    "  eax -> edx 4/4 others edx:4\n"
    "  ecx -> ecx 2/2 others ecx:2\n"
    "structure:\n"
    "  size: ours 12 bytes / 6 instructions, the reference's 14 bytes / 7 instructions\n"
    "  moves: 1 extra copy/push/pop/lea (mov eax, edx)\n"
    "cfg 3 3 3 12 14\n"
    "values:\n"
    "  +000..+00B eax -> edx 4/4 [cross] renamed=4\n"
    "  +002..+007 ecx -> ecx 2/2 [cross] renamed=0\n";

static DkStr from_hex(const char *s) {
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
    return dk_strn((const char *)out.v, out.n);
}

static void dump_mapping(DkBuf *b, const char *name, const DkMap *m) {
    dk_buf_printf(b, "%s: %s\n", name, dk_map_len(m) ? residue_mapping_text(m, 10) : "-");
    DkMapIter it = {0};
    while (dk_map_next(m, &it)) {
        const ResidueMapping *e = it.val->p;
        dk_buf_printf(b, "  %.*s -> %s %lld/%lld others ", DK_SF(it.key), e->game, (long long)e->count, (long long)e->total);
        DkMapIter oi = {0};
        bool first = true;
        while (dk_map_next(e->others, &oi)) {
            dk_buf_printf(b, "%s%.*s:%lld", first ? "" : ",", DK_SF(oi.key), (long long)oi.val->i);
            first = false;
        }
        dk_buf_putc(b, '\n');
    }
}

static void dump_none(DkBuf *b, const char *sep, i64 v) {
    if (v == RESIDUE_NONE) dk_buf_printf(b, "%sNone", sep);
    else dk_buf_printf(b, "%s%lld", sep, (long long)v);
}

static void dump(DkBuf *b, const char *id, const ResidueReport *r) {
    dk_buf_printf(b, "case %s\nstatus %s\nverdict %s\n", id, r->status, r->verdict);
    if (strcmp(r->status, "DIFF") != 0) return;
    dk_buf_putz(b, "classes:\n");
    DkMapIter it = {0};
    while (dk_map_next(r->classes, &it)) dk_buf_printf(b, "  %.*s: %s\n", DK_SF(it.key), (const char *)it.val->p);
    dk_buf_printf(b, "aligned %lld ours %lld game %lld local %lld cross %lld xmm %d gp %d reg_only %d\n",
                   (long long)r->aligned, (long long)r->insns_ours, (long long)r->insns_game, (long long)r->local_renames,
                   (long long)r->cross_renames, r->xmm, r->gp, r->has_register_only && r->register_only);
    dump_mapping(b, "mapping", r->mapping);
    dump_mapping(b, "cross_mapping", r->cross_mapping);
    dk_buf_putz(b, "structure:\n");
    for (size_t i = 0; i < r->structure.n; i++) dk_buf_printf(b, "  %s\n", r->structure.v[i]);
    dk_buf_putz(b, "cfg");
    dump_none(b, " ", r->cfg_blocks_ours);
    dump_none(b, " ", r->cfg_blocks_game);
    dump_none(b, " ", r->cfg_matched);
    dump_none(b, " ", r->cfg_size_ours);
    dump_none(b, " ", r->cfg_size_game);
    dk_buf_putz(b, "\nvalues:\n");
    for (size_t i = 0; i < r->values.n; i++)
        dk_buf_printf(b, "  %s [%s] renamed=%lld\n", residue_value_text(r->values.v[i], 3), r->values.v[i]->kind,
                       (long long)r->values.v[i]->renamed);
}

DK_TEST(compare) {
    DkArena *a = dk_arena();
    DkBuf b;
    dk_buf_init(&b, a);
    for (size_t i = 0; i < DK_ARRAY_LEN(CASES); i++) {
        DkResult *r = DK_NEW(a, DkResult);
        r->status = CASES[i].differ ? DK_DIFF : DK_MATCH;
        r->ours.symbol = "?f@@YAXXZ";
        r->ours.code = from_hex(CASES[i].ours);
        r->theirs = from_hex(CASES[i].game);
        r->theirs_va = 0x401000;
        ResidueReport *rep = residue_compare(r, NULL, "t0");
        dump(&b, CASES[i].id, rep);
    }
    DkStr got = dk_buf_str(&b), want = dk_strn(EXPECTED, sizeof EXPECTED - 1);
    if (!dk_str_eq(got, want)) {
        DkStrVec g = dk_str_splitlines(got, false), w = dk_str_splitlines(want, false);
        for (size_t i = 0; i < (g.n > w.n ? g.n : w.n); i++) {
            DkStr x = i < g.n ? g.v[i] : DK_S("<none>"), y = i < w.n ? w.v[i] : DK_S("<none>");
            if (!dk_str_eq(x, y)) {
                CHECK_MSG(false, "line %zu differs:\n  got  %.*s\n  want %.*s", i + 1, DK_SF(x), DK_SF(y));
                return;
            }
        }
        CHECK_MSG(false, "the dumps differ");
    }
}

DK_TEST_MAIN("residue_compare")
