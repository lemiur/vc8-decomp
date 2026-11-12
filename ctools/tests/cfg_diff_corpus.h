// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Hand-assembled function pairs and the report cfg_diff prints for each (verbose report, one-liner, mapping rows); the
 * bytes are synthetic. */
#pragma once
typedef struct { const char *name; const unsigned char *ours, *game; unsigned ours_n, game_n; unsigned address;
                 const char *report, *one_liner; } CfgDiffCase;
static const unsigned char cfgdiff_inverted_ours[] = {0x83, 0xF8, 0x00, 0x74, 0x09, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x03, 0xC1, 0xEB, 0x07, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x03, 0xC2, 0x5B, 0xC3};
static const unsigned char cfgdiff_inverted_game[] = {0x83, 0xF8, 0x00, 0x75, 0x09, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x03, 0xC2, 0xEB, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x03, 0xC1, 0x5B, 0xC3};
static const char cfgdiff_inverted_report[] =
    "t0   00401000  f_inverted  ours 23 bytes / 4 blocks, game 23 bytes / 4 blocks, 4 matched\n"
    "  blocks (ours -> game):  +000->+000 (inv)  +005->+00E  +00E->+005  +015->+015\n"
    "  side  block   size term    successors             mapped   score/how\n"
    "  ours  +000      5 jcc e   taken:+00E fall:+005   +000     5.5 entry\n"
    "  ours  +005      9 jmp     taken:+015             +00E     6.5 edge\n"
    "  ours  +00E      7 fall    fall:+015              +005     6.5 edge\n"
    "  ours  +015      2 ret                            +015     6.0 edge\n"
    "  game  +000      5 jcc ne  taken:+00E fall:+005   +000     5.5 entry\n"
    "  game  +005      9 jmp     taken:+015             +00E     6.5 edge\n"
    "  game  +00E      7 fall    fall:+015              +005     6.5 edge\n"
    "  game  +015      2 ret                            +015     6.0 edge\n"
    "  findings:\n"
    "    inverted-branch  ours +003 je / game +003 jne   arms swapped: ours fall +005 = game taken +00E; both arms end in a return: the arms are in the other order\n"
    "        lever: swap the if/else arms or negate the test (`if (!x) B; else A;` <-> `if (x) A; else B;`); the operand order of a short-circuit (`if (a && b)` vs `if (b && a)`); an early `return` in the source vs a single exit/else arm\n"
    "  summary: inverted-branch\n";
static const unsigned char cfgdiff_loop_ours[] = {0x33, 0xC0, 0x3B, 0xC1, 0x7D, 0x05, 0x03, 0xD0, 0x40, 0xEB, 0xF7, 0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3};
static const unsigned char cfgdiff_loop_game[] = {0x33, 0xC0, 0x3B, 0xC1, 0x7D, 0x07, 0x03, 0xD0, 0x40, 0x3B, 0xC1, 0x7C, 0xF9, 0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3};
static const char cfgdiff_loop_report[] =
    "t0   00401000  f_loop  ours 17 bytes / 4 blocks, game 19 bytes / 3 blocks, 3 matched\n"
    "  blocks (ours -> game):  +000->+000  +002->+006 (inv)  +00B->+00D\n"
    "  side  block   size term    successors             mapped   score/how\n"
    "  ours  +000      2 fall    fall:+002              +000     4.33 entry\n"
    "  ours  +002      4 jcc ge  taken:+00B fall:+006   +006     5.0 edge\n"
    "  ours  +006      5 jmp     taken:+002             -        \n"
    "  ours  +00B      6 ret                            +00D     6.5 edge\n"
    "  game  +000      6 jcc ge  taken:+00D fall:+006   +000     4.33 entry\n"
    "  game  +006      7 jcc l   taken:+006 fall:+00D   +002     5.0 edge\n"
    "  game  +00D      6 ret                            +00B     6.5 edge\n"
    "  findings:\n"
    "    other            edges differ (short-circuit / condition structure): ours +000 / game +000 ours ends in fall, game in jcc\n"
    "        lever: compare the two disassemblies (the unit's side-by-side diff)\n"
    "    inverted-branch  ours +004 jge / game +00B jl   arms swapped: ours fall +006 = game taken +006; the arm is a return block: ours places it at the end (jumped to), the game inline\n"
    "        lever: swap the if/else arms or negate the test (`if (!x) B; else A;` <-> `if (x) A; else B;`); the operand order of a short-circuit (`if (a && b)` vs `if (b && a)`); an early `return` in the source vs a single exit/else arm\n"
    "    loop-rotation    ours tests the loop at the top (header +002, latch +006), game at the bottom (header +006, latch +006)\n"
    "        lever: `while (c) {}` vs `if (c) do {} while (c);`, `for` vs `do-while` (e.g. `if (n <= 0) ...; do { } while (++i < n);`)\n"
    "  summary: inverted-branch, loop-rotation, other\n";
static const unsigned char cfgdiff_chain_ours[] = {0x83, 0xF8, 0x01, 0x74, 0x0D, 0x83, 0xF8, 0x02, 0x74, 0x0E, 0x83, 0xF8, 0x03, 0x74, 0x0F, 0x33, 0xC0, 0xC3, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0x14, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0x1E, 0x00, 0x00, 0x00, 0xC3};
static const unsigned char cfgdiff_chain_game[] = {0x83, 0xF8, 0x03, 0x74, 0x19, 0x83, 0xF8, 0x02, 0x74, 0x0E, 0x83, 0xF8, 0x01, 0x74, 0x03, 0x33, 0xC0, 0xC3, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0x14, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0x1E, 0x00, 0x00, 0x00, 0xC3};
static const char cfgdiff_chain_report[] =
    "t0   00401000  f_chain  ours 36 bytes / 7 blocks, game 36 bytes / 7 blocks, 7 matched\n"
    "  blocks (ours -> game):  +000->+000  +005->+005  +00A->+00A  +00F->+00F  +012->+01E  +018->+018  +01E->+012\n"
    "  side  block   size term    successors             mapped   score/how\n"
    "  ours  +000      5 jcc e   taken:+012 fall:+005   +000     4.5 entry\n"
    "  ours  +005      5 jcc e   taken:+018 fall:+00A   +005     6.5 edge\n"
    "  ours  +00A      5 jcc e   taken:+01E fall:+00F   +00A     5.5 edge\n"
    "  ours  +00F      3 ret                            +00F     6.0 edge\n"
    "  ours  +012      6 ret                            +01E     5.5 edge\n"
    "  ours  +018      6 ret                            +018     6.5 edge\n"
    "  ours  +01E      6 ret                            +012     5.5 edge\n"
    "  game  +000      5 jcc e   taken:+01E fall:+005   +000     4.5 entry\n"
    "  game  +005      5 jcc e   taken:+018 fall:+00A   +005     6.5 edge\n"
    "  game  +00A      5 jcc e   taken:+012 fall:+00F   +00A     5.5 edge\n"
    "  game  +00F      3 ret                            +00F     6.0 edge\n"
    "  game  +012      6 ret                            +01E     5.5 edge\n"
    "  game  +018      6 ret                            +018     6.5 edge\n"
    "  game  +01E      6 ret                            +012     5.5 edge\n"
    "  findings:\n"
    "    switch-lowering  compare chains test the same cases in another order: ours [1, 2, 3], game [3, 2, 1]\n"
    "        lever: cases in the order of their values, shared tail after the switch; `switch` vs an if/else chain; case count/density decides table vs chain\n"
    "    block-order      2 mapped block(s) laid out elsewhere: ours +012 = game +01E, ours +018 = game +018\n"
    "        lever: VC8 lays blocks out in source order: move the statement or arm, swap if/else arms, nested if vs early `return`/`continue`\n"
    "  summary: block-order, switch-lowering\n";
static const unsigned char cfgdiff_mirror_ours[] = {0x3B, 0xC1, 0x7C, 0x07, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x5B, 0xC3, 0xBA, 0x02, 0x00, 0x00, 0x00, 0x5B, 0xC3};
static const unsigned char cfgdiff_mirror_game[] = {0x3B, 0xC8, 0x7F, 0x07, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x5B, 0xC3, 0xBA, 0x02, 0x00, 0x00, 0x00, 0x5B, 0xC3};
static const char cfgdiff_mirror_report[] =
    "t0   00401000  f_mirror  ours 18 bytes / 3 blocks, game 18 bytes / 3 blocks, 3 matched\n"
    "  blocks (ours -> game):  +000->+000 (mir)  +004->+004  +00B->+00B\n"
    "  side  block   size term    successors             mapped   score/how\n"
    "  ours  +000      4 jcc l   taken:+00B fall:+004   +000     5.0 entry\n"
    "  ours  +004      7 ret                            +004     6.5 edge\n"
    "  ours  +00B      7 ret                            +00B     6.5 edge\n"
    "  game  +000      4 jcc g   taken:+00B fall:+004   +000     5.0 entry\n"
    "  game  +004      7 ret                            +004     6.5 edge\n"
    "  game  +00B      7 ret                            +00B     6.5 edge\n"
    "  findings:\n"
    "    mirrored-compare ours cmp eax, ecx; jl / game cmp ecx, eax; jg\n"
    "        lever: swap the compared operands (`if (end > frame)` vs `if (frame < end)`)\n"
    "  summary: mirrored-compare\n";
static const unsigned char cfgdiff_missing_ours[] = {0x85, 0xC0, 0x74, 0x07, 0xB9, 0x05, 0x00, 0x00, 0x00, 0x03, 0xCA, 0x5E, 0xC3};
static const unsigned char cfgdiff_missing_game[] = {0x85, 0xC0, 0x74, 0x14, 0xB9, 0x05, 0x00, 0x00, 0x00, 0x03, 0xCA, 0x83, 0xF9, 0x09, 0x75, 0x08, 0xBF, 0x4D, 0x00, 0x00, 0x00, 0x57, 0x03, 0xFA, 0x5E, 0xC3};
static const char cfgdiff_missing_report[] =
    "t0   00401000  f_missing  ours 13 bytes / 3 blocks, game 26 bytes / 4 blocks, 3 matched\n"
    "  blocks (ours -> game):  +000->+000  +004->+004  +00B->+018\n"
    "  side  block   size term    successors             mapped   score/how\n"
    "  ours  +000      4 jcc e   taken:+00B fall:+004   +000     5.0 entry\n"
    "  ours  +004      7 fall    fall:+00B              +004     5.33 edge\n"
    "  ours  +00B      2 ret                            +018     6.0 edge\n"
    "  game  +000      4 jcc e   taken:+018 fall:+004   +000     5.0 entry\n"
    "  game  +004     12 jcc ne  taken:+018 fall:+010   +004     5.33 edge\n"
    "  game  +010      8 fall    fall:+018              -        \n"
    "  game  +018      2 ret                            +00B     6.0 edge\n"
    "  findings:\n"
    "    other            edges differ (short-circuit / condition structure): ours +004 / game +004 ours ends in fall, game in jcc\n"
    "        lever: compare the two disassemblies (the unit's side-by-side diff)\n"
    "    missing-block    game +010..+018 (1 block) has no counterpart in ours: consts 77\n"
    "        lever: likely a source difference: a statement, condition or case ours lacks\n"
    "  summary: missing-block, other\n";
static const unsigned char cfgdiff_tail_ours[] = {0x85, 0xC0, 0x74, 0x0A, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x03, 0xCA, 0x5E, 0x5B, 0xC3, 0xB9, 0x02, 0x00, 0x00, 0x00, 0x03, 0xCA, 0x5E, 0x5B, 0xC3};
static const unsigned char cfgdiff_tail_game[] = {0x85, 0xC0, 0x74, 0x09, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x03, 0xCA, 0xEB, 0x07, 0xB9, 0x02, 0x00, 0x00, 0x00, 0x03, 0xCA, 0x5E, 0x5B, 0xC3};
static const char cfgdiff_tail_report[] =
    "t0   00401000  f_tail  ours 24 bytes / 3 blocks, game 23 bytes / 4 blocks, 3 matched\n"
    "  blocks (ours -> game):  +000->+000  +004->+004  +00E->+00D\n"
    "  side  block   size term    successors             mapped   score/how\n"
    "  ours  +000      4 jcc e   taken:+00E fall:+004   +000     5.0 entry\n"
    "  ours  +004     10 ret                            +004     5.83 edge\n"
    "  ours  +00E     10 ret                            +00D     5.83 edge\n"
    "  game  +000      4 jcc e   taken:+00D fall:+004   +000     5.0 entry\n"
    "  game  +004      9 jmp     taken:+014             +004     5.83 edge\n"
    "  game  +00D      7 fall    fall:+014              +00E     5.83 edge\n"
    "  game  +014      3 ret                            -        \n"
    "  findings:\n"
    "    early-return     ret/epilogue blocks: ours 2 (+004 +00E), game 1 (+014); ours returns from the middle; pops per exit: ours [2, 2], game [2]\n"
    "        lever: a `return` from the middle duplicates the destructor/epilogue at that exit; a single exit at the end does not\n"
    "  summary: early-return\n";
static const CfgDiffCase CFGDIFF_CASES[] = {
    {"inverted", cfgdiff_inverted_ours, cfgdiff_inverted_game, 23, 23, 0x401000, cfgdiff_inverted_report, "inverted-branch"},
    {"loop", cfgdiff_loop_ours, cfgdiff_loop_game, 17, 19, 0x401000, cfgdiff_loop_report, "inverted-branch, loop-rotation, other"},
    {"chain", cfgdiff_chain_ours, cfgdiff_chain_game, 36, 36, 0x401000, cfgdiff_chain_report, "block-order, switch-lowering"},
    {"mirror", cfgdiff_mirror_ours, cfgdiff_mirror_game, 18, 18, 0x401000, cfgdiff_mirror_report, "mirrored-compare"},
    {"missing", cfgdiff_missing_ours, cfgdiff_missing_game, 13, 26, 0x401000, cfgdiff_missing_report, "missing-block, other"},
    {"tail", cfgdiff_tail_ours, cfgdiff_tail_game, 24, 23, 0x401000, cfgdiff_tail_report, "early-return"},
};
