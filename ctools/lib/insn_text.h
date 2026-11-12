// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* insn_text: the instruction text of a compared function, shared by the diagnostics (unitcmp --diff, residue,
 * cfg_diff): each instruction's capstone text with the relocation it holds as a note, a normal form that hides
 * addresses (so a moved global or a relocated placeholder compares equal), the differing bytes of a result, and the
 * side-by-side diff of ours against the reference.
 *
 * Every string lives in the arena given. */
#pragma once
#include "project.h"

/* One row: an instruction (offset from the function's start, size, "<mnemonic> <operands>") or, last, the bytes the
 * disassembler could not decode ("(N bytes of data)"). note: the symbol of a relocation inside the instruction (with
 * "+0x%X" for a non-zero addend), "" when none. */
typedef struct {
    u32 offset, size;
    DkStr text, note;
} DkInsnText;
typedef DK_VEC(DkInsnText) DkInsnTextVec;

/* The rows of code disassembled at base (x86, 32-bit). relocs may be NULL. The vector is heap-owned (dk_vec_free);
 * its strings live in a. */
DkInsnTextVec dk_insn_disassemble(DkArena *a, DkStr code, u32 base, const DkReloc *relocs, size_t n_relocs);

/* The text with its addresses (0x followed by three or more hex digits) as IMM; relocated: the 0 placeholder of an
 * instruction that holds a relocation becomes IMM too. */
DkStr dk_insn_normalise(DkArena *a, DkStr text, bool relocated);

/* The offsets where a result's bytes differ: over the common length of ours and the reference, the bytes no
 * relocation of ours covers (4 bytes from each relocation's offset) and that differ; then every offset of the longer
 * side past the shorter one. Ascending; *n their count. NULL (with *n 0) when none differs. */
u32 *dk_result_differ(DkArena *a, const DkResult *r, size_t *n);

/* The side-by-side diff of a result (ours left, the reference right), aligned on the normalised instruction texts:
 * a header line, a column line, then one row per instruction. Marks: ' ' equal, '!' equal text but a raw byte
 * differs, '-' only ours, '+' only the reference. The reference's operands are named through im's symbols and
 * imports (im may be NULL). width: the left column (default 58 when 0). max_rows > 0 keeps only the first max_rows
 * rows that are not ' ' (the context of an equal row is dropped then); 0 prints every row. */
typedef struct {
    int width;
    size_t max_rows;
    const char *target_name; /* printed in the header; NULL: the result's target index */
} DkInsnDiffOpts;
DkStr dk_insn_diff(DkArena *a, const DkResult *r, const DkImage *im, const DkInsnDiffOpts *o);
