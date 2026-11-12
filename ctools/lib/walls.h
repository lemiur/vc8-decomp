// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* walls: the structural classification of a compared function that does not match, shared by the diagnostics
 * (unitcmp, cfg_diff's batch, residue). A result that is not a MATCH is put behind one wall, from the two
 * disassemblies (ours and the reference's, capstone, x86 32-bit):
 *
 *   match         the bytes and every relocation agree;
 *   referent      the bytes agree, a relocation points elsewhere or is unresolved (REFERENT, UNRESOLVED);
 *   call-set      the multisets of call and tail-jump targets differ (one target called a different number of times
 *                 is control-flow instead: a duplicated or merged tail);
 *   control-flow  the ordered sequence of conditional jumps, jmp and ret differs, or the same branches go elsewhere;
 *   body          other instructions differ (another multiset of non-move mnemonics, or more than two instructions
 *                 more or fewer);
 *   register      the same calls, branches and instructions: register allocation or scheduling;
 *   error         no result to classify (ERROR, MISSING).
 *
 * The reference's window of bytes is cut at the function's end (a ret or jmp followed by padding, or by the next
 * symbol) and before a switch table (a jump table or a byte index table after the code: data, not instructions).
 * Our call targets come from the result's relocation checks: a resolved relocation names the address the reference
 * should hold, an unresolved one its symbol ("sym:<name>").
 *
 * Instruction vectors are heap-owned (dk_wall_insns_free); strings live in the calling thread's dk_arena(). */
#pragma once
#include "dk/disasm.h"
#include "dk/map.h"
#include "project.h"

/* The walls from best to worst, and the weight each gives a closeness score (unknown walls: dflt). */
extern const char *const DK_WALL_ORDER[7];
int dk_wall_rank(const char *wall); /* the index in DK_WALL_ORDER; -1 when unknown */
double dk_wall_weight(const char *wall, double dflt);

/* ---- disassembly ---- */
/* The instructions of code at base. A prefix view (dk_wall_code_only) shares the storage: n is the view's count,
 * total the count to release. */
typedef struct {
    cs_insn *v;
    size_t n;
    size_t total;
} DkInsns;
DkInsns dk_wall_disasm(DkStr code, u64 base);
void dk_wall_insns_free(DkInsns *insns);

/* ---- call and branch tokens ---- */
/* A call or tail-jump target: an absolute address (is_int), or text: "sym:<name>", "indirect", "tail:0x%X",
 * "tail:sym:<name>". */
typedef struct {
    bool is_int;
    u64 n;
    DkStr s;
} DkCallToken;

/* The result's relocation checks by offset (value .p: the DkRefCheck; a later check of one offset replaces an
 * earlier one). dk_imap_free when done. */
DkIMap *dk_wall_verdicts(const DkResult *r);
/* The call token of ins (code at base, size bytes): a call (direct, or "indirect"), or a jmp leaving the function (a
 * tail call); false for any other instruction. verdicts: our side's relocation checks (dk_wall_verdicts); NULL for
 * the reference's bytes, whose operands are read as they are. */
bool dk_wall_call_token(const cs_insn *ins, u64 base, const DkIMap *verdicts, size_t size, DkCallToken *out);
DkStr dk_wall_tok_text(DkArena *a, const DkCallToken *t); /* "0x%X" for an address, else the text */
/* The target of a direct jmp or jcc (E9, EB, 0F 8x, 7x) whose operand reads as an address. */
bool dk_wall_target_of(const cs_insn *ins, u64 *target);
/* Whether the mnemonic is move-like: mov* (not movzx/movsx), push, pop, lea, nop, xchg, int3, x87 loads and stores
 * (fld, fst, fstp, fild, fist, fistp, fxch). */
bool dk_wall_is_move(const char *mnemonic);

/* One ret or jump, in order. target: the number of non-move instructions before the jump's target (>= 0), or one of
 * the markers. */
enum { DK_WALL_TARGET_NONE = -1, DK_WALL_TARGET_OUT = -2, DK_WALL_TARGET_INDIRECT = -3 };
typedef struct {
    char mnemonic[CS_MNEMONIC_SIZE];
    i64 target;
} DkBranch;
typedef DK_VEC(DkBranch) DkBranchVec;
/* Every ret and jump of insns; without targets every target is DK_WALL_TARGET_NONE. Heap-owned (dk_vec_free). */
DkBranchVec dk_wall_branch_tokens(const DkInsns *insns, bool targets);

/* ---- switch tables and the reference's window ---- */
/* The offset of the first switch table inside the size bytes at base: a `jmp dword ptr [reg*4 + table]` or a
 * `movzx reg, byte ptr [reg + index]` whose table lies after the instruction and inside the bytes. ours: the result
 * whose relocation checks place our tables (our bytes); NULL: the bytes are the reference's, read from the operand. */
bool dk_wall_table_start(const DkInsns *insns, u64 base, size_t size, const DkResult *ours, i64 *cut);
/* A prefix view of insns up to the first switch table (shares the storage). */
DkInsns dk_wall_code_only(const DkInsns *insns, u64 base, size_t size, const DkResult *ours);
/* The reference's bytes of the whole function (a view into the result or the image): the result's reference bytes,
 * or the sized symbol's extent from im, trailing int3 dropped; cut before a switch table; when they do not end in a
 * ret or jmp (or are shorter than ours), read on from im to the first ret or jmp followed by padding (CC, 90) or by
 * a symbol start. im may be NULL. */
DkStr dk_wall_reference_window(const DkResult *r, const DkImage *im);

/* ---- classification ---- */
typedef struct {
    i64 size;                      /* our size */
    i64 differ;                    /* differing bytes (dk_result_differ) */
    bool has_reference_size;
    i64 reference_size;            /* a sized symbol's size */
    bool classified;               /* dk_wall_classify ran (the members below are set) */
    i64 insns_ours, insns_reference;
    bool has_first_difference;
    i64 first_difference;
    i64 reference_window;
    bool same_mnemonics;
    DkCzVec calls_only_ours, calls_only_reference; /* up to five token texts each */
} DkWallInfo;

/* The wall of a result that is DIFF or SIZE: "call-set", "control-flow", "body" or "register". */
const char *dk_wall_classify(const DkResult *r, const DkImage *im, DkWallInfo *info);

typedef struct {
    DkStatus status;
    double close;                  /* (size - differing bytes) / size, in percent, one decimal */
    const char *wall;
    DkWallInfo info;
} DkBuildWall;
/* The status, closeness, wall and details of one result (r NULL: error). im: the target's image (may be NULL). */
DkBuildWall dk_build_wall(const DkResult *r, const DkImage *im);
