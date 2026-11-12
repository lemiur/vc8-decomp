// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* frame: stack-frame layouts of one function, ours against the reference's, read from the machine code of both. The
 * prologue (saved registers, frame size, frame pointer, alignment, /GS cookie, EH registration) and every stack slot
 * an instruction reads, writes or takes the address of, by its offset from the entry ESP; the slot map pairs the slots
 * of the two sides by the instructions the block alignment of cfg_diff pairs. The module has no command line:
 * unitcmp --frame reaches it (frame_slots.h). */
#pragma once
#include "dk/dk.h"

/* The reference image: the path of the executable (its import table is read to decide which imports pop their
 * arguments), read(va, n) with slice semantics (fewer bytes near the end of the image), the .text bounds, and the
 * import libraries whose functions are cdecl (shell patterns, "*" any run of characters, matched case-insensitively
 * against the library's name; none given: "msvcr*", the C runtime of the toolchain). Any other import is stdcall. */
typedef struct DkFrameRetail {
    const char *path;
    DkStr (*read)(void *ctx, i64 va, i64 n);
    void *ctx;
    i64 text_start, text_end;
    const char *const *cdecl_dlls;
    size_t n_cdecl_dlls;
} DkFrameRetail;

/* One relocation of our object's code: the word at `offset` resolved to the reference's `target` (has_target false: None). */
typedef struct {
    i64 offset;
    bool has_target;
    i64 target;
} DkFrameReloc;

typedef enum { DK_FRAME_ENTRY, DK_FRAME_ALIGNED } DkFrameBase;

/* One instruction touching a slot: its offset from the function's start, the access size (0 for a lea) and the
 * kind ('r' read, 'w' write, 'a' address taken; a read-modify-write is 'w'). In code order. */
typedef struct {
    i64 at;
    u32 size;
    char kind;
} DkFrameAccess;

typedef struct {
    DkFrameBase base;
    i64 offset;
    u64 size_mask[4]; /* the set of access sizes (0..255): bit n of the 256-bit mask */
    i64 reads, writes, addrs;
    bool indexed;
    DkFrameAccess *acc; /* every access, in code order; acc[0] is the first use */
    size_t n_acc;
} DkFrameSlot;

typedef struct DkFrame {
    DkFrameSlot **slots;  /* in the order the code first touches them */
    size_t n_slots;
    DkStr saved[8];       /* registers pushed by the prologue */
    size_t n_saved;
    i64 locals;           /* sub esp / __chkstk in the prologue */
    bool has_frame_pointer;
    i64 frame_pointer;    /* ESP offset EBP was set to */
    bool has_align;
    i64 align;            /* and esp, -n */
    bool has_cookie;
    DkFrameBase cookie_base;
    i64 cookie_offset;    /* the /GS cookie's slot */
    bool eh;              /* EH registration */
    i64 unknown_calls;    /* calls whose pops were guessed */
    DkIMap *index;        /* internal: (base, offset) -> slot */
} DkFrame;

/* The bytes a function of the reference pops on return (`ret n`); false when unknown. */
bool dk_frame_callee_pops(const DkFrameRetail *retail, bool has_target, i64 target, i64 *pops);

/* The Frame of a function's bytes at base. has_relocs false: the reference's own bytes, whose call operands are read
 * as they are; relocs: the resolved relocations of our object's code. retail may be NULL. */
DkFrame *dk_frame_analyse(DkArena *a, DkStr code, i64 base, const DkFrameRetail *retail,
                          const DkFrameReloc *relocs, size_t n_relocs, bool has_relocs);

/* What the report needs of one compared function. */
typedef struct {
    const char *build;           /* the target's name */
    i64 address;
    const char *annotation_name; /* the source name, "" or NULL when none */
    const char *function_name;   /* the compiled symbol */
    DkStr code;                  /* our bytes */
    const DkFrameReloc *relocs;
    size_t n_relocs;
    DkStr game;                  /* the reference's bytes: p == NULL or n == 0 is "not available" */
} DkFrameResult;

/* The report (the two prologues side by side, then one row per slot) appended to out. */
void dk_frame_format(DkBuf *out, const DkFrameResult *result, const DkFrameRetail *retail);
/* The same report on stdout. */
void dk_frame_print(const DkFrameResult *result, const DkFrameRetail *retail);

extern const char dk_frame_doc[];

/* ---- the slot map: ours against the reference's, paired by the aligned instructions ------------------------- */

/* A name for the range [lo, hi) of an ebp-style frame (arguments from +8, locals below 0): a local or parameter. */
typedef struct {
    i64 lo, hi;
    const char *name;
} DkFrameName;

/* One pairing: a slot of ours and the reference's slot the aligned instructions touch for it (either may be NULL: a
 * slot with no counterpart); votes is the weight of the aligned accesses that agree. */
typedef struct {
    const DkFrameSlot *ours, *game;
    i64 votes;
} DkFramePair;

/* insn_map is {our instruction offset: the reference's instruction offset} (the .i of a DkIMap, offsets from the
 * function's start: the alignment cfg_diff_insn_map gives). Every access of ours whose instruction has a counterpart
 * votes for the reference slot that counterpart touches (the same kind weighs more); the slots are then paired one to
 * one, most votes first, the same offset first on a tie. The rows: ours (the entry base from the top of the frame
 * down, the aligned base after) with their reference slot, then the reference's unpaired slots. Returns the row
 * count. */
size_t dk_frame_pair(DkArena *a, const DkFrame *ours, const DkFrame *game, const DkIMap *insn_map,
                     DkFramePair **rows);

/* The report appended to out: the table, then the summary (slots, paired, differing rows, swaps). names may be
 * empty (names of our locals, carried across the pairing). */
void dk_frame_slotmap(DkBuf *out, const DkFrame *ours, const DkFrame *game, const DkIMap *insn_map,
                      const DkFrameName *names, size_t n_names);
