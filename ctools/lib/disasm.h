// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* disasm: reference-image disassembly and cross references for any configured target.
 *
 * A DkDisasm is a view of one target's PE32 image: its sections, base relocations, import slots and the target's
 * symbol sources (names and, when the sources give them, sizes). Function bounds, notes beside operands, call and
 * jump cross references, jmp thunks and dword dumps are all computed from that view; nothing is project specific.
 * Names come from the symbol sources (TSV, PDB or map), annotated addresses from the units' annotations
 * (dk_annotations): a function or declaration address is a known function start, and every annotation names its
 * address in a dword dump. Without symbol sources the tool still decodes, bounds a function by its int3 padding and
 * finds cross references.
 *
 * Printing functions append text to a DkBuf. A failure (an address outside the image, a bad option) is returned as
 * false with *err set. A view is for one thread: known_starts, the annotation names and the thunk list are computed
 * on first use. Every string handed out lives as long as the view's arena (the project's). */
#pragma once
#include "dk/dk.h"
#include "project.h"

typedef struct DkDisasm DkDisasm;

/* Opens target `target` of p: its image is read and checked against the pinned sha256 (dk_target_image), its
 * symbols loaded (dk_project_symbols). The code section is ".text", else the first executable section. */
DkDisasm *dk_disasm_open(DkProject *p, int target, DkErr *err);
const char *dk_disasm_target_name(const DkDisasm *d);
u32 dk_disasm_image_base(const DkDisasm *d);

/* ---- relative branches ---------------------------------------------------------------------------------------- */
typedef enum { DK_DISASM_CALL = 1, DK_DISASM_JMP = 2, DK_DISASM_JCC = 4, DK_DISASM_ALL = 7 } DkDisasmKind;
typedef struct DkDisasmSite {
    u32 site;
    DkDisasmKind kind;
} DkDisasmSite;
typedef DK_VEC(DkDisasmSite) DkDisasmSiteVec;
/* The rel32 branch sites of the code section that reach each of `targets` (kinds: a mask of DkDisasmKind; E8 call,
 * E9 jmp, 0F 80..8F jcc), as {target: DkDisasmSiteVec* in .p}, sites sorted by (site, kind name); only the targets
 * found are keys, in first-found order (calls, then jmps, then each jcc opcode). Allocated from the view's arena. */
DkIMap *dk_disasm_rel32_sites(const DkDisasm *d, const DkU32Vec *targets, unsigned kinds);
const char *dk_disasm_kind_name(DkDisasmKind kind); /* "call", "jmp" or "jcc" */

/* ---- function bounds -------------------------------------------------------------------------------------------- */
/* The addresses known to start a function, sorted: every function and declaration annotation of this target, and
 * the symbols that a `call rel32` reaches or a relocated word holds (the latter two only when the target has
 * symbols). */
const DkU32Vec *dk_disasm_known_starts(DkDisasm *d);

#define DK_DISASM_BOUNDS_LIMIT 0x10000u
typedef struct DkDisasmBounds {
    u32 size;
    const char *why; /* "to the next known start %08X" or "to the int3 padding" */
} DkDisasmBounds;
/* From `address` to the int3 padding that follows a ret or jmp, or to the next known start, at most `limit` bytes. */
bool dk_disasm_function_bounds(DkDisasm *d, u32 address, u32 limit, DkDisasmBounds *out, DkErr *err);

/* Up to the int3 padding that follows a ret or jmp (the whole read when none), reading at most `limit` bytes (cut
 * to the section's data). */
#define DK_DISASM_GUESS_LIMIT 0x2000u
bool dk_disasm_guess_size(const DkDisasm *d, u32 address, u32 limit, u32 *size, DkErr *err);

/* The symbol that contains va (a sized symbol; an unsized one holds only its own address). */
bool dk_disasm_containing_function(const DkDisasm *d, u32 va, u32 *start, const char **name);

/* ---- listings --------------------------------------------------------------------------------------------------- */
/* "; <target> <address>  <size> bytes  <name>", then one line per instruction: address, the bytes (show_bytes), the
 * text and "  ; note" where an operand's hex target (5 digits or more) is a symbol, an import thunk, an import slot
 * (__imp_<name>), the image's security cookie or inside a function (name+0xOFF, on jumps and calls). A size of 0 or
 * less decodes nothing. */
bool dk_disasm_function(DkDisasm *d, u32 address, i64 size, bool show_bytes, DkBuf *out, DkErr *err);

/* The callers (call rel32), jumps and conditional jumps to address, and the relocated words that hold it. */
bool dk_disasm_xrefs(DkDisasm *d, u32 address, DkBuf *out, DkErr *err);

/* A jmp thunk at va: `jmp rel32` (form "jmp") or `mov ecx, imm32; jmp rel32` (form "mov ecx; jmp", *this_ set). */
bool dk_disasm_jmp_thunk(const DkDisasm *d, u32 va, const char **form, u32 *target, u32 *this_, bool *has_this);

typedef struct DkDisasmThunk {
    u32 va;
    const char *form;
    u32 target;
    u32 this_;
    bool has_this;
    DkU32Vec refs;  /* the absolute reference sites (relocated words) */
    DkU32Vec calls; /* the call rel32 sites */
    bool known;     /* a symbol or an annotation names va */
} DkDisasmThunk;
typedef DK_VEC(DkDisasmThunk) DkDisasmThunkVec;
/* The jmp thunks of the code section that a relocated word or a `call rel32` reaches, in address order; without
 * `everything`, only those no symbol and no annotation names. start / end of 0 are the section's bounds. */
DkDisasmThunkVec dk_disasm_hidden_thunks(DkDisasm *d, u32 start, u32 end, bool everything);
void dk_disasm_print_thunks(DkDisasm *d, u32 start, u32 end, bool everything, DkBuf *out);

/* `count` dwords from address: the offset and slot index, the value, "reloc" where a base relocation covers the word,
 * and the name the value points at (annotation, symbol, import thunk, import slot, name+0xOFF, or its section). */
bool dk_disasm_words(DkDisasm *d, u32 address, u32 count, DkBuf *out);

/* The symbols whose name matches the regular expression (Python syntax, case-insensitive search): "%08X  %6d  name"
 * per symbol in address order. */
bool dk_disasm_find_names(const DkDisasm *d, const char *pattern, DkBuf *out, DkErr *err);

/* ---- command line ----------------------------------------------------------------------------------------------- */
int dk_disasm_main(int argc, char **argv);
