// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* xmatch: find a function of one executable in another by masked bytes. Four parts:
 *   - images (DkXmImage): an executable as a search target, over the PE reader (pe.h) and a file view (fs.h);
 *   - masked functions (DkXmFn): from caller data (dk_xm_fn_new) or from an image;
 *   - exact masked search of a function in an image;
 *   - instruction tokens (a length decoder of its own) and their similarity (difflib.h).
 *
 * Addresses are VAs (image base + RVA) unless a name says RVA. Memory: images, functions, hits, token arrays and
 * blocks are heap objects released by their _free / _close functions (or free() where a comment says so).
 * Thread safety: every query is safe from several threads on one open image; the lazy structures (call index,
 * probable starts, the 4-byte key index, the relocation-gap index) are built once, on first use, under INIT_ONCE.
 * Functions (DkXmFn) are immutable once made and can be shared between threads. */
#pragma once
#include "dk/dk.h"
#include "dk/pe.h"

/* ================================================================================================== images
 * Executable sections are the sections with IMAGE_SCN_MEM_EXECUTE whose raw data is non-empty and whose first
 * 1 MiB has a Shannon entropy above 2.0 bits per byte; data sections are all the others (the non-executable ones).
 * Section bytes are the raw data (SizeOfRawData from the adjusted PointerToRawData, clipped to the file
 * get_data()); spans are in pe.h's section order (by VirtualAddress). Relocations are the sorted, distinct VAs of
 * the HIGHLOW base relocations. */
typedef struct DkXmImage DkXmImage;

typedef struct {
    const char *name; /* the section name (NUL-terminated) */
    u32 va;
    const u8 *data;
    size_t len;
} DkXmSpan;

enum { DK_XM_SPANS_EXEC = 1, DK_XM_SPANS_DATA = 2, DK_XM_SPANS_ALL = 3 };

/* Open a PE32 (machine 0x14C) file; NULL with *err (heap, free(); err may be NULL) on failure. */
DkXmImage *dk_xm_image_open(const char *path, char **err);
/* Wrap a parsed PE whose bytes outlive the image (nothing is copied; the image does not free it). */
DkXmImage *dk_xm_image_from_pe(const DkPe *pe);
void dk_xm_image_close(DkXmImage *img);

const DkPe *dk_xm_image_pe(const DkXmImage *img);
u32 dk_xm_image_base(const DkXmImage *img);
u32 dk_xm_image_size(const DkXmImage *img); /* SizeOfImage */

size_t dk_xm_image_exec_count(const DkXmImage *img);
const DkXmSpan *dk_xm_image_exec(const DkXmImage *img, size_t i); /* NULL out of range */
size_t dk_xm_image_data_count(const DkXmImage *img);
const DkXmSpan *dk_xm_image_data(const DkXmImage *img, size_t i);

bool dk_xm_image_in_exec(const DkXmImage *img, u32 a);  /* inside an exec section's raw data */
bool dk_xm_image_in_image(const DkXmImage *img, u32 a); /* base <= a < base + SizeOfImage */
/* Bytes at a from the exec section holding a: *got = min(n, bytes to that section's end); NULL (*got 0) when a is
 * not in an exec section. */
const u8 *dk_xm_image_read(const DkXmImage *img, u32 a, size_t n, size_t *got);

bool dk_xm_image_has_relocs(const DkXmImage *img);
bool dk_xm_image_is_reloc(const DkXmImage *img, u32 a);
const u32 *dk_xm_image_relocs(const DkXmImage *img, size_t *count); /* sorted HIGHLOW VAs */

/* First import by name with this name (any dll, imports by ordinal never match): its IAT slot VA, 0 when none. */
u32 dk_xm_image_import(const DkXmImage *img, const char *name);

/* One `jmp rel32` thunk hop: when dest holds E9 rel32 whose target is in an exec section, that target; else dest. */
u32 dk_xm_image_follow(const DkXmImage *img, u32 dest);

/* Call index: every E8 in an exec section whose rel32 target lands in the same section, keyed by the followed
 * target. Returns the number of call sites of `dest` (ascending in *sites, valid while the image is open). */
size_t dk_xm_image_callers(const DkXmImage *img, u32 dest, const u32 **sites);
/* All distinct call-index keys (sorted). */
const u32 *dk_xm_image_call_targets(const DkXmImage *img, size_t *count);

/* Probable function starts (xmatch's rule): call-index targets that are 16-aligned or have >= 3 call sites;
 * 16-aligned addresses right after a run of CC (not at the section end); 16-aligned exec addresses held by a
 * base-relocated word (in the first exec-or-data span that holds the word). Sorted, distinct. */
const u32 *dk_xm_image_starts(const DkXmImage *img, size_t *count);
/* The last start <= a; false when none. */
bool dk_xm_image_containing(const DkXmImage *img, u32 a, u32 *start);
/* xmatch extent(start, want): bytes from start to the next start (or start + 2*want), capped at
 * max(2*want, want+256), trailing CC stripped when longer than want. Returns the length; *p the bytes. */
size_t dk_xm_image_extent(const DkXmImage *img, u32 start, size_t want, const u8 **p);

/* Every occurrence (overlapping, ascending per span, spans in order, exec before data) of pat in the chosen spans
 * (DK_XM_SPANS_*), at most `limit`; returns the count written to out. An empty pattern matches at every position
 * and at each span's end (bytes.find(b"")). */
size_t dk_xm_image_find_all(const DkXmImage *img, const void *pat, size_t n, int spans, size_t limit, u32 *out);

/* ---- the indexes the search uses (public for tools that want them) ---- */
/* Positions p (offsets into exec span `sec`, p + 4 <= len) whose 4 bytes, read little-endian, equal key;
 * ascending. Builds the span's index on first use. */
size_t dk_xm_image_key_positions(const DkXmImage *img, size_t sec, u32 key, const u32 **pos);
/* Base relocations in executable sections (MEM_EXECUTE, any entropy, ".bind" excluded, within VirtualSize), as
 * sorted RVAs. */
const u32 *dk_xm_image_text_relocs(const DkXmImage *img, size_t *count);
/* Indices i of text_relocs with (R[i+1]-R[i], R[i+2]-R[i+1]) == (g1, g2), ascending. */
size_t dk_xm_image_reloc_gap_lookup(const DkXmImage *img, u32 g1, u32 g2, const u32 **idx);

/* =============================================================================================== functions
 * A masked function owns copies of its bytes and names; mask[i] == 1 marks a wildcard byte. */
typedef struct {
    u32 offset;      /* in the function */
    u32 size;        /* 2 for IMAGE_REL_I386_SECTION (10), else 4 */
    const char *sym; /* the symbol's name, "?" when the relocation names no symbol (an auxiliary slot) */
    u16 type;        /* DK_REL_I386_* (the retail patterns have none) */
    u32 addend;
} DkXmFnReloc;

typedef struct {
    char *name;
    char *unit;
    u8 *code;
    u8 *mask;            /* 1 = wildcard */
    size_t size;
    DkXmFnReloc *relocs; /* by offset (the COFF function's order) */
    size_t n_relocs;
    u32 align;           /* required start alignment (1 = any) */
    int ndup;            /* the number of objects defining the name (callers count; 1 when made) */
} DkXmFn;

/* A function from caller data: copies code, relocations and names; every relocated field is masked (size from the
 * relocation entry). `sym` NULL becomes "?". align 0 is 1. NULL when the code is empty. An adapter that reads COFF
 * objects converts its functions with this. */
DkXmFn *dk_xm_fn_new(const char *name, const char *unit, const u8 *code, size_t size, const DkXmFnReloc *relocs,
                     size_t n_relocs, u32 align);
/* A retail pattern : the exec bytes at addr (size or fewer at a section end), the
 * base-relocation sites masked (4 bytes each, sites in [addr, addr+len-3)), and the rel32 of every direct
 * call/jmp/jcc of length >= 5 whose target leaves [addr, addr+size) masked, decoding from the start
 * until the first invalid instruction. No relocations; align 16 (search_plain ignores it). Named "retail_XXXXXXXX",
 * unit "retail". NULL when addr is not in an exec section. */
DkXmFn *dk_xm_fn_from_image(const DkXmImage *img, u32 addr, size_t size);
void dk_xm_fn_free(DkXmFn *fn);

/* Relocation fingerprint (the fingerprint): the sorted offsets of the DIR32 (type 6) relocations. Returns their
 * count; *offs heap (free()). The search is dk_xm_reloc_fp_search. */
size_t dk_xm_fn_fingerprint(const DkXmFn *fn, u32 **offs);

/* ================================================================================================== search
 * Matching scans each exec span left to right with the pattern "unmasked bytes
 * literal, masked bytes any": matches do not overlap (a match starting inside the previous kept match is
 * skipped), and that selection is made before any alignment or relocation filtering. Per pattern the unmasked
 * 4-byte window with the fewest positions in the key index is the anchor; a pattern with no unmasked 4-byte window
 * is scanned linearly. */
#define DK_XM_MAX_HITS 64

typedef struct {
    const char *sym; /* the relocation's symbol name (points into the DkXmFn) */
    u32 addr;        /* the address it resolves to */
} DkXmResolved;

typedef struct {
    u32 addr;
    DkXmResolved *res; /* in first-relocation order (first-use order) */
    size_t n_res;
} DkXmHit;

/* xmatch resolve(): the symbol addresses of a placement of fn at `start`, or false when a relocation is
 * implausible (REL32: the followed destination is not in an exec section; DIR32: the word is outside the image, or
 * the image has base relocations and the site is not one; one symbol resolving to two addresses). Only 4-byte REL32
 * (20) and DIR32 (6) relocations take part. res/n_res may be NULL; *res is heap (free()). */
bool dk_xm_resolve(const DkXmImage *img, const DkXmFn *fn, u32 start, DkXmResolved **res, size_t *n_res);
/* xmatch exact_search(): masked matches in exec spans with start % fn->align == 0 and resolve() plausible, at most
 * DK_XM_MAX_HITS. Returns the count; *hits heap (dk_xm_hits_free); hits may be NULL to count only. */
size_t dk_xm_exact_search(const DkXmImage *img, const DkXmFn *fn, DkXmHit **hits);
void dk_xm_hits_free(DkXmHit *hits, size_t n);
/* stops_witness search_plain(): masked matches only (no alignment, no resolve), at most `limit`, into out. */
size_t dk_xm_search_plain(const DkXmImage *img, const DkXmFn *fn, size_t limit, u32 *out);
/* stops_witness exact_at(): the exec bytes at addr cover the whole function, its unmasked bytes are equal, and
 * resolve() is plausible. */
bool dk_xm_exact_at(const DkXmImage *img, const DkXmFn *fn, u32 addr);
/* stops_witness first_diff(): the first offset (over the bytes available at addr) where an unmasked byte differs;
 * -1 when none differs (or addr is not in an exec span). */
long dk_xm_first_diff(const DkXmImage *img, const DkXmFn *fn, u32 addr);
/* Fingerprint search: starts S (VAs) where the image's text relocations contain S+o1..S+ok and no other in [S, S+len),
 * with S % align == 0 (on the RVA). Needs k >= 3 offsets (0 otherwise). At most `max` hits into out; returns the
 * number found (may exceed max). */
size_t dk_xm_reloc_fp_search(const DkXmImage *img, const u32 *offs, size_t k, u32 len, u32 align, u32 *out,
                              size_t max);

/* ============================================================================================== similarity
 * Tokens (xmatch tokenise / our_tokens / target_tokens). The code is decoded with dk_xm_x86_decode from offset 0
 * until the first invalid instruction:
 *  - ours (from an DkXmFn): the masked (relocated) bytes are zeroed before decoding;
 *  - target (from an image): a 4-byte displacement or immediate whose value lies in
 *    the image, or whose address is a base relocation, is zeroed.
 * A direct relative call/jmp/jcc/jecxz (not loop*) whose target (from offset 0) is > 9 becomes a branch token (its
 * class, and "inside" when target < length and, for ours, none of its bytes is masked). Far call/jmp with a
 * selector > 9 is (class, outside). A relative branch with a target 0..9 (capstone prints it in decimal, so
 * xmatch did not see it as a branch) is a token of (class, target). Every other instruction is a 63-bit FNV-1a hash
 * of its (zeroed) bytes. Tokens are byte hashes, not text, so two encodings of one instruction text (83 C0 01 and
 * 05 01 00 00 00, "add eax, 1") are two tokens.
 *
 * Similarity: SequenceMatcher(None, a, b, autojunk=False).ratio() (difflib.h), 0.0 when either is empty
 * (similarity()). Pure functions on caller memory: thread-safe. */
typedef struct {
    u64 *t; /* heap */
    size_t n;
} DkXmTokens;

typedef struct {
    u32 a, b, size;
} DkXmMatchBlock;

/* tokenise(): `zero` (nullable, n bytes, nonzero = zero that byte) are the masked offsets; `start` the address of
 * code[0] (the target's base-relocation test); is_ours selects the rules above; img is needed for !is_ours. */
DkXmTokens dk_xm_tokenise(const u8 *code, size_t n, const u8 *zero, u32 start, bool is_ours,
                            const DkXmImage *img);
DkXmTokens dk_xm_tokens_ours(const DkXmFn *fn);                                  /* our_tokens */
DkXmTokens dk_xm_tokens_target(const DkXmImage *img, u32 start, size_t want); /* target_tokens */
void dk_xm_tokens_free(DkXmTokens *t);

/* xmatch similarity() over token arrays. */
double dk_xm_similarity(const u64 *a, size_t na, const u64 *b, size_t nb);
/* SequenceMatcher(None, a, b, autojunk=False).ratio() over byte strings (1.0 when both are empty). */
double dk_xm_bytes_ratio(const u8 *a, size_t na, const u8 *b, size_t nb);
/* get_matching_blocks() over byte strings / token arrays, the (na, nb, 0) sentinel included; *blocks heap
 * (free()). */
size_t dk_xm_bytes_matching_blocks(const u8 *a, size_t na, const u8 *b, size_t nb, DkXmMatchBlock **blocks);
size_t dk_xm_tokens_matching_blocks(const u64 *a, size_t na, const u64 *b, size_t nb, DkXmMatchBlock **blocks);

/* ---- the x86-32 instruction length decoder of the tokens and the retail patterns ----
 * Covers the one-byte map, 0F, 0F 38 and 0F 3A (MMX/SSE/SSE2..SSE4 forms), x87, the prefixes 66/67/F2/F3/F0 and the
 * segment overrides, ModRM/SIB/displacement/immediate sizes (16-bit addressing under 67). It reports the fields the
 * matcher needs; it does not produce text. It stops where compiler output stops:
 * VEX/XOP/EVEX (C4/C5/8F/62 register forms), LEA/BOUND/LES/LDS with a register operand,
 * undefined 0F opcodes, FF /7, FE /2../7, RTM (C6/C7 F8), LOCK on an instruction that cannot take it... are invalid.
 * The vendored capstone (disasm.h) decodes several of those families and rejects a few this decoder accepts (0F
 * A6/A7, some 0F AE register forms), and is about 10 times slower here, so this decoder is kept. */
/* Branch classes (DkXmInsn.branch). Conditional jumps are DK_XM_BR_JCC + the condition code (the low nibble of
 * 7x / 0F 8x: jo jno jb jae je jne jbe ja js jns jp jnp jl jge jle jg). */
enum {
    DK_XM_BR_NONE = 0,
    DK_XM_BR_CALL = 1,    /* E8 rel */
    DK_XM_BR_JMP = 2,     /* E9 / EB rel */
    DK_XM_BR_LOOP = 3,    /* E2 */
    DK_XM_BR_LOOPE = 4,   /* E1 */
    DK_XM_BR_LOOPNE = 5,  /* E0 */
    DK_XM_BR_JECXZ = 6,   /* E3 (jcxz under 67) */
    DK_XM_BR_CALLFAR = 7, /* 9A ptr16:32 (direct, absolute; no relative target) */
    DK_XM_BR_JMPFAR = 8,  /* EA ptr16:32 */
    DK_XM_BR_JCC = 16
};

typedef struct {
    u8 len;          /* total length in bytes (1..15) */
    u8 disp_off;     /* offset of the displacement field (ModRM disp or moffs), 0 when none */
    u8 disp_size;    /* 0, 1, 2 or 4 */
    u8 imm_off;      /* offset of the last immediate field (capstone's imm_offset), 0 when none */
    u8 imm_size;     /* its size */
    u8 branch;       /* DK_XM_BR_* */
    bool rel;        /* a direct relative branch (call/jmp/jcc/loop/jecxz): target is valid */
    u8 rel_off;      /* offset of the relative field */
    u8 rel_size;     /* 1, 2 or 4 */
    u8 opcode;       /* the last opcode byte */
    u8 map;          /* 0 one-byte, 1 = 0F, 2 = 0F 38, 3 = 0F 3A */
    u8 far_sel_imm;  /* far call/jmp: 1 when the selector is > 9 (capstone printed it as 0x..) */
    u32 target;      /* rel: (address + len + rel) mod 2^32, rel8/rel32 signed. A 66-prefixed rel16 (absent from
                      * compiler output) as capstone 5 printed it: a jmp/jcc's rel16 zero-extended, a call's signed;
                      * a jmp/jcc rel32 under 67 wraps in its 64 KiB page */
} DkXmInsn;

/* Decode one instruction at p[0..n) located at `address`. Returns its length (> 0) and fills *out, or 0 for an
 * invalid or truncated encoding. Pure: thread-safe. */
int dk_xm_x86_decode(const u8 *p, size_t n, u32 address, DkXmInsn *out);
