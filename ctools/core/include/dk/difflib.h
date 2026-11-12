// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Python's difflib (CPython 3.14.8), for what the tools use: SequenceMatcher (ratio, quick_ratio, real_quick_ratio,
 * find_longest_match, get_matching_blocks, get_opcodes, get_grouped_opcodes) and unified_diff. The algorithm is a
 * line-by-line port, so every result is the one Python gives, including the tie-breaking of find_longest_match,
 * the merge of adjacent matching blocks, the "popular element" pruning (autojunk: when len(b) >= 200 an element
 * that occurs more than len(b)//100 + 1 times is not used to start a match; Python's default is autojunk=True, the
 * tools pass autojunk=False almost everywhere) and the exact doubles of ratio() (2.0 * matches / length).
 *
 * Not ported because no tool uses them: Differ/ndiff, context_diff, get_close_matches, HtmlDiff, restore.
 *
 * A matcher compares two sequences. The elements can be
 *   - DkStr (lines, tokens): equal when their bytes are equal;
 *   - u64 values (ids, code points, hashes);
 *   - the code points of two UTF-8 strings (Python str compared as a sequence of characters).
 * The constructors turn the elements into dense ids once (a hash table, O(la + lb)), then b2j is a CSR index (the
 * indices of every element of b in increasing order, like CPython's dict of lists) and find_longest_match works on
 * arrays instead of dicts. All memory comes from the arena given; nothing is freed by the matcher (use a scratch
 * arena with a mark/reset in loops that compare many pairs). The input arrays must stay valid while the matcher is
 * used (the DkStr bytes are only read while the constructor runs).
 *
 *     DkArenaMark mk = dk_arena_mark(dk_scratch());
 *     DkSeqMatcher *m = dk_seqm_new_str(dk_scratch(), a, na, b, nb, NULL);   // SequenceMatcher(None, a, b)
 *     double r = dk_seqm_ratio(m);
 *     size_t n; const DkOpcode *ops = dk_seqm_opcodes(m, &n);
 *     dk_arena_reset(dk_scratch(), mk);
 *
 * Differences from Python: indices and sizes are size_t; a matcher is built from both sequences at once (there is
 * no set_seq1/set_seq2 reuse); get_grouped_opcodes works on a copy of the opcodes (CPython edits the cached list
 * in place, which only shows if get_opcodes is called again afterwards). isjunk is available for u64 and code
 * point sequences (it receives the element value); the DkStr constructor takes no isjunk. */
#pragma once
#include "str.h"

/* Options of SequenceMatcher(isjunk, a, b, autojunk). NULL means the defaults: no isjunk, autojunk True. */
typedef struct {
    bool no_autojunk;                     /* autojunk=False */
    bool (*isjunk)(void *ctx, u64 elem);  /* isjunk(elem); u64 and code point sequences only */
    void *ctx;
} DkSeqOpts;
/* The tools' usual SequenceMatcher(None, a, b, autojunk=False). */
extern const DkSeqOpts dk_seqm_no_autojunk;

typedef struct DkSeqMatcher DkSeqMatcher;

typedef struct {
    size_t a, b, size;
} DkMatch; /* difflib.Match(a, b, size) */

typedef enum { DK_OP_REPLACE, DK_OP_DELETE, DK_OP_INSERT, DK_OP_EQUAL } DkOpTag;
typedef struct {
    DkOpTag tag;
    size_t i1, i2, j1, j2;
} DkOpcode; /* ('replace' | 'delete' | 'insert' | 'equal', i1, i2, j1, j2) */
const char *dk_op_name(DkOpTag tag); /* "replace", "delete", "insert", "equal" */

DkSeqMatcher *dk_seqm_new_str(DkArena *arena, const DkStr *a, size_t na, const DkStr *b, size_t nb,
                                const DkSeqOpts *opts);
DkSeqMatcher *dk_seqm_new_u64(DkArena *arena, const u64 *a, size_t na, const u64 *b, size_t nb,
                                const DkSeqOpts *opts);
DkSeqMatcher *dk_seqm_new_u32(DkArena *arena, const u32 *a, size_t na, const u32 *b, size_t nb,
                                const DkSeqOpts *opts);
/* SequenceMatcher(None, s, t) on two Python str values: UTF-8 decoded into code points (invalid bytes become
 * U+FFFD, one per byte, as dk_u8_next does). */
DkSeqMatcher *dk_seqm_new_text(DkArena *arena, DkStr a, DkStr b, const DkSeqOpts *opts);

size_t dk_seqm_len_a(const DkSeqMatcher *m);
size_t dk_seqm_len_b(const DkSeqMatcher *m);

/* find_longest_match(alo, ahi, blo, bhi); ahi/bhi == DK_SEQ_END mean len(a)/len(b) (Python's None). */
#define DK_SEQ_END ((size_t)-1)
DkMatch dk_seqm_find_longest_match(DkSeqMatcher *m, size_t alo, size_t ahi, size_t blo, size_t bhi);
/* get_matching_blocks(): increasing in a and b, adjacent blocks merged, ending with the (len(a), len(b), 0)
 * sentinel; the array is owned by the matcher (valid as long as its arena). */
const DkMatch *dk_seqm_matching_blocks(DkSeqMatcher *m, size_t *count);
/* get_opcodes(). */
const DkOpcode *dk_seqm_opcodes(DkSeqMatcher *m, size_t *count);
/* get_grouped_opcodes(n): the groups of changes with n lines of context; *ngroups groups, group g is
 * groups[g].ops[0 .. groups[g].n). n may be negative like Python (nonsense but the same nonsense). */
typedef struct {
    const DkOpcode *ops;
    size_t n;
} DkOpGroup;
const DkOpGroup *dk_seqm_grouped_opcodes(DkSeqMatcher *m, i64 n, size_t *ngroups);

double dk_seqm_ratio(DkSeqMatcher *m);            /* 2.0 * matches / (len(a) + len(b)); 1.0 when both empty */
double dk_seqm_quick_ratio(DkSeqMatcher *m);      /* the multiset upper bound */
double dk_seqm_real_quick_ratio(DkSeqMatcher *m); /* min(len(a), len(b)) upper bound */

/* One-shot ratios (SequenceMatcher(None, a, b, autojunk=...).ratio()) that use the arena's scratch space and give it
 * back: no arena needed. */
double dk_ratio_str(const DkStr *a, size_t na, const DkStr *b, size_t nb, bool autojunk);
double dk_ratio_u64(const u64 *a, size_t na, const u64 *b, size_t nb, bool autojunk);
double dk_ratio_text(DkStr a, DkStr b, bool autojunk); /* two Python str values */

/* unified_diff(a, b, fromfile, tofile, fromfiledate, tofiledate, n, lineterm). Like Python the sequences are
 * compared with SequenceMatcher(None, a, b) (autojunk on) and every output line is ' ' / '-' / '+' plus the input
 * line (no terminator is added to those), the header and range lines end with lineterm. Defaults are made by
 * DK_UDIFF_DEFAULT: n = 3, lineterm = "\n", empty names and dates:
 *     DkUdiff o = DK_UDIFF_DEFAULT;  o.fromfile = DK_S("a/x"); o.tofile = DK_S("b/x"); o.n = 1;
 * An empty fromfiledate/tofiledate gives no tab-date part (Python tests the truth of the string). */
typedef struct {
    DkStr fromfile, tofile, fromfiledate, tofiledate;
    i64 n;
    DkStr lineterm;
} DkUdiff;
#define DK_UDIFF_DEFAULT ((DkUdiff){{"", 0}, {"", 0}, {"", 0}, {"", 0}, 3, {"\n", 1}})

/* "".join(unified_diff(...)) appended to out (nothing is appended when a == b). */
void dk_unified_diff(DkBuf *out, const DkStr *a, size_t na, const DkStr *b, size_t nb, const DkUdiff *o);
/* list(unified_diff(...)): the lines, as views into one arena block. */
DkStrVec dk_unified_diff_lines(DkArena *arena, const DkStr *a, size_t na, const DkStr *b, size_t nb,
                                 const DkUdiff *o);
