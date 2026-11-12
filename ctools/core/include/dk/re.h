// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Python's `re` module on top of the vendored PCRE2 10.44 (8-bit, JIT). The API is shaped like the module and
 * reproduces its observable behaviour: search / match / fullmatch with pos and endpos, finditer, findall (the
 * three result shapes), split (maxsplit, groups in the result, None for an unmatched group), sub / subn with a
 * Python replacement template or a callback, escape, group numbers and names, groupdict order, lastindex,
 * unmatched groups (-1 spans, like Python's None), and the empty-match rules of Python 3.7+ (an empty match right
 * after a non-empty one is allowed; after an empty match the next search starts at the same position but must not
 * give an empty match there). The scan loops are written here, not taken from pcre2_substitute, so they are
 * Python's.
 *
 * Offsets. Subjects are UTF-8 (DkStr) and every offset (pos, endpos, spans, DkReMatch accessors) is a BYTE
 * offset, because that is what the callers slice with. A tool that prints or compares Python's code-point index
 * converts with dk_u8_len on the prefix:
 *     size_t cp = dk_u8_len(dk_strn(subject.p, (size_t)dk_re_start(&m, 0)));
 * A str pattern matches code points (PCRE2_UTF); a subject that is not valid UTF-8 is an error (DK_ERR_FORMAT):
 * Python could not have held it as a str. With DK_RE_BYTES the pattern is a Python bytes pattern (rb"..."): the
 * subject is bytes, no UTF, no UCP, \w \d \s \b and case folding are ASCII only (what Python does for bytes).
 *
 * Python semantics reproduced by a translation step before compiling (the Python pattern is parsed and rewritten
 * for PCRE2; the result is cached with the compiled code):
 *   - str patterns are Unicode-aware (PCRE2_UTF | PCRE2_UCP) unless DK_RE_A or DK_RE_BYTES;
 *   - \Z is PCRE2 \z; {,n} is {0,n}; a { that does not start a Python quantifier is a literal; ^ and $ in
 *     MULTILINE mode (Python's ^ also matches after a trailing newline); `.` and DOTALL; VERBOSE mode (whitespace
 *     and # comments dropped outside character classes, kept inside, as Python) also as a scoped (?x:...);
 *   - scoped inline flags (?i:...) (?-i:...) (?s:...) (?a:...) and the global flags that must come first;
 *   - \xhh (exactly two digits), \uXXXX, \UXXXXXXXX, octal escapes, \1..\99 group references (always a
 *     reference, never an octal escape, as Python), (?P<name>...), (?P=name), (?(1)..|..), (?>...) and
 *     possessive quantifiers; `[` inside a character class is a literal (never a POSIX class);
 *   - the syntax PCRE2 accepts and Python rejects is rejected with Python's re.error message: unknown escapes of
 *     ASCII letters ("bad escape \h"), nothing to repeat, multiple repeat, unbalanced parenthesis, unterminated
 *     character set, unknown group name, bad character range, global flags not at the start, ...
 *   The message is Python's str(re.error): "<msg> at position N" plus " (line L, column C)" when the pattern
 *   holds a newline; N counts code points of a str pattern.
 *
 * \w, \s, \d, \b follow Python's definitions (a Unicode \w is letters, numbers and underscore, not PCRE2 10.43+'s
 * wider set with combining marks; \s is str.isspace without PCRE2's U+180E); they are spelled out for PCRE2.
 *
 * Not reproduced (the translation or PCRE2 differs): \N{NAME} (no Unicode name database: an error), the locale
 * flag (?L), re.DEBUG output, Python's dotless-i equivalence under IGNORECASE (other case folding is PCRE2's
 * Unicode simple case folding), a negated shorthand inside a character class of a pattern that mixes ASCII and
 * Unicode scopes, the Unicode data version (PCRE2 10.44's is older than CPython 3.14's: code points assigned
 * since, e.g. U+1C89 or U+2EBF0, are not word characters or digits), lookbehind width rules (PCRE2 accepts more
 * than Python), patterns whose compiled form exceeds 64 KiB (the PCRE2 build's link size), more than
 * DK_RE_MAX_GROUPS capturing groups.
 *
 * Thread safety. A compiled DkRe is immutable and shared by all threads (dk_re keeps a process-wide cache keyed
 * by pattern and flags; every pattern is compiled once, JIT included, and never freed). Match data, the JIT stack
 * and the match context are per thread. An DkReMatch / DkReIter belongs to the thread that uses it. */
#pragma once
#include "str.h"

/* Python's re flag values, so a flag expression can be translated one to one. */
enum {
    DK_RE_I = 2,        /* IGNORECASE */
    DK_RE_L = 4,        /* LOCALE: refused */
    DK_RE_M = 8,        /* MULTILINE */
    DK_RE_S = 16,       /* DOTALL */
    DK_RE_U = 32,       /* UNICODE: the default for str patterns, an error with DK_RE_BYTES */
    DK_RE_X = 64,       /* VERBOSE */
    DK_RE_DEBUG = 128,  /* accepted and ignored (Python prints a dump of the parsed pattern) */
    DK_RE_A = 256,      /* ASCII */
    DK_RE_BYTES = 1 << 16 /* not a Python flag: the pattern is a bytes pattern and subjects are bytes */
};

typedef struct DkRe DkRe;

/* ---- compiling ---------------------------------------------------------------------------------------------
 * dk_re: for literal patterns known to be valid; compiled once and cached (thread-safe), so it may be called
 * at every use. An invalid pattern is an internal error (dk_panic). dk_re_try: for patterns built at run time
 * (a user's --select option): throws DK_ERR_REGEX with Python's re.error text (see base.h DK_TRY); the cache is
 * used as well. dk_re_compile: the same without a throw: false and the message in err[errcap]. */
DkRe *dk_re(const char *pattern, int flags);
DkRe *dk_re_try(const char *pattern, int flags);
DkRe *dk_re_try_n(DkStr pattern, int flags); /* a pattern that is not NUL-terminated or holds NUL bytes */
bool dk_re_compile(DkStr pattern, int flags, DkRe **out, char *err, size_t errcap);

/* Pattern properties: .pattern, .flags (as given), .groups, .groupindex. */
DkStr dk_re_pattern(const DkRe *re);
int dk_re_flags(const DkRe *re);
int dk_re_groups(const DkRe *re);
/* The PCRE2 pattern the Python pattern was translated to (diagnostics and tests). */
DkStr dk_re_translated(const DkRe *re);
/* Group number of a name, or -1 (groupindex.get). The name of group g (1..groups), or NULL for an unnamed
 * group; groupdict() order is the group number order. */
int dk_re_group_index(const DkRe *re, const char *name);
const char *dk_re_group_name(const DkRe *re, int g);

/* ---- matches ---------------------------------------------------------------------------------------------- */
/* A pattern may have at most DK_RE_MAX_GROUPS capturing groups (dk_re refuses more: the match structure holds
 * the spans inline, so a match needs no allocation and no free). */
#define DK_RE_MAX_GROUPS 31

typedef struct DkReMatch {
    const DkRe *re;
    DkStr string; /* the whole subject (match.string) */
    i64 pos, endpos;
    int lastindex; /* match.lastindex, -1 for None */
    i64 span[2 * (DK_RE_MAX_GROUPS + 1)]; /* start, end of group 0..groups; -1, -1 when it did not take part */
} DkReMatch;

/* Group g (0 = the whole match) of a match. start/end give -1 for a group that did not take part (Python's
 * span() of an unmatched group); dk_re_group gives {NULL, 0} for it (Python None) and a view into the subject
 * (p != NULL, possibly empty) otherwise. Out-of-range g is an internal error (Python raises IndexError). */
i64 dk_re_start(const DkReMatch *m, int g);
i64 dk_re_end(const DkReMatch *m, int g);
bool dk_re_matched(const DkReMatch *m, int g);
DkStr dk_re_group(const DkReMatch *m, int g);
/* m.group(name): the name must exist (else an internal error); DkStr as dk_re_group. */
DkStr dk_re_group_named(const DkReMatch *m, const char *name);
/* m.lastgroup: the name of the group of lastindex, or NULL. */
const char *dk_re_lastgroup(const DkReMatch *m);
/* m.expand(template): appends the expansion to out. */
void dk_re_expand(DkBuf *out, const DkReMatch *m, DkStr tmpl);

/* ---- search / match / fullmatch ----------------------------------------------------------------------------
 * pos and endpos are Python's: bytes offsets, clamped to [0, len]; pass 0 and DK_END for the whole subject.
 * ^ does not match at pos (only at the real start); endpos behaves as if the subject ended there. m may be NULL
 * when only the answer matters. A single call validates the subject as UTF-8 (cost linear in the subject); loops
 * over one subject use dk_re_iter, or call dk_re_assume_valid first. */
bool dk_re_search(const DkRe *re, DkStr s, i64 pos, i64 endpos, DkReMatch *m);
bool dk_re_match(const DkRe *re, DkStr s, i64 pos, i64 endpos, DkReMatch *m);
bool dk_re_fullmatch(const DkRe *re, DkStr s, i64 pos, i64 endpos, DkReMatch *m);
/* Declares that the bytes of s are valid UTF-8 for the calling thread's next calls on this subject (any
 * sub-range of it), so those calls skip validation. The caller vouches for it (text read by fs.h is validated). */
void dk_re_assume_valid(DkStr s);

/* ---- finditer ----------------------------------------------------------------------------------------------
 *     DkReIter it; DkReMatch m;
 *     dk_re_iter_init(&it, re, text, 0, DK_END);
 *     while (dk_re_iter_next(&it, &m)) { ... }
 * Python's rules for empty matches; the subject is validated once. */
typedef struct DkReIter {
    const DkRe *re;
    DkStr s;
    i64 pos, endpos;
    bool must_advance;
    bool done;
} DkReIter;
void dk_re_iter_init(DkReIter *it, const DkRe *re, DkStr s, i64 pos, i64 endpos);
bool dk_re_iter_next(DkReIter *it, DkReMatch *m);

/* ---- findall -----------------------------------------------------------------------------------------------
 * Python's result shapes: no groups: the whole match; one group: that group; more: a tuple of all the groups.
 * An unmatched group gives "" (p != NULL, n 0). width is 1 for the first two shapes, the group count for tuples;
 * item i, field j is v.v[i * width + j]. Strings are views into the subject. Free with dk_re_findall_free. */
typedef struct {
    DkStrVec v;
    size_t count; /* number of items (matches) */
    int width;
} DkReFindall;
DkReFindall dk_re_findall(const DkRe *re, DkStr s, i64 pos, i64 endpos);
DkStr dk_re_findall_at(const DkReFindall *r, size_t i, int j);
void dk_re_findall_free(DkReFindall *r);

/* ---- split -------------------------------------------------------------------------------------------------
 * re.split(pattern, s, maxsplit): the pieces and, after each, the groups of its separator. A group that did not
 * take part is represented distinctly: .p == NULL (Python None); an empty string has p != NULL. maxsplit 0 is "no
 * limit" (Python); a negative maxsplit splits nothing, as Python. The pieces are views into the subject. */
DkStrVec dk_re_split(const DkRe *re, DkStr s, int maxsplit);

/* ---- sub / subn --------------------------------------------------------------------------------------------
 * repl is a Python replacement template: \1..\99, \g<n>, \g<name>, \g<0>, the escapes \a \b \f \n \r \t \v \\,
 * \0 and octal escapes, other backslash pairs of non-letters kept as written; an unmatched group gives "". Bad
 * templates throw DK_ERR_REGEX with Python's message ("invalid group reference 3 at position 1", "bad escape \q
 * at position 0", "unknown group name 'x'", ...). A template without a backslash is used as is. Templates are
 * parsed once per (pattern, template) and cached. count 0 replaces every match (Python). When nothing is replaced
 * the result is s itself (not a copy). The result is allocated from a; *n (optional) gets the number of
 * replacements (subn). */
DkStr dk_re_sub(DkArena *a, const DkRe *re, DkStr repl, DkStr s, int count);
DkStr dk_re_subn(DkArena *a, const DkRe *re, DkStr repl, DkStr s, int count, size_t *n);
/* The callback form: fn appends the replacement text for match m to out (Python's callable returns a str). */
typedef void (*DkReSubFn)(void *ctx, const DkReMatch *m, DkBuf *out);
DkStr dk_re_sub_fn(DkArena *a, const DkRe *re, DkReSubFn fn, void *ctx, DkStr s, int count, size_t *n);

/* ---- escape ------------------------------------------------------------------------------------------------
 * re.escape (3.7+): only the characters  ()[]{}?*+-|^$\.&~# and the ASCII whitespace \t \n \r \v \f and space are
 * backslash-escaped. The result is allocated from a. */
DkStr dk_re_escape(DkArena *a, DkStr s);
