// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* difflib.h against CPython 3.14.8: the corpus in difflib_corpus.h (a generated header, see its comment for the
 * Python that produced it) holds sequence cases with the expected ratio, quick_ratio, real_quick_ratio, opcodes,
 * grouped opcodes and find_longest_match results, and unified_diff cases with the expected lines. */
#include "dk/dk.h"
#include "dk/difflib.h"
#include "dk/test.h"
#include "difflib_corpus.h"

#include <stdlib.h>

/* ---- parsing the corpus ---------------------------------------------------------------------------------------- */
static const char *entry_text(size_t i) { return difflib_corpus[i]; }

/* An element list: empty, or a separator character followed by the elements joined with it. */
static DkStrVec split_us(const char *s, size_t count) {
    DkStrVec v = {0};
    if (count == 0) return v;
    char sep = s[0];
    const char *p = s + 1;
    for (;;) {
        const char *q = strchr(p, sep);
        if (!q) {
            dk_vec_push(&v, dk_str(p));
            break;
        }
        dk_vec_push(&v, dk_strn(p, (size_t)(q - p)));
        p = q + 1;
    }
    return v;
}

static double bits_to_double(const char *hex) {
    u64 u = strtoull(hex, NULL, 16);
    double d;
    memcpy(&d, &u, sizeof d);
    return d;
}

static DkOpTag tag_of(char c) {
    switch (c) {
    case 'r': return DK_OP_REPLACE;
    case 'd': return DK_OP_DELETE;
    case 'i': return DK_OP_INSERT;
    default: return DK_OP_EQUAL;
    }
}

typedef DK_VEC(DkOpcode) OpVec;

/* "r0,3,0,3;e3,4,3,4" */
static OpVec parse_ops(const char *s) {
    OpVec v = {0};
    while (*s) {
        DkOpcode op;
        op.tag = tag_of(*s++);
        char *end;
        op.i1 = (size_t)strtoull(s, &end, 10);
        op.i2 = (size_t)strtoull(end + 1, &end, 10);
        op.j1 = (size_t)strtoull(end + 1, &end, 10);
        op.j2 = (size_t)strtoull(end + 1, &end, 10);
        dk_vec_push(&v, op);
        s = *end == ';' ? end + 1 : end;
    }
    return v;
}

static bool ops_equal(const DkOpcode *x, size_t nx, const OpVec *y) {
    if (nx != y->n) return false;
    for (size_t i = 0; i < nx; i++)
        if (x[i].tag != y->v[i].tag || x[i].i1 != y->v[i].i1 || x[i].i2 != y->v[i].i2 || x[i].j1 != y->v[i].j1 ||
            x[i].j2 != y->v[i].j2)
            return false;
    return true;
}

static bool blank_junk(void *ctx, u64 e) {
    DK_UNUSED(ctx);
    return e == ' ' || e == '\t';
}
static bool mod3_junk(void *ctx, u64 e) {
    DK_UNUSED(ctx);
    return e % 3 == 0;
}

static u64 parse_u64(DkStr s) {
    char tmp[32];
    size_t n = DK_MIN(s.n, sizeof tmp - 1);
    memcpy(tmp, s.p, n);
    tmp[n] = 0;
    return strtoull(tmp, NULL, 10);
}

static int g_failures; /* failed corpus cases, to keep the report short */
static void case_failed(size_t entry, const char *what) {
    if (g_failures++ < 12) fprintf(stderr, "corpus entry %zu: %s differs\n", entry, what);
    dk_test__failed_checks++;
}

static size_t run_seq_case(size_t i) {
    /* i is the "C" entry */
    char mode[8], junk[8];
    int autojunk;
    size_t start = i;
    sscanf(entry_text(i), "C %7s %d %7s", mode, &autojunk, junk);
    i++;
    const char *a_text = NULL, *b_text = NULL;
    size_t na = 0, nb = 0;
    double ratio = 0, quick = 0, real_quick = 0;
    const char *ops_text = NULL;
    const char *g_text[8];
    int g_n[8];
    size_t ng_cases = 0;
    struct {
        size_t alo, ahi, blo, bhi, i, j, k;
    } finds[8];
    size_t nfinds = 0;
    for (; strcmp(entry_text(i), "E") != 0; i++) {
        const char *e = entry_text(i);
        switch (e[0]) {
        case 'a': a_text = e + 2; break;
        case 'b': b_text = e + 2; break;
        case 'n': sscanf(e, "n %zu %zu", &na, &nb); break;
        case 'R': {
            char h1[20], h2[20], h3[20];
            sscanf(e, "R %16s %16s %16s", h1, h2, h3);
            ratio = bits_to_double(h1);
            quick = bits_to_double(h2);
            real_quick = bits_to_double(h3);
            break;
        }
        case 'O': ops_text = e + 2; break;
        case 'G': {
            int ngroups;
            sscanf(e, "G %d %d", &g_n[ng_cases], &ngroups);
            const char *sp = strchr(e + 2, ' ');
            sp = sp ? strchr(sp + 1, ' ') : NULL;
            g_text[ng_cases++] = sp ? sp + 1 : "";
            break;
        }
        case 'L':
            sscanf(e, "L %zu %zu %zu %zu %zu %zu %zu", &finds[nfinds].alo, &finds[nfinds].ahi, &finds[nfinds].blo,
                   &finds[nfinds].bhi, &finds[nfinds].i, &finds[nfinds].j, &finds[nfinds].k);
            nfinds++;
            break;
        default: break;
        }
    }
    size_t end = i;

    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkSeqOpts opts = {autojunk == 0, NULL, NULL};
    DkSeqMatcher *m;
    if (strcmp(mode, "text") == 0) {
        if (strcmp(junk, "blank") == 0) opts.isjunk = blank_junk;
        m = dk_seqm_new_text(sc, dk_str(a_text), dk_str(b_text), &opts);
    } else if (strcmp(mode, "u64") == 0) {
        DkStrVec sa = split_us(a_text, na), sb = split_us(b_text, nb);
        u64 *va = (u64 *)dk_alloc(sc, (na + 1) * sizeof(u64)), *vb = (u64 *)dk_alloc(sc, (nb + 1) * sizeof(u64));
        for (size_t t = 0; t < na; t++) va[t] = parse_u64(sa.v[t]);
        for (size_t t = 0; t < nb; t++) vb[t] = parse_u64(sb.v[t]);
        if (strcmp(junk, "mod3") == 0) opts.isjunk = mod3_junk;
        m = dk_seqm_new_u64(sc, va, na, vb, nb, &opts);
        dk_vec_free(&sa);
        dk_vec_free(&sb);
    } else {
        DkStrVec sa = split_us(a_text, na), sb = split_us(b_text, nb);
        /* the vectors are heap-backed; the matcher copies what it needs */
        m = dk_seqm_new_str(sc, sa.v, na, sb.v, nb, &opts);
        dk_vec_free(&sa);
        dk_vec_free(&sb);
    }
    double r = dk_seqm_ratio(m);
    if (memcmp(&r, &ratio, sizeof r) != 0) case_failed(start, "ratio");
    double q = dk_seqm_quick_ratio(m);
    if (memcmp(&q, &quick, sizeof q) != 0) case_failed(start, "quick_ratio");
    double rq = dk_seqm_real_quick_ratio(m);
    if (memcmp(&rq, &real_quick, sizeof rq) != 0) case_failed(start, "real_quick_ratio");

    size_t nops;
    const DkOpcode *ops = dk_seqm_opcodes(m, &nops);
    OpVec want = parse_ops(ops_text);
    if (!ops_equal(ops, nops, &want)) case_failed(start, "opcodes");
    dk_vec_free(&want);

    for (size_t g = 0; g < ng_cases; g++) {
        size_t ngroups;
        const DkOpGroup *groups = dk_seqm_grouped_opcodes(m, g_n[g], &ngroups);
        /* groups are separated by '|' in the expected text */
        const char *p = g_text[g];
        size_t gi = 0;
        bool ok = true;
        if (*p == 0 && ngroups != 0) ok = false;
        while (*p && ok) {
            const char *bar = strchr(p, '|');
            size_t len = bar ? (size_t)(bar - p) : strlen(p);
            char *tmp = dk_cz(sc, dk_strn(p, len));
            OpVec w = parse_ops(tmp);
            if (gi >= ngroups || !ops_equal(groups[gi].ops, groups[gi].n, &w)) ok = false;
            dk_vec_free(&w);
            gi++;
            p = bar ? bar + 1 : p + len;
        }
        if (ok && gi != ngroups) ok = false;
        if (!ok) case_failed(start, "grouped opcodes");
    }
    for (size_t f = 0; f < nfinds; f++) {
        DkMatch fm = dk_seqm_find_longest_match(m, finds[f].alo, finds[f].ahi, finds[f].blo, finds[f].bhi);
        if (fm.a != finds[f].i || fm.b != finds[f].j || fm.size != finds[f].k) case_failed(start, "find_longest_match");
    }
    dk_arena_reset(sc, mk);
    return end + 1;
}

static size_t run_udiff_case(size_t i) {
    size_t start = i;
    size_t na, nb, nout;
    sscanf(entry_text(i), "U %zu %zu %zu", &na, &nb, &nout);
    i++;
    DkUdiff o = DK_UDIFF_DEFAULT;
    const char *a_text = "", *b_text = "", *x_text = "";
    for (; strcmp(entry_text(i), "E") != 0; i++) {
        const char *e = entry_text(i);
        switch (e[0]) {
        case 'f': o.fromfile = dk_str(e + 2); break;
        case 't': o.tofile = dk_str(e + 2); break;
        case 'F': o.fromfiledate = dk_str(e + 2); break;
        case 'T': o.tofiledate = dk_str(e + 2); break;
        case 'l': o.lineterm = dk_str(e + 2); break;
        case 'N': o.n = atoi(e + 2); break;
        case 'a': a_text = e + 2; break;
        case 'b': b_text = e + 2; break;
        case 'x': x_text = e + 2; break;
        default: break;
        }
    }
    DkStrVec a = split_us(a_text, na), b = split_us(b_text, nb), want = split_us(x_text, nout);
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkStrVec got = dk_unified_diff_lines(sc, a.v, na, b.v, nb, &o);
    bool ok = got.n == want.n;
    for (size_t t = 0; ok && t < got.n; t++) ok = dk_str_eq(got.v[t], want.v[t]);
    if (!ok) case_failed(start, "unified_diff lines");
    DkBuf joined;
    dk_buf_init(&joined, NULL);
    dk_unified_diff(&joined, a.v, na, b.v, nb, &o);
    DkBuf expect;
    dk_buf_init(&expect, NULL);
    for (size_t t = 0; t < want.n; t++) dk_buf_put(&expect, want.v[t]);
    if (!dk_str_eq(dk_buf_str(&joined), dk_buf_str(&expect))) case_failed(start, "unified_diff text");
    dk_buf_free(&joined);
    dk_buf_free(&expect);
    dk_arena_reset(sc, mk);
    dk_vec_free(&a);
    dk_vec_free(&b);
    dk_vec_free(&want);
    return i + 1;
}

DK_TEST(corpus_against_cpython) {
    size_t i = 0, seq_cases = 0, udiff_cases = 0;
    g_failures = 0;
    while (i < DIFFLIB_CORPUS_LEN) {
        const char *e = entry_text(i);
        if (e[0] == 'C') {
            i = run_seq_case(i);
            seq_cases++;
        } else if (e[0] == 'U') {
            i = run_udiff_case(i);
            udiff_cases++;
        } else {
            REQUIRE(false);
        }
    }
    CHECK(seq_cases > 500);
    CHECK(udiff_cases > 30);
    printf("difflib corpus: %zu sequence cases, %zu unified_diff cases, %d failures\n", seq_cases, udiff_cases,
           g_failures);
}

/* ---- the documented examples ----------------------------------------------------------------------------------- */
DK_TEST(doc_examples) {
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    /* SequenceMatcher(None, "abcd", "bcde"): ratio 0.75, quick 0.75, real_quick 1.0 */
    DkSeqMatcher *m = dk_seqm_new_text(sc, DK_S("abcd"), DK_S("bcde"), NULL);
    CHECK_EQ_F64(dk_seqm_ratio(m), 0.75);
    CHECK_EQ_F64(dk_seqm_quick_ratio(m), 0.75);
    CHECK_EQ_F64(dk_seqm_real_quick_ratio(m), 1.0);
    /* SequenceMatcher(None, " abcd", "abcd abcd").find_longest_match(0, 5, 0, 9) == Match(a=0, b=4, size=5) */
    m = dk_seqm_new_text(sc, DK_S(" abcd"), DK_S("abcd abcd"), NULL);
    DkMatch fm = dk_seqm_find_longest_match(m, 0, 5, 0, 9);
    CHECK_EQ_U64(fm.a, 0);
    CHECK_EQ_U64(fm.b, 4);
    CHECK_EQ_U64(fm.size, 5);
    /* with blanks as junk: Match(a=1, b=0, size=4) */
    DkSeqOpts blank = {false, blank_junk, NULL};
    m = dk_seqm_new_text(sc, DK_S(" abcd"), DK_S("abcd abcd"), &blank);
    fm = dk_seqm_find_longest_match(m, 0, 5, 0, 9);
    CHECK_EQ_U64(fm.a, 1);
    CHECK_EQ_U64(fm.b, 0);
    CHECK_EQ_U64(fm.size, 4);
    /* "abxcd" vs "abcd": [Match(0, 0, 2), Match(3, 2, 2), Match(5, 4, 0)] */
    m = dk_seqm_new_text(sc, DK_S("abxcd"), DK_S("abcd"), NULL);
    size_t nb;
    const DkMatch *blocks = dk_seqm_matching_blocks(m, &nb);
    REQUIRE(nb == 3);
    CHECK_EQ_U64(blocks[1].a, 3);
    CHECK_EQ_U64(blocks[1].b, 2);
    CHECK_EQ_U64(blocks[2].a, 5);
    CHECK_EQ_U64(blocks[2].b, 4);
    CHECK_EQ_U64(blocks[2].size, 0);
    /* two empty sequences: ratio 1.0, no opcodes */
    m = dk_seqm_new_text(sc, DK_S(""), DK_S(""), NULL);
    CHECK_EQ_F64(dk_seqm_ratio(m), 1.0);
    size_t nops;
    dk_seqm_opcodes(m, &nops);
    CHECK_EQ_U64(nops, 0);
    CHECK_STR(DK_S("replace"), dk_op_name(DK_OP_REPLACE));
    dk_arena_reset(sc, mk);
}

DK_TEST(one_shot_ratios) {
    DkStr a[] = {DK_S("one"), DK_S("two"), DK_S("three"), DK_S("four")};
    DkStr b[] = {DK_S("zero"), DK_S("one"), DK_S("tree"), DK_S("four")};
    CHECK_EQ_F64(dk_ratio_str(a, 4, b, 4, false), 0.5);
    u64 x[] = {1, 2, 3, 4}, y[] = {2, 3, 4, 5};
    CHECK_EQ_F64(dk_ratio_u64(x, 4, y, 4, true), 0.75);
    CHECK_EQ_F64(dk_ratio_text(DK_S("abcd"), DK_S("bcde"), false), 0.75);
    /* non-ASCII text compares code points: "é" is one element */
    CHECK_EQ_F64(dk_ratio_text(DK_S("\xc3\xa9" "a"), DK_S("\xc3\xa9" "b"), false), 0.5);
}

DK_TEST(unified_diff_documented_example) {
    /* unified_diff('one two three four'.split(), 'zero one tree four'.split(), 'Original', 'Current',
     * '2005-01-26 23:30:50', '2010-04-02 10:20:52', lineterm='') */
    DkStr a[] = {DK_S("one"), DK_S("two"), DK_S("three"), DK_S("four")};
    DkStr b[] = {DK_S("zero"), DK_S("one"), DK_S("tree"), DK_S("four")};
    DkUdiff o = DK_UDIFF_DEFAULT;
    o.fromfile = DK_S("Original");
    o.tofile = DK_S("Current");
    o.fromfiledate = DK_S("2005-01-26 23:30:50");
    o.tofiledate = DK_S("2010-04-02 10:20:52");
    o.lineterm = DK_S("");
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkStrVec v = dk_unified_diff_lines(sc, a, 4, b, 4, &o);
    REQUIRE(v.n == 9);
    CHECK_STR(v.v[0], "--- Original\t2005-01-26 23:30:50");
    CHECK_STR(v.v[1], "+++ Current\t2010-04-02 10:20:52");
    CHECK_STR(v.v[2], "@@ -1,4 +1,4 @@");
    CHECK_STR(v.v[3], "+zero");
    CHECK_STR(v.v[4], " one");
    CHECK_STR(v.v[5], "-two");
    CHECK_STR(v.v[6], "-three");
    CHECK_STR(v.v[7], "+tree");
    CHECK_STR(v.v[8], " four");
    dk_arena_reset(sc, mk);
    dk_vec_free(&v);
}

DK_TEST(large_sequences) {
    /* a deterministic 30000-element sequence and a copy with every 50th element changed: the matcher must stay
     * fast (CPython's algorithm is quadratic only in the worst case) and give the exact count of matches */
    size_t n = 30000;
    u64 *a = (u64 *)dk_xmalloc(n * sizeof(u64)), *b = (u64 *)dk_xmalloc(n * sizeof(u64));
    u64 x = 12345;
    for (size_t i = 0; i < n; i++) {
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
        a[i] = (x >> 33) % 100000 + 1000;
        b[i] = (i % 50 == 25) ? 7 : a[i];
    }
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkSeqMatcher *m = dk_seqm_new_u64(sc, a, n, b, n, &dk_seqm_no_autojunk);
    double expect = 2.0 * (double)(n - n / 50) / (double)(2 * n);
    CHECK_EQ_F64(dk_seqm_ratio(m), expect);
    dk_arena_reset(sc, mk);
    dk_xfree(a);
    dk_xfree(b);
}

DK_TEST_MAIN("difflib")
