// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Text codecs and newline handling of open() against CPython 3.14 (fs_text_corpus.h). */
#include "dk/dk.h"
#include "dk/fs.h"
#include "dk/csv.h"
#include "dk/json.h"
#include "dk/fmt.h"
#include "dk/proc.h"
#include "dk/pool.h"
#include "dk/win.h"
#include "dk/test.h"

#include "fs_text_corpus.h"

static int g_fail;

static bool same(DkStr s, const char *z, size_t n) { return s.n == n && memcmp(s.p, z, n) == 0; }

static void check_decode(const char *name, DkEncoding enc, const DkDecRow *rows, size_t count) {
    DkArena *a = dk_arena_new(0);
    g_fail = 0;
    for (size_t i = 0; i < count && g_fail < 10; i++) {
        DkStr out;
        DkStr bytes = {rows[i].b, rows[i].n};
        bool ok = dk_decode_text(a, bytes, DK_TEXT(enc, DK_ERR_REPLACE, DK_NL_LF), &out);
        if (!ok || !same(out, rows[i].replace, rows[i].repn)) {
            g_fail++;
            dk_test__fail(__FILE__, __LINE__, "%s replace case %zu (%zu bytes): got [%.*s] want [%s]", name, i, rows[i].n, (int)out.n, ok ? out.p : "", rows[i].replace);
        }
        ok = dk_decode_text(a, bytes, DK_TEXT(enc, DK_ERR_STRICT, DK_NL_LF), &out);
        if (ok != (rows[i].strict_ok != 0)) {
            g_fail++;
            dk_test__fail(__FILE__, __LINE__, "%s strict case %zu: ok=%d want %d", name, i, ok, rows[i].strict_ok);
        } else if (ok && !same(out, rows[i].strict, rows[i].strn)) {
            g_fail++;
            dk_test__fail(__FILE__, __LINE__, "%s strict case %zu: text differs", name, i);
        } else if (!ok) {
            DkStr msg = dk_io_err_str(a);
            if (dk_io_err()->kind != DK_IOE_DECODE || !same(msg, rows[i].strict, rows[i].strn)) {
                g_fail++;
                dk_test__fail(__FILE__, __LINE__, "%s strict case %zu: error [%.*s] want [%s]", name, i, (int)msg.n, msg.p, rows[i].strict);
            }
        }
    }
    CHECK(g_fail == 0);
    dk_arena_free(a);
}

DK_TEST(decode_utf8) { check_decode("utf-8", DK_ENC_UTF8, k_dec_utf_8, DK_ARRAY_LEN(k_dec_utf_8)); }
DK_TEST(decode_utf8_sig) { check_decode("utf-8-sig", DK_ENC_UTF8_SIG, k_dec_utf_8_sig, DK_ARRAY_LEN(k_dec_utf_8_sig)); }
DK_TEST(decode_ascii) { check_decode("ascii", DK_ENC_ASCII, k_dec_ascii, DK_ARRAY_LEN(k_dec_ascii)); }
DK_TEST(decode_latin1) { check_decode("latin-1", DK_ENC_LATIN1, k_dec_latin_1, DK_ARRAY_LEN(k_dec_latin_1)); }

DK_TEST(newline_modes) {
    DkArena *a = dk_arena_new(0);
    g_fail = 0;
    for (size_t i = 0; i < DK_ARRAY_LEN(k_nl) && g_fail < 10; i++) {
        DkTextMode m = DK_TEXT(DK_ENC_UTF8, DK_ERR_STRICT, (DkNewline)k_nl[i].nl);
        DkStr data = {k_nl[i].data, 0};
        /* the corpus strings have no NUL: strlen is the length */
        data.n = strlen(k_nl[i].data);
        DkStr text;
        bool ok = dk_decode_text(a, data, m, &text);
        if (!ok || !same(text, k_nl[i].read, strlen(k_nl[i].read))) {
            g_fail++;
            dk_test__fail(__FILE__, __LINE__, "newline case %zu (mode %d): read [%.*s] want [%s]", i, k_nl[i].nl, (int)text.n, text.p, k_nl[i].read);
            continue;
        }
        /* lines, joined with 0x1f */
        DkFileLines it;
        DkStr line;
        char *joined = (char *)dk_alloc(a, text.n * 2 + 64);
        size_t jn = 0, count = 0;
        dk_file_lines_init(&it, text, m.newline);
        while (dk_file_lines_next(&it, &line)) {
            if (count++) joined[jn++] = '\x1f';
            memcpy(joined + jn, line.p, line.n);
            jn += line.n;
        }
        if ((int)count != k_nl[i].nlines || strcmp(joined, k_nl[i].lines) != 0) {
            g_fail++;
            dk_test__fail(__FILE__, __LINE__, "newline case %zu (mode %d): %zu lines [%s] want %d [%s]", i, k_nl[i].nl, count, joined, k_nl[i].nlines, k_nl[i].lines);
        }
        /* writing: the text as written to a file */
        DkStr enc;
        DkStr orig = {k_nl[i].data, data.n};
        ok = dk_encode_text(a, orig, m, &enc);
        if (!ok || !same(enc, k_nl[i].written, strlen(k_nl[i].written))) {
            g_fail++;
            dk_test__fail(__FILE__, __LINE__, "newline case %zu (mode %d): written [%.*s] want [%s]", i, k_nl[i].nl, (int)enc.n, enc.p, k_nl[i].written);
        }
    }
    CHECK(g_fail == 0);
    dk_arena_free(a);
}

DK_TEST(encode_latin1_ascii) {
    DkArena *a = dk_arena_new(0);
    g_fail = 0;
    for (size_t i = 0; i < DK_ARRAY_LEN(k_enc) && g_fail < 10; i++) {
        DkStr text = {k_enc[i].text, strlen(k_enc[i].text)}, out;
        bool ok = dk_encode_text(a, text, DK_TEXT((DkEncoding)k_enc[i].enc, DK_ERR_STRICT, DK_NL_LF), &out);
        if (ok != (k_enc[i].ok != 0)) {
            g_fail++;
            dk_test__fail(__FILE__, __LINE__, "encode case %zu: ok=%d want %d", i, ok, k_enc[i].ok);
        } else if (ok && !same(out, k_enc[i].out, k_enc[i].outn)) {
            g_fail++;
            dk_test__fail(__FILE__, __LINE__, "encode case %zu: bytes differ", i);
        } else if (!ok) {
            DkStr msg = dk_io_err_str(a);
            if (dk_io_err()->kind != DK_IOE_ENCODE || !same(msg, k_enc[i].out, k_enc[i].outn)) {
                g_fail++;
                dk_test__fail(__FILE__, __LINE__, "encode case %zu: error [%.*s] want [%s]", i, (int)msg.n, msg.p, k_enc[i].out);
            }
        }
        ok = dk_encode_text(a, text, DK_TEXT((DkEncoding)k_enc[i].enc, DK_ERR_REPLACE, DK_NL_LF), &out);
        if (!ok || !same(out, k_enc[i].replace, k_enc[i].repn)) {
            g_fail++;
            dk_test__fail(__FILE__, __LINE__, "encode case %zu: replace differs", i);
        }
    }
    CHECK(g_fail == 0);
    dk_arena_free(a);
}

DK_TEST(utf8_sig_bom_is_written_once) {
    DkArena *a = dk_arena_new(0);
    DkStr out;
    CHECK(dk_encode_text(a, (DkStr){"x", 1}, DK_TM_UTF8_SIG, &out));
    CHECK(same(out, "\xEF\xBB\xBF" "x\r\n" + 0, 4) || same(out, "\xEF\xBB\xBFx", 4));
    dk_arena_free(a);
}

DK_TEST_MAIN("fs_text")
