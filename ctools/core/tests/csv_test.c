// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Tests of csv.h against CPython 3.14.8: csv_corpus.h holds thousands of generated cases (csv.reader in the three
 * file modes and over a list of lines, csv.DictReader, csv.writer, csv.DictWriter, line splitting and
 * line.split("\t")); its header comment has the generator and the layout of each case. The hand-written tests
 * below cover what the corpus does not (limits, the API around it); their expected values came from the
 * snippets in their comments. */
#include "dk/dk.h"
#include "dk/csv.h"
#include "dk/test.h"
#include "csv_corpus.h"
#include <stdlib.h>

#define SEP_ITEM '\x1e'
#define SEP_FIELD '\x1f'
#define SEP_KV '\x1d'
#define SEP_LIST '\x1c'

static DkCsvDialect dialect_for(int id) {
    DkCsvDialect d = dk_csv_excel;
    switch (id) {
    case 0: break;
    case 1: d.delimiter = '\t'; break;
    case 2: d.delimiter = '\t'; d.strict = true; break;
    case 3: d.skipinitialspace = true; break;
    case 4: d.escapechar = '\\'; break;
    case 5: d.doublequote = false; d.escapechar = '\\'; break;
    case 6: d.quoting = DK_CSV_NONE; break;
    case 7: d.quoting = DK_CSV_NONE; d.escapechar = '\\'; break;
    case 8: d.strict = true; break;
    case 9: d.quotechar = '\''; d.delimiter = ';'; break;
    case 10: d.delimiter = ' '; d.skipinitialspace = true; break;
    case 11: d.quoting = DK_CSV_ALL; d.strict = true; d.escapechar = '\\'; break;
    case 12: d.doublequote = false; break;
    case 13: d.lineterminator = DK_S("\n"); break;
    case 14: d.lineterminator = DK_S("|"); break;
    case 15: d.lineterminator = DK_S(""); break;
    case 16: d.quoting = DK_CSV_NONNUMERIC; break;
    case 17: d.quoting = DK_CSV_STRINGS; break;
    case 18: d.quoting = DK_CSV_NOTNULL; break;
    case 19: d.quotechar = -1; break;
    case 20: d.quoting = DK_CSV_ALL; d.lineterminator = DK_S("\n"); break;
    case 21: d.delimiter = ';'; d.escapechar = '\\'; d.doublequote = false; d.lineterminator = DK_S("\r"); break;
    case 22: d.delimiter = ' '; d.skipinitialspace = true; d.quoting = DK_CSV_NONE; d.escapechar = '\\'; break;
    case 23: d.delimiter = ' '; d.skipinitialspace = true; d.quoting = DK_CSV_NOTNULL; break;
    default: DK_ASSERT(false);
    }
    return d;
}

static void put_item_sep(DkBuf *b, bool *first) {
    if (!*first) dk_buf_putc(b, SEP_ITEM);
    *first = false;
}

/* The expected-output encoding of the generator, built from what the C reader gives. */
static void run_reader(DkBuf *out, const DkCsvCase *c) {
    DkCsvDialect d = dialect_for(c->dialect);
    DkCsvReader rd;
    DkStrVec lines = {0};
    DkStr text = dk_strn(c->in, c->in_n);
    if (c->mode == 3) {
        /* each line is 'L' + the line, the lines are joined by U+00FF (C3 BF); no lines is the empty input */
        const char *p = text.p, *end = text.p + text.n;
        while (p < end) {
            const char *q = p + 1;
            while (q + 1 < end && !((unsigned char)q[0] == 0xC3 && (unsigned char)q[1] == 0xBF)) q++;
            if (q + 1 >= end) q = end;
            dk_vec_push(&lines, dk_strn(p + 1, (size_t)(q - p) - 1));
            p = q + 2;
        }
        dk_csv_reader_init_lines(&rd, &d, lines.v, lines.n);
    } else {
        dk_csv_reader_init(&rd, &d, text, (DkCsvLineMode)c->mode);
    }
    bool first = true;
    for (;;) {
        int st = dk_csv_next(&rd);
        if (st == 0) break;
        put_item_sep(out, &first);
        if (st < 0) {
            dk_buf_printf(out, "E%lld%c", (long long)rd.line_num, SEP_FIELD);
            dk_buf_put(out, rd.error);
            continue;
        }
        dk_buf_printf(out, "R%lld", (long long)rd.line_num);
        for (size_t i = 0; i < rd.row.n; i++) {
            dk_buf_putc(out, SEP_FIELD);
            dk_buf_put(out, rd.row.v[i]);
        }
    }
    dk_csv_reader_free(&rd);
    dk_vec_free(&lines);
}

static void run_writer(DkBuf *out, const DkCsvCase *c) {
    DkCsvDialect d = dialect_for(c->dialect);
    const char *p = c->in, *end = c->in + c->in_n;
    bool first = true;
    /* rows are separated by 0x1E, fields by 0x1F; an empty input is a single empty row */
    for (;;) {
        const char *rend = p;
        while (rend < end && *rend != SEP_ITEM) rend++;
        DkBuf row = {0};
        DkCsvWriter w;
        dk_csvw_init(&w, &row, &d);
        dk_csvw_begin(&w);
        if (rend > p) {
            const char *f = p;
            for (;;) {
                const char *fend = f;
                while (fend < rend && *fend != SEP_FIELD) fend++;
                DkStr v = dk_strn(f + 1, (size_t)(fend - f) - 1);
                switch (*f) {
                case 's': dk_csvw_str(&w, v); break;
                case 'n': dk_csvw_none(&w); break;
                case 'b': dk_csvw_bool(&w, v.p[0] == '1'); break;
                case 'i':
                    if (v.n <= 18) dk_csvw_i64(&w, strtoll(dk_cz(dk_scratch(), v), NULL, 10));
                    else dk_csvw_number_text(&w, v);
                    break;
                case 'f': dk_csvw_f64(&w, strtod(dk_cz(dk_scratch(), v), NULL)); break;
                default: DK_ASSERT(false);
                }
                if (fend >= rend) break;
                f = fend + 1;
            }
        }
        bool ok = dk_csvw_end(&w);
        put_item_sep(out, &first);
        if (ok) {
            dk_buf_putc(out, 'W');
            dk_buf_put(out, dk_buf_str(&row));
        } else {
            dk_buf_putc(out, 'E');
            dk_buf_put(out, w.error);
        }
        dk_buf_free(&row);
        if (rend >= end) break;
        p = rend + 1;
    }
}

static void put_dict_record(DkBuf *out, const DkCsvDictReader *dr) {
    dk_buf_printf(out, "D%lld", (long long)dr->line_num);
    for (size_t i = 0; i < dr->names.n; i++) {
        DkStr n = dr->names.v[i];
        bool seen = false;
        for (size_t j = 0; j < i; j++) seen = seen || dk_str_eq(dr->names.v[j], n);
        if (seen) continue; /* a repeated name keeps its first position */
        DkStr v = dk_csv_dict_get(dr, n);
        dk_buf_putc(out, SEP_FIELD);
        dk_buf_putc(out, 'S');
        dk_buf_put(out, n);
        dk_buf_putc(out, SEP_KV);
        if (!v.p) dk_buf_putc(out, 'N');
        else {
            dk_buf_putc(out, 'S');
            dk_buf_put(out, v);
        }
    }
    if (dr->rest_present) {
        dk_buf_putc(out, SEP_FIELD);
        if (dr->restkey.p) {
            dk_buf_putc(out, 'S');
            dk_buf_put(out, dr->restkey);
        } else {
            dk_buf_putc(out, 'N');
        }
        dk_buf_putc(out, SEP_KV);
        dk_buf_putc(out, 'L');
        for (size_t i = 0; i < dr->rest.n; i++) {
            if (i) dk_buf_putc(out, SEP_LIST);
            dk_buf_put(out, dr->rest.v[i]);
        }
    }
}

static void run_dictreader(DkBuf *out, const DkCsvCase *c) {
    DkCsvDialect d = dialect_for(c->dialect);
    DkCsvReader rd;
    dk_csv_reader_init(&rd, &d, dk_strn(c->in, c->in_n), DK_CSV_UNIVERSAL);
    DkCsvDictReader dr;
    dk_csv_dictreader_init(&dr, dk_arena(), &rd);
    if (c->aux & 1) dr.restkey = DK_S("R");
    if (c->aux & 2) dr.restval = DK_S("V");
    bool first = true;
    int st;
    const DkStrVec *names = dk_csv_dictreader_fieldnames(&dr, &st);
    put_item_sep(out, &first);
    if (names) {
        dk_buf_putc(out, 'F');
        for (size_t i = 0; i < names->n; i++) {
            if (i) dk_buf_putc(out, SEP_FIELD);
            dk_buf_put(out, names->v[i]);
        }
    } else {
        dk_buf_putz(out, "F-");
        if (st < 0) {
            put_item_sep(out, &first);
            dk_buf_printf(out, "E%lld%c", (long long)dr.rd.line_num, SEP_FIELD);
            dk_buf_put(out, dr.rd.error);
        }
    }
    for (;;) {
        st = dk_csv_dict_next(&dr);
        if (st == 0) break;
        put_item_sep(out, &first);
        if (st < 0) {
            dk_buf_printf(out, "E%lld%c", (long long)dr.rd.line_num, SEP_FIELD);
            dk_buf_put(out, dr.rd.error);
            continue;
        }
        put_dict_record(out, &dr);
    }
    dk_csv_dictreader_free(&dr);
}

static void run_dictwriter(DkBuf *out, const DkCsvCase *c) {
    DkCsvDialect d = dk_csv_excel;
    d.delimiter = ';';
    d.lineterminator = DK_S("\n");
    DkCsvWriter w;
    dk_csvw_init(&w, out, &d);
    /* input: fieldnames (0x1F), then per row 0x1E 'D' key 0x1D value (0x1F ...) */
    const char *p = c->in, *end = c->in + c->in_n;
    DkStrVec names = {0};
    const char *q = p;
    for (;;) {
        const char *f = q;
        while (q < end && *q != SEP_FIELD && *q != SEP_ITEM) q++;
        dk_vec_push(&names, dk_strn(f, (size_t)(q - f)));
        if (q >= end || *q == SEP_ITEM) break;
        q++;
    }
    CHECK(dk_csvw_row(&w, names.v, names.n));
    DkStr restval = (c->aux & 1) ? DK_S("V") : DK_S("");
    DkStr *vals = (DkStr *)dk_xcalloc(names.n, sizeof(DkStr));
    while (q < end) {
        q++; /* the 0x1E */
        q++; /* the 'D' */
        const char *rend = q;
        while (rend < end && *rend != SEP_ITEM) rend++;
        memset(vals, 0, names.n * sizeof(DkStr));
        while (q < rend) {
            const char *kv = q;
            while (kv < rend && *kv != SEP_KV) kv++;
            DkStr key = dk_strn(q, (size_t)(kv - q));
            const char *ve = kv + 1;
            while (ve < rend && *ve != SEP_FIELD) ve++;
            DkStr val = dk_strn(kv + 1, (size_t)(ve - kv - 1));
            for (size_t i = 0; i < names.n; i++)
                if (dk_str_eq(names.v[i], key)) vals[i] = val;
            q = ve < rend ? ve + 1 : rend;
        }
        CHECK(dk_csvw_dict_row(&w, names.n, vals, restval));
        q = rend;
    }
    dk_xfree(vals);
    dk_vec_free(&names);
}

static void run_lines(DkBuf *out, const DkCsvCase *c) {
    DkLines it;
    dk_lines_init(&it, dk_strn(c->in, c->in_n), (DkLineMode)c->mode);
    DkStr line;
    DkStrVec f = {0};
    bool first = true;
    while (c->aux ? dk_lines_next_keep(&it, &line) : dk_lines_next(&it, &line)) {
        put_item_sep(out, &first);
        dk_buf_putc(out, 'L');
        dk_split_char(line, '\t', c->aux2, &f);
        for (size_t i = 0; i < f.n; i++) {
            if (i) dk_buf_putc(out, SEP_FIELD);
            dk_buf_put(out, f.v[i]);
        }
        if (c->aux2 < 0) { /* the two other spellings of line.split("\t") agree */
            DkStrVec g = {0};
            dk_tsv_split(line, &g);
            DkStr fixed[64];
            size_t n = dk_tsv_split_into(line, fixed, 64);
            CHECK_EQ_U64(g.n, f.n);
            CHECK_EQ_U64(n, f.n);
            for (size_t i = 0; i < g.n && i < 64; i++) CHECK(dk_str_eq(g.v[i], f.v[i]) && dk_str_eq(fixed[i], f.v[i]));
            dk_vec_free(&g);
        }
    }
    dk_vec_free(&f);
}

DK_TEST(corpus_against_cpython) {
    int failures = 0;
    size_t per_kind[5] = {0};
    for (size_t i = 0; i < DK_ARRAY_LEN(dk_csv_cases); i++) {
        const DkCsvCase *c = &dk_csv_cases[i];
        DkBuf got = {0};
        switch (c->kind) {
        case 0: run_reader(&got, c); break;
        case 1: run_writer(&got, c); break;
        case 2: run_dictreader(&got, c); break;
        case 3: run_dictwriter(&got, c); break;
        case 4: run_lines(&got, c); break;
        default: DK_ASSERT(false);
        }
        per_kind[c->kind]++;
        if (!(got.n == c->exp_n && (got.n == 0 || memcmp(got.p, c->exp, c->exp_n) == 0))) {
            if (failures++ < 8)
                dk_test__fail(__FILE__, __LINE__, "case %zu (kind %d mode %d dialect %d aux %d,%d)\n   input    %.*s\n   expected %.*s\n   got      %.*s", i,
                               c->kind, c->mode, c->dialect, c->aux, c->aux2, (int)DK_MIN(c->in_n, 160), c->in, (int)DK_MIN(c->exp_n, 240), c->exp,
                               (int)DK_MIN(got.n, 240), got.p ? got.p : "");
        }
        dk_buf_free(&got);
    }
    CHECK_EQ_I64(failures, 0);
    for (int k = 0; k < 5; k++) CHECK(per_kind[k] > 100);
}

/* ---- the limits ---- */
DK_TEST(field_size_limit) {
    /* r = list(csv.reader([text])) for 131072 x's, 131073 x's, 66000 two-byte characters, and a quoted 140000-char field:
     * the limit (csv.field_size_limit() = 131072) counts characters */
    DkBuf b = {0};
    DkCsvReader rd;
    for (int i = 0; i < 131072; i++) dk_buf_putc(&b, 'x');
    dk_buf_putc(&b, '\n');
    dk_csv_reader_init(&rd, &dk_csv_excel, dk_buf_str(&b), DK_CSV_RAW);
    CHECK_EQ_I64(dk_csv_next(&rd), 1);
    CHECK_EQ_U64(rd.row.v[0].n, 131072);
    dk_csv_reader_free(&rd);
    dk_buf_clear(&b);
    for (int i = 0; i < 131073; i++) dk_buf_putc(&b, 'x');
    dk_buf_putc(&b, '\n');
    dk_buf_putz(&b, "ok\n");
    dk_csv_reader_init(&rd, &dk_csv_excel, dk_buf_str(&b), DK_CSV_RAW);
    CHECK_EQ_I64(dk_csv_next(&rd), -1);
    CHECK_STR(rd.error, "field larger than field limit (131072)");
    CHECK_EQ_I64(dk_csv_next(&rd), 1); /* the iterator goes on with the next line */
    CHECK_STR(rd.row.v[0], "ok");
    dk_csv_reader_free(&rd);
    dk_buf_clear(&b);
    for (int i = 0; i < 66000; i++) dk_buf_putz(&b, "\303\251");
    dk_buf_putz(&b, ",a\n");
    dk_csv_reader_init(&rd, &dk_csv_excel, dk_buf_str(&b), DK_CSV_RAW);
    CHECK_EQ_I64(dk_csv_next(&rd), 1);
    CHECK_EQ_U64(rd.row.n, 2);
    CHECK_EQ_U64(rd.row.v[0].n, 132000);
    dk_csv_reader_free(&rd);
    dk_buf_clear(&b);
    dk_buf_putz(&b, "a,\"");
    for (int i = 0; i < 140000; i++) dk_buf_putc(&b, 'y');
    dk_buf_putz(&b, "\"\n");
    dk_csv_reader_init(&rd, &dk_csv_excel, dk_buf_str(&b), DK_CSV_RAW);
    CHECK_EQ_I64(dk_csv_next(&rd), -1);
    CHECK_STR(rd.error, "field larger than field limit (131072)");
    dk_csv_reader_free(&rd);
    dk_buf_free(&b);
}

/* ---- the API around the corpus ---- */
DK_TEST(views_and_kept_rows) {
    /* fields that are one run of the text are views; quoted/escaped ones are built; with a keep arena rows survive */
    DkStr text = DK_S("plain,\"quo\"\"ted\",x\n1,2\n");
    DkCsvReader rd;
    dk_csv_reader_init(&rd, &dk_csv_excel, text, DK_CSV_UNIVERSAL);
    CHECK_EQ_I64(dk_csv_next(&rd), 1);
    CHECK(rd.row.v[0].p == text.p);
    CHECK_STR(rd.row.v[1], "quo\"ted");
    CHECK(rd.row.v[1].p < text.p || rd.row.v[1].p >= text.p + text.n);
    DkArena *a = dk_arena_new(0);
    dk_csv_reader_free(&rd);
    dk_csv_reader_init(&rd, &dk_csv_excel, text, DK_CSV_UNIVERSAL);
    dk_csv_reader_keep(&rd, a);
    CHECK_EQ_I64(dk_csv_next(&rd), 1);
    DkStr kept = rd.row.v[1];
    CHECK_EQ_I64(dk_csv_next(&rd), 1);
    CHECK_STR(kept, "quo\"ted");
    CHECK_EQ_I64(rd.line_num, 2);
    CHECK_EQ_I64(dk_csv_next(&rd), 0);
    dk_csv_reader_free(&rd);
    dk_arena_free(a);
}

DK_TEST(dictreader_api) {
    /* csv.DictReader(io.StringIO(text), delimiter="\t") with a row that is short, one that is long, and blank lines */
    DkStr text = DK_S("unit\tfunction\tstatus\nu1\tf1\tMATCH\n\nu2\tf2\n\nu3\tf3\tX\textra1\textra2\n");
    DkCsvReader rd;
    dk_csv_reader_init(&rd, &dk_csv_excel_tab, text, DK_CSV_UNIVERSAL);
    DkCsvDictReader dr;
    dk_csv_dictreader_init(&dr, NULL, &rd);
    int st;
    const DkStrVec *names = dk_csv_dictreader_fieldnames(&dr, &st);
    REQUIRE(names != NULL);
    CHECK_EQ_U64(names->n, 3);
    CHECK_EQ_I64(dk_csv_dict_next(&dr), 1);
    CHECK_STR(dk_csv_dict_getz(&dr, "unit"), "u1");
    CHECK_STR(dk_csv_dict_getz(&dr, "status"), "MATCH");
    CHECK(dk_csv_dict_getz(&dr, "nope").p == NULL);
    CHECK(dk_csv_dict_has(&dr, DK_S("unit")) && !dk_csv_dict_has(&dr, DK_S("nope")));
    CHECK_EQ_I64(dk_csv_dict_next(&dr), 1);
    CHECK_STR(dk_csv_dict_getz(&dr, "function"), "f2");
    CHECK(dk_csv_dict_getz(&dr, "status").p == NULL); /* restval=None */
    dr.restval = DK_S("");
    CHECK_EQ_I64(dk_csv_dict_next(&dr), 1);
    CHECK_STR(dk_csv_dict_getz(&dr, "status"), "X");
    CHECK(dr.rest_present);
    CHECK_EQ_U64(dr.rest.n, 2);
    CHECK_STR(dr.rest.v[1], "extra2");
    CHECK_EQ_I64(dk_csv_dict_next(&dr), 0);
    dk_csv_dictreader_free(&dr);
}

DK_TEST(writer_api) {
    /* csv.DictWriter(f, fieldnames=COLUMNS, delimiter="\t", lineterminator="\n"): writeheader(), writerows(rows)
     * with a value that needs quoting, and csv.writer(f) rows with numbers */
    DkBuf b = {0};
    DkCsvDialect d = dk_csv_excel_tab;
    d.lineterminator = DK_S("\n");
    DkCsvWriter w;
    dk_csvw_init(&w, &b, &d);
    DkStr hdr[3] = {DK_S("unit"), DK_S("function"), DK_S("note")};
    CHECK(dk_csvw_row(&w, hdr, 3));
    DkStr vals[3] = {DK_S("u1"), {NULL, 0}, DK_S("has \"quote\"\tand tab")};
    CHECK(dk_csvw_dict_row(&w, 3, vals, DK_S("")));
    CHECK_STR(dk_buf_str(&b), "unit\tfunction\tnote\nu1\t\t\"has \"\"quote\"\"\tand tab\"\n");
    dk_buf_free(&b);
    dk_csvw_init(&w, &b, &dk_csv_excel);
    dk_csvw_begin(&w);
    dk_csvw_str(&w, DK_S("a,b"));
    dk_csvw_i64(&w, -12);
    dk_csvw_f64(&w, 0.1);
    dk_csvw_f64(&w, 1e22);
    dk_csvw_none(&w);
    dk_csvw_bool(&w, true);
    CHECK(dk_csvw_end(&w));
    /* the single empty field row is "" and a failing row leaves the buffer unchanged */
    CHECK(dk_csvw_row(&w, &DK_S(""), 1));
    CHECK_STR(dk_buf_str(&b), "\"a,b\",-12,0.1,1e+22,,True\r\n\"\"\r\n");
    DkCsvDialect none = dk_csv_excel;
    none.quoting = DK_CSV_NONE;
    DkBuf b2 = {0};
    DkCsvWriter w2;
    dk_csvw_init(&w2, &b2, &none);
    DkStr bad[1] = {DK_S("a,b")};
    CHECK(!dk_csvw_row(&w2, bad, 1));
    CHECK_STR(w2.error, "need to escape, but no escapechar set");
    CHECK_EQ_U64(b2.n, 0);
    DkStr empty[1] = {DK_S("")};
    CHECK(!dk_csvw_row(&w2, empty, 1));
    CHECK_STR(w2.error, "single empty field record must be quoted");
    dk_buf_free(&b2);
    dk_buf_free(&b);
}

DK_TEST(bom_and_lines) {
    CHECK_STR(dk_csv_strip_bom(DK_S("\357\273\277a,b")), "a,b");
    CHECK_STR(dk_csv_strip_bom(DK_S("a,b")), "a,b");
    /* "a\tb\t\tc".split("\t"), "".split("\t") and the maxsplit forms */
    DkStrVec v = {0};
    CHECK_EQ_U64(dk_tsv_split(DK_S("a\tb\t\tc"), &v), 4);
    CHECK_STR(v.v[2], "");
    CHECK_EQ_U64(dk_tsv_split(DK_S(""), &v), 1);
    CHECK_EQ_U64(dk_tsv_split(DK_S("\t"), &v), 2);
    CHECK_EQ_U64(dk_split_char(DK_S("a\tb\tc"), '\t', 1, &v), 2);
    CHECK_STR(v.v[1], "b\tc");
    dk_vec_free(&v);
    /* a mapped ledger is walked without copies: the lines are views of the text */
    DkStr text = DK_S("h1\th2\r\nx\ty\r\n\r\nlast");
    DkLines it;
    DkStr line;
    dk_lines_init(&it, text, DK_LINES_UNIVERSAL);
    CHECK(dk_lines_next(&it, &line) && line.p == text.p);
    CHECK_STR(line, "h1\th2");
    CHECK(dk_lines_next(&it, &line));
    CHECK(dk_lines_next(&it, &line));
    CHECK_STR(line, "");
    CHECK(dk_lines_next(&it, &line));
    CHECK_STR(line, "last");
    CHECK(!dk_lines_next(&it, &line));
}

DK_TEST_MAIN("csv")
