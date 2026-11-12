// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore csv: Python's csv.reader / csv.DictReader / csv.writer / csv.DictWriter (CPython 3.14's _csv.c and
 * csv.py) over UTF-8 text. The TSV helpers are in csv_tsv.c. */
#include "dk/csv.h"
#include "dk/arena.h"
#include <stdio.h>

#include "dk/fmt.h"

const DkCsvDialect dk_csv_excel = {',', '"', -1, true, false, false, DK_CSV_MINIMAL, {"\r\n", 2}};
const DkCsvDialect dk_csv_excel_tab = {'\t', '"', -1, true, false, false, DK_CSV_MINIMAL, {"\r\n", 2}};
const DkCsvDialect dk_csv_unix = {',', '"', -1, true, false, false, DK_CSV_ALL, {"\n", 1}};

DkStr dk_csv_strip_bom(DkStr text) {
    if (text.n >= 3 && memcmp(text.p, "\xEF\xBB\xBF", 3) == 0) return dk_strn(text.p + 3, text.n - 3);
    return text;
}

/* A dialect without a quote character cannot quote (Python's default for quotechar=None). */
static DkCsvDialect normalize(const DkCsvDialect *d) {
    DkCsvDialect n = *d;
    DK_ASSERT(n.delimiter >= 0 && n.delimiter < 128);
    DK_ASSERT(n.quotechar < 128 && n.escapechar < 128);
    if (n.quotechar < 0) n.quoting = DK_CSV_NONE;
    return n;
}

/* ---- the reader: CPython's parse_process_char ---- */
enum {
    START_RECORD,
    START_FIELD,
    ESCAPED_CHAR,
    IN_FIELD,
    IN_QUOTED_FIELD,
    ESCAPE_IN_QUOTED_FIELD,
    QUOTE_IN_QUOTED_FIELD,
    EAT_CRNL,
    AFTER_ESCAPED_CRNL
};
#define EOL (-2) /* the end of a line, as CPython's EOL: never a byte value and never "no such character" (-1) */

void dk_csv_reader_init(DkCsvReader *rd, const DkCsvDialect *d, DkStr text, DkCsvLineMode mode) {
    memset(rd, 0, sizeof *rd);
    rd->d = normalize(d);
    rd->text = text;
    rd->mode = (int)mode;
    rd->field_limit = 131072;
    const DkCsvDialect *x = &rd->d;
    u8 *f = rd->special[0], *q = rd->special[1];
    f['\n'] = f['\r'] = 1;
    f[x->delimiter] = 1;
    if (x->escapechar >= 0) f[x->escapechar] = q[x->escapechar] = 1;
    if (x->quoting != DK_CSV_NONE && x->quotechar >= 0) q[x->quotechar] = 1;
}

void dk_csv_reader_init_lines(DkCsvReader *rd, const DkCsvDialect *d, const DkStr *lines, size_t n) {
    dk_csv_reader_init(rd, d, dk_strn("", 0), DK_CSV_RAW);
    rd->mode = -1;
    rd->lines = lines;
    rd->nlines = n;
}

void dk_csv_reader_keep(DkCsvReader *rd, DkArena *a) { rd->keep = a; }

void dk_csv_reader_free(DkCsvReader *rd) {
    dk_vec_free(&rd->row);
    dk_buf_free(&rd->cur);
    if (rd->own) dk_arena_free(rd->own);
    rd->own = NULL;
}

static bool reader_fail(DkCsvReader *rd, const char *msg) {
    rd->error = dk_str(msg);
    return false;
}

static size_t field_len(const DkCsvReader *rd) { return rd->in_cur ? rd->cur.n : rd->view_n; }

static bool check_limit(DkCsvReader *rd) {
    size_t n = field_len(rd);
    if (n <= rd->field_limit) return true;
    /* the limit counts characters, not bytes */
    const char *p = rd->in_cur ? rd->cur.p : rd->view_p;
    size_t cps = 0;
    for (size_t i = 0; i < n; i++) cps += ((unsigned char)p[i] & 0xC0) != 0x80;
    if (cps <= rd->field_limit) return true;
    return reader_fail(rd, "field larger than field limit (131072)");
}

/* Appends n bytes of the text itself to the current field: a view while the field is one contiguous run. */
static bool add_run(DkCsvReader *rd, const char *p, size_t n) {
    if (!rd->in_cur) {
        if (rd->view_n == 0) {
            rd->view_p = p;
            rd->view_n = n;
            return n <= rd->field_limit || check_limit(rd);
        }
        if (rd->view_p + rd->view_n == p) {
            rd->view_n += n;
            return rd->view_n <= rd->field_limit || check_limit(rd);
        }
        dk_buf_clear(&rd->cur);
        dk_buf_putn(&rd->cur, rd->view_p, rd->view_n);
        rd->in_cur = true;
    }
    dk_buf_putn(&rd->cur, p, n);
    return rd->cur.n <= rd->field_limit || check_limit(rd);
}

static bool add_synth(DkCsvReader *rd, char c) {
    if (!rd->in_cur) {
        dk_buf_clear(&rd->cur);
        if (rd->view_n) dk_buf_putn(&rd->cur, rd->view_p, rd->view_n);
        rd->in_cur = true;
    }
    dk_buf_putc(&rd->cur, c);
    return rd->cur.n <= rd->field_limit || check_limit(rd);
}

static bool add_char(DkCsvReader *rd, int c, const char *src) {
    if (src && c >= 0) return add_run(rd, src, 1);
    return add_synth(rd, (char)c);
}

static void save_field(DkCsvReader *rd) {
    DkStr f;
    if (rd->in_cur) {
        DkArena *a = rd->keep;
        if (!a) {
            if (!rd->own) {
                rd->own = dk_arena_new(1 << 16);
                rd->own_mark = dk_arena_mark(rd->own);
            }
            a = rd->own;
        }
        f = dk_str_dup(a, dk_buf_str(&rd->cur));
    } else {
        f = (DkStr){rd->view_n ? rd->view_p : "", rd->view_n};
    }
    dk_vec_push(&rd->row, f);
    rd->view_p = NULL;
    rd->view_n = 0;
    rd->in_cur = false;
}

/* One character (c < 0 never; EOL is the end of the line). src is the character's address in the text, or NULL. */
static bool step(DkCsvReader *rd, int c, const char *src) {
    const DkCsvDialect *d = &rd->d;
    bool can_quote = d->quoting != DK_CSV_NONE;
    switch (rd->state) {
    case START_RECORD:
        if (c == EOL) break;
        if (c == '\n' || c == '\r') {
            rd->state = EAT_CRNL;
            break;
        }
        rd->state = START_FIELD;
        /* fall through: a normal character starts a field */
    case START_FIELD:
        if (c == '\n' || c == '\r' || c == EOL) {
            save_field(rd);
            rd->state = c == EOL ? START_RECORD : EAT_CRNL;
        } else if (c == d->quotechar && can_quote) {
            rd->state = IN_QUOTED_FIELD;
        } else if (c == d->escapechar) {
            rd->state = ESCAPED_CHAR;
        } else if (c == ' ' && d->skipinitialspace) {
            /* ignore a space at the start of a field */
        } else if (c == d->delimiter) {
            save_field(rd);
        } else {
            if (!add_char(rd, c, src)) return false;
            rd->state = IN_FIELD;
        }
        break;
    case ESCAPED_CHAR:
        if (c == '\n' || c == '\r') {
            if (!add_char(rd, c, src)) return false;
            rd->state = AFTER_ESCAPED_CRNL;
            break;
        }
        if (c == EOL) {
            c = '\n';
            src = NULL;
        }
        if (!add_char(rd, c, src)) return false;
        rd->state = IN_FIELD;
        break;
    case AFTER_ESCAPED_CRNL:
        if (c == EOL) break;
        /* fall through */
    case IN_FIELD:
        if (c == '\n' || c == '\r' || c == EOL) {
            save_field(rd);
            rd->state = c == EOL ? START_RECORD : EAT_CRNL;
        } else if (c == d->escapechar) {
            rd->state = ESCAPED_CHAR;
        } else if (c == d->delimiter) {
            save_field(rd);
            rd->state = START_FIELD;
        } else {
            /* the state is left as it is: after an escaped newline (AFTER_ESCAPED_CRNL) it stays, as in CPython */
            if (!add_char(rd, c, src)) return false;
        }
        break;
    case IN_QUOTED_FIELD:
        if (c == EOL) {
            /* the line break of a field that goes on in the next line is not part of the field */
        } else if (c == d->escapechar) {
            rd->state = ESCAPE_IN_QUOTED_FIELD;
        } else if (c == d->quotechar && can_quote) {
            rd->state = d->doublequote ? QUOTE_IN_QUOTED_FIELD : IN_FIELD;
        } else {
            if (!add_char(rd, c, src)) return false;
        }
        break;
    case ESCAPE_IN_QUOTED_FIELD:
        if (c == EOL) {
            c = '\n';
            src = NULL;
        }
        if (!add_char(rd, c, src)) return false;
        rd->state = IN_QUOTED_FIELD;
        break;
    case QUOTE_IN_QUOTED_FIELD:
        if (can_quote && c == d->quotechar) {
            if (!add_char(rd, c, src)) return false;
            rd->state = IN_QUOTED_FIELD;
        } else if (c == d->delimiter) {
            save_field(rd);
            rd->state = START_FIELD;
        } else if (c == '\n' || c == '\r' || c == EOL) {
            save_field(rd);
            rd->state = c == EOL ? START_RECORD : EAT_CRNL;
        } else if (!d->strict) {
            if (!add_char(rd, c, src)) return false;
            rd->state = IN_FIELD;
        } else {
            snprintf(rd->errbuf, sizeof rd->errbuf, "'%c' expected after '%c'", d->delimiter, d->quotechar);
            rd->error = dk_str(rd->errbuf);
            return false;
        }
        break;
    case EAT_CRNL:
        if (c == '\n' || c == '\r') {
            /* eaten */
        } else if (c == EOL) {
            rd->state = START_RECORD;
        } else {
            return reader_fail(rd, "new-line character seen in unquoted field - do you need to open the file with newline=''?");
        }
        break;
    }
    return true;
}

/* The characters p[0..e) of the text. Runs of ordinary characters in the two scanning states are taken at once. */
static bool feed(DkCsvReader *rd, const char *p, const char *e) {
    while (p < e) {
        if (rd->state == IN_FIELD || rd->state == IN_QUOTED_FIELD) {
            const u8 *sp = rd->special[rd->state == IN_QUOTED_FIELD];
            const char *q = p;
            while (q < e && !sp[(u8)*q]) q++;
            if (q != p) {
                if (!add_run(rd, p, (size_t)(q - p))) return false;
                p = q;
                if (p == e) break;
            }
        }
        if (!step(rd, (u8)*p, p)) return false;
        p++;
    }
    return true;
}

/* The next line of the input: its characters [*bp, *be) and whether a "\n" the text did not have in that form
 * (universal newlines) ends it. false at the end of the input. */
static bool next_line(DkCsvReader *rd, const char **bp, const char **be, bool *synth_nl) {
    *synth_nl = false;
    if (rd->mode < 0) {
        if (rd->next_line >= rd->nlines) return false;
        DkStr l = rd->lines[rd->next_line++];
        *bp = l.p;
        *be = l.p + l.n;
        return true;
    }
    const char *p = rd->text.p + rd->pos, *end = rd->text.p + rd->text.n;
    if (p >= end) return false;
    *bp = p;
    const char *q = p;
    if (rd->mode == DK_CSV_LF) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        q = nl ? nl + 1 : end;
        *be = q;
    } else {
        while (q < end && *q != '\n' && *q != '\r') q++;
        if (q < end) {
            const char *after = q + 1;
            if (*q == '\r' && after < end && *after == '\n') after++;
            if (rd->mode == DK_CSV_RAW) {
                *be = after;
            } else {
                *be = q;
                *synth_nl = true;
            }
            q = after;
        } else {
            *be = q;
        }
    }
    rd->pos = (size_t)(q - rd->text.p);
    return true;
}

int dk_csv_next(DkCsvReader *rd) {
    rd->row.n = 0;
    rd->error = (DkStr){NULL, 0};
    rd->state = START_RECORD;
    rd->view_p = NULL;
    rd->view_n = 0;
    rd->in_cur = false;
    if (rd->own) dk_arena_reset(rd->own, rd->own_mark);
    do {
        const char *bp, *be;
        bool synth_nl;
        if (!next_line(rd, &bp, &be, &synth_nl)) {
            /* the end of the input: a field in progress is the last row (or "unexpected end of data") */
            if (field_len(rd) != 0 || rd->state == IN_QUOTED_FIELD) {
                if (rd->d.strict) {
                    reader_fail(rd, "unexpected end of data");
                    return -1;
                }
                save_field(rd);
                return 1;
            }
            return 0;
        }
        rd->line_num++;
        if (!feed(rd, bp, be)) return -1;
        if (synth_nl && !step(rd, '\n', NULL)) return -1;
        if (!step(rd, EOL, NULL)) return -1;
    } while (rd->state != START_RECORD);
    return 1;
}

/* ---- DictReader ---- */
static u32 name_hash(DkStr s) {
    u32 h = 2166136261u;
    for (size_t i = 0; i < s.n; i++) h = (h ^ (u8)s.p[i]) * 16777619u;
    return h;
}

/* The slot of name in the index: the one holding it, or the empty slot where it goes. */
static u32 *index_slot(u32 *tab, u32 cap, const DkStrVec *names, DkStr name) {
    u32 mask = cap - 1, i = name_hash(name) & mask;
    while (tab[i] && !dk_str_eq(names->v[tab[i] - 1], name)) i = (i + 1) & mask;
    return &tab[i];
}

void dk_csv_dictreader_init(DkCsvDictReader *dr, DkArena *a, const DkCsvReader *rd) {
    memset(dr, 0, sizeof *dr);
    dr->rd = *rd;
    dr->a = a ? a : dk_arena();
}

void dk_csv_dictreader_free(DkCsvDictReader *dr) {
    dk_csv_reader_free(&dr->rd);
    dk_vec_free(&dr->names);
    dk_vec_free(&dr->cells);
    dk_vec_free(&dr->rest);
    dk_xfree(dr->index);
    dr->index = NULL;
}

const DkStrVec *dk_csv_dictreader_fieldnames(DkCsvDictReader *dr, int *status) {
    int st = 1;
    if (!dr->have_names) {
        st = dk_csv_next(&dr->rd);
        if (st > 0) {
            dr->have_names = true;
            dr->index_cap = 16;
            while (dr->index_cap < dr->rd.row.n * 2) dr->index_cap <<= 1;
            dr->index = (u32 *)dk_xcalloc(dr->index_cap, sizeof(u32));
            for (size_t i = 0; i < dr->rd.row.n; i++) {
                DkStr n = dk_str_dup(dr->a, dr->rd.row.v[i]);
                dk_vec_push(&dr->names, n);
                /* a repeated name: the last position wins, as dict(zip(fieldnames, row)) */
                u32 *slot = index_slot(dr->index, dr->index_cap, &dr->names, n);
                *slot = (u32)i + 1;
            }
        }
        dr->line_num = dr->rd.line_num;
    }
    if (status) *status = st;
    return dr->have_names ? &dr->names : NULL;
}

int dk_csv_dict_next(DkCsvDictReader *dr) {
    if (!dr->have_names) {
        int st;
        dk_csv_dictreader_fieldnames(dr, &st);
        if (st <= 0) return st;
    }
    int st = dk_csv_next(&dr->rd);
    if (st <= 0) return st;
    dr->line_num = dr->rd.line_num;
    while (dr->rd.row.n == 0) { /* a blank line is the empty list: skipped */
        st = dk_csv_next(&dr->rd);
        if (st <= 0) return st;
    }
    dr->line_num = dr->rd.line_num; /* csv.py's self.fieldnames getter, read after the loop, refreshes it */
    size_t lf = dr->names.n, lr = dr->rd.row.n;
    dk_vec_clear(&dr->cells);
    dk_vec_clear(&dr->rest);
    for (size_t i = 0; i < lf; i++) dk_vec_push(&dr->cells, i < lr ? dr->rd.row.v[i] : dr->restval);
    dr->rest_present = lr > lf;
    for (size_t i = lf; i < lr; i++) dk_vec_push(&dr->rest, dr->rd.row.v[i]);
    return 1;
}

DkStr dk_csv_dict_get(const DkCsvDictReader *dr, DkStr name) {
    if (!dr->index || dr->cells.n != dr->names.n) return (DkStr){NULL, 0};
    u32 idx = *index_slot(dr->index, dr->index_cap, &dr->names, name);
    if (!idx) return (DkStr){NULL, 0};
    return dr->cells.v[idx - 1];
}

DkStr dk_csv_dict_getz(const DkCsvDictReader *dr, const char *name) { return dk_csv_dict_get(dr, dk_str(name)); }

bool dk_csv_dict_has(const DkCsvDictReader *dr, DkStr name) {
    if (dr->index && *index_slot(dr->index, dr->index_cap, &dr->names, name)) return true;
    return dr->rest_present && dr->restkey.p && dk_str_eq(dr->restkey, name);
}

/* ---- the writer: CPython's join_append / csv_writerow ---- */
void dk_csvw_init(DkCsvWriter *w, DkBuf *out, const DkCsvDialect *d) {
    memset(w, 0, sizeof *w);
    w->d = normalize(d);
    w->out = out;
}

void dk_csvw_begin(DkCsvWriter *w) {
    w->row_start = w->out->n;
    w->nfields = 0;
    w->failed = false;
    w->error = (DkStr){NULL, 0};
    w->last_none = false;
}

static void writer_fail(DkCsvWriter *w, const char *msg) {
    w->failed = true;
    w->error = dk_str(msg);
}

typedef enum { FK_STR, FK_NONE, FK_NUM } FieldKind;

static bool needs_special(const DkCsvDialect *d, unsigned char c) {
    if (c == d->delimiter || c == '\n' || c == '\r') return true;
    if ((int)c == d->escapechar || (int)c == d->quotechar) return true;
    for (size_t i = 0; i < d->lineterminator.n; i++)
        if ((unsigned char)d->lineterminator.p[i] == c) return true;
    return false;
}

static void put_field(DkCsvWriter *w, DkStr s, FieldKind kind) {
    if (w->failed) return;
    const DkCsvDialect *d = &w->d;
    DkBuf *out = w->out;
    bool quoted;
    switch (d->quoting) {
    case DK_CSV_NONNUMERIC: quoted = kind != FK_NUM; break;
    case DK_CSV_ALL: quoted = true; break;
    case DK_CSV_STRINGS: quoted = kind == FK_STR; break;
    case DK_CSV_NOTNULL: quoted = kind != FK_NONE; break;
    default: quoted = false; break;
    }
    /* an empty field would vanish when read back with skipinitialspace and a space delimiter: it is quoted */
    if (s.n == 0 && d->delimiter == ' ' && d->skipinitialspace) {
        if (d->quoting == DK_CSV_NONE || (kind == FK_NONE && (d->quoting == DK_CSV_STRINGS || d->quoting == DK_CSV_NOTNULL))) {
            writer_fail(w, "empty field must be quoted if delimiter is a space and skipinitialspace is true");
            return;
        }
        quoted = true;
    }
    /* first pass: does the field need quoting, and can it be written at all? */
    size_t extra = 0;
    if (kind != FK_NONE) {
        for (size_t i = 0; i < s.n; i++) {
            unsigned char c = (unsigned char)s.p[i];
            if (!needs_special(d, c)) continue;
            bool want_escape = false;
            if (d->quoting == DK_CSV_NONE) {
                want_escape = true;
            } else {
                if ((int)c == d->quotechar) {
                    if (d->doublequote) extra++;
                    else want_escape = true;
                } else if ((int)c == d->escapechar) {
                    want_escape = true;
                }
                if (!want_escape) quoted = true;
            }
            if (want_escape) {
                if (d->escapechar < 0) {
                    writer_fail(w, "need to escape, but no escapechar set");
                    return;
                }
                extra++;
            }
        }
    }
    size_t n = (kind == FK_NONE ? 0 : s.n);
    dk_buf_reserve(out, n + extra + 4);
    if (w->nfields > 0) dk_buf_putc(out, (char)d->delimiter);
    if (quoted) dk_buf_putc(out, (char)d->quotechar);
    if (kind == FK_NONE) {
        /* nothing */
    } else if (!extra && !quoted) {
        dk_buf_putn(out, s.p, s.n);
    } else {
        for (size_t i = 0; i < s.n; i++) {
            unsigned char c = (unsigned char)s.p[i];
            if (needs_special(d, c)) {
                bool want_escape = false;
                if (d->quoting == DK_CSV_NONE) {
                    want_escape = true;
                } else if ((int)c == d->quotechar) {
                    if (d->doublequote) dk_buf_putc(out, (char)d->quotechar);
                    else want_escape = true;
                } else if ((int)c == d->escapechar) {
                    want_escape = true;
                }
                if (want_escape) dk_buf_putc(out, (char)d->escapechar);
            }
            dk_buf_putc(out, (char)c);
        }
    }
    if (quoted) dk_buf_putc(out, (char)d->quotechar);
    w->nfields++;
    w->last_none = kind == FK_NONE;
}

void dk_csvw_str(DkCsvWriter *w, DkStr s) { put_field(w, s, FK_STR); }
void dk_csvw_none(DkCsvWriter *w) { put_field(w, dk_strn("", 0), FK_NONE); }
void dk_csvw_number_text(DkCsvWriter *w, DkStr s) { put_field(w, s, FK_NUM); }
void dk_csvw_bool(DkCsvWriter *w, bool v) { put_field(w, v ? DK_S("True") : DK_S("False"), FK_NUM); }

void dk_csvw_i64(DkCsvWriter *w, i64 v) {
    char tmp[24];
    int n = snprintf(tmp, sizeof tmp, "%lld", (long long)v);
    put_field(w, dk_strn(tmp, (size_t)n), FK_NUM);
}

void dk_csvw_f64(DkCsvWriter *w, double v) {
    char tmp[32];
    size_t n = dk_float_repr(v, tmp);
    put_field(w, dk_strn(tmp, n), FK_NUM);
}

bool dk_csvw_end(DkCsvWriter *w) {
    DkBuf *out = w->out;
    const DkCsvDialect *d = &w->d;
    if (!w->failed && w->nfields > 0 && out->n == w->row_start) {
        /* a record that is a single empty field would read back as an empty line: it is written as "" */
        if (d->quoting == DK_CSV_NONE ||
            (w->last_none && (d->quoting == DK_CSV_STRINGS || d->quoting == DK_CSV_NOTNULL))) {
            writer_fail(w, "single empty field record must be quoted");
        } else {
            dk_buf_putc(out, (char)d->quotechar);
            dk_buf_putc(out, (char)d->quotechar);
        }
    }
    if (w->failed) {
        out->n = w->row_start;
        if (out->p) out->p[out->n] = 0;
        return false;
    }
    dk_buf_put(out, d->lineterminator);
    return true;
}

bool dk_csvw_row(DkCsvWriter *w, const DkStr *fields, size_t n) {
    dk_csvw_begin(w);
    for (size_t i = 0; i < n; i++) dk_csvw_str(w, fields[i]);
    return dk_csvw_end(w);
}

bool dk_csvw_dict_row(DkCsvWriter *w, size_t nfields, const DkStr *values, DkStr restval) {
    dk_csvw_begin(w);
    for (size_t i = 0; i < nfields; i++) {
        DkStr v = values[i].p ? values[i] : restval;
        if (v.p) dk_csvw_str(w, v);
        else dk_csvw_none(w);
    }
    return dk_csvw_end(w);
}
