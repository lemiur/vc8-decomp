// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Python's csv module (CPython 3.14): csv.reader / csv.DictReader, csv.writer / csv.DictWriter, the excel,
 * excel-tab and unix dialects, plus the fast TSV path for the project's ledgers.
 *
 * The reader is CPython's state machine (_csv.c) fed with the same "lines" Python hands it, so quoted fields with
 * embedded newlines, doubled quotes, lone quotes in unquoted fields, escapechar, skipinitialspace, strict and the
 * errors ("new-line character seen in unquoted field - do you need to open the file with newline=''?", "',' expected
 * after '\"'", "unexpected end of data", "field larger than field limit (131072)") come out as in Python. What a
 * line is depends on how the Python opened the file, so the reader takes a mode:
 *     DK_CSV_RAW        open(path, newline="")          lines end at \n, \r or \r\n, kept as they are
 *     DK_CSV_UNIVERSAL  open(path) (newline=None)       the same split, every ending translated to "\n"
 *     DK_CSV_LF         io.StringIO(text), newline="\n"  lines end at "\n" only ("\r" stays in the line)
 * or the caller passes the lines itself (dk_csv_reader_init_lines: text.splitlines(), a list of strings). The
 * text is UTF-8 (the BOM of utf-8-sig is the caller's to skip: dk_csv_strip_bom). Dialect characters must be
 * ASCII. Reading with QUOTE_NONNUMERIC / QUOTE_STRINGS / QUOTE_NOTNULL (float conversion, None fields) is not
 * supported (no tool uses it); QUOTE_MINIMAL and QUOTE_ALL read alike, QUOTE_NONE has no quote character.
 *
 * Fields are views into the text when the field is one contiguous run of it (the usual case: no copying), else
 * built in the reader's own buffer (or in the arena when one is given to dk_csv_reader_keep). A row is valid
 * until the next dk_csv_next call unless the reader keeps its rows in an arena; the views into the text always
 * live as long as the text.
 *
 * The writer is csv.writer.writerow: QUOTE_MINIMAL quotes a field that contains the delimiter, the quote
 * character, the escape character, "\n", "\r" or a character of the line terminator; the single empty field row
 * is written as "" ; None is the empty field; numbers are written as str() (floats through dk_float_repr);
 * the line terminator defaults to "\r\n" in the excel dialects. A failing row (csv.Error: "need to escape, but
 * no escapechar set", "single empty field record must be quoted") appends nothing.
 *
 * TSV. The project's tools mostly read tab-separated files with line.split("\t") (no quoting) and a few with
 * csv.reader(delimiter="\t"): the two differ when a field holds a double quote, so both exist here. DkLines walks
 * a mapped file's lines without copying; dk_tsv_split is str.split("\t") over a line without copying. */
#pragma once
#include "str.h"

/* ---- dialects ---- */
enum { DK_CSV_MINIMAL = 0, DK_CSV_ALL = 1, DK_CSV_NONNUMERIC = 2, DK_CSV_NONE = 3, DK_CSV_STRINGS = 4,
       DK_CSV_NOTNULL = 5 };
typedef struct {
    int delimiter;      /* ASCII character */
    int quotechar;      /* ASCII character, or -1 for None */
    int escapechar;     /* ASCII character, or -1 for None */
    bool doublequote;
    bool skipinitialspace;
    bool strict;
    int quoting;        /* DK_CSV_* (QUOTE_*) */
    DkStr lineterminator;
} DkCsvDialect;
extern const DkCsvDialect dk_csv_excel;     /* delimiter ',', quotechar '"', doublequote, lineterminator "\r\n" */
extern const DkCsvDialect dk_csv_excel_tab; /* the same with delimiter '\t' */
extern const DkCsvDialect dk_csv_unix;      /* QUOTE_ALL, lineterminator "\n" */

DkStr dk_csv_strip_bom(DkStr text); /* the text without a leading UTF-8 BOM (encoding="utf-8-sig") */

/* ---- reader ---- */
typedef enum { DK_CSV_RAW, DK_CSV_UNIVERSAL, DK_CSV_LF } DkCsvLineMode;

typedef struct {
    DkCsvDialect d;
    /* input */
    DkStr text;
    size_t pos;
    int mode;               /* DkCsvLineMode, or -1 when the caller gave lines */
    const DkStr *lines;
    size_t nlines, next_line;
    /* result of the last dk_csv_next */
    DkStrVec row;          /* the fields (row.n of them) */
    i64 line_num;           /* csv.reader.line_num: lines consumed so far */
    DkStr error;           /* the csv.Error text after dk_csv_next returned -1 */
    /* state machine */
    int state;
    u8 special[2][256];     /* IN_FIELD and IN_QUOTED_FIELD: the bytes that end a run of ordinary characters */
    DkArena *keep;         /* fields that are not views are copied here when set ... */
    DkArena *own;          /* ... else into this private arena, reset at every row */
    DkArenaMark own_mark;
    char errbuf[96];
    DkBuf cur;             /* the field under construction when it is not a view */
    bool in_cur;
    const char *view_p;     /* the field as a view of the text, while it is one contiguous run */
    size_t view_n;
    size_t field_limit;     /* csv.field_size_limit(): 131072 */
} DkCsvReader;

void dk_csv_reader_init(DkCsvReader *rd, const DkCsvDialect *d, DkStr text, DkCsvLineMode mode);
void dk_csv_reader_init_lines(DkCsvReader *rd, const DkCsvDialect *d, const DkStr *lines, size_t n);
/* Fields that are not views of the text are allocated from a instead of the reader's reusable buffer, so rows
 * stay valid after the next call. */
void dk_csv_reader_keep(DkCsvReader *rd, DkArena *a);
void dk_csv_reader_free(DkCsvReader *rd);
/* The next row into rd->row: 1 for a row, 0 at the end, -1 for a csv.Error (text in rd->error; the next call
 * goes on with the next line, as the Python iterator does). An empty line is a row with no fields ([]). */
int dk_csv_next(DkCsvReader *rd);

/* csv.DictReader. The first row gives the fieldnames (a first empty line gives none); rows that are empty lists
 * are skipped; a short row gets restval (None when restval.p == NULL) for the missing fields; a long row puts
 * the extra fields in rest (restkey, None by default; rest_present says whether there are some). Values are
 * DkStr views as in the reader; a None value has p == NULL. */
typedef struct {
    DkCsvReader rd;
    DkArena *a;
    DkStrVec names;        /* fieldnames */
    bool have_names;
    DkStr restval;         /* p == NULL: None */
    DkStr restkey;         /* p == NULL: None */
    DkStrVec cells;        /* the current row, aligned with names */
    DkStrVec rest;         /* the fields beyond names */
    bool rest_present;
    u32 *index;             /* name -> last position of that name + 1 (open addressing), built with the names */
    u32 index_cap;
    i64 line_num;
} DkCsvDictReader;
/* The reader is moved into the DictReader (init it first, do not use it after). */
void dk_csv_dictreader_init(DkCsvDictReader *dr, DkArena *a, const DkCsvReader *rd);
void dk_csv_dictreader_free(DkCsvDictReader *dr);
/* DictReader.fieldnames: reads the header row when not yet read. NULL when the input is empty. Returns -1 via
 * *status on a csv.Error (text in dr->rd.error), 0 when the input is empty, 1 otherwise. */
const DkStrVec *dk_csv_dictreader_fieldnames(DkCsvDictReader *dr, int *status);
/* The next record: 1, 0 at the end, -1 for a csv.Error. */
int dk_csv_dict_next(DkCsvDictReader *dr);
/* row[name] / row.get(name): a view; p == NULL when the key is absent or its value is None. */
DkStr dk_csv_dict_get(const DkCsvDictReader *dr, DkStr name);
DkStr dk_csv_dict_getz(const DkCsvDictReader *dr, const char *name);
bool dk_csv_dict_has(const DkCsvDictReader *dr, DkStr name); /* name in row (a restkey counts when set) */

/* ---- writer ---- */
typedef struct {
    DkCsvDialect d;
    DkBuf *out;
    size_t row_start;
    size_t nfields;
    bool last_none;
    bool failed;
    DkStr error;  /* the csv.Error text after a failed dk_csvw_end / dk_csvw_row */
} DkCsvWriter;
void dk_csvw_init(DkCsvWriter *w, DkBuf *out, const DkCsvDialect *d);
/* writerow with string fields: false on csv.Error (nothing appended). */
bool dk_csvw_row(DkCsvWriter *w, const DkStr *fields, size_t n);
/* writerow field by field. begin; any number of fields; end appends the terminator (false after any error). */
void dk_csvw_begin(DkCsvWriter *w);
void dk_csvw_str(DkCsvWriter *w, DkStr s);
void dk_csvw_none(DkCsvWriter *w);                 /* None: the empty field */
void dk_csvw_i64(DkCsvWriter *w, i64 v);           /* str(int) */
void dk_csvw_f64(DkCsvWriter *w, double v);        /* str(float) */
void dk_csvw_bool(DkCsvWriter *w, bool v);         /* "True" / "False" */
void dk_csvw_number_text(DkCsvWriter *w, DkStr s);/* a number already spelled (a big int): unquoted under QUOTE_NONNUMERIC */
bool dk_csvw_end(DkCsvWriter *w);
/* csv.DictWriter: writeheader() is dk_csvw_row of the fieldnames. A dict row is given as values aligned with
 * the fieldnames; a value with p == NULL is missing and gets restval (extrasaction="raise" is the caller's check). */
bool dk_csvw_dict_row(DkCsvWriter *w, size_t nfields, const DkStr *values, DkStr restval);

/* ---- lines and TSV ---- */
typedef enum {
    DK_LINES_UNIVERSAL, /* iterating open(path): \n, \r\n, \r end a line; the line comes without its ending */
    DK_LINES_LF,        /* open(path, newline="\n") or text.split("\n") minus the empty last piece: "\n" only */
    DK_LINES_SPLITLINES,/* text.splitlines(): the Unicode line boundaries */
    DK_LINES_SPLIT_LF   /* text.split("\n"): like LF but a text ending in "\n" gives a last empty line */
} DkLineMode;
typedef struct {
    const char *p, *end;
    int mode;
    bool done;
} DkLines;
void dk_lines_init(DkLines *it, DkStr text, DkLineMode mode);
/* The next line without its ending (a view into the text); false at the end. */
bool dk_lines_next(DkLines *it, DkStr *line);
/* The same with the ending kept (keepends=True; for DK_LINES_UNIVERSAL the ending is the original, not translated). */
bool dk_lines_next_keep(DkLines *it, DkStr *line);

/* line.split("\t") (any one-byte separator): views into line, no copying; an empty line gives one empty field.
 * The vector is cleared first. maxsplit < 0 is unlimited. Returns the field count. */
size_t dk_tsv_split(DkStr line, DkStrVec *out);
size_t dk_split_char(DkStr line, char sep, int maxsplit, DkStrVec *out);
/* The same into a fixed array; returns the true field count (when it exceeds cap only cap fields were stored). */
size_t dk_tsv_split_into(DkStr line, DkStr *out, size_t cap);
