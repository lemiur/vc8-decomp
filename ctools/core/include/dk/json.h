// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* JSON as Python's json module does it, byte for byte: json.loads / json.load into a value tree, and json.dumps /
 * json.dump out of one (CPython 3.14).
 *
 * The tree. An DkJson value is null, bool, int, float, string, array or object, allocated from an arena (the
 * whole tree lives as long as the arena). Objects are Python dicts: members keep insertion order, setting a key
 * that exists replaces the value and keeps the key's position (so json.loads of {"a":1,"b":2,"a":3} gives a=3
 * first, b=2 second), and a deleted key that is set again goes to the end. Lookup is O(1) once an object has more
 * than 8 members. Ints are an i64, or, when Python's unbounded int does not fit, the exact decimal digits (kept
 * and written back unchanged). Floats are doubles, correctly rounded from the literal; NaN, Infinity and
 * -Infinity are accepted and written as json does. Strings are UTF-8; a lone surrogate (JSON "\ud800" gives a
 * Python str holding it) is kept as its 3-byte generalized-UTF-8 form so that it survives a round trip with
 * ensure_ascii; a valid 😀 pair is one code point, as in Python. null, true and false are shared
 * immutable nodes: never modify what dk_json_null()/dk_json_bool() return.
 *
 * Reading (json.loads). dk_json_parse gives the tree or NULL with *err filled; err == NULL throws
 * DK_ERR_FORMAT with Python's text instead (use it inside DK_TRY where the Python wrapped json.load in
 * try/except). The messages, line, column and char position are JSONDecodeError's: "Expecting value: line 1
 * column 1 (char 0)"; positions count code points, as Python's str indices do. Strict mode as the defaults
 * (control characters in strings are errors), duplicate keys last-wins, depth limited as the C stack of
 * CPython is (about 10000 levels; the exact limit of CPython depends on the stack and is not reproduced).
 * Bytes that are not valid UTF-8 are DK_JSON_E_UNICODE (what reading the file in Python raises before json sees
 * it; the message is modelled on UnicodeDecodeError's but not guaranteed identical). A text starting with the BOM
 * U+FEFF is the "Unexpected UTF-8 BOM (decode using utf-8-sig)" error, which is what
 * json.load(open(path, encoding="utf-8")) does; DK_JSON_STRIP_BOM is the utf-8-sig behaviour. The hooks the
 * project's tools pass to json.loads (parse_constant raising, parse_float raising on non-finite numbers,
 * object_pairs_hook rejecting duplicate keys) are flags.
 *
 * Writing (json.dumps / json.dump). dk_json_dumps and the streaming dk_jsonw_* functions give the bytes
 * json.dumps gives for indent (none, a width, or a string), separators (the defaults (", ", ": "), or (",", ": ")
 * when indent is given, or custom ones), sort_keys (by code point), ensure_ascii (escapes as \uXXXX with
 * lower-case hex and surrogate pairs, DEL escaped; or raw UTF-8), allow_nan, floats as repr() (dk_float_repr in
 * fmt.h), ints as digits, "[]" and "{}" for empty containers even with indent. A zeroed DkJsonDumpOpts is
 * json.dumps(x) with no options. json.dumps(x, default=str) and the like are the caller's job: convert the
 * value while building the tree.
 *
 * The streaming writer is the fast path for tools that only write records out: the same bytes as json.dumps of
 * the equivalent tree, without building it. It cannot sort keys: with sort_keys the caller writes the keys in
 * sorted order itself (dk_jsonw_tree sorts when it writes a tree). */
#pragma once
#include "str.h"
#include <stdio.h>

typedef enum {
    DK_JSON_NULL,
    DK_JSON_BOOL,
    DK_JSON_INT,
    DK_JSON_FLOAT,
    DK_JSON_STRING,
    DK_JSON_ARRAY,
    DK_JSON_OBJECT
} DkJsonKind;

typedef struct DkJson DkJson;
typedef struct {
    DkStr key;
    DkJson *val;
} DkJsonMember;

struct DkJson {
    u8 kind;     /* DkJsonKind */
    u8 big;      /* INT only: the value does not fit in an i64; u.str holds its exact decimal text */
    bool b;      /* BOOL */
    union {
        i64 i;
        double f;
        DkStr str; /* STRING; INT with big */
        struct {
            DkJson **v;
            size_t n, cap;
        } arr;
        struct {
            DkJsonMember *v; /* in insertion order */
            size_t n, cap;
            u32 *index;       /* open-addressing table of member numbers + 1 (NULL up to 8 members) */
            u32 index_cap;
        } obj;
    } u;
};

/* ---- errors ---- */
enum {
    DK_JSON_E_NONE = 0,
    DK_JSON_E_DECODE,    /* json.JSONDecodeError: msg, lineno, colno, pos */
    DK_JSON_E_VALUE,     /* a ValueError without position (int digit limit, hooks, NaN with allow_nan=False) */
    DK_JSON_E_RECURSION, /* RecursionError (nesting too deep) */
    DK_JSON_E_UNICODE    /* the input bytes are not valid UTF-8 (UnicodeDecodeError when the file was read) */
};
typedef struct {
    int kind;
    DkStr msg; /* JSONDecodeError.msg ("Expecting value"), or the ValueError text; allocated from the arena */
    i64 lineno, colno, pos; /* DECODE: 1-based line and column, 0-based char position (code points) */
} DkJsonError;
/* str(exception): "msg: line L column C (char P)" for DECODE, else the message. */
DkStr dk_json_error_str(DkArena *a, const DkJsonError *err);

/* ---- reader ---- */
enum {
    DK_JSON_STRIP_BOM = 1,         /* a leading BOM is skipped (encoding="utf-8-sig") instead of an error */
    DK_JSON_REJECT_CONSTANTS = 2,  /* parse_constant raising ValueError("invalid JSON constant: NaN") */
    DK_JSON_REJECT_NONFINITE = 4,  /* parse_float raising ValueError("nonfinite JSON number") on inf (1e999) */
    DK_JSON_REJECT_DUP_KEYS = 8,   /* object_pairs_hook raising ValueError("duplicate JSON key: k") */
    DK_JSON_BYTES = 16             /* json.loads(bytes): a UTF-8 BOM is skipped silently (utf-16/32 not handled) */
};
DkJson *dk_json_parse(DkArena *a, DkStr text, DkJsonError *err);
DkJson *dk_json_parse_ex(DkArena *a, DkStr text, unsigned flags, DkJsonError *err);

/* ---- building ---- */
DkJson *dk_json_null(void);
DkJson *dk_json_bool(bool b);
DkJson *dk_json_int(DkArena *a, i64 v);
DkJson *dk_json_uint(DkArena *a, u64 v);              /* digits when above INT64_MAX */
DkJson *dk_json_int_digits(DkArena *a, DkStr digits); /* "-?(0|[1-9][0-9]*)", any length */
DkJson *dk_json_float(DkArena *a, double v);
DkJson *dk_json_str(DkArena *a, DkStr s);            /* copies s */
DkJson *dk_json_str_ref(DkArena *a, DkStr s);        /* keeps s: it must outlive the tree */
DkJson *dk_json_strz(DkArena *a, const char *cz);
DkJson *dk_json_arr(DkArena *a);
DkJson *dk_json_arr_cap(DkArena *a, size_t cap);
DkJson *dk_json_obj(DkArena *a);

/* list.append / list[i] / len */
void dk_json_arr_push(DkArena *a, DkJson *arr, DkJson *v);
size_t dk_json_len(const DkJson *v); /* items of an array, members of an object, code points NOT: bytes of a string */
DkJson *dk_json_at(const DkJson *arr, size_t i); /* NULL when out of range */

/* dict[key] = v: replaces the value of an existing key (position kept) or appends. set copies the key, set_ref
 * keeps it. Returns the previous value or NULL. */
DkJson *dk_json_set(DkArena *a, DkJson *obj, DkStr key, DkJson *v);
DkJson *dk_json_set_ref(DkArena *a, DkJson *obj, DkStr key, DkJson *v);
/* del dict[key]: true when it existed (later members move up one place). */
bool dk_json_del(DkJson *obj, DkStr key);
const DkJsonMember *dk_json_member(const DkJson *obj, size_t i); /* the i-th member in insertion order, or NULL */

/* ---- reading values ---- */
/* dict.get(key): NULL when absent (or when obj is not an object). */
DkJson *dk_json_get(const DkJson *obj, DkStr key);
DkJson *dk_json_getz(const DkJson *obj, const char *key);
/* dict.get(key, dflt) */
DkJson *dk_json_get_or(const DkJson *obj, DkStr key, DkJson *dflt);
bool dk_json_has(const DkJson *obj, DkStr key);
/* The typed accessors return the fallback when the value is NULL or of another kind (ints and floats are
 * interchangeable as numbers: dk_json_f64 of an int gives float(int); dk_json_i64 of a float gives the fallback;
 * a big int gives the fallback from dk_json_i64). */
bool dk_json_is_null(const DkJson *v);   /* true for NULL too */
bool dk_json_is_str(const DkJson *v);
bool dk_json_is_arr(const DkJson *v);
bool dk_json_is_obj(const DkJson *v);
bool dk_json_is_int(const DkJson *v);
bool dk_json_is_num(const DkJson *v);
i64 dk_json_i64(const DkJson *v, i64 fallback);
double dk_json_f64(const DkJson *v, double fallback);
bool dk_json_bool_or(const DkJson *v, bool fallback);
DkStr dk_json_str_or(const DkJson *v, DkStr fallback);
/* d.get(key, fallback) followed by the accessor. */
i64 dk_json_get_i64(const DkJson *obj, const char *key, i64 fallback);
double dk_json_get_f64(const DkJson *obj, const char *key, double fallback);
bool dk_json_get_bool(const DkJson *obj, const char *key, bool fallback);
DkStr dk_json_get_str(const DkJson *obj, const char *key, DkStr fallback);
/* Python truthiness: not null/false/0/0.0/""/[]/{} (a NULL pointer is None). */
bool dk_json_truthy(const DkJson *v);

/* ---- writer ---- */
typedef struct {
    bool indented;      /* indent is not None */
    int indent_width;   /* indent=N: N spaces (<= 0 gives just the newlines) */
    DkStr indent;      /* indent="str": used instead of the width when .p is not NULL */
    bool custom_separators;
    DkStr item_sep, key_sep; /* separators=(item, key); the defaults are (", ", ": ") and (",", ": ") with indent */
    bool sort_keys;
    bool raw_unicode;   /* ensure_ascii=False */
    bool reject_nan;    /* allow_nan=False: NaN/inf give a ValueError("Out of range float values are not JSON compliant: nan") */
    DkJsonError *err;  /* receives that error when non-NULL (kind VALUE); the dump then returns failure */
} DkJsonDumpOpts;
#define DK_JSON_INDENT(n) ((DkJsonDumpOpts){.indented = true, .indent_width = (n)})
#define DK_JSON_COMPACT   ((DkJsonDumpOpts){.custom_separators = true, .item_sep = {",", 1}, .key_sep = {":", 1}})

/* json.dumps. On failure (reject_nan met a non-finite float) the result has p == NULL. */
DkStr dk_json_dumps(DkArena *a, const DkJson *v, const DkJsonDumpOpts *opts);
/* Appends the dump to out (the caller adds the trailing "\n" the Python wrote); false on failure. */
bool dk_json_dump_buf(DkBuf *out, const DkJson *v, const DkJsonDumpOpts *opts);
/* json.dump(v, file): writes with fwrite in chunks; false on a write error or a failure of the dump. */
bool dk_json_dump_file(FILE *f, const DkJson *v, const DkJsonDumpOpts *opts);

/* The string escaper alone: json.dumps(s) / json.dumps(s, ensure_ascii=False), quotes included. */
void dk_json_put_string(DkBuf *out, DkStr s, bool raw_unicode);

/* ---- streaming writer ----
 *     DkBuf b = {0};
 *     DkJsonW w;
 *     dk_jsonw_init(&w, &b, &DK_JSON_COMPACT);      // opts may be NULL
 *     dk_jsonw_begin_object(&w);
 *     dk_jsonw_key(&w, DK_S("t")); dk_jsonw_i64(&w, 5);
 *     dk_jsonw_end_object(&w);
 * A key is followed by exactly one value (any value, a container included). After the top-level value, w.out
 * holds json.dumps' bytes. dk_jsonw_set_spill makes the writer hand its buffer to fn and clear it whenever it
 * reaches threshold bytes (writing a big file without holding it); dk_jsonw_finish spills the rest.
 * Misuse (a value where a key is due) is an internal error (dk_panic). */
typedef bool (*DkJsonSpillFn)(void *ctx, const char *p, size_t n);
typedef struct {
    DkBuf *out;
    DkJsonDumpOpts o;
    DkStr item_sep, key_sep, indent_unit;
    bool failed;
    u8 *stack; /* per open container: 1 array, 2 object; bit 0x80 once it has an item; 0x40: a key is pending */
    size_t depth, stack_cap;
    u8 inline_stack[32];
    size_t spill_threshold;
    DkJsonSpillFn spill;
    void *spill_ctx;
} DkJsonW;
void dk_jsonw_init(DkJsonW *w, DkBuf *out, const DkJsonDumpOpts *opts);
void dk_jsonw_set_spill(DkJsonW *w, size_t threshold, DkJsonSpillFn fn, void *ctx);
bool dk_jsonw_finish(DkJsonW *w); /* spills what is left, frees the writer's stack; false after a failure */
void dk_jsonw_begin_object(DkJsonW *w);
void dk_jsonw_end_object(DkJsonW *w);
void dk_jsonw_begin_array(DkJsonW *w);
void dk_jsonw_end_array(DkJsonW *w);
void dk_jsonw_key(DkJsonW *w, DkStr key);
void dk_jsonw_null(DkJsonW *w);
void dk_jsonw_bool(DkJsonW *w, bool b);
void dk_jsonw_i64(DkJsonW *w, i64 v);
void dk_jsonw_u64(DkJsonW *w, u64 v);
void dk_jsonw_int_digits(DkJsonW *w, DkStr digits); /* an int of any size, written as given */
void dk_jsonw_f64(DkJsonW *w, double v);
void dk_jsonw_str(DkJsonW *w, DkStr s);
void dk_jsonw_strz(DkJsonW *w, const char *cz);
void dk_jsonw_tree(DkJsonW *w, const DkJson *v); /* a whole tree as one value (keys sorted when o.sort_keys) */
/* key + value in one call */
void dk_jsonw_kv_str(DkJsonW *w, const char *key, DkStr s);
void dk_jsonw_kv_i64(DkJsonW *w, const char *key, i64 v);
void dk_jsonw_kv_f64(DkJsonW *w, const char *key, double v);
void dk_jsonw_kv_bool(DkJsonW *w, const char *key, bool b);
