// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Tests of json.h against CPython 3.14.8.
 *  - json_corpus.h: thousands of generated cases (json.loads + json.dumps with 23 option sets, and the exceptions),
 *    see the generator in its header comment. The option sets cover the json.dump/json.dumps combinations the
 *    tools use:
 *    none; indent=1/2/0 (alone and with sort_keys=True); sort_keys=True; allow_nan=False; ensure_ascii=False with
 *    allow_nan=False, with separators=(",", ":"), with indent=1/2, with sort_keys; separators=(",", ":") alone and
 *    with sort_keys. (default=str and the like are the caller's, see json.h.)
 *  - hand-written cases for the builder, the accessors, the streaming writer and the limits; the expected strings
 *    in them come from
 *        d = {"a": [1, 2.5, "x\u00e9"], "b": {}, "c": [], "d": None, "e": {"f": [True, False, {"g": 1}]}}
 *        json.dumps(d) / json.dumps(d, indent=2) / json.dumps(d, indent="\t", ensure_ascii=False) /
 *        json.dumps(d, separators=(",", ":"), ensure_ascii=False) / json.dumps([[], [[]], {}, [{}]], indent=1) /
 *        json.dumps({"b": 1, "a": {"z": 1, "y": 2}}, sort_keys=True, indent=1) */
#include "dk/dk.h"
#include "dk/json.h"
#include "dk/test.h"
#include <math.h>
#include "json_corpus.h"

static DkJsonDumpOpts opts_for(int id) {
    DkJsonDumpOpts o = {0};
    DkStr comma = DK_S(","), colon = DK_S(":");
    switch (id) {
    case 0: break;
    case 1: o.indented = true; o.indent_width = 1; break;
    case 2: o.indented = true; o.indent_width = 2; break;
    case 3: o.indented = true; o.indent_width = 0; break;
    case 4: o.indented = true; o.indent = DK_S("\t"); break;
    case 5: o.sort_keys = true; break;
    case 6: o.indented = true; o.indent_width = 1; o.sort_keys = true; break;
    case 7: o.indented = true; o.indent_width = 0; o.sort_keys = true; break;
    case 8: o.custom_separators = true; o.item_sep = comma; o.key_sep = colon; break;
    case 9: o.raw_unicode = true; o.reject_nan = true; break;
    case 10: o.raw_unicode = true; o.custom_separators = true; o.item_sep = comma; o.key_sep = colon; break;
    case 11: o.raw_unicode = true; o.reject_nan = true; o.custom_separators = true; o.item_sep = comma; o.key_sep = colon; o.sort_keys = true; break;
    case 12: o.indented = true; o.indent_width = 2; o.sort_keys = true; o.raw_unicode = true; break;
    case 13: o.indented = true; o.indent_width = 1; o.raw_unicode = true; break;
    case 14: o.indented = true; o.indent_width = 1; o.custom_separators = true; o.item_sep = DK_S(" ,"); o.key_sep = DK_S(" :"); break;
    case 15: o.reject_nan = true; break;
    case 16: o.raw_unicode = true; o.sort_keys = true; break;
    case 17: o.indented = true; o.indent_width = 4; break;
    case 18: o.indented = true; o.indent = DK_S("  "); o.custom_separators = true; o.item_sep = DK_S("; "); o.key_sep = DK_S("= "); break;
    case 19: o.indented = true; o.indent_width = -1; break;
    case 20: o.indented = true; o.indent_width = 2; o.sort_keys = true; break;
    case 21: o.raw_unicode = true; o.custom_separators = true; o.item_sep = comma; o.key_sep = colon; o.sort_keys = true; break;
    case 22: o.raw_unicode = true; o.reject_nan = true; o.custom_separators = true; o.item_sep = comma; o.key_sep = colon; break;
    default: DK_ASSERT(false);
    }
    return o;
}

static const char *kind_name(int k) { return k == DK_JSON_E_DECODE ? "DECODE" : k == DK_JSON_E_VALUE ? "VALUE" : k == DK_JSON_E_RECURSION ? "RECURSION" : "UNICODE"; }

static void fmt_error(DkBuf *b, const DkJsonError *e) {
    if (e->kind == DK_JSON_E_DECODE)
        dk_buf_printf(b, "E|DECODE|%.*s|%lld|%lld|%lld", DK_SF(e->msg), (long long)e->lineno, (long long)e->colno, (long long)e->pos);
    else
        dk_buf_printf(b, "E|%s|%.*s", kind_name(e->kind), DK_SF(e->msg));
}

DK_TEST(corpus_against_cpython) {
    DkArena *a = dk_arena_new(0);
    int failures = 0;
    size_t errors = 0, successes = 0;
    for (size_t i = 0; i < DK_ARRAY_LEN(dk_json_cases); i++) {
        const DkJsonCase *c = &dk_json_cases[i];
        DkArenaMark mark = dk_arena_mark(a);
        DkBuf got = {0};
        DkJsonError err = {0};
        DkJson *v = dk_json_parse(a, dk_strn(c->text, c->tn), &err);
        if (!v) {
            fmt_error(&got, &err);
            errors++;
        } else {
            DkJsonDumpOpts o = opts_for(c->opt);
            DkJsonError derr = {0};
            o.err = &derr;
            DkStr s = dk_json_dumps(a, v, &o);
            if (!s.p) fmt_error(&got, &derr);
            else dk_buf_put(&got, s);
            successes++;
        }
        DkStr g = dk_buf_str(&got);
        if (!(g.n == c->en && memcmp(g.p, c->exp, c->en) == 0)) {
            if (failures++ < 8)
                dk_test__fail(__FILE__, __LINE__, "case %zu (opt %d) text \"%.*s\"\n   expected \"%.*s\"\n   got      \"%.*s\"", i, c->opt,
                               (int)DK_MIN(c->tn, 200), c->text, (int)DK_MIN(c->en, 300), c->exp, (int)DK_MIN(g.n, 300), g.p);
        }
        dk_buf_free(&got);
        dk_arena_reset(a, mark);
    }
    CHECK_EQ_I64(failures, 0);
    CHECK(errors > 1000);
    CHECK(successes > 2000);
    dk_arena_free(a);
}

/* ---- the document of the header comment, built three ways ---- */
static const char *EXP_DEFAULT =
    "{\"a\": [1, 2.5, \"x\\u00e9\"], \"b\": {}, \"c\": [], \"d\": null, \"e\": {\"f\": [true, false, {\"g\": 1}]}}";
static const char *EXP_INDENT2 =
    "{\n  \"a\": [\n    1,\n    2.5,\n    \"x\\u00e9\"\n  ],\n  \"b\": {},\n  \"c\": [],\n  \"d\": null,\n  \"e\": {\n"
    "    \"f\": [\n      true,\n      false,\n      {\n        \"g\": 1\n      }\n    ]\n  }\n}";
static const char *EXP_TAB_RAW =
    "{\n\t\"a\": [\n\t\t1,\n\t\t2.5,\n\t\t\"x\303\251\"\n\t],\n\t\"b\": {},\n\t\"c\": [],\n\t\"d\": null,\n\t\"e\": {\n"
    "\t\t\"f\": [\n\t\t\ttrue,\n\t\t\tfalse,\n\t\t\t{\n\t\t\t\t\"g\": 1\n\t\t\t}\n\t\t]\n\t}\n}";
static const char *EXP_COMPACT_RAW =
    "{\"a\":[1,2.5,\"x\303\251\"],\"b\":{},\"c\":[],\"d\":null,\"e\":{\"f\":[true,false,{\"g\":1}]}}";

static DkJson *tree_doc(DkArena *a) {
    DkJson *d = dk_json_obj(a);
    DkJson *arr = dk_json_arr(a);
    dk_json_arr_push(a, arr, dk_json_int(a, 1));
    dk_json_arr_push(a, arr, dk_json_float(a, 2.5));
    dk_json_arr_push(a, arr, dk_json_strz(a, "x\303\251"));
    dk_json_set(a, d, DK_S("a"), arr);
    dk_json_set(a, d, DK_S("b"), dk_json_obj(a));
    dk_json_set(a, d, DK_S("c"), dk_json_arr(a));
    dk_json_set(a, d, DK_S("d"), dk_json_null());
    DkJson *e = dk_json_obj(a), *f = dk_json_arr(a), *g = dk_json_obj(a);
    dk_json_arr_push(a, f, dk_json_bool(true));
    dk_json_arr_push(a, f, dk_json_bool(false));
    dk_json_set(a, g, DK_S("g"), dk_json_int(a, 1));
    dk_json_arr_push(a, f, g);
    dk_json_set(a, e, DK_S("f"), f);
    dk_json_set(a, d, DK_S("e"), e);
    return d;
}

static void stream_doc(DkJsonW *w) {
    dk_jsonw_begin_object(w);
    dk_jsonw_key(w, DK_S("a"));
    dk_jsonw_begin_array(w);
    dk_jsonw_i64(w, 1);
    dk_jsonw_f64(w, 2.5);
    dk_jsonw_str(w, DK_S("x\303\251"));
    dk_jsonw_end_array(w);
    dk_jsonw_key(w, DK_S("b"));
    dk_jsonw_begin_object(w);
    dk_jsonw_end_object(w);
    dk_jsonw_key(w, DK_S("c"));
    dk_jsonw_begin_array(w);
    dk_jsonw_end_array(w);
    dk_jsonw_key(w, DK_S("d"));
    dk_jsonw_null(w);
    dk_jsonw_key(w, DK_S("e"));
    dk_jsonw_begin_object(w);
    dk_jsonw_key(w, DK_S("f"));
    dk_jsonw_begin_array(w);
    dk_jsonw_bool(w, true);
    dk_jsonw_bool(w, false);
    dk_jsonw_begin_object(w);
    dk_jsonw_kv_i64(w, "g", 1);
    dk_jsonw_end_object(w);
    dk_jsonw_end_array(w);
    dk_jsonw_end_object(w);
    dk_jsonw_end_object(w);
}

static void check_stream(const DkJsonDumpOpts *o, const char *expected) {
    DkBuf b = {0};
    DkJsonW w;
    dk_jsonw_init(&w, &b, o);
    stream_doc(&w);
    CHECK(dk_jsonw_finish(&w));
    CHECK_STR(dk_buf_str(&b), expected);
    dk_buf_free(&b);
}

DK_TEST(streaming_writer) {
    DkJsonDumpOpts o = {0};
    check_stream(&o, EXP_DEFAULT);
    check_stream(&DK_JSON_INDENT(2), EXP_INDENT2);
    o = (DkJsonDumpOpts){.indented = true, .indent = DK_S("\t"), .raw_unicode = true};
    check_stream(&o, EXP_TAB_RAW);
    o = DK_JSON_COMPACT;
    o.raw_unicode = true;
    check_stream(&o, EXP_COMPACT_RAW);
}

DK_TEST(tree_builder_and_dumps) {
    DkArena *a = dk_arena_new(0);
    DkJson *d = tree_doc(a);
    CHECK_STR(dk_json_dumps(a, d, NULL), EXP_DEFAULT);
    DkJsonDumpOpts o = DK_JSON_INDENT(2);
    CHECK_STR(dk_json_dumps(a, d, &o), EXP_INDENT2);
    o = (DkJsonDumpOpts){.indented = true, .indent = DK_S("\t"), .raw_unicode = true};
    CHECK_STR(dk_json_dumps(a, d, &o), EXP_TAB_RAW);
    /* dump_buf appends */
    DkBuf b = {0};
    dk_buf_putz(&b, "> ");
    o = DK_JSON_COMPACT;
    o.raw_unicode = true;
    CHECK(dk_json_dump_buf(&b, d, &o));
    CHECK_EQ_U64(b.n, 2 + strlen(EXP_COMPACT_RAW));
    dk_buf_free(&b);
    /* empty containers with indent */
    DkJson *nest = dk_json_arr(a);
    dk_json_arr_push(a, nest, dk_json_arr(a));
    DkJson *in = dk_json_arr(a);
    dk_json_arr_push(a, in, dk_json_arr(a));
    dk_json_arr_push(a, nest, in);
    dk_json_arr_push(a, nest, dk_json_obj(a));
    DkJson *w = dk_json_arr(a);
    dk_json_arr_push(a, w, dk_json_obj(a));
    dk_json_arr_push(a, nest, w);
    o = DK_JSON_INDENT(1);
    CHECK_STR(dk_json_dumps(a, nest, &o), "[\n [],\n [\n  []\n ],\n {},\n [\n  {}\n ]\n]");
    /* sort_keys with a nested object */
    DkJson *s = dk_json_obj(a), *z = dk_json_obj(a);
    dk_json_set(a, s, DK_S("b"), dk_json_int(a, 1));
    dk_json_set(a, z, DK_S("z"), dk_json_int(a, 1));
    dk_json_set(a, z, DK_S("y"), dk_json_int(a, 2));
    dk_json_set(a, s, DK_S("a"), z);
    o = DK_JSON_INDENT(1);
    o.sort_keys = true;
    CHECK_STR(dk_json_dumps(a, s, &o), "{\n \"a\": {\n  \"y\": 2,\n  \"z\": 1\n },\n \"b\": 1\n}");
    dk_arena_free(a);
}

DK_TEST(ints_floats_and_big_ints) {
    DkArena *a = dk_arena_new(0);
    CHECK_STR(dk_json_dumps(a, dk_json_int(a, INT64_MIN), NULL), "-9223372036854775808");
    CHECK_STR(dk_json_dumps(a, dk_json_uint(a, UINT64_MAX), NULL), "18446744073709551615");
    CHECK_STR(dk_json_dumps(a, dk_json_uint(a, 9223372036854775808ull), NULL), "9223372036854775808");
    CHECK_STR(dk_json_dumps(a, dk_json_int_digits(a, DK_S("1180591620717411303424")), NULL), "1180591620717411303424");
    CHECK_STR(dk_json_dumps(a, dk_json_int_digits(a, DK_S("-0")), NULL), "0");
    CHECK_STR(dk_json_dumps(a, dk_json_int_digits(a, DK_S("-9223372036854775808")), NULL), "-9223372036854775808");
    DkJson *big = dk_json_parse(a, DK_S("123456789012345678901234567890"), NULL);
    CHECK(big && big->kind == DK_JSON_INT && big->big);
    CHECK_EQ_I64(dk_json_i64(big, -7), -7);
    CHECK_EQ_F64(dk_json_f64(big, 0), 1.2345678901234568e29);
    CHECK_STR(dk_json_dumps(a, big, NULL), "123456789012345678901234567890");
    CHECK_STR(dk_json_dumps(a, dk_json_float(a, -0.0), NULL), "-0.0");
    CHECK_STR(dk_json_dumps(a, dk_json_float(a, 1e22), NULL), "1e+22");
    CHECK_STR(dk_json_dumps(a, dk_json_float(a, NAN), NULL), "NaN");
    CHECK_STR(dk_json_dumps(a, dk_json_float(a, -INFINITY), NULL), "-Infinity");
    DkJsonDumpOpts o = {.reject_nan = true};
    DkJsonError e = {0};
    o.err = &e;
    DkStr s = dk_json_dumps(a, dk_json_float(a, INFINITY), &o);
    CHECK(s.p == NULL);
    CHECK_EQ_I64(e.kind, DK_JSON_E_VALUE);
    CHECK_STR(e.msg, "Out of range float values are not JSON compliant: inf");
    dk_arena_free(a);
}

DK_TEST(object_semantics) {
    DkArena *a = dk_arena_new(0);
    DkJson *o = dk_json_obj(a);
    /* dict semantics: replace keeps the position, delete + set goes to the end */
    dk_json_set(a, o, DK_S("a"), dk_json_int(a, 1));
    dk_json_set(a, o, DK_S("b"), dk_json_int(a, 2));
    DkJson *prev = dk_json_set(a, o, DK_S("a"), dk_json_int(a, 3));
    CHECK(prev && dk_json_i64(prev, 0) == 1);
    CHECK_STR(dk_json_dumps(a, o, NULL), "{\"a\": 3, \"b\": 2}");
    CHECK(dk_json_del(o, DK_S("a")));
    CHECK(!dk_json_del(o, DK_S("a")));
    dk_json_set(a, o, DK_S("a"), dk_json_int(a, 4));
    CHECK_STR(dk_json_dumps(a, o, NULL), "{\"b\": 2, \"a\": 4}");
    CHECK_STR(dk_json_member(o, 0)->key, "b");
    CHECK(dk_json_member(o, 2) == NULL);
    /* many members: the index */
    DkJson *big = dk_json_obj(a);
    for (int i = 0; i < 500; i++) dk_json_set(a, big, dk_str(dk_sprintf(a, "key%d", i)), dk_json_int(a, i));
    CHECK_EQ_U64(dk_json_len(big), 500);
    for (int i = 0; i < 500; i += 7) CHECK_EQ_I64(dk_json_get_i64(big, dk_sprintf(a, "key%d", i), -1), i);
    CHECK(dk_json_get(big, DK_S("nokey")) == NULL);
    dk_json_set(a, big, DK_S("key3"), dk_json_int(a, 333));
    CHECK_EQ_U64(dk_json_len(big), 500);
    CHECK_EQ_I64(dk_json_get_i64(big, "key3", -1), 333);
    CHECK_STR(dk_json_member(big, 3)->key, "key3");
    for (int i = 0; i < 500; i += 2) CHECK(dk_json_del(big, dk_str(dk_sprintf(a, "key%d", i))));
    CHECK_EQ_U64(dk_json_len(big), 250);
    CHECK(dk_json_get(big, DK_S("key4")) == NULL);
    CHECK_EQ_I64(dk_json_get_i64(big, "key5", -1), 5);
    CHECK_STR(dk_json_member(big, 0)->key, "key1");
    /* a parsed object with a repeated key: first position, last value */
    DkJson *p = dk_json_parse(a, DK_S("{\"a\":1,\"b\":2,\"a\":3}"), NULL);
    CHECK_STR(dk_json_dumps(a, p, NULL), "{\"a\": 3, \"b\": 2}");
    /* a parsed object with 40 keys and repeats (the index path) */
    DkBuf t = {0};
    dk_buf_putc(&t, '{');
    for (int i = 0; i < 40; i++) dk_buf_printf(&t, "%s\"k%d\":%d", i ? "," : "", i % 25, i);
    dk_buf_putc(&t, '}');
    DkJson *q = dk_json_parse(a, dk_buf_str(&t), NULL);
    CHECK_EQ_U64(dk_json_len(q), 25);
    CHECK_EQ_I64(dk_json_get_i64(q, "k3", -1), 28);
    CHECK_EQ_I64(dk_json_get_i64(q, "k24", -1), 24);
    CHECK_STR(dk_json_member(q, 24)->key, "k24");
    dk_buf_free(&t);
    dk_arena_free(a);
}

DK_TEST(typed_accessors) {
    DkArena *a = dk_arena_new(0);
    DkJson *o = dk_json_parse(a, DK_S("{\"i\":5,\"f\":1.5,\"s\":\"x\",\"b\":true,\"n\":null,\"l\":[1],\"o\":{},\"e\":\"\",\"z\":0.0}"), NULL);
    CHECK_EQ_I64(dk_json_get_i64(o, "i", 9), 5);
    CHECK_EQ_I64(dk_json_get_i64(o, "f", 9), 9);
    CHECK_EQ_I64(dk_json_get_i64(o, "missing", 9), 9);
    CHECK_EQ_F64(dk_json_get_f64(o, "f", 0), 1.5);
    CHECK_EQ_F64(dk_json_get_f64(o, "i", 0), 5.0);
    CHECK_EQ_F64(dk_json_get_f64(o, "s", -1), -1.0);
    CHECK_STR(dk_json_get_str(o, "s", DK_S("dflt")), "x");
    CHECK_STR(dk_json_get_str(o, "i", DK_S("dflt")), "dflt");
    CHECK(dk_json_get_bool(o, "b", false));
    CHECK(dk_json_get_bool(o, "s", true));
    CHECK(dk_json_get_or(o, DK_S("i"), NULL) == dk_json_getz(o, "i"));
    CHECK(dk_json_get_or(o, DK_S("nope"), dk_json_bool(true)) == dk_json_bool(true));
    CHECK(dk_json_is_null(dk_json_getz(o, "n")));
    CHECK(dk_json_is_null(dk_json_getz(o, "nope")));
    CHECK(!dk_json_is_null(dk_json_getz(o, "i")));
    CHECK(dk_json_is_arr(dk_json_getz(o, "l")) && dk_json_is_obj(dk_json_getz(o, "o")) && dk_json_is_str(dk_json_getz(o, "s")));
    CHECK(dk_json_is_num(dk_json_getz(o, "f")) && dk_json_is_int(dk_json_getz(o, "i")) && !dk_json_is_int(dk_json_getz(o, "f")));
    CHECK_EQ_I64(dk_json_i64(dk_json_at(dk_json_getz(o, "l"), 0), 0), 1);
    CHECK(dk_json_at(dk_json_getz(o, "l"), 1) == NULL);
    CHECK(dk_json_truthy(dk_json_getz(o, "i")) && dk_json_truthy(dk_json_getz(o, "s")) && dk_json_truthy(dk_json_getz(o, "l")));
    CHECK(!dk_json_truthy(dk_json_getz(o, "n")) && !dk_json_truthy(dk_json_getz(o, "e")) && !dk_json_truthy(dk_json_getz(o, "o")));
    CHECK(!dk_json_truthy(dk_json_getz(o, "z")) && !dk_json_truthy(NULL) && dk_json_truthy(dk_json_getz(o, "b")));
    dk_arena_free(a);
}

/* ---- the reader's options and limits ---- */
static void check_err(DkArena *a, DkStr text, unsigned flags, int kind, const char *msg, i64 line, i64 col, i64 pos) {
    DkJsonError e = {0};
    DkJson *v = dk_json_parse_ex(a, text, flags, &e);
    CHECK(v == NULL);
    CHECK_EQ_I64(e.kind, kind);
    CHECK_STR(e.msg, msg);
    CHECK_EQ_I64(e.lineno, line);
    CHECK_EQ_I64(e.colno, col);
    CHECK_EQ_I64(e.pos, pos);
}

DK_TEST(reader_flags) {
    DkArena *a = dk_arena_new(0);
    /* json.load(open(f, encoding="utf-8")) on a file with a BOM, and the utf-8-sig cases */
    check_err(a, DK_S("\357\273\277[1]"), 0, DK_JSON_E_DECODE, "Unexpected UTF-8 BOM (decode using utf-8-sig)", 1, 1, 0);
    DkJson *v = dk_json_parse_ex(a, DK_S("\357\273\277[1, \"\303\251\"]"), DK_JSON_STRIP_BOM, NULL);
    CHECK(v && dk_json_len(v) == 2);
    v = dk_json_parse_ex(a, DK_S("\357\273\277[1]"), DK_JSON_BYTES, NULL);
    CHECK(v && dk_json_len(v) == 1);
    /* positions after a skipped BOM are relative to the decoded text */
    check_err(a, DK_S("\357\273\277[1,]"), DK_JSON_STRIP_BOM, DK_JSON_E_DECODE, "Illegal trailing comma before end of array", 1, 3, 2);
    /* positions count code points, lines count \n only */
    check_err(a, DK_S("[\"\303\251\303\251\",\n\"\303\251\", x]"), 0, DK_JSON_E_DECODE, "Expecting value", 2, 6, 12);
    check_err(a, DK_S("[1]\r\n[2]"), 0, DK_JSON_E_DECODE, "Extra data", 2, 1, 5);
    /* the hooks of the project's json.loads calls */
    check_err(a, DK_S("[NaN]"), DK_JSON_REJECT_CONSTANTS, DK_JSON_E_VALUE, "invalid JSON constant: NaN", 0, 0, 0);
    check_err(a, DK_S("-Infinity"), DK_JSON_REJECT_CONSTANTS, DK_JSON_E_VALUE, "invalid JSON constant: -Infinity", 0, 0, 0);
    CHECK(dk_json_parse_ex(a, DK_S("[NaN]"), 0, NULL) != NULL);
    check_err(a, DK_S("[1e999]"), DK_JSON_REJECT_NONFINITE, DK_JSON_E_VALUE, "nonfinite JSON number", 0, 0, 0);
    CHECK(dk_json_parse_ex(a, DK_S("[1e99, 7]"), DK_JSON_REJECT_NONFINITE, NULL) != NULL);
    check_err(a, DK_S("{\"a\":1,\"b\":{\"c\":1,\"a\":2},\"a\":3}"), DK_JSON_REJECT_DUP_KEYS, DK_JSON_E_VALUE, "duplicate JSON key: a", 0, 0, 0);
    CHECK(dk_json_parse_ex(a, DK_S("{\"a\":1,\"b\":{\"c\":1,\"a\":2}}"), DK_JSON_REJECT_DUP_KEYS, NULL) != NULL);
    /* invalid UTF-8 is the UnicodeDecodeError of reading the file */
    DkJsonError e = {0};
    CHECK(dk_json_parse(a, DK_S("[\"a\377\"]"), &e) == NULL);
    CHECK_EQ_I64(e.kind, DK_JSON_E_UNICODE);
    CHECK_STR(e.msg, "'utf-8' codec can't decode byte 0xff in position 3: invalid start byte");
    /* str(exception) */
    check_err(a, DK_S("[1,"), 0, DK_JSON_E_DECODE, "Expecting value", 1, 4, 3);
    CHECK(dk_json_parse(a, DK_S("[1,"), &e) == NULL);
    CHECK_STR(dk_json_error_str(a, &e), "Expecting value: line 1 column 4 (char 3)");
    /* without an error slot the error is thrown as DK_ERR_FORMAT with Python's text */
    DkTry t;
    if (DK_TRY(&t)) {
        dk_json_parse(a, DK_S("{\"a\" 1}"), NULL);
        dk_try_end(&t);
        CHECK(!"parse should have thrown");
    } else {
        CHECK_EQ_I64(t.code, DK_ERR_FORMAT);
        CHECK_CZ(t.msg, "Expecting ':' delimiter: line 1 column 6 (char 5)");
    }
    dk_arena_free(a);
}

DK_TEST(limits) {
    DkArena *a = dk_arena_new(0);
    /* 4300 digits are fine, 4301 are the ValueError of int() (floats are not limited) */
    DkBuf b = {0};
    for (int i = 0; i < 4300; i++) dk_buf_putc(&b, '7');
    DkJson *v = dk_json_parse(a, dk_buf_str(&b), NULL);
    CHECK(v && v->kind == DK_JSON_INT && v->big);
    CHECK_EQ_U64(v->u.str.n, 4300);
    dk_buf_putc(&b, '7');
    DkJsonError e = {0};
    CHECK(dk_json_parse(a, dk_buf_str(&b), &e) == NULL);
    CHECK_EQ_I64(e.kind, DK_JSON_E_VALUE);
    CHECK_STR(e.msg,
              "Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits; use sys.set_int_max_str_digits() to increase the limit");
    dk_buf_free(&b);
    /* deep nesting is iterative: 9000 levels parse and dump, far deeper is a RecursionError */
    size_t depth = 9000;
    for (size_t i = 0; i < depth; i++) {
        if (i % 2) dk_buf_putc(&b, '[');
        else dk_buf_putz(&b, "{\"k\":");
    }
    dk_buf_putc(&b, '1');
    for (size_t i = depth; i-- > 0;) dk_buf_putc(&b, i % 2 ? ']' : '}');
    v = dk_json_parse(a, dk_buf_str(&b), &e);
    REQUIRE(v != NULL);
    DkStr back = dk_json_dumps(a, v, &DK_JSON_COMPACT);
    CHECK(back.n == b.n && memcmp(back.p, b.p, b.n) == 0);
    dk_buf_free(&b);
    for (size_t i = 0; i < 20000; i++) dk_buf_putc(&b, '[');
    CHECK(dk_json_parse(a, dk_buf_str(&b), &e) == NULL);
    CHECK_EQ_I64(e.kind, DK_JSON_E_RECURSION);
    dk_buf_free(&b);
    dk_arena_free(a);
}

static bool spill_collect(void *ctx, const char *p, size_t n) {
    dk_buf_putn((DkBuf *)ctx, p, n);
    return true;
}

DK_TEST(spill_and_file) {
    DkArena *a = dk_arena_new(0);
    DkJson *d = dk_json_obj(a);
    DkJson *arr = dk_json_arr(a);
    for (int i = 0; i < 3000; i++) dk_json_arr_push(a, arr, dk_json_float(a, i * 0.37));
    dk_json_set(a, d, DK_S("values"), arr);
    dk_json_set(a, d, DK_S("name"), dk_json_strz(a, "spill \303\251"));
    DkJsonDumpOpts o = DK_JSON_INDENT(1);
    DkStr whole = dk_json_dumps(a, d, &o);
    DkBuf small = {0}, sink = {0};
    DkJsonW w;
    dk_jsonw_init(&w, &small, &o);
    dk_jsonw_set_spill(&w, 200, spill_collect, &sink);
    dk_jsonw_tree(&w, d);
    CHECK(dk_jsonw_finish(&w));
    CHECK(small.n == 0);
    CHECK(sink.n == whole.n && memcmp(sink.p, whole.p, whole.n) == 0);
    dk_buf_free(&small);
    dk_buf_free(&sink);
    /* json.dump to a FILE */
    FILE *f = tmpfile();
    REQUIRE(f != NULL);
    CHECK(dk_json_dump_file(f, d, &o));
    long len = ftell(f);
    CHECK_EQ_U64(len, whole.n);
    rewind(f);
    char *back = (char *)dk_alloc(a, whole.n + 1);
    CHECK_EQ_U64(fread(back, 1, whole.n, f), whole.n);
    CHECK(memcmp(back, whole.p, whole.n) == 0);
    fclose(f);
    dk_arena_free(a);
}

DK_TEST(string_escaper) {
    DkBuf b = {0};
    dk_json_put_string(&b, DK_S("a\"b\\c\n\t\r\b\f\001\177 \303\251 \360\237\230\200 \355\240\200"), false);
    CHECK_STR(dk_buf_str(&b), "\"a\\\"b\\\\c\\n\\t\\r\\b\\f\\u0001\\u007f \\u00e9 \\ud83d\\ude00 \\ud800\"");
    dk_buf_clear(&b);
    dk_json_put_string(&b, DK_S("a\"b\\c\n\001\177 \303\251 \360\237\230\200"), true);
    CHECK_STR(dk_buf_str(&b), "\"a\\\"b\\\\c\\n\\u0001\177 \303\251 \360\237\230\200\"");
    dk_buf_free(&b);
    /* a long string crosses the escaper's pieces, including multi-byte sequences at the boundary */
    DkBuf in = {0}, exp = {0};
    for (int i = 0; i < 5000; i++) {
        dk_buf_putz(&in, "\303\251");
        dk_buf_putz(&exp, "\\u00e9");
    }
    dk_json_put_string(&b, dk_buf_str(&in), false);
    CHECK(b.n == exp.n + 2 && memcmp(b.p + 1, exp.p, exp.n) == 0);
    dk_buf_free(&b);
    dk_buf_free(&in);
    dk_buf_free(&exp);
}

DK_TEST_MAIN("json")
