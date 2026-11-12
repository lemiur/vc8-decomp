// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* project_annot: the annotation grammar compiled from hand-built configurations, both address grammars and both name
 * rules parsed from the fixtures under tests/fixtures/project_annot, the parse errors, the unit flags line, symbol
 * binding and the undecorated-name comparison on decorated names written by hand. */
#include "dk/test.h"

#include "dk/fs.h"
#include "pdb.h"
#include "project.h"

#include <string.h>

#define FIXTURES "ctools/tests/fixtures/project_annot/"

/* ---- configurations ---------------------------------------------------------------------------------------------- */

static const char *const TA_TARGETS[] = {"tgt", "other"};
static DkAnnKindName TA_KINDS[] = {{"FUNCTION", DK_ANN_FUNCTION}, {"DATA", DK_ANN_DATA}};

/* One target per marker line, the declaration rule, an explicit symbol line. */
static DkAnnotConfig ta_config(void) {
    DkAnnotConfig c;
    memset(&c, 0, sizeof c);
    c.marker = "^\\s*//\\s*(?P<kind>FUNCTION|DATA):\\s+(?P<binary>[a-zA-Z0-9_]+)\\s+(?P<va>0x[0-9a-fA-F]+)\\s*$";
    c.kinds = TA_KINDS;
    c.n_kinds = DK_ARRAY_LEN(TA_KINDS);
    c.addr_groups = DK_ADDR_TARGET_ADDR;
    c.name = DK_NAME_DECLARATION;
    c.symbol = "^\\s*//\\s*SYMBOL:\\s*(\\S+)\\s*$";
    c.stop = "^\\s*//\\s*stop:\\s*(?P<reason>.+)$";
    return c;
}

static const char *const PT_TARGETS[] = {"alpha", "beta"};
static DkAnnKindName PT_KINDS[] = {
    {"match", DK_ANN_FUNCTION}, {"data", DK_ANN_DATA}, {"addr", DK_ANN_DECL}, {"vtable", DK_ANN_VTABLE}};

/* Several addresses per marker line, the next_line rule, stop and pending lines with an optional target. */
static DkAnnotConfig pt_config(void) {
    DkAnnotConfig c;
    memset(&c, 0, sizeof c);
    c.marker = "^\\s*//\\s*(?P<kind>match|data|addr|vtable):\\s+(?P<addr_alpha>(?:0x)?[0-9A-Fa-f]+)"
               "\\s+(?P<addr_beta>(?:0x)?[0-9A-Fa-f]+)\\s*$";
    c.kinds = PT_KINDS;
    c.n_kinds = DK_ARRAY_LEN(PT_KINDS);
    c.addr_groups = DK_ADDR_PER_TARGET;
    c.name = DK_NAME_NEXT_LINE;
    c.stop = "^\\s*//\\s*stop(?:\\((?P<target>\\w+)\\))?:\\s*(?P<reason>.+)$";
    c.pending = "^\\s*//\\s*pending(?:\\((?P<target>\\w+)\\))?:\\s*(?P<reason>.+)$";
    c.flags = "^//\\s*flags:\\s*(?P<flags>.+)$";
    c.flags_lines = 8;
    return c;
}

static DkStr fixture(const char *name) {
    DkStr text = {0};
    char path[256];
    snprintf(path, sizeof path, FIXTURES "%s", name);
    if (!dk_read_text(dk_arena(), path, DK_TM_UTF8_SIG, &text)) dk_fatal("cannot read %s", path);
    return text;
}

/* The 1-based line of the first occurrence of needle. */
static int line_with(DkStr text, const char *needle) {
    i64 at = dk_str_find(text, dk_str(needle), 0, DK_END);
    if (at < 0) return -1;
    int line = 1;
    for (i64 i = 0; i < at; i++) line += text.p[i] == '\n';
    return line;
}

static DkAnnot *parse(DkAnnotConfig *c, const char *const *targets, size_t nt, DkStr text, size_t *n, DkErr *err) {
    DkErr cerr;
    if (!dk_annot_config_compile(c, targets, nt, &cerr)) dk_fatal("config: %s", cerr.msg);
    return dk_annot_parse(dk_arena(), c, NULL, text, n, err);
}

static bool msg_has(const DkErr *err, const char *part) { return strstr(err->msg, part) != NULL; }

/* ---- configuration ----------------------------------------------------------------------------------------------- */

DK_TEST(config_groups_resolve) {
    DkAnnotConfig c = ta_config();
    DkErr err;
    REQUIRE(dk_annot_config_compile(&c, TA_TARGETS, 2, &err));
    CHECK_EQ_I64(err.code, 0);
    CHECK_EQ_I64(c.g_kind, 1);
    CHECK_EQ_I64(c.g_target, 2); /* "binary" when there is no "target" */
    CHECK_EQ_I64(c.g_addr, 3);   /* "va" when there is no "addr" */
    CHECK_EQ_I64(c.ntargets, 2);
    CHECK_CZ(c.target_names[1], "other");
    CHECK(c.re_symbol && c.re_stop && !c.re_pending && !c.re_flags);

    DkAnnotConfig p = pt_config();
    static const char *const three[] = {"alpha", "beta", "gamma"};
    REQUIRE(dk_annot_config_compile(&p, three, 3, &err));
    CHECK_EQ_I64(p.g_addr_target[0], 2);
    CHECK_EQ_I64(p.g_addr_target[1], 3);
    CHECK_EQ_I64(p.g_addr_target[2], -1); /* a target without a group has no address */
    CHECK_EQ_I64(p.g_target, -1);
    CHECK_EQ_I64(p.g_addr, -1);

    DkAnnotConfig o = ta_config();
    o.marker = "^//\\s*AT\\s+(?P<where>\\w+)\\s+(?P<at>[0-9a-f]+)$";
    o.group_target = "where";
    o.group_addr = "at";
    REQUIRE(dk_annot_config_compile(&o, TA_TARGETS, 2, &err));
    CHECK_EQ_I64(o.g_target, 1);
    CHECK_EQ_I64(o.g_addr, 2);
    CHECK_EQ_I64(o.g_kind, -1);
}

DK_TEST(config_errors) {
    DkErr err;
    DkAnnotConfig c = ta_config();
    c.marker = NULL;
    CHECK(!dk_annot_config_compile(&c, TA_TARGETS, 2, &err));
    CHECK(msg_has(&err, "annotations.marker"));

    c = ta_config();
    c.marker = "^//\\s*FUNCTION:\\s+(?P<binary>\\w+)$";
    CHECK(!dk_annot_config_compile(&c, TA_TARGETS, 2, &err));
    CHECK(msg_has(&err, "target+addr"));

    c = pt_config();
    c.marker = "^//\\s*match:\\s+(?P<addr_one>\\w+)$";
    CHECK(!dk_annot_config_compile(&c, PT_TARGETS, 2, &err));
    CHECK(msg_has(&err, "per-target"));

    c = ta_config();
    c.stop = "stop:(";
    CHECK(!dk_annot_config_compile(&c, TA_TARGETS, 2, &err));
    CHECK_EQ_I64(err.code, DK_ERR_REGEX);
    CHECK(msg_has(&err, "annotations.stop"));

    c = ta_config();
    c.group_kind = "sort";
    CHECK(!dk_annot_config_compile(&c, TA_TARGETS, 2, &err));
    CHECK(msg_has(&err, "sort"));
}

/* ---- target+addr grammar, declaration rule ------------------------------------------------------------------------ */

DK_TEST(parse_target_addr) {
    DkStr text = fixture("target_addr.cpp");
    DkAnnotConfig c = ta_config();
    size_t n = 0;
    DkErr err;
    DkAnnot *v = parse(&c, TA_TARGETS, 2, text, &n, &err);
    REQUIRE(v);
    REQUIRE(n == 5);

    const DkAnnot *f = &v[0];
    CHECK_EQ_I64(f->kind, DK_ANN_FUNCTION);
    CHECK(f->unit == NULL);
    CHECK_EQ_I64(f->line, line_with(text, "// FUNCTION: tgt 0x408276"));
    CHECK_EQ_I64(f->body_start, line_with(text, "int __cdecl nextbase"));
    CHECK_EQ_I64(f->body_end, line_with(text, "    return base;") + 1);
    CHECK_EQ_U64(f->addr[0], 0x408276);
    CHECK_EQ_U64(f->addr[1], DK_NO_ADDR);
    CHECK_EQ_U64(f->target_mask, 1);
    CHECK_CZ(f->name, "nextbase");
    CHECK_CZ(f->decl, "int __cdecl nextbase(int base)");
    CHECK_CZ(f->symbol, "?nextbase@@YAHH@Z");
    CHECK_EQ_U64(f->stop_mask, 0);
    CHECK(f->stop_reason == NULL && f->pending == NULL && f->pending_mask == 0 && f->flags == NULL);

    /* braces inside strings, characters and comments do not count */
    f = &v[1];
    CHECK_CZ(f->name, "skip_braces");
    CHECK(f->symbol == NULL);
    CHECK_EQ_I64(f->body_start, line_with(text, "static const char *__cdecl skip_braces"));
    CHECK_EQ_I64(f->body_end, line_with(text, "    return text;") + 1);
    CHECK_EQ_U64(f->stop_mask, 1);
    CHECK_CZ(f->stop_reason, "complete candidate; the compare codegen differs.");

    f = &v[2];
    CHECK_EQ_I64(f->kind, DK_ANN_DATA);
    CHECK_EQ_I64(f->line, line_with(text, "// DATA: tgt 0x00418900"));
    CHECK_CZ(f->name, "Counter");
    CHECK_CZ(f->decl, "int Counter");
    CHECK_EQ_I64(f->body_start, line_with(text, "int Counter;"));
    CHECK_EQ_I64(f->body_end, f->body_start);
    CHECK_EQ_U64(f->addr[0], 0x418900);

    f = &v[3];
    CHECK_CZ(f->name, "Table");
    CHECK_CZ(f->decl, "const int Table[] =");
    CHECK_EQ_I64(f->body_start, line_with(text, "const int Table[]"));
    CHECK_EQ_I64(f->body_end, line_with(text, "};"));

    f = &v[4];
    CHECK_CZ(f->name, "Sum2");
    CHECK_EQ_U64(f->target_mask, 2);
    CHECK_EQ_U64(f->addr[1], 0x408010);
    CHECK_EQ_U64(f->addr[0], DK_NO_ADDR);
}

/* ---- per-target grammar, next_line rule ---------------------------------------------------------------------------- */

DK_TEST(parse_per_target) {
    DkStr text = fixture("per_target.cpp");
    DkAnnotConfig c = pt_config();
    size_t n = 0;
    DkErr err;
    DkUnit u;
    memset(&u, 0, sizeof u);
    u.path = "per_target.cpp";
    u.flags_line = true;
    REQUIRE(dk_annot_config_compile(&c, PT_TARGETS, 2, &err));
    DkAnnot *v = dk_annot_parse(dk_arena(), &c, &u, text, &n, &err);
    REQUIRE(v);
    REQUIRE(n == 9);
    for (size_t i = 0; i < n; i++) {
        CHECK(v[i].unit == &u);
        CHECK_CZ(v[i].flags, "/EHa");
        CHECK(v[i].symbol == NULL);
    }

    const DkAnnot *a = &v[0];
    CHECK_EQ_I64(a->kind, DK_ANN_VTABLE);
    CHECK_CZ(a->name, "Widget");
    CHECK_CZ(a->decl, "class Widget : public Base");
    CHECK_EQ_I64(a->body_start, line_with(text, "class Widget"));
    CHECK_EQ_I64(a->body_end, line_with(text, "};"));
    CHECK_EQ_U64(a->addr[0], 0x600100);
    CHECK_EQ_U64(a->addr[1], 0x600200);
    CHECK_EQ_U64(a->target_mask, 3);

    a = &v[1];
    CHECK_EQ_I64(a->kind, DK_ANN_FUNCTION);
    CHECK_EQ_I64(a->line, line_with(text, "// match: 0x0078B0D0 0x007837A0"));
    CHECK_CZ(a->name, "Foo_Bar::MakeUpdate");
    CHECK_CZ(a->decl, "void Foo_Bar::MakeUpdate()");
    CHECK_EQ_I64(a->body_start, a->line + 1);
    CHECK_EQ_I64(a->body_end, a->line + 4);

    a = &v[2];
    CHECK_CZ(a->name, "Target::Update");
    CHECK_CZ(a->decl, "bool Target::Update(Foo* f, bool inside, float scale)");
    CHECK_EQ_U64(a->addr[0], 0x78B100);
    CHECK_EQ_U64(a->addr[1], DK_NO_ADDR);
    CHECK_EQ_U64(a->target_mask, 1);
    CHECK_EQ_U64(a->stop_mask, 1); /* a stop without a target: every target with an address */
    CHECK_CZ(a->stop_reason, "the register choice differs");
    CHECK_EQ_I64(a->body_start, a->line + 2);
    CHECK(dk_stopped(a, 0));
    CHECK(!dk_stopped(a, 1));
    CHECK(!dk_stopped(a, 40));

    a = &v[3];
    CHECK_CZ(a->name, "Target::Update");
    CHECK_CZ(a->decl, "bool Target::Update(Foo* f)");
    CHECK_EQ_U64(a->stop_mask, 0);
    CHECK_EQ_U64(a->pending_mask, 3);
    CHECK_CZ(a->pending, "R4 a fixed-offset access remains");

    a = &v[4];
    CHECK_CZ(a->name, "Widget::~Widget");
    CHECK_EQ_U64(a->stop_mask, 2);
    CHECK_CZ(a->stop_reason, "the second copy is laid out differently");
    CHECK(!dk_stopped(a, 0));
    CHECK(dk_stopped(a, 1));
    CHECK_EQ_I64(a->body_end, a->line + 4);

    a = &v[5]; /* an explicit instantiation: no body */
    CHECK_CZ(a->name, "Map<Target>::~Map");
    CHECK_CZ(a->decl, "template Map<Target>::~Map()");
    CHECK_EQ_I64(a->body_start, a->line + 1);
    CHECK_EQ_I64(a->body_end, a->line + 1);

    a = &v[6]; /* two folded copies at one address */
    CHECK_CZ(a->name, "DataStream::operator>>");
    CHECK_CZ(a->decl, "DataStream& DataStream::operator>>(unsigned int& value)");
    CHECK_CZ(v[7].name, "DataStream::operator>>");
    CHECK_CZ(v[7].decl, "DataStream& DataStream::operator>>(float& value)");
    CHECK_EQ_U64(v[7].addr[1], 0x783B00);

    a = &v[8];
    CHECK_EQ_I64(a->kind, DK_ANN_DATA);
    CHECK_CZ(a->name, "g_counter");
    CHECK_CZ(a->decl, "int g_counter = 0");
    CHECK_EQ_I64(a->body_start, a->line + 1);
    CHECK_EQ_I64(a->body_end, a->line + 1);

    /* a unit that does not apply its flags line */
    u.flags_line = false;
    v = dk_annot_parse(dk_arena(), &c, &u, text, &n, &err);
    REQUIRE(v);
    CHECK(v[0].flags == NULL);
}

DK_TEST(flags_line) {
    DkAnnotConfig c = pt_config();
    DkErr err;
    REQUIRE(dk_annot_config_compile(&c, PT_TARGETS, 2, &err));
    CHECK_CZ(dk_annot_flags_line(dk_arena(), &c, DK_S("\xEF\xBB\xBF// flags: /EHa /GR- \nint x;\n")), "/EHa /GR-");
    CHECK(dk_annot_flags_line(dk_arena(), &c, DK_S("int x;\n")) == NULL);
    c.flags_lines = 2;
    CHECK(dk_annot_flags_line(dk_arena(), &c, DK_S("\n\n// flags: /EHa\n")) == NULL);
    CHECK_CZ(dk_annot_flags_line(dk_arena(), &c, DK_S("\n// flags: /EHa\n")), "/EHa");
    DkAnnotConfig t = ta_config();
    REQUIRE(dk_annot_config_compile(&t, TA_TARGETS, 2, &err));
    CHECK(dk_annot_flags_line(dk_arena(), &t, DK_S("// flags: /EHa\n")) == NULL); /* not configured */
}

/* ---- parse errors ------------------------------------------------------------------------------------------------- */

static void expect_error(DkAnnotConfig c, const char *const *targets, size_t nt, const char *text, const char *part) {
    size_t n = 7;
    DkErr err;
    DkAnnot *v = parse(&c, targets, nt, dk_str(text), &n, &err);
    CHECK_MSG(v == NULL, "parsed without the error '%s'", part);
    CHECK_EQ_U64(n, 0);
    CHECK_MSG(err.code != 0 && strstr(err.msg, part), "error '%s' does not name '%s'", err.msg, part);
}

DK_TEST(parse_errors) {
    expect_error(ta_config(), TA_TARGETS, 2, "\n// FUNCTION: nowhere 0x401000\nint f(void)\n{\n}\n",
                 "2: unknown target 'nowhere'");
    expect_error(ta_config(), TA_TARGETS, 2,
                 "// FUNCTION: tgt 0x401000\nint f(void)\n{\n}\n// FUNCTION: tgt 0x401000\nint g(void)\n{\n}\n",
                 "5: duplicate address tgt 0x401000 (line 1)");
    expect_error(ta_config(), TA_TARGETS, 2, "// FUNCTION: tgt 0x401000\nint f(void);\n// DATA: tgt 0x402000\nint x = {0};\n",
                 "1: function annotation has no body");
    expect_error(ta_config(), TA_TARGETS, 2, "// FUNCTION: tgt 0x401000\nint f(void)\n{\n  {\n}\n", "unbalanced");

    DkAnnotConfig loose = pt_config();
    loose.marker = "^//\\s*(?P<kind>\\w+):\\s+(?P<addr_alpha>\\S+)\\s+(?P<addr_beta>\\S+)$";
    expect_error(loose, PT_TARGETS, 2, "// match: 0x40100G 0\nvoid f();\n", "1: bad address '0x40100G' for target alpha");
    expect_error(loose, PT_TARGETS, 2, "// match: 123456789 0\nvoid f();\n", "bad address '123456789'");
    expect_error(loose, PT_TARGETS, 2, "// match: 0x401000 0\nvoid f();\n\n// weird: 0x402000 0\nint x;\n",
                 "4: unknown annotation kind 'weird'");
    expect_error(pt_config(), PT_TARGETS, 2, "// match: 0x401000 0\n// stop(gamma): no\nvoid f();\n",
                 "2: unknown target 'gamma'");
    expect_error(pt_config(), PT_TARGETS, 2, "// match: 0x401000 0\n", "function annotation has no declaration");
    expect_error(pt_config(), PT_TARGETS, 2, "// match: 0x401000 0\nvoid A::f()\n", "has no body or ';'");
    /* the same declaration twice at one address; folded copies (another declaration) are fine */
    expect_error(pt_config(), PT_TARGETS, 2, "// match: 401000 0\nvoid A::f();\n// match: 401000 0\nvoid A::f();\n",
                 "3: duplicate address alpha 0x401000 (line 1)");
    expect_error(ta_config(), TA_TARGETS, 2, "\xFF\n", "not UTF-8");

    /* the per-target grammar: "0" is no copy, both spellings of an address */
    DkAnnotConfig c = pt_config();
    size_t n;
    DkErr err;
    DkAnnot *v = parse(&c, PT_TARGETS, 2, DK_S("// match: 401000 0x0\nvoid A::f();\n// match: 0 0x402000\nvoid A::g(int);\n"),
                       &n, &err);
    REQUIRE(v);
    REQUIRE(n == 2);
    CHECK_EQ_U64(v[0].target_mask, 1);
    CHECK_EQ_U64(v[0].addr[0], 0x401000);
    CHECK_EQ_U64(v[1].target_mask, 2);
    CHECK_EQ_U64(v[1].addr[1], 0x402000);
    CHECK_CZ(v[1].name, "A::g");
}

/* ---- symbols ------------------------------------------------------------------------------------------------------ */

DK_TEST(undecorate_shapes) {
    /* the shapes the matcher reads (dbghelp's full undecoration) */
    CHECK_CZ(dk_pdb_undecorate("?Update@Target@@QAE_NPAVFoo@@_NM@Z", 0),
             "public: bool __thiscall Target::Update(class Foo *,bool,float)");
    CHECK_CZ(dk_pdb_undecorate("??1?$Map@VTarget@@@@QAE@XZ", 0), "public: __thiscall Map<class Target>::~Map<class Target>(void)");
    CHECK_CZ(dk_pdb_undecorate("??5DataStream@@QAEAAV0@AAI@Z", 0),
             "public: class DataStream & __thiscall DataStream::operator>>(unsigned int &)");
    CHECK_CZ(dk_pdb_undecorate("??_7Widget@@6B@", 0), "const Widget::`vftable'");
    CHECK_CZ(dk_pdb_undecorate("_plain", 0), "_plain");
}

static DkAnnot fn(DkAnnKind kind, const char *name, const char *decl) {
    DkAnnot a;
    memset(&a, 0, sizeof a);
    a.kind = kind;
    a.name = name;
    a.decl = decl;
    a.line = 12;
    return a;
}

DK_TEST(symbol_matches) {
    DkAnnot upd3 = fn(DK_ANN_FUNCTION, "Target::Update", "bool Target::Update(Foo* f, bool inside, float scale)");
    DkAnnot upd1 = fn(DK_ANN_FUNCTION, "Target::Update", "bool Target::Update(Foo* f)");
    const char *sym3 = "?Update@Target@@QAE_NPAVFoo@@_NM@Z", *sym1 = "?Update@Target@@QAE_NPAVFoo@@@Z";
    /* overloads by parameter count */
    CHECK(dk_symbol_matches(&upd3, sym3));
    CHECK(!dk_symbol_matches(&upd3, sym1));
    CHECK(dk_symbol_matches(&upd1, sym1));
    CHECK(!dk_symbol_matches(&upd1, sym3));
    /* another class's method of the same name */
    CHECK(!dk_symbol_matches(&upd1, "?Update@Source@@QAE_NPAVFoo@@@Z"));
    /* an unqualified annotation never matches a qualified symbol */
    DkAnnot bare = fn(DK_ANN_FUNCTION, "MakeUpdate", "void MakeUpdate()");
    CHECK(!dk_symbol_matches(&bare, "?MakeUpdate@Foo_Bar@@QAEXXZ"));
    CHECK(dk_symbol_matches(&bare, "?MakeUpdate@@YAXXZ"));
    DkAnnot mk = fn(DK_ANN_FUNCTION, "Foo_Bar::MakeUpdate", "void Foo_Bar::MakeUpdate()");
    CHECK(dk_symbol_matches(&mk, "?MakeUpdate@Foo_Bar@@QAEXXZ"));
    CHECK(!dk_symbol_matches(&mk, "?MakeUpdateAll@Foo_Bar@@QAEXXZ"));

    /* overloads by parameter type */
    DkAnnot rd_u = fn(DK_ANN_FUNCTION, "DataStream::operator>>", "DataStream& DataStream::operator>>(unsigned int& value)");
    DkAnnot rd_f = fn(DK_ANN_FUNCTION, "DataStream::operator>>", "DataStream& DataStream::operator>>(float& value)");
    const char *op_u = "??5DataStream@@QAEAAV0@AAI@Z", *op_f = "??5DataStream@@QAEAAV0@AAM@Z";
    CHECK(dk_symbol_matches(&rd_u, op_u));
    CHECK(!dk_symbol_matches(&rd_u, op_f));
    CHECK(dk_symbol_matches(&rd_f, op_f));
    CHECK(!dk_symbol_matches(&rd_f, op_u));
    CHECK(!dk_symbol_matches(&rd_f, "??6DataStream@@QAEAAV0@M@Z")); /* operator<< */

    /* destructors and templates */
    DkAnnot dtor = fn(DK_ANN_FUNCTION, "Widget::~Widget", "Widget::~Widget()");
    CHECK(dk_symbol_matches(&dtor, "??1Widget@@QAE@XZ"));
    CHECK(!dk_symbol_matches(&dtor, "??0Widget@@QAE@XZ"));
    CHECK(!dk_symbol_matches(&dtor, "??1Gadget@@QAE@XZ"));
    DkAnnot inst = fn(DK_ANN_FUNCTION, "Map<Target>::~Map", "template Map<Target>::~Map()");
    CHECK(dk_symbol_matches(&inst, "??1?$Map@VTarget@@@@QAE@XZ"));
    CHECK(!dk_symbol_matches(&inst, "??1?$Map@VOther@@@@QAE@XZ"));
    CHECK(!dk_symbol_matches(&inst, "??0?$Map@VTarget@@@@QAE@XZ"));
    DkAnnot get = fn(DK_ANN_FUNCTION, "Map<Target>::Get", "Target* Map<Target>::Get(int index)");
    CHECK(dk_symbol_matches(&get, "?Get@?$Map@VTarget@@@@QAEPAVTarget@@H@Z"));
    CHECK(!dk_symbol_matches(&get, "?Get@?$Map@VTarget@@@@QAEPAVTarget@@XZ"));

    /* data, vtables and C names */
    DkAnnot data = fn(DK_ANN_DATA, "g_counter", "int g_counter = 0");
    CHECK(dk_symbol_matches(&data, "?g_counter@@3HA"));
    CHECK(!dk_symbol_matches(&data, "?g_counter2@@3HA"));
    CHECK(!dk_symbol_matches(&upd1, "?Update@Target@@3HA"));
    DkAnnot vt = fn(DK_ANN_VTABLE, "Widget", "class Widget : public Base");
    CHECK(dk_symbol_matches(&vt, "??_7Widget@@6B@"));
    CHECK(!dk_symbol_matches(&vt, "??_7Gadget@@6B@"));
    CHECK(!dk_symbol_matches(&vt, "??_7Widget@@6BBase@@@"));
    DkAnnot cfn = fn(DK_ANN_FUNCTION, "Sum2", "int __stdcall Sum2(int left, int right)");
    CHECK(dk_symbol_matches(&cfn, "_Sum2@8"));
    CHECK(dk_symbol_matches(&cfn, "_Sum2"));
    CHECK(dk_symbol_matches(&cfn, "@Sum2@8"));
    CHECK(!dk_symbol_matches(&cfn, "_Sum20"));
    CHECK(!dk_symbol_matches(&cfn, "_Sum2@x"));
    DkAnnot none = fn(DK_ANN_FUNCTION, NULL, NULL);
    CHECK(!dk_symbol_matches(&none, "_Sum2"));
}

DK_TEST(bind_declaration_rule) {
    DkStr text = fixture("target_addr.cpp");
    DkAnnotConfig c = ta_config();
    size_t n;
    DkErr err;
    DkAnnot *v = parse(&c, TA_TARGETS, 2, text, &n, &err);
    REQUIRE(v && n == 5);
    const char *syms[] = {"?nextbase@@YAHH@Z", "?skip_braces@@YAPBDPBD@Z", "_Sum2@8", "?skip_bracesX@@YAXXZ",
                          "_Counter2"};
    /* the explicit symbol */
    CHECK_CZ(dk_annot_bind(&v[0], DK_NAME_DECLARATION, syms, 5, &err), "?nextbase@@YAHH@Z");
    CHECK(dk_annot_bind(&v[0], DK_NAME_DECLARATION, syms + 1, 4, &err) == NULL);
    CHECK(msg_has(&err, "explicit symbol ?nextbase@@YAHH@Z"));
    /* the MSVC spellings of the plain name */
    CHECK_CZ(dk_annot_bind(&v[1], DK_NAME_DECLARATION, syms, 5, &err), "?skip_braces@@YAPBDPBD@Z");
    CHECK_CZ(dk_annot_bind(&v[4], DK_NAME_DECLARATION, syms, 5, &err), "_Sum2@8");
    CHECK_EQ_I64(err.code, 0);
    /* none, and several */
    char line[64];
    snprintf(line, sizeof line, ":%d: cannot bind Counter", v[2].line);
    CHECK(dk_annot_bind(&v[2], DK_NAME_DECLARATION, syms, 5, &err) == NULL);
    CHECK(msg_has(&err, line) && msg_has(&err, "0 candidates") && msg_has(&err, "add a symbol line"));
    const char *two[] = {"_Sum2@8", "?Sum2@@YGHHH@Z", "_Sum2"};
    CHECK(dk_annot_bind(&v[4], DK_NAME_DECLARATION, two, 3, &err) == NULL);
    CHECK(msg_has(&err, "3 candidates"));
}

DK_TEST(bind_next_line_rule) {
    DkStr text = fixture("per_target.cpp");
    DkAnnotConfig c = pt_config();
    size_t n;
    DkErr err;
    DkAnnot *v = parse(&c, PT_TARGETS, 2, text, &n, &err);
    REQUIRE(v && n == 9);
    const char *syms[] = {"??_7Widget@@6B@",
                          "?MakeUpdate@Foo_Bar@@QAEXXZ",
                          "?Update@Target@@QAE_NPAVFoo@@_NM@Z",
                          "?Update@Target@@QAE_NPAVFoo@@@Z",
                          "??1Widget@@UAE@XZ",
                          "??1?$Map@VTarget@@@@QAE@XZ",
                          "??5DataStream@@QAEAAV0@AAI@Z",
                          "??5DataStream@@QAEAAV0@AAM@Z",
                          "?g_counter@@3HA",
                          "??_GWidget@@UAEPAXI@Z"};
    for (size_t i = 0; i < n; i++) {
        const char *got = dk_annot_bind(&v[i], DK_NAME_NEXT_LINE, syms, DK_ARRAY_LEN(syms), &err);
        CHECK_MSG(got && strcmp(got, syms[i]) == 0, "annotation %zu (%s) bound to %s: %s", i, v[i].name,
                  got ? got : "(none)", err.msg);
    }
    /* without its declaration the two overloads are ambiguous */
    DkAnnot bare = fn(DK_ANN_FUNCTION, "Target::Update", NULL);
    CHECK(dk_annot_bind(&bare, DK_NAME_NEXT_LINE, syms, DK_ARRAY_LEN(syms), &err) == NULL);
    CHECK(msg_has(&err, ":12: cannot bind Target::Update") && msg_has(&err, "2 candidates"));
    /* an explicit symbol wins over the rule */
    bare.symbol = "?Update@Target@@QAE_NPAVFoo@@@Z";
    CHECK_CZ(dk_annot_bind(&bare, DK_NAME_NEXT_LINE, syms, DK_ARRAY_LEN(syms), &err), "?Update@Target@@QAE_NPAVFoo@@@Z");
    DkAnnot gone = fn(DK_ANN_FUNCTION, "Gone::Away", "void Gone::Away()");
    CHECK(dk_annot_bind(&gone, DK_NAME_NEXT_LINE, syms, DK_ARRAY_LEN(syms), &err) == NULL);
    CHECK(msg_has(&err, "0 candidates"));
}

DK_TEST_MAIN("project_annot")
