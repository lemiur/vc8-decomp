// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The fake toolchain of the adapter's tests (docs/c-toolkit-design.md section 7.2). A test executable that includes
 * this header copies itself to <dir>/fakecl.exe and <dir>/fakelink.exe and, started under one of those names, acts
 * as that tool (fake_tool_dispatch, called first thing in its entry point):
 *
 *   fakecl    reads /Fo<obj>, /D<define>, /GL and /GL- and the source (the last argument that is not an option);
 *             other options are accepted and ignored. The key fake_cl_key(source text, defines, GL mode) names the
 *             canned object a test registered (fake_cl_register) under %FAKECL_REGISTRY%\<key>.obj; it is copied to
 *             the /Fo path. A source holding "#error" fails like a compiler error; an unregistered key fails too.
 *   fakelink  links COFF objects: /OUT:<image>, /MAP:<map>, /BASE:<hex> (default 0x10000000); other options and
 *             .lib inputs are ignored. The code sections of every object are laid out in .text (16-byte aligned,
 *             int3 padding), the initialised data sections in .data, then one zeroed 4-byte .data slot per
 *             "__imp_" symbol; DIR32, DIR32NB and REL32 relocations are applied, each DIR32 word gets a base
 *             relocation, and an MSVC-format map lists every external and static symbol ("Publics by Value").
 *             An undefined symbol that is not "__imp_" fails with an LNK2001 line.
 *
 * fake_link is also callable in-process (to write a reference image from the same objects at another base). */
#pragma once
#include "dk/dk.h"
#include "fake_pe.h"

#include <stdio.h>
#include <string.h>

static int fake__cmp_cz(const void *x, const void *y) {
    return strcmp(*(const char *const *)x, *(const char *const *)y);
}

/* sha256 hex of the source text, then each define (sorted) and the GL mode ("", "/GL" or "/GL-"), NUL separated. */
static inline const char *fake_cl_key(DkStr text, const char *const *defines, size_t n, const char *gl) {
    DkHasher h;
    dk_hasher_init(&h, DK_HASH_SHA256);
    dk_hasher_update(&h, text.p, text.n);
    const char **sorted = (const char **)dk_xmalloc(sizeof *sorted * (n ? n : 1));
    for (size_t i = 0; i < n; i++) sorted[i] = defines[i];
    qsort((void *)sorted, n, sizeof *sorted, fake__cmp_cz);
    for (size_t i = 0; i < n; i++) {
        dk_hasher_update(&h, "", 1);
        dk_hasher_update(&h, sorted[i], strlen(sorted[i]));
    }
    dk_xfree((void *)sorted);
    dk_hasher_update(&h, "", 1);
    dk_hasher_update(&h, gl, strlen(gl));
    u8 d[32];
    dk_hasher_final(&h, d);
    dk_hasher_free(&h);
    return dk_hex(dk_arena(), d, 32);
}

/* The key of an object registered for one exact option list: sha256 hex of the source key and the options (every
 * option that is not /Fo, /D, /I, /GL[-], /nologo or /c, in command-line order, joined with one space). fakecl
 * prefers it to the plain key, so a test can answer an option variant with another object. */
static inline const char *fake_cl_flags_key(const char *key, const char *flags) {
    DkHasher h;
    dk_hasher_init(&h, DK_HASH_SHA256);
    dk_hasher_update(&h, key, strlen(key));
    dk_hasher_update(&h, "", 1);
    dk_hasher_update(&h, flags, strlen(flags));
    u8 d[32];
    dk_hasher_final(&h, d);
    dk_hasher_free(&h);
    return dk_hex(dk_arena(), d, 32);
}

static inline bool fake_cl_register(const char *registry, const char *key, DkStr obj) {
    dk_makedirs(registry, true);
    return dk_write_file(dk_join(dk_arena(), registry, dk_sprintf(dk_arena(), "%s.obj", key)), obj.p, obj.n);
}

static inline int fake_cl_main(int argc, char **argv) {
    const char *fo = NULL, *src = NULL, *gl = "";
    DkCzVec defines = {0};
    DkBuf flags;
    dk_buf_init(&flags, dk_arena());
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] == '/' || a[0] == '-') {
            if (_strnicmp(a + 1, "Fo", 2) == 0) fo = a + 3;
            else if (a[1] == 'D') dk_vec_push(&defines, (char *)a + 2);
            else if (_stricmp(a + 1, "GL") == 0) gl = "/GL";
            else if (_stricmp(a + 1, "GL-") == 0) gl = "/GL-";
            else if (a[1] != 'I' && _stricmp(a + 1, "nologo") != 0 && _stricmp(a + 1, "c") != 0) {
                if (flags.n) dk_buf_putc(&flags, ' ');
                dk_buf_putz(&flags, a);
            }
        } else {
            src = a;
        }
    }
    if (!fo || !src) {
        fprintf(stderr, "fakecl: error: need /Fo and a source\n");
        return 2;
    }
    DkBytes text = {0};
    if (!dk_read_all(dk_arena(), src, &text)) {
        printf("%s(0): fatal error C1083: cannot open source file\n", src);
        return 2;
    }
    DkStr base = dk_path_basename(src);
    printf("%.*s\n", DK_SF(base));
    DkStr t = {(const char *)text.v, text.n};
    i64 at = dk_str_find(t, DK_S("#error"), 0, DK_END);
    if (at >= 0) {
        printf("%s(1): fatal error C1189: #error: synthetic failure\n", src);
        return 2;
    }
    const char *reg = getenv("FAKECL_REGISTRY");
    const char *key = fake_cl_key(t, (const char *const *)defines.v, defines.n, gl);
    const char *canned = reg ? dk_join(dk_arena(), reg, dk_sprintf(dk_arena(), "%s.obj", key)) : NULL;
    DkBytes obj = {0};
    if (reg) {
        const char *fcanned = dk_join(dk_arena(), reg, dk_sprintf(dk_arena(), "%s.obj", fake_cl_flags_key(key, dk_buf_cz(&flags))));
        if (dk_isfile(fcanned)) canned = fcanned;
    }
    if (!canned || !dk_read_all(dk_arena(), canned, &obj)) {
        printf("%s(1): error C9999: no canned object for key %s\n", src, key);
        return 2;
    }
    return dk_write_file(fo, obj.v, obj.n) ? 0 : 2;
}

/* ---- the fake linker -------------------------------------------------------------------------------------------- */
typedef struct {
    const char *name;
    u32 va;
    int seg; /* 1 .text, 2 .data */
    u32 off;
    bool is_static, is_function;
    const char *object;
} FakeLinkSym;

static inline int fake__cmp_sym(const void *x, const void *y) {
    const FakeLinkSym *a = (const FakeLinkSym *)x, *b = (const FakeLinkSym *)y;
    if (a->va != b->va) return a->va < b->va ? -1 : 1;
    return strcmp(a->name, b->name);
}

/* Links objects into image and map; returns 0, or 1 with a message on stdout. */
static inline int fake_link(const char *const *objects, size_t nobj, u32 base, const char *image, const char *map) {
    DkArena *a = dk_arena();
    DkCoff **coffs = DK_NEWN(a, DkCoff *, nobj ? nobj : 1);
    u32 **place = DK_NEWN(a, u32 *, nobj ? nobj : 1); /* per object, per section: offset in its output section */
    int **seg = DK_NEWN(a, int *, nobj ? nobj : 1);
    DkBytes text = {0}, data = {0};
    for (size_t o = 0; o < nobj; o++) {
        DkBytes bytes = {0};
        if (!dk_read_all(a, objects[o], &bytes)) {
            printf("fakelink: error LNK1181: cannot open input file '%s'\n", objects[o]);
            return 1;
        }
        coffs[o] = dk_coff_parse(a, bytes.v, bytes.n, 0x14C);
        DkCoff *c = coffs[o];
        place[o] = DK_NEWN(a, u32, c->number_of_sections + 1);
        seg[o] = DK_NEWN(a, int, c->number_of_sections + 1);
        for (u32 s = 0; s < c->number_of_sections; s++) {
            const DkCoffSection *sec = &c->sections[s];
            DkBytes *out = NULL;
            if (sec->characteristics & (DK_SCN_LNK_INFO | DK_SCN_LNK_REMOVE)) continue;
            if (sec->characteristics & DK_SCN_CNT_CODE) {
                out = &text;
                seg[o][s] = 1;
            } else if (sec->characteristics & DK_SCN_CNT_INITIALIZED_DATA) {
                out = &data;
                seg[o][s] = 2;
            } else {
                continue;
            }
            while (out->n & 15) dk_vec_push(out, (u8)(out == &text ? 0xCC : 0));
            place[o][s] = (u32)out->n;
            if (sec->data.n) dk_vec_extend(out, sec->data.p, sec->data.n);
        }
    }
    while (text.n & 15) dk_vec_push(&text, 0xCC);
    while (data.n & 15) dk_vec_push(&data, 0);
    /* import slots after the data */
    DkMap *imps = dk_map_new();
    for (size_t o = 0; o < nobj; o++)
        for (u32 i = 0; i < coffs[o]->number_of_symbols; i++) {
            const DkCoffSymbol *s = &coffs[o]->symbols[i];
            if (s->aux || s->section != 0 || !dk_str_startswith(s->name, DK_S("__imp_"))) continue;
            bool created = false;
            DkVal *v = dk_map_put(imps, s->name, &created);
            if (created) {
                v->u = data.n;
                u8 z[4] = {0, 0, 0, 0};
                dk_vec_extend(&data, z, 4);
            }
        }
    u32 text_rva = 0x1000, data_rva = fake_pe__align(text_rva + (u32)(text.n ? text.n : 1), 0x1000);
    /* the symbols */
    DkMap *globals = dk_map_new(); /* external name -> va */
    DK_VEC(FakeLinkSym) syms = {0};
    for (size_t o = 0; o < nobj; o++) {
        DkCoff *c = coffs[o];
        for (u32 i = 0; i < c->number_of_symbols; i++) {
            const DkCoffSymbol *s = &c->symbols[i];
            if (s->aux || s->section <= 0 || !seg[o][s->section - 1]) continue;
            int sg = seg[o][s->section - 1];
            u32 off = place[o][s->section - 1] + s->value;
            FakeLinkSym m = {dk_cz(a, s->name), base + (sg == 1 ? text_rva : data_rva) + off, sg, off,
                             s->storage_class != 2, dk_coff_is_function(s), objects[o]};
            if (s->storage_class == 2) {
                bool created = false;
                DkVal *v = dk_map_put(globals, s->name, &created);
                if (created) v->u = m.va;
            }
            if ((s->storage_class == 2 || s->storage_class == 3) && s->name.n && s->name.p[0] != '.')
                dk_vec_push(&syms, m);
        }
    }
    {
        DkMapIter it = {0};
        while (dk_map_next(imps, &it)) {
            FakeLinkSym m = {dk_cz(a, it.key), base + data_rva + (u32)it.val->u, 2, (u32)it.val->u, false, false,
                             "kernel32:dll"};
            dk_vec_push(&syms, m);
            bool created = false;
            dk_map_put(globals, it.key, &created)->u = m.va;
        }
    }
    /* relocations */
    FakePe pe;
    fake_pe_init(&pe, base);
    for (size_t o = 0; o < nobj; o++) {
        DkCoff *c = coffs[o];
        for (u32 s = 0; s < c->number_of_sections; s++) {
            const DkCoffSection *sec = &c->sections[s];
            int sg = seg[o][s];
            if (!sg) continue;
            DkBytes *out = sg == 1 ? &text : &data;
            u32 sec_rva = (sg == 1 ? text_rva : data_rva) + place[o][s];
            for (size_t r = 0; r < sec->n_relocs; r++) {
                const DkCoffReloc *rel = &sec->relocs[r];
                const DkCoffSymbol *t = dk_coff_symbol(c, rel->symbol_index);
                u32 target;
                if (t->section > 0 && seg[o][t->section - 1]) {
                    int tg = seg[o][t->section - 1];
                    target = base + (tg == 1 ? text_rva : data_rva) + place[o][t->section - 1] + t->value;
                } else {
                    const DkVal *g = dk_map_get(globals, t->name);
                    if (!g) {
                        printf("%s : error LNK2001: unresolved external symbol %.*s\n", objects[o], DK_SF(t->name));
                        return 1;
                    }
                    target = (u32)g->u;
                }
                u8 *w = out->v + place[o][s] + rel->offset;
                u32 word;
                memcpy(&word, w, 4);
                u32 site = base + sec_rva + rel->offset;
                if (rel->type == 0x06) {
                    word += target;
                    fake_pe_reloc(&pe, sec_rva + rel->offset);
                } else if (rel->type == 0x07) {
                    word += target - base;
                } else if (rel->type == 0x14) {
                    word += target - (site + 4);
                } else {
                    printf("%s : error LNK1999: relocation type %u\n", objects[o], rel->type);
                    return 1;
                }
                memcpy(w, &word, 4);
            }
        }
    }
    fake_pe_section(&pe, ".text", 0x60000020u, text.v, text.n);
    fake_pe_section(&pe, ".data", 0xC0000040u, data.v, data.n);
    dk_vec_free(&text);
    dk_vec_free(&data);
    if (!fake_pe_write(&pe, image)) {
        printf("fakelink: error LNK1104: cannot write '%s'\n", image);
        return 1;
    }
    qsort(syms.v, syms.n, sizeof *syms.v, fake__cmp_sym);
    DkBuf mb;
    dk_buf_init(&mb, NULL);
    dk_buf_printf(&mb, " fake\n\n Preferred load address is %08x\n\n", base);
    dk_buf_printf(&mb, "  Address         Publics by Value              Rva+Base       Lib:Object\n\n");
    for (int pass = 0; pass < 2; pass++) {
        if (pass == 1) dk_buf_printf(&mb, "\n Static symbols\n\n");
        for (size_t i = 0; i < syms.n; i++) {
            const FakeLinkSym *m = &syms.v[i];
            if (m->is_static != (pass == 1)) continue;
            DkStr obase = dk_path_basename(m->object);
            dk_buf_printf(&mb, " %04x:%08x       %-26s %08x %s  %.*s\n", m->seg, m->off, m->name, m->va,
                          m->is_function ? "f  " : "   ", DK_SF(obase));
        }
    }
    bool ok = dk_write_file(map, mb.p, mb.n);
    dk_buf_free(&mb);
    dk_vec_free(&syms);
    return ok ? 0 : 1;
}

static inline int fake_link_main(int argc, char **argv) {
    const char *out = NULL, *map = NULL;
    u32 base = 0x10000000u;
    DkCzVec objs = {0};
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (_strnicmp(a, "/OUT:", 5) == 0) out = a + 5;
        else if (_strnicmp(a, "/MAP:", 5) == 0) map = a + 5;
        else if (_strnicmp(a, "/BASE:", 6) == 0) base = (u32)strtoul(a + 6, NULL, 16);
        else if (a[0] != '/' && strlen(a) > 4 && _stricmp(a + strlen(a) - 4, ".obj") == 0)
            dk_vec_push(&objs, (char *)a);
    }
    if (!out || !map) {
        printf("fakelink: error LNK1000: need /OUT: and /MAP:\n");
        return 1;
    }
    return fake_link((const char *const *)objs.v, objs.n, base, out, map);
}

/* -1 when the program runs under its own name; else the fake tool's exit code. */
static inline int fake_tool_dispatch(int argc, char **argv) {
    if (argc < 1) return -1;
    DkStr b = dk_path_basename(argv[0]);
    if (b.n >= 6 && _strnicmp(b.p, "fakecl", 6) == 0) return fake_cl_main(argc, argv);
    if (b.n >= 8 && _strnicmp(b.p, "fakelink", 8) == 0) return fake_link_main(argc, argv);
    return -1;
}
