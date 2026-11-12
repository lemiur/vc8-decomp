// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Minimal COFF (i386) readers and writers for the VC8 toolchain: the symbols of an object, the undefined and defined
 * externals, an object of absolute symbols, an object holding a table of pointers to symbols, a one-section code
 * object, and the two in-place rewriters (redirect, rename_symbols). These read and patch the bytes from the offsets
 * in the header, without the checks of pe.h's parser (a relocation naming a slot past the table is carried
 * through). A truncated or malformed object is a dk_panic: the input is trusted to be a VC8 object. */
#include "coff.h"

#include "dk/fs.h"
#include "dk/map.h"

#define PANIC(...) dk_panic(__FILE__, __LINE__, __VA_ARGS__)

/* ------------------------------------------------------------------------------------------ byte helpers */

/* A read or write past the end of the buffer is a panic. */
static void need(DkStr d, size_t at, size_t n) {
    if (at > d.n || n > d.n - at) PANIC("truncated object: a read needs a buffer of at least %zu bytes", at + n);
}
static u32 rd32(DkStr d, size_t at) {
    need(d, at, 4);
    u32 v;
    memcpy(&v, d.p + at, 4);
    return v;
}
static u16 rd16(DkStr d, size_t at) {
    need(d, at, 2);
    u16 v;
    memcpy(&v, d.p + at, 2);
    return v;
}
static void wr32(u8 *d, size_t n, size_t at, u32 v) {
    if (at > n || n - at < 4) PANIC("truncated object: a write needs a buffer of at least %zu bytes", at + 4);
    memcpy(d + at, &v, 4);
}

typedef DkBytes Out;
static void put16(Out *o, u16 v) { dk_vec_extend(o, (const u8 *)&v, 2); }
static void put32(Out *o, u32 v) { dk_vec_extend(o, (const u8 *)&v, 4); }
static void put8(Out *o, u8 v) { dk_vec_push(o, v); }
static void put_bytes(Out *o, const void *p, size_t n) {
    if (n) dk_vec_extend(o, (const u8 *)p, n);
}
/* A symbol record's tail: u32 value, i16 section, u16 type, u8 storage, u8 aux count. */
static void put_sym_tail(Out *o, u32 value, i16 section, u16 type, u8 storage, u8 aux) {
    put32(o, value);
    put16(o, (u16)section);
    put16(o, type);
    put8(o, storage);
    put8(o, aux);
}
/* The header: machine, section count, zero timestamp, symbol table offset and count, no optional header, no flags. */
static void put_header(Out *o, u16 nsections, u32 symtab, u32 nsyms) {
    put16(o, COFF_IMAGE_FILE_MACHINE_I386);
    put16(o, nsections);
    put32(o, 0);
    put32(o, symtab);
    put32(o, nsyms);
    put16(o, 0);
    put16(o, 0);
}
/* A result: a copy in the thread's arena, the heap vector freed. */
static DkStr finish(Out *o) {
    DkStr r = {dk_memdup(dk_arena(), o->v ? (const void *)o->v : (const void *)"", o->n), o->n};
    dk_vec_free(o);
    return r;
}

static DkStr decode_strict(const u8 *p, size_t n) {
    DkStr s = {(const char *)p, n};
    if (!dk_u8_valid(s)) PANIC("symbol name is not valid UTF-8");
    return s;
}
/* A short name field with its trailing NULs stripped, as UTF-8. */
static DkStr short_name(const u8 *raw) {
    size_t n = 8;
    while (n && raw[n - 1] == 0) n--;
    return decode_strict(raw, n);
}

/* ---------------------------------------------------------------------------------------------- readers */

const CoffSymbol *coff_symbols(const char *path, size_t *count) {
    DkArena *a = dk_arena();
    DkBytes file = {0};
    if (!dk_read_all(a, path, &file))
        PANIC("cannot read '%s'", path);
    DkStr data = {(const char *)file.v, file.n};
    u32 symtab = rd32(data, 8), nsyms = rd32(data, 12);
    rd32(data, 16); /* the 20-byte header unpack: needs all 20 bytes */
    u64 strtab = (u64)symtab + (u64)nsyms * 18;
    CoffSymbol *out = DK_NEWN(a, CoffSymbol, nsyms ? nsyms : 1);
    size_t n = 0;
    u64 i = 0;
    while (i < nsyms) {
        u64 at = (u64)symtab + i * 18;
        need(data, (size_t)at, 18);
        const u8 *raw = (const u8 *)data.p + at;
        DkStr name;
        if (!raw[0] && !raw[1] && !raw[2] && !raw[3]) {
            u64 offset = strtab + rd32(data, (size_t)at + 4);
            if (offset > data.n) PANIC("symbol name outside the string table");
            const u8 *nul = memchr(data.p + offset, 0, data.n - offset);
            if (!nul) PANIC("symbol name outside the string table");
            name = decode_strict((const u8 *)data.p + offset, (size_t)(nul - (const u8 *)data.p - offset));
        } else {
            name = short_name(raw);
        }
        CoffSymbol *s = &out[n++];
        s->name = name;
        s->value = rd32(data, (size_t)at + 8);
        s->section = (i16)rd16(data, (size_t)at + 12);
        s->type = rd16(data, (size_t)at + 14);
        s->storage = (u8)data.p[at + 16];
        i += 1 + (u8)data.p[at + 17];
    }
    *count = n;
    return out;
}

DkStrVec coff_undefined_symbols(const char *path) {
    size_t n;
    const CoffSymbol *syms = coff_symbols(path, &n);
    DkStrVec out = {0};
    for (size_t i = 0; i < n; i++)
        if (syms[i].section == 0 && syms[i].storage == COFF_IMAGE_SYM_CLASS_EXTERNAL && syms[i].value == 0)
            dk_vec_push(&out, syms[i].name);
    return out;
}

DkStrVec coff_defined_symbols(const char *path) {
    size_t n;
    const CoffSymbol *syms = coff_symbols(path, &n);
    DkStrVec out = {0};
    for (size_t i = 0; i < n; i++)
        if (syms[i].section > 0 && syms[i].storage == COFF_IMAGE_SYM_CLASS_EXTERNAL) dk_vec_push(&out, syms[i].name);
    return out;
}

/* ------------------------------------------------------------------------------------------ StringTable */

void coff_string_table_init(CoffStringTable *t) { memset(t, 0, sizeof *t); }

void coff_string_table_name_field(CoffStringTable *t, DkStr name, u8 out[8]) {
    if (name.n <= 8) {
        memset(out, 0, 8);
        if (name.n) memcpy(out, name.p, name.n);
        return;
    }
    u32 offset = (u32)(4 + t->data.n);
    dk_vec_extend(&t->data, (const u8 *)name.p, name.n);
    dk_vec_push(&t->data, 0);
    memset(out, 0, 4);
    memcpy(out + 4, &offset, 4);
}

DkStr coff_string_table_blob(const CoffStringTable *t) {
    Out o = {0};
    put32(&o, (u32)(4 + t->data.n));
    put_bytes(&o, t->data.v, t->data.n);
    return finish(&o);
}

/* A name field made from a name, appended to an output. */
static void put_name_field(Out *o, CoffStringTable *t, DkStr name) {
    u8 f[8];
    coff_string_table_name_field(t, name, f);
    put_bytes(o, f, 8);
}

/* ------------------------------------------------------------------------------------------------ writers */

DkStr coff_absolute_object(const CoffAbsoluteEntry *entries, size_t n) {
    CoffStringTable strings;
    coff_string_table_init(&strings);
    Out table = {0};
    for (size_t i = 0; i < n; i++) {
        put_name_field(&table, &strings, dk_str(entries[i].name));
        put_sym_tail(&table, entries[i].address, (i16)-1 /* COFF_IMAGE_SYM_ABSOLUTE as the signed field */, 0, COFF_IMAGE_SYM_CLASS_EXTERNAL, 0);
    }
    Out o = {0};
    put_header(&o, 0, 20, (u32)n);
    put_bytes(&o, table.v, table.n);
    dk_vec_free(&table);
    DkStr blob = coff_string_table_blob(&strings);
    put_bytes(&o, blob.p, blob.n);
    dk_vec_free(&strings.data);
    return finish(&o);
}

DkStr coff_table_object(const char *section_name, const char *public_name, const CoffWord *words, size_t n_words,
                         DkStr strings_after) {
    Out body = {0};
    struct Reloc {
        u32 offset;
        const char *symbol;
    };
    DK_VEC(struct Reloc) relocations = {0};
    DkCzVec externals = {0};
    DkMap *position = dk_map_new(); /* symbol -> its place in externals (.i) */
    for (size_t k = 0; k < n_words; k++) {
        if (words[k].symbol) {
            const char *symbol = words[k].symbol;
            if (strcmp(symbol, COFF_SECTION_SYMBOL) != 0 && !dk_map_has(position, dk_str(symbol))) {
                dk_map_put(position, dk_str(symbol), NULL)->i = (i64)externals.n;
                dk_vec_push(&externals, (char *)symbol);
            }
            struct Reloc r = {(u32)body.n, symbol};
            dk_vec_push(&relocations, r);
        }
        put32(&body, (u32)words[k].value); /* addend & 0xFFFFFFFF, or word & 0xFFFFFFFF */
    }
    put_bytes(&body, strings_after.p, strings_after.n);
    while (body.n % 4) put8(&body, 0);

    /* Symbols: the section (and its auxiliary record) are 0 and 1, the public one 2, the externals 3... */
    u32 raw_at = 20 + 40;
    u32 rel_at = raw_at + (u32)body.n;
    u32 sym_at = rel_at + (u32)relocations.n * 10;
    CoffStringTable strings;
    coff_string_table_init(&strings);
    Out o = {0};
    put_header(&o, 1, sym_at, 3 + (u32)externals.n);
    /* the section name cut to 8 bytes, NUL-padded */
    {
        size_t len = strlen(section_name);
        u8 nm[8] = {0};
        memcpy(nm, section_name, DK_MIN(len, (size_t)8));
        put_bytes(&o, nm, 8);
    }
    put32(&o, 0);
    put32(&o, 0);
    put32(&o, (u32)body.n);
    put32(&o, raw_at);
    put32(&o, rel_at);
    put32(&o, 0);
    put16(&o, (u16)relocations.n);
    put16(&o, 0);
    put32(&o, COFF_TABLE_SECTION_CHARACTERISTICS);
    put_bytes(&o, body.v, body.n);
    for (size_t k = 0; k < relocations.n; k++) {
        const char *symbol = relocations.v[k].symbol;
        u32 index = strcmp(symbol, COFF_SECTION_SYMBOL) == 0 ? 0 : 3 + (u32)dk_map_get(position, dk_str(symbol))->i;
        put32(&o, relocations.v[k].offset);
        put32(&o, index);
        put16(&o, COFF_IMAGE_REL_I386_DIR32);
    }
    /* The name fields are made in the order the symbols are laid out: section, public, externals. */
    put_name_field(&o, &strings, dk_str(section_name));
    put_sym_tail(&o, 0, 1, 0, COFF_IMAGE_SYM_CLASS_STATIC, 1);
    put32(&o, (u32)body.n); /* the aux record: u32 size, u16 nrel, then zeros */
    put16(&o, (u16)relocations.n);
    put16(&o, 0);
    put32(&o, 0);
    put16(&o, 0);
    put8(&o, 0);
    put8(&o, 0);
    put8(&o, 0);
    put8(&o, 0);
    put_name_field(&o, &strings, dk_str(public_name));
    put_sym_tail(&o, 0, 1, 0, COFF_IMAGE_SYM_CLASS_EXTERNAL, 0);
    for (size_t k = 0; k < externals.n; k++) {
        put_name_field(&o, &strings, dk_str(externals.v[k]));
        put_sym_tail(&o, 0, 0, 0x20, COFF_IMAGE_SYM_CLASS_EXTERNAL, 0);
    }
    DkStr blob = coff_string_table_blob(&strings);
    put_bytes(&o, blob.p, blob.n);
    dk_vec_free(&strings.data);
    dk_vec_free(&body);
    dk_vec_free(&relocations);
    dk_vec_free(&externals);
    dk_map_free(position);
    return finish(&o);
}

DkStr coff_code_object(DkStr code) {
    u32 raw_at = 20 + 40;
    CoffStringTable strings;
    coff_string_table_init(&strings);
    Out o = {0};
    put_header(&o, 1, raw_at + (u32)code.n, 3);
    put_bytes(&o, ".text\0\0\0", 8);
    put32(&o, 0);
    put32(&o, 0);
    put32(&o, (u32)code.n);
    put32(&o, raw_at);
    put32(&o, 0);
    put32(&o, 0);
    put16(&o, 0);
    put16(&o, 0);
    put32(&o, COFF_CODE_SECTION_CHARACTERISTICS);
    put_bytes(&o, code.p, code.n);
    put_name_field(&o, &strings, DK_S(".text"));
    put_sym_tail(&o, 0, 1, 0, COFF_IMAGE_SYM_CLASS_STATIC, 1);
    put32(&o, (u32)code.n);
    put16(&o, 0);
    put16(&o, 0);
    put32(&o, 0);
    put16(&o, 0);
    put8(&o, 0);
    put8(&o, 0);
    put8(&o, 0);
    put8(&o, 0);
    put_name_field(&o, &strings, dk_str(COFF_CODE_OBJECT_SYMBOL));
    put_sym_tail(&o, 0, 1, 0x20, COFF_IMAGE_SYM_CLASS_EXTERNAL, 0);
    DkStr blob = coff_string_table_blob(&strings);
    put_bytes(&o, blob.p, blob.n);
    dk_vec_free(&strings.data);
    return finish(&o);
}

/* ---------------------------------------------------------------------------------------------- rewriters */

/* The object being rewritten: a mutable copy of the bytes, its symbol table and the string table (without the
 * 4-byte size) as a growing heap vector. */
typedef struct {
    u8 *d;
    size_t n;
    u16 nsections;
    u32 symtab, nsyms;
    u16 optsize;
    size_t strtab;
    DkBytes strings;
} Obj;

static void obj_open(Obj *ob, DkStr data) {
    ob->d = dk_memdup(dk_scratch(), data.p, data.n);
    ob->n = data.n;
    ob->nsections = rd16(data, 2);
    ob->symtab = rd32(data, 8);
    ob->nsyms = rd32(data, 12);
    ob->optsize = rd16(data, 16);
    rd16(data, 18);
    ob->strtab = (size_t)((u64)ob->symtab + (u64)ob->nsyms * 18);
    /* the string table without its size field: clipped to the data, empty when the size is under 4 */
    u32 size = rd32(data, ob->strtab);
    u64 from = (u64)ob->strtab + 4, to = (u64)ob->strtab + size;
    if (to > data.n) to = data.n;
    memset(&ob->strings, 0, sizeof ob->strings);
    if (from < to) dk_vec_extend(&ob->strings, data.p + from, (size_t)(to - from));
}

/* name_of(at): the name of the symbol record at `at`, a copy in the scratch arena. */
static DkStr obj_name_of(Obj *ob, size_t at) {
    need((DkStr){(const char *)ob->d, ob->n}, at, 8);
    const u8 *raw = ob->d + at;
    DkStr r;
    if (!raw[0] && !raw[1] && !raw[2] && !raw[3]) {
        u32 field;
        memcpy(&field, raw + 4, 4);
        if (field < 4) PANIC("symbol name outside the string table"); /* offset -4...-1: a damaged name field */
        size_t offset = field - 4;
        if (offset > ob->strings.n) PANIC("symbol name outside the string table");
        const u8 *nul = ob->strings.n > offset ? memchr(ob->strings.v + offset, 0, ob->strings.n - offset) : NULL;
        if (!nul) PANIC("symbol name outside the string table");
        r = decode_strict(ob->strings.v + offset, (size_t)(nul - ob->strings.v) - offset);
    } else {
        r = short_name(raw);
    }
    return dk_str_dup(dk_scratch(), r);
}

/* name_field(name) of redirect: a short name NUL-padded, a long one appended to the strings. */
static void obj_name_field(Obj *ob, DkStr name, u8 out[8]) {
    if (name.n <= 8) {
        memset(out, 0, 8);
        if (name.n) memcpy(out, name.p, name.n);
        return;
    }
    u32 offset = (u32)(4 + ob->strings.n);
    dk_vec_extend(&ob->strings, (const u8 *)name.p, name.n);
    dk_vec_push(&ob->strings, 0);
    memset(out, 0, 4);
    memcpy(out + 4, &offset, 4);
}

typedef struct {
    u32 i;
    size_t at;
    DkStr name;
    i16 section;
    u16 kind;
    u8 storage;
} Entry;
typedef struct {
    DkStr name;
    u16 kind;
} Added;

typedef struct {
    Obj *ob;
    u32 nsyms;
    DK_VEC(Added) added;
    DkMap *added_at; /* name -> its place in added (.i) */
} Undef;

/* undefined(name, kind): the index of the appended undefined symbol of this name, adding it on first request. */
static u32 undefined_index(Undef *u, DkStr name, u16 kind) {
    DkVal *v = dk_map_get(u->added_at, name);
    if (v) return u->nsyms + (u32)v->i;
    dk_map_put(u->added_at, name, NULL)->i = (i64)u->added.n;
    Added ad = {dk_str_dup(dk_scratch(), name), kind};
    dk_vec_push(&u->added, ad);
    return u->nsyms + (u32)u->added.n - 1;
}

DkStr coff_redirect(DkStr data, const DkMap *own, CoffAbsoluteAliasFn absolute_alias, void *ctx) {
    DkArenaMark mark = dk_arena_mark(dk_scratch());
    Obj ob;
    obj_open(&ob, data);
    DkStr view = {(const char *)ob.d, ob.n};
    DK_VEC(Entry) entries = {0};
    for (u64 i = 0; i < ob.nsyms;) {
        size_t at = (size_t)((u64)ob.symtab + i * 18);
        need(view, at, 18);
        Entry e;
        e.i = (u32)i;
        e.at = at;
        e.name = obj_name_of(&ob, at);
        e.section = (i16)rd16(view, at + 12);
        e.kind = rd16(view, at + 14);
        e.storage = ob.d[at + 16];
        u8 aux = ob.d[at + 17];
        dk_vec_push(&entries, e);
        i += 1 + aux;
    }
    Undef u = {&ob, ob.nsyms, {0}, dk_map_new()};

    DkIMap *remap_def = dk_imap_new(); /* definition index -> the appended undefined twin */
    DkU32Vec def_order = {0};           /* its keys in insertion order */
    DkStrVec def_names = {0};           /* name_at of each of them */
    DkIMap *remap_dir = dk_imap_new(); /* the ("dir", index) keys */
    for (size_t k = 0; k < entries.n; k++) {
        Entry *e = &entries.v[k];
        DkVal *alias;
        if (e->section > 0 && e->storage == COFF_IMAGE_SYM_CLASS_EXTERNAL && (alias = dk_map_get(own, e->name))) {
            u8 f[8];
            obj_name_field(&ob, dk_str((const char *)alias->p), f);
            memcpy(ob.d + e->at, f, 8);
            dk_imap_put(remap_def, e->i, NULL)->u = undefined_index(&u, e->name, e->kind);
            dk_vec_push(&def_order, e->i);
            dk_vec_push(&def_names, e->name);
        }
    }
    /* The compiler's scalar deleting destructor has an undefined twin of its name (the target of its weak alias
     * `??_E`), which the image-relative records of the debug sections (DIR32NB) point to: they follow the
     * definition. */
    DkMap *defined_at = dk_map_new(); /* name -> index of the last renamed definition of that name */
    for (size_t k = 0; k < entries.n; k++)
        if (dk_imap_has(remap_def, entries.v[k].i)) dk_map_put(defined_at, entries.v[k].name, NULL)->i = entries.v[k].i;
    DkIMap *twins = dk_imap_new();
    for (size_t k = 0; k < entries.n; k++) {
        Entry *e = &entries.v[k];
        DkVal *d;
        if (e->section == 0 && e->storage == COFF_IMAGE_SYM_CLASS_EXTERNAL && (d = dk_map_get(defined_at, e->name)))
            dk_imap_put(twins, e->i, NULL)->u = (u64)d->i;
    }
    for (size_t k = 0; k < entries.n; k++) {
        Entry *e = &entries.v[k];
        if (e->section == 0 && e->storage == COFF_IMAGE_SYM_CLASS_EXTERNAL) {
            const char *alias = absolute_alias(ctx, dk_cz(dk_scratch(), e->name));
            if (alias && *alias) {
                /* the alias symbol is requested first, then kept only when the slot was empty */
                u32 idx = undefined_index(&u, dk_str(alias), e->kind);
                bool created;
                DkVal *slot = dk_imap_put(remap_dir, e->i, &created);
                if (created) slot->u = idx;
            }
        }
    }
    for (size_t k = 0; k < def_order.n; k++) {
        const char *alias = absolute_alias(ctx, dk_cz(dk_scratch(), def_names.v[k]));
        if (alias && *alias) dk_imap_put(remap_dir, def_order.v[k], NULL)->u = undefined_index(&u, dk_str(alias), 0);
    }
    for (u16 s = 0; s < ob.nsections; s++) {
        size_t header = 20 + (size_t)ob.optsize + (size_t)s * 40;
        u32 relocs = rd32(view, header + 24);
        u16 count = rd16(view, header + 32);
        for (u32 r = 0; r < count; r++) {
            size_t at = (size_t)relocs + (size_t)r * 10;
            u32 target = rd32(view, at + 4);
            u16 kind = rd16(view, at + 8);
            DkVal *v;
            if (kind == COFF_IMAGE_REL_I386_DIR32 && (v = dk_imap_get(remap_dir, target)))
                wr32(ob.d, ob.n, at + 4, (u32)v->u);
            else if (kind == COFF_IMAGE_REL_I386_DIR32NB && (v = dk_imap_get(twins, target)))
                wr32(ob.d, ob.n, at + 4, (u32)v->u);
            else if ((kind == COFF_IMAGE_REL_I386_DIR32 || kind == COFF_IMAGE_REL_I386_REL32) &&
                     (v = dk_imap_get(remap_def, target)))
                wr32(ob.d, ob.n, at + 4, (u32)v->u);
        }
    }
    /* out = data[:symtab] + table + u32(4 + len(strings)) + strings, the symbol count raised */
    if (ob.symtab > ob.n || ob.strtab > ob.n || ob.strtab < ob.symtab) PANIC("symbol table out of range");
    Out out = {0};
    put_bytes(&out, ob.d, ob.symtab);
    put_bytes(&out, ob.d + ob.symtab, ob.strtab - ob.symtab);
    for (size_t k = 0; k < u.added.n; k++) {
        u8 f[8];
        obj_name_field(&ob, u.added.v[k].name, f);
        put_bytes(&out, f, 8);
        put_sym_tail(&out, 0, 0, u.added.v[k].kind, COFF_IMAGE_SYM_CLASS_EXTERNAL, 0);
    }
    put32(&out, (u32)(4 + ob.strings.n));
    put_bytes(&out, ob.strings.v, ob.strings.n);
    wr32(out.v, out.n, 12, (u32)(ob.nsyms + u.added.n));
    dk_vec_free(&ob.strings);
    dk_vec_free(&entries);
    dk_vec_free(&def_order);
    dk_vec_free(&def_names);
    dk_vec_free(&u.added);
    dk_map_free(u.added_at);
    dk_map_free(defined_at);
    dk_imap_free(remap_def);
    dk_imap_free(remap_dir);
    dk_imap_free(twins);
    dk_arena_reset(dk_scratch(), mark);
    return finish(&out);
}

DkStr coff_rename_symbols(DkStr data, const DkMap *mapping) {
    DkArenaMark mark = dk_arena_mark(dk_scratch());
    Obj ob;
    obj_open(&ob, data);
    for (u64 i = 0; i < ob.nsyms;) {
        size_t at = (size_t)((u64)ob.symtab + i * 18);
        DkStr name = obj_name_of(&ob, at);
        DkVal *v = dk_map_get(mapping, name);
        if (v) {
            DkStr encoded = dk_str((const char *)v->p);
            if (encoded.n <= 8) {
                memset(ob.d + at, 0, 8);
                if (encoded.n) memcpy(ob.d + at, encoded.p, encoded.n);
            } else {
                u32 offset = (u32)(4 + ob.strings.n);
                memset(ob.d + at, 0, 4);
                memcpy(ob.d + at + 4, &offset, 4);
                dk_vec_extend(&ob.strings, (const u8 *)encoded.p, encoded.n);
                dk_vec_push(&ob.strings, 0);
            }
        }
        need((DkStr){(const char *)ob.d, ob.n}, at, 18);
        i += 1 + ob.d[at + 17];
    }
    if (ob.strtab > ob.n) PANIC("string table out of range");
    Out out = {0};
    put_bytes(&out, ob.d, ob.strtab);
    put32(&out, (u32)(4 + ob.strings.n));
    put_bytes(&out, ob.strings.v, ob.strings.n);
    dk_vec_free(&ob.strings);
    dk_arena_reset(dk_scratch(), mark);
    return finish(&out);
}
