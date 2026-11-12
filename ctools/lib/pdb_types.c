// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The TPI stream of a PDB: it names the types ("unsigned int", "Foo*", "ret (__thiscall Foo::)(args)"), sizes them,
 * and describes the named classes, structs, unions and enums with their members, bases, methods and enumerators.
 *
 * Naming and sizing tolerate a record that does not parse ("<err 0x..>", size 0); the construction and the member
 * lists let the malformed-record exception rise (pdb_fail). The memo tables are keyed by type index. */
#include "pdb_internal.h"

#define LF_POINTER 0x1002u
#define LF_MODIFIER 0x1001u
#define LF_ARRAY 0x1503u
#define LF_BITFIELD 0x1205u
#define LF_PROCEDURE 0x1008u
#define LF_MFUNCTION 0x1009u
#define LF_ARGLIST 0x1201u
#define LF_FIELDLIST 0x1203u
#define LF_METHODLIST 0x1206u

typedef struct {
    u16 leaf;
    DkStr body;
} Rec;

typedef struct {
    u32 ti;
    const char *uname, *name, *kind;
    i64 size;
    u32 utype, prop, fl, count;
    bool fwd;
} Named;

struct DkPdbTypes {
    u32 begin, end;
    Rec *recs;
    size_t nrecs;
    DkIMap *name_memo, *size_memo, *named_memo;
    DkISet *busy;
    DkMap *definition; /* key (unique name, else name) -> TI of the first definition (.i) */
};

static bool is_class_leaf(u32 leaf) { return (leaf >= 0x1504 && leaf <= 0x1507) || (leaf >= 0x1004 && leaf <= 0x1007); }

static Rec *rec_get(const DkPdbTypes *t, u32 ti) {
    if (ti < t->begin || (u64)(ti - t->begin) >= t->nrecs) return NULL;
    return &t->recs[ti - t->begin];
}

u32 dk_pdb_types_first(const DkPdbTypes *t) { return t->begin; }
u32 dk_pdb_types_end(const DkPdbTypes *t) { return t->begin + (u32)t->nrecs; }

u32 dk_pdb_types_leaf(const DkPdbTypes *t, u32 ti) {
    const Rec *r = rec_get(t, ti);
    return r ? r->leaf : 0;
}

static const char *base_name(u32 key) {
    switch (key) {
    case 0x00: return "notype";
    case 0x03: return "void";
    case 0x08: return "HRESULT";
    case 0x10: return "char";
    case 0x11: return "short";
    case 0x12: return "long";
    case 0x13: return "__int64";
    case 0x20: return "unsigned char";
    case 0x21: return "unsigned short";
    case 0x22: return "unsigned long";
    case 0x23: return "unsigned __int64";
    case 0x30: return "bool";
    case 0x31: return "bool16";
    case 0x32: return "bool32";
    case 0x33: return "bool64";
    case 0x40: return "float";
    case 0x41: return "double";
    case 0x42: return "long double";
    case 0x68: return "signed char";
    case 0x69: return "unsigned char";
    case 0x70: return "char";
    case 0x71: return "wchar_t";
    case 0x72: return "short";
    case 0x73: return "unsigned short";
    case 0x74: return "int";
    case 0x75: return "unsigned int";
    case 0x76: return "__int64";
    case 0x77: return "unsigned __int64";
    case 0x78: return "__int128";
    case 0x79: return "unsigned __int128";
    default: return NULL;
    }
}

static i64 base_size(u32 key) {
    switch (key) {
    case 0x08: case 0x12: case 0x22: case 0x32: case 0x40: case 0x74: case 0x75: return 4;
    case 0x10: case 0x20: case 0x30: case 0x68: case 0x69: case 0x70: return 1;
    case 0x11: case 0x21: case 0x31: case 0x71: case 0x72: case 0x73: return 2;
    case 0x13: case 0x23: case 0x33: case 0x41: case 0x76: case 0x77: return 8;
    case 0x42: return 10;
    case 0x78: case 0x79: return 16;
    default: return 0; /* void is 0 as well */
    }
}

static const char *callconv(DkArena *a, u32 cc) {
    switch (cc) {
    case 0: return "__cdecl";
    case 1: return "__pascal";
    case 2: return "__fastcall";
    case 4: case 5: return "__stdcall";
    case 7: return "__thiscall";
    case 0x0B: return "__clrcall";
    default: return dk_sprintf(a, "cc%u", cc);
    }
}

static const char *method_prop(DkArena *a, u32 p) {
    static const char *const names[] = {"vanilla", "virtual", "static", "friend", "intro", "pure", "pure_intro"};
    return p < 7 ? names[p] : dk_sprintf(a, "%u", p);
}

/* ---- class, struct, union and enum records --------------------------------------------------------------------- */

static Named *named(DkPdbTypes *t, u32 ti) {
    DkVal *hit = dk_imap_get(t->named_memo, ti);
    if (hit) return hit->p;
    Rec *rec = rec_get(t, ti);
    if (!rec) pdb_fail("missing type record");
    DkArena *a = dk_arena();
    u32 leaf = rec->leaf;
    DkStr b = rec->body;
    bool st = leaf >= 0x1004 && leaf <= 0x1007; /* the Pascal-string forms */
    Named *d = DK_NEW(a, Named);
    d->ti = ti;
    d->uname = "";
    i64 p;
    if (leaf == 0x1504 || leaf == 0x1505 || leaf == 0x1004 || leaf == 0x1005) {
        d->count = pdb_le16(b, 0);
        d->prop = pdb_le16(b, 2);
        d->fl = pdb_le32(b, 4);
        d->size = pdb_numeric(b, 16, &p);
        d->kind = (leaf == 0x1504 || leaf == 0x1004) ? "class" : "struct";
    } else if (leaf == 0x1506 || leaf == 0x1006) {
        d->count = pdb_le16(b, 0);
        d->prop = pdb_le16(b, 2);
        d->fl = pdb_le32(b, 4);
        d->size = pdb_numeric(b, 8, &p);
        d->kind = "union";
    } else {
        d->count = pdb_le16(b, 0);
        d->prop = pdb_le16(b, 2);
        d->utype = pdb_le32(b, 4);
        d->fl = pdb_le32(b, 8);
        p = 12;
        d->kind = "enum";
    }
    d->name = st ? pdb_pstr(b, p, &p) : pdb_cstr(b, p, &p);
    if ((d->prop & 0x200) && !st) d->uname = pdb_cstr(b, p, &p); /* has a unique name */
    d->fwd = (d->prop & 0x80) != 0;
    dk_imap_put(t->named_memo, ti, NULL)->p = d;
    return d;
}

static const char *key_of(const Named *d) { return d->uname[0] ? d->uname : d->name; }

/* A forward reference's definition (the type index itself otherwise). */
static u32 resolve(DkPdbTypes *t, u32 ti) {
    Rec *rec = rec_get(t, ti);
    if (rec && is_class_leaf(rec->leaf)) {
        Named *d = named(t, ti);
        if (d->fwd) {
            DkVal *v = dk_map_get(t->definition, dk_str(key_of(d)));
            return v ? (u32)v->i : ti;
        }
    }
    return ti;
}

/* ---- names ----------------------------------------------------------------------------------------------------- */

static const char *args_text(DkPdbTypes *t, u32 al) {
    Rec *rec = rec_get(t, al);
    if (!rec || rec->leaf != LF_ARGLIST) return "";
    DkStr b = rec->body;
    u32 count = pdb_le32(b, 0);
    pdb_at(b, 4, (size_t)count * 4);
    DkBuf out;
    dk_buf_init(&out, dk_arena());
    for (u32 i = 0; i < count; i++) {
        if (i) dk_buf_putz(&out, ", ");
        dk_buf_putz(&out, dk_pdb_types_name(t, pdb_le32(b, 4 + 4 * (i64)i)));
    }
    return dk_buf_cz(&out);
}

static const char *type_name(DkPdbTypes *t, u32 ti) {
    DkArena *a = dk_arena();
    Rec *rec = rec_get(t, ti);
    if (!rec) return dk_sprintf(a, "<missing 0x%X>", ti);
    DkStr b = rec->body;
    switch (rec->leaf) {
    case LF_POINTER: {
        u32 tt = pdb_le32(b, 0), attr = pdb_le32(b, 4);
        u32 mode = (attr >> 5) & 7; /* 0 pointer, 1 reference, 2/3 pointer to member, 4 rvalue reference */
        const char *s = dk_pdb_types_name(t, tt);
        const char *r;
        if (mode == 2 || mode == 3) {
            const char *cl = dk_pdb_types_name(t, pdb_le32(b, 8));
            r = dk_sprintf(a, "%s %s::*", s, cl);
        } else {
            r = dk_sprintf(a, "%s%s", s, mode == 1 ? "&" : mode == 4 ? "&&" : "*");
        }
        if (attr & 0x400) r = dk_sprintf(a, "%s const", r);
        if (attr & 0x200) r = dk_sprintf(a, "%s volatile", r);
        return r;
    }
    case LF_MODIFIER: {
        u32 tt = pdb_le32(b, 0), m = pdb_le16(b, 4);
        return dk_sprintf(a, "%s%s%s%s", (m & 1) ? "const " : "", (m & 2) ? "volatile " : "",
                          (m & 4) ? "__unaligned " : "", dk_pdb_types_name(t, tt));
    }
    case LF_ARRAY: {
        u32 et = pdb_le32(b, 0);
        i64 next;
        i64 size = pdb_numeric(b, 8, &next);
        i64 es = dk_pdb_types_size(t, et);
        const char *n = dk_pdb_types_name(t, et);
        if (es) return dk_sprintf(a, "%s[%lld]", n, (long long)(size / es));
        return dk_sprintf(a, "%s[%lldB]", n, (long long)size);
    }
    case LF_BITFIELD: {
        u32 tt = pdb_le32(b, 0);
        u32 ln = pdb_u8(b, 4);
        pdb_u8(b, 5);
        return dk_sprintf(a, "%s:%u", dk_pdb_types_name(t, tt), ln);
    }
    case LF_PROCEDURE: {
        u32 rt = pdb_le32(b, 0), cc = pdb_u8(b, 4), al = pdb_le32(b, 8);
        pdb_u8(b, 5);
        pdb_le16(b, 6);
        const char *rn = dk_pdb_types_name(t, rt);
        return dk_sprintf(a, "%s (%s)(%s)", rn, callconv(a, cc), args_text(t, al));
    }
    case LF_MFUNCTION: {
        u32 rt = pdb_le32(b, 0), ct = pdb_le32(b, 4), cc = pdb_u8(b, 12), al = pdb_le32(b, 16);
        pdb_le32(b, 8);
        pdb_u8(b, 13);
        pdb_le16(b, 14);
        const char *rn = dk_pdb_types_name(t, rt);
        const char *cn = dk_pdb_types_name(t, ct);
        return dk_sprintf(a, "%s (%s %s::)(%s)", rn, callconv(a, cc), cn, args_text(t, al));
    }
    case LF_ARGLIST:
        return dk_sprintf(a, "(%s)", args_text(t, ti));
    default:
        if (is_class_leaf(rec->leaf)) return named(t, ti)->name;
        return dk_sprintf(a, "<leaf 0x%X>", (unsigned)rec->leaf);
    }
}

const char *dk_pdb_types_name(DkPdbTypes *t, u32 ti) {
    DkVal *hit = dk_imap_get(t->name_memo, ti);
    if (hit) return hit->p;
    DkArena *a = dk_arena();
    const char *r;
    if (ti < 0x1000) { /* a built-in type: the low byte is the kind, the next nibble the pointer mode */
        const char *bn = base_name(ti & 0xFF);
        r = dk_sprintf(a, "%s%s", bn ? bn : dk_sprintf(a, "T_%02X", ti & 0xFF), ((ti >> 8) & 0xF) ? "*" : "");
    } else if (dk_iset_has(t->busy, ti)) {
        return "..."; /* a type that contains itself */
    } else {
        dk_iset_add(t->busy, ti);
        const char *volatile res = NULL;
        DkTry tr;
        if (DK_TRY(&tr)) {
            res = type_name(t, ti);
            dk_try_end(&tr);
        } else {
            res = dk_sprintf(a, "<err 0x%X>", ti);
        }
        r = res;
        dk_iset_del(t->busy, ti);
    }
    dk_imap_put(t->name_memo, ti, NULL)->p = (void *)r;
    return r;
}

const char *dk_pdb_types_method_class(DkPdbTypes *t, u32 ti) {
    Rec *rec = rec_get(t, ti);
    if (rec && rec->leaf == LF_MFUNCTION) return dk_pdb_types_name(t, pdb_le32(rec->body, 4));
    return "";
}

/* ---- sizes ----------------------------------------------------------------------------------------------------- */

static i64 type_size(DkPdbTypes *t, u32 ti) {
    Rec *rec = rec_get(t, ti);
    if (!rec) return 0;
    DkStr b = rec->body;
    i64 next;
    switch (rec->leaf) {
    case LF_POINTER: {
        u32 v = (pdb_le32(b, 4) >> 13) & 0x3F; /* the size field of the attributes */
        return v ? v : 4;
    }
    case LF_MODIFIER: case LF_BITFIELD:
        return dk_pdb_types_size(t, pdb_le32(b, 0));
    case LF_ARRAY:
        return pdb_numeric(b, 8, &next);
    default:
        if (is_class_leaf(rec->leaf)) {
            Named *d = named(t, resolve(t, ti));
            return strcmp(d->kind, "enum") == 0 ? dk_pdb_types_size(t, d->utype) : d->size;
        }
        return 0;
    }
}

i64 dk_pdb_types_size(DkPdbTypes *t, u32 ti) {
    DkVal *hit = dk_imap_get(t->size_memo, ti);
    if (hit) return hit->i;
    i64 r = 0;
    if (ti < 0x1000) {
        u32 mode = (ti >> 8) & 0xF;
        r = mode ? (mode < 6 ? 4 : 8) : base_size(ti & 0xFF);
    } else {
        volatile i64 res = 0;
        DkTry tr;
        if (DK_TRY(&tr)) {
            res = type_size(t, ti);
            dk_try_end(&tr);
        } else {
            res = 0;
        }
        r = res;
    }
    dk_imap_put(t->size_memo, ti, NULL)->i = r;
    return r;
}

/* ---- construction ---------------------------------------------------------------------------------------------- */

DkPdbTypes *dk_pdb_types_new(DkStr tpi) {
    DkArena *a = dk_arena();
    DkPdbTypes *t = DK_NEW(a, DkPdbTypes);
    t->name_memo = dk_imap_new();
    t->size_memo = dk_imap_new();
    t->named_memo = dk_imap_new();
    t->busy = dk_iset_new();
    t->definition = dk_map_new();
    if (tpi.n == 0) { /* no TPI stream: no types */
        t->begin = 0x1000;
        return t;
    }
    u32 hs = pdb_le32(tpi, 4);
    t->begin = pdb_le32(tpi, 8);
    t->end = pdb_le32(tpi, 12);
    u32 rb = pdb_le32(tpi, 16);
    typedef DK_VEC(Rec) RecVec;
    RecVec recs = {0};
    i64 p = hs, stop = (i64)hs + rb;
    u32 ti = t->begin;
    while (p + 4 <= stop && ti < t->end) {
        u32 ln = pdb_le16(tpi, p), leaf = pdb_le16(tpi, p + 2);
        Rec r = {(u16)leaf, dk_str_slice(tpi, p + 4, p + 2 + (i64)ln)};
        dk_vec_push(&recs, r);
        p += 2 + (i64)ln;
        ti++;
    }
    t->recs = recs.v;
    t->nrecs = recs.n;
    for (size_t i = 0; i < t->nrecs; i++) { /* the first definition of each class name, for forward references */
        if (!is_class_leaf(t->recs[i].leaf)) continue;
        Named *d = named(t, t->begin + (u32)i);
        if (!d->fwd) {
            bool created;
            DkVal *v = dk_map_put(t->definition, dk_str(key_of(d)), &created);
            if (created) v->i = d->ti;
        }
    }
    return t;
}

/* ---- members --------------------------------------------------------------------------------------------------- */

static void add_field(DkPdbTypes *t, DkPdbTypeInfo *out, const char *nm, i64 off, u32 ty) {
    DkPdbField f = {0};
    Rec *rec = rec_get(t, ty);
    f.name = nm;
    f.offset = off;
    if (rec && rec->leaf == LF_BITFIELD) {
        u32 base = pdb_le32(rec->body, 0);
        f.size = dk_pdb_types_size(t, base);
        f.type = dk_pdb_types_name(t, base);
        f.bit_len = pdb_u8(rec->body, 4);
        f.bit_pos = pdb_u8(rec->body, 5);
    } else {
        f.size = dk_pdb_types_size(t, resolve(t, ty));
        f.type = dk_pdb_types_name(t, ty);
    }
    dk_vec_push(&out->fields, f);
}

static void add_method(DkPdbTypes *t, DkPdbTypeInfo *out, const char *nm, u32 ty, u32 mprop, bool has_vt, u32 vt) {
    DkPdbMethod m = {nm, dk_pdb_types_name(t, ty), method_prop(dk_arena(), mprop), has_vt, vt};
    dk_vec_push(&out->methods, m);
}

/* Walks a field list; LF_INDEX continues in another list. false at a leaf it does not know. */
static bool fields(DkPdbTypes *t, u32 fl, DkPdbTypeInfo *out, int depth) {
    Rec *rec = rec_get(t, fl);
    if (!rec || rec->leaf != LF_FIELDLIST || depth > 50) return true;
    DkStr b = rec->body;
    i64 p = 0, n = (i64)b.n;
    while (p < n) {
        u8 first = pdb_u8(b, p);
        if (first >= 0xF0) { /* LF_PAD */
            p += first & 0xF;
            continue;
        }
        u32 leaf = pdb_le16(b, p);
        p += 2;
        if (leaf == 0x150D || leaf == 0x1405) { /* LF_MEMBER */
            pdb_le16(b, p);
            u32 ty = pdb_le32(b, p + 2);
            i64 off = pdb_numeric(b, p + 6, &p);
            const char *nm = leaf == 0x150D ? pdb_cstr(b, p, &p) : pdb_pstr(b, p, &p);
            add_field(t, out, nm, off, ty);
        } else if (leaf == 0x150E || leaf == 0x1406) { /* LF_STMEMBER: not part of the layout */
            pdb_le16(b, p);
            if (leaf == 0x150E) pdb_cstr(b, p + 6, &p);
            else pdb_pstr(b, p + 6, &p);
        } else if (leaf == 0x1400) { /* LF_BCLASS */
            pdb_le16(b, p);
            u32 ty = pdb_le32(b, p + 2);
            i64 off = pdb_numeric(b, p + 6, &p);
            DkPdbBase base = {dk_pdb_types_name(t, ty), off, false, false};
            dk_vec_push(&out->bases, base);
        } else if (leaf == 0x1401 || leaf == 0x1402) { /* LF_VBCLASS, LF_IVBCLASS */
            pdb_le16(b, p);
            u32 ty = pdb_le32(b, p + 2);
            pdb_le32(b, p + 6);
            i64 o1 = pdb_numeric(b, p + 10, &p);
            pdb_numeric(b, p, &p);
            DkPdbBase base = {dk_pdb_types_name(t, ty), o1, true, leaf == 0x1402};
            dk_vec_push(&out->bases, base);
        } else if (leaf == 0x1409) { /* LF_VFUNCTAB */
            p += 6;
            out->has_vfptr = true;
        } else if (leaf == 0x1511 || leaf == 0x1411) { /* LF_ONEMETHOD */
            u32 attr = pdb_le16(b, p), ty = pdb_le32(b, p + 2);
            p += 6;
            u32 mprop = (attr >> 2) & 7, vt = 0;
            bool has_vt = false;
            if (mprop == 4 || mprop == 6) { /* introducing virtual */
                vt = pdb_le32(b, p);
                has_vt = true;
                p += 4;
            }
            const char *nm = leaf == 0x1511 ? pdb_cstr(b, p, &p) : pdb_pstr(b, p, &p);
            add_method(t, out, nm, ty, mprop, has_vt, vt);
        } else if (leaf == 0x150F || leaf == 0x1407) { /* LF_METHOD: an overload set */
            pdb_le16(b, p);
            u32 ml = pdb_le32(b, p + 2);
            const char *nm = leaf == 0x150F ? pdb_cstr(b, p + 6, &p) : pdb_pstr(b, p + 6, &p);
            Rec *mrec = rec_get(t, ml);
            if (mrec && mrec->leaf == LF_METHODLIST) {
                DkStr mb = mrec->body;
                i64 q = 0;
                while (q + 8 <= (i64)mb.n) {
                    u32 attr = pdb_le16(mb, q), ty = pdb_le32(mb, q + 4);
                    q += 8;
                    u32 mprop = (attr >> 2) & 7, vt = 0;
                    bool has_vt = false;
                    if (mprop == 4 || mprop == 6) {
                        vt = pdb_le32(mb, q);
                        has_vt = true;
                        q += 4;
                    }
                    add_method(t, out, nm, ty, mprop, has_vt, vt);
                }
            }
        } else if (leaf == 0x1510 || leaf == 0x1403 || leaf == 0x1512) { /* LF_NESTTYPE(EX) */
            if (leaf == 0x1403) pdb_pstr(b, p + 6, &p);
            else pdb_cstr(b, p + 6, &p);
        } else if (leaf == 0x1502 || leaf == 0x0403) { /* LF_ENUMERATE */
            i64 v = pdb_numeric(b, p + 2, &p);
            const char *nm = leaf == 0x1502 ? pdb_cstr(b, p, &p) : pdb_pstr(b, p, &p);
            DkPdbEnumerator e = {nm, v};
            dk_vec_push(&out->enumerators, e);
        } else if (leaf == 0x1404) { /* LF_INDEX */
            u32 ty = pdb_le32(b, p + 2);
            p += 6;
            fields(t, ty, out, depth + 1);
        } else if (leaf == 0x150C) { /* LF_FRIENDCLS */
            pdb_cstr(b, p + 6, &p);
        } else if (leaf == 0x140A) { /* LF_VFUNCOFF */
            p += 6;
        } else {
            return false;
        }
    }
    return true;
}

bool dk_pdb_types_info(DkPdbTypes *t, u32 ti, DkPdbTypeInfo *out) {
    Rec *rec = rec_get(t, ti);
    memset(out, 0, sizeof *out);
    if (!rec || !is_class_leaf(rec->leaf)) return false;
    Named *d = named(t, ti);
    out->ti = ti;
    out->kind = d->kind;
    out->name = d->name;
    out->unique_name = d->uname;
    out->size = d->size;
    out->forward = d->fwd;
    out->underlying = "";
    if (strcmp(d->kind, "enum") == 0) {
        out->underlying = dk_pdb_types_name(t, d->utype);
        out->size = dk_pdb_types_size(t, d->utype);
    }
    if (!d->fwd && d->fl) fields(t, d->fl, out, 0);
    return true;
}
