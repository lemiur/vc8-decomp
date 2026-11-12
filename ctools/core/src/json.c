// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore json: the value tree, its builders and accessors (the reader is json_read.c, the writer json_write.c). */
#include "json_internal.h"
#include "dk/arena.h"
#include <stdlib.h>

const DkJson dk_json__null_node = {.kind = DK_JSON_NULL};
const DkJson dk_json__true_node = {.kind = DK_JSON_BOOL, .b = true};
const DkJson dk_json__false_node = {.kind = DK_JSON_BOOL, .b = false};

DkJson *dk_json_null(void) { return (DkJson *)&dk_json__null_node; }
DkJson *dk_json_bool(bool b) { return (DkJson *)(b ? &dk_json__true_node : &dk_json__false_node); }

static DkJson *new_node(DkArena *a, DkJsonKind kind) {
    DkJson *j = DK_NEW(a, DkJson);
    j->kind = (u8)kind;
    return j;
}

DkJson *dk_json_int(DkArena *a, i64 v) {
    DkJson *j = new_node(a, DK_JSON_INT);
    j->u.i = v;
    return j;
}

static DkJson *big_node(DkArena *a, DkStr digits) {
    DkJson *j = new_node(a, DK_JSON_INT);
    j->big = 1;
    j->u.str = dk_str_dup(a, digits);
    return j;
}

DkJson *dk_json_uint(DkArena *a, u64 v) {
    if (v <= (u64)INT64_MAX) return dk_json_int(a, (i64)v);
    char tmp[24];
    int n = 0;
    while (v) {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    }
    char rev[24];
    for (int i = 0; i < n; i++) rev[i] = tmp[n - 1 - i];
    return big_node(a, dk_strn(rev, (size_t)n));
}

/* Digits of an int as the reader and the builder spell them: "-?(0|[1-9][0-9]*)". Returns true and the value when
 * the number fits an i64 ("-0" is 0). */
bool dk_json__int_fits(DkStr digits, i64 *out) {
    const char *p = digits.p, *end = digits.p + digits.n;
    bool neg = false;
    if (p < end && *p == '-') {
        neg = true;
        p++;
    }
    u64 acc = 0;
    if (end - p > 19) return false; /* 19 digits at most fit a u64 without wrapping */
    for (; p < end; p++) acc = acc * 10 + (u64)(*p - '0');
    if (neg) {
        if (acc > (u64)INT64_MAX + 1u) return false;
        *out = (i64)(0u - acc);
    } else {
        if (acc > (u64)INT64_MAX) return false;
        *out = (i64)acc;
    }
    return true;
}

DkJson *dk_json_int_digits(DkArena *a, DkStr digits) {
    i64 v;
    DK_ASSERT(digits.n > 0);
    if (dk_json__int_fits(digits, &v)) return dk_json_int(a, v);
    return big_node(a, digits);
}

DkJson *dk_json_float(DkArena *a, double v) {
    DkJson *j = new_node(a, DK_JSON_FLOAT);
    j->u.f = v;
    return j;
}

DkJson *dk_json_str_ref(DkArena *a, DkStr s) {
    DkJson *j = new_node(a, DK_JSON_STRING);
    j->u.str = s;
    return j;
}

DkJson *dk_json_str(DkArena *a, DkStr s) { return dk_json_str_ref(a, dk_str_dup(a, s)); }
DkJson *dk_json_strz(DkArena *a, const char *cz) { return dk_json_str(a, dk_str(cz)); }

DkJson *dk_json_arr(DkArena *a) { return new_node(a, DK_JSON_ARRAY); }

DkJson *dk_json_arr_cap(DkArena *a, size_t cap) {
    DkJson *j = new_node(a, DK_JSON_ARRAY);
    if (cap) {
        j->u.arr.v = DK_NEWN(a, DkJson *, cap);
        j->u.arr.cap = cap;
    }
    return j;
}

DkJson *dk_json_obj(DkArena *a) { return new_node(a, DK_JSON_OBJECT); }

void dk_json_arr_push(DkArena *a, DkJson *arr, DkJson *v) {
    DK_ASSERT(arr && arr->kind == DK_JSON_ARRAY);
    if (arr->u.arr.n == arr->u.arr.cap) {
        size_t cap = arr->u.arr.cap ? arr->u.arr.cap * 2 : 4;
        arr->u.arr.v = arr->u.arr.v
                           ? dk_arena_realloc(a, arr->u.arr.v, arr->u.arr.cap * sizeof(DkJson *), cap * sizeof(DkJson *))
                           : DK_NEWN(a, DkJson *, cap);
        arr->u.arr.cap = cap;
    }
    arr->u.arr.v[arr->u.arr.n++] = v ? v : dk_json_null();
}

size_t dk_json_len(const DkJson *v) {
    if (!v) return 0;
    switch (v->kind) {
    case DK_JSON_ARRAY: return v->u.arr.n;
    case DK_JSON_OBJECT: return v->u.obj.n;
    case DK_JSON_STRING: return v->u.str.n;
    default: return 0;
    }
}

DkJson *dk_json_at(const DkJson *arr, size_t i) {
    if (!arr || arr->kind != DK_JSON_ARRAY || i >= arr->u.arr.n) return NULL;
    return arr->u.arr.v[i];
}

/* ---- the member index ---- */
u32 dk_json__hash(DkStr key) {
    const char *p = key.p;
    size_t n = key.n;
    u64 h = 0x9E3779B97F4A7C15ull ^ (u64)n;
    while (n >= 8) {
        u64 w;
        memcpy(&w, p, 8);
        h = (h ^ w) * 0xff51afd7ed558ccdull;
        h ^= h >> 32;
        p += 8;
        n -= 8;
    }
    u64 w = 0;
    if (n) memcpy(&w, p, n);
    h = (h ^ w) * 0xc4ceb9fe1a85ec53ull;
    h ^= h >> 29;
    h *= 0x9E3779B97F4A7C15ull;
    return (u32)(h >> 32);
}

u32 dk_json__index_cap_for(size_t n) {
    u32 cap = 32;
    while ((size_t)cap < n * 4) cap <<= 1;
    return cap;
}

void dk_json__index_put(u32 *tab, u32 cap, u32 hash, u32 member_number) {
    u32 mask = cap - 1, i = hash & mask;
    while (tab[i]) i = (i + 1) & mask;
    tab[i] = member_number + 1;
}

i64 dk_json__find(const DkJsonMember *members, size_t n, const u32 *tab, u32 cap, DkStr key) {
    if (!tab) {
        for (size_t i = 0; i < n; i++)
            if (members[i].key.n == key.n && (key.n == 0 || memcmp(members[i].key.p, key.p, key.n) == 0)) return (i64)i;
        return -1;
    }
    u32 mask = cap - 1, i = dk_json__hash(key) & mask;
    while (tab[i]) {
        const DkJsonMember *m = &members[tab[i] - 1];
        if (m->key.n == key.n && (key.n == 0 || memcmp(m->key.p, key.p, key.n) == 0)) return (i64)(tab[i] - 1);
        i = (i + 1) & mask;
    }
    return -1;
}

static void rebuild_index(DkArena *a, DkJson *o, bool fresh_table) {
    u32 cap = o->u.obj.index_cap;
    if (fresh_table) {
        cap = dk_json__index_cap_for(o->u.obj.n);
        o->u.obj.index = DK_NEWN(a, u32, cap);
        o->u.obj.index_cap = cap;
    } else {
        memset(o->u.obj.index, 0, (size_t)cap * sizeof(u32));
    }
    for (size_t i = 0; i < o->u.obj.n; i++) dk_json__index_put(o->u.obj.index, cap, dk_json__hash(o->u.obj.v[i].key), (u32)i);
}

DkJson *dk_json_get(const DkJson *obj, DkStr key) {
    if (!obj || obj->kind != DK_JSON_OBJECT) return NULL;
    i64 i = dk_json__find(obj->u.obj.v, obj->u.obj.n, obj->u.obj.index, obj->u.obj.index_cap, key);
    return i < 0 ? NULL : obj->u.obj.v[i].val;
}

DkJson *dk_json_getz(const DkJson *obj, const char *key) { return dk_json_get(obj, dk_str(key)); }

DkJson *dk_json_get_or(const DkJson *obj, DkStr key, DkJson *dflt) {
    DkJson *v = dk_json_get(obj, key);
    return v ? v : dflt;
}
bool dk_json_has(const DkJson *obj, DkStr key) { return dk_json_get(obj, key) != NULL; }

DkJson *dk_json_set_ref(DkArena *a, DkJson *obj, DkStr key, DkJson *v) {
    DK_ASSERT(obj && obj->kind == DK_JSON_OBJECT);
    if (!v) v = dk_json_null();
    i64 i = dk_json__find(obj->u.obj.v, obj->u.obj.n, obj->u.obj.index, obj->u.obj.index_cap, key);
    if (i >= 0) {
        DkJson *prev = obj->u.obj.v[i].val;
        obj->u.obj.v[i].val = v;
        return prev;
    }
    if (obj->u.obj.n == obj->u.obj.cap) {
        size_t cap = obj->u.obj.cap ? obj->u.obj.cap * 2 : 4;
        obj->u.obj.v = obj->u.obj.v ? dk_arena_realloc(a, obj->u.obj.v, obj->u.obj.cap * sizeof(DkJsonMember),
                                                         cap * sizeof(DkJsonMember))
                                    : DK_NEWN(a, DkJsonMember, cap);
        obj->u.obj.cap = cap;
    }
    size_t n = obj->u.obj.n++;
    obj->u.obj.v[n].key = key;
    obj->u.obj.v[n].val = v;
    if (obj->u.obj.index) {
        if ((size_t)obj->u.obj.index_cap < obj->u.obj.n * 2) rebuild_index(a, obj, true);
        else dk_json__index_put(obj->u.obj.index, obj->u.obj.index_cap, dk_json__hash(key), (u32)n);
    } else if (obj->u.obj.n > DK_JSON_LINEAR_MAX) {
        rebuild_index(a, obj, true);
    }
    return NULL;
}

DkJson *dk_json_set(DkArena *a, DkJson *obj, DkStr key, DkJson *v) {
    DK_ASSERT(obj && obj->kind == DK_JSON_OBJECT);
    /* copy the key only when it is new, so replacing a value does not grow the arena */
    i64 i = dk_json__find(obj->u.obj.v, obj->u.obj.n, obj->u.obj.index, obj->u.obj.index_cap, key);
    if (i >= 0) return dk_json_set_ref(a, obj, obj->u.obj.v[i].key, v);
    return dk_json_set_ref(a, obj, dk_str_dup(a, key), v);
}

bool dk_json_del(DkJson *obj, DkStr key) {
    if (!obj || obj->kind != DK_JSON_OBJECT) return false;
    i64 i = dk_json__find(obj->u.obj.v, obj->u.obj.n, obj->u.obj.index, obj->u.obj.index_cap, key);
    if (i < 0) return false;
    memmove(&obj->u.obj.v[i], &obj->u.obj.v[i + 1], (obj->u.obj.n - (size_t)i - 1) * sizeof(DkJsonMember));
    obj->u.obj.n--;
    if (obj->u.obj.index) {
        memset(obj->u.obj.index, 0, (size_t)obj->u.obj.index_cap * sizeof(u32));
        for (size_t k = 0; k < obj->u.obj.n; k++)
            dk_json__index_put(obj->u.obj.index, obj->u.obj.index_cap, dk_json__hash(obj->u.obj.v[k].key), (u32)k);
    }
    return true;
}

const DkJsonMember *dk_json_member(const DkJson *obj, size_t i) {
    if (!obj || obj->kind != DK_JSON_OBJECT || i >= obj->u.obj.n) return NULL;
    return &obj->u.obj.v[i];
}

/* ---- accessors ---- */
bool dk_json_is_null(const DkJson *v) { return !v || v->kind == DK_JSON_NULL; }
bool dk_json_is_str(const DkJson *v) { return v && v->kind == DK_JSON_STRING; }
bool dk_json_is_arr(const DkJson *v) { return v && v->kind == DK_JSON_ARRAY; }
bool dk_json_is_obj(const DkJson *v) { return v && v->kind == DK_JSON_OBJECT; }
bool dk_json_is_int(const DkJson *v) { return v && v->kind == DK_JSON_INT; }
bool dk_json_is_num(const DkJson *v) { return v && (v->kind == DK_JSON_INT || v->kind == DK_JSON_FLOAT); }

i64 dk_json_i64(const DkJson *v, i64 fallback) {
    if (!v || v->kind != DK_JSON_INT || v->big) return fallback;
    return v->u.i;
}

double dk_json_f64(const DkJson *v, double fallback) {
    if (!v) return fallback;
    if (v->kind == DK_JSON_FLOAT) return v->u.f;
    if (v->kind == DK_JSON_INT) {
        if (!v->big) return (double)v->u.i;
        DkArena *sc = dk_scratch();
        DkArenaMark mark = dk_arena_mark(sc);
        double d = strtod(dk_cz(sc, v->u.str), NULL); /* float(int) is correctly rounded; a huge int is an OverflowError in Python */
        dk_arena_reset(sc, mark);
        return (d - d == 0.0) ? d : fallback;
    }
    return fallback;
}

bool dk_json_bool_or(const DkJson *v, bool fallback) { return (v && v->kind == DK_JSON_BOOL) ? v->b : fallback; }

DkStr dk_json_str_or(const DkJson *v, DkStr fallback) { return (v && v->kind == DK_JSON_STRING) ? v->u.str : fallback; }

i64 dk_json_get_i64(const DkJson *obj, const char *key, i64 fallback) { return dk_json_i64(dk_json_getz(obj, key), fallback); }
double dk_json_get_f64(const DkJson *obj, const char *key, double fallback) { return dk_json_f64(dk_json_getz(obj, key), fallback); }
bool dk_json_get_bool(const DkJson *obj, const char *key, bool fallback) { return dk_json_bool_or(dk_json_getz(obj, key), fallback); }
DkStr dk_json_get_str(const DkJson *obj, const char *key, DkStr fallback) { return dk_json_str_or(dk_json_getz(obj, key), fallback); }

bool dk_json_truthy(const DkJson *v) {
    if (!v) return false;
    switch (v->kind) {
    case DK_JSON_NULL: return false;
    case DK_JSON_BOOL: return v->b;
    case DK_JSON_INT: return v->big || v->u.i != 0;
    case DK_JSON_FLOAT: return v->u.f != 0.0;
    case DK_JSON_STRING: return v->u.str.n != 0;
    case DK_JSON_ARRAY: return v->u.arr.n != 0;
    default: return v->u.obj.n != 0;
    }
}

DkStr dk_json_error_str(DkArena *a, const DkJsonError *err) {
    if (err->kind != DK_JSON_E_DECODE) return dk_str_dup(a, err->msg);
    char *t = dk_sprintf(a, "%.*s: line %lld column %lld (char %lld)", DK_SF(err->msg), (long long)err->lineno,
                          (long long)err->colno, (long long)err->pos);
    return dk_str(t);
}

size_t dk_json__put_cp(char out[4], u32 cp) {
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}
