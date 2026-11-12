// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The project configuration (project.h, "loading and accessors"): config/ctools.json, deep-merged with
 * config/ctools.local.json, checked key by key, its {"$from": "file#/pointer"} references resolved, its ${name}
 * references interpolated, then turned into the model of project.h (targets, units, compiler, backend, annotation
 * grammar, referent files, well-known names, text checks).
 *
 * Order of the work: the vars, in configuration order (a var sees ${root}, ${primary} and the vars before it); then
 * the rest of the tree is copied with every $from replaced and every string interpolated (the use-time built-ins
 * ${target} ${unit} ${out} ${objects} ${roots} are left for dk_project_expand); then the blocks are read: compiler,
 * targets (a target's compiler block is laid over the project's), units (discovered files and the unit maps), the
 * annotation grammar (compiled by dk_annot_config_compile), backend and the rest.
 *
 * Choices where the design is silent: a var may not be named after a built-in; a "${" without its "}" is an error;
 * a units.roots folder that does not exist gives no units (no error); excluded folders and extensions compare
 * case-insensitively; a unit listed by several maps takes, member by member, the last map's value (the global map
 * first, then the targets' in their order); dk_project_json_ref returns the value as the file holds it (no
 * interpolation); a malformed JSON Pointer is an error even when a default is given. */
#include "project.h"

#include "dk/fs.h"
#include "dk/json.h"
#include "dk/map.h"
#include "dk/sort.h"

#include <stdio.h>
#include <string.h>

#define FROM_DEPTH 16

struct DkProject {
    DkArena *a;
    const char *root, *primary, *config_path, *build_dir;
    DkStrVec var_names, var_values;
    DkTarget targets[DK_MAX_TARGETS];
    DkCompiler target_compilers[DK_MAX_TARGETS];
    size_t ntargets;
    DkCompiler compiler;
    DkUnit *units;
    size_t nunits;
    DkStrVec unit_roots;
    DkBackend backend;
    DkAnnotConfig annot;
    DkReferentFile *referents;
    size_t nreferents;
    bool wk_imports;
    DkStrVec wk_symbols, tc_paths, tc_no_bom;
    bool config_path_given;
    DkMap *files; /* the $from cache: absolute path -> parsed document (NULL: the file does not exist) */
};

/* ---- errors ------------------------------------------------------------------------------------------------------ */
void dk_err_set(DkErr *err, int code, DK_PRINTF_FMT const char *fmt, ...) {
    if (!err) return;
    va_list ap;
    va_start(ap, fmt);
    err->code = code;
    vsnprintf(err->msg, sizeof err->msg, fmt, ap);
    va_end(ap);
}

void dk_err_clear(DkErr *err) {
    if (!err) return;
    err->code = 0;
    err->msg[0] = 0;
}

/* The loader's state: the project being filled and where a failure goes. */
typedef struct {
    DkProject *p;
    DkArena *a;
    DkErr *err;
    const char *what; /* prefix of messages: the configuration file */
} Ld;

static bool fail(Ld *L, int code, DK_PRINTF_FMT const char *fmt, ...) {
    char msg[900];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    if (L->what) dk_err_set(L->err, code, "%s: %s", L->what, msg);
    else dk_err_set(L->err, code, "%s", msg);
    return false;
}

/* "base.key" (base NULL or empty: "key"). */
static const char *kp(Ld *L, const char *base, DkStr key) {
    if (!base || !*base) return dk_cz(L->a, key);
    return dk_sprintf(L->a, "%s.%.*s", base, DK_SF(key));
}
static const char *kpz(Ld *L, const char *base, const char *key) { return kp(L, base, dk_str(key)); }

/* ---- paths ------------------------------------------------------------------------------------------------------- */
static void to_slashes(char *s) {
    for (; *s; s++)
        if (*s == '\\') *s = '/';
}

/* s against base (kept when absolute), normalised, forward slashes, no trailing slash. */
static char *abs_against(DkArena *a, const char *base, const char *s) {
    const char *joined = dk_path_isabs(s) ? s : dk_sprintf(a, "%s/%s", base, s);
    char *n = dk_path_normpath(a, joined);
    to_slashes(n);
    size_t len = strlen(n);
    while (len > 3 && n[len - 1] == '/') n[--len] = 0;
    return n;
}

/* A repository-relative path as the model keeps it: forward slashes, no "./" prefix, no trailing slash. */
static char *rel_norm(DkArena *a, const DkProject *p, DkStr s) {
    char *r = dk_cz(a, s);
    to_slashes(r);
    size_t rn = strlen(p->root);
    if (_strnicmp(r, p->root, rn) == 0 && r[rn] == '/') r += rn + 1;
    while (r[0] == '.' && r[1] == '/') r += 2;
    size_t len = strlen(r);
    while (len > 1 && r[len - 1] == '/') r[--len] = 0;
    return r;
}

char *dk_project_path(DkArena *a, const DkProject *p, const char *rel) { return abs_against(a, p->root, rel); }

/* The main checkout of a git worktree: root/.git is a file "gitdir: X"; X/commondir names the common .git folder
 * (relative to X), whose parent is the main checkout. Anything else: the root. */
static const char *find_primary(DkArena *a, const char *root) {
    const char *git = dk_sprintf(a, "%s/.git", root);
    DkBytes raw = {0};
    if (!dk_isfile(git) || !dk_read_all(a, git, &raw)) return root;
    DkStr text = dk_str_strip(dk_strn((const char *)raw.v, raw.n));
    if (text.n >= 3 && (u8)text.p[0] == 0xEF && (u8)text.p[1] == 0xBB && (u8)text.p[2] == 0xBF)
        text = dk_str_strip(dk_str_slice(text, 3, DK_END));
    if (!dk_str_startswith(text, DK_S("gitdir:"))) return root;
    DkStr first, rest;
    dk_str_partition(dk_str_strip(dk_str_slice(text, 7, DK_END)), DK_S("\n"), &first, &rest);
    char *gitdir = abs_against(a, root, dk_cz(a, dk_str_strip(first)));
    const char *cdfile = dk_sprintf(a, "%s/commondir", gitdir);
    DkBytes cd = {0};
    if (!dk_isfile(cdfile) || !dk_read_all(a, cdfile, &cd)) return root;
    DkStr cdtext = dk_str_strip(dk_strn((const char *)cd.v, cd.n));
    dk_str_partition(cdtext, DK_S("\n"), &first, &rest);
    char *common = abs_against(a, gitdir, dk_cz(a, dk_str_strip(first)));
    char *slash = strrchr(common, '/');
    if (!slash) return root;
    if (slash - common == 2 && common[1] == ':') slash[1] = 0; /* "C:/" */
    else *slash = 0;
    return common;
}

/* ---- ${name} ------------------------------------------------------------------------------------------------------ */
static const char *const USE_TIME[] = {"target", "unit", "out", "objects", "roots"};

static int use_time_index(DkStr name) {
    for (int i = 0; i < (int)DK_ARRAY_LEN(USE_TIME); i++)
        if (dk_str_eqz(name, USE_TIME[i])) return i;
    return -1;
}

static const char *use_time_value(const DkExpandVars *v, int i) {
    if (!v) return NULL;
    switch (i) {
    case 0: return v->target;
    case 1: return v->unit;
    case 2: return v->out;
    case 3: return v->objects;
    default: return v->roots;
    }
}

static const char *lookup_var(const DkProject *p, DkStr name) {
    if (dk_str_eqz(name, "root")) return p->root;
    if (dk_str_eqz(name, "primary")) return p->primary;
    for (size_t i = 0; i < p->var_names.n; i++)
        if (dk_str_eq(p->var_names.v[i], name)) return p->var_values.v[i].p;
    return NULL;
}

/* Expands every ${name} of s: the vars, ${root}, ${primary}, and the use-time built-ins given in use (NULL, or a NULL
 * member: left in place). false with *bad = the unknown name, or the unterminated "${..." text. */
static bool expand(DkArena *a, const DkProject *p, DkStr s, const DkExpandVars *use, DkStr *out, DkStr *bad) {
    if (dk_str_find(s, DK_S("${"), 0, DK_END) < 0) {
        *out = dk_str_dup(a, s);
        return true;
    }
    DkBuf b;
    dk_buf_init(&b, a);
    size_t i = 0;
    while (i < s.n) {
        if (s.p[i] == '$' && i + 1 < s.n && s.p[i + 1] == '{') {
            size_t j = i + 2;
            while (j < s.n && s.p[j] != '}') j++;
            if (j >= s.n) {
                *bad = dk_str_slice(s, (i64)i, DK_END);
                return false;
            }
            DkStr name = dk_strn(s.p + i + 2, j - i - 2);
            const char *val = lookup_var(p, name);
            if (!val) {
                int u = use_time_index(name);
                if (u < 0) {
                    *bad = name;
                    return false;
                }
                val = use_time_value(use, u);
                if (!val) {
                    dk_buf_putn(&b, s.p + i, j + 1 - i);
                    i = j + 1;
                    continue;
                }
            }
            dk_buf_putz(&b, val);
            i = j + 1;
            continue;
        }
        dk_buf_putc(&b, s.p[i]);
        i++;
    }
    dk_buf_putz(&b, ""); /* NUL-terminated even when empty */
    *out = dk_buf_str(&b);
    return true;
}

static bool expand_ld(Ld *L, DkStr s, const char *kpath, DkStr *out) {
    DkStr bad;
    if (expand(L->a, L->p, s, NULL, out, &bad)) return true;
    if (dk_str_startswith(bad, DK_S("${")))
        return fail(L, DK_ERR_FORMAT, "%s: unterminated \"%.*s\"", kpath, DK_SF(bad));
    return fail(L, DK_ERR_FORMAT, "%s: unknown variable ${%.*s}", kpath, DK_SF(bad));
}

char *dk_project_expand(DkArena *a, const DkProject *p, const char *s, const DkExpandVars *v, DkErr *err) {
    DkStr out, bad;
    if (expand(a, p, dk_str(s), v, &out, &bad)) return (char *)out.p;
    if (dk_str_startswith(bad, DK_S("${"))) dk_err_set(err, DK_ERR_FORMAT, "unterminated \"%.*s\" in %s", DK_SF(bad), s);
    else dk_err_set(err, DK_ERR_FORMAT, "unknown variable ${%.*s} in %s", DK_SF(bad), s);
    return NULL;
}

/* ---- JSON files and $from ---------------------------------------------------------------------------------------- */
/* Reads a JSON document (UTF-8, a BOM tolerated). NULL with *missing when the file does not exist; NULL with an error
 * when it cannot be read or parsed. */
static DkJson *read_json(Ld *L, const char *path, bool *missing) {
    *missing = false;
    if (!dk_isfile(path)) {
        *missing = true;
        return NULL;
    }
    DkBytes raw = {0};
    if (!dk_read_all(L->a, path, &raw)) {
        fail(L, DK_ERR_IO, "%s: %s", path, dk_cz(L->a, dk_io_err_str(L->a)));
        return NULL;
    }
    DkJsonError je = {0};
    DkJson *doc = dk_json_parse_ex(L->a, dk_strn((const char *)raw.v, raw.n), DK_JSON_STRIP_BOM, &je);
    if (!doc) {
        DkStr m = dk_json_error_str(L->a, &je);
        if (L->what && strcmp(L->what, path) == 0) fail(L, DK_ERR_FORMAT, "%.*s", DK_SF(m));
        else fail(L, DK_ERR_FORMAT, "%s: %.*s", path, DK_SF(m));
        return NULL;
    }
    return doc;
}

/* The cached document of a $from file (absolute path). */
static DkJson *cached_json(Ld *L, const char *path, bool *missing) {
    bool created = false;
    DkVal *slot = dk_map_put(L->p->files, dk_str(path), &created);
    if (!created) {
        *missing = slot->p == NULL;
        return (DkJson *)slot->p;
    }
    DkJson *doc = read_json(L, path, missing);
    if (!doc && !*missing) {
        dk_map_del(L->p->files, dk_str(path));
        return NULL;
    }
    slot = dk_map_get(L->p->files, dk_str(path));
    slot->p = doc;
    return doc;
}

/* RFC 6901: the value ptr names in doc. NULL when absent; *bad when the pointer is malformed. */
static DkJson *json_pointer(DkArena *a, DkJson *doc, DkStr ptr, bool *bad) {
    *bad = false;
    if (!ptr.n) return doc;
    if (ptr.p[0] != '/') {
        *bad = true;
        return NULL;
    }
    DkJson *cur = doc;
    size_t i = 1;
    for (;;) {
        size_t j = i;
        while (j < ptr.n && ptr.p[j] != '/') j++;
        DkBuf tok;
        dk_buf_init(&tok, a);
        dk_buf_putz(&tok, "");
        for (size_t k = i; k < j; k++) {
            if (ptr.p[k] == '~') {
                if (k + 1 < j && ptr.p[k + 1] == '0') dk_buf_putc(&tok, '~');
                else if (k + 1 < j && ptr.p[k + 1] == '1') dk_buf_putc(&tok, '/');
                else {
                    *bad = true;
                    return NULL;
                }
                k++;
            } else {
                dk_buf_putc(&tok, ptr.p[k]);
            }
        }
        DkStr t = dk_buf_str(&tok);
        if (dk_json_is_obj(cur)) {
            cur = dk_json_get(cur, t);
        } else if (dk_json_is_arr(cur)) {
            if (!t.n || (t.n > 1 && t.p[0] == '0')) return NULL;
            u64 idx = 0;
            for (size_t k = 0; k < t.n; k++) {
                if (t.p[k] < '0' || t.p[k] > '9' || idx > 100000000) return NULL;
                idx = idx * 10 + (u64)(t.p[k] - '0');
            }
            cur = dk_json_at(cur, (size_t)idx);
        } else {
            return NULL;
        }
        if (!cur) return NULL;
        if (j >= ptr.n) return cur;
        i = j + 1;
    }
}

static bool is_from(const DkJson *v) { return dk_json_is_obj(v) && dk_json_getz(v, "$from") != NULL; }

/* The value of "file#/pointer": the file relative to the root, the pointer RFC 6901 (absent: the whole document).
 * *found false (no error) when the file or the pointer is missing; *what then says which. */
static bool lookup_ref(Ld *L, DkStr ref, const char *kpath, DkJson **out, bool *found, const char **what) {
    DkStr file, ptr;
    dk_str_partition(ref, DK_S("#"), &file, &ptr);
    *out = NULL;
    *found = false;
    if (!file.n) return fail(L, DK_ERR_FORMAT, "%s: $from \"%.*s\" names no file", kpath, DK_SF(ref));
    char *path = abs_against(L->a, L->p->root, dk_cz(L->a, file));
    bool missing = false;
    DkJson *doc = cached_json(L, path, &missing);
    if (!doc) {
        if (!missing) return false;
        *what = dk_sprintf(L->a, "no file %.*s", DK_SF(file));
        return true;
    }
    bool bad = false;
    DkJson *v = json_pointer(L->a, doc, ptr, &bad);
    if (bad) return fail(L, DK_ERR_FORMAT, "%s: $from \"%.*s\": malformed JSON pointer \"%.*s\"", kpath, DK_SF(ref), DK_SF(ptr));
    if (!v) {
        *what = dk_sprintf(L->a, "%.*s has no %.*s", DK_SF(file), DK_SF(ptr));
        return true;
    }
    *out = v;
    *found = true;
    return true;
}

static bool walk(Ld *L, DkJson *v, const char *kpath, int depth, DkJson **out);

/* Replaces a {"$from": ref, "default": v} object by the value it names, walked. */
static bool resolve_from(Ld *L, DkJson *obj, const char *kpath, int depth, DkJson **out) {
    for (size_t i = 0; i < dk_json_len(obj); i++) {
        const DkJsonMember *m = dk_json_member(obj, i);
        if (!dk_str_eqz(m->key, "$from") && !dk_str_eqz(m->key, "default"))
            return fail(L, DK_ERR_FORMAT, "%s: unknown key", kp(L, kpath, m->key));
    }
    DkJson *ref = dk_json_getz(obj, "$from");
    if (!dk_json_is_str(ref)) return fail(L, DK_ERR_FORMAT, "%s: not a string", kpz(L, kpath, "$from"));
    if (depth >= FROM_DEPTH)
        return fail(L, DK_ERR_FORMAT, "%s: $from references nested deeper than %d (a cycle?)", kpath, FROM_DEPTH);
    DkStr r;
    if (!expand_ld(L, ref->u.str, kpz(L, kpath, "$from"), &r)) return false;
    DkJson *val;
    bool found;
    const char *what = NULL;
    if (!lookup_ref(L, r, kpath, &val, &found, &what)) return false;
    if (!found) {
        DkJson *dflt = dk_json_getz(obj, "default");
        if (dflt) return walk(L, dflt, kpath, depth + 1, out);
        return fail(L, what && strncmp(what, "no file", 7) == 0 ? DK_ERR_IO : DK_ERR_FORMAT,
                    "%s: $from \"%.*s\": %s", kpath, DK_SF(r), what);
    }
    return walk(L, val, kpath, depth + 1, out);
}

/* A copy of v with every $from replaced (an array element that resolves to an array is spliced) and every string
 * interpolated. Scalars other than strings are shared. */
static bool walk(Ld *L, DkJson *v, const char *kpath, int depth, DkJson **out) {
    switch (v->kind) {
    case DK_JSON_STRING: {
        DkStr s;
        if (!expand_ld(L, v->u.str, kpath, &s)) return false;
        *out = dk_json_str_ref(L->a, s);
        return true;
    }
    case DK_JSON_ARRAY: {
        DkJson *arr = dk_json_arr_cap(L->a, dk_json_len(v));
        for (size_t i = 0; i < dk_json_len(v); i++) {
            DkJson *item = dk_json_at(v, i), *r;
            const char *ip = dk_sprintf(L->a, "%s[%zu]", kpath, i);
            if (is_from(item)) {
                if (!resolve_from(L, item, ip, depth, &r)) return false;
                if (dk_json_is_arr(r)) {
                    for (size_t k = 0; k < dk_json_len(r); k++) dk_json_arr_push(L->a, arr, dk_json_at(r, k));
                    continue;
                }
            } else if (!walk(L, item, ip, depth, &r)) {
                return false;
            }
            dk_json_arr_push(L->a, arr, r);
        }
        *out = arr;
        return true;
    }
    case DK_JSON_OBJECT: {
        if (is_from(v)) return resolve_from(L, v, kpath, depth, out);
        DkJson *obj = dk_json_obj(L->a);
        for (size_t i = 0; i < dk_json_len(v); i++) {
            const DkJsonMember *m = dk_json_member(v, i);
            DkJson *r;
            if (!walk(L, m->val, kp(L, kpath, m->key), depth, &r)) return false;
            dk_json_set(L->a, obj, m->key, r);
        }
        *out = obj;
        return true;
    }
    default:
        *out = v;
        return true;
    }
}

DkJson *dk_project_json_ref(DkProject *p, const char *ref, DkErr *err) {
    Ld L = {p, p->a, err, NULL};
    DkStr r;
    if (!expand_ld(&L, dk_str(ref), ref, &r)) return NULL;
    DkJson *val;
    bool found;
    const char *what = NULL;
    if (!lookup_ref(&L, r, ref, &val, &found, &what)) return NULL;
    if (!found) {
        fail(&L, strncmp(what, "no file", 7) == 0 ? DK_ERR_IO : DK_ERR_FORMAT, "%s: %s", ref, what);
        return NULL;
    }
    return val;
}

/* ctools.local.json over the configuration: objects merged member by member, anything else replaced. */
static void deep_merge(DkArena *a, DkJson *base, DkJson *over) {
    for (size_t i = 0; i < dk_json_len(over); i++) {
        const DkJsonMember *m = dk_json_member(over, i);
        DkJson *b = dk_json_get(base, m->key);
        if (dk_json_is_obj(b) && dk_json_is_obj(m->val) && !is_from(b) && !is_from(m->val)) deep_merge(a, b, m->val);
        else dk_json_set(a, base, m->key, m->val);
    }
}

/* ---- typed reading of the walked tree ---------------------------------------------------------------------------- */
static bool check_keys(Ld *L, const DkJson *o, const char *kpath, const char *const *known, size_t n) {
    for (size_t i = 0; i < dk_json_len(o); i++) {
        const DkJsonMember *m = dk_json_member(o, i);
        bool ok = false;
        for (size_t k = 0; k < n && !ok; k++) ok = dk_str_eqz(m->key, known[k]);
        if (!ok) return fail(L, DK_ERR_FORMAT, "%s: unknown key", kp(L, kpath, m->key));
    }
    return true;
}
#define CHECK_KEYS(L, o, kpath, ...)                                                                 \
    check_keys((L), (o), (kpath), (const char *const[]){__VA_ARGS__},                               \
               sizeof((const char *const[]){__VA_ARGS__}) / sizeof(const char *))

static bool want_obj(Ld *L, const DkJson *v, const char *kpath) {
    return dk_json_is_obj(v) ? true : fail(L, DK_ERR_FORMAT, "%s: not an object", kpath);
}

/* A string member (absent: *out unchanged). path: resolved against the root. */
static bool get_str(Ld *L, const DkJson *o, const char *key, const char *kpath, bool path, const char **out) {
    DkJson *v = dk_json_getz(o, key);
    if (!v) return true;
    if (!dk_json_is_str(v)) return fail(L, DK_ERR_FORMAT, "%s: not a string", kpz(L, kpath, key));
    *out = path ? abs_against(L->a, L->p->root, v->u.str.p) : v->u.str.p;
    return true;
}

static bool get_bool(Ld *L, const DkJson *o, const char *key, const char *kpath, bool *out, bool *set) {
    DkJson *v = dk_json_getz(o, key);
    if (!v) return true;
    if (v->kind != DK_JSON_BOOL) return fail(L, DK_ERR_FORMAT, "%s: not true or false", kpz(L, kpath, key));
    *out = v->b;
    if (set) *set = true;
    return true;
}

/* A list of strings. path: each resolved against the root. */
static bool str_list(Ld *L, const DkJson *v, const char *kpath, bool path, DkStrVec *out) {
    if (!dk_json_is_arr(v)) return fail(L, DK_ERR_FORMAT, "%s: not a list", kpath);
    DkStrVec r = {0};
    for (size_t i = 0; i < dk_json_len(v); i++) {
        DkJson *item = dk_json_at(v, i);
        if (!dk_json_is_str(item)) {
            dk_vec_free(&r);
            return fail(L, DK_ERR_FORMAT, "%s[%zu]: not a string", kpath, i);
        }
        DkStr s = item->u.str;
        if (path) s = dk_str(abs_against(L->a, L->p->root, s.p));
        dk_vec_push(&r, s);
    }
    *out = r;
    return true;
}

static bool get_list(Ld *L, const DkJson *o, const char *key, const char *kpath, bool path, DkStrVec *out) {
    DkJson *v = dk_json_getz(o, key);
    if (!v) return true;
    return str_list(L, v, kpz(L, kpath, key), path, out);
}

/* ---- compiler ---------------------------------------------------------------------------------------------------- */
/* Lays the members of the block o over c. */
static bool read_compiler(Ld *L, const DkJson *o, const char *kpath, DkCompiler *c) {
    if (!want_obj(L, o, kpath) ||
        !CHECK_KEYS(L, o, kpath, "cl", "env", "path_prepend", "base_flags", "c_flags", "cpp_flags", "include",
                    "identity_files", "show_includes", "flag_variants"))
        return false;
    if (!get_str(L, o, "cl", kpath, true, &c->cl) || !get_list(L, o, "path_prepend", kpath, true, &c->path_prepend) ||
        !get_list(L, o, "base_flags", kpath, false, &c->base_flags) ||
        !get_list(L, o, "c_flags", kpath, false, &c->c_flags) ||
        !get_list(L, o, "cpp_flags", kpath, false, &c->cpp_flags) ||
        !get_list(L, o, "include", kpath, true, &c->include) ||
        !get_list(L, o, "identity_files", kpath, true, &c->identity_files) ||
        !get_bool(L, o, "show_includes", kpath, &c->show_includes, NULL))
        return false;
    DkJson *env = dk_json_getz(o, "env");
    if (env) {
        const char *ep = kpz(L, kpath, "env");
        if (!want_obj(L, env, ep)) return false;
        DkStrVec names = {0}, values = {0};
        for (size_t i = 0; i < dk_json_len(env); i++) {
            const DkJsonMember *m = dk_json_member(env, i);
            if (!dk_json_is_str(m->val)) return fail(L, DK_ERR_FORMAT, "%s: not a string", kp(L, ep, m->key));
            dk_vec_push(&names, dk_str_dup(L->a, m->key));
            dk_vec_push(&values, m->val->u.str);
        }
        c->env_names = names;
        c->env_values = values;
    }
    DkJson *fv = dk_json_getz(o, "flag_variants");
    if (fv) {
        const char *fp = kpz(L, kpath, "flag_variants");
        if (!dk_json_is_arr(fv)) return fail(L, DK_ERR_FORMAT, "%s: not a list", fp);
        c->n_flag_variants = dk_json_len(fv);
        c->flag_variants = DK_NEWN(L->a, DkStrVec, c->n_flag_variants + 1);
        for (size_t i = 0; i < c->n_flag_variants; i++)
            if (!str_list(L, dk_json_at(fv, i), dk_sprintf(L->a, "%s[%zu]", fp, i), false, &c->flag_variants[i]))
                return false;
    }
    return true;
}

/* ---- targets ----------------------------------------------------------------------------------------------------- */
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool read_symbols(Ld *L, const DkJson *v, const char *kpath, DkTarget *t) {
    if (!dk_json_is_arr(v)) return fail(L, DK_ERR_FORMAT, "%s: not a list", kpath);
    t->n_symbols = dk_json_len(v);
    t->symbols = DK_NEWN(L->a, DkSymSource, t->n_symbols + 1);
    for (size_t i = 0; i < t->n_symbols; i++) {
        DkJson *s = dk_json_at(v, i);
        const char *sp = dk_sprintf(L->a, "%s[%zu]", kpath, i);
        if (!want_obj(L, s, sp) || !CHECK_KEYS(L, s, sp, "kind", "path", "name", "va", "rva", "size")) return false;
        DkSymSource *src = &t->symbols[i];
        const char *kind = NULL;
        if (!get_str(L, s, "kind", sp, false, &kind) || !get_str(L, s, "path", sp, true, &src->path)) return false;
        if (!kind) return fail(L, DK_ERR_FORMAT, "%s: required", kpz(L, sp, "kind"));
        if (!src->path) return fail(L, DK_ERR_FORMAT, "%s: required", kpz(L, sp, "path"));
        if (strcmp(kind, "tsv") == 0) src->kind = DK_SYM_TSV;
        else if (strcmp(kind, "pdb") == 0) src->kind = DK_SYM_PDB;
        else if (strcmp(kind, "map") == 0) src->kind = DK_SYM_MAP;
        else if (strcmp(kind, "candidates") == 0) src->kind = DK_SYM_CANDIDATES;
        else return fail(L, DK_ERR_FORMAT, "%s: \"%s\" is not tsv, pdb, map or candidates", kpz(L, sp, "kind"), kind);
        src->col_name = "name";
        src->col_va = "va";
        src->col_rva = "rva";
        src->col_size = "size";
        if (!get_str(L, s, "name", sp, false, &src->col_name) || !get_str(L, s, "va", sp, false, &src->col_va) ||
            !get_str(L, s, "rva", sp, false, &src->col_rva) || !get_str(L, s, "size", sp, false, &src->col_size))
            return false;
    }
    return true;
}

static bool read_target(Ld *L, DkStr name, const DkJson *o, const char *kpath, size_t index, DkJson **units,
                        DkJson **link_with) {
    DkProject *p = L->p;
    DkTarget *t = &p->targets[index];
    if (!want_obj(L, o, kpath) ||
        !CHECK_KEYS(L, o, kpath, "image", "sha256", "image_base", "defines", "symbols", "compiler", "units",
                    "link_with"))
        return false;
    t->name = dk_cz(L->a, name);
    if (!get_str(L, o, "image", kpath, true, &t->image_path)) return false;
    if (!t->image_path) return fail(L, DK_ERR_FORMAT, "%s: required", kpz(L, kpath, "image"));
    DkJson *sha = dk_json_getz(o, "sha256");
    if (sha) {
        const char *sp = kpz(L, kpath, "sha256");
        if (!dk_json_is_str(sha) || sha->u.str.n != 64) return fail(L, DK_ERR_FORMAT, "%s: not 64 hex digits", sp);
        for (size_t i = 0; i < 32; i++) {
            int hi = hexval(sha->u.str.p[2 * i]), lo = hexval(sha->u.str.p[2 * i + 1]);
            if (hi < 0 || lo < 0) return fail(L, DK_ERR_FORMAT, "%s: not 64 hex digits", sp);
            t->sha256[i] = (u8)(hi << 4 | lo);
        }
        t->has_sha256 = true;
    }
    DkJson *base = dk_json_getz(o, "image_base");
    if (base) {
        const char *bp = kpz(L, kpath, "image_base");
        u64 b = 0;
        if (dk_json_is_int(base) && !base->big && base->u.i >= 0) b = (u64)base->u.i;
        else if (!dk_json_is_str(base) || !dk_parse_uint(base->u.str, 0, &b))
            return fail(L, DK_ERR_FORMAT, "%s: not an address", bp);
        if (b > 0xFFFFFFFFu) return fail(L, DK_ERR_FORMAT, "%s: above 32 bits", bp);
        t->image_base = (u32)b;
    }
    if (!get_list(L, o, "defines", kpath, false, &t->defines)) return false;
    DkJson *syms = dk_json_getz(o, "symbols");
    if (syms && !read_symbols(L, syms, kpz(L, kpath, "symbols"), t)) return false;
    t->compiler = &p->compiler;
    DkJson *comp = dk_json_getz(o, "compiler");
    if (comp) {
        p->target_compilers[index] = p->compiler;
        if (!read_compiler(L, comp, kpz(L, kpath, "compiler"), &p->target_compilers[index])) return false;
        t->compiler = &p->target_compilers[index];
    }
    *units = dk_json_getz(o, "units");
    *link_with = dk_json_getz(o, "link_with");
    return true;
}

/* ---- units ------------------------------------------------------------------------------------------------------- */
typedef struct {
    DkUnit u;
    u32 tmask; /* the targets whose unit map lists it */
} UnitRec;
typedef DK_VEC(UnitRec) UnitRecVec;

typedef struct {
    UnitRecVec recs;
    DkMap *index; /* path -> record number */
} Units;

static size_t unit_rec(Units *U, const char *path) {
    bool created = false;
    DkVal *slot = dk_map_put(U->index, dk_str(path), &created);
    if (created) {
        UnitRec *r = dk_vec_push_zero(&U->recs);
        r->u.path = path;
        r->u.flags_line = true;
        slot->u = U->recs.n - 1;
    }
    return (size_t)slot->u;
}

/* A unit map: path -> {compile_flags, remove_compile_flags, link_flags, gl, flags_line}; other members (evidence
 * notes) are ignored. target -1: the global map. */
static bool read_unit_map(Ld *L, Units *U, const DkJson *map, const char *kpath, int target) {
    if (!want_obj(L, map, kpath)) return false;
    for (size_t i = 0; i < dk_json_len(map); i++) {
        const DkJsonMember *m = dk_json_member(map, i);
        const char *ep = kp(L, kpath, m->key);
        if (!want_obj(L, m->val, ep)) return false;
        size_t ri = unit_rec(U, rel_norm(L->a, L->p, m->key));
        DkUnit tmp = U->recs.v[ri].u;
        if (!get_list(L, m->val, "compile_flags", ep, false, &tmp.compile_flags) ||
            !get_list(L, m->val, "remove_compile_flags", ep, false, &tmp.remove_flags) ||
            !get_list(L, m->val, "link_flags", ep, false, &tmp.link_flags) ||
            !get_list(L, m->val, "link_with", ep, false, &tmp.link_with) ||
            !get_list(L, m->val, "link_roots", ep, false, &tmp.link_roots) ||
            !get_bool(L, m->val, "gl", ep, &tmp.gl, &tmp.gl_set) ||
            !get_bool(L, m->val, "flags_line", ep, &tmp.flags_line, NULL))
            return false;
        U->recs.v[ri].u = tmp;
        if (target >= 0) U->recs.v[ri].tmask |= 1u << target;
    }
    return true;
}

/* A link-dependency list (docs/c-toolkit-design.md section 5.2): either a map unit -> [sources], or a list of entries
 * {"unit": path, "dependencies": [sources], "roots": [symbols]} (other members ignored). Each source is added to the
 * unit's link_with, each root to its link_roots. */
static bool read_link_with(Ld *L, Units *U, const DkJson *v, const char *kpath) {
    if (dk_json_is_obj(v)) {
        for (size_t i = 0; i < dk_json_len(v); i++) {
            const DkJsonMember *m = dk_json_member(v, i);
            DkStrVec deps = {0};
            if (!str_list(L, m->val, kp(L, kpath, m->key), false, &deps)) return false;
            size_t ri = unit_rec(U, rel_norm(L->a, L->p, m->key));
            for (size_t k = 0; k < deps.n; k++) dk_vec_push(&U->recs.v[ri].u.link_with, deps.v[k]);
        }
        return true;
    }
    if (!dk_json_is_arr(v)) return fail(L, DK_ERR_FORMAT, "%s: not an object or a list", kpath);
    for (size_t i = 0; i < dk_json_len(v); i++) {
        const DkJson *e = dk_json_at(v, i);
        const char *ep = dk_sprintf(L->a, "%s[%zu]", kpath, i);
        if (!want_obj(L, e, ep)) return false;
        const char *unit = NULL;
        DkStrVec deps = {0}, roots = {0};
        if (!get_str(L, e, "unit", ep, false, &unit) || !get_list(L, e, "dependencies", ep, false, &deps) ||
            !get_list(L, e, "roots", ep, false, &roots))
            return false;
        if (!unit) return fail(L, DK_ERR_FORMAT, "%s: required", kpz(L, ep, "unit"));
        size_t ri = unit_rec(U, rel_norm(L->a, L->p, dk_str(unit)));
        for (size_t k = 0; k < deps.n; k++) dk_vec_push(&U->recs.v[ri].u.link_with, deps.v[k]);
        for (size_t k = 0; k < roots.n; k++) dk_vec_push(&U->recs.v[ri].u.link_roots, roots.v[k]);
    }
    return true;
}

static int cmp_str(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    const DkStr *a = x, *b = y;
    int c = memcmp(a->p, b->p, DK_MIN(a->n, b->n));
    return c ? c : (a->n > b->n) - (a->n < b->n);
}

/* Normalises a unit's link_with (repository-relative, without the unit, sorted, unique) and link_roots (unique). */
static void finish_link_with(Ld *L, DkUnit *u) {
    DkStrVec *v = &u->link_with;
    size_t w = 0;
    for (size_t i = 0; i < v->n; i++) {
        DkStr s = dk_str(rel_norm(L->a, L->p, v->v[i]));
        if (strcmp(s.p, u->path) != 0) v->v[w++] = s;
    }
    v->n = w;
    if (v->n > 1) dk_sort(v->v, v->n, sizeof *v->v, cmp_str, NULL, false);
    w = 0;
    for (size_t i = 0; i < v->n; i++)
        if (!w || !dk_str_eq(v->v[w - 1], v->v[i])) v->v[w++] = v->v[i];
    v->n = w;
    DkStrVec *r = &u->link_roots;
    w = 0;
    for (size_t i = 0; i < r->n; i++) {
        bool dup = false;
        for (size_t k = 0; k < w && !dup; k++) dup = dk_str_eq(r->v[k], r->v[i]);
        if (!dup) r->v[w++] = r->v[i];
    }
    r->n = w;
}

static bool under_dir(const char *rel, const char *dir) {
    size_t n = strlen(dir);
    if (!n) return true;
    return _strnicmp(rel, dir, n) == 0 && (rel[n] == 0 || rel[n] == '/');
}

static bool excluded(const DkStrVec *ex, const char *rel) {
    for (size_t i = 0; i < ex->n; i++)
        if (under_dir(rel, ex->v[i].p)) return true;
    return false;
}

static bool has_ext(const DkStrVec *exts, DkStr name) {
    for (size_t i = 0; i < exts->n; i++) {
        DkStr e = exts->v[i];
        if (name.n >= e.n && _strnicmp(name.p + name.n - e.n, e.p, e.n) == 0) return true;
    }
    return false;
}

static void discover(Ld *L, Units *U, const char *rootrel, const DkStrVec *ex, const DkStrVec *exts) {
    if (excluded(ex, rootrel)) return;
    const char *top = dk_sprintf(L->a, "%s/%s", L->p->root, rootrel);
    if (!dk_isdir(top)) return;
    size_t topn = strlen(top);
    DkWalk *w = dk_walk_open(top, true);
    DkWalkItem it = {0};
    while (dk_walk_next(w, &it)) {
        char *rel = dk_sprintf(L->a, "%s%.*s", rootrel, (int)(it.dirpath.n - DK_MIN(topn, it.dirpath.n)),
                               it.dirpath.p + DK_MIN(topn, it.dirpath.n));
        to_slashes(rel);
        size_t k = 0;
        for (size_t i = 0; i < it.dirs.n; i++) {
            const char *child = dk_sprintf(L->a, "%s/%.*s", rel, DK_SF(it.dirs.v[i]));
            if (!excluded(ex, child)) it.dirs.v[k++] = it.dirs.v[i];
        }
        it.dirs.n = k;
        for (size_t i = 0; i < it.files.n; i++)
            if (has_ext(exts, it.files.v[i])) unit_rec(U, dk_sprintf(L->a, "%s/%.*s", rel, DK_SF(it.files.v[i])));
    }
    dk_walk_close(w);
}

static bool ident_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

/* Whether text holds name as a whole token. */
static bool has_token(DkStr text, DkStr name) {
    i64 at = 0;
    while ((at = dk_str_find(text, name, at, DK_END)) >= 0) {
        size_t s = (size_t)at, e = s + name.n;
        if ((s == 0 || !ident_char(text.p[s - 1])) && (e >= text.n || !ident_char(text.p[e]))) return true;
        at++;
    }
    return false;
}

static int cmp_unit(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    return strcmp(((const DkUnit *)x)->path, ((const DkUnit *)y)->path);
}

static bool read_units(Ld *L, const DkJson *o, DkJson *const *target_maps, DkJson *const *target_links) {
    DkProject *p = L->p;
    DkStrVec exclude = {0}, exts = {0};
    DkJson *map = NULL;
    if (o) {
        if (!want_obj(L, o, "units") ||
            !CHECK_KEYS(L, o, "units", "roots", "exclude", "extensions", "map", "link_with") ||
            !get_list(L, o, "roots", "units", false, &p->unit_roots) ||
            !get_list(L, o, "exclude", "units", false, &exclude) ||
            !get_list(L, o, "extensions", "units", false, &exts))
            return false;
        map = dk_json_getz(o, "map");
    }
    if (!dk_json_getz(o, "extensions")) {
        dk_vec_push(&exts, DK_S(".c"));
        dk_vec_push(&exts, DK_S(".cpp"));
    }
    for (size_t i = 0; i < p->unit_roots.n; i++) p->unit_roots.v[i] = dk_str(rel_norm(L->a, p, p->unit_roots.v[i]));
    for (size_t i = 0; i < exclude.n; i++) exclude.v[i] = dk_str(rel_norm(L->a, p, exclude.v[i]));

    Units U = {0};
    U.index = dk_map_new();
    for (size_t i = 0; i < p->unit_roots.n; i++) discover(L, &U, p->unit_roots.v[i].p, &exclude, &exts);
    bool ok = !map || read_unit_map(L, &U, map, "units.map", -1);
    for (size_t t = 0; ok && t < p->ntargets; t++)
        if (target_maps[t])
            ok = read_unit_map(L, &U, target_maps[t], dk_sprintf(L->a, "targets.%s.units", p->targets[t].name),
                               (int)t);
    DkJson *links = o ? dk_json_getz(o, "link_with") : NULL;
    if (ok && links) ok = read_link_with(L, &U, links, "units.link_with");
    for (size_t t = 0; ok && t < p->ntargets; t++)
        if (target_links[t])
            ok = read_link_with(L, &U, target_links[t], dk_sprintf(L->a, "targets.%s.link_with", p->targets[t].name));
    dk_map_free(U.index);
    dk_vec_free(&exclude);
    dk_vec_free(&exts);
    if (!ok) {
        dk_vec_free(&U.recs);
        return false;
    }

    DkStrVec defines = {0};
    for (size_t t = 0; t < p->ntargets; t++)
        for (size_t i = 0; i < p->targets[t].defines.n; i++) {
            DkStr name, value;
            dk_str_partition(p->targets[t].defines.v[i], DK_S("="), &name, &value);
            name = dk_str_strip(name);
            if (name.n) dk_vec_push(&defines, name);
        }
    u32 all = (1u << p->ntargets) - 1;
    p->nunits = U.recs.n;
    p->units = DK_NEWN(L->a, DkUnit, U.recs.n + 1);
    for (size_t i = 0; i < U.recs.n; i++) {
        DkUnit *u = &p->units[i];
        *u = U.recs.v[i].u;
        u->target_mask = U.recs.v[i].tmask ? U.recs.v[i].tmask : all;
        finish_link_with(L, u);
        if (defines.n) {
            DkBytes raw = {0};
            if (dk_read_all(NULL, dk_sprintf(L->a, "%s/%s", p->root, u->path), &raw)) {
                DkStr text = dk_strn((const char *)raw.v, raw.n);
                for (size_t d = 0; d < defines.n && !u->per_target; d++) u->per_target = has_token(text, defines.v[d]);
                dk_vec_free(&raw);
            }
        }
    }
    dk_vec_free(&defines);
    dk_vec_free(&U.recs);
    dk_sort(p->units, p->nunits, sizeof(DkUnit), cmp_unit, NULL, false);
    return true;
}

/* ---- backend, annotations and the small blocks -------------------------------------------------------------------- */
static bool read_backend(Ld *L, const DkJson *o) {
    DkBackend *b = &L->p->backend;
    b->kind = DK_BACKEND_OBJECT;
    b->roots = "annotations";
    b->map_format = "msvc";
    if (!o) return true;
    if (!want_obj(L, o, "backend") || !CHECK_KEYS(L, o, "backend", "kind", "link", "manifest")) return false;
    const char *kind = NULL;
    if (!get_str(L, o, "kind", "backend", false, &kind)) return false;
    if (!kind || strcmp(kind, "object") == 0) b->kind = DK_BACKEND_OBJECT;
    else if (strcmp(kind, "link") == 0) b->kind = DK_BACKEND_LINK;
    else if (strcmp(kind, "manifest") == 0) b->kind = DK_BACKEND_MANIFEST;
    else return fail(L, DK_ERR_FORMAT, "backend.kind: \"%s\" is not object, link or manifest", kind);
    DkJson *link = dk_json_getz(o, "link");
    if (link) {
        const char *lp = "backend.link";
        if (!want_obj(L, link, lp) ||
            !CHECK_KEYS(L, link, lp, "linker", "argv", "roots", "map", "discovery_compile") ||
            !get_str(L, link, "linker", lp, true, &b->linker) || !get_list(L, link, "argv", lp, false, &b->link_argv) ||
            !get_str(L, link, "roots", lp, false, &b->roots) || !get_str(L, link, "map", lp, false, &b->map_format) ||
            !get_bool(L, link, "discovery_compile", lp, &b->discovery_compile, NULL))
            return false;
        if (strcmp(b->roots, "annotations") != 0)
            return fail(L, DK_ERR_FORMAT, "backend.link.roots: \"%s\" is not annotations", b->roots);
        if (strcmp(b->map_format, "msvc") != 0)
            return fail(L, DK_ERR_FORMAT, "backend.link.map: \"%s\" is not msvc", b->map_format);
    }
    DkJson *man = dk_json_getz(o, "manifest");
    if (man) {
        const char *mp = "backend.manifest";
        if (!want_obj(L, man, mp) || !CHECK_KEYS(L, man, mp, "command", "path") ||
            !get_list(L, man, "command", mp, false, &b->manifest_command) ||
            !get_str(L, man, "path", mp, true, &b->manifest_path))
            return false;
    }
    if (b->kind == DK_BACKEND_LINK && !b->linker)
        return fail(L, DK_ERR_FORMAT, "backend.link.linker: required for the link backend");
    if (b->kind == DK_BACKEND_MANIFEST && !b->manifest_command.n && !b->manifest_path)
        return fail(L, DK_ERR_FORMAT, "backend.manifest: a command or a path is required for the manifest backend");
    return true;
}

static bool read_annotations(Ld *L, const DkJson *o) {
    DkProject *p = L->p;
    DkAnnotConfig *c = &p->annot;
    c->addr_groups = DK_ADDR_TARGET_ADDR;
    c->name = DK_NAME_DECLARATION;
    c->flags_lines = 8;
    c->g_kind = c->g_target = c->g_addr = -1;
    for (int t = 0; t < DK_MAX_TARGETS; t++) c->g_addr_target[t] = -1;
    const char *names[DK_MAX_TARGETS];
    for (size_t t = 0; t < p->ntargets; t++) names[t] = p->targets[t].name;
    c->ntargets = (int)p->ntargets;
    for (size_t t = 0; t < p->ntargets; t++) c->target_names[t] = names[t];
    if (!o) return true;
    const char *ap = "annotations";
    if (!want_obj(L, o, ap) ||
        !CHECK_KEYS(L, o, ap, "marker", "kinds", "addr_groups", "name", "groups", "symbol", "stop", "pending",
                    "flags", "flags_lines") ||
        !get_str(L, o, "marker", ap, false, &c->marker) || !get_str(L, o, "symbol", ap, false, &c->symbol) ||
        !get_str(L, o, "stop", ap, false, &c->stop) || !get_str(L, o, "pending", ap, false, &c->pending) ||
        !get_str(L, o, "flags", ap, false, &c->flags))
        return false;
    if (!c->marker) return fail(L, DK_ERR_FORMAT, "annotations.marker: required");
    DkJson *kinds = dk_json_getz(o, "kinds");
    if (kinds) {
        if (!want_obj(L, kinds, "annotations.kinds")) return false;
        c->n_kinds = dk_json_len(kinds);
        c->kinds = DK_NEWN(L->a, DkAnnKindName, c->n_kinds + 1);
        for (size_t i = 0; i < c->n_kinds; i++) {
            const DkJsonMember *m = dk_json_member(kinds, i);
            const char *kpth = kp(L, "annotations.kinds", m->key);
            DkStr v = dk_json_str_or(m->val, DK_S(""));
            DkAnnKind k;
            if (dk_str_eqz(v, "function")) k = DK_ANN_FUNCTION;
            else if (dk_str_eqz(v, "data")) k = DK_ANN_DATA;
            else if (dk_str_eqz(v, "decl")) k = DK_ANN_DECL;
            else if (dk_str_eqz(v, "vtable")) k = DK_ANN_VTABLE;
            else return fail(L, DK_ERR_FORMAT, "%s: not function, data, decl or vtable", kpth);
            c->kinds[i].text = dk_cz(L->a, m->key);
            c->kinds[i].kind = k;
        }
    }
    const char *s = NULL;
    if (!get_str(L, o, "addr_groups", ap, false, &s)) return false;
    if (s && strcmp(s, "target+addr") == 0) c->addr_groups = DK_ADDR_TARGET_ADDR;
    else if (s && strcmp(s, "per-target") == 0) c->addr_groups = DK_ADDR_PER_TARGET;
    else if (s) return fail(L, DK_ERR_FORMAT, "annotations.addr_groups: \"%s\" is not target+addr or per-target", s);
    s = NULL;
    if (!get_str(L, o, "name", ap, false, &s)) return false;
    if (s && strcmp(s, "declaration") == 0) c->name = DK_NAME_DECLARATION;
    else if (s && strcmp(s, "next_line") == 0) c->name = DK_NAME_NEXT_LINE;
    else if (s) return fail(L, DK_ERR_FORMAT, "annotations.name: \"%s\" is not declaration or next_line", s);
    DkJson *groups = dk_json_getz(o, "groups");
    if (groups) {
        const char *gp = "annotations.groups";
        if (!want_obj(L, groups, gp) || !CHECK_KEYS(L, groups, gp, "kind", "target", "addr") ||
            !get_str(L, groups, "kind", gp, false, &c->group_kind) ||
            !get_str(L, groups, "target", gp, false, &c->group_target) ||
            !get_str(L, groups, "addr", gp, false, &c->group_addr))
            return false;
    }
    DkJson *fl = dk_json_getz(o, "flags_lines");
    if (fl) {
        if (!dk_json_is_int(fl) || fl->big || fl->u.i < 0 || fl->u.i > 1000000)
            return fail(L, DK_ERR_FORMAT, "annotations.flags_lines: not a line count");
        c->flags_lines = (int)fl->u.i;
    }
    return dk_annot_config_compile(c, names, p->ntargets, L->err);
}

static bool read_referents(Ld *L, const DkJson *v) {
    DkProject *p = L->p;
    if (!v) return true;
    if (!dk_json_is_arr(v)) return fail(L, DK_ERR_FORMAT, "referents: not a list");
    p->nreferents = dk_json_len(v);
    p->referents = DK_NEWN(L->a, DkReferentFile, p->nreferents + 1);
    for (size_t i = 0; i < p->nreferents; i++) {
        DkJson *r = dk_json_at(v, i);
        const char *rp = dk_sprintf(L->a, "referents[%zu]", i);
        DkReferentFile *f = &p->referents[i];
        if (!want_obj(L, r, rp) || !CHECK_KEYS(L, r, rp, "file", "format") ||
            !get_str(L, r, "file", rp, true, &f->file) || !get_str(L, r, "format", rp, false, &f->format))
            return false;
        if (!f->file) return fail(L, DK_ERR_FORMAT, "%s.file: required", rp);
        if (!f->format) return fail(L, DK_ERR_FORMAT, "%s.format: required", rp);
        if (strcmp(f->format, "json-symbols") != 0 && strcmp(f->format, "tsv") != 0)
            return fail(L, DK_ERR_FORMAT, "%s.format: \"%s\" is not json-symbols or tsv", rp, f->format);
    }
    return true;
}

static bool read_small_blocks(Ld *L, const DkJson *cfg) {
    DkProject *p = L->p;
    DkJson *wk = dk_json_getz(cfg, "well_known");
    if (wk && (!want_obj(L, wk, "well_known") || !CHECK_KEYS(L, wk, "well_known", "imports", "symbols") ||
               !get_bool(L, wk, "imports", "well_known", &p->wk_imports, NULL) ||
               !get_list(L, wk, "symbols", "well_known", false, &p->wk_symbols)))
        return false;
    DkJson *tc = dk_json_getz(cfg, "text_checks");
    if (tc && (!want_obj(L, tc, "text_checks") || !CHECK_KEYS(L, tc, "text_checks", "paths", "no_bom") ||
               !get_list(L, tc, "paths", "text_checks", false, &p->tc_paths) ||
               !get_list(L, tc, "no_bom", "text_checks", false, &p->tc_no_bom)))
        return false;
    for (size_t i = 0; i < p->tc_paths.n; i++) p->tc_paths.v[i] = dk_str(rel_norm(L->a, p, p->tc_paths.v[i]));
    p->build_dir = dk_sprintf(L->a, "%s/build/ctools", p->root);
    return get_str(L, cfg, "build_dir", "", true, &p->build_dir);
}

/* ---- loading ----------------------------------------------------------------------------------------------------- */
static const char *const RESERVED_VARS[] = {"root", "primary", "target", "unit", "out", "objects", "roots"};

static bool read_vars(Ld *L, const DkJson *vars) {
    DkProject *p = L->p;
    if (!vars) return true;
    if (!want_obj(L, vars, "vars")) return false;
    for (size_t i = 0; i < dk_json_len(vars); i++) {
        const DkJsonMember *m = dk_json_member(vars, i);
        const char *vp = kp(L, "vars", m->key);
        for (size_t r = 0; r < DK_ARRAY_LEN(RESERVED_VARS); r++)
            if (dk_str_eqz(m->key, RESERVED_VARS[r])) return fail(L, DK_ERR_FORMAT, "%s: a built-in name", vp);
        DkJson *v;
        if (!walk(L, m->val, vp, 0, &v)) return false;
        if (!dk_json_is_str(v)) return fail(L, DK_ERR_FORMAT, "%s: not a string", vp);
        dk_vec_push(&p->var_names, dk_str_dup(L->a, m->key));
        dk_vec_push(&p->var_values, v->u.str);
    }
    return true;
}

static bool load(Ld *L, const char *config) {
    DkProject *p = L->p;
    bool missing = false;
    DkJson *doc = read_json(L, config, &missing);
    if (missing) return fail(L, DK_ERR_IO, "no such file");
    if (!doc) return false;
    if (!dk_json_is_obj(doc)) return fail(L, DK_ERR_FORMAT, "not a JSON object");
    if (!p->config_path_given) {
        const char *local = dk_sprintf(L->a, "%s/config/ctools.local.json", p->root);
        DkJson *over = read_json(L, local, &missing);
        if (!over && !missing) return false;
        if (over) {
            if (!dk_json_is_obj(over)) return fail(L, DK_ERR_FORMAT, "%s: not a JSON object", local);
            deep_merge(L->a, doc, over);
        }
    }
    if (!CHECK_KEYS(L, doc, "", "schema", "vars", "targets", "units", "compiler", "backend", "annotations",
                    "referents", "well_known", "build_dir", "text_checks"))
        return false;
    if (!read_vars(L, dk_json_getz(doc, "vars"))) return false;
    DkJson *rest = dk_json_obj(L->a);
    for (size_t i = 0; i < dk_json_len(doc); i++) {
        const DkJsonMember *m = dk_json_member(doc, i);
        if (dk_str_eqz(m->key, "vars")) continue;
        DkJson *v;
        if (!walk(L, m->val, kp(L, "", m->key), 0, &v)) return false;
        dk_json_set(L->a, rest, m->key, v);
    }
    DkJson *schema = dk_json_getz(rest, "schema");
    if (!schema) return fail(L, DK_ERR_FORMAT, "schema: required (\"%s\")", DK_PROJECT_SCHEMA);
    if (!dk_json_is_str(schema) || !dk_str_eqz(schema->u.str, DK_PROJECT_SCHEMA))
        return fail(L, DK_ERR_FORMAT, "schema: not \"%s\"", DK_PROJECT_SCHEMA);

    DkJson *comp = dk_json_getz(rest, "compiler");
    if (comp && !read_compiler(L, comp, "compiler", &p->compiler)) return false;

    DkJson *targets = dk_json_getz(rest, "targets");
    DkJson *target_maps[DK_MAX_TARGETS] = {0}, *target_links[DK_MAX_TARGETS] = {0};
    if (targets) {
        if (!want_obj(L, targets, "targets")) return false;
        size_t n = dk_json_len(targets);
        if (n > DK_MAX_TARGETS)
            return fail(L, DK_ERR_FORMAT, "targets: %zu targets, at most %d", n, DK_MAX_TARGETS);
        for (size_t i = 0; i < n; i++) {
            const DkJsonMember *m = dk_json_member(targets, i);
            if (!m->key.n) return fail(L, DK_ERR_FORMAT, "targets: an empty target name");
            if (!read_target(L, m->key, m->val, kp(L, "targets", m->key), i, &target_maps[i], &target_links[i]))
                return false;
            p->ntargets = i + 1;
        }
    }
    return read_units(L, dk_json_getz(rest, "units"), target_maps, target_links) &&
           read_annotations(L, dk_json_getz(rest, "annotations")) && read_backend(L, dk_json_getz(rest, "backend")) &&
           read_referents(L, dk_json_getz(rest, "referents")) && read_small_blocks(L, rest);
}

DkProject *dk_project_load(DkArena *a, const char *root, const char *config, DkErr *err) {
    DkErr local_err = {0};
    if (!err) err = &local_err;
    dk_err_clear(err);
    if (!a) a = dk_arena();
    DkProject *p = DK_NEW(a, DkProject);
    p->a = a;
    p->root = abs_against(a, root ? root : dk_root(), ".");
    p->primary = find_primary(a, p->root);
    p->config_path_given = config != NULL;
    p->config_path = config ? abs_against(a, p->root, config) : dk_sprintf(a, "%s/config/ctools.json", p->root);
    p->files = dk_map_new();
    Ld L = {p, a, err, p->config_path};
    if (!load(&L, p->config_path)) return NULL;
    return p;
}

/* ---- accessors --------------------------------------------------------------------------------------------------- */
DkArena *dk_project_arena(const DkProject *p) { return p->a; }
const char *dk_project_root(const DkProject *p) { return p->root; }
const char *dk_project_primary(const DkProject *p) { return p->primary; }
const char *dk_project_config_path(const DkProject *p) { return p->config_path; }
size_t dk_project_ntargets(const DkProject *p) { return p->ntargets; }

const DkTarget *dk_project_target(const DkProject *p, int index) {
    return index >= 0 && (size_t)index < p->ntargets ? &p->targets[index] : NULL;
}

DkTarget *dk_project_target_mut(DkProject *p, int index) {
    return index >= 0 && (size_t)index < p->ntargets ? &p->targets[index] : NULL;
}

int dk_project_target_index(const DkProject *p, const char *name) {
    for (size_t i = 0; name && i < p->ntargets; i++)
        if (strcmp(p->targets[i].name, name) == 0) return (int)i;
    return -1;
}

const DkUnit *dk_project_units(const DkProject *p, size_t *n) {
    if (n) *n = p->nunits;
    return p->units;
}

const DkUnit *dk_project_unit(const DkProject *p, const char *path_or_stem) {
    if (!path_or_stem) return NULL;
    DkArenaMark mark = dk_arena_mark(dk_scratch());
    char *want = dk_strdup(dk_scratch(), path_or_stem);
    to_slashes(want);
    while (want[0] == '.' && want[1] == '/') want += 2;
    const DkUnit *found = NULL;
    for (size_t i = 0; i < p->nunits && !found; i++)
        if (strcmp(p->units[i].path, want) == 0) found = &p->units[i];
    if (!found && !strchr(want, '/')) {
        size_t wn = strlen(want), hits = 0;
        const DkUnit *hit = NULL;
        for (int pass = 0; pass < 2 && !hits; pass++) /* the file name, then the stem */
            for (size_t i = 0; i < p->nunits; i++) {
                const char *base = strrchr(p->units[i].path, '/');
                base = base ? base + 1 : p->units[i].path;
                const char *dot = strrchr(base, '.');
                size_t bn = pass == 0 || !dot ? strlen(base) : (size_t)(dot - base);
                if (bn == wn && strncmp(base, want, wn) == 0) {
                    hit = &p->units[i];
                    hits++;
                }
            }
        if (hits == 1) found = hit;
    }
    dk_arena_reset(dk_scratch(), mark);
    return found;
}

const DkStrVec *dk_project_unit_roots(const DkProject *p) { return &p->unit_roots; }

const DkCompiler *dk_project_compiler(const DkProject *p, int target) {
    if (target >= 0 && (size_t)target < p->ntargets) return p->targets[target].compiler;
    return &p->compiler;
}

const DkBackend *dk_project_backend(const DkProject *p) { return &p->backend; }
const DkAnnotConfig *dk_project_annot_config(const DkProject *p) { return &p->annot; }

const DkReferentFile *dk_project_referents(const DkProject *p, size_t *n) {
    if (n) *n = p->nreferents;
    return p->referents;
}

bool dk_project_well_known_imports(const DkProject *p) { return p->wk_imports; }
const DkStrVec *dk_project_well_known_symbols(const DkProject *p) { return &p->wk_symbols; }
const DkStrVec *dk_project_text_check_paths(const DkProject *p) { return &p->tc_paths; }
const DkStrVec *dk_project_text_check_no_bom(const DkProject *p) { return &p->tc_no_bom; }

const char *dk_project_build_dir(const DkProject *p, const char *tool) {
    if (!tool || !*tool) return p->build_dir;
    return dk_sprintf(p->a, "%s/%s", p->build_dir, tool);
}

const char *dk_project_var(const DkProject *p, const char *name) {
    return name ? lookup_var(p, dk_str(name)) : NULL;
}
