// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* objcache: the content-addressed cache of the object files and link outputs the compile tools produce, plus the
 * on-disk memo tables of pure functions (PickleMemo). Shared by every worktree of the machine: a build that compiles
 * only the units whose inputs changed reuses the rest. See objcache.h for the contract (environment variables, what
 * makes an object reusable, the file formats). The behaviour is defined by its tests (tests/project_objcache_test.c,
 * tests/project_objcache_memo_test.c).
 *
 * This file does not need the project adapter: the part that reads a DkCompiler (objcache_obj_cache_new,
 * objcache_open_cache) is in objcache_project.c. */
#include "objcache_internal.h"
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ================================================================================================= constants */

const char *const objcache_off_words[OBJCACHE_OFF_WORDS_N] = {"off", "0", "no", "none", "false"};
const char *const objcache_restore_modes[OBJCACHE_RESTORE_MODES_N] = {"auto", "clone", "copy"};
double objcache_prune_min_age = 600.0;

#define ENTRY_SCHEMA 1u
#define MEMO_SCHEMA 1u
#define KEEP_ENTRIES 8
#define SECONDS_PER_HOUR 3600.0

/* the memo, the maps and the lookups keep pointers into this arena for the life of the process: an arena of its own per
 * thread, not dk_arena(), which a caller may reset (a pool task of lever_sweep resets its thread's after every job) */
static DkArena *pa(void) {
    static DK_THREAD_LOCAL DkArena *keep;
    if (!keep) keep = dk_arena_new(0);
    return keep;
}

/* A NUL-terminated heap-lifetime copy of n bytes (never NULL). */
static char *dup_n(const char *p, size_t n) {
    char *r = (char *)dk_alloc_noz(pa(), n + 1);
    if (n) memcpy(r, p, n);
    r[n] = 0;
    return r;
}
static DkStr persist(DkStr s) {
    DkStr r = {dup_n(s.p, s.n), s.n};
    return r;
}
static const char *persist_cz(const char *s) { return s ? dup_n(s, strlen(s)) : NULL; }

static bool lower_in_off_words(DkStr s) {
    for (size_t i = 0; i < OBJCACHE_OFF_WORDS_N; i++)
        if (dk_str_eqz(s, objcache_off_words[i])) return true;
    return false;
}

/* ================================================================================ at exit */

typedef struct {
    void (*fn)(void *);
    void *ctx;
} ExitAction;
static DkMutex g_exit_lock;
static ExitAction *g_exit_actions;
static size_t g_exit_n, g_exit_cap;
static bool g_exit_registered;

static void run_exit_actions(void) {
    /* the last registered runs first */
    while (g_exit_n) {
        ExitAction a = g_exit_actions[--g_exit_n];
        a.fn(a.ctx);
    }
}

void objcache__at_exit(void (*fn)(void *), void *ctx) {
    dk_mutex_lock(&g_exit_lock);
    if (g_exit_n == g_exit_cap) {
        g_exit_cap = g_exit_cap ? g_exit_cap * 2 : 8;
        g_exit_actions = (ExitAction *)dk_xrealloc(g_exit_actions, g_exit_cap * sizeof(ExitAction));
    }
    g_exit_actions[g_exit_n].fn = fn;
    g_exit_actions[g_exit_n].ctx = ctx;
    g_exit_n++;
    if (!g_exit_registered) {
        g_exit_registered = true;
        atexit(run_exit_actions);
    }
    dk_mutex_unlock(&g_exit_lock);
}

/* ================================================================================================ environment */

const char *objcache_cache_dir(void) {
    DkArena *a = pa();
    const char *general = dk_getenv(a, OBJCACHE_ENV_CACHE);
    DkStr value = dk_str_lower(a, dk_str_strip(dk_str(general)));
    if (lower_in_off_words(value)) return NULL;
    DkStr own_s = dk_str_strip(dk_str(general));
    if (own_s.n) return dup_n(own_s.p, own_s.n);
    const char *base = dk_getenv(a, "LOCALAPPDATA");
    if (!base || !*base) base = dk_join(a, dk_path_expanduser(a, "~"), ".cache");
    return dk_join(a, base, "decompkit-objcache");
}

const char *objcache_restore_mode(void) {
    DkArena *a = pa();
    DkStr v = dk_str_lower(a, dk_str_strip(dk_str(dk_getenv(a, OBJCACHE_ENV_RESTORE))));
    for (size_t i = 0; i < OBJCACHE_RESTORE_MODES_N; i++)
        if (dk_str_eqz(v, objcache_restore_modes[i])) return objcache_restore_modes[i];
    return "auto";
}

i64 objcache_max_mb_setting(void) {
    const char *v = dk_getenv(pa(), OBJCACHE_ENV_MAX_MB);
    if (!v) return 4096;
    i64 n;
    bool overflow = false;
    if (!dk_parse_int(dk_str(v), 10, &n, &overflow)) {
        if (overflow) return INT64_MAX >> 21; /* an int too big for 64 bits: effectively unlimited */
        return 4096;
    }
    return n;
}

/* ============================================================================================ small file helpers */

const char *objcache__digest_bytes(const void *data, size_t n) { return dk_sha256_hex(pa(), data, n); }

bool objcache__digest_file(const char *path, const char **hex) {
    char *h = dk_file_digest_hex(pa(), DK_HASH_SHA256, path);
    if (!h) return false;
    *hex = h;
    return true;
}

static char *norm_into(DkArena *a, const char *path) {
    return dk_path_normcase(a, dk_path_normpath(a, dk_path_abspath(a, path)));
}
const char *objcache__norm(const char *path) { return norm_into(pa(), path); }

bool objcache__replace(const char *src, const char *dst, int attempts) {
    for (int i = 0; i < attempts; i++) {
        if (dk_replace(src, dst)) return true;
        dk_sleep(0.05 * (double)(i + 1));
    }
    dk_remove(src);
    return false;
}

bool objcache_remove_file(const char *path) {
    if (dk_remove(path)) return true;
    return dk_io_is(ENOENT);
}

static DK_NORETURN void panic_oserror(const char *file, int line) {
    DkStr e = dk_io_err_str(pa());
    dk_panic(file, line, "%.*s", DK_SF(e));
}
#define PANIC_IO() panic_oserror(__FILE__, __LINE__)

bool objcache_write_if_changed(const char *path, const void *data, size_t n, bool touch) {
    static const char empty[1] = {0};
    if (!data) data = empty;
    i64 size;
    if (dk_getsize(path, &size) && size == (i64)n) {
        DkBytes cur = {0};
        if (dk_read_all(NULL, path, &cur)) {
            bool same = cur.n == n && (n == 0 || memcmp(cur.v, data, n) == 0);
            dk_vec_free(&cur);
            if (same) {
                if (touch) dk_utime_now(path);
                return false;
            }
        }
    }
    if (!dk_write_file(path, data, n)) PANIC_IO();
    return true;
}

bool objcache_write_text_if_changed(const char *path, DkStr text, const char *newline, bool touch) {
    DkArena *a = pa();
    if (!newline) text = dk_str_replace(a, text, DK_S("\n"), DK_S("\r\n"), -1);
    else if (strcmp(newline, "") != 0 && strcmp(newline, "\n") != 0)
        text = dk_str_replace(a, text, DK_S("\n"), dk_str(newline), -1);
    return objcache_write_if_changed(path, text.p, text.n, touch);
}

const char *objcache_version_of(const void *data, size_t n) {
    char *h = dk_sha256_hex(pa(), data, n);
    h[16] = 0;
    return h;
}

const char *objcache_file_version(const char *path) {
    DkBytes b = {0};
    if (!dk_read_all(NULL, path, &b)) PANIC_IO();
    const char *r = objcache_version_of(b.v, b.n);
    dk_vec_free(&b);
    return r;
}

static void touch(const char *path) { dk_utime_now(path); }

static bool is_hex_digest(const char *s) {
    if (!s || strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

/* ====================================================================================================== state */

typedef struct {
    i64 size, mtime_ns;
} FileMark;
typedef struct {
    DkStrVec deps, shadow;
} InputsOf;

typedef struct {
    DkMutex lock;       /* guards the maps and the counters; never held across file I/O */
    DkMap *digests;     /* norm path -> digest char* (value .p NULL = None) */
    DkMap *dep_digests; /* dep as the entry names it -> digest now */
    DkMap *shadows;     /* deps joined by "\n" -> DkStrVec* */
    DkMap *names;       /* lower basename -> DkStrVec* (built once) */
    DkMap *restored;    /* norm obj path -> blob path */
    DkMap *restored_stat;
    DkMap *inputs_of;
    DkMap *how;         /* norm folder -> "clone" | "copy" */
    u32 cluster;
    bool cluster_known;
    bool clone_checked;
    const char **roots; /* the unit roots: folders of the checkout, relative, forward slashes, no trailing slash */
    size_t nroots;
} Priv;

static Priv *priv(const ObjcacheObjCache *c) { return (Priv *)c->priv_; }

void objcache_obj_cache_set_unit_roots(ObjcacheObjCache *c, const char *const *roots, size_t n) {
    Priv *p = priv(c);
    DkArena *a = pa();
    const char **copy = (const char **)dk_alloc(a, sizeof(char *) * (n ? n : 1));
    size_t kept = 0;
    for (size_t i = 0; i < n; i++) {
        DkStr r = dk_str_replace(a, dk_str(roots[i]), DK_S("\\"), DK_S("/"), -1);
        while (r.n && r.p[r.n - 1] == '/') r.n--;
        if (r.n) copy[kept++] = dup_n(r.p, r.n);
    }
    dk_mutex_lock(&p->lock);
    p->roots = copy;
    p->nroots = kept;
    p->names = NULL; /* rebuilt from the new roots */
    dk_mutex_unlock(&p->lock);
}

/* The value slot to remember None in a digest map: a map hit with .p == NULL is "known missing". */
static const char *map_digest(DkMap *m, DkStr key, bool *found) {
    DkVal *v = dk_map_get(m, key);
    *found = v != NULL;
    return v ? (const char *)v->p : NULL;
}

/* =========================================================================================== rel / names / shadow */

static const char *rel_into(DkArena *a, const ObjcacheObjCache *c, const char *path) {
    char *p = norm_into(a, path);
    size_t rl = strlen(c->root);
    if (strncmp(p, c->root, rl) == 0 && p[rl] == '\\') {
        DkStr tail = dk_strn(p + rl + 1, strlen(p + rl + 1));
        return dk_cz(a, dk_str_replace(a, tail, DK_S("\\"), DK_S("/"), -1));
    }
    return p;
}

const char *objcache_obj_cache_rel(const ObjcacheObjCache *c, const char *path) { return rel_into(pa(), c, path); }

const char *objcache_obj_cache_absolute(const ObjcacheObjCache *c, const char *key) {
    DkArena *a = pa();
    if (dk_path_isabs(key)) return key;
    return dk_path_join(a, c->root, dk_cz(a, dk_str_replace(a, dk_str(key), DK_S("/"), DK_S("\\"), -1)));
}

static const char *absolute_into(DkArena *a, const ObjcacheObjCache *c, const char *key) {
    if (dk_path_isabs(key)) return key;
    return dk_path_join(a, c->root, dk_cz(a, dk_str_replace(a, dk_str(key), DK_S("/"), DK_S("\\"), -1)));
}

/* Adds the files under one unit root to the name map (lower-case basename -> relative paths). */
static void names_walk(DkArena *a, const ObjcacheObjCache *c, DkMap *out, const char *root_rel) {
    DkStr back = dk_str_replace(a, dk_str(root_rel), DK_S("/"), DK_S("\\"), -1);
    const char *top = dk_path_join(a, c->root, dk_cz(a, back));
    DkWalk *w = dk_walk_open(top, true);
    DkWalkItem it;
    while (dk_walk_next(w, &it)) {
        for (size_t i = 0; i < it.files.n; i++) {
            DkStr f = it.files.v[i];
            DkStr low = dk_str_lower(a, f);
            bool created;
            DkVal *slot = dk_map_put(out, low, &created);
            if (created) slot->p = DK_NEW(a, DkStrVec);
            const char *full = dk_path_join(a, it.dirpath.p, f.p);
            const char *r = rel_into(a, c, full);
            DkStr rs = {r, strlen(r)};
            dk_vec_push((DkStrVec *)slot->p, rs);
        }
    }
    dk_walk_close(w);
}

const DkMap *objcache_obj_cache_names(ObjcacheObjCache *c) {
    Priv *p = priv(c);
    dk_mutex_lock(&p->lock);
    if (!p->names) {
        DkArena *a = pa();
        DkMap *out = dk_map_new();
        for (size_t ri = 0; ri < p->nroots; ri++) names_walk(a, c, out, p->roots[ri]);
        DkMapIter mi = {0};
        while (dk_map_next(out, &mi)) {
            DkStrVec *v = (DkStrVec *)mi.val->p;
            dk_sort_strs(v->v, v->n);
        }
        p->names = out;
    }
    const DkMap *r = p->names;
    dk_mutex_unlock(&p->lock);
    return r;
}

DkStrVec objcache_obj_cache_shadow(ObjcacheObjCache *c, const char *const *deps, size_t n) {
    const DkMap *names = objcache_obj_cache_names(c);
    DkArena *a = pa();
    DkSet *seen = dk_set_new();
    for (size_t i = 0; i < n; i++) {
        DkStr k = dk_str_replace(a, dk_str(deps[i]), DK_S("/"), DK_S("\\"), -1);
        DkStr b = dk_str_lower(a, dk_path_basename(dk_cz(a, k)));
        DkVal *v = dk_map_get(names, b);
        if (!v) continue;
        const DkStrVec *l = (const DkStrVec *)v->p;
        for (size_t j = 0; j < l->n; j++) dk_set_add(seen, l->v[j]);
    }
    DkStrVec out = dk_set_sorted(seen); /* sorted */
    for (size_t i = 0; i < out.n; i++) out.v[i] = persist(out.v[i]); /* the set's own copies die with it */
    dk_set_free(seen);
    return out;
}

/* ==================================================================================================== digests */

static const char *digest_of(ObjcacheObjCache *c, const char *path) {
    Priv *p = priv(c);
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    char *key = norm_into(sc, path);
    DkStr ks = dk_str(key);
    dk_mutex_lock(&p->lock);
    bool found;
    const char *d = map_digest(p->digests, ks, &found);
    dk_mutex_unlock(&p->lock);
    if (!found) {
        const char *h;
        d = objcache__digest_file(key, &h) ? h : NULL;
        dk_mutex_lock(&p->lock);
        dk_map_put(p->digests, ks, NULL)->p = (void *)d;
        dk_mutex_unlock(&p->lock);
    }
    dk_arena_reset(sc, mk);
    return d;
}

const char *objcache_obj_cache_digest(ObjcacheObjCache *c, const char *path) { return digest_of(c, path); }

void objcache_obj_cache_rehash(ObjcacheObjCache *c, const char *path) {
    Priv *p = priv(c);
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkStr key = dk_str(norm_into(sc, path));
    dk_mutex_lock(&p->lock);
    dk_map_del(p->digests, key);
    dk_mutex_unlock(&p->lock);
    dk_arena_reset(sc, mk);
}

const char *objcache_obj_cache_digest_now(const char *path) {
    const char *h;
    return objcache__digest_file(path, &h) ? h : NULL;
}

const char *objcache_obj_cache_rooted(const ObjcacheObjCache *c, const char *key) {
    DkArena *a = pa();
    DkBuf b = {0};
    dk_buf_init(&b, a);
    dk_buf_putz(&b, key);
    dk_buf_putc(&b, '\n');
    dk_buf_putz(&b, c->root);
    return objcache__digest_bytes(b.p, b.n);
}

/* ================================================================================================ key / identity */

static void dump_open(DkBuf *b, DkJsonW *w) {
    dk_jsonw_init(w, b, NULL); /* the key texts use ", " and ": " separators and ASCII escapes */
}
static void jstr(DkJsonW *w, const char *s) {
    if (s) dk_jsonw_strz(w, s);
    else dk_jsonw_null(w);
}

const char *objcache_obj_cache_key(ObjcacheObjCache *c, const char *const *options, size_t n_options,
                                   const char *source) {
    DkArena *a = pa();
    DkRe *safe = dk_re(OBJCACHE_SAFE_OPTION_PAT, OBJCACHE_SAFE_OPTION_FLAGS);
    DkCzVec opts = {0};
    for (size_t i = 0; i < n_options; i++) {
        const char *o = options[i];
        if (!dk_re_match(safe, dk_str(o), 0, DK_END, NULL)) {
            dk_vec_free(&opts);
            return NULL;
        }
        if (o[0] == '/' && o[1] == 'I') o = dk_sprintf(a, "/I%s", rel_into(a, c, o + 2));
        dk_vec_push(&opts, (char *)o);
    }
    const char *src = digest_of(c, source);
    if (!src) {
        dk_vec_free(&opts);
        return NULL;
    }
    DkBuf b = {0};
    DkJsonW w;
    dump_open(&b, &w);
    dk_jsonw_begin_array(&w);
    dk_jsonw_i64(&w, OBJCACHE_VERSION);
    jstr(&w, c->identity);
    dk_jsonw_begin_array(&w);
    for (size_t i = 0; i < opts.n; i++) jstr(&w, opts.v[i]);
    dk_jsonw_end_array(&w);
    jstr(&w, rel_into(a, c, source));
    jstr(&w, src);
    dk_jsonw_end_array(&w);
    dk_jsonw_finish(&w);
    const char *key = objcache__digest_bytes(b.p, b.n);
    dk_buf_free(&b);
    dk_vec_free(&opts);
    return key;
}

/* ================================================================================================== entry files */

static const char *entry_path_in(DkArena *a, const ObjcacheObjCache *c, const char *key) {
    char two[3] = {key[0], key[0] ? key[1] : 0, 0};
    char name[600];
    size_t kl = strlen(key);
    if (kl + 9 >= sizeof name) kl = sizeof name - 9;
    memcpy(name, key, kl);
    memcpy(name + kl, ".entries", 9);
    return dk_join(a, c->keys, two, name);
}
const char *objcache__entry_path(const ObjcacheObjCache *c, const char *key) { return entry_path_in(pa(), c, key); }

typedef struct {
    const char *rel;
    const char *digest; /* NULL = None */
} ODep;
typedef struct {
    ODep *deps;
    size_t ndeps;
    const char **shadow;
    size_t nshadow;
    const char *obj;
    DkStr text;
    double time;
} OEntry;
typedef struct {
    OEntry *v;
    size_t n;
} OEntries;

static const char *rd_cz(DkArena *a, DkCacheReader *r) {
    DkStr s = dk_cr_str(r);
    return dk_cz(a, s);
}

/* The entries of an object key; none when the file is missing, damaged or malformed (a miss). Strings are copied
 * into `a`, so the mapping is closed before this returns. */
static OEntries read_object_entries(DkArena *a, const char *path) {
    OEntries out = {NULL, 0};
    DkCache f;
    if (!dk_cache_open(&f, path, OBJCACHE_ENTRY_KIND, ENTRY_SCHEMA, "", 0)) return out;
    DkCacheReader *r = &f.r;
    u32 count = dk_cr_count(r, 4);
    OEntry *v = (OEntry *)dk_alloc(a, sizeof(OEntry) * (count ? count : 1));
    bool good = dk_cr_ok(r);
    for (u32 i = 0; i < count && good; i++) {
        DkCacheReader rec;
        if (!dk_cr_record(r, &rec)) {
            good = false;
            break;
        }
        OEntry *e = &v[i];
        u32 nd = dk_cr_count(&rec, 4);
        e->deps = (ODep *)dk_alloc(a, sizeof(ODep) * (nd ? nd : 1));
        for (u32 j = 0; j < nd && !rec.bad; j++) {
            DkCacheReader d;
            if (!dk_cr_record(&rec, &d)) break;
            e->deps[j].rel = rd_cz(a, &d);
            const char *dg = rd_cz(a, &d);
            e->deps[j].digest = *dg ? dg : NULL;
            dk_cr_end(&rec, &d);
        }
        e->ndeps = nd;
        u32 ns = dk_cr_count(&rec, 4);
        e->shadow = (const char **)dk_alloc(a, sizeof(char *) * (ns ? ns : 1));
        for (u32 j = 0; j < ns && !rec.bad; j++) e->shadow[j] = rd_cz(a, &rec);
        e->nshadow = ns;
        e->obj = rd_cz(a, &rec);
        DkStr t = dk_cr_str(&rec);
        e->text.p = dup_n(t.p ? t.p : "", t.n);
        e->text.n = t.n;
        e->time = dk_cr_f64(&rec);
        if (rec.bad || !is_hex_digest(e->obj)) good = false;
        dk_cr_end(r, &rec);
    }
    if (!good || !dk_cr_ok(r)) {
        dk_cache_close(&f);
        return out;
    }
    dk_cache_close(&f);
    out.v = v;
    out.n = count;
    return out;
}

static void write_object_entries(const char *path, const OEntry *es, size_t n) {
    DkCacheWriter w;
    dk_cw_init(&w);
    dk_cw_count(&w, n);
    for (size_t i = 0; i < n; i++) {
        const OEntry *e = &es[i];
        size_t tok = dk_cw_begin(&w);
        dk_cw_count(&w, e->ndeps);
        for (size_t j = 0; j < e->ndeps; j++) {
            size_t dt = dk_cw_begin(&w);
            dk_cw_cz(&w, e->deps[j].rel);
            dk_cw_cz(&w, e->deps[j].digest);
            dk_cw_end(&w, dt);
        }
        dk_cw_count(&w, e->nshadow);
        for (size_t j = 0; j < e->nshadow; j++) dk_cw_cz(&w, e->shadow[j]);
        dk_cw_cz(&w, e->obj);
        dk_cw_str(&w, e->text);
        dk_cw_f64(&w, e->time);
        dk_cw_end(&w, tok);
    }
    /* A failed publish is silent: the entry is only a cache. */
    dk_cache_write_w(path, OBJCACHE_ENTRY_KIND, ENTRY_SCHEMA, NULL, 0, &w);
    dk_cw_free(&w);
}

typedef struct {
    bool present;
    const char **outputs;
    size_t nout;
    bool has_failed;
    DkStr failed;
} LEntry;

static LEntry read_link_entry(DkArena *a, const char *path) {
    LEntry out;
    memset(&out, 0, sizeof out);
    DkCache f;
    if (!dk_cache_open(&f, path, OBJCACHE_ENTRY_KIND, ENTRY_SCHEMA, "", 0)) return out;
    DkCacheReader *r = &f.r;
    u32 count = dk_cr_count(r, 4);
    if (count == 0 || !dk_cr_ok(r)) {
        dk_cache_close(&f);
        return out;
    }
    DkCacheReader rec;
    if (!dk_cr_record(r, &rec)) {
        dk_cache_close(&f);
        return out;
    }
    u32 no = dk_cr_count(&rec, 4);
    const char **outs = (const char **)dk_alloc(a, sizeof(char *) * (no ? no : 1));
    bool good = true;
    for (u32 j = 0; j < no && !rec.bad; j++) {
        outs[j] = rd_cz(a, &rec);
        if (!is_hex_digest(outs[j])) good = false;
    }
    bool has_failed = dk_cr_u8(&rec) != 0;
    DkStr fs = dk_cr_str(&rec);
    (void)dk_cr_f64(&rec);
    if (rec.bad || !good) {
        dk_cache_close(&f);
        return out;
    }
    out.present = true;
    out.outputs = outs;
    out.nout = no;
    out.has_failed = has_failed;
    out.failed.p = dup_n(fs.p ? fs.p : "", fs.n);
    out.failed.n = fs.n;
    dk_cache_close(&f);
    return out;
}

static void write_link_entry(const char *path, const char *const *digests, size_t n, const DkStr *failed,
                             double when) {
    DkCacheWriter w;
    dk_cw_init(&w);
    dk_cw_count(&w, 1);
    size_t tok = dk_cw_begin(&w);
    dk_cw_count(&w, n);
    for (size_t i = 0; i < n; i++) dk_cw_cz(&w, digests[i]);
    dk_cw_u8(&w, failed ? 1 : 0);
    dk_cw_str(&w, failed ? *failed : DK_S(""));
    dk_cw_f64(&w, when);
    dk_cw_end(&w, tok);
    dk_cache_write_w(path, OBJCACHE_ENTRY_KIND, ENTRY_SCHEMA, NULL, 0, &w);
    dk_cw_free(&w);
}

/* ============================================================================================= known / data_of */

void objcache_obj_cache_forget(ObjcacheObjCache *c, const char *obj) {
    Priv *p = priv(c);
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkStr k = dk_str(norm_into(sc, obj));
    dk_mutex_lock(&p->lock);
    dk_map_del(p->restored, k);
    dk_map_del(p->restored_stat, k);
    dk_map_del(p->inputs_of, k);
    dk_mutex_unlock(&p->lock);
    dk_arena_reset(sc, mk);
}

static DkStr blob_name(const char *blob) {
    DkStr b = dk_path_basename(blob);
    return dk_strn(b.p, b.n >= 4 ? b.n - 4 : 0);
}

const char *objcache_obj_cache_known_digest(ObjcacheObjCache *c, const char *path) {
    Priv *p = priv(c);
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    char *key = norm_into(sc, path);
    const char *result = NULL;
    dk_mutex_lock(&p->lock);
    DkVal *bv = dk_map_get(p->restored, dk_str(key));
    const char *blob = bv ? (const char *)bv->p : NULL;
    DkVal *sv = dk_map_get(p->restored_stat, dk_str(key));
    FileMark mark = sv ? *(FileMark *)sv->p : (FileMark){-1, -1};
    dk_mutex_unlock(&p->lock);
    DkStat st;
    if (blob && dk_stat(key, &st) && sv && mark.size == st.size && mark.mtime_ns == st.mtime_ns) {
        DkStr n = blob_name(blob);
        result = dup_n(n.p, n.n);
    }
    dk_arena_reset(sc, mk);
    return result;
}

bool objcache_obj_cache_data_of(ObjcacheObjCache *c, const char *obj, DkStr *data) {
    Priv *p = priv(c);
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkStr key = dk_str(norm_into(sc, obj));
    dk_mutex_lock(&p->lock);
    DkVal *bv = dk_map_get(p->restored, key);
    const char *blob = bv ? (const char *)bv->p : NULL;
    dk_mutex_unlock(&p->lock);
    dk_arena_reset(sc, mk);
    if (!blob) return false;
    DkBytes b = {0};
    if (!dk_read_all(pa(), blob, &b)) return false;
    const char *h = objcache__digest_bytes(b.v, b.n);
    DkStr want = blob_name(blob);
    if (!dk_str_eqz(want, h)) return false;
    data->p = (const char *)b.v;
    data->n = b.n;
    return true;
}

bool objcache_obj_cache_inputs_of(ObjcacheObjCache *c, const char *path, DkStrVec *deps, DkStrVec *shadow) {
    Priv *p = priv(c);
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkStr key = dk_str(norm_into(sc, path));
    dk_mutex_lock(&p->lock);
    DkVal *v = dk_map_get(p->inputs_of, key);
    bool ok = v != NULL;
    if (ok) {
        *deps = ((InputsOf *)v->p)->deps;
        *shadow = ((InputsOf *)v->p)->shadow;
    }
    dk_mutex_unlock(&p->lock);
    dk_arena_reset(sc, mk);
    return ok;
}

static void set_inputs(ObjcacheObjCache *c, const char *obj, const char *const *deps, size_t nd,
                       const char *const *shadow, size_t ns) {
    Priv *p = priv(c);
    DkArena *a = pa();
    InputsOf *io = DK_NEW(a, InputsOf);
    for (size_t i = 0; i < nd; i++) {
        DkStr s = {persist_cz(deps[i]), strlen(deps[i])};
        dk_vec_push(&io->deps, s);
    }
    for (size_t i = 0; i < ns; i++) {
        DkStr s = {persist_cz(shadow[i]), strlen(shadow[i])};
        dk_vec_push(&io->shadow, s);
    }
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkStr key = dk_str(norm_into(sc, obj));
    dk_mutex_lock(&p->lock);
    dk_map_put(p->inputs_of, key, NULL)->p = io;
    dk_mutex_unlock(&p->lock);
    dk_arena_reset(sc, mk);
}

/* ====================================================================================== putting a blob at a path */

/* How a blob is put in the folder of `path`: "clone" (one ReFS volume as the cache) or "copy". */
static const char *how_for(ObjcacheObjCache *c, const char *path, char **folder_out) {
    Priv *p = priv(c);
    DkArena *a = pa();
    char *folder = norm_into(a, dk_cz(a, dk_path_dirname(dk_path_abspath(a, path))));
    *folder_out = folder;
    dk_mutex_lock(&p->lock);
    DkVal *v = dk_map_get(p->how, dk_str(folder));
    const char *how = v ? (const char *)v->p : NULL;
    dk_mutex_unlock(&p->lock);
    if (how) return how;
    how = "copy";
    if (strcmp(c->mode, "copy") != 0) {
        u32 s1, s2;
        char *fs1, *fs2;
        if (dk_volume_info(a, c->objs, &s1, &fs1) && dk_volume_info(a, folder, &s2, &fs2) && s1 == s2 &&
            _stricmp(fs1, "REFS") == 0)
            how = "clone";
    }
    dk_mutex_lock(&p->lock);
    dk_map_put(p->how, dk_str(folder), NULL)->p = (void *)how;
    dk_mutex_unlock(&p->lock);
    return how;
}

/* place: puts the blob's bytes at `path` by a clone or a copy; false = the I/O failed (nothing is put at
 * `path`). *mark is the (size, mtime_ns) known_digest checks. */
static bool place(ObjcacheObjCache *c, const char *blob, const char *path, FileMark *mark, bool keep_same) {
    Priv *p = priv(c);
    DkArena *a = pa();
    DkStr want = dk_path_basename(blob);
    i64 dot = dk_str_rfind(want, DK_S("."), 0, DK_END);
    if (dot >= 0) want = dk_strn(want.p, (size_t)dot);
    const char *have;
    /* (keep_same, the object restore only) an object already at `path` whose bytes hash to the blob's name is the
     * result of the restore: keep it (no delete, no clone) */
    if (keep_same && dk_exists(path)) {
        DkStat st0;
        if (objcache__digest_file(path, &have) && dk_str_eqz(want, have) && dk_stat(path, &st0)) {
            mark->size = st0.size;
            mark->mtime_ns = st0.mtime_ns;
            return true;
        }
    }
    if (!objcache_remove_file(path)) return false;
    /* _verify: the blob's bytes must still hash to its name; a damaged blob is deleted. */
    if (!objcache__digest_file(blob, &have)) return false;
    if (!dk_str_eqz(want, have)) {
        dk_remove(blob);
        return false;
    }
    char *folder;
    const char *how = how_for(c, path, &folder);
    if (strcmp(how, "clone") == 0) {
        dk_mutex_lock(&p->lock);
        if (!p->cluster_known) {
            p->cluster_known = true;
            p->cluster = 0;
            dk_mutex_unlock(&p->lock);
            u32 cs = dk_cluster_size(c->objs);
            dk_mutex_lock(&p->lock);
            p->cluster = cs;
        }
        u32 cluster = p->cluster;
        dk_mutex_unlock(&p->lock);
        if (cluster && dk_file_clone(blob, path, cluster)) {
            dk_mutex_lock(&p->lock);
            bool checked = p->clone_checked;
            p->clone_checked = true;
            dk_mutex_unlock(&p->lock);
            const char *now;
            bool same = checked;
            if (!same) {
                DkStr bn = blob_name(blob);
                same = objcache__digest_file(path, &now) && dk_str_eqz(bn, now);
            }
            if (same) {
                DkStat st;
                if (!dk_stat(path, &st)) return false;
                mark->size = st.size;
                mark->mtime_ns = st.mtime_ns;
                return true;
            }
            objcache_remove_file(path);
        }
        dk_mutex_lock(&p->lock);
        dk_map_put(p->how, dk_str(folder), NULL)->p = (void *)"copy";
        dk_mutex_unlock(&p->lock);
    }
    const char *tmp = dk_sprintf(a, "%s.cache-tmp", path);
    if (!dk_copyfile(blob, tmp)) return false;
    if (!dk_replace(tmp, path)) return false;
    DkStat st;
    if (!dk_stat(path, &st)) return false;
    mark->size = st.size;
    mark->mtime_ns = st.mtime_ns;
    return true;
}

/* ===================================================================================================== lookup */

static const char *blob_path(DkArena *a, const ObjcacheObjCache *c, const char *hex, const char *ext) {
    return dk_join(a, c->objs, dk_sprintf(a, "%s%s", hex, ext));
}

bool objcache_obj_cache_lookup(ObjcacheObjCache *c, const char *key, const char *obj, DkStr *text) {
    Priv *p = priv(c);
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    const char *keys[2] = {key, objcache_obj_cache_rooted(c, key)};
    bool hit = false;
    for (int k = 0; k < 2 && !hit; k++) {
        const char *entry_path = entry_path_in(sc, c, keys[k]);
        OEntries es = read_object_entries(sc, entry_path);
        for (size_t i = 0; i < es.n && !hit; i++) {
            OEntry *e = &es.v[i];
            bool stale = false;
            for (size_t j = 0; j < e->ndeps; j++) {
                DkStr dep = dk_str(e->deps[j].rel);
                dk_mutex_lock(&p->lock);
                bool found;
                const char *have = map_digest(p->dep_digests, dep, &found);
                dk_mutex_unlock(&p->lock);
                if (!found) {
                    have = digest_of(c, absolute_into(sc, c, e->deps[j].rel));
                    dk_mutex_lock(&p->lock);
                    dk_map_put(p->dep_digests, dep, NULL)->p = (void *)have;
                    dk_mutex_unlock(&p->lock);
                }
                const char *want = e->deps[j].digest;
                if ((have == NULL) != (want == NULL) || (have && strcmp(have, want) != 0)) {
                    stale = true;
                    break;
                }
            }
            if (stale) continue;
            /* the shadow list of these dependencies, memoised by the dependency list */
            DkBuf jb = {0};
            dk_buf_init(&jb, sc);
            const char **dep_names = (const char **)dk_alloc(sc, sizeof(char *) * (e->ndeps ? e->ndeps : 1));
            for (size_t j = 0; j < e->ndeps; j++) {
                dep_names[j] = e->deps[j].rel;
                dk_buf_putz(&jb, e->deps[j].rel);
                dk_buf_putc(&jb, '\n');
            }
            DkStr jk = dk_buf_str(&jb);
            dk_mutex_lock(&p->lock);
            DkVal *sv = dk_map_get(p->shadows, jk);
            DkStrVec *shadow = sv ? (DkStrVec *)sv->p : NULL;
            dk_mutex_unlock(&p->lock);
            if (!shadow) {
                shadow = DK_NEW(pa(), DkStrVec);
                *shadow = objcache_obj_cache_shadow(c, dep_names, e->ndeps);
                dk_mutex_lock(&p->lock);
                dk_map_put(p->shadows, jk, NULL)->p = shadow;
                dk_mutex_unlock(&p->lock);
            }
            bool same = shadow->n == e->nshadow;
            for (size_t j = 0; same && j < shadow->n; j++) same = dk_str_eqz(shadow->v[j], e->shadow[j]);
            if (!same) continue;
            const char *blob = blob_path(pa(), c, e->obj, ".obj");
            FileMark mark;
            if (!place(c, blob, obj, &mark, true)) continue;
            touch(blob); /* least recently used order for the pruning: the blob and its entry */
            touch(entry_path);
            char *nobj = norm_into(sc, obj);
            FileMark *fm = DK_NEW(pa(), FileMark);
            *fm = mark;
            dk_mutex_lock(&p->lock);
            dk_map_put(p->restored, dk_str(nobj), NULL)->p = (void *)blob;
            dk_map_put(p->restored_stat, dk_str(nobj), NULL)->p = fm;
            dk_mutex_unlock(&p->lock);
            set_inputs(c, obj, dep_names, e->ndeps, e->shadow, e->nshadow);
            dk_mutex_lock(&p->lock);
            c->hits++;
            dk_mutex_unlock(&p->lock);
            *text = persist(e->text);
            hit = true;
        }
    }
    if (!hit) {
        dk_mutex_lock(&p->lock);
        c->misses++;
        dk_mutex_unlock(&p->lock);
    }
    dk_arena_reset(sc, mk);
    return hit;
}

/* ====================================================================================================== store */

static int cmp_str_p(const void *x, const void *y, void *ctx) {
    (void)ctx;
    return dk_str_cmp(*(const DkStr *)x, *(const DkStr *)y);
}

/* Writes the blob data under objs\<hex><ext> unless a sound one is there (missing, or damaged by a crash). */
static void write_blob(ObjcacheObjCache *c, const void *data, size_t n, const char *hex, const char *ext) {
    DkArena *a = pa();
    const char *blob = blob_path(a, c, hex, ext);
    if (dk_exists(blob)) {
        const char *now = objcache_obj_cache_digest_now(blob);
        if (now && strcmp(now, hex) == 0) return;
    }
    char *tmp;
    DkFile *f = dk_mkstemp(a, "tmp", ".tmp", c->objs, &tmp);
    if (!f) PANIC_IO();
    if (n && !dk_fwrite(f, data, n)) PANIC_IO();
    if (!dk_fclose(f)) PANIC_IO();
    objcache__replace(tmp, blob, 5);
}

static void make_entry_folder(const char *path) {
    DkArena *a = pa();
    DkStr dir = dk_path_dirname(path);
    if (!dk_makedirs(dk_cz(a, dir), true)) PANIC_IO();
}

static bool entry_deps_equal(const OEntry *x, const OEntry *y) {
    if (x->ndeps != y->ndeps) return false;
    for (size_t i = 0; i < x->ndeps; i++) {
        if (strcmp(x->deps[i].rel, y->deps[i].rel) != 0) return false;
        if (strcmp(x->deps[i].digest ? x->deps[i].digest : "", y->deps[i].digest ? y->deps[i].digest : "") != 0)
            return false;
    }
    return true;
}

void objcache_obj_cache_store(ObjcacheObjCache *c, const char *key, const char *obj, const char *cwd, DkStr output,
                              DkStr text) {
    Priv *p = priv(c);
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkArena *a = sc;
    DkSet *depset = dk_set_new();
    DkStrVec lines = dk_str_splitlines(output, false);
    DkStr note = DK_S(OBJCACHE_INCLUDE_NOTE);
    for (size_t i = 0; i < lines.n; i++) {
        if (!dk_str_startswith(lines.v[i], note)) continue;
        DkStr tail = dk_str_strip(dk_str_slice(lines.v[i], (i64)note.n, DK_END));
        const char *joined = dk_path_join(a, cwd, dk_cz(a, tail));
        dk_set_add(depset, dk_str(norm_into(a, joined)));
    }
    dk_vec_free(&lines);
    DkBytes data = {0};
    if (!dk_read_all(NULL, obj, &data)) {
        dk_set_free(depset);
        dk_arena_reset(sc, mk);
        return;
    }
    /* an object that names a file of the checkout (a /GL object's source path, __FILE__) depends on where the
     * checkout is: kept for this checkout only */
    DkBytes lowered = {0};
    dk_vec_reserve(&lowered, data.n + 1);
    for (size_t i = 0; i < data.n; i++) {
        u8 ch = data.v[i];
        lowered.v[i] = (ch >= 'A' && ch <= 'Z') ? (u8)(ch + 32) : ch;
    }
    lowered.n = data.n;
    DkStr lhay = {(const char *)lowered.v, lowered.n};
    DkStr root_s = dk_str(c->root);
    DkStr root_fwd = dk_str_replace(a, root_s, DK_S("\\"), DK_S("/"), -1);
    for (size_t ri = 0; ri < p->nroots; ri++) {
        DkStr back = dk_str_replace(a, dk_str(p->roots[ri]), DK_S("/"), DK_S("\\"), -1);
        DkStr form1 = dk_str_lower(a, dk_str_concat(a, dk_str_concat(a, root_s, DK_S("\\")), back));
        DkStr form2 = dk_str_lower(a, dk_str_concat(a, dk_str_concat(a, root_fwd, DK_S("/")), dk_str(p->roots[ri])));
        if (dk_str_contains(lhay, form1) || dk_str_contains(lhay, form2)) {
            key = objcache_obj_cache_rooted(c, key);
            break;
        }
    }
    dk_vec_free(&lowered);

    DkStrVec rels = {0};
    {
        size_t pos = 0;
        DkStr d;
        while (dk_set_next(depset, &pos, &d)) {
            const char *r = rel_into(a, c, d.p);
            DkStr rs = {r, strlen(r)};
            dk_vec_push(&rels, rs);
        }
    }
    dk_set_free(depset);
    dk_sort(rels.v, rels.n, sizeof(DkStr), cmp_str_p, NULL, false);
    bool outside = false;
    for (size_t i = 0; i < rels.n; i++) {
        if (dk_path_isabs(rels.v[i].p)) continue;
        bool under = false;
        for (size_t ri = 0; ri < p->nroots && !under; ri++) {
            DkStr prefix = dk_str_concat(a, dk_str(p->roots[ri]), DK_S("/"));
            under = dk_str_startswith(rels.v[i], prefix);
        }
        if (!under) outside = true;
    }
    if (outside || rels.n == 0) {
        /* a checkout file outside the unit roots is not covered by the shadow check; no included file proves
         * nothing */
        dk_mutex_lock(&p->lock);
        c->uncacheable++;
        dk_mutex_unlock(&p->lock);
        dk_vec_free(&rels);
        dk_vec_free(&data);
        dk_arena_reset(sc, mk);
        return;
    }
    OEntry entry;
    memset(&entry, 0, sizeof entry);
    entry.ndeps = rels.n;
    entry.deps = (ODep *)dk_alloc(a, sizeof(ODep) * rels.n);
    const char **relz = (const char **)dk_alloc(a, sizeof(char *) * rels.n);
    bool missing = false;
    for (size_t i = 0; i < rels.n; i++) {
        entry.deps[i].rel = rels.v[i].p;
        relz[i] = rels.v[i].p;
        entry.deps[i].digest = digest_of(c, absolute_into(a, c, rels.v[i].p));
        if (!entry.deps[i].digest) missing = true;
    }
    DkStrVec shadow = objcache_obj_cache_shadow(c, relz, rels.n);
    entry.nshadow = shadow.n;
    entry.shadow = (const char **)dk_alloc(a, sizeof(char *) * (shadow.n ? shadow.n : 1));
    for (size_t i = 0; i < shadow.n; i++) entry.shadow[i] = shadow.v[i].p;
    entry.obj = objcache__digest_bytes(data.v, data.n);
    entry.text = text;
    entry.time = dk_time();
    if (missing) {
        dk_mutex_lock(&p->lock);
        c->uncacheable++;
        dk_mutex_unlock(&p->lock);
        dk_vec_free(&shadow);
        dk_vec_free(&rels);
        dk_vec_free(&data);
        dk_arena_reset(sc, mk);
        return;
    }
    write_blob(c, data.v, data.n, entry.obj, ".obj");
    const char *path = entry_path_in(a, c, key);
    make_entry_folder(path);
    OEntries old = read_object_entries(a, path);
    OEntry *all = (OEntry *)dk_alloc(a, sizeof(OEntry) * (KEEP_ENTRIES + 1));
    size_t n = 0;
    all[n++] = entry;
    for (size_t i = 0; i < old.n && n < KEEP_ENTRIES; i++)
        if (!entry_deps_equal(&old.v[i], &entry)) all[n++] = old.v[i];
    write_object_entries(path, all, n);
    dk_mutex_lock(&p->lock);
    c->stored++;
    dk_mutex_unlock(&p->lock);
    set_inputs(c, obj, relz, rels.n, entry.shadow, entry.nshadow);
    dk_vec_free(&shadow);
    dk_vec_free(&rels);
    dk_vec_free(&data);
    dk_arena_reset(sc, mk);
}

/* ====================================================================================================== links */

const char *objcache_obj_cache_link_key(ObjcacheObjCache *c, const char *link, DkStr rsp_text,
                                        const char *const *inputs, size_t n_inputs) {
    DkBuf b = {0};
    DkJsonW w;
    dump_open(&b, &w);
    dk_jsonw_begin_array(&w);
    dk_jsonw_i64(&w, OBJCACHE_VERSION);
    jstr(&w, c->identity);
    jstr(&w, digest_of(c, link));
    dk_jsonw_str(&w, rsp_text);
    for (size_t i = 0; i < n_inputs; i++) {
        /* not memoised: the inputs are rewritten between links; an object restored from the cache and untouched
         * since is known by its blob's name without reading the copy */
        const char *known = objcache_obj_cache_known_digest(c, inputs[i]);
        if (known) {
            dk_jsonw_strz(&w, known);
            continue;
        }
        const char *h;
        if (!objcache__digest_file(inputs[i], &h)) {
            dk_jsonw_finish(&w);
            dk_buf_free(&b);
            return NULL;
        }
        dk_jsonw_strz(&w, h);
    }
    dk_jsonw_end_array(&w);
    dk_jsonw_finish(&w);
    const char *key = objcache__digest_bytes(b.p, b.n);
    dk_buf_free(&b);
    return key;
}

ObjcacheLinkResult objcache_obj_cache_link_lookup(ObjcacheObjCache *c, const char *key, const char *const *outputs,
                                                  size_t n_outputs, DkStr *failed_text) {
    Priv *p = priv(c);
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkArena *a = sc;
    const char *lk = dk_sprintf(a, "link-%s", key);
    const char *entry_path = entry_path_in(a, c, lk);
    LEntry e = read_link_entry(a, entry_path);
    ObjcacheLinkResult result = OBJCACHE_LINK_MISS;
    if (e.present && e.has_failed) {
        dk_mutex_lock(&p->lock);
        c->hits++;
        dk_mutex_unlock(&p->lock);
        if (failed_text) *failed_text = persist(e.failed);
        result = OBJCACHE_LINK_FAILED;
    } else if (e.present && e.nout == n_outputs) {
        bool ok = true;
        for (size_t i = 0; i < n_outputs && ok; i++) {
            const char *blob = blob_path(a, c, e.outputs[i], ".bin");
            FileMark mark;
            if (!place(c, blob, outputs[i], &mark, false)) ok = false;
            else touch(blob);
        }
        if (ok) {
            touch(entry_path);
            dk_mutex_lock(&p->lock);
            c->hits++;
            dk_mutex_unlock(&p->lock);
            result = OBJCACHE_LINK_HIT;
        } else {
            for (size_t i = 0; i < n_outputs; i++) objcache_remove_file(outputs[i]);
        }
    }
    dk_arena_reset(sc, mk);
    return result;
}

void objcache_obj_cache_link_store(ObjcacheObjCache *c, const char *key, const char *const *outputs, size_t n_outputs,
                                   const DkStr *failed) {
    DkArena *sc = dk_scratch();
    DkArenaMark mk = dk_arena_mark(sc);
    DkArena *a = sc;
    const char **digests = (const char **)dk_alloc(a, sizeof(char *) * (n_outputs ? n_outputs : 1));
    for (size_t i = 0; i < n_outputs; i++) {
        DkBytes data = {0};
        if (!dk_read_all(NULL, outputs[i], &data)) {
            dk_arena_reset(sc, mk);
            return;
        }
        digests[i] = objcache__digest_bytes(data.v, data.n);
        write_blob(c, data.v, data.n, digests[i], ".bin");
        dk_vec_free(&data);
    }
    const char *path = entry_path_in(a, c, dk_sprintf(a, "link-%s", key));
    make_entry_folder(path);
    write_link_entry(path, digests, n_outputs, failed, dk_time());
    dk_arena_reset(sc, mk);
}

/* ====================================================================================================== prune */

typedef struct {
    double mtime;
    i64 size;
    char *path;
} PruneFile;

static int cmp_prune(const void *x, const void *y, void *ctx) {
    (void)ctx;
    const PruneFile *a = (const PruneFile *)x, *b = (const PruneFile *)y;
    if (a->mtime != b->mtime) return a->mtime < b->mtime ? -1 : 1;
    if (a->size != b->size) return a->size < b->size ? -1 : 1;
    return strcmp(a->path, b->path);
}

/* a file's modification time in seconds from its nanoseconds: sec + nsec * 1e-9. */
static double mtime_of(i64 ns) {
    i64 sec = ns / 1000000000, nsec = ns % 1000000000;
    if (nsec < 0) {
        nsec += 1000000000;
        sec -= 1;
    }
    return (double)sec + (double)nsec * 1e-9;
}

bool objcache_obj_cache_prune(ObjcacheObjCache *c, i64 max_mb, bool force, ObjcachePruneResult *out) {
    if (max_mb == OBJCACHE_MAX_MB_DEFAULT) max_mb = objcache_max_mb_setting();
    DkArena *a = dk_arena_new(0);
    bool result = false;
    const char *stamp = dk_join(a, c->folder, "pruned");
    if (!force) {
        double mt;
        if (dk_getmtime(stamp, &mt) && dk_time() - mt < SECONDS_PER_HOUR) goto done;
    }
    if (!dk_write_file(stamp, "", 0)) goto done;
    {
        double now = dk_time();
        i64 deleted = 0;
        struct {
            PruneFile *v;
            size_t n, cap;
        } files = {0};
        DkStrVec folders = {0};
        DkStr s;
        s = dk_str(c->objs);
        dk_vec_push(&folders, s);
        s = dk_str(c->folder);
        dk_vec_push(&folders, s);
        DkDirEntries ks;
        if (dk_scandir(a, c->keys, &ks)) {
            for (size_t i = 0; i < ks.n; i++)
                if (ks.v[i].is_dir) dk_vec_push(&folders, ks.v[i].path);
            dk_vec_free(&ks);
        }
        for (size_t fi = 0; fi < folders.n; fi++) {
            DkDirEntries es;
            if (!dk_scandir(a, folders.v[fi].p, &es)) continue;
            bool top = fi == 1;
            for (size_t i = 0; i < es.n; i++) {
                DkDirEntry *e = &es.v[i];
                if (!e->is_file) continue;
                if (dk_str_endswith(e->name, DK_S(".tmp"))) {
                    if (now - mtime_of(e->mtime_ns) > SECONDS_PER_HOUR) deleted += dk_remove(e->path.p) ? 1 : 0;
                    continue;
                }
                if (top && !dk_str_endswith(e->name, DK_S(".memo"))) continue; /* the stamp and anything else */
                PruneFile pf = {mtime_of(e->mtime_ns), e->size, (char *)e->path.p};
                dk_vec_push(&files, pf);
            }
            dk_vec_free(&es);
        }
        i64 total = 0;
        for (size_t i = 0; i < files.n; i++) total += files.v[i].size;
        i64 before = total;
        i64 limit = max_mb > (INT64_MAX >> 20) ? INT64_MAX : max_mb * ((i64)1 << 20);
        dk_sort(files.v, files.n, sizeof(PruneFile), cmp_prune, NULL, false);
        for (size_t i = 0; i < files.n; i++) {
            if (total <= limit) break;
            if (now - files.v[i].mtime < objcache_prune_min_age) break; /* every file after it is younger still */
            if (dk_remove(files.v[i].path)) {
                total -= files.v[i].size;
                deleted++;
            }
        }
        dk_vec_free(&files);
        dk_vec_free(&folders);
        out->deleted = deleted;
        out->before = before;
        out->after = total;
        out->limit = limit;
        result = true;
    }
done:
    dk_arena_free(a);
    return result;
}

const char *objcache_obj_cache_summary(const ObjcacheObjCache *c) {
    DkArena *a = pa();
    DkStr nc = c->uncacheable > 0 ? dk_pyfmt(a, ", %d not cacheable", c->uncacheable) : DK_S("");
    DkStr s = dk_pyfmt(a, "object cache: %d reused, %d compiled%S", c->hits, c->misses, &nc);
    return s.p;
}

/* ====================================================================================== construction */

ObjcacheObjCache *objcache_obj_cache_new_with(const char *root, const char *folder, const char *compiler_bin,
                                              const char *include_env, const char *compiler_version,
                                              const char **err) {
    DkArena *a = pa();
    ObjcacheObjCache *c = DK_NEW(a, ObjcacheObjCache);
    Priv *p = DK_NEW(a, Priv);
    c->priv_ = p;
    p->digests = dk_map_new();
    p->dep_digests = dk_map_new();
    p->shadows = dk_map_new();
    p->restored = dk_map_new();
    p->restored_stat = dk_map_new();
    p->inputs_of = dk_map_new();
    p->how = dk_map_new();
    c->root = norm_into(a, root);
    c->folder = dk_join(a, folder, dk_sprintf(a, "v%d", OBJCACHE_VERSION));
    c->objs = dk_join(a, c->folder, "objs");
    c->keys = dk_join(a, c->folder, "keys");
    if (!dk_makedirs(c->objs, true) || !dk_makedirs(c->keys, true)) {
        if (err) *err = dk_cz(a, dk_io_err_str(a));
        return NULL;
    }
    c->mode = objcache_restore_mode();
    {
        static const char *const default_roots[1] = {OBJCACHE_DEFAULT_UNIT_ROOT};
        objcache_obj_cache_set_unit_roots(c, default_roots, 1);
    }
    c->include_env = include_env ? include_env : "";

    DkStrVec listing = {0};
    DkStrVec dirs = dk_str_split(dk_str(c->include_env), DK_S(";"), -1);
    for (size_t di = 0; di < dirs.n; di++) {
        const char *d = dk_cz(a, dirs.v[di]);
        if (!*d) continue; /* an empty folder name lists nothing */
        DkWalk *w = dk_walk_open(d, true);
        DkWalkItem it;
        while (dk_walk_next(w, &it)) {
            dk_sort_strs(it.dirs.v, it.dirs.n); /* ds.sort() */
            dk_sort_strs(it.files.v, it.files.n);
            for (size_t i = 0; i < it.files.n; i++) {
                const char *full = dk_path_join(a, it.dirpath.p, it.files.v[i].p);
                char *rel;
                if (!dk_path_relpath(a, full, d, &rel)) continue;
                dk_vec_push(&listing, dk_str_lower(a, dk_str(rel)));
            }
        }
        dk_walk_close(w);
    }
    dk_vec_free(&dirs);

    DkBuf b = {0};
    DkJsonW w;
    dump_open(&b, &w);
    dk_jsonw_begin_array(&w);
    dk_jsonw_begin_array(&w);
    jstr(&w, compiler_version ? compiler_version : "");
    {
        const char *path = compiler_bin ? compiler_bin : "";
        jstr(&w, *path && dk_isfile(path) ? digest_of(c, path) : NULL);
    }
    dk_jsonw_end_array(&w);
    dk_jsonw_str(&w, dk_str_lower(a, dk_str(c->include_env)));
    dk_jsonw_begin_array(&w);
    for (size_t i = 0; i < listing.n; i++) dk_jsonw_str(&w, listing.v[i]);
    dk_jsonw_end_array(&w);
    dk_jsonw_end_array(&w);
    dk_jsonw_finish(&w);
    c->identity = objcache__digest_bytes(b.p, b.n);
    dk_buf_free(&b);
    dk_vec_free(&listing);
    return c;
}

/* ===================================================================================== the exit-time prune */

static DkMutex g_prune_lock;
static DkSet *g_prune_registered;

static void prune_run(void *ctx) {
    ObjcacheObjCache *c = (ObjcacheObjCache *)ctx;
    ObjcachePruneResult r;
    if (!objcache_obj_cache_prune(c, OBJCACHE_MAX_MB_DEFAULT, false, &r)) return;
    if (r.deleted) {
        DkStr s = dk_pyfmt(pa(), "object cache: pruned %d file(s), %.1f GB -> %.1f GB (limit %.1f GB)\n", r.deleted,
                             (double)r.before / 1073741824.0, (double)r.after / 1073741824.0,
                             (double)r.limit / 1073741824.0);
        fputs(s.p, stderr);
    }
}

void objcache__prune_at_exit(ObjcacheObjCache *c) {
    dk_mutex_lock(&g_prune_lock);
    if (!g_prune_registered) g_prune_registered = dk_set_new();
    bool fresh = dk_set_add(g_prune_registered, dk_str(c->folder));
    dk_mutex_unlock(&g_prune_lock);
    if (fresh) objcache__at_exit(prune_run, c);
}

/* =================================================================================================== PickleMemo */

typedef struct {
    DkStr value;
    bool used, dirty;
} MemoVal;

struct ObjcachePickleMemo {
    DkMutex lock;
    char *name, *version, *stamp, *path; /* path NULL: the cache is off */
    size_t limit;
    bool loaded;
    DkMap *entries;
    DkArena *values; /* every value ever stored; never freed or moved */
};

ObjcachePickleMemo *objcache_pickle_memo_new(const char *name, const char *version) {
    DkArena *a = pa();
    ObjcachePickleMemo *m = DK_NEW(a, ObjcachePickleMemo);
    m->name = (char *)persist_cz(name);
    m->version = (char *)persist_cz(version);
    m->stamp = dk_sprintf(a, "%s-%s", name, version);
    m->limit = OBJCACHE_PICKLE_MEMO_LIMIT;
    const char *folder = objcache_cache_dir();
    m->path = folder ? (char *)dk_join(a, folder, dk_sprintf(a, "v%d", OBJCACHE_VERSION),
                                        dk_sprintf(a, "%s-%s.memo", name, version))
                     : NULL;
    return m;
}

const char *objcache_pickle_memo_path(const ObjcachePickleMemo *m) { return m->path; }
void objcache_pickle_memo_set_limit(ObjcachePickleMemo *m, size_t limit) { m->limit = limit; }

static DkStr memo_copy(ObjcachePickleMemo *m, DkStr v) {
    char *p = (char *)dk_alloc_noz(m->values, v.n + 1);
    if (v.n) memcpy(p, v.p, v.n);
    p[v.n] = 0;
    DkStr r = {p, v.n};
    return r;
}

/* Replays the log into the table: later records win. With keep_ours, a key this process already has is left alone
 * (the save-time merge of other processes' appends). */
static void memo_replay(ObjcachePickleMemo *m, bool keep_ours) {
    DkLog l;
    if (!dk_log_open(&l, m->path, OBJCACHE_MEMO_KIND, MEMO_SCHEMA, m->stamp, strlen(m->stamp))) return;
    DkCacheReader body;
    while (dk_log_next(&l, &body)) {
        DkStr k = dk_cr_str(&body);
        DkStr v = dk_cr_str(&body);
        if (!dk_cr_ok(&body)) continue; /* a record of another layout: skipped */
        bool created;
        DkVal *slot = dk_map_put(m->entries, k, &created);
        if (!created && (keep_ours || (slot->p && ((MemoVal *)slot->p)->dirty))) continue;
        MemoVal *mv = created ? DK_NEW(m->values, MemoVal) : (MemoVal *)slot->p;
        if (!created && !mv) mv = DK_NEW(m->values, MemoVal);
        mv->value = memo_copy(m, v);
        slot->p = mv;
    }
    dk_log_close(&l);
}

static void memo_save_exit(void *ctx) { objcache_pickle_memo_save((ObjcachePickleMemo *)ctx); }

static void memo_load_locked(ObjcachePickleMemo *m) {
    if (m->loaded) return;
    m->loaded = true;
    m->entries = dk_map_new();
    m->values = dk_arena_new(0);
    if (m->path) {
        memo_replay(m, false);
        objcache__at_exit(memo_save_exit, m);
    }
}

bool objcache_pickle_memo_get(ObjcachePickleMemo *m, DkStr key, DkStr *value) {
    dk_mutex_lock(&m->lock);
    memo_load_locked(m);
    DkVal *v = dk_map_get(m->entries, key);
    bool found = v != NULL;
    if (found) {
        MemoVal *mv = (MemoVal *)v->p;
        mv->used = true;
        *value = mv->value;
    }
    dk_mutex_unlock(&m->lock);
    return found;
}

void objcache_pickle_memo_put(ObjcachePickleMemo *m, DkStr key, DkStr value) {
    dk_mutex_lock(&m->lock);
    memo_load_locked(m);
    DkVal *slot = dk_map_put(m->entries, key, NULL);
    MemoVal *mv = DK_NEW(m->values, MemoVal);
    mv->value = memo_copy(m, value);
    mv->used = mv->dirty = true;
    slot->p = mv;
    dk_mutex_unlock(&m->lock);
}

static DkMutex g_memo_create_lock;

void objcache_pickle_memo_save(ObjcachePickleMemo *m) {
    dk_mutex_lock(&m->lock);
    if (!m->loaded || !m->path) {
        dk_mutex_unlock(&m->lock);
        return;
    }
    bool any = false;
    DkMapIter it = {0};
    while (!any && dk_map_next(m->entries, &it))
        if (((MemoVal *)it.val->p)->dirty) any = true;
    if (!any) {
        dk_mutex_unlock(&m->lock);
        return;
    }
    DkArena *a = pa();
    const char *dir = dk_cz(a, dk_path_dirname(m->path));
    dk_makedirs(dir, true);
    size_t stamp_n = strlen(m->stamp);
    DkCacheWriter w;
    dk_cw_init(&w);
    if (m->limit < dk_map_len(m->entries)) {
        /* merge what other processes appended since the load, then compact if the table is over the limit */
        memo_replay(m, true);
    }
    if (dk_map_len(m->entries) > m->limit) {
        /* only the keys this process used survive: written to a new log that replaces the file atomically */
        DkBytes frames = {0};
        DkMapIter j = {0};
        while (dk_map_next(m->entries, &j)) {
            MemoVal *mv = (MemoVal *)j.val->p;
            if (!mv->used) continue;
            dk_cw_clear(&w);
            dk_cw_str(&w, j.key);
            dk_cw_str(&w, mv->value);
            dk_log_frame(&frames, w.b.v, w.b.n);
            mv->dirty = false;
        }
        dk_log_write_file(m->path, OBJCACHE_MEMO_KIND, MEMO_SCHEMA, m->stamp, stamp_n, frames.v, frames.n);
        dk_vec_free(&frames);
    } else {
        DkLogAppender ap;
        /* A missing log is created here, under a process-wide lock: dk_log_append_open would create it from every
         * thread that finds it missing, and each creation replaces the file and drops the records appended to the
         * one before. (Two processes that both find it missing can still do that once: the cache loses the first few
         * answers, never a wrong one.) */
        dk_mutex_lock(&g_memo_create_lock);
        if (!dk_exists(m->path))
            dk_log_write_file(m->path, OBJCACHE_MEMO_KIND, MEMO_SCHEMA, m->stamp, stamp_n, NULL, 0);
        dk_mutex_unlock(&g_memo_create_lock);
        if (dk_log_append_open(&ap, m->path, OBJCACHE_MEMO_KIND, MEMO_SCHEMA, m->stamp, stamp_n)) {
            DkMapIter j = {0};
            while (dk_map_next(m->entries, &j)) {
                MemoVal *mv = (MemoVal *)j.val->p;
                if (!mv->dirty) continue;
                dk_cw_clear(&w);
                dk_cw_str(&w, j.key);
                dk_cw_str(&w, mv->value);
                if (dk_log_append(&ap, w.b.v, w.b.n)) mv->dirty = false;
            }
            dk_log_append_close(&ap);
        }
    }
    dk_cw_free(&w);
    dk_mutex_unlock(&m->lock);
}

/* ---- typed helpers ---- */

enum { TAG_STR = 's', TAG_STRS = 'S', TAG_I64 = 'i', TAG_BOOL = 'b', TAG_U32S = 'U' };

void objcache_pickle_memo_put_str(ObjcachePickleMemo *m, DkStr key, DkStr value) {
    DkCacheWriter w;
    dk_cw_init(&w);
    dk_cw_u8(&w, TAG_STR);
    dk_cw_str(&w, value);
    objcache_pickle_memo_put(m, key, dk_strn((const char *)w.b.v, w.b.n));
    dk_cw_free(&w);
}

/* A blob of the given tag as a reader positioned after the tag; false for another tag. */
static bool open_tagged(ObjcachePickleMemo *m, DkStr key, int tag, DkCacheReader *r) {
    DkStr v;
    if (!objcache_pickle_memo_get(m, key, &v)) return false;
    dk_cr_init(r, v.p, v.n);
    return dk_cr_u8(r) == tag && dk_cr_ok(r);
}
static bool finished(const DkCacheReader *r) { return dk_cr_ok(r) && dk_cr_remaining(r) == 0; }

bool objcache_pickle_memo_get_str(ObjcachePickleMemo *m, DkStr key, DkStr *value) {
    DkCacheReader r;
    if (!open_tagged(m, key, TAG_STR, &r)) return false;
    DkStr s = dk_cr_str(&r);
    if (!finished(&r)) return false;
    *value = s;
    return true;
}

void objcache_pickle_memo_put_strs(ObjcachePickleMemo *m, DkStr key, const DkStr *values, size_t n) {
    DkCacheWriter w;
    dk_cw_init(&w);
    dk_cw_u8(&w, TAG_STRS);
    dk_cw_count(&w, n);
    for (size_t i = 0; i < n; i++) dk_cw_str(&w, values[i]);
    objcache_pickle_memo_put(m, key, dk_strn((const char *)w.b.v, w.b.n));
    dk_cw_free(&w);
}

bool objcache_pickle_memo_get_strs(ObjcachePickleMemo *m, DkStr key, DkStrVec *values) {
    DkCacheReader r;
    if (!open_tagged(m, key, TAG_STRS, &r)) return false;
    u32 n = dk_cr_count(&r, 4);
    DkStrVec out = {0};
    for (u32 i = 0; i < n && dk_cr_ok(&r); i++) dk_vec_push(&out, dk_cr_str(&r));
    if (!finished(&r)) {
        dk_vec_free(&out);
        return false;
    }
    *values = out;
    return true;
}

void objcache_pickle_memo_put_i64(ObjcachePickleMemo *m, DkStr key, i64 value) {
    DkCacheWriter w;
    dk_cw_init(&w);
    dk_cw_u8(&w, TAG_I64);
    dk_cw_i64(&w, value);
    objcache_pickle_memo_put(m, key, dk_strn((const char *)w.b.v, w.b.n));
    dk_cw_free(&w);
}

bool objcache_pickle_memo_get_i64(ObjcachePickleMemo *m, DkStr key, i64 *value) {
    DkCacheReader r;
    if (!open_tagged(m, key, TAG_I64, &r)) return false;
    i64 v = dk_cr_i64(&r);
    if (!finished(&r)) return false;
    *value = v;
    return true;
}

void objcache_pickle_memo_put_bool(ObjcachePickleMemo *m, DkStr key, bool value) {
    DkCacheWriter w;
    dk_cw_init(&w);
    dk_cw_u8(&w, TAG_BOOL);
    dk_cw_bool(&w, value);
    objcache_pickle_memo_put(m, key, dk_strn((const char *)w.b.v, w.b.n));
    dk_cw_free(&w);
}

bool objcache_pickle_memo_get_bool(ObjcachePickleMemo *m, DkStr key, bool *value) {
    DkCacheReader r;
    if (!open_tagged(m, key, TAG_BOOL, &r)) return false;
    bool v = dk_cr_bool(&r);
    if (!finished(&r)) return false;
    *value = v;
    return true;
}

void objcache_pickle_memo_put_u32s(ObjcachePickleMemo *m, DkStr key, const u32 *values, size_t n) {
    DkCacheWriter w;
    dk_cw_init(&w);
    dk_cw_u8(&w, TAG_U32S);
    dk_cw_count(&w, n);
    for (size_t i = 0; i < n; i++) dk_cw_u32(&w, values[i]);
    objcache_pickle_memo_put(m, key, dk_strn((const char *)w.b.v, w.b.n));
    dk_cw_free(&w);
}

bool objcache_pickle_memo_get_u32s(ObjcachePickleMemo *m, DkStr key, DkU32Vec *values) {
    DkCacheReader r;
    if (!open_tagged(m, key, TAG_U32S, &r)) return false;
    u32 n = dk_cr_count(&r, 4);
    DkU32Vec out = {0};
    for (u32 i = 0; i < n && dk_cr_ok(&r); i++) dk_vec_push(&out, dk_cr_u32(&r));
    if (!finished(&r)) {
        dk_vec_free(&out);
        return false;
    }
    *values = out;
    return true;
}

/* ================================================================================================== command line */

static void sizes_of(const char *const *folders, size_t nf, bool memo_only, i64 *n, i64 *size) {
    DkArena *a = dk_arena_new(0);
    *n = *size = 0;
    for (size_t i = 0; i < nf; i++) {
        DkDirEntries es;
        if (!dk_scandir(a, folders[i], &es)) continue;
        for (size_t j = 0; j < es.n; j++) {
            if (!es.v[j].is_file) continue;
            if (memo_only && !dk_str_endswith(es.v[j].name, DK_S(".memo"))) continue;
            (*n)++;
            *size += es.v[j].size;
        }
        dk_vec_free(&es);
    }
    dk_arena_free(a);
}

int objcache_main(int argc, char **argv) {
    DkArena *a = pa();
    char **av = (char **)dk_alloc(a, sizeof(char *) * (size_t)(argc + 2));
    av[0] = "objcache.exe";
    for (int i = 0; i < argc; i++) av[i + 1] = argv[i];
    static const char *const commands[] = {"status", "prune", NULL};
    DkArgParser *parser = dk_args_parser(
        NULL, &(DkArgParserDesc){.prog = "objcache.exe",
                                  .description = "The object cache's size: `status` prints it, `prune` deletes the "
                                                 "least recently used files past the limit now (every tool that "
                                                 "opens the cache also prunes it at exit, at most once an hour)."});
    dk_arg(parser, &(DkArgDesc){.names = "command", .choices = commands});
    dk_arg(parser, &(DkArgDesc){.names = "--max-mb", .type = DK_T_INT, .dflt = DK_DEF_NONE,
                                  .help = "the limit (default DECOMPKIT_OBJ_CACHE_MAX_MB, else 4096)"});
    DkArgs *args = dk_args_parse(parser, argc + 1, av);
    const char *folder = objcache_cache_dir();
    if (!folder) {
        dk_pyprintf("object cache: off (DECOMPKIT_OBJ_CACHE)\n");
        return 0;
    }
    const char *err = NULL;
    ObjcacheObjCache *c = objcache_obj_cache_new_with(dk_getcwd(a), folder, "", "", "", &err);
    if (!c) dk_panic(__FILE__, __LINE__, "%s", err);
    bool has_max = !dk_args_is_none(args, "max_mb");
    i64 max_mb = has_max ? dk_args_int(args, "max_mb") : OBJCACHE_MAX_MB_DEFAULT;
    if (dk_str_eqz(dk_args_str(args, "command"), "prune")) {
        ObjcachePruneResult r;
        if (!objcache_obj_cache_prune(c, max_mb, true, &r))
            dk_panic(__FILE__, __LINE__, "cannot write the prune stamp");
        dk_pyprintf("object cache %s: pruned %d file(s), %.1f GB -> %.1f GB (limit %.1f GB)\n", c->folder, r.deleted,
                     (double)r.before / 1073741824.0, (double)r.after / 1073741824.0,
                     (double)r.limit / 1073741824.0);
        return 0;
    }
    i64 limit_mb = has_max ? max_mb : objcache_max_mb_setting();
    double limit = (double)(limit_mb * ((i64)1 << 20));
    struct {
        const char *name;
        i64 n, size;
    } sizes[3] = {{"objs", 0, 0}, {"keys", 0, 0}, {"pickles", 0, 0}};
    {
        const char *objs[1] = {c->objs};
        sizes_of(objs, 1, false, &sizes[0].n, &sizes[0].size);
        DkDirEntries ks;
        DkArena *ta = dk_arena_new(0);
        DkCzVec kf = {0};
        if (dk_scandir(ta, c->keys, &ks)) {
            for (size_t i = 0; i < ks.n; i++)
                if (ks.v[i].is_dir) dk_vec_push(&kf, (char *)ks.v[i].path.p);
            dk_vec_free(&ks);
        }
        sizes_of((const char *const *)kf.v, kf.n, false, &sizes[1].n, &sizes[1].size);
        dk_vec_free(&kf);
        dk_arena_free(ta);
        const char *top[1] = {c->folder};
        sizes_of(top, 1, true, &sizes[2].n, &sizes[2].size);
    }
    i64 total = sizes[0].size + sizes[1].size + sizes[2].size;
    DkStr last = DK_S("never");
    double mt;
    if (dk_getmtime(dk_join(a, c->folder, "pruned"), &mt)) {
        DkTm tm;
        DkStr text;
        if (dk_localtime(mt, &tm) && dk_strftime(a, "%Y-%m-%d %H:%M", &tm, &text)) last = text;
    }
    DkBuf parts = {0};
    dk_buf_init(&parts, a);
    for (int i = 0; i < 3; i++) {
        if (i) dk_buf_putz(&parts, ", ");
        dk_buf_pyfmt(&parts, "%s %d files %.1f GB", sizes[i].name, sizes[i].n, (double)sizes[i].size / 1073741824.0);
    }
    DkStr ps = dk_buf_str(&parts);
    dk_pyprintf("object cache %s: %.1f GB of %.1f GB (%S); last pruned %S\n", c->folder,
                 (double)total / 1073741824.0, limit / 1073741824.0, &ps, &last);
    return 0;
}
