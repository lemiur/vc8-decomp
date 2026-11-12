// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The backends: how a unit's candidate functions are obtained (docs/c-toolkit-design.md section 5.4).
 *
 *   object    cl with the compiler's flags, the unit's options and the target's defines; each function cut from the
 *             COFF object (symbol value to the next function symbol of its section, or the section's end), with the
 *             object's relocations. Cached by objcache when the build options ask for it.
 *   link      the unit compiled with its /GL setting (and, with discovery_compile, once more with /GL- to learn the
 *             symbols the annotations bind to: the link roots), linked with the configured argv; each root found in
 *             the linker map and read from the linked image up to the next map symbol of its section (an unverified
 *             boundary: it may include padding). Relocations come from the image's base relocations and its rel32
 *             branches, named through the map. The unit's link_with sources are compiled too (each with its own
 *             unit options when it is a unit, and its /GL setting) and linked after it, in path order, with their
 *             link_flags; the unit's link_roots are added to the roots.
 *   manifest  the candidates of a build manifest ({"candidates": [{symbol, retail_va, candidate_va, size, image_path,
 *             source_path?, map_path?}], "artifacts": [{path, kind}]}), written by the configured command or read
 *             from the configured path; relocations as for link.
 *
 * Every function built here is registered with its build (an object or a linked image) so that the comparison can
 * read the compiler-made data it points at (dk__build_content). */
#include "dk/dk.h"
#include "objcache.h"
#include "project_backend.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>

enum { COFF_WEAK_EXTERNAL = 105, COFF_EXTERNAL = 2, COFF_STATIC = 3 };
enum { BUILD_OBJECT = 1, BUILD_LINKED = 2 };
#define COMPILE_TIMEOUT 900.0

typedef struct {
    const char *name;
    u32 va;
    u32 seg;
} MapSym;

typedef struct {
    int kind;
    DkArena *a;
    /* object */
    DkCoff *coff;
    DkMap *by_name; /* object: name -> symbol index (first definition); linked: name -> MapSym index */
    /* linked */
    DkImage *img;
    MapSym *map;   /* sorted by va */
    size_t nmap;
} BuildCtx;

typedef struct {
    BuildCtx *ctx;
    size_t n;
    const char *symbol;
    i32 section; /* object: the function's section number */
    u32 value;   /* object: its offset in the section */
    u32 va;      /* linked */
} FnEntry;

/* ---- the registry of built functions (keyed by the code buffer, which this file allocates) ----------------------- */
static SRWLOCK g_reg_lock = SRWLOCK_INIT;
static DkIMap *g_reg;

static void register_fn(const DkFunc *fn, BuildCtx *ctx, i32 section, u32 value) {
    FnEntry *e = (FnEntry *)dk_xmalloc(sizeof *e);
    e->ctx = ctx;
    e->n = fn->code.n;
    e->symbol = fn->symbol;
    e->section = section;
    e->value = value;
    e->va = fn->va;
    AcquireSRWLockExclusive(&g_reg_lock);
    if (!g_reg) g_reg = dk_imap_new();
    bool created = false;
    DkVal *v = dk_imap_put(g_reg, (u64)(uintptr_t)fn->code.p, &created);
    if (!created) dk_xfree(v->p);
    v->p = e;
    ReleaseSRWLockExclusive(&g_reg_lock);
}

static const FnEntry *entry_of(const DkFunc *fn) {
    if (!fn || !fn->code.p) return NULL;
    const FnEntry *e = NULL;
    AcquireSRWLockShared(&g_reg_lock);
    if (g_reg) {
        const DkVal *v = dk_imap_get(g_reg, (u64)(uintptr_t)fn->code.p);
        if (v) e = (const FnEntry *)v->p;
    }
    ReleaseSRWLockShared(&g_reg_lock);
    if (e && (e->n != fn->code.n || e->symbol != fn->symbol)) return NULL;
    return e;
}

/* ---- small helpers ----------------------------------------------------------------------------------------------- */
static char *fwd(DkArena *a, const char *path) {
    char *s = dk_strdup(a, path);
    for (char *c = s; *c; c++)
        if (*c == '\\') *c = '/';
    return s;
}

static DkStr copy_bytes(DkArena *a, const void *p, size_t n) {
    char *b = (char *)dk_alloc(a, n);
    if (n) memcpy(b, p, n);
    return (DkStr){b, n};
}

static int cmp_reloc(const void *x, const void *y) {
    const DkReloc *a = (const DkReloc *)x, *b = (const DkReloc *)y;
    return a->offset < b->offset ? -1 : a->offset > b->offset;
}

static bool is_c_unit(const char *path) {
    size_t n = strlen(path);
    return n >= 2 && _stricmp(path + n - 2, ".c") == 0;
}

/* A file name for a unit's outputs: its path with separators and dots replaced. */
static const char *unit_stem(DkArena *a, const DkUnit *u) {
    char *s = dk_strdup(a, u->path);
    for (char *c = s; *c; c++)
        if (*c == '/' || *c == '\\' || *c == '.' || *c == ':') *c = '_';
    return s;
}

static const char *first_error_line(DkArena *a, DkStr log) {
    DkStrVec lines = dk_str_splitlines(log, false);
    const char *first = NULL;
    for (size_t i = 0; i < lines.n; i++) {
        DkStr l = dk_str_strip(lines.v[i]);
        if (!l.n) continue;
        if (dk_str_find(l, DK_S("error"), 0, DK_END) >= 0) {
            first = dk_cz(a, l);
            break;
        }
        if (!first) first = dk_cz(a, l);
    }
    dk_vec_free(&lines);
    return first ? first : "no output";
}

static void log_append(DkArena *a, DkStr *log, DkStr text) {
    if (!log || !text.n) return;
    *log = log->n ? dk_str_concat(a, dk_str_concat(a, *log, DK_S("\n")), text) : dk_str_concat(a, text, DK_S(""));
}

/* The child environment of a compiler: the current one, the compiler's env and its path_prepend folders. */
static DkEnv *tool_env(DkArena *a, const DkCompiler *c) {
    DkEnv *env = dk_env_current(a);
    for (size_t i = 0; i < c->env_names.n && i < c->env_values.n; i++)
        dk_env_set(env, c->env_names.v[i].p, c->env_values.v[i].p);
    if (c->path_prepend.n) {
        const char *name = dk_env_get(env, "PATH") ? "PATH" : dk_env_get(env, "Path") ? "Path" : "PATH";
        const char *old = dk_env_get(env, name);
        DkStr joined = dk_str_join(a, DK_S(";"), c->path_prepend.v, c->path_prepend.n);
        if (old && *old) joined = dk_str_concat(a, dk_str_concat(a, joined, DK_S(";")), dk_str(old));
        dk_env_set(env, name, dk_cz(a, joined));
    }
    return env;
}

/* ---- compiling --------------------------------------------------------------------------------------------------- */
typedef struct {
    const DkCompiler *c;
    ObjcacheObjCache *cache;
} CacheSlot;
static SRWLOCK g_cache_lock = SRWLOCK_INIT;
static DkIMap *g_caches; /* DkCompiler* -> ObjcacheObjCache* (NULL: the cache is off) */

static ObjcacheObjCache *cache_for(DkProject *p, int target) {
    const DkCompiler *c = dk_project_compiler(p, target);
    AcquireSRWLockExclusive(&g_cache_lock);
    if (!g_caches) g_caches = dk_imap_new();
    bool created = false;
    DkVal *v = dk_imap_put(g_caches, (u64)(uintptr_t)c, &created);
    if (created) v->p = objcache_open_project(p, target, true);
    ObjcacheObjCache *cache = (ObjcacheObjCache *)v->p;
    ReleaseSRWLockExclusive(&g_cache_lock);
    return cache;
}

typedef enum { GL_NONE = -1, GL_OFF = 0, GL_ON = 1 } GlMode;

/* The unit's compile options (everything between cl and /Fo). */
static DkCzVec compile_options(DkArena *a, DkProject *p, const DkUnit *u, int target, const DkBuildOpts *o,
                               const char *src, GlMode gl) {
    const DkCompiler *c = dk_project_compiler(p, target);
    DkCzVec flags = {0};
    const DkStrVec *lang = is_c_unit(u->path) ? &c->c_flags : &c->cpp_flags;
    const DkStrVec *groups[2] = {&c->base_flags, lang};
    for (int g = 0; g < 2; g++)
        for (size_t i = 0; i < groups[g]->n; i++) {
            bool removed = false;
            for (size_t r = 0; r < u->remove_flags.n && !removed; r++)
                removed = _stricmp(groups[g]->v[i].p, u->remove_flags.v[r].p) == 0;
            if (!removed) dk_vec_push(&flags, (char *)groups[g]->v[i].p);
        }
    for (size_t i = 0; i < u->compile_flags.n; i++) dk_vec_push(&flags, (char *)u->compile_flags.v[i].p);
    if (u->flags_line) {
        DkBytes text = {0};
        if (dk_read_all(a, src, &text)) {
            DkStr t = {(const char *)text.v, text.n};
            if (dk_str_startswith(t, DK_S("\xEF\xBB\xBF"))) t = (DkStr){t.p + 3, t.n - 3};
            const char *line = dk_annot_flags_line(a, dk_project_annot_config(p), t);
            if (line) {
                DkStrVec parts = dk_str_split(dk_str(line), DK_S(""), -1);
                for (size_t i = 0; i < parts.n; i++) dk_vec_push(&flags, dk_cz(a, parts.v[i]));
                dk_vec_free(&parts);
            }
        }
    }
    if (o)
        for (size_t i = 0; i < o->extra_flags.n; i++) dk_vec_push(&flags, (char *)o->extra_flags.v[i].p);
    if (gl != GL_NONE) {
        size_t w = 0;
        for (size_t i = 0; i < flags.n; i++)
            if (_stricmp(flags.v[i], "/GL") != 0 && _stricmp(flags.v[i], "/GL-") != 0) flags.v[w++] = flags.v[i];
        flags.n = w;
        dk_vec_push(&flags, gl == GL_ON ? "/GL" : "/GL-");
    }
    if (u->per_target) {
        const DkTarget *t = dk_project_target(p, target);
        for (size_t i = 0; i < t->defines.n; i++) dk_vec_push(&flags, dk_sprintf(a, "/D%s", t->defines.v[i].p));
    }
    for (size_t i = 0; i < c->include.n; i++) dk_vec_push(&flags, dk_sprintf(a, "/I%s", c->include.v[i].p));
    if (c->show_includes) dk_vec_push(&flags, "/showIncludes");
    return flags;
}

static bool compile(DkProject *p, const DkUnit *u, int target, const DkBuildOpts *o, const char *src,
                    const char *obj, GlMode gl, DkStr *log, DkErr *err) {
    DkArena *a = dk_project_arena(p);
    const DkCompiler *c = dk_project_compiler(p, target);
    if (!c || !c->cl) {
        dk_err_set(err, DK_ERR_OTHER, "%s: no compiler configured", u->path);
        return false;
    }
    DkCzVec opts = compile_options(a, p, u, target, o, src, gl);
    ObjcacheObjCache *cache = o && o->use_cache && !o->source_override ? cache_for(p, target) : NULL;
    const char *key = NULL;
    if (cache && c->show_includes) {
        key = objcache_obj_cache_key(cache, (const char *const *)opts.v, opts.n, src);
        DkStr text = {0};
        if (key && objcache_obj_cache_lookup(cache, key, obj, &text)) {
            log_append(a, log, text);
            dk_vec_free(&opts);
            return true;
        }
    }
    DkCzVec argv = {0};
    dk_vec_push(&argv, (char *)c->cl);
    for (size_t i = 0; i < opts.n; i++) dk_vec_push(&argv, opts.v[i]);
    dk_vec_push(&argv, dk_sprintf(a, "/Fo%s", obj));
    dk_vec_push(&argv, (char *)src);
    dk_vec_push(&argv, NULL);
    dk_remove(obj);
    DkProcSpec spec = {0};
    spec.argv = (const char *const *)argv.v;
    spec.cwd = dk_project_root(p);
    spec.env = tool_env(a, c);
    spec.out = DK_IO_CAPTURE;
    spec.err = DK_IO_STDOUT;
    spec.text = true;
    spec.errors = DK_ERRORS_REPLACE;
    spec.timeout = COMPILE_TIMEOUT;
    spec.arena = a;
    DkProcResult r = dk_run(&spec);
    dk_vec_free(&argv);
    /* the output without the include notes */
    DkStrVec lines = dk_str_splitlines(r.out, false), kept = {0};
    for (size_t i = 0; i < lines.n; i++)
        if (dk_str_find(lines.v[i], DK_S(OBJCACHE_INCLUDE_NOTE), 0, DK_END) < 0) dk_vec_push(&kept, lines.v[i]);
    DkStr text = dk_str_join(a, DK_S("\n"), kept.v, kept.n);
    dk_vec_free(&lines);
    dk_vec_free(&kept);
    log_append(a, log, text);
    if (r.status != DK_PROC_OK || r.returncode != 0 || !dk_isfile(obj)) {
        if (r.status == DK_PROC_START_FAILED)
            dk_err_set(err, DK_ERR_IO, "%s: cannot start %s: %s", u->path, c->cl, r.message ? r.message : "?");
        else if (r.status == DK_PROC_TIMEOUT)
            dk_err_set(err, DK_ERR_OTHER, "%s: the compiler timed out", u->path);
        else
            dk_err_set(err, DK_ERR_OTHER, "%s: compile failed: %s", u->path, first_error_line(a, text));
        dk_vec_free(&opts);
        return false;
    }
    if (key) objcache_obj_cache_store(cache, key, obj, dk_project_root(p), r.out, text);
    dk_vec_free(&opts);
    return true;
}

static DkCoff *read_coff(DkArena *a, const char *obj, DkErr *err) {
    DkBytes data = {0};
    if (!dk_read_all(a, obj, &data)) {
        dk_err_set(err, DK_ERR_IO, "%s: %.*s", obj, DK_SF(dk_io_err_str(a)));
        return NULL;
    }
    DkTry tr;
    DkCoff *coff = NULL;
    if (DK_TRY(&tr)) {
        coff = dk_coff_parse(a, data.v, data.n, 0x14C);
        dk_try_end(&tr);
    } else {
        dk_err_set(err, DK_ERR_FORMAT, "%s: %s", obj, tr.msg);
    }
    return coff;
}

/* ---- functions of an object -------------------------------------------------------------------------------------- */
static const DkCoffSection *coff_section(const DkCoff *c, i32 number) {
    return number > 0 && number <= c->number_of_sections ? &c->sections[number - 1] : NULL;
}

static bool is_code_section(const DkCoffSection *s) { return s && (s->characteristics & DK_SCN_CNT_CODE); }

static bool is_function_symbol(const DkCoff *c, const DkCoffSymbol *s) {
    return dk_coff_defined(s) && dk_coff_is_function(s) &&
           (s->storage_class == COFF_EXTERNAL || s->storage_class == COFF_STATIC) &&
           is_code_section(coff_section(c, s->section));
}

static const char *sym_name(DkArena *a, const DkCoffSymbol *s) { return dk_cz(a, s->name); }

/* Whether another definition in the object has the same name (static labels, section symbols). */
static bool name_unique(BuildCtx *ctx, const DkCoffSymbol *s) {
    const DkVal *v = dk_map_get(ctx->by_name, s->name);
    return v && v->u == s->index;
}

/* The default of a weak external, else the symbol itself. */
static const DkCoffSymbol *follow_weak(const DkCoff *c, const DkCoffSymbol *s) {
    if (s->storage_class != COFF_WEAK_EXTERNAL || !s->number_of_aux) return s;
    const u8 *aux = dk_coff_aux_raw(c, s, 0);
    if (!aux) return s;
    u32 tag;
    memcpy(&tag, aux, 4);
    const DkCoffSymbol *d = dk_coff_symbol(c, tag);
    return d && !d->aux ? d : s;
}

/* The end of a definition: the next definition's value in its section, else the section's size. */
static u32 definition_end(const DkCoff *c, const DkCoffSymbol *s, bool functions_only) {
    const DkCoffSection *sec = coff_section(c, s->section);
    u32 end = sec ? sec->size : s->value;
    for (u32 i = 0; i < c->number_of_symbols; i++) {
        const DkCoffSymbol *o = &c->symbols[i];
        if (o->aux || o->section != s->section || o->value <= s->value || o->value >= end) continue;
        if (functions_only ? !is_function_symbol(c, o) : !dk_coff_defined(o)) continue;
        end = o->value;
    }
    return end;
}

/* The name a relocation records for symbol slot index: unique names as they are, others "name#<slot>". */
static const char *reloc_name(BuildCtx *ctx, const DkCoffSymbol *s) {
    if (!dk_coff_defined(s) || name_unique(ctx, s)) return sym_name(ctx->a, s);
    return dk_sprintf(ctx->a, "%.*s#%u", DK_SF(s->name), s->index);
}

/* The relocations of section sec in [start, end), offsets from start. A target in the same section as the function
 * (labels, switch tables, the section symbol) is recorded as the function itself, its offset folded into the
 * addend. */
static void cut_relocs(BuildCtx *ctx, const DkCoffSection *sec, u32 start, u32 end, const DkCoffSymbol *self,
                       DkFunc *f) {
    DkRelocVec v = {0};
    for (size_t i = 0; i < sec->n_relocs; i++) {
        const DkCoffReloc *r = &sec->relocs[i];
        if (r->offset < start || r->offset >= end) continue;
        const DkCoffSymbol *s = dk_coff_symbol(ctx->coff, r->symbol_index);
        DkReloc out = {0};
        out.offset = r->offset - start;
        out.type = r->type;
        out.addend = (i32)r->addend;
        if (s && !s->aux) {
            s = follow_weak(ctx->coff, s);
            bool section_symbol = s->storage_class == COFF_STATIC && s->name.n && s->name.p[0] == '.';
            u32 at = section_symbol ? s->value + (u32)out.addend : s->value;
            if (self && dk_coff_defined(s) && s->section == self->section && at >= start && at < end) {
                out.symbol = f->symbol;
                out.addend += (i32)(s->value - self->value);
            } else {
                out.symbol = reloc_name(ctx, s);
            }
        }
        dk_vec_push(&v, out);
    }
    f->relocs = v.n ? (DkReloc *)dk_memdup(ctx->a, v.v, v.n * sizeof *v.v) : NULL;
    f->n_relocs = v.n;
    dk_vec_free(&v);
}

static BuildCtx *object_ctx(DkArena *a, DkCoff *coff) {
    BuildCtx *ctx = DK_NEW(a, BuildCtx);
    ctx->kind = BUILD_OBJECT;
    ctx->a = a;
    ctx->coff = coff;
    ctx->by_name = dk_map_new();
    for (u32 i = 0; i < coff->number_of_symbols; i++) {
        const DkCoffSymbol *s = &coff->symbols[i];
        if (s->aux || !dk_coff_defined(s)) continue;
        bool created = false;
        DkVal *v = dk_map_put(ctx->by_name, s->name, &created);
        if (created) v->u = s->index;
        else v->u = (u64)-1; /* defined twice: no unique name */
    }
    return ctx;
}

static DkFunc *object_functions(DkArena *a, DkCoff *coff, size_t *n) {
    BuildCtx *ctx = object_ctx(a, coff);
    DK_VEC(DkFunc) out = {0};
    for (u32 i = 0; i < coff->number_of_symbols; i++) {
        const DkCoffSymbol *s = &coff->symbols[i];
        if (s->aux || !is_function_symbol(coff, s)) continue;
        const DkCoffSection *sec = coff_section(coff, s->section);
        u32 end = definition_end(coff, s, true);
        if (end > sec->data.n) end = (u32)sec->data.n;
        if (s->value > end) continue;
        DkFunc f = {0};
        f.symbol = sym_name(a, s);
        f.code = copy_bytes(a, sec->data.p + s->value, end - s->value);
        cut_relocs(ctx, sec, s->value, end, s, &f);
        dk_vec_push(&out, f);
    }
    DkFunc *v = DK_NEWN(a, DkFunc, out.n ? out.n : 1);
    if (out.n) memcpy(v, out.v, out.n * sizeof *v);
    *n = out.n;
    dk_vec_free(&out);
    for (size_t i = 0; i < *n; i++) {
        const DkVal *idx = dk_map_get(ctx->by_name, dk_str(v[i].symbol));
        const DkCoffSymbol *s = idx && idx->u != (u64)-1 ? &coff->symbols[idx->u] : NULL;
        register_fn(&v[i], ctx, s ? s->section : -1, s ? s->value : 0);
    }
    return v;
}

/* ---- linker maps and linked images ------------------------------------------------------------------------------- */
static bool hexval(DkStr s, u64 *out) {
    if (!s.n || s.n > 16) return false;
    u64 v = 0;
    for (size_t i = 0; i < s.n; i++) {
        char c = s.p[i];
        int d = c >= '0' && c <= '9'   ? c - '0'
                : c >= 'a' && c <= 'f' ? c - 'a' + 10
                : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                         : -1;
        if (d < 0) return false;
        v = v << 4 | (u64)d;
    }
    *out = v;
    return true;
}

static int cmp_mapsym(const void *x, const void *y) {
    const MapSym *a = (const MapSym *)x, *b = (const MapSym *)y;
    if (a->va != b->va) return a->va < b->va ? -1 : 1;
    return strcmp(a->name, b->name);
}

/* The symbol lines of an MSVC linker map ("Publics by Value" and "Static symbols"): "ssss:oooooooo name va [f] [i]
 * object"; an absolute symbol (section 0) is kept when its address is not 0 (the image base symbol). */
static bool read_map(DkArena *a, const char *path, MapSym **out, size_t *n, DkErr *err) {
    DkBytes data = {0};
    if (!dk_read_all(a, path, &data)) {
        dk_err_set(err, DK_ERR_IO, "%s: %.*s", path, DK_SF(dk_io_err_str(a)));
        return false;
    }
    DkStrVec lines = dk_str_splitlines((DkStr){(const char *)data.v, data.n}, false);
    DK_VEC(MapSym) v = {0};
    for (size_t i = 0; i < lines.n; i++) {
        DkStrVec tok = dk_str_split(lines.v[i], DK_S(""), -1);
        u64 seg, off, va;
        if (tok.n >= 4 && tok.v[0].n == 13 && tok.v[0].p[4] == ':' && hexval((DkStr){tok.v[0].p, 4}, &seg) &&
            hexval((DkStr){tok.v[0].p + 5, 8}, &off) && tok.v[2].n >= 8 && hexval(tok.v[2], &va) && (seg || va) &&
            va <= 0xFFFFFFFFull) {
            MapSym m = {dk_cz(a, tok.v[1]), (u32)va, (u32)seg};
            dk_vec_push(&v, m);
        }
        dk_vec_free(&tok);
    }
    dk_vec_free(&lines);
    qsort(v.v, v.n, sizeof *v.v, cmp_mapsym);
    *out = v.n ? (MapSym *)dk_memdup(a, v.v, v.n * sizeof *v.v) : NULL;
    *n = v.n;
    dk_vec_free(&v);
    return true;
}

static BuildCtx *linked_ctx(DkArena *a, DkImage *img, MapSym *map, size_t nmap) {
    BuildCtx *ctx = DK_NEW(a, BuildCtx);
    ctx->kind = BUILD_LINKED;
    ctx->a = a;
    ctx->img = img;
    ctx->map = map;
    ctx->nmap = nmap;
    ctx->by_name = dk_map_new();
    DkSymbols *syms = dk_symbols_new(a);
    for (size_t i = 0; i < nmap; i++) {
        bool created = false;
        DkVal *v = dk_map_put(ctx->by_name, dk_str(map[i].name), &created);
        v->u = created ? i : (u64)-1;
        dk_symbols_add(syms, map[i].va, 0, map[i].name, false);
    }
    dk__image_set_symbols(img, syms);
    return ctx;
}

/* The extent of map symbol i: up to the next map symbol of its section with a higher address, else the end of the
 * image section holding it. */
static u32 map_extent(const BuildCtx *ctx, size_t i) {
    u32 start = ctx->map[i].va;
    for (size_t j = i + 1; j < ctx->nmap; j++)
        if (ctx->map[j].seg == ctx->map[i].seg && ctx->map[j].va > start) return ctx->map[j].va - start;
    u32 end = dk__image_section_end(ctx->img, start);
    return end > start ? end - start : 0;
}

static bool linked_function(BuildCtx *ctx, size_t i, DkFunc *f) {
    u32 size = map_extent(ctx, i);
    DkStr code = {"", 0};
    if (size && !dk_image_read(ctx->img, ctx->map[i].va, size, &code)) return false;
    f->symbol = ctx->map[i].name;
    f->va = ctx->map[i].va;
    f->code = copy_bytes(ctx->a, size ? code.p : "", size);
    size_t nb = 0;
    const DkReloc *base = dk_image_relocs(ctx->img, f->va, size, &nb);
    DkRelocVec v = {0};
    for (size_t k = 0; k < nb; k++) dk_vec_push(&v, base[k]);
    dk__image_branch_relocs(ctx->img, f->va, f->code, ctx->a, &v);
    qsort(v.v, v.n, sizeof *v.v, cmp_reloc);
    f->relocs = v.n ? (DkReloc *)dk_memdup(ctx->a, v.v, v.n * sizeof *v.v) : NULL;
    f->n_relocs = v.n;
    dk_vec_free(&v);
    return true;
}

static size_t map_index(const BuildCtx *ctx, const char *name) {
    const DkVal *v = dk_map_get(ctx->by_name, dk_str(name));
    return v ? (size_t)v->u : (size_t)-1;
}

/* ---- the comparison's view of a build ---------------------------------------------------------------------------- */
static const DkCoffSymbol *object_symbol(const BuildCtx *ctx, const char *symbol) {
    const char *hash = strrchr(symbol, '#');
    if (hash) {
        char *end = NULL;
        unsigned long idx = strtoul(hash + 1, &end, 10);
        if (end && !*end && idx < ctx->coff->number_of_symbols) {
            const DkCoffSymbol *s = &ctx->coff->symbols[idx];
            return s->aux || !dk_coff_defined(s) ? NULL : s;
        }
    }
    const DkVal *v = dk_map_get(ctx->by_name, dk_str(symbol));
    if (!v || v->u == (u64)-1) return NULL;
    return &ctx->coff->symbols[v->u];
}

bool dk__build_defines(const DkFunc *fn, const char *symbol, bool *inside, u32 *offset) {
    *inside = false;
    *offset = 0;
    const FnEntry *e = entry_of(fn);
    if (!e || !symbol) return false;
    if (strcmp(symbol, fn->symbol) == 0) {
        *inside = true;
        return true;
    }
    if (e->ctx->kind == BUILD_OBJECT) {
        const DkCoffSymbol *s = object_symbol(e->ctx, symbol);
        if (!s) return false;
        if (s->section == e->section && s->value >= e->value && s->value < e->value + e->n) {
            *inside = true;
            *offset = s->value - e->value;
        }
        return true;
    }
    if (strncmp(symbol, "__imp_", 6) == 0) return false;
    size_t i = map_index(e->ctx, symbol);
    if (i == (size_t)-1) return false;
    u32 va = e->ctx->map[i].va;
    if (va >= e->va && va < e->va + e->n) {
        *inside = true;
        *offset = va - e->va;
    }
    return true;
}

bool dk__build_content(const DkFunc *fn, const char *symbol, DkFunc *out, bool *is_function) {
    memset(out, 0, sizeof *out);
    *is_function = false;
    const FnEntry *e = entry_of(fn);
    if (!e || !symbol) return false;
    BuildCtx *ctx = e->ctx;
    if (ctx->kind == BUILD_OBJECT) {
        const DkCoffSymbol *s = object_symbol(ctx, symbol);
        if (!s) return false;
        const DkCoffSection *sec = coff_section(ctx->coff, s->section);
        if (!sec || (sec->characteristics & DK_SCN_CNT_UNINITIALIZED_DATA) || !sec->data.n) return false;
        u32 end = definition_end(ctx->coff, s, false);
        if (end > sec->data.n) end = (u32)sec->data.n;
        if (s->value > end) return false;
        out->symbol = symbol;
        out->code = (DkStr){(const char *)sec->data.p + s->value, end - s->value};
        cut_relocs(ctx, sec, s->value, end, NULL, out);
        *is_function = dk_coff_is_function(s) || is_code_section(sec);
        return true;
    }
    if (strncmp(symbol, "__imp_", 6) == 0) return false;
    size_t i = map_index(ctx, symbol);
    if (i == (size_t)-1) return false;
    u32 size = map_extent(ctx, i);
    DkStr code = {"", 0};
    if (!size || !dk_image_read(ctx->img, ctx->map[i].va, size, &code)) return false;
    out->symbol = symbol;
    out->va = ctx->map[i].va;
    out->code = code;
    size_t nb = 0;
    const DkReloc *base = dk_image_relocs(ctx->img, out->va, size, &nb);
    out->relocs = (DkReloc *)base;
    out->n_relocs = nb;
    return true;
}

/* ---- the backends ------------------------------------------------------------------------------------------------ */
static const char *out_dir(DkProject *p, const DkUnit *u, int target, const char *backend) {
    DkArena *a = dk_project_arena(p);
    const char *scope = dk_project_target(p, target)->name;
    const char *dir = dk_join(a, dk_project_build_dir(p, "build"), backend, scope, unit_stem(a, u));
    dk_makedirs(dir, true);
    return fwd(a, dir);
}

static DkFunc *build_object(DkProject *p, const DkUnit *u, int target, const DkBuildOpts *o, const char *src,
                            size_t *n, DkStr *log, DkErr *err) {
    DkArena *a = dk_project_arena(p);
    const char *obj = dk_join(a, out_dir(p, u, target, "object"), "unit.obj");
    if (!compile(p, u, target, o, src, obj, GL_NONE, log, err)) return NULL;
    DkCoff *coff = read_coff(a, obj, err);
    if (!coff) return NULL;
    return object_functions(a, coff, n);
}

/* The defined function names of an object (the names the annotations bind to). */
static DkCzVec object_function_names(DkArena *a, const DkCoff *coff) {
    DkCzVec names = {0};
    for (u32 i = 0; i < coff->number_of_symbols; i++) {
        const DkCoffSymbol *s = &coff->symbols[i];
        if (!s->aux && is_function_symbol(coff, s)) dk_vec_push(&names, (char *)sym_name(a, s));
    }
    return names;
}

/* Splices one configured argv element: ${objects} and ${roots} as whole elements become lists. */
static bool expand_argv(DkProject *p, const DkStrVec *in, const DkExpandVars *vars, const DkCzVec *objects,
                        const DkCzVec *roots, DkCzVec *out, DkErr *err) {
    DkArena *a = dk_project_arena(p);
    for (size_t i = 0; i < in->n; i++) {
        const char *s = in->v[i].p;
        if (strcmp(s, "${objects}") == 0) {
            for (size_t k = 0; objects && k < objects->n; k++) dk_vec_push(out, objects->v[k]);
            continue;
        }
        if (strcmp(s, "${roots}") == 0) {
            for (size_t k = 0; roots && k < roots->n; k++) dk_vec_push(out, dk_sprintf(a, "/INCLUDE:%s", roots->v[k]));
            continue;
        }
        char *e = dk_project_expand(a, p, s, vars, err);
        if (!e) return false;
        dk_vec_push(out, e);
    }
    return true;
}

static const char *option_value(DkArena *a, const DkCzVec *argv, const char *prefix) {
    size_t n = strlen(prefix);
    const char *found = NULL;
    for (size_t i = 0; i < argv->n; i++)
        if (argv->v[i] && _strnicmp(argv->v[i], prefix, n) == 0) found = argv->v[i] + n;
    return found ? dk_strdup(a, found) : NULL;
}

static DkFunc *build_link(DkProject *p, const DkUnit *u, int target, const DkBuildOpts *o, const char *src,
                          size_t *n, DkStr *log, DkErr *err) {
    DkArena *a = dk_project_arena(p);
    const DkBackend *b = dk_project_backend(p);
    const char *dir = out_dir(p, u, target, "link");
    /* the roots: the annotations' symbols, learned from a /GL- compile when configured */
    size_t nann = 0;
    DkErr aerr = {0};
    DkAnnot *anns = dk_annotations(p, u, &nann, &aerr);
    if (!anns && aerr.code) {
        *err = aerr;
        return NULL;
    }
    DkCzVec names = {0}, roots = {0};
    if (b->discovery_compile) {
        const char *plain = dk_join(a, dir, "discovery.obj");
        if (!compile(p, u, target, o, src, plain, GL_OFF, log, err)) return NULL;
        DkCoff *coff = read_coff(a, plain, err);
        if (!coff) return NULL;
        names = object_function_names(a, coff);
    }
    const DkAnnotConfig *ac = dk_project_annot_config(p);
    for (size_t i = 0; i < nann; i++) {
        const DkAnnot *an = &anns[i];
        if (an->kind != DK_ANN_FUNCTION || !(an->target_mask & (1u << target))) continue;
        const char *sym = an->symbol;
        if (!sym && names.n) sym = dk_annot_bind(an, ac->name, (const char *const *)names.v, names.n, NULL);
        if (!sym) continue;
        bool seen = false;
        for (size_t k = 0; k < roots.n && !seen; k++) seen = strcmp(roots.v[k], sym) == 0;
        if (!seen) dk_vec_push(&roots, (char *)sym);
    }
    dk_vec_free(&names);
    for (size_t i = 0; i < u->link_roots.n; i++) {
        bool seen = false;
        for (size_t k = 0; k < roots.n && !seen; k++) seen = strcmp(roots.v[k], u->link_roots.v[i].p) == 0;
        if (!seen) dk_vec_push(&roots, (char *)u->link_roots.v[i].p);
    }
    bool gl = u->gl_set ? u->gl : true;
    const char *obj = fwd(a, dk_join(a, dir, "candidate.obj"));
    if (!compile(p, u, target, o, src, obj, gl ? GL_ON : GL_OFF, log, err)) return NULL;
    DkCzVec objects = {0};
    dk_vec_push(&objects, (char *)obj);
    /* the sources linked with the unit: their own unit options, never the caller's override or extra flags */
    DK_VEC(const DkUnit *) deps = {0};
    DkBuildOpts dep_opts;
    memset(&dep_opts, 0, sizeof dep_opts);
    dep_opts.use_cache = o && o->use_cache;
    for (size_t i = 0; i < u->link_with.n; i++) {
        const DkUnit *d = dk_project_unit(p, u->link_with.v[i].p);
        if (!d || strcmp(d->path, u->link_with.v[i].p) != 0) {
            DkUnit *plain = DK_NEW(a, DkUnit);
            plain->path = u->link_with.v[i].p;
            plain->flags_line = true;
            d = plain;
        }
        const char *dsrc = fwd(a, dk_project_path(a, p, d->path));
        const char *dobj = fwd(a, dk_join(a, dir, dk_sprintf(a, "dep-%03zu.obj", i)));
        bool dgl = d->gl_set ? d->gl : true;
        if (!compile(p, d, target, &dep_opts, dsrc, dobj, dgl ? GL_ON : GL_OFF, log, err)) {
            dk_vec_free(&deps);
            return NULL;
        }
        dk_vec_push(&objects, (char *)dobj);
        dk_vec_push(&deps, d);
    }
    DkExpandVars vars = {dk_project_target(p, target)->name, u->path, dir, NULL, NULL};
    DkCzVec argv = {0};
    dk_vec_push(&argv, (char *)b->linker);
    if (!expand_argv(p, &b->link_argv, &vars, &objects, &roots, &argv, err)) return NULL;
    for (size_t i = 0; i < u->link_flags.n; i++) dk_vec_push(&argv, (char *)u->link_flags.v[i].p);
    for (size_t k = 0; k < deps.n; k++)
        for (size_t i = 0; i < deps.v[k]->link_flags.n; i++) {
            const char *f = deps.v[k]->link_flags.v[i].p;
            bool seen = false;
            for (size_t j = 1; j < argv.n && !seen; j++) seen = argv.v[j] && strcmp(argv.v[j], f) == 0;
            if (!seen) dk_vec_push(&argv, (char *)f);
        }
    dk_vec_free(&deps);
    const char *image_path = option_value(a, &argv, "/OUT:");
    const char *map_path = option_value(a, &argv, "/MAP:");
    if (!image_path || !map_path) {
        dk_err_set(err, DK_ERR_OTHER, "backend.link.argv: needs /OUT: and /MAP: options");
        return NULL;
    }
    dk_vec_push(&argv, NULL);
    dk_remove(image_path);
    DkProcSpec spec = {0};
    spec.argv = (const char *const *)argv.v;
    spec.cwd = dir;
    spec.env = tool_env(a, dk_project_compiler(p, target));
    spec.out = DK_IO_CAPTURE;
    spec.err = DK_IO_STDOUT;
    spec.text = true;
    spec.errors = DK_ERRORS_REPLACE;
    spec.timeout = COMPILE_TIMEOUT;
    spec.arena = a;
    DkProcResult r = dk_run(&spec);
    log_append(a, log, dk_str_strip(r.out));
    if (r.status != DK_PROC_OK || r.returncode != 0 || !dk_isfile(image_path)) {
        dk_err_set(err, DK_ERR_OTHER, "%s: link failed: %s", u->path,
                   r.status == DK_PROC_START_FAILED ? (r.message ? r.message : "cannot start the linker")
                                                    : first_error_line(a, r.out));
        return NULL;
    }
    MapSym *map = NULL;
    size_t nmap = 0;
    if (!read_map(a, map_path, &map, &nmap, err)) return NULL;
    DkImage *img = dk__image_open(a, image_path, NULL, err);
    if (!img) return NULL;
    BuildCtx *ctx = linked_ctx(a, img, map, nmap);
    DK_VEC(DkFunc) out = {0};
    for (size_t k = 0; k < roots.n; k++) {
        size_t i = map_index(ctx, roots.v[k]);
        DkFunc f = {0};
        if (i == (size_t)-1 || !linked_function(ctx, i, &f)) continue;
        dk_vec_push(&out, f);
    }
    DkFunc *v = DK_NEWN(a, DkFunc, out.n ? out.n : 1);
    if (out.n) memcpy(v, out.v, out.n * sizeof *v);
    *n = out.n;
    dk_vec_free(&out);
    for (size_t i = 0; i < *n; i++) register_fn(&v[i], ctx, -1, 0);
    return v;
}

static bool json_u32(const DkJson *v, u32 *out) {
    if (!v) return false;
    if (dk_json_is_int(v)) {
        i64 x = dk_json_i64(v, -1);
        if (x < 0 || x > 0xFFFFFFFFll) return false;
        *out = (u32)x;
        return true;
    }
    if (!dk_json_is_str(v)) return false;
    DkStr s = dk_json_str_or(v, DK_S(""));
    u64 x;
    if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X')) {
        if (!hexval((DkStr){s.p + 2, s.n - 2}, &x) || x > 0xFFFFFFFFull) return false;
    } else {
        x = 0;
        if (!s.n) return false;
        for (size_t i = 0; i < s.n; i++) {
            if (s.p[i] < '0' || s.p[i] > '9') return false;
            x = x * 10 + (u64)(s.p[i] - '0');
            if (x > 0xFFFFFFFFull) return false;
        }
    }
    *out = (u32)x;
    return true;
}

static const char *json_cz(DkArena *a, const DkJson *obj, const char *key) {
    const DkJson *v = dk_json_getz(obj, key);
    return v && dk_json_is_str(v) ? dk_cz(a, dk_json_str_or(v, DK_S(""))) : NULL;
}

static bool same_path(DkArena *a, const char *x, const char *y) {
    return strcmp(dk_path_normcase(a, dk_path_abspath(a, x)), dk_path_normcase(a, dk_path_abspath(a, y))) == 0;
}

/* The map of a manifest candidate: map_path, the image's .map sibling, or a linker-map artifact of its folder. */
static const char *manifest_map(DkArena *a, const DkJson *man, const DkJson *cand, const char *image) {
    const char *m = json_cz(a, cand, "map_path");
    if (m && dk_isfile(m)) return m;
    DkStr root, ext;
    dk_path_splitext(image, &root, &ext);
    const char *sib = dk_sprintf(a, "%.*s.map", DK_SF(root));
    if (dk_isfile(sib)) return sib;
    const DkJson *arts = dk_json_getz(man, "artifacts");
    for (size_t i = 0; arts && i < dk_json_len(arts); i++) {
        const DkJson *art = dk_json_at(arts, i);
        const char *kind = json_cz(a, art, "kind"), *path = json_cz(a, art, "path");
        if (!kind || !path || strcmp(kind, "linker-map") != 0) continue;
        if (same_path(a, dk_cz(a, dk_path_dirname(path)), dk_cz(a, dk_path_dirname(image)))) return path;
    }
    return NULL;
}

static DkFunc *build_manifest(DkProject *p, const DkUnit *u, int target, size_t *n, DkStr *log, DkErr *err) {
    DkArena *a = dk_project_arena(p);
    const DkBackend *b = dk_project_backend(p);
    const char *dir = out_dir(p, u, target, "manifest");
    DkExpandVars vars = {dk_project_target(p, target)->name, u->path, dir, NULL, NULL};
    DkStr printed = {0};
    if (b->manifest_command.n) {
        DkCzVec argv = {0};
        if (!expand_argv(p, &b->manifest_command, &vars, NULL, NULL, &argv, err)) return NULL;
        dk_vec_push(&argv, NULL);
        DkProcSpec spec = {0};
        spec.argv = (const char *const *)argv.v;
        spec.cwd = dk_project_root(p);
        spec.out = DK_IO_CAPTURE;
        spec.err = DK_IO_CAPTURE;
        spec.text = true;
        spec.errors = DK_ERRORS_REPLACE;
        spec.timeout = COMPILE_TIMEOUT;
        spec.arena = a;
        DkProcResult r = dk_run(&spec);
        log_append(a, log, dk_str_strip(r.err));
        if (r.status != DK_PROC_OK || r.returncode != 0) {
            dk_err_set(err, DK_ERR_OTHER, "%s: manifest command failed: %s", u->path,
                       r.message ? r.message : first_error_line(a, dk_str_concat(a, r.err, r.out)));
            return NULL;
        }
        printed = r.out;
    }
    DkJson *man = NULL;
    const char *path = NULL;
    if (b->manifest_path) {
        path = dk_project_expand(a, p, b->manifest_path, &vars, err);
        if (!path) return NULL;
        path = dk_project_path(a, p, path);
    } else if (printed.n) {
        man = dk_json_parse(a, printed, NULL);
        if (!man) { /* the last printed line naming a file */
            DkStrVec lines = dk_str_splitlines(printed, false);
            for (size_t i = lines.n; i-- > 0 && !path;) {
                const char *l = dk_cz(a, dk_str_strip(lines.v[i]));
                if (*l && dk_isfile(l)) path = l;
            }
            dk_vec_free(&lines);
        }
    }
    if (!man) {
        DkBytes data = {0};
        if (!path || !dk_read_all(a, path, &data)) {
            dk_err_set(err, DK_ERR_IO, "%s: no manifest%s%s", u->path, path ? " at " : "", path ? path : "");
            return NULL;
        }
        DkJsonError je = {0};
        man = dk_json_parse(a, (DkStr){(const char *)data.v, data.n}, &je);
        if (!man) {
            dk_err_set(err, DK_ERR_FORMAT, "%s: %.*s", path, DK_SF(dk_json_error_str(a, &je)));
            return NULL;
        }
    }
    const DkJson *cands = dk_json_getz(man, "candidates");
    if (!cands || !dk_json_is_arr(cands)) {
        dk_err_set(err, DK_ERR_FORMAT, "%s: the manifest has no candidates array", path ? path : "manifest");
        return NULL;
    }
    const char *unit_abs = dk_project_path(a, p, u->path);
    DkMap *images = dk_map_new(); /* image path -> BuildCtx */
    DK_VEC(DkFunc) out = {0};
    DkPtrVec ctxs = {0};
    for (size_t i = 0; i < dk_json_len(cands); i++) {
        const DkJson *c = dk_json_at(cands, i);
        const char *sym = json_cz(a, c, "symbol"), *image = json_cz(a, c, "image_path");
        const char *source = json_cz(a, c, "source_path");
        u32 va = 0, size = 0;
        if (!sym || !image || !json_u32(dk_json_getz(c, "candidate_va"), &va) ||
            !json_u32(dk_json_getz(c, "size"), &size)) {
            dk_err_set(err, DK_ERR_FORMAT, "manifest candidate %zu: needs symbol, candidate_va, size and image_path",
                       i);
            dk_map_free(images);
            return NULL;
        }
        if (source && !same_path(a, dk_project_path(a, p, source), unit_abs)) continue;
        image = dk_project_path(a, p, image);
        bool created = false;
        DkVal *slot = dk_map_put(images, dk_str(image), &created);
        if (created) {
            DkImage *img = dk__image_open(a, image, NULL, err);
            if (!img) {
                dk_map_free(images);
                return NULL;
            }
            MapSym *map = NULL;
            size_t nmap = 0;
            const char *mp = manifest_map(a, man, c, image);
            if (mp && !read_map(a, mp, &map, &nmap, err)) {
                dk_map_free(images);
                return NULL;
            }
            slot->p = linked_ctx(a, img, map, nmap);
        }
        BuildCtx *ctx = (BuildCtx *)slot->p;
        DkStr code = {"", 0};
        if (size && !dk_image_read(ctx->img, va, size, &code)) {
            dk_err_set(err, DK_ERR_FORMAT, "%s: %08X+%X is outside the image", image, va, size);
            dk_map_free(images);
            return NULL;
        }
        DkFunc f = {0};
        f.symbol = sym;
        f.va = va;
        f.code = copy_bytes(a, size ? code.p : "", size);
        size_t nb = 0;
        const DkReloc *base = dk_image_relocs(ctx->img, va, size, &nb);
        DkRelocVec rv = {0};
        for (size_t k = 0; k < nb; k++) dk_vec_push(&rv, base[k]);
        dk__image_branch_relocs(ctx->img, va, f.code, a, &rv);
        qsort(rv.v, rv.n, sizeof *rv.v, cmp_reloc);
        f.relocs = rv.n ? (DkReloc *)dk_memdup(a, rv.v, rv.n * sizeof *rv.v) : NULL;
        f.n_relocs = rv.n;
        dk_vec_free(&rv);
        dk_vec_push(&out, f);
        dk_vec_push(&ctxs, ctx);
    }
    dk_map_free(images);
    DkFunc *v = DK_NEWN(a, DkFunc, out.n ? out.n : 1);
    if (out.n) memcpy(v, out.v, out.n * sizeof *v);
    *n = out.n;
    for (size_t i = 0; i < out.n; i++) register_fn(&v[i], (BuildCtx *)ctxs.v[i], -1, 0);
    dk_vec_free(&out);
    dk_vec_free(&ctxs);
    return v;
}

DkFunc *dk_build_unit(DkProject *p, const DkUnit *u, int target, const DkBuildOpts *o, size_t *n, DkStr *log,
                      DkErr *err) {
    *n = 0;
    if (log) *log = (DkStr){"", 0};
    dk_err_clear(err);
    if (target < 0 || (size_t)target >= dk_project_ntargets(p)) {
        dk_err_set(err, DK_ERR_OTHER, "build: no target %d", target);
        return NULL;
    }
    DkArena *a = dk_project_arena(p);
    const char *src = o && o->source_override ? o->source_override : dk_project_path(a, p, u->path);
    src = fwd(a, src);
    DkStr dummy = {0};
    if (!log) log = &dummy;
    switch (dk_project_backend(p)->kind) {
    case DK_BACKEND_OBJECT: return build_object(p, u, target, o, src, n, log, err);
    case DK_BACKEND_LINK: return build_link(p, u, target, o, src, n, log, err);
    case DK_BACKEND_MANIFEST: return build_manifest(p, u, target, n, log, err);
    }
    dk_err_set(err, DK_ERR_OTHER, "build: unknown backend");
    return NULL;
}
