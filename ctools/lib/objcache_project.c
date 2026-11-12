// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* objcache_project: the entry points of objcache that read the project adapter (project.h): a cache opened from a
 * DkCompiler or from a loaded DkProject and one of its targets. They are kept out of objcache.c so that a program
 * that builds its caches with objcache_obj_cache_new_with does not need the adapter's configuration. A NULL compiler
 * is an empty identity (no executable, no INCLUDE, no version text). */
#include "objcache_internal.h"
#include <string.h>

/* The compiler's identity text: the base name and the SHA-256 of each identity file, "name=hex" (hex "missing" for a
 * file that cannot be read), joined with ",". */
static const char *identity_text(DkArena *a, const DkCompiler *compiler) {
    DkStrVec parts = {0};
    for (size_t i = 0; i < compiler->identity_files.n; i++) {
        const char *path = dk_cz(a, compiler->identity_files.v[i]);
        const char *hex = objcache_obj_cache_digest_now(path);
        DkStr base = dk_path_basename(path);
        DkStr part = dk_str_concat(a, dk_str_concat(a, base, DK_S("=")), dk_str(hex ? hex : "missing"));
        dk_vec_push(&parts, part);
    }
    DkStr text = dk_str_join(a, DK_S(","), parts.v, parts.n);
    dk_vec_free(&parts);
    return dk_cz(a, text);
}

/* The compiler's INCLUDE value: its include folders joined with ";", else an INCLUDE entry of its environment. */
static const char *include_text(DkArena *a, const DkCompiler *compiler) {
    if (compiler->include.n) return dk_cz(a, dk_str_join(a, DK_S(";"), compiler->include.v, compiler->include.n));
    for (size_t i = 0; i < compiler->env_names.n && i < compiler->env_values.n; i++)
        if (dk_str_eqz(compiler->env_names.v[i], "INCLUDE")) return dk_cz(a, compiler->env_values.v[i]);
    return "";
}

ObjcacheObjCache *objcache_obj_cache_new(const char *root, const DkCompiler *compiler, const char *folder,
                                         const char **err) {
    const char *bin = "", *include = "", *version = "";
    if (compiler) {
        DkArena *a = dk_arena();
        bin = compiler->cl ? compiler->cl : "";
        include = include_text(a, compiler);
        version = identity_text(a, compiler);
    }
    return objcache_obj_cache_new_with(root, folder, bin, include, version, err);
}

ObjcacheObjCache *objcache_open_cache(const char *root, const DkCompiler *compiler, bool enabled) {
    if (!enabled) return NULL;
    const char *folder = objcache_cache_dir();
    if (!folder) return NULL;
    const char *err = NULL;
    ObjcacheObjCache *cache = objcache_obj_cache_new(root, compiler, folder, &err);
    if (!cache) return NULL;
    objcache__prune_at_exit(cache);
    return cache;
}

ObjcacheObjCache *objcache_open_project(const DkProject *p, int target, bool enabled) {
    ObjcacheObjCache *cache = objcache_open_cache(dk_project_root(p), dk_project_compiler(p, target), enabled);
    if (!cache) return NULL;
    /* the unit roots: units.roots when configured, else the first folder of each unit's path, once each */
    const DkStrVec *configured = dk_project_unit_roots(p);
    if (configured && configured->n) {
        DkCzVec given = {0};
        for (size_t i = 0; i < configured->n; i++) dk_vec_push(&given, (char *)configured->v[i].p);
        objcache_obj_cache_set_unit_roots(cache, (const char *const *)given.v, given.n);
        dk_vec_free(&given);
        return cache;
    }
    size_t nunits = 0;
    const DkUnit *units = dk_project_units(p, &nunits);
    DkCzVec roots = {0};
    for (size_t i = 0; i < nunits; i++) {
        const char *path = units[i].path;
        const char *slash = strchr(path, '/');
        if (!slash) continue;
        char *top = (char *)dk_alloc(dk_project_arena(p), (size_t)(slash - path) + 1);
        memcpy(top, path, (size_t)(slash - path));
        bool seen = false;
        for (size_t j = 0; j < roots.n && !seen; j++) seen = strcmp(roots.v[j], top) == 0;
        if (!seen) dk_vec_push(&roots, top);
    }
    if (roots.n) objcache_obj_cache_set_unit_roots(cache, (const char *const *)roots.v, roots.n);
    dk_vec_free(&roots);
    return cache;
}
