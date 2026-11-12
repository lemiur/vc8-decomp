// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* objcache's private seams between its two implementation files (lib/objcache.c and lib/objcache_project.c) and its
 * tests. Only those files include this header.
 *
 * Why two files: objcache.c does not depend on the project adapter's configuration model; everything that reads a
 * DkCompiler or a DkProject lives in objcache_project.c (objcache_obj_cache_new, objcache_open_cache,
 * objcache_open_project). */
#pragma once
#include "objcache.h"

/* The file name of an entry: <keys>\<key[:2]>\<key>.entries. A link entry is looked up under the key "link-" + key, so
 * it lives in the folder "li". */
const char *objcache__entry_path(const ObjcacheObjCache *c, const char *key);

/* Registers the exit-time prune (an atexit action) described at objcache_open_cache, once per cache folder per
 * process. */
void objcache__prune_at_exit(ObjcacheObjCache *c);

/* Registers an exit action: the exit actions of this module (memo saves, the prune) run at process exit in the reverse
 * order of their registration. */
void objcache__at_exit(void (*fn)(void *), void *ctx);
