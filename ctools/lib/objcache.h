// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* objcache: the content-addressed cache of the object files and link outputs the compile tools produce, plus the
 * on-disk memo tables of pure functions. It is shared by every worktree of the machine: a build compiles only the
 * units whose inputs changed. The behaviour is defined by its tests (tests/project_objcache_test.c and
 * tests/project_objcache_memo_test.c).
 *
 * Conventions: names are objcache_<function>; the cache is ObjcacheObjCache (methods objcache_obj_cache_<function>),
 * the memo is ObjcachePickleMemo (objcache_pickle_memo_<function>). A NULL char * stands for "no value". Returned
 * strings live in an arena of the module that lives as long as the process. An ObjcacheObjCache and an
 * ObjcachePickleMemo may be shared by every compile thread: every method locks internally (the public counters are
 * plain i64s, read after the threads joined).
 *
 * The compiler is described by the adapter's DkCompiler (project.h): its identity files, include folders and
 * executable make the cache's identity (objcache_project.c). A program that does not use the adapter builds a cache
 * with objcache_obj_cache_new_with.
 *
 * What makes an object reusable: the key is the SHA-256 of the format version, the compiler identity, the compile
 * options (all of them matching OBJCACHE_SAFE_OPTION_PAT), the source's path relative to the checkout and the
 * source's digest. An entry also records the digest of every file the compile read (the /showIncludes lines) and the
 * files of the unit roots that share a name with one of them (the "shadow" list: a file added under a unit root that
 * an include search could now find first). An entry is reused only when all of those still hold. A compile that
 * read a checkout file outside the unit roots, or no file, is not cached.
 *
 * Files (under <cache dir>\v1):
 *   objs\<sha256>.obj / .bin      blobs: plain bytes named by their digest, published by rename
 *   keys\<key[:2]>\<key>.entries  one cache.h file per key (kind OBJCACHE_ENTRY_KIND, schema 1): the entry list, at
 *                                 most 8, newest first. An object entry is a vector of records {deps: vector of
 *                                 {rel str, digest str or "" for none}, shadow: vector of str, obj: str (hex), text:
 *                                 str, time: f64}. A link entry (key "link-" + key) is {outputs: vector of str,
 *                                 failed: u8 present flag + str, time: f64}.
 *   <name>-<version>.memo         one append-only cache.h log per memo (kind OBJCACHE_MEMO_KIND)
 * Every file is checked on reading (magic, kind, schema, length, payload hash); a damaged file is a miss, never an
 * error. The key and identity digests are SHA-256 of JSON array texts written with ", " and ": " separators and
 * ASCII escapes.
 *
 * Environment: DECOMPKIT_OBJ_CACHE is the cache folder (an off word switches the cache off; unset: the folder
 * decompkit-objcache under %LOCALAPPDATA%, else under ~\.cache), DECOMPKIT_OBJ_CACHE_MAX_MB the size limit of the
 * exit-time prune (default 4096), DECOMPKIT_OBJ_RESTORE the way a blob is placed (auto, clone or copy). */
#pragma once
#include "dk/dk.h"
#include "project.h"

/* ================================================================================================= constants */

/* The format version: the "v%d" sub-folder and the first item of the key and link-key texts. */
#define OBJCACHE_VERSION 1
/* The words that switch the cache off (compared to the stripped, lower-cased variable). */
#define OBJCACHE_OFF_WORDS_N 5
extern const char *const objcache_off_words[OBJCACHE_OFF_WORDS_N];
/* The ways a blob is placed. */
#define OBJCACHE_RESTORE_MODES_N 3
extern const char *const objcache_restore_modes[OBJCACHE_RESTORE_MODES_N];
/* The compiler options a cached compile may carry: a regular expression matched at the start of each option (compile
 * with dk_re(OBJCACHE_SAFE_OPTION_PAT, OBJCACHE_SAFE_OPTION_FLAGS)). */
#define OBJCACHE_SAFE_OPTION_PAT                                                                                     \
    "^/(nologo|c|O[12bdgistxy0-9-]*|Ob[0-2]|Oy-?|arch:\\w+|fp:\\w+|GS-?|GL|Gy-?|GR-?|GF-?|Gm-|Gd|Gr|Gz|"             \
    "EH\\w+|MDd?|MTd?|W[0-4]|WX-?|w|wd\\d+|we\\d+|J|TP|TC|Zp\\d*|Zc:\\w+-?|D\\S+|U\\S+|I\\S+)$"
#define OBJCACHE_SAFE_OPTION_FLAGS 0
/* The line prefix of cl /showIncludes. */
#define OBJCACHE_INCLUDE_NOTE "Note: including file:"
/* The keys a memo keeps past which only the ones this process used survive a save. */
#define OBJCACHE_PICKLE_MEMO_LIMIT 400000
/* The cache.h kinds of the files. */
#define OBJCACHE_ENTRY_KIND "objcache/entry"
#define OBJCACHE_MEMO_KIND "objcache/memo"
/* Environment variables. */
#define OBJCACHE_ENV_CACHE "DECOMPKIT_OBJ_CACHE"
#define OBJCACHE_ENV_MAX_MB "DECOMPKIT_OBJ_CACHE_MAX_MB"
#define OBJCACHE_ENV_RESTORE "DECOMPKIT_OBJ_RESTORE"
/* The unit root a new cache starts with (units.roots of the adapter's configuration is the usual source of the real
 * list: objcache_obj_cache_set_unit_roots). */
#define OBJCACHE_DEFAULT_UNIT_ROOT "matching"
/* A file younger than this many seconds is never pruned. A plain global so that a test can set it to -1. */
extern double objcache_prune_min_age;

/* The max_mb argument that means "use objcache_max_mb_setting()". */
#define OBJCACHE_MAX_MB_DEFAULT ((i64)-1)

/* ============================================================================================== module functions */

/* The cache folder, or NULL when the cache is off. The value is stripped; an empty variable is "not set". */
const char *objcache_cache_dir(void);
/* DECOMPKIT_OBJ_RESTORE stripped and lower-cased when it is one of objcache_restore_modes, else "auto". */
const char *objcache_restore_mode(void);
/* DECOMPKIT_OBJ_CACHE_MAX_MB as an integer (blanks, a sign and underscores between digits accepted), 4096 when unset
 * or not an integer. */
i64 objcache_max_mb_setting(void);

/* The lower-case SHA-256 hex (64 chars) of bytes. */
const char *objcache__digest_bytes(const void *data, size_t n);
/* The same of a file's bytes; false when the file cannot be read. */
bool objcache__digest_file(const char *path, const char **hex);
/* The absolute, normalised path in lower case with backslashes: the form paths are compared in. */
const char *objcache__norm(const char *path);
/* Moves src over dst, retrying (sleeps 0.05 * (i + 1) s after attempt i); true when done. After the last failure it
 * removes src (ignoring errors) and returns false. */
bool objcache__replace(const char *src, const char *dst, int attempts);

/* Deletes a file if it exists. true when it is gone (it was missing or deleted); any other failure (an open file):
 * false with the I/O error set. */
bool objcache_remove_file(const char *path);
/* Writes the bytes unless the file already holds exactly them (compared by size first, then bytes; an unchanged file
 * only gets its time updated when touch). true when written. A failure to open or write ends the process with the
 * I/O error text. */
bool objcache_write_if_changed(const char *path, const void *data, size_t n, bool touch);
/* write_if_changed of the UTF-8 bytes of text with its newlines translated: newline NULL turns "\n" into the
 * platform's "\r\n"; "" and "\n" leave the text; any other value replaces each "\n" with it. */
bool objcache_write_text_if_changed(const char *path, DkStr text, const char *newline, bool touch);

/* The first 16 hex chars of the SHA-256 of a file's bytes: the version of the code a memo's answers come from. A
 * missing file ends the process with the I/O error text. */
const char *objcache_file_version(const char *path);
/* The same value for bytes already in hand (a build stamp, a file read elsewhere). */
const char *objcache_version_of(const void *data, size_t n);

/* ============================================================================================== ObjCache */

typedef struct ObjcacheObjCache ObjcacheObjCache;
/* The members callers read; everything else lives behind priv_. Counters change under the cache's lock; read them
 * after the compile threads joined. */
struct ObjcacheObjCache {
    const char *root;         /* the checkout, in the objcache__norm form */
    const char *folder;       /* <cache dir>\v1 */
    const char *objs;         /* folder\objs */
    const char *keys;         /* folder\keys */
    const char *identity;     /* sha256 hex of the JSON text [[version, digest of the compiler executable (null when
                               * missing)], INCLUDE lower-cased, sorted listing of every file under each INCLUDE
                               * folder, relative to it, lower case] */
    const char *include_env;  /* the compiler's INCLUDE value ("" when absent) */
    const char *mode;         /* objcache_restore_mode() at construction */
    i64 hits, misses, stored, uncacheable;
    void *priv_;              /* the memo tables, the unit roots, the restored/inputs_of tables, the clone state and
                               * the lock; nothing else reads it */
};

/* Makes folder\v1\objs and keys; the unit roots start as {OBJCACHE_DEFAULT_UNIT_ROOT}. NULL with *err (may be NULL)
 * = the I/O error text when a folder cannot be made. folder must not be NULL (pass objcache_cache_dir()).
 * compiler_bin is the compiler executable (its digest enters the identity when the file exists; "" or NULL: none),
 * include_env the INCLUDE value (the files under its folders enter the identity), compiler_version a text naming the
 * compiler's version or identity. Walks the INCLUDE folders and hashes the compiler: slow, so one per process. */
ObjcacheObjCache *objcache_obj_cache_new_with(const char *root, const char *folder, const char *compiler_bin,
                                              const char *include_env, const char *compiler_version, const char **err);
/* The same from a DkCompiler (objcache_project.c): the version text is the base name and sha256 of each of
 * compiler->identity_files, joined; the executable is compiler->cl and INCLUDE is the compiler's include folders
 * joined with ';' (an INCLUDE entry of its environment when it has no include folders). A NULL compiler is an empty
 * identity. */
ObjcacheObjCache *objcache_obj_cache_new(const char *root, const DkCompiler *compiler, const char *folder,
                                         const char **err);
/* NULL when enabled is false, the cache is off (objcache_cache_dir() NULL) or the folders cannot be made. Registers
 * the exit prune: once per cache folder per process, an atexit action that prunes and, when it deleted files, prints
 * to stderr "object cache: pruned %d file(s), %.1f GB -> %.1f GB (limit %.1f GB)\n"; a failure prints
 * "object cache: prune failed: <text>\n" and never changes the exit code. */
ObjcacheObjCache *objcache_open_cache(const char *root, const DkCompiler *compiler, bool enabled);
/* open_cache for a loaded project and one of its targets: root is the project's root, the compiler the target's
 * (dk_project_compiler), the unit roots those of the project's units (the first folder of each unit's path). */
ObjcacheObjCache *objcache_open_project(const DkProject *p, int target, bool enabled);

/* Replaces the unit roots: folders of the checkout (relative, any slashes) whose files are the units' own. Include
 * files found there are covered by the shadow check; a compile that read any other checkout file is not cached; an
 * object that names a unit root's folder is kept under the rooted key. Call it before the cache is used by other
 * threads. */
void objcache_obj_cache_set_unit_roots(ObjcacheObjCache *c, const char *const *roots, size_t n);

/* The memoised SHA-256 hex of a file (key: objcache__norm(path)); NULL when it cannot be read (memoised too).
 * rehash forgets that memo entry (a candidate source rewritten between compiles). */
const char *objcache_obj_cache_digest(ObjcacheObjCache *c, const char *path);
void objcache_obj_cache_rehash(ObjcacheObjCache *c, const char *path);
/* The digest now, not memoised; NULL when the file cannot be read. */
const char *objcache_obj_cache_digest_now(const char *path);
/* rel: a path inside the checkout relative to it with forward slashes, any other path absolute and normalised.
 * absolute: key itself when absolute, else root joined with key (forward slashes turned into backslashes). */
const char *objcache_obj_cache_rel(const ObjcacheObjCache *c, const char *path);
const char *objcache_obj_cache_absolute(const ObjcacheObjCache *c, const char *key);
/* names: {lower-case basename: sorted relative paths (a DkStrVec* in .p)} of the files under the unit roots, built
 * once. shadow: the files under the unit roots named like one of the dependencies (basename of the dependency with
 * "/" turned into "\", lower-cased), as a sorted, de-duplicated vector of relative paths. */
const DkMap *objcache_obj_cache_names(ObjcacheObjCache *c);
DkStrVec objcache_obj_cache_shadow(ObjcacheObjCache *c, const char *const *deps, size_t n);
/* The entry key (sha256 hex of the JSON text [VERSION, identity, options, rel(source), digest of source]), or NULL
 * when an option does not match OBJCACHE_SAFE_OPTION_PAT or the source cannot be read. An option starting "/I" is
 * rewritten "/I" + rel(rest) before it enters the text. */
const char *objcache_obj_cache_key(ObjcacheObjCache *c, const char *const *options, size_t n_options,
                                   const char *source);
/* The key of an object that depends on where the checkout is: sha256 hex of key + "\n" + root. */
const char *objcache_obj_cache_rooted(const ObjcacheObjCache *c, const char *key);

/* Drops what this process remembers of the object at that path (restored blob, stat, inputs_of). */
void objcache_obj_cache_forget(ObjcacheObjCache *c, const char *obj);
/* The digest of a file this cache restored and nothing rewrote since (same size and mtime_ns as just after the copy
 * or clone) = its blob's name without ".obj"; NULL otherwise. */
const char *objcache_obj_cache_known_digest(ObjcacheObjCache *c, const char *path);
/* The bytes of an object this cache restored, read from its blob and accepted only when they hash to the blob's
 * name; false otherwise. The bytes are arena-allocated. */
bool objcache_obj_cache_data_of(ObjcacheObjCache *c, const char *obj, DkStr *data);
/* The checkout files (relative, sorted) the compile of an object this process restored or stored read, and that
 * entry's shadow list. false when none is recorded. */
bool objcache_obj_cache_inputs_of(ObjcacheObjCache *c, const char *path, DkStrVec *deps, DkStrVec *shadow);

/* Looks through the entries of key, then of rooted(key), in file order; the first whose dependencies' digests all
 * equal the recorded ones, whose shadow list equals the current one and whose blob can be placed (a clone or a copy
 * per the restore mode, the blob verified against its name first; a damaged blob is deleted and the entry skipped) is
 * a hit: the object is put at obj (whatever was there is deleted first), the blob and entry files are touched (LRU),
 * the restored and inputs_of tables are filled and hits++. true with *text = the entry's text (the compiler output
 * lines kept, "\n" joined; may be empty); false counts misses++. A damaged or missing entry file is a miss. */
bool objcache_obj_cache_lookup(ObjcacheObjCache *c, const char *key, const char *obj, DkStr *text);
/* Records a successful compile run with /showIncludes (output: its full stdout and stderr; the dependencies are its
 * OBJCACHE_INCLUDE_NOTE lines, each joined to cwd and normalised). Does nothing when obj cannot be read; counts
 * uncacheable++ (and records nothing) when a dependency is a checkout file outside the unit roots, when there are
 * none, or when one cannot be hashed; an object that names the checkout (the lower-cased root + "\" + a unit root, or
 * its forward-slash form, found in the bytes, lower-cased) is stored under rooted(key). Writes the blob (temp file in
 * objs, then objcache__replace) when missing or damaged, then the entry file keeping the 7 newest older entries whose
 * deps differ, and sets inputs_of. A write error ends the process with its text. */
void objcache_obj_cache_store(ObjcacheObjCache *c, const char *key, const char *obj, const char *cwd, DkStr output,
                              DkStr text);

/* sha256 hex of the JSON text [VERSION, identity, digest(link), rsp_text, then one digest per input: known_digest(path)
 * when set, else the file's digest now (not memoised)]; NULL when an input cannot be read. */
const char *objcache_obj_cache_link_key(ObjcacheObjCache *c, const char *link, DkStr rsp_text,
                                        const char *const *inputs, size_t n_inputs);
typedef enum {
    OBJCACHE_LINK_MISS = 0,   /* nothing is cached (and nothing is left at the output paths) */
    OBJCACHE_LINK_HIT,        /* every output was placed; hits++ */
    OBJCACHE_LINK_FAILED      /* this link failed before; *failed_text is the linker's output; hits++ */
} ObjcacheLinkResult;
/* outputs are the paths in the stored order (a different count is a miss). On an I/O error placing one, every output
 * path is removed and the answer is OBJCACHE_LINK_MISS. */
ObjcacheLinkResult objcache_obj_cache_link_lookup(ObjcacheObjCache *c, const char *key, const char *const *outputs,
                                                  size_t n_outputs, DkStr *failed_text);
/* Stores each output as objs\<sha256>.bin; an unreadable output silently stores nothing. With failed set (not NULL)
 * the entry records only the text (pass no outputs then). */
void objcache_obj_cache_link_store(ObjcacheObjCache *c, const char *key, const char *const *outputs, size_t n_outputs,
                                   const DkStr *failed);

/* LRU by mtime over objs, the key folders and the *.memo files of the top folder; ".tmp" files over an hour old go
 * first; the "pruned" stamp file limits it to once an hour unless force; nothing younger than objcache_prune_min_age
 * is deleted. false = skipped by the stamp, or the stamp could not be written; else *out is (files deleted, bytes
 * before, bytes after, limit in bytes). */
typedef struct {
    i64 deleted, before, after, limit;
} ObjcachePruneResult;
bool objcache_obj_cache_prune(ObjcacheObjCache *c, i64 max_mb, bool force, ObjcachePruneResult *out);
/* "object cache: %d reused, %d compiled" + (", %d not cacheable" when uncacheable > 0). */
const char *objcache_obj_cache_summary(const ObjcacheObjCache *c);

/* ============================================================================================== PickleMemo */

/* The answers of a pure function kept on disk beside the objects, read once per process and merged back at exit when
 * new answers were added. Off with the cache (path NULL: get always misses, put is a no-op on disk but still
 * remembers in memory).
 *
 * Keys are DkStr (any bytes); values are byte blobs (DkStr, p != NULL even when empty) or the typed forms below. A
 * miss is "not found"; an empty list is a stored value, so blobs may be empty and found. The file is
 * <cache dir>\v1\<name>-<version>.memo, an append-only dkcore log (cache.h: kind OBJCACHE_MEMO_KIND, schema 1, stamp
 * "<name>-<version>"); a record is {key bytes, value bytes}. Loading replays the records in order (later ones win)
 * and a torn record is skipped; a file that is not a valid log, or has another stamp, is replaced by an empty one.
 * save() (also run at exit, registered when the table is first loaded) appends one record per key added or changed by
 * this process (other processes' appends are never lost); when the replayed table holds more than limit keys it
 * compacts instead: the keys this process used (get hit or put) are written to a new log that atomically replaces
 * the file. The version should name the code the answers come from (objcache_file_version or objcache_version_of).
 * Thread-safety: get/put/save lock internally; a returned blob is valid for the process's life (the memo keeps its
 * values on the heap and never frees or moves one): do not modify it. */
typedef struct ObjcachePickleMemo ObjcachePickleMemo;

/* Never fails. The memo is loaded lazily by the first get/put. name and version are copied. A memo is meant to live
 * for the process: there is no free. */
ObjcachePickleMemo *objcache_pickle_memo_new(const char *name, const char *version);
/* The log's path, or NULL when the cache is off. */
const char *objcache_pickle_memo_path(const ObjcachePickleMemo *m);
/* Replaces OBJCACHE_PICKLE_MEMO_LIMIT for this memo. */
void objcache_pickle_memo_set_limit(ObjcachePickleMemo *m, size_t limit);
/* true with *value (a blob; counts the key as used) on a hit; false on a miss. */
bool objcache_pickle_memo_get(ObjcachePickleMemo *m, DkStr key, DkStr *value);
/* Remembers the value (the bytes are copied), marks the key used and the memo dirty. */
void objcache_pickle_memo_put(ObjcachePickleMemo *m, DkStr key, DkStr value);
/* The exit-time merge described above; a no-op when nothing was added or the cache is off. Any write error is
 * swallowed. Callable explicitly. */
void objcache_pickle_memo_save(ObjcachePickleMemo *m);

/* Typed helpers over the blob: the first byte is a tag ('s' str, 'S' vector of str, 'i' i64, 'b' bool, 'U' vector of
 * u32), then the payload (cache.h writer/reader encodings). A get on a blob with another tag or a damaged payload is
 * a miss (false), so a layout change cannot crash a reader. */
void objcache_pickle_memo_put_str(ObjcachePickleMemo *m, DkStr key, DkStr value);
bool objcache_pickle_memo_get_str(ObjcachePickleMemo *m, DkStr key, DkStr *value);
void objcache_pickle_memo_put_strs(ObjcachePickleMemo *m, DkStr key, const DkStr *values, size_t n);
bool objcache_pickle_memo_get_strs(ObjcachePickleMemo *m, DkStr key, DkStrVec *values);
void objcache_pickle_memo_put_i64(ObjcachePickleMemo *m, DkStr key, i64 value);
bool objcache_pickle_memo_get_i64(ObjcachePickleMemo *m, DkStr key, i64 *value);
void objcache_pickle_memo_put_bool(ObjcachePickleMemo *m, DkStr key, bool value);
bool objcache_pickle_memo_get_bool(ObjcachePickleMemo *m, DkStr key, bool *value);
void objcache_pickle_memo_put_u32s(ObjcachePickleMemo *m, DkStr key, const u32 *values, size_t n);
bool objcache_pickle_memo_get_u32s(ObjcachePickleMemo *m, DkStr key, DkU32Vec *values);

/* ============================================================================================== command line */

/* `objcache status|prune [--max-mb N]`; argv is the arguments after the program name. Usage errors exit 2 with the
 * argument parser's text. Returns 0 always (stdout):
 *   cache off:  "object cache: off (DECOMPKIT_OBJ_CACHE)"
 *   prune:      "object cache <folder>: pruned <n> file(s), <before> GB -> <after> GB (limit <limit> GB)" (forced
 *               prune; %.1f of bytes / 2**30)
 *   status:     "object cache <folder>: <total> GB of <limit> GB (objs <n> files <x> GB, keys <n> files <x> GB, pickles
 *               <n> files <x> GB); last pruned <YYYY-MM-DD HH:MM local time of the "pruned" stamp's mtime, or never>"
 *               (limit = --max-mb or objcache_max_mb_setting(), in bytes; keys counts the files of every sub-folder
 *               of keys\; pickles counts the *.memo files of the folder).
 * Both build a cache for the current directory with no compiler, so they create the v1\objs and keys folders. */
int objcache_main(int argc, char **argv);
