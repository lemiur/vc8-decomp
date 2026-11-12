// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The project adapter: everything the diagnostic tools know about a matching project comes from its configuration
 * (config/ctools.json, merged with config/ctools.local.json; docs/c-toolkit-design.md section 5), never from code.
 *
 *   targets       the reference images to match (up to DK_MAX_TARGETS), each with a pinned sha256, an optional image
 *                 base, per-target preprocessor defines, ordered symbol sources and an optional compiler override;
 *   units         the source files (discovered under units.roots, plus the explicit unit maps) with their options;
 *   annotations   marker lines in a unit, matched by a configured regex, naming a kind, targets and addresses, with
 *                 companion lines (symbol, stop, pending) and a unit-level flags line;
 *   symbols       the names of a target's addresses (TSV, PDB or MSVC map sources; the first source naming an address
 *                 wins);
 *   compiler, backend, referents, well-known names: what the build and compare half (project_image.c,
 *                 project_build.c, project_compare.c) needs.
 *
 * Values in the configuration may be references into the project's own configuration files: an object
 * {"$from": "config/x.json#/json/pointer"} (RFC 6901) is replaced by the value it points at, an array element that
 * resolves to an array is spliced in, and {"$from": ..., "default": v} gives v when the file or the pointer is
 * missing. Strings interpolate ${name} from "vars" and the built-ins ${root} and ${primary} (the main checkout of a
 * git worktree) at load time; ${target}, ${unit}, ${out}, ${objects} and ${roots} are left in place and expanded at
 * use by dk_project_expand. Relative paths are relative to the root. Every string the adapter hands out is
 * NUL-terminated (DkStrVec items included) and lives as long as the project's arena.
 *
 * Implemented by project_config.c (load, accessors, expansion), project_annot.c (annotations, symbol binding),
 * project_symbols.c (symbol sources) and, for the second half of this header, project_image.c, project_build.c and
 * project_compare.c. */
#pragma once
#include "dk/arena.h"
#include "dk/re.h"
#include "dk/str.h"
#include "dk/vec.h"

#define DK_MAX_TARGETS 8
#define DK_NO_ADDR 0u
#define DK_PROJECT_SCHEMA "decompkit-project/1"

/* ---- errors ------------------------------------------------------------------------------------------------------
 * A failed call returns NULL or false and fills *err (when err is not NULL): code is one of base.h's DK_ERR_* (0 for
 * no error), msg one line naming the file, the line or the configuration key at fault. */
typedef struct {
    int code;
    char msg[1024];
} DkErr;
void dk_err_set(DkErr *err, int code, DK_PRINTF_FMT const char *fmt, ...);
void dk_err_clear(DkErr *err);

/* ---- configuration model ----------------------------------------------------------------------------------------- */
typedef enum { DK_ANN_FUNCTION, DK_ANN_DATA, DK_ANN_DECL, DK_ANN_VTABLE } DkAnnKind;
typedef enum { DK_BACKEND_OBJECT, DK_BACKEND_LINK, DK_BACKEND_MANIFEST } DkBackendKind;
typedef enum { DK_SYM_TSV, DK_SYM_PDB, DK_SYM_MAP, DK_SYM_CANDIDATES } DkSymKind;

typedef struct DkProject DkProject; /* opaque: configuration, targets, units, caches */
typedef struct DkImage DkImage;     /* a mapped reference image (project_image.c) */
typedef struct DkSymbols DkSymbols; /* a target's names by address (project_symbols.c) */

/* One symbol source of a target. tsv: a header row, then one row per symbol; the columns named col_name, col_va
 * (a VA; when the file has no such column, col_rva plus the image base) and col_size (empty or missing: unknown).
 * Numbers are decimal or 0x-prefixed hex. pdb: the publics and module procedures of a PDB 7.00. map: the
 * "Publics by Value" and "Static symbols" of an MSVC linker map. candidates: the "referents" of a candidates file
 * ({"referents": {"<binary>": {"<name>": {"va", "kind", "size"}}}}; col_name names the binary when the file has
 * several): its named objects and functions (imports, literals and typed members are not symbols). */
typedef struct {
    DkSymKind kind;
    const char *path;                                  /* absolute, forward slashes */
    const char *col_name, *col_va, *col_rva, *col_size; /* tsv: default "name", "va", "rva", "size" */
} DkSymSource;

/* The compiler: the project's "compiler" block, with a target's own "compiler" block laid over it member by member
 * (a member the target gives replaces the project's). */
typedef struct {
    const char *cl;                  /* absolute path of cl.exe */
    DkStrVec env_names, env_values;  /* "env": NAME -> value, in configuration order */
    DkStrVec path_prepend;           /* folders put before PATH */
    DkStrVec base_flags;             /* every compile */
    DkStrVec c_flags, cpp_flags;     /* added for .c / other units */
    DkStrVec include;                /* /I folders, absolute */
    DkStrVec identity_files;         /* the files whose digests identify the compiler (objcache keys) */
    bool show_includes;
    DkStrVec cdecl_import_dlls;      /* frame: import libraries (shell patterns) whose functions are cdecl; unset: "msvcr*" */
    bool cdecl_import_dlls_set;
    DkStrVec *flag_variants;         /* flag_sweep's one-option variants; NULL when not configured */
    size_t n_flag_variants;
} DkCompiler;

typedef struct {
    const char *name;
    const char *image_path;          /* absolute, forward slashes */
    u8 sha256[32];
    bool has_sha256;                 /* false only when the configuration gives none */
    u32 image_base;                  /* 0: not configured */
    DkStrVec defines;                /* "NAME=1" or "NAME" */
    DkSymSource *symbols;
    size_t n_symbols;
    const DkCompiler *compiler;      /* the effective compiler of this target */
    DkImage *image;                  /* opened lazily by dk_target_image */
    DkSymbols *syms;                 /* loaded lazily by dk_project_symbols */
} DkTarget;

typedef struct {
    const char *path;                /* repository-relative, forward slashes */
    DkStrVec compile_flags, remove_flags, link_flags;
    DkStrVec link_with;              /* link backend: the other sources compiled and linked with this one
                                      * (repository-relative, without the unit itself, sorted, unique) */
    DkStrVec link_roots;             /* link backend: extra decorated link roots (/INCLUDE:) */
    bool gl, gl_set;              /* "gl" of the unit map; gl_set false when the map does not say */
    bool flags_line;                 /* the unit's flags line (annotations.flags) is applied (default true) */
    bool per_target;                 /* the unit's text names a target define: compiled once per target */
    u32 target_mask;                 /* bit t: listed in target t's unit map; all targets' bits otherwise */
} DkUnit;

typedef struct {
    DkBackendKind kind;
    /* link */
    const char *linker;              /* absolute */
    DkStrVec link_argv;              /* ${out} ${objects} ${roots} ${target} ${unit} still unexpanded */
    const char *roots;               /* "annotations" */
    const char *map_format;          /* "msvc" */
    bool discovery_compile;
    /* manifest */
    DkStrVec manifest_command;       /* unexpanded */
    const char *manifest_path;       /* NULL: the command prints or writes the manifest */
} DkBackend;

typedef struct {
    const char *file;                /* absolute */
    const char *format;              /* "json-symbols" or "tsv" */
} DkReferentFile;

/* The annotation grammar. The marker regex (Python syntax, compiled multi-line) has the named groups
 *   kind                       optional: its text is looked up in kinds (absent: every marker is a function);
 *   target+addr grammar        target (or binary) and addr (or va): one target per marker line;
 *   per-target grammar         addr_<target> for each declared target: several addresses per line, "0" for none.
 * groups overrides those names. Addresses are hex, with or without 0x. The name rule:
 *   declaration   the first identifier followed by "(" between the marker (and its companion lines) and the body's
 *                 "{" (data: the last identifier before "=", ";", "[" or "{"); bound to a compiled symbol by the MSVC
 *                 rules (_name, _name@N, ?name@...), an explicit symbol line winning;
 *   next_line     the qualified name (Class::Method, templates, destructors, operators) of the first line after the
 *                 companions; a body is optional (an explicit instantiation ends with ";"); bound through
 *                 undecoration (dk_symbol_matches).
 * Companion lines are the "//" comment lines right after the marker line; symbol (group 1), stop (groups reason and
 * optional target) and pending (groups reason and optional target) are searched there. The flags regex (group 1, or
 * a group named flags) is searched in the first flags_lines lines of the unit. */
typedef struct {
    const char *text;
    DkAnnKind kind;
} DkAnnKindName;

typedef enum { DK_ADDR_TARGET_ADDR, DK_ADDR_PER_TARGET } DkAddrGroups;
typedef enum { DK_NAME_DECLARATION, DK_NAME_NEXT_LINE } DkNameRule;

typedef struct {
    /* as configured */
    const char *marker;              /* required */
    DkAnnKindName *kinds;
    size_t n_kinds;
    DkAddrGroups addr_groups;        /* default target+addr */
    DkNameRule name;                 /* default declaration */
    const char *group_kind, *group_target, *group_addr; /* NULL: the defaults above */
    const char *symbol, *stop, *pending, *flags;        /* NULL: not configured */
    int flags_lines;                 /* default 8 */
    /* filled by dk_annot_config_compile */
    DkRe *re_marker, *re_symbol, *re_stop, *re_pending, *re_flags;
    int g_kind, g_target, g_addr;    /* group numbers, -1 when absent */
    int g_addr_target[DK_MAX_TARGETS];
    int ntargets;
    const char *target_names[DK_MAX_TARGETS];
} DkAnnotConfig;

/* Compiles the patterns of c and resolves its groups against the targets (in their configuration order). */
bool dk_annot_config_compile(DkAnnotConfig *c, const char *const *target_names, size_t ntargets, DkErr *err);

/* ---- loading and accessors (project_config.c) -------------------------------------------------------------------
 * root NULL: dk_root(). config NULL: <root>/config/ctools.json, merged with <root>/config/ctools.local.json when it
 * exists (objects merged member by member, anything else replaced). Unknown keys are errors. */
DkProject *dk_project_load(DkArena *a, const char *root, const char *config, DkErr *err);
/* A second, independent copy of the project (its own arena, so another thread may use it) whose build folder is
 * build_dir (the scorer's concurrent builds). The caller owns the copy and never frees it. */
DkProject *dk_project_clone(const DkProject *p, const char *build_dir, DkErr *err);
DkArena *dk_project_arena(const DkProject *p);
const char *dk_project_root(const DkProject *p);     /* absolute, forward slashes, no trailing slash */
const char *dk_project_primary(const DkProject *p);  /* the main checkout (the root itself outside a worktree) */
const char *dk_project_config_path(const DkProject *p);
char *dk_project_path(DkArena *a, const DkProject *p, const char *rel); /* rel against the root; absolute kept */

size_t dk_project_ntargets(const DkProject *p);
const DkTarget *dk_project_target(const DkProject *p, int index);
DkTarget *dk_project_target_mut(DkProject *p, int index);
int dk_project_target_index(const DkProject *p, const char *name); /* -1 if unknown */

const DkUnit *dk_project_units(const DkProject *p, size_t *n);     /* sorted by path */
const DkUnit *dk_project_unit(const DkProject *p, const char *path_or_stem); /* a unique stem also finds it */
const DkStrVec *dk_project_unit_roots(const DkProject *p);   /* units.roots, repository-relative */

const DkCompiler *dk_project_compiler(const DkProject *p, int target); /* target -1: the project's own block */
const DkBackend *dk_project_backend(const DkProject *p);
const DkAnnotConfig *dk_project_annot_config(const DkProject *p);
const DkReferentFile *dk_project_referents(const DkProject *p, size_t *n);
bool dk_project_well_known_imports(const DkProject *p);
const DkStrVec *dk_project_well_known_symbols(const DkProject *p);
const DkStrVec *dk_project_text_check_paths(const DkProject *p);
const DkStrVec *dk_project_text_check_no_bom(const DkProject *p);
const char *dk_project_build_dir(const DkProject *p, const char *tool); /* <build_dir>/<tool>; tool NULL: build_dir */
const char *dk_project_var(const DkProject *p, const char *name);      /* a resolved var, NULL when unknown */

/* Expands the use-time built-ins ${target}, ${unit}, ${out}, ${objects}, ${roots} (a NULL value leaves the reference
 * in place); any other ${...} left is an error. */
typedef struct {
    const char *target, *unit, *out, *objects, *roots;
} DkExpandVars;
char *dk_project_expand(DkArena *a, const DkProject *p, const char *s, const DkExpandVars *v, DkErr *err);

/* The JSON value a "file#/pointer" reference names (the $from rule, also for tools that read the project's own
 * configuration); NULL with *err when the file or the pointer is missing. */
struct DkJson;
struct DkJson *dk_project_json_ref(DkProject *p, const char *ref, DkErr *err);

/* ---- annotations (project_annot.c) ------------------------------------------------------------------------------ */
typedef struct {
    DkAnnKind kind;
    const DkUnit *unit;
    int line;                        /* 1-based line of the marker */
    int body_start, body_end;        /* 1-based lines of the declaration's start and of the body's "}" (or ";") */
    u32 addr[DK_MAX_TARGETS];        /* DK_NO_ADDR where the target has no copy */
    u32 target_mask;                 /* bit t: addr[t] given */
    const char *name;                /* source name: plain (declaration) or qualified (next_line); NULL if none */
    const char *decl;                /* the declaration text up to "{" or ";", whitespace runs collapsed */
    const char *symbol;              /* explicit decorated name (symbol line), else NULL */
    u32 stop_mask;                   /* bit t: parked for target t */
    const char *stop_reason;
    u32 pending_mask;
    const char *pending;             /* pending reason, NULL when none */
    const char *flags;               /* the unit's flags line (when the unit applies it), else NULL */
} DkAnnot;

/* The annotations of one unit's text, in text order. Errors: a marker naming an unknown target or kind, a bad
 * address, a duplicate (target, address), a function marker without a body or name. */
DkAnnot *dk_annot_parse(DkArena *a, const DkAnnotConfig *c, const DkUnit *u, DkStr text, size_t *n, DkErr *err);
/* Reads the unit (UTF-8, a BOM skipped) and parses it. */
DkAnnot *dk_annotations(DkProject *p, const DkUnit *u, size_t *n, DkErr *err);
/* The unit's annotation named name (plain or qualified) at addr in any target; addr DK_NO_ADDR: any. */
const DkAnnot *dk_find_annotation(DkProject *p, const DkUnit *u, const char *name, u32 addr);
bool dk_stopped(const DkAnnot *a, int target);
/* The unit-level flags line of a unit's text, NULL when none. */
const char *dk_annot_flags_line(DkArena *a, const DkAnnotConfig *c, DkStr text);

/* Whether a decorated (or plain C) symbol stands for the annotated qualified name: the undecorated name is compared
 * as a whole, overloads told apart by the parameter list of decl when one is given. */
bool dk_symbol_matches(const DkAnnot *an, const char *decorated);
/* The compiled symbol an annotation stands for, out of a unit's defined symbols: the explicit symbol (which must be
 * among them), else by the name rule. NULL with *err when none or several fit. */
const char *dk_annot_bind(const DkAnnot *an, DkNameRule rule, const char *const *symbols, size_t n, DkErr *err);

/* ---- symbol sources (project_symbols.c) --------------------------------------------------------------------------- */
typedef struct {
    u32 va;
    u32 size;                        /* 0: unknown */
    const char *name;
} DkSymbol;

/* Loads the sources in order: an address keeps the name of the first source naming it; a later source only adds
 * addresses (and fills an unknown size). image_base is needed by a PDB source and a TSV without a VA column. */
DkSymbols *dk_symbols_load(DkArena *a, const DkSymSource *srcs, size_t n, u32 image_base, DkErr *err);
DkSymbols *dk_symbols_new(DkArena *a);
void dk_symbols_add(DkSymbols *s, u32 va, u32 size, const char *name, bool replace); /* layers names on top */
const DkSymbol *dk_symbols_all(const DkSymbols *s, size_t *n);  /* sorted by va */
const DkSymbol *dk_symbols_at(const DkSymbols *s, u32 va);      /* the symbol starting at va */
const DkSymbol *dk_symbols_containing(const DkSymbols *s, u32 va, u32 *start); /* sized, else the nearest below */
const DkSymbol *dk_symbols_find(const DkSymbols *s, const char *name);        /* by exact name */
u32 dk_symbols_next(const DkSymbols *s, u32 va);                 /* the next start above va, 0 when none */
/* The target's sources, loaded once and cached (the target's image base, read from the image when not configured). */
DkSymbols *dk_project_symbols(DkProject *p, int target, DkErr *err);

/* ---- reference images, building and comparing (project_image.c, project_build.c, project_compare.c) ------------- */
typedef enum { DK_MATCH, DK_DIFF, DK_SIZE, DK_REFERENT, DK_UNRESOLVED, DK_MISSING, DK_ERROR } DkStatus;

typedef struct {
    u32 offset;
    u16 type;
    const char *symbol;
    i32 addend;
} DkReloc;
typedef struct {
    const char *symbol;
    DkStr code;
    DkReloc *relocs;
    size_t n_relocs;
    u32 va;
} DkFunc;

typedef enum { DK_REF_SAME, DK_REF_OTHER, DK_REF_UNRESOLVED } DkRefVerdict;
typedef struct {
    u32 offset;
    u32 ours, theirs;
    const char *name;
    DkRefVerdict verdict;
} DkRefCheck;

typedef struct {
    const DkAnnot *ann;
    int target;
    DkStatus status;
    DkFunc ours;
    DkStr theirs;
    u32 theirs_va;
    DkRefCheck *refs;
    size_t n_refs;
    const char *error;
} DkResult;

DkImage *dk_target_image(DkProject *p, int target, DkErr *err); /* verifies sha256 */
bool dk_image_read(const DkImage *im, u32 va, size_t n, DkStr *out);
const char *dk_image_name_at(const DkImage *im, u32 va, u32 *start);
bool dk_image_function_size(const DkImage *im, u32 va, u32 *size);
const DkReloc *dk_image_relocs(const DkImage *im, u32 va, size_t n, size_t *count);

/* The structure of an image, for tools that walk it (disassemblers, simulators) without parsing the file again. */
typedef struct DkImageSection {
    DkStr name;          /* ".text" (the name without its NUL padding) */
    u32 va;              /* absolute (image base added) */
    u32 vsize, raw_size; /* virtual size, size of the raw data */
    u32 raw;             /* file offset of the raw data */
    u32 chars;           /* the section's characteristics */
} DkImageSection;
/* Any PE32 file, read whole: no hash check and no symbols (dk_target_image is the configured, verified one). */
DkImage *dk_image_open(DkArena *a, const char *path, DkErr *err);
u32 dk_image_base(const DkImage *im);
const char *dk_image_path(const DkImage *im);
const u8 *dk_image_file(const DkImage *im, size_t *n);                  /* the whole file */
const DkImageSection *dk_image_sections(const DkImage *im, size_t *n); /* in the file's section-table order */
/* The section mapping va (its virtual extent as the loader maps it), NULL when none does. */
const DkImageSection *dk_image_section_of(const DkImage *im, u32 va);
/* The end VA of the section holding va, cut to its raw data; 0 when no section holds va. */
u32 dk_image_section_end(const DkImage *im, u32 va);
/* Whether a section maps va (its raw data or the zero-filled rest: .bss counts). */
bool dk_image_has_va(const DkImage *im, u32 va);
const u32 *dk_image_base_relocs(const DkImage *im, size_t *n); /* the VAs of the HIGHLOW words, sorted */
const char *dk_image_import_at(const DkImage *im, u32 va);      /* "__imp_<import>" for an IAT slot, else NULL */
u32 dk_image_security_cookie(const DkImage *im);                /* the load config's cookie VA, 0 when none */

typedef struct {
    DkStrVec extra_flags;            /* appended to the unit's options */
    DkStrVec remove_flags;           /* options left out of the unit's own list first (case-insensitive, exact token) */
    const char *source_override;
    bool use_cache;
} DkBuildOpts;
DkFunc *dk_build_unit(DkProject *p, const DkUnit *u, int target, const DkBuildOpts *o, size_t *n, DkStr *log,
                      DkErr *err);
DkResult *dk_compare(DkProject *p, const DkAnnot *a, int target, const DkFunc *ours, DkErr *err);
DkResult *dk_compare_unit(DkProject *p, const DkUnit *u, int target, const DkBuildOpts *o, size_t *n, DkErr *err);
const char *dk_status_name(DkStatus s);
