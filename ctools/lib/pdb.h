// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* pdb: a reader of PDB 7.00 files (the multi-stream file, MSF) as the Visual C++ 2005 to 2008 linkers wrote them: the
 * PDB info stream, the DBI stream (modules, section contributions, section headers), the symbol record stream
 * (publics), each module's symbols (compile record, environment block, procedures), its C13 or C11 line tables, and
 * the TPI stream (types: names, sizes, members).
 *
 * Memory comes from the calling thread's arena (dk_arena()) and is never freed; the file stays mapped for the life of
 * the process. Malformed input throws DK_ERR_FORMAT or DK_ERR_IO (dk_throw, base.h): with no DK_TRY active that is
 * fatal, which is what a command line tool wants. Names are Latin-1 bytes in the file and UTF-8 in the results. */
#pragma once
#include "dk/dk.h"

/* ---- MSF ------------------------------------------------------------------------------------------------------- */
typedef struct DkMsf DkMsf;
/* Opens and validates a PDB 7.00 container; reads the stream directory. */
DkMsf *dk_msf_open(const char *path);
size_t dk_msf_stream_count(const DkMsf *m);
/* The bytes of stream i (empty for a nil stream, 0xFFFF or out of range). */
DkStr dk_msf_stream(const DkMsf *m, u32 i);

/* ---- module symbols -------------------------------------------------------------------------------------------- */
typedef struct {
    bool present;        /* a compile record (S_COMPILE2/3, and the legacy ones with legacy set) was read */
    const char *machine; /* "0x3 386" */
    const char *flags_hex; /* "0x10101" */
    const char *frontend_ver, *backend_ver; /* "14.0.50727.762"; "" for the oldest record */
    const char *compiler; /* the compiler's version string */
    i64 language;        /* CV_CFL_LANG: the low byte of the flags */
} DkPdbCompile;
typedef struct {
    const char *kind; /* "gproc" (global) or "lproc" (local) */
    const char *name;
    u16 seg;
    u32 off, length, typind;
} DkPdbProcSym;
typedef DK_VEC(DkPdbProcSym) DkPdbProcSymVec;
/* The compile record, the environment block (a DkMap of key -> value, `.p` a NUL-terminated string; keys such as
 * "cwd", "cl", "cmd", "src", "pdb") and the procedures of one module's symbol data (the bytes after its signature).
 * A record that does not parse is skipped. legacy: also the 16-bit-type and Pascal-string record kinds. */
void dk_pdb_parse_module_symbols(DkStr symdata, bool legacy, DkPdbCompile *comp, DkMap **env, DkPdbProcSymVec *procs);

/* ---- types ----------------------------------------------------------------------------------------------------- */
typedef struct DkPdbTypes DkPdbTypes;
/* The TPI stream (stream 2's bytes). */
DkPdbTypes *dk_pdb_types_new(DkStr tpi);
u32 dk_pdb_types_first(const DkPdbTypes *t); /* the first type index of the stream (0x1000) */
u32 dk_pdb_types_end(const DkPdbTypes *t);   /* one past the last type index read */
/* The leaf kind of a record (LF_*), 0 for a built-in or missing type. */
u32 dk_pdb_types_leaf(const DkPdbTypes *t, u32 ti);
/* The type spelled as C++ would: "unsigned int", "Foo*", "int (__cdecl)(int, Foo*)", "int (__thiscall Foo::)()"; a
 * record that cannot be read is "<err 0x1234>", a missing one "<missing 0x1234>". Memoised. */
const char *dk_pdb_types_name(DkPdbTypes *t, u32 ti);
/* The type's size in bytes (0 when unknown); a forward reference resolves to its definition; an enum is its
 * underlying type's size. */
i64 dk_pdb_types_size(DkPdbTypes *t, u32 ti);
/* The class name of an LF_MFUNCTION record, else "". */
const char *dk_pdb_types_method_class(DkPdbTypes *t, u32 ti);
typedef struct {
    const char *name, *type; /* type: spelled by dk_pdb_types_name */
    i64 offset, size;
    int bit_pos, bit_len;    /* bit fields; bit_len 0 for the others */
} DkPdbField;
typedef struct {
    const char *name, *type, *prop; /* prop: "vanilla", "virtual", "static", "friend", "intro", "pure", "pure_intro" */
    bool has_vtoff;
    u32 vtoff;
} DkPdbMethod;
typedef struct {
    const char *name;
    i64 offset;
    bool is_virtual, indirect;
} DkPdbBase;
typedef struct {
    const char *name;
    i64 value;
} DkPdbEnumerator;
typedef DK_VEC(DkPdbField) DkPdbFieldVec;
typedef DK_VEC(DkPdbMethod) DkPdbMethodVec;
typedef DK_VEC(DkPdbBase) DkPdbBaseVec;
typedef DK_VEC(DkPdbEnumerator) DkPdbEnumVec;
typedef struct {
    u32 ti;
    const char *kind;               /* "class", "struct", "union" or "enum" */
    const char *name, *unique_name; /* unique_name "" when the type has none */
    i64 size;
    bool forward, has_vfptr;
    const char *underlying;         /* enums: the underlying type's name, else "" */
    DkPdbFieldVec fields;
    DkPdbBaseVec bases;
    DkPdbMethodVec methods;
    DkPdbEnumVec enumerators;
} DkPdbTypeInfo;
/* A class, struct, union or enum record (LF_CLASS, LF_STRUCTURE, LF_UNION, LF_ENUM and their old forms): its
 * description with the members of its field list (heap vectors, never freed). false for any other record. */
bool dk_pdb_types_info(DkPdbTypes *t, u32 ti, DkPdbTypeInfo *out);

/* ---- the whole PDB --------------------------------------------------------------------------------------------- */
typedef struct {
    const char *name;
    u16 seg;
    u32 off, flags;
} DkPdbPublic;
typedef DK_VEC(DkPdbPublic) DkPdbPublicVec;
typedef struct {
    u16 sec;
    u32 off, size, flags;
    u16 mod; /* module index */
} DkPdbContrib;
typedef DK_VEC(DkPdbContrib) DkPdbContribVec;
typedef struct {
    u32 index;
    const char *name;    /* the module name as linked (an object path) */
    const char *object;  /* the base name of name */
    const char *library; /* the base name of the archive the module came from, "" for a plain object */
    const char *objname; /* the object-file-name field: the archive path, or the same as name */
    u16 sec;             /* the module's first section contribution */
    u32 sec_off, sec_size;
    DkPdbCompile compile;
    DkMap *env;          /* the environment block of its compile record */
    u32 sym_bytes, c11_bytes, c13_bytes;
} DkPdbModule;
typedef DK_VEC(DkPdbModule) DkPdbModuleVec;
typedef struct {
    const char *kind, *name;
    u16 seg;
    u32 off, length, typind;
    u32 mod;            /* index of the module */
    const char *source; /* the source file of the line table entry that covers it, or "" */
} DkPdbProc;
typedef DK_VEC(DkPdbProc) DkPdbProcVec;
/* One C13 line entry (a statement start); C11 tables give ranges with line 0. */
typedef struct {
    u32 mod;
    u16 seg;
    u32 off, end; /* end is 0 for a C13 entry (it ends where the next begins) */
    u32 line;
    const char *file;
} DkPdbLine;
typedef DK_VEC(DkPdbLine) DkPdbLineVec;
typedef struct {
    DkMsf *msf;
    DkU32Vec sections;   /* the RVA of each section of the image (its section header stream) */
    DkPdbPublicVec pubs; /* every S_PUB32 in stream order */
    DkIMap *at;          /* (seg << 32 | off) -> DkCzVec * of the code publics there (flags & 3) */
    DkPdbTypes *types;
    DkPdbModuleVec mods;
    DkPdbContribVec contribs;
    DkPdbProcVec procs;  /* every module procedure */
    DkPdbLineVec lines;  /* every module's line entries, in file order */
} DkPdb;
/* Reads everything: dk_throw on a file that is not a PDB 7.00. legacy: also the old record kinds. */
DkPdb dk_pdb_read(const char *path, bool legacy);
/* The RVA of (seg, off): false when seg is not a section of the image. */
bool dk_pdb_rva(const DkPdb *p, u32 seg, u32 off, i64 *rva);
/* The code publics at (seg, off), NULL when none. */
const DkCzVec *dk_pdb_publics_at(const DkPdb *p, u32 seg, u32 off);
/* dbghelp's undecoration of a decorated name ("?name@@..."; other names come back unchanged); flags as
 * UnDecorateSymbolName (0x1000: name only). "" when it fails. */
const char *dk_pdb_undecorate(const char *name, u32 flags);
