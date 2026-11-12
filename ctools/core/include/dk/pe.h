// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* PE images, COFF objects and archives (.lib), read-only and bounds-checked. Its results follow the pefile package
 * (2024.8.26). The input is a memory view (an DkFileView of fs.h, or any buffer) that must outlive
 * the parsed object: names and data are views into it. Everything else is allocated from the arena given.
 *
 * Errors: a parser throws DK_ERR_FORMAT (base.h dk_throw) for input it cannot read at all (what raised
 * PEFormatError, ValueError or struct.error in Python); the "try" accessors return false where pefile raised
 * PEFormatError and the caller caught it. Where pefile only recorded a warning and went on (a damaged import table,
 * a relocation block outside the image, a duplicate relocation entry), so does this code, with the same result.
 * Parsing never reads outside the buffer.
 *
 * ---- PE images ---------------------------------------------------------------------------------------------------
 * dk_pe_parse is PE(data=..., fast_load=True): the headers, the data directory table and the section table.
 * The directories are parsed on demand, like parse_data_directories(directories=[...]): dk_pe_imports,
 * dk_pe_relocations, dk_pe_load_config, dk_pe_exports. A directory that is absent or damaged gives an empty
 * result (pefile left the DIRECTORY_ENTRY_* attribute out; `present` is false then). The resource, debug, TLS,
 * delay-import, bound-import and exception directories are not parsed: no tool reads them.
 *
 * Field names follow pefile's, in snake case (ImageBase -> image_base, Misc_VirtualSize -> virtual_size). Section
 * order is pefile's: sorted (stably) by VirtualAddress. RVA<->offset, get_data and the section lookups follow
 * pefile's rules, including its alignment adjustments (PointerToRawData & ~0x1FF, the SectionAlignment rounding)
 * and the rule that a section covers max(SizeOfRawData, VirtualSize) bytes of RVA space, cut at the next section.
 * The one difference: pefile remembers the last section it found and tries it first; this code does not, which
 * only matters for two sections with the same VirtualAddress (a damaged file).
 *
 * Python slices: pe_get_data & co. return the same bytes as the Python slice (negative or oversized bounds clamp
 * as a slice does). Sizes and RVAs are 64-bit here because Python's ints did not wrap.
 *
 * ---- COFF objects ------------------------------------------------------------------------------------------------
 * dk_coff_parse reads the header, the section headers (with their relocation records), the symbol table with its
 * auxiliary records and the string table. Symbol and section numbers are
 * the file's: sections are numbered from 1 (sections[number - 1]); a symbol's `index` is its slot in the table, so
 * the auxiliary slots are in the array too (flagged `aux`, empty name) and a relocation's symbol index is also an
 * index into the array (the aux slots are flagged). Names are raw bytes: the caller decodes them (UTF-8 or Latin-1).
 * Every record's file offset is exposed (symbol_offset, header_offset, reloc offsets) for the tools that patch
 * objects in place (redirecting or renaming symbols, dropping section data). Not read: the extended
 * relocation count (IMAGE_SCN_LNK_NRELOC_OVFL) and the bigobj format, which VC8 cannot emit.
 *
 * ---- Archives ----------------------------------------------------------------------------------------------------
 * dk_archive_parse reads "!<arch>\n" files: the member headers, the long names member
 * ("//", names "/123"), the first/second linker members ("/") and, from them, the symbol -> member offsets index.
 * ---- Rich header -------------------------------------------------------------------------------------------------
 * dk_pe_rich reads the "Rich" block. */
#pragma once
#include "arena.h"
#include "str.h"
#include "vec.h"

typedef struct {
    const u8 *p;
    size_t n;
} DkPeSpan;

/* Python's seq[start:end] on a byte buffer (negative counts from the end, bounds clamp; end == DK_PE_NONE is the
 * end). */
#define DK_PE_NONE ((i64)INT64_MIN)
DkPeSpan dk_pe_slice(const u8 *p, size_t n, i64 start, i64 end);

/* ---- constants (pefile's names) ---------------------------------------------------------------------------------- */
enum {
    DK_PE_MAGIC_PE32 = 0x10B,
    DK_PE_MAGIC_PE32_PLUS = 0x20B,
    DK_PE_MACHINE_I386 = 0x14C,
    DK_PE_MACHINE_AMD64 = 0x8664,
    /* data directory indices */
    DK_PE_DIR_EXPORT = 0,
    DK_PE_DIR_IMPORT = 1,
    DK_PE_DIR_RESOURCE = 2,
    DK_PE_DIR_EXCEPTION = 3,
    DK_PE_DIR_SECURITY = 4,
    DK_PE_DIR_BASERELOC = 5,
    DK_PE_DIR_DEBUG = 6,
    DK_PE_DIR_ARCHITECTURE = 7,
    DK_PE_DIR_GLOBALPTR = 8,
    DK_PE_DIR_TLS = 9,
    DK_PE_DIR_LOAD_CONFIG = 10,
    DK_PE_DIR_BOUND_IMPORT = 11,
    DK_PE_DIR_IAT = 12,
    DK_PE_DIR_DELAY_IMPORT = 13,
    DK_PE_DIR_COM_DESCRIPTOR = 14,
    /* base relocation types */
    DK_PE_REL_BASED_ABSOLUTE = 0,
    DK_PE_REL_BASED_HIGH = 1,
    DK_PE_REL_BASED_LOW = 2,
    DK_PE_REL_BASED_HIGHLOW = 3,
    DK_PE_REL_BASED_HIGHADJ = 4,
    DK_PE_REL_BASED_DIR64 = 10,
    /* section characteristics */
    DK_SCN_CNT_CODE = 0x00000020,
    DK_SCN_CNT_INITIALIZED_DATA = 0x00000040,
    DK_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
    DK_SCN_LNK_INFO = 0x00000200,
    DK_SCN_LNK_REMOVE = 0x00000800,
    DK_SCN_LNK_COMDAT = 0x00001000,
    DK_SCN_MEM_DISCARDABLE = 0x02000000,
    DK_SCN_MEM_EXECUTE = 0x20000000,
    DK_SCN_MEM_READ = 0x40000000,
    DK_SCN_MEM_WRITE = (int)0x80000000
};

typedef struct {
    u32 virtual_address;
    u32 size;
} DkPeDataDir;

typedef struct DkPeSection {
    u8 name_raw[8];
    DkStr name;                /* name_raw without its trailing NULs (s.Name.rstrip(b"\0")); points into name_raw */
    u32 virtual_size;           /* Misc_VirtualSize */
    u32 virtual_address;
    u32 size_of_raw_data;
    u32 pointer_to_raw_data;
    u32 pointer_to_relocations;
    u32 pointer_to_linenumbers;
    u16 number_of_relocations;
    u16 number_of_linenumbers;
    u32 characteristics;
    u32 header_offset;          /* file offset of the section header (get_file_offset) */
    u32 index;                  /* the position in the file's section table (the array is sorted by address) */
    /* pefile's derived values */
    u32 pointer_to_raw_data_adj; /* get_PointerToRawData_adj */
    u32 virtual_address_adj;     /* get_VirtualAddress_adj */
    u64 min_addr, max_addr;      /* the RVAs contains_rva accepts: [min_addr, max_addr) */
} DkPeSection;

typedef struct DkPe {
    DkPeSpan file;
    u32 e_lfanew;
    /* FILE_HEADER */
    u16 machine;
    u16 number_of_sections;
    u32 time_date_stamp;
    u32 pointer_to_symbol_table;
    u32 number_of_symbols;
    u16 size_of_optional_header;
    u16 characteristics;
    /* OPTIONAL_HEADER */
    u32 optional_header_offset;  /* OPTIONAL_HEADER.get_file_offset(): DllCharacteristics is at +70 */
    u32 optional_header_size;    /* OPTIONAL_HEADER.sizeof(): 96 (PE32) or 112 (PE32+), without the directories */
    u16 magic;
    u16 pe_type;                 /* PE_TYPE: the magic when it is 0x10B or 0x20B, else 0 */
    u8 major_linker_version, minor_linker_version;
    u32 size_of_code, size_of_initialized_data, size_of_uninitialized_data;
    u32 address_of_entry_point, base_of_code, base_of_data; /* base_of_data: PE32 only (0 for PE32+) */
    u64 image_base;
    u32 section_alignment, file_alignment;
    u16 major_operating_system_version, minor_operating_system_version;
    u16 major_image_version, minor_image_version;
    u16 major_subsystem_version, minor_subsystem_version;
    u32 win32_version_value, size_of_image, size_of_headers, checksum;
    u16 subsystem, dll_characteristics;
    u64 size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve, size_of_heap_commit;
    u32 loader_flags, number_of_rva_and_sizes;
    DkPeDataDir data_directory[16];
    unsigned n_data_directory;   /* len(OPTIONAL_HEADER.DATA_DIRECTORY): at most 16 */
    DkPeSection *sections;      /* sorted by virtual_address (stable), as pefile's pe.sections */
    size_t n_sections;
    DkPeSpan header;            /* pe.header */
} DkPe;

/* PE(data=..., fast_load=True). Throws DK_ERR_FORMAT with pefile's messages (the DOS/NT signatures, a truncated
 * header, no optional header). */
DkPe *dk_pe_parse(DkArena *a, const void *data, size_t n);

/* ---- sections, offsets, data ---- */
const DkPeSection *dk_pe_section_by_rva(const DkPe *pe, u64 rva);       /* get_section_by_rva; NULL: none */
const DkPeSection *dk_pe_section_by_offset(const DkPe *pe, u64 offset); /* get_section_by_offset */
/* The first section (in address order) whose name starts with prefix: next(s for s in pe.sections if
 * s.Name.startswith(prefix), None). */
const DkPeSection *dk_pe_section_with_prefix(const DkPe *pe, DkStr prefix);
bool dk_pe_section_contains_rva(const DkPeSection *s, u64 rva);
bool dk_pe_section_contains_offset(const DkPeSection *s, u64 offset);
/* section.get_data(start, length, ignore_padding): start and length may be DK_PE_NONE (the whole raw data). */
DkPeSpan dk_pe_section_get_data(const DkPe *pe, const DkPeSection *s, i64 start, i64 length, bool ignore_padding);
#define dk_pe_section_data(pe, s) dk_pe_section_get_data((pe), (s), DK_PE_NONE, DK_PE_NONE, false)
/* pe.get_data(rva, length): length DK_PE_NONE reads to the end. false where pefile raised PEFormatError. */
bool dk_pe_try_get_data(const DkPe *pe, u64 rva, i64 length, DkPeSpan *out);
DkPeSpan dk_pe_get_data(const DkPe *pe, u64 rva, i64 length); /* throws DK_ERR_FORMAT instead of returning false */
/* pe.get_dword_at_rva / get_word_at_rva: false where pefile returned None. */
bool dk_pe_dword_at_rva(const DkPe *pe, u64 rva, u32 *out);
bool dk_pe_word_at_rva(const DkPe *pe, u64 rva, u16 *out);
/* pe.get_offset_from_rva: false where pefile raised PEFormatError (an RVA past the file that no section holds). */
bool dk_pe_offset_from_rva(const DkPe *pe, u64 rva, u64 *offset);
/* pe.get_rva_from_offset: false where pefile returned None. */
bool dk_pe_rva_from_offset(const DkPe *pe, u64 offset, u64 *rva);
/* pe.get_string_at_rva(rva, max_length): the bytes up to the first NUL (max_length defaults to 0x100000 in pefile). */
DkStr dk_pe_string_at_rva(const DkPe *pe, u64 rva, size_t max_length);
/* pe.get_memory_mapped_image(): the headers and the sections laid out at their virtual addresses, pefile's exact
 * rules (sections ignored when VirtualSize and SizeOfRawData are both 0 or when they lie outside the file or at
 * or past max_virtual_address = 0x10000000; zero padding up to each section's adjusted address; a section that
 * starts before the end of the data so far cuts that data back). The bytes are allocated from the arena. */
u8 *dk_pe_memory_mapped_image(const DkPe *pe, DkArena *a, size_t *n);

/* ---- imports (DIRECTORY_ENTRY_IMPORT) ---- */
typedef struct {
    DkStr name;            /* the function name; name.p == NULL when pefile's imp.name is None. For an import by
                               ordinal the name is pefile's ordlookup guess (ws2_32, wsock32, oleaut32), else None */
    bool by_ordinal;        /* import_by_ordinal */
    bool has_hint;
    u16 hint;
    u16 ordinal;            /* imp.ordinal: the ordinal of an import by ordinal, else 0 (None) */
    u64 address;            /* imp.address: ImageBase + FirstThunk + index * 4 (8 for PE32+): the IAT slot's VA */
    u32 hint_name_table_rva;
    u32 thunk_rva;          /* imp.thunk_rva */
    u32 thunk_offset;       /* imp.thunk_offset: the file offset of the lookup-table entry */
    u32 name_offset;        /* imp.name_offset (0 when there is no name) */
    bool has_bound;
    u64 bound;              /* imp.bound: the IAT value when it differs from the lookup table's */
} DkPeImport;

typedef struct {
    DkStr dll;             /* entry.dll */
    u32 original_first_thunk, time_date_stamp, forwarder_chain, name_rva, first_thunk; /* entry.struct */
    DkPeImport *imports;
    size_t n;
} DkPeImportDll;

typedef struct {
    bool present;           /* hasattr(pe, "DIRECTORY_ENTRY_IMPORT") */
    DkPeImportDll *dlls;
    size_t n;
} DkPeImports;

DkPeImports dk_pe_imports(const DkPe *pe, DkArena *a);

/* ---- base relocations (DIRECTORY_ENTRY_BASERELOC) ---- */
typedef struct {
    u32 rva;                /* entry.rva: the block's page + the offset */
    u8 type;                /* entry.type: the top 4 bits of the word */
    u16 word;               /* entry.Data: the whole 16-bit word */
} DkPeReloc;
typedef struct {
    u32 virtual_address;    /* the page RVA (block.struct.VirtualAddress) */
    u32 size_of_block;
    DkPeReloc *entries;    /* in file order; a repeated (offset, type) pair ends the block's list as in pefile */
    size_t n;
} DkPeRelocBlock;
typedef struct {
    bool present;
    DkPeRelocBlock *blocks;
    size_t n;
} DkPeRelocs;

DkPeRelocs dk_pe_relocations(const DkPe *pe, DkArena *a);
/* The rvas of the entries of one type (DK_PE_REL_BASED_HIGHLOW...) over all blocks, in pefile's order (file
 * order); no per-entry objects are built. present is false when the directory is absent, as for dk_pe_relocations.
 * Replaces match_builds._highlow_relocs / [e.rva for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if
 * e.type == 3]. Allocated from the arena. */
u32 *dk_pe_reloc_rvas(const DkPe *pe, DkArena *a, unsigned type, size_t *n, bool *present);

/* ---- load configuration (DIRECTORY_ENTRY_LOAD_CONFIG.struct) ---- */
typedef struct {
    bool present;
    u32 size;               /* the structure's own Size field */
    u32 time_date_stamp;
    u64 security_cookie;    /* a field the (possibly shorter) structure lacks reads as 0, like getattr(lc, x, 0) */
    u64 se_handler_table;
    u64 se_handler_count;
    u64 guard_cf_check_function_pointer;
    u64 guard_cf_function_table;
    u64 guard_cf_function_count;
    u32 guard_flags;
    unsigned field_count;   /* the number of fields pefile unpacked (it cuts the format at the structure's Size) */
} DkPeLoadConfig;
DkPeLoadConfig dk_pe_load_config(const DkPe *pe);

/* ---- exports (DIRECTORY_ENTRY_EXPORT) ---- */
typedef struct {
    u32 ordinal;            /* Base + index */
    u32 address;            /* the RVA (or the forwarder string's RVA) */
    DkStr name;            /* name.p == NULL: exported by ordinal only */
    DkStr forwarder;       /* forwarder.p == NULL: not a forwarder */
    u32 name_rva;
} DkPeExport;
typedef struct {
    bool present;
    u32 characteristics, time_date_stamp;
    u16 major_version, minor_version;
    u32 base, number_of_functions, number_of_names;
    DkStr name;            /* the DLL's own name */
    DkPeExport *exports;   /* pefile's order: the named exports first (by name-table index), then the ordinal-only ones */
    size_t n;
} DkPeExports;
DkPeExports dk_pe_exports(const DkPe *pe, DkArena *a);

/* ---- the Rich header ---- */
typedef struct {
    u16 product;            /* compid >> 16 */
    u16 build;              /* compid & 0xFFFF */
    u32 count;
} DkPeRichEntry;
typedef struct {
    u32 key;                /* the XOR key (the dword after "Rich") */
    DkPeRichEntry *entries;
    size_t n;
} DkPeRich;
/* false: no Rich header (rich() returned None). Python's rich() raised TypeError when "Rich" is there without the
 * "DanS" marker; that is false here too. */
bool dk_pe_rich(const void *file, size_t n, DkArena *a, DkPeRich *out);

/* ======================================================================================================== COFF */
enum {
    DK_COFF_MACHINE_I386 = 0x14C,
    DK_SYM_ABSOLUTE = -1,         /* IMAGE_SYM_ABSOLUTE as a section number (the 16-bit 0xFFFF read signed) */
    DK_SYM_DEBUG = -2,
    DK_SYM_CLASS_EXTERNAL = 2,
    DK_SYM_CLASS_STATIC = 3,
    DK_SYM_CLASS_LABEL = 6,
    DK_SYM_CLASS_FILE = 103,
    DK_SYM_CLASS_WEAK_EXTERNAL = 105,
    DK_REL_I386_DIR32 = 6,
    DK_REL_I386_DIR32NB = 7,
    DK_REL_I386_SECTION = 0x0A,
    DK_REL_I386_SECREL = 0x0B,
    DK_REL_I386_REL32 = 0x14,
    /* COMDAT selection (the section definition's auxiliary record) */
    DK_COMDAT_NODUPLICATES = 1,
    DK_COMDAT_ANY = 2,
    DK_COMDAT_SAME_SIZE = 3,
    DK_COMDAT_EXACT_MATCH = 4,
    DK_COMDAT_ASSOCIATIVE = 5,
    DK_COMDAT_LARGEST = 6
};

typedef struct {
    u32 offset;             /* r.offset: from the start of the section's data */
    u32 symbol_index;       /* an index into DkCoff.symbols (the table slot) */
    u16 type;
    u32 addend;             /* the u32 at offset in the section's data, 0 when it does not fit (matchlib's addend) */
    u32 record_offset;      /* the 10-byte record's file offset */
} DkCoffReloc;

typedef struct {
    u32 index;              /* the 1-based section number */
    u8 name_raw[8];
    DkStr name;            /* name_raw without trailing NULs, as matchlib read it ("/123" stays as it is) */
    DkStr long_name;       /* the string-table name when name is "/<decimal>", else the same as name */
    u32 virtual_size;       /* the header's VirtualSize/PhysicalAddress field (0 in objects) */
    u32 size;               /* SizeOfRawData (matchlib's Section.size) */
    u32 pointer_to_raw_data, pointer_to_relocations, pointer_to_linenumbers;
    u16 number_of_relocations, number_of_linenumbers;
    u32 characteristics;
    u32 header_offset;      /* file offset of the section header */
    DkPeSpan data;         /* file[rawptr : rawptr + size] clamped to the file; empty when rawptr is 0 */
    DkCoffReloc *relocs;   /* sorted by offset (stable), as matchlib sorts them */
    size_t n_relocs;
} DkCoffSection;

typedef struct {
    u32 index;              /* the slot in the symbol table */
    bool aux;               /* an auxiliary slot: only index and aux are meaningful */
    DkStr name;            /* the short name without trailing NULs, or the string-table name */
    u32 value;
    i16 section;            /* 0 undefined, > 0 a section number, -1 absolute, -2 debug */
    u16 type;
    u8 storage_class;
    u8 number_of_aux;
    u32 record_offset;      /* the 18-byte record's file offset */
} DkCoffSymbol;

typedef struct {
    DkPeSpan file;
    u16 machine;
    u16 number_of_sections;
    u32 time_date_stamp;
    u32 pointer_to_symbol_table;
    u32 number_of_symbols;
    u16 size_of_optional_header;
    u16 characteristics;
    DkCoffSection *sections;   /* sections[number - 1] */
    DkCoffSymbol *symbols;     /* number_of_symbols slots */
    DkPeSpan string_table;     /* the table after the symbols, its 4-byte size field included (offsets count from
                                   its start); empty when the file has none */
} DkCoff;

/* expect_machine: 0 accepts any, else the header's machine must equal it (matchlib: 0x14C, "is not a 32-bit x86
 * object"). Throws DK_ERR_FORMAT where Python raised (a table outside the file, a string-table name without
 * its NUL, a relocation naming a slot beyond the table, an auxiliary run past the table's end). */
DkCoff *dk_coff_parse(DkArena *a, const void *data, size_t n, unsigned expect_machine);

/* sym.is_function / sym.defined of matchlib. */
static inline bool dk_coff_is_function(const DkCoffSymbol *s) { return (s->type & 0xF0) == 0x20; }
static inline bool dk_coff_defined(const DkCoffSymbol *s) { return !s->aux && s->section > 0; }
/* The symbol at a slot (a relocation's symbol_index), NULL for an auxiliary slot or an index out of range
 * (matchlib's None). */
const DkCoffSymbol *dk_coff_symbol(const DkCoff *c, u32 index);

/* Auxiliary records (sym's following slots). `k` counts from 0. */
const u8 *dk_coff_aux_raw(const DkCoff *c, const DkCoffSymbol *sym, unsigned k); /* 18 bytes; NULL if absent */
typedef struct {
    u32 length;             /* the section's size */
    u16 number_of_relocations, number_of_linenumbers;
    u32 checksum;
    u16 number;             /* the associated section's number (selection == DK_COMDAT_ASSOCIATIVE) */
    u8 selection;           /* COMDAT selection: DK_COMDAT_*; 0 for a section that is not a COMDAT */
} DkCoffSectionAux;
/* The section definition record of a static symbol with one auxiliary record (vc8_build.drop_sections_data reads
 * number at +12 and selection at +14 of it). false when sym has no aux record. */
bool dk_coff_aux_section(const DkCoff *c, const DkCoffSymbol *sym, DkCoffSectionAux *out);
typedef struct {
    u32 tag_index;          /* the default symbol (matchlib's weak_defaults[i]) */
    u32 characteristics;    /* IMAGE_WEAK_EXTERN_SEARCH_* */
} DkCoffWeakAux;
bool dk_coff_aux_weak(const DkCoff *c, const DkCoffSymbol *sym, DkCoffWeakAux *out);
/* The file name of a .file symbol (its aux records' bytes up to the first NUL). */
DkStr dk_coff_aux_file(const DkCoff *c, const DkCoffSymbol *sym);

/* The section a COMDAT-like symbol names: the first static symbol with value 0, type 0 in a section, per section
 * (matchlib's Coff.section_symbols); the array has number_of_sections + 1 slots, index 0 unused, NULL where none. */
const DkCoffSymbol **dk_coff_section_symbols(const DkCoff *c, DkArena *a);

/* coff.undefined_symbols / defined_symbols: the external symbols an object uses without defining them (section 0,
 * storage EXTERNAL, value 0) and the ones it defines (section > 0, EXTERNAL), in table order. */
DkStrVec dk_coff_undefined_symbols(const DkCoff *c, DkArena *a);
DkStrVec dk_coff_defined_symbols(const DkCoff *c, DkArena *a);

/* A short import object of an import library (libobj.is_short_import): the first dword is 0xFFFF0000. */
bool dk_coff_is_short_import(const void *data, size_t n);
typedef struct {
    u16 version, machine;
    u32 time_date_stamp, size_of_data;
    u16 ordinal_hint;
    u16 kind;               /* the type word: bits 0-1 import type, 2-4 name type */
    unsigned name_type;     /* (kind >> 2) & 7 */
    DkStr symbol;          /* the NUL-terminated name at +20 */
    DkStr dll;             /* the name after it */
} DkCoffShortImport;
/* false when data is not a short import or is shorter than 20 bytes or lacks the NUL (libobj would have raised). */
bool dk_coff_short_import(const void *data, size_t n, DkCoffShortImport *out);

/* =================================================================================================== archives */
typedef struct {
    DkStr name;            /* the member name: "/123" resolved through the long names member, a trailing "/" removed */
    u32 header_offset;      /* file offset of the 60-byte member header */
    DkPeSpan data;
} DkArMember;

typedef struct DkArchive {
    DkPeSpan file;
    DkArMember *members;   /* in file order; the "/" linker members and the "//" long names member are not listed */
    size_t n_members;
    size_t short_imports;   /* the count of short import objects among the members */
    /* the symbol index of the second linker member (else the first): `symbol[i]` is defined by the member whose
     * header is at `symbol_member_offset[i]`, in the linker member's order */
    DkStr *symbol;
    u32 *symbol_member_offset;
    size_t n_symbols;
    u32 *hash;              /* internal: lookup table over symbol (first slot + 1 of each distinct name) */
    u32 *next_same;         /* internal: the next slot with the same name */
    size_t hash_cap;
} DkArchive;

/* Throws DK_ERR_FORMAT for a file without the "!<arch>\n" signature or with a damaged linker member. */
DkArchive *dk_archive_parse(DkArena *a, const void *data, size_t n);
/* Archive.definers(symbol): the names of the members that define the symbol, in the linker member's order (only
 * those members that exist). */
DkStrVec dk_archive_definers(const DkArchive *ar, DkArena *a, DkStr symbol);
/* Archive.member(name, symbol): the data of the member called name; when several members share the name and a
 * symbol is given, the first of them that defines the symbol, else the first. false (Python KeyError): no such
 * member. */
bool dk_archive_member(const DkArchive *ar, DkStr name, const DkStr *symbol, DkPeSpan *out);
