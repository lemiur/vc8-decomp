// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* coff: minimal COFF (i386) readers and writers for the VC8 toolchain: the symbols and the undefined and defined
 * externals of an object, an object of absolute symbols, an object holding a table of pointers to symbols, a
 * one-section code object, and two in-place rewriters (redirect, rename_symbols). Not the comparer's object model.
 *
 * Conventions:
 *   - Everything returned is allocated from the calling thread's dk_arena(); nothing here keeps state, so every
 *     function is thread-safe.
 *   - "bytes" results (the objects) are DkStr with p != NULL (binary: n counts bytes, no NUL needed). Input objects
 *     are DkStr too. Names are UTF-8 DkStr / NUL-terminated char*.
 *   - Errors: none of these functions reports an error code; an unreadable file or a malformed object (a table or
 *     string outside the data, a long name without its terminating NUL, a name that is not UTF-8) is dk_panic. The
 *     input is trusted to be a VC8 object. redirect and rename_symbols patch the bytes from the offsets in the
 *     header and tolerate what dk_coff_parse (pe.h) rejects, such as a relocation naming a slot past the table.
 *
 * Byte layouts: the header is 20 bytes {u16 machine, u16 nsections, u32 timestamp, u32 symtab offset, u32 nsyms,
 * u16 optional-header size, u16 flags}; a section header 40 bytes at 20 + optsize + 40 * s {8-byte name, u32 vsize,
 * u32 vaddr, u32 rawsize, u32 rawptr, u32 relptr, u32 lineptr, u16 nrel, u16 nline, u32 flags}; a symbol 18 bytes
 * {8-byte name field, u32 value, i16 section, u16 type, u8 storage, u8 aux count} followed by `aux` 18-byte records;
 * a relocation 10 bytes {u32 offset, u32 symbol index, u16 type}; the string table follows the symbols: u32 size
 * (itself included) then NUL-terminated names, a long name's field being {4 zero bytes, u32 offset from the table's
 * start}. A name of at most 8 bytes is NUL-padded in place. */
#pragma once
#include "dk/dk.h"

/* ================================================================================================= constants */

enum {
    COFF_IMAGE_FILE_MACHINE_I386 = 0x14C,
    COFF_IMAGE_SYM_ABSOLUTE = 0xFFFF,        /* the section field as the file stores it (u16); i16 -1 once read signed */
    COFF_IMAGE_SYM_CLASS_EXTERNAL = 2,
    COFF_IMAGE_SYM_CLASS_STATIC = 3,
    COFF_IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105,
    COFF_IMAGE_REL_I386_DIR32 = 6,
    COFF_IMAGE_REL_I386_DIR32NB = 7,
    COFF_IMAGE_REL_I386_REL32 = 0x14         /* */
};
/* The section flags table_object and code_object write: initialized data, 4-byte aligned, read/write
 * (0xC0300040) and code, 16-byte aligned, execute/read (0x60500020). */
#define COFF_TABLE_SECTION_CHARACTERISTICS 0xC0300040u
#define COFF_CODE_SECTION_CHARACTERISTICS 0x60500020u
/* The symbol name table_object's words use for "the section itself" (the base of the strings after the words). */
#define COFF_SECTION_SYMBOL "@"
/* The public symbol code_object defines at the start of its code. */
#define COFF_CODE_OBJECT_SYMBOL "_code"

/* ============================================================================================== readers */

/* One entry of coff_symbols: (name, value, section, type, storage). Auxiliary records are skipped, so the table
 * index is not kept. section is signed (0 undefined, > 0 a section, -1 absolute, -2 debug). */
typedef struct {
    DkStr name;     /* the short name with trailing NULs stripped, or the string-table name; strict UTF-8 */
    u32 value;
    i16 section;
    u16 type;        /* the symbol's type field */
    u8 storage;      /* storage class */
} CoffSymbol;

/* symbols(path): every symbol of an object file, in table order, as a new array of *count entries. An unreadable file
 * is an OSError traceback (dk_panic). The header's symbol table pointer and count are trusted. */
const CoffSymbol *coff_symbols(const char *path, size_t *count);
/* undefined_symbols(path): the external symbols an object uses without defining them (section 0, storage EXTERNAL,
 * value 0), in table order (duplicates kept). No caller outside the module today; the same as
 * dk_coff_undefined_symbols. */
DkStrVec coff_undefined_symbols(const char *path);
/* defined_symbols(path): the external symbols an object defines (section > 0, storage EXTERNAL), in table order. */
DkStrVec coff_defined_symbols(const char *path);

/* ============================================================================================== StringTable */

/* class StringTable: the string table being built for an object being written. `data` is heap memory owned by the
 * table (a short-lived tool: nothing frees it; call coff_string_table_init once per table, no fields are needed by
 * callers). */
typedef struct {
    DkBytes data;   /* the NUL-terminated long names so far (without the 4-byte size) */
} CoffStringTable;
void coff_string_table_init(CoffStringTable *t);
/* name_field(name): the 8-byte symbol-name field into out. At most 8 UTF-8 bytes: the name NUL-padded.
 * Longer: {4 zero bytes, u32 LE offset = 4 + len(data)} and the name plus a NUL appended to data. */
void coff_string_table_name_field(CoffStringTable *t, DkStr name, u8 out[8]);
/* blob(): u32 LE (4 + len(data)) followed by data, as a new string. */
DkStr coff_string_table_blob(const CoffStringTable *t);

/* ============================================================================================== writers */

/* One name and address for absolute_object. */
typedef struct {
    const char *name;
    u32 address;     
} CoffAbsoluteEntry;
/* absolute_object(entries): an object (no sections) defining each name as an absolute external symbol with that
 * address: header {I386, 0 sections, 0, symtab offset 20, nsyms = n, 0, 0}, then one 18-byte symbol per entry
 * (name field, address, section COFF_IMAGE_SYM_ABSOLUTE, type 0, storage EXTERNAL, 0 aux), then the string table. The
 * name fields are made while the symbols are laid out, in entry order. */
DkStr coff_absolute_object(const CoffAbsoluteEntry *entries, size_t n);

/* One word of table_object: either a plain integer or a (symbol, addend) pair. */
typedef struct {
    const char *symbol;   /* NULL: a plain word of value `value`. Else the symbol whose address (a DIR32 relocation)
                           * plus `value` the word holds; COFF_SECTION_SYMBOL means the section itself */
    i64 value;            /* the int, or the addend; stored as value & 0xFFFFFFFF (negative values wrap) */
} CoffWord;
/* table_object(section_name, public_name, words, strings_after=b""): an object with one data section holding `words`
 * as u32 LE then strings_after (n_strings bytes, may be NULL/0), padded with NULs to a multiple of 4. Symbols, in
 * this order: the section's own static symbol (index 0, with its auxiliary record, index 1), `public_name` as an
 * external symbol at the section's start (index 2), then the externals in first-use order (index 3...; undefined,
 * type 0x20). One DIR32 relocation per symbol word (offset of the word, symbol index, "@" naming symbol 0). Quirks
 * to keep: the section header's name is section_name encoded and cut to 8 bytes, while the section symbol's name
 * field is made from the whole name (a long one goes to the string table); the header's section flags are
 * COFF_TABLE_SECTION_CHARACTERISTICS; the aux record is {u32 size, u16 nrel, u16 0, u32 0, u16 0, u8 0, 3 zero
 * bytes}. Layout: header, section header, body, relocations, symbol table, string table. */
DkStr coff_table_object(const char *section_name, const char *public_name, const CoffWord *words, size_t n_words,
                         DkStr strings_after);
/* code_object(code): an object with one ".text" section (COFF_CODE_SECTION_CHARACTERISTICS, no relocations) holding
 * code, the section's static symbol with its aux record and the external COFF_CODE_OBJECT_SYMBOL at offset 0, type
 * 0x20 (function). For dumpbin /disasm. */
DkStr coff_code_object(DkStr code);

/* ============================================================================================== rewriters */

/* absolute_alias callback of redirect: for an undefined symbol that is pointed to (a DIR32), the name to point to
 * instead, or NULL / "" to leave it. It must be a pure function of the name (it may be called more than once per name:
 * in the two loops below). ctx is the caller's. */
typedef const char *(*CoffAbsoluteAliasFn)(void *ctx, const char *symbol);

/* redirect(data, own, absolute_alias): rewrites an object so that definitions that replace an existing program's functions are
 * reached through their old names.
 * `own`: {symbol: alias (char* in .p)} of the functions the object defines that replace the program's: each definition
 * (section > 0, EXTERNAL) is renamed alias, and the REL32 / DIR32 relocations that targeted it go to a new undefined
 * external of the symbol's old name, appended after the existing symbols (with the same type field). The undefined
 * twin of such a definition (the compiler's `??_E` weak target) is followed by the DIR32NB records. For undefined
 * externals that absolute_alias maps, DIR32 relocations go to an undefined external of the alias, so a call and a
 * pointer to one function use two symbols. The order of the appended symbols (their first request, in the order of the
 * three phases below) fixes their indexes, and the alias lookup of a key is evaluated even when the key was already
 * set. The string table is rebuilt with the
 * longer names appended and the header's symbol count updated; everything after the original symbol table is dropped
 * (the string table is the last thing in a VC8 object). Returns the new object. */
DkStr coff_redirect(DkStr data, const DkMap *own, CoffAbsoluteAliasFn absolute_alias, void *ctx);
/* rename_symbols(data, mapping): the object with the symbols of `mapping` ({old: new}, char* in .p) renamed where
 * defined and where used (the symbol table is the only place names live); a short new name replaces the field in
 * place, a longer one is appended to the string table (whose size field is recomputed). Auxiliary records are
 * stepped over with the aux count at +17 of the record. Anything after the string table is dropped. Returns the new
 * object (the header is unchanged). */
DkStr coff_rename_symbols(DkStr data, const DkMap *mapping);
