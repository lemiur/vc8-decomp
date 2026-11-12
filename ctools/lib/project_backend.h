// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Internal to the adapter's second half (project_image.c, project_build.c, project_compare.c): what one of them gives
 * the others beyond project.h. Not for tools. */
#pragma once
#include "project.h"

/* The COFF relocation types the comparison understands (i386). */
enum { DK_RELOC_DIR32 = 0x06, DK_RELOC_DIR32NB = 0x07, DK_RELOC_REL32 = 0x14 };

/* ---- images (project_image.c) ----------------------------------------------------------------------------------- */
/* Opens any PE32 image (a reference image or a linked candidate); sha256 NULL: not checked. */
DkImage *dk__image_open(DkArena *a, const char *path, const u8 *sha256, DkErr *err);
void dk__image_set_symbols(DkImage *im, DkSymbols *syms);
DkSymbols *dk__image_symbols(const DkImage *im);
u32 dk__image_base(const DkImage *im);
const char *dk__image_path(const DkImage *im);
/* The end VA of the section holding va (its virtual size, cut to its raw data); 0 when no section holds va. */
u32 dk__image_section_end(const DkImage *im, u32 va);
/* The IAT slot of an import: name is a decorated "__imp_" name or a plain import name. */
bool dk__image_import_va(const DkImage *im, const char *name, u32 *va);
/* The "__imp_" name of the IAT slot at va, NULL when va is none. */
const char *dk__image_import_at(const DkImage *im, u32 va);
/* The rel32 branch and call fields (E8, E9, 0F 8x) of code at va whose target leaves [va, va + code.n), as REL32
 * relocations named through the image's symbols (addend: the offset of the target into its symbol). */
typedef DK_VEC(DkReloc) DkRelocVec;
void dk__image_branch_relocs(const DkImage *im, u32 va, DkStr code, DkArena *a, DkRelocVec *out);
/* The relocation that names the word at site (a DIR32 base relocation of a linked image): the symbol holding the
 * word's target and the target's offset into it; false when the image has no base relocation there. */
bool dk__image_word_reloc(const DkImage *im, u32 site, DkArena *a, DkReloc *out);
/* Per-image caches of the comparison (lazily filled, guarded by the image's lock). */
void dk__image_lock(DkImage *im);
void dk__image_unlock(DkImage *im);
void **dk__image_compare_slot(DkImage *im);

/* ---- build contexts (project_build.c) ----------------------------------------------------------------------------
 * A function built by dk_build_unit remembers where it came from, so the comparison can read the compiler-made data
 * it points at. dk__build_content fills *out with the bytes and relocations of a symbol defined in the same build
 * (an object's section slice up to the next symbol, or a linked image's bytes up to the next map symbol of the
 * section): true when the build defines it. *is_function says whether it is code. */
bool dk__build_content(const DkFunc *fn, const char *symbol, DkFunc *out, bool *is_function);
/* Whether symbol is defined by the build of fn, and its offset into fn when it lies inside fn (labels, switch
 * tables): *inside is set then. */
bool dk__build_defines(const DkFunc *fn, const char *symbol, bool *inside, u32 *offset);
