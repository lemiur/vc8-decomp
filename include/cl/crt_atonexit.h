#ifndef VC8_CL_CRT_ATONEXIT_H
#define VC8_CL_CRT_ATONEXIT_H

/* Canonical client-side _onexit/atexit declarations and CRT build context.
 *
 * Installed-era provenance: VC8 SP1 8.0.50727.762; crt/src/crtassem.h SHA-256
 * 65329b6bf669e1966086fef1fb09e8f2dfd9b6c447ceb2d48e4f5baf333e6e91 records
 * _CRT_ASSEMBLY_VERSION "8.0.50727.762". The reconstructed unit is
 * crt/src/atonexit.c SHA-256
 * 798cf1e69b03b0016726c5cc5148c6a4b4629376909d7645365223c63643430f.
 * PDB module strings for the retail publics name build/intel/dll_obj/atonexit.obj.
 *
 * atonexit.c is a client-side CRT object: its own build context forces _DLL
 * and leaves CRTDLL undefined before the CRT internal headers are read. That
 * context is reproduced here, followed by the era internal headers:
 * cruntime.h SHA-256 d1245829d64198109953651ca787743bdca7c0b1ad43397f5615966b08c0ff1c,
 * internal.h SHA-256 ef40fbb44e0d03151dccdaf586c9715a51bc6f958b706b7869ab1f6d477f1df,
 * mtdll.h SHA-256 6ae00bae29b2105c8d12c65490b4ba639757bb329063a3189eb97eecb2f1102b,
 * oscalls.h SHA-256 d6c2c188f444dbb78f6528e1549fb0771593096112e99124489a78b8ca79cddc.
 * The installed source declares __dllonexit and the x86 _imp___onexit pointer
 * at file scope and defines the onexit pointers at file scope; R2 keeps the
 * shared declarations here, and the definitions stay in the unit.
 */
#undef  CRTDLL
#ifndef _DLL
#define _DLL
#endif  /* _DLL */

#include <cruntime.h>
#include <oscalls.h>
#include <internal.h>
#include <stdlib.h>
#include <mtdll.h>

extern _PVFV *__onexitbegin;
extern _PVFV *__onexitend;

extern _onexit_t __dllonexit(_onexit_t, _PVFV**, _PVFV**);

#ifdef _M_IX86
extern _onexit_t (__cdecl *_imp___onexit)(_onexit_t func);
#else  /* _M_IX86 */
extern _onexit_t (__cdecl *__imp__onexit)(_onexit_t func);
#endif  /* _M_IX86 */

#endif
