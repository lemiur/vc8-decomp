#ifndef VC8_CL_CRT_FP8_H
#define VC8_CL_CRT_FP8_H

/*
 * Canonical declaration for the CRT default-precision setter owned by the
 * installed-era CRT intel/fp8.c. Source provenance:
 *   C:/Program Files (x86)/Microsoft Visual Studio 8/VC/crt/src/intel/fp8.c
 *     SHA-256 FC1AF3276F8C97BAB88A78B3A8B16A408EFF214ACA73F132AA6F049BF8DB5D6B
 *     file time 2005-09-22 23:48:02; the installed tree is the 8.0.50727.762
 *     lineage (crt/src/crtassem.h). This records provenance, not byte identity.
 * The era file includes <stddef.h>, <float.h> and <internal.h> itself; internal.h
 * supplies _controlfp_s, _invoke_watson and the _ERRCHECK macro.
 *
 * Retail PDB ownership: fp8.obj (module 44) owns __setdefaultprecision at
 * 0x0040c638 (41 bytes, PDB public start plus next public start bound). C
 * decoration turns the source spelling _setdefaultprecision into that public
 * spelling. Retail calls the msvcr80.dll _controlfp_s and _invoke_watson import
 * thunks, so the unit builds with _CRTBLD and an empty _CRTIMP (non-dllimport
 * CRT internals) and links the era import library.
 */

void  __CLRCALL_OR_CDECL _setdefaultprecision(void);

#endif
