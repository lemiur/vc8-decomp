#ifndef VC8_CL_CRT_GS_H
#define VC8_CL_CRT_GS_H

/*
 * Canonical declarations for the /GS security cookie support owned by the
 * installed-era CRT gs_support.c / gs_cookie.c. Source provenance:
 *   C:/Program Files (x86)/Microsoft Visual Studio 8/VC/crt/src/gs_support.c
 *     SHA-256 AD03EE25A3A9DF28A4BD780A99E31C4462ABC036F8FF6D5792495650419FBEE8,
 *     file time 2006-12-01 21:53:28 (the SP1 build window; crt/src/crtassem.h
 *     records 8.0.50727.762). This records the installed lineage, not proof of
 *     the exact retail source revision.
 * Retail PDB ownership: gs_support.obj (module 31) owns ___security_init_cookie
 * at 0x0040c664; gs_cookie.obj (module 29) owns the two .data cookies at
 * 0x00417c44 and 0x00417c48. The era source declares the cookies extern, so the
 * defining unit is reconstructed separately in crt_gs_cookie.c.
 * PDB spellings of the C names add the C decoration underscore:
 *   __security_init_cookie -> ___security_init_cookie
 *   __security_cookie      -> ___security_cookie
 * A release (/D_DEBUG absent) build is proven by the retail body: the debug
 * late-cookie-init check in gs_support.c compiles no code without _DEBUG.
 */

#include <windows.h>
#include <intrin.h>

/* The compiler-known global cookie and its complement (gs_cookie.c). */
extern UINT_PTR __security_cookie;
extern UINT_PTR __security_cookie_complement;

/* Era gs_support.c preamble types (the debug-only late-cookie-init block).
 * They are recovered from the installed source and kept in this canonical
 * header so no reconstruction unit redeclares an SDK/CRT type (rule R1).
 * They compile no code in the release build the retail image used. */
typedef
EXCEPTION_DISPOSITION
(*PEXCEPTION_ROUTINE) (
    IN struct _EXCEPTION_RECORD *ExceptionRecord,
    IN PVOID EstablisherFrame,
    IN OUT struct _CONTEXT *ContextRecord,
    IN OUT PVOID DispatcherContext
    );

typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD;

typedef EXCEPTION_REGISTRATION_RECORD *PEXCEPTION_REGISTRATION_RECORD;

void __cdecl __security_init_cookie(void);

#endif
