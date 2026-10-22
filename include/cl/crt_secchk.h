#ifndef VC8_CL_CRT_SECCHK_H
#define VC8_CL_CRT_SECCHK_H

/* Canonical /GS cookie and failure-report declarations.
 *
 * Installed-era provenance: VC8 SP1 8.0.50727.762; crt/src/crtassem.h SHA-256
 * 65329b6bf669e1966086fef1fb09e8f2dfd9b6c447ceb2d48e4f5baf333e6e91 records
 * _CRT_ASSEMBLY_VERSION "8.0.50727.762". The reconstructed unit is
 * crt/src/intel/secchk.c SHA-256
 * c899827141eb425e80dbce7d9afa49f000f46ae99eb5543d5a940a505fab0b59.
 * PDB module strings for the retail public name build/intel/dll_obj/secchk.obj.
 *
 * The installed secchk.c repeats "extern UINT_PTR __security_cookie;" itself;
 * <process.h> SHA-256
 * eb65dbd38d8b60fd1ecce979567da173a21939ce591a55a800d4f29fae3f2a81 already
 * declares __security_cookie, __security_check_cookie and the noreturn
 * __report_gsfailure, so that canonical declaration is not duplicated in the
 * unit. windows.h platform provenance is recorded in crt_pesect.h.
 */
#include <windows.h>
#include <process.h>

#endif
