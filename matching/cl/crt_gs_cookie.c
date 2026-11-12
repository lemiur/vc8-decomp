#include "../../include/cl/crt_gs.h"

/*
 * Reconstruction of the installed-era CRT gs_cookie.c data. Retail PDB module
 * 29 (build/intel/dll_obj/gs_cookie.obj) owns two four-byte .data objects:
 *   0x00417c44 ___security_cookie            = 0xBB40E64E
 *   0x00417c48 ___security_cookie_complement = 0x44BF19B1 (== ~0xBB40E64E)
 * The bytes were read directly from retail cl.exe .data. gs_support.c declares
 * both objects extern (see crt_gs.h); this unit is their defining unit and is
 * linked as a dependency of ___security_init_cookie.
 */

// DATA: cl 0x417c44
UINT_PTR __security_cookie = 0xBB40E64E;

// DATA: cl 0x417c48
UINT_PTR __security_cookie_complement = ~0xBB40E64E;
