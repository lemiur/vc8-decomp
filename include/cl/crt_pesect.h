#ifndef VC8_CL_CRT_PESECT_H
#define VC8_CL_CRT_PESECT_H

/* Canonical PE image types and the linker-defined image base.
 *
 * Installed-era provenance: VC8 SP1 8.0.50727.762; crt/src/crtassem.h SHA-256
 * 65329b6bf669e1966086fef1fb09e8f2dfd9b6c447ceb2d48e4f5baf333e6e91 records
 * _CRT_ASSEMBLY_VERSION "8.0.50727.762". The reconstructed unit is
 * crt/src/pesect.c SHA-256
 * c878dd31d495c21e91ce525f2ca173aac5a63b691c8d819d4a4c5466c3f98833.
 * PDB module strings for the retail publics name build/intel/dll_obj/pesect.obj.
 *
 * The PE structures are the Platform SDK's; include/windows.h in
 * PlatformSDK/Include SHA-256
 * c5ae461b1a3cbee914eec883ef55bd7dfd3eb287a8f178c0ed71eb3d1b1fb6f1.
 * The installed source declares the linker-defined __ImageBase at file scope;
 * it is declared once here because R2 keeps shared declarations out of units.
 * The _WIN64/_M_IA64 allocate(".base") branch in the installed source is not
 * part of this x86 unit and is not reproduced.
 */
#include <windows.h>

extern IMAGE_DOS_HEADER __ImageBase;

#endif
