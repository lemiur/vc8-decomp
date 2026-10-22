#ifndef VC8_CL_CRT_INITSECT_H
#define VC8_CL_CRT_INITSECT_H

/*
 * Canonical declarations for the RTC init/term tables and their runners owned
 * by the installed-era CRT initsect.c (retail module 52, object path
 * ..\build\intel\dll_obj\initsect.obj). The installed source tree does not
 * ship initsect.c, so this unit is decoded from retail, not quoted:
 *   _RTC_Initialize 0x0040c49c, 36 bytes
 *   _RTC_Terminate  0x0040c4c0, 36 bytes
 * and the four four-byte .rdata markers:
 *   ___rtc_iaa 0x00415c64
 *   ___rtc_izz 0x00415c68
 *   ___rtc_taa 0x00415c6c
 *   ___rtc_tzz 0x00415c70
 * all owned by the same module (PDB data symbols). C decoration turns the
 * source spellings _RTC_Initialize/_RTC_Terminate into the public decorations
 * __RTC_Initialize/__RTC_Terminate.
 *
 * The table regions are empty in retail (the linker placed the four null
 * sentinels back to back), so the runner loops execute zero iterations. The
 * exact two address references per runner are iaa+4 and izz for the init table
 * and taa+4 and tzz for the term table: the IAA/TAA sentinel slot itself is not
 * an entry. That is recovered from the decoded immediates (both init bounds are
 * 0x00415c68 == izz == iaa+4; both term bounds are 0x00415c70 == tzz == taa+4)
 * and is the only source shape that reproduces them.
 */

typedef void (__cdecl *_PVFV)(void);

extern _PVFV __rtc_iaa[];
extern _PVFV __rtc_izz[];
extern _PVFV __rtc_taa[];
extern _PVFV __rtc_tzz[];

void __cdecl _RTC_Initialize(void);
void __cdecl _RTC_Terminate(void);

#endif
