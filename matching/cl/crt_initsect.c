#include "../../include/cl/crt_initsect.h"

/*
 * Reconstruction of the installed-era CRT initsect.c (retail module 52). The
 * installed source tree does not ship this file, so the body is decoded from
 * retail; the four table markers and the two runner loops are the only objects
 * this module contributes. Both retail runners are 36 bytes:
 *
 * 0x0040c49c  push esi; push edi
 *             mov eax, 0x00415c68 (iaa+4 == izz); mov edi, 0x00415c68
 *             cmp eax, edi; mov esi, eax; jae done
 *             loop: mov eax, [esi]; test eax, eax; je next; call eax
 *             next: add esi, 4; cmp esi, edi; jb loop
 * 0x0040c4c0  same shape over 0x00415c70 (taa+4 == tzz) for the term table.
 *
 * The sentinel slots themselves are null and are not entries, which is why the
 * first bound is iaa+4/taa+4. The tables are empty in retail, so both loops run
 * zero iterations and no callback is registered by this build.
 */

#pragma section(".rtc$IAA",long,read)
#pragma section(".rtc$IZZ",long,read)
#pragma section(".rtc$TAA",long,read)
#pragma section(".rtc$TZZ",long,read)

// DATA: cl 0x415c64
__declspec(allocate(".rtc$IAA")) _PVFV __rtc_iaa[1] = { 0 };
// DATA: cl 0x415c68
__declspec(allocate(".rtc$IZZ")) _PVFV __rtc_izz[1] = { 0 };
// DATA: cl 0x415c6c
__declspec(allocate(".rtc$TAA")) _PVFV __rtc_taa[1] = { 0 };
// DATA: cl 0x415c70
__declspec(allocate(".rtc$TZZ")) _PVFV __rtc_tzz[1] = { 0 };

// FUNCTION: cl 0x40c49c
// SYMBOL: __RTC_Initialize
void __cdecl _RTC_Initialize(void)
{
    _PVFV *ppfn;

    for (ppfn = __rtc_iaa + 1; ppfn < __rtc_izz; ppfn++)
    {
        if (*ppfn)
            (*ppfn)();
    }
}

// FUNCTION: cl 0x40c4c0
// SYMBOL: __RTC_Terminate
void __cdecl _RTC_Terminate(void)
{
    _PVFV *ppfn;

    for (ppfn = __rtc_taa + 1; ppfn < __rtc_tzz; ppfn++)
    {
        if (*ppfn)
            (*ppfn)();
    }
}
