/*
 * Reconstruction of the installed-era CRT unhandld.cpp (retail module 36). The
 * installed source tree does not ship this file; the two bodies are decoded
 * from retail and are quoted with their full byte evidence in
 * include/cl/crt_unhandld.h.
 *
 * 0x0040c44b (61 bytes) __CxxUnhandledExceptionFilter:
 *   mov eax,[esp+4] ; pExceptionPtrs
 *   mov eax,[eax]   ; pExceptionPtrs->ExceptionRecord
 *   cmp dword [eax],0xE06D7363 ; jne return-0
 *   cmp dword [eax+0x10],3     ; jne return-0   (NumberParameters)
 *   mov eax,[eax+0x14]         ; ExceptionInformation[0]
 *   cmp 0x19930520 / 0x19930521 / 0x19930522 / 0x01994000, each je terminate
 *   call terminate ; return-0: xor eax,eax ; ret 4
 * 0x0040c488 (14 bytes) __CxxSetUnhandledExceptionFilter:
 *   push offset __CxxUnhandledExceptionFilter ; call [__imp_SetUnhandledExceptionFilter]
 *   xor eax,eax ; ret     (the decoded literal zero return)
 */

#include <windows.h>
#include <eh.h>

#include "../../include/cl/crt_unhandld.h"

// FUNCTION: cl 0x40c44b
// SYMBOL: ?__CxxUnhandledExceptionFilter@@YGJPAU_EXCEPTION_POINTERS@@@Z
LONG __stdcall __CxxUnhandledExceptionFilter(
        struct _EXCEPTION_POINTERS *pExceptionPtrs
        )
{
    EXCEPTION_RECORD *pRecord = pExceptionPtrs->ExceptionRecord;

    if (pRecord->ExceptionCode == EH_EXCEPTION_NUMBER
        && pRecord->NumberParameters == 3
        && (pRecord->ExceptionInformation[0] == EH_MAGIC_NUMBER
            || pRecord->ExceptionInformation[0] == EH_MAGIC_NUMBER2
            || pRecord->ExceptionInformation[0] == EH_MAGIC_NUMBER3
            || pRecord->ExceptionInformation[0] == EH_PURE_MAGIC_NUMBER))
    {
        terminate();
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// FUNCTION: cl 0x40c488
// SYMBOL: ___CxxSetUnhandledExceptionFilter
extern "C" LONG __cdecl __CxxSetUnhandledExceptionFilter(void)
{
    SetUnhandledExceptionFilter(__CxxUnhandledExceptionFilter);
    return 0;
}
