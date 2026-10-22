#ifndef VC8_CL_CRT_UNHANDLD_H
#define VC8_CL_CRT_UNHANDLD_H

/*
 * Canonical declarations for the C++ unhandled-exception filter owned by the
 * installed-era CRT unhandld.cpp (retail module 36, object path
 * build\intel\dll_obj\unhandld.obj). The installed source tree does not ship
 * unhandld.cpp, so both bodies are decoded from retail:
 *   __CxxUnhandledExceptionFilter 0x0040c44b, 61 bytes
 *   __CxxSetUnhandledExceptionFilter 0x0040c488, 14 bytes
 * C decoration turns the source spellings __CxxUnhandledExceptionFilter and
 * __CxxSetUnhandledExceptionFilter into the public decorations.
 *
 * The exception-classification values below are the decoded retail immediates
 * (cmp 0xE06D7363, and 0x19930520/0x19930521/0x19930522/0x01994000 against
 * ExceptionInformation[0]). Their spellings are invented because the era
 * ehdata.h is not shipped; the values are evidenced by the decode and are the
 * documented Visual C++ EH record magic numbers.
 */

#include <windows.h>

#define EH_EXCEPTION_NUMBER      0xE06D7363
#define EH_MAGIC_NUMBER          0x19930520
#define EH_MAGIC_NUMBER2         0x19930521
#define EH_MAGIC_NUMBER3         0x19930522
#define EH_PURE_MAGIC_NUMBER     0x01994000

/* The canonical declaration of terminate is the installed-era crt/src/eh.h:65
 * (`_CRTIMP __declspec(noreturn) void __cdecl terminate(void)`), which the unit
 * includes; it is not restated here, so exactly one declaration exists. The
 * unit builds with an empty _CRTIMP so the reference is a non-dllimport
 * external resolved through the era import library, exactly like retail's call
 * to the MSVCR80.dll import thunk. */

LONG __stdcall __CxxUnhandledExceptionFilter(
        struct _EXCEPTION_POINTERS *pExceptionPtrs);
extern "C" LONG __cdecl __CxxSetUnhandledExceptionFilter(void);

#endif
