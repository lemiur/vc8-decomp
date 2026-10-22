#include "../../include/cl/clmain.h"
#include "../../include/cl/util_watson.h"

#include <stdlib.h>
#include <windows.h>

// Source filename inferred from the PDB object owner clmain.obj; the original
// extension and assert line mappings remain unresolved. Public names and stack
// cleanup prove these cdecl callbacks; their flag_s argument is unused.

// FUNCTION: cl 0x004015a8
// SYMBOL: ?error_report_prompt@@YAXPAUflag_s@@@Z
void __cdecl error_report_prompt(flag_s*)
{
    ErrorReportingSetMode(ErrorReportingMode_Prompt);
}

// FUNCTION: cl 0x004015b1
// SYMBOL: ?error_report_queue@@YAXPAUflag_s@@@Z
void __cdecl error_report_queue(flag_s*)
{
    ErrorReportingSetMode(ErrorReportingMode_Queue);
}

// FUNCTION: cl 0x004015ba
// SYMBOL: ?error_report_send@@YAXPAUflag_s@@@Z
void __cdecl error_report_send(flag_s*)
{
    ErrorReportingSetMode(ErrorReportingMode_Send);
}

// FUNCTION: cl 0x004015c3
// SYMBOL: ?error_report_none@@YAXPAUflag_s@@@Z
void __cdecl error_report_none(flag_s*)
{
    ErrorReportingSetMode(ErrorReportingMode_None);
}

// DATA: cl 0x00417034
// Public ?RedirStderr@@3HA; four file-backed bytes initialize the int to one.
int RedirStderr = 1;

// FUNCTION: cl 0x0040218a
// SYMBOL: ?IsRunningUnderIDE@@YAHXZ
int __cdecl IsRunningUnderIDE()
{
    return GetEnvironmentVariableW(L"VS_UNICODE_OUTPUT", 0, 0) != 0;
}

// FUNCTION: cl 0x004024a8
// SYMBOL: ?fullccpath@@YAPAGXZ
wchar_t* __cdecl fullccpath()
{
    wchar_t* path = 0;
    _get_wpgmptr(&path);
    return path;
}

// DATA: cl 0x00419640
// Public ?pPCHBaseAddress@@3PAXA proves void* storage; clmain.obj owns it.
// Retail places this zero-initialized pointer in the .data virtual tail.
void* pPCHBaseAddress;

// DATA: cl 0x004188ec
// Public ?pPCHAstExtraBaseAddress@@3PAXA; clmain.obj owns the zero-valued pointer.
void* pPCHAstExtraBaseAddress;

// FUNCTION: cl 0x00402c06
// SYMBOL: ?release_filelife_heap@@YAXXZ
void __cdecl release_filelife_heap()
{
    VirtualFree(pPCHBaseAddress, 0, MEM_RELEASE);
}

// FUNCTION: cl 0x00402c1a
// SYMBOL: ?release_ast_extra_heap@@YAXXZ
void __cdecl release_ast_extra_heap()
{
    VirtualFree(pPCHAstExtraBaseAddress, 0, MEM_RELEASE);
}

// FUNCTION: cl 0x004014d5
// SYMBOL: ??0CConsoleLock@@QAE@XZ
CConsoleLock::CConsoleLock()
{
    if (g_hMutex)
    {
        DWORD result = WaitForSingleObject(g_hMutex, INFINITE);
        if (result == WAIT_OBJECT_0 || result == WAIT_ABANDONED)
        {
            locked = true;
            return;
        }
    }
    locked = false;
}
