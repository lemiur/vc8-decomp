#include "../../include/cl/util_watson.h"
#include <windows.h>

// Source filename inferred from the PDB object owner util_watson.obj; the
// original extension is unresolved. No assert line mappings are claimed here.

// DATA: cl 0x0041a020
// Invented spelling; canonical declaration and evidence are in util_watson.h.
// Retail .data virtual tail supplies loader-zero initialization.
ErrorReportingMode g_errorReportingMode;

// FUNCTION: cl 0x00409934
// SYMBOL: ?ErrorReportingGetMode@@YA?AW4ErrorReportingMode@@XZ
ErrorReportingMode __cdecl ErrorReportingGetMode()
{
    return g_errorReportingMode;
}

// FUNCTION: cl 0x0040993a
// SYMBOL: ?ErrorReportingSetMode@@YA_NW4ErrorReportingMode@@@Z
bool __cdecl ErrorReportingSetMode(ErrorReportingMode mode)
{
    g_errorReportingMode = mode;
    return true;
}

// DATA: cl 0x00417be8
// Invented spelling; module ownership and pointer type are recorded in header.
// /Zc:wchar_t- makes the genuine L"" initializer const unsigned short[1].
const unsigned short *g_errorReportingDlls = L"";

// DATA: cl 0x00417bec
// Invented spelling; retail shares the same empty wide literal initializer.
const unsigned short *g_errorReportingFormalAppName = L"";

// FUNCTION: cl 0x00409946
// SYMBOL: ?ErrorReportingSetDlls@@YA_NPBG@Z
bool __cdecl ErrorReportingSetDlls(const unsigned short *dlls)
{
    g_errorReportingDlls = dlls;
    return true;
}

// FUNCTION: cl 0x00409952
// SYMBOL: ?ErrorReportingSetFormalAppName@@YA_NPBG@Z
bool __cdecl ErrorReportingSetFormalAppName(const unsigned short *appName)
{
    g_errorReportingFormalAppName = appName;
    return true;
}

// FUNCTION: cl 0x0040995e
// SYMBOL: ?ErrorReportingCheckOptIn@@YA_NXZ
// Public name/ABI, direct retail imports and both literal contents are proven.
// Local names are invented semantic spellings. The size/type/value objects are
// the actual DWORD outputs passed to RegQueryValueExA, not artificial spills.
bool __cdecl ErrorReportingCheckOptIn()
{
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                     "Software\\Microsoft\\VisualStudio\\8.0\\General",
                     0, KEY_READ, &key) == ERROR_SUCCESS)
    {
        DWORD type;
        DWORD value;
        DWORD size = sizeof(value);
        LONG result = RegQueryValueExA(key, "UserCanAutoSendErrorReport", 0,
                                      &type, reinterpret_cast<BYTE *>(&value),
                                      &size);
        RegCloseKey(key);
        if (result == ERROR_SUCCESS && type == REG_DWORD)
            return value == 1;
    }
    return false;
}

// FUNCTION: cl 0x00409acb
// SYMBOL: ?ErrorReportingDisabled@@YA_NXZ
// Mode comparisons, the real opt-in call and all three terminal returns are
// directly evidenced. The nested guards preserve the observed branch order.
bool __cdecl ErrorReportingDisabled()
{
    if (g_errorReportingMode > ErrorReportingMode_None)
    {
        if (g_errorReportingMode > ErrorReportingMode_Queue)
        {
            if (g_errorReportingMode == ErrorReportingMode_Send)
                return !ErrorReportingCheckOptIn();
        }
        else
            return false;
    }
    return true;
}

// DATA: cl 0x0041a014
// Invented spelling. The complete canonical layout is the installed Win32 SDK
// SECURITY_ATTRIBUTES, corroborated by the API argument and nLength == 12.
SECURITY_ATTRIBUTES g_errorReportingMappingAttributes;

// DATA: cl 0x0041a02c
// Invented spelling; receives CreateFileMappingA's HANDLE and feeds CloseHandle.
HANDLE g_errorReportingMappingHandle;

// DATA: cl 0x0041a028
// Invented spelling; receives MapViewOfFile's LPVOID result.
LPVOID g_errorReportingMappingView;

// FUNCTION: cl 0x00409a58
// SYMBOL: ?ErrorReportingCreateMapping@@YA_NXZ
// Invented helper spelling; original name and linkage are unresolved. Its body
// and no-argument/caller-clean ABI are directly decoded. Both returned AL values
// are boolean, and ErrorReportingFilter tests AL after calling this entry.
bool __cdecl ErrorReportingCreateMapping()
{
    g_errorReportingMappingHandle = CreateFileMappingA(
        INVALID_HANDLE_VALUE, &g_errorReportingMappingAttributes,
        PAGE_READWRITE, 0, 0x9c9c, 0);
    if (!g_errorReportingMappingHandle)
        return false;
    g_errorReportingMappingView = MapViewOfFile(
        g_errorReportingMappingHandle, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
    if (!g_errorReportingMappingView)
    {
        CloseHandle(g_errorReportingMappingHandle);
        g_errorReportingMappingHandle = 0;
        return false;
    }
    return true;
}

// FUNCTION: cl 0x00409aab
// SYMBOL: ?ErrorReportingInitialize@@YAXXZ
// stop: referents: gate must independently resolve the real SDK object's fields.
void __cdecl ErrorReportingInitialize()
{
    g_errorReportingMappingAttributes.nLength = sizeof(g_errorReportingMappingAttributes);
    g_errorReportingMappingAttributes.lpSecurityDescriptor = 0;
    g_errorReportingMappingAttributes.bInheritHandle = TRUE;
    ErrorReportingCreateMapping();
}
