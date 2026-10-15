#include "../../include/cl/util_watson.h"

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
