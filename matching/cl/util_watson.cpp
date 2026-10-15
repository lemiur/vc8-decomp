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
