#include "../../include/cl/clmain.h"
#include "../../include/cl/util_watson.h"

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
