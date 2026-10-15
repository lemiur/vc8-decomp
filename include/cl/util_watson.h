#ifndef CL_UTIL_WATSON_H
#define CL_UTIL_WATSON_H

// ErrorReportingMode is the public PDB's enum type spelling. The enumerator
// spellings below are invented; values follow the four clmain error_report_*
// callers and ErrorReportingDisabled's range checks. Original names unresolved.
enum ErrorReportingMode
{
    ErrorReportingMode_None = 0,
    ErrorReportingMode_Prompt = 1,
    ErrorReportingMode_Queue = 2,
    ErrorReportingMode_Send = 3
};

// Invented global spelling. Getter/setter load/store a four-byte enum at
// 0x0041a020. PDB DBI section contribution proves util_watson.obj ownership:
// section 3, offset 0x3014, size 28. The address has no exact public data name.
extern ErrorReportingMode g_errorReportingMode;

// Public PDB spellings and bounded retail instructions agree on these ABIs.
ErrorReportingMode __cdecl ErrorReportingGetMode();
bool __cdecl ErrorReportingSetMode(ErrorReportingMode mode);

#endif
