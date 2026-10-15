// PDB DBI module 7: dos.obj. Original source filename and line layout unresolved.
#include "../../include/cl/dos.h"
#include <windows.h>

// FUNCTION: cl 0x408f04
// SYMBOL: ?FallThroughFilter@@YAHKPAUpassinfo_s@@PAH@Z
// Parameter names are descriptive placeholders; public types and retail ABI agree.
int FallThroughFilter(unsigned long exception_code, passinfo_s *pass, int *status)
{
    if (exception_code != EXCEPTION_BREAKPOINT)
        *status = 4;
    return EXCEPTION_CONTINUE_SEARCH;
}
