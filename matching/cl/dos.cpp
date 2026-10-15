// PDB DBI module 7: dos.obj. Original source filename and line layout unresolved.
#include "../../include/cl/dos.h"
#include "../../include/cl/clmain.h"
#include <windows.h>
#include <io.h>

// FUNCTION: cl 0x408f04
// SYMBOL: ?FallThroughFilter@@YAHKPAUpassinfo_s@@PAH@Z
// Parameter names are descriptive placeholders; public types and retail ABI agree.
int FallThroughFilter(unsigned long exception_code, passinfo_s *pass, int *status)
{
    if (exception_code != EXCEPTION_BREAKPOINT)
        *status = 4;
    return EXCEPTION_CONTINUE_SEARCH;
}

// FUNCTION: cl 0x4092d4
// SYMBOL: ?screen_length@@YAHXZ
int screen_length()
{
    CONSOLE_SCREEN_BUFFER_INFO info;
    HANDLE console = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    if (console == INVALID_HANDLE_VALUE)
        return 25;

    BOOL success = GetConsoleScreenBufferInfo(console, &info);
    CloseHandle(console);
    if (!success)
        return 25;

    int height = info.srWindow.Bottom - info.srWindow.Top + 1;
    return height > 0 ? height : 1;
}

// FUNCTION: cl 0x4092be
// SYMBOL: ?redirect@@YAXXZ
void redirect()
{
    if (RedirStderr)
        _dup2(1, 2);
}
