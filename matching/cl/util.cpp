#include "../../include/cl/util.h"
#include <stdlib.h>
#include <wctype.h>
#include <wchar.h>

// Reconstruction unit named for PDB contribution owner util.obj.
// Original source filename and parameter spelling are unresolved.

// FUNCTION: cl 0x408276
// SYMBOL: ?nextbase@@YAHH@Z
int __cdecl nextbase(int base)
{
    if (base == 1)
        return 2;
    if (base == 2)
        return 3;
    return 1;
}

// FUNCTION: cl 0x4082dc
// SYMBOL: ?xfree@@YAXPAX@Z
void __cdecl xfree(void* allocation)
{
    if (allocation)
        free(allocation);
}

// FUNCTION: cl 0x407f99
// SYMBOL: ?gobblewhite@@YAPAGPAG@Z
unsigned short* __cdecl gobblewhite(unsigned short* text)
{
    while (*text && iswspace(*text))
        ++text;
    return text;
}

// FUNCTION: cl 0x408010
// SYMBOL: ?strqlen@@YAHPBG@Z
// stop: complete candidate; quote test and backslash-counter codegen differ.
int __cdecl strqlen(const unsigned short* text)
{
    int length = 0;
    int backslashes = 0;
    int quote = 0;

    while (*text) {
        if (iswspace(*text))
            quote = 1;
        int character = *text;
        if (character == '"')
            length += backslashes + 1;
        backslashes = character == '\\' ? backslashes + 1 : 0;
        ++length;
        ++text;
    }
    if (quote)
        length += backslashes + 2;
    return length;
}

// FUNCTION: cl 0x408145
// SYMBOL: ?strrchars@@YAPAGPAGPBG@Z
unsigned short* __cdecl strrchars(unsigned short* text, const unsigned short* characters)
{
    unsigned short* last = 0;
    for (; *characters; ++characters) {
        unsigned short* found = wcsrchr(text, *characters);
        if (found && (!last || found > last))
            last = found;
    }
    return last;
}

// FUNCTION: cl 0x407fba
// SYMBOL: ?concat@@YAPAGPAGIPBG@Z
unsigned short* __cdecl concat(unsigned short* destination, unsigned int capacity, const unsigned short* source)
{
    if (source)
        wcscat_s(destination, capacity, source);
    return destination + wcslen(destination);
}

// FUNCTION: cl 0x407fe5
// SYMBOL: ?append@@YAPAGPAGIPBG@Z
unsigned short* __cdecl append(unsigned short* destination, unsigned int capacity, const unsigned short* source)
{
    if (source)
        wcscpy_s(destination, capacity, source);
    return destination + wcslen(destination);
}

// FUNCTION: cl 0x407f69
// SYMBOL: ?IsOutputToConsole@@YAHPAX@Z
int __cdecl IsOutputToConsole(HANDLE output)
{
    DWORD mode;
    if ((GetFileType(output) & ~FILE_TYPE_REMOTE) != FILE_TYPE_CHAR)
        return 0;
    return GetConsoleMode(output, &mode) != 0;
}

// FUNCTION: cl 0x407f08
// SYMBOL: ?IsRunningUnderIDE@@YAHPAPAX@Z
int __cdecl IsRunningUnderIDE(HANDLE* output)
{
    WCHAR handleText[64];
    if (GetEnvironmentVariableW(L"VS_UNICODE_OUTPUT", 0, 0)) {
        GetEnvironmentVariableW(L"VS_UNICODE_OUTPUT", handleText, 64);
        *output = (HANDLE)_wtoi(handleText);
        return 1;
    }
    return 0;
}
