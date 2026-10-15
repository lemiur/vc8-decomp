#include "../../include/cl/util.h"
#include <stdlib.h>
#include <wctype.h>

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
