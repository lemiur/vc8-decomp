#include "../../include/cl/util.h"

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
