#include "../../include/cl/mpcl.h"

// mpcl.obj attribution: PDB DBI section contribution contains the public start.
// The original source filename, extension and line positions are unresolved.
// Complete retail CFG at 0x40A25F is a single C3 return with no referents.
// Callers retain variadic arguments although this retail body ignores them.

// FUNCTION: cl 0x40A25F
// SYMBOL: ?thread_print@@YAXPBGZZ
void __cdecl thread_print(const unsigned short *, ...)
{
}

// FUNCTION: cl 0x40A2DC
// SYMBOL: ?env_size@@YAIPBG@Z
// Complete retail CFG: 45 decoded bytes, all local branches, ret 0x40A308.
// Names environment/cursor are reconstructed, not recovered identifiers.
// The final zero is excluded; an empty environment returns zero.
unsigned int __cdecl env_size(const unsigned short *environment)
{
    const unsigned short *cursor = environment;

    while (*cursor) {
        while (*cursor)
            ++cursor;
        ++cursor;
    }
    return cursor - environment;
}
