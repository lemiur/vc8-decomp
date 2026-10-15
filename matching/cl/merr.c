#include "../../include/cl/merr.h"

/* CRT lineage: installed VC8 crt/src/merr.c:36-39, SHA-256
 * 250b49faa3afa8bb94b9dcf92d967fe2feb93bb1aae09f38eeaab9b043b80f9d.
 * crt/src/crtassem.h:23 records 8.0.50727.762. This identifies the installed
 * lineage, not proof of the exact retail source revision. Public PDB ownership:
 * merr.obj. Retail body 0x40c661..0x40c663 is xor eax,eax; ret, with no referents.
 * This partial unit recovers only _matherr; __defaultmatherr is not defined here.
 * No assertion or other line-sensitive operation occurs in this body.
 */
// FUNCTION: cl 0x40c661
// SYMBOL: __matherr
int __CRTDECL _matherr(struct _exception *pexcept)
{
    return 0;
}
