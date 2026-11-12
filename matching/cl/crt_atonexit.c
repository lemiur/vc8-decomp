#include "../../include/cl/crt_atonexit.h"

/* CRT lineage: installed VC8 SP1 crt/src/atonexit.c, SHA-256
 * 798cf1e69b03b0016726c5cc5148c6a4b4629376909d7645365223c63643430f,
 * 8.0.50727.762 (crt/src/crtassem.h). PDB publics and DBI contributions place
 * _onexit and atexit in build/intel/dll_obj/atonexit.obj, module 25.
 *
 * SPECIAL BUILD MACRO! Note that atonexit.c is linked in with the client's
 * code. It does not go into crtdll.dll! Therefore, it must be built under
 * the _DLL switch (like user code) and CRTDLL must be undefined. The header
 * reproduces that build context. No assertion or other line-sensitive
 * operation occurs in these bodies.
 */

/*
 * Pointers to beginning and end of the table of function pointers manipulated
 * by _onexit()/atexit().  If this module is an EXE, _onexitbegin will be -1.
 * Otherwise _onexitbegin will point to a block of malloc-ed memory used to
 * maintain the DLL module's private onexit list of terminator routines.
 * NOTE - the pointers are stored encoded.
 */

_PVFV *__onexitbegin;
_PVFV *__onexitend;

// FUNCTION: cl 0x40bbc4
// SYMBOL: __onexit
_onexit_t __cdecl _onexit (
        _onexit_t func
        )
{
        _PVFV * onexitbegin;
        _PVFV * onexitend;
        _onexit_t retval;

        onexitbegin = (_PVFV *)_decode_pointer(__onexitbegin);

        if (onexitbegin == (_PVFV *)-1)
        {
            /* EXE */
#ifdef _M_IX86
            return (*_imp___onexit)(func);
#else  /* _M_IX86 */
            return (*__imp__onexit)(func);
#endif  /* _M_IX86 */
        }

        /*
         * Note that we decode/encode the onexit array pointers on the
         * client side, not the CRT DLL side, to ease backwards compatibility.
         * That means we have to take a lock on this side, making the lock
         * found in __dllonexit redundant.
         */

        _lock(_EXIT_LOCK1);

        __try
        {
            onexitbegin = (_PVFV *)_decode_pointer(__onexitbegin);
            onexitend   = (_PVFV *)_decode_pointer(__onexitend);

            retval = __dllonexit((_onexit_t)_encode_pointer(func), &onexitbegin, &onexitend);

            __onexitbegin = (_PVFV *)_encode_pointer(onexitbegin);
            __onexitend   = (_PVFV *)_encode_pointer(onexitend);
        }
        __finally
        {
            _unlock(_EXIT_LOCK1);
        }

        return retval;
}

// FUNCTION: cl 0x40bc69
// SYMBOL: _atexit
int __cdecl atexit (
        _PVFV func
        )
{
        return (_onexit((_onexit_t)func) == NULL) ? -1 : 0;
}
