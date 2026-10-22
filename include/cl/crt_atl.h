#ifndef VC8_CL_CRT_ATL_H
#define VC8_CL_CRT_ATL_H

/*
 * Canonical declarations for the three ATL thread-ACP helpers owned by
 * atltrace.obj (retail module 54, object path INTEL\Release_1\atltrace.obj).
 *
 * Era source provenance (installed ATL 8, both files part of the SP1 tree):
 *   VC/atlmfc/include/atlconv.h
 *     SHA-256 2C5D02E9026441A34EDB9297384515965A0E526AEBD2C62165BDBAB6A4E9984B,
 *     file time 2006-12-01 21:55:36. The three functions are the `inline`
 *     definitions at lines 104-128 (Fake), 130-133 (Real) and 137-156 (Thunk);
 *     ATLGETTHREADACP is typedef'd at line 102 and g_pfnGetThreadACP declared
 *     extern at line 135.
 *   VC/atlmfc/src/atl/atls/atltrace.cpp
 *     SHA-256 B670E9F0DBD9747AF2A7E9C90585475DB0E1BA47760FD3AC31F8ECDC00987198,
 *     file time 2005-09-22 23:48:56. Lines 15-19 are the defining translation
 *     unit: namespace ATL, `#pragma init_seg(lib)` and
 *     `ATLGETTHREADACP g_pfnGetThreadACP = _AtlGetThreadACPThunk;`.
 * This records provenance, not a claim that the retail source revision is
 * byte-identical; the decoded retail bodies are the byte authority.
 *
 * Retail sizes and starts (PDB publics, module 54):
 *   _AtlGetThreadACPFake  0x0040c716  101 bytes
 *   _AtlGetThreadACPReal  0x0040c77b    4 bytes
 *   _AtlGetThreadACPThunk 0x0040c77f  100 bytes
 *   ?g_pfnGetThreadACP@ATL@@3P6GIXZA 0x00417c80 (4-byte .data pointer)
 * All three functions are emitted out of line because their addresses are taken
 * by g_pfnGetThreadACP and by the thunk's InterlockedExchangePointer store.
 */

#include <windows.h>

namespace ATL
{
    typedef UINT (WINAPI *ATLGETTHREADACP)();

    UINT WINAPI _AtlGetThreadACPFake() throw();
    UINT WINAPI _AtlGetThreadACPReal() throw();
    UINT WINAPI _AtlGetThreadACPThunk() throw();

    extern ATLGETTHREADACP g_pfnGetThreadACP;
}

#endif
