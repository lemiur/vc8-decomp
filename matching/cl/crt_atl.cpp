/*
 * Reconstruction of ATL's atltrace.obj thread-ACP helpers (retail module 54).
 * The bodies are the installed-era ATL 8 inline definitions, quoted from
 * atlmfc/include/atlconv.h lines 104-156 with provenance recorded in
 * include/cl/crt_atl.h; atltrace.cpp lines 15-19 supply the defining object's
 * namespace, init_seg and the g_pfnGetThreadACP initializer. All three bodies
 * decode to exactly these statements:
 *   Fake  0x0040c716 (101 B): /GS cookie, GetThreadLocale, GetLocaleInfoA with
 *         LOCALE_IDEFAULTANSICODEPAGE into char[7], the decimal parse loop and
 *         the GetACP fallback.
 *   Real  0x0040c77b (4 B): push CP_THREAD_ACP (3); pop eax; ret.
 *   Thunk 0x0040c77f (100 B): OSVERSIONINFO fill, GetVersionExA, platform/version
 *         select between Real and Fake, ATL's InterlockedExchangePointer store
 *         through ::InterlockedExchange, then the pointer call.
 */

#include "../../include/cl/crt_atl.h"

namespace ATL
{

#pragma init_seg( lib )

// FUNCTION: cl 0x40c716
// SYMBOL: ?_AtlGetThreadACPFake@ATL@@YGIXZ
UINT WINAPI _AtlGetThreadACPFake() throw()
{
	UINT nACP = 0;

	LCID lcidThread = ::GetThreadLocale();

	char szACP[7];
	// GetLocaleInfoA will fail for a Unicode-only LCID, but those are only supported on
	// Windows 2000.  Since Windows 2000 supports CP_THREAD_ACP, this code path is never
	// executed on Windows 2000.
	if (::GetLocaleInfoA(lcidThread, LOCALE_IDEFAULTANSICODEPAGE, szACP, 7) != 0)
	{
		char* pch = szACP;
		while (*pch != '\0')
		{
			nACP *= 10;
			nACP += *pch++ - '0';
		}
	}
	// Use the Default ANSI Code Page if we were unable to get the thread ACP or if one does not exist.
	if (nACP == 0)
		nACP = ::GetACP();

	return nACP;
}

// FUNCTION: cl 0x40c77b
// SYMBOL: ?_AtlGetThreadACPReal@ATL@@YGIXZ
UINT WINAPI _AtlGetThreadACPReal() throw()
{
	return( CP_THREAD_ACP );
}

// FUNCTION: cl 0x40c77f
// SYMBOL: ?_AtlGetThreadACPThunk@ATL@@YGIXZ
UINT WINAPI _AtlGetThreadACPThunk() throw()
{
	OSVERSIONINFO ver;
	ATLGETTHREADACP pfnGetThreadACP;

	ver.dwOSVersionInfoSize = sizeof( ver );
	::GetVersionEx( &ver );
	if( (ver.dwPlatformId == VER_PLATFORM_WIN32_NT) && (ver.dwMajorVersion >= 5) )
	{
		// On Win2K, CP_THREAD_ACP is supported
		pfnGetThreadACP = _AtlGetThreadACPReal;
	}
	else
	{
		pfnGetThreadACP = _AtlGetThreadACPFake;
	}
	// ATL's own InterlockedExchangePointer inline (atlconv.h lines 87-94) uses
	// ::InterlockedExchange because the platform macro is unreliable.
	::InterlockedExchange( reinterpret_cast< LONG* >( &g_pfnGetThreadACP ),
		static_cast< LONG >( reinterpret_cast< LONG_PTR >( pfnGetThreadACP ) ) );

	return( g_pfnGetThreadACP() );
}

// The defining atltrace.cpp translation unit initializes the pointer to the
// thunk; this is the reference that forces all three COMDATs out of line.
// DATA: cl 0x417c80
ATLGETTHREADACP g_pfnGetThreadACP = _AtlGetThreadACPThunk;

}
