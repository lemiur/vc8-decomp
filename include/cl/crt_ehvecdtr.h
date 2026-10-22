#ifndef VC8_CL_CRT_EHVECDTR_H
#define VC8_CL_CRT_EHVECDTR_H

/*
 * Canonical declarations for the EH-aware array destructor helpers owned by the
 * installed-era CRT ehvecdtr.cpp (retail module 28, object path
 * build\intel\dll_obj\ehvecdtr.obj). The installed source tree does not ship
 * ehvecdtr.cpp, and the CRT build consumes a prebuilt object (crt/src's
 * makefile.inc copies ehvecdtr.obj from PREOBJDIR), so the bodies are decoded
 * from retail:
 *   __ArrayUnwind 0x0040c38a, 94 bytes (body + inlined except filter + epilog)
 *   ??_M         0x0040c3e8, 99 bytes (body + finally block after the epilog)
 *
 * The destructor callback type is proven by the mangled parameter
 * P6EX0@Z = `void (__thiscall *)(void *)` and by the decoded call sites, which
 * pass the element pointer in ECX and push nothing. The CRT builds C++ sources
 * with -d1Binl precisely to allow a user-level __thiscall, per the era
 * crt/src/makefile.sub CXXFLAGS line; this unit therefore records -d1Binl.
 *
 * The EH record constant and terminate are the canonical era declarations in
 * crt/src/eh.h:65; the unit builds with an empty _CRTIMP so terminate resolves
 * to the MSVCR80.dll import thunk exactly as retail's call does.
 */

#include <windows.h>
#include <eh.h>

typedef void (__thiscall *PFUNC)(void *);

#define EH_EXCEPTION_NUMBER      0xE06D7363

void __stdcall __ArrayUnwind(void *ptr, unsigned size, int count, PFUNC pfunc);

/*
 * ??_M ("`eh vector destructor iterator'") cannot be declared from ordinary
 * C++ source with this toolchain: the name is the compiler's internal special
 * name and the backtick spelling is rejected (C2018). It is therefore not
 * declared here; see crt_ehvecdtr.cpp for the recorded wall.
 */

#endif
