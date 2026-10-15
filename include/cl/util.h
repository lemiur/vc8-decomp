#ifndef VC8_DECOMP_CL_UTIL_H
#define VC8_DECOMP_CL_UTIL_H

#include <windows.h>

// PDB identity: ?nextbase@@YAHH@Z. Caller at 0x408e80 cleans one
// stack argument; the body returns the integer in EAX.
int __cdecl nextbase(int);

// PBG/PAG in the public symbols identifies unsigned short, independent of
// the still-unresolved native wchar_t compiler setting.
unsigned short* __cdecl gobblewhite(unsigned short*);
void __cdecl xfree(void*);
int __cdecl strqlen(const unsigned short*);
unsigned short* __cdecl strrchars(unsigned short*, const unsigned short*);
unsigned short* __cdecl concat(unsigned short*, unsigned int, const unsigned short*);
unsigned short* __cdecl append(unsigned short*, unsigned int, const unsigned short*);
int __cdecl IsOutputToConsole(HANDLE);
int __cdecl IsRunningUnderIDE(HANDLE*);
unsigned short* __cdecl strqcpy(unsigned short*, const unsigned short*);
int __cdecl initscreenline();

// PDB ?cmderr@@YAXIZZ; all retail paths call done(2), which calls the
// canonical CRT exit import. The real body is still an open dependency.
__declspec(noreturn) void __cdecl cmderr(unsigned int, ...);

#endif
