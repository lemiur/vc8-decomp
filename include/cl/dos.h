#ifndef VC8_CL_DOS_H
#define VC8_CL_DOS_H

#include <windows.h>

// PDB public ?Passinfo@@3PAUpassinfo_s@@A proves a 36-byte passinfo_s table
// owned by clmain.obj (0x417950, ten rows, stride 0x24). Each observed retail
// access pins one member: +0 and +4 are UTF-16 string pointers, +8/+0A are two
// WCHAR selector values, +0C is a DWORD options field, +10 an HMODULE, +14/+18
// and +1C are callable slots, and +20 is a UTF-16 profile pointer. The member
// spellings are reconstructed from those uses; no public field names survive.
struct passinfo_s
{
    wchar_t *command;
    wchar_t *environment;
    wchar_t selector[2];
    unsigned int options;
    HMODULE module;
    int (__stdcall *invoke)(int, wchar_t **, int, HMODULE *);
    int (__stdcall *abort)(int);
    void (__stdcall *cleanup)();
    wchar_t *profile;
};

int FallThroughFilter(unsigned long exception_code, passinfo_s *pass, int *status);
int screen_length();
void redirect();

#endif
