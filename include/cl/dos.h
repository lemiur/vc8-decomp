#ifndef VC8_CL_DOS_H
#define VC8_CL_DOS_H

#include <windows.h>
#include "clmain.h"

// passinfo_s is owned by clmain.obj (?Passinfo@@3PAUpassinfo_s@@A, ten 0x24-byte
// rows). Its one canonical definition lives in clmain.h; this unit consumes it
// and must never redeclare the type.

int FallThroughFilter(unsigned long exception_code, passinfo_s *pass, int *status);
int screen_length();
void redirect();

#endif
