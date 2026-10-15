#ifndef VC8_CL_DOS_H
#define VC8_CL_DOS_H

// Public PDB spelling proves this tag, but its layout remains unresolved.
struct passinfo_s;

int FallThroughFilter(unsigned long exception_code, passinfo_s *pass, int *status);

#endif
