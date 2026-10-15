#ifndef VC8_DECOMP_CL_UTIL_H
#define VC8_DECOMP_CL_UTIL_H

// PDB identity: ?nextbase@@YAHH@Z. Caller at 0x408e80 cleans one
// stack argument; the body returns the integer in EAX.
int __cdecl nextbase(int);

// PBG/PAG in the public symbols identifies unsigned short, independent of
// the still-unresolved native wchar_t compiler setting.
unsigned short* __cdecl gobblewhite(unsigned short*);
void __cdecl xfree(void*);

#endif
