#ifndef VC8_DECOMP_CL_MPCL_H
#define VC8_DECOMP_CL_MPCL_H

// Public PDB: ?thread_print@@YAXPBGZZ (mpcl.obj).
// PBG is const unsigned short*. Original wchar_t typedef spelling is unresolved.
// Caller evidence at 0x40AAAB and 0x40AABF uses differing variadic argument
// counts and caller cleanup; the retail function is a plain return.
void __cdecl thread_print(const unsigned short *, ...);

// ?env_size@@YAIPBG@Z; caller merge_env passes GetEnvironmentStringsW's
// result, uses EAX as a character count, then allocates twice that count + 2.
unsigned int __cdecl env_size(const unsigned short *);

#endif
