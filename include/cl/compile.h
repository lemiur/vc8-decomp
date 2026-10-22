#ifndef VC8_DECOMP_CL_COMPILE_H
#define VC8_DECOMP_CL_COMPILE_H

#include "clmain.h"

// Reconstruction unit for the PDB DBI section-contribution owner compile.obj
// (module 9). The original source filename, extension, declaration spellings
// and line layout are unresolved and are not claimed here.
//
// Public PDB identities are the primary evidence for the declarations below.
// PAG/PBG in the mangled names encode unsigned short*, never native wchar_t
// (_W), so this unit is built in typedef-wchar mode (/Zc:wchar_t-).

struct worklist_s;
enum pass_type;

// context_s is owned by clmain.obj (?Context@@3PAUcontext_s@@A -> ?CX at
// 0x418900, extent 0x28). Its one canonical definition lives in clmain.h:
// +0x20 is the wide base name this module's decoded consumers read
// (0x4060a6, 0x406113, 0x4069b9). Never redeclare the type here.

// Public PDB data identities owned by clmain.obj; DllFlg and NoAssembly are
// declared once in clmain.h (included above). MaxBatchId is consumed by the
// limit_batch_files draft and has no reconstructed definition yet.
extern int MaxBatchId;

// Public template tag from ??$PstNext@USRCTARG@@@@YAPAUSRCTARG@@PAU0@@Z.
// PstNext reads the first dword of the argument (0x4062ff "mov eax,[eax]"),
// proving a next pointer at offset zero; the remaining layout is unresolved.
struct SRCTARG {
    SRCTARG *next; // +0x00
};

// One call per list step; the public out-of-line instantiation
// ??$PstNext@USRCTARG@@@@YAPAUSRCTARG@@PAU0@@Z is the 14-byte retail body.
// The member name is reconstructed, not recovered.
template<class T>
T *PstNext(T *node);

// Actual PDB public starts and mangled ABI. The element type is unsigned short
// (PAG/PBG), consistent with the typedef-wchar CRT mode the callers use.
unsigned short *__cdecl basename(unsigned short *output, unsigned int capacity,
                                 const unsigned short *source);
unsigned short *__cdecl filename(unsigned short *output, unsigned int capacity,
                                 const unsigned short *source);
unsigned short *__cdecl pathname(unsigned short *output, unsigned int capacity,
                                 const unsigned short *source);
unsigned short *__cdecl module_extension();
int __cdecl replaca_strlen(const unsigned short *text, context_s *context);
unsigned short *__cdecl replaca(unsigned short *output, unsigned int capacity,
                                const unsigned short *source, context_s *context);
void __cdecl limit_batch_files(context_s *context);
int __cdecl passes(pass_type *steps, context_s *context, int write,
                   int (__cdecl *callback)(context_s *));
worklist_s *__cdecl build_full_worklist(context_s *context);
int __cdecl dopass(context_s *context);
void __cdecl post_compile(context_s *context);
void __cdecl compile(context_s *context);

#endif

