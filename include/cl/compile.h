#ifndef VC8_DECOMP_CL_COMPILE_H
#define VC8_DECOMP_CL_COMPILE_H

// Reconstruction unit for the PDB DBI section-contribution owner compile.obj
// (module 9). The original source filename, extension, declaration spellings
// and line layout are unresolved and are not claimed here.
//
// Public PDB identities are the primary evidence for the declarations below.
// PAG/PBG in the mangled names encode unsigned short*, never native wchar_t
// (_W), so this unit is built in typedef-wchar mode (/Zc:wchar_t-).

struct context_s;
struct worklist_s;
enum pass_type;

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
// (PAH/PBG), consistent with the typedef-wchar CRT mode the callers use.
unsigned short *__cdecl basename(unsigned short *output, unsigned int capacity,
                                 const unsigned short *source);
unsigned short *__cdecl filename(unsigned short *output, unsigned int capacity,
                                 const unsigned short *source);
unsigned short *__cdecl pathname(unsigned short *output, unsigned int capacity,
                                 const unsigned short *source);
unsigned short *__cdecl module_extension();
unsigned int __cdecl replaca_strlen(const unsigned short *text, context_s *context);
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
