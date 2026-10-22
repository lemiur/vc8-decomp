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

// Compile-driver context. Only the public PDB type tag is proved; the complete
// layout belongs to the clmain.obj reconstruction. This is the canonical
// partial model: +0x20 is the only member this module's decoded bodies read as
// a value (the wide source path passed to wcschr, GetDiskFreeSpaceExW and
// strqlen at 0x4060a6, 0x406113 and 0x4069b9). Offsets 0x00..0x1c are reserved
// placeholder storage with no established semantics here; extend, do not copy.
struct context_s {
    int reserved_00;
    int reserved_04;
    int reserved_08;
    int reserved_0c;
    int reserved_10;
    int reserved_14;
    int reserved_18;
    int reserved_1c;
    unsigned short *source_path; // +0x20
};

// Public PDB data identities owned by clmain.obj; declared once here for the
// compile.obj bodies that consume them (see the per-function evidence).
extern int DllFlg;
extern int NoAssembly;
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

