#include "../../include/cl/compile.h"

#include <stdlib.h>

// Reconstruction unit for the PDB DBI section-contribution owner compile.obj
// (module 9). Original source filename, extension and line layout unresolved.
// Every function here is byte-exact against its DBI contribution extent.

// FUNCTION: cl 0x4062f7
// SYMBOL: ??$PstNext@USRCTARG@@@@YAPAUSRCTARG@@PAU0@@Z
template<class T>
T *PstNext(T *node)
{
    return node ? node->next : 0;
}

template SRCTARG *PstNext<SRCTARG>(SRCTARG *);

// FUNCTION: cl 0x4061f5
// SYMBOL: ?basename@@YAPAGPAGIPBG@Z
unsigned short *__cdecl basename(unsigned short *output, unsigned int capacity,
                                 const unsigned short *source)
{
    _wsplitpath_s(source, 0, 0, 0, 0, output, capacity, 0, 0);
    return output;
}

// FUNCTION: cl 0x406217
// SYMBOL: ?filename@@YAPAGPAGIPBG@Z
unsigned short *__cdecl filename(unsigned short *output, unsigned int capacity,
                                 const unsigned short *source)
{
    unsigned short name[_MAX_FNAME];
    unsigned short extension[_MAX_EXT];

    _wsplitpath_s(source, 0, 0, 0, 0, name, _MAX_FNAME, extension, _MAX_EXT);
    _wmakepath_s(output, capacity, L"", L"", name, extension);
    return output;
}

// FUNCTION: cl 0x406284
// SYMBOL: ?pathname@@YAPAGPAGIPBG@Z
unsigned short *__cdecl pathname(unsigned short *output, unsigned int capacity,
                                 const unsigned short *source)
{
    unsigned short drive[_MAX_DRIVE];
    unsigned short directory[_MAX_DIR];
    unsigned short name[_MAX_FNAME];

    _wsplitpath_s(source, drive, _MAX_DRIVE, directory, _MAX_DIR, name, _MAX_FNAME, 0, 0);
    _wmakepath_s(output, capacity, drive, directory, name, L"");
    return output;
}

// FUNCTION: cl 0x4061d2
// SYMBOL: ?module_extension@@YAPAGXZ
unsigned short *__cdecl module_extension()
{
    if (DllFlg)
        return L"dll";
    return NoAssembly ? L"netmodule" : L"exe";
}
