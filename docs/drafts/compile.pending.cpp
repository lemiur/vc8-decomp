#include "../../include/cl/compile.h"

#include <wchar.h>
#include <windows.h>

// BLOCKED RECONSTRUCTION DRAFTS - NOT A BUILD UNIT.
//
// This file carries compile.obj bodies that are decoded and modelled but cannot
// be enabled in the reconstruction unit, because their foreign referents
// (clmain.obj data, util.obj helpers) have no real source yet. It deliberately
// carries no FUNCTION annotation: tools/match.py skips files without one, so
// this file is never compiled or linked. Do not add annotations here. When the
// owning units define the externals named in each stop note, move the function
// into matching/cl/compile.cpp, annotate it, add the owning unit to the
// candidate's dependencies and give it a review record.

// stop: measured byte-exact with a disposable lane-local probe, not linkable
// yet. Retail: 35 bytes at 0x4061d2 (DBI contribution 20946). Decoded body:
// cmp [DllFlg],0; je; mov eax,L"dll"; ret; cmp [NoAssembly],0;
// mov eax,L"netmodule"; jne; mov eax,L"exe"; ret.
// Probe measurement: 100.0, boundary=verified, referents=resolved. Blocker:
// matching/cl/clmain.cpp must define ?DllFlg@@3HA (0x41913c) and
// ?NoAssembly@@3HA (0x419648). Required referent bindings when enabling:
// literal L"dll" 0x4152d4 (8 bytes), L"netmodule" 0x40d3a4 (20 bytes) and
// L"exe" 0x40d39c (8 bytes), plus both globals; the lane removed those records
// after measuring so the integration merge cannot conflict with the owning
// lane's evidence. Caveat for the integration owner: both retail
// globals are loader-zero, and scan_referents tries hash-keyed literal bindings
// before MAP aliases, so the two-byte empty-literal binding can swallow a
// zero-initialized four-byte global. The probe had to initialize them nonzero
// to measure; the real definitions will need that resolution order revisited
// (or an exact-size guard on literal bindings) or this referent stays masked.
unsigned short *__cdecl module_extension()
{
    if (DllFlg)
        return L"dll";
    return NoAssembly ? L"netmodule" : L"exe";
}

// stop: complete structural candidate, not byte-exact, so disabled. Retail:
// 221 bytes at 0x406082 (DBI contribution 20610, next contribution 20831).
// Decoded shape: clamp MaxBatchId against 199; accept drive-absolute
// (p[1]==':' && p[2]=='\\') or UNC (p[0..1]=="\\\\") source paths; on a
// separator, temporarily NUL the wide path, query free space on it with
// GetDiskFreeSpaceExW, and if free < limit*3000000 set
// limit = free/3000000; restore the character and store MaxBatchId.
// Measured residue against retail (score 18.1, raw-bytes comparison): the
// candidate frame is 0x1c versus retail 0x18 (separator spilled to a stack slot
// that retail keeps in ESI), the MaxBatchId/199 compare operands are swapped,
// and the conditional limit assignment is laid out with the 199 immediate in a
// register. The clamp and separator logic are otherwise instruction-for-
// instruction. Missing foreign definitions: ?MaxBatchId@@3HA (0x417838). The
// compiler-generated __aulldiv call and the wcschr/GetDiskFreeSpaceExW imports
// are already bound. Required referent bindings when enabling:
// ?MaxBatchId@@3HA 0x417838, msvcr80.dll!wcschr 0x40d2e4,
// kernel32.dll!GetDiskFreeSpaceExW 0x40d120 and __aulldiv 0x40bd80; the lane
// removed those records after measuring so the integration merge cannot
// conflict with the owning lane's evidence.
void __cdecl limit_batch_files(context_s *context)
{
    ULARGE_INTEGER free_bytes;
    ULARGE_INTEGER total_bytes;
    unsigned short *separator = 0;
    unsigned short *directory = 0;
    unsigned short saved = 0;
    int limit = 199;

    if (MaxBatchId <= 199)
        limit = MaxBatchId;

    if (context->source_path[1] == L':') {
        if (context->source_path[2] == L'\\')
            separator = context->source_path + 2;
    } else if (context->source_path[0] == L'\\' && context->source_path[1] == L'\\') {
        separator = wcschr(context->source_path + 2, L'\\');
        if (separator)
            separator = wcschr(separator + 1, L'\\');
    }

    if (separator) {
        ++separator;
        saved = *separator;
        *separator = 0;
        directory = context->source_path;
    }

    if (GetDiskFreeSpaceExW(directory, &free_bytes, &total_bytes, 0)
        && free_bytes.QuadPart < (unsigned __int64)limit * 3000000)
        limit = (int)(free_bytes.QuadPart / 3000000);

    if (separator)
        *separator = saved;

    MaxBatchId = limit;
}
