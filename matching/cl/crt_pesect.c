#include "../../include/cl/crt_pesect.h"

/* CRT lineage: installed VC8 SP1 crt/src/pesect.c, SHA-256
 * c878dd31d495c21e91ce525f2ca173aac5a63b691c8d819d4a4c5466c3f98833,
 * 8.0.50727.762 (crt/src/crtassem.h). PDB publics and DBI contributions place
 * all three functions in build/intel/dll_obj/pesect.obj, module 34. The installed
 * source's own "#pragma optimize("t", on)" is retained: it makes these three
 * bodies speed-optimized, which is why both /O1 and /O2 reproduce their bytes.
 * No assertion or other line-sensitive operation occurs in these bodies.
 */

#pragma optimize("t", on)   // optimize for speed, not space

// FUNCTION: cl 0x40c4f0
// SYMBOL: __ValidateImageBase
BOOL __cdecl _ValidateImageBase(
    PBYTE pImageBase
    )
{
    PIMAGE_DOS_HEADER      pDOSHeader;
    PIMAGE_NT_HEADERS      pNTHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader;

    pDOSHeader = (PIMAGE_DOS_HEADER)pImageBase;
    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }

    pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDOSHeader + pDOSHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }

    pOptHeader = (PIMAGE_OPTIONAL_HEADER)&pNTHeader->OptionalHeader;
    if (pOptHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    {
        return FALSE;
    }

    return TRUE;
}

// FUNCTION: cl 0x40c520
// SYMBOL: __FindPESection
PIMAGE_SECTION_HEADER __cdecl _FindPESection(
    PBYTE     pImageBase,
    DWORD_PTR rva
    )
{
    PIMAGE_NT_HEADERS     pNTHeader;
    PIMAGE_SECTION_HEADER pSection;
    unsigned int          iSection;

    pNTHeader =
        (PIMAGE_NT_HEADERS)
            (pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);

    //
    // Find the section holding the desired address.  We make no assumptions
    // here about the sort order of the section descriptors (though they
    // always appear to be sorted by ascending section RVA).
    //
    for (iSection = 0, pSection = IMAGE_FIRST_SECTION(pNTHeader);
         iSection < pNTHeader->FileHeader.NumberOfSections;
         ++iSection, ++pSection)
    {
        if (rva >= pSection->VirtualAddress &&
            rva <  pSection->VirtualAddress + pSection->Misc.VirtualSize)
        {
            //
            // Section found
            //
            return pSection;
        }
    }

    //
    // Section not found
    //
    return NULL;
}

// FUNCTION: cl 0x40c570
// SYMBOL: __IsNonwritableInCurrentImage
BOOL __cdecl _IsNonwritableInCurrentImage(
    PBYTE pTarget
    )
{
    PBYTE                 pImageBase;
    DWORD_PTR             rvaTarget;
    PIMAGE_SECTION_HEADER pSection;

    pImageBase = (PBYTE)&__ImageBase;

    __try {
        //
        // Make sure __ImageBase does address a PE image.  This is likely an
        // unnecessary check, since we should be running from a normal image,
        // but it is fast, this routine is rarely called, and the normal call
        // is for security purposes.  If we don't have a PE image, return
        // failure.
        //
        if (!_ValidateImageBase(pImageBase))
        {
            return FALSE;
        }

        //
        // Convert the targetaddress to a Relative Virtual Address (RVA) within
        // the image, and find the corresponding PE section.  Return failure if
        // the target address is not found within the current image.
        //
        rvaTarget = pTarget - pImageBase;
        pSection = _FindPESection(pImageBase, rvaTarget);
        if (pSection == NULL)
        {
            return FALSE;
        }

        //
        // Check the section characteristics to see if the target address is
        // located within a writable section, returning a failure if yes.
        //
        return (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) == 0;
    }
    __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION)
    {
        //
        // Just return failure if the PE image is corrupted in any way that
        // triggers an AV.
        //
        return FALSE;
    }
}
