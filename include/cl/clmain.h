#ifndef CL_CLMAIN_H
#define CL_CLMAIN_H

#include <stddef.h>
#include "mpcl.h"

// Public PDB argument spelling PAUflag_s proves a struct pointer. These four
// callbacks do not access it, so its layout and original parameter name remain
// unresolved. Keep this the canonical declaration until field evidence exists.
struct flag_s;

// Public class identity comes from its constructor. The byte flag is observed
// at this+0; cmderr constructs the object at EBP-1, proving its one-byte extent.
// The field name is reconstructed. The inline destructor follows cmderr's
// conditional ReleaseMutex cleanup; no out-of-line destructor is public.
class CConsoleLock
{
public:
    CConsoleLock();
    ~CConsoleLock()
    {
        if (locked)
            ReleaseMutex(g_hMutex);
    }

private:
    bool locked;
};

// Public ?RedirStderr@@3HA proves int storage; the retail image initializes it
// to one. DBI contribution attribution establishes clmain.obj ownership.
extern int RedirStderr;
extern void* pPCHBaseAddress;
extern void* pPCHAstExtraBaseAddress;

void __cdecl error_report_prompt(flag_s*);
void __cdecl error_report_queue(flag_s*);
void __cdecl error_report_send(flag_s*);
void __cdecl error_report_none(flag_s*);
int __cdecl IsRunningUnderIDE();
wchar_t* __cdecl fullccpath();
void __cdecl release_filelife_heap();
void __cdecl release_ast_extra_heap();

#endif
