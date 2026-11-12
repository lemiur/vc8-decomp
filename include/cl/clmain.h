#ifndef CL_CLMAIN_H
#define CL_CLMAIN_H

#include <stddef.h>
#include "mpcl.h"

// Public PDB tags PAUflag_s, PAUpassinfo_s and PAUcontext_s identify these
// structures; their member spellings are reconstructed from retail consumers.
// Vector's PAUpassinfo_s already proves the tag in command-line arguments.

// One option record. newflag (0x40182a) allocates 0x18 zeroed bytes and fills
// +0 (the caller's integer selector mask, stored as a word), +8, +0xc and
// +0x10 with separately duplicated wide strings; appendflag links records
// through +4. mark_defaults ORs 0x80/0x20 into the word at +0. flag_this_pass
// and deactivate_passes* consume the +8/+0x10 selector strings.
struct flag_s
{
    unsigned short flags;   // +0x00 option state words
    flag_s *next;           // +0x04 intrusive list link
    wchar_t *passes;        // +0x08 selector set tested by flag_this_pass
    wchar_t *keyword;       // +0x0c duplicated option spelling
    wchar_t *value;         // +0x10 selector-prefixed option value
};

// One compiler pass row. ?Passinfo@@3PAUpassinfo_s@@A is a public 10-row table
// at 0x417950 with stride 0x24 proven by the pass loops' `add esi, 0x24`.
// Row +8 is the pass selector compared against flag selector strings, +0xc is
// the int state word the pass loops OR with 1 / AND with ~1, and the remaining
// slots are corroborated by the pass driver: +0x10 receives LoadLibraryW's
// handle, +0x14/+0x18/+0x1c receive GetProcAddress results and +0x20 is the
// mutable duplicated profile string.
struct passinfo_s
{
    const wchar_t *command;      // +0x00
    const wchar_t *environment;  // +0x04
    wchar_t selector;            // +0x08
    wchar_t prefix;              // +0x0a
    int options;                 // +0x0c
    HMODULE module;              // +0x10
    FARPROC invoke;              // +0x14
    FARPROC abort;               // +0x18
    FARPROC cleanup;             // +0x1c
    wchar_t *profile;            // +0x20
};

// One intermediate-file suffix row. The public ?Il_suffix@@3QBUilsuffix_s@@B
// spells an externally visible const array: each 8-byte row is a wide suffix
// name plus an integer gate, and the cleanup loop stops at a null-suffix row.
// Names and gates below are the retail bytes 0x4127c0..0x412800.
struct ilsuffix_s
{
    const wchar_t *suffix;
    int enabled;
};

// Node behind context_s::items; the pass driver walks next and saves value at
// context_s::current while it processes each entry.
struct context_node
{
    context_node *next;
    void *value;
};

// Public ?Context@@3PAUcontext_s@@A points at the public ?CX@@3Ucontext_s@@A
// object (0x418900): the loader-initialized pointer word at 0x417030 holds
// 0x418900 and the next public data object after CX starts at 0x418928, which
// fixes the structure extent at 0x28. Slots and their consumers:
//   +0x00 flag list walked first by mark_defaults; cc_switches takes it as
//         the option list root.
//   +0x04 the second flag list (mark_defaults) and the list the unlink helper
//         at 0x4018d9 is applied to (its head address is Context+4).
//   +0x08 current passinfo_s row read by the pass driver.
//   +0x0c source_s list walked by addsource and required non-null by _wmain.
//   +0x10 intrusive {next,value} list the IL-file cleanup walks.
//   +0x14 unresolved dword slot: no consumer observed yet.
//   +0x18 unresolved dword slot: no consumer observed yet.
//   +0x1c value saved/restored around the +0x10 list walk.
//   +0x20 wide base name: get_ilfile result, consumed by wcslen/wcscat_s and
//         by compile.obj's replaca family.
//   +0x24 wide name passed as findpass' first argument and extended with
//         ".exe"/".dll" by acquire_pass and handlematch.
struct context_s
{
    flag_s *flags;         // +0x00
    flag_s *defaults;      // +0x04
    passinfo_s *pass;      // +0x08
    source_s *sources;     // +0x0c
    context_node *items;   // +0x10
    int field_14;          // +0x14 role unresolved
    int field_18;          // +0x18 role unresolved
    void *current;         // +0x1c saved value during the item walk
    wchar_t *base_name;    // +0x20
    wchar_t *tool_name;    // +0x24
};

extern context_s CX;
extern context_s *Context;
extern const ilsuffix_s Il_suffix[];
extern int EncDefaults[];
extern int DefaultsMarked;
extern passinfo_s Passinfo[];
extern wchar_t *CluiPath;
extern int Nologo;
extern int Preprocess;
extern int Verbose;
extern int Keepfiles;
extern int Cmd_Prefast;
extern unsigned long g_hCryptProv;
extern wchar_t *EncEventName;
extern int DllFlg;
extern int NoAssembly;
extern wchar_t *Exefilename;

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
flag_s* __cdecl appendflag(flag_s**, flag_s*);
int __cdecl flag_this_pass(flag_s*, passinfo_s*);
unsigned short __cdecl flag_these_pass_ids(flag_s*, const wchar_t*);
int __cdecl file_exists(const wchar_t*, wchar_t*, const wchar_t*);
void __cdecl activate_pass(flag_s*);
void __cdecl deactivate_passes_except(flag_s*);
void __cdecl deactivate_passes(flag_s*);
void __cdecl mark_defaults();
void __cdecl double_percent(wchar_t*, const wchar_t*, unsigned int);

#endif
