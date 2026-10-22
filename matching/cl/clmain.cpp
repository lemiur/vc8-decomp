#include "../../include/cl/clmain.h"
#include "../../include/cl/util_watson.h"

#include <stdlib.h>
#include <windows.h>
#include <wchar.h>
#include <io.h>
#include <errno.h>
#include <stdio.h>
#include <share.h>

// Source filename inferred from the PDB object owner clmain.obj; the original
// extension and assert line mappings remain unresolved. Public names and stack
// cleanup prove these cdecl callbacks; their flag_s argument is unused.

// FUNCTION: cl 0x00401501
// SYMBOL: ?OpenClSqmLogFileForWriting@@YAPAU_iobuf@@PBG@Z
FILE* __cdecl OpenClSqmLogFileForWriting(const wchar_t* path)
{
    unsigned long header[4];
    FILE* file;
    unsigned long length;

    file = _wfsopen(path, L"a+b", _SH_DENYRW);
    if (!file)
        return 0;
    length = _filelength(_fileno(file));
    if (length > 0x200000) {
        fclose(file);
        return 0;
    }
    if (length == 0) {
        header[0] = 0x51534356;
        header[1] = 1;
        header[2] = header[3] = 0;
        if (fwrite(header, sizeof(header), 1, file) != 1) {
            fclose(file);
            return 0;
        }
    } else {
        if (fread(header, sizeof(header), 1, file) != 1 ||
            header[0] != 0x51534356 || header[1] != 1) {
            fclose(file);
            return 0;
        }
        if (fseek(file, 0, SEEK_END) != 0) {
            fclose(file);
            return 0;
        }
    }
    return file;
}

// FUNCTION: cl 0x004015a8
// SYMBOL: ?error_report_prompt@@YAXPAUflag_s@@@Z
void __cdecl error_report_prompt(flag_s*)
{
    ErrorReportingSetMode(ErrorReportingMode_Prompt);
}

// FUNCTION: cl 0x004015b1
// SYMBOL: ?error_report_queue@@YAXPAUflag_s@@@Z
void __cdecl error_report_queue(flag_s*)
{
    ErrorReportingSetMode(ErrorReportingMode_Queue);
}

// FUNCTION: cl 0x004015ba
// SYMBOL: ?error_report_send@@YAXPAUflag_s@@@Z
void __cdecl error_report_send(flag_s*)
{
    ErrorReportingSetMode(ErrorReportingMode_Send);
}

// FUNCTION: cl 0x004015c3
// SYMBOL: ?error_report_none@@YAXPAUflag_s@@@Z
void __cdecl error_report_none(flag_s*)
{
    ErrorReportingSetMode(ErrorReportingMode_None);
}

// FUNCTION: cl 0x00401886
// SYMBOL: ?appendflag@@YAPAUflag_s@@PAPAU1@PAU1@@Z
flag_s* __cdecl appendflag(flag_s** list, flag_s* flag)
{
    flag_s* node;

    for (node = *list; node; node = node->next)
        list = &node->next;
    *list = flag;
    return flag;
}

// FUNCTION: cl 0x0040189c
// SYMBOL: ?flag_this_pass@@YAHPAUflag_s@@PAUpassinfo_s@@@Z
int __cdecl flag_this_pass(flag_s* flag, passinfo_s* pass)
{
    return wcschr(flag->passes, pass->selector) != 0;
}

// FUNCTION: cl 0x004018bc
// SYMBOL: ?flag_these_pass_ids@@YAGPAUflag_s@@PBG@Z
unsigned short __cdecl flag_these_pass_ids(flag_s* flag, const wchar_t* ids)
{
    const wchar_t* found = wcspbrk(flag->passes, ids);
    if (!found)
        return 0;
    return *found;
}

// DATA: cl 0x00418900
// Public ?CX@@3Ucontext_s@@A; the next public data object starts at 0x418928,
// fixing the recorded 40-byte extent. All 40 bytes read zero in the image.
context_s CX;

// DATA: cl 0x00417030
// Public ?Context@@3PAUcontext_s@@A; file initializer is the CX address, so the
// pointer is a statically initialized alias of the public context object.
context_s* Context = &CX;

// DATA: cl 0x004127c0
// Public ?Il_suffix@@3QBUilsuffix_s@@B const array; eight 8-byte rows read from
// .rdata, the last one the null-suffix terminator the cleanup loop tests.
const ilsuffix_s Il_suffix[] = {
    { L"ex", 1 },
    { L"sy", 1 },
    { L"gl", 1 },
    { L"in", 1 },
    { L"db", 1 },
    { L"md", 1 },
    { L"lk", 0 },
    { 0, 0 }
};

// DATA: cl 0x00417034
// Public ?RedirStderr@@3HA; four file-backed bytes initialize the int to one.
int RedirStderr = 1;

// FUNCTION: cl 0x0040218a
// SYMBOL: ?IsRunningUnderIDE@@YAHXZ
int __cdecl IsRunningUnderIDE()
{
    return GetEnvironmentVariableW(L"VS_UNICODE_OUTPUT", 0, 0) != 0;
}

// FUNCTION: cl 0x00402267
// SYMBOL: ?file_exists@@YAHPBGPAG0@Z
int __cdecl file_exists(const wchar_t* path, wchar_t* destination, const wchar_t* replacement)
{
    destination[0] = replacement[0];
    destination[1] = replacement[1];
    errno_t status = _waccess_s(path, 0);
    return status == 0 || status == EACCES;
}

// FUNCTION: cl 0x0040229b
// SYMBOL: ?mark_defaults@@YAXXZ
void __cdecl mark_defaults()
{
    flag_s* flag;
    int* defaults;

    for (flag = Context->flags; flag; flag = flag->next)
        flag->flags |= 0x80;
    defaults = EncDefaults;
    for (flag = Context->defaults; flag; flag = flag->next, ++defaults) {
        flag->flags |= 0x80;
        if (*defaults)
            flag->flags |= 0x20;
    }
    DefaultsMarked = 1;
}

// FUNCTION: cl 0x004024a8
// SYMBOL: ?fullccpath@@YAPAGXZ
wchar_t* __cdecl fullccpath()
{
    wchar_t* path = 0;
    _get_wpgmptr(&path);
    return path;
}

// FUNCTION: cl 0x00402549
// SYMBOL: ?activate_pass@@YAXPAUflag_s@@@Z
void __cdecl activate_pass(flag_s* flag)
{
    wchar_t selector = flag->value[0];

    for (int i = 0; i < 10; ++i) {
        passinfo_s* pass = &Passinfo[i];
        if (selector == L'.' || pass->selector == selector)
            pass->options |= 1;
    }
}

// FUNCTION: cl 0x00402572
// SYMBOL: ?deactivate_passes_except@@YAXPAUflag_s@@@Z
void __cdecl deactivate_passes_except(flag_s* flag)
{
    for (int i = 0; i < 10; ++i) {
        if (!wcschr(flag->value, Passinfo[i].selector))
            Passinfo[i].options &= ~1;
    }
}

// FUNCTION: cl 0x004025a1
// SYMBOL: ?deactivate_passes@@YAXPAUflag_s@@@Z
void __cdecl deactivate_passes(flag_s* flag)
{
    int all = flag->value[0] == L'.';

    for (int i = 0; i < 10; ++i) {
        if (all || wcschr(flag->value, Passinfo[i].selector))
            Passinfo[i].options &= ~1;
    }
}

// FUNCTION: cl 0x00402915
// SYMBOL: ?double_percent@@YAXPAGPBGI@Z
void __cdecl double_percent(wchar_t* destination, const wchar_t* source, unsigned int count)
{
    for (unsigned int i = 0; i < count; ++i) {
        *destination++ = *source;
        if (*source++ == L'%') {
            *destination++ = L'%';
            ++i;
        }
    }
}

// DATA: cl 0x004178b8
// Public ?EncDefaults@@3PAHA; the 100-byte slot up to the next public data
// object (0x41791c) holds 25 ints, mostly zero with two one-valued entries.
int EncDefaults[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

// DATA: cl 0x00419650
// Public ?CluiPath@@3PAGA; storage lies in .data's zero-filled virtual tail
// (past the 0x2000 file-backed bytes), so the initial value is loader zero.
wchar_t* CluiPath;

// DATA: cl 0x00419178
// Public ?Nologo@@3HA; loader-zero storage in .data's virtual tail.
int Nologo;

// DATA: cl 0x0041917c
// Public ?EncEventName@@3PAGA; loader-zero pointer storage in the same tail.
wchar_t* EncEventName;

// DATA: cl 0x00419184
// Public ?Keepfiles@@3HA; loader-zero storage in .data's virtual tail.
int Keepfiles;

// DATA: cl 0x0041918c
// Public ?Preprocess@@3HA; loader-zero storage in .data's virtual tail.
int Preprocess;

// DATA: cl 0x004191a0
// Public ?Cmd_Prefast@@3HA; loader-zero storage in .data's virtual tail.
int Cmd_Prefast;

// DATA: cl 0x00419e54
// Public ?Verbose@@3HA; loader-zero storage in .data's virtual tail.
int Verbose;

// DATA: cl 0x00419e80
// Public ?g_hCryptProv@@3KA proven unsigned long storage; loader-zero tail.
unsigned long g_hCryptProv;

// DATA: cl 0x0041913c
// Public ?DllFlg@@3HA; clmain.obj int in .data past the 0x2000 file-backed
// bytes, so the initial value is loader zero. Read/written by the DLL option
// path and by compile.obj's module_extension.
int DllFlg;

// DATA: cl 0x00419648
// Public ?NoAssembly@@3HA; clmain.obj int in the same zero-filled .data tail.
int NoAssembly;

// DATA: cl 0x00419164
// Public ?Exefilename@@3PAGA; clmain.obj pointer in .data past the 0x2000
// file-backed bytes, so the initial value is loader zero. The /Fe option-table
// row (row 1, tag 3, target 0x419164) stores the output name through the
// dispatcher, and compile.obj's replaca/dopass/post_compile push the pointer.
wchar_t* Exefilename;

// DATA: cl 0x00419e6c
// Public ?DefaultsMarked@@3HA; loader-zeroed one-shot state word.
int DefaultsMarked;

// DATA: cl 0x00417950
// Public ?Passinfo@@3PAUpassinfo_s@@A; ten zero-initialized pass rows.
// Row initializers (names, selectors, options) are still unresolved data work.
passinfo_s Passinfo[10];

// DATA: cl 0x00419640
// Public ?pPCHBaseAddress@@3PAXA proves void* storage; clmain.obj owns it.
// Retail places this zero-initialized pointer in the .data virtual tail.
void* pPCHBaseAddress;

// DATA: cl 0x004188ec
// Public ?pPCHAstExtraBaseAddress@@3PAXA; clmain.obj owns the zero-valued pointer.
void* pPCHAstExtraBaseAddress;

// FUNCTION: cl 0x00402c06
// SYMBOL: ?release_filelife_heap@@YAXXZ
void __cdecl release_filelife_heap()
{
    VirtualFree(pPCHBaseAddress, 0, MEM_RELEASE);
}

// FUNCTION: cl 0x00402c1a
// SYMBOL: ?release_ast_extra_heap@@YAXXZ
void __cdecl release_ast_extra_heap()
{
    VirtualFree(pPCHAstExtraBaseAddress, 0, MEM_RELEASE);
}

// FUNCTION: cl 0x004014d5
// SYMBOL: ??0CConsoleLock@@QAE@XZ
CConsoleLock::CConsoleLock()
{
    if (g_hMutex)
    {
        DWORD result = WaitForSingleObject(g_hMutex, INFINITE);
        if (result == WAIT_OBJECT_0 || result == WAIT_ABANDONED)
        {
            locked = true;
            return;
        }
    }
    locked = false;
}
