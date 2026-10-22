#include "../../include/cl/crt_secchk.h"

/* CRT lineage: installed VC8 SP1 crt/src/intel/secchk.c, SHA-256
 * c899827141eb425e80dbce7d9afa49f000f46ae99eb5543d5a940a505fab0b59,
 * 8.0.50727.762 (crt/src/crtassem.h). PDB public @__security_check_cookie@4
 * and its DBI contribution name build/intel/dll_obj/secchk.obj, module 47.
 * The function has no locals and no line-sensitive operation.
 */

// FUNCTION: cl 0x40bba8
// SYMBOL: @__security_check_cookie@4
void __declspec(naked) __fastcall __security_check_cookie(UINT_PTR cookie)
{
    // RULE-EXCEPTION: R18, the installed-era secchk.c body is a naked __asm
    // helper the original had. Retail is exactly cmp ecx,[___security_cookie]
    // (3b 0d), jne +2 (75 02), rep ret (f3 c3), jmp ___report_gsfailure (e9
    // rel32): 15 bytes. VC8 x86 C cannot emit f3 c3 (rep ret) nor place the
    // ret between the inverted branch and the noreturn tail jmp, so the era
    // body is the only attributable source.
    /* x86 version written in asm to preserve all regs */
    __asm {
        cmp ecx, __security_cookie
        jne failure
        rep ret /* REP to avoid AMD branch prediction penalty */
failure:
        jmp __report_gsfailure
    }
}
