/*
 * Reconstruction of the installed-era CRT ehvecdtr.cpp (retail module 28). The
 * installed source tree does not ship this file and the CRT build consumes a
 * prebuilt ehvecdtr.obj (crt/src/makefile.inc copies it from PREOBJDIR), so the
 * body below is decoded from retail and checked byte for byte against
 * 0x0040c38a..0x0040c3e7:
 *
 *   push 14h ; push <sehtable> ; call __SEH_prolog4 ; and [ebp-4],0
 *   loop: dec [ebp+10h] ; js done        (--count >= 0, signed)
 *         ecx = [ebp+08h]-[ebp+0Ch] ; [ebp+08h]=ecx ; call [ebp+14h] ; jmp loop
 *   filter: eax=[ebp-14h] ; [ebp-1Ch]=eax ; eax=[eax] ; [ebp-20h]=eax (pExcept)
 *           cmp [eax],0E06D7363h ; je terminate ; return EXCEPTION_CONTINUE_SEARCH
 *   done: mov [ebp-4],0FFFFFFFEh ; call __SEH_epilog4 ; ret 10h
 *
 * The static filter is inlined into the except expression by /O1, which is why
 * its locals live in this frame; the object's separate 18-byte copy is dead in
 * the retail link. The destructor is called through ECX (this) with no stack
 * argument, which is why the callback type is __thiscall.
 */

#include <windows.h>
#include "../../include/cl/crt_ehvecdtr.h"

static int __cdecl ArrayUnwindFilter(EXCEPTION_POINTERS *pExPtrs)
{
    EXCEPTION_RECORD *pExcept = pExPtrs->ExceptionRecord;

    switch (pExcept->ExceptionCode)
    {
        case EH_EXCEPTION_NUMBER:
            terminate();
        default:
            return EXCEPTION_CONTINUE_SEARCH;
    }
}

// FUNCTION: cl 0x40c38a
// SYMBOL: ?__ArrayUnwind@@YGXPAXIHP6EX0@Z@Z
void __stdcall __ArrayUnwind(void *ptr, unsigned size, int count, PFUNC pfunc)
{
    __try
    {
        while (--count >= 0)
        {
            ptr = (char *)ptr - size;
            pfunc(ptr);
        }
    }
    __except (ArrayUnwindFilter(GetExceptionInformation()))
    {
    }
}

/*
 * WALL: ??_M@YGXPAXIHP6EX0@Z@Z (0x0040c3e8, 99 bytes) is the compiler's internal
 * `eh vector destructor iterator'. Its source-level spelling is not expressible
 * with this toolchain: a backtick-quoted identifier is rejected (C2018), and no
 * documented compiler flag exposes a way to define the special name, so the
 * object cannot be recreated from honest source here. The decoded body is
 * `bool success = false; ptr += size*count; __try { while (count-- > 0)
 * { ptr -= size; pfunc(ptr); } success = true; } __finally { if (!success)
 * __ArrayUnwind(ptr, size, count, pfunc); }`, and the installed era
 * libcmt.lib member build of the same object is byte-identical to retail outside
 * relocation operands. Recorded as unregistered open work.
 */
