/*
 * Reconstruction of the installed-era CRT intel/fp8.c. Provenance is recorded
 * in include/cl/crt_fp8.h (file SHA-256 and file time). The retail body
 * 0x0040c638..0x0040c660 is 41 bytes and decodes to exactly this source:
 *   _controlfp_s(NULL, _PC_53, _MCW_PC) is called as
 *   push _PC_53 (0x30000); push _MCW_PC (0x10000); push NULL,
 *   and _ERRCHECK expands to the inline _invoke_watson_if_error, producing the
 *   five NULL pushes and the second call. No assert or __LINE__ use occurs.
 */

#include <stddef.h>
#include <float.h>
#include <internal.h>

#include "../../include/cl/crt_fp8.h"

/*
 * Routine to set default FP precision to 53 bits.
 */

#ifdef __cplusplus
extern "C"
#endif  /* __cplusplus */
// FUNCTION: cl 0x40c638
// SYMBOL: __setdefaultprecision
void __CLRCALL_OR_CDECL _setdefaultprecision()
{
        _ERRCHECK(_controlfp_s(NULL, _PC_53, _MCW_PC));
}
