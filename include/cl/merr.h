#ifndef VC8_CL_MERR_H
#define VC8_CL_MERR_H

/* Canonical CRT type and declaration belong to the installed VC8 math.h.
 * include/math.h SHA-256:
 * 3cdf840fdb5db5a4c98fb849b6247f0f74dbd3071620ab218634d2c9ab58b791.
 * crt/src/cruntime.h SHA-256:
 * d1245829d64198109953651ca787743bdca7c0b1ad43397f5615966b08c0ff1c.
 * Original merr.c includes cruntime.h through internal.h; this partial unit
 * needs only the CRT build context and math declarations. Build with _CRTBLD.
 * The installed crt/src/crtassem.h identifies this source tree as 8.0.50727.762.
 */
#include <cruntime.h>
#include <math.h>

#endif
