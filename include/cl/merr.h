#ifndef VC8_CL_MERR_H
#define VC8_CL_MERR_H

/* Canonical CRT type and declaration from the installed VC8 include/math.h,
 * lines 39-46 and 147-149. SHA-256:
 * 3cdf840fdb5db5a4c98fb849b6247f0f74dbd3071620ab218634d2c9ab58b791.
 * include/crtdefs.h:644-649 defines __CRTDECL as __cdecl for native x86.
 * The installed crt/src/crtassem.h identifies this source tree as 8.0.50727.762.
 */
struct _exception {
    int type;
    char *name;
    double arg1;
    double arg2;
    double retval;
};

int __cdecl _matherr(struct _exception *pexcept);

#endif
