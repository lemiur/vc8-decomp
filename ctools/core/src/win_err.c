// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Win32 error text and the winerror -> errno table of CPython (PC/errmap.h). */
#include "fs_priv.h"

#include <stdio.h>

typedef struct {
    unsigned winerror;
    int err;
} ErrPair;

/* Generated from CPython 3.14: for w in range(2000): OSError(0, "x", None, w).errno, entries that are not EINVAL,
 * plus the WSA codes that map to a CRT errno (OSError(0, "x", None, w).errno for 10004, 10009, 10013, 10014, 10024). */
static const ErrPair k_errmap[] = {
    {2,2},{3,2},{4,24},{5,13},{6,9},{7,12},{8,12},{9,12},{10,7},{11,8},{15,2},{16,13},{17,18},{18,2},{19,13},
    {20,13},{21,13},{22,13},{23,13},{24,13},{25,13},{26,13},{27,13},{28,13},{29,13},{30,13},{31,13},{32,13},
    {33,13},{34,13},{35,13},{36,13},{53,2},{65,13},{67,2},{80,17},{82,13},{83,13},{89,11},{108,13},{109,32},
    {112,28},{114,9},{128,10},{129,10},{130,9},{132,13},{145,41},{158,13},{161,2},{164,11},{167,13},{183,17},
    {188,8},{189,8},{190,8},{191,8},{192,8},{193,8},{194,8},{195,8},{196,8},{197,8},{198,8},{199,8},{200,8},
    {201,8},{202,8},{206,2},{215,11},{232,32},{258,138},{267,20},{1113,42},{1816,12},{10004,4},{10009,9},
    {10013,13},{10014,14},{10024,24},
};

int dk_winerror_to_errno(unsigned w) {
    size_t lo = 0, hi = DK_ARRAY_LEN(k_errmap);
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (k_errmap[mid].winerror < w) lo = mid + 1;
        else hi = mid;
    }
    if (lo < DK_ARRAY_LEN(k_errmap) && k_errmap[lo].winerror == w) return k_errmap[lo].err;
    if (w >= 10000 && w < 11000) return (int)w; /* the other WSA errors are their own errno */
    return EINVAL;
}

DkStr dk_win_error_message(DkArena *a, unsigned code) {
    wchar_t *msg = NULL;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&msg, 0, NULL);
    if (n == 0 || !msg) {
        char t[48];
        int k = snprintf(t, sizeof t, "Windows Error 0x%x", code);
        return fs_dup(a, t, (size_t)k);
    }
    /* CPython strips the trailing blanks, line ends and dots. */
    while (n > 0 && (msg[n - 1] <= L' ' || msg[n - 1] == L'.')) n--;
    char *u = dk_fs_w_to_u8(a, msg, (i64)n);
    LocalFree(msg);
    DkStr s = {u, strlen(u)};
    return s;
}

DkStr dk_win_error_str(DkArena *a, unsigned winerror) {
    FsBuf b;
    fsb_init(&b, a);
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    DkStr m = dk_win_error_message(sc, winerror);
    fsb_printf(&b, "[WinError %u] ", winerror);
    fsb_put(&b, m.p, m.n);
    fs_tmp_done(sc, mk);
    return fsb_str(&b);
}
