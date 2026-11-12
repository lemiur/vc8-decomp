// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* base64.b64encode (standard alphabet, '=' padding, no line breaks), added in W5 for the MCP image content. */
#include "dk/str.h"

DkStr dk_base64_encode(DkArena *a, const void *data, size_t n) {
    static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const u8 *p = data;
    size_t outn = (n + 2) / 3 * 4;
    char *o = dk_alloc_noz(a, outn + 1);
    size_t k = 0, i = 0;
    for (; i + 2 < n; i += 3) {
        u32 v = (u32)p[i] << 16 | (u32)p[i + 1] << 8 | p[i + 2];
        o[k++] = tab[v >> 18];
        o[k++] = tab[v >> 12 & 63];
        o[k++] = tab[v >> 6 & 63];
        o[k++] = tab[v & 63];
    }
    if (n - i == 1) {
        u32 v = (u32)p[i] << 16;
        o[k++] = tab[v >> 18];
        o[k++] = tab[v >> 12 & 63];
        o[k++] = '=';
        o[k++] = '=';
    } else if (n - i == 2) {
        u32 v = (u32)p[i] << 16 | (u32)p[i + 1] << 8;
        o[k++] = tab[v >> 18];
        o[k++] = tab[v >> 12 & 63];
        o[k++] = tab[v >> 6 & 63];
        o[k++] = '=';
    }
    o[k] = 0;
    return (DkStr){o, k};
}
