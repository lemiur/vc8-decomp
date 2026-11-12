// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* rich_header <file> [...]: prints the Rich header of PE files, which Microsoft tools (compiler, linker, assembler...)
 * built how many objects of the image, by their product id and build number. Product ids (the high word of each
 * entry) are those of the Visual Studio 2005 to 2010 tools. The tool has no option parsing: every argument is a
 * path; a path that cannot be read or a malformed header is an internal error. A test defines
 * DK_RICH_HEADER_AS_LIBRARY and includes this file to call rich_header_describe on an in-memory image. */
#include "dk/dk.h"

#include <string.h>

static const struct {
    u32 id;
    const char *name;
} PRODUCTS[] = {
    {0x0001, "Import0 (imports without a tool)"},
    {0x0002, "Linker510"},
    {0x0004, "Cvtomf510"},
    {0x005D, "Utc1310_C (VS2003 C)"},
    {0x005E, "Utc1310_CPP (VS2003 C++)"},
    {0x006D, "Utc1400_C (VS2005 C)"},
    {0x006E, "Utc1400_CPP (VS2005 C++)"},
    {0x006F, "Utc1400_C_Std"},
    {0x0070, "Utc1400_CPP_Std"},
    {0x0071, "Utc1400_CVTCIL_C"},
    {0x0072, "Utc1400_CVTCIL_CPP"},
    {0x0078, "Linker800 (VS2005)"},
    {0x0079, "Cvtomf800"},
    {0x007A, "Export800"},
    {0x007B, "Implib800"},
    {0x007C, "Cvtres800"},
    {0x007D, "Masm800"},
    {0x0083, "Utc1500_C (VS2008 C)"},
    {0x0084, "Utc1500_CPP (VS2008 C++)"},
    {0x0091, "Linker900 (VS2008)"},
    {0x0093, "Export900"},
    {0x0094, "Implib900"},
    {0x0095, "Masm900"},
    {0x009A, "Cvtres900"},
    {0x009D, "Linker1000 (VS2010)"},
    {0x00AA, "Utc1600_C (VS2010 C)"},
    {0x00AB, "Utc1600_CPP (VS2010 C++)"},
    {0x0103, "Linker800? (alt)"},
};

static const char *product_name(u32 id) {
    for (size_t i = 0; i < DK_ARRAY_LEN(PRODUCTS); i++)
        if (PRODUCTS[i].id == id) return PRODUCTS[i].name;
    return "?";
}

/* A read past the end of the image is an internal error. */
static u32 u32_at(DkBytes data, size_t at) {
    if (at > data.n || data.n - at < 4)
        dk_panic(__FILE__, __LINE__, "image too short: a 4-byte read at %zu is past the end", at);
    u32 v;
    memcpy(&v, data.v + at, 4);
    return v;
}

/* Appends the listing of one image to out. The "Rich" marker is searched in [0x80, 0x400); the "DanS" start marker
 * is found by walking back from it in 4-byte steps, both xored with the key that follows "Rich". */
static void rich_header_describe(DkBuf *out, const char *path, DkBytes data) {
    i64 end = -1;
    for (size_t at = 0x80; at + 4 <= 0x400 && at + 4 <= data.n; at++)
        if (memcmp(data.v + at, "Rich", 4) == 0) {
            end = (i64)at;
            break;
        }
    if (end < 0) {
        dk_buf_pyfmt(out, "== %s\n", path);
        dk_buf_pyfmt(out, "   no Rich header\n");
        return;
    }
    u32 key = u32_at(data, (size_t)end + 4);
    i64 start = -1;
    for (i64 at = end - 4; at > 0x40; at -= 4)
        if ((u32_at(data, (size_t)at) ^ key) == 0x536E6144u) {
            start = at;
            break;
        }
    if (start < 0) dk_panic(__FILE__, __LINE__, "Rich header has no DanS start marker");
    DkU64Vec entries = {0}; /* the whole list is decoded before printing: an error prints nothing */
    for (i64 at = start + 16; at < end; at += 8) {
        u32 compid = u32_at(data, (size_t)at) ^ key;
        u32 count = u32_at(data, (size_t)at + 4) ^ key;
        dk_vec_push(&entries, ((u64)compid << 32) | count);
    }
    dk_buf_pyfmt(out, "== %s\n", path);
    for (size_t k = 0; k < entries.n; k++) {
        u32 compid = (u32)(entries.v[k] >> 32), count = (u32)entries.v[k];
        u32 product = compid >> 16, build = compid & 0xFFFF;
        dk_buf_pyfmt(out, "   product %04X build %5d  x%-5d %s\n", product, build, count, product_name(product));
    }
    dk_vec_free(&entries);
}

#ifndef DK_RICH_HEADER_AS_LIBRARY
static int run(int argc, char **argv) {
    DkArena *a = dk_arena();
    for (int i = 1; i < argc; i++) {
        DkBytes data = {0};
        if (!dk_read_all(a, argv[i], &data)) dk_panic(__FILE__, __LINE__, "%.*s", DK_SF(dk_io_err_str(a)));
        DkBuf out;
        dk_buf_init(&out, a);
        rich_header_describe(&out, argv[i], data);
        fwrite(out.p, 1, out.n, stdout);
    }
    return 0;
}

DK_MAIN(run, "rich_header")
#endif
