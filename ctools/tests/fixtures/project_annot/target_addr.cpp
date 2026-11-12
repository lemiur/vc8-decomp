// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
#include <stdlib.h>

// FUNCTION: tgt 0x408276
// SYMBOL: ?nextbase@@YAHH@Z
int __cdecl nextbase(int base)
{
    if (base == 1)
        return 2;
    return base;
}

// FUNCTION: tgt 0x4082dc
// stop: complete candidate; the compare codegen differs.
static const char *__cdecl skip_braces(const char *text)
{
    /* a } in a block comment */
    const char *open = "{{}";  // and a { in a line comment
    char close = '}';
    while (*text && *text != close && *text != open[0])
        ++text;
    return text;
}

// DATA: tgt 0x00418900
// Public data object; the next one starts 40 bytes later.
// All of its bytes read zero.
int Counter;

// DATA: tgt 0x00417030
// A constant table of rows.
const int Table[] = {
    1, 2,
    3, 4,
};

// FUNCTION: other 0x408010
int __stdcall Sum2(int left, int right)
{
    return left + right;
}
