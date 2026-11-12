// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore str: declarations shared by str.c, str_unicode.c and str_parse.c (not part of the public API). */
#pragma once
#include "dk/str.h"

/* Whether cp lies in one of the {first, last} pairs of the sorted range list r (npairs pairs). */
bool dk__in_ranges(const u32 *r, size_t npairs, u32 cp);
/* The value 0..9 of a Unicode decimal digit (category Nd, which int() and float() accept), else -1. */
int dk__cp_decimal(u32 cp);
/* The code point that ends just before p (p > begin) and where it starts; invalid bytes count one each. */
u32 dk__u8_prev(const char *begin, const char **p);
