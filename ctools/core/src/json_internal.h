// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Private to json.c, json_read.c and json_write.c. */
#pragma once
#include "dk/json.h"

/* The member index of an object: an open-addressing table of member numbers + 1 (0 is empty). */
u32 dk_json__hash(DkStr key);
void dk_json__index_put(u32 *tab, u32 cap, u32 hash, u32 member_number);
/* Looks key up in members[base .. base + n) through tab (cap slots); tab may be NULL for a linear scan.
 * Returns the member number (relative to base) or -1. */
i64 dk_json__find(const DkJsonMember *members, size_t n, const u32 *tab, u32 cap, DkStr key);
/* The number of members above which an object gets an index. */
#define DK_JSON_LINEAR_MAX 8
u32 dk_json__index_cap_for(size_t n);

/* digits of an int ("-?digits"): true and the value when it fits an i64 */
bool dk_json__int_fits(DkStr digits, i64 *out);

extern const DkJson dk_json__null_node, dk_json__true_node, dk_json__false_node;

/* UTF-8 encoding of a code point, including lone surrogates (generalized UTF-8). */
size_t dk_json__put_cp(char out[4], u32 cp);
