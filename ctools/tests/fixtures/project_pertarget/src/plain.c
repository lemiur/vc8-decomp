// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Fixture unit: names no target define as a whole token. */
// flags: /GS- /Oy
// data: 0x00430000 0x00530000
int ALPHABET_SIZE = 26;

// match: 0x00401100 0x00501100
// stop: synthetic schedule residue
int plain_value(void) { return ALPHABET_SIZE; }

// match: 0x00401120 0x00501130
// pending: R4 a synthetic fixed-offset access
int plain_twice(int x)
{
    return 2 * x;
}
