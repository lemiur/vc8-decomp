// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Fixture unit: a discovered unit listed in a target unit map. Target+addr annotations of the cl target. */
// FUNCTION: cl 0x00401000
int util_leaf(void) { return 1; }

// FUNCTION: cl 0x00401040
// SYMBOL: ?util_twice@@YAHH@Z
// stop: synthetic register residue
int util_twice(int x)
{
    return x * 2;
}

// FUNCTION: cl 0x00401080
int util_sum(const int *v, int n)
{
    int total = 0;
    for (int i = 0; i < n; i++)
        total += v[i];
    return total;
}

// DATA: cl 0x00430010
int util_table[4] = {1, 2, 3, 4};
