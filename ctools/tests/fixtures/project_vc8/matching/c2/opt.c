// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Fixture unit: discovered only, no unit map names it; annotations of two targets. */
// FUNCTION: c2 0x10001000
int opt_pass(int x) { return x + 1; }

// FUNCTION: c1 0x10002000
int opt_fold(int x) { return x - 1; }

// DATA: c2 0x10030000
int opt_level = 2;
