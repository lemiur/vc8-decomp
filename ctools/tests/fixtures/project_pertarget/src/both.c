// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Fixture unit: compiled once per target. */
// flags: /O1
#if ALPHA
// match: 0x00401000 0
int both_value(void) { return 1; }
#else
// match: 0 0x00501000
int both_value(void) { return 2; }
#endif
