// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* float_order.exe: float expression orders against the reference (lib/float_order.h). float_order.exe <unit> <Name> [--target T] [--address 0x..] [--minutes 5] [--workers N] [--line N] [--max-site 400] [--quiet] [--full-unit] [--tree-only]; float_order.exe --batch [--select REGEX] [--units a,b] [--wall body] [--minutes 3] [--jobs N] [--workers 3] [--limit N]; float_order.exe --selftest. */
#include "float_order.h"

static int run(int argc, char **argv) { return float_order_main(argc, argv); }

DK_MAIN(run, "float_order")
