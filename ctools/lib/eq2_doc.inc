// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
    "Symbolic equivalence check of a compiled function (ours) against the reference image's bytes: both are executed\n"
    "in lockstep on symbolic inputs (registers, arguments, memory), and their events (conditional branches with their\n"
    "conditions, calls with their callee, `this` and arguments, the stores before each call and at the return, switches,\n"
    "returns and the returned value) are compared path by path.\n"
    "\n"
    "    eq2.exe <unit> <Function>[,<Function>...|ALL] [--target T] [-v] [--root DIR] [--config FILE]\n"
    "\n"
    "<unit>: a unit of the project (repository-relative path or unique stem); ALL: every function of the unit that\n"
    "carries a stop mark. Without --target each function is checked in the first target that has a copy of it.\n"
    "Prints `<Function> <target>: EQUIVALENT` or `DIFFERENT` with one line per difference. The exit code is 0 when\n"
    "every function is EQUIVALENT, 1 when one is DIFFERENT or cannot be built, 2 for a usage or configuration error.\n"
