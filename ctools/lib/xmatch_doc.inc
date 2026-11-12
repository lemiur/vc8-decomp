// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
    "Find a function of one 32-bit executable in another by masked bytes.\n"
    "\n"
    "The function at <va> of imageA is read (its size from --size, else up to the next probable function start),\n"
    "its base-relocated words and out-of-function relative branch targets are masked, and imageB is searched for\n"
    "the remaining bytes. Exact hits are listed first; when there is none, the --top K candidates of imageB\n"
    "(probable function starts) closest by instruction-token similarity are listed.\n"
    "\n"
    "    xmatch.exe imageA.dll 0x1000a2c0 imageB.dll\n"
    "    xmatch.exe imageA.exe 0x00401000 --size 0x80 imageB.exe --top 10\n"
    ""
