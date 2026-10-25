"""Synthetic /LTCG probes of c2's link-time inlining and custom-convention decisions.

Usage:
  python tools/ltcg_probes.py [P1 P5 P1a ...] --out build/probes/ltcg_conv [--no-trace] [--list]

Each probe variant is a handful of tiny objects written from the sources below into
<out>/<probe>/<variant>/, compiled with the matching project's options (/O2 /Oy /arch:SSE2 /fp:fast /GS
/EHsc /GR- /MD /Gy /W3, plus /GL unless the variant says otherwise), linked as the matching project links
an LTCG group (/DLL /NOENTRY /LTCG /OPT:REF,ICF /NODEFAULTLIB /MACHINE:X86 /MAP, one /INCLUDE'd root
driver; unresolved runtime names are pointed at a stub with /ALTERNATENAME), then linked again under
tools/c2_inline_trace.py (--link-rsp, own /OUT and /MAP). <variant>.summary.txt gets, for each studied
callee: its traced call sites (caller, depth, decision, rule), its conventions record (custom yes|no and the
refusal, declared convention, parameter locations, the raw entry+0x20 / entry+0x50 words MdmAllowFlexParams
read), and from the linked image: whether it survived, its first instructions, whether its frame has
`and esp,-8`, and the call sites to it. --no-trace links and disassembles only (seconds per variant).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import probe_toolchain  # noqa: E402

BASE_FLAGS = "/O2 /Oy /arch:SSE2 /fp:fast /GS /EHsc /GR- /MD /Gy /W3 /nologo /c"
LINK_FLAGS = "/nologo /DLL /NOENTRY /LTCG /OPT:REF,ICF /NODEFAULTLIB /MACHINE:X86"
STUB_SOURCE = 'extern "C" void ltcg_probe_stub(void) {}\nextern "C" int ltcg_probe_stub_data = 0;\n'

# ---------------------------------------------------------------- sources

REG_H = """#ifndef REG_H
#define REG_H
struct RegNode {
    int id;
    int flags;
    RegNode* next;
};
struct Registry {
    RegNode* head;
    int misses;
    int Find(int id, int mode);
};
extern Registry g_regA;
extern Registry g_regB;
extern Registry g_regC;
#endif
"""

REG_CPP = """#include "reg.h"
Registry g_regA;
Registry g_regB;
Registry g_regC;
__declspec(noinline) int Registry::Find(int id, int mode)
{
    for (RegNode* n = head; n != 0; n = n->next) {
        if (n->id == id && (n->flags & mode) != 0) {
            return n->flags;
        }
    }
    misses++;
    return -1;
}
"""

WRAP_INLINE_DEFS = """inline int WrapA(int id) { return g_regA.Find(id, 1); }
inline int WrapB(int id) { return g_regB.Find(id, 1); }
inline int WrapC(int id) { return g_regC.Find(id, 1); }
"""

WRAP_H_INLINE = '#ifndef WRAP_H\n#define WRAP_H\n#include "reg.h"\n' + WRAP_INLINE_DEFS + "#endif\n"
WRAP_H_DECL = ('#ifndef WRAP_H\n#define WRAP_H\n#include "reg.h"\n'
               "int WrapA(int id);\nint WrapB(int id);\nint WrapC(int id);\n#endif\n")
WRAP_CPP = '#include "wrap.h"\n' + WRAP_INLINE_DEFS.replace("inline ", "")

STATE_H = """#ifndef STATE_H
#define STATE_H
struct State {
    int v[64];
};
extern State g_state;
#endif
"""


def update_body(blocks, name="Update"):
    """A large caller: BLOCKS blocks of arithmetic around one wrapper call each (A, B, C in turn)."""
    lines = ["int %s(int x)" % name, "{", "    State* s = &g_state;", "    int acc = x;"]
    for i in range(blocks):
        w = "ABC"[i % 3]
        lines += [
            "    if (s->v[%d] > acc) {" % (i % 64),
            "        acc += Wrap%s(s->v[%d] + %d) * %d;" % (w, (i * 7) % 64, i, i + 3),
            "        s->v[%d] ^= acc;" % ((i * 5) % 64),
            "    } else {",
            "        s->v[%d] -= acc >> %d;" % ((i * 3) % 64, i % 5 + 1),
            "    }",
        ]
    lines += ["    return acc;", "}", ""]
    return "\n".join(lines)


M1_CPP = '#include "wrap.h"\nint M1_Small(int x)\n{\n    return WrapA(x) + WrapB(x + 1);\n}\n'
M2_CPP = '#include "wrap.h"\nint M2_Small(int x)\n{\n    return WrapA(x * 2) - WrapC(x);\n}\n'
STATE_CPP = '#include "state.h"\nState g_state;\n'


def driver(calls, decls=None, extra=""):
    decls = decls if decls is not None else ["int %s(int x);" % c for c in calls]
    body = " + ".join("%s(x)" % c for c in calls) or "x"
    return "\n".join(decls) + "\n" + extra + 'extern "C" int Driver(int x)\n{\n    return %s;\n}\n' % body


def p1_files(update_blocks, modules):
    """P1: the wrappers as header inline functions, the header in MODULES (u, m1, m2)."""
    files = {"reg.h": REG_H, "reg.cpp": REG_CPP, "state.h": STATE_H, "state.cpp": STATE_CPP,
             "wrap.h": WRAP_H_INLINE,
             "u.cpp": '#include "wrap.h"\n#include "state.h"\n' + update_body(update_blocks)}
    calls = ["Update"]
    if "m1" in modules:
        files["m1.cpp"] = M1_CPP
        calls.append("M1_Small")
    if "m2" in modules:
        files["m2.cpp"] = M2_CPP
        calls.append("M2_Small")
    files["driver.cpp"] = driver(calls)
    return files


def p1_one_module(update_blocks):
    """P1c: the inline wrappers defined in one module only, every caller in it."""
    files = {"reg.h": REG_H, "reg.cpp": REG_CPP, "state.h": STATE_H, "state.cpp": STATE_CPP}
    files["u.cpp"] = ('#include "reg.h"\n#include "state.h"\n' + WRAP_INLINE_DEFS + update_body(update_blocks)
                      + M1_CPP.split("\n", 1)[1] + M2_CPP.split("\n", 1)[1])
    files["driver.cpp"] = driver(["Update", "M1_Small", "M2_Small"])
    return files


def p1_ordinary(update_blocks):
    """P1d: the wrappers ordinary (non-inline) functions of one module, callers in three others."""
    files = p1_files(update_blocks, ("m1", "m2"))
    files["wrap.h"] = WRAP_H_DECL
    files["wrap.cpp"] = WRAP_CPP
    return files


NATIVE_CPP = '#include "wrap.h"\nint Native_Call(int x)\n{\n    return WrapA(x + 7);\n}\n'

# P5: x87 float helpers
MATHX_H = """#ifndef MATHX_H
#define MATHX_H
float Math_Tan(float a);
float Math_TanF(float a);
float Math_Half(float a);
float Math_Cos(float a);
struct Body {
    float a;
    float b;
    float t;
    float h;
    float c;
};
extern Body g_body[32];
#endif
"""

MATHX_CPP = """#include <math.h>
#include "mathx.h"
Body g_body[32];
float Math_Tan(float a)
{
    return (float)tan((double)a);
}
float Math_TanF(float a)
{
    return tanf(a);
}
float Math_Half(float a)
{
    return a * 0.5f;
}
float Math_Cos(float a)
{
    return (float)cos((double)a);
}
"""


def k_module(k, count, cos_callers=0):
    lines = ['#include "mathx.h"']
    for i in range(count):
        j = (k * 8 + i) % 32
        lines += ["void K%d_F%d()" % (k, i), "{", "    Body* p = &g_body[%d];" % j,
                  "    p->t = Math_Tan(p->a * p->b + %d.25f);" % i,
                  "    p->h = Math_Half(p->a - p->b);"]
        if i % 3 == 0:
            lines.append("    p->c = Math_TanF(p->b * %d.5f);" % (i + 1))
        if i < cos_callers:
            lines.append("    p->c += Math_Cos(p->a + p->t);")
        lines += ["}", ""]
    return "\n".join(lines)


def p5_files(native_init=False):
    files = {"mathx.h": MATHX_H, "mathx.cpp": MATHX_CPP}
    names = []
    for k, cos in ((1, 1), (2, 1), (3, 0)):
        files["k%d.cpp" % k] = k_module(k, 7, cos)
        names += ["K%d_F%d" % (k, i) for i in range(7)]
    extra = ""
    if native_init:
        files["kinit.cpp"] = ('#include "mathx.h"\nfloat g_cosInit = Math_Cos(g_body[1].a);\n'
                              "float g_cosInit2 = Math_Cos(g_body[2].b);\n")
    decls = ["void %s();" % n for n in names]
    body = "\n".join("    %s();" % n for n in names)
    files["driver.cpp"] = "\n".join(decls) + '\nextern "C" int Driver(int x)\n{\n%s\n    return x;\n}\n' % body
    return files


MATHASM_CPP = """#include "mathx.h"
Body g_body[32];
#pragma warning(disable: 4035)
float Math_Tan(float a)
{
    __asm {
        fld a
        fptan
        fstp st(0)
    }
}
float Math_TanF(float a)
{
    float r;
    __asm {
        fld a
        fptan
        fstp st(0)
        fstp r
    }
    return r;
}
float Math_Half(float a)
{
    return a * 0.5f;
}
float Math_Cos(float a)
{
    __asm {
        fld a
        fcos
    }
}
"""


def cold_body(name="UpdateCold", wrapper="WrapA", deepest=8):
    """Two hot wrapper sites, then one site under k nested ifs for k = 1..DEEPEST (c2's static block
    frequency halves at each if: the deeper sites are colder)."""
    lines = ["int %s(int x)" % name, "{", "    State* s = &g_state;", "    int acc = x;",
             "    acc += %s(s->v[1]);" % wrapper, "    acc += %s(s->v[2] + acc) * 3;" % wrapper]
    slot = 3
    for k in range(1, deepest + 1):
        for level in range(k):
            lines.append("    " * (level + 1) + "if (s->v[%d] > acc + %d) {" % (slot % 64, level))
            slot += 1
        lines.append("    " * (k + 1) + "acc ^= %s(s->v[%d] + %d) << %d;" % (wrapper, slot % 64, k, k % 7))
        for level in reversed(range(k)):
            lines.append("    " * (level + 1) + "}")
        slot += 1
    lines += ["    return acc;", "}", ""]
    return "\n".join(lines)


def p1_cold(blocks=20):
    files = p1_files(blocks, ("m1", "m2"))
    files["u2.cpp"] = '#include "wrap.h"\n#include "state.h"\n' + cold_body()
    files["driver.cpp"] = driver(["Update", "M1_Small", "M2_Small", "UpdateCold"])
    return files


NATIVE_DEAD_CPP = '#include "wrap.h"\nint Native_Dead(int x)\n{\n    return WrapA(x + 9);\n}\n'
WRAP_TABLE_CPP = ('#include "wrap.h"\ntypedef int (*WrapFn)(int);\n'
                  "WrapFn g_wrapTable[3] = { WrapA, WrapB, WrapC };\n")

# P5 with retail-shaped callers: constructors with an EH state and property reads, three Math_Tan calls each
SENSE_H = """#ifndef SENSE_H
#define SENSE_H
struct Holder {
    Holder();
    ~Holder();
    int v;
};
int Props_Get(int key, float* out);
extern float g_fov;
#endif
"""

SENSE_SUPPORT_CPP = """#include "sense.h"
float g_fov;
__declspec(noinline) Holder::Holder() : v(1) {}
__declspec(noinline) Holder::~Holder() { g_fov += (float)v; }
__declspec(noinline) int Props_Get(int key, float* out)
{
    if ((key & 3) == 0) {
        return 0;
    }
    *out = (float)(key >> 4);
    return 1;
}
"""


def sense_module(k, count):
    lines = ['#include "mathx.h"', '#include "sense.h"']
    for i in range(count):
        cls = "SenseK%d_%d" % (k, i)
        lines += ["class %s {" % cls, "public:", "    %s();" % cls,
                  "    float f20;", "    float f24;", "    float f28;", "    float f2C;", "};",
                  "%s::%s()" % (cls, cls), "{", "    Holder holder;", "    float value;", "    f20 = 0.0f;"]
        for j in range(8):
            lines.append("    if (Props_Get(0x%X, &value)) {\n        f20 += value * %d.0f;\n    }"
                         % (0x1000 * (k * 8 + i) + j * 0x11 + 1, j + 1))
        lines += ["    float a24 = g_fov * 170.0f;", "    f24 = Math_Tan(a24 * 0.5f);",
                  "    float a28 = g_fov * 130.0f;", "    f28 = Math_Tan(a28 * 0.25f);",
                  "    float a2C = g_fov * 110.0f;", "    f2C = Math_Tan(a2C * 0.6f);", "}", "",
                  "float Make%s()" % cls, "{", "    %s s;" % cls, "    return s.f24 + s.f28 + s.f2C;", "}", ""]
    return "\n".join(lines)


def p5_ctor(extra=None):
    files = {"mathx.h": MATHX_H, "mathx.cpp": MATHX_CPP, "sense.h": SENSE_H, "sense_support.cpp": SENSE_SUPPORT_CPP}
    names = []
    for k, count in ((1, 4), (2, 3)):
        files["s%d.cpp" % k] = sense_module(k, count)
        names += ["MakeSenseK%d_%d" % (k, i) for i in range(count)]
    decls = ["float %s();" % n for n in names]
    body = " + ".join("%s()" % n for n in names)
    files["driver.cpp"] = ("\n".join(decls) + '\nextern "C" int Driver(int x)\n{\n    return (int)(%s) + x;\n}\n'
                           % body)
    files.update(extra or {})
    return files


MIX_H = """#ifndef MIX_H
#define MIX_H
inline int Mix(int a, int b)
{
    int r = 0;
    for (int i = 0; i < a; ++i) {
        if ((i & b) != 0) {
            r += i * b;
        } else {
            r ^= i + a;
        }
        if (r > 1000) {
            r -= b;
        }
    }
    return r;
}
#endif
"""


def big_body(mixes):
    lines = ["int UpdateBig(int x)", "{", "    State* s = &g_state;", "    int acc = x;",
             "    acc += WrapA(s->v[1]);", "    acc += WrapA(s->v[2] + acc) * 3;"]
    for i in range(mixes):
        lines.append("    acc += Mix(s->v[%d], %d);" % (i % 64, i + 1))
    for i in range(4):
        lines.append("    acc ^= WrapA(s->v[%d] + acc) << %d;" % ((i * 9) % 64, i + 1))
    lines += ["    return acc;", "}", ""]
    return "\n".join(lines)


P7_H = """#ifndef P7_H
#define P7_H
float Math_Tan(float a);
struct Obj {
    float a;
    float b;
    float c;
};
extern float g_k;
#endif
"""

P7_CALLER = """__declspec(noinline) void Caller(Obj* o)
{
    o->a = Math_Tan(g_k * 170.0f * 0.5f);
    o->b = Math_Tan(g_k * 130.0f * 0.25f);
    o->c = Math_Tan(g_k * 110.0f * 0.6f);
}
"""


def p7_files(how, noinline, k_in_caller):
    tan = "float Math_Tan(float a)\n{\n    return (float)tan((double)a);\n}\n"
    if noinline:
        tan = "__declspec(noinline) " + tan
    files = {"p7.h": P7_H, "tanmod.cpp": '#include <math.h>\n#include "p7.h"\n' + tan}
    caller = '#include "p7.h"\n'
    if k_in_caller:
        caller += "float g_k = 1.5f;\n"
    else:
        files["kmod.cpp"] = '#include "p7.h"\nfloat g_k = 1.5f;\n'
    files["caller.cpp"] = caller + P7_CALLER
    decls = ["void Caller(Obj* o);"]
    body = "    g_k = (float)x;\n    Obj o;\n    Caller(&o);\n"
    if how in ("native", "native_dead"):
        files["native7.cpp"] = ('#include "p7.h"\nfloat Native_UseTan(float x)\n{\n'
                                "    return Math_Tan(x) * 2.0f;\n}\n")
        if how == "native":
            decls.append("float Native_UseTan(float x);")
            body += "    o.a += Native_UseTan(o.b);\n"
    if how == "table":
        files["table7.cpp"] = ('#include "p7.h"\ntypedef float (*MathFn)(float);\n'
                               "MathFn g_tanTable[1] = { Math_Tan };\n")
    files["driver.cpp"] = ('#include "p7.h"\n' + "\n".join(decls) + '\nextern "C" int Driver(int x)\n{\n' + body
                           + "    return (int)(o.a + o.b + o.c) + x;\n}\n")
    return files


def p7_variants(add):
    tan = "?Math_Tan@@YAMM@Z"
    for how, label in (("include", "a"), ("native", "b"), ("native_dead", "c"), ("table", "d"), ("none", "e")):
        for noinline, k_in_caller, tag in ((False, False, "Ob1"), (True, False, "noinline"), (False, True, "Ob1_klocal")):
            flags = {} if noinline else {"tanmod.cpp": BASE_FLAGS + " /GL /Ob1"}
            if how in ("native", "native_dead"):
                flags["native7.cpp"] = BASE_FLAGS
            roots = ("_Driver", tan) if how == "include" else ("_Driver",)
            add("P7", "P7%s_%s_%s" % (label, how, tag), p7_files(how, noinline, k_in_caller), [tan], "Math_Tan",
                flags=flags, roots=roots, show=["?Caller@@YAXPAUObj@@@Z"], globals_=["?g_k@@3MA"],
                note="Caller: g_k * c1 * c2 into Math_Tan three times; Math_Tan %s; g_k defined in %s; outside "
                     "reference: %s" % ("__declspec(noinline)" if noinline else "in a /Ob1 module",
                                        "caller.cpp" if k_in_caller else "kmod.cpp",
                                        {"include": "/INCLUDE", "native": "native7.cpp (no /GL) calls it, kept",
                                         "native_dead": "native7.cpp (no /GL) calls it, removed by /OPT:REF",
                                         "table": "address in an unread /GL table", "none": "none (control)"}[how]))
    add("P7", "P7f_native_callee", p7_files("none", False, False), [tan], "Math_Tan",
        flags={"tanmod.cpp": BASE_FLAGS}, show=["?Caller@@YAXPAUObj@@@Z"], globals_=["?g_k@@3MA"],
        note="P7e with tanmod.cpp compiled without /GL: Math_Tan is native code the link cannot see into")
    # g_k's own address escapes (a console-variable style registration): may o->a alias it?
    for how, label in (("include", "a"), ("native", "b"), ("none", "e")):
        for kaddr in ("gltable", "native"):
            files = p7_files(how, False, False)
            flags = {"tanmod.cpp": BASE_FLAGS + " /GL /Ob1"}
            if how == "native":
                flags["native7.cpp"] = BASE_FLAGS
            if kaddr == "gltable":
                files["kaddr.cpp"] = '#include "p7.h"\nfloat* g_vars[1] = { &g_k };\n'
            else:
                files["kaddr.cpp"] = ('#include "p7.h"\nvoid Vars_Register(float* p);\n'
                                      "void Native_RegisterK()\n{\n    Vars_Register(&g_k);\n}\n")
                flags["kaddr.cpp"] = BASE_FLAGS
            roots = ("_Driver", tan) if how == "include" else ("_Driver",)
            if kaddr == "native":
                roots += ("?Native_RegisterK@@YAXXZ",)
            add("P7", "P7%s_%s_kaddr_%s" % (label, how, kaddr), files, [tan], "Math_Tan", flags=flags, roots=roots,
                show=["?Caller@@YAXPAUObj@@@Z"], globals_=["?g_k@@3MA"],
                note="P7%s (/Ob1, g_k in kmod.cpp) + g_k's address taken: %s" % (
                    label, "in an unread /GL table g_vars" if kaddr == "gltable"
                    else "passed by a native (no /GL) function, /INCLUDE'd, to an external Vars_Register"))


def p8_files(trigger, noinline):
    files = p7_files("native" if trigger == "native" else "include", noinline, False)
    files["caller2.cpp"] = '#include "p7.h"\n' + P7_CALLER.replace("void Caller(", "void Caller2(")
    files["driver.cpp"] = files["driver.cpp"].replace(
        "void Caller(Obj* o);", "void Caller(Obj* o);\nvoid Caller2(Obj* o);").replace(
        "    Caller(&o);\n", "    Caller(&o);\n    Caller2(&o);\n")
    return files


P8_ORDERS = (
    ("a_first", ["tanmod", "kmod", "caller", "caller2", "driver"]),
    ("b_between", ["kmod", "tanmod", "caller", "caller2", "driver"]),
    ("c_after_caller", ["kmod", "caller", "tanmod", "caller2", "driver"]),
    ("d_last", ["kmod", "caller", "caller2", "driver", "tanmod"]),
    ("d2_last_caller_first", ["caller", "caller2", "kmod", "driver", "tanmod"]),
    ("d3_last_driver_first", ["driver", "kmod", "caller", "caller2", "tanmod"]),
    ("e_split", ["kmod", "caller", "tanmod", "caller2", "driver"]),
)


def p8_variants(add):
    tan = "?Math_Tan@@YAMM@Z"
    callers = ["?Caller@@YAXPAUObj@@@Z", "?Caller2@@YAXPAUObj@@@Z"]
    runs = [(order, trigger, False) for order in P8_ORDERS for trigger in ("include", "native")]
    runs += [(P8_ORDERS[0], "include", True), (P8_ORDERS[3], "include", True)]
    for (tag, order), trigger, noinline in runs:
        files = p8_files(trigger, noinline)
        order = list(order)
        if trigger == "native":
            # the kept native caller just before the callee's module (last but one when the callee is last)
            order.insert(order.index("tanmod"), "native7")
        flags = {} if noinline else {"tanmod.cpp": BASE_FLAGS + " /GL /Ob1"}
        if trigger == "native":
            flags["native7.cpp"] = BASE_FLAGS
        roots = ("_Driver", tan) if trigger == "include" else ("_Driver",)
        add("P8", "P8%s_%s%s" % (tag, trigger, "_noinline" if noinline else ""), files, [tan], "Math_Tan",
            flags=flags, roots=roots, show=callers, globals_=["?g_k@@3MA"], order=[o + ".cpp" for o in order],
            note="link order %s; 0x2000 by %s; Math_Tan %s" % (
                " ".join(order), "/INCLUDE" if trigger == "include" else "a kept native caller (native7.cpp)",
                "__declspec(noinline)" if noinline else "in a /Ob1 module"))


# P9-P12: what keeps the callers of Math_Tan from using its register-use summary (c2_trace RegUseModel:
# node+0x60, stored by MscRecordInterProcRegInfo, read by LoAddCallScratchRegs). Base: P7a (tanmod /Ob1,
# /INCLUDE of Math_Tan: the retail body, the caller keeps g_k in XMM0).
TAN = "?Math_Tan@@YAMM@Z"
TAN_BODY = "float Math_Tan(float a)\n{\n    return (float)tan((double)a);\n}\n"


def p9_12_add(add, name, files, note, flags=None, roots=("_Driver", TAN), callees=(TAN,), show=()):
    merged = {"tanmod.cpp": BASE_FLAGS + " /GL /Ob1"}
    merged.update(flags or {})
    for k in [k for k, v in merged.items() if v is None]:
        del merged[k]
    add(name[:3] if name[2].isdigit() else name[:2], name, files, list(callees), "Math_Tan", flags=merged,
        roots=roots, show=["?Caller@@YAXPAUObj@@@Z"] + list(show), globals_=["?g_k@@3MA"], note=note)


def p9_12_variants(add):
    base = lambda: p7_files("include", False, False)
    # P9: a call-graph cycle through the callee (Math_Tan calls Caller on a cold path)
    f = base()
    f["tanmod.cpp"] = ('#include <math.h>\n#include "p7.h"\nvoid Caller(Obj* o);\nfloat Math_Tan(float a)\n{\n'
                       "    if (a > 1.0e30f) {\n        Obj o;\n        Caller(&o);\n    }\n"
                       "    return (float)tan((double)a);\n}\n")
    p9_12_add(add, "P9a_cycle", f, "Math_Tan and Caller in one call-graph cycle (Math_Tan calls Caller when "
              "a > 1e30): which of the two c2 compiles first")
    f = base()
    f["other9.cpp"] = ('#include "p7.h"\nvoid Caller(Obj* o);\n__declspec(noinline) void Other(Obj* o, int n)\n{\n'
                       "    if (n > 0) {\n        Caller(o);\n    }\n}\n")
    f["caller.cpp"] = ('#include "p7.h"\nvoid Other(Obj* o, int n);\n' + P7_CALLER.replace(
        "    o->c = Math_Tan(g_k * 110.0f * 0.6f);\n",
        "    o->c = Math_Tan(g_k * 110.0f * 0.6f);\n    if (o->a > 1.0e30f) {\n        Other(o, 1);\n    }\n"))
    p9_12_add(add, "P9b_cycle_caller_only", f, "Caller in a cycle with Other (not with Math_Tan)")
    # P10: the calls reach Math_Tan only through a body inlined from another module
    f = base()
    f["wrap10.cpp"] = '#include "p7.h"\nfloat Tan_Scaled(float x, float s)\n{\n    return Math_Tan(x * s);\n}\n'
    f["caller.cpp"] = ('#include "p7.h"\nfloat Tan_Scaled(float x, float s);\n'
                       "__declspec(noinline) void Caller(Obj* o)\n{\n"
                       "    o->a = Tan_Scaled(g_k * 170.0f, 0.5f);\n    o->b = Tan_Scaled(g_k * 130.0f, 0.25f);\n"
                       "    o->c = Tan_Scaled(g_k * 110.0f, 0.6f);\n}\n")
    p9_12_add(add, "P10a_via_other_module", f, "Caller calls Tan_Scaled (wrap10.cpp, /GL) three times; the link "
              "inlines it, so the Math_Tan calls come from another module's body", callees=(TAN, "?Tan_Scaled@@YAMMM@Z"))
    f = base()
    f["p7.h"] = P7_H.replace("#endif", "inline float Tan_Scaled(float x, float s)\n{\n    return Math_Tan(x * s);\n}\n#endif")
    f["caller.cpp"] = ('#include "p7.h"\n__declspec(noinline) void Caller(Obj* o)\n{\n'
                       "    o->a = Tan_Scaled(g_k * 170.0f, 0.5f);\n    o->b = Tan_Scaled(g_k * 130.0f, 0.25f);\n"
                       "    o->c = Tan_Scaled(g_k * 110.0f, 0.6f);\n}\n")
    p9_12_add(add, "P10b_via_header_inline", f, "the calls through a header inline Tan_Scaled")
    # P11: a large link (many modules and functions compiled before the caller)
    for tag, modules, per in (("a", 100, 30), ("b", 300, 30)):
        f = base()
        roots = ["_Driver", TAN]
        for k in range(modules):
            lines = ["int g_fill%d = %d;" % (k, k + 1)]
            for i in range(per):
                call = "Fill%d_%d(x * 3 + %d)" % (k, i - 1, i) if i else "x + g_fill%d" % k
                lines.append("__declspec(noinline) int Fill%d_%d(int x)\n{\n    return %s ^ (x >> %d);\n}\n"
                             % (k, i, call, i % 7 + 1))
            f["fill%03d.cpp" % k] = "\n".join(lines)
            roots.append("?Fill%d_%d@@YAHH@Z" % (k, per - 1))
        p9_12_add(add, "P11%s_large_%dx%d" % (tag, modules, per), f, "P7a + %d /GL modules of %d chained "
                  "noinline functions (%d functions), each module's last one a root" % (modules, per, modules * per),
                  roots=tuple(roots))
    # P12: options on the callee's or the callers' module
    pragma = lambda text, opt: ('#pragma optimize("%s", off)\n' % opt) + text + '#pragma optimize("", on)\n'
    for tag, opt, ob1, note in (("a", "g", True, "Math_Tan under #pragma optimize(\"g\", off), /Ob1 module"),
                                ("b", "g", False, "Math_Tan under #pragma optimize(\"g\", off), /Ob2 module"),
                                ("c", "y", True, "Math_Tan under #pragma optimize(\"y\", off), /Ob1"),
                                ("d", "t", True, "Math_Tan under #pragma optimize(\"t\", off), /Ob1")):
        f = base()
        f["tanmod.cpp"] = '#include <math.h>\n#include "p7.h"\n' + pragma(TAN_BODY, opt)
        p9_12_add(add, "P12%s_callee_pragma_%s%s" % (tag, opt, "" if ob1 else "_ob2"), f, note,
                  flags={} if ob1 else {"tanmod.cpp": None})
        if tag in ("a", "b"):
            p9_12_add(add, "P12%s2_callee_pragma_%s%s_noinclude" % (tag, opt, "" if ob1 else "_ob2"), f,
                      note + "; no /INCLUDE (no 0x2000 trigger)", flags={} if ob1 else {"tanmod.cpp": None},
                      roots=("_Driver",))
    for tag, extra, note in (("e", "/Oy-", "tanmod /Oy-"), ("f", "/Os", "tanmod /Os"), ("g", "/Ob0", "tanmod /Ob0"),
                             ("h", "/Od", "tanmod /Od")):
        flags = {"tanmod.cpp": BASE_FLAGS.replace("/O2 ", "") + " /Od /GL"} if extra == "/Od" else \
            {"tanmod.cpp": BASE_FLAGS + " /GL /Ob1 " + extra}
        p9_12_add(add, "P12%s_callee_%s" % (tag, extra.strip("/").replace("-", "minus")), base(), note, flags=flags)
    for tag, how, note in (("i", "pragma_g", "caller.cpp: Caller under #pragma optimize(\"g\", off)"),
                           ("j", "/Oy-", "caller.cpp /Oy-"), ("k", "/Ob0", "caller.cpp /Ob0"),
                           ("l", "/Os", "caller.cpp /Os"), ("m", "pragma_y", "caller.cpp: #pragma optimize(\"y\", off)")):
        f = base()
        flags = {}
        if how.startswith("pragma_"):
            f["caller.cpp"] = '#include "p7.h"\n' + pragma(P7_CALLER, how[-1])
        else:
            flags["caller.cpp"] = BASE_FLAGS + " /GL " + how
        p9_12_add(add, "P12%s_caller_%s" % (tag, how.strip("/").replace("-", "minus")), f, note, flags=flags)

    # P13: Math_Tan as a header inline (a COMDAT of selection ANY): MscRecordInterProcRegInfo skips the record
    # when entry+0x37 & 0x1E0 == 0xA0, entry+0x20 bit 0x20 and the function's section has selection 2 (ANY)
    for tag, attr, trigger, note in (
            ("a", "inline __declspec(noinline) ", "include", "/INCLUDE"),
            ("b", "inline __declspec(noinline) ", "native", "a native (no /GL) object calls it (its COMDAT copy)"),
            ("c", "inline __declspec(noinline) ", "none", "no outside reference"),
            ("d", "inline ", "native", "plain inline (inlinable), a native object calls it"),
            ("e", "inline ", "include", "plain inline, /INCLUDE")):
        f = p7_files("none", False, False)
        del f["tanmod.cpp"]
        f["p7.h"] = P7_H.replace("float Math_Tan(float a);\n", "#include <math.h>\n%sfloat Math_Tan(float a)\n{\n"
                                 "    return (float)tan((double)a);\n}\n" % attr)
        flags = {"tanmod.cpp": None}
        roots = ("_Driver",)
        if trigger == "include":
            roots += (TAN,)
        if trigger == "native":
            f["native7.cpp"] = ('#include "p7.h"\nfloat Native_UseTan(float x)\n{\n'
                                "    return Math_Tan(x) * 2.0f;\n}\n")
            f["driver.cpp"] = f["driver.cpp"].replace("void Caller(Obj* o);", "void Caller(Obj* o);\n"
                                                      "float Native_UseTan(float x);").replace(
                "    Caller(&o);\n", "    Caller(&o);\n    o.a += Native_UseTan(o.b);\n")
            flags["native7.cpp"] = BASE_FLAGS
        p9_12_add(add, "P13%s_header_%s_%s" % (tag, "noinline" if "noinline" in attr else "inline", trigger), f,
                  "Math_Tan defined in p7.h as `%sfloat Math_Tan(float)` (selectany COMDAT); 0x2000 trigger: %s"
                  % (attr, note), flags=flags, roots=roots)


# P14: the link size InlInitLtcgSetting steps SpeedLimit / FoldCmpSpeedWeight by (LtcgInlClassify: the sum of
# the entry+0x54 sizes of the entries with a body): MODULES modules of FUNCS noinline functions of BLOCKS blocks,
# each module's Mod_<k> calling its functions (dead: nothing calls them)
NL = chr(10)


def p14_files(modules, funcs, blocks, dead=False):
    files = {"v.cpp": "int g_v[64];" + NL}
    roots = []
    for k in range(modules):
        lines = ["extern int g_v[64];"]
        for i in range(funcs):
            lines += ["__declspec(noinline) int F%d_%d(int x)" % (k, i), "{", "    int acc = x;"]
            for j in range(blocks):
                a, b, c = (i + j) % 64, (i * 7 + j * 3) % 64, (j * 5 + k) % 64
                lines += ["    if (g_v[%d] > acc) {" % a, "        acc += g_v[%d] * %d;" % (b, j + 3),
                          "    } else {", "        g_v[%d] -= acc >> %d;" % (c, j % 5 + 1), "    }"]
            lines += ["    return acc;", "}"]
        if not dead:
            calls = " + ".join("F%d_%d(x + %d)" % (k, i, i) for i in range(funcs))
            lines += ["int Mod_%d(int x)" % k, "{", "    return %s;" % calls, "}"]
            roots.append("Mod_%d" % k)
        files["m%03d.cpp" % k] = NL.join(lines) + NL
    files["driver.cpp"] = driver(roots)
    return files


P14_SWEEP = (   # name, modules, functions per module, blocks per function, dead
    ("P14a_m1_f1_tiny", 1, 1, 2, False),
    ("P14b_m40_f1_tiny", 40, 1, 2, False),
    ("P14c_m1_f1000_tiny", 1, 1000, 1, False),
    ("P14d_m1_f20_b100", 1, 20, 100, False),
    ("P14e_m20_f1_b100", 20, 1, 100, False),
    ("P14f_m1_f13_b100", 1, 13, 100, False),
    ("P14g_m1_f14_b100", 1, 14, 100, False),
    ("P14h_m1_f26_b100", 1, 26, 100, False),
    ("P14i_m1_f28_b100", 1, 28, 100, False),
    ("P14j_m4_f15_b100_dead", 4, 15, 100, True),
    ("P14k_m4_f15_b100", 4, 15, 100, False),
    ("P14l_m10_f13_b100", 10, 13, 100, False),
    ("P14m_m10_f14_b100", 10, 14, 100, False),
    ("P14n_m1_f1_b2000", 1, 1, 2000, False),
)


def p14_variants(add):
    for name, modules, funcs, blocks, dead in P14_SWEEP:
        add("P14", name, p14_files(modules, funcs, blocks, dead), [], "Mod_",
            note="link size: %d modules x %d noinline functions x %d blocks%s" % (
                modules, funcs, blocks, " (no caller: dead)" if dead else ""))


# P6 / P3 / P4: one mid-size cdecl callee
CALLEE_H = "int Callee(int a, int b);\n"


def callee_cpp(attr=""):
    return """#include "callee.h"
%sint Callee(int a, int b)
{
    int r = 0;
    for (int i = 0; i < a; ++i) {
        if ((i & b) != 0) {
            r += i * b;
        } else {
            r ^= i + a;
        }
        if (r > 1000) {
            r -= b;
        }
    }
    return r;
}
""" % attr


C1_CPP = ('#include "callee.h"\nint C1_Use(int x)\n{\n    return Callee(x, 3) + Callee(x + 1, x) * 2;\n}\n'
          'int C1_Use2(int x)\n{\n    return Callee(x >> 1, 5) - x;\n}\n')
C2_CPP = ('#include "callee.h"\nint C2_Use(int x)\n{\n    return Callee(x * 3, x - 1) ^ Callee(7, x);\n}\n')


def callee_files(attr="", table=None):
    files = {"callee.h": CALLEE_H, "callee.cpp": callee_cpp(attr), "c1.cpp": C1_CPP, "c2.cpp": C2_CPP}
    calls = ["C1_Use", "C1_Use2", "C2_Use"]
    decls = ["int %s(int x);" % c for c in calls]
    extra = ""
    if table == "unused":
        files["table.cpp"] = ('#include "callee.h"\ntypedef int (*CalleeFn)(int, int);\n'
                              "CalleeFn g_unusedTable[2] = { Callee, 0 };\n")
    elif table == "used":
        files["table.cpp"] = ('#include "callee.h"\ntypedef int (*CalleeFn)(int, int);\n'
                              "CalleeFn g_usedTable[2] = { Callee, Callee };\n")
        decls += ["typedef int (*CalleeFn)(int, int);", "extern CalleeFn g_usedTable[2];"]
        calls_expr = " + ".join("%s(x)" % c for c in calls) + " + g_usedTable[x & 1](x, x)"
        return files | {"driver.cpp": "\n".join(decls) + '\nextern "C" int Driver(int x)\n{\n    return %s;\n}\n'
                        % calls_expr}
    files["driver.cpp"] = driver(calls, decls, extra)
    return files


# ---------------------------------------------------------------- probes

UPDATE_BLOCKS = 120


def variants():
    v = []

    def add(probe, name, files, callees, filt, flags=None, roots=("_Driver",), note="", default=True, show=(),
            globals_=(), order=None):
        v.append({"probe": probe, "name": name, "files": files, "callees": callees, "filter": filt,
                  "flags": flags or {}, "roots": list(roots), "note": note, "default": default,
                  "show": list(show), "globals": list(globals_), "order": order})

    wraps = ["?WrapA@@YAHH@Z", "?WrapB@@YAHH@Z", "?WrapC@@YAHH@Z"]
    add("P1", "P1a_hdr2", p1_files(UPDATE_BLOCKS, ("m1",)), wraps, "Wrap",
        note="inline wrappers in a header included by 2 modules (u, m1) + reg")
    add("P1", "P1b_hdr3", p1_files(UPDATE_BLOCKS, ("m1", "m2")), wraps, "Wrap",
        note="inline wrappers in a header included by 3 modules (u, m1, m2)")
    add("P1", "P1c_onemod", p1_one_module(UPDATE_BLOCKS), wraps, "Wrap",
        note="inline wrappers defined in one module (u.cpp), every caller there")
    add("P1", "P1d_ordinary", p1_ordinary(UPDATE_BLOCKS), wraps, "Wrap",
        note="ordinary (non-inline) wrappers in wrap.cpp, callers in u, m1, m2")
    f = p1_ordinary(UPDATE_BLOCKS)
    f["native.cpp"] = NATIVE_CPP
    f["driver.cpp"] = driver(["Update", "M1_Small", "M2_Small", "Native_Call"])
    add("P2", "P2a_native_caller", f, wraps, "Wrap", flags={"native.cpp": BASE_FLAGS},
        note="P1d + native.cpp (no /GL) calling WrapA")
    f = p1_files(UPDATE_BLOCKS, ("m1", "m2"))
    f["native.cpp"] = NATIVE_CPP
    f["driver.cpp"] = driver(["Update", "M1_Small", "M2_Small", "Native_Call"])
    add("P2", "P2b_native_comdat", f, wraps, "Wrap", flags={"native.cpp": BASE_FLAGS + " /Ob0"},
        note="P1b + native.cpp (no /GL, /Ob0) with its own out-of-line COMDAT copy of WrapA")
    add("P5", "P5a_x87", p5_files(), ["?Math_Tan@@YAMM@Z", "?Math_TanF@@YAMM@Z", "?Math_Half@@YAMM@Z",
                                      "?Math_Cos@@YAMM@Z"], "Math_",
        note="float helpers in mathx.cpp, 21 tan / 21 half / 9 tanf / 2 cos callers in k1..k3, all /GL")
    add("P5", "P5b_native_init", p5_files(native_init=True), ["?Math_Tan@@YAMM@Z", "?Math_Cos@@YAMM@Z"],
        "Math_", flags={"kinit.cpp": BASE_FLAGS},
        note="P5a + kinit.cpp (no /GL): two dynamic initializers calling Math_Cos")
    f = p5_files()
    f["mathx.cpp"] = MATHASM_CPP
    add("P5", "P5c_asm", f, ["?Math_Tan@@YAMM@Z", "?Math_TanF@@YAMM@Z", "?Math_Half@@YAMM@Z",
                             "?Math_Cos@@YAMM@Z"], "Math_",
        note="P5a with inline-asm helpers: Math_Tan = fld/fptan/fstp st(0) and no return (ST0), Math_TanF the "
             "same stored to a local and returned, Math_Cos = fld/fcos no return; Math_Half plain "
             "(the untraced /LTCG link hangs in 'Generating code' (killed after 10 min): run only by name)",
        default=False)
    f = p5_files(native_init=True)
    f["mathx.cpp"] = MATHASM_CPP
    add("P5", "P5d_asm_native_init", f, ["?Math_Tan@@YAMM@Z", "?Math_Cos@@YAMM@Z"], "Math_",
        flags={"kinit.cpp": BASE_FLAGS}, default=False,
        note="P5c + kinit.cpp (no /GL): two dynamic initializers calling Math_Cos (hangs like P5c: run only by name)")
    add("P1", "P1e_cold", p1_cold(), wraps, "Wrap",
        note="P1b (Update 20 blocks) + u2.cpp UpdateCold: 2 hot WrapA sites, then sites under 1..8 nested ifs")
    f = p1_cold()
    f["native.cpp"] = NATIVE_CPP
    f["driver.cpp"] = driver(["Update", "M1_Small", "M2_Small", "UpdateCold", "Native_Call"])
    add("P2", "P2c_cold_native", f, wraps, "Wrap", flags={"native.cpp": BASE_FLAGS},
        note="P1e + native.cpp (no /GL) calling WrapA from Native_Call (live)")
    f = p1_cold()
    f["native_dead.cpp"] = NATIVE_DEAD_CPP
    add("P2", "P2d_cold_phantom", f, wraps, "Wrap", flags={"native_dead.cpp": BASE_FLAGS + " /Ob0"},
        note="P1e + native_dead.cpp (no /GL, /Ob0): Native_Dead calls WrapA out of line, nothing references "
             "Native_Dead (removed by /OPT:REF)")
    f = p1_cold()
    f["wrap_table.cpp"] = WRAP_TABLE_CPP
    add("P3", "P3d_cold_wraptable", f, wraps, "Wrap",
        note="P1e + wrap_table.cpp (/GL): g_wrapTable = {WrapA, WrapB, WrapC}, nothing reads it")
    f = callee_files()
    f["table.cpp"] = ('#include "callee.h"\ntypedef int (*CalleeFn)(int, int);\n'
                      "__declspec(selectany) CalleeFn g_unusedTable[2] = { Callee, 0 };\n")
    add("P3", "P3c_selectany_table", f, ["?Callee@@YAHHH@Z"], "Callee",
        note="the callee's address in a /GL __declspec(selectany) (COMDAT) table nothing reads")
    tans = ["?Math_Tan@@YAMM@Z"]
    add("P5", "P5e_ctor", p5_ctor(), tans, "Math_Tan",
        note="Math_Tan (C) called 3x from each of 7 EH constructors (8 property reads each) in 2 units, all /GL")
    add("P5", "P5f_ctor_native",
        p5_ctor({"kinit.cpp": '#include "mathx.h"\nfloat g_tanInit = Math_Tan(g_body[1].a);\n'}),
        tans, "Math_Tan", flags={"kinit.cpp": BASE_FLAGS},
        note="P5e + kinit.cpp (no /GL): a dynamic initializer calling Math_Tan")
    add("P5", "P5g_ctor_phantom",
        p5_ctor({"kdead.cpp": '#include "mathx.h"\nfloat Native_DeadTan(float a)\n{\n'
                              '    return Math_Tan(a) + 1.0f;\n}\n'}),
        tans, "Math_Tan", flags={"kdead.cpp": BASE_FLAGS},
        note="P5e + kdead.cpp (no /GL): Native_DeadTan calls Math_Tan, nothing references it (removed by /OPT:REF)")
    add("P5", "P5h_ctor_table",
        p5_ctor({"ktable.cpp": '#include "mathx.h"\ntypedef float (*MathFn)(float);\n'
                               "MathFn g_mathTable[2] = { Math_Tan, Math_Half };\n"}),
        tans + ["?Math_Half@@YAMM@Z"], "Math_",
        note="P5e + ktable.cpp (/GL): g_mathTable = {Math_Tan, Math_Half}, nothing reads it")
    add("P5", "P5i_ctor_Ob1_table",
        p5_ctor({"ktable.cpp": '#include "mathx.h"\ntypedef float (*MathFn)(float);\n'
                               "MathFn g_mathTable[1] = { Math_Tan };\n"}),
        tans, "Math_Tan", flags={"mathx.cpp": BASE_FLAGS + " /GL /Ob1"},
        note="P5h with mathx.cpp compiled /Ob1 (Math_Tan not a candidate) and its address in an unread table")
    f = p5_ctor()
    f["mathx.cpp"] = MATHX_CPP.replace("float Math_Tan(float a)", "__declspec(noinline) float Math_Tan(float a)")
    add("P5", "P5j_ctor_noinline", f, tans, "Math_Tan",
        note="P5e with Math_Tan __declspec(noinline), no outside reference (its custom-convention body)")
    callee = ["?Callee@@YAHHH@Z"]
    add("P6", "P6a_noinline", callee_files("__declspec(noinline) "), callee, "Callee",
        note="mid-size cdecl callee, __declspec(noinline), callers /GL")
    add("P6", "P6b_include", callee_files(), callee, "Callee", roots=("_Driver", "?Callee@@YAHHH@Z"),
        note="the same callee without noinline, /INCLUDE'd")
    add("P6", "P6c_base", callee_files(), callee, "Callee", note="baseline: the callee, no attribute, no /INCLUDE")
    add("P3", "P3a_unused_table", callee_files(table="unused"), callee, "Callee",
        note="the callee's address in a /GL table nothing reads")
    add("P3", "P3b_used_table", callee_files(table="used"), callee, "Callee",
        note="the callee's address in a /GL table the driver reads")
    add("P4", "P4a_Ob1", callee_files(), callee, "Callee", flags={"callee.cpp": BASE_FLAGS + " /GL /Ob1"},
        note="callee module /Ob1, callers /O2 (/Ob2)")
    add("P4", "P4b_fp_precise", callee_files(), callee, "Callee",
        flags={"callee.cpp": BASE_FLAGS.replace("/fp:fast", "/fp:precise") + " /GL"},
        note="callee module /fp:precise, callers /fp:fast")
    add("P4", "P4c_no_Gy", callee_files(), callee, "Callee",
        flags={"callee.cpp": BASE_FLAGS.replace(" /Gy", "") + " /GL"}, note="callee module without /Gy")
    add("P4", "P4d_callers_Ob1", callee_files(), callee, "Callee",
        flags={"c1.cpp": BASE_FLAGS + " /GL /Ob1", "c2.cpp": BASE_FLAGS + " /GL /Ob1"},
        note="callers' modules /Ob1, callee module /O2 (/Ob2)")
    # R1 follow-up: Math_Tan's module options (callers keep the project options), no outside reference
    no_sse2 = BASE_FLAGS.replace(" /arch:SSE2", "")
    for name, fl, what in (
            ("P4e_tan_noSSE2", no_sse2 + " /GL", "without /arch:SSE2, /fp:fast"),
            ("P4f_tan_fp_precise", BASE_FLAGS.replace("/fp:fast", "/fp:precise") + " /GL", "/arch:SSE2 /fp:precise"),
            ("P4g_tan_noSSE2_precise", no_sse2.replace("/fp:fast", "/fp:precise") + " /GL",
             "without /arch:SSE2, /fp:precise"),
            ("P4h_tan_Oi-", BASE_FLAGS + " /Oi- /GL", "/Oi-"),
            ("P4i_tan_O1", BASE_FLAGS.replace("/O2", "/O1") + " /GL", "/O1 instead of /O2")):
        add("P4", name, p5_ctor(), ["?Math_Tan@@YAMM@Z"], "Math_Tan", flags={"mathx.cpp": fl},
            note="R1 follow-up (ran, superseded by P5f/P5h/P5i): P5e with mathx.cpp " + what)
    f = p5_ctor()
    f["mathx.cpp"] = MATHX_CPP.replace("float Math_Tan(float a)", "__declspec(noinline) float Math_Tan(float a)")
    add("P4", "P4j_tan_noSSE2_noinline", f, ["?Math_Tan@@YAMM@Z"], "Math_Tan", flags={"mathx.cpp": no_sse2 + " /GL"},
        note="R1 follow-up (ran, superseded): P4e with Math_Tan __declspec(noinline): the body a non-SSE2 /fp:fast module gives it out of line")
    add("P4", "P4k_tan_noSSE2_table",
        p5_ctor({"ktable.cpp": '#include "mathx.h"\ntypedef float (*MathFn)(float);\n'
                               "MathFn g_mathTable[1] = { Math_Tan };\n"}),
        ["?Math_Tan@@YAMM@Z"], "Math_Tan", flags={"mathx.cpp": no_sse2 + " /GL"},
        note="R1 follow-up (ran, superseded): P4e + Math_Tan's address in an unread /GL table (0x2000)")
    # R1 follow-up: the caller's budget used up by other inlined bodies before late wrapper sites
    f = p1_files(20, ("m1", "m2"))
    f["mix.h"] = MIX_H
    f["u3.cpp"] = '#include "wrap.h"\n#include "state.h"\n#include "mix.h"\n' + big_body(40)
    f["driver.cpp"] = driver(["Update", "M1_Small", "M2_Small", "UpdateBig"])
    add("P1", "P1f_budget", f, wraps + ["?Mix@@YAHHH@Z"], "Wrap",
        note="UpdateBig: 2 early WrapA sites, 40 sites of an inline 87-tuple Mix, then 4 late WrapA sites")
    f = p1_files(20, ("m1", "m2"))
    f["mix.h"] = MIX_H
    f["u3.cpp"] = '#include "wrap.h"\n#include "state.h"\n#include "mix.h"\n' + big_body(120)
    f["driver.cpp"] = driver(["Update", "M1_Small", "M2_Small", "UpdateBig"])
    add("P1", "P1g_budget120", f, wraps + ["?Mix@@YAHHH@Z"], "Wrap",
        note="P1f with 120 Mix sites before the late WrapA sites")
    f = p1_files(20, ("m1", "m2"))
    f["u3.cpp"] = ('#pragma inline_depth(1)\n#include "wrap.h"\n#include "state.h"\n'
                   "inline int Outer(int x)\n{\n    return WrapA(x + 1) + 2;\n}\n"
                   "int UpdateDepth(int x)\n{\n    return Outer(x) + Outer(x * 3) + WrapA(x);\n}\n")
    f["driver.cpp"] = driver(["Update", "M1_Small", "M2_Small", "UpdateDepth"])
    add("P1", "P1h_inline_depth", f, wraps, "Wrap",
        note="u3.cpp with #pragma inline_depth(1): WrapA reached at depth 2 through inline Outer, and at depth 1")
    p7_variants(add)
    p8_variants(add)
    p9_12_variants(add)
    p14_variants(add)
    return v


# ---------------------------------------------------------------- build, link, trace

def run(cmd, cwd, env, log=None, timeout=900):
    r = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout)
    text = (r.stdout or "") + (r.stderr or "")
    if log:
        Path(log).write_text(text, encoding="utf-8")
    return r.returncode, text


UNRESOLVED = re.compile(r'unresolved external symbol (?:"[^"]*" \((\S+)\)|(\S+))')


def build_variant(var, out, toolchain, env, trace=True):
    d = out / var["probe"] / var["name"]
    d.mkdir(parents=True, exist_ok=True)
    for name, text in var["files"].items():
        (d / name).write_text(text, encoding="utf-8")
    (d / "ltcg_probe_stub.cpp").write_text(STUB_SOURCE, encoding="utf-8")
    cl = str(Path(toolchain["bin"]) / "cl.exe")
    link = str(Path(toolchain["bin"]) / "link.exe")
    objs = []
    sources = sorted(n for n in var["files"] if n.endswith(".cpp"))
    if var.get("order"):   # the response-file order of the objects (the order the link reads the IL modules)
        sources = list(var["order"]) + [n for n in sources if n not in var["order"]]
    for name in sources + ["ltcg_probe_stub.cpp"]:
        flags = var["flags"].get(name, BASE_FLAGS + " /GL")
        if name == "ltcg_probe_stub.cpp":
            flags = BASE_FLAGS
        obj = name[:-4] + ".obj"
        code, text = run([cl] + flags.split() + ["/Fo" + obj, name], d, env)
        if code:
            raise RuntimeError("cl %s failed:\n%s" % (name, text))
        objs.append((obj, flags))
    alternates = []
    for _ in range(4):
        rsp = d / "link.rsp"
        write_rsp(rsp, var, objs, alternates, "probe")
        code, text = run([link, "@link.rsp"], d, env, d / "link.log", timeout=300)
        if code == 0:
            break
        missing = sorted({a or b for a, b in UNRESOLVED.findall(text)} - set(alternates))
        if not missing:
            raise RuntimeError("link failed:\n%s" % text)
        alternates += missing
    else:
        raise RuntimeError("link failed after retries:\n%s" % text)
    (d / "objects.txt").write_text("".join("%s  %s\n" % o for o in objs) +
                                   "".join("/ALTERNATENAME %s\n" % a for a in alternates), encoding="utf-8")
    dumpbin = str(Path(toolchain["bin"]) / "dumpbin.exe")
    run([dumpbin, "/nologo", "/disasm", "probe.dll"], d, env, d / "probe.disasm.txt")
    trace_text = ""
    if trace:
        write_rsp(d / "trace.rsp", var, objs, alternates, "trace")
        cmd = [sys.executable, str(HERE / "c2_inline_trace.py"), "--link-rsp", str(d / "trace.rsp"),
               "--linker", link, "--function", var["filter"], "--out", str(d / "trace.jsonl"),
               "--raw", str(d / "trace.raw.jsonl"), "--timeout", "900"]
        code, trace_text = run(cmd, ROOT, None, d / "trace.out.txt", timeout=1200)
        if code not in (0,):
            trace_text = "TRACER EXIT %d\n%s" % (code, trace_text)
    summary = summarise(var, d, trace_text if trace else None)
    (d / (var["name"] + ".summary.txt")).write_text(summary, encoding="utf-8")
    return summary


def write_rsp(path, var, objs, alternates, stem):
    lines = [LINK_FLAGS, '/MAP:"%s.map" /OUT:"%s.dll"' % (stem, stem)]
    lines += ['"/INCLUDE:%s"' % r for r in var["roots"]]
    lines += ['"/ALTERNATENAME:%s=%s"' % (a, "_ltcg_probe_stub_data" if a.startswith("__imp_") else
                                          "_ltcg_probe_stub") for a in alternates]
    lines += ['"%s"' % o for o, _ in objs]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- summary

MAP_LINE = re.compile(r"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8})\s+(f?)\s*(?:i\s+)?(\S*)")
DIS_LINE = re.compile(r"^\s+([0-9A-F]{8}): (?:[0-9A-F]{2} )+\s*(.*)$")


def read_map(path):
    syms = {}
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            m = MAP_LINE.match(line)
            if m:
                syms[m.group(1)] = (int(m.group(2), 16), m.group(4))
    return syms


def read_disasm(path):
    ins = []
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            m = DIS_LINE.match(line)
            if m and m.group(2).strip():
                ins.append((int(m.group(1), 16), re.sub(r"\s+", " ", m.group(2).strip())))
    return ins


def summarise(var, d, trace_text):
    out = ["%s  %s" % (var["name"], var["note"]), "objects: " + ", ".join(
        "%s[%s]" % (o, ("/GL " if "/GL" in f else "native ") + " ".join(x for x in f.split() if x not in
                                                                          BASE_FLAGS.split() + ["/GL"]))
        for o, f in (l.split("  ", 1) for l in (d / "objects.txt").read_text().splitlines()
                     if not l.startswith("/ALTERNATENAME"))),
        "roots: " + " ".join(var["roots"])]
    alts = [l for l in (d / "objects.txt").read_text().splitlines() if l.startswith("/ALTERNATENAME")]
    if alts:
        out.append("stubbed: " + " ".join(a.split()[1] for a in alts))
    syms = read_map(d / "probe.map")
    ins = read_disasm(d / "probe.disasm.txt")
    starts = sorted((a, n) for n, (a, _) in syms.items())

    def owner(addr):
        best = None
        for a, n in starts:
            if a <= addr:
                best = n
            else:
                break
        return best
    sites, conv, raw_allow = [], [], {}
    if trace_text is not None:
        tracer_lines = [l for l in trace_text.splitlines() if l.startswith(("link.exe exit", "WARNING", "TRACER",
                                                                            "c2_inline_trace", "conventions:"))]
        out += ["tracer: " + l for l in tracer_lines]
        if (d / "trace.jsonl").exists():
            sites = [json.loads(l) for l in (d / "trace.jsonl").read_text().splitlines() if l.strip()]
        extra = d / "trace.extra.json"
        if extra.exists():
            data = json.loads(extra.read_text())
            conv = data.get("conventions", [])
            st = data.get("ltcg_setting") or {}
            if st:
                out.append("ltcg setting: link_size=%s bodies=%s entries=%s bodies_size=%s before=%s after=%s delta=%s"
                           % (st.get("link_size"), st.get("bodies"), st.get("entries"), st.get("bodies_size"),
                              st.get("before"), st.get("after"), st.get("delta")))
            cc = data.get("consts") or {}
            if cc:
                out.append("consts at the first InlCallGraphDecision: SpeedLimit=%s FoldCmpSpeedWeight=%s"
                           % (cc.get("SpeedLimit"), cc.get("FoldCmpSpeedWeight")))
            reg_use = data.get("reg_use") or {}
            calls = {}
            for c in reg_use.get("calls", []):
                if c.get("callee") in var["callees"]:
                    key = (c.get("function"), c.get("callee"), c.get("verdict"), ",".join(c.get("summary") or []))
                    calls[key] = calls.get(key, 0) + 1
            for (fn, callee, verdict, regs), n in sorted(calls.items(), key=lambda kv: str(kv[0])):
                out.append("reg-use call: %s -> %s x%d: %s [%s]" % (fn, callee, n, verdict, regs))
            for name in var["callees"]:
                rec = (reg_use.get("summaries") or {}).get(name)
                if rec:
                    out.append("reg-use summary %s: compiled #%s stored=%s skip=%s regs=%s" % (
                        name, rec.get("order"), rec.get("stored"), rec.get("skip"),
                        ",".join(rec.get("summary") or [])))
            if data.get("dropped"):
                out.append("tracer WARNING: dropped %s %s" % (data["dropped"], data.get("dropped_by")))
        if (d / "trace.raw.jsonl").exists():
            codegen = []
            for l in (d / "trace.raw.jsonl").read_text().splitlines():
                if '"MdmFlexParams"' in l:   # dop2_CodegenUpdate: one per function, in code-generation order
                    ev = json.loads(l)
                    name = ev.get("entry_name") or ev.get("function")
                    if name not in codegen:
                        codegen.append(name)
                if '"MdmAllowFlexParams"' in l:
                    ev = json.loads(l)
                    if "flags20" in ev:
                        raw_allow.setdefault(ev.get("entry_name") or ev.get("function"), []).append(ev)
            out.append("codegen order (MdmFlexParams, after register allocation, per function): " + " ".join(codegen))
    for callee in var["callees"]:
        out += ["", "== " + callee]
        if trace_text is not None:
            mine = [s for s in sites if s.get("callee") == callee]
            inl = sum(1 for s in mine if s["decision"] == "inlined")
            out.append("traced sites: %d (inlined %d, not inlined %d)" % (len(mine), inl, len(mine) - inl))
            for s in mine:
                if s["decision"] != "inlined" or len(mine) <= 12:
                    out.append("  %-24s d%s %-11s budget=%s func_size=%s %s" % (
                        s.get("caller"), s.get("depth"), s["decision"], s.get("budget"), s.get("func_size"),
                        s.get("rule")))
            recs = [c for c in conv if c["function"] == callee]
            if not recs:
                out.append("conventions: no record (not compiled by the link, or inlined before it was compiled)")
            for c in recs:
                params = " ".join("%s=%s%s" % (p.get("name") or "#%d" % p["index"], p["location"],
                                               "(const %s)" % (p["const"].get("value", p["const"].get("symbol")))
                                               if p["const"] else "") for p in c["params"])
                out.append("conventions: custom %s%s declared=%s ret_pop=%s stack_bytes=%s flex=%s xmm=%s "
                           "dead_map=%s params: %s" % (
                               "yes" if c["custom"] else "no", "" if c["custom"] else " (%s)" % c["refused"],
                               c["declared"], c["ret_pop"], c["stack_bytes"], c["flex"], c.get("flex_xmm"),
                               c["dead_map"], params))
                if "sites" in c:
                    out.append("  sites %s inlined_everywhere=%s" % (c["sites"], c.get("inlined_everywhere")))
            for ev in raw_allow.get(callee, []):
                out.append("MdmAllowFlexParams raw: flags20=0x%X flags50=0x%X ret=%s" % (
                    ev.get("flags20", 0), ev.get("flags50", 0), ev.get("ret")))
        if callee in syms:
            addr, obj = syms[callee]
            body, i = [], 0
            nxt = min([a for a, _ in starts if a > addr] or [addr + 0x200])
            body = [t for a, t in ins if addr <= a < nxt]
            out.append("image: %08X (%s), %d instructions, and esp,-8: %s" % (
                addr, obj, len(body), "yes" if any("and esp,0FFFFFFF8h" in t for t in body) else "no"))
            out += ["  | " + t for t in body[:14]]
            callers = {}
            for a, t in ins:
                if re.search(r"\b(call|jmp) %08X\b" % addr, t):
                    callers[owner(a)] = callers.get(owner(a), 0) + 1
            out.append("image call/jmp sites: " + (", ".join("%s x%d" % kv for kv in sorted(callers.items()))
                                                   or "none"))
        else:
            out.append("image: not in the map (inlined everywhere or removed)")
    for name in var.get("show", []):
        out += ["", "== disassembly of " + name]
        if name not in syms:
            out.append("not in the map (inlined or removed)")
            continue
        addr = syms[name][0]
        nxt = min([a for a, _ in starts if a > addr] or [addr + 0x400])
        body = [t for a, t in ins if addr <= a < nxt]
        while body and body[-1] == "int 3":
            body.pop()
        for g in var.get("globals", []):
            if g in syms:
                text = "%08X" % syms[g][0]
                n = sum(1 for t in body if text in t.upper())
                out.append("references to %s (%s): %d" % (g, text, n))
        out += ["  | " + t for t in body]
    return "\n".join(out) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("select", nargs="*", help="probes (P1) or variants (P1a_hdr2); default all")
    parser.add_argument("--out", type=Path, default=ROOT / "build/probes/ltcg_conv")
    parser.add_argument("--no-trace", action="store_true", help="build, link and disassemble only")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--blocks", type=int, default=120, help="blocks (wrapper calls) in Update")
    args = parser.parse_args(argv)
    global UPDATE_BLOCKS
    UPDATE_BLOCKS = args.blocks
    chosen = [v for v in variants() if (not args.select and v["default"]) or v["name"] in args.select
              or (v["probe"] in args.select and v["default"])
              or any(len(s) > 2 and v["name"].startswith(s) for s in args.select)]
    if args.list:
        for v in chosen:
            print("%-20s %s" % (v["name"], v["note"]))
        return 0
    toolchain = probe_toolchain.load_toolchain("sp1")
    probe_toolchain.verify_toolchain(toolchain)
    env = probe_toolchain.toolchain_environment(toolchain)
    env["__COMPAT_LAYER"] = "RunAsInvoker"
    out = args.out if args.out.is_absolute() else (Path.cwd() / args.out)
    status = 0
    for v in chosen:
        try:
            summary = build_variant(v, out.resolve(), toolchain, env, trace=not args.no_trace)
            print(summary)
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            print("%s: %s" % (v["name"], error))
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
