
#include <stdio.h>
inline __declspec(noinline) int shared_inline(int x) { return x * 41 + 3; }
int a_first(int x) { return shared_inline(x) + 1; }
const char* a_str() { return "pool both"; }
float a_flt(float x) { return x * 0.75f; }
struct Base { virtual int Get() { return 1; } virtual ~Base() {} };
int a_vt(Base* b) { return b->Get(); }
Base* a_make() { return new Base; }
int a_eh(int x) { try { if (x) throw x; } catch (int y) { return y; } return 0; }
#pragma code_seg(".text$zz")
int a_late(int x) { return x - 9; }
#pragma code_seg(".text$aa")
int a_early(int x) { return x - 19; }
#pragma code_seg()
int a_last(int x) { return x * x * x; }
