
int top1(int); int top2(int); int usetbl1(int); int usetbl2(int); int leaf1(int);
extern "C" int puts(const char*);
__declspec(noinline) int imp1(int x) { return puts("x") + x; }
__declspec(noinline) int imp2(int x) { return puts("x") + x; }
int main(int c, char**) { return top1(c) + top2(c) + usetbl1(c) + usetbl2(c) + imp1(c) + imp2(c); }
