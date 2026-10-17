#pragma comment(lib, "ld")
extern "C" int a2(int);
extern "C" int c1(int x) { return a2(x) + 1; }
