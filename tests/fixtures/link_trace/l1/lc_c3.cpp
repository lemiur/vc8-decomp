#pragma comment(lib, "le")
extern "C" int e1(int);
extern "C" __declspec(noinline) int same_c(int x) { return x * 13 + 5; }
extern "C" int c3(int x) { return e1(x) + same_c(x); }
