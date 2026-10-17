extern "C" int c3(int);
extern "C" __declspec(noinline) int same_n(int x) { return x * 13 + 5; }
extern "C" int n1(int x) { return c3(x) + same_n(x) + 2; }
