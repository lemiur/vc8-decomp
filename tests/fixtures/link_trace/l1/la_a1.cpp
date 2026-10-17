extern "C" int b1(int);
extern "C" __declspec(noinline) int same_a(int x) { return x * 13 + 5; }
extern "C" int a1(int x) { return b1(x) + same_a(x); }
