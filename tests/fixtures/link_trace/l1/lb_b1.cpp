extern "C" int c1(int);
extern "C" __declspec(noinline) int twin_b(int x) { return c1(x) + 3; }
extern "C" int b1(int x) { return twin_b(x) - 1; }
