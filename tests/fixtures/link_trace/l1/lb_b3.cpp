extern "C" __declspec(noinline) int same_b(int x) { return x * 13 + 5; }
extern "C" int b3(int x) { return same_b(x) + 9; }
