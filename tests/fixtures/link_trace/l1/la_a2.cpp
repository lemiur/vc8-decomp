extern "C" int c2(int);
extern "C" int a2(int x) { return c2(x) * 3; }
