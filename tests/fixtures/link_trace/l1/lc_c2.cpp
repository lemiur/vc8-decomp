extern "C" int b2(int);
extern "C" int d1(int);
extern "C" int c2(int x) { return b2(x) + d1(x); }
