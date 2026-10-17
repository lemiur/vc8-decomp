extern "C" int a3(int);
extern "C" int b4(int);
extern "C" int b2(int x) { return a3(x) + b4(x); }
