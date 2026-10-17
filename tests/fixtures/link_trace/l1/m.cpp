#include <stdlib.h>
extern "C" int a1(int);
extern "C" int b3(int);
extern "C" int n1(int);
extern "C" __declspec(noinline) int same_m(int x) { return x * 13 + 5; }
extern "C" __declspec(noinline) int twin_m(int x) { return a1(x) + 3; }
int main(int c, char** v) { return a1(c) + b3(c) + n1(c) + same_m(c) + twin_m(c) + atoi(v[0]); }
