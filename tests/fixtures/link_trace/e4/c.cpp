
__declspec(noinline) int leaf1(int x) { return x * 5 + 1; }
__declspec(noinline) int leaf2(int x) { return x * 5 + 1; }
__declspec(noinline) int mid1(int x) { return leaf1(x) + 7; }
__declspec(noinline) int mid2(int x) { return leaf2(x) + 7; }
__declspec(noinline) int top1(int x) { return mid1(x) * 3; }
__declspec(noinline) int top2(int x) { return mid2(x) * 3; }
static const int tbl[4] = {1, 2, 3, 4};
__declspec(noinline) int usetbl1(int x) { return tbl[x & 3] + 2; }
__declspec(noinline) int usetbl2(int x) { return tbl[x & 3] + 2; }
