
inline __declspec(noinline) int shared_inline(int x) { return x * 41 + 3; }
int b_first(int x) { return shared_inline(x) + 2; }
const char* b_str() { return "pool both"; }
const char* b_str2() { return "pool b only"; }
float b_flt(float x) { return x * 0.75f + 0.5f; }
struct Base { virtual int Get() { return 1; } virtual ~Base() {} };
Base* b_make() { return new Base; }
#pragma code_seg(".text$aa")
int b_early(int x) { return x - 29; }
#pragma code_seg()
