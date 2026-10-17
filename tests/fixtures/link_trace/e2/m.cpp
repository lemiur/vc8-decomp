
struct Base { virtual int Get() { return 1; } virtual ~Base() {} };
int a_first(int); const char* a_str(); float a_flt(float); int a_vt(Base*); Base* a_make(); int a_eh(int);
int a_late(int); int a_early(int); int a_last(int);
int b_first(int); const char* b_str(); const char* b_str2(); float b_flt(float); Base* b_make(); int b_early(int);
int main(int argc, char** argv) {
    Base* p = argc > 5 ? a_make() : b_make();
    return a_first(argc) + b_first(argc) + *a_str() + *b_str() + *b_str2() + (int)a_flt((float)argc)
        + (int)b_flt((float)argc) + a_vt(p) + a_eh(argc) + a_late(argc) + a_early(argc) + a_last(argc) + b_early(argc);
}
