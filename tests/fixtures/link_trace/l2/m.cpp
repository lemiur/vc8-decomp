#pragma comment(linker, "/EXPORT:_exp_lib")
#pragma comment(linker, "/EXPORT:_exp_alpha")
#pragma comment(linker, "/ALTERNATENAME:_f_alt=_f_default")
#pragma comment(linker, "/ALTERNATENAME:_g_alt=_g_default")
extern "C" int f_alt();
extern "C" int g_alt();
extern "C" int m_ref();
int main() { return f_alt() + g_alt() + m_ref(); }
