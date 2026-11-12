#ifndef VC8_CL_LOADUI_H
#define VC8_CL_LOADUI_H

#include <windows.h>

// PDB module 6 (loadui.obj) owns these three public starts. The decorated names
// prove the cdecl ABI, the return types and the seven/one/two-parameter shapes;
// parameter names below are descriptive placeholders. Pointer arguments use the
// era's typedef-wchar_t mode (unsigned short), so the unit is compiled with
// /Zc:wchar_t-.
HRESULT LoadUILibrary(WCHAR *root, WCHAR *name, DWORD flags, HINSTANCE *module,
    WCHAR *resolved_path, UINT resolved_chars, DWORD *language);
HINSTANCE LoadSearchPath(WCHAR *resolved_path, UINT resolved_chars);
HINSTANCE LoadCLUI(WCHAR *resolved_path, UINT resolved_chars);

#endif
