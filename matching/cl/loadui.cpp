// PDB DBI module 6: loadui.obj. Original source filename and line layout are
// unresolved; parameter and local names below are descriptive placeholders.
#include "../../include/cl/loadui.h"
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

// FUNCTION: cl 0x409330
// SYMBOL: ?LoadUILibrary@@YAJPAG0KPAPAUHINSTANCE__@@0IPAK@Z
// Returns S_OK with the chosen UI language and module, or E_FAIL. Retail walks
// the three candidate LCIDs, then falls back to the first subdirectory whose
// directory name converts to a language id.
HRESULT LoadUILibrary(WCHAR *root, WCHAR *name, DWORD flags, HINSTANCE *module,
    WCHAR *resolved_path, UINT resolved_chars, DWORD *language)
{
    WCHAR path[1024] = L"";
    DWORD selected_language = (DWORD)-1;
    HRESULT result = E_FAIL;

    if (!*root || !*name)
        return E_INVALIDARG;
    if (module)
        *module = NULL;

    wcsncpy_s(path, _countof(path), root, _TRUNCATE);
    if (path[wcslen(path) - 1] != L'\\')
        wcsncat_s(path, _countof(path), L"\\", _TRUNCATE);
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
        return E_FAIL;

    int root_length = min(wcslen(path), _countof(path) - 1);
    LCID candidates[3];
    candidates[0] = GetUserDefaultUILanguage();
    candidates[1] = MAKELCID(MAKELANGID(PRIMARYLANGID(candidates[0]), SUBLANG_DEFAULT),
        SORTIDFROMLCID(candidates[0]));
    candidates[2] = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);

    for (int index = 0; index < _countof(candidates); ++index) {
        int previous;
        for (previous = 0; previous < index; ++previous)
            if (candidates[previous] == candidates[index])
                break;
        if (previous < index)
            continue;

        path[root_length] = L'\0';
        WCHAR language_text[10];
        _itow_s(candidates[index], language_text, _countof(language_text), 10);
        wcsncat_s(path, _countof(path), language_text, _TRUNCATE);
        wcsncat_s(path, _countof(path), L"\\", _TRUNCATE);
        wcsncat_s(path, _countof(path), name, _TRUNCATE);
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
            continue;

        UINT console_page = GetConsoleOutputCP();
        if (candidates[index] != MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US)) {
            if (PRIMARYLANGID(candidates[index]) == LANG_ARABIC ||
                PRIMARYLANGID(candidates[index]) == LANG_HEBREW)
                continue;
            WCHAR page_text[12];
            GetLocaleInfoW(MAKELCID((LANGID)candidates[index], SORT_DEFAULT),
                LOCALE_IDEFAULTCODEPAGE, page_text, _countof(page_text));
            int oem_page = _wtoi(page_text);
            GetLocaleInfoW(MAKELCID((LANGID)candidates[index], SORT_DEFAULT),
                LOCALE_IDEFAULTANSICODEPAGE, page_text, _countof(page_text));
            int ansi_page = _wtoi(page_text);
            if (console_page != CP_UTF8 && console_page != oem_page &&
                console_page != ansi_page)
                continue;
        }
        selected_language = candidates[index];
        result = S_OK;
        break;
    }

    if (FAILED(result)) {
        path[root_length] = L'\0';
        wcsncat_s(path, _countof(path), L"*.*", _TRUNCATE);
        WIN32_FIND_DATAW data;
        HANDLE search = FindFirstFileW(path, &data);
        int pattern_length = min(wcslen(path), _countof(path) - 1);
        if (search == INVALID_HANDLE_VALUE)
            goto Finished;
        while (FindNextFileW(search, &data)) {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                wcscmp(data.cFileName, L".") == 0 ||
                wcscmp(data.cFileName, L"..") == 0)
                continue;
            path[pattern_length - 3] = L'\0';
            wcsncat_s(path, _countof(path), data.cFileName, _TRUNCATE);
            wcsncat_s(path, _countof(path), L"\\", _TRUNCATE);
            wcsncat_s(path, _countof(path), name, _TRUNCATE);
            if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
                selected_language = _wtol(data.cFileName);
                result = S_OK;
                break;
            }
        }
        FindClose(search);
        if (FAILED(result))
            goto Finished;
    }

    if (language)
        *language = selected_language;
    if (module) {
        *module = LoadLibraryExW(path, NULL, flags);
        result = *module ? S_OK : E_FAIL;
    }
    if (resolved_path)
        wcscpy_s(resolved_path, resolved_chars, path);
Finished:
    return result;
}

// FUNCTION: cl 0x409755
// SYMBOL: ?LoadSearchPath@@YAPAUHINSTANCE__@@PAGI@Z
// Walks the PATH environment string and returns the first directory that holds
// a loadable UI library, writing the resolved path when asked.
HINSTANCE LoadSearchPath(WCHAR *resolved_path, UINT resolved_chars)
{
    WCHAR *environment = NULL;
    HINSTANCE module = NULL;
    WCHAR directory[1024];

    _wdupenv_s(&environment, NULL, L"PATH");
    WCHAR *cursor = environment;
    if (cursor) {
        while (*cursor) {
            while (*cursor == L' ' || *cursor == L';')
                ++cursor;
            if (!*cursor)
                break;
            int length = 0;
            WCHAR *output = directory;
            while (*cursor && *cursor != L';') {
                if (++length >= 1024)
                    break;
                *output++ = *cursor++;
            }
            *output = L'\0';
            if (length != 0 && length < 1024) {
                LoadUILibrary(directory, L"clui.dll", LOAD_LIBRARY_AS_DATAFILE,
                    &module, resolved_path, resolved_chars, NULL);
                if (module)
                    break;
            }
        }
    }
    free(environment);
    return module;
}

// FUNCTION: cl 0x40983b
// SYMBOL: ?LoadCLUI@@YAPAUHINSTANCE__@@PAGI@Z
// Tries the UI library next to the running executable, then along PATH.
HINSTANCE LoadCLUI(WCHAR *resolved_path, UINT resolved_chars)
{
    WCHAR executable[1024];
    WCHAR loaded_path[1024];
    HINSTANCE module;

    GetModuleFileNameW(GetModuleHandleW(NULL), executable, _countof(executable));
    WCHAR *end = executable + min(wcslen(executable), _countof(executable) - 1) - 1;
    while (*end != L'\\' && end != executable)
        --end;
    *end = L'\0';
    LoadUILibrary(executable, L"clui.dll", LOAD_LIBRARY_AS_DATAFILE, &module,
        loaded_path, _countof(loaded_path), NULL);
    if (!module)
        module = LoadSearchPath(loaded_path, _countof(loaded_path));
    if (module && resolved_path)
        wcscpy_s(resolved_path, resolved_chars, loaded_path);
    return module;
}
