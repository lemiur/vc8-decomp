// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The Win32 calls the Python tools made through ctypes, winreg, msvcrt, socket and getpass (see win.h). */
#include "fs_priv.h"

#include <bcrypt.h>
#include <conio.h>
#include <dbghelp.h>
#include <io.h>
#include <lmcons.h>
#include <tlhelp32.h>

/* ---- registry --------------------------------------------------------------------------------------------------- */

static HKEY root_key(DkRegRoot r) {
    switch (r) {
    case DK_HKEY_CLASSES_ROOT: return HKEY_CLASSES_ROOT;
    case DK_HKEY_CURRENT_USER: return HKEY_CURRENT_USER;
    case DK_HKEY_LOCAL_MACHINE: return HKEY_LOCAL_MACHINE;
    case DK_HKEY_USERS: return HKEY_USERS;
    default: return HKEY_CURRENT_CONFIG;
    }
}

bool dk_reg_get(DkArena *a, DkRegRoot root, const char *subkey, unsigned wow64, const char *name, DkRegValue *out) {
    memset(out, 0, sizeof *out);
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    HKEY key = NULL;
    LSTATUS st = RegOpenKeyExW(root_key(root), dk_fs_u8_to_w(sc, subkey ? subkey : ""), 0, KEY_READ | wow64, &key);
    if (st != ERROR_SUCCESS) {
        dk_io_fail_win((unsigned)st, NULL, NULL);
        fs_tmp_done(sc, mk);
        return false;
    }
    wchar_t *vn = dk_fs_u8_to_w(sc, name ? name : "");
    DWORD type = 0, size = 0;
    st = RegQueryValueExW(key, vn, NULL, &type, NULL, &size);
    BYTE *data = NULL;
    while (st == ERROR_SUCCESS || st == ERROR_MORE_DATA) {
        data = (BYTE *)dk_alloc_noz(sc, (size_t)size + 4);
        DWORD sz2 = size;
        st = RegQueryValueExW(key, vn, NULL, &type, data, &sz2);
        if (st == ERROR_MORE_DATA) continue;
        size = sz2;
        break;
    }
    RegCloseKey(key);
    if (st != ERROR_SUCCESS) {
        dk_io_fail_win((unsigned)st, NULL, NULL);
        fs_tmp_done(sc, mk);
        return false;
    }
    out->type = type;
    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ: {
        size_t units = size / sizeof(wchar_t);
        size_t k = 0;
        while (k < units && ((wchar_t *)data)[k]) k++; /* winreg stops at the first NUL */
        char *u = dk_fs_w_to_u8(a, (wchar_t *)data, (i64)k);
        out->str.p = u;
        out->str.n = strlen(u);
        break;
    }
    case REG_DWORD:
        out->num = size >= 4 ? *(DWORD *)data : 0;
        break;
    case REG_QWORD:
        out->num = size >= 8 ? *(u64 *)data : 0;
        break;
    case REG_MULTI_SZ: {
        const wchar_t *w = (const wchar_t *)data, *end = w + size / sizeof(wchar_t);
        while (w < end && *w) {
            size_t k = wcslen(w);
            char *u = dk_fs_w_to_u8(a, w, (i64)k);
            DkStr s = {u, strlen(u)};
            dk_vec_push(&out->multi, s);
            w += k + 1;
        }
        break;
    }
    default: {
        out->bin = fs_dup(a, (const char *)data, size);
        break;
    }
    }
    fs_tmp_done(sc, mk);
    return true;
}

bool dk_reg_get_string(DkArena *a, DkRegRoot root, const char *subkey, unsigned wow64, const char *name, DkStr *out) {
    DkRegValue v;
    if (!dk_reg_get(a, root, subkey, wow64, name, &v)) return false;
    if (v.type != REG_SZ && v.type != REG_EXPAND_SZ) {
        dk_vec_free(&v.multi);
        dk_io_clear();
        return false;
    }
    *out = v.str;
    return true;
}

/* ---- named mutexes ------------------------------------------------------------------------------------------------ */

struct DkNamedMutex {
    HANDLE h;
};

DkNamedMutex *dk_named_mutex_open(const char *name) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    size_t nl = strlen(name);
    char *full = (char *)dk_alloc_noz(sc, nl + 16);
    snprintf(full, nl + 16, "Global\\%s", name);
    HANDLE h = CreateMutexW(NULL, FALSE, dk_fs_u8_to_w(sc, full));
    if (!h) {
        snprintf(full, nl + 16, "Local\\%s", name);
        h = CreateMutexW(NULL, FALSE, dk_fs_u8_to_w(sc, full));
    }
    fs_tmp_done(sc, mk);
    if (!h) {
        dk_fs_fail_last(NULL, NULL);
        return NULL;
    }
    DkNamedMutex *m = (DkNamedMutex *)dk_xmalloc(sizeof *m);
    m->h = h;
    return m;
}

int dk_named_mutex_wait(DkNamedMutex *m, u32 timeout_ms) {
    DWORD r = WaitForSingleObject(m->h, timeout_ms);
    switch (r) {
    case WAIT_OBJECT_0: return DK_WAIT_ACQUIRED;
    case WAIT_ABANDONED: return DK_WAIT_ABANDONED;
    case WAIT_TIMEOUT: return DK_WAIT_TIMEOUT;
    default: return DK_WAIT_FAILED;
    }
}

bool dk_named_mutex_release(DkNamedMutex *m) {
    if (!ReleaseMutex(m->h)) {
        dk_fs_fail_last(NULL, NULL);
        return false;
    }
    return true;
}

void dk_named_mutex_close(DkNamedMutex *m) {
    if (!m) return;
    CloseHandle(m->h);
    dk_xfree(m);
}

bool dk_named_mutex_exists(const char *full_name) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    HANDLE h = OpenMutexW(SYNCHRONIZE, FALSE, dk_fs_u8_to_w(sc, full_name));
    fs_tmp_done(sc, mk);
    if (!h) return false;
    CloseHandle(h);
    return true;
}

/* ---- byte-range locks ------------------------------------------------------------------------------------------- */

bool dk_filelock_try(void *handle, i64 offset, i64 len) {
    OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    ov.Offset = (DWORD)offset;
    ov.OffsetHigh = (DWORD)((u64)offset >> 32);
    if (LockFileEx((HANDLE)handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, (DWORD)len,
                   (DWORD)((u64)len >> 32), &ov))
        return true;
    /* msvcrt.locking reports a held lock as OSError(EACCES, "Permission denied") */
    dk_io_fail_errno(EACCES, NULL, NULL);
    return false;
}

bool dk_filelock_unlock(void *handle, i64 offset, i64 len) {
    OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    ov.Offset = (DWORD)offset;
    ov.OffsetHigh = (DWORD)((u64)offset >> 32);
    if (UnlockFileEx((HANDLE)handle, 0, (DWORD)len, (DWORD)((u64)len >> 32), &ov)) return true;
    dk_io_fail_errno(EACCES, NULL, NULL);
    return false;
}

/* ---- processes -------------------------------------------------------------------------------------------------- */


u32 dk_getppid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W e;
    e.dwSize = sizeof e;
    u32 me = GetCurrentProcessId(), parent = 0;
    for (BOOL ok = Process32FirstW(snap, &e); ok; ok = Process32NextW(snap, &e))
        if (e.th32ProcessID == me) {
            parent = e.th32ParentProcessID;
            break;
        }
    CloseHandle(snap);
    return parent;
}

bool dk_pid_alive(u32 pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return GetLastError() == ERROR_ACCESS_DENIED;
    DWORD code = 0;
    BOOL ok = GetExitCodeProcess(h, &code);
    CloseHandle(h);
    return ok && code == STILL_ACTIVE;
}

char *dk_proc_image_path(DkArena *a, u32 pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return NULL;
    wchar_t buf[32768];
    DWORD n = (DWORD)DK_ARRAY_LEN(buf);
    char *r = NULL;
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) r = dk_fs_w_to_u8(a, buf, (i64)n);
    CloseHandle(h);
    return r;
}

bool dk_proc_creation_time(u32 pid, u64 *filetime) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        dk_fs_fail_last(NULL, NULL);
        return false;
    }
    FILETIME c, e, k, u;
    bool ok = GetProcessTimes(h, &c, &e, &k, &u) != 0;
    if (ok) *filetime = ((u64)c.dwHighDateTime << 32) | c.dwLowDateTime;
    else dk_fs_fail_last(NULL, NULL);
    CloseHandle(h);
    return ok;
}

bool dk_proc_list(DkArena *a, DkProcInfoVec *out) {
    out->v = NULL;
    out->n = out->cap = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        dk_fs_fail_last(NULL, NULL);
        return false;
    }
    PROCESSENTRY32W e;
    e.dwSize = sizeof e;
    for (BOOL ok = Process32FirstW(snap, &e); ok; ok = Process32NextW(snap, &e)) {
        DkProcInfo pi;
        pi.pid = e.th32ProcessID;
        pi.parent_pid = e.th32ParentProcessID;
        pi.threads = e.cntThreads;
        char *u = dk_fs_w_to_u8(a, e.szExeFile, -1);
        pi.exe.p = u;
        pi.exe.n = strlen(u);
        dk_vec_push(out, pi);
    }
    CloseHandle(snap);
    return true;
}

bool dk_set_priority_class(u32 priority_class) {
    if (SetPriorityClass(GetCurrentProcess(), priority_class)) return true;
    dk_fs_fail_last(NULL, NULL);
    return false;
}

bool dk_set_priority_below_normal(void) { return dk_set_priority_class(BELOW_NORMAL_PRIORITY_CLASS); }


/* ---- machine and user -------------------------------------------------------------------------------------------- */

char *dk_hostname(DkArena *a) {
    wchar_t buf[256];
    DWORD n = (DWORD)DK_ARRAY_LEN(buf);
    if (GetComputerNameExW(ComputerNameDnsHostname, buf, &n)) return dk_fs_w_to_u8(a, buf, (i64)n);
    n = (DWORD)DK_ARRAY_LEN(buf);
    if (GetComputerNameW(buf, &n)) return dk_fs_w_to_u8(a, buf, (i64)n);
    return dk_strdup(a, "localhost");
}

char *dk_getuser(DkArena *a) {
    static const char *const names[] = {"LOGNAME", "USER", "LNAME", "USERNAME"};
    for (size_t i = 0; i < DK_ARRAY_LEN(names); i++) {
        char *v = dk_getenv(a, names[i]);
        if (v && *v) return v;
    }
    wchar_t buf[UNLEN + 1];
    DWORD n = (DWORD)DK_ARRAY_LEN(buf);
    if (GetUserNameW(buf, &n) && n > 0) return dk_fs_w_to_u8(a, buf, (i64)n - 1);
    return dk_strdup(a, "");
}

/* ---- volumes ---------------------------------------------------------------------------------------------------- */

static bool volume_root(DkArena *sc, const char *path, wchar_t **root) {
    char *abs = dk_path_abspath(sc, path);
    wchar_t *w = dk_fs_u8_to_w(sc, abs);
    wchar_t *buf = (wchar_t *)dk_alloc_noz(sc, 1024 * sizeof(wchar_t));
    if (!GetVolumePathNameW(w, buf, 1024)) return false;
    *root = buf;
    return true;
}

bool dk_volume_info(DkArena *a, const char *path, u32 *serial, char **fs_name) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *root;
    bool ok = false;
    if (volume_root(sc, path, &root)) {
        DWORD ser = 0, maxlen = 0, flags = 0;
        wchar_t fs[64];
        if (GetVolumeInformationW(root, NULL, 0, &ser, &maxlen, &flags, fs, 64)) {
            *serial = ser;
            *fs_name = dk_fs_w_to_u8(a, fs, -1);
            ok = true;
        }
    }
    fs_tmp_done(sc, mk);
    return ok;
}

u32 dk_cluster_size(const char *path) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *root;
    u32 r = 0;
    if (volume_root(sc, path, &root)) {
        DWORD spc, bps, free_c, total;
        if (GetDiskFreeSpaceW(root, &spc, &bps, &free_c, &total)) r = spc * bps;
    }
    fs_tmp_done(sc, mk);
    return r;
}

bool dk_file_clone(const char *src, const char *dst, u32 cluster) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    bool ok = false;
    HANDLE hs = CreateFileW(dk_fs_wpath(sc, src), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0,
                            NULL);
    if (hs != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz;
        if (cluster && GetFileSizeEx(hs, &sz)) {
            HANDLE hd = CreateFileW(dk_fs_wpath(sc, dst), GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL, CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL, NULL);
            if (hd != INVALID_HANDLE_VALUE) {
                FILE_END_OF_FILE_INFO eof;
                eof.EndOfFile = sz;
                ok = SetFileInformationByHandle(hd, FileEndOfFileInfo, &eof, sizeof eof) != 0;
                if (ok && sz.QuadPart) {
                    DUPLICATE_EXTENTS_DATA d;
                    d.FileHandle = hs;
                    d.SourceFileOffset.QuadPart = 0;
                    d.TargetFileOffset.QuadPart = 0;
                    /* whole clusters: the last one may run past the end of both files */
                    d.ByteCount.QuadPart = (sz.QuadPart + cluster - 1) / cluster * cluster;
                    DWORD ret = 0;
                    ok = DeviceIoControl(hd, FSCTL_DUPLICATE_EXTENTS_TO_FILE, &d, sizeof d, NULL, 0, &ret, NULL) != 0;
                }
                if (!ok) {
                    FILE_DISPOSITION_INFO del = {TRUE};
                    SetFileInformationByHandle(hd, FileDispositionInfo, &del, sizeof del);
                }
                CloseHandle(hd);
            }
        }
        CloseHandle(hs);
    }
    fs_tmp_done(sc, mk);
    if (ok) {
        i64 a1 = 0, a2 = 0;
        ok = dk_getsize(src, &a1) && dk_getsize(dst, &a2) && a1 == a2;
    }
    return ok;
}

/* ---- console ---------------------------------------------------------------------------------------------------- */

bool dk_isatty(int fd) {
    if (fd < 0 || fd > 2) return false;
    HANDLE h = GetStdHandle(fd == 0 ? STD_INPUT_HANDLE : fd == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    DWORD mode;
    return h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode);
}

int dk_console_width(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO ci;
    if (h && h != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(h, &ci)) {
        int w = ci.srWindow.Right - ci.srWindow.Left + 1;
        if (w > 0) return w;
    }
    return 80;
}

bool dk_kbhit(void) { return _kbhit() != 0; }
u32 dk_getwch(void) { return (u32)_getwch(); }

/* ---- symbols and crypto ------------------------------------------------------------------------------------------ */

static SRWLOCK g_dbghelp_lock = SRWLOCK_INIT;

DkStr dk_undecorate_symbol(DkArena *a, const char *name, u32 flags) {
    char buf[4096];
    AcquireSRWLockExclusive(&g_dbghelp_lock);
    DWORD n = UnDecorateSymbolName(name, buf, (DWORD)sizeof buf, flags);
    ReleaseSRWLockExclusive(&g_dbghelp_lock);
    return fs_dup(a, buf, n);
}

bool dk_aes128_decrypt(const u8 key[16], const u8 *data, size_t n, bool cbc, u8 *out) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hk = NULL;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return false;
    const wchar_t *mode = cbc ? BCRYPT_CHAIN_MODE_CBC : BCRYPT_CHAIN_MODE_ECB;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)mode, (ULONG)((wcslen(mode) + 1) * sizeof(wchar_t)), 0) == 0 &&
        BCryptGenerateSymmetricKey(alg, &hk, NULL, 0, (PUCHAR)key, 16, 0) == 0) {
        u8 iv[16] = {0};
        ULONG got = 0;
        ok = BCryptDecrypt(hk, (PUCHAR)data, (ULONG)n, NULL, cbc ? iv : NULL, cbc ? 16 : 0, out, (ULONG)n, &got, 0) == 0;
    }
    if (hk) BCryptDestroyKey(hk);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}
