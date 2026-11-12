// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* stat and the os / os.path file functions: exists/isfile/isdir/islink, getsize/getmtime, mkdir/makedirs, remove,
 * rmdir, rename/replace, getcwd/chdir, utime, chmod, links and junctions, the environment, and the directory
 * listings (scandir, listdir, walk) in the order the file system returns them. Errors are recorded as the OSError
 * Python would raise ([WinError n] with the system text, the path quoted). */
#include "fs_priv.h"

#include <stdio.h>
#include <winioctl.h>

/* ---- stat ------------------------------------------------------------------------------------------------------ */

static u32 attrs_to_mode(DWORD attr) {
    u32 m = 0;
    if (attr & FILE_ATTRIBUTE_DIRECTORY) m |= DK_S_IFDIR | 0111;
    else m |= DK_S_IFREG;
    m |= (attr & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666;
    return m;
}

static void fill_times(DkStat *st, FILETIME at, FILETIME mt, FILETIME ct) {
    /* CPython: sec = ticks / 1e7 - 11644473600, nsec = ticks % 1e7 * 100; float = sec + nsec * 1e-9 */
    struct { FILETIME f; i64 *ns; double *d; } t[3] = {{at, &st->atime_ns, &st->atime}, {mt, &st->mtime_ns, &st->mtime},
                                                       {ct, &st->ctime_ns, &st->ctime}};
    for (int i = 0; i < 3; i++) {
        i64 in = (i64)(((u64)t[i].f.dwHighDateTime << 32) | t[i].f.dwLowDateTime);
        i64 sec = in / 10000000 - 11644473600LL;
        int nsec = (int)(in % 10000000) * 100;
        *t[i].ns = sec * 1000000000LL + nsec;
        *t[i].d = (double)sec + (double)nsec * 1e-9;
    }
}

bool dk_fs_stat_handle(HANDLE h, const char *path, DkStat *st) {
    BY_HANDLE_FILE_INFORMATION bi;
    if (!GetFileInformationByHandle(h, &bi)) {
        DWORD e = GetLastError();
        if (GetFileType(h) != FILE_TYPE_DISK) {
            /* a pipe or a console: CPython reports a character device / FIFO; the tools never stat these */
            memset(st, 0, sizeof *st);
            st->mode = 0020000;
            return true;
        }
        SetLastError(e);
        dk_fs_fail_last(path, NULL);
        return false;
    }
    memset(st, 0, sizeof *st);
    FILE_ID_INFO idi;
    FILE_ATTRIBUTE_TAG_INFO tag = {0};
    st->dev = bi.dwVolumeSerialNumber;
    st->ino = ((u64)bi.nFileIndexHigh << 32) | bi.nFileIndexLow;
    if (GetFileInformationByHandleEx(h, FileIdInfo, &idi, sizeof idi)) {
        st->dev = idi.VolumeSerialNumber;
        memcpy(&st->ino, &idi.FileId.Identifier[0], sizeof st->ino);
        memcpy(&st->ino_hi, &idi.FileId.Identifier[8], sizeof st->ino_hi); /* CPython's st_ino is all 128 bits */
    }
    if ((bi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
        GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tag, sizeof tag))
        st->reparse_tag = tag.ReparseTag;
    st->file_attributes = bi.dwFileAttributes;
    st->mode = attrs_to_mode(bi.dwFileAttributes);
    if (st->reparse_tag == DK_IO_REPARSE_TAG_SYMLINK) st->mode = (st->mode & ~(u32)DK_S_IFMT) | DK_S_IFLNK;
    st->nlink = bi.nNumberOfLinks;
    st->size = (i64)(((u64)bi.nFileSizeHigh << 32) | bi.nFileSizeLow);
    fill_times(st, bi.ftLastAccessTime, bi.ftLastWriteTime, bi.ftCreationTime);
    return true;
}

/* Directory-entry data of path (attributes_from_dir in CPython), used when the file cannot be opened. */
static bool stat_from_find(const wchar_t *wpath, DkStat *st) {
    WIN32_FIND_DATAW fd;
    HANDLE fh = FindFirstFileW(wpath, &fd);
    if (fh == INVALID_HANDLE_VALUE) return false;
    FindClose(fh);
    memset(st, 0, sizeof *st);
    st->file_attributes = fd.dwFileAttributes;
    st->mode = attrs_to_mode(fd.dwFileAttributes);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) st->reparse_tag = fd.dwReserved0;
    if (st->reparse_tag == DK_IO_REPARSE_TAG_SYMLINK) st->mode = (st->mode & ~(u32)DK_S_IFMT) | DK_S_IFLNK;
    st->nlink = 1;
    st->size = (i64)(((u64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow);
    fill_times(st, fd.ftLastAccessTime, fd.ftLastWriteTime, fd.ftCreationTime);
    return true;
}

static bool stat_impl(const char *path, DkStat *st, bool traverse) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *w = dk_fs_wpath(sc, path);
    DWORD flags = FILE_FLAG_BACKUP_SEMANTICS | (traverse ? 0 : FILE_FLAG_OPEN_REPARSE_POINT);
    HANDLE h = CreateFileW(w, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, flags, NULL);
    bool ok;
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        ok = false;
        if (e == ERROR_ACCESS_DENIED || e == ERROR_SHARING_VIOLATION) {
            DkStat tmp;
            if (stat_from_find(w, &tmp) &&
                !((tmp.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                  (traverse || tmp.reparse_tag != DK_IO_REPARSE_TAG_SYMLINK))) {
                *st = tmp;
                ok = true;
            }
        } else if (e == ERROR_CANT_ACCESS_FILE && traverse) {
            /* an unhandled reparse point: report the point itself */
            h = CreateFileW(w, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                            OPEN_EXISTING, flags | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                ok = dk_fs_stat_handle(h, path, st);
                CloseHandle(h);
                fs_tmp_done(sc, mk);
                return ok;
            }
        }
        if (!ok) {
            SetLastError(e);
            dk_fs_fail_last(path, NULL);
        }
    } else {
        ok = dk_fs_stat_handle(h, path, st);
        CloseHandle(h);
    }
    fs_tmp_done(sc, mk);
    return ok;
}

bool dk_stat(const char *p, DkStat *st) { return stat_impl(p, st, true); }
bool dk_lstat(const char *p, DkStat *st) { return stat_impl(p, st, false); }

/* Attributes of an existing path without opening it (os.path.exists/isdir/isfile): false when it does not exist. */
static bool quick_attrs(const char *p, DkStat *st) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *w = dk_fs_wpath(sc, p);
    WIN32_FILE_ATTRIBUTE_DATA d;
    bool ok;
    if (GetFileAttributesExW(w, GetFileExInfoStandard, &d) && !(d.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        memset(st, 0, sizeof *st);
        st->file_attributes = d.dwFileAttributes;
        st->mode = attrs_to_mode(d.dwFileAttributes);
        ok = true;
    } else ok = stat_impl(p, st, true);
    fs_tmp_done(sc, mk);
    return ok;
}

bool dk_exists(const char *p) {
    DkStat st;
    return quick_attrs(p, &st);
}
bool dk_isdir(const char *p) {
    DkStat st;
    return quick_attrs(p, &st) && (st.file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}
bool dk_isfile(const char *p) {
    DkStat st;
    return quick_attrs(p, &st) && !(st.file_attributes & FILE_ATTRIBUTE_DIRECTORY);
}
bool dk_lexists(const char *p) {
    DkStat st;
    return stat_impl(p, &st, false);
}
bool dk_islink(const char *p) {
    DkStat st;
    return stat_impl(p, &st, false) && DK_S_ISLNK(st.mode);
}
bool dk_isjunction(const char *p) {
    DkStat st;
    return stat_impl(p, &st, false) && (st.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
           st.reparse_tag == DK_IO_REPARSE_TAG_MOUNT_POINT;
}
bool dk_getsize(const char *p, i64 *size) {
    DkStat st;
    if (!dk_stat(p, &st)) return false;
    *size = st.size;
    return true;
}
bool dk_getmtime(const char *p, double *seconds) {
    DkStat st;
    if (!dk_stat(p, &st)) return false;
    *seconds = st.mtime;
    return true;
}

/* ---- folders and files -------------------------------------------------------------------------------------------- */

bool dk_mkdir(const char *p) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    bool ok = CreateDirectoryW(dk_fs_wpath(sc, p), NULL) != 0;
    if (!ok) dk_fs_fail_last(p, NULL);
    fs_tmp_done(sc, mk);
    return ok;
}

bool dk_makedirs(const char *name, bool exist_ok) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    DkStr head, tail;
    dk_path_split(name, &head, &tail);
    if (tail.n == 0) {
        char *h0 = fs_cz(sc, head);
        dk_path_split(h0, &head, &tail);
    }
    bool ok = true;
    if (head.n && tail.n) {
        char *hz = fs_cz(sc, head);
        if (!dk_exists(hz)) {
            if (!dk_makedirs(hz, exist_ok) && !dk_io_is(EEXIST)) ok = false; /* a racing creator is fine */
            if (ok && tail.n == 1 && tail.p[0] == '.') {
                fs_tmp_done(sc, mk);
                return true; /* xxx/newdir/. exists if xxx/newdir exists */
            }
        }
    }
    if (ok) {
        if (!dk_mkdir(name)) {
            if (!exist_ok || !dk_isdir(name)) ok = false;
        }
    }
    fs_tmp_done(sc, mk);
    return ok;
}

static BOOL py_delete_file(const wchar_t *w) {
    WIN32_FILE_ATTRIBUTE_DATA info;
    bool is_dir = false, is_link = false;
    if (GetFileAttributesExW(w, GetFileExInfoStandard, &info)) {
        is_dir = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (is_dir && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            WIN32_FIND_DATAW fd;
            HANDLE fh = FindFirstFileW(w, &fd);
            if (fh != INVALID_HANDLE_VALUE) {
                is_link = fd.dwReserved0 == IO_REPARSE_TAG_SYMLINK || fd.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT;
                FindClose(fh);
            }
        }
    }
    if (is_dir && is_link) return RemoveDirectoryW(w);
    return DeleteFileW(w);
}

bool dk_remove(const char *p) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    bool ok = py_delete_file(dk_fs_wpath(sc, p)) != 0;
    if (!ok) dk_fs_fail_last(p, NULL);
    fs_tmp_done(sc, mk);
    return ok;
}

bool dk_rmdir(const char *p) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    bool ok = RemoveDirectoryW(dk_fs_wpath(sc, p)) != 0;
    if (!ok) dk_fs_fail_last(p, NULL);
    fs_tmp_done(sc, mk);
    return ok;
}

static bool move_impl(const char *src, const char *dst, DWORD flags) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    bool ok = MoveFileExW(dk_fs_wpath(sc, src), dk_fs_wpath(sc, dst), flags) != 0;
    if (!ok) dk_fs_fail_last(src, dst);
    fs_tmp_done(sc, mk);
    return ok;
}
bool dk_rename(const char *src, const char *dst) { return move_impl(src, dst, 0); }
bool dk_replace(const char *src, const char *dst) { return move_impl(src, dst, MOVEFILE_REPLACE_EXISTING); }

char *dk_getcwd(DkArena *a) {
    DWORD n = GetCurrentDirectoryW(0, NULL);
    wchar_t *w = (wchar_t *)dk_alloc_noz(a, ((size_t)n + 1) * sizeof(wchar_t));
    DWORD got = GetCurrentDirectoryW(n, w);
    w[got] = 0;
    return dk_fs_w_to_u8(a, w, (i64)got);
}

bool dk_chdir(const char *p) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    bool ok = SetCurrentDirectoryW(dk_fs_wpath(sc, p)) != 0;
    if (!ok) dk_fs_fail_last(p, NULL);
    fs_tmp_done(sc, mk);
    return ok;
}

static FILETIME ns_to_filetime(i64 ns) {
    i64 sec = ns / 1000000000LL, rem = ns % 1000000000LL;
    if (rem < 0) {
        rem += 1000000000LL;
        sec--;
    }
    u64 ticks = (u64)((sec + 11644473600LL) * 10000000LL + rem / 100);
    FILETIME f;
    f.dwLowDateTime = (DWORD)ticks;
    f.dwHighDateTime = (DWORD)(ticks >> 32);
    return f;
}

static bool utime_impl(const char *p, const FILETIME *at, const FILETIME *mt) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    HANDLE h = CreateFileW(dk_fs_wpath(sc, p), FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
                           NULL);
    bool ok = false;
    if (h == INVALID_HANDLE_VALUE) dk_fs_fail_last(p, NULL);
    else {
        ok = SetFileTime(h, NULL, at, mt) != 0;
        if (!ok) dk_fs_fail_last(p, NULL);
        CloseHandle(h);
    }
    fs_tmp_done(sc, mk);
    return ok;
}

bool dk_utime_now(const char *p) {
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    return utime_impl(p, &now, &now);
}

bool dk_utime_ns(const char *p, i64 atime_ns, i64 mtime_ns) {
    FILETIME a = ns_to_filetime(atime_ns), m = ns_to_filetime(mtime_ns);
    return utime_impl(p, &a, &m);
}

bool dk_chmod(const char *p, int mode) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *w = dk_fs_wpath(sc, p);
    DWORD attr = GetFileAttributesW(w);
    bool ok = false;
    if (attr == INVALID_FILE_ATTRIBUTES) dk_fs_fail_last(p, NULL);
    else {
        if (mode & 0200) attr &= ~(DWORD)FILE_ATTRIBUTE_READONLY;
        else attr |= FILE_ATTRIBUTE_READONLY;
        ok = SetFileAttributesW(w, attr) != 0;
        if (!ok) dk_fs_fail_last(p, NULL);
    }
    fs_tmp_done(sc, mk);
    return ok;
}

/* ---- links ----------------------------------------------------------------------------------------------------- */

bool dk_symlink(const char *target, const char *link, bool target_is_dir) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *wt = dk_fs_u8_to_w(sc, target), *wl = dk_fs_wpath(sc, link);
    for (wchar_t *c = wt; *c; c++)
        if (*c == L'/') *c = L'\\';
    DWORD flags = (target_is_dir ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0) | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    BOOLEAN ok = CreateSymbolicLinkW(wl, wt, flags);
    if (!ok && GetLastError() == ERROR_INVALID_PARAMETER) ok = CreateSymbolicLinkW(wl, wt, flags & ~(DWORD)SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
    if (!ok) dk_fs_fail_last(target, link);
    fs_tmp_done(sc, mk);
    return ok != 0;
}

bool dk_link(const char *existing, const char *newlink) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    bool ok = CreateHardLinkW(dk_fs_wpath(sc, newlink), dk_fs_wpath(sc, existing), NULL) != 0;
    if (!ok) dk_fs_fail_last(existing, newlink);
    fs_tmp_done(sc, mk);
    return ok;
}

typedef struct {
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset, SubstituteNameLength, PrintNameOffset, PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } Symlink;
        struct {
            USHORT SubstituteNameOffset, SubstituteNameLength, PrintNameOffset, PrintNameLength;
            WCHAR PathBuffer[1];
        } Mount;
        UCHAR Raw[1];
    } u;
} ReparseBuf;

bool dk_junction_create(const char *link, const char *target) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    bool ok = false;
    wchar_t *wl = dk_fs_wpath(sc, link);
    wchar_t *wt = dk_fs_u8_to_w(sc, target);
    DWORD need = GetFullPathNameW(wt, 0, NULL, NULL);
    wchar_t *full = (wchar_t *)dk_alloc_noz(sc, ((size_t)need + 8) * sizeof(wchar_t));
    GetFullPathNameW(wt, need, full, NULL);
    size_t fl = wcslen(full);
    while (fl > 3 && full[fl - 1] == L'\\') full[--fl] = 0;
    wchar_t *sub = (wchar_t *)dk_alloc_noz(sc, (fl + 16) * sizeof(wchar_t));
    wcscpy(sub, L"\\??\\");
    wcscat(sub, full);
    size_t sl = wcslen(sub);
    size_t bytes = offsetof(ReparseBuf, u.Mount.PathBuffer) + (sl + 1 + fl + 1) * sizeof(wchar_t);
    ReparseBuf *rb = (ReparseBuf *)dk_alloc(sc, bytes);
    rb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rb->u.Mount.SubstituteNameOffset = 0;
    rb->u.Mount.SubstituteNameLength = (USHORT)(sl * sizeof(wchar_t));
    rb->u.Mount.PrintNameOffset = (USHORT)((sl + 1) * sizeof(wchar_t));
    rb->u.Mount.PrintNameLength = (USHORT)(fl * sizeof(wchar_t));
    memcpy(rb->u.Mount.PathBuffer, sub, (sl + 1) * sizeof(wchar_t));
    memcpy(rb->u.Mount.PathBuffer + sl + 1, full, (fl + 1) * sizeof(wchar_t));
    rb->ReparseDataLength = (USHORT)(bytes - offsetof(ReparseBuf, u));
    if (!CreateDirectoryW(wl, NULL)) {
        dk_fs_fail_last(link, NULL);
    } else {
        HANDLE h = CreateFileW(wl, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        DWORD ret = 0;
        if (h == INVALID_HANDLE_VALUE || !DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, rb, (DWORD)bytes, NULL, 0, &ret, NULL)) {
            dk_fs_fail_last(link, NULL);
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
            RemoveDirectoryW(wl);
        } else {
            CloseHandle(h);
            ok = true;
        }
    }
    fs_tmp_done(sc, mk);
    return ok;
}

bool dk_readlink(DkArena *a, const char *p, char **out) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    bool ok = false;
    HANDLE h = CreateFileW(dk_fs_wpath(sc, p), 0, 0, NULL, OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        dk_fs_fail_last(p, NULL);
    } else {
        ReparseBuf *rb = (ReparseBuf *)dk_alloc(sc, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
        DWORD ret = 0;
        if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0, rb, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &ret, NULL)) {
            dk_fs_fail_last(p, NULL);
        } else {
            const WCHAR *name = NULL;
            size_t len = 0;
            if (rb->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
                name = rb->u.Symlink.PathBuffer + rb->u.Symlink.SubstituteNameOffset / sizeof(WCHAR);
                len = rb->u.Symlink.SubstituteNameLength / sizeof(WCHAR);
            } else if (rb->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
                name = rb->u.Mount.PathBuffer + rb->u.Mount.SubstituteNameOffset / sizeof(WCHAR);
                len = rb->u.Mount.SubstituteNameLength / sizeof(WCHAR);
            }
            if (!name) {
                SetLastError(ERROR_REPARSE_TAG_INVALID);
                dk_fs_fail_last(p, NULL);
                /* CPython raises OSError(EINVAL, "Not a symbolic link", path) here, via winerror 4390 */
                dk_io_fail_win(ERROR_NOT_A_REPARSE_POINT, p, NULL);
            } else {
                /* "\??\C:\x" is returned as "\\?\C:\x", the form CPython gives */
                wchar_t *tmp = (wchar_t *)dk_alloc(sc, (len + 8) * sizeof(wchar_t));
                if (len >= 4 && name[0] == L'\\' && name[1] == L'?' && name[2] == L'?' && name[3] == L'\\') {
                    wcscpy(tmp, L"\\\\?\\");
                    memcpy(tmp + 4, name + 4, (len - 4) * sizeof(wchar_t));
                    len += 0;
                } else memcpy(tmp, name, len * sizeof(wchar_t));
                *out = dk_fs_w_to_u8(a, tmp, (i64)wcslen(tmp));
                ok = true;
            }
        }
        CloseHandle(h);
    }
    fs_tmp_done(sc, mk);
    return ok;
}

/* ---- environment -------------------------------------------------------------------------------------------------- */

char *dk_getenv(DkArena *a, const char *name) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *wn = dk_fs_u8_to_w(sc, name);
    SetLastError(0);
    DWORD n = GetEnvironmentVariableW(wn, NULL, 0);
    char *res = NULL;
    if (n != 0) {
        wchar_t *v = (wchar_t *)dk_alloc_noz(sc, ((size_t)n + 1) * sizeof(wchar_t));
        DWORD got = GetEnvironmentVariableW(wn, v, n);
        if (got < n) res = dk_fs_w_to_u8(a, v, (i64)got);
    } else if (GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
        res = dk_fs_w_to_u8(a, L"", 0); /* set, but empty */
    }
    fs_tmp_done(sc, mk);
    return res;
}

const char *dk_getenv_or(DkArena *a, const char *name, const char *dflt) {
    char *v = dk_getenv(a, name);
    return v ? v : dflt;
}

bool dk_setenv(const char *name, const char *value) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *wn = dk_fs_u8_to_w(sc, name), *wv = dk_fs_u8_to_w(sc, value);
    /* The CRT copy first: _wputenv_s with an empty value removes the variable from the CRT and from the process
       environment, so the process environment (what dk_getenv reads and children inherit) is set after it. */
    _wputenv_s(wn, wv);
    bool ok = SetEnvironmentVariableW(wn, wv) != 0;
    if (!ok) dk_io_fail_errno(EINVAL, NULL, NULL);
    fs_tmp_done(sc, mk);
    return ok;
}

bool dk_unsetenv(const char *name) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *wn = dk_fs_u8_to_w(sc, name);
    bool ok = SetEnvironmentVariableW(wn, NULL) != 0;
    if (ok) _wputenv_s(wn, L"");
    fs_tmp_done(sc, mk);
    return ok;
}

DkEnvVec dk_environ(DkArena *a) {
    DkEnvVec out = {0};
    wchar_t *block = GetEnvironmentStringsW();
    if (!block) return out;
    for (const wchar_t *e = block; *e; e += wcslen(e) + 1) {
        const wchar_t *eq = wcschr(e + 1, L'=');
        if (!eq) continue;
        size_t kl = (size_t)(eq - e);
        wchar_t *key = (wchar_t *)dk_alloc_noz(a, (kl + 1) * sizeof(wchar_t));
        memcpy(key, e, kl * sizeof(wchar_t));
        key[kl] = 0;
        CharUpperBuffW(key, (DWORD)kl); /* os.environ upper-cases the names */
        DkEnvEntry ent;
        char *k = dk_fs_w_to_u8(a, key, (i64)kl);
        ent.name.p = k;
        ent.name.n = strlen(k);
        char *v = dk_fs_w_to_u8(a, eq + 1, -1);
        ent.value.p = v;
        ent.value.n = strlen(v);
        dk_vec_push(&out, ent);
    }
    FreeEnvironmentStringsW(block);
    return out;
}

/* ---- directory listings ----------------------------------------------------------------------------------------- */

static DkStr make_path(DkArena *a, const char *dir, size_t dl, const char *name, size_t nl) {
    bool sep = dl > 0 && dir[dl - 1] != '\\' && dir[dl - 1] != '/';
    char *d = (char *)dk_alloc_noz(a, dl + nl + 2);
    memcpy(d, dir, dl);
    size_t k = dl;
    if (sep) d[k++] = '\\';
    memcpy(d + k, name, nl);
    k += nl;
    d[k] = 0;
    DkStr s = {d, k};
    return s;
}

bool dk_scandir(DkArena *a, const char *p, DkDirEntries *out) {
    out->v = NULL;
    out->n = out->cap = 0;
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *w = dk_fs_wpath(sc, p);
    size_t wl = wcslen(w);
    wchar_t *pat = (wchar_t *)dk_alloc_noz(sc, (wl + 4) * sizeof(wchar_t));
    wcscpy(pat, w);
    if (wl && w[wl - 1] != L'\\' && w[wl - 1] != L'/' && w[wl - 1] != L':') wcscat(pat, L"\\");
    wcscat(pat, L"*");
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(pat, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND) e = ERROR_PATH_NOT_FOUND; /* an empty name list is a missing folder */
        SetLastError(e);
        dk_fs_fail_last(p, NULL);
        fs_tmp_done(sc, mk);
        return false;
    }
    size_t pl = strlen(p);
    do {
        const wchar_t *nm = fd.cFileName;
        if (nm[0] == L'.' && (nm[1] == 0 || (nm[1] == L'.' && nm[2] == 0))) continue;
        DkDirEntry e;
        memset(&e, 0, sizeof e);
        char *name = dk_fs_w_to_u8(a, nm, -1);
        e.name.p = name;
        e.name.n = strlen(name);
        e.path = make_path(a, p, pl, name, e.name.n);
        e.attrs = fd.dwFileAttributes;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) e.reparse_tag = fd.dwReserved0;
        e.is_symlink = e.reparse_tag == DK_IO_REPARSE_TAG_SYMLINK;
        e.is_junction = e.reparse_tag == DK_IO_REPARSE_TAG_MOUNT_POINT;
        e.size = (i64)(((u64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow);
        DkStat tmp;
        fill_times(&tmp, fd.ftLastAccessTime, fd.ftLastWriteTime, fd.ftCreationTime);
        e.atime_ns = tmp.atime_ns;
        e.mtime_ns = tmp.mtime_ns;
        e.ctime_ns = tmp.ctime_ns;
        if (e.is_symlink) {
            DkStat t;
            if (dk_stat(e.path.p, &t)) {
                e.is_dir = (t.file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                e.is_file = !e.is_dir;
            }
        } else {
            e.is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            e.is_file = !e.is_dir;
        }
        dk_vec_push(out, e);
    } while (FindNextFileW(h, &fd));
    DWORD last = GetLastError();
    FindClose(h);
    fs_tmp_done(sc, mk);
    if (last != ERROR_NO_MORE_FILES) {
        SetLastError(last);
        dk_fs_fail_last(p, NULL);
        dk_vec_free(out);
        return false;
    }
    return true;
}

bool dk_listdir(DkArena *a, const char *p, DkStrVec *out) {
    out->v = NULL;
    out->n = out->cap = 0;
    DkDirEntries es;
    if (!dk_scandir(a, p, &es)) return false;
    for (size_t i = 0; i < es.n; i++) dk_vec_push(out, es.v[i].name);
    dk_vec_free(&es);
    return true;
}

/* ---- walk ------------------------------------------------------------------------------------------------------ */

typedef struct {
    char *path;          /* a folder still to be listed, or the top of a saved result */
    bool is_result;
    DkStrVec dirs, files; /* result entries (bottom-up): strings live in the walk's keep arena */
} WalkEntry;

struct DkWalk {
    bool topdown;
    DkArena *keep, *item;
    DK_VEC(WalkEntry) stack;
    bool prev_valid;       /* the item last returned is still owned by the walk */
    bool prev_push;        /* topdown: its sub-folders have still to be pushed */
    DkWalkItem *prev;     /* the caller's item: its dirs may have been pruned since */
    DkArenaMark item_mark;
};

DkWalk *dk_walk_open(const char *top, bool topdown) {
    DkWalk *w = (DkWalk *)dk_xcalloc(1, sizeof *w);
    w->topdown = topdown;
    w->keep = dk_arena_new(0);
    w->item = dk_arena_new(0);
    w->item_mark = dk_arena_mark(w->item);
    WalkEntry e = {0};
    e.path = dk_strdup(w->keep, top);
    dk_vec_push(&w->stack, e);
    return w;
}

void dk_walk_close(DkWalk *w) {
    if (!w) return;
    if (w->prev_valid) {
        dk_vec_free(&w->prev->dirs);
        dk_vec_free(&w->prev->files);
    }
    dk_vec_free(&w->stack);
    dk_arena_free(w->keep);
    dk_arena_free(w->item);
    dk_xfree(w);
}

static void walk_push_children(DkWalk *w) {
    /* Python: for dirname in reversed(dirs): if not islink(join(top, dirname)): stack.append(...) */
    DkWalkItem *it = w->prev;
    for (size_t i = it->dirs.n; i-- > 0;) {
        DkStr d = it->dirs.v[i];
        DkStr full = make_path(w->keep, it->dirpath.p, it->dirpath.n, d.p, d.n);
        if (dk_islink(full.p)) continue;
        WalkEntry e = {0};
        e.path = (char *)full.p;
        dk_vec_push(&w->stack, e);
    }
}

bool dk_walk_next(DkWalk *w, DkWalkItem *item) {
    if (w->prev_valid) {
        if (w->prev_push) walk_push_children(w);
        dk_vec_free(&w->prev->dirs);
        dk_vec_free(&w->prev->files);
        w->prev_valid = w->prev_push = false;
    }
    dk_arena_reset(w->item, w->item_mark);
    while (w->stack.n) {
        WalkEntry e = dk_vec_pop(&w->stack);
        if (e.is_result) {
            item->dirpath.p = e.path;
            item->dirpath.n = strlen(e.path);
            item->dirs = e.dirs;
            item->files = e.files;
            w->prev = item;
            w->prev_valid = true;
            w->prev_push = false;
            return true;
        }
        DkDirEntries es;
        if (!dk_scandir(w->item, e.path, &es)) continue;
        DkStrVec dirs = {0}, files = {0}, walk_dirs = {0};
        for (size_t i = 0; i < es.n; i++) {
            if (es.v[i].is_dir) {
                dk_vec_push(&dirs, es.v[i].name);
                if (!w->topdown && !es.v[i].is_symlink) dk_vec_push(&walk_dirs, es.v[i].path);
            } else dk_vec_push(&files, es.v[i].name);
        }
        dk_vec_free(&es);
        if (w->topdown) {
            item->dirpath.p = e.path;
            item->dirpath.n = strlen(e.path);
            item->dirs = dirs;
            item->files = files;
            w->prev = item;
            w->prev_valid = true;
            w->prev_push = true;
            dk_vec_free(&walk_dirs);
            return true;
        }
        /* bottom-up: the result is yielded after its sub-folders */
        WalkEntry res = {0};
        res.path = e.path;
        res.is_result = true;
        for (size_t i = 0; i < dirs.n; i++) dk_vec_push(&res.dirs, fs_dup(w->keep, dirs.v[i].p, dirs.v[i].n));
        for (size_t i = 0; i < files.n; i++) dk_vec_push(&res.files, fs_dup(w->keep, files.v[i].p, files.v[i].n));
        dk_vec_free(&dirs);
        dk_vec_free(&files);
        dk_vec_push(&w->stack, res);
        for (size_t i = walk_dirs.n; i-- > 0;) {
            WalkEntry c = {0};
            c.path = dk_strdup(w->keep, walk_dirs.v[i].p);
            dk_vec_push(&w->stack, c);
        }
        dk_vec_free(&walk_dirs);
    }
    return false;
}
