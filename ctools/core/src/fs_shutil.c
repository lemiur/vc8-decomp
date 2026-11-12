// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* shutil (rmtree, copyfile, copy2, copystat, copytree, move, which) and tempfile (gettempdir, mkstemp, mkdtemp,
 * TemporaryDirectory cleanup) with CPython 3.14's behaviour on Windows. */
#include "fs_priv.h"

#include <bcrypt.h>
#include <stdio.h>

/* ---- rmtree ------------------------------------------------------------------------------------------------------ */

typedef struct {
    unsigned flags;
    bool failed;
} Rm;

static bool rm_ignore(const Rm *r) { return (r->flags & DK_RMTREE_IGNORE_ERRORS) != 0; }

/* A failure of one step: ignored with IGNORE_ERRORS, else the walk stops (Python's default onexc re-raises). */
static void rm_fail(Rm *r) {
    if (!rm_ignore(r)) r->failed = true;
}

static bool clear_readonly(const char *path) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    wchar_t *w = dk_fs_wpath(sc, path);
    DWORD attr = GetFileAttributesW(w);
    bool ok = attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY) &&
              SetFileAttributesW(w, attr & ~(DWORD)FILE_ATTRIBUTE_READONLY);
    fs_tmp_done(sc, mk);
    return ok;
}

static void rm_unlink(Rm *r, const char *path, bool dir) {
    if (r->failed) return;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (dir ? dk_rmdir(path) : dk_remove(path)) return;
        if (dk_io_is(ENOENT)) return;
        if (attempt == 0 && (r->flags & DK_RMTREE_CLEAR_READONLY) && dk_io_is(EACCES) && clear_readonly(path)) continue;
        break;
    }
    rm_fail(r);
}

static void rm_dir(Rm *r, const char *path) {
    if (r->failed) return;
    DkArena *sc = dk_arena_new(0);
    DkDirEntries es;
    if (!dk_scandir(sc, path, &es)) {
        if (!dk_io_is(ENOENT)) rm_fail(r);
        dk_arena_free(sc);
        return;
    }
    /* os.walk(topdown=False, followlinks=_walk_symlinks_as_files): only real folders are entered; symlinks and
     * junctions to folders count as files and are removed as links. */
    for (size_t i = 0; i < es.n && !r->failed; i++) {
        const DkDirEntry *e = &es.v[i];
        bool real_dir = (e->attrs & FILE_ATTRIBUTE_DIRECTORY) && !e->is_junction && !e->is_symlink;
        if (real_dir) rm_dir(r, e->path.p);
    }
    for (size_t i = 0; i < es.n && !r->failed; i++) {
        const DkDirEntry *e = &es.v[i];
        if ((e->attrs & FILE_ATTRIBUTE_DIRECTORY) && !e->is_junction && !e->is_symlink) rm_unlink(r, e->path.p, true);
    }
    for (size_t i = 0; i < es.n && !r->failed; i++) {
        const DkDirEntry *e = &es.v[i];
        bool real_dir = (e->attrs & FILE_ATTRIBUTE_DIRECTORY) && !e->is_junction && !e->is_symlink;
        if (!real_dir) rm_unlink(r, e->path.p, false);
    }
    dk_vec_free(&es);
    dk_arena_free(sc);
}

bool dk_rmtree(const char *path, unsigned flags) {
    Rm r = {flags, false};
    DkStat st;
    if (!dk_lstat(path, &st)) {
        rm_fail(&r);
        return !r.failed;
    }
    if (DK_S_ISLNK(st.mode) ||
        ((st.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) && st.reparse_tag == DK_IO_REPARSE_TAG_MOUNT_POINT)) {
        dk_io_fail_msg(DK_IOE_OS, 0, "Cannot call rmtree on a symbolic link");
        rm_fail(&r);
        return !r.failed;
    }
    rm_dir(&r, path);
    if (!r.failed) rm_unlink(&r, path, true);
    return !r.failed;
}

/* ---- copyfile / copy2 / copystat ------------------------------------------------------------------------------------- */

static void fail_shutil(int tag, const char *fmt, ...) {
    char text[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof text, fmt, ap);
    va_end(ap);
    dk_io_fail_msg(DK_IOE_SHUTIL, tag, "%s", text);
}

bool dk_copyfile(const char *src, const char *dst) {
    if (dk_exists(src) && dk_exists(dst) && dk_path_samefile(src, dst)) {
        DkArena *sc = fs_tmp();
        DkArenaMark mk = dk_arena_mark(sc);
        FsBuf b;
        fsb_init(&b, sc);
        dk_fs_repr(&b, src);
        fsb_putz(&b, " and ");
        dk_fs_repr(&b, dst);
        fsb_putz(&b, " are the same file");
        fail_shutil(1, "%s", fsb_cz(&b));
        fs_tmp_done(sc, mk);
        return false;
    }
    HANDLE hs = dk_fs_open_handle(src, GENERIC_READ, OPEN_EXISTING);
    if (hs == INVALID_HANDLE_VALUE) return false;
    HANDLE hd = dk_fs_open_handle(dst, GENERIC_WRITE, CREATE_ALWAYS);
    if (hd == INVALID_HANDLE_VALUE) {
        CloseHandle(hs);
        return false;
    }
    const size_t BUF = 1024 * 1024;
    u8 *buf = (u8 *)dk_xmalloc(BUF);
    bool ok = true;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(hs, buf, (DWORD)BUF, &got, NULL)) {
            dk_fs_fail_open(GetLastError(), src);
            ok = false;
            break;
        }
        if (got == 0) break;
        DWORD off = 0;
        while (off < got) {
            DWORD put = 0;
            if (!WriteFile(hd, buf + off, got - off, &put, NULL)) {
                dk_fs_fail_open(GetLastError(), dst);
                ok = false;
                break;
            }
            off += put;
        }
        if (!ok) break;
    }
    dk_xfree(buf);
    CloseHandle(hs);
    if (!CloseHandle(hd) && ok) {
        dk_fs_fail_open(GetLastError(), dst);
        ok = false;
    }
    return ok;
}

bool dk_copystat(const char *src, const char *dst) {
    DkStat st;
    if (!dk_stat(src, &st)) return false;
    if (!dk_utime_ns(dst, st.atime_ns, st.mtime_ns)) return false;
    return dk_chmod(dst, (int)(st.mode & 07777));
}

bool dk_copy2(const char *src, const char *dst0) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    const char *dst = dst0;
    if (dk_isdir(dst)) {
        DkStr bn = dk_path_basename(src);
        dst = dk_path_join(sc, dst0, fs_cz(sc, bn));
    }
    COPYFILE2_EXTENDED_PARAMETERS params = {sizeof params, COPY_FILE_ALLOW_DECRYPTED_DESTINATION, NULL, NULL, NULL};
    HRESULT hr = CopyFile2(dk_fs_wpath(sc, src), dk_fs_wpath(sc, dst), &params);
    if (SUCCEEDED(hr)) {
        fs_tmp_done(sc, mk);
        return true;
    }
    unsigned code = ((hr & 0xFFFF0000) == 0x80070000) ? (unsigned)(hr & 0xFFFF) : (unsigned)hr;
    bool ok;
    if (code == ERROR_ACCESS_DENIED) {
        ok = dk_copyfile(src, dst) && dk_copystat(src, dst);
    } else {
        dk_io_fail_win(code, NULL, NULL);
        ok = false;
    }
    fs_tmp_done(sc, mk);
    return ok;
}

/* ---- copytree ---------------------------------------------------------------------------------------------------- */

typedef struct {
    const DkCopytreeOpts *o;
    FsBuf errors; /* the items of the repr() of shutil.Error's list */
    size_t nerrors;
} Ct;

static void ct_error(Ct *c, const char *src, const char *dst, DkStr why) {
    if (c->nerrors++) fsb_putz(&c->errors, ", ");
    fsb_putc(&c->errors, '(');
    dk_fs_repr(&c->errors, src);
    fsb_putz(&c->errors, ", ");
    dk_fs_repr(&c->errors, dst);
    fsb_putz(&c->errors, ", ");
    char *z = (char *)fs_dup(dk_arena(), why.p, why.n).p;
    dk_fs_repr(&c->errors, z);
    fsb_putc(&c->errors, ')');
}

static bool ct_ignored(const Ct *c, const char *name) {
    if (!c->o) return false;
    for (size_t i = 0; i < c->o->n_ignore; i++)
        if (dk_fnmatch(name, c->o->ignore[i])) return true;
    return false;
}

static bool copytree_impl(Ct *c, const char *src, const char *dst, bool top) {
    DkArena *sc = dk_arena_new(0);
    DkDirEntries es;
    if (!dk_scandir(sc, src, &es)) {
        dk_arena_free(sc);
        return false; /* the OSError of os.scandir propagates */
    }
    if (!dk_makedirs(dst, c->o && c->o->dirs_exist_ok)) {
        dk_arena_free(sc);
        return false;
    }
    for (size_t i = 0; i < es.n; i++) {
        const DkDirEntry *e = &es.v[i];
        if (ct_ignored(c, e->name.p)) continue;
        DkStr dstname = {dk_path_join(sc, dst, e->name.p), 0};
        dstname.n = strlen(dstname.p);
        bool ok = true;
        if (e->is_symlink) {
            char *linkto = NULL;
            if (!dk_readlink(sc, e->path.p, &linkto)) ok = false;
            else if (c->o && c->o->symlinks) {
                ok = dk_symlink(linkto, dstname.p, e->is_dir) && dk_copystat(e->path.p, dstname.p);
            } else if (e->is_dir) ok = copytree_impl(c, e->path.p, dstname.p, false);
            else ok = dk_copy2(e->path.p, dstname.p);
        } else if (e->is_dir) {
            ok = copytree_impl(c, e->path.p, dstname.p, false);
        } else ok = dk_copy2(e->path.p, dstname.p);
        if (!ok) {
            const DkIoErr *ie = dk_io_err();
            if (ie->kind == DK_IOE_SHUTIL && ie->err == 2) {
                /* a nested shutil.Error: its items are flattened into ours */
                if (c->nerrors++) fsb_putz(&c->errors, ", ");
                const char *m = ie->msg;
                size_t ml = strlen(m);
                if (ml >= 2) fsb_put(&c->errors, m + 1, ml - 2);
            } else {
                DkStr why = dk_io_err_str(sc);
                ct_error(c, e->path.p, dstname.p, why);
            }
        }
    }
    dk_vec_free(&es);
    dk_arena_free(sc);
    if (!dk_copystat(src, dst)) {
        const DkIoErr *ie = dk_io_err();
        if (ie->winerror == 0) {
            DkArena *s2 = fs_tmp();
            DkArenaMark mk = dk_arena_mark(s2);
            DkStr why = dk_io_err_str(s2);
            ct_error(c, src, dst, why);
            fs_tmp_done(s2, mk);
        }
    }
    (void)top;
    return true;
}

bool dk_copytree(const char *src, const char *dst, const DkCopytreeOpts *opts) {
    Ct c = {opts, {0}, 0};
    fsb_init(&c.errors, NULL);
    bool ok = copytree_impl(&c, src, dst, true);
    if (ok && c.nerrors) {
        dk_io_fail_msg(DK_IOE_SHUTIL, 2, "[%s]", fsb_cz(&c.errors));
        ok = false;
    }
    dk_xfree(c.errors.p);
    return ok;
}

bool dk_move(const char *src, const char *dst) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    const char *real_dst = dst;
    bool ok = true;
    if (dk_isdir(dst)) {
        if (dk_path_samefile(src, dst) && !dk_islink(src)) {
            ok = dk_rename(src, dst);
            fs_tmp_done(sc, mk);
            return ok;
        }
        DkStr bn = dk_path_basename(src);
        real_dst = dk_path_join(sc, dst, fs_cz(sc, bn));
        if (dk_exists(real_dst)) {
            fail_shutil(0, "Destination path '%s' already exists", real_dst);
            fs_tmp_done(sc, mk);
            return false;
        }
    }
    if (!dk_rename(src, real_dst)) {
        if (dk_islink(src)) {
            char *linkto;
            ok = dk_readlink(sc, src, &linkto) && dk_symlink(linkto, real_dst, dk_isdir(src)) && dk_remove(src);
        } else if (dk_isdir(src)) {
            DkCopytreeOpts o = {NULL, 0, false, true};
            ok = dk_copytree(src, real_dst, &o) && dk_rmtree(src, 0);
        } else ok = dk_copy2(src, real_dst) && dk_remove(src);
    }
    fs_tmp_done(sc, mk);
    return ok;
}

/* ---- tempfile ---------------------------------------------------------------------------------------------------- */

static void random_name(char out[9]) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789_";
    u8 r[8];
    if (BCryptGenRandom(NULL, r, sizeof r, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        LARGE_INTEGER t;
        QueryPerformanceCounter(&t);
        for (int i = 0; i < 8; i++) r[i] = (u8)(t.QuadPart >> (i * 3)) ^ (u8)(GetCurrentThreadId() + i * 31);
    }
    for (int i = 0; i < 8; i++) out[i] = chars[r[i] % 37];
    out[8] = 0;
}

static INIT_ONCE g_tmp_once = INIT_ONCE_STATIC_INIT;
static char *g_tmpdir;

static BOOL CALLBACK find_tmpdir(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)param;
    (void)ctx;
    DkArena *sc = dk_arena_new(0);
    const char *cands[12];
    size_t n = 0;
    const char *envs[] = {"TMPDIR", "TEMP", "TMP"};
    for (size_t i = 0; i < 3; i++) {
        char *v = dk_getenv(sc, envs[i]);
        if (v) cands[n++] = v;
    }
    cands[n++] = dk_path_expanduser(sc, "~\\AppData\\Local\\Temp");
    char *sr = dk_getenv(sc, "SYSTEMROOT");
    cands[n++] = sr ? dk_path_join(sc, sr, "Temp") : "%SYSTEMROOT%\\Temp";
    cands[n++] = "c:\\temp";
    cands[n++] = "c:\\tmp";
    cands[n++] = "\\temp";
    cands[n++] = "\\tmp";
    cands[n++] = dk_getcwd(sc);
    for (size_t i = 0; i < n; i++) {
        const char *dir = cands[i];
        if (strcmp(dir, ".") != 0) dir = dk_path_abspath(sc, dir);
        for (int tries = 0; tries < 100; tries++) {
            char nm[9];
            random_name(nm);
            char leaf[16] = "tmp";
            memcpy(leaf + 3, nm, 9);
            const char *file = dk_path_join(sc, dir, leaf);
            HANDLE h = dk_fs_open_handle(file, GENERIC_WRITE, CREATE_NEW);
            if (h != INVALID_HANDLE_VALUE) {
                DWORD put;
                WriteFile(h, "blat", 4, &put, NULL);
                CloseHandle(h);
                dk_remove(file);
                g_tmpdir = _strdup(dir);
                dk_arena_free(sc);
                return TRUE;
            }
            if (!dk_io_is(EEXIST)) break;
        }
    }
    g_tmpdir = _strdup(".");
    dk_arena_free(sc);
    return TRUE;
}

char *dk_gettempdir(DkArena *a) {
    InitOnceExecuteOnce(&g_tmp_once, find_tmpdir, NULL, NULL);
    return dk_strdup(a, g_tmpdir);
}

static char *temp_name(DkArena *a, const char *prefix, const char *suffix, const char *dir) {
    char nm[9];
    random_name(nm);
    size_t pl = strlen(prefix), sl = strlen(suffix);
    char *leaf = (char *)dk_alloc_noz(a, pl + 8 + sl + 1);
    memcpy(leaf, prefix, pl);
    memcpy(leaf + pl, nm, 8);
    memcpy(leaf + pl + 8, suffix, sl + 1);
    return dk_path_join(a, dir, leaf);
}

DkFile *dk_mkstemp(DkArena *a, const char *prefix, const char *suffix, const char *dir, char **path_out) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    if (!prefix) prefix = "tmp";
    if (!suffix) suffix = "";
    char *d = dir ? dk_path_abspath(sc, dir) : dk_gettempdir(sc);
    DkFile *f = NULL;
    for (int seq = 0; seq < 10000 && !f; seq++) {
        DkArenaMark m2 = dk_arena_mark(sc);
        char *file = temp_name(sc, prefix, suffix, d);
        f = dk_fopen(file, "x+b", DK_TM_UTF8);
        if (f) {
            *path_out = dk_path_abspath(a, file);
            break;
        }
        dk_arena_reset(sc, m2);
        if (dk_io_is(EEXIST)) continue;
        if (dk_io_is(EACCES) && dk_isdir(d)) continue; /* a race with a deleted name on Windows */
        break;
    }
    fs_tmp_done(sc, mk);
    if (!f && !dk_io_err()->kind) dk_io_fail_errno(EEXIST, NULL, NULL);
    return f;
}

char *dk_mkdtemp(DkArena *a, const char *prefix, const char *suffix, const char *dir) {
    DkArena *sc = fs_tmp();
    DkArenaMark mk = dk_arena_mark(sc);
    if (!prefix) prefix = "tmp";
    if (!suffix) suffix = "";
    char *d = dir ? dk_path_abspath(sc, dir) : dk_gettempdir(sc);
    char *res = NULL;
    for (int seq = 0; seq < 10000 && !res; seq++) {
        DkArenaMark m2 = dk_arena_mark(sc);
        char *file = temp_name(sc, prefix, suffix, d);
        if (dk_mkdir(file)) {
            res = dk_path_abspath(a, file);
            break;
        }
        dk_arena_reset(sc, m2);
        if (dk_io_is(EEXIST)) continue;
        if (dk_io_is(EACCES) && dk_isdir(d)) continue;
        break;
    }
    fs_tmp_done(sc, mk);
    return res;
}

void dk_tempdir_cleanup(const char *path) { dk_rmtree(path, DK_RMTREE_CLEAR_READONLY | DK_RMTREE_IGNORE_ERRORS); }
