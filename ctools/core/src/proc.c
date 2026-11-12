// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Subprocesses: Python's subprocess module, shutil.which and kill_children_with_parent on Windows (proc.h). */
#include "dk/proc.h"
#include "dk/clock.h"
#include "dk/fmt.h"
#include "dk/fs.h"
#include "dk/pool.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
#include <tlhelp32.h>
#include <restartmanager.h>
#pragma comment(lib, "rstrtmgr.lib")

/* ---- small helpers ---- */

static wchar_t *to_wide(DkArena *a, const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = dk_alloc_noz(a, sizeof(wchar_t) * (size_t)(n > 0 ? n : 1));
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    else w[0] = 0;
    return w;
}

static char *from_wide(DkArena *a, const wchar_t *w, size_t n) {
    int bytes = n ? WideCharToMultiByte(CP_UTF8, 0, w, (int)n, NULL, 0, NULL, NULL) : 0;
    char *p = dk_alloc_noz(a, (size_t)bytes + 1);
    if (bytes) WideCharToMultiByte(CP_UTF8, 0, w, (int)n, p, bytes, NULL, NULL);
    p[bytes] = 0;
    return p;
}

/* A growable byte buffer on the heap. */
typedef struct {
    u8 *p;
    size_t n, cap;
} Bytes;

static void bytes_reserve(Bytes *b, size_t extra) {
    if (b->n + extra + 1 <= b->cap) return;
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < b->n + extra + 1) cap *= 2;
    b->p = dk_xrealloc(b->p, cap);
    b->cap = cap;
}

static void bytes_free(Bytes *b) {
    dk_xfree(b->p);
    memset(b, 0, sizeof *b);
}

/* ---- list2cmdline ---- */

/* subprocess.list2cmdline: CPython's loop over the characters. The characters that matter are ASCII, so the loop
 * runs on the UTF-8 bytes. */
static void cmdline_append(Bytes *out, const char *const *argv, size_t argc) {
    for (size_t i = 0; i < argc; i++) {
        const char *arg = argv[i];
        size_t len = strlen(arg);
        if (i > 0) {
            bytes_reserve(out, 1);
            out->p[out->n++] = ' ';
        }
        bool needquote = len == 0 || strchr(arg, ' ') != NULL || strchr(arg, '\t') != NULL;
        bytes_reserve(out, len * 2 + 4);
        if (needquote) out->p[out->n++] = '"';
        size_t bs = 0; /* pending backslashes */
        for (size_t k = 0; k < len; k++) {
            char c = arg[k];
            bytes_reserve(out, 2 * bs + 4);
            if (c == '\\') {
                bs++;
            } else if (c == '"') {
                for (size_t m = 0; m < bs * 2; m++) out->p[out->n++] = '\\';
                bs = 0;
                out->p[out->n++] = '\\';
                out->p[out->n++] = '"';
            } else {
                for (size_t m = 0; m < bs; m++) out->p[out->n++] = '\\';
                bs = 0;
                out->p[out->n++] = (u8)c;
            }
        }
        bytes_reserve(out, 2 * bs + 4);
        for (size_t m = 0; m < bs; m++) out->p[out->n++] = '\\'; /* the remaining backslashes */
        if (needquote) {
            for (size_t m = 0; m < bs; m++) out->p[out->n++] = '\\'; /* doubled before the closing quote */
            out->p[out->n++] = '"';
        }
    }
}

char *dk_list2cmdline_n(DkArena *a, const char *const *argv, size_t argc) {
    Bytes b = {0};
    bytes_reserve(&b, 16);
    cmdline_append(&b, argv, argc);
    char *r = dk_alloc_noz(a, b.n + 1);
    memcpy(r, b.p, b.n);
    r[b.n] = 0;
    bytes_free(&b);
    return r;
}

char *dk_list2cmdline(DkArena *a, const char *const *argv) {
    size_t n = 0;
    while (argv[n]) n++;
    return dk_list2cmdline_n(a, argv, n);
}

/* ---- shutil.which ---- */

static bool is_sep(char c) { return c == '\\' || c == '/'; }

/* ntpath.split: (head, tail). tail is the part after the last separator of the path without its drive and root. */
static size_t nt_split(const char *p, size_t n, size_t *head_len) {
    size_t drive = (n >= 2 && p[1] == ':') ? 2 : 0;
    size_t root = (drive < n && is_sep(p[drive])) ? 1 : 0;
    size_t start = drive + root;
    size_t i = n;
    while (i > start && !is_sep(p[i - 1])) i--;
    size_t h = i;
    while (h > start && is_sep(p[h - 1])) h--; /* strip trailing separators unless all are separators */
    if (h == start) h = i;
    *head_len = h;
    return i; /* tail starts here */
}

/* ntpath.join(dir, name) for a name without separators. */
static char *nt_join(DkArena *a, const char *dir, const char *name) {
    size_t dl = strlen(dir), nl = strlen(name);
    char *r = dk_alloc_noz(a, dl + nl + 2);
    memcpy(r, dir, dl);
    size_t k = dl;
    size_t drive = (dl >= 2 && dir[1] == ':') ? 2 : 0;
    if (dl > drive && !is_sep(dir[dl - 1])) r[k++] = '\\';
    memcpy(r + k, name, nl);
    r[k + nl] = 0;
    return r;
}

static bool path_is_file(const char *path) {
    DkArena *s = dk_scratch();
    DkArenaMark m = dk_arena_mark(s);
    DWORD attr = GetFileAttributesW(to_wide(s, path));
    dk_arena_reset(s, m);
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static char ascii_lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

/* ntpath.normcase for the comparison of PATH entries: lower case, '/' as '\'. */
static char *nt_normcase(DkArena *a, const char *s) {
    size_t n = strlen(s);
    char *r = dk_alloc_noz(a, n + 1);
    for (size_t i = 0; i < n; i++) r[i] = s[i] == '/' ? '\\' : ascii_lower(s[i]);
    r[n] = 0;
    return r;
}

static bool ends_with_nocase(const char *s, const char *suffix) {
    size_t sl = strlen(s), xl = strlen(suffix);
    if (xl > sl) return false;
    for (size_t i = 0; i < xl; i++)
        if (ascii_lower(s[sl - xl + i]) != ascii_lower(suffix[i])) return false;
    return true;
}

static const char *env_get_utf8(DkArena *a, const char *name) {
    wchar_t *wn = to_wide(a, name);
    DWORD n = GetEnvironmentVariableW(wn, NULL, 0);
    if (n == 0) return NULL;
    wchar_t *v = dk_alloc_noz(a, sizeof(wchar_t) * n);
    DWORD got = GetEnvironmentVariableW(wn, v, n);
    return from_wide(a, v, got);
}

char *dk_which(DkArena *a, const char *cmd, const char *path, const char *pathext) {
    DkArena *s = dk_scratch();
    DkArenaMark mark = dk_arena_mark(s);
    char *result = NULL;
    size_t cl = strlen(cmd), head_len;
    size_t tail_at = nt_split(cmd, cl, &head_len);
    const char *name = cmd + tail_at;
    DkPtrVec dirs = {0};
    if (tail_at > 0) {
        char *d = dk_alloc_noz(s, head_len + 1);
        memcpy(d, cmd, head_len);
        d[head_len] = 0;
        dk_vec_push(&dirs, d);
    } else {
        if (!path) path = env_get_utf8(s, "PATH");
        if (!path || !*path) goto done; /* PATH='' matches nothing */
        const char *p = path;
        for (;;) {
            const char *semi = strchr(p, ';');
            size_t len = semi ? (size_t)(semi - p) : strlen(p);
            char *d = dk_alloc_noz(s, len + 1);
            memcpy(d, p, len);
            d[len] = 0;
            dk_vec_push(&dirs, d);
            if (!semi) break;
            p = semi + 1;
        }
        /* shutil._win_path_needs_curdir: the current folder comes first unless the system says otherwise */
        if (NeedCurrentDirectoryForExePathW(to_wide(s, name))) dk_vec_insert(&dirs, 0, (void *)".");
    }
    if (!pathext || !*pathext) pathext = env_get_utf8(s, "PATHEXT");
    if (!pathext || !*pathext) pathext = ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC";
    DkPtrVec files = {0};
    DkPtrVec exts = {0};
    {
        const char *p = pathext;
        for (;;) {
            const char *semi = strchr(p, ';');
            size_t len = semi ? (size_t)(semi - p) : strlen(p);
            if (len > 0) {
                while (len > 0 && p[len - 1] == '.') len--; /* ext.rstrip('.') */
                char *e = dk_alloc_noz(s, len + 1);
                memcpy(e, p, len);
                e[len] = 0;
                dk_vec_push(&exts, e);
            }
            if (!semi) break;
            p = semi + 1;
        }
    }
    bool direct = false;
    for (size_t i = 0; i < exts.n; i++)
        if (ends_with_nocase(name, exts.v[i])) direct = true;
    if (direct) dk_vec_push(&files, (void *)name);
    for (size_t i = 0; i < exts.n; i++) dk_vec_push(&files, dk_sprintf(s, "%s%s", name, (char *)exts.v[i]));
    DkPtrVec seen = {0};
    for (size_t di = 0; di < dirs.n && !result; di++) {
        char *norm = nt_normcase(s, dirs.v[di]);
        bool dup = false;
        for (size_t k = 0; k < seen.n; k++)
            if (strcmp(seen.v[k], norm) == 0) dup = true;
        if (dup) continue;
        dk_vec_push(&seen, norm);
        for (size_t fi = 0; fi < files.n; fi++) {
            char *full = nt_join(s, dirs.v[di], files.v[fi]);
            if (path_is_file(full)) {
                result = dk_strdup(a, full);
                break;
            }
        }
    }
    dk_vec_free(&seen);
    dk_vec_free(&files);
    dk_vec_free(&exts);
done:
    dk_vec_free(&dirs);
    dk_arena_reset(s, mark);
    return result;
}

/* ---- environments ---- */

typedef struct {
    char *name, *value;
} EnvEntry;
struct DkEnv {
    DkArena *a;
    EnvEntry *ent;
    size_t n, cap;
};

DkEnv *dk_env_new(DkArena *a) {
    DkEnv *e = DK_NEW(a, DkEnv);
    e->a = a;
    return e;
}

static EnvEntry *env_find(const DkEnv *e, const char *name) {
    for (size_t i = 0; i < e->n; i++)
        if (strcmp(e->ent[i].name, name) == 0) return &e->ent[i];
    return NULL;
}

void dk_env_set(DkEnv *e, const char *name, const char *value) {
    DK_ASSERT(name && *name && !strchr(name, '='));
    EnvEntry *x = env_find(e, name);
    if (x) {
        x->value = dk_strdup(e->a, value);
        return;
    }
    if (e->n == e->cap) {
        size_t cap = e->cap ? e->cap * 2 : 64;
        EnvEntry *ne = dk_alloc_noz(e->a, cap * sizeof *ne);
        if (e->n) memcpy(ne, e->ent, e->n * sizeof *ne);
        e->ent = ne;
        e->cap = cap;
    }
    e->ent[e->n].name = dk_strdup(e->a, name);
    e->ent[e->n].value = dk_strdup(e->a, value);
    e->n++;
}

bool dk_env_unset(DkEnv *e, const char *name) {
    EnvEntry *x = env_find(e, name);
    if (!x) return false;
    size_t i = (size_t)(x - e->ent);
    memmove(&e->ent[i], &e->ent[i + 1], (e->n - i - 1) * sizeof *e->ent);
    e->n--;
    return true;
}

const char *dk_env_get(const DkEnv *e, const char *name) {
    EnvEntry *x = env_find(e, name);
    return x ? x->value : NULL;
}

size_t dk_env_count(const DkEnv *e) { return e->n; }

DkEnv *dk_env_copy(DkArena *a, const DkEnv *src) {
    DkEnv *e = dk_env_new(a);
    for (size_t i = 0; i < src->n; i++) dk_env_set(e, src->ent[i].name, src->ent[i].value);
    return e;
}

DkEnv *dk_env_current(DkArena *a) {
    DkEnv *e = dk_env_new(a);
    wchar_t *block = GetEnvironmentStringsW();
    DK_ASSERT(block != NULL);
    for (const wchar_t *p = block; *p; p += wcslen(p) + 1) {
        const wchar_t *eq = wcschr(p, L'=');
        if (!eq || eq == p) continue; /* the "=C:=C:\\dir" entries are not in os.environ */
        size_t nl = (size_t)(eq - p);
        wchar_t *up = dk_alloc_noz(a, sizeof(wchar_t) * (nl + 1));
        memcpy(up, p, nl * sizeof(wchar_t));
        up[nl] = 0;
        /* os.environ upper-cases the names on Windows (LCMapStringEx is in kernel32: user32 would be loaded by every tool) */
        LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE, up, (int)nl, up, (int)nl, NULL, NULL, 0);
        char *name = from_wide(a, up, nl);
        char *value = from_wide(a, eq + 1, wcslen(eq + 1));
        dk_env_set(e, name, value);
    }
    FreeEnvironmentStringsW(block);
    return e;
}

typedef struct {
    const wchar_t *name;
    size_t name_len;
    const wchar_t *entry; /* NAME=VALUE */
    size_t index;
} EnvSortItem;

static int env_cmp(const void *x, const void *y) {
    const EnvSortItem *a = x, *b = y;
    int c = CompareStringOrdinal(a->name, (int)a->name_len, b->name, (int)b->name_len, TRUE);
    if (c != CSTR_EQUAL) return c == CSTR_LESS_THAN ? -1 : 1;
    return a->index < b->index ? -1 : (a->index > b->index);
}

/* The Windows environment block: NAME=VALUE entries sorted by name (case-insensitive ordinal), each ending in NUL,
 * and an extra NUL. */
static wchar_t *env_block(DkArena *a, const DkEnv *e) {
    size_t total = 2;
    EnvSortItem *items = dk_alloc(a, (e->n + 1) * sizeof *items);
    for (size_t i = 0; i < e->n; i++) {
        wchar_t *wn = to_wide(a, e->ent[i].name);
        wchar_t *wv = to_wide(a, e->ent[i].value);
        size_t nl = wcslen(wn), vl = wcslen(wv);
        wchar_t *entry = dk_alloc_noz(a, sizeof(wchar_t) * (nl + vl + 2));
        memcpy(entry, wn, nl * sizeof(wchar_t));
        entry[nl] = L'=';
        memcpy(entry + nl + 1, wv, (vl + 1) * sizeof(wchar_t));
        items[i].name = entry;
        items[i].name_len = nl;
        items[i].entry = entry;
        items[i].index = i;
        total += nl + vl + 2;
    }
    qsort(items, e->n, sizeof *items, env_cmp);
    wchar_t *block = dk_alloc(a, sizeof(wchar_t) * total);
    size_t k = 0;
    for (size_t i = 0; i < e->n; i++) {
        size_t len = wcslen(items[i].entry);
        memcpy(block + k, items[i].entry, (len + 1) * sizeof(wchar_t));
        k += len + 1;
    }
    block[k] = 0;
    return block;
}

/* ---- text decoding ---- */

/* CPython's UTF-8 decoder with errors="replace": one U+FFFD per maximal invalid subpart. Newlines are translated
 * (CRLF and a lone CR become LF) in the same pass when `universal`. out holds `cap` bytes. Returns 0 on success
 * (*out_n set), 1 on invalid input when !replace (UnicodeDecodeError), 2 when the output would not fit in cap (a
 * replacement character is three bytes where the input had one). */
static int decode_utf8(const u8 *in, size_t n, bool replace, bool universal, u8 *out, size_t cap, size_t *out_n) {
    size_t i = 0, o = 0;
    while (i < n) {
        u8 c = in[i];
        if (c < 0x80) {
            if (o + 1 > cap) return 2;
            if (universal && c == '\r') {
                out[o++] = '\n';
                i++;
                if (i < n && in[i] == '\n') i++;
                continue;
            }
            out[o++] = c;
            i++;
            continue;
        }
        size_t need;
        u8 lo = 0x80, hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF) {
            need = 1;
        } else if (c >= 0xE0 && c <= 0xEF) {
            need = 2;
            if (c == 0xE0) lo = 0xA0;
            if (c == 0xED) hi = 0x9F;
        } else if (c >= 0xF0 && c <= 0xF4) {
            need = 3;
            if (c == 0xF0) lo = 0x90;
            if (c == 0xF4) hi = 0x8F;
        } else {
            need = 0; /* 0x80-0xC1, 0xF5-0xFF: never a valid lead byte */
        }
        size_t k = 1;
        bool ok = need > 0;
        for (; ok && k <= need; k++) {
            if (i + k >= n) {
                ok = false;
                break;
            }
            u8 d = in[i + k];
            u8 l = k == 1 ? lo : 0x80, h = k == 1 ? hi : 0xBF;
            if (d < l || d > h) {
                ok = false;
                break;
            }
        }
        if (ok) {
            if (o + need + 1 > cap) return 2;
            memcpy(out + o, in + i, need + 1);
            o += need + 1;
            i += need + 1;
        } else {
            if (!replace) return 1;
            if (o + 3 > cap) return 2;
            out[o++] = 0xEF;
            out[o++] = 0xBF;
            out[o++] = 0xBD;
            i += need ? k : 1; /* the lead byte and the valid prefix that follows it */
        }
    }
    *out_n = o;
    return 0;
}

/* Decodes into memory from `a` (NUL-terminated): the exact-size attempt first, the worst case on overflow. */
static bool decode_to_arena(DkArena *a, const u8 *in, size_t n, bool replace, bool universal, DkStr *out) {
    u8 *d = dk_alloc_noz(a, n + 1);
    size_t on = 0;
    int r = decode_utf8(in, n, replace, universal, d, n, &on);
    if (r == 2) {
        d = dk_alloc_noz(a, n * 3 + 1);
        r = decode_utf8(in, n, replace, universal, d, n * 3, &on);
    }
    if (r != 0) {
        *out = (DkStr){"", 0};
        return false;
    }
    d[on] = 0;
    *out = (DkStr){(const char *)d, on};
    return true;
}

/* ---- the process engine ---- */

typedef struct {
    HANDLE h;      /* the parent's end (overlapped), or NULL */
    HANDLE ev;     /* manual-reset event for ov */
    OVERLAPPED ov;
    bool pending;
    bool eof;
    Bytes data;    /* read: received bytes; data.n is the fill, `pos` the consumed part */
    size_t pos;
    Bytes line;    /* readline: the decoded line handed out */
} Stream;

struct DkProc {
    HANDLE hproc;
    HANDLE job;
    u32 pid;
    bool exited;
    u32 exitcode;
    Stream out, err;
    /* stdin */
    HANDLE in_h, in_ev;
    OVERLAPPED in_ov;
    bool in_pending;
    const u8 *wdata;
    size_t wlen, wpos;
    size_t wchunk;
    bool close_in_when_written;
    bool text;
    bool replace;
    DkArena *arena;
    bool merged; /* stderr goes to the stdout pipe */
    /* the wall-clock ceiling (crash and hang policy, proc.h) */
    PTP_TIMER ceil_timer;
    double ceil_s;
    bool ceil_is_ceiling; /* DECOMPKIT_PROC_CEILING (timeout 0), else a backstop a little past the spec's timeout */
    volatile LONG ceil_hit;
    char name[64]; /* the program's file name, for the message */
};

enum { DK_PROC_CEILING_EXIT = 124 }; /* exit code of a process killed by its ceiling */
static void arm_ceiling(DkProc *p, double limit_s, bool is_ceiling);

#define PIPE_BUF_SIZE 65536
#define READ_CHUNK 65536

static DkAtomic32 g_pipe_counter;

static SECURITY_ATTRIBUTES inherit_sa(void) {
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    return sa;
}

/* A pipe with an overlapped parent end and a synchronous inheritable child end. */
static bool make_pipe(bool parent_reads, HANDLE *parent, HANDLE *child) {
    wchar_t name[96];
    swprintf(name, 96, L"\\\\.\\pipe\\dk-%lu-%lu", (unsigned long)GetCurrentProcessId(),
             (unsigned long)dk_atomic_add32(&g_pipe_counter, 1));
    DWORD open_mode = (parent_reads ? PIPE_ACCESS_INBOUND : PIPE_ACCESS_OUTBOUND) | FILE_FLAG_OVERLAPPED |
                      FILE_FLAG_FIRST_PIPE_INSTANCE;
    HANDLE srv = CreateNamedPipeW(name, open_mode, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                  1, PIPE_BUF_SIZE, PIPE_BUF_SIZE, 0, NULL);
    if (srv == INVALID_HANDLE_VALUE) return false;
    SECURITY_ATTRIBUTES sa = inherit_sa();
    HANDLE cli = CreateFileW(name, parent_reads ? GENERIC_WRITE : GENERIC_READ, 0, &sa, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    if (cli == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        CloseHandle(srv);
        SetLastError(e);
        return false;
    }
    *parent = srv;
    *child = cli;
    return true;
}

static HANDLE dup_inheritable(HANDLE h) {
    HANDLE d = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, 0, TRUE, DUPLICATE_SAME_ACCESS)) return NULL;
    return d;
}

static HANDLE open_null(void) {
    SECURITY_ATTRIBUTES sa = inherit_sa();
    return CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
}

static HANDLE open_file(const char *path, bool write, bool append) {
    DkArena *s = dk_scratch();
    DkArenaMark m = dk_arena_mark(s);
    wchar_t *w = to_wide(s, path);
    SECURITY_ATTRIBUTES sa = inherit_sa();
    HANDLE h;
    if (!write) {
        h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &sa, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    } else {
        h = CreateFileW(w, FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &sa,
                        append ? OPEN_ALWAYS : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE && append) {
            LARGE_INTEGER z = {0};
            SetFilePointerEx(h, z, NULL, FILE_END);
        }
    }
    dk_arena_reset(s, m);
    return h;
}

static const char *winerror_message(DkArena *a, DWORD code) {
    wchar_t buf[512];
    DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code,
                             MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, 512, NULL);
    while (n > 0 && (buf[n - 1] <= L' ' || buf[n - 1] == L'.')) n--;
    char *text = from_wide(a, buf, n);
    return dk_sprintf(a, "[WinError %lu] %s", (unsigned long)code, n ? text : "Unknown error");
}

static void set_failure(DkProcResult *r, DkArena *a, DWORD code) {
    memset(r, 0, sizeof *r);
    r->status = DK_PROC_START_FAILED;
    r->returncode = -1;
    r->winerror = code;
    r->message = winerror_message(a, code);
}

static void close_h(HANDLE *h) {
    if (*h && *h != INVALID_HANDLE_VALUE) CloseHandle(*h);
    *h = NULL;
}

static void stream_init(Stream *s, HANDLE h) {
    memset(s, 0, sizeof *s);
    s->h = h;
    if (h) s->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
}

/* Cancels a pending overlapped operation and waits for it to end (the buffer must outlive it). */
static void cancel_pending(HANDLE h, OVERLAPPED *ov, bool *pending) {
    if (!*pending) return;
    CancelIoEx(h, ov);
    DWORD n;
    GetOverlappedResult(h, ov, &n, TRUE);
    *pending = false;
}

static bool is_filtered_console_handle(HANDLE h) {
    return (((uintptr_t)h & 3) == 3) && GetFileType(h) == FILE_TYPE_CHAR;
}

static HANDLE std_or_null(DWORD which) {
    HANDLE h = GetStdHandle(which);
    if (h == NULL || h == INVALID_HANDLE_VALUE) return NULL;
    return h;
}

typedef struct {
    HANDLE h;
    bool ours; /* a handle we made for the child: closed after the spawn */
} ChildHandle;

static bool spawn(const DkProcSpec *spec, DkProc **out, DkProcResult *fail) {
    DkArena *a = spec->arena ? spec->arena : dk_arena();
    DkArena *s = dk_scratch();
    DkArenaMark mark = dk_arena_mark(s);
    DkProc *p = dk_xcalloc(1, sizeof *p);
    p->arena = a;
    p->text = spec->text;
    p->replace = spec->errors == DK_ERRORS_REPLACE;
    DWORD err = 0;
    bool ok = false;

    ChildHandle ch_in = {0}, ch_out = {0}, ch_err = {0};
    HANDLE par_in = NULL, par_out = NULL, par_err = NULL;
    HANDLE hproc = NULL, hthread = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    bool attrs_inited = false;

    /* the command line */
    char *cmd_utf8;
    if (spec->cmdline) cmd_utf8 = (char *)spec->cmdline;
    else if (spec->argv) cmd_utf8 = dk_list2cmdline(s, spec->argv);
    else dk_fatal("dk_run: neither argv nor cmdline");
    {
        /* the program's file name for messages: argv[0], or the command line's first word (quoted or not), without
         * its folder */
        const char *w = spec->argv ? spec->argv[0] : cmd_utf8;
        char stop = ' ';
        if (*w == '"') {
            w++;
            stop = '"';
        }
        const char *end = w;
        while (*end && !(*end == stop && !spec->argv)) end++;
        const char *base = w;
        for (const char *c = w; c < end; c++)
            if (*c == '/' || *c == '\\') base = c + 1;
        size_t n = (size_t)(end - base);
        if (n >= sizeof p->name) n = sizeof p->name - 1;
        memcpy(p->name, base, n);
        p->name[n] = 0;
        if (spec->shell) strcpy(p->name, "cmd.exe");
    }
    const wchar_t *executable = NULL;
    STARTUPINFOEXW si;
    memset(&si, 0, sizeof si);
    si.StartupInfo.cb = sizeof(STARTUPINFOW);
    if (spec->shell) {
        si.StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
        si.StartupInfo.wShowWindow = SW_HIDE;
        const char *comspec = env_get_utf8(s, "ComSpec");
        if (!comspec || !*comspec) {
            const char *root = env_get_utf8(s, "SystemRoot");
            comspec = dk_sprintf(s, "%s\\System32\\cmd.exe", root ? root : "");
            if (!(comspec[0] && comspec[1] == ':')) {
                err = ERROR_FILE_NOT_FOUND;
                goto fail_start;
            }
        }
        bool absolute = (comspec[0] && comspec[1] == ':' && is_sep(comspec[2])) || (is_sep(comspec[0]) && is_sep(comspec[1]));
        if (absolute) executable = to_wide(s, comspec);
        cmd_utf8 = dk_sprintf(s, "%s /c \"%s\"", comspec, cmd_utf8);
    }
    size_t wlen = (size_t)MultiByteToWideChar(CP_UTF8, 0, cmd_utf8, -1, NULL, 0);
    wchar_t *wcmd = dk_alloc_noz(s, sizeof(wchar_t) * (wlen + 1));
    MultiByteToWideChar(CP_UTF8, 0, cmd_utf8, -1, wcmd, (int)wlen);

    /* the standard handles */
    /* Always pass the three handles, inherited ones included: with no STARTF_USESTDHANDLES and no inheritance a
     * redirected stdout (a pipe or a file) never reaches the child, where Python's subprocess hands the child its
     * GetStdHandle values (found by cport-w2-g). */
    bool use_std = true;
    HANDLE hstd[3] = {NULL, NULL, NULL};
    if (use_std) {
        /* stdin */
        switch (spec->in) {
        case DK_IO_CAPTURE:
            if (!make_pipe(false, &par_in, &ch_in.h)) { err = GetLastError(); goto fail_start; }
            ch_in.ours = true;
            break;
        case DK_IO_NULL:
            ch_in.h = open_null();
            ch_in.ours = true;
            break;
        case DK_IO_FILE:
            ch_in.h = open_file(spec->in_path, false, false);
            ch_in.ours = true;
            break;
        case DK_IO_HANDLE:
            ch_in.h = dup_inheritable(spec->in_handle);
            ch_in.ours = true;
            break;
        default: {
            HANDLE h = std_or_null(STD_INPUT_HANDLE);
            ch_in.h = h ? dup_inheritable(h) : open_null();
            ch_in.ours = true;
        }
        }
        if (!ch_in.h || ch_in.h == INVALID_HANDLE_VALUE) { err = GetLastError(); goto fail_start; }
        /* stdout */
        switch (spec->out) {
        case DK_IO_CAPTURE:
            if (!make_pipe(true, &par_out, &ch_out.h)) { err = GetLastError(); goto fail_start; }
            ch_out.ours = true;
            break;
        case DK_IO_NULL:
            ch_out.h = open_null();
            ch_out.ours = true;
            break;
        case DK_IO_FILE:
            ch_out.h = open_file(spec->out_path, true, spec->out_append);
            ch_out.ours = true;
            break;
        case DK_IO_HANDLE:
            ch_out.h = dup_inheritable(spec->out_handle);
            ch_out.ours = true;
            break;
        default: {
            HANDLE h = std_or_null(STD_OUTPUT_HANDLE);
            ch_out.h = h ? dup_inheritable(h) : open_null();
            ch_out.ours = true;
        }
        }
        if (!ch_out.h || ch_out.h == INVALID_HANDLE_VALUE) { err = GetLastError(); goto fail_start; }
        /* stderr */
        switch (spec->err) {
        case DK_IO_CAPTURE:
            if (!make_pipe(true, &par_err, &ch_err.h)) { err = GetLastError(); goto fail_start; }
            ch_err.ours = true;
            break;
        case DK_IO_STDOUT:
            ch_err.h = ch_out.h; /* the same handle; not closed twice (ours = false) */
            p->merged = true;
            break;
        case DK_IO_NULL:
            ch_err.h = open_null();
            ch_err.ours = true;
            break;
        case DK_IO_FILE:
            ch_err.h = open_file(spec->err_path, true, spec->err_append);
            ch_err.ours = true;
            break;
        case DK_IO_HANDLE:
            ch_err.h = dup_inheritable(spec->err_handle);
            ch_err.ours = true;
            break;
        default: {
            HANDLE h = std_or_null(STD_ERROR_HANDLE);
            ch_err.h = h ? dup_inheritable(h) : open_null();
            ch_err.ours = true;
        }
        }
        if (!ch_err.h || ch_err.h == INVALID_HANDLE_VALUE) { err = GetLastError(); goto fail_start; }
        si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = ch_in.h;
        si.StartupInfo.hStdOutput = ch_out.h;
        si.StartupInfo.hStdError = ch_err.h;
        hstd[0] = ch_in.h;
        hstd[1] = ch_out.h;
        hstd[2] = ch_err.h;
    }

    /* only the standard handles are inherited (a handle list), as Python does with close_fds=True */
    HANDLE hlist[3];
    DWORD hcount = 0;
    if (use_std) {
        for (int i = 0; i < 3; i++) {
            bool dup = false;
            for (DWORD k = 0; k < hcount; k++)
                if (hlist[k] == hstd[i]) dup = true;
            if (!dup && !is_filtered_console_handle(hstd[i])) hlist[hcount++] = hstd[i];
        }
    }
    DWORD flags = spec->creation_flags | CREATE_UNICODE_ENVIRONMENT;
    if (spec->debug) flags |= DEBUG_ONLY_THIS_PROCESS;
    if (hcount > 0) {
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &size);
        attrs = dk_alloc(s, size);
        if (!InitializeProcThreadAttributeList(attrs, 1, 0, &size)) {
            err = GetLastError();
            goto fail_start;
        }
        attrs_inited = true;
        if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, hlist, hcount * sizeof(HANDLE), NULL,
                                       NULL)) {
            err = GetLastError();
            goto fail_start;
        }
        si.lpAttributeList = attrs;
        si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
        flags |= EXTENDED_STARTUPINFO_PRESENT;
    }
    /* Every child lives in its own Job object (limits below), so it is killed with its whole tree whenever it
     * overruns or is abandoned. It starts suspended so no grandchild can escape the job. */
    flags |= CREATE_SUSPENDED;

    wchar_t *wenv = spec->env ? env_block(s, spec->env) : NULL;
    wchar_t *wcwd = spec->cwd ? to_wide(s, spec->cwd) : NULL;
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(executable, wcmd, NULL, NULL, hcount > 0, flags, wenv, wcwd, &si.StartupInfo, &pi)) {
        err = GetLastError();
        goto fail_start;
    }
    hproc = pi.hProcess;
    hthread = pi.hThread;
    p->pid = pi.dwProcessId;
    {
        HANDLE job = CreateJobObjectW(NULL, NULL);
        if (job) {
            /* KILL_ON_JOB_CLOSE: the tree dies with our handle. DIE_ON_UNHANDLED_EXCEPTION: a crashing child (cl, link,
             * git, python) ends at once instead of raising a Windows Error Reporting box. */
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
            memset(&info, 0, sizeof info);
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof info);
            if (AssignProcessToJobObject(job, hproc)) p->job = job;
            else CloseHandle(job);
        }
        ResumeThread(hthread);
    }
    close_h(&hthread);
    p->hproc = hproc;
    ok = true;
    arm_ceiling(p, spec->timeout > 0 ? spec->timeout + 30.0 : 0.0, spec->timeout <= 0);
    goto cleanup;

fail_start:
    close_h(&par_in);
    close_h(&par_out);
    close_h(&par_err);
    set_failure(fail, a, err);
    dk_xfree(p);
    p = NULL;
cleanup:
    if (attrs_inited) DeleteProcThreadAttributeList(attrs);
    if (ch_in.ours) close_h(&ch_in.h);
    if (ch_out.ours) close_h(&ch_out.h);
    if (ch_err.ours) close_h(&ch_err.h);
    if (ok) {
        stream_init(&p->out, par_out);
        stream_init(&p->err, par_err);
        p->in_h = par_in;
        if (par_in) p->in_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    }
    dk_arena_reset(s, mark);
    *out = p;
    return ok;
}

static void ensure_exit(DkProc *p) {
    if (p->exited) return;
    if (WaitForSingleObject(p->hproc, 0) == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(p->hproc, &code);
        p->exitcode = code;
        p->exited = true;
    }
}

static void rd_arm(Stream *s) {
    if (!s->h || s->eof || s->pending) return;
    if (s->pos > 0 && s->pos == s->data.n) {
        s->pos = s->data.n = 0;
    } else if (s->pos >= 65536 && s->pos >= s->data.n / 2) { /* keep a long line-by-line read from growing without bound */
        memmove(s->data.p, s->data.p + s->pos, s->data.n - s->pos);
        s->data.n -= s->pos;
        s->pos = 0;
    }
    bytes_reserve(&s->data, READ_CHUNK);
    memset(&s->ov, 0, sizeof s->ov);
    s->ov.hEvent = s->ev;
    if (ReadFile(s->h, s->data.p + s->data.n, READ_CHUNK, NULL, &s->ov) || GetLastError() == ERROR_IO_PENDING) {
        s->pending = true;
    } else {
        s->eof = true; /* ERROR_BROKEN_PIPE: the child closed its end */
    }
}

static void rd_complete(Stream *s) {
    DWORD n = 0;
    BOOL ok = GetOverlappedResult(s->h, &s->ov, &n, FALSE);
    s->pending = false;
    if (ok && n > 0) s->data.n += n;
    else s->eof = true;
}

static void wr_arm(DkProc *p) {
    if (!p->in_h || p->in_pending || p->wpos >= p->wlen) return;
    size_t left = p->wlen - p->wpos;
    p->wchunk = left > 65536 ? 65536 : left;
    memset(&p->in_ov, 0, sizeof p->in_ov);
    p->in_ov.hEvent = p->in_ev;
    if (WriteFile(p->in_h, p->wdata + p->wpos, (DWORD)p->wchunk, NULL, &p->in_ov) || GetLastError() == ERROR_IO_PENDING) {
        p->in_pending = true;
    } else {
        p->wpos = p->wlen; /* the child closed its stdin: the rest is dropped (BrokenPipeError is ignored) */
    }
}

static void wr_complete(DkProc *p) {
    DWORD n = 0;
    BOOL ok = GetOverlappedResult(p->in_h, &p->in_ov, &n, FALSE);
    p->in_pending = false;
    if (ok) p->wpos += n;
    else p->wpos = p->wlen;
}

static void maybe_close_stdin(DkProc *p) {
    if (p->close_in_when_written && p->in_h && !p->in_pending && p->wpos >= p->wlen) {
        close_h(&p->in_h);
        close_h(&p->in_ev);
    }
}

/* One step of the I/O loop: arms the reads and the write, waits up to `ms` for any of them or the process to end,
 * and completes everything that is ready. Returns false on timeout; true when something happened or there is
 * nothing left to wait for. */
static bool io_step(DkProc *p, DWORD ms) {
    HANDLE hs[4];
    int kind[4]; /* 0 out, 1 err, 2 in, 3 process */
    DWORD n = 0;
    rd_arm(&p->out);
    rd_arm(&p->err);
    wr_arm(p);
    if (p->out.pending) { hs[n] = p->out.ev; kind[n++] = 0; }
    if (p->err.pending) { hs[n] = p->err.ev; kind[n++] = 1; }
    if (p->in_pending) { hs[n] = p->in_ev; kind[n++] = 2; }
    if (!p->exited) { hs[n] = p->hproc; kind[n++] = 3; }
    if (n == 0) return true;
    DWORD r = WaitForMultipleObjects(n, hs, FALSE, ms);
    if (r == WAIT_TIMEOUT) return false;
    if (r >= WAIT_OBJECT_0 + n) return true; /* WAIT_FAILED: nothing sensible to do */
    /* complete everything that is ready, so one busy stream cannot starve the others */
    for (DWORD i = 0; i < n; i++) {
        if (i != r - WAIT_OBJECT_0 && WaitForSingleObject(hs[i], 0) != WAIT_OBJECT_0) continue;
        switch (kind[i]) {
        case 0: rd_complete(&p->out); break;
        case 1: rd_complete(&p->err); break;
        case 2: wr_complete(p); maybe_close_stdin(p); break;
        default: ensure_exit(p); break;
        }
    }
    return true;
}

static bool streams_done(const DkProc *p) {
    return (!p->out.h || p->out.eof) && (!p->err.h || p->err.eof);
}

/* Milliseconds left until `deadline` (dk_monotonic seconds; < 0: none), at most INFINITE-1; 0 when passed. */
static DWORD ms_left(double deadline) {
    if (deadline < 0) return INFINITE;
    double left = (deadline - dk_monotonic()) * 1000.0;
    if (left <= 0) return 0;
    if (left >= 4.0e9) return 4000000000u;
    return (DWORD)ceil(left);
}

static size_t kill_tree_walk(DWORD pid, int depth, bool kill_root) {
    size_t found = 0;
    if (depth > 32) return 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W e;
        e.dwSize = sizeof e;
        DWORD kids[256];
        int nk = 0;
        for (BOOL ok = Process32FirstW(snap, &e); ok && nk < 256; ok = Process32NextW(snap, &e))
            if (e.th32ParentProcessID == pid && e.th32ProcessID != pid) kids[nk++] = e.th32ProcessID;
        CloseHandle(snap);
        for (int i = 0; i < nk; i++) found += kill_tree_walk(kids[i], depth + 1, true) + 1;
    }
    if (kill_root) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) {
            TerminateProcess(h, 1);
            CloseHandle(h);
        }
    }
    return found;
}

/* ---- the wall-clock ceiling ----
 * A process with no timeout of its own (spec->timeout 0: Python's None) still ends after DECOMPKIT_PROC_CEILING seconds
 * (default 1800): a threadpool timer terminates its job, whoever waits on it and however (dk_run, communicate, wait
 * with a negative timeout, a reader). The process then exits with DK_PROC_CEILING_EXIT, dk_run reports
 * DK_PROC_TIMEOUT, and this line goes to stderr. With a spec->timeout the timer is only a backstop past it. */

static double ceiling_seconds(void) {
    const char *e = getenv("DECOMPKIT_PROC_CEILING");
    if (e && *e) {
        char *end = NULL;
        double v = strtod(e, &end);
        if (end != e && *end == 0 && v > 0 && v < 1.0e7) return v;
    }
    return 1800.0;
}

static VOID CALLBACK ceiling_fired(PTP_CALLBACK_INSTANCE inst, PVOID ctx, PTP_TIMER timer) {
    DkProc *p = (DkProc *)ctx;
    DK_UNUSED(inst);
    DK_UNUSED(timer);
    if (p->exited || WaitForSingleObject(p->hproc, 0) == WAIT_OBJECT_0) return;
    InterlockedExchange(&p->ceil_hit, 1);
    if (p->ceil_is_ceiling)
        dk_warn("%s: killed %s after %g s (process ceiling DECOMPKIT_PROC_CEILING)", dk_tool_name(), p->name, p->ceil_s);
    else
        dk_warn("%s: killed %s after %g s (past its timeout)", dk_tool_name(), p->name, p->ceil_s);
    if (p->job) TerminateJobObject(p->job, DK_PROC_CEILING_EXIT);
    else kill_tree_walk(p->pid, 0, true);
    TerminateProcess(p->hproc, DK_PROC_CEILING_EXIT);
}

static void arm_ceiling(DkProc *p, double limit_s, bool is_ceiling) {
    p->ceil_is_ceiling = is_ceiling;
    p->ceil_s = is_ceiling ? ceiling_seconds() : limit_s;
    p->ceil_timer = CreateThreadpoolTimer(ceiling_fired, p, NULL);
    if (!p->ceil_timer) return;
    LONGLONG rel = -(LONGLONG)(p->ceil_s * 1.0e7); /* 100 ns units, negative: relative */
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)((ULONGLONG)rel & 0xFFFFFFFFu);
    ft.dwHighDateTime = (DWORD)((ULONGLONG)rel >> 32);
    SetThreadpoolTimer(p->ceil_timer, &ft, 0, 0);
}

static void disarm_ceiling(DkProc *p) {
    if (!p->ceil_timer) return;
    SetThreadpoolTimer(p->ceil_timer, NULL, 0, 0);
    WaitForThreadpoolTimerCallbacks(p->ceil_timer, TRUE);
    CloseThreadpoolTimer(p->ceil_timer);
    p->ceil_timer = NULL;
}

bool dk_proc_ceiling_hit(const DkProc *p) { return p->ceil_hit != 0; }

u32 dk_getpid(void) { return GetCurrentProcessId(); }

size_t dk_kill_descendants(void) { return kill_tree_walk(GetCurrentProcessId(), 0, false); }

void dk_proc_kill(DkProc *p) {
    if (!p->exited) TerminateProcess(p->hproc, 1);
}

void dk_proc_kill_tree(DkProc *p) {
    if (p->job) TerminateJobObject(p->job, 1);
    else kill_tree_walk(p->pid, 0, true);
    if (!p->exited) TerminateProcess(p->hproc, 1);
}

u32 dk_proc_pid(const DkProc *p) { return p->pid; }

bool dk_proc_poll(DkProc *p, i64 *rc) {
    ensure_exit(p);
    if (p->exited && rc) *rc = p->exitcode;
    return p->exited;
}

bool dk_proc_wait(DkProc *p, double timeout, i64 *rc) {
    double deadline = timeout >= 0 ? dk_monotonic() + timeout : -1;
    ensure_exit(p);
    while (!p->exited) {
        DWORD ms = ms_left(deadline);
        if (deadline >= 0 && ms == 0) return false;
        io_step(p, ms); /* the pipes are read meanwhile, so a chatty child cannot block on a full pipe */
        if (deadline >= 0 && !p->exited && ms_left(deadline) == 0) return false;
    }
    if (rc) *rc = p->exitcode;
    return true;
}

int dk_proc_wait_any(DkProc *const *ps, size_t n, double timeout) {
    double deadline = timeout >= 0 ? dk_monotonic() + timeout : -1;
    for (;;) {
        for (size_t i = 0; i < n; i++) {
            ensure_exit(ps[i]);
            if (ps[i]->exited) return (int)i;
        }
        DWORD ms = ms_left(deadline);
        if (deadline >= 0 && ms == 0) return -1;
        if (n <= MAXIMUM_WAIT_OBJECTS) {
            HANDLE hs[MAXIMUM_WAIT_OBJECTS];
            for (size_t i = 0; i < n; i++) hs[i] = ps[i]->hproc;
            DWORD r = WaitForMultipleObjects((DWORD)n, hs, FALSE, ms);
            if (r == WAIT_TIMEOUT) return -1;
        } else {
            dk_sleep(0.001);
        }
    }
}

bool dk_proc_write(DkProc *p, const void *data, size_t n) {
    if (!p->in_h) return false;
    p->wdata = data;
    p->wlen = n;
    p->wpos = 0;
    bool wrote_all = true;
    while (p->wpos < p->wlen || p->in_pending) {
        io_step(p, INFINITE);
        if (!p->in_h) break;
    }
    if (p->wpos < p->wlen) wrote_all = false;
    p->wdata = NULL;
    p->wlen = p->wpos = 0;
    return wrote_all;
}

void dk_proc_close_stdin(DkProc *p) {
    if (!p->in_h) return;
    cancel_pending(p->in_h, &p->in_ov, &p->in_pending);
    close_h(&p->in_h);
    close_h(&p->in_ev);
}

static Stream *stream_of(DkProc *p, int which) { return which == 2 ? &p->err : &p->out; }

/* Waits until the stream holds at least `want` unread bytes, ends, or the deadline passes. */
static void fill_stream(DkProc *p, Stream *s, size_t want, double deadline) {
    while (s->data.n - s->pos < want && !s->eof) {
        DWORD ms = ms_left(deadline);
        if (deadline >= 0 && ms == 0) return;
        io_step(p, ms);
    }
}

size_t dk_proc_read(DkProc *p, int which, void *buf, size_t cap, double timeout, bool *timed_out) {
    Stream *s = stream_of(p, which);
    if (timed_out) *timed_out = false;
    if (!s->h || cap == 0) return 0;
    double deadline = timeout >= 0 ? dk_monotonic() + timeout : -1;
    fill_stream(p, s, 1, deadline);
    size_t avail = s->data.n - s->pos;
    if (avail == 0) {
        if (timed_out && !s->eof) *timed_out = true;
        return 0;
    }
    size_t k = avail < cap ? avail : cap;
    memcpy(buf, s->data.p + s->pos, k);
    s->pos += k;
    return k;
}

size_t dk_proc_read_exact(DkProc *p, int which, void *buf, size_t n) {
    Stream *s = stream_of(p, which);
    if (!s->h) return 0;
    fill_stream(p, s, n, -1);
    size_t avail = s->data.n - s->pos;
    size_t k = avail < n ? avail : n;
    memcpy(buf, s->data.p + s->pos, k);
    s->pos += k;
    return k;
}

bool dk_proc_readline(DkProc *p, int which, DkStr *line) {
    Stream *s = stream_of(p, which);
    if (!s->h) return false;
    size_t scanned = 0;
    for (;;) {
        const u8 *base = s->data.p + s->pos;
        size_t avail = s->data.n - s->pos;
        size_t i = scanned;
        size_t term = (size_t)-1, term_len = 0;
        for (; i < avail; i++) {
            if (base[i] == '\n') {
                term = i;
                term_len = 1;
                break;
            }
            if (p->text && base[i] == '\r') {
                if (i + 1 < avail) {
                    term = i;
                    term_len = base[i + 1] == '\n' ? 2 : 1;
                    break;
                }
                if (s->eof) {
                    term = i;
                    term_len = 1;
                    break;
                }
                break; /* a final "\r": wait to see whether "\n" follows */
            }
        }
        if (term != (size_t)-1) {
            size_t total = term + term_len;
            if (p->text) {
                bytes_reserve(&s->line, term * 3 + 4);
                size_t on = 0;
                if (decode_utf8(base, term, p->replace, false, s->line.p, s->line.cap - 2, &on) != 0) on = 0;
                s->line.p[on++] = '\n';
                s->line.p[on] = 0;
                s->line.n = on;
                *line = (DkStr){(const char *)s->line.p, on};
            } else {
                *line = (DkStr){(const char *)base, total};
            }
            s->pos += total;
            return true;
        }
        if (s->eof) {
            if (avail == 0) return false;
            /* the last line has no terminator */
            if (p->text) {
                bytes_reserve(&s->line, avail * 3 + 4);
                size_t on = 0;
                if (decode_utf8(base, avail, p->replace, false, s->line.p, s->line.cap - 2, &on) != 0) on = 0;
                s->line.p[on] = 0;
                s->line.n = on;
                *line = (DkStr){(const char *)s->line.p, on};
            } else {
                *line = (DkStr){(const char *)base, avail};
            }
            s->pos += avail;
            return true;
        }
        scanned = avail;
        if (scanned > 0 && p->text && base[scanned - 1] == '\r') scanned--; /* re-examine a trailing \r */
        io_step(p, INFINITE);
    }
}

static DkStr finish_stream(DkProc *p, Stream *s, bool *decode_err) {
    if (!s->h) return (DkStr){NULL, 0};
    const u8 *src = s->data.p ? s->data.p + s->pos : (const u8 *)"";
    size_t n = s->data.n - s->pos;
    DkArena *a = p->arena;
    if (!p->text) {
        u8 *d = dk_alloc_noz(a, n + 1);
        if (n) memcpy(d, src, n);
        d[n] = 0;
        return (DkStr){(const char *)d, n};
    }
    DkStr text;
    if (!decode_to_arena(a, src, n, p->replace, true, &text)) *decode_err = true;
    return text;
}

bool dk_proc_communicate(DkProc *p, const void *input, size_t input_n, double timeout, DkProcResult *r) {
    double deadline = timeout >= 0 ? dk_monotonic() + timeout : -1;
    memset(r, 0, sizeof *r);
    r->pid = p->pid;
    if (p->in_h) {
        if (input && input_n) {
            p->wdata = input;
            p->wlen = input_n;
            p->wpos = 0;
            p->close_in_when_written = true;
        } else {
            dk_proc_close_stdin(p);
        }
    }
    bool timed_out = false;
    for (;;) {
        ensure_exit(p);
        bool writing = p->in_h && (p->wpos < p->wlen || p->in_pending);
        if (streams_done(p) && !writing && p->exited) break;
        if (streams_done(p) && !writing && !p->exited) {
            DWORD ms = ms_left(deadline);
            if (deadline >= 0 && ms == 0) { timed_out = true; break; }
            if (WaitForSingleObject(p->hproc, ms) == WAIT_TIMEOUT) { timed_out = true; break; }
            continue;
        }
        DWORD ms = ms_left(deadline);
        if (deadline >= 0 && ms == 0) { timed_out = true; break; }
        if (!io_step(p, ms) && deadline >= 0 && ms_left(deadline) == 0) { timed_out = true; break; }
    }
    p->wdata = NULL;
    p->wlen = p->wpos = 0;
    bool decode_err = false;
    r->out = finish_stream(p, &p->out, &decode_err);
    r->err = finish_stream(p, &p->err, &decode_err);
    if (!timed_out) { /* what was returned is consumed (after a timeout the caller may collect the rest) */
        p->out.pos = p->out.data.n;
        p->err.pos = p->err.data.n;
    }
    ensure_exit(p);
    r->returncode = p->exited ? (i64)p->exitcode : -1;
    if (timed_out) r->status = DK_PROC_TIMEOUT;
    else if (decode_err) r->status = DK_PROC_DECODE_ERROR;
    return !timed_out;
}

void dk_proc_close(DkProc *p) {
    disarm_ceiling(p); /* before the job handle goes: the timer's callback uses it */
    cancel_pending(p->out.h, &p->out.ov, &p->out.pending);
    cancel_pending(p->err.h, &p->err.ov, &p->err.pending);
    if (p->in_h) cancel_pending(p->in_h, &p->in_ov, &p->in_pending);
    close_h(&p->out.h);
    close_h(&p->err.h);
    close_h(&p->out.ev);
    close_h(&p->err.ev);
    close_h(&p->in_h);
    close_h(&p->in_ev);
    close_h(&p->hproc);
    close_h(&p->job);
    bytes_free(&p->out.data);
    bytes_free(&p->err.data);
    bytes_free(&p->out.line);
    bytes_free(&p->err.line);
    dk_xfree(p);
}

DkProc *dk_proc_start(const DkProcSpec *spec, DkProcResult *failure) {
    DkProc *p = NULL;
    DkProcResult dummy;
    if (!failure) failure = &dummy;
    if (!spawn(spec, &p, failure)) return NULL;
    return p;
}

DkProcResult dk_run(const DkProcSpec *spec) {
    DkProcResult r;
    DkProc *p = NULL;
    if (!spawn(spec, &p, &r)) return r;
    bool in_time = dk_proc_communicate(p, spec->input, spec->input_n, spec->timeout > 0 ? spec->timeout : -1, &r);
    if (!in_time) {
        /* TimeoutExpired: the tree is killed and what it wrote so far is kept (Python's communicate() after kill) */
        dk_proc_kill_tree(p);
        double deadline = dk_monotonic() + 5.0;
        while (!(streams_done(p) && p->exited) && ms_left(deadline) > 0) io_step(p, ms_left(deadline));
        DkProcResult again;
        dk_proc_communicate(p, NULL, 0, 0.0, &again);
        r.out = again.out;
        r.err = again.err;
        ensure_exit(p);
        r.returncode = p->exited ? (i64)p->exitcode : -1;
        r.status = DK_PROC_TIMEOUT;
    } else if (dk_proc_ceiling_hit(p)) {
        r.status = DK_PROC_TIMEOUT; /* the ceiling killed it: the caller sees a timeout, the line is on stderr */
    } else if (r.status == DK_PROC_OK && spec->check && r.returncode != 0) {
        r.status = DK_PROC_BAD_EXIT;
    }
    dk_proc_close(p);
    return r;
}

DkProcResult dk_run_text(DkArena *a, const char *cwd, const char *const *argv) {
    DkProcSpec s = {0};
    s.argv = argv;
    s.cwd = cwd;
    s.out = DK_IO_CAPTURE;
    s.err = DK_IO_CAPTURE;
    s.text = true;
    s.errors = DK_ERRORS_REPLACE;
    s.arena = a;
    return dk_run(&s);
}

/* ---- children die with the tool ---- */

static HANDLE g_job;
static DkOnce g_job_once;

static void make_kill_job(void *ctx) {
    DK_UNUSED(ctx);
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job) return;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
    memset(&info, 0, sizeof info);
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof info) &&
        AssignProcessToJobObject(job, GetCurrentProcess())) {
        g_job = job; /* held open for the life of the process; the system closes it when the process ends */
    } else {
        CloseHandle(job);
    }
}

bool dk_kill_children_with_parent(void) {
    dk_once(&g_job_once, make_kill_job, NULL);
    return g_job != NULL;
}

/* ---- processes holding files ---- */

size_t dk_file_lockers(DkArena *a, const char *dir, bool end, DkStrVec *held) {
    DkPtrVec files = {0};
    DkWalk *w = dk_walk_open(dir, true);
    DkWalkItem it = {0};
    while (w && dk_walk_next(w, &it))
        for (size_t i = 0; i < it.files.n; i++) {
            char *full = dk_path_join(a, dk_cz(a, it.dirpath), dk_cz(a, it.files.v[i]));
            dk_vec_push(&files, dk_to_wz(a, full));
        }
    if (w) dk_walk_close(w);
    if (!files.n) {
        dk_vec_free(&files);
        return 0;
    }
    DWORD session;
    WCHAR key[CCH_RM_SESSION_KEY + 1] = {0};
    if (RmStartSession(&session, 0, key) != ERROR_SUCCESS) {
        dk_vec_free(&files);
        return 0;
    }
    size_t found = 0;
    if (RmRegisterResources(session, (UINT)files.n, (LPCWSTR *)files.v, 0, NULL, 0, NULL) == ERROR_SUCCESS) {
        UINT need = 0, have = 0;
        DWORD reasons = 0;
        RM_PROCESS_INFO *info = NULL;
        DWORD rc = RmGetList(session, &need, &have, NULL, &reasons);
        if (rc == ERROR_MORE_DATA && need) {
            have = need;
            info = dk_xcalloc(have, sizeof *info);
            rc = RmGetList(session, &need, &have, info, &reasons);
        }
        if (rc == ERROR_SUCCESS && info) {
            DWORD self = GetCurrentProcessId();
            for (UINT i = 0; i < have; i++) {
                DWORD pid = info[i].Process.dwProcessId;
                if (pid == self) continue;
                found++;
                DkStr name = dk_from_w(a, info[i].strAppName, -1);
                if (held) dk_vec_push(held, dk_pyfmt(a, "%S (pid %u)", &name, (unsigned)pid));
                if (!end) continue;
                HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
                if (!h) continue;
                TerminateProcess(h, 1);
                WaitForSingleObject(h, 5000);
                CloseHandle(h);
            }
        }
        dk_xfree(info);
    }
    RmEndSession(session);
    dk_vec_free(&files);
    return found;
}
