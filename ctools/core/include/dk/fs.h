// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Files, paths and directory walking with CPython 3.14-on-Windows behaviour: open() and its text modes, the os,
 * os.path (ntpath), glob, fnmatch, shutil and tempfile functions the tools call, returning what Python returns and
 * failing the way Python fails.
 *
 * Paths are UTF-8, NUL-terminated (`const char *`), with / or \ as separators, and are passed to Win32 as UTF-16
 * (a \\?\ prefix is added by the module when a path would exceed MAX_PATH, so long paths work as they do for Python).
 * Strings the module returns are allocated from the arena given; vectors (DkStrVec, ...) are heap vectors whose
 * strings live in that arena, and every DkStr in them is NUL-terminated (p[n] == 0) so `.p` is a C string.
 *
 * ---- errors ------------------------------------------------------------------------------------------------------
 * A function that can fail returns false (or NULL, or -1 for a count) and records the failure in a thread-local
 * DkIoErr, which describes the exception Python would have raised: its class, errno, winerror and filename(s).
 * dk_io_err_str() is str(exception), e.g.
 *     [Errno 2] No such file or directory: 'x.txt'                       open()
 *     [WinError 2] The system cannot find the file specified: 'x.txt'    os.remove, os.stat, os.rename, ...
 *     [WinError 2] The system cannot find the file specified: 'a' -> 'b' os.replace, os.rename
 * (open() reports CRT errno values with strerror texts; the os.* functions report the Win32 error with the system's
 * FormatMessage text; both quote the path with repr(), so backslashes are doubled). The record of the last failure is
 * valid until the same thread's next failing call in this module; successful calls leave it alone. Python
 * "except FileNotFoundError" is dk_io_is(ENOENT); "except OSError" is any failure of kind DK_IOE_OS.
 *
 * ---- text ------------------------------------------------------------------------------------------------------
 * open(path, encoding=E, errors=R, newline=N) is the DkTextMode {E, R, N}: reading decodes the bytes and translates
 * newlines the way TextIOWrapper does, writing does the reverse. Text inside the program is always UTF-8.
 *   newline=None  (DK_NL_DEFAULT): reading turns \r\n and \r into \n; writing turns \n into the platform's \r\n
 *   newline=""    (DK_NL_EMPTY):   reading splits lines at \n, \r and \r\n but does not translate; writing as is
 *   newline="\n"  (DK_NL_LF):      reading splits at \n only; writing as is
 *   newline="\r" / "\r\n"           (DK_NL_CR / DK_NL_CRLF): reading splits at that only; writing turns \n into it
 * Encodings: utf-8, utf-8-sig (reading drops one leading BOM, writing puts one at the start of the file), latin-1,
 * ascii and mbcs (the ANSI code page). Errors: strict (a bad byte fails with kind DK_IOE_DECODE and Python's
 * UnicodeDecodeError text) or replace (U+FFFD, one per maximal invalid subpart exactly as CPython's utf-8 decoder).
 *
 * Environment variable names are case-insensitive as os.environ is on Windows (keys are upper-cased when listed).
 *
 * Deviations from Python (also in the report of the worker): temporary names are random (D1); the order of
 * pathlib's glob/rglob is not reproduced (callers sort, as the tools do); UnicodeDecodeError positions are those of
 * a whole-file read (a `for line in f` loop in Python reports them relative to its 8 KiB chunk).
 */
#pragma once
#include "arena.h"
#include "str.h"
#include "vec.h"

/* ---- errors ----------------------------------------------------------------------------------------------------- */
enum {
    DK_IOE_NONE = 0,
    DK_IOE_OS,       /* OSError and its subclasses (FileNotFoundError, PermissionError, ...) */
    DK_IOE_DECODE,   /* UnicodeDecodeError */
    DK_IOE_ENCODE,   /* UnicodeEncodeError */
    DK_IOE_VALUE,    /* ValueError: "embedded null character", relpath's "no path specified", commonpath, ... */
    DK_IOE_SHUTIL    /* shutil.Error / SameFileError / SpecialFileError (msg holds str(exception)) */
};
typedef struct DkIoErr {
    int kind;            /* DK_IOE_* */
    int err;             /* OSError.errno (the CRT <errno.h> numbers, as Python's errno module on Windows) */
    int winerror;        /* OSError.winerror; 0 when Python's text has the "[Errno n]" form */
    char path[1040];     /* OSError.filename ("" when none), UTF-8, as passed (longer names are cut) */
    char path2[1040];    /* OSError.filename2 */
    char msg[512];       /* the full str(exception) of non-OSError kinds */
} DkIoErr;

const DkIoErr *dk_io_err(void);               /* this thread's last failure */
bool dk_io_is(int err);                        /* last failure is an OSError with this errno (ENOENT, EEXIST, EACCES, ...) */
const char *dk_io_err_class(void);             /* type(exc).__name__: "FileNotFoundError", "PermissionError", "OSError", ... */
DkStr dk_io_err_str(DkArena *a);             /* str(exc) */
DkStr dk_io_err_repr_path(DkArena *a, const char *s); /* repr(str) as Python prints it ('it''s' -> "it's") */
void dk_io_clear(void);
/* For other modules that raise an OSError the way Python does (the fields are copied into the thread's record). */
void dk_io_fail_errno(int err, const char *path, const char *path2);     /* [Errno n] text: 'path' */
void dk_io_fail_win(unsigned winerror, const char *path, const char *path2); /* [WinError n] text: 'path' */
void dk_io_fail_msg(int kind, int err, const char *fmt, ...);            /* a preformatted text */

/* ---- text modes -------------------------------------------------------------------------------------------------- */
typedef enum { DK_ENC_UTF8, DK_ENC_UTF8_SIG, DK_ENC_LATIN1, DK_ENC_ASCII, DK_ENC_MBCS } DkEncoding;
typedef enum { DK_ERR_STRICT, DK_ERR_REPLACE } DkErrorsMode;
typedef enum { DK_NL_DEFAULT, DK_NL_EMPTY, DK_NL_LF, DK_NL_CR, DK_NL_CRLF } DkNewline;
typedef struct {
    DkEncoding enc;
    DkErrorsMode errors;
    DkNewline newline;
} DkTextMode;
#define DK_TEXT(e, r, n) ((DkTextMode){(e), (r), (n)})
#define DK_TM_UTF8 DK_TEXT(DK_ENC_UTF8, DK_ERR_STRICT, DK_NL_DEFAULT)          /* open(p, encoding="utf-8") */
#define DK_TM_UTF8_NL_EMPTY DK_TEXT(DK_ENC_UTF8, DK_ERR_STRICT, DK_NL_EMPTY)   /* ..., newline="" */
#define DK_TM_UTF8_NL_LF DK_TEXT(DK_ENC_UTF8, DK_ERR_STRICT, DK_NL_LF)         /* ..., newline="\n" */
#define DK_TM_UTF8_REPLACE DK_TEXT(DK_ENC_UTF8, DK_ERR_REPLACE, DK_NL_DEFAULT) /* ..., errors="replace" */
#define DK_TM_UTF8_SIG DK_TEXT(DK_ENC_UTF8_SIG, DK_ERR_STRICT, DK_NL_DEFAULT)
#define DK_TM_UTF8_SIG_REPLACE DK_TEXT(DK_ENC_UTF8_SIG, DK_ERR_REPLACE, DK_NL_DEFAULT)
#define DK_TM_LATIN1 DK_TEXT(DK_ENC_LATIN1, DK_ERR_STRICT, DK_NL_DEFAULT)

/* bytes.decode() plus TextIOWrapper's newline handling, over a whole file's bytes. false: kind DK_IOE_DECODE. */
bool dk_decode_text(DkArena *a, DkStr bytes, DkTextMode m, DkStr *out);
/* str.encode() plus the writer's newline translation (what open(p, "w", ...).write(text) puts in the file).
 * false: kind DK_IOE_ENCODE (a character the encoding cannot hold). The result is allocated from `a`. */
bool dk_encode_text(DkArena *a, DkStr text, DkTextMode m, DkStr *out);

/* `for line in f` over decoded text: lines keep their terminator; the last one may have none. In DK_NL_DEFAULT
 * mode the text was already translated, so lines end at \n. */
typedef struct {
    DkStr rest;
    DkNewline newline;
} DkFileLines;
void dk_file_lines_init(DkFileLines *it, DkStr text, DkNewline newline);
bool dk_file_lines_next(DkFileLines *it, DkStr *line);

/* ---- whole files ------------------------------------------------------------------------------------------------ */
/* A read-only view of a whole file: memory-mapped above 64 KiB, read into memory below. An empty file gives
 * p != NULL and n == 0. file/mapping are the Win32 handles (NULL for a file read into memory). */
typedef struct {
    const u8 *p;
    size_t n;
    void *file, *mapping;
} DkFileView;
bool dk_view_open(const char *path, DkFileView *v);
void dk_view_close(DkFileView *v);
/* open(path, "rb").read() into `a` (a == NULL: heap memory, release with dk_vec_free). */
bool dk_read_all(DkArena *a, const char *path, DkBytes *out);
/* open(path, "r", encoding=..., errors=..., newline=...).read(): the text as UTF-8 in `a`. */
bool dk_read_text(DkArena *a, const char *path, DkTextMode m, DkStr *out);
/* list(open(path, ...)): the lines (terminators kept) as NUL-terminated strings of `a`, in a heap vector. */
bool dk_read_lines(DkArena *a, const char *path, DkTextMode m, DkStrVec *out);
/* Path.read_bytes()/read_text() are the same calls. */

/* open(path, "wb").write(p) / open(path, "w", ...).write(text) / open(path, "a", ...).write(text) */
bool dk_write_file(const char *path, const void *p, size_t n);
bool dk_write_text(const char *path, DkStr text, DkTextMode m);
bool dk_append_text(const char *path, DkStr text, DkTextMode m);
bool dk_append_file(const char *path, const void *p, size_t n);
/* A temporary file in the same folder, then MoveFileExW(MOVEFILE_REPLACE_EXISTING): a reader never sees half a file.
 * The temporary name is path + ".<pid>.<tid>.<n>.tmp" (D1). */
bool dk_write_atomic(const char *path, const void *p, size_t n);
bool dk_write_text_atomic(const char *path, DkStr text, DkTextMode m);

/* ---- open files (a buffered handle: open(), .read/.write/.seek/.flush, os.fsync, close) ---------------------------
 * mode as Python's open(): "r" "rb" "w" "wb" "a" "ab" "x" "xb" "r+" "r+b" "w+" "w+b" "a+" "a+b". In a text mode ("w", "a",
 * "x", "w+", "a+") dk_fwrite_text encodes and translates newlines per `tm`; dk_fwrite always writes the bytes as
 * given. Reading through an DkFile is binary (read whole text files with dk_read_text). */
typedef struct DkFile DkFile;
DkFile *dk_fopen(const char *path, const char *mode, DkTextMode tm);
bool dk_fwrite(DkFile *f, const void *p, size_t n);
bool dk_fwrite_text(DkFile *f, DkStr text);
bool dk_fprintf(DkFile *f, DK_PRINTF_FMT const char *fmt, ...); /* C printf rules, then dk_fwrite_text */
i64 dk_fread(DkFile *f, void *p, size_t n);                      /* bytes read (0 at the end), -1 on error */
bool dk_fseek(DkFile *f, i64 offset, int whence);                /* whence: 0 start, 1 current, 2 end */
i64 dk_ftell(DkFile *f);
i64 dk_fsize(DkFile *f);
bool dk_ftruncate(DkFile *f, i64 size);
bool dk_fflush(DkFile *f);
bool dk_fsync(DkFile *f);                                        /* flush, then FlushFileBuffers (os.fsync) */
void *dk_fhandle(DkFile *f);                                     /* the Win32 HANDLE (for byte-range locks in win.h) */
bool dk_fclose(DkFile *f);                                       /* false when the final flush failed */

/* ---- os.path (ntpath) -------------------------------------------------------------------------------------------- */
/* Pure string functions, exactly ntpath's results (checked against os.path on thousands of paths). */
char *dk_path_normcase(DkArena *a, const char *p);   /* LCMapStringEx lower case (invariant locale) and / -> \ */
bool dk_path_isabs(const char *p);                    /* 3.13+: "\x" and "c:x" are not absolute */
char *dk_path_join(DkArena *a, const char *first, const char *second);
char *dk_path_joinv(DkArena *a, size_t n, const char *const *parts); /* join(parts[0], parts[1:]...); n >= 1 */
#define dk_join(a, ...) \
    dk_path_joinv((a), sizeof((const char *const[]){__VA_ARGS__}) / sizeof(const char *), (const char *const[]){__VA_ARGS__})
/* splitroot -> (drive, root, tail): views into p. splitdrive -> (drive, rest). */
void dk_path_splitroot(const char *p, DkStr *drive, DkStr *root, DkStr *tail);
void dk_path_splitdrive(const char *p, DkStr *drive, DkStr *rest);
void dk_path_split(const char *p, DkStr *head, DkStr *tail);   /* head keeps no trailing separator unless it is the root */
void dk_path_splitext(const char *p, DkStr *root, DkStr *ext);  /* leading dots of the name are not an extension */
DkStr dk_path_basename(const char *p);                           /* views into p */
DkStr dk_path_dirname(const char *p);
char *dk_path_normpath(DkArena *a, const char *p);
char *dk_path_abspath(DkArena *a, const char *p);                /* GetFullPathNameW, fallbacks as ntpath */
char *dk_path_realpath(DkArena *a, const char *p);               /* strict=False; resolves symlinks and junctions */
/* relpath(path, start): false with kind DK_IOE_VALUE ("no path specified", "path is on mount 'C:', start on mount
 * 'D:'"). start == NULL is the current directory. */
bool dk_path_relpath(DkArena *a, const char *p, const char *start, char **out);
/* commonpath(paths): false with kind DK_IOE_VALUE (empty list, "Paths don't have the same drive", "Can't mix
 * absolute and relative paths", "Can't mix rooted and not-rooted paths"). */
bool dk_path_commonpath(DkArena *a, const char *const *paths, size_t n, char **out);
char *dk_path_expanduser(DkArena *a, const char *p);             /* ~ via USERPROFILE / HOMEDRIVE+HOMEPATH */
bool dk_path_samefile(const char *a, const char *b);              /* os.path.samefile; false (and an error) when either fails */
/* Backslash form to forward slashes: Path.as_posix(), str.replace("\\", "/"). */
char *dk_path_as_posix(DkArena *a, const char *p);

/* Queries: exist, isfile, isdir follow links and are false on any error, as in Python. */
bool dk_exists(const char *p);
bool dk_lexists(const char *p);       /* os.path.lexists: a dangling link exists */
bool dk_isfile(const char *p);
bool dk_isdir(const char *p);
bool dk_islink(const char *p);        /* symbolic links only (a junction is not a link for os.path.islink) */
bool dk_isjunction(const char *p);
bool dk_getsize(const char *p, i64 *size);            /* os.path.getsize; false with OSError */
bool dk_getmtime(const char *p, double *seconds);     /* os.path.getmtime (float seconds since 1970) */

/* ---- stat ------------------------------------------------------------------------------------------------------ */
#define DK_S_IFMT 0170000
#define DK_S_IFDIR 0040000
#define DK_S_IFREG 0100000
#define DK_S_IFLNK 0120000
#define DK_S_ISDIR(m) (((m) & DK_S_IFMT) == DK_S_IFDIR)
#define DK_S_ISREG(m) (((m) & DK_S_IFMT) == DK_S_IFREG)
#define DK_S_ISLNK(m) (((m) & DK_S_IFMT) == DK_S_IFLNK)
#define DK_FILE_ATTRIBUTE_DIRECTORY 0x10
#define DK_FILE_ATTRIBUTE_REPARSE_POINT 0x400
#define DK_IO_REPARSE_TAG_MOUNT_POINT 0xA0000003u
#define DK_IO_REPARSE_TAG_SYMLINK 0xA000000Cu
typedef struct {
    u32 mode;                       /* st_mode */
    u32 nlink;
    u64 dev, ino;                   /* volume serial number, file index (as CPython reports them) */
    u64 ino_hi;                     /* the high half of a 128-bit file id (ReFS); 0 where ids are 64 bits (NTFS) */
    i64 size;
    i64 atime_ns, mtime_ns, ctime_ns; /* st_*time_ns (ctime is the creation time on Windows) */
    double atime, mtime, ctime;     /* st_*time: sec + nsec * 1e-9 computed as CPython does */
    u32 file_attributes;            /* st_file_attributes */
    u32 reparse_tag;                /* st_reparse_tag (0 when not a reparse point) */
} DkStat;
bool dk_stat(const char *p, DkStat *st);   /* os.stat: follows links */
bool dk_lstat(const char *p, DkStat *st);  /* os.lstat */
bool dk_fstat(DkFile *f, DkStat *st);     /* os.fstat */

/* ---- os: files, folders, environment ---------------------------------------------------------------------------- */
bool dk_mkdir(const char *p);
bool dk_makedirs(const char *p, bool exist_ok);   /* os.makedirs(p, exist_ok=...) incl. the error cases */
bool dk_remove(const char *p);                    /* os.remove / os.unlink (a directory link is removed with RemoveDirectory) */
bool dk_rmdir(const char *p);
bool dk_rename(const char *src, const char *dst); /* fails when dst exists */
bool dk_replace(const char *src, const char *dst);/* MoveFileExW(MOVEFILE_REPLACE_EXISTING) */
char *dk_getcwd(DkArena *a);
bool dk_chdir(const char *p);
/* os.utime(p, None) sets both times to now; with times: (atime_ns, mtime_ns). */
bool dk_utime_now(const char *p);
bool dk_utime_ns(const char *p, i64 atime_ns, i64 mtime_ns);
/* os.chmod(p, mode): on Windows only the S_IWRITE bit counts (clear = read-only attribute). */
bool dk_chmod(const char *p, int mode);
bool dk_symlink(const char *target, const char *link, bool target_is_dir);
bool dk_junction_create(const char *link, const char *target);   /* mklink /J */
bool dk_link(const char *existing, const char *newlink);          /* os.link (hard link) */
bool dk_readlink(DkArena *a, const char *p, char **out);         /* os.readlink, with the \\?\ prefix as Python gives it */

/* Environment: getenv returns NULL when unset; the value is allocated from `a`. */
char *dk_getenv(DkArena *a, const char *name);
const char *dk_getenv_or(DkArena *a, const char *name, const char *dflt);
bool dk_setenv(const char *name, const char *value);   /* os.environ[name] = value (also for child processes) */
bool dk_unsetenv(const char *name);
typedef struct {
    DkStr name;    /* upper-cased as os.environ's keys are */
    DkStr value;
} DkEnvEntry;
typedef DK_VEC(DkEnvEntry) DkEnvVec;
DkEnvVec dk_environ(DkArena *a);                      /* dict(os.environ), in the environment block's order */

/* ---- directories ------------------------------------------------------------------------------------------------ */
typedef struct {
    DkStr name;          /* DirEntry.name */
    DkStr path;          /* DirEntry.path: join(scandir argument, name) */
    u32 attrs;            /* dwFileAttributes */
    u32 reparse_tag;      /* the reparse tag when the entry is a reparse point, else 0 */
    bool is_dir;          /* DirEntry.is_dir(): follows symlinks and junctions (false when the target is gone) */
    bool is_file;         /* DirEntry.is_file() */
    bool is_symlink;      /* DirEntry.is_symlink(): symbolic links only */
    bool is_junction;     /* DirEntry.is_junction() */
    i64 size;             /* DirEntry.stat(follow_symlinks=False) data from the listing itself */
    i64 atime_ns, mtime_ns, ctime_ns;
} DkDirEntry;
typedef DK_VEC(DkDirEntry) DkDirEntries;
/* list(os.scandir(p)): the entries in the order the file system returns them (what FindFirstFile gives, "." and ".."
 * left out). An empty p lists the current directory. */
bool dk_scandir(DkArena *a, const char *p, DkDirEntries *out);
/* os.listdir(p): the names in the same order. */
bool dk_listdir(DkArena *a, const char *p, DkStrVec *out);

/* os.walk(top, topdown, followlinks=False). Each dk_walk_next yields (dirpath, dirnames, filenames); topdown:
 * the caller may drop entries from item.dirs (compact the vector in place and lower n) to prune the walk, as
 * `dirnames[:] = ...` does. A folder that cannot be listed is skipped silently (os.walk's default onerror=None).
 * Strings are valid until the next dk_walk_next or dk_walk_close; the item struct passed in must stay alive (and
 * be the same one) until then, because the walk reads the pruned dirs back from it. */
typedef struct {
    DkStr dirpath;
    DkStrVec dirs;
    DkStrVec files;
} DkWalkItem;
typedef struct DkWalk DkWalk;
DkWalk *dk_walk_open(const char *top, bool topdown);
bool dk_walk_next(DkWalk *w, DkWalkItem *item);
void dk_walk_close(DkWalk *w);

/* ---- fnmatch and glob -------------------------------------------------------------------------------------------- */
/* fnmatch.fnmatch: both sides normcase'd (case-insensitive on Windows); fnmatchcase: exact. Patterns: * ? [seq]
 * [!seq] with Python 3.14's rules for ranges and for an unclosed [. */
bool dk_fnmatch(const char *name, const char *pat);
bool dk_fnmatchcase(const char *name, const char *pat);
/* fnmatch.filter(names, pat): the names that match, in order (views of the input strings). */
DkStrVec dk_fnmatch_filter(const DkStrVec *names, const char *pat);
bool dk_glob_has_magic(const char *s);               /* glob.has_magic: any of * ? [ */
char *dk_glob_escape(DkArena *a, const char *s);    /* glob.escape */
typedef struct {
    const char *root_dir;   /* glob(root_dir=...): NULL for none */
    bool recursive;         /* recursive=True: "**" matches any folders */
    bool include_hidden;    /* include_hidden=True: wildcards match names starting with '.' */
} DkGlobOpts;
/* glob.glob(pattern, ...): the list in glob's order (scandir order per level, "**" parent first), the strings with
 * the separators glob.glob produces (those of the pattern, and "\" where it joins). */
DkStrVec dk_glob_ex(DkArena *a, const char *pattern, const DkGlobOpts *opts);
DkStrVec dk_glob(DkArena *a, const char *pattern, bool recursive);

/* ---- shutil ---------------------------------------------------------------------------------------------------- */
enum { DK_RMTREE_IGNORE_ERRORS = 1, DK_RMTREE_CLEAR_READONLY = 2 };
/* shutil.rmtree(path, ignore_errors=...): does not follow links; a junction or symlink is removed, never its
 * target; the first failure stops it (false, errors as Python) unless IGNORE_ERRORS. DK_RMTREE_CLEAR_READONLY
 * additionally clears the read-only attribute and retries (the `onexc=chmod` idiom; tempfile's cleanup). */
bool dk_rmtree(const char *path, unsigned flags);
bool dk_copyfile(const char *src, const char *dst);  /* contents only; SameFileError text for the same file */
bool dk_copy2(const char *src, const char *dst);     /* contents and metadata (CopyFile2); dst may be a folder */
bool dk_copystat(const char *src, const char *dst);  /* times and the read-only bit */
typedef struct {
    const char *const *ignore;  /* shutil.ignore_patterns(*ignore): fnmatch patterns on names, NULL for none */
    size_t n_ignore;
    bool dirs_exist_ok;
    bool symlinks;
} DkCopytreeOpts;
bool dk_copytree(const char *src, const char *dst, const DkCopytreeOpts *opts);
bool dk_move(const char *src, const char *dst);      /* shutil.move: rename, else copy and delete */
/* shutil.which is dk_which in proc.h. */

/* ---- tempfile -------------------------------------------------------------------------------------------------- */
char *dk_gettempdir(DkArena *a);                    /* tempfile.gettempdir() (TMP, TEMP, ... then abspath) */
/* mkstemp: creates and opens (mode "w+b", not inherited) a new file prefix + 8 random chars + suffix in dir
 * (NULL: gettempdir()); *path_out receives the absolute path. NULL on failure. */
DkFile *dk_mkstemp(DkArena *a, const char *prefix, const char *suffix, const char *dir, char **path_out);
/* mkdtemp: creates the folder, returns its absolute path (NULL on failure). TemporaryDirectory is
 * dk_mkdtemp(a, prefix "tmp", ...) and dk_tempdir_cleanup(path) at the end. */
char *dk_mkdtemp(DkArena *a, const char *prefix, const char *suffix, const char *dir);
/* TemporaryDirectory.cleanup(): rmtree that clears read-only files and retries; errors are not reported. */
void dk_tempdir_cleanup(const char *path);

/* ---- pathlib ---------------------------------------------------------------------------------------------------- */
/* str(PureWindowsPath(p)): separators to \, repeated separators and "." components dropped, a trailing separator
 * dropped; ".." is not resolved. */
char *dk_pl_str(DkArena *a, const char *p);
DkStr dk_pl_name(const char *p);                    /* Path.name (views into p, which must be dk_pl_str form) */
DkStr dk_pl_suffix(const char *p);                  /* Path.suffix */
DkStr dk_pl_stem(const char *p);                    /* Path.stem */
char *dk_pl_parent(DkArena *a, const char *p);      /* str(Path.parent) */
char *dk_pl_with_suffix(DkArena *a, const char *p, const char *suffix); /* NULL: ValueError (kind DK_IOE_VALUE) */
char *dk_pl_with_name(DkArena *a, const char *p, const char *name);     /* NULL: ValueError */
/* Path.relative_to(base) (3.12+ rules, walk_up False): false with kind DK_IOE_VALUE:
 * "'x' is not in the subpath of 'y'". is_relative_to is the same test. */
bool dk_pl_relative_to(DkArena *a, const char *p, const char *base, char **out);
bool dk_pl_is_relative_to(const char *p, const char *base);
DkStrVec dk_pl_parts(DkArena *a, const char *p);   /* Path.parts: "C:\\" then the names */
/* Path ordering (case-insensitive, compared by components): the comparison sorted(paths) uses. */
int dk_pl_cmp(const char *x, const char *y);
/* Path.resolve() (strict=False): realpath; Path.expanduser(); Path.iterdir() is dk_listdir (same order). */
char *dk_pl_resolve(DkArena *a, const char *p);
/* Path.rglob(pattern) / Path.glob(pattern): every match under root (hidden names included; case-insensitive), in an
 * unspecified order. */
DkStrVec dk_pl_glob(DkArena *a, const char *root, const char *pattern);
DkStrVec dk_pl_rglob(DkArena *a, const char *root, const char *pattern);
