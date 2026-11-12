// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The Win32 calls the Python tools made through ctypes, winreg, msvcrt, socket and getpass: registry reads, named
 * mutexes, byte-range file locks, process helpers, volume queries, console helpers, process priority, host/user
 * names, error-message formatting. Failures are recorded the way fs.h records them (dk_io_err(): an OSError with
 * its winerror), so a caller prints what Python would have printed for the exception.
 *
 * What is NOT here: the window/input/GDI calls of the MCP's input and capture modules (SendInput, EnumWindows,
 * PrintWindow, ...) and process-memory access (ReadProcessMemory, VirtualQueryEx): those modules call <windows.h>
 * directly; they use dk_win_error_message()/dk_io_fail_win() for the text of a failure. The Job object
 * (matchlib.kill_children_with_parent) belongs to proc.h.
 */
#pragma once
#include "fs.h"

/* ---- Win32 errors ------------------------------------------------------------------------------------------------ */
/* FormatMessageW(system default language) with the trailing dots and whitespace removed, as OSError's text:
 * 2 -> "The system cannot find the file specified". Unknown codes give "Unknown error <n>" as Python does. */
DkStr dk_win_error_message(DkArena *a, unsigned code);
/* CPython's winerror -> errno table (PC/errmap.h): 2 -> ENOENT, 5 -> EACCES, 183 -> EEXIST, 145 -> ENOTEMPTY, ... */
int dk_winerror_to_errno(unsigned winerror);
/* "[WinError 5] Access is denied" -- the text of OSError(None, msg, None, winerror) without filename. */
DkStr dk_win_error_str(DkArena *a, unsigned winerror);

/* ---- registry (winreg) ------------------------------------------------------------------------------------------- */
typedef enum {
    DK_HKEY_CLASSES_ROOT,
    DK_HKEY_CURRENT_USER,
    DK_HKEY_LOCAL_MACHINE,
    DK_HKEY_USERS,
    DK_HKEY_CURRENT_CONFIG
} DkRegRoot;
enum { DK_KEY_WOW64_DEFAULT = 0, DK_KEY_WOW64_64KEY = 0x0100, DK_KEY_WOW64_32KEY = 0x0200 };
enum { DK_REG_NONE = 0, DK_REG_SZ = 1, DK_REG_EXPAND_SZ = 2, DK_REG_BINARY = 3, DK_REG_DWORD = 4,
       DK_REG_MULTI_SZ = 7, DK_REG_QWORD = 11 };
typedef struct {
    u32 type;         /* DK_REG_* */
    DkStr str;       /* REG_SZ, REG_EXPAND_SZ (not expanded): the text up to the first NUL, as winreg returns it */
    u64 num;          /* REG_DWORD, REG_QWORD */
    DkStr bin;       /* REG_BINARY (and any other type): the raw bytes */
    DkStrVec multi;  /* REG_MULTI_SZ: the strings */
} DkRegValue;
/* with winreg.OpenKey(root, subkey, 0, KEY_READ | wow64) as key: value, type = winreg.QueryValueEx(key, name)
 * name "" or NULL is the key's default value. false: FileNotFoundError ([WinError 2]) and the other OSErrors. */
bool dk_reg_get(DkArena *a, DkRegRoot root, const char *subkey, unsigned wow64, const char *name, DkRegValue *out);
/* The same for a string value: false (without an error recorded) when the value is not REG_SZ/REG_EXPAND_SZ. */
bool dk_reg_get_string(DkArena *a, DkRegRoot root, const char *subkey, unsigned wow64, const char *name,
                        DkStr *out);

/* ---- named mutexes (System.Threading.Mutex / gamelock.ps1) ------------------------------------------------------- */
typedef struct DkNamedMutex DkNamedMutex;
/* Creates or opens the named mutex "Global\<name>", falling back to "Local\<name>" when Global is refused; not owned
 * yet. NULL on failure. */
DkNamedMutex *dk_named_mutex_open(const char *name);
enum { DK_WAIT_ACQUIRED = 0, DK_WAIT_ABANDONED = 1 /* acquired: the holder died */, DK_WAIT_TIMEOUT = 2, DK_WAIT_FAILED = 3 };
/* WaitOne(timeout_ms) (0xFFFFFFFF: forever). A mutex is owned by the thread that waited: release it on that thread. */
int dk_named_mutex_wait(DkNamedMutex *m, u32 timeout_ms);
bool dk_named_mutex_release(DkNamedMutex *m);
void dk_named_mutex_close(DkNamedMutex *m);                    /* releases ownership held by the closing thread's handle */
bool dk_named_mutex_exists(const char *full_name);          /* OpenMutexW(SYNCHRONIZE, name): true when it exists (any session) */

/* ---- byte-range file locks (msvcrt.locking, LockFileEx) ---------------------------------------------------------- */
/* Exclusive, non-blocking lock of `len` bytes at `offset` of an open file (dk_fhandle). msvcrt.locking(fd,
 * LK_NBLCK, 1) after seek(0) is dk_filelock_try(h, 0, 1). false: OSError (EACCES "Permission denied") when held. */
bool dk_filelock_try(void *handle, i64 offset, i64 len);
bool dk_filelock_unlock(void *handle, i64 offset, i64 len);   /* msvcrt.locking(fd, LK_UNLCK, n) */

/* ---- processes --------------------------------------------------------------------------------------------------- */
/* os.getpid() is dk_getpid in proc.h. */
u32 dk_getppid(void);                                 /* os.getppid() */
/* lane_lock.pid_alive: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION); access denied counts as alive; alive when
 * GetExitCodeProcess says STILL_ACTIVE. */
bool dk_pid_alive(u32 pid);
char *dk_proc_image_path(DkArena *a, u32 pid);       /* QueryFullProcessImageNameW, NULL when it cannot be read */
bool dk_proc_creation_time(u32 pid, u64 *filetime);   /* GetProcessTimes: creation FILETIME (100 ns since 1601) */
typedef struct {
    u32 pid, parent_pid, threads;
    DkStr exe;    /* PROCESSENTRY32W.szExeFile in UTF-8 */
} DkProcInfo;
typedef DK_VEC(DkProcInfo) DkProcInfoVec;
bool dk_proc_list(DkArena *a, DkProcInfoVec *out);  /* Toolhelp snapshot in snapshot order */
bool dk_set_priority_below_normal(void);              /* priority.lower(): BELOW_NORMAL_PRIORITY_CLASS for this process */
bool dk_set_priority_class(u32 priority_class);       /* SetPriorityClass(GetCurrentProcess(), c) */
/* os.cpu_count() is dk_cpu_count in pool.h. */

/* ---- machine and user -------------------------------------------------------------------------------------------- */
char *dk_hostname(DkArena *a);                       /* socket.gethostname() */
char *dk_getuser(DkArena *a);                        /* getpass.getuser(): LOGNAME, USER, LNAME, USERNAME, else the account name */

/* ---- volumes (objcache) ------------------------------------------------------------------------------------------ */
/* The volume holding `path`: serial number and file system name ("NTFS", "ReFS"); false when unknown. */
bool dk_volume_info(DkArena *a, const char *path, u32 *serial, char **fs_name);
/* Bytes per cluster of the volume holding `path` (sectors per cluster * bytes per sector); 0 when unknown. */
u32 dk_cluster_size(const char *path);
/* A ReFS block clone of src into the new file dst (FSCTL_DUPLICATE_EXTENTS_TO_FILE): dst shares src's clusters until
 * either is written. true when done; otherwise dst does not exist. cluster from dk_cluster_size. */
bool dk_file_clone(const char *src, const char *dst, u32 cluster);

/* ---- console ----------------------------------------------------------------------------------------------------- */
bool dk_isatty(int fd);                               /* 0 stdin, 1 stdout, 2 stderr: a character device (console) */
int dk_console_width(void);                           /* the console's columns, or 80 (shutil.get_terminal_size fallback) */
bool dk_kbhit(void);                                  /* msvcrt.kbhit() */
u32 dk_getwch(void);                                  /* msvcrt.getwch(): one UTF-16 unit, no echo */

/* ---- symbols and crypto ------------------------------------------------------------------------------------------ */
/* dbghelp's UnDecorateSymbolName(name, flags): the undecorated text (names are Latin-1 bytes in Python's ctypes use,
 * here UTF-8/ASCII), or an empty string when it fails. UNDNAME_NAME_ONLY = 0x1000. Serialized: dbghelp is not
 * thread-safe. */
DkStr dk_undecorate_symbol(DkArena *a, const char *name, u32 flags);
/* AES-128 ECB (cbc false) or CBC with a zero IV through BCrypt, decrypting n bytes (a multiple of 16) into out
 * (proto_extract.aes_decrypt). false on any BCrypt failure. */
bool dk_aes128_decrypt(const u8 key[16], const u8 *data, size_t n, bool cbc, u8 *out);
