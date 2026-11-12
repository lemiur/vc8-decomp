// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Subprocesses: what the tools took from Python's `subprocess` module, `shutil.which` and
 * matchlib.kill_children_with_parent (CPython 3.14 on Windows, PYTHONUTF8=1).
 *
 * Starting a process is the same CreateProcessW call Python makes (no shell, lpApplicationName NULL), so the
 * executable is found the way Python finds it: the command line's first word gets ".exe" when it has no
 * extension, and is searched in the folder of the running executable, the current folder, the system folders and
 * PATH. The command line of an argument vector is subprocess.list2cmdline's, byte for byte. Standard handles are
 * passed explicitly (a handle list, so concurrent starts never leak pipe ends into each other's children). A
 * redirected standard handle that is left alone (DK_IO_INHERIT) is this process's own; nothing is flushed first
 * (Python does not flush sys.stdout either: flush where the Python code passed flush=True).
 *
 * Capturing. stdout and stderr (separately, or merged by DK_IO_STDOUT for stderr) are read while the process
 * runs, on the calling thread with overlapped pipe I/O: no deadlock on big outputs and no helper threads. stdin
 * bytes are written the same way (communicate(input=...): the bytes go as they are, no newline translation).
 * Text mode is text=True with encoding="utf-8": the captured bytes are decoded (errors "strict" or "replace":
 * CPython's rule, one U+FFFD per maximal invalid subpart) and "\r\n" and lone "\r" become "\n". Bytes mode leaves
 * them alone. A stream that was not captured has p == NULL; a captured empty one has a valid p and n == 0. All
 * captured text is NUL-terminated.
 *
 * Timeout. When the time runs out the whole process tree is killed (a Job object around the child; Python kills
 * the child only and may hang on a grandchild's pipe) with exit code 1 as TerminateProcess(h, 1), and the output
 * collected so far is returned with status DK_PROC_TIMEOUT (TimeoutExpired.stdout/.stderr).
 *
 * Crash and hang policy (also base.h). Nothing may ever wait on a UI or forever:
 *   - Every child runs in its own Job object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (it dies with its tree when the
 *     DkProc is closed or this process ends) and JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION (a crashing cl, link,
 *     git or python ends at once instead of raising an error box). Children inherit this process's error mode
 *     (SEM_NOGPFAULTERRORBOX ...): CREATE_DEFAULT_ERROR_MODE is never passed.
 *   - A wall-clock ceiling covers a process whatever the caller does (dk_run, Popen-style start/wait/read with a
 *     negative timeout, communicate): with spec->timeout 0 ("no limit" in Python) it is DECOMPKIT_PROC_CEILING seconds from
 *     the environment, default 1800. A threadpool timer then terminates the job (exit code 124), prints
 *     "<tool>: killed <argv0> after <n> s (process ceiling DECOMPKIT_PROC_CEILING)" on stderr, and the caller sees the
 *     failure: dk_run returns DK_PROC_TIMEOUT, Popen-style waits return code 124 and dk_proc_ceiling_hit is true.
 *     With spec->timeout > 0 the usual DK_PROC_TIMEOUT semantics apply (the timer is only a backstop 30 s later).
 *
 * Return codes are the DWORD exit code as an unsigned value, as Python shows it (an access violation is
 * 3221225477, not -1073741819), held in an i64. */
#pragma once
#include "arena.h"
#include "str.h"

/* ---- command lines ---- */
/* subprocess.list2cmdline for an argument vector (UTF-8), NULL-terminated. */
char *dk_list2cmdline(DkArena *a, const char *const *argv);
char *dk_list2cmdline_n(DkArena *a, const char *const *argv, size_t argc);
/* shutil.which(cmd, mode=F_OK|X_OK, path=None): the path found or NULL. path/pathext NULL: the environment's PATH
 * and PATHEXT (PATH unset gives NULL, PATHEXT unset or empty ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC"). The
 * returned text is os.path.join(dir, name) as Python builds it (".\git.exe" for the current folder). */
char *dk_which(DkArena *a, const char *cmd, const char *path, const char *pathext);

/* ---- environments ----
 * An environment is a dict of names to values (UTF-8; names are matched exactly, as a dict). dk_env_current is
 * dict(os.environ): names upper-cased (os.environ does it on Windows) and the "=C:" entries Windows keeps left
 * out. A spawn with an environment passes exactly these entries, in the order Windows requires (case-insensitive
 * ordinal order of the names), with CREATE_UNICODE_ENVIRONMENT. */
typedef struct DkEnv DkEnv;
DkEnv *dk_env_current(DkArena *a);
DkEnv *dk_env_new(DkArena *a);
DkEnv *dk_env_copy(DkArena *a, const DkEnv *e);
void dk_env_set(DkEnv *e, const char *name, const char *value); /* env[name] = value */
bool dk_env_unset(DkEnv *e, const char *name);                  /* env.pop(name, None): true when it was there */
const char *dk_env_get(const DkEnv *e, const char *name);       /* env.get(name): NULL when absent */
size_t dk_env_count(const DkEnv *e);

/* ---- what to run ---- */
typedef enum {
    DK_IO_INHERIT = 0, /* the parent's standard handle (stdin=None) */
    DK_IO_CAPTURE,     /* a pipe: stdout=PIPE / stderr=PIPE; for stdin the `input` bytes, then end of file */
    DK_IO_NULL,        /* subprocess.DEVNULL */
    DK_IO_STDOUT,      /* stderr only: stderr=subprocess.STDOUT (merged into the stdout pipe or handle) */
    DK_IO_HANDLE,      /* an open file handle of the caller's (stdout=fh); the handle is not closed */
    DK_IO_FILE         /* open the path given (created/truncated; appended with *_append) and close it afterwards */
} DkProcIo;

typedef enum { DK_ERRORS_STRICT = 0, DK_ERRORS_REPLACE } DkProcErrors;

/* CreateProcess flags the tools use (subprocess.CREATE_NO_WINDOW and the priority classes). */
enum {
    DK_CREATE_NEW_CONSOLE = 0x00000010,
    DK_CREATE_NEW_PROCESS_GROUP = 0x00000200,
    DK_DETACHED_PROCESS = 0x00000008,
    DK_CREATE_NO_WINDOW = 0x08000000,
    DK_IDLE_PRIORITY_CLASS = 0x00000040,
    DK_BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
    DK_ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
    DK_HIGH_PRIORITY_CLASS = 0x00000080
};

/* A zeroed spec is subprocess.run(args) with every default. Set argv (NULL-terminated, UTF-8) or cmdline. */
typedef struct DkProcSpec {
    const char *const *argv; /* args as a list: the command line is list2cmdline(argv) */
    const char *cmdline;     /* args as a string, used as it is (argv must be NULL) */
    bool shell;              /* shell=True: COMSPEC (else cmd.exe) /c "<command>", hidden window */
    const char *cwd;         /* NULL: this process's folder */
    const DkEnv *env;       /* NULL: inherit; else the child's whole environment (env=...) */
    DkProcIo in, out, err;
    const void *input;       /* stdin bytes when in == DK_IO_CAPTURE */
    size_t input_n;
    void *in_handle, *out_handle, *err_handle; /* DK_IO_HANDLE */
    const char *in_path, *out_path, *err_path; /* DK_IO_FILE (in_path is opened for reading) */
    bool out_append, err_append;
    bool text;               /* text=True, encoding="utf-8": decode and translate newlines */
    DkProcErrors errors;    /* errors= for the decoding */
    double timeout;          /* seconds; 0: no limit (Python's None). dk_run only: see dk_proc_communicate for Popen */
    u32 creation_flags;      /* creationflags= */
    bool debug;              /* creationflags |= DEBUG_ONLY_THIS_PROCESS (Python's 0x2): the calling thread is the debugger of
                              * the child and must run WaitForDebugEvent / ContinueDebugEvent itself, on that same thread,
                              * until the child's EXIT_PROCESS event. The Job object, the timeout and the ceiling still
                              * apply: the kill ends the child and its exit event arrives in the loop. */
    bool check;              /* check=True: a non-zero return code gives status DK_PROC_BAD_EXIT */
    DkArena *arena;         /* where the captured text goes; NULL: the calling thread's dk_arena() */
} DkProcSpec;

typedef enum {
    DK_PROC_OK = 0,
    DK_PROC_START_FAILED, /* OSError from Popen: winerror/message say why (FileNotFoundError is winerror 2) */
    DK_PROC_TIMEOUT,      /* TimeoutExpired */
    DK_PROC_DECODE_ERROR, /* UnicodeDecodeError (text mode, errors strict) */
    DK_PROC_BAD_EXIT      /* CalledProcessError (check set and the return code is not 0) */
} DkProcStatus;

typedef struct {
    DkProcStatus status;
    i64 returncode;     /* the exit code, unsigned; -1 when the process never started */
    DkStr out, err;    /* captured streams (see the header comment) */
    u32 pid;
    u32 winerror;       /* GetLastError for DK_PROC_START_FAILED */
    const char *message; /* "[WinError 2] The system cannot find the file specified" for a failed start, else NULL */
} DkProcResult;

/* subprocess.run(spec). */
DkProcResult dk_run(const DkProcSpec *spec);
/* subprocess.run(argv, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace"): the usual
 * way the tools ran git and the compilers. */
DkProcResult dk_run_text(DkArena *a, const char *cwd, const char *const *argv);

/* ---- Popen ---- */
typedef struct DkProc DkProc;
/* subprocess.Popen(spec): NULL on failure with *failure filled in (status DK_PROC_START_FAILED). A spec with
 * in == DK_IO_CAPTURE gives dk_proc_write/dk_proc_close_stdin; out/err == DK_IO_CAPTURE give the read
 * functions (the `input` field of the spec is not used: write it yourself). */
DkProc *dk_proc_start(const DkProcSpec *spec, DkProcResult *failure);
u32 dk_proc_pid(const DkProc *p);
/* True when the wall-clock ceiling killed this process (see the header comment). */
bool dk_proc_ceiling_hit(const DkProc *p);
/* Popen.poll(): true and *returncode when the process has ended. */
bool dk_proc_poll(DkProc *p, i64 *returncode);
/* Popen.wait(timeout): timeout < 0 waits without limit, 0 only checks. False when it ran out of time. */
bool dk_proc_wait(DkProc *p, double timeout, i64 *returncode);
/* Waits until one of the processes ends (a fan-out): its index, or -1 on timeout. Ended ones count again. It
 * waits on the process handles only and reads no pipe: use it for processes whose output goes to a file or NUL, or
 * is read by the caller meanwhile. */
int dk_proc_wait_any(DkProc *const *ps, size_t n, double timeout);
/* Popen.kill() / terminate() (both TerminateProcess with exit code 1 on Windows); the _tree form takes the
 * whole tree down (taskkill /T /F). */
void dk_proc_kill(DkProc *p);
void dk_proc_kill_tree(DkProc *p);
/* Popen.stdin.write / close. False when the child closed its end (Python's BrokenPipeError). */
bool dk_proc_write(DkProc *p, const void *data, size_t n);
void dk_proc_close_stdin(DkProc *p);
/* Reads from stream 1 (stdout) or 2 (stderr): up to cap bytes that are available (blocking until at least one,
 * the end of the stream, or the timeout; timeout < 0: no limit). Returns the count, 0 at the end of the stream
 * (or on timeout: *timed_out set when non-NULL). Raw bytes. */
size_t dk_proc_read(DkProc *p, int stream, void *buf, size_t cap, double timeout, bool *timed_out);
/* Reads exactly n bytes (fewer at the end of the stream; returns the count). Raw bytes. */
size_t dk_proc_read_exact(DkProc *p, int stream, void *buf, size_t n);
/* `for line in p.stdout` / p.stdout.readline(): the next line without decoding, terminator included
 * ("\n" only); false at the end of the stream. The text is valid until the next call on this stream. In text mode
 * (spec.text) a line ends at "\n", "\r" or "\r\n", is decoded as the spec's errors say and ends with a single
 * "\n" (universal newlines); the last line may lack it. */
bool dk_proc_readline(DkProc *p, int stream, DkStr *line);
/* Popen.communicate(input, timeout) for the rest of the streams: the captured text into *r (as dk_run does,
 * from the data not yet read), returncode when the process ended. timeout < 0: no limit; 0: only what is ready.
 * Returns false on a timeout (r->status DK_PROC_TIMEOUT, r holds what was read so far and nothing is consumed);
 * the process is not killed here (the caller decides: dk_proc_kill_tree and communicate again, as
 * permute.run_bounded did). */
bool dk_proc_communicate(DkProc *p, const void *input, size_t input_n, double timeout, DkProcResult *r);
/* Closes the pipes and the process handle (Popen.__exit__ without the wait). A process still running is killed with
 * its tree (its Job object closes). */
void dk_proc_close(DkProc *p);

/* ---- the tree of this process ----
 * os.getpid(). */
u32 dk_getpid(void);
/* permute.kill_children (psutil.Process().children(recursive=True) and kill): terminates every process below this
 * one with exit code 1, children before their parents' reads of them. Returns how many it found. */
size_t dk_kill_descendants(void);

/* ---- children die with the tool ----
 * matchlib.kill_children_with_parent(): puts this process in a Job object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
 * so every process it starts (and theirs) ends when this one does, however it ends. Idempotent and thread safe.
 * False where the job cannot be made (the tree behaves as before). */
bool dk_kill_children_with_parent(void);

/* ---- processes holding files ----
 * The processes that hold a file under dir open (Restart Manager over every file of the tree), each as
 * "<image> (pid N)" in `held`, ended with exit code 1 when `end` is true. For a tool's own scratch folder that an
 * earlier, killed run left locked (orphaned cl.exe or link.exe): no other process has a reason to hold it. Returns
 * how many it found; 0 when none or the query fails. */
size_t dk_file_lockers(DkArena *a, const char *dir, bool end, DkStrVec *held);
