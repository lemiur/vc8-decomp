// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* dkcore base: fixed-width types, common macros, process start-up, fatal errors and the small try/throw used where
 * the Python caught a library's exception. Every other dkcore header includes this one. */
#pragma once

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define DK_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define DK_MIN(a, b) ((a) < (b) ? (a) : (b))
#define DK_MAX(a, b) ((a) > (b) ? (a) : (b))
#define DK_UNUSED(x) ((void)(x))
#define DK_THREAD_LOCAL __declspec(thread)
#define DK_NORETURN __declspec(noreturn)
#define DK_PRINTF_FMT _Printf_format_string_

/* Always on (also in Release): a broken invariant is an internal error (D3), never undefined behaviour. */
#define DK_ASSERT(cond) ((cond) ? (void)0 : dk_panic(__FILE__, __LINE__, "assertion failed: %s", #cond))

/* ---- process start-up ------------------------------------------------------------------------------------------
 * Each tool's main file is
 *     static int run(int argc, char **argv) { ... }      (argv in UTF-8, argv[0] the program)
 *     DK_MAIN(run, "gate")
 * DK_MAIN defines wmain: it converts the arguments to UTF-8, records the tool name (for messages), sets the
 * console output code page to UTF-8, gives stdout a large buffer when it is not a console (Python block-buffers a
 * redirected stdout too), keeps stdout/stderr in text mode ("\n" -> "\r\n", as Python's print on Windows) and
 * flushes both at exit. The return value of run is the exit code. */
int dk_start(int argc, wchar_t **wargv, const char *tool, int (*run)(int argc, char **argv));
/* Crash and hang policy. Nothing the tools run may ever wait on a UI (a crash, assert, abort or Windows Error
 * Reporting box), on any machine: the fix is in code, not in registry settings. dk_start calls this as its very
 * first statement, so every executable (tools, eqh, every test binary through DK_TEST_MAIN) has it; the CTest test
 * entry_points fails when an executable has an entry point that does not go through DK_MAIN. It is idempotent and:
 *   - SetErrorMode(FAILCRITICALERRORS | NOGPFAULTERRORBOX | NOOPENFILEERRORBOX) (children inherit it: never pass
 *     CREATE_DEFAULT_ERROR_MODE) and WerSetFlags(WER_FAULT_REPORTING_NO_UI);
 *   - abort() / SIGABRT: "<tool>: aborted" on stderr, exit code 3; a pure call is the same;
 *   - an invalid CRT parameter: "<tool>: invalid parameter passed to a C runtime function", exit code 0xC000000D;
 *   - an unhandled exception (access violation, stack overflow, ...): "<tool>: unhandled exception 0x%08lX at %p" on
 *     stderr, exit code = the exception code (distinct from the tools' own 0/1/2);
 *   - the debug CRT's assert/error/warning reports go to stderr (an _ASSERTE prints and carries on).
 * Every process a tool starts is killed with its tree when it overruns (proc.h: timeouts and the ceiling). */
void dk_crash_quiet_init(void);
#define DK_MAIN(run_fn, tool_name) \
    int wmain(int argc, wchar_t **wargv) { return dk_start(argc, wargv, (tool_name), (run_fn)); }

const char *dk_tool_name(void);
/* The repository root: --root / DECOMPKIT_ROOT when given (dk_set_root), else the nearest folder at or above the
 * executable that holds ctools/CMakeLists.txt, else the nearest folder at or above the current directory that holds
 * config/ctools.json, else the current directory. A root computed from the current directory is exported as
 * DECOMPKIT_ROOT for the tools this one starts. Forward slashes, no trailing slash. */
const char *dk_root(void);
void dk_set_root(const char *root);
/* The folder of the running executable (forward slashes, no trailing slash): sibling tools are started from it. */
const char *dk_exe_dir(void);
/* The build stamp of the tools: sha256 hex over the names and contents of core/ and lib/ (generated at build time by
 * cmake/tools_stamp.cmake). It versions the on-disk memos: every executable built from the same sources shares them, a changed source invalidates them. */
const char *dk_tools_stamp(void);

/* ---- errors ----------------------------------------------------------------------------------------------------
 * dk_fatal is Python's sys.exit("message"): the message and a newline on stderr, exit code 1.
 * dk_exit flushes stdout and stderr, then exits with code.
 * dk_warn writes one line on stderr (no prefix added: the caller spells the line as the Python did).
 * dk_panic is an internal error (the Python's traceback, deviation D3): "<tool>: internal error: <file>:<line>:
 * <message>" on stderr, exit code 1. */
DK_NORETURN void dk_fatal(DK_PRINTF_FMT const char *fmt, ...);
DK_NORETURN void dk_exit(int code);
void dk_warn(DK_PRINTF_FMT const char *fmt, ...);
DK_NORETURN void dk_panic(const char *file, int line, DK_PRINTF_FMT const char *fmt, ...);
/* Out of memory is always fatal. */
void *dk_xmalloc(size_t n);
void *dk_xcalloc(size_t count, size_t n);
void *dk_xrealloc(void *p, size_t n);
void dk_xfree(void *p);

/* ---- try / throw -----------------------------------------------------------------------------------------------
 * Only where the Python caught an exception raised by a library (a malformed PE, a JSON decode error, a regex
 * that does not compile) and went on. Library code throws with dk_throw; the catcher reads code and msg.
 *     DkTry t;
 *     if (DK_TRY(&t)) { ... code that may throw ...; dk_try_end(&t); }
 *     else { ... t.code, t.msg ... }
 * A throw with no DK_TRY active is fatal (dk_fatal with the message). Throws do not unwind resources: code
 * between DK_TRY and the throw allocates from arenas only. */
enum {
    DK_ERR_IO = 1,     /* file or OS error (Python OSError) */
    DK_ERR_FORMAT,     /* malformed input: PE, COFF, JSON, cache, tar (ValueError / PEFormatError / JSONDecodeError) */
    DK_ERR_REGEX,      /* re.error */
    DK_ERR_PROC,       /* a subprocess could not start or timed out */
    DK_ERR_OTHER
};
typedef struct DkTry {
    jmp_buf jb;
    struct DkTry *prev;
    int code;
    char msg[1024];
} DkTry;
void dk_try_push(DkTry *t);
void dk_try_end(DkTry *t);
#define DK_TRY(t) (dk_try_push(t), setjmp((t)->jb) == 0)
DK_NORETURN void dk_throw(int code, DK_PRINTF_FMT const char *fmt, ...);
