// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* proc.h against CPython 3.14.8's subprocess and shutil.which. The expected values (list2cmdline, UTF-8 decoding
 * with universal newlines, which) are in proc_corpus.h; the processes are this executable started with --child. */
#include "dk/dk.h"
#include "dk/clock.h"
#include "dk/pool.h"
#include "dk/proc.h"
#include "dk/test.h"
#include "proc_corpus.h"

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* ---- the child side ---- */

static void out_bytes(DWORD which, const void *p, size_t n) {
    HANDLE h = GetStdHandle(which);
    const u8 *b = p;
    while (n > 0) {
        DWORD k = 0, step = n > 65536 ? 65536 : (DWORD)n;
        if (!WriteFile(h, b, step, &k, NULL) || k == 0) return;
        b += k;
        n -= k;
    }
}
static void out_str(DWORD which, const char *s) { out_bytes(which, s, strlen(s)); }

static size_t read_stdin_chunk(void *buf, size_t cap) {
    DWORD n = 0;
    if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, (DWORD)cap, &n, NULL)) return 0;
    return n;
}

static u8 pattern_byte(size_t i) { return (u8)((i * 31 + (i >> 8)) & 255); }

static int child_main(int argc, char **argv) {
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    const char *mode = argv[2];
    char buf[65536];
    if (strcmp(mode, "exit") == 0) {
        ExitProcess((UINT)strtoul(argv[3], NULL, 10));
    } else if (strcmp(mode, "crash") == 0) {
        volatile int *p = NULL;
        *p = 1;
    } else if (strcmp(mode, "echo") == 0) {
        for (int i = 3; i < argc; i++) {
            if (i > 3) out_str(STD_OUTPUT_HANDLE, " ");
            out_str(STD_OUTPUT_HANDLE, argv[i]);
        }
        out_str(STD_OUTPUT_HANDLE, "\n");
    } else if (strcmp(mode, "err") == 0) {
        out_str(STD_ERROR_HANDLE, argv[3]);
    } else if (strcmp(mode, "args") == 0) {
        char line[4096];
        for (int i = 3; i < argc; i++) {
            int n = snprintf(line, sizeof line, "<");
            for (const char *p = argv[i]; *p; p++) n += snprintf(line + n, sizeof line - (size_t)n, "%02x", (unsigned char)*p);
            n += snprintf(line + n, sizeof line - (size_t)n, ">\n");
            out_bytes(STD_OUTPUT_HANDLE, line, (size_t)n);
        }
    } else if (strcmp(mode, "cmdline") == 0) {
        const wchar_t *w = GetCommandLineW();
        char u[8192];
        int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, u, sizeof u, NULL, NULL);
        out_bytes(STD_OUTPUT_HANDLE, u, n > 0 ? (size_t)n - 1 : 0);
    } else if (strcmp(mode, "big") == 0 || strcmp(mode, "bigerr") == 0 || strcmp(mode, "both") == 0) {
        size_t n = (size_t)strtoull(argv[3], NULL, 10);
        size_t done = 0;
        while (done < n) {
            size_t k = n - done > 4096 ? 4096 : n - done;
            for (size_t i = 0; i < k; i++) buf[i] = (char)pattern_byte(done + i);
            if (strcmp(mode, "big") == 0 || strcmp(mode, "both") == 0) out_bytes(STD_OUTPUT_HANDLE, buf, k);
            if (strcmp(mode, "bigerr") == 0 || strcmp(mode, "both") == 0) {
                for (size_t i = 0; i < k; i++) buf[i] = (char)(pattern_byte(done + i) ^ 0x5a);
                out_bytes(STD_ERROR_HANDLE, buf, k);
            }
            done += k;
        }
    } else if (strcmp(mode, "cat") == 0 || strcmp(mode, "catboth") == 0) {
        size_t k;
        while ((k = read_stdin_chunk(buf, sizeof buf)) > 0) {
            out_bytes(STD_OUTPUT_HANDLE, buf, k);
            if (strcmp(mode, "catboth") == 0) out_bytes(STD_ERROR_HANDLE, buf, k);
        }
    } else if (strcmp(mode, "stdin_sum") == 0) {
        u64 h = 1469598103934665603ULL, total = 0;
        size_t k;
        while ((k = read_stdin_chunk(buf, sizeof buf)) > 0) {
            for (size_t i = 0; i < k; i++) h = (h ^ (u8)buf[i]) * 1099511628211ULL;
            total += k;
        }
        char line[128];
        int n = snprintf(line, sizeof line, "%llu %016llx\n", (unsigned long long)total, (unsigned long long)h);
        out_bytes(STD_OUTPUT_HANDLE, line, (size_t)n);
    } else if (strcmp(mode, "sleep") == 0) {
        out_str(STD_OUTPUT_HANDLE, "start\n");
        Sleep((DWORD)strtoul(argv[3], NULL, 10));
        return argc > 4 ? atoi(argv[4]) : 0;
    } else if (strcmp(mode, "span") == 0) {
        /* start and end of a run in QueryPerformanceCounter ticks, one clock for every process */
        LARGE_INTEGER a, b;
        QueryPerformanceCounter(&a);
        Sleep((DWORD)strtoul(argv[3], NULL, 10));
        QueryPerformanceCounter(&b);
        char line[128];
        int n = snprintf(line, sizeof line, "%lld %lld\n", a.QuadPart, b.QuadPart);
        out_bytes(STD_OUTPUT_HANDLE, line, (size_t)n);
    } else if (strcmp(mode, "env") == 0) {
        wchar_t w[32768], name[256]; /* 32767 is the most an environment variable can hold (PATH under vcvars is over 2048) */
        MultiByteToWideChar(CP_UTF8, 0, argv[3], -1, name, 256);
        DWORD n = GetEnvironmentVariableW(name, w, 32768);
        if (n == 0) {
            out_str(STD_OUTPUT_HANDLE, "(unset)");
        } else {
            static char u[3 * 32768];
            int k = WideCharToMultiByte(CP_UTF8, 0, w, (int)n, u, sizeof u, NULL, NULL);
            out_bytes(STD_OUTPUT_HANDLE, u, (size_t)k);
        }
    } else if (strcmp(mode, "envdump") == 0) {
        wchar_t *block = GetEnvironmentStringsW();
        for (const wchar_t *p = block; *p; p += wcslen(p) + 1) {
            char u[4096];
            int k = WideCharToMultiByte(CP_UTF8, 0, p, -1, u, sizeof u, NULL, NULL);
            out_bytes(STD_OUTPUT_HANDLE, u, (size_t)k - 1);
            out_str(STD_OUTPUT_HANDLE, "\n");
        }
    } else if (strcmp(mode, "cwd") == 0) {
        wchar_t w[1024];
        DWORD n = GetCurrentDirectoryW(1024, w);
        char u[4096];
        int k = WideCharToMultiByte(CP_UTF8, 0, w, (int)n, u, sizeof u, NULL, NULL);
        out_bytes(STD_OUTPUT_HANDLE, u, (size_t)k);
    } else if (strcmp(mode, "grandchild") == 0) {
        /* starts a sleeper that shares this process's stdout pipe, reports its pid, then sleeps too */
        const char *self = argv[0];
        const char *gargv[] = {self, "--child", "sleep", "60000", NULL};
        DkProcSpec s = {0};
        s.argv = gargv;
        s.out = DK_IO_HANDLE;
        s.out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        s.err = DK_IO_NULL;
        DkProc *g = dk_proc_start(&s, NULL);
        char line[64];
        int n = snprintf(line, sizeof line, "%lu\n", g ? (unsigned long)dk_proc_pid(g) : 0UL);
        out_bytes(STD_OUTPUT_HANDLE, line, (size_t)n);
        Sleep(60000);
    } else if (strcmp(mode, "jobtest") == 0) {
        bool ok = dk_kill_children_with_parent();
        const char *gargv[] = {argv[0], "--child", "sleep", "60000", NULL};
        DkProcSpec s = {0};
        s.argv = gargv;
        s.out = DK_IO_NULL;
        DkProc *g = dk_proc_start(&s, NULL);
        char line[64];
        int n = snprintf(line, sizeof line, "%d %lu\n", ok ? 1 : 0, g ? (unsigned long)dk_proc_pid(g) : 0UL);
        out_bytes(STD_OUTPUT_HANDLE, line, (size_t)n);
        /* exit: the job closes with this process and takes the sleeper along */
    } else if (strcmp(mode, "inherit") == 0) {
        /* a grandchild started with nothing redirected, then with only stdout left alone: both write to our stdout */
        const char *g1[] = {argv[0], "--child", "echo", "plain-inherit", NULL};
        DkProcSpec s1 = {0};
        s1.argv = g1;
        dk_run(&s1);
        const char *g2[] = {argv[0], "--child", "order", NULL};
        DkProcSpec s2 = {0};
        s2.argv = g2;
        s2.err = DK_IO_CAPTURE;
        s2.text = true;
        DkProcResult r2 = dk_run(&s2);
        char line[64];
        int n = snprintf(line, sizeof line, "|err=%.*s|", (int)r2.err.n, r2.err.p);
        out_bytes(STD_OUTPUT_HANDLE, line, (size_t)n);
        const char *g3[] = {argv[0], "--child", "echo", "stderr-inherit", NULL};
        DkProcSpec s3 = {0};
        s3.argv = g3;
        s3.out = DK_IO_CAPTURE;
        s3.text = true;
        DkProcResult r3 = dk_run(&s3);
        n = snprintf(line, sizeof line, "|out=%.*s|", (int)r3.out.n - 1, r3.out.p);
        out_bytes(STD_OUTPUT_HANDLE, line, (size_t)n);
    } else if (strcmp(mode, "bin") == 0) {
        for (int i = 0; i < 256; i++) buf[i] = (char)i;
        out_bytes(STD_OUTPUT_HANDLE, buf, 256);
    } else if (strcmp(mode, "lines") == 0) {
        DWORD ms = (DWORD)strtoul(argv[3], NULL, 10);
        for (int i = 0; i < 5; i++) {
            char line[32];
            int n = snprintf(line, sizeof line, "line %d\n", i);
            out_bytes(STD_OUTPUT_HANDLE, line, (size_t)n);
            Sleep(ms);
        }
    } else if (strcmp(mode, "order") == 0) {
        out_str(STD_OUTPUT_HANDLE, "A");
        out_str(STD_ERROR_HANDLE, "B");
        out_str(STD_OUTPUT_HANDLE, "C");
        out_str(STD_ERROR_HANDLE, "D");
    } else if (strcmp(mode, "cpucount") == 0) {
        char line[32];
        int n = snprintf(line, sizeof line, "%d %d\n", dk_cpu_count(), dk_process_cpu_count());
        out_bytes(STD_OUTPUT_HANDLE, line, (size_t)n);
    } else {
        return 99;
    }
    return 0;
}

/* ---- the test side ---- */

static const char *self_exe(void) {
    static char path[1024];
    if (!path[0]) {
        wchar_t w[1024];
        DWORD n = GetModuleFileNameW(NULL, w, 1024);
        WideCharToMultiByte(CP_UTF8, 0, w, (int)n, path, sizeof path - 1, NULL, NULL);
    }
    return path;
}

static DkProcResult run_child_ex(DkProcSpec *spec, const char *a1, const char *a2, const char *a3, const char *a4) {
    const char *argv[8];
    int n = 0;
    argv[n++] = self_exe();
    argv[n++] = "--child";
    argv[n++] = a1;
    if (a2) argv[n++] = a2;
    if (a3) argv[n++] = a3;
    if (a4) argv[n++] = a4;
    argv[n] = NULL;
    spec->argv = argv;
    return dk_run(spec);
}

static DkProcSpec captured_text(void) {
    DkProcSpec s = {0};
    s.out = DK_IO_CAPTURE;
    s.err = DK_IO_CAPTURE;
    s.text = true;
    s.errors = DK_ERRORS_REPLACE;
    return s;
}

static DkProcSpec captured_bytes(void) {
    DkProcSpec s = {0};
    s.out = DK_IO_CAPTURE;
    s.err = DK_IO_CAPTURE;
    return s;
}

DK_TEST(list2cmdline_matches_python) {
    for (size_t i = 0; i < DK_ARRAY_LEN(proc_cmdline_cases); i++) {
        const ProcCmdlineCase *c = &proc_cmdline_cases[i];
        char *got = dk_list2cmdline(dk_scratch(), c->argv);
        CHECK_MSG(strcmp(got, c->expect) == 0, "list2cmdline case %zu: \"%s\", Python \"%s\"", i, got, c->expect);
    }
}

DK_TEST(command_line_reaches_the_child_byte_for_byte) {
    size_t checked = 0;
    for (size_t i = 0; i < DK_ARRAY_LEN(proc_cmdline_cases); i += 3) {
        const ProcCmdlineCase *c = &proc_cmdline_cases[i];
        const char *argv[16];
        size_t n = 0;
        argv[n++] = self_exe();
        argv[n++] = "--child";
        argv[n++] = "cmdline";
        for (size_t k = 0; c->argv[k]; k++) argv[n++] = c->argv[k];
        argv[n] = NULL;
        DkProcSpec s = captured_bytes();
        s.argv = argv;
        DkProcResult r = dk_run(&s);
        REQUIRE(r.status == DK_PROC_OK);
        char *want = dk_list2cmdline(dk_scratch(), argv);
        CHECK_MSG(dk_str_eqz(r.out, want), "command line seen by the child: \"%.*s\", wanted \"%s\"", DK_SF(r.out), want);
        checked++;
    }
    CHECK(checked > 100);
}

DK_TEST(arguments_survive_the_round_trip_through_the_c_runtime) {
    for (size_t i = 0; i < DK_ARRAY_LEN(proc_cmdline_cases); i += 4) {
        const ProcCmdlineCase *c = &proc_cmdline_cases[i];
        if (!c->argv[0]) continue;
        const char *argv[16];
        size_t n = 0;
        argv[n++] = self_exe();
        argv[n++] = "--child";
        argv[n++] = "args";
        size_t first = n;
        for (size_t k = 0; c->argv[k]; k++) argv[n++] = c->argv[k];
        argv[n] = NULL;
        DkProcSpec s = captured_bytes();
        s.argv = argv;
        DkProcResult r = dk_run(&s);
        REQUIRE(r.status == DK_PROC_OK);
        DkBuf want;
        dk_buf_init(&want, dk_scratch());
        for (size_t k = first; k < n; k++) {
            dk_buf_putz(&want, "<");
            for (const char *p = argv[k]; *p; p++) dk_buf_printf(&want, "%02x", (unsigned char)*p);
            dk_buf_putz(&want, ">\n");
        }
        CHECK_MSG(dk_str_eq(r.out, dk_buf_str(&want)), "args of case %zu came back as \"%.*s\"", i, DK_SF(r.out));
    }
}

DK_TEST(which_matches_python) {
    wchar_t wtmp[MAX_PATH + 1];
    GetTempPathW(MAX_PATH, wtmp);
    char tmp[1024];
    WideCharToMultiByte(CP_UTF8, 0, wtmp, -1, tmp, sizeof tmp, NULL, NULL);
    char T[1024];
    snprintf(T, sizeof T, "%savpwhich%lu", tmp, (unsigned long)GetCurrentProcessId());
    /* the layout of the expectation records */
    const char *dirs[] = {"", "\\bin1", "\\bin2", "\\bin3", "\\cwd", "\\bin2\\xdir.exe"};
    const char *files[] = {"\\bin1\\tool.exe", "\\bin1\\tool.bat", "\\bin1\\script.cmd", "\\bin1\\readme.txt", "\\bin2\\tool.com",
                           "\\bin2\\other.EXE", "\\cwd\\here.exe", "\\bin2\\noext", "\\bin1\\dup.exe"};
    for (size_t i = 0; i < DK_ARRAY_LEN(dirs); i++) CreateDirectoryW(dk_to_wz(dk_scratch(), dk_sprintf(dk_scratch(), "%s%s", T, dirs[i])), NULL);
    for (size_t i = 0; i < DK_ARRAY_LEN(files); i++) {
        HANDLE h = CreateFileW(dk_to_wz(dk_scratch(), dk_sprintf(dk_scratch(), "%s%s", T, files[i])), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    wchar_t oldcwd[1024], oldpath[32768];
    GetCurrentDirectoryW(1024, oldcwd);
    GetEnvironmentVariableW(L"PATH", oldpath, 32768);
    SetCurrentDirectoryW(dk_to_wz(dk_scratch(), dk_sprintf(dk_scratch(), "%s\\cwd", T)));
    for (size_t i = 0; i < DK_ARRAY_LEN(proc_which_cases); i++) {
        const ProcWhichCase *c = &proc_which_cases[i];
        DkArena *a = dk_scratch();
        DkArenaMark mark = dk_arena_mark(a);
        DkStr path = c->path ? dk_str_replace(a, dk_str(c->path), DK_S("@"), dk_str(T), -1) : (DkStr){NULL, 0};
        if (!c->path) {
            DkStr envp = dk_str_replace(a, DK_S("@\\bin1;.;@\\bin2"), DK_S("@"), dk_str(T), -1);
            SetEnvironmentVariableW(L"PATH", dk_to_wz(a, dk_cz(a, envp)));
        }
        char *got = dk_which(a, c->cmd, c->path ? dk_cz(a, path) : NULL, c->pathext);
        DkStr shown = got ? dk_str_replace(a, dk_str(got), dk_str(T), DK_S("@"), -1) : (DkStr){NULL, 0};
        if (!c->expect) {
            CHECK_MSG(!got, "which(\"%s\", path=\"%s\", pathext=%s) found \"%s\", Python None", c->cmd, c->path ? c->path : "(env)",
                      c->pathext ? c->pathext : "default", got ? got : "");
        } else {
            CHECK_MSG(got && dk_str_eqz(shown, c->expect), "which(\"%s\", path=\"%s\", pathext=%s) = \"%s\", Python \"%s\"", c->cmd,
                      c->path ? c->path : "(env)", c->pathext ? c->pathext : "default", got ? got : "(none)", c->expect);
        }
        dk_arena_reset(a, mark);
    }
    SetCurrentDirectoryW(oldcwd);
    SetEnvironmentVariableW(L"PATH", oldpath);
    /* the real PATH: cmd is found and is cmd.exe */
    char *cmd = dk_which(dk_scratch(), "cmd", NULL, NULL);
    CHECK(cmd != NULL);
    if (cmd) CHECK(strlen(cmd) > 7 && _stricmp(cmd + strlen(cmd) - 7, "cmd.exe") == 0);
    CHECK(dk_which(dk_scratch(), "definitely-not-a-program-xyz", NULL, NULL) == NULL);
    /* remove the layout */
    for (size_t i = 0; i < DK_ARRAY_LEN(files); i++) DeleteFileW(dk_to_wz(dk_scratch(), dk_sprintf(dk_scratch(), "%s%s", T, files[i])));
    for (size_t i = DK_ARRAY_LEN(dirs); i-- > 0;) RemoveDirectoryW(dk_to_wz(dk_scratch(), dk_sprintf(dk_scratch(), "%s%s", T, dirs[i])));
}

DK_TEST(environment_dict_semantics) {
    DkArena *a = dk_scratch();
    DkEnv *e = dk_env_new(a);
    CHECK_EQ_U64(dk_env_count(e), 0);
    dk_env_set(e, "A", "1");
    dk_env_set(e, "b", "2");
    dk_env_set(e, "A", "3");
    CHECK_EQ_U64(dk_env_count(e), 2);
    CHECK_CZ(dk_env_get(e, "A"), "3");
    CHECK(dk_env_get(e, "a") == NULL); /* a dict: names are exact */
    DkEnv *c = dk_env_copy(a, e);
    CHECK(dk_env_unset(e, "A"));
    CHECK(!dk_env_unset(e, "A"));
    CHECK(dk_env_get(e, "A") == NULL && dk_env_get(c, "A") != NULL);
    DkEnv *cur = dk_env_current(a);
    CHECK(dk_env_get(cur, "PATH") != NULL);
    CHECK(dk_env_get(cur, "Path") == NULL);       /* os.environ upper-cases the names */
    CHECK(dk_env_get(cur, "SYSTEMROOT") != NULL);
    CHECK(dk_env_get(cur, "=C:") == NULL);
}

DK_TEST(environment_block_is_sorted_and_replaces_the_environment) {
    DkArena *a = dk_scratch();
    DkEnv *e = dk_env_new(a);
    dk_env_set(e, "zeta", "last");
    dk_env_set(e, "Beta", "2");
    dk_env_set(e, "alpha", "caf\xc3\xa9 \xe5\xb9\xb4");
    dk_env_set(e, "_under", "u");
    dk_env_set(e, "ALPHA2", "x=y");
    dk_env_set(e, "SystemRoot", getenv("SystemRoot")); /* needed by some programs; not by ours */
    DkProcSpec s = captured_bytes();
    s.env = e;
    DkProcResult r = run_child_ex(&s, "envdump", NULL, NULL, NULL);
    REQUIRE(r.status == DK_PROC_OK);
    char want[512];
    snprintf(want, sizeof want, "alpha=caf\xc3\xa9 \xe5\xb9\xb4\nALPHA2=x=y\nBeta=2\nSystemRoot=%s\nzeta=last\n_under=u\n", getenv("SystemRoot"));
    CHECK_MSG(dk_str_eqz(r.out, want), "environment seen by the child:\n%.*s", DK_SF(r.out));
    /* an overlay on the current environment */
    DkEnv *o = dk_env_current(a);
    dk_env_set(o, "DK_TEST_VAR", "from the overlay");
    dk_env_unset(o, "USERNAME");
    DkProcSpec s2 = captured_text();
    s2.env = o;
    DkProcResult r2 = run_child_ex(&s2, "env", "DK_TEST_VAR", NULL, NULL);
    CHECK_STR(r2.out, "from the overlay");
    DkProcResult r3 = run_child_ex(&s2, "env", "USERNAME", NULL, NULL);
    CHECK_STR(r3.out, "(unset)");
    DkProcResult r4 = run_child_ex(&s2, "env", "PATH", NULL, NULL);
    CHECK(r4.out.n > 5);
    /* an empty environment is a valid (all NUL) block */
    DkProcSpec s5 = captured_bytes();
    s5.env = dk_env_new(a);
    DkProcResult r5 = run_child_ex(&s5, "envdump", NULL, NULL, NULL);
    CHECK(r5.status == DK_PROC_OK && r5.out.n == 0);
}

DK_TEST(run_captures_text_and_bytes) {
    DkProcSpec s = captured_text();
    DkProcResult r = run_child_ex(&s, "echo", "hello", "w\xc3\xb6rld", NULL);
    CHECK(r.status == DK_PROC_OK);
    CHECK_EQ_I64(r.returncode, 0);
    CHECK_STR(r.out, "hello w\xc3\xb6rld\n");
    CHECK(r.err.p != NULL && r.err.n == 0);
    CHECK(r.pid != 0);
    DkProcSpec b = captured_bytes();
    DkProcResult rb = run_child_ex(&b, "bin", NULL, NULL, NULL);
    REQUIRE(rb.out.n == 256);
    for (int i = 0; i < 256; i++) CHECK_MSG((u8)rb.out.p[i] == i, "byte %d is %d", i, (u8)rb.out.p[i]);
    /* a stream that is not captured has no text */
    DkProcSpec n = {0};
    n.out = DK_IO_NULL;
    n.err = DK_IO_NULL;
    DkProcResult rn = run_child_ex(&n, "echo", "x", NULL, NULL);
    CHECK(rn.out.p == NULL && rn.err.p == NULL && rn.returncode == 0);
    /* the usual way the tools ran things */
    const char *argv[] = {"cmd", "/c", "echo", "hi", NULL};
    DkProcResult rt = dk_run_text(dk_scratch(), NULL, argv);
    CHECK_STR(rt.out, "hi\n");
    CHECK_EQ_I64(rt.returncode, 0);
}

DK_TEST(exit_codes_are_unsigned_as_python_shows_them) {
    DkProcSpec s = captured_text();
    CHECK_EQ_I64(run_child_ex(&s, "exit", "0", NULL, NULL).returncode, 0);
    CHECK_EQ_I64(run_child_ex(&s, "exit", "3", NULL, NULL).returncode, 3);
    CHECK_EQ_I64(run_child_ex(&s, "exit", "255", NULL, NULL).returncode, 255);
    CHECK_EQ_I64(run_child_ex(&s, "exit", "4294967295", NULL, NULL).returncode, 4294967295LL);
    CHECK_EQ_I64(run_child_ex(&s, "crash", NULL, NULL, NULL).returncode, 3221225477LL); /* an access violation */
    const char *argv[] = {"cmd", "/c", "exit", "3221225477", NULL};
    DkProcSpec c = captured_text();
    c.argv = argv;
    CHECK_EQ_I64(dk_run(&c).returncode, 3221225477LL); /* as the Python in subprocess shows it */
}

DK_TEST(big_outputs_on_both_pipes_do_not_deadlock) {
    const char *n = "5000000";
    DkProcSpec s = captured_bytes();
    double t0 = dk_monotonic();
    DkProcResult r = run_child_ex(&s, "both", n, NULL, NULL);
    CHECK(dk_monotonic() - t0 < 30.0);
    REQUIRE(r.status == DK_PROC_OK);
    REQUIRE(r.out.n == 5000000 && r.err.n == 5000000);
    bool ok = true;
    for (size_t i = 0; i < 5000000 && ok; i += 997) ok = (u8)r.out.p[i] == pattern_byte(i) && (u8)r.err.p[i] == (pattern_byte(i) ^ 0x5a);
    CHECK(ok);
    DkProcResult e = run_child_ex(&s, "bigerr", "3000000", NULL, NULL);
    CHECK(e.out.n == 0 && e.err.n == 3000000);
}

DK_TEST(stderr_merged_into_stdout_keeps_the_order) {
    DkProcSpec s = {0};
    s.out = DK_IO_CAPTURE;
    s.err = DK_IO_STDOUT;
    s.text = true;
    DkProcResult r = run_child_ex(&s, "order", NULL, NULL, NULL);
    CHECK_STR(r.out, "ABCD");
    CHECK(r.err.p == NULL);
}

DK_TEST(stdin_bytes_are_delivered_exactly) {
    static u8 big[3 * 1024 * 1024];
    for (size_t i = 0; i < sizeof big; i++) big[i] = pattern_byte(i);
    u64 h = 1469598103934665603ULL;
    for (size_t i = 0; i < sizeof big; i++) h = (h ^ big[i]) * 1099511628211ULL;
    char want[64];
    snprintf(want, sizeof want, "%zu %016llx\n", sizeof big, (unsigned long long)h);
    DkProcSpec s = captured_text();
    s.in = DK_IO_CAPTURE;
    s.input = big;
    s.input_n = sizeof big;
    DkProcResult r = run_child_ex(&s, "stdin_sum", NULL, NULL, NULL);
    CHECK_STR(r.out, want);
    /* input and output at once on all three pipes: no deadlock */
    DkProcSpec b = captured_bytes();
    b.in = DK_IO_CAPTURE;
    b.input = big;
    b.input_n = sizeof big;
    double t0 = dk_monotonic();
    DkProcResult rb = run_child_ex(&b, "catboth", NULL, NULL, NULL);
    CHECK(dk_monotonic() - t0 < 30.0);
    REQUIRE(rb.out.n == sizeof big && rb.err.n == sizeof big);
    CHECK_MEM(rb.out.p, big, sizeof big);
    CHECK_MEM(rb.err.p, big, sizeof big);
    /* text input is sent as it is: "\n" stays one byte */
    DkProcSpec t = captured_bytes();
    t.in = DK_IO_CAPTURE;
    t.input = "a\nb\r\nc\n";
    t.input_n = 7;
    DkProcResult rt = run_child_ex(&t, "cat", NULL, NULL, NULL);
    CHECK_EQ_U64(rt.out.n, 7);
    CHECK_MEM(rt.out.p, "a\nb\r\nc\n", 7);
    /* an empty input and no input end the child's stdin at once */
    DkProcSpec e = captured_text();
    e.in = DK_IO_CAPTURE;
    DkProcResult re = run_child_ex(&e, "stdin_sum", NULL, NULL, NULL);
    CHECK_STR(re.out, "0 14650fb0739d0383\n");
    /* the child exits without reading its input: the write fails quietly */
    DkProcSpec q = captured_text();
    q.in = DK_IO_CAPTURE;
    q.input = big;
    q.input_n = sizeof big;
    DkProcResult rq = run_child_ex(&q, "exit", "7", NULL, NULL);
    CHECK(rq.status == DK_PROC_OK && rq.returncode == 7);
}

DK_TEST(devnull_files_and_handles) {
    DkProcSpec s = {0};
    s.in = DK_IO_NULL;
    s.out = DK_IO_CAPTURE;
    s.text = true;
    DkProcResult r = run_child_ex(&s, "stdin_sum", NULL, NULL, NULL);
    CHECK_STR(r.out, "0 14650fb0739d0383\n");
    wchar_t wtmp[MAX_PATH + 1];
    GetTempPathW(MAX_PATH, wtmp);
    char tmp[1024];
    WideCharToMultiByte(CP_UTF8, 0, wtmp, -1, tmp, sizeof tmp, NULL, NULL);
    char path[1100];
    snprintf(path, sizeof path, "%sdk_proc_out_%lu.txt", tmp, (unsigned long)GetCurrentProcessId());
    DkProcSpec f = {0};
    f.out = DK_IO_FILE;
    f.out_path = path;
    f.err = DK_IO_STDOUT;
    DkProcResult rf = run_child_ex(&f, "order", NULL, NULL, NULL);
    CHECK(rf.status == DK_PROC_OK);
    DkProcSpec g = f;
    g.out_append = true;
    run_child_ex(&g, "echo", "more", NULL, NULL);
    FILE *fp = fopen(path, "rb");
    REQUIRE(fp != NULL);
    char buf[64] = {0};
    size_t n = fread(buf, 1, sizeof buf - 1, fp);
    fclose(fp);
    CHECK_MSG(n == 9 && memcmp(buf, "ABCDmore\n", 9) == 0, "file holds \"%s\" (%zu)", buf, n);
    /* an open handle of ours: written to, not closed */
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, FALSE};
    HANDLE h = CreateFileW(dk_to_wz(dk_scratch(), path), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    DkProcSpec hs = {0};
    hs.out = DK_IO_HANDLE;
    hs.out_handle = h;
    run_child_ex(&hs, "echo", "via handle", NULL, NULL);
    DWORD written = 0;
    CHECK(WriteFile(h, "!", 1, &written, NULL)); /* still ours and open */
    CloseHandle(h);
    fp = fopen(path, "rb");
    REQUIRE(fp != NULL);
    memset(buf, 0, sizeof buf);
    n = fread(buf, 1, sizeof buf - 1, fp);
    fclose(fp);
    CHECK_MSG(n >= 11 && memcmp(buf, "via handle\n", 11) == 0, "file holds \"%s\"", buf);
    DeleteFileW(dk_to_wz(dk_scratch(), path));
}

DK_TEST(cwd_and_unicode_names) {
    wchar_t wtmp[MAX_PATH + 1];
    GetTempPathW(MAX_PATH, wtmp);
    char tmp[1024];
    WideCharToMultiByte(CP_UTF8, 0, wtmp, -1, tmp, sizeof tmp, NULL, NULL);
    char dir[1100];
    snprintf(dir, sizeof dir, "%sdk_t\xc3\xa9st_\xe5\xb9\xb4_%lu", tmp, (unsigned long)GetCurrentProcessId());
    wchar_t *wdir = dk_to_wz(dk_scratch(), dir);
    REQUIRE(CreateDirectoryW(wdir, NULL) || GetLastError() == ERROR_ALREADY_EXISTS);
    DkProcSpec s = captured_text();
    s.cwd = dir;
    DkProcResult r = run_child_ex(&s, "cwd", NULL, NULL, NULL);
    CHECK_MSG(dk_str_eqz(r.out, dir), "child cwd \"%.*s\", wanted \"%s\"", DK_SF(r.out), dir);
    /* a unicode argument and a unicode environment value */
    DkProcSpec e = captured_text();
    DkEnv *env = dk_env_current(dk_scratch());
    dk_env_set(env, "DK_U", "\xc3\xa9\xe5\xb9\xb4 x");
    e.env = env;
    CHECK_STR(run_child_ex(&e, "env", "DK_U", NULL, NULL).out, "\xc3\xa9\xe5\xb9\xb4 x");
    CHECK_STR(run_child_ex(&e, "echo", "\xe5\xb9\xb4 a b", "\"q\"", NULL).out, "\xe5\xb9\xb4 a b \"q\"\n");
    RemoveDirectoryW(wdir);
    /* a folder that does not exist: Python's NotADirectoryError, WinError 267 */
    DkProcSpec bad = captured_text();
    bad.cwd = "C:\\no_such_folder_for_dk_tests";
    DkProcResult rb = run_child_ex(&bad, "echo", "x", NULL, NULL);
    CHECK(rb.status == DK_PROC_START_FAILED);
    CHECK_EQ_U64(rb.winerror, 267);
}

DK_TEST(start_failures_carry_the_windows_error) {
    const char *argv[] = {"no_such_program_for_dk_tests", NULL};
    DkProcSpec s = captured_text();
    s.argv = argv;
    DkProcResult r = dk_run(&s);
    CHECK(r.status == DK_PROC_START_FAILED);
    CHECK_EQ_U64(r.winerror, 2);
    CHECK(r.returncode == -1);
    REQUIRE(r.message != NULL);
    CHECK_CZ(r.message, "[WinError 2] The system cannot find the file specified");
    const char *argv2[] = {"C:\\Windows\\System32\\drivers\\etc\\hosts", NULL};
    s.argv = argv2;
    DkProcResult r2 = dk_run(&s);
    CHECK(r2.status == DK_PROC_START_FAILED);
    CHECK_EQ_U64(r2.winerror, 193);
    CHECK_CZ(r2.message, "[WinError 193] %1 is not a valid Win32 application");
    DkProcResult failure;
    DkProc *p = dk_proc_start(&s, &failure);
    CHECK(p == NULL && failure.winerror == 193);
}

DK_TEST(check_flag_reports_a_bad_exit) {
    DkProcSpec s = captured_text();
    s.check = true;
    CHECK(run_child_ex(&s, "exit", "0", NULL, NULL).status == DK_PROC_OK);
    DkProcResult r = run_child_ex(&s, "exit", "3", NULL, NULL);
    CHECK(r.status == DK_PROC_BAD_EXIT && r.returncode == 3);
}

DK_TEST(timeout_returns_what_the_process_wrote) {
    DkProcSpec s = captured_text();
    s.timeout = 3.0; /* the Debug child must start and write "start" inside it: 0.5 s lost that race on a loaded machine */
    double t0 = dk_monotonic();
    DkProcResult r = run_child_ex(&s, "sleep", "20000", NULL, NULL);
    double dt = dk_monotonic() - t0;
    CHECK(r.status == DK_PROC_TIMEOUT);
    CHECK(dt >= 2.99 && dt < 20.0);
    CHECK_STR(r.out, "start\n");
    CHECK_EQ_I64(r.returncode, 1); /* TerminateProcess(h, 1) */
    /* a process that finishes in time is not touched */
    DkProcSpec f = captured_text();
    f.timeout = 30;
    DkProcResult rf = run_child_ex(&f, "sleep", "50", "5", NULL);
    CHECK(rf.status == DK_PROC_OK && rf.returncode == 5);
}

static bool process_alive(u32 pid) {
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    bool alive = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
    CloseHandle(h);
    return alive;
}

DK_TEST(timeout_kills_the_whole_tree_even_if_a_grandchild_holds_the_pipe) {
    DkProcSpec s = captured_text();
    s.timeout = 1.0;
    double t0 = dk_monotonic();
    DkProcResult r = run_child_ex(&s, "grandchild", NULL, NULL, NULL);
    double dt = dk_monotonic() - t0;
    CHECK(r.status == DK_PROC_TIMEOUT);
    CHECK_MSG(dt < 15.0, "took %.1f s: the grandchild kept the pipe open", dt);
    u32 pid = (u32)strtoul(r.out.p, NULL, 10);
    CHECK(pid != 0);
    dk_sleep(0.2);
    CHECK_MSG(!process_alive(pid), "grandchild %u is still running", pid);
}

DK_TEST(children_die_with_the_job_that_holds_them) {
    DkProcSpec s = captured_text();
    DkProcResult r = run_child_ex(&s, "jobtest", NULL, NULL, NULL);
    REQUIRE(r.status == DK_PROC_OK);
    int ok = 0;
    unsigned long pid = 0;
    CHECK(sscanf(r.out.p, "%d %lu", &ok, &pid) == 2);
    if (ok) {
        bool gone = false;
        for (int i = 0; i < 50 && !gone; i++) {
            gone = !process_alive((u32)pid);
            if (!gone) dk_sleep(0.1);
        }
        CHECK_MSG(gone, "the sleeper %lu outlived its parent", pid);
    } else {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
        if (h) {
            TerminateProcess(h, 1);
            CloseHandle(h);
        }
    }
    CHECK(dk_kill_children_with_parent() == dk_kill_children_with_parent());
}

DK_TEST(decoding_matches_python) {
    int checked = 0;
    for (size_t i = 0; i < DK_ARRAY_LEN(proc_decode_cases); i++) {
        const ProcDecodeCase *c = &proc_decode_cases[i];
        DkProcSpec s = {0};
        s.in = DK_IO_CAPTURE;
        s.input = c->in;
        s.input_n = c->in_n;
        s.out = DK_IO_CAPTURE;
        s.text = true;
        s.errors = DK_ERRORS_REPLACE;
        DkProcResult r = run_child_ex(&s, "cat", NULL, NULL, NULL);
        REQUIRE(r.status == DK_PROC_OK);
        CHECK_MSG(r.out.n == c->expect_n && memcmp(r.out.p, c->expect, c->expect_n) == 0, "decode case %zu: %zu bytes differ from Python", i,
                  r.out.n);
        if (i % 4 != 0) {
            checked++;
            continue;
        }
        DkProcSpec t = s;
        t.errors = DK_ERRORS_STRICT;
        DkProcResult rs = run_child_ex(&t, "cat", NULL, NULL, NULL);
        if (c->strict_ok) {
            CHECK_MSG(rs.status == DK_PROC_OK && rs.out.n == c->expect_n, "strict decode case %zu", i);
        } else {
            CHECK_MSG(rs.status == DK_PROC_DECODE_ERROR, "strict decode case %zu should fail", i);
        }
        checked++;
    }
    CHECK(checked > 400);
}

DK_TEST(bytes_mode_leaves_text_alone) {
    DkProcSpec s = captured_bytes();
    s.in = DK_IO_CAPTURE;
    s.input = "a\r\nb\rc\xff\n";
    s.input_n = 8;
    DkProcResult r = run_child_ex(&s, "cat", NULL, NULL, NULL);
    CHECK_EQ_U64(r.out.n, 8);
    CHECK_MEM(r.out.p, "a\r\nb\rc\xff\n", 8);
    DkProcSpec t = s;
    t.text = true;
    t.errors = DK_ERRORS_REPLACE;
    DkProcResult rt = run_child_ex(&t, "cat", NULL, NULL, NULL);
    CHECK_STR(rt.out, "a\nb\nc\xef\xbf\xbd\n");
}

DK_TEST(popen_reads_lines_while_the_process_runs) {
    const char *argv[] = {self_exe(), "--child", "lines", "300", NULL};
    DkProcSpec s = {0};
    s.argv = argv;
    s.out = DK_IO_CAPTURE;
    s.err = DK_IO_STDOUT;
    s.text = true;
    DkProc *p = dk_proc_start(&s, NULL);
    REQUIRE(p != NULL);
    double t0 = dk_monotonic();
    DkStr line;
    REQUIRE(dk_proc_readline(p, 1, &line));
    double first = dk_monotonic() - t0;
    CHECK_STR(line, "line 0\n");
    CHECK_MSG(first < 1.2, "the first line came after %.2f s", first);
    i64 rc;
    CHECK(!dk_proc_poll(p, &rc));
    for (int i = 1; i < 5; i++) {
        REQUIRE(dk_proc_readline(p, 1, &line));
        char want[16];
        snprintf(want, sizeof want, "line %d\n", i);
        CHECK_STR(line, want);
    }
    CHECK(!dk_proc_readline(p, 1, &line));
    CHECK(dk_proc_wait(p, 10, &rc) && rc == 0);
    double total = dk_monotonic() - t0;
    CHECK(total >= 1.1);
    dk_proc_close(p);
}

DK_TEST(popen_talks_to_a_child_like_git_cat_file) {
    const char *argv[] = {self_exe(), "--child", "cat", NULL};
    DkProcSpec s = {0};
    s.argv = argv;
    s.in = DK_IO_CAPTURE;
    s.out = DK_IO_CAPTURE;
    DkProc *p = dk_proc_start(&s, NULL);
    REQUIRE(p != NULL);
    CHECK(dk_proc_write(p, "request one\n", 12));
    DkStr line;
    REQUIRE(dk_proc_readline(p, 1, &line));
    CHECK_EQ_U64(line.n, 12);
    CHECK_MEM(line.p, "request one\n", 12);
    CHECK(dk_proc_write(p, "0123456789abcdef", 16));
    char buf[16];
    CHECK_EQ_U64(dk_proc_read_exact(p, 1, buf, 10), 10);
    CHECK_MEM(buf, "0123456789", 10);
    bool timed_out = false;
    size_t k = dk_proc_read(p, 1, buf, sizeof buf, 5.0, &timed_out);
    CHECK(k == 6 && !timed_out);
    CHECK_MEM(buf, "abcdef", 6);
    k = dk_proc_read(p, 1, buf, sizeof buf, 0.2, &timed_out);
    CHECK(k == 0 && timed_out);
    /* a big answer while we are not reading: the engine keeps draining */
    static char blob[2 * 1024 * 1024];
    memset(blob, 'x', sizeof blob);
    CHECK(dk_proc_write(p, blob, sizeof blob));
    dk_proc_close_stdin(p);
    i64 rc = -1;
    CHECK(dk_proc_wait(p, 20, &rc) && rc == 0);
    size_t total = 0;
    while ((k = dk_proc_read(p, 1, blob, sizeof blob, -1, NULL)) > 0) total += k;
    CHECK_EQ_U64(total, sizeof blob);
    dk_proc_close(p);
}

DK_TEST(popen_text_lines_follow_universal_newlines_across_chunks) {
    size_t checked = 0;
    for (size_t i = 0; i < DK_ARRAY_LEN(proc_decode_cases) && checked < 150; i++) {
        const ProcDecodeCase *c = &proc_decode_cases[i];
        if ((c->nlines == 0 && c->in_n > 0) || memchr(c->in, 0, c->in_n)) continue; /* the expected lines are C strings */
        const char *argv[] = {self_exe(), "--child", "cat", NULL};
        DkProcSpec s = {0};
        s.argv = argv;
        s.in = DK_IO_CAPTURE;
        s.out = DK_IO_CAPTURE;
        s.text = true;
        s.errors = DK_ERRORS_REPLACE;
        DkProc *p = dk_proc_start(&s, NULL);
        REQUIRE(p != NULL);
        /* the data in up to three pieces with pauses, so line ends can fall on chunk borders */
        size_t cut1 = c->in_n / 3, cut2 = 2 * c->in_n / 3;
        if (cut1) dk_proc_write(p, c->in, cut1);
        dk_sleep(0.01);
        if (cut2 > cut1) dk_proc_write(p, c->in + cut1, cut2 - cut1);
        dk_sleep(0.01);
        if (c->in_n > cut2) dk_proc_write(p, c->in + cut2, c->in_n - cut2);
        dk_proc_close_stdin(p);
        DkStr line;
        unsigned k = 0;
        while (dk_proc_readline(p, 1, &line)) {
            if (k < c->nlines) CHECK_MSG(dk_str_eqz(line, c->lines[k]), "case %zu line %u differs from Python's readlines()", i, k);
            k++;
        }
        CHECK_MSG(k == c->nlines, "case %zu: %u lines, Python %u", i, k, c->nlines);
        dk_proc_close(p);
        checked++;
    }
    CHECK(checked > 100);
}

DK_TEST(wait_any_follows_a_fan_out) {
    const char *durations[] = {"900", "100", "400"};
    DkProc *ps[3];
    for (int i = 0; i < 3; i++) {
        const char *argv[] = {self_exe(), "--child", "sleep", durations[i], NULL};
        DkProcSpec s = {0};
        s.argv = argv;
        s.out = DK_IO_NULL;
        ps[i] = dk_proc_start(&s, NULL);
        REQUIRE(ps[i] != NULL);
    }
    CHECK_EQ_I64(dk_proc_wait_any(ps, 3, 20), 1);
    i64 rc;
    CHECK(dk_proc_wait(ps[1], 0, &rc) && rc == 0);
    DkProc *rest[2] = {ps[0], ps[2]};
    CHECK_EQ_I64(dk_proc_wait_any(rest, 2, 20), 1);
    CHECK_EQ_I64(dk_proc_wait_any(ps, 3, 0.0) >= 0, 1);
    CHECK(dk_proc_wait(ps[0], -1, &rc));
    for (int i = 0; i < 3; i++) dk_proc_close(ps[i]);
    /* nothing ends in time */
    const char *argv[] = {self_exe(), "--child", "sleep", "3000", NULL};
    DkProcSpec s = {0};
    s.argv = argv;
    s.out = DK_IO_NULL;
    DkProc *slow = dk_proc_start(&s, NULL);
    REQUIRE(slow != NULL);
    CHECK_EQ_I64(dk_proc_wait_any(&slow, 1, 0.1), -1);
    CHECK(!dk_proc_wait(slow, 0.05, &rc));
    dk_proc_kill_tree(slow);
    CHECK(dk_proc_wait(slow, 10, &rc) && rc == 1);
    dk_proc_close(slow);
}

DK_TEST(shell_runs_through_comspec) {
    DkProcSpec s = captured_text();
    s.cmdline = "echo hello && echo world";
    s.shell = true;
    DkProcResult r = dk_run(&s);
    CHECK(r.status == DK_PROC_OK);
    CHECK_STR(r.out, "hello \nworld\n"); /* as subprocess.run(..., shell=True, text=True).stdout */
    DkProcSpec q = captured_text();
    q.cmdline = "\"C:\\Windows\\System32\\cmd.exe\" /c echo \"a b\"";
    q.shell = true;
    CHECK_STR(dk_run(&q).out, "\"a b\"\n");
    DkProcSpec x = captured_text();
    const char *argv[] = {"echo", "list", "form", NULL};
    x.argv = argv;
    x.shell = true;
    CHECK_STR(dk_run(&x).out, "list form\n");
    DkProcSpec e = captured_text();
    e.cmdline = "exit 5";
    e.shell = true;
    CHECK_EQ_I64(dk_run(&e).returncode, 5);
}

DK_TEST(left_alone_standard_handles_are_the_parents_own) {
    DkProcSpec s = captured_bytes();
    DkProcResult r = run_child_ex(&s, "inherit", NULL, NULL, NULL);
    REQUIRE(r.status == DK_PROC_OK);
    /* "A" from the second grandchild went to our stdout pipe, its "B" and "D" were captured */
    CHECK_MSG(dk_str_eqz(r.out, "plain-inherit\nAC|err=BD||out=stderr-inherit|"), "the child's stdout was \"%.*s\"", DK_SF(r.out));
}

DK_TEST(descendants_can_be_killed_and_the_pid_is_ours) {
    CHECK(dk_getpid() == GetCurrentProcessId());
    CHECK_EQ_U64(dk_kill_descendants(), 0);
    const char *argv[] = {self_exe(), "--child", "sleep", "60000", NULL};
    DkProcSpec s = {0};
    s.argv = argv;
    s.out = DK_IO_NULL;
    DkProc *a = dk_proc_start(&s, NULL), *b = dk_proc_start(&s, NULL);
    REQUIRE(a != NULL && b != NULL);
    CHECK_EQ_U64(dk_kill_descendants(), 2);
    i64 rc = -1;
    CHECK(dk_proc_wait(a, 10, &rc) && rc == 1);
    CHECK(dk_proc_wait(b, 10, &rc) && rc == 1);
    dk_proc_close(a);
    dk_proc_close(b);
}

DK_TEST(creation_flags_are_passed_through) {
    DkProcSpec s = captured_text();
    s.creation_flags = DK_CREATE_NO_WINDOW | DK_BELOW_NORMAL_PRIORITY_CLASS;
    DkProcResult r = run_child_ex(&s, "echo", "quiet", NULL, NULL);
    CHECK(r.status == DK_PROC_OK);
    CHECK_STR(r.out, "quiet\n");
}

typedef struct {
    int id;
    int bad;
} Spawner;

static int spawn_many(void *ctx, size_t index, const void *item, void *result) {
    DK_UNUSED(ctx);
    DK_UNUSED(result);
    const Spawner *sp = item;
    char word[32];
    snprintf(word, sizeof word, "w%zu", index);
    for (int k = 0; k < 4; k++) {
        DkProcSpec s = captured_text();
        char num[16];
        snprintf(num, sizeof num, "%d", k);
        DkProcResult r = run_child_ex(&s, "echo", word, num, NULL);
        char want[64];
        snprintf(want, sizeof want, "%s %d\n", word, k);
        if (r.status != DK_PROC_OK || !dk_str_eqz(r.out, want)) {
            ((Spawner *)sp)->bad++;
            return 1;
        }
    }
    return 0;
}

DK_TEST(concurrent_spawns_from_many_threads_do_not_mix_pipes) {
    Spawner items[24];
    for (int i = 0; i < 24; i++) items[i] = (Spawner){i, 0};
    i64 r = dk_pool_map(NULL, 12, spawn_many, NULL, items, 24, sizeof items[0], NULL, 0);
    CHECK_EQ_I64(r, -1);
    for (int i = 0; i < 24; i++) CHECK_EQ_I64(items[i].bad, 0);
}

static int run_check_ok(void *ctx, size_t index) {
    DK_UNUSED(ctx);
    DK_UNUSED(index);
    return 0;
}

DK_TEST(many_runs_leak_no_handles) {
    DWORD before = 0, after = 0;
    GetProcessHandleCount(GetCurrentProcess(), &before);
    for (int i = 0; i < 40; i++) {
        DkProcSpec s = captured_text();
        s.in = DK_IO_CAPTURE;
        s.input = "x";
        s.input_n = 1;
        s.timeout = 30;
        run_child_ex(&s, "cat", NULL, NULL, NULL);
    }
    GetProcessHandleCount(GetCurrentProcess(), &after);
    CHECK_MSG(after <= before + 6, "handles before %lu, after %lu", (unsigned long)before, (unsigned long)after);
    dk_pool_for(NULL, 2, run_check_ok, NULL, 4);
}

/* Crash and hang policy: a process with no timeout still ends at the wall-clock ceiling (DECOMPKIT_PROC_CEILING seconds). */
DK_TEST(ceiling_kills_a_process_that_has_no_timeout) {
    _putenv_s("DECOMPKIT_PROC_CEILING", "1");
    DkProcSpec s = captured_text(); /* timeout 0: Python's "no limit" */
    double t0 = dk_monotonic();
    DkProcResult r = run_child_ex(&s, "sleep", "60000", NULL, NULL);
    double dt = dk_monotonic() - t0;
    _putenv_s("DECOMPKIT_PROC_CEILING", "");
    CHECK(r.status == DK_PROC_TIMEOUT);
    CHECK_EQ_I64(r.returncode, 124);
    CHECK_MSG(dt >= 0.9 && dt < 20.0, "the ceiling killed it after %.1f s", dt);
    CHECK_STR(r.out, "start\n");
}

DK_TEST(ceiling_kills_a_started_process_whoever_waits_on_it) {
    _putenv_s("DECOMPKIT_PROC_CEILING", "1");
    const char *argv[] = {self_exe(), "--child", "sleep", "60000", NULL};
    DkProcSpec s = {0};
    s.argv = argv;
    s.out = DK_IO_NULL;
    s.err = DK_IO_NULL;
    DkProc *p = dk_proc_start(&s, NULL);
    _putenv_s("DECOMPKIT_PROC_CEILING", "");
    REQUIRE(p != NULL);
    i64 rc = -1;
    double t0 = dk_monotonic();
    CHECK(dk_proc_wait(p, -1, &rc)); /* no timeout: only the ceiling ends it */
    double dt = dk_monotonic() - t0;
    CHECK_EQ_I64(rc, 124);
    CHECK(dk_proc_ceiling_hit(p));
    CHECK_MSG(dt < 20.0, "took %.1f s", dt);
    dk_proc_close(p);
}

DK_TEST(a_process_still_running_is_killed_when_its_handle_is_closed) {
    const char *argv[] = {self_exe(), "--child", "sleep", "60000", NULL};
    DkProcSpec s = {0};
    s.argv = argv;
    s.out = DK_IO_NULL;
    s.err = DK_IO_NULL;
    DkProc *p = dk_proc_start(&s, NULL);
    REQUIRE(p != NULL);
    u32 pid = dk_proc_pid(p);
    CHECK(process_alive(pid));
    dk_proc_close(p);
    bool gone = false;
    for (int i = 0; i < 50 && !gone; i++) {
        gone = !process_alive(pid);
        if (!gone) dk_sleep(0.1);
    }
    CHECK_MSG(gone, "process %u survived the close of its job", pid);
}

static int run_main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--child") == 0) return child_main(argc, argv);
    return dk_test__run(argc, argv);
}
DK_MAIN(run_main, "test_proc")
