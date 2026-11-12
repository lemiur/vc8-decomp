// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* proc.h's `debug` field: a child started with DkProcSpec.debug is debugged by the calling thread (Python's
 * creationflags=... | 0x2, DEBUG_ONLY_THIS_PROCESS) inside its Job object. The children are this executable started
 * with --child. No expected values come from Python: the events are the Win32 debug API's. */
#include "dk/dk.h"
#include "dk/proc.h"
#include "dk/test.h"

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* ---- the child side ---- */

static int child_main(int argc, char **argv) {
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    const char *mode = argv[2];
    if (strcmp(mode, "exit") == 0) ExitProcess((UINT)strtoul(argv[3], NULL, 10));
    if (strcmp(mode, "break") == 0) {
        DebugBreak(); /* a breakpoint exception the debugger continues */
        ExitProcess(5);
    }
    if (strcmp(mode, "sleep") == 0) {
        Sleep((DWORD)strtoul(argv[3], NULL, 10));
        return 0;
    }
    return 99;
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

typedef struct {
    int created, exited, loaded, breakpoints, exceptions;
    DWORD exit_code;
    bool saw_mz; /* the first bytes of the image, read through the debuggee's process handle */
    bool timed_out;
} Seen;

/* The debug loop of c2_trace.Tracer.run in miniature: wait one second at a time, continue every event, stop at the
 * debuggee's exit. kill_after_create: dk_proc_kill when the process-creation event arrives. */
static Seen pump(DkProc *p, bool kill_after_create) {
    Seen s = {0};
    ULONGLONG deadline = GetTickCount64() + 60000;
    for (;;) {
        if (GetTickCount64() > deadline) {
            s.timed_out = true;
            dk_proc_kill_tree(p);
            return s;
        }
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, 1000)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) continue;
            s.timed_out = true;
            return s;
        }
        DWORD status = DBG_CONTINUE;
        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            s.created++;
            u8 head[2] = {0, 0};
            SIZE_T got = 0;
            if (ReadProcessMemory(ev.u.CreateProcessInfo.hProcess, ev.u.CreateProcessInfo.lpBaseOfImage, head, 2, &got) &&
                got == 2 && head[0] == 'M' && head[1] == 'Z')
                s.saw_mz = true;
            if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
            if (kill_after_create) dk_proc_kill(p);
            break;
        }
        case LOAD_DLL_DEBUG_EVENT:
            s.loaded++;
            if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
            break;
        case EXCEPTION_DEBUG_EVENT:
            s.exceptions++;
            if (ev.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) s.breakpoints++;
            else status = DBG_EXCEPTION_NOT_HANDLED;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            s.exited++;
            s.exit_code = ev.u.ExitProcess.dwExitCode;
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
            return s;
        default:
            break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
    }
}

static DkProc *start(const char *a1, const char *a2, bool debug) {
    const char *argv[6];
    int n = 0;
    argv[n++] = self_exe();
    argv[n++] = "--child";
    argv[n++] = a1;
    if (a2) argv[n++] = a2;
    argv[n] = NULL;
    DkProcSpec spec = {0};
    spec.argv = argv;
    spec.out = DK_IO_NULL;
    spec.err = DK_IO_NULL;
    spec.in = DK_IO_NULL;
    spec.creation_flags = DK_CREATE_NO_WINDOW;
    spec.debug = debug;
    DkProcResult fail;
    DkProc *p = dk_proc_start(&spec, &fail);
    return p;
}

DK_TEST(a_debugged_child_reports_creation_loads_and_exit) {
    DkProc *p = start("exit", "7", true);
    REQUIRE(p != NULL);
    Seen s = pump(p, false);
    CHECK(!s.timed_out);
    CHECK_EQ_I64(s.created, 1);
    CHECK_EQ_I64(s.exited, 1);
    CHECK_EQ_I64(s.exit_code, 7);
    CHECK(s.loaded >= 1);
    CHECK(s.saw_mz);
    CHECK(s.breakpoints >= 1); /* the loader's initial breakpoint */
    i64 rc = -1;
    CHECK(dk_proc_wait(p, 10.0, &rc));
    CHECK_EQ_I64(rc, 7);
    dk_proc_close(p);
}

DK_TEST(a_breakpoint_the_child_raises_arrives_as_a_first_chance_exception) {
    DkProc *p = start("break", NULL, true);
    REQUIRE(p != NULL);
    Seen s = pump(p, false);
    CHECK(!s.timed_out);
    CHECK_EQ_I64(s.exit_code, 5);
    CHECK(s.breakpoints >= 2); /* the loader's and the child's own */
    dk_proc_close(p);
}

DK_TEST(a_debugged_child_is_killed_through_its_job_and_the_loop_sees_the_exit) {
    DkProc *p = start("sleep", "60000", true);
    REQUIRE(p != NULL);
    Seen s = pump(p, true);
    CHECK(!s.timed_out);
    CHECK_EQ_I64(s.exited, 1);
    CHECK_EQ_I64(s.exit_code, 1); /* TerminateProcess(h, 1) */
    dk_proc_close(p);
}

DK_TEST(a_child_started_without_debug_raises_no_debug_events) {
    DkProc *p = start("exit", "3", false);
    REQUIRE(p != NULL);
    i64 rc = -1;
    CHECK(dk_proc_wait(p, 20.0, &rc));
    CHECK_EQ_I64(rc, 3);
    DEBUG_EVENT ev;
    SetLastError(0);
    CHECK(!WaitForDebugEvent(&ev, 0));
    dk_proc_close(p);
}

static int run_main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--child") == 0) return child_main(argc, argv);
    return dk_test__run(argc, argv);
}
DK_MAIN(run_main, "test_proc_debug")
