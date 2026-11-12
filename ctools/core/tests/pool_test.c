// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* pool.h: atomics, locks, threads, pools with ordered results, futures, the process fan-out and os.cpu_count. */
#include "dk/dk.h"
#include "dk/clock.h"
#include "dk/pool.h"
#include "dk/proc.h"
#include "dk/test.h"

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* ---- child side: the fan-out jobs and the cpu count ---- */

/* Writes a marker file <prefix><pid> and waits until `need` markers exist: that many children are alive at once. */
static void rendezvous(const char *prefix, int need) {
    char path[1100], pat[1100];
    snprintf(path, sizeof path, "%s%lu", prefix, (unsigned long)GetCurrentProcessId());
    snprintf(pat, sizeof pat, "%s*", prefix);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    for (int tries = 0; tries < 120000; tries++) { /* up to 120 s: only trips when the parent's limit is broken */
        int n = 0;
        WIN32_FIND_DATAA fd;
        HANDLE f = FindFirstFileA(pat, &fd);
        if (f != INVALID_HANDLE_VALUE) {
            do n++;
            while (FindNextFileA(f, &fd));
            FindClose(f);
        }
        if (n >= need) return;
        Sleep(1);
    }
}

static int child_main(int argc, char **argv) {
    const char *mode = argv[2];
    char line[128];
    int n = 0;
    if (strcmp(mode, "span") == 0) {
        LARGE_INTEGER a, b;
        QueryPerformanceCounter(&a);
        if (argc >= 6) rendezvous(argv[4], (int)strtol(argv[5], NULL, 10));
        Sleep((DWORD)strtoul(argv[3], NULL, 10));
        QueryPerformanceCounter(&b);
        n = snprintf(line, sizeof line, "%lld %lld\n", a.QuadPart, b.QuadPart);
    } else if (strcmp(mode, "cpucount") == 0) {
        n = snprintf(line, sizeof line, "%d %d\n", dk_cpu_count(), dk_process_cpu_count());
    } else {
        return 99;
    }
    (void)argc;
    DWORD w;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, (DWORD)n, &w, NULL);
    return 0;
}

static const char *self_exe(void) {
    static char path[1024];
    if (!path[0]) {
        wchar_t w[1024];
        DWORD n = GetModuleFileNameW(NULL, w, 1024);
        WideCharToMultiByte(CP_UTF8, 0, w, (int)n, path, sizeof path - 1, NULL, NULL);
    }
    return path;
}

/* ---- cpu count ---- */

DK_TEST(cpu_count_is_the_windows_processor_count_and_honours_the_override) {
    CHECK_EQ_I64(dk_cpu_count(), (long long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    CHECK_EQ_I64(dk_process_cpu_count(), dk_cpu_count());
    CHECK(dk_cpu_count() >= 1);
    const char *cases[][2] = {{"5", "5 5"}, {"1", "1 1"}, {"0", NULL}, {"-3", NULL}, {"abc", NULL}, {"default", NULL}, {"", NULL}, {"7x", NULL}};
    for (size_t i = 0; i < DK_ARRAY_LEN(cases); i++) {
        DkEnv *env = dk_env_current(dk_scratch());
        dk_env_set(env, "PYTHON_CPU_COUNT", cases[i][0]);
        const char *argv[] = {self_exe(), "--child", "cpucount", NULL};
        DkProcSpec s = {0};
        s.argv = argv;
        s.env = env;
        s.out = DK_IO_CAPTURE;
        s.text = true;
        DkProcResult r = dk_run(&s);
        REQUIRE(r.status == DK_PROC_OK);
        char want[32];
        if (cases[i][1]) snprintf(want, sizeof want, "%s\n", cases[i][1]);
        else snprintf(want, sizeof want, "%d %d\n", dk_cpu_count(), dk_cpu_count());
        CHECK_MSG(dk_str_eqz(r.out, want), "PYTHON_CPU_COUNT=\"%s\": \"%.*s\", wanted \"%s\"", cases[i][0], DK_SF(r.out), want);
    }
}

/* ---- atomics ---- */

typedef struct {
    DkAtomic32 n32;
    DkAtomic64 n64;
    DkAtomic64 high;
    long plain_guarded;
    DkMutex mu;
    int go;
} Shared;

static void hammer(void *arg) {
    Shared *s = arg;
    for (int i = 0; i < 100000; i++) {
        dk_atomic_add32(&s->n32, 1);
        dk_atomic_add64(&s->n64, 3);
        dk_atomic_max64(&s->high, i);
        dk_mutex_lock(&s->mu);
        s->plain_guarded++;
        dk_mutex_unlock(&s->mu);
    }
}

DK_TEST(atomics_and_mutex_under_contention) {
    Shared s;
    memset(&s, 0, sizeof s);
    DkThread *t[8];
    for (int i = 0; i < 8; i++) t[i] = dk_thread_start(hammer, &s, 0);
    for (int i = 0; i < 8; i++) dk_thread_join(t[i]);
    CHECK_EQ_I64(dk_atomic_load32(&s.n32), 800000);
    CHECK_EQ_I64(dk_atomic_load64(&s.n64), 2400000);
    CHECK_EQ_I64(dk_atomic_load64(&s.high), 99999);
    CHECK_EQ_I64(s.plain_guarded, 800000);
}

DK_TEST(atomic_operations_return_what_they_say) {
    DkAtomic32 a = {0};
    DkAtomic64 b = {0};
    CHECK_EQ_I64(dk_atomic_add32(&a, 5), 5);
    CHECK_EQ_I64(dk_atomic_add32(&a, -7), -2);
    CHECK_EQ_I64(dk_atomic_xchg32(&a, 9), -2);
    CHECK(dk_atomic_cas32(&a, 9, 11));
    CHECK(!dk_atomic_cas32(&a, 9, 12));
    CHECK_EQ_I64(dk_atomic_load32(&a), 11);
    dk_atomic_store32(&a, 4);
    CHECK_EQ_I64(dk_atomic_load32(&a), 4);
    CHECK_EQ_I64(dk_atomic_add64(&b, 1LL << 40), 1LL << 40);
    CHECK_EQ_I64(dk_atomic_xchg64(&b, 3), 1LL << 40);
    CHECK(dk_atomic_cas64(&b, 3, 1LL << 50));
    CHECK_EQ_I64(dk_atomic_load64(&b), 1LL << 50);
    CHECK_EQ_I64(dk_atomic_max64(&b, 5), 1LL << 50);
    CHECK_EQ_I64(dk_atomic_max64(&b, (1LL << 50) + 1), (1LL << 50) + 1);
    dk_atomic_store64(&b, -1);
    CHECK_EQ_I64(dk_atomic_load64(&b), -1);
}

/* ---- locks, condition variable, once, event, semaphore ---- */

DK_TEST(mutex_try_and_shared_modes) {
    DkMutex m = {0};
    CHECK(dk_mutex_trylock(&m));
    CHECK(!dk_mutex_trylock(&m));
    CHECK(!dk_mutex_trylock_shared(&m));
    dk_mutex_unlock(&m);
    CHECK(dk_mutex_trylock_shared(&m));
    CHECK(dk_mutex_trylock_shared(&m));
    CHECK(!dk_mutex_trylock(&m));
    dk_mutex_unlock_shared(&m);
    dk_mutex_unlock_shared(&m);
    dk_mutex_lock_shared(&m);
    dk_mutex_unlock_shared(&m);
    dk_mutex_lock(&m);
    dk_mutex_unlock(&m);
}

DK_TEST(recursive_mutex_is_reentrant) {
    DkRMutex m;
    dk_rmutex_init(&m);
    dk_rmutex_lock(&m);
    dk_rmutex_lock(&m);
    CHECK(dk_rmutex_trylock(&m));
    dk_rmutex_unlock(&m);
    dk_rmutex_unlock(&m);
    dk_rmutex_unlock(&m);
    dk_rmutex_destroy(&m);
}

typedef struct {
    DkMutex mu;
    DkCond cv;
    int turn; /* 0: ping, 1: pong */
    int rounds, done;
} PingPong;

static void pinger(void *arg) {
    PingPong *p = arg;
    for (int i = 0; i < p->rounds; i++) {
        dk_mutex_lock(&p->mu);
        while (p->turn != 0) dk_cond_wait(&p->cv, &p->mu, -1);
        p->turn = 1;
        dk_cond_broadcast(&p->cv);
        dk_mutex_unlock(&p->mu);
    }
}

DK_TEST(condition_variable_ping_pong_and_timeout) {
    PingPong p;
    memset(&p, 0, sizeof p);
    p.rounds = 2000;
    DkThread *t = dk_thread_start(pinger, &p, 0);
    for (int i = 0; i < p.rounds; i++) {
        dk_mutex_lock(&p.mu);
        while (p.turn != 1) dk_cond_wait(&p.cv, &p.mu, -1);
        p.turn = 0;
        p.done++;
        dk_cond_signal(&p.cv);
        dk_mutex_unlock(&p.mu);
    }
    dk_thread_join(t);
    CHECK_EQ_I64(p.done, 2000);
    DkMutex m = {0};
    DkCond c = {0};
    dk_mutex_lock(&m);
    double t0 = dk_monotonic();
    CHECK(!dk_cond_wait(&c, &m, 0.1));
    double dt = dk_monotonic() - t0;
    dk_mutex_unlock(&m);
    CHECK_MSG(dt >= 0.09, "a 0.1 s wait returned after %.3f s", dt); /* no upper bound: how late a loaded machine wakes the thread says nothing about the timeout path */
}

static DkAtomic32 g_once_runs;
static void once_fn(void *ctx) {
    dk_sleep(0.02);
    dk_atomic_add32(&g_once_runs, 1);
    *(int *)ctx = 42;
}
typedef struct {
    DkOnce *once;
    int *value;
    int seen;
} OnceArg;
static void once_thread(void *arg) {
    OnceArg *a = arg;
    dk_once(a->once, once_fn, a->value);
    a->seen = *a->value; /* the others wait for the first run to end */
}

DK_TEST(once_runs_exactly_once) {
    DkOnce once = {0};
    int value = 0;
    OnceArg args[16];
    DkThread *t[16];
    for (int i = 0; i < 16; i++) {
        args[i] = (OnceArg){&once, &value, -1};
        t[i] = dk_thread_start(once_thread, &args[i], 0);
    }
    for (int i = 0; i < 16; i++) dk_thread_join(t[i]);
    CHECK_EQ_I64(dk_atomic_load32(&g_once_runs), 1);
    for (int i = 0; i < 16; i++) CHECK_EQ_I64(args[i].seen, 42);
}

static void setter(void *arg) {
    dk_sleep(0.05);
    dk_event_set((DkEvent *)arg);
}

DK_TEST(event_and_semaphore) {
    DkEvent e;
    dk_event_init(&e);
    CHECK(!dk_event_is_set(&e));
    CHECK(!dk_event_wait(&e, 0.0));
    double t0 = dk_monotonic();
    CHECK(!dk_event_wait(&e, 0.08));
    CHECK(dk_monotonic() - t0 >= 0.075);
    DkThread *t = dk_thread_start(setter, &e, 0);
    CHECK(dk_event_wait(&e, 120.0));
    dk_thread_join(t);
    CHECK(dk_event_is_set(&e));
    CHECK(dk_event_wait(&e, -1)); /* stays set */
    dk_event_clear(&e);
    CHECK(!dk_event_is_set(&e));
    dk_event_destroy(&e);
    DkSem s;
    dk_sem_init(&s, 2);
    CHECK(dk_sem_acquire(&s, 0));
    CHECK(dk_sem_acquire(&s, 0));
    CHECK(!dk_sem_acquire(&s, 0.03));
    dk_sem_release(&s);
    CHECK(dk_sem_acquire(&s, 60.0));
    dk_sem_destroy(&s);
}

static int g_deep_ok;
static int recurse(int depth) {
    volatile char pad[2048];
    pad[0] = (char)depth;
    if (depth == 0) return pad[0];
    return recurse(depth - 1) + (pad[0] & 1);
}
static void deep_thread(void *arg) {
    (void)arg;
    g_deep_ok = recurse(30000) >= 0; /* 60 MB of stack */
}

DK_TEST(threads_have_ids_and_a_chosen_stack) {
    CHECK(dk_thread_id() == GetCurrentThreadId());
    DkThread *t = dk_thread_start(deep_thread, NULL, 128 * 1024 * 1024);
    dk_thread_join(t);
    CHECK(g_deep_ok);
}

/* ---- map ---- */

typedef struct {
    DkAtomic32 running, max_running, calls;
    DkAtomic64 caller_id;
    int fail_at, fail_at2;
    int sleep_scale;
    int rendezvous; /* items below this index wait until that many items run at once */
    int gate_after; /* when >= 0: items above this index wait until the item at it has failed */
    DkAtomic32 gate_open;
} MapCtx;

/* Polls a counter with a bound that only fails when the thing never happens. */
static bool poll_until(DkAtomic32 *flag, i32 want, double limit) {
    double t0 = dk_monotonic();
    while (dk_atomic_load32(flag) < want) {
        if (dk_monotonic() - t0 > limit) return false;
        Sleep(1);
    }
    return true;
}

static unsigned delay_ms(size_t i) { return (unsigned)((i * 2654435761u >> 7) % 4); }

static int map_square(void *ctx, size_t index, const void *item, void *result) {
    MapCtx *c = ctx;
    i32 now = dk_atomic_add32(&c->running, 1);
    for (;;) {
        i32 m = dk_atomic_load32(&c->max_running);
        if (now <= m || dk_atomic_cas32(&c->max_running, m, now)) break;
    }
    dk_atomic_add32(&c->calls, 1);
    if ((int)index < c->rendezvous) poll_until(&c->running, c->rendezvous, 120.0);
    if (c->gate_after >= 0 && (int)index > c->gate_after) {
        poll_until(&c->gate_open, 1, 120.0);
        Sleep(20); /* slow work next to the failing item's bookkeeping */
    }
    if (c->sleep_scale) Sleep(delay_ms(index) * (DWORD)c->sleep_scale);
    int v = *(const int *)item;
    *(i64 *)result = (i64)v * v;
    dk_atomic_add32(&c->running, -1);
    if ((int)index == c->fail_at || (int)index == c->fail_at2) {
        if ((int)index == c->gate_after) dk_atomic_store32(&c->gate_open, 1);
        return 1;
    }
    return 0;
}

DK_TEST(map_gives_results_in_input_order_whatever_the_delays) {
    enum { N = 600 };
    static int items[N];
    static i64 results[N];
    for (int i = 0; i < N; i++) items[i] = i - 100;
    MapCtx c;
    memset(&c, 0, sizeof c);
    c.fail_at = c.fail_at2 = -1;
    c.sleep_scale = 1;
    c.gate_after = -1;
    c.rendezvous = 3; /* items 0..2 each wait for the other two: three really run at once */
    i64 r = dk_pool_map(NULL, 8, map_square, &c, items, N, sizeof items[0], results, sizeof results[0]);
    CHECK_EQ_I64(r, -1);
    for (int i = 0; i < N; i++) CHECK_MSG(results[i] == (i64)(i - 100) * (i - 100), "result %d is %lld", i, (long long)results[i]);
    CHECK_EQ_I64(dk_atomic_load32(&c.calls), N);
    CHECK_MSG(dk_atomic_load32(&c.max_running) <= 8, "%d tasks ran at once", (int)dk_atomic_load32(&c.max_running));
    CHECK_MSG(dk_atomic_load32(&c.max_running) >= 3, "only %d tasks ran at once", (int)dk_atomic_load32(&c.max_running));
}

DK_TEST(map_reports_the_lowest_failing_index_and_cancels_the_rest) {
    enum { N = 400 };
    static int items[N];
    static i64 results[N];
    for (int i = 0; i < N; i++) items[i] = i;
    MapCtx c;
    memset(&c, 0, sizeof c);
    c.fail_at = 37;
    c.fail_at2 = 80;
    c.sleep_scale = 2;
    c.gate_after = 37; /* everything after the failing item is held until it has failed */
    i64 r = dk_pool_map(NULL, 4, map_square, &c, items, N, sizeof items[0], results, sizeof results[0]);
    CHECK_EQ_I64(r, 37);
    /* Items are claimed in index order and a claimed one finishes, so 0..37 all ran; at most the other three threads
       were inside later items, and each looks at the failure before claiming another one. */
    CHECK_MSG(dk_atomic_load32(&c.calls) >= 38, "%d items ran, the 38 up to the failure must", (int)dk_atomic_load32(&c.calls));
    CHECK_MSG(dk_atomic_load32(&c.calls) < 100, "%d items ran after the failure", (int)dk_atomic_load32(&c.calls));
    for (int i = 0; i <= 37; i++) CHECK_EQ_I64(results[i], (i64)i * i);
}

static DkAtomic64 g_other_thread_runs;
static int map_note_thread(void *ctx, size_t index, const void *item, void *result) {
    DK_UNUSED(item);
    DK_UNUSED(result);
    DK_UNUSED(index);
    if (dk_thread_id() != (u32)(uintptr_t)ctx) dk_atomic_add64(&g_other_thread_runs, 1);
    return 0;
}

DK_TEST(one_thread_or_one_item_runs_on_the_caller) {
    dk_atomic_store64(&g_other_thread_runs, 0);
    CHECK_EQ_I64(dk_pool_map(NULL, 1, map_note_thread, (void *)(uintptr_t)dk_thread_id(), NULL, 50, 0, NULL, 0), -1);
    CHECK_EQ_I64(dk_atomic_load64(&g_other_thread_runs), 0);
    CHECK_EQ_I64(dk_pool_map(NULL, 8, map_note_thread, (void *)(uintptr_t)dk_thread_id(), NULL, 1, 0, NULL, 0), -1);
    CHECK_EQ_I64(dk_atomic_load64(&g_other_thread_runs), 0);
    CHECK_EQ_I64(dk_pool_map(NULL, 8, map_note_thread, NULL, NULL, 0, 0, NULL, 0), -1);
}

typedef struct {
    DkAtomic64 sum;
} SumCtx;
static void sum_range(void *ctx, size_t begin, size_t end) {
    i64 s = 0;
    for (size_t i = begin; i < end; i++) s += (i64)i;
    dk_atomic_add64(&((SumCtx *)ctx)->sum, s);
}
static int for_flag(void *ctx, size_t index) {
    ((u8 *)ctx)[index] = 1;
    return index == 777 ? 5 : 0;
}

DK_TEST(parallel_for_and_ranges_cover_every_index_once) {
    SumCtx c = {{0}};
    dk_pool_for_range(NULL, 6, sum_range, &c, 1000001, 1000);
    CHECK_EQ_I64(dk_atomic_load64(&c.sum), 1000000LL * 1000001LL / 2);
    c.sum.v = 0;
    dk_pool_for_range(NULL, 1, sum_range, &c, 5, 100);
    CHECK_EQ_I64(dk_atomic_load64(&c.sum), 10);
    static u8 flags[1000];
    CHECK_EQ_I64(dk_pool_for(NULL, 4, for_flag, flags, 700), -1);
    for (int i = 0; i < 700; i++) CHECK_EQ_I64(flags[i], 1);
    memset(flags, 0, sizeof flags);
    CHECK_EQ_I64(dk_pool_for(NULL, 4, for_flag, flags, 1000), 777);
    CHECK_EQ_I64(flags[0], 1);
}

typedef struct {
    int outer_threads, inner_threads;
    DkAtomic64 total;
} NestCtx;
static int inner_item(void *ctx, size_t index) {
    dk_atomic_add64(&((NestCtx *)ctx)->total, (i64)index + 1);
    Sleep(1);
    return 0;
}
static int outer_item(void *ctx, size_t index) {
    NestCtx *n = ctx;
    DK_UNUSED(index);
    return (int)(dk_pool_for(NULL, n->inner_threads, inner_item, n, 10) != -1);
}

DK_TEST(maps_inside_maps_do_not_deadlock) {
    NestCtx n = {4, 4, {0}};
    double t0 = dk_monotonic();
    CHECK_EQ_I64(dk_pool_for(NULL, 4, outer_item, &n, 40), -1);
    CHECK(dk_monotonic() - t0 < 30.0);
    CHECK_EQ_I64(dk_atomic_load64(&n.total), 40 * 55);
}

/* ---- pools with their own threads, futures, completions ---- */

typedef struct {
    int ms;
    int result;
    DkEvent started, gate; /* task_gated: signals started, then holds until the test opens gate */
} Task;

static int task_run(void *arg) {
    Task *t = arg;
    Sleep((DWORD)t->ms);
    return t->result;
}

static int task_gated(void *arg) {
    Task *t = arg;
    dk_event_set(&t->started);
    dk_event_wait(&t->gate, 120.0); /* a bound that only trips when the test is broken */
    return t->result;
}

static void task_init(Task *t, int ms, int result) {
    memset(t, 0, sizeof *t);
    t->ms = ms;
    t->result = result;
    dk_event_init(&t->started);
    dk_event_init(&t->gate);
}

static void task_done(Task *t) {
    dk_event_destroy(&t->started);
    dk_event_destroy(&t->gate);
}

/* Opens a gate once a future has been cancelled (what a shutdown with cancel_pending does while it waits). */
typedef struct {
    DkFuture *watch;
    Task *gated;
} Opener;
static void opener_thread(void *arg) {
    Opener *o = arg;
    double t0 = dk_monotonic();
    while (!dk_future_cancelled(o->watch) && dk_monotonic() - t0 < 120.0) Sleep(1);
    dk_event_set(&o->gated->gate);
}

static DkAtomic32 g_inits;
static DkAtomic32 g_worker_seen[16];
static void pool_init(int index, void *ctx) {
    DK_UNUSED(ctx);
    dk_atomic_add32(&g_inits, 1);
    if (index >= 0 && index < 16) dk_atomic_store32(&g_worker_seen[index], 1);
}
static int report_index(void *arg) {
    *(int *)arg = dk_pool_worker_index();
    Sleep(5);
    return 0;
}

DK_TEST(pool_submit_futures_and_worker_indexes) {
    DkPoolOpts o = {0};
    o.threads = 3;
    o.thread_init = pool_init;
    DkPool *p = dk_pool_new_ex(&o);
    enum { N = 12 };
    int idx[N];
    DkFuture *f[N];
    for (int i = 0; i < N; i++) {
        idx[i] = -9;
        f[i] = dk_pool_submit(p, report_index, &idx[i]);
    }
    for (int i = 0; i < N; i++) {
        int r = -1;
        CHECK(dk_future_result(f[i], -1, &r));
        CHECK_EQ_I64(r, 0);
        CHECK_MSG(idx[i] >= 0 && idx[i] < 3, "task ran on worker %d", idx[i]);
        CHECK(dk_future_done(f[i]));
        dk_future_free(f[i]);
    }
    CHECK_EQ_I64(dk_pool_worker_index(), -1);
    dk_pool_shutdown(p, false);
    CHECK_MSG(dk_atomic_load32(&g_inits) >= 1 && dk_atomic_load32(&g_inits) <= 3, "%d initialisers ran", (int)dk_atomic_load32(&g_inits));
}

DK_TEST(pool_cancel_timeout_and_shutdown_semantics) {
    DkPool *p = dk_pool_new(1);
    Task slow, queued, queued2;
    task_init(&slow, 0, 7);
    task_init(&queued, 10, 8);
    task_init(&queued2, 10, 9);
    DkFuture *a = dk_pool_submit(p, task_gated, &slow);
    DkFuture *b = dk_pool_submit(p, task_run, &queued);
    DkFuture *c = dk_pool_submit(p, task_run, &queued2);
    int r = -1;
    CHECK(dk_event_wait(&slow.started, 120.0)); /* the only worker holds a, so b and c stay queued */
    CHECK(!dk_future_result(a, 0.02, &r)); /* timeout: a cannot finish before the gate opens */
    CHECK(dk_future_cancel(b));            /* still queued */
    CHECK(dk_future_cancelled(b));
    CHECK(!dk_future_cancel(a));           /* running */
    CHECK(!dk_future_result(b, -1, &r));   /* cancelled: no result */
    dk_event_set(&slow.gate);
    dk_pool_shutdown(p, false);            /* runs what is queued, waits for the rest */
    CHECK(dk_future_result(a, 0, &r) && r == 7);
    CHECK(dk_future_result(c, 0, &r) && r == 9);
    dk_future_free(a);
    dk_future_free(b);
    dk_future_free(c);
    task_done(&slow);
    task_done(&queued);
    task_done(&queued2);
    /* shutdown with cancel_pending drops what has not started */
    DkPool *q = dk_pool_new(1);
    Task t1, t2;
    task_init(&t1, 0, 1);
    task_init(&t2, 10, 2);
    DkFuture *f1 = dk_pool_submit(q, task_gated, &t1);
    DkFuture *f2 = dk_pool_submit(q, task_run, &t2);
    CHECK(dk_event_wait(&t1.started, 120.0));
    Opener op = {f2, &t1}; /* shutdown waits for the running f1, which only ends once f2 is seen cancelled */
    DkThread *th = dk_thread_start(opener_thread, &op, 0);
    dk_pool_shutdown(q, true);
    dk_thread_join(th);
    CHECK(dk_future_result(f1, 0, &r) && r == 1);
    CHECK(dk_future_cancelled(f2));
    dk_future_free(f1);
    dk_future_free(f2);
    task_done(&t1);
    task_done(&t2);
}

DK_TEST(completions_come_in_finishing_order) {
    DkPool *p = dk_pool_new(12);
    DkCompletions *done = dk_completions_new();
    enum { N = 8 };
    Task tasks[N];
    DkFuture *f[N];
    for (int i = 0; i < N; i++) {
        task_init(&tasks[i], 0, i);
        f[i] = dk_pool_submit_to(p, task_gated, &tasks[i], done);
    }
    for (int i = 0; i < N; i++) CHECK(dk_event_wait(&tasks[i].started, 120.0));
    /* the tasks finish in the order the test opens their gates: task 7 first, task 0 last */
    for (int k = 0; k < N; k++) {
        dk_event_set(&tasks[N - 1 - k].gate);
        DkFuture *d = dk_completions_next(done, 120.0);
        REQUIRE(d != NULL);
        int r = -1;
        CHECK(dk_future_result(d, 0, &r));
        CHECK_MSG(r == N - 1 - k, "completion %d was task %d", k, r);
    }
    CHECK(dk_completions_next(done, 0.02) == NULL); /* nothing left: the timeout path */
    for (int i = 0; i < N; i++) {
        dk_future_free(f[i]);
        task_done(&tasks[i]);
    }
    dk_completions_free(done);
    dk_pool_shutdown(p, false);
}

DK_TEST(map_on_a_bounded_pool_respects_its_size) {
    DkPool *p = dk_pool_new(2);
    static int items[100];
    static i64 results[100];
    for (int i = 0; i < 100; i++) items[i] = i;
    MapCtx c;
    memset(&c, 0, sizeof c);
    c.fail_at = c.fail_at2 = -1;
    c.sleep_scale = 1;
    c.gate_after = -1;
    CHECK_EQ_I64(dk_pool_map(p, 16, map_square, &c, items, 100, sizeof items[0], results, sizeof results[0]), -1);
    CHECK_MSG(dk_atomic_load32(&c.max_running) <= 2, "%d tasks ran at once on a 2-thread pool", (int)dk_atomic_load32(&c.max_running));
    for (int i = 0; i < 100; i++) CHECK_EQ_I64(results[i], (i64)i * i);
    dk_pool_shutdown(p, false);
}

/* ---- the process fan-out ---- */

typedef struct {
    DkAtomic32 calls;
    DkMutex mu;
    unsigned seen_mask;
} FanCtx;

static void fan_done(void *ctx, size_t index, DkProcResult *r) {
    FanCtx *f = ctx;
    dk_atomic_add32(&f->calls, 1);
    dk_mutex_lock(&f->mu);
    if (r->status == DK_PROC_OK) f->seen_mask |= 1u << index;
    dk_mutex_unlock(&f->mu);
}

static void remove_markers(const char *prefix) {
    char pat[1100], dir[1100], path[1400];
    snprintf(pat, sizeof pat, "%s*", prefix);
    snprintf(dir, sizeof dir, "%s", prefix);
    char *slash = strrchr(dir, '\\');
    if (slash) slash[1] = 0;
    WIN32_FIND_DATAA fd;
    HANDLE f = FindFirstFileA(pat, &fd);
    if (f == INVALID_HANDLE_VALUE) return;
    do {
        snprintf(path, sizeof path, "%s%s", slash ? dir : "", fd.cFileName);
        DeleteFileA(path);
    } while (FindNextFileA(f, &fd));
    FindClose(f);
}

DK_TEST(process_fan_out_runs_at_most_j_at_once) {
    enum { N = 12, J = 4 };
    const char *argvs[N][7];
    char prefix[600], jstr[16];
    snprintf(prefix, sizeof prefix, "%s\\dk_pool_test_%lu_", getenv("TEMP") ? getenv("TEMP") : ".", (unsigned long)GetCurrentProcessId());
    snprintf(jstr, sizeof jstr, "%d", J);
    DkProcSpec specs[N];
    DkProcResult results[N];
    memset(specs, 0, sizeof specs);
    for (int i = 0; i < N; i++) {
        argvs[i][0] = self_exe();
        argvs[i][1] = "--child";
        argvs[i][2] = "span";
        argvs[i][3] = "250";
        argvs[i][4] = prefix; /* the children meet here: the first J wait for each other */
        argvs[i][5] = jstr;
        argvs[i][6] = NULL;
        specs[i].argv = argvs[i];
        specs[i].out = DK_IO_CAPTURE;
        specs[i].text = true;
    }
    FanCtx f;
    memset(&f, 0, sizeof f);
    remove_markers(prefix);
    double t0 = dk_monotonic();
    size_t ok = dk_procpool_run(J, specs, N, fan_done, &f, results);
    double dt = dk_monotonic() - t0;
    CHECK_EQ_U64(ok, N);
    CHECK_EQ_I64(dk_atomic_load32(&f.calls), N);
    CHECK_EQ_U64(f.seen_mask, (1u << N) - 1);
    /* the children's own clocks: no more than J spans overlap, and J do */
    i64 start[N], end[N];
    for (int i = 0; i < N; i++) {
        REQUIRE(results[i].status == DK_PROC_OK);
        CHECK(sscanf(results[i].out.p, "%lld %lld", &start[i], &end[i]) == 2);
    }
    int max_overlap = 0;
    for (int i = 0; i < N; i++) {
        int n = 0;
        for (int k = 0; k < N; k++)
            if (start[k] <= start[i] && end[k] > start[i]) n++;
        if (n > max_overlap) max_overlap = n;
    }
    CHECK_MSG(max_overlap <= J, "%d processes ran at once, the limit is %d", max_overlap, J);
    CHECK_MSG(max_overlap == J, "only %d processes ran at once", max_overlap);
    CHECK_MSG(dt >= 0.7, "12 jobs of 250 ms by 4 took %.2f s", dt); /* three waves at least: a lower bound only */
    remove_markers(prefix);
    /* a program that does not start is not counted */
    const char *bad[] = {"no_such_program_for_dk_tests", NULL};
    const char *solo[] = {self_exe(), "--child", "span", "10", NULL};
    DkProcSpec sb[2] = {specs[0], {0}};
    sb[0].argv = solo;
    sb[1].argv = bad;
    DkProcResult rb[2];
    FanCtx g;
    memset(&g, 0, sizeof g);
    CHECK_EQ_U64(dk_procpool_run(2, sb, 2, fan_done, &g, rb), 1);
    CHECK_EQ_I64(dk_atomic_load32(&g.calls), 2);
    CHECK(rb[1].status == DK_PROC_START_FAILED);
}

static int run_main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--child") == 0) return child_main(argc, argv);
    return dk_test__run(argc, argv);
}
DK_MAIN(run_main, "test_pool")
