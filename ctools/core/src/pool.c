// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Threads, synchronisation primitives and job pools (pool.h). */
#include "dk/pool.h"
#include "dk/arena.h"
#include "dk/clock.h"

#include <math.h>
#include <process.h>
#include <stdlib.h>
#include <windows.h>

/* ---- cpu count ---- */

int dk_cpu_count(void) {
    /* CPython: PYTHON_CPU_COUNT (a number >= 1) overrides, else GetActiveProcessorCount(ALL_PROCESSOR_GROUPS). */
    static DkAtomic32 cached; /* 0: not computed */
    i32 c = dk_atomic_load32(&cached);
    if (c) return c;
    int n = 0;
    const char *env = getenv("PYTHON_CPU_COUNT");
    if (env && *env) {
        char *end;
        long v = strtol(env, &end, 10);
        if (*end == '\0' && v >= 1 && v < 1000000) n = (int)v;
    }
    if (n == 0) n = (int)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (n < 1) n = 1;
    dk_atomic_store32(&cached, n);
    return n;
}

int dk_process_cpu_count(void) { return dk_cpu_count(); }

/* ---- atomics ---- */

i64 dk_atomic_max64(DkAtomic64 *a, i64 x) {
    for (;;) {
        i64 cur = dk_atomic_load64(a);
        if (cur >= x) return cur;
        if (dk_atomic_cas64(a, cur, x)) return x;
    }
}

/* ---- mutex, condition variable, once, event, semaphore ---- */

static DWORD timeout_ms(double timeout) {
    if (timeout < 0) return INFINITE;
    double ms = ceil(timeout * 1000.0);
    return ms >= (double)(INFINITE - 1) ? INFINITE - 1 : (DWORD)ms;
}

void dk_mutex_lock(DkMutex *m) { AcquireSRWLockExclusive((PSRWLOCK)m); }
bool dk_mutex_trylock(DkMutex *m) { return TryAcquireSRWLockExclusive((PSRWLOCK)m) != 0; }
void dk_mutex_unlock(DkMutex *m) { ReleaseSRWLockExclusive((PSRWLOCK)m); }
void dk_mutex_lock_shared(DkMutex *m) { AcquireSRWLockShared((PSRWLOCK)m); }
bool dk_mutex_trylock_shared(DkMutex *m) { return TryAcquireSRWLockShared((PSRWLOCK)m) != 0; }
void dk_mutex_unlock_shared(DkMutex *m) { ReleaseSRWLockShared((PSRWLOCK)m); }

void dk_rmutex_init(DkRMutex *m) {
    DK_ASSERT(sizeof(DkRMutex) >= sizeof(CRITICAL_SECTION));
    InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)m, 2000);
}
void dk_rmutex_destroy(DkRMutex *m) { DeleteCriticalSection((LPCRITICAL_SECTION)m); }
void dk_rmutex_lock(DkRMutex *m) { EnterCriticalSection((LPCRITICAL_SECTION)m); }
bool dk_rmutex_trylock(DkRMutex *m) { return TryEnterCriticalSection((LPCRITICAL_SECTION)m) != 0; }
void dk_rmutex_unlock(DkRMutex *m) { LeaveCriticalSection((LPCRITICAL_SECTION)m); }

bool dk_cond_wait(DkCond *c, DkMutex *m, double timeout) {
    return SleepConditionVariableSRW((PCONDITION_VARIABLE)c, (PSRWLOCK)m, timeout_ms(timeout), 0) != 0;
}
void dk_cond_signal(DkCond *c) { WakeConditionVariable((PCONDITION_VARIABLE)c); }
void dk_cond_broadcast(DkCond *c) { WakeAllConditionVariable((PCONDITION_VARIABLE)c); }

typedef struct {
    void (*fn)(void *);
    void *ctx;
} OnceCall;
static BOOL CALLBACK once_trampoline(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    DK_UNUSED(once);
    DK_UNUSED(ctx);
    OnceCall *c = param;
    c->fn(c->ctx);
    return TRUE;
}
void dk_once(DkOnce *o, void (*fn)(void *ctx), void *ctx) {
    OnceCall c = {fn, ctx};
    InitOnceExecuteOnce((PINIT_ONCE)o, once_trampoline, &c, NULL);
}

void dk_event_init(DkEvent *e) {
    e->h = CreateEventW(NULL, TRUE, FALSE, NULL);
    DK_ASSERT(e->h != NULL);
}
void dk_event_destroy(DkEvent *e) {
    if (e->h) CloseHandle(e->h);
    e->h = NULL;
}
void dk_event_set(DkEvent *e) { SetEvent(e->h); }
void dk_event_clear(DkEvent *e) { ResetEvent(e->h); }
bool dk_event_is_set(DkEvent *e) { return WaitForSingleObject(e->h, 0) == WAIT_OBJECT_0; }
bool dk_event_wait(DkEvent *e, double timeout) {
    return WaitForSingleObject(e->h, timeout_ms(timeout)) == WAIT_OBJECT_0;
}

void dk_sem_init(DkSem *s, int value) {
    s->h = CreateSemaphoreW(NULL, value, 0x7fffffff, NULL);
    DK_ASSERT(s->h != NULL);
}
void dk_sem_destroy(DkSem *s) {
    if (s->h) CloseHandle(s->h);
    s->h = NULL;
}
bool dk_sem_acquire(DkSem *s, double timeout) {
    return WaitForSingleObject(s->h, timeout_ms(timeout)) == WAIT_OBJECT_0;
}
void dk_sem_release(DkSem *s) { ReleaseSemaphore(s->h, 1, NULL); }

/* ---- threads ---- */

struct DkThread {
    HANDLE h;
    void (*fn)(void *);
    void *arg;
};

static unsigned __stdcall thread_entry(void *p) {
    DkThread *t = p;
    t->fn(t->arg);
    return 0;
}

DkThread *dk_thread_start(void (*fn)(void *arg), void *arg, size_t stack_bytes) {
    DkThread *t = dk_xcalloc(1, sizeof *t);
    t->fn = fn;
    t->arg = arg;
    t->h = (HANDLE)_beginthreadex(NULL, (unsigned)stack_bytes, thread_entry, t, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (!t->h) dk_fatal("cannot start a thread (error %lu)", (unsigned long)GetLastError());
    return t;
}

void dk_thread_join(DkThread *t) {
    WaitForSingleObject(t->h, INFINITE);
    CloseHandle(t->h);
    dk_xfree(t);
}

void dk_thread_detach(DkThread *t) {
    /* The entry point reads fn and arg before it can be freed: wait for nothing, the struct is leaked (24 bytes). */
    CloseHandle(t->h);
}

u32 dk_thread_id(void) { return GetCurrentThreadId(); }

/* ---- the pool ---- */

typedef struct Task Task;
typedef struct MapJob MapJob;

struct Task {
    Task *next, *prev;
    void (*run)(Task *self);
    MapJob *map; /* a helper of a map: counted in map->running while it executes */
    DkFuture *future;
};

struct MapJob {
    enum { JOB_MAP, JOB_FOR, JOB_RANGE } kind;
    DkMapFn mapfn;
    DkForFn forfn;
    DkRangeFn rangefn;
    void *ctx;
    const u8 *items;
    u8 *results;
    size_t count, item_size, result_size, grain;
    DkAtomic64 next;
    DkAtomic64 fail; /* lowest failing index + 1, 0 when none */
    int running;      /* helpers executing (under pool->mu) */
    DkPool *pool;
};

struct DkPool {
    DkMutex mu;
    DkCond work_cv; /* workers wait here */
    DkCond done_cv; /* futures, maps and shutdown wait here */
    Task *head, *tail;
    size_t queued;
    int idle;
    int fresh; /* started, not yet in the queue loop */
    int max_threads;
    int nstarted;
    bool shutdown;
    DkPoolOpts opts;
    DkThread **threads;
    size_t threads_cap;
};

static DK_THREAD_LOCAL int t_worker_index = -1;

int dk_pool_worker_index(void) { return t_worker_index; }

struct DkFuture {
    DkAtomic32 state; /* 0 pending, 1 running, 2 done, 3 cancelled */
    DkPool *pool;
    int (*fn)(void *);
    void *arg;
    int result;
    Task task;
    DkCompletions *done_q;
    DkFuture *next_done;
};

struct DkCompletions {
    DkMutex mu;
    DkCond cv;
    DkFuture *head, *tail;
};

static void queue_push(DkPool *p, Task *t) {
    t->next = NULL;
    t->prev = p->tail;
    if (p->tail) p->tail->next = t;
    else p->head = t;
    p->tail = t;
    p->queued++;
}

static void queue_unlink(DkPool *p, Task *t) {
    if (t->prev) t->prev->next = t->next;
    else p->head = t->next;
    if (t->next) t->next->prev = t->prev;
    else p->tail = t->prev;
    t->next = t->prev = NULL;
    p->queued--;
}

typedef struct {
    DkPool *pool;
    int index;
} WorkerArg;

static void worker_main(void *arg) {
    WorkerArg wa = *(WorkerArg *)arg;
    dk_xfree(arg);
    DkPool *p = wa.pool;
    t_worker_index = wa.index;
    if (p->opts.thread_init) p->opts.thread_init(wa.index, p->opts.ctx);
    dk_mutex_lock(&p->mu);
    p->fresh--;
    for (;;) {
        while (!p->head && !p->shutdown) {
            p->idle++;
            dk_cond_wait(&p->work_cv, &p->mu, -1);
            p->idle--;
        }
        if (!p->head) break; /* shutdown and nothing left */
        Task *t = p->head;
        queue_unlink(p, t);
        if (t->map) t->map->running++;
        dk_mutex_unlock(&p->mu);
        t->run(t);
        dk_mutex_lock(&p->mu);
    }
    dk_mutex_unlock(&p->mu);
}

/* Starts workers while queued tasks outnumber the workers that are idle or just started and have not yet looked at
 * the queue, and there is room for more threads. Holds p->mu. */
static void spawn_locked(DkPool *p) {
    while (p->nstarted < p->max_threads && (int)p->queued > p->idle + p->fresh) {
        if ((size_t)p->nstarted == p->threads_cap) {
            p->threads_cap = p->threads_cap ? p->threads_cap * 2 : 16;
            p->threads = dk_xrealloc(p->threads, p->threads_cap * sizeof *p->threads);
        }
        WorkerArg *wa = dk_xmalloc(sizeof *wa);
        wa->pool = p;
        wa->index = p->nstarted;
        p->fresh++;
        p->threads[p->nstarted++] = dk_thread_start(worker_main, wa, p->opts.stack_bytes);
    }
}

DkPool *dk_pool_new_ex(const DkPoolOpts *opts) {
    DkPool *p = dk_xcalloc(1, sizeof *p);
    p->opts = *opts;
    p->max_threads = opts->threads > 0 ? opts->threads : dk_cpu_count();
    return p;
}

DkPool *dk_pool_new(int threads) {
    DkPoolOpts o = {0};
    o.threads = threads;
    return dk_pool_new_ex(&o);
}

void dk_pool_shutdown(DkPool *p, bool cancel_pending) {
    dk_mutex_lock(&p->mu);
    p->shutdown = true;
    if (cancel_pending) {
        while (p->head) {
            Task *t = p->head;
            queue_unlink(p, t);
            if (t->future) dk_atomic_store32(&t->future->state, 3);
        }
    }
    dk_cond_broadcast(&p->work_cv);
    dk_cond_broadcast(&p->done_cv);
    int n = p->nstarted;
    dk_mutex_unlock(&p->mu);
    for (int i = 0; i < n; i++) dk_thread_join(p->threads[i]);
    dk_xfree(p->threads);
    dk_xfree(p);
}

/* The process-wide pool used when a map is given no pool of its own. */
static DkPool *g_default;
static DkOnce g_default_once;
static void make_default(void *ctx) {
    DK_UNUSED(ctx);
    g_default = dk_pool_new(dk_cpu_count());
}
static DkPool *default_pool(int need_threads) {
    dk_once(&g_default_once, make_default, NULL);
    dk_mutex_lock(&g_default->mu);
    if (g_default->max_threads < need_threads) g_default->max_threads = need_threads;
    dk_mutex_unlock(&g_default->mu);
    return g_default;
}

/* ---- map and parallel-for ---- */

static void job_fail(MapJob *j, size_t index) {
    for (;;) {
        i64 cur = dk_atomic_load64(&j->fail);
        if (cur != 0 && cur <= (i64)index + 1) return;
        if (dk_atomic_cas64(&j->fail, cur, (i64)index + 1)) return;
    }
}

static void job_run(MapJob *j) {
    for (;;) {
        if (dk_atomic_load64(&j->fail) != 0) return; /* an item failed: later ones are cancelled */
        size_t step = j->kind == JOB_RANGE ? j->grain : 1;
        size_t i = (size_t)dk_atomic_add64(&j->next, (i64)step) - step;
        if (i >= j->count) return;
        if (j->kind == JOB_RANGE) {
            size_t end = i + step < j->count ? i + step : j->count;
            j->rangefn(j->ctx, i, end);
        } else if (j->kind == JOB_FOR) {
            if (j->forfn(j->ctx, i) != 0) job_fail(j, i);
        } else {
            const void *item = j->items ? j->items + i * j->item_size : NULL;
            void *res = j->results ? j->results + i * j->result_size : NULL;
            if (j->mapfn(j->ctx, i, item, res) != 0) job_fail(j, i);
        }
    }
}

static void helper_run(Task *t) {
    MapJob *j = t->map;
    DkPool *p = j->pool;
    job_run(j);
    dk_mutex_lock(&p->mu);
    j->running--;
    dk_cond_broadcast(&p->done_cv);
    dk_mutex_unlock(&p->mu);
}

static i64 run_job(DkPool *pool, int nthreads, MapJob *j) {
    if (nthreads <= 0) nthreads = pool ? pool->max_threads : dk_cpu_count();
    if (pool && nthreads > pool->max_threads) nthreads = pool->max_threads; /* max_workers is a limit */
    j->next.v = 0;
    j->fail.v = 0;
    size_t units = j->kind == JOB_RANGE ? (j->count + j->grain - 1) / j->grain : j->count;
    size_t helpers = nthreads > 1 && units > 1 ? (size_t)(nthreads - 1) : 0;
    if (helpers > units - 1) helpers = units - 1;
    if (helpers == 0) {
        job_run(j);
        return j->kind == JOB_RANGE ? -1 : (i64)dk_atomic_load64(&j->fail) - 1;
    }
    if (!pool) pool = default_pool(nthreads - 1);
    j->pool = pool;
    j->running = 0;
    Task *tasks = dk_xcalloc(helpers, sizeof *tasks);
    dk_mutex_lock(&pool->mu);
    for (size_t k = 0; k < helpers; k++) {
        tasks[k].run = helper_run;
        tasks[k].map = j;
        queue_push(pool, &tasks[k]);
    }
    spawn_locked(pool);
    dk_cond_broadcast(&pool->work_cv);
    dk_mutex_unlock(&pool->mu);
    job_run(j); /* the calling thread works too */
    /* Helpers that never started are of no use now: take them back, then wait for the ones executing. */
    dk_mutex_lock(&pool->mu);
    for (size_t k = 0; k < helpers; k++) {
        Task *t = &tasks[k];
        if (t->next || t->prev || pool->head == t) queue_unlink(pool, t);
    }
    while (j->running > 0) dk_cond_wait(&pool->done_cv, &pool->mu, -1);
    dk_mutex_unlock(&pool->mu);
    dk_xfree(tasks);
    return j->kind == JOB_RANGE ? -1 : (i64)dk_atomic_load64(&j->fail) - 1;
}

i64 dk_pool_map(DkPool *pool, int nthreads, DkMapFn fn, void *ctx, const void *items, size_t count,
                 size_t item_size, void *results, size_t result_size) {
    if (count == 0) return -1;
    MapJob j = {0};
    j.kind = JOB_MAP;
    j.mapfn = fn;
    j.ctx = ctx;
    j.items = items;
    j.results = results;
    j.count = count;
    j.item_size = item_size;
    j.result_size = result_size;
    return run_job(pool, nthreads, &j);
}

i64 dk_pool_for(DkPool *pool, int nthreads, DkForFn fn, void *ctx, size_t count) {
    if (count == 0) return -1;
    MapJob j = {0};
    j.kind = JOB_FOR;
    j.forfn = fn;
    j.ctx = ctx;
    j.count = count;
    return run_job(pool, nthreads, &j);
}

void dk_pool_for_range(DkPool *pool, int nthreads, DkRangeFn fn, void *ctx, size_t count, size_t grain) {
    if (count == 0) return;
    MapJob j = {0};
    j.kind = JOB_RANGE;
    j.rangefn = fn;
    j.ctx = ctx;
    j.count = count;
    j.grain = grain ? grain : 1;
    run_job(pool, nthreads, &j);
}

/* ---- futures ---- */

static void future_run(Task *t) {
    DkFuture *f = t->future;
    DkPool *p = f->pool;
    if (!dk_atomic_cas32(&f->state, 0, 1)) return; /* cancelled while queued */
    f->result = f->fn(f->arg);
    DkCompletions *q = f->done_q;
    if (q) { /* queued before the state flips: the consumer's result() then waits the instant that takes */
        dk_mutex_lock(&q->mu);
        f->next_done = NULL;
        if (q->tail) q->tail->next_done = f;
        else q->head = f;
        q->tail = f;
        dk_cond_signal(&q->cv);
        dk_mutex_unlock(&q->mu);
    }
    dk_mutex_lock(&p->mu);
    dk_atomic_store32(&f->state, 2); /* the last touch of f */
    dk_cond_broadcast(&p->done_cv);
    dk_mutex_unlock(&p->mu);
}

DkFuture *dk_pool_submit_to(DkPool *p, int (*fn)(void *arg), void *arg, DkCompletions *done) {
    DkFuture *f = dk_xcalloc(1, sizeof *f);
    f->pool = p;
    f->fn = fn;
    f->arg = arg;
    f->done_q = done;
    f->task.run = future_run;
    f->task.future = f;
    dk_mutex_lock(&p->mu);
    DK_ASSERT(!p->shutdown);
    queue_push(p, &f->task);
    spawn_locked(p);
    dk_cond_signal(&p->work_cv);
    dk_mutex_unlock(&p->mu);
    return f;
}

DkFuture *dk_pool_submit(DkPool *p, int (*fn)(void *arg), void *arg) {
    return dk_pool_submit_to(p, fn, arg, NULL);
}

bool dk_future_done(DkFuture *f) { return dk_atomic_load32(&f->state) >= 2; }
bool dk_future_cancelled(DkFuture *f) { return dk_atomic_load32(&f->state) == 3; }

bool dk_future_result(DkFuture *f, double timeout, int *result) {
    DkPool *p = f->pool;
    if (dk_atomic_load32(&f->state) < 2) {
        dk_mutex_lock(&p->mu);
        double t0 = timeout >= 0 ? dk_monotonic() : 0;
        while (dk_atomic_load32(&f->state) < 2) {
            double left = -1;
            if (timeout >= 0) {
                double used = dk_monotonic() - t0;
                left = timeout - used;
                if (left <= 0) break;
            }
            dk_cond_wait(&p->done_cv, &p->mu, left);
        }
        dk_mutex_unlock(&p->mu);
    }
    i32 st = dk_atomic_load32(&f->state);
    if (st == 2) {
        if (result) *result = f->result;
        return true;
    }
    return false;
}

bool dk_future_cancel(DkFuture *f) {
    /* A future that is running, done or cancelled is final here: its pool is not touched (it may be shut down and
       freed already: a future may outlive its pool once it has finished, as after dk_pool_shutdown). */
    if (dk_atomic_load32(&f->state) != 0) return false;
    DkPool *p = f->pool;
    dk_mutex_lock(&p->mu);
    bool ok = false;
    if (dk_atomic_cas32(&f->state, 0, 3)) {
        if (f->task.next || f->task.prev || p->head == &f->task) queue_unlink(p, &f->task);
        dk_cond_broadcast(&p->done_cv);
        ok = true;
    }
    dk_mutex_unlock(&p->mu);
    return ok;
}

void dk_future_free(DkFuture *f) {
    /* A running task still holds the struct, so a free waits for it (a task still queued is cancelled first). */
    dk_future_cancel(f);
    dk_future_result(f, -1, NULL);
    dk_xfree(f);
}

DkCompletions *dk_completions_new(void) { return dk_xcalloc(1, sizeof(DkCompletions)); }

DkFuture *dk_completions_next(DkCompletions *c, double timeout) {
    dk_mutex_lock(&c->mu);
    double t0 = dk_monotonic();
    while (!c->head) {
        double left = -1;
        if (timeout >= 0) {
            left = timeout - (dk_monotonic() - t0);
            if (left <= 0) {
                dk_mutex_unlock(&c->mu);
                return NULL;
            }
        }
        dk_cond_wait(&c->cv, &c->mu, left);
    }
    DkFuture *f = c->head;
    c->head = f->next_done;
    if (!c->head) c->tail = NULL;
    dk_mutex_unlock(&c->mu);
    /* The worker queues f before it flips the state to done (the flip is its last touch of f), so wait for that
     * instant here: like as_completed, every future handed out is done and result(f, 0) succeeds. */
    dk_future_result(f, -1, NULL);
    return f;
}

void dk_completions_free(DkCompletions *c) { dk_xfree(c); }

/* ---- the compiler fan-out ---- */

typedef struct {
    const DkProcSpec *specs;
    DkProcDoneFn done;
    void *ctx;
    DkProcResult *results;
    DkAtomic64 started_ok;
} ProcFan;

static int procfan_one(void *ctx, size_t index) {
    ProcFan *f = ctx;
    DkProcResult r = dk_run(&f->specs[index]);
    if (r.status != DK_PROC_START_FAILED) dk_atomic_add64(&f->started_ok, 1);
    if (f->results) f->results[index] = r;
    if (f->done) f->done(f->ctx, index, &r);
    return 0;
}

size_t dk_procpool_run(int max_parallel, const DkProcSpec *specs, size_t n, DkProcDoneFn done, void *ctx,
                        DkProcResult *results) {
    ProcFan f = {specs, done, ctx, results, {0}};
    dk_pool_for(NULL, max_parallel, procfan_one, &f, n);
    return (size_t)dk_atomic_load64(&f.started_ok);
}
