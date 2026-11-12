// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Threads and job pools: what the tools took from `concurrent.futures` (ThreadPoolExecutor and its map/submit/
 * as_completed, ProcessPoolExecutor and multiprocessing.Pool, whose work is CPU-bound and runs here on threads),
 * `threading` (Thread, Lock, RLock, Event, Semaphore), `os.cpu_count` and the -j fan-out of the compilers.
 *
 * Pool. Workers are threads started on demand (like ThreadPoolExecutor: one more thread per submit while fewer
 * than max_workers exist) and kept for the life of the pool; work is claimed from a queue, or, for map and
 * parallel-for, by an atomic index, so there is no per-item allocation and results land in input order. The
 * calling thread takes part in a map (so a map inside a task cannot starve the pool) and the number of tasks
 * running at once never exceeds the `nthreads` asked for. A task function returns an int (0 = success): that is
 * the replacement for an exception; the first failure in index order is reported as ThreadPoolExecutor.map raises
 * the first exception in order, and items that had not started when a failure was seen are skipped (cancelled).
 *
 * Primitives. DkMutex is an SRW lock (non-recursive, exclusive or shared), DkRMutex a CRITICAL_SECTION
 * (threading.RLock), DkCond a CONDITION_VARIABLE, DkOnce an INIT_ONCE, DkEvent threading.Event, DkSem
 * threading.Semaphore; DkAtomic32/64 are sequentially consistent Interlocked operations. A zeroed DkMutex,
 * DkCond and DkOnce is ready to use (static storage needs no init call). Timeouts are seconds as doubles;
 * negative means no limit, 0 only checks. */
#pragma once
#include "base.h"
#include "proc.h"

#include <intrin.h>

/* ---- cpu count ---- */
/* os.cpu_count(): the logical processors of all processor groups (GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)),
 * or PYTHON_CPU_COUNT from the environment when it is a number >= 1; never 0. */
int dk_cpu_count(void);
/* os.process_cpu_count(): on Windows the same value (CPython only subtracts an affinity mask on Linux). */
int dk_process_cpu_count(void);

/* ---- atomics ---- */
typedef struct { volatile long v; } DkAtomic32;
typedef struct { volatile __int64 v; } DkAtomic64;
static inline i32 dk_atomic_load32(DkAtomic32 *a) { return (i32)_InterlockedOr(&a->v, 0); }
static inline void dk_atomic_store32(DkAtomic32 *a, i32 x) { (void)_InterlockedExchange(&a->v, x); }
static inline i32 dk_atomic_add32(DkAtomic32 *a, i32 d) { return (i32)_InterlockedExchangeAdd(&a->v, d) + d; } /* the new value */
static inline i32 dk_atomic_xchg32(DkAtomic32 *a, i32 x) { return (i32)_InterlockedExchange(&a->v, x); }       /* the old value */
static inline bool dk_atomic_cas32(DkAtomic32 *a, i32 expect, i32 desire) {
    return _InterlockedCompareExchange(&a->v, desire, expect) == expect;
}
static inline i64 dk_atomic_load64(DkAtomic64 *a) { return (i64)_InterlockedOr64(&a->v, 0); }
static inline void dk_atomic_store64(DkAtomic64 *a, i64 x) { (void)_InterlockedExchange64(&a->v, x); }
static inline i64 dk_atomic_add64(DkAtomic64 *a, i64 d) { return (i64)_InterlockedExchangeAdd64(&a->v, d) + d; }
static inline i64 dk_atomic_xchg64(DkAtomic64 *a, i64 x) { return (i64)_InterlockedExchange64(&a->v, x); }
static inline bool dk_atomic_cas64(DkAtomic64 *a, i64 expect, i64 desire) {
    return _InterlockedCompareExchange64(&a->v, desire, expect) == expect;
}
/* Raises *max to x when x is larger (a high-water mark); returns the maximum now held. */
i64 dk_atomic_max64(DkAtomic64 *a, i64 x);

/* ---- mutex, condition variable, once ---- */
typedef struct { void *p; } DkMutex; /* SRWLOCK */
void dk_mutex_lock(DkMutex *m);
bool dk_mutex_trylock(DkMutex *m);
void dk_mutex_unlock(DkMutex *m);
void dk_mutex_lock_shared(DkMutex *m); /* reader side of the same lock */
bool dk_mutex_trylock_shared(DkMutex *m);
void dk_mutex_unlock_shared(DkMutex *m);

typedef struct { void *p[5]; } DkRMutex; /* CRITICAL_SECTION (40 bytes on x64) */
void dk_rmutex_init(DkRMutex *m);
void dk_rmutex_destroy(DkRMutex *m);
void dk_rmutex_lock(DkRMutex *m);
bool dk_rmutex_trylock(DkRMutex *m);
void dk_rmutex_unlock(DkRMutex *m);

typedef struct { void *p; } DkCond; /* CONDITION_VARIABLE */
/* Releases m (held exclusively), waits for a signal or the timeout, takes m again. False on timeout. Spurious
 * wake-ups happen: wait in a loop on the condition. */
bool dk_cond_wait(DkCond *c, DkMutex *m, double timeout);
void dk_cond_signal(DkCond *c);
void dk_cond_broadcast(DkCond *c);

typedef struct { void *p; } DkOnce; /* INIT_ONCE */
/* Runs fn(ctx) once per DkOnce, whichever thread gets there first; the others wait for it. */
void dk_once(DkOnce *o, void (*fn)(void *ctx), void *ctx);

typedef struct { void *h; } DkEvent; /* threading.Event: a manual-reset event */
void dk_event_init(DkEvent *e);
void dk_event_destroy(DkEvent *e);
void dk_event_set(DkEvent *e);
void dk_event_clear(DkEvent *e);
bool dk_event_is_set(DkEvent *e);
bool dk_event_wait(DkEvent *e, double timeout); /* Event.wait(timeout): true when set */

typedef struct { void *h; } DkSem; /* threading.Semaphore */
void dk_sem_init(DkSem *s, int value);
void dk_sem_destroy(DkSem *s);
bool dk_sem_acquire(DkSem *s, double timeout);
void dk_sem_release(DkSem *s);

/* ---- threads ---- */
typedef struct DkThread DkThread;
/* threading.Thread(target=fn, args=(arg,)).start(); stack_bytes 0: the default (threading.stack_size()). */
DkThread *dk_thread_start(void (*fn)(void *arg), void *arg, size_t stack_bytes);
void dk_thread_join(DkThread *t); /* Thread.join(); frees the handle */
void dk_thread_detach(DkThread *t); /* a daemon thread: no join, ends with the process */
u32 dk_thread_id(void);              /* threading.get_ident() */

/* ---- pools ---- */
typedef struct DkPool DkPool;
typedef struct {
    int threads;         /* max_workers (<= 0: dk_cpu_count()) */
    size_t stack_bytes;  /* per worker thread; 0: default */
    /* ProcessPoolExecutor(initializer=...): runs on each worker thread before its first task, with its index. */
    void (*thread_init)(int worker_index, void *ctx);
    void *ctx;
} DkPoolOpts;
DkPool *dk_pool_new(int threads);
DkPool *dk_pool_new_ex(const DkPoolOpts *opts);
/* Executor.shutdown(wait=True) and free: tasks still queued are cancelled when cancel_pending, else run first. */
void dk_pool_shutdown(DkPool *p, bool cancel_pending);
/* 0..threads-1 on a pool worker thread, -1 elsewhere, which includes the thread that called a map and works in it
 * (per-thread state such as a capstone handle: keep it in DK_THREAD_LOCAL storage, or index with this and treat -1
 * as one more slot). */
int dk_pool_worker_index(void);

/* Executor.map(fn, items): runs fn for every index, results in place. */
typedef int (*DkMapFn)(void *ctx, size_t index, const void *item, void *result);
/* On `pool` (NULL: the process-wide default pool, grown to nthreads). items and results may be NULL (index-only
 * work); item i is items + i * item_size, its result slot results + i * result_size. nthreads <= 0 uses
 * dk_cpu_count(), 1 runs on the calling thread alone. Returns -1 when every item returned 0, else the lowest
 * index whose fn returned non-zero (later unstarted items are skipped and their result slots left as they were). */
i64 dk_pool_map(DkPool *pool, int nthreads, DkMapFn fn, void *ctx, const void *items, size_t count,
                 size_t item_size, void *results, size_t result_size);
/* The same for a plain function of the index. */
typedef int (*DkForFn)(void *ctx, size_t index);
i64 dk_pool_for(DkPool *pool, int nthreads, DkForFn fn, void *ctx, size_t count);
/* Parallel-for over [0, count) in chunks of `grain` indices (CPU-bound loops): fn(ctx, begin, end) per chunk. */
typedef void (*DkRangeFn)(void *ctx, size_t begin, size_t end);
void dk_pool_for_range(DkPool *pool, int nthreads, DkRangeFn fn, void *ctx, size_t count, size_t grain);

/* Executor.submit: the future of one task. */
typedef struct DkFuture DkFuture;
typedef struct DkCompletions DkCompletions;
DkFuture *dk_pool_submit(DkPool *p, int (*fn)(void *arg), void *arg);
/* As submit, and the future is also queued on `done` when it finishes (concurrent.futures.as_completed). */
DkFuture *dk_pool_submit_to(DkPool *p, int (*fn)(void *arg), void *arg, DkCompletions *done);
bool dk_future_done(DkFuture *f);
/* Future.result(timeout): waits; true with *result = fn's return when finished, false on timeout or when the task
 * was cancelled. */
bool dk_future_result(DkFuture *f, double timeout, int *result);
bool dk_future_cancel(DkFuture *f); /* true when it had not started */
bool dk_future_cancelled(DkFuture *f);
/* Waits for a running task, then frees. Allowed after dk_pool_shutdown (every future is then final). */
void dk_future_free(DkFuture *f);

DkCompletions *dk_completions_new(void);
/* The next finished future in completion order, NULL on timeout (the caller counts what it submitted). */
DkFuture *dk_completions_next(DkCompletions *c, double timeout);
void dk_completions_free(DkCompletions *c);

/* ---- the compiler fan-out: up to max_parallel processes at once ---- */
typedef void (*DkProcDoneFn)(void *ctx, size_t index, DkProcResult *r);
/* Runs specs[0..n) with at most max_parallel running at once (<= 0: dk_cpu_count()), each from a pool worker
 * thread that starts it, captures its output and calls done(ctx, index, &result) on that thread when it ends (the
 * callback may run on several threads at once; serialise inside it if needed). Results go to results[index] when
 * results is not NULL (their text lives in the worker thread's arena, valid to the end of the process). Starting
 * order is the index order. Returns the count of processes that started and ended without DK_PROC_START_FAILED. */
size_t dk_procpool_run(int max_parallel, const DkProcSpec *specs, size_t n, DkProcDoneFn done, void *ctx,
                        DkProcResult *results);
