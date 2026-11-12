// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Time: what the tools took from Python's `time` and `datetime` modules (CPython 3.14 on Windows).
 *
 * Clocks. time.time() is GetSystemTimePreciseAsFileTime (100 ns, float seconds = integer nanoseconds / 1e9);
 * time.perf_counter() and time.monotonic() are QueryPerformanceCounter (CPython 3.13+ uses it for both; seconds =
 * nanoseconds / 1e9 with the nanoseconds computed as ticks * 1e9 / frequency in exact integer arithmetic);
 * time.sleep() waits on a high-resolution waitable timer and rounds the duration up to 100 ns.
 *
 * Calendar. time.gmtime/localtime give a struct_time (here DkTm: Python's field conventions, tm_wday with Monday as
 * 0 and tm_yday from 1), time.strftime calls the UCRT's wcsftime in the "C" locale as CPython does (so %e, %F, %T,
 * %G, %V, %Ex, %Oy, %z and %Z are the UCRT's, and a directive it rejects (%k, %s, %P, %Q, a lone %) is an error:
 * ValueError("Invalid format string") in Python, `false` here). datetime.now()/now(timezone.utc)/fromtimestamp()/
 * isoformat()/strftime(), date.today()/isoformat()/fromisoformat() and timedelta's str() are reproduced, including
 * the rounding of float timestamps to microseconds (ROUND_HALF_EVEN) and isoformat dropping a zero microsecond.
 *
 * Elapsed times. The tools print durations as "%.0f s", "%.1fs", "%.1f minutes" of `time.time() - t0` or of
 * round(time.time() - t0, 1). The figures are deviation D1 (they differ from run to run) but the shape of the
 * text must be Python's: dk_fmt_fixed gives '%.Nf' exactly as Python (and dk_pyfmt in fmt.h) does for finite
 * values, dk_clock_round is round(x, ndigits) (correctly rounded, half-even on the exact binary value).
 *
 * Timezone: this machine's rules come from Windows (the UCRT reads them), like Python's. */
#pragma once
#include "arena.h"
#include "str.h"

/* ---- time.time / perf_counter / monotonic / process_time / sleep ---- */
double dk_time(void);          /* time.time() */
i64 dk_time_ns(void);          /* time.time_ns() */
double dk_perf_counter(void);  /* time.perf_counter() */
i64 dk_perf_counter_ns(void);
double dk_monotonic(void);     /* time.monotonic() */
i64 dk_monotonic_ns(void);
double dk_process_time(void);  /* time.process_time(): kernel + user time of this process */
/* time.sleep(seconds): seconds <= 0 returns at once (Python raises ValueError for a negative one). */
void dk_sleep(double seconds);

/* ---- struct_time ---- */
typedef struct {
    int year;  /* 1..9999 */
    int mon;   /* 1..12 */
    int mday;  /* 1..31 */
    int hour;  /* 0..23 */
    int min;   /* 0..59 */
    int sec;   /* 0..61 */
    int wday;  /* Monday is 0 */
    int yday;  /* January 1st is 1 */
    int isdst; /* 0, 1 or -1 */
} DkTm;

/* time.gmtime(t) / time.localtime(t): t is floored to whole seconds (ROUND_FLOOR). False when Windows cannot
 * convert the value (Python raises OSError / OverflowError). time.localtime() with no argument is the _now form. */
bool dk_gmtime(double t, DkTm *out);
bool dk_localtime(double t, DkTm *out);
void dk_localtime_now(DkTm *out);
void dk_gmtime_now(DkTm *out);
/* time.mktime(tm): seconds since the epoch of a local time (isdst < 0: let Windows decide). False when out of range. */
bool dk_mktime(const DkTm *tm, double *out);

/* time.strftime(fmt, tm): fmt is UTF-8; the result (UTF-8, NUL-terminated) is allocated from `a`. False on a
 * directive the UCRT rejects (Python's ValueError("Invalid format string")); *out is then empty. Python's other
 * checks of the tuple (field ranges, %y before 1900) are not repeated: DkTm comes from this header's functions. */
bool dk_strftime(DkArena *a, const char *fmt, const DkTm *tm, DkStr *out);
/* time.strftime(fmt): the local time now. */
bool dk_strftime_now(DkArena *a, const char *fmt, DkStr *out);

/* ---- datetime.date ---- */
typedef struct {
    int year, month, day;
} DkDate;
DkDate dk_date_today(void);                           /* date.today() */
bool dk_date_valid(int year, int month, int day);       /* 1 <= year <= 9999, real calendar day */
i64 dk_date_toordinal(DkDate d);                       /* date.toordinal(): 0001-01-01 is 1 */
DkDate dk_date_fromordinal(i64 ordinal);               /* ordinal in 1..3652059 */
int dk_date_weekday(DkDate d);                         /* Monday is 0 */
/* date.isoformat(): "YYYY-MM-DD" into out (11 bytes with the NUL). */
void dk_date_isoformat(DkDate d, char out[16]);
/* date.fromisoformat(s): "YYYY-MM-DD", "YYYYMMDD", "YYYY-Www-D", "YYYY-Www", "YYYYWwwD", "YYYYWww" (3.11+). False
 * where Python raises ValueError. */
bool dk_date_fromisoformat(DkStr s, DkDate *out);
/* (a - b).days */
i64 dk_date_diff_days(DkDate a, DkDate b);

/* ---- datetime.datetime ---- */
typedef struct {
    int year, month, day, hour, minute, second, microsecond;
    bool aware;       /* false: a naive datetime; true: tzinfo is a fixed offset */
    i32 utcoffset_s;  /* the offset in seconds when aware (0 for timezone.utc) */
} DkDateTime;
DkDateTime dk_datetime_now(void);      /* datetime.now(): naive, local time */
DkDateTime dk_datetime_now_utc(void);  /* datetime.now(timezone.utc) */
DkDateTime dk_datetime_utcnow(void);   /* datetime.utcnow(): naive, UTC */
/* datetime.fromtimestamp(ts): naive local time; the float is split and rounded to microseconds as CPython does
 * (ROUND_HALF_EVEN). With utc, datetime.fromtimestamp(ts, timezone.utc) (aware). False when Windows cannot convert. */
bool dk_datetime_fromtimestamp(double ts, bool utc, DkDateTime *out);
/* dt.isoformat(sep='T', timespec='auto'): "YYYY-MM-DDTHH:MM:SS[.ffffff][+HH:MM[:SS]]" into out (at most 40 bytes
 * with the NUL). The fraction is left out when the microsecond is 0. */
void dk_datetime_isoformat(const DkDateTime *dt, char sep, char out[48]);
/* dt.strftime(fmt): %f (6-digit microsecond), %z (+HHMM[SS]) and %Z ("UTC" for an aware offset 0, "UTC+HH:MM"
 * otherwise, "" when naive) are expanded as datetime does, the rest goes to dk_strftime. */
bool dk_datetime_strftime(DkArena *a, const DkDateTime *dt, const char *fmt, DkStr *out);
/* dt.date() and the struct_time of dt.timetuple() (isdst -1 when naive, 0 when aware). */
DkDate dk_datetime_date(const DkDateTime *dt);
DkTm dk_datetime_timetuple(const DkDateTime *dt);

/* ---- datetime.timedelta ---- */
typedef struct {
    i64 days;  /* any sign; seconds and microseconds are normalised to 0 <= s < 86400, 0 <= us < 1e6 */
    i32 seconds;
    i32 microseconds;
} DkTimeDelta;
/* timedelta(seconds=x): rounds to microseconds half-even like Python; false for nan, inf or a value beyond +-999999999 days. */
bool dk_timedelta_from_seconds(double seconds, DkTimeDelta *out);
double dk_timedelta_total_seconds(DkTimeDelta td);
/* str(td): "1 day, 2:03:04.000005", "0:00:01", "-1 day, 23:59:59", "2 days, 0:00:00". out holds up to 48 bytes. */
void dk_timedelta_str(DkTimeDelta td, char out[64]);

/* ---- elapsed times ---- */
typedef struct {
    double t0; /* time.time() at the start */
} DkStopwatch;
DkStopwatch dk_stopwatch_start(void);
double dk_stopwatch_secs(const DkStopwatch *w); /* time.time() - t0 (the same double subtraction) */
/* Python round(x, ndigits) on a float (ndigits may be negative): the nearest double to the correctly rounded
 * decimal, ties to even on the exact value. nan/inf come back unchanged. */
double dk_clock_round(double x, int ndigits);
/* '%.{decimals}f' % x for a finite x (and "inf", "-inf", "nan" as Python prints them): out gets the text and its
 * length is returned. cap must hold the longest result (400 bytes for any double). */
size_t dk_fmt_fixed(char *out, size_t cap, double x, int decimals);
