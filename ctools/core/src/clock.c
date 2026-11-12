// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Time: Python's time and datetime modules on Windows (clock.h). */
#include "dk/clock.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

/* ---- clocks ---- */

#define NS_PER_SEC 1000000000LL

/* CPython's _PyTime_AsSecondsDouble. */
static double ns_to_seconds(i64 ns) {
    volatile double d;
    if (ns % NS_PER_SEC == 0) {
        d = (double)(ns / NS_PER_SEC);
    } else {
        d = (double)ns;
        d /= 1e9;
    }
    return d;
}

i64 dk_time_ns(void) {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    u64 t = ((u64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    t -= 116444736000000000ULL; /* 1601-01-01 to 1970-01-01 in 100 ns */
    return (i64)(t * 100);
}

double dk_time(void) { return ns_to_seconds(dk_time_ns()); }

static i64 gcd64(i64 a, i64 b) {
    while (b) {
        i64 t = a % b;
        a = b;
        b = t;
    }
    return a;
}

/* QueryPerformanceCounter in nanoseconds with CPython's exact integer arithmetic (_PyTimeFraction_Mul). */
i64 dk_perf_counter_ns(void) {
    static volatile LONG64 numer, denom; /* published together through denom (written last) */
    if (denom == 0) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        i64 freq = f.QuadPart;
        i64 g = gcd64(NS_PER_SEC, freq);
        numer = NS_PER_SEC / g;
        denom = freq / g;
    }
    i64 n = numer, d = denom;
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    i64 ticks = c.QuadPart;
    i64 intpart = ticks / d;
    i64 rem = ticks % d;
    return intpart * n + rem * n / d;
}

double dk_perf_counter(void) { return ns_to_seconds(dk_perf_counter_ns()); }
i64 dk_monotonic_ns(void) { return dk_perf_counter_ns(); } /* CPython 3.13+: the same counter */
double dk_monotonic(void) { return dk_perf_counter(); }

double dk_process_time(void) {
    FILETIME create, exit_, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &create, &exit_, &kernel, &user)) return 0.0;
    u64 k = ((u64)kernel.dwHighDateTime << 32) | kernel.dwLowDateTime;
    u64 u = ((u64)user.dwHighDateTime << 32) | user.dwLowDateTime;
    return ns_to_seconds((i64)((k + u) * 100));
}

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

void dk_sleep(double seconds) {
    if (!(seconds > 0.0)) return;
    /* the due time in 100 ns units, rounded up (CPython's ROUND_TIMEOUT = ceiling) */
    double units = ceil(seconds * 1e7);
    if (units > 9.0e18) units = 9.0e18;
    static DK_THREAD_LOCAL HANDLE timer;
    static DK_THREAD_LOCAL bool tried;
    if (!tried) {
        tried = true;
        timer = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    }
    if (timer) {
        LARGE_INTEGER due;
        due.QuadPart = -(LONGLONG)units;
        if (SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE)) {
            WaitForSingleObject(timer, INFINITE);
            return;
        }
    }
    double ms = ceil(seconds * 1000.0);
    while (ms > 0) {
        DWORD step = ms > 2.0e9 ? 2000000000u : (DWORD)ms;
        Sleep(step);
        ms -= step;
    }
}

/* ---- struct_time ---- */

static void tm_to_avp(const struct tm *t, DkTm *out) {
    out->year = t->tm_year + 1900;
    out->mon = t->tm_mon + 1;
    out->mday = t->tm_mday;
    out->hour = t->tm_hour;
    out->min = t->tm_min;
    out->sec = t->tm_sec;
    out->wday = (t->tm_wday + 6) % 7;
    out->yday = t->tm_yday + 1;
    out->isdst = t->tm_isdst;
}

static void dk_to_tm(const DkTm *a, struct tm *t) {
    memset(t, 0, sizeof *t);
    t->tm_year = a->year - 1900;
    t->tm_mon = a->mon - 1;
    t->tm_mday = a->mday;
    t->tm_hour = a->hour;
    t->tm_min = a->min;
    t->tm_sec = a->sec;
    t->tm_wday = (a->wday + 1) % 7;
    t->tm_yday = a->yday - 1;
    t->tm_isdst = a->isdst < 0 ? -1 : (a->isdst > 0 ? 1 : 0);
}

static bool seconds_floor(double t, __time64_t *secs) {
    if (!isfinite(t)) return false;
    double f = floor(t);
    if (f < -9.0e15 || f > 9.0e15) return false;
    *secs = (__time64_t)f;
    return true;
}

bool dk_gmtime(double t, DkTm *out) {
    __time64_t s;
    struct tm tmv;
    if (!seconds_floor(t, &s) || _gmtime64_s(&tmv, &s) != 0) return false;
    tm_to_avp(&tmv, out);
    return true;
}

bool dk_localtime(double t, DkTm *out) {
    __time64_t s;
    struct tm tmv;
    if (!seconds_floor(t, &s) || _localtime64_s(&tmv, &s) != 0) return false;
    tm_to_avp(&tmv, out);
    return true;
}

void dk_localtime_now(DkTm *out) {
    __time64_t s = dk_time_ns() / NS_PER_SEC;
    struct tm tmv;
    DK_ASSERT(_localtime64_s(&tmv, &s) == 0);
    tm_to_avp(&tmv, out);
}

void dk_gmtime_now(DkTm *out) {
    __time64_t s = dk_time_ns() / NS_PER_SEC;
    struct tm tmv;
    DK_ASSERT(_gmtime64_s(&tmv, &s) == 0);
    tm_to_avp(&tmv, out);
}

bool dk_mktime(const DkTm *tm, double *out) {
    struct tm t;
    dk_to_tm(tm, &t);
    t.tm_wday = -1;
    __time64_t r = _mktime64(&t);
    if (r == (__time64_t)-1 && t.tm_wday == -1) return false;
    *out = (double)r;
    return true;
}

/* The UCRT calls the invalid-parameter handler for a format it does not know; CPython installs a silent one and
 * reads errno == EINVAL (time.strftime then raises ValueError("Invalid format string")). */
static void silent_invalid_parameter(const wchar_t *expr, const wchar_t *func, const wchar_t *file, unsigned line,
                                     uintptr_t reserved) {
    DK_UNUSED(expr);
    DK_UNUSED(func);
    DK_UNUSED(file);
    DK_UNUSED(line);
    DK_UNUSED(reserved);
}

/* UTF-8 <-> UTF-16 with the OS (strict conversions are not needed: the inputs are our own format strings). */
static wchar_t *utf8_to_w_heap(const char *s, size_t *len) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = dk_xmalloc(sizeof(wchar_t) * (size_t)(n > 0 ? n : 1));
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    else w[0] = 0;
    *len = n > 0 ? (size_t)n - 1 : 0;
    return w;
}

static DkStr w_to_utf8(DkArena *a, const wchar_t *w, size_t n) {
    int bytes = n ? WideCharToMultiByte(CP_UTF8, 0, w, (int)n, NULL, 0, NULL, NULL) : 0;
    char *p = dk_alloc_noz(a, (size_t)bytes + 1);
    if (bytes) WideCharToMultiByte(CP_UTF8, 0, w, (int)n, p, bytes, NULL, NULL);
    p[bytes] = 0;
    return (DkStr){p, (size_t)bytes};
}

bool dk_strftime(DkArena *a, const char *fmt, const DkTm *tm, DkStr *out) {
    struct tm t;
    dk_to_tm(tm, &t);
    size_t fmtlen;
    wchar_t *wfmt = utf8_to_w_heap(fmt, &fmtlen);
    _invalid_parameter_handler old = _set_thread_local_invalid_parameter_handler(silent_invalid_parameter);
    bool ok = false;
    /* CPython's loop: a buffer of 1024 characters, doubled while the result is empty, up to 256 times the format. */
    for (size_t i = 1024;; i += i) {
        wchar_t *buf = dk_xmalloc(i * sizeof(wchar_t));
        errno = 0;
        size_t n = wcsftime(buf, i, wfmt, &t);
        if (n == 0 && errno == EINVAL) {
            dk_xfree(buf);
            break;
        }
        if (n > 0 || i >= 256 * fmtlen) {
            *out = w_to_utf8(a, buf, n);
            dk_xfree(buf);
            ok = true;
            break;
        }
        dk_xfree(buf);
    }
    _set_thread_local_invalid_parameter_handler(old);
    dk_xfree(wfmt);
    if (!ok) *out = (DkStr){"", 0};
    return ok;
}

bool dk_strftime_now(DkArena *a, const char *fmt, DkStr *out) {
    DkTm tm;
    dk_localtime_now(&tm);
    return dk_strftime(a, fmt, &tm, out);
}

/* ---- dates ---- */

static const int days_in_month_tab[13] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
static const int days_before_month_tab[13] = {0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

static bool is_leap(int y) { return y % 4 == 0 && (y % 100 != 0 || y % 400 == 0); }
static int days_in_month(int y, int m) { return m == 2 && is_leap(y) ? 29 : days_in_month_tab[m]; }
static i64 days_before_year(int y) {
    i64 y1 = y - 1;
    return y1 * 365 + y1 / 4 - y1 / 100 + y1 / 400;
}

bool dk_date_valid(int year, int month, int day) {
    return year >= 1 && year <= 9999 && month >= 1 && month <= 12 && day >= 1 && day <= days_in_month(year, month);
}

i64 dk_date_toordinal(DkDate d) {
    int dbm = days_before_month_tab[d.month] + (d.month > 2 && is_leap(d.year) ? 1 : 0);
    return days_before_year(d.year) + dbm + d.day;
}

DkDate dk_date_fromordinal(i64 ordinal) {
    /* CPython's ord_to_ymd. */
    i64 n = ordinal - 1;
    i64 n400 = n / 146097;
    n %= 146097;
    i64 year = n400 * 400 + 1;
    i64 n100 = n / 36524;
    n %= 36524;
    i64 n4 = n / 1461;
    n %= 1461;
    i64 n1 = n / 365;
    n %= 365;
    year += n100 * 100 + n4 * 4 + n1;
    DkDate d;
    if (n1 == 4 || n100 == 4) {
        d.year = (int)(year - 1);
        d.month = 12;
        d.day = 31;
        return d;
    }
    d.year = (int)year;
    int leap = n1 == 3 && (n4 != 24 || n100 == 3);
    int month = ((int)n + 50) >> 5;
    int preceding = days_before_month_tab[month] + (month > 2 && leap ? 1 : 0);
    if (preceding > n) {
        month--;
        preceding -= days_in_month_tab[month] + (month == 2 && leap ? 1 : 0);
    }
    d.month = month;
    d.day = (int)(n - preceding) + 1;
    return d;
}

int dk_date_weekday(DkDate d) { return (int)((dk_date_toordinal(d) + 6) % 7); }

void dk_date_isoformat(DkDate d, char out[16]) { snprintf(out, 16, "%04d-%02d-%02d", d.year, d.month, d.day); }

i64 dk_date_diff_days(DkDate a, DkDate b) { return dk_date_toordinal(a) - dk_date_toordinal(b); }

DkDate dk_date_today(void) {
    DkTm tm;
    dk_localtime_now(&tm);
    return (DkDate){tm.year, tm.mon, tm.mday};
}

static bool digits(const char *p, int n, int *out) {
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return false;
        v = v * 10 + (p[i] - '0');
    }
    *out = v;
    return true;
}

/* The ISO calendar: the date of day `wd` (1..7) of week `week` of `year` (CPython's _isoweek_to_gregorian). */
static bool isoweek_to_date(int year, int week, int wd, DkDate *out) {
    if (year < 1 || year > 9999) return false;
    if (week < 1 || week > 53) return false;
    if (wd < 1 || wd > 7) return false;
    if (week == 53) {
        /* a year has 53 ISO weeks when Jan 1 is a Thursday, or a Wednesday in a leap year */
        DkDate jan1 = {year, 1, 1};
        int w = dk_date_weekday(jan1); /* Monday is 0 */
        bool has53 = (w == 3) || (w == 2 && is_leap(year));
        if (!has53) return false;
    }
    DkDate jan4 = {year, 1, 4};
    i64 first_monday = dk_date_toordinal(jan4) - dk_date_weekday(jan4);
    i64 ord = first_monday + (i64)(week - 1) * 7 + (wd - 1);
    if (ord < 1 || ord > 3652059) return false;
    *out = dk_date_fromordinal(ord);
    return true;
}

bool dk_date_fromisoformat(DkStr s, DkDate *out) {
    int year, a, b;
    const char *p = s.p;
    if (s.n == 10) {
        if (!digits(p, 4, &year) || p[4] != '-') return false;
        if (p[5] == 'W') {
            /* YYYY-Www-D */
            int week, wd;
            if (!digits(p + 6, 2, &week) || p[8] != '-' || !digits(p + 9, 1, &wd)) return false;
            return isoweek_to_date(year, week, wd, out);
        }
        if (!digits(p + 5, 2, &a) || p[7] != '-' || !digits(p + 8, 2, &b)) return false;
        if (!dk_date_valid(year, a, b)) return false;
        *out = (DkDate){year, a, b};
        return true;
    }
    if (s.n == 8) {
        if (!digits(p, 4, &year)) return false;
        if (p[4] == '-') {
            /* YYYY-Www */
            int week;
            if (p[5] != 'W' || !digits(p + 6, 2, &week)) return false;
            return isoweek_to_date(year, week, 1, out);
        }
        if (p[4] == 'W') {
            /* YYYYWwwD */
            int week, wd;
            if (!digits(p + 5, 2, &week) || !digits(p + 7, 1, &wd)) return false;
            return isoweek_to_date(year, week, wd, out);
        }
        if (!digits(p + 4, 2, &a) || !digits(p + 6, 2, &b)) return false;
        if (!dk_date_valid(year, a, b)) return false;
        *out = (DkDate){year, a, b};
        return true;
    }
    if (s.n == 7) {
        /* YYYYWww */
        int week;
        if (!digits(p, 4, &year) || p[4] != 'W' || !digits(p + 5, 2, &week)) return false;
        return isoweek_to_date(year, week, 1, out);
    }
    return false;
}

/* ---- datetime ---- */

static DkDateTime from_tm(const DkTm *tm, int us, bool aware) {
    DkDateTime d;
    d.year = tm->year;
    d.month = tm->mon;
    d.day = tm->mday;
    d.hour = tm->hour;
    d.minute = tm->min;
    d.second = tm->sec > 59 ? 59 : tm->sec; /* a leap second is 59 as in datetime */
    d.microsecond = us;
    d.aware = aware;
    d.utcoffset_s = 0;
    return d;
}

DkDateTime dk_datetime_now(void) {
    i64 ns = dk_time_ns();
    __time64_t s = ns / NS_PER_SEC;
    DkTm tm;
    DK_ASSERT(dk_localtime((double)s, &tm));
    return from_tm(&tm, (int)((ns % NS_PER_SEC) / 1000), false);
}

DkDateTime dk_datetime_now_utc(void) {
    i64 ns = dk_time_ns();
    DkTm tm;
    DK_ASSERT(dk_gmtime((double)(ns / NS_PER_SEC), &tm));
    return from_tm(&tm, (int)((ns % NS_PER_SEC) / 1000), true);
}

DkDateTime dk_datetime_utcnow(void) {
    DkDateTime d = dk_datetime_now_utc();
    d.aware = false;
    return d;
}

/* _PyTime_Round with ROUND_HALF_EVEN. */
static double round_half_even(double x) {
    double rounded = round(x);
    if (fabs(x - rounded) == 0.5) rounded = 2.0 * round(x / 2.0);
    return rounded;
}

bool dk_datetime_fromtimestamp(double ts, bool utc, DkDateTime *out) {
    if (!isfinite(ts)) return false;
    double intpart;
    volatile double frac = modf(ts, &intpart);
    frac *= 1e6;
    frac = round_half_even(frac);
    if (frac >= 1e6) {
        frac -= 1e6;
        intpart += 1.0;
    } else if (frac < 0) {
        frac += 1e6;
        intpart -= 1.0;
    }
    DkTm tm;
    bool ok = utc ? dk_gmtime(intpart, &tm) : dk_localtime(intpart, &tm);
    if (!ok || tm.year < 1 || tm.year > 9999) return false;
    *out = from_tm(&tm, (int)frac, utc);
    return true;
}

static void fmt_offset(char *out, size_t cap, i32 off, bool colon, bool with_seconds_always) {
    char sign = '+';
    if (off < 0) {
        sign = '-';
        off = -off;
    }
    int hh = off / 3600, mm = (off % 3600) / 60, ss = off % 60;
    if (colon) {
        if (ss || with_seconds_always) snprintf(out, cap, "%c%02d:%02d:%02d", sign, hh, mm, ss);
        else snprintf(out, cap, "%c%02d:%02d", sign, hh, mm);
    } else {
        if (ss || with_seconds_always) snprintf(out, cap, "%c%02d%02d%02d", sign, hh, mm, ss);
        else snprintf(out, cap, "%c%02d%02d", sign, hh, mm);
    }
}

void dk_datetime_isoformat(const DkDateTime *dt, char sep, char out[48]) {
    int n = snprintf(out, 48, "%04d-%02d-%02d%c%02d:%02d:%02d", dt->year, dt->month, dt->day, sep, dt->hour,
                     dt->minute, dt->second);
    if (dt->microsecond) n += snprintf(out + n, (size_t)(48 - n), ".%06d", dt->microsecond);
    if (dt->aware) fmt_offset(out + n, (size_t)(48 - n), dt->utcoffset_s, true, false);
}

DkDate dk_datetime_date(const DkDateTime *dt) { return (DkDate){dt->year, dt->month, dt->day}; }

DkTm dk_datetime_timetuple(const DkDateTime *dt) {
    DkDate d = dk_datetime_date(dt);
    DkTm tm;
    tm.year = dt->year;
    tm.mon = dt->month;
    tm.mday = dt->day;
    tm.hour = dt->hour;
    tm.min = dt->minute;
    tm.sec = dt->second;
    tm.wday = dk_date_weekday(d);
    tm.yday = days_before_month_tab[d.month] + (d.month > 2 && is_leap(d.year) ? 1 : 0) + d.day;
    tm.isdst = -1;
    return tm;
}

bool dk_datetime_strftime(DkArena *a, const DkDateTime *dt, const char *fmt, DkStr *out) {
    /* datetime's wrap_strftime: %z %Z %f (and %:z) are replaced, everything else is left for time.strftime. A
     * directive grows at most sevenfold (%Z of an offset is "UTC+HH:MM:SS"). */
    size_t cap = strlen(fmt) * 7 + 16, n = 0;
    char *nf = dk_xmalloc(cap);
    for (const char *p = fmt; *p;) {
        if (*p != '%' || p[1] == '\0') {
            nf[n++] = *p++;
            continue;
        }
        char ch = p[1], tmp[32];
        const char *rep = NULL;
        if (ch == 'z' || (ch == ':' && p[2] == 'z')) {
            tmp[0] = 0;
            if (dt->aware) fmt_offset(tmp, sizeof tmp, dt->utcoffset_s, ch == ':', false);
            rep = tmp;
            p += ch == 'z' ? 2 : 3;
        } else if (ch == 'Z') {
            tmp[0] = 0;
            if (dt->aware) {
                strcpy(tmp, "UTC");
                if (dt->utcoffset_s != 0) fmt_offset(tmp + 3, sizeof tmp - 3, dt->utcoffset_s, true, false);
            }
            rep = tmp;
            p += 2;
        } else if (ch == 'f') {
            snprintf(tmp, sizeof tmp, "%06d", dt->microsecond);
            rep = tmp;
            p += 2;
        } else {
            nf[n++] = '%';
            nf[n++] = ch;
            p += 2;
            continue;
        }
        size_t rl = strlen(rep);
        memcpy(nf + n, rep, rl);
        n += rl;
    }
    nf[n] = 0;
    DkTm tm = dk_datetime_timetuple(dt);
    bool ok = dk_strftime(a, nf, &tm, out);
    dk_xfree(nf);
    return ok;
}

/* ---- timedelta ---- */

static void td_normalize(i64 seconds, i64 us, DkTimeDelta *td) {
    i64 carry = us >= 0 ? us / 1000000 : -((-us + 999999) / 1000000);
    us -= carry * 1000000;
    seconds += carry;
    i64 days = seconds >= 0 ? seconds / 86400 : -((-seconds + 86399) / 86400);
    seconds -= days * 86400;
    td->days = days;
    td->seconds = (i32)seconds;
    td->microseconds = (i32)us;
}

bool dk_timedelta_from_seconds(double seconds, DkTimeDelta *out) {
    if (!isfinite(seconds)) return false;
    double intpart;
    double frac = modf(seconds, &intpart);
    if (fabs(intpart) > 999999999.0 * 86400.0 + 86400.0) return false;
    /* delta_new accumulates the microseconds of the whole seconds (always even) and rounds the fraction half-even */
    double leftover = frac * 1e6;
    double whole = round(leftover);
    if (fabs(whole - leftover) == 0.5) whole = 2.0 * round(leftover * 0.5);
    td_normalize((i64)intpart, (i64)whole, out);
    return out->days >= -999999999 && out->days <= 999999999;
}

double dk_timedelta_total_seconds(DkTimeDelta td) {
    i64 secs = td.days * 86400 + td.seconds;
    return ((double)secs * 1e6 + (double)td.microseconds) / 1e6;
}

void dk_timedelta_str(DkTimeDelta td, char out[64]) {
    int mm = td.seconds / 60, ss = td.seconds % 60;
    int hh = mm / 60;
    mm %= 60;
    int n = 0;
    if (td.days) n = snprintf(out, 64, "%lld day%s, ", (long long)td.days, (td.days != 1 && td.days != -1) ? "s" : "");
    n += snprintf(out + n, (size_t)(64 - n), "%d:%02d:%02d", hh, mm, ss);
    if (td.microseconds) snprintf(out + n, (size_t)(64 - n), ".%06d", td.microseconds);
}

/* ---- elapsed times ---- */

DkStopwatch dk_stopwatch_start(void) { return (DkStopwatch){dk_time()}; }
double dk_stopwatch_secs(const DkStopwatch *w) { return dk_time() - w->t0; }

size_t dk_fmt_fixed(char *out, size_t cap, double x, int decimals) {
    if (isnan(x)) return (size_t)snprintf(out, cap, "nan");
    if (isinf(x)) return (size_t)snprintf(out, cap, x < 0 ? "-inf" : "inf");
    int n = snprintf(out, cap, "%.*f", decimals, x);
    return n < 0 ? 0 : (size_t)n;
}

double dk_clock_round(double x, int ndigits) {
    if (!isfinite(x) || x == 0.0) return x;
    if (ndigits > 323) return x;
    if (ndigits < -308) return 0.0 * x;
    char buf[512];
    if (ndigits >= 0) {
        snprintf(buf, sizeof buf, "%.*f", ndigits, x);
        return strtod(buf, NULL);
    }
    /* A negative ndigits rounds to a multiple of 10**-ndigits: round the exact decimal expansion half-even. */
    static char big[1024];
    int len = snprintf(big, sizeof big, "%.60f", fabs(x));
    char *dot = strchr(big, '.');
    int intlen = (int)(dot - big);
    int k = -ndigits;
    if (k > intlen) return x < 0 ? -0.0 : 0.0; /* below half of one unit: zero, keeping the sign */
    int keep = intlen - k; /* digits kept before the rounded-away part */
    /* the digit string without the dot, rounded at position keep */
    char digs[1024];
    int nd = 0;
    for (int i = 0; i < len; i++)
        if (big[i] != '.') digs[nd++] = big[i];
    bool up;
    char first = digs[keep];
    bool rest_nonzero = false;
    for (int i = keep + 1; i < nd; i++)
        if (digs[i] != '0') rest_nonzero = true;
    if (first > '5') up = true;
    else if (first < '5') up = false;
    else if (rest_nonzero) up = true;
    else up = keep > 0 && ((digs[keep - 1] - '0') & 1);
    for (int i = keep; i < nd; i++) digs[i] = '0';
    if (up) {
        int i = keep - 1;
        while (i >= 0 && digs[i] == '9') digs[i--] = '0';
        if (i >= 0) {
            digs[i]++;
        } else {
            /* carry out of the top: 1 followed by zeros */
            memmove(digs + 1, digs, (size_t)nd);
            digs[0] = '1';
            nd++;
            intlen++;
        }
    }
    digs[intlen] = '\0'; /* only the integer digits matter now */
    double r = strtod(digs, NULL);
    return x < 0 ? -r : r;
}
