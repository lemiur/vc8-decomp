// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Python's text formatting of numbers and objects, byte for byte as CPython 3.14: repr(float), the % operator, the
 * format-spec mini-language of str.format / f-strings / format(), round(), repr(str) and the container reprs, and
 * the arithmetic whose results reach the output (floor division and modulo, sum() and math.fsum over floats).
 * The digits come from exact big-integer arithmetic, not from the C runtime: the C printf rounds the same
 * way for most values but spells inf/nan, exponents, %x of negatives and %g differently, and the project's
 * outputs must not depend on the C library.
 *
 * ---- floats ----
 * dk_float_repr is repr(x) == str(x): the shortest digit string that reads back as the same double (when two
 * shortest strings exist, the one closest to the exact value), written positionally for 1e-4 <= |x| < 1e16 and as
 * d.ddde+XX otherwise (the exponent has a sign and at least two digits: 1e-05, 1e+16), "1.0" for integral values,
 * "inf", "-inf", "nan" (a NaN never prints a sign), "-0.0".
 * dk_float_to_string is PyOS_double_to_string: types e E f F g G r (r ignores the precision and is the repr mode).
 * dk_dtoa is _Py_dg_dtoa (modes 0, 2, 3): the digit string without trailing zeros and the decimal point position.
 *
 * ---- % formatting (dk_pyfmt and friends) ----
 * The format string follows Python's % operator: %[flags][width][.precision][modifier]type with flags - + space # 0,
 * a width and precision that are digits or *, and the modifiers h l L (accepted and ignored, as Python does).
 * %% is a percent sign. There is no %(name) form. Python's rules apply to the output (not C's): the result of
 * '%d' % -5, '%x' % -255 is "-ff" (and "-0xff" with #), '%o' with # gives "0o10", '%c' of a code point gives that
 * character, %f/%e/%g of inf and nan give "inf" and "nan" ("INF"/"NAN" for the upper-case types, a sign flag still
 * adds "+" and the 0 flag pads with zeros: "00inf"), %.0f rounds half to even on the exact binary value
 * ('%.0f' % 0.5 == '0', '%.0f' % 2.5 == '2'), %g drops trailing zeros unless # is given, a 0 flag pads numbers
 * with zeros after the sign and the 0x prefix and is ignored with the - flag, and widths and precisions of %s
 * count code points.
 *
 * The C arguments follow this convention (the macros dk_pyfmt, dk_pyprintf, dk_pyfprintf and dk_buf_pyfmt
 * widen the integer arguments for you, so an int, a u32, a size_t, a bool or a long all work; the va_list functions
 * dk_pyvfmt and dk_buf_pyvfmt take the widened types as listed here):
 *   %d %i            long long (a signed integer)
 *   %u               unsigned long long (decimal)
 *   %x %X %o        long long, signed as Python's ints are: -255 prints "-ff". A u64 above INT64_MAX needs the
 *                    U modifier: %Ux %UX %Uo %Ud take unsigned long long (an extension to Python's syntax)
 *   %c               long long: the code point, written as UTF-8 (a character, not a byte)
 *   %f %F %e %E %g %G double
 *   %v               double printed as str(float) (what Python's %s gives for a float); flags, width and precision
 *                    act on that text as they do for %s ('%.3s' % 1.5 == '1.5')
 *   %s               const char * (UTF-8, NUL-terminated); NULL prints "None"
 *   %S               a const DkStr * (the address: a struct cannot go through the widening macros; write &s)
 *   %r %R            repr() of a const char * / of a const DkStr *: quotes and escapes as repr(str)
 *   *                width or precision taken from the arguments (an integer; a negative width means - and its
 *                    absolute value)
 * A malformed format string or a missing/mistyped argument is a programming error (dk_panic).
 *
 * ---- format specs (dk_format_*) ----
 * [[fill]align][sign][z][#][0][width][grouping][.precision][type] exactly as Python's format(): align < > ^ =,
 * sign + - space, grouping , or _ (3 digits; _ groups binary/octal/hex by 4), z (no negative zero), width counted in
 * code points. Integer types b c d n o x X and none (also e E f F g G % with the int converted to float, as
 * format(5, '.2f')); float types e E f F g G n % and none (repr when there is no precision; with a precision
 * like g but with at least one digit after the point: format(1e5, '.6') == '1e+05'); str types s and none.
 * An invalid spec is Python's ValueError: dk_throw(DK_ERR_OTHER, <Python's message>), fatal if no DK_TRY is
 * active. 'n' is 'd'/'g' (the C locale, as the tools run).
 *
 * ---- round() ----
 * dk_py_round is round(x, ndigits): correctly rounded half-even on the exact binary value (round(2.675, 2) ==
 * 2.67). dk_py_round_int is round(x) for a float: half-even to an integer (the C rounding of x.5 is away from zero).
 *
 * ---- repr of str and containers ----
 * dk_repr_str is repr(str): single quotes unless the text has a ' and no ", \\ \n \r \t and \x.. \u.... \U........
 * escapes for the non-printable code points (the table is Python 3.14's str.isprintable), the printable non-ASCII
 * ones kept. The container helpers take the already-built reprs of the items.
 *
 * ---- arithmetic ----
 * Python's // and % round toward minus infinity and % takes the sign of the divisor; a zero divisor is Python's
 * ZeroDivisionError (dk_throw). dk_fsum_neumaier is the built-in sum() over floats of CPython 3.12+ (Neumaier
 * compensated summation, the same bits), dk_math_fsum is math.fsum (exactly rounded). */
#pragma once
#include "str.h"
#include <stdio.h>

/* ---- floats ---- */
size_t dk_float_repr(double x, char out[32]); /* repr(x); returns the length; out is NUL-terminated */
DkStr dk_repr_f64(DkArena *a, double x);    /* the same as an DkStr from the arena */

enum {
    DK_DTSF_SIGN = 1,      /* always write a sign: "+1.5" (Py_DTSF_SIGN) */
    DK_DTSF_ADD_DOT_0 = 2, /* integral values get ".0" in g and r modes (Py_DTSF_ADD_DOT_0) */
    DK_DTSF_ALT = 4,       /* keep the decimal point and the trailing zeros of g (Py_DTSF_ALT) */
    DK_DTSF_NO_NEG_0 = 8   /* a result that rounds to zero loses its minus sign (Py_DTSF_NO_NEG_0) */
};
/* Appends PyOS_double_to_string(x, type, precision, flags): type is one of e E f F g G r; precision is the number
 * of digits after the point (e f) or of significant digits (g), ignored for r. */
void dk_float_to_string(DkBuf *b, double x, char type, int precision, int flags);

/* _Py_dg_dtoa: mode 0 is the shortest string that round-trips, mode 2 gives ndigits significant digits (at least 1),
 * mode 3 gives ndigits digits after the decimal point; modes 2 and 3 round half to even on the exact value. buf
 * receives the digits without trailing zeros (no digits at all when mode 3 rounds to zero; "0" for 0.0), NUL
 * terminated; the value is 0.DIGITS * 10**decpt; *neg is the sign bit. x must be finite. Returns the digit count. */
#define DK_DTOA_BUF 800
size_t dk_dtoa(double x, int mode, int ndigits, char buf[DK_DTOA_BUF], int *decpt, bool *neg);

/* The digits of v in base 2..16 (lower case, or upper case for hex when upper), most significant first, no sign,
 * no prefix; out needs 64 bytes; returns the count ("0" for 0). */
size_t dk_u64_digits(char *out, u64 v, int base, bool upper);

/* ---- % formatting ---- */
void dk_buf_pyvfmt(DkBuf *b, const char *fmt, va_list ap);
DkStr dk_pyvfmt(DkArena *a, const char *fmt, va_list ap); /* a NUL-terminated string from the arena */
void dk_buf_pyfmt_(DkBuf *b, const char *fmt, ...);
DkStr dk_pyfmt_(DkArena *a, const char *fmt, ...);
size_t dk_pyprintf_(const char *fmt, ...);               /* to stdout; returns the bytes written */
size_t dk_pyfprintf_(FILE *f, const char *fmt, ...);

/* The macros widen the integer arguments to the types above. Up to 16 arguments after the format. */
#define DK__W(x)                                                                                                    \
    _Generic((x), _Bool: (long long)(x), char: (long long)(x), signed char: (long long)(x),                          \
             unsigned char: (long long)(x), short: (long long)(x), unsigned short: (long long)(x),                   \
             int: (long long)(x), long: (long long)(x), long long: (long long)(x),                                   \
             unsigned int: (unsigned long long)(x), unsigned long: (unsigned long long)(x),                          \
             unsigned long long: (unsigned long long)(x), default: (x))
#define DK__W1(x) , DK__W(x)
#define DK__W2(x, ...) , DK__W(x) DK__W1(__VA_ARGS__)
#define DK__W3(x, ...) , DK__W(x) DK__W2(__VA_ARGS__)
#define DK__W4(x, ...) , DK__W(x) DK__W3(__VA_ARGS__)
#define DK__W5(x, ...) , DK__W(x) DK__W4(__VA_ARGS__)
#define DK__W6(x, ...) , DK__W(x) DK__W5(__VA_ARGS__)
#define DK__W7(x, ...) , DK__W(x) DK__W6(__VA_ARGS__)
#define DK__W8(x, ...) , DK__W(x) DK__W7(__VA_ARGS__)
#define DK__W9(x, ...) , DK__W(x) DK__W8(__VA_ARGS__)
#define DK__W10(x, ...) , DK__W(x) DK__W9(__VA_ARGS__)
#define DK__W11(x, ...) , DK__W(x) DK__W10(__VA_ARGS__)
#define DK__W12(x, ...) , DK__W(x) DK__W11(__VA_ARGS__)
#define DK__W13(x, ...) , DK__W(x) DK__W12(__VA_ARGS__)
#define DK__W14(x, ...) , DK__W(x) DK__W13(__VA_ARGS__)
#define DK__W15(x, ...) , DK__W(x) DK__W14(__VA_ARGS__)
#define DK__W16(x, ...) , DK__W(x) DK__W15(__VA_ARGS__)
#define DK__PICK(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, name, ...) name
#define DK__WIDEN(...)                                                                                              \
    __VA_OPT__(DK__PICK(__VA_ARGS__, DK__W16, DK__W15, DK__W14, DK__W13, DK__W12, DK__W11, DK__W10, DK__W9, \
                         DK__W8, DK__W7, DK__W6, DK__W5, DK__W4, DK__W3, DK__W2, DK__W1)(__VA_ARGS__))
#define dk_pyfmt(a, fmt, ...) dk_pyfmt_((a), (fmt) DK__WIDEN(__VA_ARGS__))
#define dk_buf_pyfmt(b, fmt, ...) dk_buf_pyfmt_((b), (fmt) DK__WIDEN(__VA_ARGS__))
#define dk_pyprintf(fmt, ...) dk_pyprintf_((fmt) DK__WIDEN(__VA_ARGS__))
#define dk_pyfprintf(f, fmt, ...) dk_pyfprintf_((f), (fmt) DK__WIDEN(__VA_ARGS__))

/* ---- format specs: the spec is the text after the colon, "" for none ---- */
DkStr dk_format_i64(DkArena *a, i64 v, const char *spec);
DkStr dk_format_u64(DkArena *a, u64 v, const char *spec);
DkStr dk_format_f64(DkArena *a, double v, const char *spec);
DkStr dk_format_str(DkArena *a, DkStr s, const char *spec);
void dk_buf_format_i64(DkBuf *b, i64 v, const char *spec);
void dk_buf_format_u64(DkBuf *b, u64 v, const char *spec);
void dk_buf_format_f64(DkBuf *b, double v, const char *spec);
void dk_buf_format_str(DkBuf *b, DkStr s, const char *spec);

/* ---- round() ---- */
double dk_py_round(double x, int ndigits); /* round(x, ndigits); an overflow gives +-inf where Python raises */
i64 dk_py_round_int(double x);             /* round(x) for |x| < 2**63 (larger values saturate); x must be finite */

/* ---- repr ---- */
bool dk_cp_isprintable(u32 cp); /* str.isprintable for one code point (Python 3.14's Unicode tables) */
bool dk_str_isprintable(DkStr s);
DkStr dk_repr_str(DkArena *a, DkStr s);
void dk_buf_repr_str(DkBuf *b, DkStr s);
DkStr dk_repr_i64(DkArena *a, i64 v);
DkStr dk_repr_bool(bool v);                                   /* "True" / "False" */
DkStr dk_repr_list(DkArena *a, const DkStr *items, size_t n);  /* "[a, b]", "[]" */
DkStr dk_repr_tuple(DkArena *a, const DkStr *items, size_t n); /* "(a, b)", "(a,)" for one item, "()" */
DkStr dk_repr_set(DkArena *a, const DkStr *items, size_t n);   /* "{a, b}", "set()" for none */
DkStr dk_repr_dict(DkArena *a, const DkStr *keys, const DkStr *vals, size_t n); /* "{k: v, ...}", "{}" */

/* ---- arithmetic with Python's semantics ---- */
i64 dk_floordiv_i64(i64 a, i64 b); /* a // b (b == 0: ZeroDivisionError; INT64_MIN // -1 saturates) */
i64 dk_mod_i64(i64 a, i64 b);      /* a % b: the sign of b */
double dk_floordiv_f64(double a, double b); /* a // b for floats */
double dk_floormod_f64(double a, double b); /* a % b for floats (the sign of b; a zero result takes b's sign) */
/* sum(values): an int 0 start, then the floats added with Neumaier compensation as CPython 3.12+ (so sum([-0.0])
 * is 0.0); dk_sum_f64 is sum(values, start) for a float start. */
double dk_fsum_neumaier(const double *v, size_t n);
double dk_sum_f64(const double *v, size_t n, double start);
/* math.fsum: exactly rounded sum; "-inf + inf in fsum" (ValueError) and "intermediate overflow in fsum"
 * (OverflowError) are dk_throw(DK_ERR_OTHER, ...). */
double dk_math_fsum(const double *v, size_t n);
/* math.hypot(*v) / math.dist: CPython 3.12+'s vector_norm (the last bit differs from the C library's hypot for some
 * inputs); inf wins over nan, any nan gives nan, no arguments gives 0.0. */
double dk_math_hypot(const double *v, size_t n);
