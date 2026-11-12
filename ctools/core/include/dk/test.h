// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The unit-test harness (replaces unittest and the projects' check() helpers). Header-only: a test file is
 *
 *     #include "dk/test.h"
 *     DK_TEST(split_on_whitespace) {
 *         DkStrVec v = dk_str_split(DK_S(" a  b "), DK_S(""), -1);
 *         CHECK_EQ_U64(v.n, 2);
 *         CHECK_STR(v.v[0], "a");
 *     }
 *     DK_TEST_MAIN("str")
 *
 * Tests run in the order the linker places their registrations (not necessarily the order of definition: keep
 * tests independent of each other); a failed CHECK reports file:line and continues with the next check (the
 * test counts as failed). REQUIRE stops the test. The exit code is 0 when every test passed, else 1. Arguments:
 * --filter <substring> runs the tests whose name contains it; -v prints every test name. The last line printed is
 * "OK (<n> tests)" or "FAILED (<k> of <n> tests)", which ci_local.sh shows. */
#pragma once
#include "str.h"
#include <stdio.h>

typedef void (*DkTestFn)(void);
typedef struct {
    const char *name;
    DkTestFn fn;
} DkTestCase;

#define DK_TEST_MAX 4096
static DkTestCase dk_test__cases[DK_TEST_MAX];
static int dk_test__count;
static int dk_test__failed_checks;

static inline void dk_test__register(const char *name, DkTestFn fn) {
    DK_ASSERT(dk_test__count < DK_TEST_MAX);
    dk_test__cases[dk_test__count].name = name;
    dk_test__cases[dk_test__count].fn = fn;
    dk_test__count++;
}

/* MSVC C has no constructors: register through a .CRT$XCU initializer. The pointer has external linkage and a
 * linker /include so that /O2 /GL /OPT:REF keep it (a static one is optimised away). Test names are unique per
 * test executable. */
#pragma section(".CRT$XCU", read)
#define DK_TEST(name)                                                                         \
    static void dk_test_##name(void);                                                         \
    static void dk_test_reg_##name(void) { dk_test__register(#name, dk_test_##name); }      \
    __declspec(allocate(".CRT$XCU")) void (*dk_test_init_##name)(void) = dk_test_reg_##name; \
    __pragma(comment(linker, "/include:dk_test_init_" #name))                                \
    static void dk_test_##name(void)

static inline void dk_test__fail(const char *file, int line, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s(%d): check failed: ", file, line);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    dk_test__failed_checks++;
}

#define CHECK(cond) \
    ((cond) ? (void)0 : dk_test__fail(__FILE__, __LINE__, "%s", #cond))
#define REQUIRE(cond) \
    do { if (!(cond)) { dk_test__fail(__FILE__, __LINE__, "%s (required)", #cond); return; } } while (0)
#define CHECK_MSG(cond, ...) \
    ((cond) ? (void)0 : dk_test__fail(__FILE__, __LINE__, __VA_ARGS__))
#define CHECK_EQ_I64(a, b)                                                                                 \
    do { long long dk_a_ = (long long)(a), dk_b_ = (long long)(b);                                       \
         if (dk_a_ != dk_b_) dk_test__fail(__FILE__, __LINE__, "%s == %s: %lld != %lld", #a, #b, dk_a_, dk_b_); \
    } while (0)
#define CHECK_EQ_U64(a, b)                                                                                 \
    do { unsigned long long dk_a_ = (unsigned long long)(a), dk_b_ = (unsigned long long)(b);            \
         if (dk_a_ != dk_b_) dk_test__fail(__FILE__, __LINE__, "%s == %s: %llu != %llu", #a, #b, dk_a_, dk_b_); \
    } while (0)
/* Bit-exact double comparison (the port must give Python's exact value). */
#define CHECK_EQ_F64(a, b)                                                                                 \
    do { double dk_a_ = (a), dk_b_ = (b);                                                                \
         if (memcmp(&dk_a_, &dk_b_, sizeof dk_a_) != 0)                                                 \
             dk_test__fail(__FILE__, __LINE__, "%s == %s: %.17g != %.17g", #a, #b, dk_a_, dk_b_);       \
    } while (0)
/* An DkStr against a C string literal (exact bytes). */
#define CHECK_STR(s, lit)                                                                                  \
    do { DkStr dk_s_ = (s); const char *dk_l_ = (lit);                                                  \
         if (!dk_str_eqz(dk_s_, dk_l_))                                                                 \
             dk_test__fail(__FILE__, __LINE__, "%s == \"%s\": got \"%.*s\"", #s, dk_l_, DK_SF(dk_s_)); \
    } while (0)
#define CHECK_CZ(cz, lit)                                                                                  \
    do { const char *dk_c_ = (cz); const char *dk_l_ = (lit);                                            \
         if (!dk_c_ || strcmp(dk_c_, dk_l_) != 0)                                                       \
             dk_test__fail(__FILE__, __LINE__, "%s == \"%s\": got \"%s\"", #cz, dk_l_, dk_c_ ? dk_c_ : "(null)"); \
    } while (0)
#define CHECK_MEM(p, q, n) \
    CHECK_MSG(memcmp((p), (q), (n)) == 0, "%s and %s differ in their %zu bytes", #p, #q, (size_t)(n))

static inline int dk_test__run(int argc, char **argv) {
    const char *filter = NULL;
    bool verbose = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc) filter = argv[++i];
        else if (strcmp(argv[i], "-v") == 0) verbose = true;
    }
    int ran = 0, failed = 0;
    for (int i = 0; i < dk_test__count; i++) {
        if (filter && !strstr(dk_test__cases[i].name, filter)) continue;
        int before = dk_test__failed_checks;
        if (verbose) printf("%s\n", dk_test__cases[i].name);
        dk_test__cases[i].fn();
        ran++;
        if (dk_test__failed_checks != before) {
            failed++;
            fprintf(stderr, "FAIL: %s\n", dk_test__cases[i].name);
        }
    }
    fflush(stderr);
    if (failed) printf("FAILED (%d of %d tests)\n", failed, ran);
    else printf("OK (%d tests)\n", ran);
    return failed ? 1 : 0;
}

#define DK_TEST_MAIN(suite_name)                                    \
    static int dk_test__main(int argc, char **argv) {               \
        return dk_test__run(argc, argv);                            \
    }                                                                \
    DK_MAIN(dk_test__main, "test_" suite_name)
