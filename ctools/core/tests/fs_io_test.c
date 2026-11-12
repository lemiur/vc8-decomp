// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* open() / Path.read_text / write_text / os.replace / tempfile / os.environ behaviour of fs.h (expected values are the
 * results of the equivalent CPython 3.14 calls, noted beside each check). */
#include "dk/dk.h"
#include "dk/fs.h"
#include "dk/test.h"

#include <stdio.h>

static DkArena *g_a;
static char *g_root;

static void setup(void) {
    g_a = dk_arena_new(0);
    g_root = dk_mkdtemp(g_a, "dkio_", "", NULL);
}

static void teardown(void) {
    dk_tempdir_cleanup(g_root);
    dk_arena_free(g_a);
}

static char *p(const char *name) { return dk_path_join(g_a, g_root, name); }

static bool file_is(const char *path, const void *want, size_t n) {
    DkBytes b;
    if (!dk_read_all(g_a, path, &b)) return false;
    return b.n == n && (n == 0 || memcmp(b.v, want, n) == 0);
}

#define FILE_IS(path, lit) CHECK_MSG(file_is((path), (lit), sizeof(lit) - 1), "%s has other bytes than " #lit, (path))

DK_TEST(write_text_newline_modes) {
    setup();
    DkStr t = DK_S("a\nb\n");
    /* open(p, "w", encoding="utf-8").write("a\nb\n") on Windows */
    CHECK(dk_write_text(p("1"), t, DK_TM_UTF8));
    FILE_IS(p("1"), "a\r\nb\r\n");
    CHECK(dk_write_text(p("2"), t, DK_TM_UTF8_NL_LF)); /* newline="\n" */
    FILE_IS(p("2"), "a\nb\n");
    CHECK(dk_write_text(p("3"), t, DK_TM_UTF8_NL_EMPTY)); /* newline="" */
    FILE_IS(p("3"), "a\nb\n");
    CHECK(dk_write_text(p("4"), t, DK_TEXT(DK_ENC_UTF8, DK_ERR_STRICT, DK_NL_CR)));
    FILE_IS(p("4"), "a\rb\r");
    CHECK(dk_write_text(p("5"), t, DK_TEXT(DK_ENC_UTF8, DK_ERR_STRICT, DK_NL_CRLF)));
    FILE_IS(p("5"), "a\r\nb\r\n");
    /* a "\r\n" already in the text is translated again (the file holds \r\r\n), as Python does */
    CHECK(dk_write_text(p("6"), DK_S("x\r\ny"), DK_TM_UTF8));
    FILE_IS(p("6"), "x\r\r\ny");
    /* utf-8-sig: the BOM is written, even for empty text; "a" on a non-empty file adds none */
    CHECK(dk_write_text(p("7"), DK_S(""), DK_TM_UTF8_SIG));
    FILE_IS(p("7"), "\xEF\xBB\xBF");
    CHECK(dk_write_text(p("8"), DK_S("ab"), DK_TM_UTF8_SIG));
    CHECK(dk_append_text(p("8"), DK_S("c"), DK_TM_UTF8_SIG));
    FILE_IS(p("8"), "\xEF\xBB\xBF" "abc");
    CHECK(dk_append_text(p("9"), DK_S("c"), DK_TM_UTF8_SIG));
    FILE_IS(p("9"), "\xEF\xBB\xBF" "c");
    CHECK(dk_append_text(p("9"), DK_S("d\n"), DK_TM_UTF8));
    FILE_IS(p("9"), "\xEF\xBB\xBF" "cd\r\n");
    /* latin-1 and an unencodable character: the file is left as it was (created empty by open()) */
    CHECK(dk_write_text(p("10"), DK_S("\xC3\xA9"), DK_TM_LATIN1));
    FILE_IS(p("10"), "\xE9");
    CHECK(!dk_write_text(p("11"), DK_S("\xE2\x82\xAC"), DK_TM_LATIN1));
    CHECK_EQ_I64(dk_io_err()->kind, DK_IOE_ENCODE);
    CHECK_CZ(dk_io_err_str(g_a).p, "'latin-1' codec can't encode character '\\u20ac' in position 0: ordinal not in range(256)");
    teardown();
}

DK_TEST(read_text_and_lines) {
    setup();
    /* open(p, "wb").write(b"a\r\nb\rc\n") then open(p, encoding="utf-8").read() -> 'a\nb\nc\n';
     * list(open(p, ...)): default ['a\n', 'b\n', 'c\n']; newline="" ['a\r\n', 'b\r', 'c\n']; newline="\n" ['a\r\n', 'b\rc\n'] */
    CHECK(dk_write_file(p("n"), "a\r\nb\rc\n", 7));
    DkStr s;
    CHECK(dk_read_text(g_a, p("n"), DK_TM_UTF8, &s));
    CHECK_STR(s, "a\nb\nc\n");
    CHECK(dk_read_text(g_a, p("n"), DK_TM_UTF8_NL_EMPTY, &s));
    CHECK_STR(s, "a\r\nb\rc\n");
    DkStrVec ls;
    CHECK(dk_read_lines(g_a, p("n"), DK_TM_UTF8, &ls));
    CHECK_EQ_U64(ls.n, 3);
    CHECK_STR(ls.v[0], "a\n");
    CHECK_STR(ls.v[2], "c\n");
    dk_vec_free(&ls);
    CHECK(dk_read_lines(g_a, p("n"), DK_TM_UTF8_NL_EMPTY, &ls));
    CHECK_EQ_U64(ls.n, 3);
    CHECK_STR(ls.v[0], "a\r\n");
    CHECK_STR(ls.v[1], "b\r");
    dk_vec_free(&ls);
    CHECK(dk_read_lines(g_a, p("n"), DK_TM_UTF8_NL_LF, &ls));
    CHECK_EQ_U64(ls.n, 2);
    CHECK_STR(ls.v[1], "b\rc\n");
    dk_vec_free(&ls);
    /* BOM: "utf-8" keeps U+FEFF, "utf-8-sig" drops one */
    CHECK(dk_write_file(p("bom"), "\xEF\xBB\xBFx\xEF\xBB\xBF", 7));
    CHECK(dk_read_text(g_a, p("bom"), DK_TM_UTF8, &s));
    CHECK_STR(s, "\xEF\xBB\xBFx\xEF\xBB\xBF");
    CHECK(dk_read_text(g_a, p("bom"), DK_TM_UTF8_SIG, &s));
    CHECK_STR(s, "x\xEF\xBB\xBF");
    /* errors: strict fails like UnicodeDecodeError, replace gives U+FFFD */
    CHECK(dk_write_file(p("bad"), "a\xFF" "b", 3));
    CHECK(!dk_read_text(g_a, p("bad"), DK_TM_UTF8, &s));
    CHECK_EQ_I64(dk_io_err()->kind, DK_IOE_DECODE);
    CHECK_CZ(dk_io_err_class(), "UnicodeDecodeError");
    CHECK_CZ(dk_io_err_str(g_a).p, "'utf-8' codec can't decode byte 0xff in position 1: invalid start byte");
    CHECK(dk_read_text(g_a, p("bad"), DK_TM_UTF8_REPLACE, &s));
    CHECK_STR(s, "a\xEF\xBF\xBD" "b");
    /* a missing file: FileNotFoundError, errno ENOENT, the Python text */
    CHECK(!dk_read_text(g_a, p("missing"), DK_TM_UTF8, &s));
    CHECK(dk_io_is(ENOENT));
    teardown();
}

DK_TEST(read_all_and_views) {
    setup();
    /* b"" / b"abc" / 200 KiB */
    u8 *big = (u8 *)dk_alloc(g_a, 200000);
    u32 x = 12345;
    for (size_t i = 0; i < 200000; i++) {
        x = x * 1103515245u + 12345u;
        big[i] = (u8)(x >> 16);
    }
    CHECK(dk_write_file(p("empty"), "", 0));
    CHECK(dk_write_file(p("small"), "abc", 3));
    CHECK(dk_write_file(p("big"), big, 200000));
    DkBytes b;
    CHECK(dk_read_all(g_a, p("empty"), &b) && b.n == 0 && b.v != NULL);
    CHECK(dk_read_all(g_a, p("small"), &b) && b.n == 3 && memcmp(b.v, "abc", 3) == 0 && b.v[3] == 0);
    CHECK(dk_read_all(g_a, p("big"), &b) && b.n == 200000 && memcmp(b.v, big, 200000) == 0);
    CHECK(dk_read_all(NULL, p("small"), &b) && b.n == 3);
    dk_vec_free(&b);
    DkFileView v;
    CHECK(dk_view_open(p("empty"), &v) && v.p != NULL && v.n == 0);
    dk_view_close(&v);
    CHECK(dk_view_open(p("small"), &v) && v.n == 3 && memcmp(v.p, "abc", 3) == 0 && v.mapping == NULL);
    dk_view_close(&v);
    CHECK(dk_view_open(p("big"), &v) && v.n == 200000 && memcmp(v.p, big, 200000) == 0 && v.mapping != NULL);
    dk_view_close(&v);
    CHECK(!dk_view_open(p("nope"), &v));
    CHECK_CZ(dk_io_err_class(), "FileNotFoundError");
    teardown();
}

DK_TEST(atomic_replace) {
    setup();
    char *t = p("target.json");
    CHECK(dk_write_file(t, "old", 3));
    CHECK(dk_write_atomic(t, "new!", 4));
    FILE_IS(t, "new!");
    CHECK(dk_write_text_atomic(t, DK_S("a\nb"), DK_TM_UTF8_NL_LF));
    FILE_IS(t, "a\nb");
    DkStrVec names;
    CHECK(dk_listdir(g_a, g_root, &names));
    CHECK_EQ_U64(names.n, 1); /* no temporary file is left */
    /* a folder that does not exist: FileNotFoundError like open() of the temporary file */
    CHECK(!dk_write_atomic(p("nodir\\x"), "x", 1));
    CHECK(dk_io_is(ENOENT));
    /* a read-only target: os.replace fails with [WinError 5] Access is denied: 'tmp' -> 'target', tmp removed */
    CHECK(dk_chmod(t, 0400));
    CHECK(!dk_write_atomic(t, "zzz", 3));
    CHECK_EQ_I64(dk_io_err()->winerror, 5);
    CHECK(dk_listdir(g_a, g_root, &names) && names.n == 1);
    teardown();
}

DK_TEST(open_files) {
    setup();
    DkFile *f = dk_fopen(p("w.txt"), "w", DK_TM_UTF8);
    REQUIRE(f != NULL);
    CHECK(dk_fprintf(f, "n=%d\n", 42));
    CHECK(dk_fwrite_text(f, DK_S("x\n")));
    CHECK(dk_fwrite(f, "raw\n", 4)); /* bytes as given */
    CHECK(dk_fclose(f));
    FILE_IS(p("w.txt"), "n=42\r\nx\r\nraw\n");
    f = dk_fopen(p("w.txt"), "a", DK_TM_UTF8_NL_LF);
    REQUIRE(f != NULL);
    CHECK(dk_fwrite_text(f, DK_S("tail\n")));
    CHECK(dk_fclose(f));
    FILE_IS(p("w.txt"), "n=42\r\nx\r\nraw\ntail\n");
    f = dk_fopen(p("b.bin"), "wb", DK_TM_UTF8);
    REQUIRE(f != NULL);
    CHECK(dk_fwrite(f, "0123456789", 10));
    CHECK_EQ_I64(dk_ftell(f), 10);
    CHECK(dk_fsync(f));
    CHECK(dk_fhandle(f) != NULL);
    CHECK(dk_fclose(f));
    f = dk_fopen(p("b.bin"), "r+b", DK_TM_UTF8);
    REQUIRE(f != NULL);
    char buf[16] = {0};
    CHECK_EQ_I64(dk_fread(f, buf, 4), 4);
    CHECK(memcmp(buf, "0123", 4) == 0);
    CHECK(dk_fseek(f, -2, 2));
    CHECK_EQ_I64(dk_fread(f, buf, 8), 2);
    CHECK(memcmp(buf, "89", 2) == 0);
    CHECK_EQ_I64(dk_fread(f, buf, 8), 0);
    CHECK(dk_fseek(f, 3, 0));
    CHECK(dk_fwrite(f, "XY", 2));
    CHECK_EQ_I64(dk_fsize(f), 10);
    CHECK(dk_ftruncate(f, 6));
    CHECK(dk_fclose(f));
    FILE_IS(p("b.bin"), "012XY5");
    /* "x" fails when the file exists: [Errno 17] File exists: 'path' */
    CHECK(dk_fopen(p("b.bin"), "xb", DK_TM_UTF8) == NULL);
    CHECK(dk_io_is(EEXIST));
    CHECK_CZ(dk_io_err_class(), "FileExistsError");
    /* a text file with utf-8-sig: one BOM for two writes */
    f = dk_fopen(p("sig.txt"), "w", DK_TM_UTF8_SIG);
    REQUIRE(f != NULL);
    CHECK(dk_fwrite_text(f, DK_S("a")));
    CHECK(dk_fwrite_text(f, DK_S("b")));
    CHECK(dk_fclose(f));
    FILE_IS(p("sig.txt"), "\xEF\xBB\xBF" "ab");
    /* big write through the buffer */
    char *big = (char *)dk_alloc(g_a, 300000);
    memset(big, 'z', 299999);
    f = dk_fopen(p("big.bin"), "wb", DK_TM_UTF8);
    REQUIRE(f != NULL);
    CHECK(dk_fwrite(f, "q", 1));
    CHECK(dk_fwrite(f, big, 299999));
    CHECK(dk_fclose(f));
    i64 sz;
    CHECK(dk_getsize(p("big.bin"), &sz) && sz == 300000);
    teardown();
}

DK_TEST(environment) {
    setup();
    CHECK(dk_getenv(g_a, "DK_FS_TEST_VAR") == NULL);
    CHECK(dk_setenv("DK_FS_TEST_VAR", "caf\xC3\xA9 \xE2\x82\xAC"));
    CHECK_CZ(dk_getenv(g_a, "DK_FS_TEST_VAR"), "caf\xC3\xA9 \xE2\x82\xAC");
    CHECK_CZ(dk_getenv(g_a, "dk_fs_test_var"), "caf\xC3\xA9 \xE2\x82\xAC"); /* names are case-insensitive */
    CHECK(dk_setenv("DK_FS_TEST_EMPTY", ""));
    CHECK_CZ(dk_getenv(g_a, "DK_FS_TEST_EMPTY"), "");
    CHECK(dk_setenv("DK_FS_TEST_EMPTY", "x")); /* a set variable made empty stays set (os.environ[k] = "") */
    CHECK(dk_setenv("DK_FS_TEST_EMPTY", ""));
    CHECK_CZ(dk_getenv(g_a, "DK_FS_TEST_EMPTY"), "");
    CHECK_CZ(dk_getenv_or(g_a, "DK_FS_TEST_NOPE", "dflt"), "dflt");
    DkEnvVec env = dk_environ(g_a);
    bool found = false;
    for (size_t i = 0; i < env.n; i++)
        if (env.v[i].name.n == 14 && memcmp(env.v[i].name.p, "DK_FS_TEST_VAR", 14) == 0) found = true;
    CHECK(found);
    CHECK(dk_unsetenv("DK_FS_TEST_VAR"));
    CHECK(dk_getenv(g_a, "DK_FS_TEST_VAR") == NULL);
    dk_unsetenv("DK_FS_TEST_EMPTY");
    teardown();
}

DK_TEST(cwd_and_relative_paths) {
    setup();
    char *old = dk_getcwd(g_a);
    CHECK(dk_makedirs(p("w\\sub"), false));
    CHECK(dk_write_file(p("w\\sub\\f.txt"), "1", 1));
    CHECK(dk_chdir(p("w")));
    CHECK_CZ(dk_getcwd(g_a), p("w"));
    CHECK(dk_isfile("sub\\f.txt") && dk_isdir("sub") && !dk_exists("nope"));
    DkStrVec r = dk_glob(g_a, "s*\\*.txt", false);
    CHECK_EQ_U64(r.n, 1);
    CHECK_STR(r.v[0], "sub\\f.txt");
    dk_vec_free(&r);
    r = dk_glob(g_a, "*.txt", false);
    CHECK_EQ_U64(r.n, 0);
    dk_vec_free(&r);
    CHECK_CZ(dk_path_abspath(g_a, "sub\\..\\x"), dk_path_join(g_a, p("w"), "x"));
    CHECK(dk_chdir(old));
    teardown();
}

DK_TEST(long_paths) {
    setup();
    char *deep = g_root;
    for (int i = 0; i < 8; i++) deep = dk_path_join(g_a, deep, "0123456789012345678901234567890123456789");
    CHECK(strlen(deep) > 330);
    CHECK(dk_makedirs(deep, false));
    char *f = dk_path_join(g_a, deep, "file.txt");
    CHECK(dk_write_text(f, DK_S("long"), DK_TM_UTF8_NL_LF));
    DkStr s;
    CHECK(dk_read_text(g_a, f, DK_TM_UTF8, &s));
    CHECK_STR(s, "long");
    CHECK(dk_exists(f) && dk_isfile(f) && dk_isdir(deep));
    DkStrVec names;
    CHECK(dk_listdir(g_a, deep, &names) && names.n == 1);
    i64 sz;
    CHECK(dk_getsize(f, &sz) && sz == 4);
    CHECK(dk_rename(f, dk_path_join(g_a, deep, "g.txt")));
    CHECK(dk_remove(dk_path_join(g_a, deep, "g.txt")));
    CHECK(dk_rmtree(dk_path_join(g_a, g_root, "0123456789012345678901234567890123456789"), 0));
    teardown();
}

DK_TEST(tempfile_functions) {
    setup();
    char *tmp = dk_gettempdir(g_a);
    CHECK(dk_isdir(tmp));
    char *path1 = NULL, *path2 = NULL;
    DkFile *f1 = dk_mkstemp(g_a, "pre_", ".sfx", g_root, &path1);
    REQUIRE(f1 != NULL);
    DkFile *f2 = dk_mkstemp(g_a, "pre_", ".sfx", g_root, &path2);
    REQUIRE(f2 != NULL);
    CHECK(strcmp(path1, path2) != 0);
    /* mkstemp names: dir\prefix + 8 characters of [a-z0-9_] + suffix, absolute */
    DkStr bn = dk_path_basename(path1);
    CHECK_EQ_U64(bn.n, 4 + 8 + 4);
    CHECK(memcmp(bn.p, "pre_", 4) == 0 && memcmp(bn.p + 12, ".sfx", 4) == 0);
    for (int i = 4; i < 12; i++) CHECK((bn.p[i] >= 'a' && bn.p[i] <= 'z') || (bn.p[i] >= '0' && bn.p[i] <= '9') || bn.p[i] == '_');
    CHECK(dk_path_isabs(path1));
    CHECK(dk_fwrite(f1, "x", 1));
    CHECK(dk_fclose(f1));
    CHECK(dk_fclose(f2));
    FILE_IS(path1, "x");
    char *d1 = dk_mkdtemp(g_a, "tree_", "", g_root);
    REQUIRE(d1 != NULL);
    CHECK(dk_isdir(d1));
    DkStr dn = dk_path_basename(d1);
    CHECK_EQ_U64(dn.n, 5 + 8);
    /* TemporaryDirectory cleanup removes a tree holding a read-only file */
    CHECK(dk_write_file(dk_path_join(g_a, d1, "ro.txt"), "1", 1));
    CHECK(dk_chmod(dk_path_join(g_a, d1, "ro.txt"), 0400));
    dk_tempdir_cleanup(d1);
    CHECK(!dk_exists(d1));
    /* default prefix is "tmp" */
    char *d2 = dk_mkdtemp(g_a, NULL, NULL, g_root);
    REQUIRE(d2 != NULL);
    DkStr dn2 = dk_path_basename(d2);
    CHECK(dn2.n == 11 && memcmp(dn2.p, "tmp", 3) == 0);
    teardown();
}

DK_TEST(io_error_record) {
    setup();
    dk_io_clear();
    DkStr s;
    CHECK(!dk_read_text(g_a, p("missing.txt"), DK_TM_UTF8, &s));
    CHECK_EQ_I64(dk_io_err()->kind, DK_IOE_OS);
    CHECK_EQ_I64(dk_io_err()->err, ENOENT);
    CHECK_EQ_I64(dk_io_err()->winerror, 0);
    /* a successful call leaves the record alone */
    CHECK(dk_write_file(p("ok.txt"), "x", 1));
    CHECK_EQ_I64(dk_io_err()->err, ENOENT);
    /* repr() of the path as Python prints it: quotes and escapes */
    CHECK_CZ(dk_io_err_repr_path(g_a, "it's").p, "\"it's\"");
    CHECK_CZ(dk_io_err_repr_path(g_a, "a\\b").p, "'a\\\\b'");
    CHECK_CZ(dk_io_err_repr_path(g_a, "a\"b'c").p, "'a\"b\\'c'");
    CHECK_CZ(dk_io_err_repr_path(g_a, "t\tn\n\x01").p, "'t\\tn\\n\\x01'");
    CHECK_CZ(dk_io_err_repr_path(g_a, "caf\xC3\xA9").p, "'caf\xC3\xA9'");
    teardown();
}

DK_TEST_MAIN("fs_io")
