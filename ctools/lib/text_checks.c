// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Text checks over the tracked files: a UTF-8 BOM in a file under a configured folder, and merge conflict markers. A
 * `=======` line counts as a conflict marker only between a `<<<<<<<` and a `>>>>>>>` line (markdown setext headings
 * use it). The file list is `git ls-files -z` run in the toplevel of the repository dk_root() is in. */
#include "text_checks.h"

#include "dk/fmt.h"
#include "dk/fs.h"
#include "dk/proc.h"

#include <stdio.h>
#include <string.h>

#define MAX_SIZE ((i64)20 << 20)

bool dk_text_checks_under(DkStr name, DkStr prefix) {
    while (prefix.n && prefix.p[prefix.n - 1] == '/') prefix.n--;
    if (!prefix.n) return true;
    if (!dk_str_startswith(name, prefix)) return false;
    return name.n == prefix.n || name.p[prefix.n] == '/';
}

static bool under_any(DkStr name, const DkStrVec *prefixes) {
    if (!prefixes || !prefixes->n) return false;
    for (size_t i = 0; i < prefixes->n; i++)
        if (dk_text_checks_under(name, prefixes->v[i])) return true;
    return false;
}

/* Whether the byte run `ch` x 7 occurs anywhere in data: the cheap test that lets a file with no marker skip the
 * decoding (an invalid byte becomes U+FFFD and can neither create nor hide such a run). */
static bool has_run7(DkStr data, char ch) {
    const char *p = data.p, *end = data.p + data.n;
    while (p + 7 <= end) {
        const char *hit = memchr(p, ch, (size_t)(end - p - 6));
        if (!hit) return false;
        if (hit[1] == ch && hit[2] == ch && hit[3] == ch && hit[4] == ch && hit[5] == ch && hit[6] == ch) return true;
        p = hit + 1;
    }
    return false;
}

static void add_finding(DkArena *a, DkStrVec *found, DkStr name, i64 line, const char *what) {
    if (line > 0) dk_vec_push(found, dk_str(dk_sprintf(a, "%.*s:%lld: %s", DK_SF(name), (long long)line, what)));
    else dk_vec_push(found, dk_str(dk_sprintf(a, "%.*s: %s", DK_SF(name), what)));
}

void dk_text_checks_scan(DkArena *a, DkStr name, DkStr data, const DkStrVec *bom_under, DkStrVec *found) {
    if (under_any(name, bom_under) && dk_str_startswith(data, DK_S("\xef\xbb\xbf")))
        add_finding(a, found, name, 0, "UTF-8 BOM");
    if (memchr(data.p, 0, DK_MIN(data.n, (size_t)8192))) return; /* binary: a NUL byte in the first 8192 */
    if (!has_run7(data, '<') && !has_run7(data, '>') && !has_run7(data, '|')) return;
    DkArenaMark mark = dk_arena_mark(dk_scratch());
    DkStr text;
    if (!dk_decode_text(dk_scratch(), data, DK_TEXT(DK_ENC_UTF8, DK_ERR_REPLACE, DK_NL_EMPTY), &text))
        dk_panic(__FILE__, __LINE__, "decode: %.*s", DK_SF(dk_io_err_str(dk_scratch())));
    DkStrVec lines = dk_str_splitlines(text, false);
    bool inside = false;
    for (size_t i = 0; i < lines.n; i++) {
        DkStr line = lines.v[i];
        i64 n = (i64)i + 1;
        char next = line.n > 7 ? line.p[7] : 0; /* line[7:8] in ("", " ") */
        if (dk_str_startswith(line, DK_S("<<<<<<<")) && (line.n == 7 || next == ' ')) {
            inside = true;
            add_finding(a, found, name, n, "conflict marker");
        } else if (dk_str_startswith(line, DK_S(">>>>>>> ")) || dk_str_eqz(line, ">>>>>>>")) {
            inside = false;
            add_finding(a, found, name, n, "conflict marker");
        } else if (dk_str_startswith(line, DK_S("||||||| "))) {
            add_finding(a, found, name, n, "conflict marker");
        } else if (dk_str_eqz(line, "=======") && inside) {
            add_finding(a, found, name, n, "conflict marker");
        }
    }
    dk_vec_free(&lines);
    dk_arena_reset(dk_scratch(), mark);
}

static DK_NORETURN void io_panic(const char *what, const char *path) {
    dk_panic(__FILE__, __LINE__, "%s %s: %.*s", what, path, DK_SF(dk_io_err_str(dk_scratch())));
}

int dk_text_checks_run(const DkTextChecksOpts *opts) {
    DkArena *a = dk_arena();
    const char *const rev_argv[] = {"git", "-C", dk_root(), "rev-parse", "--show-toplevel", NULL};
    DkProcResult r = dk_run(&(DkProcSpec){.argv = rev_argv, .out = DK_IO_CAPTURE, .text = true, .check = true});
    if (r.status != DK_PROC_OK) dk_panic(__FILE__, __LINE__, "git rev-parse --show-toplevel failed");
    char *root = dk_cz(a, dk_str_strip(r.out));

    const char *const ls_argv[] = {"git", "ls-files", "-z", NULL};
    r = dk_run(&(DkProcSpec){.argv = ls_argv, .cwd = root, .out = DK_IO_CAPTURE, .check = true});
    if (r.status != DK_PROC_OK) dk_panic(__FILE__, __LINE__, "git ls-files -z failed");
    DkStrVec files = dk_str_split(r.out, dk_strn("\0", 1), -1);
    size_t kept = 0;
    for (size_t i = 0; i < files.n; i++) {
        if (!files.v[i].n) continue;
        if (opts && opts->paths && opts->paths->n && !under_any(files.v[i], opts->paths)) continue;
        files.v[kept++] = files.v[i];
    }
    files.n = kept;

    DkStrVec found = {0};
    for (size_t i = 0; i < files.n; i++) {
        DkStr f = files.v[i];
        char *p = dk_sprintf(a, "%s/%.*s", root, DK_SF(f));
        if (!dk_isfile(p)) continue; /* deleted in the worktree, or a submodule */
        i64 size;
        if (!dk_getsize(p, &size)) io_panic("stat", p);
        if (size > MAX_SIZE) continue;
        DkFileView v;
        if (!dk_view_open(p, &v)) io_panic("read", p);
        DkStr data = dk_strn((const char *)v.p, v.n);
        dk_text_checks_scan(a, f, data, opts ? opts->bom_under : NULL, &found);
        dk_view_close(&v);
    }
    for (size_t i = 0; i < found.n; i++) printf("%.*s\n", DK_SF(found.v[i]));
    printf("%zu finding(s) in %zu file(s)\n", found.n, files.n);
    return found.n ? 1 : 0;
}
