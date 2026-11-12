// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* text_checks: the library part of the text checks (the tool is tools/text_checks_main.c): a UTF-8 BOM in a file under
 * a configured folder, and merge conflict markers, over the tracked files of the repository. */
#pragma once
#include "dk/str.h"

/* What to check. Both lists hold repository-relative prefixes with forward slashes ("src/", "docs/a.md"); a prefix
 * names a folder (a trailing slash is optional) or one file. */
typedef struct {
    const DkStrVec *paths;     /* only the tracked files under these prefixes; NULL or empty: every tracked file */
    const DkStrVec *bom_under; /* a UTF-8 BOM is a finding in files under these prefixes; NULL or empty: never */
} DkTextChecksOpts;

/* Runs the checks over the tracked files (`git ls-files -z`) of the repository that dk_root() belongs to, restricted
 * to opts->paths. Prints one line per finding, then "<n> finding(s) in <m> file(s)", on stdout. Returns the exit
 * code: 0 when clean, 1 otherwise. A git failure or an unreadable file ends the process with a message. */
int dk_text_checks_run(const DkTextChecksOpts *opts);

/* Whether the repository-relative `name` is the prefix or lies under it. */
bool dk_text_checks_under(DkStr name, DkStr prefix);

/* The findings for the bytes of one file whose repository-relative path is `name` (forward slashes), appended to
 * `found` (arena strings): the BOM check when the name is under one of `bom_under` (NULL: skipped), then (unless a
 * NUL byte is in the first 8192 bytes: a binary file) the conflict markers. The size limit is the caller's. A `=======`
 * line is a marker only between a `<<<<<<<` and a `>>>>>>>` line (markdown setext headings use it). */
void dk_text_checks_scan(DkArena *a, DkStr name, DkStr data, const DkStrVec *bom_under, DkStrVec *found);
