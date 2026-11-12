// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Checkout locks and the lane registry: which session works in which checkout, on which branch, on which units. A
 * claim is one JSON file in <git common dir>/lane-locks/ (shared by every worktree of the repository, never
 * versioned). The registry is read and rewritten under a lock file created exclusively (.mutex); claims of dead
 * processes or with an old heartbeat are stale and never block. */
#include "lane_lock.h"

#include "dk/clock.h"
#include "dk/fmt.h"
#include "dk/fs.h"
#include "dk/proc.h"
#include "dk/hash.h"
#include "dk/win.h"

#include <errno.h>
#include <stdio.h>

const char dk_lane_lock_doc[] =
#include "lane_lock_doc.inc"
    "";

/* ---- small helpers ------------------------------------------------------------------------------- */

static DkArena *arena(void) { return dk_arena(); }

static void print_line(DkStr s) {
    fwrite(s.p, 1, s.n, stdout);
    fputc('\n', stdout);
}

static void print_line_err(DkStr s) {
    fwrite(s.p, 1, s.n, stderr);
    fputc('\n', stderr);
}

/* A claim file that cannot be handled (a missing or mistyped key in a hand-edited file) or an I/O error ends the process with a message. */
#define INTERNAL(...) dk_panic(__FILE__, __LINE__, __VA_ARGS__)

/* The text of the last failed file operation, as the operating system reported it. */
static void io_panic(void) {
    DkStr e = dk_io_err_str(arena());
    INTERNAL("%.*s", DK_SF(e));
}

/* The text of the scalar JSON values a claim holds. */
static DkStr py_str(DkJson *v) {
    DkArena *a = arena();
    if (!v) return DK_S("None");
    switch (v->kind) {
    case DK_JSON_NULL: return DK_S("None");
    case DK_JSON_BOOL: return v->b ? DK_S("True") : DK_S("False");
    case DK_JSON_INT: return v->big ? v->u.str : dk_repr_i64(a, v->u.i);
    case DK_JSON_FLOAT: return dk_repr_f64(a, v->u.f);
    case DK_JSON_STRING: return v->u.str;
    default: INTERNAL("claim field is a container where a scalar is needed");
    }
}

/* The string member `key` of a claim; a missing or mistyped one ends the process. */
static DkStr req_str(DkJson *c, const char *key) {
    DkJson *v = dk_json_getz(c, key);
    if (!v || v->kind != DK_JSON_STRING) INTERNAL("claim has no string \"%s\"", key);
    return v->u.str;
}

/* The strings of a claim's list member: a missing or falsy value is empty, anything but a list of strings ends the process. */
static DkStrVec str_list(DkJson *v) {
    DkStrVec out = {0};
    if (!dk_json_truthy(v)) return out;
    if (v->kind != DK_JSON_ARRAY) INTERNAL("claim units is not a list");
    for (size_t i = 0; i < dk_json_len(v); i++) {
        DkJson *e = dk_json_at(v, i);
        if (!e || e->kind != DK_JSON_STRING) INTERNAL("claim units holds a non-string");
        dk_vec_push(&out, e->u.str);
    }
    return out;
}

static double num_of(DkJson *v) {
    if (!v) INTERNAL("number expected, got None");
    if (v->kind == DK_JSON_INT && !v->big) return (double)v->u.i;
    if (v->kind == DK_JSON_FLOAT) return v->u.f;
    if (v->kind == DK_JSON_BOOL) return v->b ? 1.0 : 0.0;
    INTERNAL("number expected in claim");
}

static DkStr join_strs(DkStr sep, const DkStrVec *v) { return dk_str_join(arena(), sep, v->v, v->n); }

/* os.path.normcase(c["checkout"]) of a claim. */
static DkStr claim_checkout_norm(DkJson *c) {
    DkArena *a = arena();
    return dk_str(dk_path_normcase(a, dk_cz(a, req_str(c, "checkout"))));
}

/* ---- git ---------------------------------------------------------------------------------------------------- */

/* git(path, *args): stdout stripped when git succeeded, else p == NULL (NULL). */
static DkStr git(const char *path, const char *const *args) {
    DkArena *a = arena();
    size_t n = 0;
    while (args[n]) n++;
    const char **argv = (const char **)dk_alloc(a, (n + 4) * sizeof(char *));
    argv[0] = "git";
    argv[1] = "-C";
    argv[2] = path;
    for (size_t i = 0; i < n; i++) argv[3 + i] = args[i];
    DkProcResult r = dk_run_text(a, NULL, argv);
    if (r.status == DK_PROC_START_FAILED) INTERNAL("cannot run git (%s)", r.message ? r.message : "");
    if (r.returncode != 0) return (DkStr){NULL, 0};
    return dk_str_strip(r.out);
}

static char *toplevel(const char *path) {
    DkArena *a = arena();
    const char *p = (path && *path) ? path : dk_getcwd(a);
    const char *args[] = {"rev-parse", "--show-toplevel", NULL};
    DkStr top = git(p, args);
    if (!top.p || top.n == 0) dk_fatal("lane_lock: %s is not in a git checkout", p);
    return dk_path_normcase(a, dk_path_realpath(a, dk_cz(a, top)));
}

static char *lock_dir(const char *checkout) {
    DkArena *a = arena();
    const char *args[] = {"rev-parse", "--path-format=absolute", "--git-common-dir", NULL};
    DkStr common = git(checkout, args);
    if (!common.p) INTERNAL("git --git-common-dir failed for %s", checkout);
    char *d = dk_path_join(a, dk_cz(a, common), "lane-locks");
    if (!dk_makedirs(d, true)) io_panic();
    return d;
}

static DkStr branch_of(const char *checkout) {
    const char *args[] = {"rev-parse", "--abbrev-ref", "HEAD", NULL};
    DkStr b = git(checkout, args);
    return (b.p && b.n) ? b : DK_S("-");
}

/* ---- session, pid ------------------------------------------------------------------------------------------- */

static DkStr my_session(const char *arg) {
    DkArena *a = arena();
    if (arg && *arg) return dk_str(arg);
    const char *e = dk_getenv(a, "LANE_SESSION");
    if (e && *e) return dk_str(e);
    e = dk_getenv(a, "CLAUDE_CODE_SESSION_ID");
    if (e && *e) return dk_str(e);
    return dk_pyfmt(a, "%s@%s", dk_getuser(a), dk_hostname(a));
}

/* my_pid(arg): 0 when there is none (or it is 0), else the pid. */
static i64 my_pid(bool given, i64 arg) {
    DkArena *a = arena();
    if (given && arg != 0) return arg;
    const char *e = dk_getenv(a, "CLAUDE_PID");
    if (!e || !*e) return 0;
    i64 pid = 0;
    bool overflow = false;
    if (!dk_parse_int(dk_str(e), 10, &pid, &overflow)) {
        if (overflow) INTERNAL("CLAUDE_PID does not fit in 64 bits");
        return 0;
    }
    return pid;
}

char *dk_lane_claim_id(DkArena *a, DkStr session, DkStr checkout) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_put(&b, session);
    dk_buf_putc(&b, '|');
    dk_buf_put(&b, checkout);
    u8 digest[DK_SHA1_LEN];
    dk_sha1(b.p, b.n, digest);
    char *hex = dk_hex(a, digest, DK_SHA1_LEN);
    hex[12] = '\0';
    return hex;
}

static bool pid_alive_json(DkJson *pid) {
    if (!pid || pid->kind != DK_JSON_INT || pid->big) INTERNAL("pid is not an int");
    if (pid->u.i < INT32_MIN || pid->u.i > INT32_MAX) INTERNAL("int too long to convert");
    return dk_pid_alive((u32)(i32)pid->u.i);
}

/* stale_reason(c, ttl): p == NULL for a live claim, else why it is stale. */
static DkStr stale_reason(DkJson *c, double ttl) {
    DkArena *a = arena();
    DkJson *pid = dk_json_getz(c, "pid");
    if (dk_json_truthy(pid)) {
        DkJson *host = dk_json_getz(c, "host");
        if (host && host->kind == DK_JSON_STRING && dk_str_eqz(host->u.str, dk_hostname(a)) && !pid_alive_json(pid))
            return dk_pyfmt(a, "pid %d dead", pid->u.i);
    }
    DkJson *hb = dk_json_getz(c, "heartbeat");
    double age = dk_time() - (hb ? num_of(hb) : 0.0);
    if (age > ttl * 3600) return dk_pyfmt(a, "heartbeat %.1fh old", age / 3600);
    return (DkStr){NULL, 0};
}

/* ---- the registry files ----------------------------------------------------------------------------------- */

typedef DK_VEC(DkJson *) ClaimVec;

/* load(d): every readable <id>.json in name order; unreadable or invalid ones are skipped. */
static ClaimVec load(const char *d) {
    DkArena *a = arena();
    ClaimVec out = {0};
    DkStrVec names = {0};
    if (!dk_listdir(a, d, &names)) io_panic();
    dk_sort_strs(names.v, names.n);
    for (size_t i = 0; i < names.n; i++) {
        DkStr n = names.v[i];
        if (!dk_str_endswith(n, DK_S(".json"))) continue;
        DkStr text;
        if (!dk_read_text(a, dk_path_join(a, d, n.p), DK_TM_UTF8, &text)) continue;
        DkJsonError err = {0};
        DkJson *c = dk_json_parse(a, text, &err);
        if (!c) continue;
        if (c->kind != DK_JSON_OBJECT) INTERNAL("claim file %s is not an object", n.p);
        dk_json_set(a, c, DK_S("id"), dk_json_str(a, dk_strn(n.p, n.n - 5)));
        dk_vec_push(&out, c);
    }
    dk_vec_free(&names);
    return out;
}

/* A copy of the claim's members in order, without the member `skip`. */
static DkJson *dict_copy(DkJson *c, const char *skip) {
    DkArena *a = arena();
    DkJson *o = dk_json_obj(a);
    for (size_t i = 0; i < dk_json_len(c); i++) {
        const DkJsonMember *m = dk_json_member(c, i);
        if (skip && dk_str_eqz(m->key, skip)) continue;
        dk_json_set_ref(a, o, m->key, m->val);
    }
    return o;
}

/* save(d, c): the claim without "id", json.dump(indent=1) into a temporary file, then os.replace. */
static bool save(const char *d, DkJson *c) {
    DkArena *a = arena();
    DkJson *body = dict_copy(c, "id");
    char *id = dk_lane_claim_id(a, req_str(body, "session"), req_str(body, "checkout"));
    char *path = dk_path_join(a, d, dk_sprintf(a, "%s.json", id));
    char *tmp = dk_sprintf(a, "%s.%u.tmp", path, (unsigned)dk_getpid());
    DkJsonDumpOpts o = DK_JSON_INDENT(1);
    DkStr text = dk_json_dumps(a, body, &o);
    if (!dk_write_text(tmp, text, DK_TM_UTF8)) return false;
    return dk_replace(tmp, path);
}

/* Mutex: <lane-locks>\.mutex created exclusively around a read-modify-write of the registry. */
typedef struct {
    char *path;
} Mutex;

static Mutex mutex_enter(const char *d) {
    DkArena *a = arena();
    Mutex m = {dk_path_join(a, d, ".mutex")};
    for (int i = 0; i < 100; i++) {
        DkFile *f = dk_fopen(m.path, "xb", DK_TM_UTF8);
        if (f) {
            dk_fclose(f);
            return m;
        }
        if (!dk_io_is(EEXIST)) io_panic();
        double mt;
        if (dk_getmtime(m.path, &mt) && dk_time() - mt > 30) { /* left by a killed process */
            if (dk_remove(m.path)) continue;
        }
        dk_sleep(0.1);
    }
    dk_fatal("lane_lock: %s is held; remove it if no lane_lock is running", m.path);
}

static void mutex_exit(Mutex *m) { dk_remove(m->path); }

/* ---- description, conflicts ------------------------------------------------------------------------------ */

DkStr dk_lane_age(DkArena *a, double s) {
    if (s < 3600) return dk_pyfmt(a, "%dm", (i64)(s / 60));
    return dk_pyfmt(a, "%.1fh", s / 3600);
}

static DkStr age_of(DkJson *c, const char *key) {
    DkJson *t = dk_json_getz(c, key);
    return dk_lane_age(arena(), dk_time() - (t ? num_of(t) : 0.0));
}

/* describe(c) */
static DkStr describe(DkJson *c) {
    DkArena *a = arena();
    DkStr id = req_str(c, "id");
    DkStr session = req_str(c, "session");
    DkStr checkout = req_str(c, "checkout");
    DkJson *branch = dk_json_getz(c, "branch");
    DkStr branch_s = branch ? py_str(branch) : DK_S("-");
    DkStrVec uv = str_list(dk_json_getz(c, "units"));
    DkStr units = uv.n ? join_strs(DK_S(","), &uv) : DK_S("");
    if (!units.n) units = DK_S("-");
    dk_vec_free(&uv);
    DkJson *pid = dk_json_getz(c, "pid");
    DkStr pid_s = dk_json_truthy(pid) ? py_str(pid) : DK_S("-");
    DkJson *host = dk_json_getz(c, "host");
    DkStr host_s = host ? py_str(host) : DK_S("-");
    DkStr tage = age_of(c, "time");
    DkStr hage = age_of(c, "heartbeat");
    DkJson *note = dk_json_getz(c, "note");
    DkStr note_text = dk_json_truthy(note) ? py_str(note) : DK_S("");
    DkStr note_s = dk_json_truthy(note) ? dk_pyfmt(a, " (%S)", &note_text) : DK_S("");
    return dk_pyfmt(a,
        "%S session %S, checkout %S, branch %S, units %S, pid %S on %S, claimed %S ago, heartbeat %S ago%S", &id,
        &session, &checkout, &branch_s, &units, &pid_s, &host_s, &tage, &hage, &note_s);
}

/* sorted(set of lower-cased units) as a vector without duplicates. */
static DkStrVec lower_set(const DkStrVec *units) {
    DkStrVec out = {0};
    if (!units) return out;
    for (size_t i = 0; i < units->n; i++) {
        DkStr l = dk_str_lower(arena(), units->v[i]);
        bool dup = false;
        for (size_t j = 0; j < out.n; j++) dup |= dk_str_eq(out.v[j], l);
        if (!dup) dk_vec_push(&out, l);
    }
    dk_sort_strs(out.v, out.n);
    return out;
}

/* conflicts(claims, session, checkout, units, ttl): the blocking lines and the stale lines. */
static void conflicts(DkJson *const *claims, size_t n, DkStr session, DkStr checkout, const DkStrVec *units,
                      double ttl, DkStrVec *block, DkStrVec *stale) {
    DkArena *a = arena();
    DkStrVec mine_units = lower_set(units);
    for (size_t i = 0; i < n; i++) {
        DkJson *c = claims[i];
        DkStr why = stale_reason(c, ttl);
        bool mine = dk_str_eq(req_str(c, "session"), session);
        bool same = dk_str_eq(claim_checkout_norm(c), checkout);
        DkStrVec cu = str_list(dk_json_getz(c, "units"));
        DkStrVec theirs = lower_set(&cu);
        DkStrVec overlap = {0};
        for (size_t k = 0; k < mine_units.n; k++)
            for (size_t j = 0; j < theirs.n; j++)
                if (dk_str_eq(mine_units.v[k], theirs.v[j])) dk_vec_push(&overlap, mine_units.v[k]);
        dk_sort_strs(overlap.v, overlap.n);
        bool skip = !(same || overlap.n) || (mine && !same);
        if (!skip) {
            if (why.p) {
                DkStr d = describe(c);
                dk_vec_push(stale,
                             dk_pyfmt(a, "stale claim (%S): %S; clear with `lane_lock.exe release --stale`", &why, &d));
            } else if (!mine) {
                DkStr what = same ? DK_S("checkout")
                                   : dk_str_concat(a, DK_S("unit(s) "), join_strs(DK_S(","), &overlap));
                DkStr d = describe(c);
                dk_vec_push(block, dk_pyfmt(a, "held by another session (%S): %S", &what, &d));
            } else {
                DkJson *br = dk_json_getz(c, "branch");
                if (dk_json_truthy(br)) {
                    DkStr claimed = py_str(br);
                    DkStr now = branch_of(dk_cz(a, checkout));
                    if (!dk_str_eq(claimed, now))
                        dk_vec_push(block, dk_pyfmt(a,
                            "this session claimed %S on branch %S but it is on %S now (switched under the claim?); "
                            "re-claim with --branch if that is intended",
                            &checkout, &claimed, &now));
                }
            }
        }
        dk_vec_free(&cu);
        dk_vec_free(&theirs);
        dk_vec_free(&overlap);
    }
    dk_vec_free(&mine_units);
}

/* ---- check ---------------------------------------------------------------------------------------------- */

static void out_print(void *ctx, DkStr line) {
    (void)ctx;
    print_line(line);
}

bool dk_lane_check(const char *checkout, const DkStrVec *units, const char *session_arg, double ttl, DkLaneOut out,
                    void *ctx) {
    DkArena *a = arena();
    if (!out) out = out_print;
    char *top = toplevel(checkout);
    char *d = lock_dir(top);
    DkStr session = my_session(session_arg);
    Mutex mx = mutex_enter(d);
    ClaimVec claims = load(d);
    for (size_t i = 0; i < claims.n; i++) {
        DkJson *c = claims.v[i];
        if (dk_str_eq(req_str(c, "session"), session) && dk_str_eqz(claim_checkout_norm(c), top)) {
            dk_json_set(a, c, DK_S("heartbeat"), dk_json_int(a, (i64)dk_time()));
            if (!save(d, c)) {
                DkStr e = dk_io_err_str(a);
                mutex_exit(&mx);
                INTERNAL("%.*s", DK_SF(e));
            }
        }
    }
    mutex_exit(&mx);
    DkStrVec block = {0}, stale = {0};
    conflicts(claims.v, claims.n, session, dk_str(top), units, ttl, &block, &stale);
    for (size_t i = 0; i < stale.n; i++) out(ctx, dk_str_concat(a, DK_S("lane_lock: "), stale.v[i]));
    for (size_t i = 0; i < block.n; i++) out(ctx, dk_str_concat(a, DK_S("lane_lock: refused: "), block.v[i]));
    bool ok = block.n == 0;
    dk_vec_free(&block);
    dk_vec_free(&stale);
    dk_vec_free(&claims);
    return ok;
}

/* [u.strip() for u in s.split(",") if u.strip()] */
static DkStrVec split_units(DkStr s) {
    DkStrVec parts = dk_str_split(s, DK_S(","), -1), out = {0};
    for (size_t i = 0; i < parts.n; i++) {
        DkStr u = dk_str_strip(parts.v[i]);
        if (u.n) dk_vec_push(&out, u);
    }
    dk_vec_free(&parts);
    return out;
}

/* ---- the sub-commands --------------------------------------------------------------------------------------- */

int dk_lane_cmd_claim(const DkLaneClaimArgs *args) {
    DkArena *a = arena();
    char *top = toplevel(args->checkout);
    char *d = lock_dir(top);
    DkStr session = my_session(args->session);
    bool have_units = args->units != NULL;
    DkStrVec units = have_units ? split_units(dk_str(args->units)) : (DkStrVec){0};
    Mutex mx = mutex_enter(d);
    ClaimVec claims = load(d);
    DkJson *old = NULL;
    for (size_t i = 0; i < claims.n && !old; i++) {
        DkJson *c = claims.v[i];
        if (dk_str_eq(req_str(c, "session"), session) && dk_str_eqz(claim_checkout_norm(c), top)) old = c;
    }
    /* want = units if units is not None else (old or {}).get("units", []) */
    DkJson *want_json;
    if (have_units) {
        want_json = dk_json_arr(a);
        for (size_t i = 0; i < units.n; i++) dk_json_arr_push(a, want_json, dk_json_str(a, units.v[i]));
    } else if (old && dk_json_has(old, DK_S("units"))) {
        want_json = dk_json_getz(old, "units");
    } else {
        want_json = dk_json_arr(a);
    }
    DkStrVec want = str_list(want_json);
    ClaimVec others = {0};
    for (size_t i = 0; i < claims.n; i++)
        if (!dk_str_eq(req_str(claims.v[i], "session"), session)) dk_vec_push(&others, claims.v[i]);
    DkStrVec block = {0}, stale = {0};
    conflicts(others.v, others.n, session, dk_str(top), &want, args->ttl, &block, &stale);
    for (size_t i = 0; i < stale.n; i++) print_line(dk_str_concat(a, DK_S("lane_lock: "), stale.v[i]));
    if (block.n && !args->force) {
        for (size_t i = 0; i < block.n; i++) print_line(dk_str_concat(a, DK_S("lane_lock: refused: "), block.v[i]));
        mutex_exit(&mx);
        return 1;
    }
    i64 now = (i64)dk_time();
    DkJson *c;
    if (old) {
        c = dict_copy(old, NULL);
    } else {
        c = dk_json_obj(a);
        dk_json_set(a, c, DK_S("session"), dk_json_str(a, session));
        dk_json_set(a, c, DK_S("checkout"), dk_json_strz(a, top));
        dk_json_set(a, c, DK_S("time"), dk_json_int(a, now));
    }
    DkStr branch = (args->branch && *args->branch) ? dk_str(args->branch) : branch_of(top);
    /* "pid": my_pid(args.pid) or c.get("pid") */
    i64 pid = my_pid(args->pid_given, args->pid);
    DkJson *pid_json;
    if (pid) {
        pid_json = dk_json_int(a, pid);
    } else {
        pid_json = dk_json_getz(c, "pid");
        if (!pid_json) pid_json = dk_json_null();
    }
    dk_json_set(a, c, DK_S("branch"), dk_json_str(a, branch));
    dk_json_set(a, c, DK_S("units"), want_json);
    dk_json_set(a, c, DK_S("pid"), pid_json);
    dk_json_set(a, c, DK_S("host"), dk_json_strz(a, dk_hostname(a)));
    dk_json_set(a, c, DK_S("heartbeat"), dk_json_int(a, now));
    if (args->note) dk_json_set(a, c, DK_S("note"), dk_json_strz(a, args->note));
    if (!save(d, c)) {
        DkStr e = dk_io_err_str(a);
        mutex_exit(&mx);
        INTERNAL("%.*s", DK_SF(e));
    }
    mutex_exit(&mx);
    dk_json_set(a, c, DK_S("id"), dk_json_strz(a, dk_lane_claim_id(a, session, dk_str(top))));
    DkStr desc = describe(c);
    DkStr what = old ? DK_S("updated") : DK_S("claimed");
    print_line(dk_pyfmt(a, "lane_lock: %S %S", &what, &desc));
    return 0;
}

int dk_lane_cmd_release(const DkLaneReleaseArgs *args) {
    DkArena *a = arena();
    char *top = toplevel(args->checkout);
    char *d = lock_dir(top);
    DkStr session = my_session(args->session);
    ClaimVec gone = {0};
    Mutex mx = mutex_enter(d);
    ClaimVec claims = load(d);
    for (size_t i = 0; i < claims.n; i++) {
        DkJson *c = claims.v[i];
        bool hit;
        if (args->stale) {
            hit = stale_reason(c, args->ttl).p != NULL;
        } else if (args->id && *args->id) {
            hit = dk_str_eqz(req_str(c, "id"), args->id);
        } else {
            hit = dk_str_eq(req_str(c, "session"), session) &&
                  (args->all || dk_str_eqz(claim_checkout_norm(c), top));
        }
        if (hit) {
            char *file = dk_sprintf(a, "%.*s.json", DK_SF(req_str(c, "id")));
            if (!dk_remove(dk_path_join(a, d, file))) {
                DkStr e = dk_io_err_str(a);
                mutex_exit(&mx);
                INTERNAL("%.*s", DK_SF(e));
            }
            dk_vec_push(&gone, c);
        }
    }
    mutex_exit(&mx);
    for (size_t i = 0; i < gone.n; i++) {
        DkStr desc = describe(gone.v[i]);
        print_line(dk_pyfmt(a, "lane_lock: released %S", &desc));
    }
    if (!gone.n) print_line(DK_S("lane_lock: nothing to release"));
    return 0;
}

int dk_lane_cmd_status(const DkLaneStatusArgs *args) {
    DkArena *a = arena();
    char *d = lock_dir(toplevel(args->checkout));
    ClaimVec claims = load(d);
    DkStr me = my_session(args->session);
    print_line(dk_pyfmt(a, "lane_lock: %d claim(s) in %s (this session: %S)", (i64)claims.n, d, &me));
    for (size_t i = 0; i < claims.n; i++) {
        DkJson *c = claims.v[i];
        DkStr why = stale_reason(c, args->ttl);
        char *checkout = dk_cz(a, req_str(c, "checkout"));
        DkStr now = dk_isdir(checkout) ? branch_of(checkout) : DK_S("missing");
        DkJson *br = dk_json_getz(c, "branch");
        DkStr moved = DK_S("");
        if (dk_json_truthy(br)) {
            DkStr claimed = py_str(br);
            if (!dk_str_eq(now, claimed)) moved = dk_pyfmt(a, "; checkout now on %S", &now);
        }
        DkStr tail = moved;
        if (why.p) tail = dk_str_concat(a, dk_pyfmt(a, " [%S]", &why), moved);
        DkStr desc = describe(c);
        DkStr state = why.p ? DK_S("STALE") : DK_S("live");
        print_line(dk_pyfmt(a, "  %-5S %S%S", &state, &desc, &tail));
    }
    return 0;
}

static void out_warning(void *ctx, DkStr line) {
    (void)ctx;
    print_line_err(dk_str_replace(arena(), line, DK_S("refused: "), DK_S("warning: "), -1));
}

int dk_lane_cmd_check(const DkLaneCheckArgs *args) {
    DkStrVec units = split_units(dk_str(args->units ? args->units : ""));
    bool ok = dk_lane_check(args->checkout, &units, args->session, args->ttl, args->hook ? out_warning : NULL, NULL);
    dk_vec_free(&units);
    if (args->hook) return 0;
    if (ok) print_line(DK_S("lane_lock: ok"));
    return ok ? 0 : 1;
}
