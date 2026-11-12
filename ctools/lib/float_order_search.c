// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* float_order search: the search over the spellings of a function's float expressions and the batch over the adapter's body-wall results. Candidate bodies are built through the scorer (scorer.h) on a pool of slots, each ranked by (FScore, extra operations, scorer score); the best body and a frontier of distinct better states are kept, and result.json and up to four state<k>_<tag>.diff files are written under <build_dir>/float_order/<Name>_<address>/. The time budget (--minutes) and the pool decide how far a run gets: only the deterministic modes (--tree-only, --selftest, the error paths, a search that ends before its budget) are reproducible. */
#include "float_order.h"

#include "dk/args.h"
#include "dk/difflib.h"
#include "dk/fmt.h"
#include "dk/fs.h"
#include "dk/pool.h"
#include "dk/re.h"
#include "dk/sort.h"
#include "priority.h"
#include "unitcmp.h"

#define RE(p) dk_re((p), 0)

static DkStr S(const char *z) { return dk_str(z); }

static bool g_quiet;
static const char *g_root;       /* the project root */
static const char *g_out_root;   /* <build_dir>/float_order */
#define PRINT(...)                                                \
    do {                                                          \
        DkStr t_ = dk_pyfmt(dk_arena(), __VA_ARGS__);          \
        dk_pyprintf("%s\n", t_.p);                               \
    } while (0)
#define LOG(...)                    \
    do {                            \
        if (!g_quiet) PRINT(__VA_ARGS__); \
    } while (0)

/* ----------------------------------------------------------------------------------------------- helpers */

static char *dupv(DkStr s) { return dk_cz(dk_arena(), s); }

static char *fmt_(DK_PRINTF_FMT const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *r = dk_vsprintf(dk_arena(), fmt, ap);
    va_end(ap);
    return r;
}

/* write(path, text) as open(path, "w", encoding="utf-8") (CRLF) / newline="\n" (LF); a failure is an OSError traceback. */
static void write_crlf(const char *path, DkStr text) {
    if (!dk_write_text(path, text, DK_TM_UTF8)) dk_panic(__FILE__, __LINE__, "cannot write %s", path);
}
static void write_lf(const char *path, DkStr text) {
    if (!dk_write_text(path, text, DK_TM_UTF8_NL_LF)) dk_panic(__FILE__, __LINE__, "cannot write %s", path);
}

/* os.path.relpath(path, ROOT) (backslashes) and .replace("\\", "/") */
static const char *relpath_native(const char *path) {
    char *rel = NULL;
    if (!dk_path_relpath(dk_arena(), path, g_root, &rel)) return path;
    return rel;
}
static const char *rel_root(const char *path) {
    DkArena *a = dk_arena();
    return dk_cz(a, dk_str_replace(a, S(relpath_native(path)), S("\\"), S("/"), -1));
}

/* "\n".join(lines) */
static DkStr join_nl(DkBuf *b, const DkCzVec *lines) {
    for (size_t i = 0; i < lines->n; i++) {
        if (i) dk_buf_putc(b, '\n');
        dk_buf_putz(b, lines->v[i]);
    }
    return dk_buf_str(b);
}

static char *join_key(const DkCzVec *lines) {
    DkBuf b = {0};
    join_nl(&b, lines);
    char *r = dk_strdup(dk_arena(), b.p ? b.p : "");
    dk_buf_free(&b);
    return r;
}

static char *join_notes(const DkCzVec *notes) {
    DkBuf b = {0};
    for (size_t i = 0; i < notes->n; i++) {
        if (i) dk_buf_putz(&b, "; ");
        dk_buf_putz(&b, notes->v[i]);
    }
    char *r = dk_strdup(dk_arena(), b.p ? b.p : "");
    dk_buf_free(&b);
    return r;
}

static DkCzVec vec_copy(const DkCzVec *v) {
    DkCzVec c = {0};
    if (v->n) dk_vec_extend(&c, v->v, v->n);
    return c;
}

static DkCzVec vec_slice(const DkCzVec *v, size_t from, size_t to) {
    DkCzVec c = {0};
    for (size_t i = from; i < to && i < v->n; i++) dk_vec_push(&c, v->v[i]);
    return c;
}

/* The contents of a file as lines split on "\n" (open(..).read().split("\n"), universal newlines). */
static DkCzVec read_lines_nl(const char *path) {
    DkStr text;
    if (!dk_read_text(dk_arena(), path, DK_TM_UTF8, &text)) dk_panic(__FILE__, __LINE__, "cannot read %s", path);
    DkStrVec parts = dk_str_split(text, DK_S("\n"), -1);
    DkCzVec lines = {0};
    for (size_t i = 0; i < parts.n; i++) dk_vec_push(&lines, dupv(parts.v[i]));
    dk_vec_free(&parts);
    return lines;
}

/* The candidate unit: "\n".join(head + body + tail) + "\n", written with newline="\n". */
static void write_unit(const char *path, const DkCzVec *head, const DkCzVec *body, const DkCzVec *tail) {
    DkBuf b = {0};
    const DkCzVec *parts[3] = {head, body, tail};
    bool first = true;
    for (int q = 0; q < 3; q++)
        for (size_t i = 0; i < parts[q]->n; i++) {
            if (!first) dk_buf_putc(&b, '\n');
            dk_buf_putz(&b, parts[q]->v[i]);
            first = false;
        }
    dk_buf_putc(&b, '\n');
    write_lf(path, dk_buf_str(&b));
    dk_buf_free(&b);
}

static const char *tuple3(const i64 f[3]) { return fmt_("(%lld, %lld, %lld)", (long long)f[0], (long long)f[1], (long long)f[2]); }

/* ----------------------------------------------------------------------------------------------- ranks */

/* (FScore, extra, Score): compared lexicographically. */
typedef struct Rank {
    i64 f[3];
    i64 extra;
    DkScore score;
} Rank;

static int rank_cmp(const Rank *a, const Rank *b) {
    for (int i = 0; i < 3; i++)
        if (a->f[i] != b->f[i]) return a->f[i] < b->f[i] ? -1 : 1;
    if (a->extra != b->extra) return a->extra < b->extra ? -1 : 1;
    return dk_score_cmp(a->score, b->score);
}

static const char *score_tuple(DkScore s) {
    return fmt_("(%lld, %lld, %lld)", (long long)s.status, (long long)s.differ, (long long)s.dissim);
}

/* repr of ((a, b, c), extra, (s, m, t, d)) */
static const char *rank_repr(const Rank *r) { return fmt_("(%s, %lld, %s)", tuple3(r->f), (long long)r->extra, score_tuple(r->score)); }

/* ---------------------------------------------------------------------------------------------- JSON helpers */

static DkJson *jstr(const char *z) { return dk_json_strz(dk_arena(), z); }
static DkJson *jint(i64 v) { return dk_json_int(dk_arena(), v); }
static DkJson *jf3(const i64 f[3]) {
    DkArena *a = dk_arena();
    DkJson *l = dk_json_arr(a);
    for (int i = 0; i < 3; i++) dk_json_arr_push(a, l, jint(f[i]));
    return l;
}
static DkJson *jscore(DkScore s) {
    DkArena *a = dk_arena();
    DkJson *l = dk_json_arr(a);
    dk_json_arr_push(a, l, jint(s.status));
    dk_json_arr_push(a, l, jint(s.differ));
    dk_json_arr_push(a, l, jint(s.dissim));
    return l;
}
static DkJson *jbase(const i64 f[3], DkScore s) {
    DkArena *a = dk_arena();
    DkJson *l = dk_json_arr(a);
    dk_json_arr_push(a, l, jf3(f));
    dk_json_arr_push(a, l, jscore(s));
    return l;
}
static DkJson *jclasses(const u8 *classes, size_t n) {
    DkArena *a = dk_arena();
    i64 c[4] = {0, 0, 0, 0};
    for (size_t i = 0; i < n; i++) c[classes[i]]++;
    DkJson *o = dk_json_obj(a);
    for (int k = 0; k < 4; k++) dk_json_set(a, o, S(FO_CLASS_NAMES[k]), jint(c[k]));
    return o;
}
static DkJson *jstrs(const DkCzVec *v) {
    DkArena *a = dk_arena();
    DkJson *l = dk_json_arr(a);
    for (size_t i = 0; i < v->n; i++) dk_json_arr_push(a, l, jstr(v->v[i]));
    return l;
}
#define JSET(obj, key, val) dk_json_set(dk_arena(), (obj), S(key), (val))

static void dump_indent1(const char *path, const DkJson *v) {
    DkJsonDumpOpts o = DK_JSON_INDENT(1);
    write_crlf(path, dk_json_dumps(dk_arena(), v, &o));
}

/* ------------------------------------------------------------------------------------------ the search */

typedef struct Entry { /* an evaluated candidate (the dict evaluate() returned) */
    int state;         /* 0: False (past the deadline), 1: None (did not compile / no symbol), 2: a result */
    Rank rank;
    DkScore score;
    u8 *classes;
    size_t n_classes;
    DkIMap *osig;     /* Counter {ordered signature: n (.i)} */
    const char *key;
} Entry;

typedef struct Front { /* frontier[k] = (rank, notes, body) */
    Rank rank;
    DkCzVec notes, body;
} Front;

typedef struct KSite {
    int k;
    FoSite s;
} KSite;
typedef DK_VEC(KSite) KSiteVec;

typedef struct Search {
    FloatOrderArgs *args;
    DkScorer *scorer;
    const char *unit, *out;
    DkCzVec head, body0, tail, tail_used;
    const char **workdirs;
    int n_workers;
    /* the free work folders */
    DkMutex free_lock;
    DkCond free_cond;
    int *free_stack;
    int n_free;
    FoTree *game_tree;
    Rank base_rank;
    i64 base_f[3], base_x;
    DkScore base_score;
    u8 *base_classes;
    DkIMap *base_osig;
    DkISet *all_osigs;
    DkMutex lock;
    i64 tried, failed;
    volatile double deadline;
    /* best */
    Rank best_rank;
    DkCzVec best_body, best_notes;
    u8 *best_classes;
    DkMap *frontier;      /* {state key: Front*} */
    DkSet *seen;
    unsigned allowed;
    DkSet *float_names;
    DkISet *only;
    KSiteVec sensitive, insensitive;
    KSiteVec sites0;
    DkPool *pool;
} Search;

/* Builds and scores the candidate at src in builder slot `slot`; false when it does not build. */
static bool eval_source(Search *S_, int slot, const char *src, DkScored *out) {
    DkErr err = {0};
    return dk_scorer_evaluate(S_->scorer, slot, src, out, NULL, &err);
}

static int free_get(Search *s) {
    dk_mutex_lock(&s->free_lock);
    while (s->n_free == 0) dk_cond_wait(&s->free_cond, &s->free_lock, -1);
    int w = s->free_stack[--s->n_free];
    dk_mutex_unlock(&s->free_lock);
    return w;
}

static void free_put(Search *s, int w) {
    dk_mutex_lock(&s->free_lock);
    s->free_stack[s->n_free++] = w;
    dk_mutex_unlock(&s->free_lock);
    dk_cond_signal(&s->free_cond);
}

/* The relocated bytes of a function as a bitmap (rbytes.update(range(r.offset, r.offset + 4))). */
static u8 *reloc_bitmap(const DkScored *fn, size_t *n) {
    size_t len = fn->code.n + 8;
    for (size_t i = 0; i < fn->n_relocs; i++)
        if ((size_t)fn->reloc_offsets[i] + 4 > len) len = (size_t)fn->reloc_offsets[i] + 4;
    u8 *bm = dk_xcalloc(len, 1);
    for (size_t i = 0; i < fn->n_relocs; i++)
        for (u32 k = 0; k < 4; k++) bm[fn->reloc_offsets[i] + k] = 1;
    *n = len;
    return bm;
}

static DkIMap *osig_of(const FoTree *t) {
    DkIMap *m = dk_imap_new();
    for (size_t i = 0; i < t->interesting.n; i++) dk_imap_put(m, fo_ordered(t->interesting.v[i]), NULL)->i += 1;
    return m;
}

static bool counter_eq(const DkIMap *a, const DkIMap *b) {
    if (dk_imap_len(a) != dk_imap_len(b)) return false;
    DkIMapIter it = {0};
    while (dk_imap_next(a, &it)) {
        DkVal *v = dk_imap_get(b, it.key);
        if (!v || v->i != it.val->i) return false;
    }
    return true;
}

static void entry_free(Entry *e) {
    dk_xfree(e->classes);
    if (e->osig) dk_imap_free(e->osig);
    memset(e, 0, sizeof *e);
}

/* evaluate(body) */
static void evaluate(Search *s, const DkCzVec *body, Entry *res) {
    memset(res, 0, sizeof *res);
    if (dk_time() > s->deadline) {
        res->state = 0;
        return;
    }
    int w = free_get(s);
    const char *src = dk_path_join(dk_arena(), s->workdirs[w], dupv(dk_path_basename(s->unit)));
    write_unit(src, &s->head, body, &s->tail_used);
    DkScored sd;
    bool got = eval_source(s, w, src, &sd);
    free_put(s, w);
    dk_mutex_lock(&s->lock);
    s->tried++;
    if (!got) {
        s->failed++;
        dk_mutex_unlock(&s->lock);
        res->state = 1;
        return;
    }
    dk_mutex_unlock(&s->lock);
    DkScore score = sd.score;
    size_t nrb;
    u8 *rb = reloc_bitmap(&sd, &nrb);
    DkArena *sc = dk_scratch();
    DkArenaMark mark = dk_arena_mark(sc);
    FoTree *tr = fo_float_tree(sc, sd.code, s->scorer->address, rb, nrb);
    dk_xfree(rb);
    size_t ng = s->game_tree->interesting.n;
    u8 *classes = dk_xcalloc(ng ? ng : 1, 1), *used = dk_xcalloc(tr->interesting.n ? tr->interesting.n : 1, 1);
    fo_match_nodes(s->game_tree, tr, classes, used);
    dk_xfree(used);
    DkIMap *osig = osig_of(tr);
    i64 extra = fo_extra_ops(s->game_tree, tr);
    dk_mutex_lock(&s->lock);
    DkIMapIter it = {0};
    while (dk_imap_next(osig, &it)) dk_iset_add(s->all_osigs, it.key);
    dk_mutex_unlock(&s->lock);
    fo_tree_free(tr);
    dk_arena_reset(sc, mark);
    res->state = 2;
    fo_fscore(classes, ng, res->rank.f);
    res->rank.extra = extra;
    res->rank.score = score;
    res->score = score;
    res->classes = classes;
    res->n_classes = ng;
    res->osig = osig;
    res->key = sd.key;
    dk_scored_free(&sd);
}

static int eval_job(void *ctx, size_t index, const void *item, void *result) {
    DK_UNUSED(index);
    evaluate(ctx, item, result);
    return 0;
}

static Entry *run_bodies(Search *s, const DkCzVec *bodies, size_t n) {
    Entry *res = DK_NEWN(dk_arena(), Entry, n ? n : 1);
    if (n) dk_pool_map(s->pool, s->n_workers, eval_job, s, bodies, n, sizeof(DkCzVec), res, sizeof(Entry));
    return res;
}

static Front *front_new(const Rank *rank, const DkCzVec *notes, const DkCzVec *body) {
    Front *f = DK_NEW(dk_arena(), Front);
    f->rank = *rank;
    f->notes = vec_copy(notes);
    f->body = *body;
    return f;
}

static void front_set(Search *s, const char *key, const Rank *rank, const DkCzVec *notes, const DkCzVec *body) {
    dk_map_put(s->frontier, S(key), NULL)->p = front_new(rank, notes, body);
}

/* consider(res, body, notes): True when it is a new best. */
static bool consider(Search *s, const Entry *res, const DkCzVec *body, const DkCzVec *notes) {
    if (res->state == 2 && rank_cmp(&res->rank, &s->base_rank) < 0) {
        DkVal *fv = dk_map_get(s->frontier, S(res->key));
        if (!fv || rank_cmp(&res->rank, &((Front *)fv->p)->rank) < 0) front_set(s, res->key, &res->rank, notes, body);
    }
    if (res->state == 2 && rank_cmp(&res->rank, &s->best_rank) < 0) {
        s->best_rank = res->rank;
        s->best_body = *body;
        s->best_notes = vec_copy(notes);
        dk_xfree(s->best_classes);
        s->best_classes = dk_xmalloc(res->n_classes ? res->n_classes : 1);
        memcpy(s->best_classes, res->classes, res->n_classes);
        LOG("  %s extra %d %s (%s)", tuple3(res->rank.f), res->rank.extra, dk_score_str(res->rank.score), join_notes(notes));
        if (dk_score_exact(res->score)) {
            double d = dk_time() + 30;
            if (d < s->deadline) s->deadline = d;
        }
        return true;
    }
    return false;
}

/* float_names_of(signature, body) */
static DkSet *float_names_of(DkStr signature, const DkCzVec *body) {
    DkBuf b = {0};
    dk_buf_put(&b, signature);
    dk_buf_putc(&b, '\n');
    join_nl(&b, body);
    DkSet *names = dk_set_new();
    DkReIter it;
    DkReMatch m;
    DkStr text = dk_buf_str(&b);
    dk_re_iter_init(&it, RE("\\b(?:float|double|Vector\\d?|Vec\\w*|Matrix\\w*|Quat\\w*)\\b[\\s*&]*(\\w+)"), text, 0, DK_END);
    while (dk_re_iter_next(&it, &m)) dk_set_add(names, dk_str_dup(dk_arena(), dk_re_group(&m, 1)));
    dk_buf_free(&b);
    return names;
}

/* allowed_for(classes) */
static unsigned allowed_for(const u8 *classes, size_t n) {
    i64 f[3];
    fo_fscore(classes, n, f);
    if (f[0]) return FO_ALL_MOVES;
    if (f[1]) return FOM_COMMUTE | FOM_ASSOC | FOM_SUMORDER | FOM_SIGN;
    return FOM_COMMUTE;
}

/* site_list(body, float_names, only, big_ok): [(k, site)] */
static KSiteVec site_list(const DkCzVec *body, const DkSet *names, const DkISet *only, bool big_ok) {
    KSiteVec out = {0};
    FoStmtVec stmts = fo_group_statements(body);
    for (size_t k = 0; k < stmts.n; k++) {
        if (only && !dk_iset_has(only, k)) continue;
        FoStmtInfo info = fo_parse_stmt(stmts.v[k].text);
        FoSiteVec sites = fo_find_sites(stmts.v[k].text, &info, names);
        for (size_t i = 0; i < sites.n; i++) {
            if (sites.v[i].leaves > 8 && !big_ok) continue;
            KSite ks = {(int)k, sites.v[i]};
            dk_vec_push(&out, ks);
        }
        dk_vec_free(&sites);
        dk_vec_free(&info.roots);
    }
    dk_vec_free(&stmts);
    return out;
}

/* apply_site(body, k, text, nth, new): the body with the site rewritten, or false. */
static bool apply_site(const DkCzVec *body, int k, DkStr text, int nth, DkStr new_, DkCzVec *out) {
    FoStmtVec stmts = fo_group_statements(body);
    if ((size_t)k >= stmts.n) {
        dk_vec_free(&stmts);
        return false;
    }
    FoStmt st = stmts.v[k];
    dk_vec_free(&stmts);
    FoStmtInfo info = fo_parse_stmt(st.text);
    FoSiteVec sites = fo_find_sites(st.text, &info, NULL);
    bool found = false;
    for (size_t i = 0; i < sites.n && !found; i++) {
        const FoSite *s = &sites.v[i];
        if (dk_str_eq(s->text, text) && s->nth == nth) {
            DkBuf b;
            dk_buf_init(&b, dk_arena());
            dk_buf_put(&b, dk_str_slice(st.text, 0, s->s));
            dk_buf_put(&b, new_);
            dk_buf_put(&b, dk_str_slice(st.text, s->e, DK_END));
            DkStr line = dk_buf_str(&b);
            /* with_statement(body, st, [line]) */
            DkStr first = S(body->v[st.lo]);
            DkStr ind = dk_strn(first.p, first.n - dk_str_lstrip(first).n);
            DkStr tail = {"", 0};
            if (st.lo == st.hi) {
                DkReMatch m;
                if (dk_re_search(RE("\\s*//.*$"), first, 0, DK_END, &m)) tail = dk_re_group(&m, 0);
            }
            DkCzVec r = {0};
            for (i64 q = 0; q < st.lo; q++) dk_vec_push(&r, body->v[q]);
            DkBuf nb;
            dk_buf_init(&nb, dk_arena());
            dk_buf_put(&nb, ind);
            dk_buf_put(&nb, line);
            dk_buf_put(&nb, tail);
            dk_vec_push(&r, dk_buf_cz(&nb));
            for (size_t q = (size_t)st.hi + 1; q < body->n; q++) dk_vec_push(&r, body->v[q]);
            *out = r;
            found = true;
        }
    }
    dk_vec_free(&sites);
    dk_vec_free(&info.roots);
    return found;
}

typedef struct Cand {
    DkCzVec body;
    const char *note;
} Cand;
typedef DK_VEC(Cand) CandVec;

static const char *stmt_note(int k, const char *text, const FoPath *path) { return fmt_("stmt %d: %s [%s]", k, text, fo_path_text(path)); }

static DkCzVec notes_plus(const DkCzVec *notes, const char *note) {
    DkCzVec n = vec_copy(notes);
    dk_vec_push(&n, (char *)note);
    return n;
}

static DkCzVec notes_one(const char *note) {
    DkCzVec n = {0};
    dk_vec_push(&n, (char *)note);
    return n;
}

static DkCzVec *bodies_of(const CandVec *c) {
    DkCzVec *b = DK_NEWN(dk_arena(), DkCzVec, c->n ? c->n : 1);
    for (size_t i = 0; i < c->n; i++) b[i] = c->v[i].body;
    return b;
}

/* probe (phase B) */
static void probe(Search *s) {
    s->sensitive.n = 0;
    s->insensitive.n = 0;
    KSiteVec ordered_sites = {0};
    for (size_t i = 0; i < s->sites0.n; i++)
        if (s->sites0.v[i].s.hint) dk_vec_push(&ordered_sites, s->sites0.v[i]);
    for (size_t i = 0; i < s->sites0.n; i++)
        if (!s->sites0.v[i].s.hint) dk_vec_push(&ordered_sites, s->sites0.v[i]);
    for (size_t si = 0; si < ordered_sites.n; si++) {
        const KSite *ks = &ordered_sites.v[si];
        if (dk_time() > s->deadline) break;
        FoSpellingVec sp = fo_spellings(ks->s.tree, 6, s->allowed, ks->s.hint, ks->s.paren);
        CandVec bodies = {0};
        for (size_t i = 0; i < sp.n; i++) {
            DkCzVec b;
            if (apply_site(&s->body0, ks->k, ks->s.text, ks->s.nth, S(sp.v[i].text), &b)) {
                Cand c = {b, stmt_note(ks->k, sp.v[i].text, sp.v[i].path)};
                dk_vec_push(&bodies, c);
            }
        }
        DkCzVec *bs = bodies_of(&bodies);
        Entry *res = run_bodies(s, bs, bodies.n);
        bool changed = false;
        for (size_t i = 0; i < bodies.n; i++) {
            Entry *r = &res[i];
            if (r->state == 2) {
                changed |= !counter_eq(r->osig, s->base_osig);
                DkCzVec notes = notes_one(bodies.v[i].note);
                consider(s, r, &bodies.v[i].body, &notes);
            }
            dk_set_add(s->seen, S(join_key(&bodies.v[i].body)));
            entry_free(r);
        }
        dk_vec_push(changed ? &s->sensitive : &s->insensitive, *ks);
        dk_vec_free(&sp);
        dk_vec_free(&bodies);
    }
    dk_vec_free(&ordered_sites);
    LOG("%d sites, %d sensitive", (int)s->sites0.n, (int)s->sensitive.n);
}

/* site_pass (phase C) */
static bool site_pass(Search *s) {
    bool improved = false;
    KSiteVec now = site_list(&s->best_body, s->float_names, s->only, s->args->line != 0);
    for (size_t ni = 0; ni < now.n; ni++) {
        const KSite *ks = &now.v[ni];
        if (dk_time() > s->deadline) break;
        bool matched = false;
        for (size_t j = 0; j < s->sensitive.n; j++) {
            const KSite *k2 = &s->sensitive.v[j];
            if (ks->k == k2->k && (ks->s.tree == k2->s.tree || dk_str_eq(ks->s.text, k2->s.text))) matched = true;
        }
        if (!matched && s->sensitive.n) continue;
        FoSpellingVec sp = fo_spellings(ks->s.tree, (size_t)s->args->max_site, s->allowed, ks->s.hint, ks->s.paren);
        CandVec bodies = {0};
        for (size_t i = 0; i < sp.n; i++) {
            DkCzVec b;
            if (!apply_site(&s->best_body, ks->k, ks->s.text, ks->s.nth, S(sp.v[i].text), &b)) continue;
            char *key = join_key(&b);
            if (dk_set_has(s->seen, S(key))) {
                dk_vec_free(&b);
                continue;
            }
            dk_set_add(s->seen, S(key));
            Cand c = {b, stmt_note(ks->k, sp.v[i].text, sp.v[i].path)};
            dk_vec_push(&bodies, c);
        }
        DkCzVec *bs = bodies_of(&bodies);
        Entry *res = run_bodies(s, bs, bodies.n);
        DkCzVec cur_notes = vec_copy(&s->best_notes);
        int round_best = -1;
        for (size_t i = 0; i < bodies.n; i++) {
            Entry *r = &res[i];
            if (r->state != 2) continue;
            if (rank_cmp(&r->rank, &s->base_rank) < 0) {
                DkVal *fv = dk_map_get(s->frontier, S(r->key));
                if (!fv || rank_cmp(&r->rank, &((Front *)fv->p)->rank) < 0) {
                    DkCzVec n2 = notes_plus(&cur_notes, bodies.v[i].note);
                    front_set(s, r->key, &r->rank, &n2, &bodies.v[i].body);
                }
            }
            if (rank_cmp(&r->rank, &s->best_rank) < 0 && (round_best < 0 || rank_cmp(&r->rank, &res[round_best].rank) < 0))
                round_best = (int)i;
        }
        if (round_best >= 0) {
            DkCzVec n2 = notes_plus(&cur_notes, bodies.v[round_best].note);
            consider(s, &res[round_best], &bodies.v[round_best].body, &n2);
            improved = true;
        }
        for (size_t i = 0; i < bodies.n; i++) entry_free(&res[i]);
        dk_vec_free(&sp);
        dk_vec_free(&bodies);
    }
    dk_vec_free(&now);
    return improved;
}

/* stmt_pass */
static bool stmt_pass(Search *s) {
    bool improved = false;
    FoVariantVec vars = fo_stmt_variants(&s->best_body, s->only);
    CandVec bodies = {0};
    for (size_t i = 0; i < vars.n; i++) {
        char *key = join_key(&vars.v[i].body);
        if (dk_set_has(s->seen, S(key))) continue;
        dk_set_add(s->seen, S(key));
        Cand c = {vars.v[i].body, vars.v[i].note};
        dk_vec_push(&bodies, c);
    }
    DkCzVec *bs = bodies_of(&bodies);
    Entry *res = run_bodies(s, bs, bodies.n);
    DkCzVec cur = vec_copy(&s->best_notes);
    int top = -1;
    for (size_t i = 0; i < bodies.n; i++) {
        Entry *r = &res[i];
        if (r->state != 2) continue;
        if (rank_cmp(&r->rank, &s->best_rank) < 0 && (top < 0 || rank_cmp(&r->rank, &res[top].rank) < 0)) top = (int)i;
        if (rank_cmp(&r->rank, &s->base_rank) < 0 && !dk_map_has(s->frontier, S(r->key))) {
            DkCzVec n2 = notes_plus(&cur, bodies.v[i].note);
            front_set(s, r->key, &r->rank, &n2, &bodies.v[i].body);
        }
    }
    if (top >= 0) {
        DkCzVec n2 = notes_plus(&cur, bodies.v[top].note);
        consider(s, &res[top], &bodies.v[top].body, &n2);
        improved = true;
    }
    for (size_t i = 0; i < bodies.n; i++) entry_free(&res[i]);
    dk_vec_free(&bodies);
    dk_vec_free(&vars);
    return improved;
}

static void descend(Search *s) {
    while (dk_time() < s->deadline) {
        bool a = site_pass(s);
        bool b = dk_time() < s->deadline ? stmt_pass(s) : false;
        if (!(a || b)) break;
    }
}

/* out_dir(name, address) */
static const char *out_dir(DkStr name, u32 address) {
    DkArena *a = dk_arena();
    DkStr n = dk_re_sub(a, RE("\\W+"), S("_"), name, 0);
    n = dk_str_strip_chars(n, S("_"));
    return dk_path_join(a, g_out_root,
                         fmt_("%.*s_%08X", DK_SF(n), address));
}

typedef struct SearchEnv {
    DkJson *result;
    const char *out;
    double t0;
    const char *const *workdirs;
    int n_workers;
} SearchEnv;

static int finish(SearchEnv *e, const char *status) {
    JSET(e->result, "status", jstr(status));
    JSET(e->result, "seconds", dk_json_float(dk_arena(), dk_py_round(dk_time() - e->t0, 1)));
    dump_indent1(dk_path_join(dk_arena(), e->out, "result.json"), e->result);
    for (int w = 0; w < e->n_workers; w++) dk_rmtree(e->workdirs[w], DK_RMTREE_IGNORE_ERRORS);
    return 0;
}

static int cmp_front_ptr(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    const Front *a = *(Front *const *)x, *b = *(Front *const *)y;
    int c = rank_cmp(&a->rank, &b->rank);
    if (c) return c;
    return a->notes.n < b->notes.n ? -1 : a->notes.n > b->notes.n ? 1 : 0;
}

typedef struct Unreached {
    size_t len;
    const char *text;
} Unreached;
static int cmp_unreached(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    const Unreached *a = x, *b = y;
    if (a->len != b->len) return a->len < b->len ? -1 : 1;
    return dk_str_cmp(S(a->text), S(b->text));
}

typedef struct Body {
    const char *signature;
    i64 first, last; /* 0-based line indexes of the lines inside the braces */
} Body;

/* The lines of annotation an inside its braces: the declaration starts at an->body_start, the first "{" opens the
 * body, an->body_end is the line of the closing "}". The braces are on lines of their own (the usual layout). */
static bool find_body(const DkCzVec *lines, const DkAnnot *an, Body *out, const char **why) {
    size_t i = (size_t)an->body_start - 1;
    while (i < lines->n && !strchr(lines->v[i], '{')) i++;
    size_t close = (size_t)an->body_end - 1;
    if (i >= lines->n || close >= lines->n || close <= i) {
        *why = "the function body is not delimited by braces";
        return false;
    }
    const char *open = strchr(lines->v[i], '{');
    DkStr after = dk_str_strip(S(open + 1));
    DkStr before_close = dk_str_strip(S(lines->v[close]));
    if (after.n || !dk_str_eqz(before_close, "}")) {
        *why = "the braces of the function share a line with code";
        return false;
    }
    DkBuf b = {0};
    for (size_t k = (size_t)an->body_start - 1; k <= i; k++) {
        if (k > (size_t)an->body_start - 1) dk_buf_putc(&b, '\n');
        dk_buf_putz(&b, lines->v[k]);
    }
    out->signature = dk_strdup(dk_arena(), b.p ? b.p : "");
    dk_buf_free(&b);
    out->first = (i64)i + 1;
    out->last = (i64)close - 1;
    return true;
}

static int search_fail(const char *fmt, const char *a1, const char *a2) {
    fprintf(stderr, "float_order: ");
    fprintf(stderr, fmt, a1, a2);
    fprintf(stderr, "\n");
    return 2;
}

static const DkUnit *find_unit(DkProject *p, const char *spec) {
    const DkUnit *u = dk_project_unit(p, spec);
    if (u) return u;
    char *rel = NULL;
    DkArena *a = dk_arena();
    if (dk_path_relpath(a, dk_path_abspath(a, spec), dk_project_root(p), &rel)) {
        for (char *c = rel; *c; c++)
            if (*c == '\\') *c = '/';
        return dk_project_unit(p, rel);
    }
    return NULL;
}

int float_order_search(FloatOrderArgs *args) {
    DkArena *a = dk_arena();
    DkProject *proj = args->project;
    g_root = dk_project_root(proj);
    g_out_root = dk_project_build_dir(proj, "float_order");
    const DkUnit *udef = find_unit(proj, args->unit);
    if (!udef) return search_fail("%s: not a unit of the project%s", args->unit, "");
    const char *unit = dk_project_path(a, proj, udef->path);
    u32 want_address = 0;
    if (args->address) {
        i64 v;
        if (!dk_parse_int(S(args->address), 16, &v, NULL))
            return search_fail("--address %s: not a hex number%s", args->address, "");
        want_address = (u32)v;
    }
    int target = -1;
    DkErr err = {0};
    const DkAnnot *ann = NULL;
    for (size_t t = 0; t < dk_project_ntargets(proj); t++) {
        if (args->target && strcmp(args->target, dk_project_target(proj, (int)t)->name) != 0) continue;
        DkErr e = {0};
        ann = dk_scorer_select(proj, udef, args->name, want_address, (int)t, &e);
        if (ann) {
            target = (int)t;
            break;
        }
        err = e;
    }
    if (!ann) return search_fail("%s", err.msg[0] ? err.msg : "no such function", "");
    const char *tname = dk_project_target(proj, target)->name;
    DkCzVec lines = read_lines_nl(unit);
    Body pb;
    const char *why = NULL;
    if (!find_body(&lines, ann, &pb, &why)) return search_fail("%s: %s", ann->name, why);
    int n_workers = (int)DK_MAX(1, args->workers);
    const char *out = out_dir(S(ann->name), ann->addr[target]);
    if (dk_isdir(out)) {
        DkStrVec names;
        memset(&names, 0, sizeof names);
        if (dk_listdir(a, out, &names)) {
            for (size_t i = 0; i < names.n; i++)
                if (dk_str_endswith(names.v[i], DK_S(".diff")) || dk_str_eqz(names.v[i], "result.json"))
                    dk_remove(dk_path_join(a, out, dupv(names.v[i])));
        }
    }
    dk_makedirs(out, true);
    DkScorer *scorer = dk_scorer_new(proj, udef, ann, target, n_workers, dk_path_join(a, out, "b"), &err);
    if (!scorer) return search_fail("%s", err.msg, "");
    const char *name = dupv(S(scorer->name));
    Search *s = DK_NEW(a, Search);
    s->args = args;
    s->scorer = scorer;
    s->unit = unit;
    s->head = vec_slice(&lines, 0, (size_t)pb.first);
    s->body0 = vec_slice(&lines, (size_t)pb.first, (size_t)pb.last + 1);
    s->tail = vec_slice(&lines, (size_t)pb.last + 1, lines.n);
    s->out = out;
    const char **workdirs = DK_NEWN(a, const char *, n_workers);
    for (int w = 0; w < n_workers; w++) {
        workdirs[w] = dk_path_join(a, out, fmt_("w%d", w));
        dk_makedirs(workdirs[w], true);
    }
    s->workdirs = workdirs;
    s->n_workers = n_workers;
    g_quiet = args->quiet;
    double t0 = dk_time();
    DkJson *result = dk_json_obj(a);
    JSET(result, "unit", jstr(rel_root(unit)));
    JSET(result, "name", jstr(name));
    JSET(result, "target", jstr(tname));
    JSET(result, "address", jstr(fmt_("%08X", scorer->address)));
    JSET(result, "stop", ann->stop_reason && (ann->stop_mask >> target & 1) ? dk_json_str(a, S(ann->stop_reason)) : dk_json_null());
    JSET(result, "states", dk_json_arr(a));
    SearchEnv env = {result, out, t0, workdirs, n_workers};

    DkScored full;
    DkStr clog = {"", 0};
    if (!dk_scorer_evaluate(scorer, 0, unit, &full, &clog, &err)) {
        JSET(result, "error", jstr(err.msg[0] ? err.msg : "the unit does not compile"));
        return finish(&env, "error");
    }
    size_t nrb;
    u8 *rbytes = reloc_bitmap(&full, &nrb);
    FoTree *game_tree = fo_float_tree(a, scorer->game, scorer->address, NULL, 0);
    FoTree *our_tree = fo_float_tree(a, full.code, scorer->address, rbytes, nrb);
    s->game_tree = game_tree;
    size_t ng = game_tree->interesting.n;
    u8 *base_classes = dk_xcalloc(ng ? ng : 1, 1), *used = dk_xcalloc(our_tree->interesting.n ? our_tree->interesting.n : 1, 1);
    fo_match_nodes(game_tree, our_tree, base_classes, used);
    dk_xfree(used);
    fo_fscore(base_classes, ng, s->base_f);
    s->base_x = fo_extra_ops(game_tree, our_tree);
    DkScore base_score = full.score;
    s->base_score = base_score;
    s->base_classes = base_classes;
    {
        DkJson *gn = dk_json_obj(a);
        JSET(gn, "before", jclasses(base_classes, ng));
        JSET(result, "reference_nodes", gn);
    }
    DkStr signature = S(pb.signature);
    s->float_names = float_names_of(signature, &s->body0);
    bool f000 = s->base_f[0] == 0 && s->base_f[1] == 0 && s->base_f[2] == 0;

    if (args->tree_only) {
        PRINT("%s (%s %08X): reference %d float nodes (add/sub/mul/div), ours %d; FScore (absent, assoc, commute) = %s, extra %d; %s",
              name, tname, scorer->address, (int)ng, (int)our_tree->interesting.n, tuple3(s->base_f), s->base_x,
              dk_score_str(base_score));
        const FoTree *trees[2] = {game_tree, our_tree};
        const char *titles[2] = {"reference", "ours"};
        for (int q = 0; q < 2; q++) {
            PRINT("%s float roots:", titles[q]);
            for (size_t i = 0; i < trees[q]->roots.n && i < 16; i++) {
                const FoRoot *r = &trees[q]->roots.v[i];
                if (r->store) PRINT("  store %-10s = %s", r->label, fo_cut(fo_render(r->node, 5, true), 120));
                else PRINT("  cmp %s", fo_cut(fo_render(r->node, 5, true), 120));
            }
        }
        PRINT("reference nodes against ours:");
        for (size_t i = 0; i < ng && i < 40; i++)
            PRINT("  %-8s %s", FO_CLASS_NAMES[base_classes[i]], fo_cut(fo_render(game_tree->interesting.v[i], 5, true), 120));
        KSiteVec sites = site_list(&s->body0, s->float_names, NULL, true);
        PRINT("%d sites in the body:", (int)sites.n);
        for (size_t i = 0; i < sites.n && i < 20; i++)
            PRINT("  stmt %d%s: %s", sites.v[i].k, sites.v[i].s.hint ? " (float hint)" : "",
                  fo_cut(dupv(sites.v[i].s.text), 100));
        return 0;
    }

    if (!ng && !our_tree->interesting.n) {
        LOG("%s: no float add/sub/mul/div in the reference's function or ours", name);
        JSET(result, "base", jbase(s->base_f, base_score));
        JSET(result, "best", jbase(s->base_f, base_score));
        JSET(result, "tried", jint(0));
        JSET(result, "failed", jint(0));
        JSET(result, "sites", jint(0));
        JSET(result, "sensitive", jint(0));
        JSET(result, "unreached", dk_json_arr(a));
        JSET(result, "insensitive_sites", dk_json_arr(a));
        return finish(&env, "no-float");
    }

    /* the truncated unit */
    s->tail_used = s->tail;
    {
        bool any_tail = false;
        for (size_t i = 1; i < s->tail.n; i++)
            if (dk_str_strip(S(s->tail.v[i])).n) any_tail = true;
        if (!args->full_unit && any_tail) {
            const char *src = dk_path_join(a, workdirs[0], dupv(dk_path_basename(unit)));
            DkCzVec t1 = vec_slice(&s->tail, 0, 1);
            write_unit(src, &s->head, &s->body0, &t1);
            DkScored cut;
            if (eval_source(s, 0, src, &cut)) {
                if (strcmp(cut.key, full.key) == 0) s->tail_used = t1;
                dk_scored_free(&cut);
            }
        }
    }

    dk_mutex_lock(&s->free_lock); /* a zeroed DkMutex needs no init; the lock call only documents the queue is ours */
    s->free_stack = DK_NEWN(a, int, n_workers);
    for (int w = 0; w < n_workers; w++) s->free_stack[w] = n_workers - 1 - w; /* w0 is taken first */
    s->n_free = n_workers;
    dk_mutex_unlock(&s->free_lock);
    s->all_osigs = dk_iset_new();
    s->base_osig = osig_of(our_tree);
    {
        DkIMapIter it = {0};
        while (dk_imap_next(s->base_osig, &it)) dk_iset_add(s->all_osigs, it.key);
    }
    s->deadline = t0 + args->minutes * 60.0 * (f000 ? 1.0 / 3 : 1.0);
    fo_tree_prepare(game_tree);
    DkPoolOpts po = {.threads = n_workers, .stack_bytes = (size_t)128 * 1024 * 1024};
    s->pool = dk_pool_new_ex(&po);
    s->base_rank.f[0] = s->base_f[0];
    s->base_rank.f[1] = s->base_f[1];
    s->base_rank.f[2] = s->base_f[2];
    s->base_rank.extra = s->base_x;
    s->base_rank.score = base_score;
    s->best_rank = s->base_rank;
    s->best_body = s->body0;
    s->best_classes = dk_xmalloc(ng ? ng : 1);
    memcpy(s->best_classes, base_classes, ng);
    s->frontier = dk_map_new();
    s->seen = dk_set_new();
    dk_set_add(s->seen, S(join_key(&s->body0)));
    s->allowed = allowed_for(base_classes, ng);
    if (f000 && !dk_score_exact(base_score)) LOG("float order already the reference's: the wall is elsewhere (schedule/register)");
    LOG("%s (%s %08X): FScore %s extra %d %s, %s; moves %s", name, tname, scorer->address, tuple3(s->base_f), s->base_x,
        dk_score_str(base_score), fo_class_counts_repr(base_classes, ng), fo_moves_repr(s->allowed));

    if (args->line) {
        i64 rel = args->line - 1 - pb.first;
        s->only = dk_iset_new();
        FoStmtVec gs = fo_group_statements(&s->body0);
        for (size_t k = 0; k < gs.n; k++)
            if (gs.v[k].lo <= rel && rel <= gs.v[k].hi) dk_iset_add(s->only, k);
        dk_vec_free(&gs);
        if (!dk_iset_len(s->only)) {
            JSET(result, "error", jstr(fmt_("no statement at line %d", (int)args->line)));
            dk_pool_shutdown(s->pool, false);
            return finish(&env, "unparsed");
        }
    }
    s->sites0 = site_list(&s->body0, s->float_names, s->only, args->line != 0);
    JSET(result, "sites", jint((i64)s->sites0.n));
    if (!s->sites0.n) {
        FoVariantVec v0 = fo_stmt_variants(&s->body0, s->only);
        bool none = v0.n == 0;
        dk_vec_free(&v0);
        if (none) {
            JSET(result, "base", jbase(s->base_f, base_score));
            JSET(result, "best", jbase(s->base_f, base_score));
            JSET(result, "tried", jint(0));
            JSET(result, "failed", jint(0));
            JSET(result, "sensitive", jint(0));
            JSET(result, "unreached", dk_json_arr(a));
            JSET(result, "insensitive_sites", dk_json_arr(a));
            dk_pool_shutdown(s->pool, false);
            return finish(&env, "unparsed");
        }
    }

    probe(s);
    descend(s);
    if (rank_cmp(&s->best_rank, &s->base_rank) >= 0 && s->allowed != FO_ALL_MOVES && dk_time() < s->deadline) {
        /* the classification-pruned moves found nothing: the other moves, for the bounding evidence */
        s->allowed = FO_ALL_MOVES;
        LOG("widening to all moves");
        probe(s);
        descend(s);
    }
    dk_pool_shutdown(s->pool, false);

    /* D: the states */
    DK_VEC(Front *) cand = {0};
    {
        DkMapIter it = {0};
        while (dk_map_next(s->frontier, &it)) dk_vec_push(&cand, it.val->p);
    }
    dk_sort(cand.v, cand.n, sizeof(Front *), cmp_front_ptr, NULL, false);
    size_t n_states = DK_MIN(cand.n, 4);
    DkJson *result_states = dk_json_getz(result, "states");
    for (size_t n = 0; n < n_states; n++) {
        Front *f = cand.v[n];
        const Rank *rk = &f->rank;
        const char *tag = fmt_("F%lld_%lld_%lld_%s", (long long)rk->f[0], (long long)rk->f[1], (long long)rk->f[2],
                               dk_score_tag(rk->score));
        const char *path = dk_path_join(a, out, fmt_("state%d_%s.diff", (int)n, tag));
        DkBuf db;
        dk_buf_init(&db, a);
        dk_buf_pyfmt(&db, "# %s: %s -> %s; %s\n", name, rank_repr(&s->base_rank), rank_repr(rk), join_notes(&f->notes));
        DkStrVec av = {0}, bv = {0};
        const DkCzVec *pa[3] = {&s->head, &s->body0, &s->tail}, *pb2[3] = {&s->head, &f->body, &s->tail};
        for (int q = 0; q < 3; q++) {
            for (size_t i = 0; i < pa[q]->n; i++) dk_vec_push(&av, S(fmt_("%s\n", pa[q]->v[i])));
            for (size_t i = 0; i < pb2[q]->n; i++) dk_vec_push(&bv, S(fmt_("%s\n", pb2[q]->v[i])));
        }
        DkUdiff uo = DK_UDIFF_DEFAULT;
        uo.fromfile = S(args->unit);
        uo.tofile = S(fmt_("%s (candidate)", args->unit));
        uo.n = 2;
        dk_unified_diff(&db, av.v, av.n, bv.v, bv.n, &uo);
        write_crlf(path, dk_buf_str(&db));
        dk_vec_free(&av);
        dk_vec_free(&bv);
        DkJson *entry = dk_json_obj(a);
        DkJson *rj = dk_json_arr(a);
        dk_json_arr_push(a, rj, jf3(rk->f));
        dk_json_arr_push(a, rj, jint(rk->extra));
        dk_json_arr_push(a, rj, jscore(rk->score));
        JSET(entry, "rank", rj);
        JSET(entry, "notes", jstrs(&f->notes));
        JSET(entry, "diff", jstr(rel_root(path)));
        dk_json_arr_push(a, result_states, entry);
    }
    /* E: unreached */
    DK_VEC(Unreached) unreached = {0};
    {
        DkISet *seen_sig = dk_iset_new();
        for (size_t i = 0; i < ng; i++) {
            FoNode *g = game_tree->interesting.v[i];
            u64 sg = fo_ordered(g);
            if (!dk_iset_has(s->all_osigs, sg) && !dk_iset_has(seen_sig, sg)) {
                dk_iset_add(seen_sig, sg);
                Unreached u = {dk_u8_len(S(fo_render(g, 12, true))),
                               fmt_("%s [%s]", fo_cut(fo_render(g, 5, true), 120), FO_CLASS_NAMES[s->best_classes[i]])};
                dk_vec_push(&unreached, u);
            }
        }
        dk_iset_free(seen_sig);
    }
    dk_sort(unreached.v, unreached.n, sizeof(Unreached), cmp_unreached, NULL, false);
    if (unreached.n > 12) unreached.n = 12;
    DkCzVec unreached_texts = {0};
    for (size_t i = 0; i < unreached.n; i++) dk_vec_push(&unreached_texts, (char *)unreached.v[i].text);
    JSET(result, "unreached", jstrs(&unreached_texts));
    {
        DkJson *ins = dk_json_arr(a);
        for (size_t i = 0; i < s->insensitive.n; i++)
            dk_json_arr_push(a, ins, jstr(fo_cut(dupv(s->insensitive.v[i].s.text), 100)));
        JSET(result, "insensitive_sites", ins);
    }
    JSET(result, "sensitive", jint((i64)s->sensitive.n));
    JSET(result, "base", jbase(s->base_f, base_score));
    {
        DkJson *b = dk_json_arr(a);
        dk_json_arr_push(a, b, jf3(s->best_rank.f));
        dk_json_arr_push(a, b, jscore(s->best_rank.score));
        JSET(result, "best", b);
    }
    {
        DkJson *ex = dk_json_obj(a);
        JSET(ex, "before", jint(s->base_x));
        JSET(ex, "after", jint(s->best_rank.extra));
        JSET(result, "extra", ex);
    }
    JSET(result, "tried", jint(s->tried));
    JSET(result, "failed", jint(s->failed));
    JSET(dk_json_getz(result, "reference_nodes"), "after", jclasses(s->best_classes, ng));
    DkScore ps_exact = DK_SCORE_EXACT;
    bool exact = dk_score_cmp(s->best_rank.score, ps_exact) == 0;
    if (exact) {
        DkJson *others = dk_json_obj(a);
        for (size_t t2 = 0; t2 < dk_project_ntargets(proj); t2++) {
            if ((int)t2 == target) continue;
            DkErr e2 = {0};
            const DkAnnot *an2 = dk_scorer_select(proj, udef, args->name, DK_NO_ADDR, (int)t2, &e2);
            if (!an2 || an2->addr[t2] == DK_NO_ADDR) continue;
            const char *odir = dk_path_join(a, out, fmt_("other%d", (int)t2));
            dk_makedirs(odir, true);
            DkScorer *sc2 = dk_scorer_new(proj, udef, an2, (int)t2, 1, dk_path_join(a, odir, "b"), &e2);
            const char *src = dk_path_join(a, odir, dupv(dk_path_basename(unit)));
            write_unit(src, &s->head, &s->best_body, &s->tail_used);
            DkScored m2;
            DkJson *verdict = dk_json_null();
            if (sc2 && dk_scorer_evaluate(sc2, 0, src, &m2, NULL, &e2)) {
                verdict = dk_json_bool(dk_score_exact(m2.score));
                dk_scored_free(&m2);
            }
            JSET(others, dk_project_target(proj, (int)t2)->name, verdict);
            dk_rmtree(odir, DK_RMTREE_IGNORE_ERRORS);
        }
        JSET(result, "exact_other", others);
    }
    LOG("%d candidates (%d did not compile), %d sites (%d sensitive); best %s extra %d %s (original %s extra %d %s)",
        s->tried, s->failed, (int)s->sites0.n, (int)s->sensitive.n, tuple3(s->best_rank.f), s->best_rank.extra,
        dk_score_str(s->best_rank.score), tuple3(s->base_f), s->base_x, dk_score_str(base_score));
    LOG("reference nodes: before %s, after %s", fo_class_counts_repr(base_classes, ng), fo_class_counts_repr(s->best_classes, ng));
    if (unreached.n) {
        LOG("unreached reference nodes (%d candidates compiled over %d sites, none produces them):", s->tried, (int)s->sites0.n);
        for (size_t i = 0; i < unreached.n; i++) LOG("  %s", unreached.v[i].text);
    }
    if (s->frontier && dk_map_len(s->frontier)) LOG("%d distinct better state(s) in %s", (int)n_states, relpath_native(out));
    const char *status = exact ? "exact"
                         : rank_cmp(&s->best_rank, &s->base_rank) < 0 ? "improved"
                         : (s->sites0.n && !s->sensitive.n) ? "insensitive"
                                                            : "none";
    return finish(&env, status);
}

/* ------------------------------------------------------------------------------------------------- batch */

static const char *jlist_repr(const DkJson *v);

/* the text of a JSON value as a list or dictionary would print */
static void repr_json(DkBuf *b, const DkJson *v) {
    if (!v || v->kind == DK_JSON_NULL) {
        dk_buf_putz(b, "None");
    } else if (v->kind == DK_JSON_BOOL) {
        dk_buf_putz(b, v->b ? "True" : "False");
    } else if (v->kind == DK_JSON_STRING) {
        dk_buf_repr_str(b, v->u.str);
    } else if (v->kind == DK_JSON_ARRAY) {
        dk_buf_putc(b, '[');
        for (size_t i = 0; i < dk_json_len(v); i++) {
            if (i) dk_buf_putz(b, ", ");
            repr_json(b, dk_json_at(v, i));
        }
        dk_buf_putc(b, ']');
    } else if (v->kind == DK_JSON_OBJECT) {
        dk_buf_putc(b, '{');
        for (size_t i = 0; i < dk_json_len(v); i++) {
            const DkJsonMember *m = dk_json_member(v, i);
            if (i) dk_buf_putz(b, ", ");
            dk_buf_repr_str(b, m->key);
            dk_buf_putz(b, ": ");
            repr_json(b, m->val);
        }
        dk_buf_putc(b, '}');
    } else {
        DkJsonDumpOpts o = {0};
        dk_json_dump_buf(b, v, &o); /* numbers: json.dumps spells ints and floats as repr does */
    }
}

static const char *jrepr(const DkJson *v) {
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    repr_json(&b, v);
    return dk_buf_cz(&b);
}

/* str(x): strings raw, everything else its repr */
static const char *jstr_of(const DkJson *v) {
    if (v && v->kind == DK_JSON_STRING) return dupv(v->u.str);
    return jrepr(v);
}

/* str(tuple(list)) : a JSON array of ints as "(a, b, c)" */
static const char *jtuple(const DkJson *v) {
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    dk_buf_putc(&b, '(');
    size_t n = dk_json_len(v);
    for (size_t i = 0; i < n; i++) {
        if (i) dk_buf_putz(&b, ", ");
        repr_json(&b, dk_json_at(v, i));
    }
    if (n == 1) dk_buf_putc(&b, ',');
    dk_buf_putc(&b, ')');
    return dk_buf_cz(&b);
}

typedef struct BatchJob {
    const char *unit, *name, *target;
    u32 address;
    const char *stop;   /* NULL: None */
} BatchJob;
typedef DK_VEC(BatchJob) BatchJobVec;

typedef struct BatchCtx {
    FloatOrderArgs *args;
    const char *exe;
} BatchCtx;

static const char *num_text(double v, bool is_int) {
    if (is_int) return fmt_("%lld", (long long)v);
    char buf[32];
    dk_float_repr(v, buf);
    return fmt_("%s", buf);
}

static int batch_run(void *vctx, size_t index, const void *item, void *result) {
    DK_UNUSED(index);
    BatchCtx *ctx = vctx;
    const BatchJob *job = item;
    FloatOrderArgs *args = ctx->args;
    DkArena *a = dk_arena();
    DkCzVec cmd = {0};
    dk_vec_push(&cmd, (char *)ctx->exe);
    dk_vec_push(&cmd, (char *)job->unit);
    dk_vec_push(&cmd, (char *)job->name);
    dk_vec_push(&cmd, "--target");
    dk_vec_push(&cmd, (char *)job->target);
    dk_vec_push(&cmd, "--address");
    dk_vec_push(&cmd, fmt_("%08X", job->address));
    dk_vec_push(&cmd, "--minutes");
    dk_vec_push(&cmd, (char *)num_text(args->minutes, args->minutes_int));
    dk_vec_push(&cmd, "--workers");
    dk_vec_push(&cmd, fmt_("%lld", (long long)args->workers));
    dk_vec_push(&cmd, "--quiet");
    if (args->root) {
        dk_vec_push(&cmd, "--root");
        dk_vec_push(&cmd, (char *)args->root);
    }
    if (args->config) {
        dk_vec_push(&cmd, "--config");
        dk_vec_push(&cmd, (char *)args->config);
    }
    dk_vec_push(&cmd, NULL);
    double t = dk_time();
    DkProcSpec spec = {0};
    spec.argv = (const char *const *)cmd.v;
    spec.cwd = g_root;
    spec.out = DK_IO_CAPTURE;
    spec.err = DK_IO_CAPTURE;
    spec.text = true;
    spec.errors = DK_ERRORS_REPLACE;
    spec.timeout = args->minutes * 60.0 + 900.0;
    DkProcResult pr = dk_run(&spec);
    if (pr.status == DK_PROC_TIMEOUT) dk_panic(__FILE__, __LINE__, "subprocess.TimeoutExpired: the search did not end in time");
    const char *proc_out = pr.out.p ? pr.out.p : "", *proc_err = pr.err.p ? pr.err.p : "";
    const char *res_path = dk_path_join(a, out_dir(S(job->name), job->address), "result.json");
    DkJson *res = NULL;
    double mtime;
    if (dk_exists(res_path) && dk_getmtime(res_path, &mtime) && mtime >= t - 1) {
        DkStr txt;
        if (!dk_read_text(a, res_path, DK_TM_UTF8, &txt)) dk_panic(__FILE__, __LINE__, "cannot read %s", res_path);
        DkJsonError err = {0};
        res = dk_json_parse(a, txt, &err);
        if (!res) dk_panic(__FILE__, __LINE__, "%s", dk_json_error_str(a, &err).p);
    }
    if (!res) {
        const char *msg = *proc_err ? proc_err : proc_out;
        DkStrVec ls = dk_str_splitlines(dk_str_strip(S(msg)), false);
        const char *last = ls.n ? dupv(ls.v[ls.n - 1]) : "?";
        dk_vec_free(&ls);
        res = dk_json_obj(a);
        JSET(res, "unit", jstr(job->unit));
        JSET(res, "name", jstr(job->name));
        JSET(res, "target", jstr(job->target));
        JSET(res, "stop", job->stop ? jstr(job->stop) : dk_json_null());
        JSET(res, "status", jstr("error"));
        JSET(res, "error", jstr(last));
    }
    DkStr status = dk_json_get_str(res, "status", S(""));
    if (!dk_str_eqz(status, "no-float")) {
        DkJson *base = dk_json_getz(res, "base"), *best = dk_json_getz(res, "best");
        PRINT("%-11s %-60s %s -> %s", dupv(status), dupv(dk_u8_slice(S(job->name), 0, 60)),
              base ? jrepr(dk_json_at(base, 0)) : "'-'", best ? jrepr(dk_json_at(best, 0)) : "'-'");
    }
    fflush(stdout);
    *(DkJson **)result = res;
    return 0;
}

static int status_order(DkStr s) {
    static const char *const names[] = {"exact", "improved", "none", "insensitive", "unparsed", "error", "no-float"};
    for (int i = 0; i < 7; i++)
        if (dk_str_eqz(s, names[i])) return i;
    return 9;
}

typedef struct SortKey {
    DkJson *r;
    int order;
    DkStr unit, name;
} SortKey;
static int cmp_sortkey(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    const SortKey *a = x, *b = y;
    if (a->order != b->order) return a->order < b->order ? -1 : 1;
    int c = dk_str_cmp(a->unit, b->unit);
    return c ? c : dk_str_cmp(a->name, b->name);
}

static bool jtruthy(const DkJson *v) { return v && dk_json_truthy(v); }

static int cmp_order_only(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    const SortKey *a = x, *b = y;
    return a->order < b->order ? -1 : a->order > b->order ? 1 : 0;
}

int float_order_batch(FloatOrderArgs *args) {
    DkArena *a = dk_arena();
    DkProject *proj = args->project;
    g_root = dk_project_root(proj);
    g_out_root = dk_project_build_dir(proj, "float_order");
    const DkRe *select = args->select ? dk_re_try(args->select, DK_RE_I) : NULL;
    DkUnitcmpOpts o;
    memset(&o, 0, sizeof o);
    o.target = -1;
    o.use_cache = true;
    DkCzVec stems = {0};
    if (args->units && *args->units) {
        DkStrVec us = dk_str_split(S(args->units), S(","), -1);
        for (size_t i = 0; i < us.n; i++) dk_vec_push(&stems, dupv(dk_str_strip(us.v[i])));
        dk_vec_free(&us);
        o.units = (const char *const *)stems.v;
        o.n_units = stems.n;
    } else {
        o.all = true;
    }
    DkUnitcmpRowVec rows = {0};
    DkErr err = {0};
    if (!dk_unitcmp_collect(proj, &o, &rows, &err)) {
        fprintf(stderr, "float_order: %s\n", err.msg);
        return 2;
    }
    BatchJobVec jobs = {0};
    DkSet *seen = dk_set_new();
    for (size_t i = 0; i < rows.n; i++) {
        const DkUnitcmpRow *row = &rows.v[i];
        if (!row->r || row->r->status == DK_MATCH || row->r->status == DK_ERROR || row->r->status == DK_MISSING) continue;
        if (!row->wall.wall || strcmp(row->wall.wall, args->wall) != 0) continue;
        const DkAnnot *an = row->r->ann;
        if (!an || !an->name) continue;
        const char *stop = dk_stopped(an, row->r->target) ? an->stop_reason : NULL;
        if (select && !dk_re_search(select, S(stop ? stop : ""), 0, DK_END, NULL)) continue;
        BatchJob j = {0};
        j.unit = dk_project_path(a, proj, row->unit->path);
        j.name = dupv(S(an->name));
        j.target = dk_project_target(proj, row->r->target)->name;
        j.address = an->addr[row->r->target];
        j.stop = stop;
        DkStr key = S(fmt_("%s|%s|%08X", j.unit, j.name, j.address));
        if (dk_set_has(seen, key)) continue;
        dk_set_add(seen, dk_str_dup(a, key));
        dk_vec_push(&jobs, j);
    }
    if (args->limit) { /* jobs[:args.limit] */
        i64 n = (i64)jobs.n, end = args->limit < 0 ? n + args->limit : args->limit;
        if (end < 0) end = 0;
        if (end < n) jobs.n = (size_t)end;
    }
    PRINT("%d functions, %.1f minutes each, %d at a time (%d workers each)", (int)jobs.n, args->minutes, (int)args->jobs,
          (int)args->workers);
    const char *outroot = g_out_root;
    dk_makedirs(outroot, true);

    BatchCtx ctx = {args, dk_path_join(a, dk_exe_dir(), "float_order.exe")};
    DK_VEC(DkJson *) found = {0};
    dk_vec_reserve(&found, jobs.n ? jobs.n : 1);
    found.n = jobs.n;
    DkPool *pool = dk_pool_new((int)DK_MAX(1, args->jobs));
    dk_pool_map(pool, (int)DK_MAX(1, args->jobs), batch_run, &ctx, jobs.v, jobs.n, sizeof(BatchJob), found.v, sizeof(DkJson *));
    dk_pool_shutdown(pool, false);

    /* results.sort(key=(order.get(status, 9), unit, name)): stable */
    DK_VEC(SortKey) keys = {0};
    for (size_t i = 0; i < found.n; i++) {
        SortKey k = {found.v[i], 0, {0}, {0}};
        k.order = status_order(dk_json_get_str(k.r, "status", S("")));
        k.unit = dk_json_get_str(k.r, "unit", S(""));
        k.name = dk_json_get_str(k.r, "name", S(""));
        dk_vec_push(&keys, k);
    }
    dk_sort(keys.v, keys.n, sizeof(SortKey), cmp_sortkey, NULL, false);
    DkJson *all = dk_json_arr(a);
    for (size_t i = 0; i < keys.n; i++) dk_json_arr_push(a, all, keys.v[i].r);
    {
        DkJsonDumpOpts jo = DK_JSON_INDENT(1);
        write_crlf(dk_path_join(a, outroot, "summary.json"), dk_json_dumps(a, all, &jo));
    }
    DkBuf rows_b;
    dk_buf_init(&rows_b, a);
    dk_buf_putz(&rows_b,
                 "| status | unit | function | FScore before | after | extra before | after | classes before | after | sites | "
                 "candidates | best diff |\n|---|---|---|---|---|---|---|---|---|---|---|---|");
    for (size_t i = 0; i < keys.n; i++) {
        const DkJson *r = keys.v[i].r;
        if (dk_str_eqz(dk_json_get_str(r, "status", S("")), "no-float")) continue;
        DkJson *gn = dk_json_getz(r, "reference_nodes");
        DkJson *states = dk_json_getz(r, "states");
        const char *diff = jtruthy(states) ? jstr_of(dk_json_getz(dk_json_at(states, 0), "diff")) : jstr_of(dk_json_get_or(r, S("error"), jstr("")));
        DkJson *base = dk_json_getz(r, "base"), *best = dk_json_getz(r, "best");
        DkJson *extra = dk_json_getz(r, "extra");
        const char *eb = extra ? jstr_of(dk_json_get_or(extra, S("before"), jstr(""))) : "";
        const char *ea = extra ? jstr_of(dk_json_get_or(extra, S("after"), jstr(""))) : "";
        const char *gb = gn ? jstr_of(dk_json_get_or(gn, S("before"), jstr(""))) : "";
        const char *ga = gn ? jstr_of(dk_json_get_or(gn, S("after"), jstr(""))) : "";
        DkStr unit_b = dk_path_basename(dupv(dk_json_get_str(r, "unit", S(""))));
        dk_buf_pyfmt(&rows_b, "\n| %s | %s | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s |", jstr_of(dk_json_getz(r, "status")),
                      dupv(unit_b), jstr_of(dk_json_getz(r, "name")), jtruthy(base) ? jtuple(dk_json_at(base, 0)) : "-",
                      jtruthy(best) ? jtuple(dk_json_at(best, 0)) : "-", eb, ea, gb, ga,
                      jstr_of(dk_json_get_or(r, S("sites"), jstr(""))), jstr_of(dk_json_get_or(r, S("tried"), jstr(""))), diff);
    }
    dk_buf_putz(&rows_b, "\n");
    for (size_t i = 0; i < keys.n; i++) {
        const DkJson *r = keys.v[i].r;
        if (dk_str_eqz(dk_json_get_str(r, "status", S("")), "no-float")) continue;
        DkJson *un = dk_json_getz(r, "unreached");
        if (!jtruthy(un)) continue;
        DkBuf j;
        dk_buf_init(&j, a);
        for (size_t q = 0; q < dk_json_len(un) && q < 4; q++) {
            if (q) dk_buf_putz(&j, "; ");
            dk_buf_put(&j, dk_json_at(un, q)->u.str);
        }
        dk_buf_pyfmt(&rows_b, "\n- `%s` unreached: %s", jstr_of(dk_json_getz(r, "name")), dk_buf_cz(&j));
    }
    /* counts = Counter(status): first-seen order, then sorted by the status order (stable) */
    DkMap *counts = dk_map_new();
    for (size_t i = 0; i < keys.n; i++) dk_map_put(counts, dk_json_get_str(keys.v[i].r, "status", S("")), NULL)->i += 1;
    DkStrVec cn = dk_map_keys(counts);
    SortKey *ck = DK_NEWN(a, SortKey, cn.n ? cn.n : 1);
    for (size_t i = 0; i < cn.n; i++) {
        ck[i].name = cn.v[i];
        ck[i].order = status_order(cn.v[i]);
    }
    dk_sort(ck, cn.n, sizeof(SortKey), cmp_order_only, NULL, false);
    DkBuf sum;
    dk_buf_init(&sum, a);
    dk_buf_pyfmt(&sum, "%d functions: ", (int)keys.n);
    for (size_t i = 0; i < cn.n; i++) {
        if (i) dk_buf_putz(&sum, ", ");
        dk_buf_pyfmt(&sum, "%d %s", (int)dk_map_get(counts, ck[i].name)->i, dupv(ck[i].name));
    }
    const char *summary = dk_buf_cz(&sum);
    const char *md = dk_path_join(a, outroot, "summary.md");
    write_crlf(md, dk_pyfmt(a, "# float_order.exe --batch\n\n%s (%.1f minutes each; no-float rows are only counted)\n\n%s\n", summary,
                              args->minutes, dk_buf_cz(&rows_b)));
    PRINT("%s", summary);
    PRINT("summary: %s", relpath_native(md));
    return 0;
}
