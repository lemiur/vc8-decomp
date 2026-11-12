// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* xmatch images: an executable as a search target, see xmatch.h. */
#include "xmatch.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

typedef struct {
    INIT_ONCE once;
    u32 *pos;    /* positions sorted by (key, pos) */
    u32 *bucket; /* 65537 starts by key >> 16 */
    size_t n;
} KeyIndex;

typedef struct {
    const char *name;
    u32 iat;
} ImportName;

struct DkXmImage {
    DkArena *arena;   /* the PE and the names */
    DkFileView view;  /* when opened from a file */
    bool has_view;
    const DkPe *pe;
    u32 base, size;
    DkXmSpan *execs, *datas;
    size_t nexec, ndata;
    u32 *relocs;
    size_t nrelocs;
    ImportName *imports;
    size_t nimports;

    INIT_ONCE call_once;
    u32 *call_key;  /* the followed target of each call site, sorted by (key, site) */
    u32 *call_site; /* the sites, parallel to call_key */
    size_t ncalls;
    u32 *call_keys;
    size_t ncall_keys;

    INIT_ONCE starts_once;
    u32 *starts;
    size_t nstarts;

    KeyIndex *kidx; /* per exec span */

    INIT_ONCE fp_once;
    u32 *trel; /* text relocations (RVAs) */
    size_t ntrel;
    u32 *gap_idx; /* indices sorted by (g1, g2, i) */
    size_t ngap;
};

static u32 rd32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static int cmp_u32(const void *a, const void *b) {
    u32 x = *(const u32 *)a, y = *(const u32 *)b;
    return x < y ? -1 : x > y;
}

static int cmp_u64(const void *a, const void *b) {
    u64 x = *(const u64 *)a, y = *(const u64 *)b;
    return x < y ? -1 : x > y;
}

static double entropy(const u8 *d, size_t n) {
    if (!n) return 0.0;
    size_t cnt[256] = {0};
    for (size_t i = 0; i < n; i++) cnt[d[i]]++;
    double h = 0.0;
    for (int k = 0; k < 256; k++) {
        if (!cnt[k]) continue;
        double p = (double)cnt[k] / (double)n;
        h -= p * log2(p);
    }
    return h;
}

static DkXmImage *make_image(const DkPe *pe, DkArena *arena) {
    DkXmImage *img = dk_xcalloc(1, sizeof(DkXmImage));
    img->arena = arena;
    img->pe = pe;
    img->base = (u32)pe->image_base;
    img->size = pe->size_of_image;
    size_t ns = pe->n_sections;
    img->execs = dk_xcalloc(ns ? ns : 1, sizeof(DkXmSpan));
    img->datas = dk_xcalloc(ns ? ns : 1, sizeof(DkXmSpan));
    for (size_t i = 0; i < ns; i++) {
        const DkPeSection *s = &pe->sections[i];
        DkPeSpan d = dk_pe_section_data(pe, s);
        DkXmSpan sp = {dk_cz(arena, s->name), img->base + s->virtual_address, d.p, d.n};
        if (s->characteristics & (u32)DK_SCN_MEM_EXECUTE) {
            size_t m = d.n < (1u << 20) ? d.n : (1u << 20);
            if (d.n && entropy(d.p, m) > 2.0) img->execs[img->nexec++] = sp;
        } else {
            img->datas[img->ndata++] = sp;
        }
    }
    /* HIGHLOW relocations: sorted, distinct VAs */
    size_t nr = 0;
    bool present = false;
    u32 *rv = dk_pe_reloc_rvas(pe, arena, DK_PE_REL_BASED_HIGHLOW, &nr, &present);
    img->relocs = dk_xmalloc((nr ? nr : 1) * sizeof(u32));
    for (size_t i = 0; i < nr; i++) img->relocs[i] = img->base + rv[i];
    qsort(img->relocs, nr, sizeof(u32), cmp_u32);
    size_t m = 0;
    for (size_t i = 0; i < nr; i++)
        if (!m || img->relocs[m - 1] != img->relocs[i]) img->relocs[m++] = img->relocs[i];
    img->nrelocs = m;
    /* imports by name, in file order */
    DkPeImports im = dk_pe_imports(pe, arena);
    size_t total = 0;
    for (size_t d = 0; d < im.n; d++) total += im.dlls[d].n;
    img->imports = dk_xcalloc(total ? total : 1, sizeof(ImportName));
    for (size_t d = 0; d < im.n; d++)
        for (size_t k = 0; k < im.dlls[d].n; k++) {
            const DkPeImport *e = &im.dlls[d].imports[k];
            if (e->by_ordinal || !e->name.p) continue;
            img->imports[img->nimports].name = dk_cz(arena, e->name);
            img->imports[img->nimports].iat = (u32)e->address;
            img->nimports++;
        }
    img->kidx = dk_xcalloc(img->nexec ? img->nexec : 1, sizeof(KeyIndex));
    for (size_t i = 0; i < img->nexec; i++) InitOnceInitialize(&img->kidx[i].once);
    InitOnceInitialize(&img->call_once);
    InitOnceInitialize(&img->starts_once);
    InitOnceInitialize(&img->fp_once);
    return img;
}

static char *heap_err(const char *fmt, const char *a, const char *b) {
    size_t n = strlen(fmt) + strlen(a) + (b ? strlen(b) : 0) + 1;
    char *s = dk_xmalloc(n);
    snprintf(s, n, fmt, a, b ? b : "");
    return s;
}

DkXmImage *dk_xm_image_open(const char *path, char **err) {
    if (err) *err = NULL;
    DkFileView v;
    if (!dk_view_open(path, &v)) {
        if (err) *err = heap_err("cannot read %s%s", path, NULL);
        return NULL;
    }
    DkArena *arena = dk_arena_new(0);
    DkTry t;
    DkPe *pe = NULL;
    if (DK_TRY(&t)) {
        pe = dk_pe_parse(arena, v.p, v.n);
        dk_try_end(&t);
    } else {
        if (err) *err = heap_err("%s: %s", path, t.msg);
        dk_arena_free(arena);
        dk_view_close(&v);
        return NULL;
    }
    if (pe->machine != DK_PE_MACHINE_I386 || pe->magic != DK_PE_MAGIC_PE32) {
        if (err) *err = heap_err("%s: %s", path, "not a PE32 x86 image");
        dk_arena_free(arena);
        dk_view_close(&v);
        return NULL;
    }
    DkXmImage *img = make_image(pe, arena);
    img->view = v;
    img->has_view = true;
    return img;
}

DkXmImage *dk_xm_image_from_pe(const DkPe *pe) {
    return make_image(pe, dk_arena_new(0));
}

void dk_xm_image_close(DkXmImage *img) {
    if (!img) return;
    for (size_t i = 0; i < img->nexec; i++) {
        free(img->kidx[i].pos);
        free(img->kidx[i].bucket);
    }
    free(img->kidx);
    free(img->call_key);
    free(img->call_site);
    free(img->call_keys);
    free(img->starts);
    free(img->trel);
    free(img->gap_idx);
    free(img->execs);
    free(img->datas);
    free(img->relocs);
    free(img->imports);
    dk_arena_free(img->arena);
    if (img->has_view) dk_view_close(&img->view);
    free(img);
}

const DkPe *dk_xm_image_pe(const DkXmImage *img) { return img->pe; }
u32 dk_xm_image_base(const DkXmImage *img) { return img->base; }
u32 dk_xm_image_size(const DkXmImage *img) { return img->size; }
size_t dk_xm_image_exec_count(const DkXmImage *img) { return img->nexec; }
size_t dk_xm_image_data_count(const DkXmImage *img) { return img->ndata; }

const DkXmSpan *dk_xm_image_exec(const DkXmImage *img, size_t i) {
    return i < img->nexec ? &img->execs[i] : NULL;
}

const DkXmSpan *dk_xm_image_data(const DkXmImage *img, size_t i) {
    return i < img->ndata ? &img->datas[i] : NULL;
}

static const DkXmSpan *exec_of(const DkXmImage *img, u32 a) {
    for (size_t i = 0; i < img->nexec; i++) {
        const DkXmSpan *s = &img->execs[i];
        if (a >= s->va && (u64)(a - s->va) < s->len) return s;
    }
    return NULL;
}

bool dk_xm_image_in_exec(const DkXmImage *img, u32 a) { return exec_of(img, a) != NULL; }

bool dk_xm_image_in_image(const DkXmImage *img, u32 a) {
    return a >= img->base && (u64)a < (u64)img->base + img->size;
}

const u8 *dk_xm_image_read(const DkXmImage *img, u32 a, size_t n, size_t *got) {
    const DkXmSpan *s = exec_of(img, a);
    if (!s) {
        if (got) *got = 0;
        return NULL;
    }
    size_t off = a - s->va;
    size_t avail = s->len - off;
    if (got) *got = n < avail ? n : avail;
    return s->data + off;
}

bool dk_xm_image_has_relocs(const DkXmImage *img) { return img->nrelocs != 0; }

bool dk_xm_image_is_reloc(const DkXmImage *img, u32 a) {
    size_t lo = 0, hi = img->nrelocs;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (img->relocs[mid] < a)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo < img->nrelocs && img->relocs[lo] == a;
}

const u32 *dk_xm_image_relocs(const DkXmImage *img, size_t *count) {
    if (count) *count = img->nrelocs;
    return img->relocs;
}

u32 dk_xm_image_import(const DkXmImage *img, const char *name) {
    for (size_t i = 0; i < img->nimports; i++)
        if (strcmp(img->imports[i].name, name) == 0) return img->imports[i].iat;
    return 0;
}

u32 dk_xm_image_follow(const DkXmImage *img, u32 dest) {
    size_t got;
    const u8 *b = dk_xm_image_read(img, dest, 5, &got);
    if (got == 5 && b[0] == 0xE9) {
        u32 d2 = dest + 5 + rd32(b + 1);
        if (dk_xm_image_in_exec(img, d2)) return d2;
    }
    return dest;
}

/* ---- call index ---- */
static BOOL CALLBACK build_calls(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)ctx;
    DkXmImage *img = param;
    size_t cap = 1 << 16, n = 0;
    u64 *v = dk_xmalloc(cap * sizeof(u64));
    for (size_t s = 0; s < img->nexec; s++) {
        const DkXmSpan *sp = &img->execs[s];
        const u8 *d = sp->data;
        size_t len = sp->len;
        const u8 *q = d;
        while ((q = memchr(q, 0xE8, len - (size_t)(q - d))) != NULL) {
            size_t i = (size_t)(q - d);
            if (i + 5 > len) break;
            u32 dest = sp->va + (u32)i + 5 + rd32(d + i + 1);
            if (dest >= sp->va && (u64)(dest - sp->va) < len) {
                u32 key = dk_xm_image_follow(img, dest);
                if (n == cap) {
                    cap *= 2;
                    v = dk_xrealloc(v, cap * sizeof(u64));
                }
                v[n++] = ((u64)key << 32) | (sp->va + (u32)i);
            }
            q++;
            if ((size_t)(q - d) >= len) break;
        }
    }
    qsort(v, n, sizeof(u64), cmp_u64);
    img->call_key = dk_xmalloc((n ? n : 1) * sizeof(u32));
    img->call_site = dk_xmalloc((n ? n : 1) * sizeof(u32));
    for (size_t i = 0; i < n; i++) {
        img->call_key[i] = (u32)(v[i] >> 32);
        img->call_site[i] = (u32)v[i];
    }
    free(v);
    img->ncalls = n;
    u32 *k = dk_xmalloc((n ? n : 1) * sizeof(u32));
    size_t nk = 0;
    for (size_t i = 0; i < n; i++) {
        u32 key = img->call_key[i];
        if (!nk || k[nk - 1] != key) k[nk++] = key;
    }
    img->call_keys = k;
    img->ncall_keys = nk;
    return TRUE;
}

static void need_calls(const DkXmImage *img) {
    InitOnceExecuteOnce((PINIT_ONCE)&img->call_once, build_calls, (PVOID)img, NULL);
}

size_t dk_xm_image_callers(const DkXmImage *img, u32 dest, const u32 **sites) {
    need_calls(img);
    size_t lo = 0, hi = img->ncalls;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (img->call_key[mid] < dest)
            lo = mid + 1;
        else
            hi = mid;
    }
    size_t a = lo;
    hi = img->ncalls;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (img->call_key[mid] <= dest)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (sites) *sites = img->call_site + a;
    return lo - a;
}

const u32 *dk_xm_image_call_targets(const DkXmImage *img, size_t *count) {
    need_calls(img);
    if (count) *count = img->ncall_keys;
    return img->call_keys;
}

/* ---- starts ---- */
typedef struct {
    u32 *v;
    size_t n, cap;
} U32Buf;

static void push(U32Buf *b, u32 x) {
    if (b->n == b->cap) {
        b->cap = b->cap ? b->cap * 2 : 1 << 16;
        b->v = dk_xrealloc(b->v, b->cap * sizeof(u32));
    }
    b->v[b->n++] = x;
}

static BOOL CALLBACK build_starts(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)ctx;
    DkXmImage *img = param;
    need_calls(img);
    U32Buf b = {0};
    for (size_t i = 0; i < img->ncalls;) {
        u32 key = img->call_key[i];
        size_t j = i;
        while (j < img->ncalls && img->call_key[j] == key) j++;
        if (key % 16 == 0 || j - i >= 3) push(&b, key);
        i = j;
    }
    for (size_t s = 0; s < img->nexec; s++) {
        const DkXmSpan *sp = &img->execs[s];
        size_t i = 0;
        while (i < sp->len) {
            if (sp->data[i] != 0xCC) {
                i++;
                continue;
            }
            size_t e = i;
            while (e < sp->len && sp->data[e] == 0xCC) e++;
            if (e < sp->len && (sp->va + e) % 16 == 0) push(&b, sp->va + (u32)e);
            i = e;
        }
    }
    for (size_t r = 0; r < img->nrelocs; r++) {
        u32 a = img->relocs[r];
        const DkXmSpan *hit = NULL;
        for (size_t s = 0; s < img->nexec + img->ndata && !hit; s++) {
            const DkXmSpan *sp = s < img->nexec ? &img->execs[s] : &img->datas[s - img->nexec];
            if (a >= sp->va && (i64)(a - sp->va) < (i64)sp->len - 3) hit = sp;
        }
        if (hit) {
            u32 val = rd32(hit->data + (a - hit->va));
            if (val % 16 == 0 && dk_xm_image_in_exec(img, val)) push(&b, val);
        }
    }
    qsort(b.v, b.n, sizeof(u32), cmp_u32);
    size_t m = 0;
    for (size_t i = 0; i < b.n; i++)
        if (!m || b.v[m - 1] != b.v[i]) b.v[m++] = b.v[i];
    if (!b.v) b.v = dk_xmalloc(sizeof(u32));
    img->starts = b.v;
    img->nstarts = m;
    return TRUE;
}

const u32 *dk_xm_image_starts(const DkXmImage *img, size_t *count) {
    InitOnceExecuteOnce((PINIT_ONCE)&img->starts_once, build_starts, (PVOID)img, NULL);
    if (count) *count = img->nstarts;
    return img->starts;
}

/* the index of the first start > a */
static size_t upper(const u32 *v, size_t n, u32 a) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v[mid] <= a)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

bool dk_xm_image_containing(const DkXmImage *img, u32 a, u32 *start) {
    size_t n;
    const u32 *st = dk_xm_image_starts(img, &n);
    size_t i = upper(st, n, a);
    if (i == 0) return false;
    if (start) *start = st[i - 1];
    return true;
}

size_t dk_xm_image_extent(const DkXmImage *img, u32 start, size_t want, const u8 **p) {
    size_t n;
    const u32 *st = dk_xm_image_starts(img, &n);
    size_t i = upper(st, n, start);
    u64 end = i < n ? st[i] : (u64)start + want * 2;
    u64 cap = want * 2 > want + 256 ? want * 2 : want + 256;
    if (end > (u64)start + cap) end = (u64)start + cap;
    size_t got;
    const u8 *b = dk_xm_image_read(img, start, (size_t)(end - start), &got);
    if (p) *p = b;
    if (!b) return 0;
    if (got > want)
        while (got && b[got - 1] == 0xCC) got--;
    return got;
}

size_t dk_xm_image_find_all(const DkXmImage *img, const void *pat, size_t n, int spans, size_t limit, u32 *out) {
    size_t k = 0;
    const u8 *pp = pat;
    for (int pass = 0; pass < 2; pass++) {
        if (!(spans & (pass == 0 ? DK_XM_SPANS_EXEC : DK_XM_SPANS_DATA))) continue;
        size_t ns = pass == 0 ? img->nexec : img->ndata;
        for (size_t s = 0; s < ns && k < limit; s++) {
            const DkXmSpan *sp = pass == 0 ? &img->execs[s] : &img->datas[s];
            if (n == 0) {
                for (size_t i = 0; i <= sp->len && k < limit; i++) out[k++] = sp->va + (u32)i;
                continue;
            }
            if (sp->len < n) continue;
            const u8 *d = sp->data;
            size_t i = 0;
            while (k < limit && i + n <= sp->len) {
                const u8 *q = memchr(d + i, pp[0], sp->len - n + 1 - i);
                if (!q) break;
                i = (size_t)(q - d);
                if (memcmp(q, pp, n) == 0) out[k++] = sp->va + (u32)i;
                i++;
            }
        }
    }
    return k;
}

/* ---- 4-byte key index: a two-pass radix sort of the positions by the little-endian word ---- */
typedef struct {
    DkXmImage *img;
    size_t sec;
} KParam;

static BOOL CALLBACK build_kidx(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)ctx;
    const KParam *kp = param;
    const DkXmSpan *sp = &kp->img->execs[kp->sec];
    KeyIndex *ki = &kp->img->kidx[kp->sec];
    size_t n = sp->len >= 4 ? sp->len - 3 : 0;
    const u8 *d = sp->data;
    u32 *a = dk_xmalloc((n ? n : 1) * sizeof(u32));
    u32 *b = dk_xmalloc((n ? n : 1) * sizeof(u32));
    u32 *cnt = dk_xcalloc(65537, sizeof(u32));
    /* pass 1: by the low 16 bits (bytes 0, 1), positions in order */
    for (size_t i = 0; i < n; i++) cnt[(d[i] | (d[i + 1] << 8)) + 1]++;
    for (size_t k = 0; k < 65536; k++) cnt[k + 1] += cnt[k];
    for (size_t i = 0; i < n; i++) b[cnt[d[i] | (d[i + 1] << 8)]++] = (u32)i;
    /* pass 2: by the high 16 bits (bytes 2, 3), stable */
    memset(cnt, 0, 65537 * sizeof(u32));
    for (size_t i = 0; i < n; i++) cnt[(d[i + 2] | (d[i + 3] << 8)) + 1]++;
    for (size_t k = 0; k < 65536; k++) cnt[k + 1] += cnt[k];
    u32 *bucket = dk_xmalloc(65537 * sizeof(u32));
    memcpy(bucket, cnt, 65537 * sizeof(u32));
    for (size_t j = 0; j < n; j++) {
        u32 i = b[j];
        a[cnt[d[i + 2] | (d[i + 3] << 8)]++] = i;
    }
    free(b);
    free(cnt);
    ki->pos = a;
    ki->bucket = bucket;
    ki->n = n;
    return TRUE;
}

size_t dk_xm_image_key_positions(const DkXmImage *img, size_t sec, u32 key, const u32 **pos) {
    if (sec >= img->nexec) {
        if (pos) *pos = NULL;
        return 0;
    }
    KParam kp = {(DkXmImage *)img, sec};
    InitOnceExecuteOnce(&img->kidx[sec].once, build_kidx, &kp, NULL);
    const KeyIndex *ki = &img->kidx[sec];
    const u8 *d = img->execs[sec].data;
    u32 hiw = key >> 16, low = key & 0xFFFF;
    size_t lo = ki->bucket[hiw], hi = ki->bucket[hiw + 1];
    /* within a bucket the positions are sorted by the low 16 bits, then by position */
    size_t a = lo, b = hi;
    while (a < b) {
        size_t mid = a + (b - a) / 2;
        u32 p = ki->pos[mid];
        if ((u32)(d[p] | (d[p + 1] << 8)) < low)
            a = mid + 1;
        else
            b = mid;
    }
    size_t first = a;
    b = hi;
    while (a < b) {
        size_t mid = a + (b - a) / 2;
        u32 p = ki->pos[mid];
        if ((u32)(d[p] | (d[p + 1] << 8)) <= low)
            a = mid + 1;
        else
            b = mid;
    }
    if (pos) *pos = ki->pos + first;
    return a - first;
}

/* ---- relocation-gap index ---- */
static int __cdecl cmp_gap(void *ctx, const void *x, const void *y) {
    const u32 *R = ctx;
    u32 i = *(const u32 *)x, j = *(const u32 *)y;
    u32 a1 = R[i + 1] - R[i], b1 = R[j + 1] - R[j];
    if (a1 != b1) return a1 < b1 ? -1 : 1;
    u32 a2 = R[i + 2] - R[i + 1], b2 = R[j + 2] - R[j + 1];
    if (a2 != b2) return a2 < b2 ? -1 : 1;
    return i < j ? -1 : i > j;
}

static BOOL CALLBACK build_fp(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)ctx;
    DkXmImage *img = param;
    const DkPe *pe = img->pe;
    u32 *v = dk_xmalloc((img->nrelocs ? img->nrelocs : 1) * sizeof(u32));
    size_t n = 0;
    for (size_t r = 0; r < img->nrelocs; r++) {
        u32 rva = img->relocs[r] - img->base;
        for (size_t s = 0; s < pe->n_sections; s++) {
            const DkPeSection *sc = &pe->sections[s];
            if (!(sc->characteristics & (u32)DK_SCN_MEM_EXECUTE) || dk_str_eq(sc->name, DK_S(".bind"))) continue;
            u32 a = sc->virtual_address;
            if (rva >= a && rva - a < sc->virtual_size) {
                v[n++] = rva;
                break;
            }
        }
    }
    img->trel = v;
    img->ntrel = n;
    size_t ng = n >= 3 ? n - 2 : 0;
    u32 *g = dk_xmalloc((ng ? ng : 1) * sizeof(u32));
    for (size_t i = 0; i < ng; i++) g[i] = (u32)i;
    qsort_s(g, ng, sizeof(u32), cmp_gap, v);
    img->gap_idx = g;
    img->ngap = ng;
    return TRUE;
}

const u32 *dk_xm_image_text_relocs(const DkXmImage *img, size_t *count) {
    InitOnceExecuteOnce((PINIT_ONCE)&img->fp_once, build_fp, (PVOID)img, NULL);
    if (count) *count = img->ntrel;
    return img->trel;
}

size_t dk_xm_image_reloc_gap_lookup(const DkXmImage *img, u32 g1, u32 g2, const u32 **idx) {
    dk_xm_image_text_relocs(img, NULL);
    const u32 *R = img->trel;
    const u32 *G = img->gap_idx;
    u64 want = ((u64)g1 << 32) | g2;
    size_t lo = 0, hi = img->ngap;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        u32 i = G[mid];
        u64 k = ((u64)(R[i + 1] - R[i]) << 32) | (R[i + 2] - R[i + 1]);
        if (k < want)
            lo = mid + 1;
        else
            hi = mid;
    }
    size_t first = lo;
    hi = img->ngap;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        u32 i = G[mid];
        u64 k = ((u64)(R[i + 1] - R[i]) << 32) | (R[i + 2] - R[i + 1]);
        if (k <= want)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (idx) *idx = G + first;
    return lo - first;
}
