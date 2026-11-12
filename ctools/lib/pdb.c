// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* PDB 7.00 reader: the MSF container, the PDB info stream, the DBI stream, the symbol record stream, module symbols
 * and line tables. The TPI reader is in pdb_types.c. The formats are those the Visual C++ linkers wrote (the CodeView
 * and MSF layouts); where a table is shorter than its header says, the readers throw (pdb_fail) and only the sites
 * that tolerate a bad record (module symbol records, line tables) catch it. */
#include "pdb_internal.h"

#include "dk/dk.h"

/* ---- binary reading helpers ------------------------------------------------------------------------------------ */

void pdb_fail(const char *what) { dk_throw(DK_ERR_FORMAT, "pdb: %s", what); }

const u8 *pdb_at(DkStr b, i64 off, size_t n) {
    if (off < 0 || (u64)off > b.n || n > b.n - (size_t)off) pdb_fail("record or table is shorter than its header says");
    return (const u8 *)b.p + off;
}

char *pdb_latin1(DkArena *a, const void *p, size_t n) {
    const u8 *s = p;
    size_t extra = 0;
    for (size_t i = 0; i < n; i++) extra += s[i] >= 0x80;
    char *out = dk_alloc_noz(a, n + extra + 1), *o = out;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < 0x80) {
            *o++ = (char)s[i];
        } else {
            *o++ = (char)(0xC0 | (s[i] >> 6));
            *o++ = (char)(0x80 | (s[i] & 0x3F));
        }
    }
    *o = 0;
    return out;
}

static char *to_latin1(DkArena *a, const char *s) {
    size_t n = strlen(s);
    char *out = dk_alloc_noz(a, n + 1), *o = out;
    const char *p = s, *end = s + n;
    while (p < end) {
        u32 cp = dk_u8_next(&p, end);
        *o++ = cp <= 0xFF ? (char)cp : '?';
    }
    *o = 0;
    return out;
}

const char *pdb_cstr(DkStr b, i64 p, i64 *next) {
    if (p < 0 || (u64)p >= b.n) pdb_fail("string starts past its table");
    const char *z = memchr(b.p + p, 0, b.n - (size_t)p);
    if (!z) pdb_fail("string has no terminator");
    *next = (i64)(z - b.p) + 1;
    return pdb_latin1(dk_arena(), b.p + p, (size_t)(z - (b.p + p)));
}

const char *pdb_pstr(DkStr b, i64 p, i64 *next) {
    size_t n = pdb_u8(b, p);
    DkStr s = dk_str_slice(b, p + 1, p + 1 + (i64)n);
    *next = p + 1 + (i64)n;
    return pdb_latin1(dk_arena(), s.p, s.n);
}

i64 pdb_numeric(DkStr b, i64 p, i64 *next) {
    u32 v = pdb_le16(b, p);
    p += 2;
    if (v < 0x8000) {
        *next = p;
        return v;
    }
    i64 r;
    switch (v) {
    case 0x8000: r = (i8)pdb_u8(b, p); p += 1; break;
    case 0x8001: r = (i16)pdb_le16(b, p); p += 2; break;
    case 0x8002: r = pdb_le16(b, p); p += 2; break;
    case 0x8003: r = (i32)pdb_le32(b, p); p += 4; break;
    case 0x8004: r = pdb_le32(b, p); p += 4; break;
    case 0x8009:
    case 0x800A: r = (i64)((u64)pdb_le32(b, p) | ((u64)pdb_le32(b, p + 4) << 32)); p += 8; break;
    default: pdb_fail("numeric leaf is not an integer"); /* float leaves included */
    }
    *next = p;
    return r;
}

const char *dk_pdb_undecorate(const char *name, u32 flags) {
    if (name[0] != '?') return name;
    DkArena *a = dk_arena();
    DkStr r = dk_undecorate_symbol(a, to_latin1(a, name), flags);
    return r.n ? pdb_latin1(a, r.p, r.n) : "";
}

/* ---- MSF ------------------------------------------------------------------------------------------------------- */

struct DkMsf {
    DkFileView v;
    u32 bs;
    size_t ns;
    u32 *size;    /* per stream */
    u32 **blocks; /* per stream */
    u32 *nblocks;
};

static DkStr msf_block(const DkMsf *m, u64 i) {
    u64 start = i * m->bs;
    if (start >= m->v.n) return (DkStr){"", 0};
    u64 len = DK_MIN((u64)m->bs, (u64)m->v.n - start);
    return (DkStr){(const char *)m->v.p + start, (size_t)len};
}

/* The blocks joined, cut to limit bytes. */
static DkStr msf_join(const DkMsf *m, const u32 *blocks, size_t n, size_t limit) {
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    for (size_t i = 0; i < n; i++) {
        DkStr s = msf_block(m, blocks[i]);
        dk_buf_putn(&b, s.p, s.n);
    }
    if (b.n > limit) b.n = limit;
    return (DkStr){b.p ? b.p : "", b.n};
}

static const char MSF_MAGIC[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS";

DkMsf *dk_msf_open(const char *path) {
    DkArena *a = dk_arena();
    DkMsf *m = DK_NEW(a, DkMsf);
    if (!dk_view_open(path, &m->v)) dk_throw(DK_ERR_IO, "%s", dk_io_err_str(a).p);
    DkStr d = {(const char *)m->v.p, m->v.n};
    if (d.n < 29 || memcmp(d.p, MSF_MAGIC, 29) != 0) dk_throw(DK_ERR_FORMAT, "pdb: %s is not an MSF 7.00 file", path);
    m->bs = pdb_le32(d, 32);
    u32 dirsize = pdb_le32(d, 44), mapaddr = pdb_le32(d, 52);
    pdb_at(d, 36, 12); /* free block map, block count, unused: must exist */
    if (m->bs == 0) pdb_fail("block size is zero");
    u64 nd = ((u64)dirsize + m->bs - 1) / m->bs;
    u64 nm = (nd * 4 + m->bs - 1) / m->bs;
    DkBuf mapb;
    dk_buf_init(&mapb, a);
    for (u64 i = 0; i < nm; i++) {
        DkStr s = msf_block(m, (u64)mapaddr + i);
        dk_buf_putn(&mapb, s.p, s.n);
    }
    DkStr mapd = {mapb.p ? mapb.p : "", mapb.n};
    pdb_at(mapd, 0, (size_t)nd * 4);
    u32 *dirblocks = DK_NEWN(a, u32, nd + 1);
    for (u64 i = 0; i < nd; i++) dirblocks[i] = pdb_le32(mapd, (i64)i * 4);
    DkStr dr = msf_join(m, dirblocks, (size_t)nd, dirsize);
    m->ns = pdb_le32(dr, 0);
    pdb_at(dr, 4, m->ns * 4);
    m->size = DK_NEWN(a, u32, m->ns + 1);
    m->blocks = DK_NEWN(a, u32 *, m->ns + 1);
    m->nblocks = DK_NEWN(a, u32, m->ns + 1);
    for (size_t i = 0; i < m->ns; i++) m->size[i] = pdb_le32(dr, 4 + 4 * (i64)i);
    i64 pos = 4 + 4 * (i64)m->ns;
    for (size_t i = 0; i < m->ns; i++) {
        u32 s = m->size[i];
        if (s == 0xFFFFFFFFu) { /* nil stream */
            m->size[i] = 0;
            continue;
        }
        u32 n = (u32)(((u64)s + m->bs - 1) / m->bs);
        pdb_at(dr, pos, (size_t)n * 4);
        m->blocks[i] = DK_NEWN(a, u32, n + 1);
        for (u32 j = 0; j < n; j++) m->blocks[i][j] = pdb_le32(dr, pos + 4 * (i64)j);
        m->nblocks[i] = n;
        pos += 4 * (i64)n;
    }
    return m;
}

size_t dk_msf_stream_count(const DkMsf *m) { return m->ns; }

DkStr dk_msf_stream(const DkMsf *m, u32 i) {
    if (i == 0xFFFF || i >= m->ns || m->size[i] == 0 || !m->blocks[i]) return (DkStr){"", 0};
    return msf_join(m, m->blocks[i], m->nblocks[i], m->size[i]);
}

/* ---- the PDB info stream --------------------------------------------------------------------------------------- */

/* The named-stream map of stream 1: name -> stream index (.i). */
static DkMap *parse_pdb_info(DkStr info) {
    i64 p = 28; /* version, signature, age, GUID */
    u32 sz = pdb_le32(info, p);
    p += 4;
    DkStr buf = dk_str_slice(info, p, p + sz);
    p += sz;
    u32 size = pdb_le32(info, p);
    pdb_le32(info, p + 4);
    p += 8;
    u32 nw = pdb_le32(info, p); /* the present bit vector */
    p += 4 + 4 * (i64)nw;
    u32 nw2 = pdb_le32(info, p); /* the deleted bit vector */
    p += 4 + 4 * (i64)nw2;
    DkMap *out = dk_map_new();
    for (u32 i = 0; i < size; i++) {
        u32 no = pdb_le32(info, p), si = pdb_le32(info, p + 4);
        p += 8;
        i64 nx;
        dk_map_put(out, dk_str(pdb_cstr(buf, no, &nx)), NULL)->i = si;
    }
    return out;
}

/* ---- module symbols -------------------------------------------------------------------------------------------- */

static const char *machine_name(u32 m) {
    switch (m) {
    case 0x03: return "386";
    case 0x06: return "P6";
    case 0xD3: return "AMD64";
    case 0xF0: return "ARM";
    default: return "";
    }
}

static DkMap *env_pairs(DkStr body, i64 q) {
    DkStrVec items = {0};
    while (q < (i64)body.n) {
        i64 nx;
        const char *t = pdb_cstr(body, q, &nx);
        dk_vec_push(&items, dk_str(t));
        q = nx;
    }
    DkMap *env = dk_map_new();
    for (size_t i = 0; i + 1 < items.n && items.v[i].n != 0; i += 2) {
        dk_map_put(env, items.v[i], NULL)->p = (void *)items.v[i + 1].p;
    }
    dk_vec_free(&items);
    return env;
}

static const char *versions(DkArena *a, DkStr b, i64 off, int n) {
    DkBuf s;
    dk_buf_init(&s, a);
    for (int i = 0; i < n; i++) dk_buf_printf(&s, "%s%u", i ? "." : "", pdb_le16(b, off + 2 * i));
    return dk_buf_cz(&s);
}

typedef struct {
    DkPdbCompile *comp;
    DkMap **env;
    DkPdbProcSymVec *procs;
    bool legacy;
} SymState;

static void add_proc(SymState *s, const char *kind, const char *name, u32 seg, u32 off, u32 plen, u32 typ) {
    DkPdbProcSym pr = {kind, name, (u16)seg, off, plen, typ};
    dk_vec_push(s->procs, pr);
}

static void set_compile(DkArena *a, DkPdbCompile *comp, u32 mach, u32 flags, i64 language,
                        const char *fe, const char *be, const char *str) {
    comp->present = true;
    comp->machine = dk_sprintf(a, "0x%X %s", mach, machine_name(mach));
    comp->language = language;
    comp->flags_hex = dk_sprintf(a, "0x%X", flags);
    comp->frontend_ver = fe;
    comp->backend_ver = be;
    comp->compiler = str;
}

static void sym_record(SymState *s, u32 ty, DkStr body) {
    DkArena *a = dk_arena();
    DkPdbCompile *comp = s->comp;
    i64 nx;
    if (ty == 0x1110 || ty == 0x110F || ty == 0x1146 || ty == 0x1147) { /* S_GPROC32, S_LPROC32 (and _ID forms) */
        u32 plen = pdb_le32(body, 12), typ = pdb_le32(body, 24), off = pdb_le32(body, 28), seg = pdb_le16(body, 32);
        add_proc(s, (ty == 0x1110 || ty == 0x1146) ? "gproc" : "lproc", pdb_cstr(body, 35, &nx), seg, off, plen, typ);
    } else if (ty == 0x100B || ty == 0x100A) { /* S_GPROC32_ST / S_LPROC32_ST */
        u32 plen = pdb_le32(body, 12), typ = pdb_le32(body, 24), off = pdb_le32(body, 28), seg = pdb_le16(body, 32);
        add_proc(s, ty == 0x100B ? "gproc" : "lproc", pdb_pstr(body, 35, &nx), seg, off, plen, typ);
    } else if ((ty == 0x1116 || ty == 0x113C) && !comp->present) { /* S_COMPILE2, S_COMPILE3 */
        u32 flags = pdb_le32(body, 0), mach = pdb_le16(body, 4);
        const char *fe, *be;
        i64 q;
        if (ty == 0x113C) {
            fe = versions(a, body, 6, 4);
            be = versions(a, body, 14, 4);
            q = 22;
        } else {
            fe = versions(a, body, 6, 3);
            be = versions(a, body, 12, 3);
            q = 18;
        }
        const char *str = pdb_cstr(body, q, &q);
        DkMap *newenv = NULL;
        if (ty == 0x1116 && dk_map_len(*s->env) == 0) newenv = env_pairs(body, q);
        if (newenv) *s->env = newenv;
        set_compile(a, comp, mach, flags, flags & 0xFF, fe, be, str);
    } else if (ty == 0x113D && dk_map_len(*s->env) == 0) { /* S_ENVBLOCK */
        *s->env = env_pairs(body, 1);
    } else if (s->legacy && (ty == 0x0205 || ty == 0x0204)) { /* S_GPROC32_16t / S_LPROC32_16t */
        u32 plen = pdb_le32(body, 12), off = pdb_le32(body, 24), seg = pdb_le16(body, 28), typ = pdb_le16(body, 30);
        add_proc(s, ty == 0x0205 ? "gproc" : "lproc", pdb_pstr(body, 31, &nx), seg, off, plen, typ);
    } else if (s->legacy && ty == 0x1013 && !comp->present) { /* S_COMPILE2_ST */
        u32 flags = pdb_le32(body, 0), mach = pdb_le16(body, 4);
        const char *fe = versions(a, body, 6, 4), *be = versions(a, body, 14, 4);
        const char *str = pdb_pstr(body, 22, &nx);
        set_compile(a, comp, mach, flags, flags & 0xFF, fe, be, str);
    } else if (s->legacy && ty == 0x0001 && !comp->present) { /* S_COMPILE */
        u32 mach = pdb_u8(body, 0), fl = pdb_u8(body, 1) | ((u32)pdb_u8(body, 2) << 8) | ((u32)pdb_u8(body, 3) << 16);
        const char *str = pdb_pstr(body, 4, &nx);
        set_compile(a, comp, mach, fl, pdb_u8(body, 1), "", "", str);
    }
}

void dk_pdb_parse_module_symbols(DkStr symdata, bool legacy, DkPdbCompile *comp, DkMap **env, DkPdbProcSymVec *procs) {
    memset(comp, 0, sizeof *comp);
    *env = dk_map_new();
    SymState st = {comp, env, procs, legacy};
    i64 p = 0, n = (i64)symdata.n;
    while (p + 4 <= n) {
        u32 ln = pdb_le16(symdata, p);
        if (ln < 2) break;
        u32 ty = pdb_le16(symdata, p + 2);
        DkStr body = dk_str_slice(symdata, p + 4, p + 2 + (i64)ln);
        p += 2 + (i64)ln;
        DkTry tr;
        if (DK_TRY(&tr)) {
            sym_record(&st, ty, body);
            dk_try_end(&tr);
        } /* a record that does not parse is skipped */
    }
}

/* ---- line tables ----------------------------------------------------------------------------------------------- */

typedef struct {
    u32 seg;
    i64 off; /* the block's first line offset */
    u32 fid; /* offset of the file in the checksum subsection */
} LineBlock;
typedef DK_VEC(LineBlock) LineBlockVec;

typedef struct {
    u32 seg, off, line, fid;
} LineEnt;
typedef DK_VEC(LineEnt) LineEntVec;

typedef struct {
    u32 seg, start, end;
    const char *name;
} C11Range;
typedef DK_VEC(C11Range) C11RangeVec;

/* DEBUG_S_LINES (0xF2) and DEBUG_S_FILECHKSMS (0xF4) subsections: the blocks, the entries and file id -> name offset. */
static void parse_c13_lines(DkStr c13, LineBlockVec *blocks, LineEntVec *ents, DkIMap *files) {
    i64 p = 0, n = (i64)c13.n;
    while (p + 8 <= n) {
        u32 ty = pdb_le32(c13, p), ln = pdb_le32(c13, p + 4);
        p += 8;
        DkStr sub = dk_str_slice(c13, p, p + ln);
        p += ((i64)ln + 3) & ~(i64)3;
        ty &= 0x7FFFFFFF;
        if (ty == 0xF4) {
            i64 q = 0;
            while (q + 6 <= (i64)sub.n) {
                dk_imap_put(files, (u64)q, NULL)->i = pdb_le32(sub, q);
                q = (q + 6 + pdb_u8(sub, q + 4) + 3) & ~(i64)3;
            }
        } else if (ty == 0xF2) {
            u32 off0 = pdb_le32(sub, 0);
            u32 seg = pdb_le16(sub, 4);
            pdb_le16(sub, 6);
            pdb_le32(sub, 8);
            i64 q = 12;
            while (q + 12 <= (i64)sub.n) {
                u32 fid = pdb_le32(sub, q), nl = pdb_le32(sub, q + 4), cbb = pdb_le32(sub, q + 8);
                for (u32 i = 0; i < nl; i++) {
                    LineEnt e = {seg, off0 + pdb_le32(sub, q + 12 + 8 * (i64)i),
                                 pdb_le32(sub, q + 16 + 8 * (i64)i) & 0xFFFFFFu, fid};
                    dk_vec_push(ents, e);
                }
                if (nl) {
                    LineBlock b = {seg, (i64)off0 + pdb_le32(sub, q + 12), fid};
                    dk_vec_push(blocks, b);
                }
                q += cbb >= 12 ? (i64)cbb : 12 + (i64)nl * 8;
            }
        }
    }
}

/* The old (C11) line table: per file, the code ranges it covers. */
static void parse_c11_lines(DkStr c11, C11RangeVec *out) {
    u32 cfile = pdb_le16(c11, 0);
    pdb_le16(c11, 2);
    pdb_at(c11, 4, (size_t)cfile * 4);
    for (u32 f = 0; f < cfile; f++) {
        i64 b = pdb_le32(c11, 4 + 4 * (i64)f);
        u32 cs = pdb_le16(c11, b);
        pdb_at(c11, b + 4, (size_t)cs * 4);
        pdb_at(c11, b + 4 + 4 * (i64)cs, (size_t)cs * 8);
        i64 q = b + 4 + 12 * (i64)cs;
        u32 nl = pdb_le16(c11, q);
        DkStr nm = dk_str_slice(c11, q + 2, q + 2 + nl);
        while (nm.n && nm.p[nm.n - 1] == 0) nm.n--;
        const char *name = pdb_latin1(dk_arena(), nm.p, nm.n);
        for (u32 i = 0; i < cs; i++) {
            u32 bsl = pdb_le32(c11, b + 4 + 4 * (i64)i);
            C11Range r = {pdb_le16(c11, bsl), pdb_le32(c11, b + 4 + 4 * (i64)cs + 8 * (i64)i),
                          pdb_le32(c11, b + 4 + 4 * (i64)cs + 8 * (i64)i + 4), name};
            dk_vec_push(out, r);
        }
    }
}

static int cmp_block(const void *x, const void *y, void *ctx) {
    DK_UNUSED(ctx);
    const LineBlock *p = x, *q = y;
    if (p->seg != q->seg) return p->seg < q->seg ? -1 : 1;
    if (p->off != q->off) return p->off < q->off ? -1 : 1;
    if (p->fid != q->fid) return p->fid < q->fid ? -1 : 1;
    return 0;
}

/* The /names string at 12 + off, "" where there is none. */
static const char *name_at(DkStr names, i64 off) {
    i64 p = 12 + off;
    if (p < 0 || (u64)p >= names.n) return "";
    const char *z = memchr(names.p + p, 0, names.n - (size_t)p);
    if (!z) return "";
    return pdb_latin1(dk_arena(), names.p + p, (size_t)(z - (names.p + p)));
}

/* ---- read ------------------------------------------------------------------------------------------------------ */

bool dk_pdb_rva(const DkPdb *p, u32 seg, u32 off, i64 *rva) {
    if (seg < 1 || seg > p->sections.n) return false;
    *rva = (i64)p->sections.v[seg - 1] + off;
    return true;
}

const DkCzVec *dk_pdb_publics_at(const DkPdb *p, u32 seg, u32 off) {
    DkVal *v = dk_imap_get(p->at, ((u64)seg << 32) | off);
    return v ? v->p : NULL;
}

static const char *base_name_of(DkArena *a, const char *s) {
    char *z = dk_strdup(a, s);
    for (char *c = z; *c; c++)
        if (*c == '\\') *c = '/';
    return dk_cz(a, dk_path_basename(z));
}

static void read_contribs(DkPdb *out, DkStr sc) {
    if (sc.n < 4) return;
    u32 ver = pdb_le32(sc, 0);
    size_t esz = ver == 0xF12EBA2Du ? 28 : ver == 0xF13151E4u ? 32 : 0;
    if (!esz) return;
    for (size_t p = 4; p + esz <= sc.n; p += esz) {
        DkPdbContrib c = {pdb_le16(sc, (i64)p), pdb_le32(sc, (i64)p + 4), pdb_le32(sc, (i64)p + 8),
                          pdb_le32(sc, (i64)p + 12), pdb_le16(sc, (i64)p + 16)};
        dk_vec_push(&out->contribs, c);
    }
}

static void read_publics(DkPdb *out, DkStr srec) {
    DkArena *a = dk_arena();
    i64 p = 0;
    while (p + 4 <= (i64)srec.n) {
        u32 ln = pdb_le16(srec, p), ty = pdb_le16(srec, p + 2);
        if (ln < 2) break;
        DkStr body = dk_str_slice(srec, p + 4, p + 2 + (i64)ln);
        p += 2 + (i64)ln;
        if (ty == 0x110E || ty == 0x1009) { /* S_PUB32, S_PUB32_ST */
            u32 fl = pdb_le32(body, 0), off = pdb_le32(body, 4), seg = pdb_le16(body, 8);
            i64 nx;
            const char *nm = ty == 0x110E ? pdb_cstr(body, 10, &nx) : pdb_pstr(body, 10, &nx);
            DkPdbPublic pub = {nm, (u16)seg, off, fl};
            dk_vec_push(&out->pubs, pub);
            if (fl & 3) { /* code or function */
                bool created;
                DkVal *v = dk_imap_put(out->at, ((u64)seg << 32) | off, &created);
                if (created) v->p = DK_NEW(a, DkCzVec);
                dk_vec_push((DkCzVec *)v->p, (char *)nm);
            }
        }
    }
}

DkPdb dk_pdb_read(const char *pdb_path, bool legacy) {
    DkArena *a = dk_arena();
    DkPdb out = {0};
    DkMsf *msf = dk_msf_open(pdb_path);
    out.msf = msf;
    DkMap *info = parse_pdb_info(dk_msf_stream(msf, 1));
    DkVal *nv = dk_map_get(info, DK_S("/names"));
    DkStr names = nv ? dk_msf_stream(msf, (u32)nv->i) : (DkStr){"", 0};

    DkStr dbi = dk_msf_stream(msf, 3);
    u32 srs = pdb_le16(dbi, 20);
    i64 modsz = (i32)pdb_le32(dbi, 24), scsz = (i32)pdb_le32(dbi, 28), smsz = (i32)pdb_le32(dbi, 32),
        fisz = (i32)pdb_le32(dbi, 36), tsmsz = (i32)pdb_le32(dbi, 40), optsz = (i32)pdb_le32(dbi, 48),
        ecsz = (i32)pdb_le32(dbi, 52);
    pdb_at(dbi, 0, 64);
    DkStr modinfo = dk_str_slice(dbi, 64, 64 + modsz);
    read_contribs(&out, dk_str_slice(dbi, 64 + modsz, 64 + modsz + scsz));
    i64 p = 64 + modsz + scsz + smsz + fisz + tsmsz + ecsz;
    DkStr opt = dk_str_slice(dbi, p, p + optsz);
    u32 opt5 = 0xFFFF;
    if (opt.n >= 12) opt5 = pdb_le16(opt, 10); /* the section header stream: the sixth optional debug stream */
    DkStr sh = dk_msf_stream(msf, opt5);
    for (size_t i = 0; i < sh.n / 40; i++) dk_vec_push(&out.sections, pdb_le32(sh, (i64)i * 40 + 12));

    out.at = dk_imap_new();
    read_publics(&out, dk_msf_stream(msf, srs));

    out.types = dk_pdb_types_new(dk_msf_stream(msf, 2));
    p = 0;
    while (p < (i64)modinfo.n) {
        pdb_at(modinfo, p, 48);
        u32 sec = pdb_le16(modinfo, p + 4);
        u32 soff = pdb_le32(modinfo, p + 8), ssz = pdb_le32(modinfo, p + 12);
        u32 msi = pdb_le16(modinfo, p + 34);
        u32 symsz = pdb_le32(modinfo, p + 36), c11sz = pdb_le32(modinfo, p + 40), c13sz = pdb_le32(modinfo, p + 44);
        i64 q;
        const char *mname = pdb_cstr(modinfo, p + 64, &q);
        const char *oname = pdb_cstr(modinfo, q, &q);
        p = (q + 3) & ~(i64)3;
        u32 idx = (u32)out.mods.n;
        DkPdbCompile comp = {0};
        DkMap *env = dk_map_new();
        DkPdbProcSymVec mprocs = {0};
        LineBlockVec blocks = {0};
        LineEntVec ents = {0};
        C11RangeVec ranges = {0};
        DkIMap *files = dk_imap_new();
        if (msi != 0xFFFF) {
            DkStr ms = dk_msf_stream(msf, msi);
            dk_pdb_parse_module_symbols(dk_str_slice(ms, 4, symsz), legacy, &comp, &env, &mprocs);
            DkStr c11b = dk_str_slice(ms, symsz, (i64)symsz + c11sz);
            DkStr c13b = dk_str_slice(ms, (i64)symsz + c11sz, (i64)symsz + c11sz + c13sz);
            if (c13b.n) {
                DkTry tr;
                if (DK_TRY(&tr)) {
                    parse_c13_lines(c13b, &blocks, &ents, files);
                    dk_try_end(&tr);
                } else { /* a bad table: no lines for this module */
                    dk_vec_clear(&blocks);
                    dk_vec_clear(&ents);
                    files = dk_imap_new();
                }
            }
            if (c11b.n && blocks.n == 0) {
                DkTry tr;
                if (DK_TRY(&tr)) {
                    parse_c11_lines(c11b, &ranges);
                    dk_try_end(&tr);
                } else {
                    dk_vec_clear(&ranges);
                }
            }
        }
        if (blocks.n) dk_sort(blocks.v, blocks.n, sizeof(LineBlock), cmp_block, NULL, false);
        const char *obj = base_name_of(a, mname);
        bool same = strcmp(oname, mname) == 0;
        DkPdbModule mod = {0};
        mod.index = idx;
        mod.name = mname;
        mod.object = obj;
        mod.library = (oname[0] && !same) ? base_name_of(a, oname) : "";
        mod.objname = oname;
        mod.sec = (u16)sec;
        mod.sec_off = soff;
        mod.sec_size = ssz;
        mod.compile = comp;
        mod.env = env;
        mod.sym_bytes = symsz;
        mod.c11_bytes = c11sz;
        mod.c13_bytes = c13sz;
        dk_vec_push(&out.mods, mod);
        for (size_t i = 0; i < ents.n; i++) {
            DkVal *fv = dk_imap_get(files, ents.v[i].fid);
            DkPdbLine l = {idx, (u16)ents.v[i].seg, ents.v[i].off, 0, ents.v[i].line, name_at(names, fv ? fv->i : 0)};
            dk_vec_push(&out.lines, l);
        }
        for (size_t i = 0; i < ranges.n; i++) {
            DkPdbLine l = {idx, (u16)ranges.v[i].seg, ranges.v[i].start, ranges.v[i].end, 0, ranges.v[i].name};
            dk_vec_push(&out.lines, l);
        }
        for (size_t i = 0; i < mprocs.n; i++) {
            const DkPdbProcSym *pr = &mprocs.v[i];
            const char *src = "";
            if (blocks.n) {
                /* the last block at or before (seg, off) */
                size_t lo = 0, hi = blocks.n;
                while (lo < hi) {
                    size_t mid = (lo + hi) / 2;
                    const LineBlock *b = &blocks.v[mid];
                    bool le = b->seg < pr->seg || (b->seg == pr->seg && b->off <= (i64)pr->off);
                    if (le) lo = mid + 1;
                    else hi = mid;
                }
                if (lo > 0 && blocks.v[lo - 1].seg == pr->seg) {
                    DkVal *fv = dk_imap_get(files, blocks.v[lo - 1].fid);
                    src = name_at(names, fv ? fv->i : 0);
                }
            } else {
                for (size_t j = 0; j < ranges.n; j++) {
                    const C11Range *r = &ranges.v[j];
                    if (r->seg == pr->seg && r->start <= pr->off && pr->off < r->end) {
                        src = r->name;
                        break;
                    }
                }
            }
            DkPdbProc pp = {pr->kind, pr->name, pr->seg, pr->off, pr->length, pr->typind, idx, src};
            dk_vec_push(&out.procs, pp);
        }
        dk_vec_free(&mprocs);
        dk_vec_free(&blocks);
        dk_vec_free(&ents);
        dk_vec_free(&ranges);
    }
    return out;
}
