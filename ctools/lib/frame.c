// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Stack-frame layouts of one function, ours against the reference's, read from the machine code of both: the
 * prologue (saved registers, frame size, frame pointer, alignment, /GS cookie, EH registration) and every stack slot an
 * instruction reads, writes or takes the address of, by its offset from the entry ESP. ESP is followed instruction by
 * instruction, two passes so backward jumps count; calls pop what the callee's `ret n` says, imports from a cdecl
 * library (frame.h) pop nothing, other calls pop the pushes since the previous call. */
#include "frame.h"

#include "dk/disasm.h"
#include "dk/fmt.h"
#include "dk/fs.h"
#include "dk/pe.h"

#include <stdio.h>

const char dk_frame_doc[] =
#include "frame_doc.inc"
    ;

#define INTERNAL(...) dk_panic(__FILE__, __LINE__, __VA_ARGS__)
#define F(...) (dk_pyfmt(dk_arena(), __VA_ARGS__))

enum { CS_AC_READ_ = 1, CS_AC_WRITE_ = 2 };

/* ---- import table ----------------------------------------------------------------------------------------------- */

/* {IAT slot: the import library's name, lower case} of an executable, cached per path. The cache is for a single
 * thread. */
static DkMap *g_import_cache; /* path -> DkIMap* */

static DkIMap *import_dlls(const DkFrameRetail *retail) {
    if (!g_import_cache) g_import_cache = dk_map_new();
    DkStr key = dk_str(retail->path);
    DkVal *hit = dk_map_get(g_import_cache, key);
    if (hit) return (DkIMap *)hit->p;
    DkArena *a = dk_arena();
    DkFileView *v = DK_NEW(a, DkFileView); /* the mapping stays open: names are views into it */
    if (!dk_view_open(retail->path, v)) {
        DkStr e = dk_io_err_str(a);
        dk_throw(DK_ERR_IO, "%.*s", DK_SF(e));
    }
    DkPe *pe = dk_pe_parse(a, v->p, v->n);
    DkPeImports imps = dk_pe_imports(pe, a);
    DkIMap *out = dk_imap_new();
    for (size_t i = 0; imps.present && i < imps.n; i++) {
        DkPeImportDll *d = &imps.dlls[i];
        DkStr lower = dk_str_lower(a, d->dll);
        for (size_t k = 0; k < d->n; k++) dk_imap_put(out, d->imports[k].address, NULL)->p = (void *)dk_cz(a, lower);
    }
    dk_map_put(g_import_cache, dk_str_dup(a, key), NULL)->p = out;
    return out;
}

/* Shell match of name against pattern, "*" any run, case-insensitive. */
static bool glob_ci(const char *pat, const char *s) {
    if (!*pat) return !*s;
    if (*pat == '*') {
        for (;; s++) {
            if (glob_ci(pat + 1, s)) return true;
            if (!*s) return false;
        }
    }
    if (!*s) return false;
    char a = *pat, b = *s;
    if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
    if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
    return a == b && glob_ci(pat + 1, s + 1);
}

/* Whether the import at the IAT slot is cdecl: its library is one of the cdecl patterns. */
static bool import_is_cdecl(const DkFrameRetail *retail, u64 slot) {
    DkVal *d = dk_imap_get(import_dlls(retail), slot);
    if (!d) return false;
    const char *dll = (const char *)d->p;
    if (!retail->n_cdecl_dlls) return glob_ci("msvcr*", dll);
    for (size_t i = 0; i < retail->n_cdecl_dlls; i++)
        if (glob_ci(retail->cdecl_dlls[i], dll)) return true;
    return false;
}

/* ---- callee_pops ---------------------------------------------------------------------------------------------- */

static DkMap *g_pops_cache; /* "path|target" -> pops, INT64_MIN for a cached None */

bool dk_frame_callee_pops(const DkFrameRetail *retail, bool has_target, i64 target, i64 *pops) {
    if (!has_target || !retail) return false;
    DkArena *a = dk_arena();
    if (!g_pops_cache) g_pops_cache = dk_map_new();
    DkStr key = dk_pyfmt(a, "%s|%d", retail->path, target);
    DkVal *hit = dk_map_get(g_pops_cache, key);
    if (hit) {
        if (hit->i == INT64_MIN) return false;
        *pops = hit->i;
        return true;
    }
    bool have = false;
    i64 result = 0;
    DkStr head = retail->read(retail->ctx, target, 6);
    if (head.n >= 2 && (u8)head.p[0] == 0xFF && (u8)head.p[1] == 0x25) { /* jmp [IAT]: the linker's import thunk */
        if (head.n < 6) INTERNAL("struct.error: unpack_from requires a buffer of at least 6 bytes");
        const u8 *h = (const u8 *)head.p;
        u64 slot = (u64)h[2] | (u64)h[3] << 8 | (u64)h[4] << 16 | (u64)h[5] << 24;
        if (import_is_cdecl(retail, slot)) {
            have = true;
            result = 0;
        }
    } else if (retail->text_start <= target && target < retail->text_end) {
        i64 want = DK_MIN((i64)8192, retail->text_end - target);
        DkStr code = retail->read(retail->ctx, target, want);
        DkDisIter it;
        dk_dis_iter(&it, dk_dis(DK_DIS_X86_32, 0), code.p, code.n, (u64)target, 0);
        while (dk_dis_next(&it)) {
            const cs_insn *ins = it.insn;
            if (strcmp(ins->mnemonic, "ret") == 0) {
                if (ins->op_str[0]) {
                    i64 v;
                    if (dk_parse_int(dk_str(ins->op_str), 16, &v, NULL)) { /* else except ValueError: None */
                        have = true;
                        result = v;
                    }
                } else {
                    have = true;
                    result = 0;
                }
                break;
            }
            if (strcmp(ins->mnemonic, "int3") == 0) break;
        }
    }
    dk_map_put(g_pops_cache, dk_str_dup(a, key), NULL)->i = have ? result : INT64_MIN;
    *pops = result;
    return have;
}

/* ---- Slot and Frame ----------------------------------------------------------------------------------------- */

static u64 slot_key(DkFrameBase base, i64 offset) { return ((u64)offset << 1) | (u64)base; }

static DkFrameSlot *frame_slot(DkArena *a, DkFrame *f, DkFrameBase base, i64 offset) {
    bool created;
    DkVal *v = dk_imap_put(f->index, slot_key(base, offset), &created);
    if (created) {
        DkFrameSlot *s = DK_NEW(a, DkFrameSlot);
        s->base = base;
        s->offset = offset;
        v->p = s;
        f->slots = (DkFrameSlot **)dk_arena_realloc(a, f->slots, f->n_slots * sizeof(void *),
                                                      (f->n_slots + 1) * sizeof(void *));
        f->slots[f->n_slots++] = s;
    }
    return (DkFrameSlot *)v->p;
}

static const DkFrameSlot *frame_find(const DkFrame *f, DkFrameBase base, i64 offset) {
    DkVal *v = dk_imap_get(f->index, slot_key(base, offset));
    return v ? (const DkFrameSlot *)v->p : NULL;
}

/* Slot.label() */
static DkStr slot_label(const DkFrameSlot *s) {
    i64 mag = s->offset < 0 ? -s->offset : s->offset;
    return F("%s%s0x%X", s->base == DK_FRAME_ALIGNED ? "A" : "", s->offset < 0 ? "-" : "+", mag);
}

/* Slot.access() */
static DkStr slot_access(const DkFrameSlot *s) {
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    if (s->reads) dk_buf_put(&b, F("r%d", s->reads));
    if (s->writes) {
        if (b.n) dk_buf_putc(&b, ' ');
        dk_buf_put(&b, F("w%d", s->writes));
    }
    if (s->addrs) {
        if (b.n) dk_buf_putc(&b, ' ');
        dk_buf_put(&b, F("a%d", s->addrs));
    }
    return dk_buf_str(&b);
}

static bool size_has(const DkFrameSlot *s, unsigned n) { return (s->size_mask[n >> 6] >> (n & 63)) & 1; }

/* Slot.size_text() */
static DkStr slot_size_text(const DkFrameSlot *s) {
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    for (unsigned n = 0; n < 256; n++) {
        if (!size_has(s, n)) continue;
        if (b.n) dk_buf_putc(&b, '/');
        dk_buf_put(&b, F("%d", (i64)n));
    }
    return b.n ? dk_buf_str(&b) : DK_S("-");
}

static bool sizes_equal(const DkFrameSlot *x, const DkFrameSlot *y) {
    return memcmp(x->size_mask, y->size_mask, sizeof x->size_mask) == 0;
}

/* ---- analyse ------------------------------------------------------------------------------------------- */

typedef struct {
    DkFrameBase mode;
    i64 delta;
    bool has_ebp;
    i64 ebp;
} EspState;

static const char *reg_name(const DkDis *d, unsigned reg) {
    const char *n = dk_dis_reg_name(d, reg);
    return n ? n : "";
}

/* ins.operands[i]: an IndexError (D3) when the instruction has fewer operands. */
static const cs_x86_op *op_at(const cs_insn *ins, unsigned i) {
    if (!ins->detail || i >= ins->detail->x86.op_count) INTERNAL("IndexError: operand %u of '%s'", i, ins->mnemonic);
    return &ins->detail->x86.operands[i];
}
#define OPC(ins) ((ins)->detail ? (ins)->detail->x86.op_count : 0u)

typedef enum { CALL_DIRECT, CALL_IMPORT, CALL_INDIRECT } CallKind;

static const DkFrameReloc *reloc_get(DkIMap *rmap, i64 off) {
    DkVal *v = dk_imap_get(rmap, (u64)off);
    return v ? (const DkFrameReloc *)v->p : NULL;
}

/* _call_target: the kind and the target (has_target false: None). */
static CallKind call_target(const cs_insn *ins, DkIMap *rmap, bool has_relocs, i64 base, bool *has_target, i64 *target) {
    const cs_x86_op *op = op_at(ins, 0);
    i64 off = (i64)ins->address - base;
    if (ins->bytes[0] == 0xE8) {
        if (has_relocs) {
            const DkFrameReloc *r = reloc_get(rmap, off + 1);
            *has_target = r && r->has_target;
            *target = *has_target ? r->target : 0;
        } else {
            *has_target = true;
            *target = (i64)((u64)op->imm & 0xFFFFFFFFull);
        }
        return CALL_DIRECT;
    }
    if (op->type == X86_OP_MEM && op->mem.base == 0 && op->mem.index == 0) {
        if (has_relocs) {
            const DkFrameReloc *r = reloc_get(rmap, off + 2);
            *has_target = r && r->has_target;
            *target = *has_target ? r->target : 0;
        } else {
            *has_target = true;
            *target = (i64)((u64)op->mem.disp & 0xFFFFFFFFull);
        }
        return CALL_IMPORT;
    }
    *has_target = false;
    *target = 0;
    return CALL_INDIRECT;
}

static bool is_mnem(const cs_insn *ins, const char *m) { return strcmp(ins->mnemonic, m) == 0; }
static bool opstr_starts(const cs_insn *ins, const char *p) { return strncmp(ins->op_str, p, strlen(p)) == 0; }
static bool reg_is(const DkDis *d, const cs_x86_op *op, const char *name) {
    return strcmp(reg_name(d, op->reg), name) == 0;
}

static EspState *known_get(DkIMap *known, u64 address) {
    DkVal *v = dk_imap_get(known, address);
    return v ? (EspState *)v->p : NULL;
}

DkFrame *dk_frame_analyse(DkArena *a, DkStr code, i64 base, const DkFrameRetail *retail,
                            const DkFrameReloc *relocs, size_t n_relocs, bool has_relocs) {
    DkDis *dis = dk_dis(DK_DIS_X86_32, DK_DIS_DETAIL);
    size_t n_insns = 0;
    cs_insn *insns = dk_dis_all(dis, code.p, code.n, (u64)base, 0, &n_insns);
    DkIMap *rmap = dk_imap_new();
    for (size_t i = 0; i < n_relocs; i++) dk_imap_put(rmap, (u64)relocs[i].offset, NULL)->p = (void *)&relocs[i];
    DkIMap *known = dk_imap_new(); /* address -> (esp mode, delta, ebp) */
    DkFrame *frame = NULL;
    for (int pass = 0; pass < 2; pass++) {
        frame = DK_NEW(a, DkFrame);
        frame->index = dk_imap_new();
        EspState st = {DK_FRAME_ENTRY, 0, false, 0};
        i64 pending = 0; /* bytes pushed since the previous call (the arguments of the next one) */
        bool in_prologue = true, after_end = false;
        const cs_insn *prev = NULL;
        for (size_t k = 0; k < n_insns; k++) {
            const cs_insn *ins = &insns[k];
            EspState *kn = known_get(known, ins->address);
            if (after_end) {
                if (kn) st = *kn;
                after_end = false;
            } else if (kn && pass == 1) {
                st = *kn;
            }
            const char *m = ins->mnemonic;
            unsigned nops = OPC(ins);
            /* the memory operands, at the ESP of the instruction's start */
            for (unsigned oi = 0; oi < nops; oi++) {
                const cs_x86_op *op = op_at(ins, oi);
                if (op->type != X86_OP_MEM) continue;
                unsigned reg = op->mem.base;
                DkFrameBase wb;
                i64 woff;
                if (reg == X86_REG_ESP) {
                    wb = st.mode;
                    woff = op->mem.disp + st.delta;
                } else if (reg == X86_REG_EBP && st.has_ebp) {
                    wb = DK_FRAME_ENTRY;
                    woff = op->mem.disp + st.ebp;
                } else {
                    continue;
                }
                DkFrameSlot *s = frame_slot(a, frame, wb, woff);
                if (is_mnem(ins, "lea")) {
                    s->addrs++;
                } else {
                    s->size_mask[op->size >> 6] |= (u64)1 << (op->size & 63);
                    if ((op->access & CS_AC_READ_) || strncmp(m, "push", 4) == 0) s->reads++;
                    if (op->access & CS_AC_WRITE_) s->writes++;
                }
                if (op->mem.index) s->indexed = true;
                s->acc = (DkFrameAccess *)dk_arena_realloc(a, s->acc, s->n_acc * sizeof(DkFrameAccess),
                                                             (s->n_acc + 1) * sizeof(DkFrameAccess));
                s->acc[s->n_acc++] = (DkFrameAccess){(i64)ins->address - base, is_mnem(ins, "lea") ? 0u : op->size,
                                                      is_mnem(ins, "lea")                  ? 'a'
                                                      : (op->access & CS_AC_WRITE_)        ? 'w'
                                                                                           : 'r'};
            }
            if (in_prologue) {
                const cs_x86_op *o0 = nops ? op_at(ins, 0) : NULL;
                const char *r0 = (o0 && o0->type == X86_OP_REG) ? reg_name(dis, o0->reg) : "";
                if (is_mnem(ins, "push") && o0 && o0->type == X86_OP_REG &&
                    (!strcmp(r0, "ebx") || !strcmp(r0, "esi") || !strcmp(r0, "edi") || !strcmp(r0, "ebp"))) {
                    if (frame->n_saved >= DK_ARRAY_LEN(frame->saved)) INTERNAL("too many saved registers");
                    frame->saved[frame->n_saved++] = dk_str(r0);
                } else if (is_mnem(ins, "push") && o0 && o0->type == X86_OP_IMM &&
                           ((u64)o0->imm & 0xFFFFFFFFull) == 0xFFFFFFFFull) {
                    frame->eh = true;
                } else if (is_mnem(ins, "sub") && reg_is(dis, op_at(ins, 0), "esp") && op_at(ins, 1)->type == X86_OP_IMM) {
                    frame->locals += op_at(ins, 1)->imm;
                } else if (is_mnem(ins, "mov") || is_mnem(ins, "push") || is_mnem(ins, "xor") || is_mnem(ins, "and") ||
                           is_mnem(ins, "lea")) {
                    /* pass */
                } else if (is_mnem(ins, "call") && prev && is_mnem(prev, "mov") && opstr_starts(prev, "eax, 0x")) {
                    /* pass: __chkstk, counted below */
                } else {
                    in_prologue = false;
                }
                if (k > 16) in_prologue = false;
            }
            if (is_mnem(ins, "xor") && nops == 2 && op_at(ins, 0)->type == X86_OP_REG &&
                op_at(ins, 1)->type == X86_OP_REG &&
                (reg_is(dis, op_at(ins, 1), "esp") || reg_is(dis, op_at(ins, 1), "ebp")) && k + 1 < n_insns &&
                !frame->has_cookie) {
                const cs_insn *nxt = &insns[k + 1];
                if (is_mnem(nxt, "mov") && op_at(nxt, 0)->type == X86_OP_MEM) {
                    const x86_op_mem *mo = &op_at(nxt, 0)->mem;
                    if (mo->base == X86_REG_ESP) {
                        frame->has_cookie = true;
                        frame->cookie_base = st.mode;
                        frame->cookie_offset = mo->disp + st.delta;
                    } else if (mo->base == X86_REG_EBP && st.has_ebp) {
                        frame->has_cookie = true;
                        frame->cookie_base = DK_FRAME_ENTRY;
                        frame->cookie_offset = mo->disp + st.ebp;
                    }
                }
            }
            if (is_mnem(ins, "mov") && strstr(ins->op_str, "fs:") && opstr_starts(ins, "eax")) frame->eh = true;
            /* ESP */
            if (is_mnem(ins, "push")) {
                st.delta -= (nops && op_at(ins, 0)->size == 2) ? 2 : 4;
                pending += 4;
            } else if (is_mnem(ins, "pushfd")) {
                st.delta -= 4;
            } else if (is_mnem(ins, "pop")) {
                st.delta += 4;
            } else if (is_mnem(ins, "popfd")) {
                st.delta += 4;
            } else if ((is_mnem(ins, "sub") || is_mnem(ins, "add")) && nops && op_at(ins, 0)->type == X86_OP_REG &&
                       reg_is(dis, op_at(ins, 0), "esp")) {
                if (op_at(ins, 1)->type == X86_OP_IMM) {
                    i64 imm = op_at(ins, 1)->imm;
                    st.delta += is_mnem(ins, "sub") ? -imm : imm;
                    if (is_mnem(ins, "add")) pending = DK_MAX((i64)0, pending - imm);
                }
            } else if (is_mnem(ins, "lea") && op_at(ins, 0)->type == X86_OP_REG && reg_is(dis, op_at(ins, 0), "esp")) {
                const x86_op_mem *mo = &op_at(ins, 1)->mem;
                if (mo->base == X86_REG_ESP) {
                    st.delta += mo->disp;
                } else if (mo->base == X86_REG_EBP && st.has_ebp) {
                    st.mode = DK_FRAME_ENTRY;
                    st.delta = st.ebp + mo->disp;
                }
            } else if (is_mnem(ins, "mov") && op_at(ins, 0)->type == X86_OP_REG && op_at(ins, 1)->type == X86_OP_REG) {
                const char *dst = reg_name(dis, op_at(ins, 0)->reg), *src = reg_name(dis, op_at(ins, 1)->reg);
                if (strcmp(dst, "ebp") == 0 && strcmp(src, "esp") == 0) {
                    if (st.mode == DK_FRAME_ENTRY) {
                        st.has_ebp = true;
                        st.ebp = st.delta;
                        frame->has_frame_pointer = true;
                        frame->frame_pointer = st.delta;
                    }
                } else if (strcmp(dst, "esp") == 0 && strcmp(src, "ebp") == 0 && st.has_ebp) {
                    st.mode = DK_FRAME_ENTRY;
                    st.delta = st.ebp;
                }
            } else if (is_mnem(ins, "lea") && op_at(ins, 0)->type == X86_OP_REG && reg_is(dis, op_at(ins, 0), "ebp") &&
                       op_at(ins, 1)->mem.base == X86_REG_ESP && st.mode == DK_FRAME_ENTRY) {
                st.has_ebp = true;
                st.ebp = st.delta + op_at(ins, 1)->mem.disp;
                frame->has_frame_pointer = true;
                frame->frame_pointer = st.ebp;
            } else if (is_mnem(ins, "and") && op_at(ins, 0)->type == X86_OP_REG && reg_is(dis, op_at(ins, 0), "esp")) {
                if (op_at(ins, 1)->type == X86_OP_IMM) {
                    frame->has_align = true;
                    frame->align = (i64)(((u64)0 - (u64)op_at(ins, 1)->imm) & 0xFFFFFFFFull);
                } else {
                    frame->has_align = false;
                }
                st.mode = DK_FRAME_ALIGNED;
                st.delta = 0;
            } else if (is_mnem(ins, "leave") && st.has_ebp) {
                st.mode = DK_FRAME_ENTRY;
                st.delta = st.ebp + 4;
            } else if (is_mnem(ins, "call")) {
                bool has_target;
                i64 target;
                CallKind kind = call_target(ins, rmap, has_relocs, base, &has_target, &target);
                i64 pops = 0;
                bool have_pops = false;
                const cs_insn *nxt = k + 1 < n_insns ? &insns[k + 1] : NULL;
                bool cdecl_ = nxt && is_mnem(nxt, "add") && opstr_starts(nxt, "esp,");
                bool chkstk = false;
                i64 chk_size = 0;
                if (prev && is_mnem(prev, "mov") && opstr_starts(prev, "eax, 0x")) {
                    if (!dk_parse_int(dk_str(prev->op_str + 5), 16, &chk_size, NULL))
                        INTERNAL("ValueError: invalid literal for int() with base 16: '%s'", prev->op_str + 5);
                    chkstk = chk_size >= 0x1000 && kind == CALL_DIRECT;
                }
                if (chkstk) {
                    st.delta -= chk_size;
                    frame->locals += chk_size;
                    pops = 0;
                    have_pops = true;
                } else if (cdecl_) {
                    pops = 0;
                    have_pops = true;
                } else if (kind == CALL_DIRECT) {
                    have_pops = dk_frame_callee_pops(retail, has_target, target, &pops);
                } else if (kind == CALL_IMPORT && retail && has_target) {
                    if (import_is_cdecl(retail, (u64)target)) {
                        pops = 0;
                        have_pops = true;
                    }
                }
                if (!have_pops) {
                    pops = pending;
                    frame->unknown_calls++;
                }
                st.delta += pops;
                pending = 0;
            }
            if (is_mnem(ins, "jmp") || m[0] == 'j') {
                if (nops && op_at(ins, 0)->type == X86_OP_IMM) {
                    u64 key = (u64)op_at(ins, 0)->imm & 0xFFFFFFFFull;
                    if (!known_get(known, key)) { /* known.setdefault(...) */
                        EspState *copy = DK_NEW(a, EspState);
                        *copy = st;
                        dk_imap_put(known, key, NULL)->p = copy;
                    }
                }
            }
            if (is_mnem(ins, "ret") || is_mnem(ins, "jmp")) after_end = true;
            prev = ins;
        }
    }
    dk_dis_free(insns, n_insns);
    return frame;
}

/* ---- print_frames -------------------------------------------------------------------------------------------- */

static DK_THREAD_LOCAL DkBuf *g_out; /* where the report goes while dk_frame_format runs */

static void say(DkStr s) {
    dk_buf_put(g_out, s);
    dk_buf_putc(g_out, '\n');
}

typedef struct {
    const char *label;
    DkStr value;
} HeadRow;

static DkStr cookie_text(const DkFrame *f) {
    if (!f->has_cookie) return DK_S("-");
    i64 mag = f->cookie_offset < 0 ? -f->cookie_offset : f->cookie_offset;
    return F("%s%s0x%X", f->cookie_base == DK_FRAME_ALIGNED ? "A" : "", f->cookie_offset < 0 ? "-" : "+", mag);
}

/* head(f) */
static void head_rows(const DkFrame *f, HeadRow rows[7]) {
    DkBuf saved;
    dk_buf_init(&saved, dk_arena());
    for (size_t i = 0; i < f->n_saved; i++) {
        if (i) dk_buf_putc(&saved, ' ');
        dk_buf_put(&saved, f->saved[i]);
    }
    rows[0] = (HeadRow){"saved registers", saved.n ? dk_buf_str(&saved) : DK_S("-")};
    rows[1] = (HeadRow){"locals (sub esp)", F("0x%X", f->locals)};
    rows[2] = (HeadRow){"frame pointer", f->has_frame_pointer ? F("ebp = entry%+d", f->frame_pointer) : DK_S("-")};
    rows[3] = (HeadRow){"aligned", f->has_align ? F("and esp, -%d", f->align) : DK_S("-")};
    rows[4] = (HeadRow){"/GS cookie", cookie_text(f)};
    rows[5] = (HeadRow){"EH registration", f->eh ? DK_S("yes") : DK_S("-")};
    rows[6] = (HeadRow){"calls with a guessed convention", F("%d", f->unknown_calls)};
}

/* spans(f)[(base, off)]: the distance to the next slot offset of the same base (the next one in sorted order). */
static bool slot_span(const DkFrame *f, const DkFrameSlot *s, i64 *span) {
    bool have = false;
    i64 best = 0;
    for (size_t i = 0; i < f->n_slots; i++) {
        const DkFrameSlot *o = f->slots[i];
        if (o->base != s->base || o->offset <= s->offset) continue;
        if (!have || o->offset < best) {
            best = o->offset;
            have = true;
        }
    }
    if (have) *span = best - s->offset;
    return have;
}

/* cell(f, sp, k) */
static DkStr cell(const DkFrame *f, DkFrameBase base, i64 off) {
    const DkFrameSlot *s = frame_find(f, base, off);
    if (!s) return DK_S("-");
    i64 span = 0;
    bool has_span = slot_span(f, s, &span);
    DkStr size = slot_size_text(s), acc = slot_access(s);
    DkStr ext = (has_span && off < 0) ? F(" ext %d", span) : DK_S("");
    return F("%-5S %-10S%S%s", &size, &acc, &ext, s->indexed ? " [i]" : "");
}

typedef struct {
    DkFrameBase base;
    i64 offset;
} SlotKey;

/* key=lambda k: (k[0] != "entry", -k[1]) */
static int cmp_key(const void *x, const void *y, void *ctx) {
    (void)ctx;
    const SlotKey *p = x, *q = y;
    int pa = p->base != DK_FRAME_ENTRY, qa = q->base != DK_FRAME_ENTRY;
    if (pa != qa) return pa < qa ? -1 : 1;
    if (p->offset != q->offset) return p->offset > q->offset ? -1 : 1;
    return 0;
}

void dk_frame_format(DkBuf *out, const DkFrameResult *r, const DkFrameRetail *retail) {
    DkArena *a = dk_arena();
    g_out = out;
    DkFrame *ours = dk_frame_analyse(a, r->code, r->address, retail, r->relocs, r->n_relocs, true);
    bool have_game = r->game.p && r->game.n;
    DkFrame *game = have_game ? dk_frame_analyse(a, r->game, r->address, retail, NULL, 0, false) : NULL;
    const char *name = (r->annotation_name && *r->annotation_name) ? r->annotation_name : r->function_name;
    say(F("%s frame of %s at %08X (offsets from the entry ESP: +0x0 the return address, +0x4.. the arguments)", r->build,
          name, r->address));
    if (!game) {
        say(DK_S("  the reference's bytes are not available"));
        return;
    }
    i64 width = 34;
    say(F("  %-32s %-*s %s", "", width, "ours", "reference"));
    HeadRow ho[7], hg[7];
    head_rows(ours, ho);
    head_rows(game, hg);
    for (int i = 0; i < 7; i++) {
        bool same = dk_str_eq(ho[i].value, hg[i].value);
        say(F("%s %-32s %-*S %S", same ? " " : "!", ho[i].label, width, &ho[i].value, &hg[i].value));
    }
    /* keys = sorted(set(ours.slots) | set(game.slots), key=...): the keys are distinct, so the order is total */
    DK_VEC(SlotKey) keys = {0};
    const DkFrame *both[2] = {ours, game};
    for (int fi = 0; fi < 2; fi++)
        for (size_t i = 0; i < both[fi]->n_slots; i++) {
            const DkFrameSlot *s = both[fi]->slots[i];
            bool dup = false;
            for (size_t k = 0; k < keys.n; k++) dup |= keys.v[k].base == s->base && keys.v[k].offset == s->offset;
            if (!dup) dk_vec_push(&keys, ((SlotKey){s->base, s->offset}));
        }
    dk_sort(keys.v, keys.n, sizeof(SlotKey), cmp_key, NULL, false);
    say(F("\n  %-9s %-*s %s", "slot", width + 23, "ours: size access (ext = distance to the next slot)", "reference"));
    i64 differ = 0;
    for (size_t i = 0; i < keys.n; i++) {
        SlotKey k = keys.v[i];
        DkStr ca = cell(ours, k.base, k.offset), cb = cell(game, k.base, k.offset);
        const DkFrameSlot *oa = frame_find(ours, k.base, k.offset), *ob = frame_find(game, k.base, k.offset);
        bool same = oa && ob && sizes_equal(oa, ob) && dk_str_eq(slot_access(oa), slot_access(ob));
        differ += !same;
        DkStr label = slot_label(oa ? oa : ob);
        say(F("%s %-9S %-*S %S", same ? " " : "!", &label, width + 23, &ca, &cb));
    }
    say(F("  %d slot(s) ours, %d the reference's, %d line(s) differ", (i64)ours->n_slots, (i64)game->n_slots, differ));
    dk_vec_free(&keys);
}

void dk_frame_print(const DkFrameResult *result, const DkFrameRetail *retail) {
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    dk_frame_format(&b, result, retail);
    fwrite(b.p, 1, b.n, stdout);
}

/* ---- the slot map -------------------------------------------------------------------------------------------- */

static int cmp_rows(const void *x, const void *y, void *ctx) {
    (void)ctx;
    const DkFramePair *p = x, *q = y;
    if ((p->ours == NULL) != (q->ours == NULL)) return p->ours ? -1 : 1; /* the reference's unpaired slots last */
    const DkFrameSlot *a = p->ours ? p->ours : p->game, *b = q->ours ? q->ours : q->game;
    SlotKey ka = {a->base, a->offset}, kb = {b->base, b->offset};
    return cmp_key(&ka, &kb, NULL);
}

static const DkFrameAccess *access_at(const DkFrameSlot *s, i64 at, char kind) {
    const DkFrameAccess *first = NULL;
    for (size_t i = 0; i < s->n_acc; i++) {
        if (s->acc[i].at != at) continue;
        if (s->acc[i].kind == kind) return &s->acc[i];
        if (!first) first = &s->acc[i];
    }
    return first;
}

size_t dk_frame_pair(DkArena *a, const DkFrame *ours, const DkFrame *game, const DkIMap *insn_map,
                      DkFramePair **rows_out) {
    size_t no = ours->n_slots, ng = game->n_slots;
    i64 *votes = DK_NEWN(a, i64, no * ng + 1);
    for (size_t i = 0; i < no; i++) {
        const DkFrameSlot *o = ours->slots[i];
        for (size_t k = 0; k < o->n_acc; k++) {
            DkVal *g = dk_imap_get(insn_map, (u64)o->acc[k].at);
            if (!g) continue;
            for (size_t j = 0; j < ng; j++) {
                const DkFrameAccess *ga = access_at(game->slots[j], g->i, o->acc[k].kind);
                if (ga) votes[i * ng + j] += (ga->kind == o->acc[k].kind) ? 2 : 1;
            }
        }
    }
    bool *used_o = DK_NEWN(a, bool, no + 1), *used_g = DK_NEWN(a, bool, ng + 1);
    DkFramePair *rows = DK_NEWN(a, DkFramePair, no + ng + 1);
    size_t n = 0;
    for (;;) {
        i64 best = 0;
        size_t bi = 0, bj = 0;
        bool bsame = false;
        for (size_t i = 0; i < no; i++) {
            if (used_o[i]) continue;
            for (size_t j = 0; j < ng; j++) {
                if (used_g[j] || votes[i * ng + j] <= 0) continue;
                bool same = ours->slots[i]->base == game->slots[j]->base && ours->slots[i]->offset == game->slots[j]->offset;
                i64 v = votes[i * ng + j];
                if (v > best || (v == best && same && !bsame)) {
                    best = v;
                    bi = i;
                    bj = j;
                    bsame = same;
                }
            }
        }
        if (!best) break;
        used_o[bi] = used_g[bj] = true;
        rows[n++] = (DkFramePair){ours->slots[bi], game->slots[bj], best};
    }
    for (size_t i = 0; i < no; i++)
        if (!used_o[i]) rows[n++] = (DkFramePair){ours->slots[i], NULL, 0};
    for (size_t j = 0; j < ng; j++)
        if (!used_g[j]) rows[n++] = (DkFramePair){NULL, game->slots[j], 0};
    dk_sort(rows, n, sizeof(DkFramePair), cmp_rows, NULL, false);
    *rows_out = rows;
    return n;
}

/* c2 counts from an ebp frame: the arguments from +8 (entry +4), the locals below 0 (below the saved ebp: entry -4,
 * or the return address itself in a frame without a frame pointer). */
static DkStr slot_names(const DkFrame *f, const DkFrameSlot *s, const DkFrameName *names, size_t n_names) {
    DkBuf b;
    dk_buf_init(&b, dk_arena());
    i64 c2 = s->offset + (s->offset > 0 ? 4 : (f->has_frame_pointer ? 4 : 0));
    if (s->base == DK_FRAME_ENTRY)
        for (size_t i = 0; i < n_names; i++)
            if (names[i].lo <= c2 && c2 < names[i].hi) {
                if (b.n) dk_buf_putc(&b, '/');
                dk_buf_put(&b, dk_str(names[i].name));
            }
    return b.n ? dk_buf_str(&b) : DK_S("");
}

/* "size access first use": the first use is the offset of the first instruction touching the slot */
static DkStr slot_cell(const DkFrameSlot *s) {
    if (!s) return DK_S("-");
    DkStr size = slot_size_text(s), acc = slot_access(s);
    return F("%-5S %-9S +%03X", &size, &acc, s->n_acc ? s->acc[0].at : 0);
}

void dk_frame_slotmap(DkBuf *out, const DkFrame *ours, const DkFrame *game, const DkIMap *insn_map,
                       const DkFrameName *names, size_t n_names) {
    DkArena *a = dk_arena();
    g_out = out;
    DkFramePair *rows;
    size_t n = dk_frame_pair(a, ours, game, insn_map, &rows);
    say(DK_S("  slot map (offsets from the entry ESP; paired by the aligned instructions; size, access, first use)"));
    say(F("  %-9s %-26s %-9s %-26s %s", "ours", "", "reference", "", "name (ours)"));
    i64 paired = 0, differ = 0;
    for (size_t i = 0; i < n; i++) {
        const DkFramePair *r = &rows[i];
        DkStr lo = r->ours ? slot_label(r->ours) : DK_S("-"), lg = r->game ? slot_label(r->game) : DK_S("-");
        DkStr co = slot_cell(r->ours), cg = slot_cell(r->game);
        DkStr nm = r->ours ? slot_names(ours, r->ours, names, n_names) : DK_S("");
        bool both = r->ours && r->game;
        paired += both;
        bool moved = both && (r->ours->base != r->game->base || r->ours->offset != r->game->offset);
        bool flagged = moved || !both;
        differ += flagged;
        say(F("%s %-9S %-26S %-9S %-26S %S%s", flagged ? "!" : " ", &lo, &co, &lg, &cg, &nm,
              both ? "" : (r->ours ? "  (ours only)" : "  (reference only)")));
    }
    say(F("  %d slot(s) ours, %d the reference's, %d paired, %d row(s) differ", (i64)ours->n_slots, (i64)game->n_slots, paired,
          differ));
    for (size_t i = 0; i < n; i++) {
        const DkFramePair *p = &rows[i];
        if (!p->ours || !p->game || p->ours->base != p->game->base || p->ours->offset == p->game->offset) continue;
        for (size_t k = i + 1; k < n; k++) {
            const DkFramePair *q = &rows[k];
            if (!q->ours || !q->game || q->ours->base != p->ours->base || q->game->base != p->ours->base) continue;
            if (p->ours->offset == q->game->offset && q->ours->offset == p->game->offset) {
                DkStr a1 = slot_label(p->ours), a2 = slot_label(q->ours);
                DkStr n1 = slot_names(ours, p->ours, names, n_names), n2 = slot_names(ours, q->ours, names, n_names);
                say(F("  swap: ours %S %S and %S %S hold the reference's %S and %S", &a1, &n1, &a2, &n2, &a2, &a1));
            }
        }
    }
}
