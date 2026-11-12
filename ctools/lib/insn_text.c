// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Instruction text, normal forms, differing bytes and the side-by-side diff of a compared function (insn_text.h). */
#include "insn_text.h"

#include "dk/difflib.h"
#include "dk/disasm.h"
#include "dk/fmt.h"
#include "dk/re.h"

#include <string.h>

DkInsnTextVec dk_insn_disassemble(DkArena *a, DkStr code, u32 base, const DkReloc *relocs, size_t n_relocs) {
    DkInsnTextVec out = {0};
    DkDisIter it;
    dk_dis_iter(&it, dk_dis(DK_DIS_X86_32, 0), code.p, code.n, base, 0);
    while (dk_dis_next(&it)) {
        const cs_insn *ins = it.insn;
        u32 off = (u32)(ins->address - base);
        DkStr note = {"", 0};
        for (size_t i = 0; i < n_relocs; i++) {
            const DkReloc *r = &relocs[i];
            if (off <= r->offset && r->offset < off + ins->size && r->symbol) {
                note = dk_str(r->symbol);
                if (r->addend) note = dk_str(dk_sprintf(a, "%s+0x%X", r->symbol, (u32)r->addend));
            }
        }
        DkInsnText row = {off, ins->size, dk_str(dk_sprintf(a, "%s %s", ins->mnemonic, ins->op_str)), note};
        dk_vec_push(&out, row);
    }
    u32 done = out.n ? out.v[out.n - 1].offset + out.v[out.n - 1].size : 0;
    if (done < code.n) {
        u32 rest = (u32)(code.n - done);
        DkInsnText row = {done, rest, dk_str(dk_sprintf(a, "(%u bytes of data)", rest)), {"", 0}};
        dk_vec_push(&out, row);
    }
    return out;
}

DkStr dk_insn_normalise(DkArena *a, DkStr text, bool relocated) {
    text = dk_re_sub(a, dk_re("0x[0-9a-f]{3,}", 0), DK_S("IMM"), text, 0);
    if (relocated) text = dk_re_sub(a, dk_re("(?<![\\w*.])0(?![\\w.])", 0), DK_S("IMM"), text, 0);
    return text;
}

u32 *dk_result_differ(DkArena *a, const DkResult *r, size_t *n) {
    *n = 0;
    size_t no = r->ours.code.n, nt = r->theirs.n;
    size_t common = no < nt ? no : nt, longest = no > nt ? no : nt;
    if (!longest) return NULL;
    u8 *mask = (u8 *)dk_alloc(a, longest + 4);
    memset(mask, 0, longest + 4);
    for (size_t i = 0; i < r->ours.n_relocs; i++) {
        u32 off = r->ours.relocs[i].offset;
        for (u32 k = 0; k < 4; k++)
            if ((size_t)off + k < longest) mask[off + k] = 1;
    }
    size_t count = 0;
    for (size_t i = 0; i < common; i++) count += !mask[i] && r->ours.code.p[i] != r->theirs.p[i];
    count += longest - common;
    if (!count) return NULL;
    u32 *out = DK_NEWN(a, u32, count);
    size_t k = 0;
    for (size_t i = 0; i < common; i++)
        if (!mask[i] && r->ours.code.p[i] != r->theirs.p[i]) out[k++] = (u32)i;
    for (size_t i = common; i < longest; i++) out[k++] = (u32)i;
    *n = k;
    return out;
}

/* ---- the side-by-side diff ---- */

/* "+%03X  text" with the note after "  ; " */
static DkStr cell(DkArena *a, const DkInsnText *t, DkStr note) {
    DkBuf b;
    dk_buf_init(&b, a);
    dk_buf_printf(&b, "+%03X  %.*s", t->offset, DK_SF(t->text));
    if (note.n) {
        dk_buf_putz(&b, "  ; ");
        dk_buf_put(&b, note);
    }
    return dk_buf_str(&b);
}

/* The name of the symbol (or import) at the address the last operand holds, "" when none. */
static DkStr name_of(const DkImage *im, DkStr text) {
    DkReMatch m;
    if (!im || !dk_re_search(dk_re("0x([0-9a-f]+)$", 0), text, 0, DK_END, &m)) return (DkStr){"", 0};
    DkStr hex = dk_re_group(&m, 1);
    if (hex.n > 8) return (DkStr){"", 0};
    u32 addr = 0;
    for (size_t i = 0; i < hex.n; i++) {
        char c = hex.p[i];
        addr = addr * 16 + (u32)(c <= '9' ? c - '0' : c - 'a' + 10);
    }
    u32 start = 0;
    const char *name = dk_image_name_at(im, addr, &start);
    if (!name || start != addr) return (DkStr){"", 0};
    return dk_str(name);
}

static void put_ljust(DkBuf *b, DkStr s, int width) {
    int cp = (int)dk_u8_len(s);
    dk_buf_put(b, s);
    for (; cp < width; cp++) dk_buf_putc(b, ' ');
}

typedef struct {
    char mark;
    DkStr text;
} Row;

DkStr dk_insn_diff(DkArena *a, const DkResult *r, const DkImage *im, const DkInsnDiffOpts *o) {
    int width = o && o->width > 0 ? o->width : 58;
    size_t max_rows = o ? o->max_rows : 0;
    u32 base = r->theirs_va;
    const DkFunc *fn = &r->ours;
    DkInsnTextVec ours = dk_insn_disassemble(a, fn->code, base, fn->relocs, fn->n_relocs);
    DkInsnTextVec theirs = dk_insn_disassemble(a, r->theirs, base, NULL, 0);
    DkStr *av = DK_NEWN(a, DkStr, ours.n + 1), *bv = DK_NEWN(a, DkStr, theirs.n + 1);
    for (size_t i = 0; i < ours.n; i++) av[i] = dk_insn_normalise(a, ours.v[i].text, ours.v[i].note.n != 0);
    for (size_t j = 0; j < theirs.n; j++) bv[j] = dk_insn_normalise(a, theirs.v[j].text, false);
    DkSeqMatcher *sm = dk_seqm_new_str(a, av, ours.n, bv, theirs.n, &dk_seqm_no_autojunk);

    size_t nd = 0;
    u32 *differ = dk_result_differ(a, r, &nd);
    size_t span = fn->code.n + 1;
    u8 *raw = (u8 *)dk_alloc(a, span);
    memset(raw, 0, span);
    for (size_t i = 0; i < nd; i++)
        if (differ[i] < span) raw[differ[i]] = 1;

    DkBuf out;
    dk_buf_init(&out, a);
    const char *tname = o && o->target_name ? o->target_name : dk_sprintf(a, "target %d", r->target);
    const char *name = r->ann && r->ann->name ? r->ann->name : fn->symbol ? fn->symbol : "?";
    dk_buf_printf(&out, "%s  %s  %08X  %s  ours: %zu bytes, reference: %zu bytes\n", tname, name, base,
                  dk_status_name(r->status), fn->code.n, r->theirs.n);
    dk_buf_putz(&out, "  ");
    put_ljust(&out, DK_S("ours"), width);
    dk_buf_putz(&out, " | reference\n");

    DK_VEC(Row) rows = {0};
    size_t nops = 0;
    const DkOpcode *ops = dk_seqm_opcodes(sm, &nops);
    for (size_t k = 0; k < nops; k++) {
        const DkOpcode *op = &ops[k];
        if (op->tag == DK_OP_EQUAL) {
            for (size_t i = op->i1, j = op->j1; i < op->i2; i++, j++) {
                const DkInsnText *t = &ours.v[i];
                bool bad = false;
                for (u32 q = t->offset; q < t->offset + t->size && !bad; q++) bad = q < span && raw[q];
                DkBuf b;
                dk_buf_init(&b, a);
                dk_buf_putc(&b, bad ? '!' : ' ');
                dk_buf_putc(&b, ' ');
                put_ljust(&b, dk_u8_slice(cell(a, t, t->note), 0, width), width);
                dk_buf_putz(&b, " | ");
                dk_buf_put(&b, cell(a, &theirs.v[j], name_of(im, theirs.v[j].text)));
                Row row = {bad ? '!' : ' ', dk_buf_str(&b)};
                dk_vec_push(&rows, row);
            }
            continue;
        }
        for (size_t i = op->i1; i < op->i2; i++) {
            DkBuf b;
            dk_buf_init(&b, a);
            dk_buf_putz(&b, "- ");
            put_ljust(&b, dk_u8_slice(cell(a, &ours.v[i], ours.v[i].note), 0, width), width);
            dk_buf_putz(&b, " |");
            Row row = {'-', dk_buf_str(&b)};
            dk_vec_push(&rows, row);
        }
        for (size_t j = op->j1; j < op->j2; j++) {
            DkBuf b;
            dk_buf_init(&b, a);
            dk_buf_putz(&b, "+ ");
            put_ljust(&b, DK_S(""), width);
            dk_buf_putz(&b, " | ");
            dk_buf_put(&b, cell(a, &theirs.v[j], name_of(im, theirs.v[j].text)));
            Row row = {'+', dk_buf_str(&b)};
            dk_vec_push(&rows, row);
        }
    }
    size_t shown = 0;
    for (size_t i = 0; i < rows.n; i++) {
        if (max_rows && rows.v[i].mark == ' ') continue;
        if (max_rows && shown == max_rows) break;
        dk_buf_put(&out, rows.v[i].text);
        dk_buf_putc(&out, '\n');
        shown++;
    }
    dk_vec_free(&rows);
    dk_vec_free(&ours);
    dk_vec_free(&theirs);
    return dk_buf_str(&out);
}
