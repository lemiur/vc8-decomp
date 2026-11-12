// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Capstone wrapper (see disasm.h): one handle per thread and configuration. */
#include "dk/disasm.h"

struct DkDis {
    csh handle;
    DkDisMode mode;
    unsigned flags;
    cs_insn *scratch; /* one instruction reused by the iterators of this handle */
};

static DK_THREAD_LOCAL DkDis *g_handles[3][4];

DkDis *dk_dis(DkDisMode mode, unsigned flags) {
    DK_ASSERT((unsigned)mode < 3 && flags < 4);
    DkDis *d = g_handles[mode][flags];
    if (d) return d;
    static const cs_mode modes[3] = {CS_MODE_16, CS_MODE_32, CS_MODE_64};
    d = dk_xcalloc(1, sizeof *d);
    d->mode = mode;
    d->flags = flags;
    cs_err err = cs_open(CS_ARCH_X86, modes[mode], &d->handle);
    if (err != CS_ERR_OK) dk_panic(__FILE__, __LINE__, "cs_open failed: %s", cs_strerror(err));
    /* The option is set explicitly so that the text never depends on capstone's default syntax. */
    err = cs_option(d->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    if (err == CS_ERR_OK) err = cs_option(d->handle, CS_OPT_DETAIL, (flags & DK_DIS_DETAIL) ? CS_OPT_ON : CS_OPT_OFF);
    if (err == CS_ERR_OK) err = cs_option(d->handle, CS_OPT_SKIPDATA, (flags & DK_DIS_SKIPDATA) ? CS_OPT_ON : CS_OPT_OFF);
    if (err != CS_ERR_OK) dk_panic(__FILE__, __LINE__, "cs_option failed: %s", cs_strerror(err));
    d->scratch = cs_malloc(d->handle);
    DK_ASSERT(d->scratch != NULL);
    g_handles[mode][flags] = d;
    return d;
}

csh dk_dis_handle(const DkDis *d) { return d->handle; }

unsigned dk_dis_version(void) {
    int major = 0, minor = 0;
    cs_version(&major, &minor);
    return (unsigned)(major << 8 | minor);
}

void dk_dis_iter(DkDisIter *it, DkDis *d, const void *code, size_t n, u64 address, size_t count) {
    it->dis = d;
    it->code = code;
    it->size = n;
    it->address = address;
    it->left = count;
    it->limited = count != 0;
    it->scratch = cs_malloc(d->handle);
    DK_ASSERT(it->scratch != NULL);
    it->insn = NULL;
}

bool dk_dis_next(DkDisIter *it) {
    if (it->limited && it->left == 0) goto done;
    if (it->size == 0) goto done;
    if (!cs_disasm_iter(it->dis->handle, &it->code, &it->size, &it->address, it->scratch)) goto done;
    if (it->limited) it->left--;
    it->insn = it->scratch;
    return true;
done:
    if (it->scratch) {
        cs_free(it->scratch, 1);
        it->scratch = NULL;
    }
    it->insn = NULL;
    return false;
}

void dk_dis_iter_end(DkDisIter *it) {
    if (it->scratch) {
        cs_free(it->scratch, 1);
        it->scratch = NULL;
    }
    it->insn = NULL;
}

static void lite_from(DkInsnLite *out, const cs_insn *i) {
    out->address = i->address;
    out->id = i->id;
    out->size = i->size;
    memcpy(out->bytes, i->bytes, sizeof out->bytes);
    memcpy(out->mnemonic, i->mnemonic, sizeof out->mnemonic);
    memcpy(out->op_str, i->op_str, sizeof out->op_str);
}

size_t dk_dis_range(DkDis *d, const void *code, size_t n, u64 address, DkInsnLite *out, size_t max) {
    size_t k = 0;
    const uint8_t *p = code;
    size_t left = n;
    u64 addr = address;
    while (k < max && left > 0 && cs_disasm_iter(d->handle, &p, &left, &addr, d->scratch)) lite_from(&out[k++], d->scratch);
    return k;
}

bool dk_dis_one(DkDis *d, const void *code, size_t n, u64 address, DkInsnLite *out) {
    return dk_dis_range(d, code, n, address, out, 1) == 1;
}

cs_insn *dk_dis_all(DkDis *d, const void *code, size_t size, u64 address, size_t count, size_t *n) {
    cs_insn *insns = NULL;
    *n = cs_disasm(d->handle, code, size, address, count, &insns);
    return *n ? insns : NULL;
}

void dk_dis_free(cs_insn *insns, size_t n) {
    if (insns) cs_free(insns, n);
}

const char *dk_dis_reg_name(const DkDis *d, unsigned reg) { return cs_reg_name(d->handle, reg); }
const char *dk_dis_insn_name(const DkDis *d, unsigned insn_id) { return insn_id ? cs_insn_name(d->handle, insn_id) : NULL; }
const char *dk_dis_group_name(const DkDis *d, unsigned group) { return cs_group_name(d->handle, group); }

bool dk_dis_regs_access(const DkDis *d, const cs_insn *insn, DkDisRegs *out) {
    if (insn->id == 0) return false;
    cs_regs rr, rw;
    uint8_t nr = 0, nw = 0;
    if (cs_regs_access(d->handle, insn, rr, &nr, rw, &nw) != CS_ERR_OK) return false;
    out->n_read = nr;
    out->n_write = nw;
    memcpy(out->read, rr, nr * sizeof(u16));
    memcpy(out->write, rw, nw * sizeof(u16));
    return true;
}

bool dk_dis_in_group(const cs_insn *insn, unsigned group) {
    if (insn->id == 0 || !insn->detail) return false;
    for (unsigned i = 0; i < insn->detail->groups_count; i++)
        if (insn->detail->groups[i] == group) return true;
    return false;
}

bool dk_dis_reads_reg(const cs_insn *insn, unsigned reg) {
    if (insn->id == 0 || !insn->detail) return false;
    for (unsigned i = 0; i < insn->detail->regs_read_count; i++)
        if (insn->detail->regs_read[i] == reg) return true;
    return false;
}

bool dk_dis_writes_reg(const cs_insn *insn, unsigned reg) {
    if (insn->id == 0 || !insn->detail) return false;
    for (unsigned i = 0; i < insn->detail->regs_write_count; i++)
        if (insn->detail->regs_write[i] == reg) return true;
    return false;
}

unsigned dk_dis_op_count(const cs_insn *insn, unsigned op_type) {
    if (insn->id == 0 || !insn->detail) return 0;
    unsigned c = 0;
    for (unsigned i = 0; i < insn->detail->x86.op_count; i++)
        if ((unsigned)insn->detail->x86.operands[i].type == op_type) c++;
    return c;
}

/* The binding's loop: `for op in operands: if op.type == t: c += 1; if c == position: return op`, so a position of 0
 * returns the first operand of another type. */
const cs_x86_op *dk_dis_op_find(const cs_insn *insn, unsigned op_type, unsigned position) {
    if (insn->id == 0 || !insn->detail) return NULL;
    unsigned c = 0;
    for (unsigned i = 0; i < insn->detail->x86.op_count; i++) {
        const cs_x86_op *op = &insn->detail->x86.operands[i];
        if ((unsigned)op->type == op_type) c++;
        if (c == position) return op;
    }
    return NULL;
}
