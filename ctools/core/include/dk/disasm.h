// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Capstone for the tools (vendored capstone 5.0.7, x86 only: third_party/capstone, CMake target dk_capstone). The
 * The mnemonic and op_str text, the instruction ids, the operands and the register/group names are the C library's own.
 *
 * Handles: one handle per thread and configuration. dk_dis(mode, flags) returns the calling thread's handle for
 * that combination, created on first use (Intel syntax; the default of Cs()); use it only from the thread that got
 * it. Python's `md.detail = True` is DK_DIS_DETAIL, `md.skipdata = True` is DK_DIS_SKIPDATA (skipped bytes come
 * back as a ".byte" pseudo-instruction with id 0, op_str "0x.."; the accessors the binding refused for id 0
 * (regs_read, groups, regs_access...) must not be used on it: check insn->id first).
 *
 * The decoded data is capstone's own cs_insn / cs_detail (include <capstone/capstone.h>): the fields the tools read
 * are insn->address, size, bytes, mnemonic, op_str, id, and with detail insn->detail->{regs_read, regs_write,
 * groups, x86.{prefix, opcode, modrm, sib, disp, sib_index, sib_scale, sib_base, op_count, operands[],
 * disp_offset, disp_size, encoding, eflags...}}, each operand's type, reg, imm, mem.{segment, base, index, scale,
 * disp}, size and access: the same names as the Python X86Op/X86 attributes (X86_OP_IMM, X86_REG_ESP, CS_GRP_CALL
 * and the other constants come from capstone.h and x86.h).
 *
 * Ways to decode:
 *   - DkDisIter: Python's `for ins in md.disasm(code, address[, count])`, with no allocation. The instruction
 *     (it.insn) is valid until the next dk_dis_next call. Without skipdata the walk ends at the first byte that
 *     does not decode (as cs_disasm does; the binding then just stops yielding).
 *   - dk_dis_range / dk_dis_one: `md.disasm_lite`, into a caller buffer of DkInsnLite (no detail).
 *   - dk_dis_all: cs_disasm for the whole buffer (all instructions kept, with detail when the handle has it). */
#pragma once
#include "base.h"
#include "str.h"
#include <capstone/capstone.h>

typedef enum {
    DK_DIS_X86_16 = 0, /* CS_MODE_16 */
    DK_DIS_X86_32 = 1, /* CS_MODE_32: the tools' default */
    DK_DIS_X86_64 = 2 /* CS_MODE_64 */
} DkDisMode;

enum {
    DK_DIS_DETAIL = 1,   /* CS_OPT_DETAIL on */
    DK_DIS_SKIPDATA = 2  /* CS_OPT_SKIPDATA on, mnemonic ".byte", no callback */
};

typedef struct DkDis DkDis;

/* The calling thread's handle; never NULL (an internal error aborts). Do not close it. */
DkDis *dk_dis(DkDisMode mode, unsigned flags);
csh dk_dis_handle(const DkDis *d); /* for calling capstone directly */
/* The capstone library version as (major << 8 | minor), and "5.0.7"-style text. */
unsigned dk_dis_version(void);

/* ---- iteration ---- */
typedef struct {
    DkDis *dis;
    const u8 *code;
    size_t size;
    u64 address;
    size_t left;          /* instructions still allowed; 0 with limited == false: no limit */
    bool limited;
    cs_insn *scratch;     /* internal */
    const cs_insn *insn;  /* the current instruction, valid until the next call */
} DkDisIter;
/* count: Python's `count` argument; 0 is unlimited. */
void dk_dis_iter(DkDisIter *it, DkDis *d, const void *code, size_t n, u64 address, size_t count);
/* Decodes the next instruction into it->insn; false at the end (or at an undecodable byte without skipdata). */
bool dk_dis_next(DkDisIter *it);
/* Releases the iterator's buffer when the walk is abandoned before dk_dis_next returned false (calling it after the
 * end is harmless). */
void dk_dis_iter_end(DkDisIter *it);

/* ---- light records (disasm_lite) ---- */
typedef struct {
    u64 address;
    u32 id;
    u16 size;
    u8 bytes[16];
    char mnemonic[CS_MNEMONIC_SIZE];
    char op_str[160];
} DkInsnLite;
/* Decodes up to max instructions of code into out (count as Python's `count` limit: the caller's max). Returns how
 * many. */
size_t dk_dis_range(DkDis *d, const void *code, size_t n, u64 address, DkInsnLite *out, size_t max);
/* One instruction at code (the first one): false when it does not decode. */
bool dk_dis_one(DkDis *d, const void *code, size_t n, u64 address, DkInsnLite *out);

/* ---- everything at once (cs_disasm) ---- */
/* The instructions of code, allocated by capstone; free with dk_dis_free. count 0: all. Returns NULL with *n == 0
 * when nothing decodes. */
cs_insn *dk_dis_all(DkDis *d, const void *code, size_t size, u64 address, size_t count, size_t *n);
void dk_dis_free(cs_insn *insns, size_t n);

/* ---- names and register access (CsInsn.reg_name / insn_name / group_name / regs_access ...) ---- */
/* NULL where the binding returned None (an unknown id). */
const char *dk_dis_reg_name(const DkDis *d, unsigned reg);
const char *dk_dis_insn_name(const DkDis *d, unsigned insn_id);
const char *dk_dis_group_name(const DkDis *d, unsigned group);
/* CsInsn.regs_access(): the registers an instruction reads and writes, implicit and explicit. The arrays hold up to
 * 64 registers. false where the binding raised CsError (no access table for the instruction, the pseudo
 * instruction of skipdata, a handle without detail). */
typedef struct {
    u16 read[64];
    u16 write[64];
    unsigned n_read, n_write;
} DkDisRegs;
bool dk_dis_regs_access(const DkDis *d, const cs_insn *insn, DkDisRegs *out);
/* CsInsn.group(g), reg_read(r), reg_write(r): the instruction's detail lists (needs detail and id != 0). */
bool dk_dis_in_group(const cs_insn *insn, unsigned group);
bool dk_dis_reads_reg(const cs_insn *insn, unsigned reg);  /* implicit reads (regs_read) */
bool dk_dis_writes_reg(const cs_insn *insn, unsigned reg); /* implicit writes (regs_write) */
/* CsInsn.op_count(type) and op_find(type, position) for x86: the number of operands of a type
 * (X86_OP_REG/IMM/MEM) and the position-th (1-based) operand of that type, NULL when there is none. */
unsigned dk_dis_op_count(const cs_insn *insn, unsigned op_type);
const cs_x86_op *dk_dis_op_find(const cs_insn *insn, unsigned op_type, unsigned position);
