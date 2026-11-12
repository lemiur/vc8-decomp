// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* xmatch: the x86-32 instruction length decoder of the tokens and the retail patterns (see xmatch.h). */
#include "xmatch.h"

#include <string.h>

#include "xmatch_x86_tables.h"

/* operand kinds */
enum {
    K_NONE = 0, /* no operand bytes */
    K_M,        /* ModRM */
    K_MB,       /* ModRM + imm8 */
    K_MZ,       /* ModRM + imm16/32 */
    K_B,        /* imm8 */
    K_Z,        /* imm16/32 */
    K_W,        /* imm16 */
    K_R8,       /* rel8 */
    K_RZ,       /* rel16/32 */
    K_MOFFS,    /* moffs16/32 */
    K_FAR,      /* ptr16:16/32 */
    K_ENTER,    /* imm16 + imm8 */
    K_GRP3B,    /* F6: ModRM, imm8 for /0 /1 */
    K_GRP3Z,    /* F7: ModRM, immz for /0 /1 */
    K_ESC,      /* 0F */
    K_PFX,      /* prefix */
    K_CR,       /* ModRM read as a register form (0F 20..23) */
    K_MBB,      /* ModRM + imm8 + imm8 */
    K_BAD
};

/* one-byte map */
static const u8 one[256] = {
    /* 00 */ K_M, K_M, K_M, K_M, K_B, K_Z, K_NONE, K_NONE, K_M, K_M, K_M, K_M, K_B, K_Z, K_NONE, K_ESC,
    /* 10 */ K_M, K_M, K_M, K_M, K_B, K_Z, K_NONE, K_NONE, K_M, K_M, K_M, K_M, K_B, K_Z, K_NONE, K_NONE,
    /* 20 */ K_M, K_M, K_M, K_M, K_B, K_Z, K_PFX, K_NONE, K_M, K_M, K_M, K_M, K_B, K_Z, K_PFX, K_NONE,
    /* 30 */ K_M, K_M, K_M, K_M, K_B, K_Z, K_PFX, K_NONE, K_M, K_M, K_M, K_M, K_B, K_Z, K_PFX, K_NONE,
    /* 40 */ K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE,
    /* 50 */ K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE,
    /* 60 */ K_NONE, K_NONE, K_M, K_M, K_PFX, K_PFX, K_PFX, K_PFX, K_Z, K_MZ, K_B, K_MB, K_NONE, K_NONE, K_NONE, K_NONE,
    /* 70 */ K_R8, K_R8, K_R8, K_R8, K_R8, K_R8, K_R8, K_R8, K_R8, K_R8, K_R8, K_R8, K_R8, K_R8, K_R8, K_R8,
    /* 80 */ K_MB, K_MZ, K_MB, K_MB, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M,
    /* 90 */ K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_FAR, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE,
    /* A0 */ K_MOFFS, K_MOFFS, K_MOFFS, K_MOFFS, K_NONE, K_NONE, K_NONE, K_NONE, K_B, K_Z, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE,
    /* B0 */ K_B, K_B, K_B, K_B, K_B, K_B, K_B, K_B, K_Z, K_Z, K_Z, K_Z, K_Z, K_Z, K_Z, K_Z,
    /* C0 */ K_MB, K_MB, K_W, K_NONE, K_M, K_M, K_MB, K_MZ, K_ENTER, K_NONE, K_W, K_NONE, K_NONE, K_B, K_NONE, K_NONE,
    /* D0 */ K_M, K_M, K_M, K_M, K_B, K_B, K_NONE, K_NONE, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M,
    /* E0 */ K_R8, K_R8, K_R8, K_R8, K_B, K_B, K_B, K_B, K_RZ, K_RZ, K_FAR, K_R8, K_NONE, K_NONE, K_NONE, K_NONE,
    /* F0 */ K_PFX, K_NONE, K_PFX, K_PFX, K_NONE, K_NONE, K_GRP3B, K_GRP3Z, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_M, K_M,
};

/* 0F map */
static const u8 two[256] = {
    /* 00 */ K_M, K_M, K_M, K_M, K_BAD, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_BAD, K_NONE, K_BAD, K_M, K_NONE, K_MB,
    /* 10 */ K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M,
    /* 20 */ K_M, K_M, K_M, K_M, K_BAD, K_BAD, K_BAD, K_BAD, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M,
    /* 30 */ K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_BAD, K_NONE, K_ESC, K_BAD, K_ESC, K_BAD, K_BAD, K_BAD, K_BAD, K_BAD,
    /* 40 */ K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M,
    /* 50 */ K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M,
    /* 60 */ K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M,
    /* 70 */ K_MB, K_MB, K_MB, K_MB, K_M, K_M, K_M, K_NONE, K_M, K_M, K_BAD, K_BAD, K_M, K_M, K_M, K_M,
    /* 80 */ K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ, K_RZ,
    /* 90 */ K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M,
    /* A0 */ K_NONE, K_NONE, K_NONE, K_M, K_MB, K_M, K_M, K_M, K_NONE, K_NONE, K_NONE, K_M, K_MB, K_M, K_M, K_M,
    /* B0 */ K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_NONE, K_MB, K_M, K_M, K_M, K_M, K_M,
    /* C0 */ K_M, K_M, K_MB, K_M, K_MB, K_MB, K_MB, K_M, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE, K_NONE,
    /* D0 */ K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M,
    /* E0 */ K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M,
    /* F0 */ K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_M, K_NONE,
};

typedef struct {
    const u8 *p;
    size_t n;
    size_t i;
    bool ok;
} cur;

static u8 get(cur *c) {
    if (c->i >= c->n || c->i >= 15) {
        c->ok = false;
        return 0;
    }
    return c->p[c->i++];
}

/* ModRM (+SIB, disp). Returns the ModRM byte; fills disp_off/size. */
static u8 modrm(cur *c, bool asz16, DkXmInsn *o) {
    u8 m = get(c);
    if (!c->ok)
        return 0;
    u8 mod = m >> 6, rm = m & 7;
    unsigned disp = 0;
    if (mod == 3)
        return m;
    if (asz16) {
        if (mod == 0 && rm == 6)
            disp = 2;
        else if (mod == 1)
            disp = 1;
        else if (mod == 2)
            disp = 2;
    } else {
        if (rm == 4) {
            u8 sib = get(c);
            if (!c->ok)
                return 0;
            if (mod == 0 && (sib & 7) == 5)
                disp = 4;
        }
        if (mod == 0 && rm == 5)
            disp = 4;
        else if (mod == 1)
            disp = 1;
        else if (mod == 2)
            disp = 4;
    }
    if (disp) {
        o->disp_off = (u8)c->i;
        o->disp_size = (u8)disp;
        if (c->i + disp > c->n || c->i + disp > 15) {
            c->ok = false;
            return 0;
        }
        c->i += disp;
    }
    return m;
}

static void imm(cur *c, unsigned size, DkXmInsn *o) {
    if (!size)
        return;
    o->imm_off = (u8)c->i;
    o->imm_size = (u8)size;
    if (c->i + size > c->n || c->i + size > 15) {
        c->ok = false;
        return;
    }
    c->i += size;
}

static i32 rdrel(const u8 *p, unsigned size) {
    if (size == 1)
        return (i8)p[0];
    if (size == 2)
        return (i16)(p[0] | (p[1] << 8));
    return (i32)((u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24));
}

int dk_xm_x86_decode(const u8 *p, size_t n, u32 address, DkXmInsn *out) {
    DkXmInsn o;
    memset(&o, 0, sizeof o);
    cur c = {p, n, 0, true};
    bool osz = false, asz = false, lock = false;
    u8 rep = 0;
    u8 b;
    for (;;) {
        b = get(&c);
        if (!c.ok)
            return 0;
        if (one[b] != K_PFX)
            break;
        if (b == 0x66)
            osz = true;
        else if (b == 0x67)
            asz = true;
        else if (b == 0xF2 || b == 0xF3)
            rep = b;
        else if (b == 0xF0)
            lock = true;
    }
    /* mandatory-prefix class of the SSE maps: the last F2/F3, else 66 */
    int pcls = rep == 0xF3 ? 2 : rep == 0xF2 ? 3 : osz ? 1 : 0;
    unsigned zsize = osz ? 2 : 4;
    u8 kind;
    u8 op = b;
    u8 map = 0;
    if (b == 0x0F) {
        op = get(&c);
        if (!c.ok)
            return 0;
        map = 1;
        kind = two[op];
        if (kind == K_ESC) {
            u8 esc = op;
            op = get(&c);
            if (!c.ok)
                return 0;
            map = esc == 0x38 ? 2 : 3;
            kind = map == 2 ? K_M : K_MB;
        } else if (op >= 0x20 && op <= 0x23) {
            kind = K_CR; /* mov to/from cr/dr: the ModRM is always a register form */
        } else if (op == 0x78 && (pcls == 1 || pcls == 3)) {
            kind = K_MBB; /* extrq / insertq imm8, imm8 */
        }
    } else {
        kind = one[b];
    }
    o.opcode = op;
    o.map = map;
    if (kind == K_BAD)
        return 0;
    u8 m = 0;
    switch (kind) {
    case K_NONE:
        break;
    case K_M:
        m = modrm(&c, asz, &o);
        break;
    case K_MB:
        m = modrm(&c, asz, &o);
        imm(&c, 1, &o);
        break;
    case K_MBB:
        m = modrm(&c, asz, &o);
        if (c.ok && c.i < n && c.i < 15)
            c.i++;
        else
            c.ok = false;
        imm(&c, 1, &o);
        break;
    case K_CR:
        m = get(&c) | 0xC0;
        break;
    case K_MZ:
        m = modrm(&c, asz, &o);
        imm(&c, zsize, &o);
        break;
    case K_B:
        imm(&c, 1, &o);
        break;
    case K_Z:
        imm(&c, zsize, &o);
        break;
    case K_W:
        imm(&c, 2, &o);
        break;
    case K_ENTER:
        if (c.i + 3 > n || c.i + 3 > 15)
            return 0;
        c.i += 2;
        imm(&c, 1, &o);
        break;
    case K_GRP3B:
    case K_GRP3Z:
        m = modrm(&c, asz, &o);
        if (c.ok && ((m >> 3) & 7) < 2)
            imm(&c, kind == K_GRP3B ? 1 : zsize, &o);
        break;
    case K_MOFFS: {
        unsigned s = asz ? 2 : 4;
        o.disp_off = (u8)c.i;
        o.disp_size = (u8)s;
        if (c.i + s > n)
            return 0;
        c.i += s;
        break;
    }
    case K_FAR: {
        unsigned s = zsize + 2;
        if (c.i + s > n)
            return 0;
        o.far_sel_imm = (u8)((p[c.i + zsize] | (p[c.i + zsize + 1] << 8)) > 9);
        c.i += s;
        o.imm_off = (u8)(c.i - 2);
        o.imm_size = 0;
        o.branch = b == 0x9A ? DK_XM_BR_CALLFAR : DK_XM_BR_JMPFAR;
        break;
    }
    case K_R8:
    case K_RZ: {
        unsigned s = kind == K_R8 ? 1 : zsize;
        if (c.i + s > n || c.i + s > 15)
            return 0;
        o.rel = true;
        o.rel_off = (u8)c.i;
        o.rel_size = (u8)s;
        o.imm_off = (u8)c.i;
        o.imm_size = (u8)s;
        i32 r = rdrel(p + c.i, s);
        if (s == 2 && !(op == 0xE8 && map == 0))
            r = (i32)(u16)r; /* capstone 5 reads a jmp/jcc rel16 zero-extended (a call's sign-extended) */
        c.i += s;
        o.target = address + (u32)c.i + (u32)r;
        if (asz && s == 4 && !(op == 0xE8 && map == 0)) /* capstone 5, jmp/jcc under 67: wraps in the 64 KiB page */
            o.target = ((address + (u32)c.i) & 0xFFFF0000u) | (o.target & 0xFFFFu);
        if (map == 1)
            o.branch = (u8)(DK_XM_BR_JCC + (op & 0xF));
        else if (op >= 0x70 && op <= 0x7F)
            o.branch = (u8)(DK_XM_BR_JCC + (op & 0xF));
        else if (op == 0xE8)
            o.branch = DK_XM_BR_CALL;
        else if (op == 0xE9 || op == 0xEB)
            o.branch = DK_XM_BR_JMP;
        else if (op == 0xE0)
            o.branch = DK_XM_BR_LOOPNE;
        else if (op == 0xE1)
            o.branch = DK_XM_BR_LOOPE;
        else if (op == 0xE2)
            o.branch = DK_XM_BR_LOOP;
        else
            o.branch = DK_XM_BR_JECXZ;
        break;
    }
    default:
        return 0;
    }
    if (!c.ok)
        return 0;
    /* validity of particular forms */
    bool has_modrm = kind == K_M || kind == K_MB || kind == K_MZ || kind == K_GRP3B || kind == K_GRP3Z ||
                     kind == K_CR || kind == K_MBB;
    u8 mod = m >> 6, reg = (m >> 3) & 7;
    if (lock) {
        if (!has_modrm || mod == 3 || map > 1)
            return 0;
        if (!(((map == 0 ? lock1_mem : lock0f_mem)[op] >> reg) & 1))
            return 0;
    }
    if (map == 0) {
        switch (op) {
        case 0x62: case 0xC4: case 0xC5: case 0x8D: /* bound, les, lds (VEX when mod 3), lea */
            if (mod == 3)
                return 0;
            break;
        case 0x8F:
            if (reg != 0)
                return 0;
            break;
        case 0xC6: case 0xC7:
            if (reg != 0)
                return 0;
            break;
        case 0xFE:
            if (reg > 1)
                return 0;
            break;
        case 0xFF:
            if (reg == 7 || ((reg == 3 || reg == 5) && mod == 3))
                return 0;
            break;
        case 0x8C: case 0x8E:
            if (reg > 5)
                return 0;
            break;
        default:
            if (op >= 0xD8 && op <= 0xDF) {
                if (mod == 3 ? !((x87_reg[op - 0xD8] >> (m & 0x3F)) & 1) : !((x87_mem[op - 0xD8] >> reg) & 1))
                    return 0;
            }
            break;
        }
    } else if (map == 1 && op == 0x0F) {
        u8 suf = p[c.i - 1]; /* 3DNow!: the opcode is the trailing byte */
        if (!((amd3dnow_ok[suf >> 5] >> (suf & 31)) & 1))
            return 0;
    } else {
        u16 pat = sse_pat[sse_idx[map - 1][op]][pcls];
        unsigned bit = has_modrm ? (unsigned)reg + (mod == 3 ? 8u : 0u) : 0u;
        if (!((pat >> bit) & 1))
            return 0;
    }
    o.len = (u8)c.i;
    *out = o;
    return (int)c.i;
}
