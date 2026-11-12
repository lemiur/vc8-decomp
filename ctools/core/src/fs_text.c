// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* Text codecs and newline handling of Python's open(): bytes -> UTF-8 text with TextIOWrapper's newline translation,
 * and the reverse. The UTF-8 decoder follows CPython's: every error covers the bytes CPython reports (its
 * "maximal subpart" ranges), and errors="replace" puts one U+FFFD per error range. */
#include "fs_priv.h"

#include <stdio.h>

typedef struct {
    size_t start, end;
    const char *reason;
} Utf8Err;

static bool is_cont(unsigned char c) { return (c & 0xC0) == 0x80; }

/* CPython's UTF-8 decoder step for the sequence starting at s[0] >= 0x80: returns the length of the valid sequence
 * (and the code point) or 0 with the error range [0, *bad_end) and the reason. `left` is the byte count to the end. */
static size_t utf8_step(const unsigned char *s, size_t left, u32 *cp, size_t *bad_end, const char **reason) {
    unsigned char c = s[0];
    if (c < 0xC2) {
        *reason = "invalid start byte";
        *bad_end = 1;
        return 0;
    }
    if (c < 0xE0) {
        if (left < 2) goto truncated;
        if (!is_cont(s[1])) goto invalid1;
        *cp = ((u32)(c & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    }
    if (c < 0xF0) {
        if (left < 2) goto truncated;
        if (!is_cont(s[1]) || (c == 0xE0 && s[1] < 0xA0) || (c == 0xED && s[1] >= 0xA0)) goto invalid1;
        if (left < 3) goto truncated;
        if (!is_cont(s[2])) goto invalid2;
        *cp = ((u32)(c & 0x0F) << 12) | ((u32)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return 3;
    }
    if (c < 0xF5) {
        if (left < 2) goto truncated;
        if (!is_cont(s[1]) || (c == 0xF0 && s[1] < 0x90) || (c == 0xF4 && s[1] >= 0x90)) goto invalid1;
        if (left < 3) goto truncated;
        if (!is_cont(s[2])) goto invalid2;
        if (left < 4) goto truncated;
        if (!is_cont(s[3])) {
            *reason = "invalid continuation byte";
            *bad_end = 3;
            return 0;
        }
        *cp = ((u32)(c & 0x07) << 18) | ((u32)(s[1] & 0x3F) << 12) | ((u32)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return 4;
    }
    *reason = "invalid start byte";
    *bad_end = 1;
    return 0;
invalid1:
    *reason = "invalid continuation byte";
    *bad_end = 1;
    return 0;
invalid2:
    *reason = "invalid continuation byte";
    *bad_end = 2;
    return 0;
truncated:
    *reason = "unexpected end of data";
    *bad_end = left;
    return 0;
}

static void fail_decode(const char *codec, const unsigned char *base, size_t start, size_t end, const char *reason) {
    char text[512];
    if (end == start + 1)
        snprintf(text, sizeof text, "'%s' codec can't decode byte 0x%02x in position %zu: %s", codec, base[start], start, reason);
    else
        snprintf(text, sizeof text, "'%s' codec can't decode bytes in position %zu-%zu: %s", codec, start, end - 1, reason);
    dk_io_fail_msg(DK_IOE_DECODE, 0, "%s", text);
}

/* Appends the decoded text of p[0..n) as UTF-8 to b; error positions are offsets into p. */
static bool decode_utf8(FsBuf *b, const unsigned char *p, size_t n, DkErrorsMode errors) {
    size_t i = 0;
    fsb_reserve(b, n);
    while (i < n) {
        /* ASCII run, eight bytes at a time */
        size_t j = i;
        while (j + 8 <= n) {
            u64 w;
            memcpy(&w, p + j, 8);
            if (w & 0x8080808080808080ULL) break;
            j += 8;
        }
        while (j < n && p[j] < 0x80) j++;
        if (j > i) {
            fsb_put(b, p + i, j - i);
            i = j;
            if (i >= n) break;
        }
        u32 cp = 0;
        size_t bad_end = 0;
        const char *reason = NULL;
        size_t len = utf8_step(p + i, n - i, &cp, &bad_end, &reason);
        if (len) {
            fsb_put(b, p + i, len); /* a valid sequence is copied as is */
            i += len;
            continue;
        }
        if (errors == DK_ERR_STRICT) {
            fail_decode("utf-8", p, i, i + bad_end, reason);
            return false;
        }
        fsb_put(b, "\xEF\xBF\xBD", 3);
        i += bad_end;
    }
    return true;
}

/* Translates \r\n and \r to \n in place (newline=None reading); returns the new length. */
static size_t translate_universal(char *p, size_t n) {
    char *first = memchr(p, '\r', n);
    if (!first) return n;
    char *w = first;
    const char *r = first, *end = p + n;
    while (r < end) {
        if (*r == '\r') {
            *w++ = '\n';
            r++;
            if (r < end && *r == '\n') r++;
        } else *w++ = *r++;
    }
    return (size_t)(w - p);
}

bool dk_fs_decode_bytes(DkArena *a, const u8 *p, size_t n, DkTextMode m, DkStr *out) {
    FsBuf b;
    fsb_init(&b, a);
    bool ok = true;
    switch (m.enc) {
    case DK_ENC_UTF8_SIG:
        if (n >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) {
            p += 3;
            n -= 3;
        }
        /* fall through */
    case DK_ENC_UTF8:
        ok = decode_utf8(&b, p, n, m.errors); /* utf-8-sig errors count from after the BOM, as CPython's */
        break;
    case DK_ENC_LATIN1:
        fsb_reserve(&b, n * 2);
        for (size_t i = 0; i < n; i++) {
            if (p[i] < 0x80) fsb_putc(&b, (char)p[i]);
            else fsb_putcp(&b, p[i]);
        }
        break;
    case DK_ENC_ASCII:
        fsb_reserve(&b, n);
        for (size_t i = 0; i < n; i++) {
            if (p[i] < 0x80) fsb_putc(&b, (char)p[i]);
            else if (m.errors == DK_ERR_STRICT) {
                char t[160];
                snprintf(t, sizeof t, "'ascii' codec can't decode byte 0x%02x in position %zu: ordinal not in range(128)", p[i], i);
                dk_io_fail_msg(DK_IOE_DECODE, 0, "%s", t);
                ok = false;
                break;
            } else fsb_put(&b, "\xEF\xBF\xBD", 3);
        }
        break;
    case DK_ENC_MBCS: {
        if (n == 0) break;
        DkArena *sc = fs_tmp();
        DkArenaMark mk = dk_arena_mark(sc);
        int wl = MultiByteToWideChar(CP_ACP, 0, (const char *)p, (int)n, NULL, 0);
        wchar_t *w = (wchar_t *)dk_alloc_noz(sc, ((size_t)wl + 1) * sizeof(wchar_t));
        MultiByteToWideChar(CP_ACP, 0, (const char *)p, (int)n, w, wl);
        int ul = WideCharToMultiByte(CP_UTF8, 0, w, wl, NULL, 0, NULL, NULL);
        fsb_reserve(&b, (size_t)ul);
        WideCharToMultiByte(CP_UTF8, 0, w, wl, b.p + b.n, ul, NULL, NULL);
        b.n += (size_t)ul;
        fs_tmp_done(sc, mk);
        break;
    }
    }
    if (!ok) return false;
    if (m.newline == DK_NL_DEFAULT && b.n) b.n = translate_universal(b.p, b.n);
    fsb_cz(&b);
    out->p = b.p;
    out->n = b.n;
    return true;
}

bool dk_decode_text(DkArena *a, DkStr bytes, DkTextMode m, DkStr *out) {
    return dk_fs_decode_bytes(a, (const u8 *)bytes.p, bytes.n, m, out);
}

/* ---- encoding ------------------------------------------------------------------------------------------------- */

static void repr_cp(FsBuf *b, u32 c) {
    /* the character as repr() shows it inside the error text: '€' */
    char t[16];
    if (c <= 0xFF) snprintf(t, sizeof t, "\\x%02x", c);
    else if (c <= 0xFFFF) snprintf(t, sizeof t, "\\u%04x", c);
    else snprintf(t, sizeof t, "\\U%08x", c);
    fsb_putz(b, t);
}

static bool encode_limited(FsBuf *out, DkStr t, DkErrorsMode errors, u32 limit, const char *codec) {
    const char *p = t.p, *end = t.p + t.n;
    size_t pos = 0;
    while (p < end) {
        const char *at = p;
        u32 c = dk_fs_u8_next(&p, end);
        if (c < limit) {
            fsb_putc(out, (char)c);
            pos++;
            continue;
        }
        if (errors == DK_ERR_REPLACE) {
            fsb_putc(out, '?');
            pos++;
            continue;
        }
        /* a run of consecutive unencodable characters is one error */
        size_t first = pos, count = 1;
        u32 firstc = c;
        const char *q = p;
        while (q < end) {
            const char *s2 = q;
            u32 c2 = dk_fs_u8_next(&q, end);
            if (c2 < limit) {
                q = s2;
                break;
            }
            count++;
        }
        (void)at;
        FsBuf msg;
        fsb_init(&msg, NULL);
        if (count == 1) {
            fsb_printf(&msg, "'%s' codec can't encode character '", codec);
            repr_cp(&msg, firstc);
            fsb_printf(&msg, "' in position %zu: ordinal not in range(%u)", first, limit);
        } else {
            fsb_printf(&msg, "'%s' codec can't encode characters in position %zu-%zu: ordinal not in range(%u)", codec,
                       first, first + count - 1, limit);
        }
        dk_io_fail_msg(DK_IOE_ENCODE, 0, "%s", fsb_cz(&msg));
        dk_xfree(msg.p);
        return false;
    }
    return true;
}

bool dk_fs_encode_text(FsBuf *out, DkStr text, DkTextMode m, bool bom) {
    DkStr t = text;
    FsBuf tr;
    fsb_init(&tr, NULL);
    if (m.newline == DK_NL_DEFAULT || m.newline == DK_NL_CR || m.newline == DK_NL_CRLF) {
        const char *nl = m.newline == DK_NL_CR ? "\r" : "\r\n";
        size_t nll = strlen(nl);
        const char *p = text.p, *end = text.p + text.n;
        if (memchr(p, '\n', text.n)) {
            fsb_reserve(&tr, text.n + text.n / 8);
            while (p < end) {
                const char *q = memchr(p, '\n', (size_t)(end - p));
                if (!q) {
                    fsb_put(&tr, p, (size_t)(end - p));
                    break;
                }
                fsb_put(&tr, p, (size_t)(q - p));
                fsb_put(&tr, nl, nll);
                p = q + 1;
            }
            t.p = fsb_cz(&tr);
            t.n = tr.n;
        }
    }
    bool ok = true;
    switch (m.enc) {
    case DK_ENC_UTF8_SIG:
        if (bom) fsb_put(out, "\xEF\xBB\xBF", 3);
        /* fall through */
    case DK_ENC_UTF8:
        fsb_put(out, t.p, t.n);
        break;
    case DK_ENC_LATIN1:
        ok = encode_limited(out, t, m.errors, 0x100, "latin-1");
        break;
    case DK_ENC_ASCII:
        ok = encode_limited(out, t, m.errors, 0x80, "ascii");
        break;
    case DK_ENC_MBCS: {
        DkArena *sc = fs_tmp();
        DkArenaMark mk = dk_arena_mark(sc);
        char *z = (char *)dk_alloc_noz(sc, t.n + 1);
        memcpy(z, t.p, t.n);
        z[t.n] = 0;
        wchar_t *w = dk_fs_u8_to_w(sc, z);
        int wl = (int)wcslen(w);
        int bl = wl ? WideCharToMultiByte(CP_ACP, 0, w, wl, NULL, 0, NULL, NULL) : 0;
        fsb_reserve(out, (size_t)bl);
        if (bl) WideCharToMultiByte(CP_ACP, 0, w, wl, out->p + out->n, bl, NULL, NULL);
        out->n += (size_t)bl;
        fs_tmp_done(sc, mk);
        break;
    }
    }
    dk_xfree(tr.p);
    return ok;
}

bool dk_encode_text(DkArena *a, DkStr text, DkTextMode m, DkStr *out) {
    FsBuf b;
    fsb_init(&b, a);
    if (!dk_fs_encode_text(&b, text, m, true)) return false;
    fsb_cz(&b);
    out->p = b.p;
    out->n = b.n;
    return true;
}

/* ---- lines ---------------------------------------------------------------------------------------------------- */

void dk_file_lines_init(DkFileLines *it, DkStr text, DkNewline newline) {
    it->rest = text;
    it->newline = newline;
}

bool dk_file_lines_next(DkFileLines *it, DkStr *line) {
    DkStr r = it->rest;
    if (r.n == 0) return false;
    size_t k = 0;
    switch (it->newline) {
    case DK_NL_DEFAULT:
    case DK_NL_LF: {
        const char *q = memchr(r.p, '\n', r.n);
        k = q ? (size_t)(q - r.p) + 1 : r.n;
        break;
    }
    case DK_NL_CR: {
        const char *q = memchr(r.p, '\r', r.n);
        k = q ? (size_t)(q - r.p) + 1 : r.n;
        break;
    }
    case DK_NL_CRLF: {
        k = r.n;
        for (size_t i = 0; i + 1 < r.n; i++)
            if (r.p[i] == '\r' && r.p[i + 1] == '\n') {
                k = i + 2;
                break;
            }
        break;
    }
    case DK_NL_EMPTY: {
        k = r.n;
        for (size_t i = 0; i < r.n; i++) {
            if (r.p[i] == '\n') {
                k = i + 1;
                break;
            }
            if (r.p[i] == '\r') {
                k = (i + 1 < r.n && r.p[i + 1] == '\n') ? i + 2 : i + 1;
                break;
            }
        }
        break;
    }
    }
    line->p = r.p;
    line->n = k;
    it->rest.p = r.p + k;
    it->rest.n = r.n - k;
    return true;
}
