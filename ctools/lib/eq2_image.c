// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The reference image as the symbolic engine reads it: the file's bytes by virtual address, the section holding an
 * address (its name and characteristics, which decide whether a load reads constant data), and the dwords of a jump
 * table. A PE32 file read whole; reads follow the section table, not the loaded layout. */
#include "eq2.h"
#include "dk/dk.h"
#include "dk/fs.h"

#include <string.h>

struct Eq2Image {
    const char *path;
    DkBytes data;
    DkPe *pe;
    u32 base;
    Eq2ImageSection *sections; /* in the file's section-table order */
    size_t n_sections;
    char err[512];
};

Eq2Image *eq2_image_open(DkArena *a, const char *path, DkErr *err) {
    Eq2Image *im = DK_NEW(a, Eq2Image);
    im->path = dk_strdup(a, path);
    if (!dk_read_all(a, path, &im->data)) {
        dk_err_set(err, DK_ERR_IO, "%s: %.*s", path, DK_SF(dk_io_err_str(a)));
        return NULL;
    }
    DkTry tr;
    if (DK_TRY(&tr)) {
        im->pe = dk_pe_parse(a, im->data.v, im->data.n);
        if (im->pe->pe_type != DK_PE_MAGIC_PE32 || im->pe->image_base > 0xFFFFFFFFull)
            dk_throw(DK_ERR_FORMAT, "not a PE32 image");
        dk_try_end(&tr);
    } else {
        dk_err_set(err, DK_ERR_FORMAT, "%s: %s", path, tr.msg);
        return NULL;
    }
    im->base = (u32)im->pe->image_base;
    size_t n = im->pe->n_sections;
    im->sections = DK_NEWN(a, Eq2ImageSection, n ? n : 1);
    for (size_t i = 0; i < n; i++) {
        const DkPeSection *s = &im->pe->sections[i];
        Eq2ImageSection *o = &im->sections[s->index < n ? s->index : i];
        o->name = s->name;
        o->va = im->base + s->virtual_address;
        o->vsize = s->virtual_size;
        o->raw_size = s->size_of_raw_data;
        o->raw = s->pointer_to_raw_data;
        o->chars = s->characteristics;
    }
    im->n_sections = n;
    return im;
}

const Eq2ImageSection *eq2_image_section_of(const Eq2Image *im, u32 va) {
    for (size_t i = 0; i < im->n_sections; i++) {
        const Eq2ImageSection *s = &im->sections[i];
        u32 span = s->vsize > s->raw_size ? s->vsize : s->raw_size;
        if (va >= s->va && (u64)va < (u64)s->va + span) return s;
    }
    return NULL;
}

bool eq2_image_offset_of(const Eq2Image *im, u32 va, u32 *offset, const char **err) {
    const Eq2ImageSection *s = eq2_image_section_of(im, va);
    if (!s) {
        if (err) {
            Eq2Image *m = (Eq2Image *)im; /* the message buffer is scratch, not state */
            DkStr base = dk_path_basename(im->path);
            snprintf(m->err, sizeof m->err, "address %08X is not in %.*s", va, DK_SF(base));
            *err = m->err;
        }
        return false;
    }
    *offset = s->raw + (va - s->va);
    return true;
}

bool eq2_image_read(const Eq2Image *im, u32 va, u32 size, DkStr *out, const char **err) {
    u32 off;
    if (!eq2_image_offset_of(im, va, &off, err)) return false;
    size_t avail = off < im->data.n ? im->data.n - off : 0;
    out->p = (const char *)im->data.v + (avail ? off : 0);
    out->n = size < avail ? size : avail;
    return true;
}

u32 eq2_image_read_u32(const Eq2Image *im, u32 va) {
    DkStr b;
    const char *err = NULL;
    if (!eq2_image_read(im, va, 4, &b, &err)) dk_panic(__FILE__, __LINE__, "%s", err);
    u32 v = 0;
    memcpy(&v, b.p, b.n < 4 ? b.n : 4);
    return v;
}
