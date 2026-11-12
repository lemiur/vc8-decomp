// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* The reference image as the symbolic engine reads it: the file's bytes by virtual address, the section holding an
 * address (its name and characteristics, which decide whether a load reads constant data), and the dwords of a jump
 * table. The adapter's DkImage (lib/project.h) parses the file; reads follow the section table, not the loaded
 * layout. */
#include "eq2.h"
#include "dk/dk.h"
#include "dk/fs.h"

#include <string.h>

struct Eq2Image {
    const char *path;
    const DkImage *image;
    const u8 *data;
    size_t size;
    char err[512];
};

Eq2Image *eq2_image_of(DkArena *a, const DkImage *image) {
    Eq2Image *im = DK_NEW(a, Eq2Image);
    im->path = dk_image_path(image);
    im->image = image;
    im->data = dk_image_file(image, &im->size);
    return im;
}

Eq2Image *eq2_image_open(DkArena *a, const char *path, DkErr *err) {
    DkImage *image = dk_image_open(a, path, err);
    return image ? eq2_image_of(a, image) : NULL;
}

const Eq2ImageSection *eq2_image_section_of(const Eq2Image *im, u32 va) {
    size_t n = 0;
    const DkImageSection *sections = dk_image_sections(im->image, &n);
    for (size_t i = 0; i < n; i++) {
        const DkImageSection *s = &sections[i];
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
    size_t avail = off < im->size ? im->size - off : 0;
    out->p = (const char *)im->data + (avail ? off : 0);
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
