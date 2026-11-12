// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
/* frame_slots: see frame_slots.h. */
#include "frame_slots.h"

#include "cfg_diff.h"
#include "dk/fmt.h"
#include "dk/map.h"
#include "project_backend.h"
#include "walls.h"

/* DkFrameRetail.read over the target's image: the bytes at va up to the end of its section, so the end of an image
 * reads as fewer bytes, and an address outside every section as nothing. */
static DkStr image_read(void *ctx, i64 va, i64 n) {
    const DkImage *im = ctx;
    if (va < 0 || va > 0xFFFFFFFFll || n <= 0) return (DkStr){"", 0};
    u32 end = dk__image_section_end(im, (u32)va);
    if (end <= (u32)va) return (DkStr){"", 0};
    if (n > (i64)(end - (u32)va)) n = (i64)(end - (u32)va);
    DkStr out;
    if (!dk_image_read(im, (u32)va, (size_t)n, &out)) return (DkStr){"", 0};
    return out;
}

static DkFrameRetail retail_of(DkArena *a, const DkProject *p, int target, const DkImage *im) {
    const DkTarget *t = dk_project_target(p, target);
    DkFrameRetail fr = {t->image_path, image_read, (void *)im, 0, 0xFFFFFFFFll, NULL, 0};
    const DkCompiler *c = t->compiler;
    if (c && c->cdecl_import_dlls_set) {
        const char **v = DK_NEWN(a, const char *, c->cdecl_import_dlls.n + 1);
        for (size_t i = 0; i < c->cdecl_import_dlls.n; i++) v[i] = dk_cz(a, c->cdecl_import_dlls.v[i]);
        fr.cdecl_dlls = v;
        fr.n_cdecl_dlls = c->cdecl_import_dlls.n;
        if (!fr.n_cdecl_dlls) fr.cdecl_dlls = NULL;
    }
    return fr;
}

static DkFrameReloc *relocs_of(DkArena *a, const DkResult *r) {
    DkFrameReloc *v = DK_NEWN(a, DkFrameReloc, r->n_refs + 1);
    for (size_t i = 0; i < r->n_refs; i++) {
        v[i].offset = r->refs[i].offset;
        v[i].has_target = r->refs[i].verdict != DK_REF_UNRESOLVED;
        v[i].target = v[i].has_target ? (i64)r->refs[i].ours : 0;
    }
    return v;
}

static bool has_reference(const DkResult *r) { return r->theirs_va != 0 && r->ours.code.n && (r->theirs.n || r->theirs_va); }

void dk_frame_slots_format(DkBuf *out, const DkProject *p, const DkResult *r, const DkImage *im,
                           const DkFrameName *names, size_t n_names) {
    DkArena *a = dk_arena();
    const char *build = dk_project_target(p, r->target)->name;
    if (!has_reference(r)) {
        dk_buf_put(out, dk_pyfmt(a, "%s slot map: the reference's bytes are not available\n", build));
        return;
    }
    const char *err = NULL;
    CfgDiffAnalysis *an = cfg_diff_analyse(r, im, build, CFG_DIFF_NONE, &err);
    if (!an) {
        dk_buf_put(out, dk_pyfmt(a, "%s slot map: cfg_diff failed: %s\n", build, err));
        return;
    }
    DkFrameRetail fr = retail_of(a, p, r->target, im);
    DkFrameReloc *relocs = relocs_of(a, r);
    DkFrame *ours = dk_frame_analyse(a, an->ours->code, an->address, &fr, relocs, r->n_refs, true);
    DkFrame *game = dk_frame_analyse(a, an->game->code, an->address, &fr, NULL, 0, false);
    DkIMap *map = cfg_diff_insn_map(an);
    dk_buf_put(out, dk_pyfmt(a, "%s slot map of %s at %08X, %d of %d blocks aligned\n", build, r->ours.symbol,
                             (u32)an->address, an->matched, an->blocks_ours));
    dk_frame_slotmap(out, ours, game, map, names, n_names);
}

void dk_frame_report(DkBuf *out, const DkProject *p, const DkResult *r, const DkImage *im) {
    DkArena *a = dk_arena();
    const char *build = dk_project_target(p, r->target)->name;
    if (!has_reference(r)) {
        dk_buf_put(out, dk_pyfmt(a, "%s frame: the reference's bytes are not available\n", build));
        return;
    }
    DkFrameRetail fr = retail_of(a, p, r->target, im);
    DkFrameResult fres = {build, (i64)r->theirs_va, r->ours.symbol, r->ours.symbol, r->ours.code, relocs_of(a, r),
                          r->n_refs, dk_wall_reference_window(r, im)};
    fres.annotation_name = r->ann && r->ann->name ? r->ann->name : "";
    dk_frame_format(out, &fres, &fr);
    dk_buf_putc(out, '\n');
    dk_frame_slots_format(out, p, r, im, NULL, 0);
}

static DkJson *side_json(DkArena *a, const DkFrame *f) {
    DkJson *o = dk_json_obj(a);
    DkJson *saved = dk_json_arr(a);
    for (size_t i = 0; i < f->n_saved; i++) dk_json_arr_push(a, saved, dk_json_str(a, f->saved[i]));
    dk_json_set(a, o, DK_S("saved"), saved);
    dk_json_set(a, o, DK_S("locals"), dk_json_int(a, f->locals));
    dk_json_set(a, o, DK_S("frame_pointer"), f->has_frame_pointer ? dk_json_int(a, f->frame_pointer) : dk_json_null());
    dk_json_set(a, o, DK_S("align"), f->has_align ? dk_json_int(a, f->align) : dk_json_null());
    dk_json_set(a, o, DK_S("cookie"), f->has_cookie ? dk_json_int(a, f->cookie_offset) : dk_json_null());
    dk_json_set(a, o, DK_S("eh"), dk_json_bool(f->eh));
    dk_json_set(a, o, DK_S("unknown_calls"), dk_json_int(a, f->unknown_calls));
    dk_json_set(a, o, DK_S("slots"), dk_json_int(a, (i64)f->n_slots));
    return o;
}

DkJson *dk_frame_json(DkArena *a, const DkProject *p, const DkResult *r, const DkImage *im) {
    if (!has_reference(r)) return NULL;
    const char *err = NULL;
    CfgDiffAnalysis *an = cfg_diff_analyse(r, im, dk_project_target(p, r->target)->name, CFG_DIFF_NONE, &err);
    if (!an) return NULL;
    DkFrameRetail fr = retail_of(a, p, r->target, im);
    DkFrame *ours = dk_frame_analyse(a, an->ours->code, an->address, &fr, relocs_of(a, r), r->n_refs, true);
    DkFrame *game = dk_frame_analyse(a, an->game->code, an->address, &fr, NULL, 0, false);
    DkJson *o = dk_json_obj(a);
    dk_json_set(a, o, DK_S("ours"), side_json(a, ours));
    dk_json_set(a, o, DK_S("reference"), side_json(a, game));
    DkFramePair *rows;
    size_t n = dk_frame_pair(a, ours, game, cfg_diff_insn_map(an), &rows);
    i64 differ = 0;
    for (size_t i = 0; i < n; i++)
        differ += !(rows[i].ours && rows[i].game && rows[i].ours->base == rows[i].game->base &&
                    rows[i].ours->offset == rows[i].game->offset);
    dk_json_set(a, o, DK_S("slot_rows_differ"), dk_json_int(a, differ));
    return o;
}
