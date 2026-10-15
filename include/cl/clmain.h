#ifndef CL_CLMAIN_H
#define CL_CLMAIN_H

// Public PDB argument spelling PAUflag_s proves a struct pointer. These four
// callbacks do not access it, so its layout and original parameter name remain
// unresolved. Keep this the canonical declaration until field evidence exists.
struct flag_s;

void __cdecl error_report_prompt(flag_s*);
void __cdecl error_report_queue(flag_s*);
void __cdecl error_report_send(flag_s*);
void __cdecl error_report_none(flag_s*);

#endif
