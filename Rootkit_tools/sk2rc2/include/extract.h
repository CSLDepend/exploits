/*
 * $Id: extract.h, various kernel-struct extracting routines
 */

#ifndef PATTERN_H
#define PATTERN_H

#include "sktypes.h"

#ifndef __ASSEMBLY__
ulong	get_kbase();
ulong	get_ep();
ulong	get_current();
ulong	get_sct();
ulong	get_vmalloc(ulong sct, ulong *gfps);
ulong	get_idt_table(void);

extern	struct  sc_info sc;

#endif


#endif
