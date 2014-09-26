/*
 * $Id: kmem.h, routines for work with /dev/mem and /dev/kmem
 */

#ifndef KMEM_H
#define KMEM_H

#include "sktypes.h"

#ifndef __ASSEMBLY__
extern int	kmem_init(void);
extern void	kmem_cleanup(void);
extern int	rkm(void *buf, int count, ulong off);
extern int	wkm(void *buf, int count, ulong off);
extern int	rkml(ulong *l, ulong off);
extern int	wkml(ulong l, ulong off);
#endif

#endif
