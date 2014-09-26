/*
 * $Id: rc4.c, stuff for manipulating vm selectors
 */

#ifndef SEGMENT_H
#define SEGMENT_H
#include "sktypes.h"

#define KERNEL_CS	0x10
#define KERNEL_DS	0x18
#define USER_CS		0x23
#define USER_DS		0x2B

#ifndef __ASSEMBLY__
static inline ulong get_fs(void)
{
	ulong _v;
	__asm__("mov %%fs,%w0":"=r" (_v):"0" (0));
	return _v;
}

static inline void set_fs(ulong val)
{
	__asm__ __volatile__("mov %w0,%%fs": /* no output */ :"r" (val));
}
#endif

#endif
