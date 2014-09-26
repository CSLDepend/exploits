/*
 * $Id: extract.h, inlines, strucs and macros for manipulating
 *	interrupt descriptor tables
 */

#ifndef IDT_H
#define IDT_H

#include "sktypes.h"

#define	IDT_OFF1	0
#define	IDT_OFF2	6
#define	IDT_MAGIC	226

#ifndef __ASSEMBLY__
struct idtr {
        ushort	limit;
	ulong	base;
} __attribute__ ((packed));

struct idt {
	ushort	off1;
	ushort	sel;
	uchar	none, flags;
	ushort	off2;
} __attribute__ ((packed));

static	inline void get_idt(struct idtr *idtr)
{
	asm ("sidt %0" : "=m" (*idtr));
//	idtr->base = 0xc023f000;
}

static	inline void set_idt(struct idtr *idtr)
{
	asm (	"pushf\n\t"
		"cli\n\t"
		"lidt %0\n\t"
		"popf\n\t"
		: "=m" (*idtr));
}

#endif

#define IDT_BASE(x) ((x).off1 | ((x).off2 << 16))
#define	SET_IDT_BASE(x, addr) do { (x).off1 = (addr) & 0xffff; (x).off2 = (addr) >> 16; } while (0)

#endif
