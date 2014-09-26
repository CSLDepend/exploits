/*
 * $Id: extract.h, inlines, strucs and macros for manipulating
 *	global descriptor tables
 */

#ifndef GDT_H
#define GDT_H

#define	IDT_OFF1	0
#define	IDT_OFF2	6
#define	IDT_MAGIC	226

#ifndef __ASSEMBLY__

struct gdtr {
	unsigned short limit;
	unsigned long base;
} __attribute__ ((packed));

struct gdt {
	unsigned short limit;
	unsigned short baselo;
	unsigned char basemed;
	unsigned short dummy;
	unsigned char basehi;
} __attribute__ ((packed));

static	inline void get_gdt(struct gdtr *gdtr)
{
	asm ("sgdt %0" : "=m" (*gdtr));
}

#endif

#define	GDT_BASE(x) (x.baselo | (x.basemed << 16) | (x.basehi) << 24)

#endif
