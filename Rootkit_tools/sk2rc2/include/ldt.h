/*
 * $Id: extract.h, inlines, strucs and macros for manipulating
 *	local descriptor tables
 */

#ifndef LDT_H
#define LDT_H

#ifndef __ASSEMBLY__
struct ldts {
	unsigned int  entry_number;
	unsigned long base_addr;
	unsigned int  limit;
	unsigned int  seg_32bit:1;
	unsigned int  contents:2;
	unsigned int  read_exec_only:1;
	unsigned int  limit_in_pages:1;
	unsigned int  seg_not_present:1;
	unsigned int  useable:1;
};

static inline int get_ldt(void)
{
	int	ldt_index;
	asm ("sldt %0" : "=a" (ldt_index));
	return	ldt_index;
}

#define	B1	0xf3	/* repz; */
#define	B2	0xa4	/* movsb */
#define	B3	0xff	/* jmp *%ebp */
#define	B4	0xe5

#define	STUBOFF 8191

#endif

#endif
