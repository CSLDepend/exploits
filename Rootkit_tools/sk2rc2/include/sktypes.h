/*
 * $Id: sktypes.h, general data types definition for sk
 */


#ifndef SKTYPES_H
#define SKTYPES_H

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef ushort
#define ushort unsigned short
#endif

#ifndef ulong
#define ulong unsigned long
#endif

#ifndef uint
#define uint ulong
#endif

#ifndef __ASSEMBLY__
struct sc_info {
	ulong	trace;
	ulong	ret;
	ulong	pt_ret;
	ulong	pt_off;
	uchar	pt_bit;
} __attribute__ ((packed));

struct	wsize {
	uchar	id;
	ushort	col;
	ushort	row;
} __attribute__ ((packed));
#endif

#endif
