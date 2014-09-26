/*
 * $Id: infect.h, in-the-bss parasite infector, ynit.S concept
 */

#ifndef INFECT_H
#define INFECT_H

#include "sktypes.h"

typedef struct {
	char	magic[16];
	ushort	type;
	ushort	arch;
	ulong	ver;
	ulong	ep;
	ulong	phtab;
	ulong	shtab;
	ulong	flags;
	ushort	size;
	
	ushort	phentsize;
	ushort	phnum;
	ushort	shentsize;
	ushort	shnum;
	ushort	shstridx;
} __attribute__ ((packed)) ELF;


typedef struct {
	ulong	type;
	ulong	off;
	ulong	va;
	ulong	pa;
	ulong	fsize;
	ulong	msize;
	ulong	flags;
	ulong	align;
}  __attribute__ ((packed)) PH;

typedef struct {
	ulong	name;
	ulong	type;
	ulong	flags;
	ulong	addr;
	ulong	off;
	ulong	size;
	ulong	link;
	ulong	info;
	ulong	align;
	ulong	entsize;
}  __attribute__ ((packed)) SH;

extern	int	infect_binary(char *fn, char *exec);


#endif
