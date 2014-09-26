/*
 * $Id: strasm.h, simple string actions in assembly
 */

#ifndef STRASM_H
#define STRASM_H

#include "ktypes.h"

#ifndef NULL
#define	NULL ((void *) 0x0)
#endif

#ifndef __ASSEMBLY__
static inline void * memcpy(void *dest, void *src, ulong count)
{
	int d1,d2,d3;
	__asm__ __volatile__ (
		"rep; movsb"
		: "=&c" (d1), "=&S" (d2), "=&D" (d3)
		: "0" (count), "1" ((ulong) src), "2" ((ulong) dest));
	return dest;
}

static inline char * strcpy(char *dest, char *src)
{
	int	d1, d2, d3;
	__asm__ __volatile__ (
		"1:\tlodsb\n\t"
		"stosb\n\t"
		"testb %%al, %%al\n\t"
		"jne 1b\n\t"
		: "=&a" (d1), "=&S" (d2), "=&D" (d3)
		: "1" ((ulong) src), "2" ((ulong) dest));
	return dest;
}

static inline char * strcat(char *dest, char *src)
{
	int	d1, d2, d3, d4;
	__asm__ __volatile__ (
		"decl	%0\n\t"
		"repnz; scasb\n\t"
		"decl   %1\n\t"
		"1:\tlodsb\n\t"
		"stosb\n\t"
		"testb %%al, %%al\n\t"
		"jnz 1b\n\t"
		: "=&a" (d1), "=&c" (d2), "=&D" (d3), "=&S" (d4)
		: "0" (0), "1" (0), "2" ((ulong) dest), "3" ((ulong) src));
	return dest;
}

static inline int strcmp(const char * cs,const char * ct)
{
int d0, d1;
register int __res;
__asm__ __volatile__(
	"1:\tlodsb\n\t"
	"scasb\n\t"
	"jne 2f\n\t"
	"testb %%al,%%al\n\t"
	"jne 1b\n\t"
	"xorl %%eax,%%eax\n\t"
	"jmp 3f\n"
	"2:\tsbbl %%eax,%%eax\n\t"
	"orb $1,%%al\n"
	"3:"
	:"=a" (__res), "=&S" (d0), "=&D" (d1)
		     :"1" (cs),"2" (ct));
return __res;
}

static inline char *strchr(char *s, char c)
{
	register char *res;
	int	d1, d2;
	uchar	d3;
	__asm__ __volatile__ (
		"1:\tlodsb\n\t"
		"test %%al, %%al\n\t"
		"jz 2f\n\t"
		"cmpb %2, %%al\n\t"
		"jne 1b\n\t"
		"lea -1(%%esi), %0\n\t"
		"jmp 1b\n\t"
		"2:\n\t"
		: "=&r" (res), "=&r" ((uchar) d3), "=&a"  (d1), "=&S" (d2)
		: "0" (0), "1" (c), "3" (s));
	return res;
}

static inline int strlen(char *s)
{
	int d1, d2;
	register int res;
	__asm__ __volatile (
		"decl %0\n\t"
		"repnz; scasb\n\t"
		"notl %0\n\t"
		"decl %0\n\t"
		: "=c" (res), "=&D" (d1), "=&a" (d2) : "0" (0), "1" (s), "2" (0));
	return res;
}

static inline void * memmove(void * dest,void * src, ulong n)
{
int d0, d1, d2;
if (dest<src)
__asm__ __volatile__(
	"rep\n\t"
	"movsb"
	: "=&c" (d0), "=&S" (d1), "=&D" (d2)
	:"0" (n),"1" (src),"2" (dest)
	: "memory");
else
__asm__ __volatile__(
	"std\n\t"
	"rep\n\t"
	"movsb\n\t"
	"cld"
	: "=&c" (d0), "=&S" (d1), "=&D" (d2)
	:"0" (n),
	 "1" (n-1+(const char *)src),
	 "2" (n-1+(char *)dest)
	:"memory");
return dest;
}

static inline void * memchr(const void * cs,int c,ulong count)
{
int d0;
register void * __res;
if (!count)
	return NULL;
__asm__ __volatile__(
	"repne\n\t"
	"scasb\n\t"
	"je 1f\n\t"
	"movl $1,%0\n"
	"1:\tdecl %0"
	:"=D" (__res), "=&c" (d0) : "a" (c),"0" (cs),"1" (count));
return __res;
}

static inline void * memset(void * s, char c, ulong count)
{
int d0, d1;
__asm__ __volatile__(
	"rep\n\t"
	"stosb"
	: "=&c" (d0), "=&D" (d1)
	:"a" (c),"1" (s),"0" (count)
	:"memory");
return s;
}

static inline unsigned strnlen(const char * s, unsigned count)
{
        const char *sc;

        for (sc = s; count-- && *sc != '\0'; ++sc)
                /* nothing */;
        return sc - s;
}

static inline int memcmp(const void * cs,const void * ct,size_t count)
{
int	d0, d1, d2;
register int __res;
__asm__ __volatile__(
	"repe\n\t"
	"cmpsb\n\t"
	"je 1f\n\t"
	"sbbl %0,%0\n\t"
	"orb $1,%b0\n"
	"1:"
	:"=a" (__res), "=&S" (d0), "=&D" (d1), "=&c" (d2)
	:"0" (0), "1" (cs), "2" (ct), "3" (count));
return __res;
}

static inline int strncmp(const char * cs,const char * ct,size_t count)
{
register int __res;
int d0, d1, d2;
__asm__ __volatile__(
	"1:\tdecl %3\n\t"
	"js 2f\n\t"
	"lodsb\n\t"
	"scasb\n\t"
	"jne 3f\n\t"
	"testb %%al,%%al\n\t"
	"jne 1b\n"
	"2:\txorl %%eax,%%eax\n\t"
	"jmp 4f\n"
	"3:\tsbbl %%eax,%%eax\n\t"
	"orb $1,%%al\n"
	"4:"
		     :"=a" (__res), "=&S" (d0), "=&D" (d1), "=&c" (d2)
		     :"1" (cs),"2" (ct),"3" (count));
return __res;
}

static inline char * strncpy(char * dest,const char *src,int count)
{
	char *tmp = dest;

	while (count-- && (*dest++ = *src++) != '\0')
		/* nothing */;

	return tmp;
}


#endif

#define	CLEAR(var) memset(&var, 0, sizeof(var))
#endif
