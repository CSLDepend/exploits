/*
 * $Id: kernel.h, structs/externs/defines for kernel related part
 */

#ifndef KERNEL_H
#define KERNEL_H

#include "sk.h"
#include "idt.h"
#include "segment.h"

/* offsets in task struct */
#define	FALLTHRU -200
#define	TASK_LIMIT 12
#define TASK_FLAGS 4
#define	TASK_STATE 0

//#define	KERNEL_SECTION	".data.kernelcode"
//#define	kd(x...) x __attribute__((__section__(KERNEL_SECTION))); x

#define do_syscall __do_syscall
#define	SYS(x, y...) do_syscall(__NR_##x, y)

#ifndef __ASSEMBLY__
extern	void	kernel_start(void);
extern	void	kernel_end(void);
extern	struct idt kernel_idt[256];
extern	void	int80_hook(void);
extern	ulong	kcount;

extern	ulong	kernel_old80;
extern	ulong	kernel_sysaux;
extern	ulong	*kernel_sct;
extern	ulong	kbase;
extern	struct	idt *kidt;
extern	int	kernel_entry(void);

extern	int	__do_syscall(int nr, ...);
//extern	int	kernel_thread(void (*fn)(ulong, ulong), ulong, ulong);
extern	int	kernel_thread(void *, ulong, ulong);


static inline void	*current()
{
	void *current;
	__asm__("andl %%esp,%0; ":"=r" (current) : "0" (~8191UL));
	return current;
}

#define current ((char *) current())

#define	SYSTEM_CALL_SZ	1024
#define	KERNEL_SIZE	(4*1024*1024)
#define SIGPENDING	8

#else /* __ASSEMBLY */
//.section	KERNEL_SECTION
.data
.align		0
.p2align 	0
#endif

#endif
