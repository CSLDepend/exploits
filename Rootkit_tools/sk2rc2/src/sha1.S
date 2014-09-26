/*
 * $Id: sha1.S, my tiny SHA1 implementation, ~400 bytes!
 */

.align	0
.p2align 0

#ifndef __KERNEL__
.globl	sha1_asm
#else
.globl	sha1_kernel
#endif

/*
 * esi - input bytes
 * ecx - number of input bytes
 * edi - 20 bytes of digest
 */
.sha1:
	pusha
	push	%edi
	pushl	$0x67452301	// state[0]
	pushl	$0xEFCDAB89	// state[1]
	pushl	$0x98BADCFE	// state[2]
	pushl	$0x10325476	// state[3]
	pushl	$0xC3D2E1F0	// state[4]
	mov	%ecx, %eax
	mov	%ecx, %ebp
	shl	$3, %eax
	bswap	%eax		// sha1 works with big endian only ;(
	push	%eax		// count[0]
	sub	$128, %esp	// for padding stuff
.trans_loop:
	cmp	$64, %ecx
	jc	.gopad1
	call	.transform
	add	$64, %esi
	sub	$64, %ecx
	jmp	.trans_loop
.gopad1:
	mov	%esp, %edi
	push	%ecx
	repz;	movsb
	movb	$0x80, %al	// padding mark
	stosb
	pop	%ebx
	mov	$127, %cl
	sub	%ebx, %ecx
	xor	%eax, %eax
	repz;	stosb
	mov	%esp, %esi	// start to esi
	inc	%ecx
	mov	127(%esi,%ecx), %eax	// size to eax
	cmp	$56, %ebx
	jc	.single_align
.double_align:
	mov	%eax, 124(%esi)
	call	.transform
	add	$64, %esi
	.byte	0xba
.single_align:
	mov	%eax, 60(%esp)
	call	.transform
	add	$128+4, %esp
	
	mov	$5, %cl
	mov	20(%esp), %edi
1:	mov	-4(%esp, %ecx, 4), %eax
	bswap	%eax
	stosl
	loop	1b
	add	$24, %esp
	popa
ret

/*
 well, this is the main SHA1 function
 it must preserve all registers
 0(%esp) - count - unused
 4(%esp) - state[4]
 8(%esp) - state[3]
 12(%esp) - state[2]
 16(%esp) - state[1]
 20(%esp) - state[0]
 */
.transform:
	pusha
	// create private copy of processed data
	pushl	$64
	popl	%ecx
	sub	%ecx, %esp
	mov	%esp, %edi
	repz;	movsb
	mov	%esp, %esi

	add	$128+36+4, %edi

	mov	16(%edi), %ebp //   state[0] v a eax
	mov	12(%edi), %eax //	[1] w b ebx
	mov	8(%edi), %ebx  //	[2] x c edx
	mov	4(%edi), %edx  //	[3] y d edi
	mov	(%edi), %edi   //	[4] z e ebp

	// e = a
	// a = b
	// b = c
	// c = d
	// d = e
	xor	%ecx, %ecx
.aloop:
	// rotate a,b,c,d,e
	push	%eax
	push	%ebx
	push	%edx
	push	%edi
	push	%ebp
	pop	%eax
	pop	%ebp
	pop	%edi
	pop	%edx
	pop	%ebx
	push	%edx
	call	.rop
	push	%eax
	rol	$5, %eax
	add	%eax, %edx
	pop	%eax
	add	%edx, %ebp
	rol	$30, %ebx
	pop	%edx

	inc	%ecx
	cmp	$80, %cl
	jc	.aloop
	add	$64, %esp

	lea	128+36+4(%esp), %ecx

	add	%ebp, 16(%ecx)	// state[0]
	add	%eax, 12(%ecx)	// state[1]
	add	%ebx, 8(%ecx)	// state[2]
	add	%edx, 4(%ecx)	// state[3]
	add	%edi, (%ecx)	// state[4]

	popa
ret

.rop:
	cmp	$20, %cl
	jae	.r2
// R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
// R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
.r0:
	xor	%edi, %edx	// x = x^y
	and	%ebx, %edx	// x = x&w
	xor	%edi, %edx	// x = x^y

	cmp	$20, %cl
	jae	.r2
	cmp	$16, %cl
	jae	.r1
.r0_:
	push	%eax
	mov	(%esi, %ecx, 4), %eax // x += blk0(i)
	bswap	%eax
	mov	%eax, (%esi, %ecx, 4)
	add	%eax, %edx
	pop	%eax
	jmp	.rx
.r1:
	call	.blk
.rx:	add	$0x5A827999, %edx
.rall:	ret
//R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
//R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

.r2:
	cmp	$40, %cl
	jae	.mayber3
.r2r4:
	xor	%ebx, %edx	// x^w
	xor	%edi, %edx	// ^y
	call	.blk
	add	$0x6ED9EBA1, %edx
	cmp	$60, %cl
	jc	.rall
	// alternatively R4
	add	$(0xCA62C1D6-0x6ED9EBA1), %edx
	ret
.mayber3:
	cmp	$60, %cl
	jae	.r2r4
.r3:
//R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
	push	%edx
	or	%ebx, %edx	//x|w
	and	%edi, %edx	// &y
	and	%ebx, (%esp)
	or	(%esp), %edx
	add	$4, %esp
	call	.blk
	add	$0x8F1BBCDC, %edx
	ret

// this performs block expand function
// blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15]
//         ^block->l[(i+2)&15]^block->l[i&15],1))
// i => ecx
// result will be added to X (%edx), block itself is in esi
.blk:
	pusha
	lea	13(%ecx), %eax
	and	$15, %al	// block->l[(i+13)&15] = ebx
	lea	8(%ecx), %ebx
	and	$15, %bl	// block->l[(i+8)&15] = ebx
	lea	2(%ecx), %edx
	and	$15, %dl	// block->l[(i+2)&15] = edx
	and	$15, %cl	// block->l[i&15] = ecx

	mov	(%esi, %eax, 4), %edi // block->l[i&15]
	xor	(%esi, %ebx, 4), %edi // ^block->l[(i+8)&15]
	xor	(%esi, %edx, 4), %edi // ^block->l[(i+2)&15]
	xor	(%esi, %ecx, 4), %edi // ^block->l[i&15]
	rol	$1, %edi	// rol 1
	mov	%edi, (%esi, %ecx, 4) // result to block->l[i&15]
	add	%edi, 20(%esp)	// add to pushed %edx
	popa
ret
.sha1_end:

// sha1_asm(char *digest, char *input, int len)
#ifndef __KERNEL__
sha1_asm:
#else
sha1_kernel:
#endif
	pushal
	mov	32+4(%esp), %edi
	mov	32+8(%esp), %esi
	mov	32+12(%esp), %ecx
	call	.sha1
	popal
ret
