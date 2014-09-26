/*
 * $Id: rc4.h, the RC4 stream-cipher
 */

#ifndef RC4_H
#define RC4_H

#include "sktypes.h"

#ifndef __ASSEMBLY__
typedef struct {      
	uchar	state[256];
	uchar	x, y;
} rc4_ctx;

#ifdef __KERNEL__
extern void	k_rc4_init(uchar *key, int len, rc4_ctx *ctx);
extern void	k_rc4(uchar *data, int len, rc4_ctx *ctx);
#else
extern void	rc4_init(uchar *key, int len, rc4_ctx *ctx);
extern void	rc4(uchar *data, int len, rc4_ctx *ctx);
#endif

#endif

#endif
