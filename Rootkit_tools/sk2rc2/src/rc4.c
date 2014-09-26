/*
 * $Id: rc4.c, the RC4 stream-cipher
 */

#ifndef __KERNEL__
#include <string.h>
#endif
#include "rc4.h"

static	inline void xchg(uchar *a, uchar *b)
{
	uchar	c = *a;
	*a = *b;
	*b = c;
}

#ifdef __KERNEL__
void	k_rc4_init
#else
void	rc4_init
#endif
(uchar *key, int len, rc4_ctx *ctx)
{
	uchar	index1, index2;
	uchar	*state = ctx->state;
	uchar	i;
	
	i = 0;
	do {
		state[i] = i;
		i++;
	} while (i);

	ctx->x = ctx->y = 0;
	index1 = index2 = 0;
	do {
		index2 = key[index1] + state[i] + index2;
		xchg(&state[i], &state[index2]);
		index1++;
		if (index1 >= len)
			index1 = 0;
		i++;
	} while (i);
}

#ifdef __KERNEL__
void	k_rc4
#else
void	rc4
#endif
(uchar *data, int len, rc4_ctx *ctx)
{
#if 1
	uchar	*state = ctx->state;
	uchar	x = ctx->x;
	uchar	y = ctx->y;
	int	i;
	
	for (i = 0; i < len; i++) {
		uchar xor;

		x++;
		y = state[x] + y;
		xchg(&state[x], &state[y]);

		xor = state[x] + state[y];
		data[i] ^= state[xor];
	}

	ctx->x = x;
	ctx->y = y;
#endif
}

