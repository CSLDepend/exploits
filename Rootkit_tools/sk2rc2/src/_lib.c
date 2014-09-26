/*
 * $Id: _lib.c, kernel-local library functions
 */

#ifndef _KLIB_C
#define _KLIB_C

#include "lib.h"


#if 1
static int	select(ulong n, fd_set *inp, fd_set *outp, fd_set *exp,
	struct timeval *tvp)
{
        struct  sel_arg_struct b;
        b.n = n;
        b.inp = inp;
        b.outp = outp;
        b.exp = exp;
        b.tvp = tvp;
	return SYS(select, (ulong *) &b);
}
#endif

static	int	socketpair(int d, int type, int p, int *sv)
{
	ulong	a[4];
	a[0] = d;
	a[1] = type;
	a[2] = p;
	a[3] = (ulong) sv;
	return SYS(socketcall, SYS_SOCKETPAIR, a);
}

static	int	getpeername(int fd, struct sockaddr *name, int *len)
{
	ulong	a[3];
	a[0] = fd;
	a[1] = (ulong) name;
	a[2] = (ulong) len;
	return SYS(socketcall, SYS_GETPEERNAME, a);
}

static	int	recv(int fd, void *buf, int len, int flags)
{
	ulong	a[4];
	a[0] = fd;
	a[1] = (ulong) buf;
	a[2] = len;
	a[3] = flags;
	return SYS(socketcall, SYS_RECV, a);
}


static	int	socket(int domain, int type, int proto)
{
	ulong	a[3];

	a[0] = domain;
	a[1] = type;
	a[2] = proto;
	return SYS(socketcall, SYS_SOCKET, a);
}

#if 0
static	int	connect(int sock, struct sockaddr *addr, int len)
{
	ulong	a[3];

	a[0] = sock;
	a[1] = (ulong) addr;
	a[2] = len;
	return SYS(socketcall, SYS_CONNECT, a);
}
#endif

static int	k_hard_write(int fd, char *buf, int count)
{
#if 1
	int	red = 0;

	while (red < count) {
		int	i;

		i = SYS(write, fd, buf + red, count - red);
		if (i < 0) {
			if ((i == -EAGAIN) || (i == -EINTR))
				continue;
			return red;
		}
		if (i == 0)
			return red;
		red += i;
	}
	return red;
#else
	return SYS(write, fd, buf, count);
#endif

}


#endif
