/*
 * $Id: lib.h, libc emulation -- some defs and externs
 */

#ifndef LIB_H
#define LIB_H

#include "sktypes.h"

#define POLLIN		0x0001
#define POLLPRI		0x0002
#define POLLOUT		0x0004
#define POLLERR		0x0008
#define POLLHUP		0x0010
#define POLLNVAL	0x0020
#define POLLRDNORM	0x0040
#define POLLRDBAND	0x0080
#define POLLWRBAND	0x0200
#define POLLMSG		0x0400

struct pollfd {
	int fd;
	short events;
	short revents;
};

#define SYS_SOCKET      1               /* sys_socket(2)                */
#define SYS_BIND        2               /* sys_bind(2)                  */
#define SYS_CONNECT     3               /* sys_connect(2)               */
#define SYS_LISTEN      4               /* sys_listen(2)                */
#define SYS_ACCEPT      5               /* sys_accept(2)                */
#define SYS_GETSOCKNAME 6               /* sys_getsockname(2)           */
#define SYS_GETPEERNAME 7               /* sys_getpeername(2)           */
#define SYS_SOCKETPAIR  8               /* sys_socketpair(2)            */
#define SYS_SEND        9               /* sys_send(2)                  */
#define SYS_RECV        10              /* sys_recv(2)                  */
#define SYS_SENDTO      11              /* sys_sendto(2)                */
#define SYS_RECVFROM    12              /* sys_recvfrom(2)              */
#define SYS_SHUTDOWN    13              /* sys_shutdown(2)              */
#define SYS_SETSOCKOPT  14              /* sys_setsockopt(2)            */
#define SYS_GETSOCKOPT  15              /* sys_getsockopt(2)            */
#define SYS_SENDMSG     16              /* sys_sendmsg(2)               */
#define SYS_RECVMSG     17              /* sys_recvmsg(2)               */

/* Socket types. */
#define SOCK_STREAM	1		/* stream (connection) socket	*/
#define SOCK_DGRAM	2		/* datagram (conn.less) socket	*/
#define SOCK_RAW	3		/* raw socket			*/
#define SOCK_RDM	4		/* reliably-delivered message	*/
#define SOCK_SEQPACKET	5		/* sequential packet socket	*/
#define SOCK_PACKET	10		/* linux specific way of	*/
					/* getting packets at the dev	*/
					/* level.  For writing rarp and	*/
					/* other similar things on the	*/
					/* user level.			*/

/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_ATMPVC	8	/* ATM PVCs			*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			*/
#define AF_ROSE		11	/* Amateur Radio X.25 PLP	*/
#define AF_DECnet	12	/* Reserved for DECnet project	*/
#define AF_NETBEUI	13	/* Reserved for 802.2LLC project*/
#define AF_SECURITY	14	/* Security callback pseudo AF */
#define AF_KEY		15      /* PF_KEY key management API */
#define AF_NETLINK	16
#define AF_ROUTE	AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET	17	/* Packet family		*/
#define AF_ASH		18	/* Ash				*/
#define AF_ECONET	19	/* Acorn Econet			*/
#define AF_ATMSVC	20	/* ATM SVCs			*/
#define AF_SNA		22	/* Linux SNA Project (nutters!) */
#define AF_IRDA		23	/* IRDA sockets			*/
#define AF_PPPOX	24	/* PPPoX sockets		*/
#define AF_WANPIPE	25	/* Wanpipe API Sockets */
#define AF_MAX		32	/* For now.. */


typedef struct {
	ulong	v[32];
} fd_set;

struct sel_arg_struct {
	ulong		n;
	fd_set		*inp, *outp, *exp;
        struct timeval	*tvp;
};

typedef struct {
	ulong	__val[32];
} sigset_t;

struct	sigaction {
	void	(*sa_handler)(int);
	sigset_t sa_mask;
	int	sa_flags;
	void	(*sa_restorer)(void);
};


struct in_addr {
	ulong	s_addr;
} __attribute__ ((packed));

struct sockaddr {
	ushort		sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
} __attribute__ ((packed));

struct sockaddr_in {
	ushort		sin_family;	/* Address family		*/
	ushort		sin_port;	/* Port number			*/
	struct in_addr	sin_addr;	/* Internet address		*/
	uchar		__pad[8];	/* padding */
} __attribute__ ((packed));

#define UNIX_PATH_MAX	108

struct sockaddr_un {
	ushort	sun_family;	/* AF_UNIX */
	char sun_path[UNIX_PATH_MAX];	/* pathname */
} __attribute__ ((packed));

/* this linux select() really sucks! */
#define FD_SET(fd, set) (set)->v[fd / 32] |= (1 << fd % 32)
#define FD_CLR(fd, set) (set)->v[fd / 32] &= ~(1 << fd % 32)
#define FD_ZERO(set) memset(set, 0, sizeof(*set));
#define FD_ISSET(fd, set) ((set)->v[fd / 32] & (1 << fd % 32))


#endif
