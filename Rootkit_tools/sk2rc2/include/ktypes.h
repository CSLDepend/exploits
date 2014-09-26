/*
 * $Id: types.h, types/structures we need in kernel
 */

#ifndef KTYPES_H
#define KTYPES_H

#include "sktypes.h"

#define size_t ulong

#ifndef __ASSEMBLY__

struct old_stat {
	unsigned short st_dev;
	unsigned short st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned short st_rdev;
	unsigned long  st_size;
	unsigned long  st_atime;
	unsigned long  st_mtime;
	unsigned long  st_ctime;
} __attribute__ ((packed));


struct stat {
	unsigned short st_dev;
	unsigned short __pad1;
	unsigned long st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned short st_rdev;
	unsigned short __pad2;
	unsigned long  st_size;
	unsigned long  st_blksize;
	unsigned long  st_blocks;
	unsigned long  st_atime;
	unsigned long  __unused1;
	unsigned long  st_mtime;
	unsigned long  __unused2;
	unsigned long  st_ctime;
	unsigned long  __unused3;
	unsigned long  __unused4;
	unsigned long  __unused5;
}  __attribute__ ((packed));

struct stat64 {
	unsigned short	st_dev;
	unsigned char	__pad0[10];

#define STAT64_HAS_BROKEN_ST_INO	1
	unsigned long	__st_ino;

	unsigned int	st_mode;
	unsigned int	st_nlink;

	unsigned long	st_uid;
	unsigned long	st_gid;

	unsigned short	st_rdev;
	unsigned char	__pad3[10];

__extension__	long long	st_size;
	unsigned long	st_blksize;

	unsigned long	st_blocks;	/* Number 512-byte blocks allocated. */
	unsigned long	__pad4;		/* future possible st_blocks high bits */

	unsigned long	st_atime;
	unsigned long	__pad5;

	  signed long	st_mtime;
	unsigned long	__pad6;

	unsigned long	st_ctime;
	unsigned long	__pad7;		/* will be high 32 bits of ctime someday */

__extension__	unsigned long long	st_ino;
} __attribute__ ((packed));


struct timespec {
	uint	tv_sec;
	ulong	tv_nsec;
}  __attribute__ ((packed));

struct timeval {
	uint	tv_sec;
	ulong	tv_usec;
}  __attribute__ ((packed));

struct de {
	long		d_ino;
	int		d_off;
	unsigned short	d_reclen;
	char		d_name[256];
} __attribute__ ((packed));

struct de64 {
        ulong long      d_ino;
        ulong long      d_off;
        unsigned short  d_reclen;
        uchar           d_type;
        uchar           d_name[256];
}  __attribute__ ((packed));

struct statfs {
	long f_type;
	long f_bsize;
	long f_blocks;
	long f_bfree;
	long f_bavail;
	long f_files;
	long f_ffree;
	long f_fsid;
	long f_namelen;
	long f_spare[6];
}  __attribute__ ((packed));

/* ELF stuff */
typedef struct {
	ulong	elf;
	char	magic[12];
	ushort	type;
	ushort	arch;
	ulong	ver;
	ulong	ep;
	ulong	phtab;
	ulong	shtab;
	ulong	flags;
	ushort	size;
	
	ushort	phentsize;
	ushort	phnum;
	ushort	shentsize;
	ushort	shnum;
	ushort	shstridx;
} __attribute__ ((packed)) ELF;


typedef struct {
	ulong	type;
	ulong	off;
	ulong	va;
	ulong	pa;
	ulong	fsize;
	ulong	msize;
	ulong	flags;
	ulong	align;
}  __attribute__ ((packed)) PH;

/*
typedef	struct {
	ushort	pid;
	void	*ts;
} __attribute__ ((packed)) pid_struc;
*/
struct mmap {
        unsigned long addr;
        unsigned long len;
        unsigned long prot;
        unsigned long flags;
        unsigned long fd;
        unsigned long offset;
} __attribute__ ((packed));

struct pt_regs {
	ulong ebx;
	ulong ecx;
	ulong edx;
	ulong esi;
	ulong edi;
	ulong ebp;
	ulong eax;
	ulong xds;
	ulong xes;
	ulong orig_eax;
	ulong eip;
	ulong xcs;
	ulong flags;
	ulong esp;
	ulong xss;
} __attribute__ ((packed));


struct hook {
	uchar	nr;
	void	*handler;
} __attribute__ ((packed));

struct net {
	int	fd;
	int	len;
	int	pos;
	uchar	data[1];
} __attribute__ ((packed));

#endif

#endif
