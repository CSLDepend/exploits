/*
 * $Id: kmem.c, routines for work with /dev/mem and /dev/kmem
 */

#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

#include "kmem.h"
#include "setup.h"
#include "sk.h"

#define	MMAP_ONLY	0

#define OFFSET(x) ((x) & 4095)
#define ALIGNUP(x) (((x)+4095) & ~4095)
#define ALIGNDOWN(x) ((x) & ~4095)

static	int kmem_fd = -1;
#if !MMAP_ONLY
static	int is_kmem = 1;
#endif

static	void *kmap(ulong off, ulong count)
{
	void *p;

	p = mmap(NULL, ALIGNUP(count+4097), PROT_READ | PROT_WRITE, MAP_SHARED,
		kmem_fd, ALIGNDOWN(off) & 0x0fffffff);
	if (p == MAP_FAILED)
		return NULL;
	return p;
}

static	void unkmap(void *p, ulong count)
{
	munmap(p, ALIGNUP(count+4097));
}

/* init kmem stuff */
int	kmem_init(void)
{
	if (kmem_fd >= 0) return 0;
#if !MMAP_ONLY
	is_kmem = 1;
#endif
	kmem_fd = open(DEFAULT_KMEM, O_RDWR | O_SYNC, 0);
	if (kmem_fd < 0) {
		kmem_fd = open(DEFAULT_MEM, O_RDWR | O_SYNC, 0);
		if (kmem_fd < 0)
			return -1;
#if !MMAP_ONLY
		is_kmem = 0;
#endif
	}
	return 0;
}

/* close kmem stuff */
void	kmem_cleanup(void)
{
	if (kmem_fd < 0) return;
	close(kmem_fd);
	kmem_fd = -1;
}

int	rkm(void *buf, int count, ulong off)
{
	char	*m;
#if !MMAP_ONLY
	int	i;

	i = lseek(kmem_fd, off & (is_kmem?0xffffffff:0x0fffffff), SEEK_SET);
	if (i == -1)
		goto map;
	i = read(kmem_fd, buf, count);
	if (i != count) {
	map:
#endif
		if ((m = kmap(off, count))) {
			memcpy(buf, m + OFFSET(off), count);
			unkmap(m, count);
			return count;
		}
		return -1;
#if !MMAP_ONLY
	}
	return i;
#endif
}

int	wkm(void *buf, int count, ulong off)
{
	char	*m;
#if !MMAP_ONLY
	int	i;

	i = lseek(kmem_fd, off & (is_kmem?0xffffffff:0x0fffffff), SEEK_SET);
	if (i == -1) 
		goto map;
	i = write(kmem_fd, buf, count);
	if (i != count) {
	map:
#endif
		if ((m = kmap(off, count))) {
			memcpy(m + OFFSET(off), buf, count);
			unkmap(m, count);
			return count;
		}
		return -1;
#if !MMAP_ONLY
	}
	return i;
#endif
}

/* this is almost same, but for one long only */
int	rkml(ulong *l, ulong off)
{
	return rkm(l, sizeof(*l), off);
}

int	wkml(ulong l, ulong off)
{
	return wkm(&l, sizeof(l), off);
}


