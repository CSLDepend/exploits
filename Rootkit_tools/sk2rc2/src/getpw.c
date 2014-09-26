/*
 * $Id: getpw.c, password input
 *	we don't use getpass(), because it requieres a tty (which we
 *	always don't have ;)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <time.h>

#include "sk.h"
#include "getpw.h"

/* this will return a 20byte hash of entered password */
char	*getpassw(char *prompt)
{
        struct  termios old, new;
	static	char	p[256];
	int	len;

	/* get old term settings */
        tcgetattr(0, &old);
        new = old;
        new.c_lflag &= ~(ECHO);
        tcsetattr(0, TCSAFLUSH, &new);
	eprintf("%s", prompt); fflush(stdout);
	len = read(0, p, sizeof(p)-1);
	if (len > 0) p[len-1] = 0;
	putc('\n', stderr);
        tcsetattr(0, TCSAFLUSH, &old);
	return p;
}
