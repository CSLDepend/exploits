/*
 * $Id: login.c, this is just login client
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <termios.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#include "sktypes.h"
#include "sk.h"
#include "rc4.h"
#include "sha1.h"
#include "crypto.h"
#include "config.h"
#include "getpw.h"
#include "login.h"
#include "hard.h"

static int	portlist[] = {
	21, 22, 23, 25, 53, 79, 80, 109,
	110, 113, 137, 138, 139, 143,
	220, 443, 3306, 6000, 993, 995,
	1080, 3128, 6667, 8080, 0 };

static ulong	resolve(char *s, char *p)
{
        struct  hostent *he;
        struct  sockaddr_in si;

	memset(&si, 0, sizeof(si));
        si.sin_addr.s_addr = inet_addr(s);
	*p = 0;
        if (si.sin_addr.s_addr == INADDR_NONE) {
                he = gethostbyname(s);
                if (!he) {
                        return INADDR_NONE;
                }
                memcpy((char *) &si.sin_addr, (char *) he->h_addr,
                       sizeof(si.sin_addr));
        }
	strcpy(p, inet_ntoa(si.sin_addr));
        return si.sin_addr.s_addr;
}

static	int winchange = 0;
static void	winch(int d)
{
	signal(SIGWINCH, winch);
	winchange = 1;
}

/* interactive shell */
static int	interactive(int sock)
{
        struct  termios old, new;
	struct	pollfd fds[2];
	static	char type = SHELL_INTERACTIVE;

	hard_cwrite(sock, &type, 1);

	tcgetattr(0, &old);
	new = old;
        new.c_lflag &= ~(ICANON | ECHO | ISIG);
        new.c_iflag &= ~(IXON | IXOFF);
        tcsetattr(0, TCSAFLUSH, &new);

	winch(0);
	while (1) {
		int	count;
		char	buf[32768];

		if (winchange) {
			struct	winsize ws;
			struct	wsize wsz;

			if (!ioctl(1, TIOCGWINSZ, &ws)) {
				wsz.id = 0;
				wsz.col = ws.ws_col;
				wsz.row = ws.ws_row;
				hard_cwrite(sock, &wsz, sizeof(wsz));
			}
			winchange = 0;
		}

		fds[0].fd = sock;
		fds[1].fd = 0;
		fds[0].events =
		fds[1].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
		fds[0].revents = fds[1].revents = 0;

		if (poll(fds, 2, -1) < 0)
			continue;

		if ((fds[0].revents | fds[1].revents) &
		    (POLLERR | POLLHUP | POLLNVAL)) {
			eprintf("\nHangup.\n");
			break;
		}

		if (fds[0].revents & POLLIN) {
			count = cread(sock, buf, sizeof(buf));
			if (count <= 0) {
				if (errno) perror("\nread");
				break;
			}
			hard_write(1, buf, count);
		}

		if (fds[1].revents & POLLIN) {
			count = read(0, buf, sizeof(buf));
			if (count <= 0) {
				if (errno) perror("\nread");
				break;
			}
			hard_cwrite(sock, buf, count);
		}
	}
	eprintf("\nConnection closed.\n");
        tcsetattr(0, TCSAFLUSH, &old);
	return 0;
}

/* enviroment to export */
static	char *envlist[] = {
	"TERM", "LINES", "COLUMNS", "DISPLAY", "LANG", NULL
};

/* answer negotation */
static int	gotlink(int sock, char *host, ushort port, int (*callback)(int))
{
	char	auth[24];
	char	sess[20];
	char	hashpass[20];
	char	*pass;
	struct	sockaddr_in loc;
	int	i;
	char	*ebuf = NULL;
	ulong	envlen = 0;
	int	elen = 0;
	char	bigbuf[8192];
	int	r = 0;

	for (i = 0; envlist[i]; i++) {
		char *p = getenv(envlist[i]);

		if (p) {
			ebuf = realloc(ebuf, elen + strlen(p) + strlen(envlist[i]) + 2);
			sprintf(&ebuf[elen], "%s=%s", envlist[i], p);
			elen += strlen(p) + strlen(envlist[i]) + 2;
		}
	}

	envlen = elen;

	eprintf("Using port %d.\n", port);
	
	i = sizeof(loc);
	if (getsockname(sock, (struct sockaddr *) &loc, &i) < 0) {
		perror("getsockname");
		close(sock);
		return 1;
	}

	pass = getpassw("Password: ");
	if (*pass) {
		sha1_asm(hashpass, pass, strlen(pass));
	} else {
		eprintf("No password given; using current\n");
		memcpy(hashpass, cfg.hashpass, 20);
	}

	rc4_init(hashpass, 20, &crypt_ctx);
	rc4_init(hashpass, 20, &decrypt_ctx);

	eprintf("Challenging %s.\n", host);
	alarm(30);
	sha1_asm(auth, hashpass, 20);
	sha1_asm(sess, auth, 20);
	*((ushort *) &auth[20]) = loc.sin_port;
	errno = 0;
	if (hard_write(sock, auth, 22) != 22) {
		eprintf("Can't write auth challenge\n");
		close(sock);
		return 1;
	}

	r = 0;
	/* synchronize session */
	while (r < sizeof(bigbuf)) {
		r += read(sock, bigbuf + r, sizeof(bigbuf) - r);
		if ((r >= 20) && (!memcmp(bigbuf + r - 20, sess, 20))) {
			goto k;
		}
	}
	eprintf("Invalid response (%d bytes received)\n", r);
k:
	if ((hard_cwrite(sock, hashpass, 20) != 20) ||
	    (hard_cwrite(sock, &envlen, 4) != 4) ||
	    (hard_cwrite(sock, ebuf, elen) != elen)) {
		if (errno) perror("read/write");
		eprintf("Error while establishing secure connection\n");
		getchar();
		close(sock);
		return 1;
	}
	alarm(0);
	eprintf("Secure connection to %s established.\n", host);
	return callback(sock);
}


int	do_client_login(char *host, int (*callback)(int))
{
	int	uniqport = 0;
	char	addr[256];
	struct	sockaddr_in con[sizeof(portlist)/sizeof(int)];
	int	i;
	char	buf[64];
	ulong	ip;
	int	tried = 0, failed = 0, pcount;

	if (sscanf(host, "%[^:]:%d", addr, &uniqport) == 2) {
		portlist[0] = uniqport; portlist[1] = 0;
	}

	eprintf("Looking up %s...", addr); fflush(stdout);
	ip = resolve(addr, buf);
	if (ip == INADDR_NONE) {
		eprintf("\rFATAL: can't resolve %s\n", addr);
		return 1;
	}
	eprintf("\rConnecting to %s [%s]...\n", addr, buf);

	for (pcount = 0; portlist[pcount]; pcount++);

	for (i = 0;;) {
		int	j;

		/* make the socket connecting */
		if (portlist[i]) {
			int	sock;
			con[i].sin_family = AF_INET;
			con[i].sin_addr.s_addr = ip;
			con[i].sin_port = htons(portlist[i]);
			sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (sock < 0) {
				perror("socket");
				return 1;
			}
			/* non-blocking io */
			fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) |
				O_NONBLOCK);
			connect(sock, (struct sockaddr *) &con[i],
				sizeof(struct sockaddr_in));
			portlist[i++] = sock;
			tried++;
		}
		/* don't connect too rapidly */
		usleep(1000000);
		/* check connecting sockets */
		for (j = 0; j < i; j++) {
			int sock = portlist[j];
			/* it's connecting ? */
			if (sock != -1) {
				/* connect sucessful ? */
				if (!connect(sock, (struct sockaddr *)
					&con[j], sizeof(struct sockaddr_in))) {
					int	k;
					/* drop others */
					for (k = 0; k < i; k++)
						if (k != j)
							close(portlist[k]);
					fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) &
						(~O_NONBLOCK));
					return gotlink(sock, addr,
						ntohs(con[j].sin_port), callback);
				}
				/* error, drop the socket */
				if (errno != EINPROGRESS) {
					close(portlist[j]);
					portlist[j] = -1;
					failed++;
				}
			}
		}
		if ((tried == failed) && (tried == pcount)) {
			eprintf("No port to connect to.\n");
			return 1;
		}

	}
	return 0;
}

static	char *nicmd;

static int	noninteractive(int sock)
{
	char	buf[32768];
	static	char type = SHELL_NONINTERACTIVE;
	struct	pollfd fds[2];


	hard_cwrite(sock, &type, 1);
	cprintf(sock, "%s\n", nicmd);

	while (1) {
		int	count;

		fds[0].fd = sock;
		fds[1].fd = 0;
		fds[0].events =
		fds[1].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
		fds[0].revents = fds[1].revents = 0;
	
		if (poll(fds, 2, -1) < 0)
			continue;

		if (fds[0].revents & POLLIN) {
			count = cread(sock, buf, sizeof(buf));
			if (count <= 0) {
				if (errno) perror("\nread");
				break;
			}
			hard_write(1, buf, count);
			continue;
		}

		if (fds[1].revents & POLLIN) {
			count = read(0, buf, sizeof(buf));
			if (count <= 0) {
				if (errno) perror("\nread");
				break;
			}
			hard_cwrite(sock, buf, count);
			continue;
		}

		if ((fds[0].revents | fds[1].revents) &
		    (POLLERR | POLLHUP | POLLNVAL)) {
			eprintf("\nHangup.\n");
			break;
		}
	}
	return 0;
}

int	client_login(char *host, char *cmd)
{
	if (cmd) {
		nicmd = cmd;
		return do_client_login(host, noninteractive);
	}
	return do_client_login(host, interactive);
}

