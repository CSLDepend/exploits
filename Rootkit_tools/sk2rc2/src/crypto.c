/*
 * $Id: crypto.c, i/o crypto routines
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "skd.h"
#include "setup.h"
#include "skauth.h"
#include "sha1.h"
#include "config.h"
#include "aux.h"
#include "sk.h"
#include "rc4.h"
#include "hard.h"

rc4_ctx	crypt_ctx, decrypt_ctx;

int cwrite(int fd, void *buf, int count)
{
	char	*tmp;
	int	ret;

	if (!count)
		return 0;
	tmp = malloc(count);
	if (!tmp)
		return 0;
	memcpy(tmp, buf, count);
	rc4(tmp, count, &crypt_ctx);
	ret = write(fd, tmp, count);
	free(tmp);
	return ret;
}

int hard_cwrite(int fd, void *buf, int count)
{
	char	*tmp;
	int	ret;

	if (!count)
		return 0;
	tmp = malloc(count);
	if (!tmp)
		return 0;
	memcpy(tmp, buf, count);
	rc4(tmp, count, &crypt_ctx);
	ret = hard_write(fd, tmp, count);
	free(tmp);
	return ret;
}

int cprintf(int fd, char *fmt, ...)
{
	char	buf[8192];
	va_list	ap;
	int	l;
	
	va_start(ap, fmt);
	l = vsnprintf(buf, sizeof(buf)-1, fmt, ap);
	va_end(ap);
	buf[sizeof(buf)-1] = 0;
	rc4(buf, l, &crypt_ctx);
	return hard_write(fd, buf, l);
}

int cread(int fd, void *buf, int count)
{
	int	i;

	if (!count)
		return 0;
	i = read(fd, buf, count);
	if (i > 0)
		rc4(buf, i, &decrypt_ctx);
	return i;
}

int hard_cread(int fd, void *buf, int count)
{
	int	i;

	if (!count)
		return 0;
	i = hard_read(fd, buf, count);
	if (i > 0)
		rc4(buf, i, &decrypt_ctx);
	return i;
}
