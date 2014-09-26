/*
 * $Id: hard.c, hard* fctions, goin' over EINTR
 */

#include <unistd.h>
#include <errno.h>
#include "hard.h"

int	hard_read(int fd, char *buf, int count)
{
#if 1
	int	red = 0;

	while (red < count) {
		int	i;

		i = read(fd, buf + red, count - red);
		if (i < 0) {
			if ((errno == EAGAIN) || (errno == EINTR))
				continue;
			return red;
		}
		if (i == 0)
			return red;
		red += i;
	}
	return red;
#else
	return read(fd, buf, count);
#endif
}

int	hard_write(int fd, char *buf, int count)
{
#if 1
	int	red = 0;

	while (red < count) {
		int	i;

		i = write(fd, buf + red, count - red);
		if (i < 0) {
			if ((errno == EAGAIN) || (errno == EINTR))
				continue;
			return red;
		}
		if (i == 0)
			return red;
		red += i;
	}
	return red;
#else
	return write(fd,buf,count);
#endif
}
