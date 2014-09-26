/*
 * $Id: crypto.h, i/o crypto routines
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include "rc4.h"

extern	rc4_ctx	crypt_ctx, decrypt_ctx;
extern	int cwrite(int fd, void *buf, int count);
extern	int cprintf(int fd, char *fmt, ...);
extern	int cread(int fd, void *buf, int count);
extern	int hard_cwrite(int fd, void *buf, int count);
extern	int hard_cread(int fd, void *buf, int count);

#endif
