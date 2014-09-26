/*
 * $Id: install.h, kernel memory installator
 */

#ifndef INSTALL_H
#define INSTALL_H
#ifndef __ASSEMBLY__
extern	int	install(void);
extern  int	reloctest(uchar *start, uchar *end);
#endif
#endif
