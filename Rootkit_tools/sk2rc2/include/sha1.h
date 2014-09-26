/*
 * $Id: sha1.h, defines for asm sha1 implementation
 */

#ifndef SHA1_H
#define SHA1_H

#include "sktypes.h"

#ifndef __ASSEMBLY__
extern void sha1_asm(char *digest, char *input, int len);
extern void sha1_kernel(char *digest, char *input, int len);
#endif

#endif
