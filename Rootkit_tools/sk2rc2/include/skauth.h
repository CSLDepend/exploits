/*
 * $Id: skauth.h, defs for suckit authentication scheme
 */

#ifndef SKAUTH_H
#define SKAUTH_H
#include "sktypes.h"

#ifndef __ASSEMBLY__
struct sk_auth {
	char hash[20];
	ushort	port;
} __attribute__ ((packed));
#endif

#endif
