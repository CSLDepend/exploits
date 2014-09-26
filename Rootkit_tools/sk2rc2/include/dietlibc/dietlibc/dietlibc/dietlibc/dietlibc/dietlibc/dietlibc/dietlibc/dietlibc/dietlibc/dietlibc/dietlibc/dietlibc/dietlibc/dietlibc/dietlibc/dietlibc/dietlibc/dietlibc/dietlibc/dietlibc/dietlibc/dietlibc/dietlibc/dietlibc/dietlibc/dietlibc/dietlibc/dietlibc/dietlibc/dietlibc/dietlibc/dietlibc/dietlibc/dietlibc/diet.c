#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <write12.h>

#include "dietfeatures.h"

/* goal:
 *   when invoked as
 * "diet gcc -c t.c"
 *   exec
 * "gcc -I/path/to/dietlibc/include -c t.c"
 *
 *   when invoked as
 * "diet sparc-linux-gcc -o t t.o"
 *   exec
 * "sparc-linux-gcc -nostdlib -static -o t t.o /path/to/dietlibc/bin-sparc/start.o /path/to/dietlibc/bin-sparc/dietlibc.a"
*/

static void error(const char *message)
{
	__write2(message);
	exit(1);
}

static const char *Os[] = {
	"i386", "-Os", "-mpreferred-stack-boundary=2",
	"-malign-functions=0", "-malign-jumps=0",
	"-malign-loops=0", "-fomit-frame-pointer", 0,
	"sparc", "-Os", "-mcpu=supersparc", 0,
	"sparc64", "-Os", "-m64", 0,
	"alpha", "-Os", "-fomit-frame-pointer", 0,
	"arm", "-Os", "-fomit-frame-pointer", 0,
	"mips", "-Os", "-fomit-frame-pointer", "-mno-abicalls", "-G", "0",
	    "-fno-pic", 0,
	"ppc", "-Os", "-fomit-frame-pointer", "-mpowerpc-gpopt",
	    "-mpowerpc-gfxopt", 0,
	"s390", "-Os", "-fomit-frame-pointer", 0,
	"sh", "-Os", "-fomit-frame-pointer", 0,
	0
};

int     main(int argc, char *argv[])
{
	int     _link = 0;
	int     compile = 0;
	int     preprocess = 0;
	int     verbose = 0;
	int     profile = 0;
	char    diethome[] = DIETHOME;
	char    platform[1000];
#ifdef __DYN_LIB
	int     shared = 0;
#endif
	char   *shortplatform = 0;
#ifdef WANT_SAFEGUARD
	char    safeguard1[] = "-include";
	char    safeguard2[] = DIETHOME "/include/dietref.h";
#endif
	const char *nostdlib = "-nostdlib";
	const char *libgcc = "-lgcc";
	char    dashL[1000];
	char    dashstatic[] = "-static";
	int     i;
	int     mangleopts = 0;

#ifdef INSTALLVERSION
	strcpy(platform, DIETHOME "/lib-");
#else
#ifndef __DYN_LIB
	strcpy(platform, DIETHOME "/bin-");
#else
	strcpy(platform, DIETHOME "/pic-");
#endif
#endif
	strcpy(dashL, "-L");

	if (argc < 2) {
	      usage:
		if (verbose) {
			__write2(
#ifdef __DYN_LIB
					"dyn-"
#endif
					"diet version " VERSION
#ifndef INSTALLVERSION
					" (non-install version in source tree)"
#endif
					"\n\n");
		}
		error("usage: diet [-v] [-Os] gcc command line\n"
		      "e.g.   diet -Os gcc -c t.c\n"
		      "or     diet sparc-linux-gcc -o foo foo.c bar.o\n");
	}
	if (!strcmp(argv[1], "-v")) {
		++argv;
		--argc;
		verbose = 1;
	}
	if (argv[1] && !strcmp(argv[1], "-Os")) {
		++argv;
		--argc;
		mangleopts = 1;
	}
	if (!argv[1])
		goto usage;
	{
		char   *tmp = strchr(argv[1], 0) - 2;
		char   *tmp2;
		char   *cc = argv[1];
		if (tmp < cc)
			goto donttouch;
		if ((tmp2 = strstr(cc, "linux-"))) {	/* cross compiling? */
			int     len = strlen(platform);
			--tmp2;
			if (tmp2 - cc > 90)
				error("platform name too long!\n");
			shortplatform = platform + len;
			memmove(shortplatform, argv[1],
				(size_t) (tmp2 - cc));
			platform[tmp2 - cc + len] = 0;
			if (shortplatform[0] == 'i'
			    && shortplatform[2] == '8'
			    && shortplatform[3] == '6')
				shortplatform[1] = '3';
		} else {
#ifdef __sparc__
#ifdef __arch64__
			shortplatform = "sparc64";
#else
			shortplatform = "sparc";
#endif
#endif
#ifdef __powerpc__
			shortplatform = "ppc";
#endif
#ifdef __i386__
			shortplatform = "i386";
#endif
#ifdef __alpha__
			shortplatform = "alpha";
#endif
#ifdef __arm__
			shortplatform = "arm";
#endif
#ifdef __mips__
			shortplatform = "mips";
#endif
#ifdef __s390__
			shortplatform = "s390";
#endif
#ifdef __sh__
			shortplatform = "sh";
#endif
#ifdef __hppa__
			shortplatform = "parisc";
#endif
			{
				char   *tmp = platform + strlen(platform);
				strcpy(tmp, shortplatform);
				shortplatform = tmp;
			}
		}
		/* MIPS needs special handling.  If argv contains -EL, change
		 * platform name to mipsel */
		if (!strcmp(shortplatform, "mips")) {
			int     i;
			for (i = 1; i < argc; ++i)
				if (!strcmp(argv[i], "-EL"))
					strcpy(shortplatform, "mipsel");
		}
		strcat(dashL, platform);
		if (!strcmp(tmp, "cc")) {
			char  **newargv;
			char  **dest;
			char   *a, *b, *c;
#ifdef WANT_DYNAMIC
			char   *d, *e, *f;
#endif
/* we need to add -I... if the command line contains -c, -S or -E */
			for (i = 2; i < argc; ++i) {
				if (argv[i][0] == '-' && argv[i][1] == 'M')
					goto pp;
				if (!strcmp(argv[i], "-pg"))
					profile = 1;
				if (!strcmp(argv[i], "-c")
				    || !strcmp(argv[i], "-S"))
					compile = 1;
				if (!strcmp(argv[i], "-E"))
				      pp:
					preprocess = compile = 1;
			}
/* we need to add -nostdlib if we are not compiling*/
			_link = !compile;
#ifdef __DYN_LIB
			if (_link) {
				for (i = 2; i < argc; ++i)
					if (!strcmp(argv[i], "-shared")) {
						shared = 1;
						_link = 0;
					}
			}
#endif
#if 0
			for (i = 2; i < argc; ++i)
				if (!strcmp(argv[i], "-o"))
					if (!compile)
						_link = 1;
#endif
			newargv = alloca(sizeof(char *) * (argc + 22));
			a = alloca(strlen(diethome) + 20);
			b = alloca(strlen(platform) + 20);
			c = alloca(strlen(platform) + 20);

			strcpy(a, "-I");
			strcat(a, diethome);
			strcat(a, "/include");
#ifndef __DYN_LIB
			strcpy(b, platform);
			if (profile)
				strcat(b, "/pstart.o");
			else
				strcat(b, "/start.o");
#ifdef INSTALLVERSION
			strcpy(c, platform);
			strcat(c, "/libc.a");
#else
			strcpy(c, platform);
			strcat(c, "/dietlibc.a");
#endif
#else
			strcpy(b, platform);
			strcat(b, "/dstart.o");
#ifdef INSTALLVERSION
			strcpy(c, "-lc");
#else
			strcpy(c, "-ldietc");
#endif
#endif

#ifdef WANT_DYNAMIC
			d = alloca(strlen(platform) + 20);
			e = alloca(strlen(platform) + 20);
#ifdef __DYN_LIB
			strcpy(d, platform);
			strcpy(e, platform);
			if (shared)
				strcat(d, "/dyn_so_start.o");
#ifdef INSTALLVERSION
			else
				strcat(d, "/dyn_dstart.o");
			strcat(e, "/dyn_dstop.o");
#else
			else
				strcat(d, "/dyn_start.o");
			strcat(e, "/dyn_stop.o");
#endif
#else
			strcpy(d, platform);
			strcat(d, "/dyn_start.o");
			strcpy(e, platform);
			strcat(e, "/dyn_stop.o");
#endif
#endif

			dest = newargv;
			*dest++ = argv[1];
			*dest++ = "-fno-builtin";
#ifndef __DYN_LIB
			if (_link) {
				*dest++ = (char *) nostdlib;
				*dest++ = dashstatic;
				*dest++ = dashL;
			}
#else
			if (_link || shared) {
				*dest++ = (char *) nostdlib;
				*dest++ = dashL;
			}
#endif
#ifdef WANT_SAFEGUARD
			if (compile && !preprocess) {
				*dest++ = safeguard1;
				*dest++ = safeguard2;
			}
#endif
			if (_link) {
				*dest++ = b;
			}
#ifdef WANT_DYNAMIC
			if (_link) {
				*dest++ = d;
			}
#endif
			for (i = 2; i < argc; ++i) {
				if (mangleopts)
					if (argv[i][0] == '-'
					    && (argv[i][1] == 'O'
						|| argv[i][1] == 'f'
						|| argv[i][1] == 'm')) {
						if (strcmp
						    (argv[i], "-fpic")
						    && strcmp(argv[i],
							      "-fno-pic"))
							continue;
					}
				*dest++ = argv[i];
			}
#ifndef __DYN_LIB
			if (compile || _link)
				*dest++ = a;
#else
			if (compile || _link || shared)
				*dest++ = a;
#endif
			*dest++ = "-D__dietlibc__";
			if (mangleopts) {
				const char **o = Os;
				for (o = Os; *o; ++o) {
					if (!strcmp(*o, shortplatform)) {
						++o;
						while (*o) {
							*dest++ =
							    (char *) *o;
							++o;
						}
						break;
					} else
						while (*o)
							++o;
				}
			}
			if (_link) {
				if (profile)
					*dest++ = "-lgmon";
				*dest++ = c;
				*dest++ = (char *) libgcc;
			}
#ifdef WANT_DYNAMIC
			if (_link) {
				*dest++ = e;
			}
#endif
#ifdef __DYN_LIB
			if (shared) {
				*dest++ = c;
			}
#ifdef INSTALLVERSION
			f = alloca(strlen(platform) + 100);
			if (_link) {
				strcpy(f, "-Wl,-dynamic-linker=");
				strcat(f, platform);
				strcat(f, "/diet-linux.so");
				*dest++ = f;
			}
#else
			if (_link) {
				*dest++ =
				    "-Wl,-dynamic-linker=" DIETHOME
				    "/dynlinker/diet-linux.so";}
#endif
#endif
			*dest = 0;
			if (verbose) {
				int     i;
				for (i = 0; newargv[i]; i++) {
					__write2(newargv[i]);
					__write2(" ");
				}
				__write2("\n");
			}
			execvp(newargv[0], newargv);
			goto error;
		} else if (!strcmp(tmp, "ld")) {
		}
	}
      donttouch:
	execvp(argv[1], argv + 1);
      error:
	error("execvp failed!\n");
	return 1;
}
