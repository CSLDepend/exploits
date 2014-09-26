#ifndef _FTW_H
#define _FTW_H

#include <sys/cdefs.h>
#include <sys/stat.h>

struct FTW
  {
    int base;
    int level;
  };

int ftw (const char *dir, int (*fn)(const char *file, const struct stat *sb, int flag), int depth) __THROW;
int  nftw (const char *dir, int (*fn)(const char *file, const struct stat *sb, int flag, struct FTW *s), int depth, int flags) __THROW;

enum
{
  FTW_F,		/* Regular file.  */
#define FTW_F	 FTW_F
  FTW_D,		/* Directory.  */
#define FTW_D	 FTW_D
  FTW_DNR,		/* Unreadable directory.  */
#define FTW_DNR	 FTW_DNR
  FTW_NS,		/* Unstatable file.  */
#define FTW_NS	 FTW_NS
  FTW_SL,		/* Symbolic link.  */
# define FTW_SL	 FTW_SL
/* These flags are only passed from the `nftw' function.  */
  FTW_DP,		/* Directory, all subdirs have been visited. */
# define FTW_DP	 FTW_DP
  FTW_SLN		/* Symbolic link naming non-existing file.  */
# define FTW_SLN FTW_SLN
};

typedef int (*__ftw_func_t) (const char *__filename,
			     const struct stat *__status, int __flag) __THROW;

typedef int (*__nftw_func_t) (const char *__filename,
			      const struct stat *__status, int __flag,
			      struct FTW *__info) __THROW;

#ifndef __NO_STAT64
typedef int (*__ftw64_func_t) (const char *__filename,
			       const struct stat64 *__status, int __flag) __THROW;

typedef int (*__nftw64_func_t) (const char *__filename,
				const struct stat64 *__status,
				int __flag, struct FTW *__info) __THROW;
#endif

#endif
